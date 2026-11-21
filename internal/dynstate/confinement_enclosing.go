package dynstate

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type rootOriginPolicy struct {
	verifyLocalOrigins   bool
	allowEnclosingParams bool
	inInitFlow           bool
	nestedClosure        bool
	unattestedBroken     map[string]bool
	singleSubjectVars    map[string]bool
	settledGlobals       settledGlobalMap
	currentTargets       []*types.Var
	checkCarryingValue   func(*flowir.Value) bool
	checkEnclosingParam  func(pIdx int, paramVar *types.Var) bool
	carrierAliasRoots    map[types.Object]bool
	linkedCarrierGlobals map[string]bool
}

type enclosingConfinementState struct {
	selfLit           *ast.FuncLit
	exemptCall        *ast.CallExpr
	origin            *rootOriginPolicy
	aliases           map[types.Object]map[types.Object]bool
	definedOnce       map[types.Object]bool
	usedCarrierGlobal bool
}

// enclosingConfinesRoots verifies via confinementEngine (confinementModeEnclosingRoots)
// that enclosing never mutates, rebinds after initialization, addresses, spawns
// goroutines with, or leaks mutable backing storage of roots outside selfLit
// (and exemptCall when non-nil).
func enclosingConfinesRoots(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	enclosing ast.Node,
	selfLit *ast.FuncLit,
	exemptCall *ast.CallExpr,
	roots map[types.Object]bool,
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
	origin *rootOriginPolicy,
) bool {
	if p == nil || p.TypesInfo == nil || enclosing == nil {
		return false
	}
	if len(roots) == 0 {
		return true
	}
	enclBody := fc.scopeBody(p, enclosing)
	if enclBody == nil {
		return false
	}
	eng := &confinementEngine{
		mode:        confinementModeEnclosingRoots,
		audited:     audited,
		p:           p,
		fc:          fc,
		rootBody:    enclBody,
		roots:       roots,
		wants:       wants,
		methodWants: methodWants,
		encl: &enclosingConfinementState{
			selfLit:     selfLit,
			exemptCall:  exemptCall,
			origin:      origin,
			definedOnce: map[types.Object]bool{},
		},
	}
	return eng.run()
}

func enclReachOrSyncOrStr(t types.Type) bool {
	return typeHandsOutReachOrAddr(t) || refconfine.TypeReachesSyncNoCopyByValue(t)
}

func (e *confinementEngine) runEnclosingRoots() bool {
	st := e.encl
	var exemptMap map[*ast.CallExpr]bool
	if st.exemptCall != nil {
		exemptMap = map[*ast.CallExpr]bool{st.exemptCall: true}
	}
	st.aliases = flowir.BuildEnclosingMemAliasesExcept(
		e.rootBody,
		func(o types.Object) bool { return syntaxutil.IsLocalVar(o) || e.roots[o] },
		typeHandsOutReachOrAddr,
		exemptMap,
	)
	for changed := true; changed; {
		changed = false
		for r := range e.roots {
			for nb := range st.aliases[r] {
				if !e.roots[nb] {
					e.roots[nb] = true
					changed = true
				}
			}
		}
	}

	if !e.validateEnclosingRoots() {
		return false
	}

	sound := true
	e.rootBody.ForEachSyncOp(func(op *flowir.Op) bool {
		if !e.checkEnclosingOp(op) {
			sound = false
			return false
		}
		return true
	})
	if !sound {
		return false
	}

	if st.origin != nil && len(st.origin.carrierAliasRoots) > 0 {
		for changed := true; changed; {
			changed = false
			for r := range st.origin.carrierAliasRoots {
				for nb := range st.aliases[r] {
					if !st.origin.carrierAliasRoots[nb] {
						st.origin.carrierAliasRoots[nb] = true
						changed = true
					}
				}
			}
		}
		flowir.VisitAllOps(e.rootBody, func(op *flowir.Op) {
			if !sound {
				return
			}
			forEachOpTopValues(op, func(v *flowir.Value) {
				if !sound || v == nil {
					return
				}
				v.WalkValues(func(cur *flowir.Value) bool {
					if !sound {
						return false
					}
					if cur.Kind == flowir.ValMakeClosure && cur.Lit != st.selfLit {
						if cur.Closure == nil || !closureExtractsNoCarrierFromRoots(e.audited, cur.Closure, st.origin.carrierAliasRoots) {
							sound = false
							return false
						}
					}
					return true
				})
			})
		})
	}
	return sound
}

func (e *confinementEngine) validateEnclosingRoots() bool {
	origin := e.encl.origin
	enclBody := e.rootBody
	for r := range e.roots {
		if r == nil || refconfine.TypeReachesSyncNoCopyByValue(r.Type()) {
			return false
		}
		v, ok := r.(*types.Var)
		if !ok {
			return false
		}
		if syntaxutil.IsLocalVar(v) {
			if enclBody.ResultSet[v] {
				return false
			}
			if origin != nil && !origin.nestedClosure {
				if !enclBody.OwnsVar(v) {
					return false
				}
				nonScalar := typeHandsOutReachOrAddr(v.Type()) ||
					refconfine.TypeCarriesSignature(v.Type()) ||
					refconfine.TypeMayCarryUnknownDynamic(e.audited, v.Type())
				if nonScalar && v == enclBody.Recv {
					return false
				}
				if nonScalar && !origin.allowEnclosingParams {
					if pIdx, isParam := enclBody.ParamIndex[v]; isParam {
						if origin.checkEnclosingParam == nil || !origin.checkEnclosingParam(pIdx, v) {
							return false
						}
					}
				}
			} else {
				if !enclBody.OwnsVar(v) && !enclBody.FreeVars[v] {
					return false
				}
				if origin != nil && origin.verifyLocalOrigins {
					if v == enclBody.Recv {
						return false
					}
					if _, isParam := enclBody.ParamIndex[v]; isParam {
						return false
					}
				}
			}
		} else {
			e.globalRoots = append(e.globalRoots, v)
		}
	}
	return true
}

func (e *confinementEngine) isOuterOrSigVar(v *types.Var) bool {
	if v == nil || !syntaxutil.IsLocalVar(v) {
		return true
	}
	if v == e.rootBody.Recv || e.rootBody.ResultSet[v] {
		return true
	}
	if _, isParam := e.rootBody.ParamIndex[v]; isParam {
		return true
	}
	return v.Pos() < e.rootBody.BodyStart || v.Pos() > e.rootBody.BodyEnd
}

func (e *confinementEngine) isCleanRootInitValue(v *flowir.Value) bool {
	origin := e.encl.origin
	var settled settledGlobalMap
	var targets []*types.Var
	if origin != nil {
		settled = origin.settledGlobals
		targets = origin.currentTargets
	}
	if isPureFreshDataValue(settled, v) {
		return true
	}
	return checkPureOrFreshValue(v, valuePurityPolicy{
		allowAppend:          true,
		allowValuePlane:      true,
		allowRuntimeOps:      true,
		allowTypeAssert:      true,
		allowNonMutableReach: true,
		allowSigLeaf: func(leaf *flowir.Value) bool {
			if leaf.Kind == flowir.ValScalarLitOrConst ||
				(leaf.Kind == flowir.ValPlace && (leaf.Place.Root == flowir.RootConstOrNil || (leaf.Place.Root == flowir.RootFunc && !leaf.Place.IsMethodExpr))) {
				return true
			}
			return origin != nil && origin.checkCarryingValue != nil && origin.checkCarryingValue(leaf)
		},
		allowPlace: func(pv *flowir.Value) bool {
			if pv.Place.Root == flowir.RootFunc && !pv.Place.IsMethodExpr {
				return true
			}
			if pv.Place.Root == flowir.RootPkgGlobal {
				gv := pv.Place.Obj
				if gv == nil {
					return false
				}
				if settled.allowedForTargets(gv, targets) {
					return true
				}
				if origin != nil && origin.inInitFlow && !origin.nestedClosure && len(pv.Place.Projs) == 0 &&
					!gv.IsField() && gv.Pkg() != nil && gv.Parent() == gv.Pkg().Scope() &&
					refconfine.TypeMayCarryUnknownDynamic(e.audited, gv.Type()) {
					gvKey := syntaxutil.DynamicVarKey(gv)
					if (e.p.Types == nil || gv.Pkg() != e.p.Types || !origin.unattestedBroken[gvKey]) && !origin.singleSubjectVars[gvKey] {
						if origin.linkedCarrierGlobals == nil {
							origin.linkedCarrierGlobals = map[string]bool{}
						}
						origin.linkedCarrierGlobals[gvKey] = true
						e.encl.usedCarrierGlobal = true
						return true
					}
				}
				return false
			}
			if pv.Place.Obj != nil && e.roots[pv.Place.Obj] {
				if origin != nil && origin.carrierAliasRoots[pv.Place.Obj] {
					e.encl.usedCarrierGlobal = true
				}
				return true
			}
			if pv.Place.Root == flowir.RootTransient && pv.Place.Base != nil {
				return e.isCleanRootInitValue(pv.Place.Base)
			}
			return false
		},
	})
}

func (e *confinementEngine) collectPlaceMutableRoots(pl flowir.Place, out map[*types.Var]bool) {
	if pl.Obj != nil && e.roots[pl.Obj] && enclReachOrSyncOrStr(pl.Obj.Type()) {
		out[pl.Obj] = true
	}
	if pl.Root == flowir.RootTransient && pl.Base != nil {
		e.collectValMutableRoots(pl.Base, out)
	}
}

func (e *confinementEngine) collectValMutableRoots(v *flowir.Value, out map[*types.Var]bool) {
	if v == nil {
		return
	}
	if e.encl.selfLit != nil && v.Kind == flowir.ValMakeClosure && v.Lit == e.encl.selfLit {
		return
	}
	if e.encl.exemptCall != nil && v.Kind == flowir.ValCall && v.CallAST == e.encl.exemptCall {
		return
	}
	isStrBuiltin := v.Kind == flowir.ValCall && v.CallKind == flowir.CallBuiltin &&
		(v.BuiltinName == "String" || v.BuiltinName == "StringData")
	if !isStrBuiltin && v.Kind != flowir.ValAddrOf && v.Kind != flowir.ValMethodVal &&
		v.Type != nil && !enclReachOrSyncOrStr(v.Type) {
		return
	}
	switch v.Kind {
	case flowir.ValPlace:
		if len(v.Place.Projs) > 0 && v.Type != nil && !enclReachOrSyncOrStr(v.Type) {
			return
		}
		e.collectPlaceMutableRoots(v.Place, out)
	case flowir.ValAddrOf:
		if v.AddrPlace.Obj != nil && e.roots[v.AddrPlace.Obj] {
			out[v.AddrPlace.Obj] = true
		} else if v.AddrPlace.Root == flowir.RootTransient && v.AddrPlace.Base != nil {
			e.collectValMutableRoots(v.AddrPlace.Base, out)
		}
	case flowir.ValMethodVal:
		if v.HasRecvPlace && v.RecvPlace.Obj != nil && e.roots[v.RecvPlace.Obj] {
			out[v.RecvPlace.Obj] = true
		}
		e.collectValMutableRoots(v.Recv, out)
	case flowir.ValAllocFresh:
		switch v.AllocKind {
		case flowir.AllocBuiltinNewExpr:
			for _, a := range v.Args {
				e.collectValMutableRoots(a, out)
			}
		case flowir.AllocCompositeLit:
			for i := range v.CompositeElts {
				e.collectValMutableRoots(v.CompositeElts[i].MapKey, out)
				e.collectValMutableRoots(v.CompositeElts[i].Value, out)
			}
		}
	case flowir.ValMakeClosure:
		if v.Closure != nil {
			for fv := range v.Closure.FreeVars {
				if e.roots[fv] && enclReachOrSyncOrStr(fv.Type()) {
					out[fv] = true
				}
			}
			for _, gv := range e.globalRoots {
				if enclReachOrSyncOrStr(gv.Type()) && flowir.BodyMentionsVar(v.Closure, gv) {
					out[gv] = true
				}
			}
		}
	case flowir.ValCall:
		if v.CallKind == flowir.CallBuiltin {
			switch v.BuiltinName {
			case "len", "cap", "Sizeof", "Alignof", "Offsetof":
				return
			case "Slice", "SliceData", "String", "StringData":
				if len(v.Args) > 0 {
					e.collectValMutableRoots(v.Args[0], out)
				}
				return
			}
		}
		if v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj != nil && e.roots[v.RecvPlace.Obj] {
			out[v.RecvPlace.Obj] = true
		}
		e.collectValMutableRoots(v.Recv, out)
		e.collectValMutableRoots(v.Callee, out)
		for _, a := range v.Args {
			e.collectValMutableRoots(a, out)
		}
	case flowir.ValConvert:
		e.collectValMutableRoots(v.Arg, out)
	case flowir.ValChanRecv:
		e.collectValMutableRoots(v.Chan, out)
	case flowir.ValCompositeExpr:
		for _, a := range v.Args {
			e.collectValMutableRoots(a, out)
		}
	}
}

func (e *confinementEngine) suppliesMutableRoot(v *flowir.Value) bool {
	m := map[*types.Var]bool{}
	e.collectValMutableRoots(v, m)
	return len(m) > 0
}

func (e *confinementEngine) checkEnclosingValue(v *flowir.Value) bool {
	if v == nil {
		return true
	}
	st := e.encl
	if st.selfLit != nil && v.Kind == flowir.ValMakeClosure && v.Lit == st.selfLit {
		return true
	}
	if st.exemptCall != nil && v.Kind == flowir.ValCall && v.CallAST == st.exemptCall {
		return true
	}
	switch v.Kind {
	case flowir.ValInvalid:
		return false
	case flowir.ValConvert:
		if syntaxutil.IsUnsafePointerType(v.Type) &&
			(e.suppliesMutableRoot(v.Arg) || (e.valueTouchesAnyRoot(v.Arg) && (v.Arg == nil || syntaxutil.ContainsUintptr(v.Arg.Type)))) {
			return false
		}
	case flowir.ValAddrOf:
		if v.AddrPlace.Obj != nil && e.roots[v.AddrPlace.Obj] {
			return false
		}
		if v.AddrPlace.Root == flowir.RootTransient && e.suppliesMutableRoot(v.AddrPlace.Base) {
			return false
		}
	case flowir.ValMethodVal:
		if v.AutoAddr && v.HasRecvPlace && v.RecvPlace.Obj != nil && e.roots[v.RecvPlace.Obj] {
			return false
		}
		if e.suppliesMutableRoot(v.Recv) {
			return false
		}
	case flowir.ValChanRecv:
		if e.suppliesMutableRoot(v.Chan) {
			return false
		}
	case flowir.ValMakeClosure:
		if v.Lit == nil || v.Closure == nil {
			return false
		}
		localRoots := map[types.Object]bool{}
		subRoots := map[types.Object]bool{}
		for fv := range v.Closure.FreeVars {
			if e.roots[fv] {
				subRoots[fv] = true
				if syntaxutil.IsLocalVar(fv) {
					localRoots[fv] = true
				}
			}
		}
		for _, gv := range e.globalRoots {
			if flowir.BodyMentionsVar(v.Closure, gv) {
				subRoots[gv] = true
			}
		}
		if len(localRoots) > 0 && !boundValueClosureEnvLeakFreeJudged(e.audited, e.p, e.fc, localRoots, v.Lit.Body, e.wants, e.methodWants) {
			return false
		}
		if len(subRoots) > 0 {
			var subOrigin *rootOriginPolicy
			if st.origin != nil {
				cp := *st.origin
				cp.nestedClosure = true
				subOrigin = &cp
			}
			if !enclosingConfinesRoots(e.audited, e.p, e.fc, v.Lit, st.selfLit, st.exemptCall, subRoots, e.wants, e.methodWants, subOrigin) {
				return false
			}
		}
		return true
	case flowir.ValCall:
		if !e.checkEnclosingCall(v) {
			return false
		}
	}
	ok := true
	v.ForEachChildValue(func(ch *flowir.Value) bool {
		if !e.checkEnclosingValue(ch) {
			ok = false
			return false
		}
		return true
	})
	return ok
}

func (e *confinementEngine) checkEnclosingCall(v *flowir.Value) bool {
	switch v.CallKind {
	case flowir.CallBuiltin:
		switch v.BuiltinName {
		case "StringData", "String":
			return !e.suppliesMutableRoot(v) && !e.valueTouchesAnyRoot(v)
		case "Sizeof", "Alignof", "Offsetof":
			return true
		case "delete", "clear", "close":
			return len(v.Args) == 0 || !e.suppliesMutableRoot(v.Args[0])
		case "copy":
			if len(v.Args) > 0 && e.suppliesMutableRoot(v.Args[0]) {
				return false
			}
			if len(v.Args) == 2 && e.suppliesMutableRoot(v.Args[1]) &&
				(v.Args[0] == nil || containerElemHandsOutReach(v.Args[0].Type)) {
				return false
			}
			return true
		case "append":
			if len(v.Args) > 0 && e.suppliesMutableRoot(v.Args[0]) {
				return false
			}
			if len(v.Args) >= 2 && !isPureFreshDataValueWith(v.Args[0], nil) {
				for _, a := range v.Args[1:] {
					if e.suppliesMutableRoot(a) {
						return false
					}
				}
			}
			return true
		}
	case flowir.CallPlain:
		if v.CalleeFunc == nil || v.IsMethodExprCall {
			for _, a := range v.Args {
				if e.suppliesMutableRoot(a) {
					return false
				}
			}
			return true
		}
		fk := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Origin().Name()}
		if !auditset.ValuePlaneClone(fk.Pkg, fk.Name) {
			okArgs := true
			v.ForEachArgParam(func(a *flowir.Value, slotType types.Type, _ int, pIdx int, pOK bool, _ bool) bool {
				if !e.suppliesMutableRoot(a) {
					return true
				}
				if slotType != nil && !refconfine.CallResultHandsOut(slotType) {
					return true
				}
				if e.wants == nil || !pOK {
					okArgs = false
					return false
				}
				e.wants[syntaxutil.ParamKey{Func: fk, Index: pIdx}] = true
				return true
			})
			return okArgs
		}
		return true
	case flowir.CallMethod:
		for _, a := range v.Args {
			if e.suppliesMutableRoot(a) {
				return false
			}
		}
		recvMutable := e.suppliesMutableRoot(v.Recv) ||
			(v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj != nil && e.roots[v.RecvPlace.Obj])
		if recvMutable {
			if v.IsMethodExprCall || v.Selection == nil {
				return false
			}
			fn, ok := v.Selection.Obj().(*types.Func)
			if !ok || fn == nil || syntaxutil.InterfaceReceiver(fn) || refconfine.AuditedSynchronization(e.audited, fn) {
				return false
			}
			if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
				_, ptrRecv := types.Unalias(sig.Recv().Type()).(*types.Pointer)
				if ptrRecv || typeHandsOutReachOrAddr(sig.Recv().Type()) {
					if e.methodWants == nil {
						return false
					}
					e.methodWants[syntaxutil.MethodFactKey(fn)] = true
				}
			}
		}
		return true
	case flowir.CallIIFE:
		return !e.valueTouchesAnyRoot(v)
	default:
		if e.suppliesMutableRoot(v.Callee) {
			return false
		}
		for _, a := range v.Args {
			if e.suppliesMutableRoot(a) {
				return false
			}
		}
		return true
	}
	return true
}

func (e *confinementEngine) checkEnclosingOp(op *flowir.Op) bool {
	st := e.encl
	origin := st.origin
	switch op.Kind {
	case flowir.OpAssign:
		if op.AssignKind == flowir.AssignRange {
			if len(op.Srcs) != 1 || op.Srcs[0] == nil || op.Srcs[0].Type == nil {
				return false
			}
			bindsRoot := false
			for _, dst := range op.Dsts {
				if dst.Obj != nil && e.roots[dst.Obj] {
					bindsRoot = true
					break
				}
			}
			switch types.Unalias(op.Srcs[0].Type).Underlying().(type) {
			case *types.Chan:
				if bindsRoot || e.suppliesMutableRoot(op.Srcs[0]) {
					return false
				}
			case *types.Signature:
				if bindsRoot || e.suppliesMutableRoot(op.Srcs[0]) || e.valueTouchesAnyRoot(op.Srcs[0]) {
					return false
				}
			}
		}
		sound := true
		op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
			dst.ForEachChildValue(func(cv *flowir.Value) bool {
				if !e.checkEnclosingValue(cv) {
					sound = false
					return false
				}
				return true
			})
			if !sound {
				return false
			}
			if dst.Obj != nil && e.roots[dst.Obj] {
				if !dst.IsBareVar() || !isDef || e.isOuterOrSigVar(dst.Obj) ||
					op.AssignKind == flowir.AssignCompound || op.AssignKind == flowir.AssignIncDec ||
					st.definedOnce[dst.Obj] {
					sound = false
					return false
				}
				st.definedOnce[dst.Obj] = true
				if op.AssignKind != flowir.AssignZeroDecl {
					if src == nil {
						sound = false
						return false
					}
					st.usedCarrierGlobal = false
					if origin != nil && origin.verifyLocalOrigins && typeHandsOutReachOrAddr(dst.Obj.Type()) {
						if !e.isCleanRootInitValue(src) {
							sound = false
							return false
						}
						if st.usedCarrierGlobal {
							if origin.carrierAliasRoots == nil {
								origin.carrierAliasRoots = map[types.Object]bool{}
							}
							origin.carrierAliasRoots[dst.Obj] = true
						}
					}
					isBareCarrierAlias := st.usedCarrierGlobal && src.Kind == flowir.ValPlace && len(src.Place.Projs) == 0
					if !isBareCarrierAlias && origin != nil && refconfine.TypeCarriesSignature(dst.Obj.Type()) {
						if !origin.nestedClosure && origin.checkCarryingValue != nil && !origin.checkCarryingValue(src) {
							sound = false
							return false
						}
					}
				}
			} else if dst.Root == flowir.RootTransient && e.suppliesMutableRoot(dst.Base) {
				sound = false
				return false
			}
			if _, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil && e.suppliesMutableRoot(keyVal) {
				sound = false
				return false
			}
			if src != nil && e.suppliesMutableRoot(src) {
				allowedDst := dst.IsBlank() ||
					(dst.IsBareVar() && syntaxutil.IsLocalVar(dst.Obj) && e.roots[dst.Obj] && isDef && !e.isOuterOrSigVar(dst.Obj))
				if !allowedDst {
					sound = false
					return false
				}
			}
			return true
		})
		if !sound {
			return false
		}
		for _, src := range op.Srcs {
			if !e.checkEnclosingValue(src) {
				return false
			}
		}
		return true

	case flowir.OpTypeSwitchBind:
		if !e.checkEnclosingValue(op.SwitchSrc) {
			return false
		}
		if op.SwitchDst != nil && e.roots[op.SwitchDst] {
			if st.definedOnce[op.SwitchDst] || op.SwitchSrc == nil {
				return false
			}
			st.definedOnce[op.SwitchDst] = true
			st.usedCarrierGlobal = false
			if origin != nil && origin.verifyLocalOrigins && typeHandsOutReachOrAddr(op.SwitchDst.Type()) {
				if !e.isCleanRootInitValue(op.SwitchSrc) {
					return false
				}
				if st.usedCarrierGlobal {
					if origin.carrierAliasRoots == nil {
						origin.carrierAliasRoots = map[types.Object]bool{}
					}
					origin.carrierAliasRoots[op.SwitchDst] = true
				}
			}
			if refconfine.TypeCarriesSignature(op.SwitchDst.Type()) {
				if op.SwitchSrc.Type == nil || !types.Identical(op.SwitchDst.Type(), op.SwitchSrc.Type) {
					return false
				}
				if !st.usedCarrierGlobal && origin != nil && !origin.nestedClosure &&
					origin.checkCarryingValue != nil && !origin.checkCarryingValue(op.SwitchSrc) {
					return false
				}
			}
		} else if op.SwitchDst != nil && op.SwitchSrc != nil && e.suppliesMutableRoot(op.SwitchSrc) &&
			(op.SwitchDst.Type() == nil ||
				typeHandsOutReachOrAddr(op.SwitchDst.Type()) ||
				refconfine.TypeCarriesSignature(op.SwitchDst.Type()) ||
				refconfine.TypeReachesSyncNoCopyByValue(op.SwitchDst.Type())) {
			return false
		}
		return true

	case flowir.OpChanSend:
		if (op.ChanPlace.Obj != nil && e.roots[op.ChanPlace.Obj]) ||
			e.suppliesMutableRoot(op.ChanVal) || e.suppliesMutableRoot(op.SendVal) {
			return false
		}
		return e.checkEnclosingValue(op.ChanVal) && e.checkEnclosingValue(op.SendVal)

	case flowir.OpReturn:
		for _, resVal := range op.Results {
			if !e.checkEnclosingValue(resVal) {
				return false
			}
			m := map[*types.Var]bool{}
			e.collectValMutableRoots(resVal, m)
			for r := range m {
				if _, isParam := e.rootBody.ParamIndex[r]; !isParam {
					return false
				}
			}
		}
		return true

	case flowir.OpDefer:
		return e.checkEnclosingValue(op.Call)

	case flowir.OpGo:
		return !e.valueTouchesAnyRoot(op.Call)

	case flowir.OpExpr:
		return e.checkEnclosingValue(op.Expr)
	}
	return true
}
