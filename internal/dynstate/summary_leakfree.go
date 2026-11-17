package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func boundValueLeakFreeJudged(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	returns *bool,
	methodWants map[syntaxutil.FuncKey]bool,
	fieldWants map[syntaxutil.FieldPosKey]bool,
	elemWants map[syntaxutil.ElemParamUse]bool,
) bool {
	return boundValueJudged(audited, p, fc, roots, body, wants, returns, methodWants, fieldWants, elemWants, false, false)
}

func boundValueClosureEnvLeakFreeJudged(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
) bool {
	return boundValueJudged(audited, p, fc, roots, body, wants, nil, methodWants, nil, nil, false, true)
}

func boundValueRetentionFreeJudged(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
) bool {
	return boundValueJudged(audited, p, fc, roots, body, wants, nil, methodWants, nil, nil, true, false)
}

type rootConfinementConfig struct {
	audited              bool
	p                    *packages.Package
	fc                   *pkgFlowCache
	roots                map[types.Object]bool
	body                 ast.Node
	wants                map[syntaxutil.ParamKey]bool
	returns              *bool
	methodWants          map[syntaxutil.FuncKey]bool
	fieldWants           map[syntaxutil.FieldPosKey]bool
	elemWants            map[syntaxutil.ElemParamUse]bool
	tolerateRootedStores bool
	allowCapturedClosure bool
}

func confineFlowRoots(cfg rootConfinementConfig) bool {
	if cfg.p == nil || cfg.p.TypesInfo == nil || cfg.body == nil || len(cfg.roots) == 0 {
		return false
	}
	for r := range cfg.roots {
		if r == nil || refconfine.TypeReachesSyncNoCopyByValue(r.Type()) {
			return false
		}
	}
	lowered := cfg.fc.body(cfg.p, cfg.body)
	if lowered == nil {
		return false
	}
	eng := &confinementEngine{
		audited:              cfg.audited,
		p:                    cfg.p,
		fc:                   cfg.fc,
		rootBody:             lowered,
		roots:                cfg.roots,
		tainted:              map[types.Object]bool{},
		tolerateRootedStores: cfg.tolerateRootedStores,
		allowCapturedClosure: cfg.allowCapturedClosure,
		wants:                cfg.wants,
		returns:              cfg.returns,
		methodWants:          cfg.methodWants,
		fieldWants:           cfg.fieldWants,
		elemWants:            cfg.elemWants,
	}
	return eng.run()
}

func boundValueJudged(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	returns *bool,
	methodWants map[syntaxutil.FuncKey]bool,
	fieldWants map[syntaxutil.FieldPosKey]bool,
	elemWants map[syntaxutil.ElemParamUse]bool,
	tolerateRootedStores bool,
	allowCapturedClosure bool,
) bool {
	return confineFlowRoots(rootConfinementConfig{
		audited:              audited,
		p:                    p,
		fc:                   fc,
		roots:                roots,
		body:                 body,
		wants:                wants,
		returns:              returns,
		methodWants:          methodWants,
		fieldWants:           fieldWants,
		elemWants:            elemWants,
		tolerateRootedStores: tolerateRootedStores,
		allowCapturedClosure: allowCapturedClosure,
	})
}

type valueEvalMode uint8

const (
	modeGeneral valueEvalMode = iota
	modeGovernedBindOrReturn
	modeBlankDiscard
)

type confinementEngine struct {
	audited              bool
	p                    *packages.Package
	fc                   *pkgFlowCache
	rootBody             *flowir.Body
	roots                map[types.Object]bool
	tainted              map[types.Object]bool
	externalReaching     map[types.Object]bool
	tolerateRootedStores bool
	allowCapturedClosure bool

	// Bound-value deferral sinks.
	wants       map[syntaxutil.ParamKey]bool
	returns     *bool
	methodWants map[syntaxutil.FuncKey]bool
	fieldWants  map[syntaxutil.FieldPosKey]bool
	elemWants   map[syntaxutil.ElemParamUse]bool

	// Receiver read-only mode configuration.
	recvMode                bool
	inGoSubtree             bool
	recvObj                 types.Object
	methods                 map[string]methodBodyEntry
	declared                map[string]bool
	declaredByName          map[string][]string
	bodyless                map[string]bool
	closedFields            map[*types.Var][]string
	admittedOnceDo          map[*ast.CallExpr]*onceDoAdmission
	activeOnceAdmission     *onceDoAdmission
	recordMethodChain       func(target string)
}

type onceDoAdmission struct {
	doBody             *flowir.Body
	candidates         map[*types.Var]bool
	confinedOnceFields map[*types.Var]bool
	confinedTainted    map[types.Object]bool
	fillFields         map[*types.Var]bool
	freshFillFields    map[*types.Var]bool
	freshTainted       map[types.Object]bool
	smuggledLocals     map[types.Object]bool
}

type methodBodyEntry struct {
	decl *ast.FuncDecl
	recv *ast.Ident
}

func (e *confinementEngine) run() bool {
	e.propagateTaint()
	if e.tolerateRootedStores {
		e.propagateExternalReaching()
	}
	return e.checkBody(e.rootBody, true, false)
}

func (e *confinementEngine) typeHandsOut(t types.Type) bool {
	return refconfine.CallResultHandsOut(t)
}

func (e *confinementEngine) isRootOrTainted(obj types.Object) bool {
	return obj != nil && (e.roots[obj] || e.tainted[obj])
}

func (e *confinementEngine) placeIsRooted(pl flowir.Place) bool {
	if pl.Obj != nil {
		return e.isRootOrTainted(pl.Obj)
	}
	if pl.Root == flowir.RootTransient && pl.Base != nil {
		return e.valueIsRooted(pl.Base) || (e.recvMode && e.isGovernableRecvCall(pl.Base))
	}
	return false
}

func (e *confinementEngine) valueIsRooted(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	switch v.Kind {
	case flowir.ValPlace:
		return e.placeIsRooted(v.Place)
	case flowir.ValAddrOf:
		return e.placeIsRooted(v.AddrPlace)
	case flowir.ValMethodVal:
		return e.valueIsRooted(v.Recv) || (v.HasRecvPlace && e.placeIsRooted(v.RecvPlace))
	case flowir.ValConvert:
		if !v.IsTypeAssert && v.Arg != nil && syntaxutil.IsFreshStringSliceCopy(v.Arg.Type, v.Type) {
			return false
		}
		return e.valueIsRooted(v.Arg)
	case flowir.ValChanRecv:
		return e.valueIsRooted(v.Chan)
	default:
		return false
	}
}

func (e *confinementEngine) isMethodVal(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	if v.Kind == flowir.ValMethodVal {
		return true
	}
	if v.Kind == flowir.ValConvert {
		return e.isMethodVal(v.Arg)
	}
	return false
}

// isGovernableRecvCall reports whether v is a method call on a receiver-rooted
// expression targeting an in-package sibling, unexported interface method, or
// closed-world interface field on recvObj.
func (e *confinementEngine) isGovernableRecvCall(v *flowir.Value) bool {
	if !e.recvMode || e.inGoSubtree || v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallMethod || v.IsMethodExprCall {
		return false
	}
	if !e.valueIsRooted(v.Recv) || v.CalleeFunc == nil || v.Selection == nil || v.CallAST == nil {
		return false
	}
	if v.CalleeFunc.Pkg() != e.p.Types {
		return false
	}
	sel := v.CalleeSelector()
	if sel == nil {
		return false
	}
	target := syntaxutil.RecvTypeNameOf(e.p, sel) + "." + v.CalleeFunc.Name()
	if _, sibling := e.methods[target]; sibling {
		return true
	}
	if _, ok := unexportedDispatchTargets(e.p, v.Selection, v.CalleeFunc, e.declaredByName, e.bodyless); ok {
		return true
	}
	if !e.bodyless[v.CalleeFunc.Name()] {
		if _, ok := closedFieldDispatchTargets(e.p.TypesInfo, e.recvObj, sel, v.CalleeFunc.Name(), e.closedFields, e.declared); ok {
			return true
		}
	}
	return false
}

func (e *confinementEngine) isSyncOnceCall(v *flowir.Value) bool {
	if e.inGoSubtree || v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallMethod || v.IsMethodExprCall {
		return false
	}
	if len(v.Args) != 1 || v.Args[0] == nil || v.Args[0].Kind != flowir.ValMakeClosure || v.Args[0].Closure == nil {
		return false
	}
	if e.recvMode {
		return v.CallAST != nil && e.admittedOnceDo[v.CallAST] != nil
	}
	if !refconfine.AuditedOnceDo(e.audited, v.CalleeFunc) {
		return false
	}
	if !v.HasRecvPlace || !refconfine.InPlaceSyncReceiver(e.p.TypesInfo, v.RecvPlace.Raw) {
		return false
	}
	if e.valueIsRooted(v.Recv) {
		return e.tolerateRootedStores
	}
	return true
}

func (e *confinementEngine) valueSuppliesRoot(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	if v.Type != nil &&
		!e.typeHandsOut(v.Type) &&
		!refconfine.TypeReachesSyncNoCopyByValue(v.Type) {
		return false
	}
	if e.valueIsRooted(v) {
		return true
	}
	switch v.Kind {
	case flowir.ValInvalid:
		return true
	case flowir.ValPlace:
		if v.Place.Root == flowir.RootTransient {
			return e.valueSuppliesRoot(v.Place.Base)
		}
		return false
	case flowir.ValAddrOf:
		if v.AddrPlace.Root == flowir.RootTransient {
			return e.valueSuppliesRoot(v.AddrPlace.Base)
		}
		return false
	case flowir.ValMethodVal:
		return e.valueSuppliesRoot(v.Recv)
	case flowir.ValChanRecv:
		return e.valueSuppliesRoot(v.Chan)
	case flowir.ValConvert:
		if !v.IsTypeAssert && v.Arg != nil {
			if syntaxutil.IsFreshStringSliceCopy(v.Arg.Type, v.Type) {
				return false
			}
			if !refconfine.CallResultHandsOut(v.Type) {
				return false
			}
		}
		return e.valueSuppliesRoot(v.Arg)
	case flowir.ValAllocFresh:
		switch v.AllocKind {
		case flowir.AllocMake, flowir.AllocBuiltinNewType:
			return false
		case flowir.AllocBuiltinNewExpr:
			return len(v.Args) > 0 && e.valueSuppliesRoot(v.Args[0])
		case flowir.AllocCompositeLit:
			for i := range v.CompositeElts {
				elt := &v.CompositeElts[i]
				if e.valueSuppliesRoot(elt.MapKey) || e.valueSuppliesRoot(elt.Value) {
					return true
				}
			}
			return false
		}
	case flowir.ValMakeClosure:
		if v.Closure != nil {
			for fv := range v.Closure.FreeVars {
				if e.isRootOrTainted(fv) {
					return true
				}
			}
		}
		return false
	case flowir.ValCall:
		if e.recvMode && e.isGovernableRecvCall(v) {
			return !refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type())
		}
		if v.CallKind == flowir.CallBuiltin {
			switch v.BuiltinName {
			case "append", "Add", "min", "max":
				for _, a := range v.Args {
					if e.valueSuppliesRoot(a) {
						return true
					}
				}
			case "Slice", "SliceData", "String", "StringData":
				if len(v.Args) > 0 && e.valueSuppliesRoot(v.Args[0]) {
					return true
				}
			}
			return false
		}
		// CallIIFE bodies run under checkBody(..., isTopBody=false), where
		// checkBody already rejects any rooted/tainted explicit or named
		// result of a CallResultHandsOut type.
	case flowir.ValCompositeExpr:
		for _, a := range v.Args {
			if e.valueSuppliesRoot(a) {
				return true
			}
		}
	}
	return false
}

func (e *confinementEngine) propagateTaint() {
	propagateFlowVarTaint(e.audited, e.fc, e.rootBody, e.tainted, flowVarTaintConfig{
		exclude:        e.roots,
		allowOuterVars: true,
		varTypeFilter:  e.typeHandsOut,
		iifeSlotFilter: e.typeHandsOut,
		valTaints:      e.valueSuppliesRoot,
		isSyncOnceCall: e.isSyncOnceCall,
	})
}

func (e *confinementEngine) isExternalSeedVar(v *types.Var) bool {
	if v == nil || v.IsField() || e.roots[v] {
		return false
	}
	if e.externalReaching[v] {
		return true
	}
	isPkgGlobal := v.Pkg() != nil && v.Parent() == v.Pkg().Scope()
	isOuter := v.Pos() < e.rootBody.BodyStart || v.Pos() > e.rootBody.BodyEnd
	if !isPkgGlobal && !isOuter {
		return false
	}
	return sharesMemOrSigOrDynamic(e.audited)(v.Type())
}

func (e *confinementEngine) valueReachesExternal(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	shares := sharesMemOrSigOrDynamic(e.audited)
	found := false
	var walk func(cur *flowir.Value)
	walk = func(cur *flowir.Value) {
		if found || cur == nil {
			return
		}
		switch cur.Kind {
		case flowir.ValPlace:
			if cur.Place.Obj != nil && !e.roots[cur.Place.Obj] && e.isExternalSeedVar(cur.Place.Obj) {
				found = true
				return
			}
		case flowir.ValAddrOf:
			if vObj := cur.AddrPlace.Obj; vObj != nil && !e.roots[vObj] {
				if e.externalReaching[vObj] || vObj.Pos() < e.rootBody.BodyStart || vObj.Pos() > e.rootBody.BodyEnd ||
					(vObj.Pkg() != nil && vObj.Parent() == vObj.Pkg().Scope()) {
					found = true
					return
				}
			}
		case flowir.ValMethodVal:
			if cur.AutoAddr && cur.HasRecvPlace && cur.RecvPlace.Obj != nil && !e.roots[cur.RecvPlace.Obj] {
				vObj := cur.RecvPlace.Obj
				if e.externalReaching[vObj] || vObj.Pos() < e.rootBody.BodyStart || vObj.Pos() > e.rootBody.BodyEnd ||
					(vObj.Pkg() != nil && vObj.Parent() == vObj.Pkg().Scope()) {
					found = true
					return
				}
			}
		case flowir.ValChanRecv:
			found = true
			return
		case flowir.ValAllocFresh:
			if cur.AllocKind == flowir.AllocMake || cur.AllocKind == flowir.AllocBuiltinNewType {
				return
			}
		case flowir.ValMakeClosure:
			if cur.Closure != nil {
				for fv := range cur.Closure.FreeVars {
					if e.isExternalSeedVar(fv) {
						found = true
						return
					}
				}
			}
			return
		case flowir.ValCall:
			ct := cur.Type
			if shares(ct) {
				switch cur.CallKind {
				case flowir.CallBuiltin:
					switch cur.BuiltinName {
					case "Sizeof", "Alignof", "Offsetof":
						return
					case "append":
						for _, a := range cur.Args {
							walk(a)
						}
						return
					default:
						found = true
						return
					}
				case flowir.CallPlain:
					if cur.IsMethodExprCall {
						found = true
						return
					}
					calleeName := ""
					if cur.CalleeFunc != nil {
						calleeName = cur.CalleeFunc.Name()
					}
					if !auditset.ValuePlaneClone(cur.CalleePkg, calleeName) {
						found = true
						return
					}
				default:
					found = true
					return
				}
			}
		}
		cur.ForEachChildValue(func(child *flowir.Value) bool {
			walk(child)
			return !found
		})
	}
	walk(v)
	return found
}

type flowVarTaintConfig struct {
	exclude                   map[types.Object]bool
	allowOuterVars            bool
	varTypeFilter             func(types.Type) bool
	iifeSlotFilter            func(types.Type) bool
	valTaints                 func(*flowir.Value) bool
	isSyncOnceCall            func(*flowir.Value) bool
	transientDstExempt        func(flowir.Place) bool
	reverseFlowAndCallTargets bool
	taintRootReturns          bool
	checkAssignDstType        bool
	checkCopyDstElem          bool
}

func propagateFlowVarTaint(
	audited bool,
	fc *pkgFlowCache,
	rootBody *flowir.Body,
	out map[types.Object]bool,
	cfg flowVarTaintConfig,
) {
	if rootBody == nil || out == nil || cfg.valTaints == nil {
		return
	}
	shares := sharesMemOrSigOrDynamic(audited)
	slotFilter := cfg.iifeSlotFilter
	if slotFilter == nil {
		slotFilter = shares
	}
	memAdj := fc.scopedBodyInteriorAliases(audited, rootBody, cfg.exclude)
	eligible := func(v *types.Var) bool {
		if v == nil || v.IsField() || cfg.exclude[v] {
			return false
		}
		if !cfg.allowOuterVars && isPkgOrOuterToBody(rootBody, v) {
			return false
		}
		if cfg.varTypeFilter != nil && !cfg.varTypeFilter(v.Type()) {
			return false
		}
		return true
	}
	markVar := func(v *types.Var) bool {
		if !eligible(v) {
			return false
		}
		changed := false
		if !out[v] {
			out[v] = true
			changed = true
		}
		for nb := range memAdj[v] {
			if nv, ok := nb.(*types.Var); ok && eligible(nv) && !out[nv] {
				out[nv] = true
				changed = true
			}
		}
		return changed
	}
	var markTargetVal func(a *flowir.Value) bool
	var markPlaceBase func(pl flowir.Place) bool
	if cfg.reverseFlowAndCallTargets {
		markTargetVal = func(a *flowir.Value) bool {
			return markEscapingValueVars(audited, a, markVar)
		}
		markPlaceBase = func(pl flowir.Place) bool {
			if pl.Obj != nil {
				return markVar(pl.Obj)
			}
			if pl.Root == flowir.RootTransient && pl.Base != nil &&
				(cfg.transientDstExempt == nil || !cfg.transientDstExempt(pl)) {
				return markTargetVal(pl.Base)
			}
			return false
		}
	} else {
		markPlaceBase = func(pl flowir.Place) bool {
			if pl.Obj != nil {
				return markVar(pl.Obj)
			}
			if pl.Root == flowir.RootTransient && pl.Base != nil &&
				(cfg.transientDstExempt == nil || !cfg.transientDstExempt(pl)) {
				return markTargetVal(pl.Base)
			}
			return false
		}
		markTargetVal = func(v *flowir.Value) bool {
			if v == nil {
				return false
			}
			didMark := false
			walkTransientTargetValues(v, func(cur *flowir.Value) {
				switch cur.Kind {
				case flowir.ValPlace:
					if markPlaceBase(cur.Place) {
						didMark = true
					}
				case flowir.ValAddrOf:
					if markPlaceBase(cur.AddrPlace) {
						didMark = true
					}
				}
			})
			return didMark
		}
	}
	isPureNonMutatingCall := func(v *flowir.Value) bool {
		switch v.CallKind {
		case flowir.CallBuiltin:
			switch v.BuiltinName {
			case "len", "cap", "delete", "clear", "copy", "append", "Sizeof", "Alignof", "Offsetof":
				return true
			}
		case flowir.CallPlain:
			if !v.IsMethodExprCall && v.CalleeFunc != nil {
				return auditset.ValuePlaneClone(v.CalleePkg, v.CalleeFunc.Name())
			}
		}
		return false
	}
	for changed := true; changed; {
		changed = false
		var visitBody func(b *flowir.Body)
		var visitVal func(v *flowir.Value)
		visitVal = func(v *flowir.Value) {
			if v == nil {
				return
			}
			if v.Kind == flowir.ValMakeClosure && v.Closure != nil {
				visitBody(v.Closure)
			}
			if v.Kind == flowir.ValCall {
				if v.CallKind == flowir.CallBuiltin && v.BuiltinName == "copy" && len(v.Args) == 2 {
					if v.Args[0] != nil && (!cfg.checkCopyDstElem || sliceCopyElemCarriesReachOrDynamic(audited, v.Args[0].Type)) &&
						cfg.valTaints(v.Args[1]) && markTargetVal(v.Args[0]) {
						changed = true
					}
				} else if v.CallKind == flowir.CallBuiltin && v.BuiltinName == "append" && len(v.Args) >= 2 {
					for _, elem := range v.Args[1:] {
						if cfg.valTaints(elem) {
							if markTargetVal(v.Args[0]) {
								changed = true
							}
							break
						}
					}
				} else if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
					v.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, _ int, pIdx int, ok bool, _ bool) bool {
						if ok && pIdx < len(v.IIFE.Params) && (slotType == nil || slotFilter(slotType)) {
							if pv := v.IIFE.Params[pIdx]; pv != nil && cfg.valTaints(arg) && markVar(pv) {
								changed = true
							}
						}
						return true
					})
					visitBody(v.IIFE)
				} else if cfg.isSyncOnceCall != nil && cfg.isSyncOnceCall(v) {
					visitBody(v.Args[0].Closure)
				} else if cfg.reverseFlowAndCallTargets && !isPureNonMutatingCall(v) {
					if markCallTargetVars(audited, v, markVar) {
						changed = true
					}
				}
			}
			v.ForEachChildValue(func(child *flowir.Value) bool {
				visitVal(child)
				return true
			})
		}
		visitBody = func(b *flowir.Body) {
			if b == nil {
				return
			}
			b.ForEachSyncOp(func(op *flowir.Op) bool {
				switch op.Kind {
				case flowir.OpAssign:
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
						if (!cfg.checkAssignDstType || dst.Type == nil || shares(dst.Type)) && src != nil && cfg.valTaints(src) {
							if markPlaceBase(dst) {
								changed = true
							}
						}
						if cfg.reverseFlowAndCallTargets {
							isExtDst := dst.Obj != nil && !cfg.exclude[dst.Obj] && isPkgOrOuterToBody(rootBody, dst.Obj)
							if !isExtDst && dst.Root == flowir.RootTransient && dst.Base != nil &&
								(cfg.transientDstExempt == nil || !cfg.transientDstExempt(dst)) && cfg.valTaints(dst.Base) {
								isExtDst = true
							}
							if isExtDst {
								if (dst.Type == nil || shares(dst.Type)) && markTargetVal(src) {
									changed = true
								}
								if _, keyVal, isMapWrite := dst.AsMapWrite(); isMapWrite && markTargetVal(keyVal) {
									changed = true
								}
							}
						}
						if mapPlace, keyVal, isMapWrite := dst.AsMapWrite(); isMapWrite && keyVal != nil && cfg.valTaints(keyVal) {
							if mapPlace.Obj != nil {
								if markVar(mapPlace.Obj) {
									changed = true
								}
							} else if mapPlace.Root == flowir.RootTransient && mapPlace.Base != nil &&
								(cfg.transientDstExempt == nil || !cfg.transientDstExempt(dst)) && markTargetVal(mapPlace.Base) {
								changed = true
							}
						}
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							visitVal(cv)
							return true
						})
						return true
					})
					for _, src := range op.Srcs {
						visitVal(src)
					}
				case flowir.OpTypeSwitchBind:
					if cfg.valTaints(op.SwitchSrc) && markVar(op.SwitchDst) {
						changed = true
					}
					visitVal(op.SwitchSrc)
				case flowir.OpChanSend:
					if cfg.valTaints(op.SendVal) {
						if cfg.reverseFlowAndCallTargets {
							if markVar(op.ChanPlace.Obj) {
								changed = true
							}
						} else if markPlaceBase(op.ChanPlace) {
							changed = true
						}
					}
					if cfg.reverseFlowAndCallTargets && markTargetVal(op.SendVal) {
						changed = true
					}
					visitVal(op.ChanVal)
					visitVal(op.SendVal)
				case flowir.OpReturn:
					if cfg.taintRootReturns && b == rootBody {
						for _, r := range op.Results {
							if markTargetVal(r) {
								changed = true
							}
						}
					}
					for _, r := range op.Results {
						visitVal(r)
					}
				case flowir.OpDefer:
					visitVal(op.Call)
				case flowir.OpGo:
					if cfg.reverseFlowAndCallTargets {
						if markCallTargetVars(audited, op.Call, markVar) {
							changed = true
						}
						visitVal(op.Call)
					}
				case flowir.OpExpr:
					visitVal(op.Expr)
				}
				return true
			})
		}
		visitBody(rootBody)
	}
}

func (e *confinementEngine) propagateExternalReaching() {
	e.externalReaching = map[types.Object]bool{}
	propagateFlowVarTaint(e.audited, e.fc, e.rootBody, e.externalReaching, flowVarTaintConfig{
		exclude:                   e.roots,
		valTaints:                 e.valueReachesExternal,
		isSyncOnceCall:            e.isSyncOnceCall,
		transientDstExempt:        e.placeIsRooted,
		reverseFlowAndCallTargets: true,
		taintRootReturns:          true,
		checkAssignDstType:        true,
		checkCopyDstElem:          true,
	})
}

func valueTouchesRootSet(v *flowir.Value, isRoot func(types.Object) bool, globalRoots []*types.Var) bool {
	if v == nil || isRoot == nil {
		return false
	}
	hit := false
	v.WalkValues(func(cur *flowir.Value) bool {
		if hit {
			return false
		}
		switch cur.Kind {
		case flowir.ValPlace:
			if cur.Place.Obj != nil && isRoot(cur.Place.Obj) {
				hit = true
				return false
			}
		case flowir.ValAddrOf:
			if cur.AddrPlace.Obj != nil && isRoot(cur.AddrPlace.Obj) {
				hit = true
				return false
			}
		case flowir.ValMethodVal:
			if cur.HasRecvPlace && cur.RecvPlace.Obj != nil && isRoot(cur.RecvPlace.Obj) {
				hit = true
				return false
			}
		case flowir.ValMakeClosure:
			if cur.Closure != nil {
				for fv := range cur.Closure.FreeVars {
					if isRoot(fv) {
						hit = true
						return false
					}
				}
				for _, gv := range globalRoots {
					if bodyMentionsVar(cur.Closure, gv) {
						hit = true
						return false
					}
				}
			}
		case flowir.ValCall:
			if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil {
				for fv := range cur.IIFE.FreeVars {
					if isRoot(fv) {
						hit = true
						return false
					}
				}
				for _, gv := range globalRoots {
					if bodyMentionsVar(cur.IIFE, gv) {
						hit = true
						return false
					}
				}
			}
		}
		return true
	})
	return hit
}

func (e *confinementEngine) valueTouchesAnyRoot(v *flowir.Value) bool {
	return valueTouchesRootSet(v, e.isRootOrTainted, nil)
}

func (e *confinementEngine) bodyTouchesAnyRoot(b *flowir.Body) bool {
	if b == nil {
		return false
	}
	for fv := range b.FreeVars {
		if e.isRootOrTainted(fv) {
			return true
		}
	}
	hit := false
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		switch op.Kind {
		case flowir.OpAssign:
			for i := range op.Dsts {
				if op.Dsts[i].Obj != nil && e.isRootOrTainted(op.Dsts[i].Obj) {
					hit = true
					return false
				}
				op.Dsts[i].ForEachChildValue(func(cv *flowir.Value) bool {
					if e.valueTouchesAnyRoot(cv) {
						hit = true
						return false
					}
					return true
				})
				if hit {
					return false
				}
			}
			for _, s := range op.Srcs {
				if e.valueTouchesAnyRoot(s) {
					hit = true
					return false
				}
			}
		case flowir.OpTypeSwitchBind:
			if (op.SwitchDst != nil && e.isRootOrTainted(op.SwitchDst)) || e.valueTouchesAnyRoot(op.SwitchSrc) {
				hit = true
			}
		case flowir.OpChanSend:
			if (op.ChanPlace.Obj != nil && e.isRootOrTainted(op.ChanPlace.Obj)) ||
				e.valueTouchesAnyRoot(op.ChanVal) || e.valueTouchesAnyRoot(op.SendVal) {
				hit = true
			}
		case flowir.OpReturn:
			for _, r := range op.Results {
				if e.valueTouchesAnyRoot(r) {
					hit = true
					break
				}
			}
		case flowir.OpGo, flowir.OpDefer:
			if e.valueTouchesAnyRoot(op.Call) {
				hit = true
			}
		case flowir.OpExpr:
			if e.valueTouchesAnyRoot(op.Expr) {
				hit = true
			}
		}
		return !hit
	})
	return hit
}

func (e *confinementEngine) placeMapKeysSmuggle(pl flowir.Place, allowEmptyCarrier bool) bool {
	for i := range pl.Projs {
		pr := &pl.Projs[i]
		if pr.Kind != flowir.ProjIndex || pr.Key == nil || !syntaxutil.TypeMayBeMap(pr.BaseType) {
			continue
		}
		var slotT types.Type
		if mt, isMap := syntaxutil.UnderlyingType(pr.BaseType).(*types.Map); isMap {
			slotT = mt.Key()
		} else {
			// Type parameter constrained by ~map[K]V: use key's static type.
			slotT = pr.Key.Type
		}
		kt := pr.Key.Type
		if slotT == nil || kt == nil ||
			refconfine.TypeReachesSyncNoCopyByValue(slotT) || refconfine.TypeReachesSyncNoCopyByValue(kt) {
			return true
		}
		if (refconfine.TypeMayCarryUnknownDynamic(e.audited, slotT) || refconfine.TypeCarriesSignature(slotT) ||
			refconfine.TypeMayCarryUnknownDynamic(e.audited, kt) || refconfine.TypeCarriesSignature(kt)) &&
			(!allowEmptyCarrier || !isCarrierEmptySlotValue(e.audited, slotT, pr.Key)) {
			return true
		}
		if (refconfine.TypeHandsOutMutableReach(slotT) || syntaxutil.ContainsUintptr(slotT) ||
			refconfine.TypeHandsOutMutableReach(kt) || syntaxutil.ContainsUintptr(kt)) &&
			(!e.tolerateRootedStores || e.valueReachesExternal(pr.Key)) {
			return true
		}
	}
	return false
}

func (e *confinementEngine) checkPlaceChildValues(pl flowir.Place) bool {
	ok := true
	if pl.Root == flowir.RootTransient && pl.Base != nil {
		if e.placeIsRooted(pl) {
			if !e.checkRootedReadOperand(pl.Base) {
				return false
			}
		} else if !e.checkValue(pl.Base, modeGeneral) {
			return false
		}
	}
	for i := range pl.Projs {
		pr := &pl.Projs[i]
		if pr.Key != nil && !e.checkValue(pr.Key, modeGeneral) {
			ok = false
			break
		}
		if pr.Low != nil && !e.checkValue(pr.Low, modeGeneral) {
			ok = false
			break
		}
		if pr.High != nil && !e.checkValue(pr.High, modeGeneral) {
			ok = false
			break
		}
		if pr.Max != nil && !e.checkValue(pr.Max, modeGeneral) {
			ok = false
			break
		}
	}
	return ok
}

func (e *confinementEngine) checkRootedReadOperand(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	switch v.Kind {
	case flowir.ValInvalid, flowir.ValMethodVal, flowir.ValAddrOf, flowir.ValChanRecv:
		return false
	case flowir.ValPlace:
		return e.checkPlaceChildValues(v.Place)
	case flowir.ValConvert:
		if v.Type == nil || v.Arg == nil || v.Arg.Type == nil ||
			syntaxutil.IsUnsafePointerType(v.Type) ||
			syntaxutil.IsUnsafePointerType(v.Arg.Type) ||
			refconfine.TypeReachesSyncNoCopyByValue(v.Type) ||
			refconfine.TypeReachesSyncNoCopyByValue(v.Arg.Type) {
			return false
		}
		if v.IsTypeAssert && refconfine.TypeCarriesSignature(v.Type) && !refconfine.TypeCarriesSignature(v.Arg.Type) {
			return false
		}
		return e.checkRootedReadOperand(v.Arg)
	case flowir.ValCall:
		if e.recvMode && e.isGovernableRecvCall(v) {
			return e.checkCall(v, true)
		}
		return false
	default:
		return false
	}
}

func (e *confinementEngine) isEscapingGlobalType(t types.Type) bool {
	return t == nil ||
		refconfine.CallResultHandsOut(t) ||
		refconfine.TypeReachesSyncNoCopyByValue(t)
}

func (e *confinementEngine) checkRootedStoreAllowed(op *flowir.Op, dst flowir.Place, isDef bool, src *flowir.Value, inOnceDo bool) bool {
	if e.tolerateRootedStores {
		switch op.AssignKind {
		case flowir.AssignIncDec:
			return !e.placeMapKeysSmuggle(dst, true)
		case flowir.AssignRange:
			return !isDef &&
				dst.Type != nil &&
				!refconfine.TypeMayCarryUnknownDynamic(e.audited, dst.Type) &&
				!refconfine.CallResultHandsOut(dst.Type) &&
				!refconfine.TypeReachesSyncNoCopyByValue(dst.Type) &&
				!e.placeMapKeysSmuggle(dst, true)
		case flowir.AssignPlain:
			if dst.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(dst.Type) {
				return false
			}
			if refconfine.TypeMayCarryUnknownDynamic(e.audited, dst.Type) || refconfine.TypeCarriesSignature(dst.Type) {
				if src == nil || !isCarrierEmptySlotValue(e.audited, dst.Type, src) {
					return false
				}
			}
			if refconfine.TypeHandsOutMutableReach(dst.Type) || syntaxutil.ContainsUintptr(dst.Type) {
				if src == nil || e.valueReachesExternal(src) {
					return false
				}
			}
			return !e.placeMapKeysSmuggle(dst, true)
		default:
			return dst.Type != nil &&
				!refconfine.TypeMayCarryUnknownDynamic(e.audited, dst.Type) &&
				!refconfine.CallResultHandsOut(dst.Type) &&
				!refconfine.TypeReachesSyncNoCopyByValue(dst.Type) &&
				!e.placeMapKeysSmuggle(dst, true)
		}
	}
	if e.recvMode && inOnceDo && op.TopLevelInBody && op.AssignKind != flowir.AssignRange {
		adm := e.activeOnceAdmission
		if adm == nil || !refconfine.FillSelection(e.p.TypesInfo, dst.Raw) {
			return false
		}
		if dst.Type == nil ||
			refconfine.TypeMayCarryUnknownDynamic(e.audited, dst.Type) ||
			refconfine.TypeCarriesSignature(dst.Type) ||
			refconfine.TypeReachesSyncNoCopyByValue(dst.Type) {
			return false
		}
		if e.placeMapKeysSmuggleInOnceFill(dst, adm) {
			return false
		}
		if !refconfine.TypeHandsOutMutableReach(dst.Type) && !syntaxutil.ContainsUintptr(dst.Type) {
			if fld, _ := receiverByValueOnceFillField(dst, e.recvObj); fld != nil {
				return adm.confinedOnceFields[fld]
			}
			return dst.Obj != nil && adm.confinedTainted[dst.Obj]
		}
		if op.AssignKind != flowir.AssignPlain && op.AssignKind != flowir.AssignMulti {
			return false
		}
		if src == nil || onceFillValueSmuggles(e.audited, adm.doBody, adm.smuggledLocals, adm.candidates, e.recvObj, src) {
			return false
		}
		if fld, whole := receiverByValueOnceFillField(dst, e.recvObj); fld != nil {
			if whole {
				return adm.fillFields[fld]
			}
			return adm.freshFillFields[fld]
		}
		if dst.Obj != nil && adm.freshTainted[dst.Obj] {
			return true
		}
		return false
	}
	return false
}

func (e *confinementEngine) placeMapKeysSmuggleInOnceFill(pl flowir.Place, adm *onceDoAdmission) bool {
	for i := range pl.Projs {
		pr := &pl.Projs[i]
		if pr.Kind != flowir.ProjIndex || pr.Key == nil || !syntaxutil.TypeMayBeMap(pr.BaseType) {
			continue
		}
		var slotT types.Type
		if mt, isMap := syntaxutil.UnderlyingType(pr.BaseType).(*types.Map); isMap {
			slotT = mt.Key()
		} else {
			slotT = pr.Key.Type
		}
		kt := pr.Key.Type
		if slotT == nil || kt == nil ||
			refconfine.TypeReachesSyncNoCopyByValue(slotT) || refconfine.TypeReachesSyncNoCopyByValue(kt) ||
			refconfine.TypeMayCarryUnknownDynamic(e.audited, slotT) || refconfine.TypeCarriesSignature(slotT) ||
			refconfine.TypeMayCarryUnknownDynamic(e.audited, kt) || refconfine.TypeCarriesSignature(kt) {
			return true
		}
		if (refconfine.TypeHandsOutMutableReach(slotT) || syntaxutil.ContainsUintptr(slotT) ||
			refconfine.TypeHandsOutMutableReach(kt) || syntaxutil.ContainsUintptr(kt)) &&
			(adm == nil || onceFillValueSmuggles(e.audited, adm.doBody, adm.smuggledLocals, adm.candidates, e.recvObj, pr.Key)) {
			return true
		}
	}
	return false
}

func (e *confinementEngine) checkBody(b *flowir.Body, isTopBody bool, inOnceDo bool) bool {
	if b == nil {
		return false
	}
	for _, resVar := range b.Results {
		if resVar == nil || !e.isRootOrTainted(resVar) {
			continue
		}
		synth := &flowir.Value{
			Kind: flowir.ValPlace,
			Type: resVar.Type(),
			Place: flowir.Place{
				Root: flowir.RootResult,
				Obj:  resVar,
				Type: resVar.Type(),
			},
		}
		if !e.checkReturnResult(synth, resVar.Type(), isTopBody) {
			return false
		}
	}
	for i := range b.Ops {
		if !e.checkOp(&b.Ops[i], b, isTopBody, inOnceDo) {
			return false
		}
	}
	return true
}

func (e *confinementEngine) checkOp(op *flowir.Op, b *flowir.Body, isTopBody bool, inOnceDo bool) bool {
	switch op.Kind {
	case flowir.OpGo:
		if op.Call == nil || op.Call.Kind != flowir.ValCall || op.Call.CallKind == flowir.CallBuiltin {
			return !e.valueTouchesAnyRoot(op.Call)
		}
		if op.Call.CallKind == flowir.CallIIFE && (op.Call.IIFE == nil || e.bodyTouchesAnyRoot(op.Call.IIFE)) {
			return false
		}
		if (op.Call.Recv != nil && e.valueIsRooted(op.Call.Recv)) ||
			(op.Call.AutoAddrRecv && op.Call.HasRecvPlace && e.placeIsRooted(op.Call.RecvPlace)) ||
			(op.Call.Callee != nil && e.valueIsRooted(op.Call.Callee)) {
			return false
		}
		prevAllow := e.allowCapturedClosure
		prevInGo := e.inGoSubtree
		e.allowCapturedClosure = false
		e.inGoSubtree = true
		defer func() {
			e.allowCapturedClosure = prevAllow
			e.inGoSubtree = prevInGo
		}()
		if op.Call.Recv != nil && !e.checkValue(op.Call.Recv, modeGeneral) {
			return false
		}
		if op.Call.Callee != nil && !e.checkValue(op.Call.Callee, modeGeneral) {
			return false
		}
		for _, arg := range op.Call.Args {
			if e.valueSuppliesRoot(arg) || !e.checkValue(arg, modeGeneral) {
				return false
			}
		}
		return true

	case flowir.OpDefer:
		return e.checkValue(op.Call, modeGeneral)

	case flowir.OpBranch:
		return true

	case flowir.OpExpr:
		return e.checkValue(op.Expr, modeGeneral)

	case flowir.OpChanSend:
		if e.placeIsRooted(op.ChanPlace) || e.valueIsRooted(op.ChanVal) {
			return false
		}
		if !e.checkValue(op.ChanVal, modeGeneral) {
			return false
		}
		return e.checkValue(op.SendVal, modeGeneral)

	case flowir.OpTypeSwitchBind:
		if e.valueIsRooted(op.SwitchSrc) || (e.recvMode && e.isGovernableRecvCall(op.SwitchSrc)) {
			if e.isMethodVal(op.SwitchSrc) ||
				op.SwitchSrc.Type == nil ||
				refconfine.TypeReachesSyncNoCopyByValue(op.SwitchSrc.Type) ||
				(op.SwitchDst != nil && (op.SwitchDst.Type() == nil ||
					refconfine.TypeReachesSyncNoCopyByValue(op.SwitchDst.Type()) ||
					(refconfine.TypeCarriesSignature(op.SwitchDst.Type()) && !refconfine.TypeCarriesSignature(op.SwitchSrc.Type)))) {
				return false
			}
			return e.checkValue(op.SwitchSrc, modeGovernedBindOrReturn)
		}
		return e.checkValue(op.SwitchSrc, modeGeneral)

	case flowir.OpReturn:
		for i, res := range op.Results {
			var slotType types.Type
			if b != nil && i < len(b.ResultTypes) {
				slotType = b.ResultTypes[i]
			}
			if !e.checkReturnResult(res, slotType, isTopBody) {
				return false
			}
		}
		return true

	case flowir.OpAssign:
		return e.checkAssignOp(op, isTopBody, inOnceDo)

	default:
		return false
	}
}

func (e *confinementEngine) checkReturnResult(res *flowir.Value, slotType types.Type, isTopBody bool) bool {
	if res == nil {
		return false
	}
	effType := res.Type
	if slotType != nil && refconfine.CallResultHandsOut(slotType) {
		effType = slotType
	}
	if !e.recvMode && !isTopBody && e.valueSuppliesRoot(res) && refconfine.CallResultHandsOut(effType) {
		return false
	}
	if e.valueIsRooted(res) || (e.recvMode && e.isGovernableRecvCall(res)) {
		if e.isMethodVal(res) || res.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(res.Type) {
			return false
		}
		if e.recvMode {
			if !isTopBody {
				return false
			}
			return e.checkValue(res, modeGovernedBindOrReturn)
		}
		if refconfine.TypeHandsOutMutableReach(effType) || syntaxutil.ContainsUintptr(effType) {
			if isTopBody && e.returns != nil {
				*e.returns = true
				return e.checkValue(res, modeGovernedBindOrReturn)
			}
			return false
		}
		if refconfine.TypeCarriesSignature(effType) {
			return false
		}
		return e.checkValue(res, modeGovernedBindOrReturn)
	}
	return e.checkValue(res, modeGeneral)
}

func (e *confinementEngine) dstAcceptsGovernedRoot(dst flowir.Place) bool {
	if dst.IsBlank() {
		return true
	}
	if !dst.IsBareVar() {
		return false
	}
	if dst.Root == flowir.RootPkgGlobal {
		return !e.isEscapingGlobalType(dst.Type)
	}
	return true
}

func (e *confinementEngine) checkAssignLHS(op *flowir.Op, dst flowir.Place, isDef bool, src *flowir.Value, inOnceDo bool) bool {
	if !e.checkPlaceChildValues(dst) {
		return false
	}
	if dst.IsBlank() {
		return true
	}
	if dst.IsBareVar() {
		if dst.Root == flowir.RootPkgGlobal {
			if src != nil && (e.valueIsRooted(src) || e.valueSuppliesRoot(src) || (e.recvMode && e.isGovernableRecvCall(src))) {
				if e.isEscapingGlobalType(dst.Type) {
					return false
				}
			}
			return true
		}
		if e.recvMode && dst.Obj == e.recvObj {
			return false
		}
		if e.isRootOrTainted(dst.Obj) {
			if dst.Obj.Pos() < e.rootBody.BodyStart || dst.Obj.Pos() > e.rootBody.BodyEnd {
				return false
			}
			if !e.recvMode && e.fieldWants != nil && refconfine.TypeCarriesSignature(dst.Obj.Type()) {
				originDefine := e.roots[dst.Obj] && isDef
				if (src == nil || !e.valueIsRooted(src)) && !originDefine {
					return false
				}
			}
		}
		return true
	}
	if e.placeIsRooted(dst) {
		return e.checkRootedStoreAllowed(op, dst, isDef, src, inOnceDo)
	}
	return true
}

func (e *confinementEngine) checkAssignOp(op *flowir.Op, isTopBody bool, inOnceDo bool) bool {
	if op.AssignKind == flowir.AssignRange {
		var rngSrc *flowir.Value
		if len(op.Srcs) == 1 {
			rngSrc = op.Srcs[0]
		}
		for i, dst := range op.Dsts {
			isDef := i < len(op.DstDefs) && op.DstDefs[i]
			if !e.checkAssignLHS(op, dst, isDef, rngSrc, inOnceDo) {
				return false
			}
		}
		if rngSrc != nil {
			if e.valueIsRooted(rngSrc) || (e.recvMode && e.isGovernableRecvCall(rngSrc)) {
				if rngSrc.Type == nil || e.isMethodVal(rngSrc) {
					return false
				}
				switch syntaxutil.UnderlyingType(rngSrc.Type).(type) {
				case *types.Chan, *types.Signature:
					return false
				}
				for _, dst := range op.Dsts {
					if !e.dstAcceptsGovernedRoot(dst) {
						return false
					}
					if !dst.IsBlank() && refconfine.TypeReachesSyncNoCopyByValue(dst.Type) {
						return false
					}
				}
				if !e.checkValue(rngSrc, modeGovernedBindOrReturn) {
					return false
				}
			} else if !e.checkValue(rngSrc, modeGeneral) {
				return false
			}
		}
		if op.RangeBody != nil {
			return e.checkBody(op.RangeBody, isTopBody, false)
		}
		return true
	}

	if op.AssignKind == flowir.AssignIncDec {
		if len(op.Dsts) != 1 {
			return false
		}
		return e.checkAssignLHS(op, op.Dsts[0], false, op.Srcs[0], inOnceDo)
	}

	if op.AssignKind == flowir.AssignCompound {
		if len(op.Dsts) != 1 || len(op.Srcs) != 1 {
			return false
		}
		dst := op.Dsts[0]
		var rhsOperand *flowir.Value
		if op.Srcs[0] != nil && op.Srcs[0].Kind == flowir.ValCompositeExpr && len(op.Srcs[0].Args) == 2 {
			rhsOperand = op.Srcs[0].Args[1]
		} else {
			rhsOperand = op.Srcs[0]
		}
		if !e.checkAssignLHS(op, dst, false, rhsOperand, inOnceDo) {
			return false
		}
		if !e.placeIsRooted(dst) && op.Srcs[0] != nil && op.Srcs[0].Kind == flowir.ValCompositeExpr && len(op.Srcs[0].Args) == 2 {
			if !e.checkValue(op.Srcs[0].Args[0], modeGeneral) {
				return false
			}
		}
		return rhsOperand == nil || e.checkValue(rhsOperand, modeGeneral)
	}

	if op.AssignKind == flowir.AssignZeroDecl {
		for i, dst := range op.Dsts {
			isDef := i < len(op.DstDefs) && op.DstDefs[i]
			if !e.checkAssignLHS(op, dst, isDef, nil, inOnceDo) {
				return false
			}
		}
		return true
	}

	if op.AssignKind == flowir.AssignMulti && len(op.Srcs) == 1 {
		src := op.Srcs[0]
		allGoverned := true
		for i, dst := range op.Dsts {
			isDef := i < len(op.DstDefs) && op.DstDefs[i]
			if !e.checkAssignLHS(op, dst, isDef, src, inOnceDo) {
				return false
			}
			accepted := e.dstAcceptsGovernedRoot(dst) || (e.recvMode && inOnceDo && op.TopLevelInBody && e.placeIsRooted(dst))
			if !accepted || (!dst.IsBlank() && refconfine.TypeReachesSyncNoCopyByValue(dst.Type)) {
				allGoverned = false
			}
		}
		mode := modeGeneral
		if allGoverned {
			mode = modeGovernedBindOrReturn
			if len(op.Dsts) > 0 && op.Dsts[0].IsBlank() {
				blankPrimary := true
				for _, dst := range op.Dsts[1:] {
					if !dst.IsBlank() && (dst.Type == nil || e.typeHandsOut(dst.Type) || refconfine.TypeReachesSyncNoCopyByValue(dst.Type)) {
						blankPrimary = false
						break
					}
				}
				if blankPrimary {
					mode = modeBlankDiscard
				}
			}
		}
		if (mode == modeGovernedBindOrReturn || mode == modeBlankDiscard) && e.valueIsRooted(src) {
			if e.isMethodVal(src) || refconfine.TypeReachesSyncNoCopyByValue(src.Type) {
				return false
			}
		}
		return e.checkValue(src, mode)
	}

	// AssignPlain (1:1 or N:N).
	ok := true
	op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
		if !e.checkAssignLHS(op, dst, isDef, src, inOnceDo) {
			ok = false
			return false
		}
		if src == nil {
			return true
		}
		mode := modeGeneral
		if dst.IsBlank() {
			mode = modeBlankDiscard
		} else if e.dstAcceptsGovernedRoot(dst) || (e.recvMode && inOnceDo && op.TopLevelInBody && e.placeIsRooted(dst)) {
			mode = modeGovernedBindOrReturn
		}
		if (mode == modeGovernedBindOrReturn || mode == modeBlankDiscard) && e.valueIsRooted(src) {
			if e.isMethodVal(src) || refconfine.TypeReachesSyncNoCopyByValue(src.Type) ||
				(!dst.IsBlank() && refconfine.TypeReachesSyncNoCopyByValue(dst.Type)) {
				ok = false
				return false
			}
		}
		if !e.checkValue(src, mode) {
			ok = false
			return false
		}
		return true
	})
	return ok
}

func (e *confinementEngine) checkValue(v *flowir.Value, mode valueEvalMode) bool {
	if v == nil {
		return true
	}
	switch v.Kind {
	case flowir.ValInvalid:
		return false

	case flowir.ValScalarLitOrConst:
		return true

	case flowir.ValPlace:
		if e.placeIsRooted(v.Place) {
			if mode == modeGovernedBindOrReturn || mode == modeBlankDiscard {
				return e.checkRootedReadOperand(v)
			}
			if v.Type == nil || refconfine.CallResultHandsOut(v.Type) {
				return false
			}
			return e.checkRootedReadOperand(v)
		}
		return e.checkPlaceChildValues(v.Place)

	case flowir.ValAddrOf:
		if e.placeIsRooted(v.AddrPlace) {
			return false
		}
		if !e.checkPlaceChildValues(v.AddrPlace) {
			return false
		}
		if v.Low != nil && !e.checkValue(v.Low, modeGeneral) {
			return false
		}
		if v.High != nil && !e.checkValue(v.High, modeGeneral) {
			return false
		}
		if v.Max != nil && !e.checkValue(v.Max, modeGeneral) {
			return false
		}
		return true

	case flowir.ValMethodVal:
		if e.valueIsRooted(v.Recv) || (v.HasRecvPlace && e.placeIsRooted(v.RecvPlace)) {
			return false
		}
		return e.checkValue(v.Recv, modeGeneral)

	case flowir.ValChanRecv:
		if e.valueIsRooted(v.Chan) {
			return false
		}
		return e.checkValue(v.Chan, modeGeneral)

	case flowir.ValConvert:
		if syntaxutil.IsUnsafePointerType(v.Type) &&
			(v.Arg == nil || v.Arg.Type == nil || syntaxutil.ContainsUintptr(v.Arg.Type) || e.valueSuppliesRoot(v.Arg)) {
			return false
		}
		if e.valueIsRooted(v.Arg) || (e.recvMode && e.isGovernableRecvCall(v.Arg)) {
			if e.isMethodVal(v.Arg) || v.Arg == nil || v.Arg.Type == nil || v.Type == nil ||
				syntaxutil.IsUnsafePointerType(v.Type) ||
				syntaxutil.IsUnsafePointerType(v.Arg.Type) ||
				refconfine.TypeReachesSyncNoCopyByValue(v.Arg.Type) ||
				refconfine.TypeReachesSyncNoCopyByValue(v.Type) {
				return false
			}
			if v.IsTypeAssert && mode != modeBlankDiscard &&
				refconfine.TypeCarriesSignature(v.Type) && !refconfine.TypeCarriesSignature(v.Arg.Type) {
				return false
			}
			if !refconfine.CallResultHandsOut(v.Type) {
				return e.checkRootedReadOperand(v.Arg)
			}
			if !v.IsTypeAssert && !refconfine.CallResultHandsOut(v.Arg.Type) {
				if _, isSlice := syntaxutil.UnderlyingType(v.Type).(*types.Slice); isSlice {
					return e.checkRootedReadOperand(v.Arg)
				}
			}
			if v.IsTypeAssert && (mode == modeGovernedBindOrReturn || mode == modeBlankDiscard) {
				return e.checkRootedReadOperand(v.Arg)
			}
			return false
		}
		return e.checkValue(v.Arg, mode)

	case flowir.ValCompare:
		for _, side := range []*flowir.Value{v.Left, v.Right} {
			if side == nil {
				continue
			}
			if e.valueIsRooted(side) {
				if e.isMethodVal(side) || side.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(side.Type) {
					return false
				}
				if !e.checkRootedReadOperand(side) {
					return false
				}
			} else if !e.checkValue(side, modeGeneral) {
				return false
			}
		}
		return true

	case flowir.ValAllocFresh:
		for i := range v.CompositeElts {
			elt := &v.CompositeElts[i]
			if elt.MapKey != nil && !e.checkValue(elt.MapKey, modeGeneral) {
				return false
			}
			if elt.Index != nil && !e.checkValue(elt.Index, modeGeneral) {
				return false
			}
			if elt.Value != nil && !e.checkValue(elt.Value, modeGeneral) {
				return false
			}
		}
		for _, a := range v.Args {
			if !e.checkValue(a, modeGeneral) {
				return false
			}
		}
		return true

	case flowir.ValMakeClosure:
		if v.Closure == nil {
			return false
		}
		captured := map[types.Object]bool{}
		for fv := range v.Closure.FreeVars {
			if e.isRootOrTainted(fv) {
				captured[fv] = true
			}
		}
		if len(captured) == 0 {
			return true
		}
		if !e.allowCapturedClosure {
			return false
		}
		subEng := &confinementEngine{
			audited:              e.audited,
			p:                    e.p,
			fc:                   e.fc,
			rootBody:             v.Closure,
			roots:                captured,
			tainted:              map[types.Object]bool{},
			tolerateRootedStores: e.tolerateRootedStores,
			allowCapturedClosure: true,
			wants:                e.wants,
			methodWants:          e.methodWants,
			fieldWants:           e.fieldWants,
			elemWants:            e.elemWants,
		}
		return subEng.run()

	case flowir.ValCall:
		return e.checkCall(v, mode == modeGovernedBindOrReturn || mode == modeBlankDiscard)

	case flowir.ValCompositeExpr:
		for _, a := range v.Args {
			if !e.checkValue(a, modeGeneral) {
				return false
			}
		}
		return true

	default:
		return false
	}
}

func (e *confinementEngine) checkCall(v *flowir.Value, governed bool) bool {
	switch v.CallKind {
	case flowir.CallBuiltin:
		if v.BuiltinName == "StringData" && len(v.Args) > 0 && (e.valueIsRooted(v.Args[0]) || e.valueSuppliesRoot(v.Args[0])) {
			return false
		}
		switch v.BuiltinName {
		case "Sizeof", "Alignof", "Offsetof":
			return true
		case "len", "cap":
			for _, arg := range v.Args {
				if e.valueIsRooted(arg) {
					if e.isMethodVal(arg) || !e.checkRootedReadOperand(arg) {
						return false
					}
				} else if !e.checkValue(arg, modeGeneral) {
					return false
				}
			}
			return true
		}
		for _, arg := range v.Args {
			if !e.checkValue(arg, modeGeneral) {
				return false
			}
		}
		return true

	case flowir.CallIIFE:
		if v.IIFE == nil {
			return false
		}
		if len(v.Args) == 1 && !v.Ellipsis && v.Args[0] != nil && v.Args[0].Type != nil {
			if tup, isTuple := types.Unalias(v.Args[0].Type).(*types.Tuple); isTuple && tup.Len() > 1 {
				arg := v.Args[0]
				allGoverned := true
				v.ForEachArgParam(func(_ *flowir.Value, slotType types.Type, _ int, pIdx int, ok bool, packedVariadic bool) bool {
					if !ok || packedVariadic || pIdx >= len(v.IIFE.Params) {
						allGoverned = false
						return false
					}
					pv := v.IIFE.Params[pIdx]
					isBlank := pv != nil && pv.Name() == "_"
					if !isBlank && (slotType == nil || refconfine.TypeReachesSyncNoCopyByValue(slotType)) {
						allGoverned = false
						return false
					}
					return true
				})
				if allGoverned && (e.valueIsRooted(arg) || (e.recvMode && e.isGovernableRecvCall(arg))) {
					if e.isMethodVal(arg) || refconfine.TypeReachesSyncNoCopyByValue(arg.Type) {
						return false
					}
					if !e.checkValue(arg, modeGovernedBindOrReturn) {
						return false
					}
				} else if !e.checkValue(arg, modeGeneral) {
					return false
				}
				return e.checkBody(v.IIFE, false, false)
			}
		}
		for i, arg := range v.Args {
			pIdx, ok := v.ParamIndexForArg(i)
			isPackedVariadic := v.CalleeSig != nil && v.CalleeSig.Variadic() && !v.Ellipsis && i >= v.CalleeSig.Params().Len()-1
			if ok && !isPackedVariadic && pIdx < len(v.IIFE.Params) {
				if e.valueIsRooted(arg) || (e.recvMode && e.isGovernableRecvCall(arg)) {
					if e.isMethodVal(arg) || arg.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(arg.Type) {
						return false
					}
					if !e.checkValue(arg, modeGovernedBindOrReturn) {
						return false
					}
					continue
				}
			}
			if !e.checkValue(arg, modeGeneral) {
				return false
			}
		}
		return e.checkBody(v.IIFE, false, false)

	case flowir.CallMethod:
		if e.isSyncOnceCall(v) {
			if e.valueIsRooted(v.Recv) {
				if !e.checkRootedReadOperand(v.Recv) {
					return false
				}
			} else if !e.checkValue(v.Recv, modeGeneral) {
				return false
			}
			prevAdm := e.activeOnceAdmission
			if e.recvMode && v.CallAST != nil {
				e.activeOnceAdmission = e.admittedOnceDo[v.CallAST]
			}
			defer func() { e.activeOnceAdmission = prevAdm }()
			return e.checkBody(v.Args[0].Closure, false, e.recvMode && e.activeOnceAdmission != nil)
		}
		if e.valueIsRooted(v.Recv) {
			if e.inGoSubtree || v.IsMethodExprCall || !e.checkRootedReadOperand(v.Recv) {
				return false
			}
			if refconfine.AuditedSynchronization(e.audited, v.CalleeFunc) {
				if !v.HasRecvPlace || !refconfine.InPlaceSyncReceiver(e.p.TypesInfo, v.RecvPlace.Raw) {
					return false
				}
				return e.checkCallArgs(v)
			}
			if e.recvMode {
				if v.CalleeFunc == nil || v.Selection == nil || v.CallAST == nil {
					return false
				}
				if v.CalleeFunc.Pkg() != e.p.Types {
					if e.methodWants == nil || v.CalleeFunc.Pkg() == nil ||
						v.CalleeFunc.Pkg().Path() == "sync" || syntaxutil.InterfaceReceiver(v.CalleeFunc) ||
						!refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type()) {
						return false
					}
					e.methodWants[syntaxutil.MethodFactKey(v.CalleeFunc)] = true
					return e.checkCallArgs(v)
				}
				sel := v.CalleeSelector()
				if sel == nil {
					return false
				}
				target := syntaxutil.RecvTypeNameOf(e.p, sel) + "." + v.CalleeFunc.Name()
				if _, sibling := e.methods[target]; sibling {
					if e.recordMethodChain != nil {
						e.recordMethodChain(target)
					}
					if !refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type()) && !governed {
						return false
					}
				} else {
					targets, ok := unexportedDispatchTargets(e.p, v.Selection, v.CalleeFunc, e.declaredByName, e.bodyless)
					if !ok && !e.bodyless[v.CalleeFunc.Name()] {
						targets, ok = closedFieldDispatchTargets(e.p.TypesInfo, e.recvObj, sel, v.CalleeFunc.Name(), e.closedFields, e.declared)
					}
					if !ok {
						return false
					}
					if e.recordMethodChain != nil {
						for _, t := range targets {
							e.recordMethodChain(t)
						}
					}
					if !refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type()) && !governed {
						return false
					}
				}
				return e.checkCallArgs(v)
			}
			if e.methodWants == nil || v.CalleeFunc == nil || v.CalleeFunc.Pkg() == nil ||
				v.CalleeFunc.Pkg().Path() == "sync" || syntaxutil.InterfaceReceiver(v.CalleeFunc) ||
				v.Selection == nil || !refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type()) {
				return false
			}
			e.methodWants[syntaxutil.MethodFactKey(v.CalleeFunc)] = true
			return e.checkCallArgs(v)
		}
		if !e.checkValue(v.Recv, modeGeneral) {
			return false
		}
		return e.checkCallArgs(v)

	case flowir.CallPlain:
		return e.checkCallArgs(v)

	case flowir.CallIndirect:
		if e.valueIsRooted(v.Callee) {
			if e.recvMode || e.isMethodVal(v.Callee) || e.typeHandsOut(v.Type) {
				return false
			}
			if !e.checkRootedReadOperand(v.Callee) {
				return false
			}
		} else if !e.checkValue(v.Callee, modeGeneral) {
			return false
		}
		return e.checkCallArgs(v)

	default:
		return false
	}
}

func (e *confinementEngine) checkCallArgs(v *flowir.Value) bool {
	var checkedUnrooted *flowir.Value
	okAll := true
	v.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, _ int, pIdx int, hasParam bool, packedVariadic bool) bool {
		paramType := v.FormalParamSlotType(pIdx, packedVariadic)
		if !e.valueIsRooted(arg) {
			if arg != checkedUnrooted {
				checkedUnrooted = arg
				if !e.checkValue(arg, modeGeneral) {
					okAll = false
					return false
				}
			}
			return true
		}
		if slotType == nil || e.isMethodVal(arg) ||
			refconfine.TypeReachesSyncNoCopyByValue(slotType) ||
			(paramType != nil && refconfine.TypeReachesSyncNoCopyByValue(paramType)) {
			okAll = false
			return false
		}
		handsOutSlot := refconfine.CallResultHandsOut(slotType)
		if !handsOutSlot {
			if !e.checkRootedReadOperand(arg) {
				okAll = false
				return false
			}
			return true
		}
		if e.inGoSubtree {
			okAll = false
			return false
		}
		deferred := false
		if v.CallKind == flowir.CallPlain && e.wants != nil && v.CalleeFunc != nil && v.CalleeSig != nil && v.CalleeSig.Recv() == nil &&
			(!e.recvMode || (!refconfine.TypeCarriesSignature(slotType) && (paramType == nil || !refconfine.TypeCarriesSignature(paramType)))) {
			if hasParam {
				e.wants[syntaxutil.ParamKey{
					Func:  syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Name()},
					Index: pIdx,
				}] = true
				deferred = true
			}
		}
		if !deferred && v.CallKind == flowir.CallIndirect && e.fieldWants != nil &&
			v.Callee != nil && v.Callee.Kind == flowir.ValPlace && len(v.Callee.Place.Projs) > 0 {
			last := v.Callee.Place.Projs[len(v.Callee.Place.Projs)-1]
			prefix := v.Callee.Place
			prefix.Projs = v.Callee.Place.Projs[:len(v.Callee.Place.Projs)-1]
			if last.Kind == flowir.ProjField && last.Field != nil && e.placeIsRooted(prefix) {
				if hasParam {
					e.fieldWants[syntaxutil.FieldPosKey{Field: last.Field.Name(), Index: pIdx}] = true
					deferred = true
				}
			}
		}
		if !deferred && v.CallKind == flowir.CallIndirect && e.elemWants != nil &&
			v.Callee != nil && v.Callee.Kind == flowir.ValPlace &&
			v.Callee.Place.Root == flowir.RootPkgGlobal && v.Callee.Place.Obj != nil &&
			len(v.Callee.Place.Projs) == 1 && v.Callee.Place.Projs[0].Kind == flowir.ProjIndex &&
			refconfine.TypeMayCarryUnknownDynamic(e.audited, v.Callee.Place.Obj.Type()) {
			if hasParam {
				e.elemWants[syntaxutil.ElemParamUse{
					Owner: syntaxutil.DynamicVarKey(v.Callee.Place.Obj),
					Index: pIdx,
				}] = true
				deferred = true
			}
		}
		if !deferred {
			okAll = false
			return false
		}
		if !e.checkRootedReadOperand(arg) {
			okAll = false
			return false
		}
		return true
	})
	return okAll
}

type packageConfinementSummary struct {
	readOnly          map[string]bool
	condReadOnly      map[string]bool
	readOnlyDeps      map[string]map[syntaxutil.FuncKey]bool
	readOnlyParamDeps map[string]map[syntaxutil.ParamKey]bool
	retentionMethods  map[string]bool
	paramLeakFree     map[syntaxutil.ParamKey]bool
	condParam         map[syntaxutil.ParamKey]bool
	paramDeps         map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool
	paramMethodDeps   map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool
	paramRetention    map[syntaxutil.ParamKey]bool
	paramRetDeps      map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool
}

func (c *packageConfinementSummary) classifyParam(ownPath string, pk syntaxutil.ParamKey) (provenLocal, conditional bool) {
	if c == nil || !pk.Valid() {
		return false, false
	}
	if pk.Func.Pkg != ownPath {
		return false, true
	}
	if c.paramLeakFree[pk] {
		return true, false
	}
	if c.condParam[pk] {
		return false, true
	}
	return false, false
}

func (c *packageConfinementSummary) classifyMethod(ownPath string, mk syntaxutil.FuncKey) (provenLocal, conditional bool) {
	if c == nil || !mk.Valid() || mk.Pkg == "sync" {
		return false, false
	}
	if mk.Pkg != ownPath {
		return false, true
	}
	if c.readOnly[mk.Name] {
		return true, false
	}
	if c.condReadOnly[mk.Name] {
		return false, true
	}
	return false, false
}

func resolveLocalParamDeps(ownPath string, proven map[syntaxutil.ParamKey]bool, allWants map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool, satisfied func(syntaxutil.ParamKey) bool) map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool {
	conditional := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	deps := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	for key, wants := range allWants {
		crossPackage := false
		for want := range wants {
			if want.Func.Pkg != ownPath {
				crossPackage = true
				break
			}
		}
		if crossPackage {
			deps[key] = wants
		} else {
			conditional[key] = wants
		}
	}
	syntaxutil.SolveLeastFixedPoint(proven, conditional, satisfied)
	for key, needs := range conditional {
		if satisfied(key) {
			continue
		}
		edges := map[syntaxutil.ParamKey]bool{}
		for need := range needs {
			if !satisfied(need) {
				edges[need] = true
			}
		}
		if len(edges) > 0 {
			deps[key] = edges
		}
	}
	for key, wants := range deps {
		if satisfied(key) {
			delete(deps, key)
			continue
		}
		edges := map[syntaxutil.ParamKey]bool{}
		for need := range wants {
			if !satisfied(need) {
				edges[need] = true
			}
		}
		if len(edges) > 0 {
			deps[key] = edges
		} else {
			delete(deps, key)
		}
	}
	return deps
}

func receiverRetentionFreeMethods(audited bool, p *packages.Package, fc *pkgFlowCache, readOnlyLocal map[string]bool) map[string]bool {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	proven := map[string]bool{}
	pending := map[string]map[string]bool{}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name == nil || fd.Body == nil || len(fd.Recv.List) != 1 {
				continue
			}
			recvName := syntaxutil.RecvTypeName(fd)
			if recvName == "" {
				continue
			}
			key := recvName + "." + fd.Name.Name
			if readOnlyLocal[key] {
				proven[key] = true
				continue
			}
			var recvIdent *ast.Ident
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
				recvIdent = names[0]
			}
			if recvIdent == nil {
				if recvField := fd.Recv.List[0]; recvField != nil && refconfine.TypeReachesSyncNoCopyByValue(p.TypesInfo.TypeOf(recvField.Type)) {
					continue
				}
				proven[key] = true
				continue
			}
			recvObj := p.TypesInfo.Defs[recvIdent]
			if recvObj == nil {
				continue
			}
			wants := map[syntaxutil.ParamKey]bool{}
			methodWants := map[syntaxutil.FuncKey]bool{}
			if !boundValueRetentionFreeJudged(audited, p, fc, map[types.Object]bool{recvObj: true}, fd.Body, wants, methodWants) {
				continue
			}
			if len(wants) != 0 {
				continue
			}
			needs := map[string]bool{}
			sound := true
			for want := range methodWants {
				if want.Pkg != ownPath {
					sound = false
					break
				}
				if !readOnlyLocal[want.Name] {
					needs[want.Name] = true
				}
			}
			if !sound {
				continue
			}
			if len(needs) == 0 {
				proven[key] = true
				continue
			}
			pending[key] = needs
		}
	}
	syntaxutil.SolveLeastFixedPoint(proven, pending, func(need string) bool {
		return proven[need] || readOnlyLocal[need]
	})
	return proven
}

// onceFieldOfDo resolves a call of the shape `x.field.Do(f)` — Do on a
// by-value sync.Once field selected from some value — to that field,
// or nil for every other shape.
func onceFieldOfDo(audited bool, info *types.Info, call *ast.CallExpr) *types.Var {
	if len(call.Args) != 1 {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.MethodVal {
		return nil
	}
	fn, ok := selection.Obj().(*types.Func)
	if !ok || !refconfine.AuditedOnceDo(audited, fn) {
		return nil
	}
	fieldSel, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	fieldSelection, ok := info.Selections[fieldSel]
	if !ok || fieldSelection.Kind() != types.FieldVal || len(fieldSelection.Index()) != 1 {
		return nil
	}
	field, ok := fieldSelection.Obj().(*types.Var)
	if !ok {
		return nil
	}
	named, ok := types.Unalias(field.Type()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Once" {
		return nil
	}
	return field
}

func closedInterfaceFields(p *packages.Package, callIdx *refconfine.CallSiteIndex) map[*types.Var][]string {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil
	}
	info := p.TypesInfo
	candidateField := func(field *types.Var) bool {
		if field == nil || !field.IsField() || field.Exported() || field.Pkg() != p.Types {
			return false
		}
		_, isIface := types.Unalias(field.Type()).Underlying().(*types.Interface)
		return isIface
	}
	any := false
	for _, name := range p.Types.Scope().Names() {
		typeName, ok := p.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := typeName.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields() && !any; i++ {
			any = candidateField(st.Field(i))
		}
	}
	if !any {
		return nil
	}
	if callIdx == nil {
		callIdx = refconfine.BuildCallSiteIndex(p)
	}
	memberTypes := func(expr ast.Expr) ([]string, bool) {
		var members []string
		ok := callIdx.JudgeExpr(expr, func(t types.Type) (bool, bool) {
			if _, isIface := types.Unalias(t).Underlying().(*types.Interface); isIface {
				return false, false
			}
			concrete := types.Unalias(t)
			if ptr, ok := concrete.(*types.Pointer); ok {
				concrete = types.Unalias(ptr.Elem())
			}
			named, ok := concrete.(*types.Named)
			if !ok || named.Obj() == nil || named.Obj().Pkg() != p.Types {
				return true, false
			}
			members = append(members, named.Obj().Name())
			return true, true
		})
		return members, ok
	}
	fieldOf := func(structType types.Type, index int) *types.Var {
		if ptr, ok := types.Unalias(structType).(*types.Pointer); ok {
			structType = ptr.Elem()
		}
		st, ok := types.Unalias(structType).Underlying().(*types.Struct)
		if !ok || index < 0 || index >= st.NumFields() {
			return nil
		}
		if field := st.Field(index); candidateField(field) {
			return field
		}
		return nil
	}
	members := map[*types.Var][]string{}
	open := map[*types.Var]bool{}
	store := func(field *types.Var, value ast.Expr) {
		if !candidateField(field) || open[field] {
			return
		}
		more, ok := memberTypes(value)
		if !ok {
			open[field] = true
			delete(members, field)
			return
		}
		members[field] = append(members[field], more...)
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				t := info.TypeOf(n)
				if t == nil {
					return true
				}
				if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
					t = ptr.Elem()
				}
				for i, elt := range n.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if key, ok := ast.Unparen(kv.Key).(*ast.Ident); ok {
							if field, ok := info.Uses[key].(*types.Var); ok {
								store(field, kv.Value)
							}
						}
						continue
					}
					store(fieldOf(t, i), elt)
				}
			case *ast.AssignStmt:
				if len(n.Lhs) != len(n.Rhs) {
					for _, lhs := range n.Lhs {
						if sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr); ok {
							if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
								if field, ok := selection.Obj().(*types.Var); ok {
									open[field] = true
									delete(members, field)
								}
							}
						}
					}
					return true
				}
				for i, lhs := range n.Lhs {
					sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr)
					if !ok {
						continue
					}
					selection, ok := info.Selections[sel]
					if !ok || selection.Kind() != types.FieldVal {
						continue
					}
					if field, ok := selection.Obj().(*types.Var); ok {
						store(field, n.Rhs[i])
					}
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					if sel, ok := ast.Unparen(n.X).(*ast.SelectorExpr); ok {
						if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
							if field, ok := selection.Obj().(*types.Var); ok {
								open[field] = true
								delete(members, field)
							}
						}
					}
				}
			case *ast.CallExpr:
				tv, ok := info.Types[ast.Unparen(n.Fun)]
				if !ok || !tv.IsType() || len(n.Args) != 1 {
					return true
				}
				to := info.TypeOf(n)
				if to == nil {
					return true
				}
				if ptr, ok := types.Unalias(to).(*types.Pointer); ok {
					to = ptr.Elem()
				}
				st, ok := types.Unalias(to).Underlying().(*types.Struct)
				if !ok || types.Identical(info.TypeOf(n.Args[0]), to) {
					return true
				}
				for i := 0; i < st.NumFields(); i++ {
					if field := fieldOf(to, i); field != nil {
						open[field] = true
						delete(members, field)
					}
				}
			}
			return true
		})
	}
	closed := map[*types.Var][]string{}
	for field, names := range members {
		if open[field] || len(names) == 0 {
			continue
		}
		sort.Strings(names)
		closed[field] = slices.Compact(names)
	}
	return closed
}

func closedFieldDispatchTargets(info *types.Info, recvObj types.Object, sel *ast.SelectorExpr, name string, closed map[*types.Var][]string, declared map[string]bool) ([]string, bool) {
	fieldSel, ok := ast.Unparen(sel.X).(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	ident, ok := ast.Unparen(fieldSel.X).(*ast.Ident)
	if !ok || info.Uses[ident] != recvObj {
		return nil, false
	}
	selection, ok := info.Selections[fieldSel]
	if !ok || selection.Kind() != types.FieldVal || len(selection.Index()) != 1 {
		return nil, false
	}
	field, ok := selection.Obj().(*types.Var)
	if !ok {
		return nil, false
	}
	members, ok := closed[field]
	if !ok {
		return nil, false
	}
	targets := make([]string, 0, len(members))
	for _, member := range members {
		target := member + "." + name
		if !declared[target] {
			return nil, false
		}
		targets = append(targets, target)
	}
	return targets, true
}

func unexportedDispatchTargets(p *packages.Package, selection *types.Selection, fn *types.Func, declaredByName map[string][]string, bodyless map[string]bool) ([]string, bool) {
	if p.Types == nil || fn.Exported() || fn.Pkg() != p.Types || selection.Recv() == nil || bodyless[fn.Name()] {
		return nil, false
	}
	recv := types.Unalias(selection.Recv())
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = types.Unalias(ptr.Elem())
	}
	if _, ok := recv.Underlying().(*types.Interface); !ok {
		return nil, false
	}
	targets := append([]string(nil), declaredByName[fn.Name()]...)
	return targets, len(targets) > 0
}

func solvePackageConfinement(audited bool, p *packages.Package, fc *pkgFlowCache, callIdx *refconfine.CallSiteIndex) packageConfinementSummary {
	var out packageConfinementSummary
	if p == nil || p.TypesInfo == nil {
		return out
	}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}

	methods := map[string]methodBodyEntry{}
	bodyless := map[string]bool{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && fd.Recv != nil && fd.Name != nil && fd.Body == nil {
				bodyless[fd.Name.Name] = true
			}
			if !ok || fd.Recv == nil || fd.Name == nil || fd.Body == nil || len(fd.Recv.List) != 1 {
				continue
			}
			recvName := syntaxutil.RecvTypeName(fd)
			if recvName == "" {
				continue
			}
			var recvIdent *ast.Ident
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
				recvIdent = names[0]
			}
			methods[recvName+"."+fd.Name.Name] = methodBodyEntry{decl: fd, recv: recvIdent}
		}
	}

	disqualified := map[string]bool{}
	chains := map[string]map[string]bool{}
	mParamWants := map[string]map[syntaxutil.ParamKey]bool{}
	mForeignMethodWants := map[string]map[syntaxutil.FuncKey]bool{}

	if len(methods) > 0 {
		onceSites, fieldRefIdents, disqualifiedOnceFields, aliasedInitOnceFields := collectPackageOnceFieldUsage(audited, p, fc)
		declaredByName := map[string][]string{}
		declared := map[string]bool{}
		for key := range methods {
			declared[key] = true
			if dot := strings.LastIndex(key, "."); dot >= 0 {
				declaredByName[key[dot+1:]] = append(declaredByName[key[dot+1:]], key)
			}
		}
		closedFields := closedInterfaceFields(p, callIdx)
		for _, keys := range declaredByName {
			sort.Strings(keys)
		}
		for key, m := range methods {
			if m.recv == nil {
				if recvField := m.decl.Recv.List[0]; recvField != nil && refconfine.TypeReachesSyncNoCopyByValue(p.TypesInfo.TypeOf(recvField.Type)) {
					disqualified[key] = true
				}
				continue
			}
			recvObj := p.TypesInfo.Defs[m.recv]
			if recvObj == nil || refconfine.TypeReachesSyncNoCopyByValue(recvObj.Type()) {
				disqualified[key] = true
				continue
			}
			lowered := fc.funcBody(p, m.decl)
			if lowered == nil {
				disqualified[key] = true
				continue
			}
			admittedOnceDo := findAdmittedReceiverOnceDo(audited, p, fc, m.decl, lowered, recvObj, onceSites, fieldRefIdents, disqualifiedOnceFields, aliasedInitOnceFields)
			wants := map[syntaxutil.ParamKey]bool{}
			methodWants := map[syntaxutil.FuncKey]bool{}
			eng := &confinementEngine{
				audited:        audited,
				p:              p,
				fc:             fc,
				rootBody:       lowered,
				roots:          map[types.Object]bool{recvObj: true},
				tainted:        map[types.Object]bool{},
				wants:          wants,
				methodWants:    methodWants,
				recvMode:       true,
				recvObj:        recvObj,
				methods:        methods,
				declared:       declared,
				declaredByName: declaredByName,
				bodyless:       bodyless,
				closedFields:   closedFields,
				admittedOnceDo: admittedOnceDo,
				recordMethodChain: func(target string) {
					if chains[key] == nil {
						chains[key] = map[string]bool{}
					}
					chains[key][target] = true
				},
			}
			if !eng.run() {
				disqualified[key] = true
				continue
			}
			if len(wants) > 0 {
				mParamWants[key] = wants
			}
			if len(methodWants) > 0 {
				mForeignMethodWants[key] = methodWants
			}
		}
		syntaxutil.SolveReachFixedPoint(disqualified, chains, func(d string) bool { return disqualified[d] })
		for changed := true; changed; {
			changed = false
			for caller, targets := range chains {
				if disqualified[caller] {
					continue
				}
				for callee := range targets {
					if disqualified[callee] {
						continue
					}
					for pk := range mParamWants[callee] {
						if mParamWants[caller] == nil {
							mParamWants[caller] = map[syntaxutil.ParamKey]bool{}
						}
						if !mParamWants[caller][pk] {
							mParamWants[caller][pk] = true
							changed = true
						}
					}
					for fk := range mForeignMethodWants[callee] {
						if mForeignMethodWants[caller] == nil {
							mForeignMethodWants[caller] = map[syntaxutil.FuncKey]bool{}
						}
						if !mForeignMethodWants[caller][fk] {
							mForeignMethodWants[caller][fk] = true
							changed = true
						}
					}
				}
			}
		}
	}

	type retainCandidate struct {
		obj  types.Object
		body ast.Node
		key  syntaxutil.ParamKey
	}
	var retainInputs []retainCandidate
	paramProven := map[syntaxutil.ParamKey]bool{}
	pCandidate := map[syntaxutil.ParamKey]bool{}
	pParamWants := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	pMethodWants := map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool{}

	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil || fd.Type.Params == nil {
				continue
			}
			ownFunc := syntaxutil.FuncKey{Pkg: ownPath, Name: fd.Name.Name}
			index := 0
			for _, field := range fd.Type.Params.List {
				names := field.Names
				if len(names) == 0 {
					names = []*ast.Ident{nil}
				}
				for _, name := range names {
					idx := index
					index++
					key := syntaxutil.ParamKey{Func: ownFunc, Index: idx}
					if name == nil || name.Name == "_" {
						paramProven[key] = true
						continue
					}
					obj := p.TypesInfo.Defs[name]
					if obj == nil || (!refconfine.TypeHandsOutMutableReach(obj.Type()) && !syntaxutil.ContainsUintptr(obj.Type())) {
						continue
					}
					retainInputs = append(retainInputs, retainCandidate{obj: obj, body: fd.Body, key: key})
					wants := map[syntaxutil.ParamKey]bool{}
					methodWants := map[syntaxutil.FuncKey]bool{}
					if !boundValueLeakFreeJudged(audited, p, fc, map[types.Object]bool{obj: true}, fd.Body, wants, nil, methodWants, nil, nil) {
						continue
					}
					pCandidate[key] = true
					if len(wants) > 0 {
						pParamWants[key] = wants
					}
					if len(methodWants) > 0 {
						pMethodWants[key] = methodWants
					}
				}
			}
		}
	}

	readOnlyLocal := map[string]bool{}
	for key := range methods {
		if !disqualified[key] && len(mParamWants[key]) == 0 && len(mForeignMethodWants[key]) == 0 {
			readOnlyLocal[key] = true
		}
	}
	for key := range pCandidate {
		if len(pParamWants[key]) == 0 && len(pMethodWants[key]) == 0 {
			paramProven[key] = true
		}
	}

	// Solve intra-package (readOnlyLocal, paramProven) jointly to a single
	// least fixed point so mutual recursion across Param <-> Method refuses
	// while acyclic intra-package chains prove unconditionally at fact time.
	for changed := true; changed; {
		changed = false
		for key := range methods {
			if disqualified[key] || readOnlyLocal[key] || len(mForeignMethodWants[key]) > 0 {
				continue
			}
			ok := true
			for pk := range mParamWants[key] {
				if !paramProven[pk] {
					ok = false
					break
				}
			}
			if ok {
				readOnlyLocal[key] = true
				changed = true
			}
		}
		for key := range pCandidate {
			if paramProven[key] {
				continue
			}
			ok := true
			for pk := range pParamWants[key] {
				if !paramProven[pk] {
					ok = false
					break
				}
			}
			if ok {
				for mk := range pMethodWants[key] {
					if mk.Pkg != ownPath || !readOnlyLocal[mk.Name] {
						ok = false
						break
					}
				}
			}
			if ok {
				paramProven[key] = true
				changed = true
			}
		}
	}

	// Prune methods whose intra-package parameter prerequisites failed
	// outright (so dead intra-package method candidates emit no spurious
	// conditional edges), while retaining unsatisfied ParamDepEdges for
	// explain chain traversal.
	for changed := true; changed; {
		changed = false
		for key := range methods {
			if disqualified[key] || readOnlyLocal[key] {
				continue
			}
			for callee := range chains[key] {
				if disqualified[callee] {
					disqualified[key] = true
					changed = true
					break
				}
			}
			if disqualified[key] {
				continue
			}
			for pk := range mParamWants[key] {
				if pk.Func.Pkg == ownPath && !paramProven[pk] && !pCandidate[pk] {
					disqualified[key] = true
					changed = true
					break
				}
			}
		}
		for key := range pCandidate {
			if paramProven[key] {
				continue
			}
			for mk := range pMethodWants[key] {
				if mk.Pkg == ownPath {
					if _, exists := methods[mk.Name]; !exists || disqualified[mk.Name] {
						delete(pCandidate, key)
						changed = true
						break
					}
				}
			}
		}
	}

	readOnlyDeps := map[string]map[syntaxutil.FuncKey]bool{}
	readOnlyParamDeps := map[string]map[syntaxutil.ParamKey]bool{}
	for key := range methods {
		if disqualified[key] || readOnlyLocal[key] {
			continue
		}
		for fk := range mForeignMethodWants[key] {
			if readOnlyDeps[key] == nil {
				readOnlyDeps[key] = map[syntaxutil.FuncKey]bool{}
			}
			readOnlyDeps[key][fk] = true
		}
		for pk := range mParamWants[key] {
			if !paramProven[pk] {
				if readOnlyParamDeps[key] == nil {
					readOnlyParamDeps[key] = map[syntaxutil.ParamKey]bool{}
				}
				readOnlyParamDeps[key][pk] = true
			}
		}
	}

	paramDeps := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	paramMethodDeps := map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool{}
	for key := range pCandidate {
		if paramProven[key] {
			continue
		}
		for pk := range pParamWants[key] {
			if !paramProven[pk] {
				if paramDeps[key] == nil {
					paramDeps[key] = map[syntaxutil.ParamKey]bool{}
				}
				paramDeps[key][pk] = true
			}
		}
		for mk := range pMethodWants[key] {
			if mk.Pkg != ownPath || !readOnlyLocal[mk.Name] {
				if paramMethodDeps[key] == nil {
					paramMethodDeps[key] = map[syntaxutil.FuncKey]bool{}
				}
				paramMethodDeps[key][mk] = true
			}
		}
	}
	// Preserve unsatisfied intra-package parameter edges even when a same-package
	// method prerequisite failed, matching legacy explain chain behavior for
	// pure parameter-to-parameter chains.
	for _, rc := range retainInputs {
		if paramProven[rc.key] || pCandidate[rc.key] {
			continue
		}
		if len(pMethodWants[rc.key]) == 0 && len(pParamWants[rc.key]) > 0 {
			for pk := range pParamWants[rc.key] {
				if !paramProven[pk] {
					if paramDeps[rc.key] == nil {
						paramDeps[rc.key] = map[syntaxutil.ParamKey]bool{}
					}
					paramDeps[rc.key][pk] = true
				}
			}
		}
	}

	retentionMethods := receiverRetentionFreeMethods(audited, p, fc, readOnlyLocal)
	paramRetention := map[syntaxutil.ParamKey]bool{}
	allRetentionWants := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	for _, rc := range retainInputs {
		if paramProven[rc.key] {
			continue
		}
		wants := map[syntaxutil.ParamKey]bool{}
		methodWants := map[syntaxutil.FuncKey]bool{}
		if !boundValueRetentionFreeJudged(audited, p, fc, map[types.Object]bool{rc.obj: true}, rc.body, wants, methodWants) {
			continue
		}
		ok := true
		for want := range methodWants {
			if want.Pkg != ownPath || (!retentionMethods[want.Name] && !readOnlyLocal[want.Name]) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if len(wants) == 0 {
			paramRetention[rc.key] = true
			continue
		}
		allRetentionWants[rc.key] = wants
	}
	paramRetDeps := resolveLocalParamDeps(ownPath, paramRetention, allRetentionWants, func(need syntaxutil.ParamKey) bool {
		return paramRetention[need] || paramProven[need]
	})
	for key := range paramProven {
		delete(paramRetDeps, key)
	}

	condReadOnly := map[string]bool{}
	for k := range readOnlyLocal {
		condReadOnly[k] = true
	}
	condParam := map[syntaxutil.ParamKey]bool{}
	for k := range paramProven {
		condParam[k] = true
	}
	for changed := true; changed; {
		changed = false
		for key := range methods {
			if disqualified[key] || condReadOnly[key] {
				continue
			}
			ok := true
			for fk := range mForeignMethodWants[key] {
				if fk.Pkg == ownPath && !condReadOnly[fk.Name] {
					ok = false
					break
				}
			}
			if ok {
				for pk := range mParamWants[key] {
					if pk.Func.Pkg == ownPath && !condParam[pk] {
						ok = false
						break
					}
				}
			}
			if ok {
				condReadOnly[key] = true
				changed = true
			}
		}
		for key := range pCandidate {
			if condParam[key] {
				continue
			}
			ok := true
			for pk := range pParamWants[key] {
				if pk.Func.Pkg == ownPath && !condParam[pk] {
					ok = false
					break
				}
			}
			if ok {
				for mk := range pMethodWants[key] {
					if mk.Pkg == ownPath && !condReadOnly[mk.Name] {
						ok = false
						break
					}
				}
			}
			if ok {
				condParam[key] = true
				changed = true
			}
		}
	}

	out.readOnly = readOnlyLocal
	out.condReadOnly = condReadOnly
	out.readOnlyDeps = readOnlyDeps
	out.readOnlyParamDeps = readOnlyParamDeps
	out.retentionMethods = retentionMethods
	out.paramLeakFree = paramProven
	out.condParam = condParam
	out.paramDeps = paramDeps
	out.paramMethodDeps = paramMethodDeps
	out.paramRetention = paramRetention
	out.paramRetDeps = paramRetDeps
	return out
}

func markStructFieldsDisqualified(t types.Type, out map[*types.Var]bool) {
	seen := map[types.Type]bool{}
	var walk func(cur types.Type)
	walk = func(cur types.Type) {
		if cur == nil {
			return
		}
		u := types.Unalias(cur)
		if seen[u] {
			return
		}
		seen[u] = true
		st, ok := u.Underlying().(*types.Struct)
		if !ok {
			return
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			out[f] = true
			walk(f.Type())
		}
	}
	walk(t)
}

func collectPackageOnceFieldUsage(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
) (
	onceSites map[*types.Var]int,
	fieldRefIdents map[*types.Var][]*ast.Ident,
	disqualifiedOnceFields map[*types.Var]bool,
	aliasedInitOnceFields map[*types.Var]bool,
) {
	onceSites = map[*types.Var]int{}
	fieldRefIdents = map[*types.Var][]*ast.Ident{}
	disqualifiedOnceFields = map[*types.Var]bool{}
	aliasedInitOnceFields = map[*types.Var]bool{}
	zeroKeyIdents := map[*ast.Ident]bool{}
	pureInitKeyIdents := map[*ast.Ident]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if field := onceFieldOfDo(audited, p.TypesInfo, x); field != nil {
					onceSites[field]++
				}
				if tv, ok := p.TypesInfo.Types[ast.Unparen(x.Fun)]; ok && tv.IsType() && len(x.Args) == 1 {
					to := p.TypesInfo.TypeOf(x)
					from := p.TypesInfo.TypeOf(x.Args[0])
					if to != nil && from != nil && !types.Identical(from, to) {
						for _, convT := range []types.Type{to, from} {
							if ptr, isPtr := types.Unalias(convT).(*types.Pointer); isPtr {
								convT = ptr.Elem()
							}
							markStructFieldsDisqualified(convT, disqualifiedOnceFields)
							markStructFieldsDisqualified(convT, aliasedInitOnceFields)
						}
					}
				}
			case *ast.CompositeLit:
				ct := p.TypesInfo.TypeOf(x)
				if ct != nil {
					if ptr, isPtr := types.Unalias(ct).Underlying().(*types.Pointer); isPtr {
						ct = ptr.Elem()
					}
					if st, isSt := types.Unalias(ct).Underlying().(*types.Struct); isSt && len(x.Elts) > 0 {
						if _, keyed := x.Elts[0].(*ast.KeyValueExpr); keyed {
							for _, elt := range x.Elts {
								if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
									if keyID, isID := ast.Unparen(kv.Key).(*ast.Ident); isID {
										if fld, isVar := p.TypesInfo.Uses[keyID].(*types.Var); isVar && fld != nil && fld.IsField() {
											val := fc.exprValue(p, kv.Value)
											if isZeroFieldInitValue(fld.Type(), val) {
												zeroKeyIdents[keyID] = true
											} else {
												disqualifiedOnceFields[fld] = true
												markStructFieldsDisqualified(fld.Type(), disqualifiedOnceFields)
												if isPureFreshDataValueWith(val, nil) {
													pureInitKeyIdents[keyID] = true
												} else {
													aliasedInitOnceFields[fld] = true
													markStructFieldsDisqualified(fld.Type(), aliasedInitOnceFields)
												}
											}
										}
									}
								}
							}
						} else {
							for i, elt := range x.Elts {
								if i < st.NumFields() {
									fld := st.Field(i)
									val := fc.exprValue(p, elt)
									if !isZeroFieldInitValue(fld.Type(), val) {
										disqualifiedOnceFields[fld] = true
										markStructFieldsDisqualified(fld.Type(), disqualifiedOnceFields)
										if !isPureFreshDataValueWith(val, nil) {
											aliasedInitOnceFields[fld] = true
											markStructFieldsDisqualified(fld.Type(), aliasedInitOnceFields)
										}
									}
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && !zeroKeyIdents[id] && !pureInitKeyIdents[id] {
				if fld, isVar := p.TypesInfo.Uses[id].(*types.Var); isVar && fld != nil && fld.IsField() {
					fieldRefIdents[fld] = append(fieldRefIdents[fld], id)
				}
			}
			return true
		})
	}
	return onceSites, fieldRefIdents, disqualifiedOnceFields, aliasedInitOnceFields
}

func funcBodyHasGotoOutsideClosures(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	found := false
	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		if br, ok := n.(*ast.BranchStmt); ok && br.Tok == token.GOTO {
			found = true
			return false
		}
		return true
	}
	ast.Inspect(body, walk)
	return found
}

func identInPostDoAsyncSubtree(methodBody *ast.BlockStmt, afterPos token.Pos, target *ast.Ident) bool {
	if methodBody == nil || target == nil {
		return true
	}
	hit := false
	ast.Inspect(methodBody, func(n ast.Node) bool {
		if hit || n == nil {
			return false
		}
		if n.End() <= afterPos {
			return false
		}
		switch sub := n.(type) {
		case *ast.FuncLit:
			if target.Pos() >= sub.Pos() && target.Pos() <= sub.End() {
				hit = true
				return false
			}
		case *ast.GoStmt:
			if target.Pos() >= sub.Pos() && target.Pos() <= sub.End() {
				hit = true
				return false
			}
		}
		return true
	})
	return hit
}

func collectByValuePrivateStructFields(recvPtrType types.Type, pkg *types.Package) []*types.Var {
	ptr, ok := types.Unalias(recvPtrType).(*types.Pointer)
	if !ok || pkg == nil {
		return nil
	}
	var fields []*types.Var
	seen := map[types.Type]bool{}
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil {
			return
		}
		u := types.Unalias(t)
		if seen[u] {
			return
		}
		seen[u] = true
		st, ok := u.Underlying().(*types.Struct)
		if !ok {
			return
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f == nil || f.Exported() || f.Pkg() != pkg {
				continue
			}
			fields = append(fields, f)
			walk(f.Type())
		}
	}
	walk(ptr.Elem())
	return fields
}

func receiverByValueOnceFillField(dst flowir.Place, recvObj types.Object) (fld *types.Var, whole bool) {
	if dst.Obj == nil || dst.Obj != recvObj || len(dst.Projs) == 0 {
		return nil, false
	}
	start := 0
	if dst.Projs[0].Kind == flowir.ProjDeref {
		start = 1
	}
	if start >= len(dst.Projs) || dst.Projs[start].Kind != flowir.ProjField {
		return nil, false
	}
	var lastField *types.Var
	k := start
	for k < len(dst.Projs) {
		pr := &dst.Projs[k]
		if pr.Kind != flowir.ProjField || pr.Field == nil || pr.Field.Exported() || syntaxutil.SelectionCrossesEmbeddedPointer(pr.Selection) {
			break
		}
		if k > start && pr.Indirect {
			break
		}
		lastField = pr.Field
		k++
	}
	if lastField == nil {
		return nil, false
	}
	if k < len(dst.Projs) {
		if _, isByValStruct := types.Unalias(lastField.Type()).Underlying().(*types.Struct); isByValStruct {
			return nil, false
		}
	}
	return lastField, k == len(dst.Projs)
}

func isPkgOrOuterToBody(body *flowir.Body, v *types.Var) bool {
	if v == nil || v.IsField() {
		return false
	}
	if v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
		return true
	}
	if body == nil {
		return true
	}
	return v.Pos() < body.BodyStart || v.Pos() > body.BodyEnd
}

func isOnceExternalCarrierOrReachVar(audited bool, doBody *flowir.Body, recvObj types.Object, v *types.Var) bool {
	if v == nil || v.IsField() || v == recvObj {
		return false
	}
	if !isPkgOrOuterToBody(doBody, v) {
		return false
	}
	return sharesMemOrSigOrDynamic(audited)(v.Type())
}

func onceFillValueSmuggles(
	audited bool,
	doBody *flowir.Body,
	smuggledLocals map[types.Object]bool,
	admCandidates map[*types.Var]bool,
	recvObj types.Object,
	v *flowir.Value,
) bool {
	if v == nil {
		return true
	}
	found := false
	var walk func(cur *flowir.Value)
	var walkBody func(b *flowir.Body)
	walkBody = func(b *flowir.Body) {
		if found || b == nil {
			return
		}
		b.ForEachSyncOp(func(op *flowir.Op) bool {
			switch op.Kind {
			case flowir.OpAssign:
				for i := range op.Dsts {
					op.Dsts[i].ForEachChildValue(func(cv *flowir.Value) bool {
						walk(cv)
						return !found
					})
					if found {
						return false
					}
				}
				for _, s := range op.Srcs {
					walk(s)
					if found {
						return false
					}
				}
			case flowir.OpTypeSwitchBind:
				walk(op.SwitchSrc)
			case flowir.OpChanSend:
				walk(op.ChanVal)
				walk(op.SendVal)
			case flowir.OpReturn:
				for _, r := range op.Results {
					walk(r)
					if found {
						return false
					}
				}
			case flowir.OpDefer, flowir.OpGo:
				walk(op.Call)
			case flowir.OpExpr:
				walk(op.Expr)
			}
			return !found
		})
	}
	walk = func(cur *flowir.Value) {
		if found || cur == nil {
			return
		}
		if cur.Kind == flowir.ValInvalid || cur.Kind == flowir.ValChanRecv {
			found = true
			return
		}
		if cur.Type != nil && !sharesMemOrSigOrDynamic(audited)(cur.Type) {
			return
		}
		switch cur.Kind {
		case flowir.ValPlace:
			if vObj := cur.Place.Obj; vObj != nil {
				if vObj == recvObj {
					fld, _ := receiverByValueOnceFillField(cur.Place, recvObj)
					if fld == nil || !admCandidates[fld] {
						found = true
						return
					}
				} else if smuggledLocals[vObj] || isOnceExternalCarrierOrReachVar(audited, doBody, recvObj, vObj) {
					found = true
					return
				}
			}
		case flowir.ValAddrOf:
			if vObj := cur.AddrPlace.Obj; vObj != nil {
				if vObj == recvObj {
					fld, _ := receiverByValueOnceFillField(cur.AddrPlace, recvObj)
					if fld == nil || !admCandidates[fld] {
						found = true
						return
					}
				} else if smuggledLocals[vObj] || isPkgOrOuterToBody(doBody, vObj) {
					found = true
					return
				}
			}
		case flowir.ValMethodVal:
			found = true
			return
		case flowir.ValMakeClosure:
			if cur.Closure == nil {
				found = true
				return
			}
			for fv := range cur.Closure.FreeVars {
				if fv == recvObj || smuggledLocals[fv] || isOnceExternalCarrierOrReachVar(audited, doBody, recvObj, fv) {
					found = true
					return
				}
			}
			walkBody(cur.Closure)
			return
		case flowir.ValCall:
			switch {
			case cur.CallKind == flowir.CallIIFE && cur.IIFE != nil:
				for _, a := range cur.Args {
					walk(a)
					if found {
						return
					}
				}
				walkBody(cur.IIFE)
				return
			case cur.CallKind == flowir.CallBuiltin && (cur.BuiltinName == "Sizeof" || cur.BuiltinName == "Alignof" || cur.BuiltinName == "Offsetof"):
				return
			case cur.CallKind == flowir.CallBuiltin && cur.BuiltinName == "append":
				for _, a := range cur.Args {
					walk(a)
					if found {
						return
					}
				}
				return
			case cur.CallKind == flowir.CallPlain && !cur.IsMethodExprCall && cur.CalleeFunc != nil && auditset.ValuePlaneClone(cur.CalleePkg, cur.CalleeFunc.Name()):
				for _, a := range cur.Args {
					walk(a)
					if found {
						return
					}
				}
				return
			default:
				found = true
				return
			}
		}
		cur.ForEachChildValue(func(child *flowir.Value) bool {
			walk(child)
			return !found
		})
	}
	walk(v)
	return found
}

func sharesMemOrSigOrDynamic(audited bool) func(types.Type) bool {
	return func(t types.Type) bool {
		return t == nil ||
			refconfine.TypeHandsOutMutableReach(t) ||
			refconfine.TypeMayCarryUnknownDynamic(audited, t) ||
			refconfine.TypeCarriesSignature(t) ||
			syntaxutil.ContainsUintptr(t)
	}
}

func markEscapingAddrPlaceVars(audited bool, p flowir.Place, markObj func(*types.Var) bool) bool {
	if p.Obj != nil {
		return markObj(p.Obj)
	}
	if p.Root == flowir.RootTransient && p.Base != nil {
		return markEscapingValueVars(audited, p.Base, markObj)
	}
	return false
}

func markEscapingValueVars(audited bool, v *flowir.Value, markObj func(*types.Var) bool) bool {
	if v == nil || markObj == nil {
		return false
	}
	canCarry := sharesMemOrSigOrDynamic(audited)
	didMark := false
	var walk func(cur *flowir.Value)
	walk = func(cur *flowir.Value) {
		if cur == nil {
			return
		}
		if cur.Type != nil && !canCarry(cur.Type) {
			return
		}
		switch cur.Kind {
		case flowir.ValScalarLitOrConst, flowir.ValCompare:
			return
		case flowir.ValPlace:
			if cur.Place.Obj != nil {
				if cur.Place.Obj.Type() == nil || canCarry(cur.Place.Obj.Type()) {
					if markObj(cur.Place.Obj) {
						didMark = true
					}
				}
			} else if cur.Place.Root == flowir.RootTransient && cur.Place.Base != nil {
				walk(cur.Place.Base)
			}
		case flowir.ValAddrOf:
			if markEscapingAddrPlaceVars(audited, cur.AddrPlace, markObj) {
				didMark = true
			}
		case flowir.ValMethodVal:
			if cur.HasRecvPlace {
				if cur.AutoAddr || cur.RecvPlace.Obj == nil || cur.RecvPlace.Obj.Type() == nil || canCarry(cur.RecvPlace.Obj.Type()) {
					if markEscapingAddrPlaceVars(audited, cur.RecvPlace, markObj) {
						didMark = true
					}
				}
			}
			walk(cur.Recv)
		case flowir.ValAllocFresh:
			switch cur.AllocKind {
			case flowir.AllocMake, flowir.AllocBuiltinNewType:
				return
			case flowir.AllocBuiltinNewExpr:
				for _, a := range cur.Args {
					walk(a)
				}
			case flowir.AllocCompositeLit:
				for i := range cur.CompositeElts {
					elt := &cur.CompositeElts[i]
					walk(elt.MapKey)
					walk(elt.Value)
				}
			}
		case flowir.ValMakeClosure:
			if cur.Closure != nil {
				for fv := range cur.Closure.FreeVars {
					if markObj(fv) {
						didMark = true
					}
				}
			}
		case flowir.ValCall:
			if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil {
				for fv := range cur.IIFE.FreeVars {
					if markObj(fv) {
						didMark = true
					}
				}
				for _, a := range cur.Args {
					walk(a)
				}
				cur.IIFE.ForEachSyncOp(func(op *flowir.Op) bool {
					if op.Kind == flowir.OpReturn {
						for _, r := range op.Results {
							walk(r)
						}
					}
					return true
				})
				for _, rv := range cur.IIFE.Results {
					if rv != nil && (rv.Type() == nil || canCarry(rv.Type())) && markObj(rv) {
						didMark = true
					}
				}
				return
			}
			if cur.AutoAddrRecv && cur.HasRecvPlace && markEscapingAddrPlaceVars(audited, cur.RecvPlace, markObj) {
				didMark = true
			}
			walk(cur.Recv)
			walk(cur.Callee)
			for _, a := range cur.Args {
				walk(a)
			}
		case flowir.ValConvert:
			walk(cur.Arg)
		case flowir.ValChanRecv:
			walk(cur.Chan)
		default:
			cur.ForEachChildValue(func(ch *flowir.Value) bool {
				walk(ch)
				return true
			})
		}
	}
	walk(v)
	return didMark
}

func markCallTargetVars(audited bool, callVal *flowir.Value, markObj func(*types.Var) bool) bool {
	if callVal == nil || markObj == nil {
		return false
	}
	didMark := false
	if callVal.CallKind == flowir.CallIIFE && callVal.IIFE != nil {
		for fv := range callVal.IIFE.FreeVars {
			if markObj(fv) {
				didMark = true
			}
		}
	}
	if callVal.AutoAddrRecv && callVal.HasRecvPlace && markEscapingAddrPlaceVars(audited, callVal.RecvPlace, markObj) {
		didMark = true
	}
	if markEscapingValueVars(audited, callVal.Recv, markObj) {
		didMark = true
	}
	if markEscapingValueVars(audited, callVal.Callee, markObj) {
		didMark = true
	}
	for _, a := range callVal.Args {
		if markEscapingValueVars(audited, a, markObj) {
			didMark = true
		}
	}
	return didMark
}

func sliceCopyElemCarriesReachOrDynamic(audited bool, dstType types.Type) bool {
	if dstType == nil {
		return true
	}
	sl, ok := types.Unalias(dstType).Underlying().(*types.Slice)
	if !ok {
		return true
	}
	elemT := sl.Elem()
	return sharesMemOrSigOrDynamic(audited)(elemT)
}

func computeOnceFillSmuggledLocals(
	audited bool,
	fc *pkgFlowCache,
	doBody *flowir.Body,
	admCandidates map[*types.Var]bool,
	recvObj types.Object,
) map[types.Object]bool {
	smuggled := map[types.Object]bool{}
	var exclude map[types.Object]bool
	if recvObj != nil {
		exclude = map[types.Object]bool{recvObj: true}
	}
	propagateFlowVarTaint(audited, fc, doBody, smuggled, flowVarTaintConfig{
		exclude: exclude,
		valTaints: func(v *flowir.Value) bool {
			return onceFillValueSmuggles(audited, doBody, smuggled, admCandidates, recvObj, v)
		},
		reverseFlowAndCallTargets: true,
		checkAssignDstType:        true,
		checkCopyDstElem:          true,
	})
	return smuggled
}

func propagateReceiverFieldTaint(
	doBody *flowir.Body,
	recvObj types.Object,
	allowField map[*types.Var]bool,
) (map[types.Object]map[*types.Var]bool, func(*flowir.Value) map[*types.Var]bool) {
	tainted := map[types.Object]map[*types.Var]bool{}
	addTaint := func(obj types.Object, fld *types.Var) bool {
		if obj == nil || fld == nil {
			return false
		}
		if tainted[obj] == nil {
			tainted[obj] = map[*types.Var]bool{}
		}
		if !tainted[obj][fld] {
			tainted[obj][fld] = true
			return true
		}
		return false
	}
	valTaints := func(v *flowir.Value) map[*types.Var]bool {
		var out map[*types.Var]bool
		if v == nil {
			return nil
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			switch cur.Kind {
			case flowir.ValPlace:
				if fld, _ := receiverByValueOnceFillField(cur.Place, recvObj); fld != nil {
					if allowField == nil || allowField[fld] {
						if out == nil {
							out = map[*types.Var]bool{}
						}
						out[fld] = true
					}
				} else if cur.Place.Obj != nil {
					for f := range tainted[cur.Place.Obj] {
						if out == nil {
							out = map[*types.Var]bool{}
						}
						out[f] = true
					}
				}
			case flowir.ValAddrOf:
				if fld, _ := receiverByValueOnceFillField(cur.AddrPlace, recvObj); fld != nil {
					if allowField == nil || allowField[fld] {
						if out == nil {
							out = map[*types.Var]bool{}
						}
						out[fld] = true
					}
				} else if cur.AddrPlace.Obj != nil {
					for f := range tainted[cur.AddrPlace.Obj] {
						if out == nil {
							out = map[*types.Var]bool{}
						}
						out[f] = true
					}
				}
			}
			return true
		})
		return out
	}
	if doBody != nil {
		for changed := true; changed; {
			changed = false
			doBody.ForEachSyncOp(func(op *flowir.Op) bool {
				if op.Kind == flowir.OpAssign {
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
						if dst.Obj != nil && dst.Obj != recvObj {
							for fld := range valTaints(src) {
								if addTaint(dst.Obj, fld) {
									changed = true
								}
							}
						}
						return true
					})
				} else if op.Kind == flowir.OpTypeSwitchBind && op.SwitchDst != nil {
					for fld := range valTaints(op.SwitchSrc) {
						if addTaint(op.SwitchDst, fld) {
							changed = true
						}
					}
				}
				return true
			})
		}
	}
	return tainted, valTaints
}

func computeOnceDoFieldAdmissions(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	methodDecl *ast.FuncDecl,
	doCall *ast.CallExpr,
	doLit *ast.FuncLit,
	doBody *flowir.Body,
	recvObj types.Object,
	fieldRefIdents map[*types.Var][]*ast.Ident,
	disqualifiedOnceFields map[*types.Var]bool,
	aliasedInitOnceFields map[*types.Var]bool,
) *onceDoAdmission {
	adm := &onceDoAdmission{
		doBody:             doBody,
		candidates:         map[*types.Var]bool{},
		confinedOnceFields: map[*types.Var]bool{},
		confinedTainted:    map[types.Object]bool{},
		fillFields:         map[*types.Var]bool{},
		freshFillFields:    map[*types.Var]bool{},
		freshTainted:       map[types.Object]bool{},
	}
	if methodDecl == nil || methodDecl.Body == nil || doCall == nil || doLit == nil || doLit.Body == nil || funcBodyHasGotoOutsideClosures(methodDecl.Body) {
		adm.smuggledLocals = computeOnceFillSmuggledLocals(audited, fc, doBody, adm.candidates, recvObj)
		return adm
	}

	isConfinedToDoAndPost := func(fld *types.Var, disallow map[*types.Var]bool) bool {
		if disallow[fld] {
			return false
		}
		confinedRefs := true
		var checkRefs func(t types.Type, seen map[types.Type]bool)
		checkRefs = func(t types.Type, seen map[types.Type]bool) {
			if !confinedRefs || t == nil {
				return
			}
			u := types.Unalias(t)
			if seen[u] {
				return
			}
			seen[u] = true
			st, ok := u.Underlying().(*types.Struct)
			if !ok {
				return
			}
			for i := 0; i < st.NumFields(); i++ {
				sf := st.Field(i)
				if sf.Exported() || sf.Pkg() != p.Types || disallow[sf] {
					confinedRefs = false
					return
				}
				for _, id := range fieldRefIdents[sf] {
					inDo := id.Pos() >= doLit.Body.Pos() && id.Pos() <= doLit.Body.End()
					postDo := id.Pos() > doCall.End() && id.Pos() <= methodDecl.Body.End() && !identInPostDoAsyncSubtree(methodDecl.Body, doCall.End(), id)
					if !inDo && !postDo {
						confinedRefs = false
						return
					}
				}
				checkRefs(sf.Type(), seen)
			}
		}
		for _, id := range fieldRefIdents[fld] {
			inDo := id.Pos() >= doLit.Body.Pos() && id.Pos() <= doLit.Body.End()
			postDo := id.Pos() > doCall.End() && id.Pos() <= methodDecl.Body.End() && !identInPostDoAsyncSubtree(methodDecl.Body, doCall.End(), id)
			if !inDo && !postDo {
				return false
			}
		}
		checkRefs(fld.Type(), map[types.Type]bool{})
		return confinedRefs
	}

	candidates := adm.candidates
	for _, fld := range collectByValuePrivateStructFields(recvObj.Type(), p.Types) {
		ft := fld.Type()
		if refconfine.TypeMayCarryUnknownDynamic(audited, ft) ||
			refconfine.TypeCarriesSignature(ft) ||
			refconfine.TypeReachesSyncNoCopyByValue(ft) ||
			refconfine.TypeReachesOnce(ft) {
			continue
		}
		if isConfinedToDoAndPost(fld, aliasedInitOnceFields) {
			adm.confinedOnceFields[fld] = true
		}
		if (refconfine.TypeHandsOutMutableReach(ft) || syntaxutil.ContainsUintptr(ft)) && isConfinedToDoAndPost(fld, disqualifiedOnceFields) {
			candidates[fld] = true
		}
	}
	adm.smuggledLocals = computeOnceFillSmuggledLocals(audited, fc, doBody, candidates, recvObj)

	if len(adm.confinedOnceFields) > 0 {
		confSmuggled := computeOnceFillSmuggledLocals(audited, fc, doBody, adm.confinedOnceFields, recvObj)
		confTainted, _ := propagateReceiverFieldTaint(doBody, recvObj, nil)
		for obj, flds := range confTainted {
			if len(flds) == 0 || confSmuggled[obj] {
				continue
			}
			allConf := true
			for fld := range flds {
				if !adm.confinedOnceFields[fld] {
					allConf = false
					break
				}
			}
			if allConf {
				adm.confinedTainted[obj] = true
			}
		}
	}

	if len(candidates) == 0 {
		return adm
	}

	var excludeRecv map[types.Object]bool
	if recvObj != nil {
		excludeRecv = map[types.Object]bool{recvObj: true}
	}
	freshLocals := computeBodyFreshSelfContainedLocals(audited, fc, doBody, excludeRecv, adm.smuggledLocals)

	// Track whole-field stores, fresh whole-field stores, local aliases of each
	// candidate field, and interior/element mutations in doBody.
	wholeCount := map[*types.Var]int{}
	nonFreshWhole := map[*types.Var]bool{}
	taintedFromField, valueFieldTaints := propagateReceiverFieldTaint(doBody, recvObj, candidates)

	interiorMutated := map[*types.Var]bool{}
	markCallInterior := func(v *flowir.Value) {
		if v == nil {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallBuiltin {
				switch cur.BuiltinName {
				case "clear", "delete", "copy":
					if len(cur.Args) >= 1 {
						for fld := range valueFieldTaints(cur.Args[0]) {
							interiorMutated[fld] = true
						}
					}
				}
			}
			return true
		})
	}
	doBody.ForEachSyncOp(func(op *flowir.Op) bool {
		switch op.Kind {
		case flowir.OpAssign:
			if op.AssignKind == flowir.AssignMulti && len(op.Srcs) == 1 {
				for _, dst := range op.Dsts {
					if fld, whole := receiverByValueOnceFillField(dst, recvObj); fld != nil && candidates[fld] {
						if whole {
							wholeCount[fld]++
							nonFreshWhole[fld] = true
						} else {
							interiorMutated[fld] = true
						}
					} else if !dst.IsBareVar() && dst.Obj != nil {
						for f := range taintedFromField[dst.Obj] {
							interiorMutated[f] = true
						}
					}
				}
			} else {
				op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
					if fld, whole := receiverByValueOnceFillField(dst, recvObj); fld != nil && candidates[fld] {
						if whole {
							wholeCount[fld]++
							if op.AssignKind != flowir.AssignPlain || !isFreshLocalOnceValue(audited, src, freshLocals) {
								nonFreshWhole[fld] = true
							}
						} else {
							interiorMutated[fld] = true
						}
					} else if !dst.IsBareVar() && dst.Obj != nil {
						for f := range taintedFromField[dst.Obj] {
							interiorMutated[f] = true
						}
					}
					return true
				})
			}
			for _, s := range op.Srcs {
				markCallInterior(s)
			}
		case flowir.OpExpr:
			markCallInterior(op.Expr)
		case flowir.OpDefer, flowir.OpGo:
			markCallInterior(op.Call)
		case flowir.OpReturn:
			for _, r := range op.Results {
				markCallInterior(r)
			}
		}
		return true
	})

	for fld := range candidates {
		freshInit := wholeCount[fld] > 0 && !nonFreshWhole[fld]
		if interiorMutated[fld] && !freshInit {
			continue
		}
		adm.fillFields[fld] = true
		if freshInit {
			if _, isByValStruct := types.Unalias(fld.Type()).Underlying().(*types.Struct); !isByValStruct {
				adm.freshFillFields[fld] = true
			}
		}
	}
	for obj, flds := range taintedFromField {
		if len(flds) == 0 || adm.smuggledLocals[obj] {
			continue
		}
		allFresh := true
		for fld := range flds {
			if !adm.freshFillFields[fld] {
				allFresh = false
				break
			}
		}
		if allFresh {
			adm.freshTainted[obj] = true
		}
	}
	return adm
}

func findAdmittedReceiverOnceDo(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	methodDecl *ast.FuncDecl,
	body *flowir.Body,
	recvObj types.Object,
	onceSites map[*types.Var]int,
	fieldRefIdents map[*types.Var][]*ast.Ident,
	disqualifiedOnceFields map[*types.Var]bool,
	aliasedInitOnceFields map[*types.Var]bool,
) map[*ast.CallExpr]*onceDoAdmission {
	if body == nil || recvObj == nil {
		return nil
	}
	if _, pointer := types.Unalias(recvObj.Type()).(*types.Pointer); !pointer {
		return nil
	}
	if refconfine.OnceFieldCount(recvObj.Type()) != 1 {
		return nil
	}
	for i := range body.Ops {
		op := &body.Ops[i]
		if !op.TopLevelInBody {
			return nil
		}
		if op.Kind == flowir.OpExpr && op.Expr != nil && op.Expr.Kind == flowir.ValCall && op.Expr.CallAST != nil {
			call := op.Expr.CallAST
			field := onceFieldOfDo(audited, p.TypesInfo, call)
			if field != nil && !field.Exported() && !disqualifiedOnceFields[field] && onceSites[field] == 1 && len(fieldRefIdents[field]) == 1 {
				if ident, ok := call.Fun.(*ast.SelectorExpr).X.(*ast.SelectorExpr).X.(*ast.Ident); ok && p.TypesInfo.Uses[ident] == recvObj {
					if rawLit, isLit := call.Args[0].(*ast.FuncLit); isLit && len(op.Expr.Args) == 1 &&
						op.Expr.Args[0] != nil && op.Expr.Args[0].Kind == flowir.ValMakeClosure && op.Expr.Args[0].Closure != nil {
						doBody := op.Expr.Args[0].Closure
						capturesOther := false
						for fv := range doBody.FreeVars {
							if fv != recvObj {
								capturesOther = true
								break
							}
						}
						if !capturesOther {
							adm := computeOnceDoFieldAdmissions(audited, p, fc, methodDecl, call, rawLit, doBody, recvObj, fieldRefIdents, disqualifiedOnceFields, aliasedInitOnceFields)
							return map[*ast.CallExpr]*onceDoAdmission{call: adm}
						}
					}
				}
			}
		}
		if !opCleanBeforeOnceDo(op, recvObj) {
			return nil
		}
	}
	return nil
}

func opCleanBeforeOnceDo(op *flowir.Op, recvObj types.Object) bool {
	if op == nil || !op.TopLevelInBody || op.Kind != flowir.OpAssign || op.AssignKind == flowir.AssignRange {
		return false
	}
	clean := true
	checkVal := func(v *flowir.Value) {
		if v == nil || !clean {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			switch cur.Kind {
			case flowir.ValInvalid, flowir.ValCall, flowir.ValChanRecv:
				clean = false
				return false
			case flowir.ValPlace:
				if cur.Place.Obj == recvObj || cur.Place.Root == flowir.RootPkgGlobal {
					clean = false
					return false
				}
			case flowir.ValAddrOf:
				if cur.AddrPlace.Obj == recvObj || cur.AddrPlace.Root == flowir.RootPkgGlobal {
					clean = false
					return false
				}
			case flowir.ValMethodVal:
				if cur.HasRecvPlace && (cur.RecvPlace.Obj == recvObj || cur.RecvPlace.Root == flowir.RootPkgGlobal) {
					clean = false
					return false
				}
			case flowir.ValMakeClosure:
				if rVar, ok := recvObj.(*types.Var); ok && cur.Closure != nil && cur.Closure.FreeVars[rVar] {
					clean = false
					return false
				}
			}
			return true
		})
	}
	op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
		if !dst.IsBareVar() || dst.Root != flowir.RootLocal {
			clean = false
			return false
		}
		checkVal(src)
		return clean
	})
	return clean
}
