package dynstate

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
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
		mode:                 confinementModeBoundValue,
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

type confinementMode uint8

const (
	confinementModeBoundValue confinementMode = iota
	confinementModeReceiver
	confinementModeEnclosingRoots
	confinementModeOnceMemoRecv
)

type valueEvalMode uint8

const (
	modeGeneral valueEvalMode = iota
	modeGovernedBindOrReturn
	modeBlankDiscard
)

type confinementEngine struct {
	mode                 confinementMode
	audited              bool
	p                    *packages.Package
	fc                   *pkgFlowCache
	rootBody             *flowir.Body
	roots                map[types.Object]bool
	globalRoots          []*types.Var
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
	inGoSubtree         bool
	recvObj             types.Object
	methods             map[string]methodBodyEntry
	declared            map[string]bool
	declaredByName      map[string][]string
	bodyless            map[string]bool
	closedFields        map[*types.Var][]string
	admittedOnceDo      map[*ast.CallExpr]*onceDoAdmission
	activeOnceAdmission *onceDoAdmission
	recordMethodChain   func(target string)

	// Enclosing-scope root confinement & once-memo receiver modes.
	encl     *enclosingConfinementState
	onceMemo *onceMemoRecvState
}

func (e *confinementEngine) isRecvMode() bool {
	return e.mode == confinementModeReceiver
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
	switch e.mode {
	case confinementModeEnclosingRoots:
		return e.runEnclosingRoots()
	case confinementModeOnceMemoRecv:
		return e.runOnceMemoRecv()
	default:
		e.propagateTaint()
		if e.tolerateRootedStores {
			e.propagateExternalReaching()
		}
		return e.checkBody(e.rootBody, true, false)
	}
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
		return e.valueIsRooted(pl.Base) || (e.isRecvMode() && e.isGovernableRecvCall(pl.Base))
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
	if !e.isRecvMode() || e.inGoSubtree || v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallMethod || v.IsMethodExprCall {
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
	if e.isRecvMode() {
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
		if e.isRecvMode() && e.isGovernableRecvCall(v) {
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
					if flowir.BodyMentionsVar(cur.Closure, gv) {
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
					if flowir.BodyMentionsVar(cur.IIFE, gv) {
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
	return valueTouchesRootSet(v, e.isRootOrTainted, e.globalRoots)
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

func (e *confinementEngine) placeMapKeysSmuggle(pl flowir.Place, allowEmptyCarrier bool, reachKeySmuggles func(*flowir.Value) bool) bool {
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
		if (typeHandsOutReachOrAddr(slotT) || typeHandsOutReachOrAddr(kt)) &&
			(reachKeySmuggles == nil || reachKeySmuggles(pr.Key)) {
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
		if e.isRecvMode() && e.isGovernableRecvCall(v) {
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
		reachKeySmuggles := e.valueReachesExternal
		switch op.AssignKind {
		case flowir.AssignIncDec:
			return !e.placeMapKeysSmuggle(dst, true, reachKeySmuggles)
		case flowir.AssignRange:
			return !isDef &&
				dst.Type != nil &&
				!refconfine.TypeMayCarryUnknownDynamic(e.audited, dst.Type) &&
				!refconfine.CallResultHandsOut(dst.Type) &&
				!refconfine.TypeReachesSyncNoCopyByValue(dst.Type) &&
				!e.placeMapKeysSmuggle(dst, true, reachKeySmuggles)
		case flowir.AssignPlain:
			if dst.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(dst.Type) {
				return false
			}
			if refconfine.TypeMayCarryUnknownDynamic(e.audited, dst.Type) || refconfine.TypeCarriesSignature(dst.Type) {
				if src == nil || !isCarrierEmptySlotValue(e.audited, dst.Type, src) {
					return false
				}
			}
			if typeHandsOutReachOrAddr(dst.Type) {
				if src == nil || e.valueReachesExternal(src) {
					return false
				}
			}
			return !e.placeMapKeysSmuggle(dst, true, reachKeySmuggles)
		default:
			return dst.Type != nil &&
				!refconfine.TypeMayCarryUnknownDynamic(e.audited, dst.Type) &&
				!refconfine.CallResultHandsOut(dst.Type) &&
				!refconfine.TypeReachesSyncNoCopyByValue(dst.Type) &&
				!e.placeMapKeysSmuggle(dst, true, reachKeySmuggles)
		}
	}
	if e.isRecvMode() && inOnceDo && op.TopLevelInBody && op.AssignKind != flowir.AssignRange {
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
		if e.placeMapKeysSmuggle(dst, false, func(key *flowir.Value) bool {
			return onceFillValueSmuggles(e.audited, adm.doBody, adm.smuggledLocals, adm.candidates, e.recvObj, key)
		}) {
			return false
		}
		if !typeHandsOutReachOrAddr(dst.Type) {
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
