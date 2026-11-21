package dynstate

import (
	"go/types"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

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
