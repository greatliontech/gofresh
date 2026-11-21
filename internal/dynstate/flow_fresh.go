package dynstate

import (
	"go/types"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func isSliceOrMapType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch types.Unalias(t).Underlying().(type) {
	case *types.Slice, *types.Map:
		return true
	}
	return false
}

func isStructPtrType(t types.Type) bool {
	if t == nil {
		return false
	}
	ptr, ok := types.Unalias(t).Underlying().(*types.Pointer)
	if !ok {
		return false
	}
	_, isSt := types.Unalias(ptr.Elem()).Underlying().(*types.Struct)
	return isSt
}

func isSliceResliceOnlyPlace(pl flowir.Place) bool {
	if pl.Obj == nil || pl.Obj.Type() == nil {
		return false
	}
	if _, isSl := types.Unalias(pl.Obj.Type()).Underlying().(*types.Slice); !isSl {
		return false
	}
	for _, pr := range pl.Projs {
		if pr.Kind != flowir.ProjSlice {
			return false
		}
	}
	return true
}

func isElementReadPlace(pl flowir.Place) bool {
	if pl.Obj == nil || len(pl.Projs) == 0 {
		return false
	}
	idxPos := 0
	for idxPos < len(pl.Projs) && pl.Projs[idxPos].Kind == flowir.ProjSlice {
		idxPos++
	}
	if idxPos >= len(pl.Projs) || pl.Projs[idxPos].Kind != flowir.ProjIndex || pl.Projs[idxPos].BaseType == nil {
		return false
	}
	if idxPos > 0 {
		if pl.Obj.Type() == nil {
			return false
		}
		if _, isSl := types.Unalias(pl.Obj.Type()).Underlying().(*types.Slice); !isSl {
			return false
		}
	}
	return isSliceOrMapType(pl.Projs[idxPos].BaseType)
}

func isDirectIndexPlace(pl flowir.Place) bool {
	if pl.Obj == nil || len(pl.Projs) == 0 {
		return false
	}
	last := len(pl.Projs) - 1
	if pl.Projs[last].Kind != flowir.ProjIndex || pl.Projs[last].BaseType == nil {
		return false
	}
	if !isSliceOrMapType(pl.Projs[last].BaseType) {
		return false
	}
	if last > 0 {
		if pl.Obj.Type() == nil {
			return false
		}
		if _, isSl := types.Unalias(pl.Obj.Type()).Underlying().(*types.Slice); !isSl {
			return false
		}
		for i := 0; i < last; i++ {
			if pl.Projs[i].Kind != flowir.ProjSlice {
				return false
			}
		}
	}
	return true
}

func isSelfAppendBind(obj types.Object, src *flowir.Value) bool {
	return src != nil && src.Kind == flowir.ValCall && src.CallKind == flowir.CallBuiltin &&
		src.BuiltinName == "append" && len(src.Args) > 0 &&
		src.Args[0] != nil && src.Args[0].Kind == flowir.ValPlace &&
		src.Args[0].Place.IsBareVar() && src.Args[0].Place.Obj == obj
}

type freshAllocEvalPolicy struct {
	allowScalarLitOrConst bool
	typeOK                func(types.Type) bool
	convertOK             func(*flowir.Value) bool
	elemOK                func(*flowir.Value) bool
	placeOK               func(*flowir.Value) bool
	allowNilAppendBase    bool
	checkAppendElems      bool
}

func evalFreshAllocValue(v *flowir.Value, pol freshAllocEvalPolicy) bool {
	if v == nil {
		return false
	}
	switch v.Kind {
	case flowir.ValScalarLitOrConst:
		return pol.allowScalarLitOrConst
	case flowir.ValAllocFresh:
		if pol.typeOK != nil && !pol.typeOK(v.Type) {
			return false
		}
		switch v.AllocKind {
		case flowir.AllocMake, flowir.AllocBuiltinNewType:
			return true
		case flowir.AllocBuiltinNewExpr:
			if len(v.Args) != 1 || v.Ellipsis {
				return false
			}
			if pol.elemOK != nil {
				return pol.elemOK(v.Args[0])
			}
			return evalFreshAllocValue(v.Args[0], pol)
		case flowir.AllocCompositeLit:
			if pol.elemOK != nil {
				for _, ce := range v.CompositeElts {
					if ce.MapKey != nil && !pol.elemOK(ce.MapKey) {
						return false
					}
					if !pol.elemOK(ce.Value) {
						return false
					}
				}
			}
			return true
		}
		return false
	case flowir.ValPlace:
		return pol.placeOK != nil && pol.placeOK(v)
	case flowir.ValConvert:
		if v.IsTypeAssert || v.Arg == nil {
			return false
		}
		if pol.convertOK != nil && !pol.convertOK(v) {
			return false
		}
		return evalFreshAllocValue(v.Arg, pol)
	case flowir.ValCall:
		if v.CallKind == flowir.CallBuiltin && v.BuiltinName == "append" && len(v.Args) >= 1 && v.Args[0] != nil {
			baseOK := (pol.allowNilAppendBase && v.Args[0].Kind == flowir.ValPlace && v.Args[0].Place.Root == flowir.RootConstOrNil) ||
				evalFreshAllocValue(v.Args[0], pol)
			if !baseOK {
				return false
			}
			if !pol.checkAppendElems {
				return true
			}
			if v.Ellipsis {
				return len(v.Args) == 2 && pol.elemOK != nil && pol.elemOK(v.Args[1])
			}
			for _, elem := range v.Args[1:] {
				if pol.elemOK != nil && !pol.elemOK(elem) {
					return false
				}
			}
			return true
		}
	}
	return false
}

func isFreshLocalOnceValue(audited bool, v *flowir.Value, freshLocals map[types.Object]bool) bool {
	shares := sharesMemOrSigOrDynamic(audited)
	typeOK := func(t types.Type) bool {
		return t != nil && !refconfine.TypeMayCarryUnknownDynamic(audited, t) && !refconfine.TypeCarriesSignature(t)
	}
	var isSafeElem func(el *flowir.Value) bool
	isSafeElem = func(el *flowir.Value) bool {
		if el == nil {
			return false
		}
		if el.Kind == flowir.ValScalarLitOrConst || (el.Kind == flowir.ValPlace && el.Place.Root == flowir.RootConstOrNil) {
			return true
		}
		if el.Type != nil && !shares(el.Type) {
			return true
		}
		return isFreshLocalOnceValue(audited, el, freshLocals)
	}
	return evalFreshAllocValue(v, freshAllocEvalPolicy{
		allowScalarLitOrConst: true,
		typeOK:                typeOK,
		convertOK: func(cv *flowir.Value) bool {
			return typeOK(cv.Type)
		},
		elemOK: isSafeElem,
		placeOK: func(pv *flowir.Value) bool {
			return pv.Place.IsBareVar() && pv.Place.Obj != nil && freshLocals[pv.Place.Obj]
		},
		allowNilAppendBase: true,
		checkAppendElems:   true,
	})
}

// computeBodyFreshSelfContainedLocals computes the greatest fixed point of local
// variables in rootBody whose every binding and interior element mutation stays
// freshly allocated and free of smuggled external references.
func computeBodyFreshSelfContainedLocals(
	audited bool,
	fc *pkgFlowCache,
	rootBody *flowir.Body,
	exclude map[types.Object]bool,
	disqualified map[types.Object]bool,
) map[types.Object]bool {
	freshLocals := map[types.Object]bool{}
	if rootBody == nil {
		return freshLocals
	}
	shares := sharesMemOrSigOrDynamic(audited)
	localAssignCount := map[types.Object]int{}
	localNonFresh := map[types.Object]bool{}
	freshMemAdj := fc.scopedBodyInteriorAliases(audited, rootBody, exclude)

	var collectFreshCandidates func(b *flowir.Body)
	collectFreshCandidates = func(b *flowir.Body) {
		if b == nil {
			return
		}
		var scanSubVal func(v *flowir.Value)
		scanSubVal = func(v *flowir.Value) {
			if v == nil {
				return
			}
			if v.Kind == flowir.ValMakeClosure && v.Closure != nil {
				collectFreshCandidates(v.Closure)
			}
			if v.Kind == flowir.ValCall && v.CallKind == flowir.CallIIFE && v.IIFE != nil {
				for _, pv := range v.IIFE.Params {
					if pv != nil {
						localNonFresh[pv] = true
					}
				}
				collectFreshCandidates(v.IIFE)
			}
			v.ForEachChildValue(func(ch *flowir.Value) bool {
				scanSubVal(ch)
				return true
			})
		}
		for i := range b.Ops {
			op := &b.Ops[i]
			op.ForEachValue(func(v *flowir.Value) bool {
				scanSubVal(v)
				return true
			})
			switch op.Kind {
			case flowir.OpAssign:
				if op.AssignKind != flowir.AssignPlain {
					for _, dst := range op.Dsts {
						if dst.Obj != nil {
							localNonFresh[dst.Obj] = true
						}
					}
				} else {
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, _ *flowir.Value) bool {
						if dst.IsBareVar() && dst.Obj != nil && dst.Root == flowir.RootLocal {
							localAssignCount[dst.Obj]++
						}
						return true
					})
				}
				if op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
					collectFreshCandidates(op.RangeBody)
				}
			case flowir.OpTypeSwitchBind:
				if op.SwitchDst != nil {
					localNonFresh[op.SwitchDst] = true
				}
			case flowir.OpChanSend:
				if op.ChanPlace.Obj != nil {
					localNonFresh[op.ChanPlace.Obj] = true
				}
			}
		}
	}
	collectFreshCandidates(rootBody)
	for obj, cnt := range localAssignCount {
		if cnt > 0 && !localNonFresh[obj] && !disqualified[obj] {
			freshLocals[obj] = true
		}
	}
	isSafeFreshInteriorElem := func(el *flowir.Value) bool {
		if el == nil {
			return false
		}
		if el.Kind == flowir.ValScalarLitOrConst || (el.Kind == flowir.ValPlace && el.Place.Root == flowir.RootConstOrNil) {
			return true
		}
		if el.Type != nil && !shares(el.Type) {
			return true
		}
		return isFreshLocalOnceValue(audited, el, freshLocals)
	}
	evictFreshObj := func(obj types.Object) bool {
		if obj != nil && freshLocals[obj] {
			delete(freshLocals, obj)
			return true
		}
		return false
	}
	evictFreshVar := func(v *types.Var) bool {
		if v == nil {
			return false
		}
		return evictFreshObj(v)
	}
	evictArgObj := func(a *flowir.Value) bool {
		return markEscapingValueVars(audited, a, evictFreshVar)
	}
	for changed := true; changed; {
		changed = false
		for obj := range freshLocals {
			for nb := range freshMemAdj[obj] {
				if !freshLocals[nb] && shares(nb.Type()) {
					delete(freshLocals, obj)
					changed = true
					break
				}
			}
		}
		var checkFreshBody func(b *flowir.Body)
		var checkFreshVal func(v *flowir.Value)
		checkFreshVal = func(v *flowir.Value) {
			if v == nil {
				return
			}
			switch v.Kind {
			case flowir.ValAddrOf:
				if markEscapingAddrPlaceVars(audited, v.AddrPlace, evictFreshVar) {
					changed = true
				}
			case flowir.ValMethodVal:
				if v.HasRecvPlace && markEscapingAddrPlaceVars(audited, v.RecvPlace, evictFreshVar) {
					changed = true
				}
				if evictArgObj(v.Recv) {
					changed = true
				}
			case flowir.ValMakeClosure:
				if v.Closure != nil {
					checkFreshBody(v.Closure)
				}
			case flowir.ValCall:
				switch {
				case v.CallKind == flowir.CallIIFE && v.IIFE != nil:
					checkFreshBody(v.IIFE)
				case v.CallKind == flowir.CallBuiltin && (v.BuiltinName == "len" || v.BuiltinName == "cap" || v.BuiltinName == "delete" || v.BuiltinName == "clear" || v.BuiltinName == "Sizeof" || v.BuiltinName == "Alignof" || v.BuiltinName == "Offsetof"):
				case v.CallKind == flowir.CallBuiltin && v.BuiltinName == "copy" && len(v.Args) == 2:
					if v.Args[0] != nil && sliceCopyElemCarriesReachOrDynamic(audited, v.Args[0].Type) &&
						!isFreshLocalOnceValue(audited, v.Args[1], freshLocals) && evictArgObj(v.Args[0]) {
						changed = true
					}
				case v.CallKind == flowir.CallBuiltin && v.BuiltinName == "append" && len(v.Args) >= 1:
					for _, elem := range v.Args[1:] {
						if !isSafeFreshInteriorElem(elem) {
							if evictArgObj(v.Args[0]) {
								changed = true
							}
							break
						}
					}
				case v.CallKind == flowir.CallPlain && !v.IsMethodExprCall && v.CalleeFunc != nil && auditset.ValuePlaneClone(v.CalleePkg, v.CalleeFunc.Name()):
				default:
					if markCallTargetVars(audited, v, evictFreshVar) {
						changed = true
					}
				}
			}
			v.ForEachChildValue(func(ch *flowir.Value) bool {
				checkFreshVal(ch)
				return true
			})
		}
		checkFreshBody = func(b *flowir.Body) {
			if b == nil {
				return
			}
			for i := range b.Ops {
				op := &b.Ops[i]
				op.ForEachValue(func(v *flowir.Value) bool {
					checkFreshVal(v)
					return true
				})
				if op.Kind == flowir.OpAssign {
					if op.AssignKind == flowir.AssignPlain {
						op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
							if dst.Obj != nil && freshLocals[dst.Obj] {
								if dst.IsBareVar() {
									if !isFreshLocalOnceValue(audited, src, freshLocals) && evictFreshObj(dst.Obj) {
										changed = true
									}
								} else {
									if !isSafeFreshInteriorElem(src) && evictFreshObj(dst.Obj) {
										changed = true
									}
									if mapPlace, keyVal, isMapWrite := dst.AsMapWrite(); isMapWrite && mapPlace.Obj != nil &&
										!isSafeFreshInteriorElem(keyVal) && evictFreshObj(mapPlace.Obj) {
										changed = true
									}
								}
							}
							return true
						})
					}
					if op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
						checkFreshBody(op.RangeBody)
					}
				}
			}
		}
		checkFreshBody(rootBody)
	}
	return freshLocals
}

type outflowPendingStore struct {
	robj     types.Object
	place    flowir.Place
	source   *flowir.Value
	isMapKey bool
}

type outflowFreshInput struct {
	directBinds         map[types.Object][]*flowir.Value
	hasZeroDecl         map[types.Object]bool
	params              map[types.Object]bool
	localBroken         map[types.Object]bool
	rangeBound          map[types.Object]bool
	hasSpreadAppend     map[types.Object]bool
	headerMembers       map[types.Object][]types.Object
	headerEmbedded      map[types.Object]bool
	headerFind          func(types.Object) types.Object
	insertionWrites     map[types.Object][]*flowir.Value
	pendingStores       []outflowPendingStore
	pendingAppendSlices []outflowPendingStore
}

// computeOutflowFreshOwnedLocals computes the mutual greatest fixed point
// (freshObj, elemOwned) of local variables whose backing allocations and
// 1-hop container elements originate exclusively from fresh allocations in the
// enclosing function body.
func computeOutflowFreshOwnedLocals(in outflowFreshInput) (map[types.Object]bool, map[types.Object]bool) {
	freshObj := map[types.Object]bool{}
	elemOwned := map[types.Object]bool{}

	var srcFresh func(v *flowir.Value) bool
	srcFresh = func(v *flowir.Value) bool {
		return evalFreshAllocValue(v, freshAllocEvalPolicy{
			convertOK: func(cv *flowir.Value) bool {
				return !syntaxutil.IsUnsafePointerType(cv.Type) && !syntaxutil.IsUnsafePointerType(cv.Arg.Type)
			},
			placeOK: func(pv *flowir.Value) bool {
				obj := pv.Place.Obj
				if obj == nil || in.params[obj] || !freshObj[obj] || in.localBroken[obj] || in.rangeBound[obj] {
					return false
				}
				if len(pv.Place.Projs) == 0 || isSliceResliceOnlyPlace(pv.Place) {
					return true
				}
				if len(pv.Place.Projs) == 1 && pv.Place.Projs[0].Kind == flowir.ProjIndex && pv.Place.Projs[0].BaseType != nil {
					var elemT types.Type
					switch u := types.Unalias(pv.Place.Projs[0].BaseType).Underlying().(type) {
					case *types.Map:
						elemT = u.Elem()
					case *types.Slice:
						elemT = u.Elem()
					}
					if elemT != nil && (isSliceOrMapType(elemT) || isStructPtrType(elemT)) {
						return elemOwned[in.headerFind(obj)]
					}
				}
				return false
			},
		})
	}

	var bindConstructsOwnedElems func(hRoot types.Object, v *flowir.Value) bool
	bindConstructsOwnedElems = func(hRoot types.Object, v *flowir.Value) bool {
		if v == nil {
			return false
		}
		switch v.Kind {
		case flowir.ValAllocFresh:
			switch v.AllocKind {
			case flowir.AllocMake:
				return true
			case flowir.AllocCompositeLit:
				for i := range v.CompositeElts {
					if v.CompositeElts[i].Value == nil || !srcFresh(v.CompositeElts[i].Value) {
						return false
					}
				}
				return true
			}
			return false
		case flowir.ValConvert:
			return !v.IsTypeAssert && isSliceOrMapType(v.Type) && bindConstructsOwnedElems(hRoot, v.Arg)
		case flowir.ValCall:
			if v.CallKind == flowir.CallBuiltin && v.BuiltinName == "append" {
				if v.Ellipsis || len(v.Args) == 0 || !bindConstructsOwnedElems(hRoot, v.Args[0]) {
					return false
				}
				for _, a := range v.Args[1:] {
					if !srcFresh(a) {
						return false
					}
				}
				return true
			}
			return false
		case flowir.ValPlace:
			obj := v.Place.Obj
			if obj == nil || in.headerFind(obj) != hRoot || !freshObj[obj] || in.localBroken[obj] || in.rangeBound[obj] {
				return false
			}
			return len(v.Place.Projs) == 0 || isSliceResliceOnlyPlace(v.Place)
		}
		return false
	}

	for obj, binds := range in.directBinds {
		if in.params[obj] || in.localBroken[obj] || in.rangeBound[obj] || len(binds) == 0 {
			continue
		}
		nonSelf := 0
		for _, b := range binds {
			if !isSelfAppendBind(obj, b) {
				nonSelf++
			}
		}
		if nonSelf > 0 || in.hasZeroDecl[obj] {
			freshObj[obj] = true
		}
	}
	for hRoot, members := range in.headerMembers {
		if !in.headerEmbedded[hRoot] && len(members) > 0 {
			elemOwned[hRoot] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for obj, binds := range in.directBinds {
			if !freshObj[obj] {
				continue
			}
			for _, b := range binds {
				if isSelfAppendBind(obj, b) {
					continue
				}
				if !srcFresh(b) {
					freshObj[obj] = false
					changed = true
					break
				}
			}
		}
		for hRoot, members := range in.headerMembers {
			if !elemOwned[hRoot] {
				continue
			}
			okOwned := !in.headerEmbedded[hRoot] && len(members) > 0
			for _, o := range members {
				if !okOwned {
					break
				}
				if !freshObj[o] || in.params[o] || in.localBroken[o] || in.rangeBound[o] || in.hasSpreadAppend[o] || len(in.directBinds[o]) == 0 {
					okOwned = false
					break
				}
				for _, b := range in.directBinds[o] {
					if !bindConstructsOwnedElems(hRoot, b) {
						okOwned = false
						break
					}
				}
				if !okOwned {
					break
				}
				for _, iw := range in.insertionWrites[o] {
					if !srcFresh(iw) {
						okOwned = false
						break
					}
				}
			}
			if okOwned {
				for _, ps := range in.pendingStores {
					if ps.robj == nil || in.headerFind(ps.robj) != hRoot || ps.isMapKey {
						continue
					}
					if !isDirectIndexPlace(ps.place) || !srcFresh(ps.source) {
						okOwned = false
						break
					}
				}
			}
			if okOwned {
				for _, pa := range in.pendingAppendSlices {
					if pa.robj == nil || in.headerFind(pa.robj) != hRoot {
						continue
					}
					if !isSliceResliceOnlyPlace(pa.place) || !srcFresh(pa.source) {
						okOwned = false
						break
					}
				}
			}
			if !okOwned {
				elemOwned[hRoot] = false
				changed = true
			}
		}
	}
	return freshObj, elemOwned
}
