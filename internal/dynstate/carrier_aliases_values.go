package dynstate

import (
	"go/types"

	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// localCarrierAliases separates carriers aliased directly at a local's own
// single-hop reference header (root) from all carriers reachable anywhere in
// the local's interior (all). Writes or non-carrier-capable address captures
// staying within the local's own root header (or bare-addressed pointer
// dereference) consult root, whereas escapes, carrier-capable address captures,
// or multi-hop interior accesses consult all.
type localCarrierAliases struct {
	root []*types.Var
	all  []*types.Var
}

func appendUniqueVars(dst *[]*types.Var, srcs []*types.Var) bool {
	changed := false
	for _, v := range srcs {
		if v == nil {
			continue
		}
		found := false
		for _, cur := range *dst {
			if cur == v {
				found = true
				break
			}
		}
		if !found {
			*dst = append(*dst, v)
			changed = true
		}
	}
	return changed
}

func isTypeParamType(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := types.Unalias(t).(*types.TypeParam)
	return ok
}

func canAliasCarrierType(audited bool, t types.Type) bool {
	return refconfine.TypeHandsOutDynamicAlias(audited, t) ||
		refconfine.TypeHandsOutMutableReach(t) ||
		refconfine.TypeReachesSyncNoCopyByValue(t) ||
		syntaxutil.ContainsUintptr(t)
}

func addrOfSubplaceCanAliasCarrier(audited bool, v *flowir.Value) bool {
	if v == nil || v.Kind != flowir.ValAddrOf {
		return true
	}
	if v.IsArraySlice {
		if v.Type == nil {
			return true
		}
		sl, ok := types.Unalias(v.Type).Underlying().(*types.Slice)
		if !ok {
			return true
		}
		return canAliasCarrierType(audited, sl.Elem())
	}
	return v.AddrPlace.Type == nil || canAliasCarrierType(audited, v.AddrPlace.Type)
}

func walkTransientTargetValues(root *flowir.Value, fn func(*flowir.Value)) {
	if root == nil || fn == nil {
		return
	}
	var walk func(cur *flowir.Value)
	walk = func(cur *flowir.Value) {
		if cur == nil || cur.Kind == flowir.ValMakeClosure {
			return
		}
		if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallIIFE {
			flowir.ForEachIIFEReturnValue(cur, walk)
			return
		}
		fn(cur)
		cur.ForEachChildValue(func(ch *flowir.Value) bool {
			walk(ch)
			return true
		})
	}
	walk(root)
}

func forEachOpTopValues(op *flowir.Op, fn func(*flowir.Value)) {
	if op == nil || fn == nil {
		return
	}
	op.ForEachValue(func(v *flowir.Value) bool {
		fn(v)
		return true
	})
}

func transientValueHasUnresolvedTarget(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	unresolved := false
	walkTransientTargetValues(v, func(cur *flowir.Value) {
		switch cur.Kind {
		case flowir.ValCall:
			if cur.CallKind != flowir.CallIIFE {
				unresolved = true
			}
		case flowir.ValChanRecv:
			unresolved = true
		}
	})
	return unresolved
}

// forEachNestedLiteralAndGo invokes onLit for each immediate nested
// ValMakeClosure or CallIIFE body and invokes onGo for each synchronous OpGo.
func forEachNestedLiteralAndGo(b *flowir.Body, onLit func(*flowir.Body), onGo func(*flowir.Op)) {
	if b == nil {
		return
	}
	var scanVal func(v *flowir.Value)
	scanVal = func(v *flowir.Value) {
		if v == nil {
			return
		}
		if v.Kind == flowir.ValMakeClosure {
			if onLit != nil && v.Closure != nil {
				onLit(v.Closure)
			}
			return
		}
		if v.Kind == flowir.ValCall && v.CallKind == flowir.CallIIFE {
			for _, a := range v.Args {
				scanVal(a)
			}
			if onLit != nil && v.IIFE != nil {
				onLit(v.IIFE)
			}
			return
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			scanVal(ch)
			return true
		})
	}
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind == flowir.OpGo {
			if onGo != nil {
				onGo(op)
			}
			return true
		}
		forEachOpTopValues(op, scanVal)
		return true
	})
}

func collectValueCarrierVars(
	audited bool,
	v *flowir.Value,
	carrierVar func(types.Object) (*types.Var, bool),
	aliases map[types.Object]localCarrierAliases,
	skipMethodRecv func(*flowir.Value) bool,
) []*types.Var {
	return collectValueCarrierVarsWithOpts(audited, v, carrierVar, aliases, skipMethodRecv, false)
}

func collectValueCarrierVarsWithOpts(
	audited bool,
	v *flowir.Value,
	carrierVar func(types.Object) (*types.Var, bool),
	aliases map[types.Object]localCarrierAliases,
	skipMethodRecv func(*flowir.Value) bool,
	skipNonBuiltinCalls bool,
) []*types.Var {
	if v == nil {
		return nil
	}
	var vars []*types.Var
	addObj := func(u *types.Var) {
		if u == nil {
			return
		}
		if cv, isC := carrierVar(u); isC {
			appendUniqueVars(&vars, []*types.Var{cv})
		} else {
			appendUniqueVars(&vars, aliases[u].all)
		}
	}
	var walk func(cur *flowir.Value)
	walk = func(cur *flowir.Value) {
		if cur == nil || cur.Kind == flowir.ValMakeClosure {
			return
		}
		isStrBuiltin := cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallBuiltin &&
			(cur.BuiltinName == "String" || cur.BuiltinName == "StringData")
		if !isStrBuiltin && cur.Type != nil && !canAliasCarrierType(audited, cur.Type) && !isTypeParamType(cur.Type) {
			return
		}
		if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallIIFE {
			flowir.ForEachIIFEReturnValue(cur, walk)
			return
		}
		switch cur.Kind {
		case flowir.ValAllocFresh:
			if cur.AllocKind == flowir.AllocMake || cur.AllocKind == flowir.AllocBuiltinNewType {
				return
			}
		case flowir.ValConvert:
			if !cur.IsTypeAssert && cur.Arg != nil && syntaxutil.IsFreshStringSliceCopy(cur.Arg.Type, cur.Type) {
				return
			}
		case flowir.ValPlace:
			addObj(cur.Place.Obj)
		case flowir.ValAddrOf:
			addObj(cur.AddrPlace.Obj)
		case flowir.ValCall:
			if cur.CallKind == flowir.CallBuiltin {
				switch cur.BuiltinName {
				case "len", "cap", "Sizeof", "Alignof", "Offsetof", "StringData":
					return
				case "Slice", "SliceData", "String":
					if len(cur.Args) > 0 {
						walk(cur.Args[0])
					}
					return
				}
			}
			if skipNonBuiltinCalls && cur.CallKind != flowir.CallBuiltin {
				return
			}
			if skipMethodRecv != nil && skipMethodRecv(cur) {
				for _, a := range cur.Args {
					walk(a)
				}
				return
			}
			if cur.AutoAddrRecv && cur.HasRecvPlace {
				addObj(cur.RecvPlace.Obj)
			}
		}
		cur.ForEachChildValue(func(ch *flowir.Value) bool {
			walk(ch)
			return true
		})
	}
	walk(v)
	return vars
}

func valueCarrierSources(
	audited bool,
	v *flowir.Value,
	carrierVar func(types.Object) (*types.Var, bool),
	aliases map[types.Object]localCarrierAliases,
	skipMethodRecv func(*flowir.Value) bool,
	skipNonBuiltinCalls bool,
) (rootSrcs, allSrcs []*types.Var) {
	if v == nil {
		return nil, nil
	}
	allSrcs = collectValueCarrierVarsWithOpts(audited, v, carrierVar, aliases, skipMethodRecv, skipNonBuiltinCalls)
	if len(allSrcs) == 0 {
		return nil, nil
	}
	switch v.Kind {
	case flowir.ValAllocFresh:
		return nil, allSrcs
	case flowir.ValPlace:
		if v.Place.IsBareVar() {
			if cv, isC := carrierVar(v.Place.Obj); isC {
				if syntaxutil.IsRefHeaderType(cv.Type()) || isTypeParamType(cv.Type()) {
					return []*types.Var{cv}, allSrcs
				}
				return nil, allSrcs
			}
			return aliases[v.Place.Obj].root, allSrcs
		}
		if v.Place.Obj != nil && len(v.Place.Projs) == 1 && v.Place.Projs[0].Kind == flowir.ProjSlice {
			if cv, isC := carrierVar(v.Place.Obj); isC {
				return []*types.Var{cv}, allSrcs
			}
			return aliases[v.Place.Obj].root, allSrcs
		}
		return allSrcs, allSrcs
	case flowir.ValAddrOf:
		if v.AddrPlace.Obj != nil {
			if _, isC := carrierVar(v.AddrPlace.Obj); isC {
				return allSrcs, allSrcs
			}
			if v.IsArraySlice {
				if flowir.PlaceEntersInterior(v.AddrPlace, false) {
					return allSrcs, allSrcs
				}
				return aliases[v.AddrPlace.Obj].root, allSrcs
			}
			if v.AddrPlace.IsBareVar() {
				return nil, allSrcs
			}
			if !flowir.PlaceEntersInterior(v.AddrPlace, false) {
				return aliases[v.AddrPlace.Obj].root, allSrcs
			}
		}
		return allSrcs, allSrcs
	case flowir.ValCall:
		if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
			var rSrcs []*types.Var
			flowir.ForEachIIFEReturnValue(v, func(retVal *flowir.Value) {
				rs, _ := valueCarrierSources(audited, retVal, carrierVar, aliases, skipMethodRecv, skipNonBuiltinCalls)
				appendUniqueVars(&rSrcs, rs)
			})
			return rSrcs, allSrcs
		}
		return allSrcs, allSrcs
	default:
		return allSrcs, allSrcs
	}
}

// collectValueLinkVars collects init-flow carrier storage links without crossing
// general plain/method/indirect function calls, while traversing places,
// &place, array [:], composite literals, Go 1.26+ new(expr), CallResultHandsOut
// conversions/type assertions, and pointer/value-forwarding builtins.
func collectValueLinkVars(
	v *flowir.Value,
	carrierVar func(types.Object) (*types.Var, bool),
	linkAliases map[types.Object][]*types.Var,
) []*types.Var {
	if v == nil {
		return nil
	}
	var vars []*types.Var
	addObj := func(u *types.Var) {
		if u == nil {
			return
		}
		if cv, isC := carrierVar(u); isC {
			appendUniqueVars(&vars, []*types.Var{cv})
		} else {
			appendUniqueVars(&vars, linkAliases[u])
		}
	}
	inStringData := false
	var walkPlaceBase func(pl flowir.Place, addressed bool)
	var walk func(cur *flowir.Value)
	walkPlaceBase = func(pl flowir.Place, addressed bool) {
		if !addressed && !inStringData && pl.Type != nil && !refconfine.CallResultHandsOut(pl.Type) && !isTypeParamType(pl.Type) {
			return
		}
		if pl.Obj != nil {
			addObj(pl.Obj)
			return
		}
		if pl.Root == flowir.RootTransient && pl.Base != nil {
			walk(pl.Base)
		}
	}
	walk = func(cur *flowir.Value) {
		if cur == nil {
			return
		}
		isStrBuiltin := cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallBuiltin &&
			(cur.BuiltinName == "String" || cur.BuiltinName == "StringData")
		if !isStrBuiltin && !inStringData && cur.Type != nil && !refconfine.CallResultHandsOut(cur.Type) {
			return
		}
		switch cur.Kind {
		case flowir.ValPlace:
			walkPlaceBase(cur.Place, false)
		case flowir.ValAddrOf:
			walkPlaceBase(cur.AddrPlace, true)
		case flowir.ValMethodVal:
			if cur.HasRecvPlace {
				walkPlaceBase(cur.RecvPlace, cur.AutoAddr)
			} else {
				walk(cur.Recv)
			}
		case flowir.ValConvert:
			walk(cur.Arg)
		case flowir.ValCompositeExpr:
			for _, a := range cur.Args {
				walk(a)
			}
		case flowir.ValAllocFresh:
			switch cur.AllocKind {
			case flowir.AllocBuiltinNewExpr:
				if len(cur.Args) == 1 && !cur.Ellipsis {
					walk(cur.Args[0])
				}
			case flowir.AllocCompositeLit:
				for i := range cur.CompositeElts {
					elt := &cur.CompositeElts[i]
					if elt.MapKey != nil {
						walk(elt.MapKey)
					}
					if elt.Value != nil {
						walk(elt.Value)
					}
				}
			}
		case flowir.ValCall:
			if cur.CallKind == flowir.CallIIFE {
				flowir.ForEachIIFEReturnValue(cur, walk)
			} else if cur.CallKind == flowir.CallBuiltin {
				switch cur.BuiltinName {
				case "append", "Add", "min", "max":
					for _, a := range cur.Args {
						walk(a)
					}
				case "Slice", "SliceData", "String":
					if len(cur.Args) > 0 {
						walk(cur.Args[0])
					}
				case "StringData":
					if len(cur.Args) > 0 {
						prev := inStringData
						inStringData = true
						walk(cur.Args[0])
						inStringData = prev
					}
				}
			}
		}
	}
	walk(v)
	return vars
}
