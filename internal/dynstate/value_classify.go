package dynstate

import (
	"go/types"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// valuePurityPolicy parameterizes the shared *flowir.Value purity and freshness
// classifier so callers across registration confinement, return freshness,
// once-field initialization, local fresh-allocation fixed points, and memoizer
// input checking evaluate one structural tree walker without Raw AST back-edges.
type valuePurityPolicy struct {
	allowVar                func(*types.Var) bool
	allowPlace              func(*flowir.Value) bool
	allowAppend             bool
	allowValuePlane         bool
	allowRuntimeOps         bool
	allowTypeAssert         bool
	allowNonMutableReach    bool
	allowSigLeaf            func(*flowir.Value) bool
	allowSyncNoCopy         bool
	ignoreSizeAndIndexArgs  bool
	preserveAppendBasePlace bool
	skipContainerElems      bool
	allocTypeOK             func(types.Type) bool
	convertOK               func(*flowir.Value) bool
	elemOK                  func(*flowir.Value) bool
}

func typeHandsOutReachOrAddr(t types.Type) bool {
	return refconfine.TypeHandsOutMutableReach(t) || syntaxutil.ContainsUintptr(t)
}

func containerElemHandsOutReach(t types.Type) bool {
	if t == nil {
		return true
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Slice:
		return typeHandsOutReachOrAddr(u.Elem())
	case *types.Array:
		return typeHandsOutReachOrAddr(u.Elem())
	case *types.Map:
		return typeHandsOutReachOrAddr(u.Key()) || typeHandsOutReachOrAddr(u.Elem())
	default:
		return true
	}
}

func isPureFreshDataValue(settledGlobals settledGlobalMap, v *flowir.Value) bool {
	return isPureFreshDataValueWith(v, settledGlobals.hasUnembedded)
}

func isPureFreshDataValueWith(v *flowir.Value, allowVar func(*types.Var) bool) bool {
	return checkPureOrFreshValue(v, valuePurityPolicy{
		allowVar:        allowVar,
		allowAppend:     true,
		allowValuePlane: true,
		allowRuntimeOps: true,
	})
}

func isPureConstantOrCompositeDataValue(v *flowir.Value) bool {
	return checkPureOrFreshValue(v, valuePurityPolicy{})
}

func checkPureOrFreshValue(v *flowir.Value, pol valuePurityPolicy) bool {
	if v == nil || v.IsTypeExpr || v.Type == nil {
		return false
	}
	if !pol.allowSyncNoCopy && refconfine.TypeReachesSyncNoCopyByValue(v.Type) {
		return false
	}
	if pol.allowNonMutableReach {
		if !typeHandsOutReachOrAddr(v.Type) {
			if refconfine.TypeCarriesSignature(v.Type) {
				return pol.allowSigLeaf != nil && pol.allowSigLeaf(v)
			}
			return true
		}
	}
	if v.IsConst || v.IsNil {
		return true
	}
	switch v.Kind {
	case flowir.ValScalarLitOrConst:
		return true

	case flowir.ValPlace:
		if v.Place.Root == flowir.RootConstOrNil {
			return true
		}
		if pol.allowPlace != nil {
			return pol.allowPlace(v)
		}
		if len(v.Place.Projs) == 0 && v.Place.Obj != nil && pol.allowVar != nil {
			return pol.allowVar(v.Place.Obj)
		}
		return false

	case flowir.ValAllocFresh:
		if pol.allocTypeOK != nil && !pol.allocTypeOK(v.Type) {
			return false
		}
		switch v.AllocKind {
		case flowir.AllocMake:
			if pol.ignoreSizeAndIndexArgs {
				return true
			}
			for _, a := range v.Args {
				if !checkPureOrFreshValue(a, pol) {
					return false
				}
			}
			return true
		case flowir.AllocBuiltinNewType:
			return true
		case flowir.AllocBuiltinNewExpr:
			if len(v.Args) != 1 || v.Ellipsis {
				return false
			}
			if pol.elemOK != nil {
				return pol.elemOK(v.Args[0])
			}
			return checkPureOrFreshValue(v.Args[0], pol)
		case flowir.AllocCompositeLit:
			if v.ElemType == nil ||
				(!pol.allowNonMutableReach && !pol.skipContainerElems && refconfine.TypeCarriesSignature(v.ElemType)) ||
				(!pol.allowSyncNoCopy && refconfine.TypeReachesSyncNoCopyByValue(v.ElemType)) {
				return false
			}
			if pol.skipContainerElems {
				return true
			}
			checkElem := pol.elemOK
			if checkElem == nil {
				checkElem = func(el *flowir.Value) bool { return checkPureOrFreshValue(el, pol) }
			}
			for i := range v.CompositeElts {
				elt := &v.CompositeElts[i]
				if elt.MapKey != nil && !checkElem(elt.MapKey) {
					return false
				}
				if !pol.ignoreSizeAndIndexArgs && elt.Index != nil && !checkPureOrFreshValue(elt.Index, pol) {
					return false
				}
				if !checkElem(elt.Value) {
					return false
				}
			}
			return true
		default:
			return false
		}

	case flowir.ValConvert:
		if v.Arg == nil {
			return false
		}
		if v.IsTypeAssert && !pol.allowTypeAssert {
			return false
		}
		if pol.convertOK != nil {
			if !pol.convertOK(v) {
				return false
			}
		} else if syntaxutil.IsUnsafePointerType(v.Type) || syntaxutil.IsUnsafePointerType(v.Arg.Type) {
			return false
		}
		return checkPureOrFreshValue(v.Arg, pol)

	case flowir.ValCompare:
		if !pol.allowRuntimeOps || v.Left == nil || v.Right == nil {
			return false
		}
		if (!v.Left.IsNil && !v.Right.IsNil) &&
			(refconfine.TypeContainsRefOrPointer(v.Left.Type) || refconfine.TypeContainsRefOrPointer(v.Right.Type)) {
			return false
		}
		return checkPureOrFreshValue(v.Left, pol) && checkPureOrFreshValue(v.Right, pol)

	case flowir.ValCompositeExpr:
		if !pol.allowRuntimeOps || len(v.Args) == 0 || refconfine.TypeContainsRefOrPointer(v.Type) {
			return false
		}
		for _, a := range v.Args {
			if !checkPureOrFreshValue(a, pol) {
				return false
			}
		}
		return true

	case flowir.ValCall:
		switch v.CallKind {
		case flowir.CallBuiltin:
			switch v.BuiltinName {
			case "Sizeof", "Alignof", "Offsetof":
				return true
			case "append":
				if !pol.allowAppend || len(v.Args) == 0 || v.Args[0] == nil {
					return false
				}
				// Unless preserveAppendBasePlace is set (local fresh-allocation GFPs),
				// appending onto a variable-backed slice could mutate its spare capacity;
				// require a variable-free fresh base expression for append.
				basePol := pol
				if !pol.preserveAppendBasePlace {
					basePol.allowVar = nil
					basePol.allowPlace = nil
				}
				if !checkPureOrFreshValue(v.Args[0], basePol) {
					return false
				}
				if pol.skipContainerElems {
					return true
				}
				if pol.elemOK != nil {
					if v.Ellipsis {
						return len(v.Args) == 2 && pol.elemOK(v.Args[1])
					}
					for _, a := range v.Args[1:] {
						if !pol.elemOK(a) {
							return false
						}
					}
					return true
				}
				for _, a := range v.Args[1:] {
					if !checkPureOrFreshValue(a, pol) {
						return false
					}
				}
				return true
			default:
				return false
			}
		case flowir.CallPlain:
			if !pol.allowValuePlane || v.IsMethodExprCall || v.CalleeFunc == nil {
				return false
			}
			if !auditset.ValuePlaneClone(v.CalleePkg, v.CalleeFunc.Origin().Name()) {
				return false
			}
			for _, a := range v.Args {
				if !checkPureOrFreshValue(a, pol) {
					return false
				}
			}
			return true
		default:
			return false
		}

	default:
		return false
	}
}

func isZeroSyncOnceValue(v *flowir.Value) bool {
	if v == nil || v.Kind != flowir.ValAllocFresh || v.AllocKind != flowir.AllocCompositeLit || len(v.CompositeElts) != 0 || v.Type == nil {
		return false
	}
	named, ok := types.Unalias(v.Type).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "sync" && named.Obj().Name() == "Once"
}

func isNilInterfaceValue(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	if v.Kind == flowir.ValScalarLitOrConst && v.IsNil {
		return true
	}
	if v.Kind == flowir.ValConvert && !v.IsTypeAssert && v.Type != nil && types.IsInterface(v.Type) {
		return isNilInterfaceValue(v.Arg)
	}
	return false
}

func isTypedNilNonInterfaceValue(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	if v.Kind == flowir.ValScalarLitOrConst && v.IsNil {
		return true
	}
	if v.Kind == flowir.ValConvert && !v.IsTypeAssert && v.Type != nil && !types.IsInterface(v.Type) {
		return isTypedNilNonInterfaceValue(v.Arg)
	}
	return false
}

func isZeroFieldInitValue(fieldType types.Type, v *flowir.Value) bool {
	if fieldType == nil || v == nil {
		return false
	}
	if isZeroSyncOnceValue(v) {
		return true
	}
	if types.IsInterface(fieldType) {
		return isNilInterfaceValue(v)
	}
	if isTypedNilNonInterfaceValue(v) {
		return true
	}
	if v.Kind == flowir.ValAllocFresh && v.AllocKind == flowir.AllocCompositeLit && len(v.CompositeElts) == 0 && v.Type != nil {
		if _, isPtr := types.Unalias(v.Type).Underlying().(*types.Pointer); !isPtr {
			switch types.Unalias(fieldType).Underlying().(type) {
			case *types.Struct, *types.Array:
				return true
			}
		}
	}
	return false
}

// isCarrierEmptySlotValue reports whether v produces a value for slotType whose
// every dynamic-carrier or function-signature slot is provably nil/zero (and
// contains no sync.noCopy value).
func isCarrierEmptySlotValue(audited bool, slotType types.Type, v *flowir.Value) bool {
	if slotType == nil || v == nil {
		return false
	}
	if refconfine.TypeReachesSyncNoCopyByValue(slotType) {
		return false
	}
	if !refconfine.TypeMayCarryUnknownDynamic(audited, slotType) && !refconfine.TypeCarriesSignature(slotType) {
		return true
	}
	if types.IsInterface(slotType) {
		return isNilInterfaceValue(v)
	}
	if isTypedNilNonInterfaceValue(v) {
		return true
	}
	if v.Kind != flowir.ValAllocFresh || v.Type == nil {
		return false
	}
	switch v.AllocKind {
	case flowir.AllocMake, flowir.AllocBuiltinNewType:
		return true
	case flowir.AllocBuiltinNewExpr:
		ptr, ok := types.Unalias(slotType).Underlying().(*types.Pointer)
		return ok && len(v.Args) == 1 && !v.Ellipsis && isCarrierEmptySlotValue(audited, ptr.Elem(), v.Args[0])
	case flowir.AllocCompositeLit:
		targetT := slotType
		if _, vIsPtr := types.Unalias(v.Type).Underlying().(*types.Pointer); vIsPtr {
			slotPtr, ok := types.Unalias(targetT).Underlying().(*types.Pointer)
			if !ok {
				return false
			}
			targetT = slotPtr.Elem()
		}
		switch u := types.Unalias(targetT).Underlying().(type) {
		case *types.Struct:
			for i := range v.CompositeElts {
				elt := &v.CompositeElts[i]
				if elt.Field == nil || !isCarrierEmptySlotValue(audited, elt.Field.Type(), elt.Value) {
					return false
				}
			}
			return true
		case *types.Array, *types.Slice:
			elemT := u.(interface{ Elem() types.Type }).Elem()
			for i := range v.CompositeElts {
				if !isCarrierEmptySlotValue(audited, elemT, v.CompositeElts[i].Value) {
					return false
				}
			}
			return true
		case *types.Map:
			for i := range v.CompositeElts {
				elt := &v.CompositeElts[i]
				if elt.MapKey == nil ||
					!isCarrierEmptySlotValue(audited, u.Key(), elt.MapKey) ||
					!isCarrierEmptySlotValue(audited, u.Elem(), elt.Value) {
					return false
				}
			}
			return true
		default:
			return false
		}
	default:
		return false
	}
}
