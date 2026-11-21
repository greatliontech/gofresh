package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (s *refConfinementSolver) verifyGlobalPreChecks() bool {
	for v := range s.taintedCarrier {
		if v.Parent() == s.p.Types.Scope() {
			return s.reject(v.Pos(), "tainted package-scope variable "+v.Name())
		}
	}
	return s.walkAllBodies(func(b *flowir.Body, enclFunc *types.Func, _ bool) bool {
		if len(b.Results) == 0 || s.canPropagateReturn(enclFunc) {
			return true
		}
		for _, rv := range b.Results {
			if rv != nil && s.taintedCarrier[rv] {
				return s.reject(rv.Pos(), "tainted named result variable "+rv.Name())
			}
		}
		return true
	})
}

func (s *refConfinementSolver) verifyCapsuleAndSeedStructGlobals() bool {
	if len(s.capsuleStructs) > 0 && !verifyCapsuleStructsWriteFree(s.p, s.capsuleStructs) {
		return s.reject(token.NoPos, "capsule struct write-free check failed")
	}

	if len(s.propagatedStructs) > 0 {
		scope := s.p.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			switch x := obj.(type) {
			case *types.Var:
				if typeMentionsSeedStruct(x.Type(), s.isPropagatedStruct) {
					return s.reject(x.Pos(), "field-propagated struct in package-scope variable "+x.Name())
				}
			case *types.Func:
				if x.Exported() && typeMentionsSeedStruct(x.Type(), s.isPropagatedStruct) {
					return s.reject(x.Pos(), "field-propagated struct in exported function signature "+x.Name())
				}
			case *types.TypeName:
				if x.Exported() {
					if typeMentionsSeedStruct(x.Type(), s.isPropagatedStruct) {
						return s.reject(x.Pos(), "field-propagated struct in exported type "+x.Name())
					}
					if named, isN := types.Unalias(x.Type()).(*types.Named); isN {
						mset := types.NewMethodSet(types.NewPointer(named))
						for mi := 0; mi < mset.Len(); mi++ {
							if m := mset.At(mi).Obj(); m != nil && m.Exported() && typeMentionsSeedStruct(m.Type(), s.isPropagatedStruct) {
								return s.reject(m.Pos(), "field-propagated struct in exported method signature "+m.Name())
							}
						}
					}
				}
			}
		}
		for id, inst := range s.info.Instances {
			if inst.TypeArgs != nil {
				for ti := 0; ti < inst.TypeArgs.Len(); ti++ {
					if typeMentionsSeedStruct(inst.TypeArgs.At(ti), s.isPropagatedStruct) {
						return s.reject(id.Pos(), "field-propagated struct in generic type argument")
					}
				}
			}
		}
	}

	if s.cfg.ForbidNonNilSeedStructPtrCompare {
		hasMapWithSeedKey := func(root types.Type) bool {
			seen := map[types.Type]bool{}
			hit := false
			var walk func(t types.Type)
			walk = func(t types.Type) {
				if t == nil || hit {
					return
				}
				t = types.Unalias(t)
				if seen[t] {
					return
				}
				seen[t] = true
				switch u := t.Underlying().(type) {
				case *types.Map:
					if s.typeContainsPtrToSeedStruct(u.Key()) {
						hit = true
						return
					}
					walk(u.Key())
					walk(u.Elem())
				case *types.Pointer:
					walk(u.Elem())
				case *types.Slice:
					walk(u.Elem())
				case *types.Array:
					walk(u.Elem())
				case *types.Chan:
					walk(u.Elem())
				case *types.Struct:
					for i := 0; i < u.NumFields(); i++ {
						walk(u.Field(i).Type())
					}
				case *types.Signature:
					if u.Params() != nil {
						for i := 0; i < u.Params().Len(); i++ {
							walk(u.Params().At(i).Type())
						}
					}
					if u.Results() != nil {
						for i := 0; i < u.Results().Len(); i++ {
							walk(u.Results().At(i).Type())
						}
					}
				}
			}
			walk(root)
			return hit
		}
		for expr, tv := range s.info.Types {
			if hasMapWithSeedKey(tv.Type) {
				return s.reject(expr.Pos(), "map keyed by protected struct pointer")
			}
		}
		for id, obj := range s.info.Defs {
			if obj != nil && hasMapWithSeedKey(obj.Type()) {
				return s.reject(id.Pos(), "map keyed by protected struct pointer")
			}
		}
	}
	return true
}

func (s *refConfinementSolver) checkLHSPlaceOK(dst flowir.Place, isFreshDef bool, inSyncAllowed bool) bool {
	if s.placeMutatesTaintedTarget(dst) ||
		(!inSyncAllowed && placeHitsStructPred(dst, s.isSeedStruct, true)) ||
		s.placeHitsPropagated(dst, !isFreshDef) {
		return s.reject(dst.RootPos, "mutates tainted or protected target")
	}
	if _, key, isMapW := dst.AsMapWrite(); isMapW && key != nil {
		if _, kCar := s.classifyValue(key); kCar {
			return s.reject(valPos(key), "tainted map key")
		}
	}
	return true
}

func (s *refConfinementSolver) checkAllocValueOK(v *flowir.Value, inSyncAllowed bool) bool {
	switch v.AllocKind {
	case flowir.AllocBuiltinNewType:
		return true
	case flowir.AllocBuiltinNewExpr:
		if len(v.Args) == 1 && v.Args[0] != nil {
			if s.seedStructTypeViolated(nil, v.Args[0].Type) {
				return s.reject(valPos(v), "new(expr) on protected struct")
			}
			if _, aCar := s.classifyValue(v.Args[0]); aCar {
				return s.reject(valPos(v), "new(expr) on tainted value")
			}
			return s.checkValueOK(v.Args[0], inSyncAllowed)
		}
		return true
	case flowir.AllocMake:
		for _, a := range v.Args {
			if a == nil {
				continue
			}
			if s.seedStructTypeViolated(nil, a.Type) {
				return s.reject(valPos(a), "make arg seed struct violation")
			}
			if _, aCar := s.classifyValue(a); aCar {
				return s.reject(valPos(a), "make arg tainted")
			}
			if !s.checkValueOK(a, inSyncAllowed) {
				return false
			}
		}
		return true
	case flowir.AllocCompositeLit:
		cl := allocCompositeLitAST(v)
		if cl == nil {
			return v.ForEachChildValue(func(cv *flowir.Value) bool { return s.checkValueOK(cv, inSyncAllowed) })
		}
		clT := s.info.TypeOf(cl)
		if clT == nil {
			return v.ForEachChildValue(func(cv *flowir.Value) bool { return s.checkValueOK(cv, inSyncAllowed) })
		}
		baseT := types.Unalias(clT)
		if ptr, isP := baseT.(*types.Pointer); isP {
			baseT = types.Unalias(ptr.Elem())
		}
		_, isSlice := baseT.Underlying().(*types.Slice)
		_, isArray := baseT.Underlying().(*types.Array)
		_, isMap := baseT.Underlying().(*types.Map)
		_, isStruct := baseT.Underlying().(*types.Struct)
		allowedSeedSt := isStruct && s.isAllowedStructCompositeLit(v)

		for i := range v.CompositeElts {
			elt := &v.CompositeElts[i]
			if elt.MapKey != nil {
				if isMap && s.seedStructTypeViolated(baseT.Underlying().(*types.Map).Key(), elt.MapKey.Type) {
					return s.reject(valPos(elt.MapKey), "map key seed struct violation")
				}
				if _, kCar := s.classifyValue(elt.MapKey); kCar {
					return s.reject(valPos(elt.MapKey), "tainted composite map key")
				}
				if !s.checkValueOK(elt.MapKey, inSyncAllowed) {
					return false
				}
			}
			if elt.Index != nil && !s.checkValueOK(elt.Index, inSyncAllowed) {
				return false
			}
			if elt.Value == nil {
				continue
			}
			if !s.checkValueOK(elt.Value, inSyncAllowed) {
				return false
			}
			var dstElemT types.Type
			switch {
			case isSlice:
				dstElemT = baseT.Underlying().(*types.Slice).Elem()
			case isArray:
				dstElemT = baseT.Underlying().(*types.Array).Elem()
			case isMap:
				dstElemT = baseT.Underlying().(*types.Map).Elem()
			case isStruct && elt.Field != nil:
				dstElemT = elt.Field.Type()
			}
			if s.seedStructTypeViolated(dstElemT, elt.Value.Type) {
				return s.reject(valPos(elt.Value), "composite element seed struct violation")
			}
			if _, vCar := s.classifyValue(elt.Value); !vCar {
				continue
			}
			if !isSlice && !isArray && !allowedSeedSt {
				return s.reject(valPos(elt.Value), "tainted composite element in disallowed type")
			}
			if dstElemT == nil || assignErasesTaint(dstElemT, elt.Value.Type) {
				return s.reject(valPos(elt.Value), "composite element erases taint")
			}
		}
		return true
	}
	return true
}

func (s *refConfinementSolver) checkCallValueOK(v *flowir.Value, inSyncAllowed bool) bool {
	if !inSyncAllowed && v.CallAST != nil && callMutatesSeedStructContainer(s.info, v.CallAST, s.isSeedStruct) {
		return s.reject(valPos(v), "call mutates seed struct container")
	}
	if v.CallKind == flowir.CallMethod && !v.IsMethodExprCall && v.Selection != nil &&
		v.Selection.Kind() == types.MethodVal && !v.Selection.Indirect() && SelectionHasPointerReceiver(v.Selection) {
		if (!inSyncAllowed && valueOrPlaceHitsStructPred(v.Recv, v.RecvPlace, v.HasRecvPlace, s.isSeedStruct, false)) ||
			s.valueOrPlaceHitsPropagated(v.Recv, v.RecvPlace, v.HasRecvPlace, false) {
			return s.reject(valPos(v), "auto-addressed pointer-receiver method call on protected struct")
		}
	}
	if callValueErasesSeedStruct(v, s.seedStructTypeViolated, s.cfg.AllowCallArg) {
		return s.reject(valPos(v), "call arg erases seed struct")
	}

	if v.CallKind == flowir.CallMethod && !v.IsMethodExprCall && v.Selection != nil && v.Selection.Kind() == types.MethodVal {
		if _, rCar := s.classifyValue(v.Recv); rCar {
			if callee := s.resolveConcretePkgCalleeVal(v); callee != nil {
				// Taint propagated to callee's receiver parameter.
			} else if v.Selection.Recv() != nil && !types.IsInterface(v.Selection.Recv()) && s.cfg.AllowMethodRecv != nil && v.CallAST != nil && v.CalleeSel != nil {
				mFn, _ := v.Selection.Obj().(*types.Func)
				if !s.cfg.AllowMethodRecv(v.CallAST, mFn, v.CalleeSel.X) {
					return s.reject(valPos(v), "disallowed method call on tainted receiver")
				}
			} else {
				return s.reject(valPos(v), "unapproved method call on tainted receiver")
			}
		}
	} else if v.Callee != nil {
		if _, fCar := s.classifyValue(v.Callee); fCar {
			return s.reject(valPos(v), "indirect call on tainted callee")
		}
	}

	if !v.ForEachChildValue(func(cv *flowir.Value) bool { return s.checkValueOK(cv, inSyncAllowed) }) {
		return false
	}

	if v.CallKind == flowir.CallBuiltin {
		for argIdx, arg := range v.Args {
			if arg == nil {
				continue
			}
			aRef, aCar := s.classifyValue(arg)
			if !aCar {
				continue
			}
			if v.BuiltinName == "len" || v.BuiltinName == "cap" || v.BuiltinName == "Sizeof" || v.BuiltinName == "Alignof" || v.BuiltinName == "Offsetof" {
				continue
			}
			if v.BuiltinName == "append" {
				if argIdx == 0 {
					if !aRef && v.CallAST != nil && s.selfAssignedAppendCalls[v.CallAST] {
						continue
					}
					return s.reject(valPos(arg), "append into non-fresh or tainted-ref slice")
				}
				if v.Ellipsis {
					if sl, isSl := syntaxutil.UnderlyingType(arg.Type).(*types.Slice); isSl && !s.elemHasHandle(sl.Elem()) {
						continue
					}
				} else if v.CallAST != nil && s.selfAssignedAppendCalls[v.CallAST] {
					if sl, isSl := syntaxutil.UnderlyingType(v.Type).(*types.Slice); isSl && !assignErasesTaint(sl.Elem(), arg.Type) {
						continue
					}
				}
				return s.reject(valPos(arg), "append of tainted element")
			}
			if v.BuiltinName == "copy" && argIdx == 1 {
				if sl, isSl := syntaxutil.UnderlyingType(arg.Type).(*types.Slice); isSl && !s.elemHasHandle(sl.Elem()) {
					continue
				}
			}
			if v.CallAST != nil && argIdx < len(v.CallAST.Args) && s.cfg.AllowCallArg != nil && s.cfg.AllowCallArg(v.CallAST, argIdx, v.CallAST.Args[argIdx]) {
				continue
			}
			return s.reject(valPos(arg), "tainted argument to builtin "+v.BuiltinName)
		}
		return true
	}

	if v.IsMethodExprCall {
		if v.Recv != nil {
			if _, rCar := s.classifyValue(v.Recv); rCar {
				if !(v.CallAST != nil && len(v.CallAST.Args) > 0 && s.cfg.AllowCallArg != nil && s.cfg.AllowCallArg(v.CallAST, 0, v.CallAST.Args[0])) {
					return s.reject(valPos(v.Recv), "tainted receiver in method expression call")
				}
			}
		}
		for i, arg := range v.Args {
			if arg == nil {
				continue
			}
			if _, aCar := s.classifyValue(arg); !aCar {
				continue
			}
			rawIdx := i + 1
			if v.CallAST != nil && rawIdx < len(v.CallAST.Args) && s.cfg.AllowCallArg != nil && s.cfg.AllowCallArg(v.CallAST, rawIdx, v.CallAST.Args[rawIdx]) {
				continue
			}
			return s.reject(valPos(arg), "tainted argument in method expression call")
		}
		return true
	}

	callee := s.resolveConcretePkgCalleeVal(v)
	isTupleUnpack := len(v.Args) == 1 && !v.Ellipsis && v.Args[0] != nil && v.Args[0].Type != nil
	if isTupleUnpack {
		_, isTupleUnpack = types.Unalias(v.Args[0].Type).(*types.Tuple)
	}
	callOK := true
	v.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, slotIdx int, paramIdx int, okP bool, packedVariadic bool) bool {
		var aCar bool
		if isTupleUnpack {
			_, aCar = s.classifyMultiReturnSlot(arg, slotIdx, slotType)
		} else {
			_, aCar = s.classifyValue(arg)
		}
		if !aCar {
			return true
		}
		if callee != nil {
			if !okP {
				callOK = s.reject(valPos(arg), "missing formal param on intra-pkg call")
				return false
			}
			pt := v.FormalParamSlotType(paramIdx, packedVariadic)
			if (s.cfg.AllowIntraPkgInterfaceParam && !packedVariadic && pt != nil && types.IsInterface(pt)) || !assignErasesTaint(pt, slotType) {
				return true
			}
		}
		if !isTupleUnpack && v.CallAST != nil && slotIdx < len(v.CallAST.Args) && s.cfg.AllowCallArg != nil && s.cfg.AllowCallArg(v.CallAST, slotIdx, v.CallAST.Args[slotIdx]) {
			return true
		}
		callOK = s.reject(valPos(arg), "unapproved tainted call argument")
		return false
	})
	return callOK
}

func (s *refConfinementSolver) checkValueOK(v *flowir.Value, inSyncAllowed bool) bool {
	if v == nil {
		return true
	}
	switch v.Kind {
	case flowir.ValPlace:
		return v.Place.ForEachChildValue(func(cv *flowir.Value) bool { return s.checkValueOK(cv, inSyncAllowed) })

	case flowir.ValCompare:
		if s.cfg.ForbidNonNilSeedStructPtrCompare && (v.CompareOp == token.EQL || v.CompareOp == token.NEQ) && v.Left != nil && v.Right != nil {
			if (s.isPtrToSeedStruct(v.Left.Type) && !v.Right.IsNil) ||
				(s.isPtrToSeedStruct(v.Right.Type) && !v.Left.IsNil) {
				return s.reject(valPos(v), "non-nil seed struct pointer comparison")
			}
		}
		return s.checkValueOK(v.Left, inSyncAllowed) && s.checkValueOK(v.Right, inSyncAllowed)

	case flowir.ValMethodVal:
		if v.Selection != nil && v.Selection.Kind() == types.MethodVal && !v.Selection.Indirect() && SelectionHasPointerReceiver(v.Selection) {
			if (!inSyncAllowed && valueOrPlaceHitsStructPred(v.Recv, v.RecvPlace, v.HasRecvPlace, s.isSeedStruct, false)) ||
				s.valueOrPlaceHitsPropagated(v.Recv, v.RecvPlace, v.HasRecvPlace, false) {
				return s.reject(valPos(v), "auto-addressed pointer-receiver method value on protected struct")
			}
		}
		_, xCar, mutX, seedX := s.methodValHasTaintedOrSeedRecv(v)
		if xCar || mutX || seedX {
			if _, okM := s.boundPkgMethodRecvVal(v); !okM {
				return s.reject(valPos(v), "unapproved bound method value")
			}
		}
		return s.checkValueOK(v.Recv, inSyncAllowed)

	case flowir.ValAddrOf:
		if s.placeMutatesTaintedTarget(v.AddrPlace) ||
			(!inSyncAllowed && placeHitsStructPred(v.AddrPlace, s.isSeedStruct, false)) ||
			s.placeHitsPropagated(v.AddrPlace, false) {
			return s.reject(valPos(v), "address-of or array-slice on tainted or protected place")
		}
		return v.ForEachChildValue(func(cv *flowir.Value) bool { return s.checkValueOK(cv, inSyncAllowed) })

	case flowir.ValChanRecv:
		if _, cCar := s.classifyValue(v.Chan); cCar {
			return s.reject(valPos(v), "receive from tainted channel")
		}
		return s.checkValueOK(v.Chan, inSyncAllowed)

	case flowir.ValConvert:
		if v.IsTypeAssert {
			if _, xCar := s.classifyValue(v.Arg); xCar {
				return s.reject(valPos(v), "type assertion on tainted value")
			}
			return s.checkValueOK(v.Arg, inSyncAllowed)
		}
		if v.Arg != nil {
			if s.seedStructTypeViolated(v.Type, v.Arg.Type) {
				return s.reject(valPos(v), "seed struct conversion violation")
			}
			if _, aCar := s.classifyValue(v.Arg); aCar && assignErasesTaint(v.Type, v.Arg.Type) {
				return s.reject(valPos(v), "conversion erases taint")
			}
		}
		return s.checkValueOK(v.Arg, inSyncAllowed)

	case flowir.ValAllocFresh:
		return s.checkAllocValueOK(v, inSyncAllowed)

	case flowir.ValCall:
		return s.checkCallValueOK(v, inSyncAllowed)

	default:
		return v.ForEachChildValue(func(cv *flowir.Value) bool { return s.checkValueOK(cv, inSyncAllowed) })
	}
}

func (s *refConfinementSolver) checkAssignOpOK(op *flowir.Op, inSyncAllowed bool) bool {
	for _, dst := range op.Dsts {
		if !dst.ForEachChildValue(func(cv *flowir.Value) bool { return s.checkValueOK(cv, inSyncAllowed) }) {
			return false
		}
	}
	for _, src := range op.Srcs {
		if !s.checkValueOK(src, inSyncAllowed) {
			return false
		}
	}
	switch op.AssignKind {
	case flowir.AssignZeroDecl:
		for idxDst, dst := range op.Dsts {
			isDef := idxDst < len(op.DstDefs) && op.DstDefs[idxDst] && dst.IsBareVar()
			if !s.checkLHSPlaceOK(dst, isDef, inSyncAllowed) {
				return false
			}
		}

	case flowir.AssignIncDec:
		for _, dst := range op.Dsts {
			if !s.checkLHSPlaceOK(dst, false, inSyncAllowed) {
				return false
			}
		}

	case flowir.AssignCompound:
		for idxDst, dst := range op.Dsts {
			if !s.checkLHSPlaceOK(dst, false, inSyncAllowed) {
				return false
			}
			if idxDst < len(op.Srcs) && op.Srcs[idxDst] != nil && len(op.Srcs[idxDst].Args) == 2 {
				rhs := op.Srcs[idxDst].Args[1]
				if rhs != nil {
					if s.seedStructTypeViolated(dst.Type, rhs.Type) {
						return s.reject(valPos(rhs), "compound assign seed struct violation")
					}
					if _, rCar := s.classifyValue(rhs); rCar {
						return s.reject(valPos(rhs), "compound assign tainted rhs")
					}
				}
			}
		}

	case flowir.AssignPlain:
		pairsOK := true
		op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
			if !s.checkLHSPlaceOK(dst, isDef && dst.IsBareVar(), inSyncAllowed) {
				pairsOK = false
				return false
			}
			if src == nil {
				return true
			}
			if !dst.IsBlank() && s.seedStructTypeViolated(dst.Type, src.Type) {
				pairsOK = s.reject(valPos(src), "assign seed struct violation")
				return false
			}
			rRef, rCar := s.classifyValue(src)
			if !rCar || dst.IsBlank() {
				return true
			}
			if dst.IsBareVar() {
				if assignErasesTaint(dst.Obj.Type(), src.Type) {
					pairsOK = s.reject(valPos(src), "assign to bare var erases taint")
					return false
				}
				return true
			}
			if len(dst.Projs) == 1 && dst.Projs[0].Kind == flowir.ProjIndex && dst.Obj != nil && s.localFreshContainer[dst.Obj] {
				if !assignErasesTaint(dst.Type, src.Type) {
					return true
				}
			}
			if s.cfg.AllowAssignTarget != nil && dst.Raw != nil && src.Raw != nil &&
				!assignErasesTaint(dst.Type, src.Type) &&
				s.cfg.AllowAssignTarget(dst.Raw, src.Raw, rRef) {
				return true
			}
			pairsOK = s.reject(valPos(src), "assign tainted value to non-bare target")
			return false
		})
		return pairsOK

	case flowir.AssignMulti:
		for idxDst, dst := range op.Dsts {
			isDef := idxDst < len(op.DstDefs) && op.DstDefs[idxDst] && dst.IsBareVar()
			if !s.checkLHSPlaceOK(dst, isDef, inSyncAllowed) {
				return false
			}
		}
		if len(op.Srcs) == 1 && op.Srcs[0] != nil {
			rhs := op.Srcs[0]
			rhsTup, _ := rhs.Type.(*types.Tuple)
			if rhsTup != nil {
				for idxDst, dst := range op.Dsts {
					if idxDst < rhsTup.Len() && !dst.IsBlank() && s.seedStructTypeViolated(dst.Type, rhsTup.At(idxDst).Type()) {
						return s.reject(valPos(rhs), "multi-assign seed struct violation")
					}
				}
			} else if len(op.Dsts) > 0 && !op.Dsts[0].IsBlank() && s.seedStructTypeViolated(op.Dsts[0].Type, rhs.Type) {
				return s.reject(valPos(rhs), "comma-ok assign seed struct violation")
			}
			for idxDst, dst := range op.Dsts {
				srcElemT := dst.Type
				if rhsTup != nil && idxDst < rhsTup.Len() {
					srcElemT = rhsTup.At(idxDst).Type()
				}
				if _, sCar := s.classifyMultiReturnSlot(rhs, idxDst, srcElemT); !sCar || dst.IsBlank() {
					continue
				}
				if !dst.IsBareVar() || (srcElemT != nil && assignErasesTaint(dst.Obj.Type(), srcElemT)) {
					return s.reject(valPos(rhs), "multi-assign tainted value to non-bare or erasing target")
				}
			}
		}

	case flowir.AssignRange:
		for idxDst, dst := range op.Dsts {
			isDef := idxDst < len(op.DstDefs) && op.DstDefs[idxDst]
			if !isDef && !dst.IsBlank() && !s.checkLHSPlaceOK(dst, false, inSyncAllowed) {
				return false
			}
		}
		if len(op.Srcs) == 1 && op.Srcs[0] != nil {
			rngX := op.Srcs[0]
			if _, xCar := s.classifyValue(rngX); xCar {
				for idxDst, dst := range op.Dsts {
					isDef := idxDst < len(op.DstDefs) && op.DstDefs[idxDst]
					if isDef || dst.IsBlank() {
						continue
					}
					if _, pCar := s.projectedClassify(dst.Type, rngX.Raw); !pCar {
						continue
					}
					if !dst.IsBareVar() {
						return s.reject(valPos(rngX), "range over tainted container into non-bare target")
					}
				}
			}
		}
	}
	return true
}

func (s *refConfinementSolver) checkReturnOpOK(op *flowir.Op, enclFunc *types.Func, inSyncAllowed bool) bool {
	for _, r := range op.Results {
		if !s.checkValueOK(r, inSyncAllowed) {
			return false
		}
	}
	if len(op.Results) == 1 && op.Results[0] != nil && (s.cfg.ForbidNonNilSeedStructPtrCompare || len(s.propagatedStructs) > 0) {
		if tup, isTup := op.Results[0].Type.(*types.Tuple); isTup {
			for ti := 0; ti < tup.Len(); ti++ {
				rT := tup.At(ti).Type()
				if enclFunc != nil && enclFunc.Signature().Results() != nil && ti < enclFunc.Signature().Results().Len() {
					if s.seedStructTypeViolated(enclFunc.Signature().Results().At(ti).Type(), rT) {
						return s.reject(valPos(op.Results[0]), "tuple return seed struct violation")
					}
				} else if (s.cfg.ForbidNonNilSeedStructPtrCompare && typeMentionsSeedStruct(rT, s.isSeedStruct)) ||
					(len(s.propagatedStructs) > 0 && typeMentionsSeedStruct(rT, s.isPropagatedStruct)) {
					return s.reject(valPos(op.Results[0]), "tuple return mentions protected struct")
				}
			}
		}
	}
	for ri, r := range op.Results {
		if r == nil {
			continue
		}
		if enclFunc != nil {
			res := enclFunc.Signature().Results()
			if ri < res.Len() {
				if s.seedStructTypeViolated(res.At(ri).Type(), r.Type) {
					return s.reject(valPos(r), "return seed struct violation")
				}
			} else if (s.cfg.ForbidNonNilSeedStructPtrCompare && typeMentionsSeedStruct(r.Type, s.isSeedStruct)) ||
				(len(s.propagatedStructs) > 0 && typeMentionsSeedStruct(r.Type, s.isPropagatedStruct)) {
				return s.reject(valPos(r), "return mentions protected struct")
			}
		} else if s.isSeedStruct(syntaxutil.DerefNamedStruct(r.Type)) ||
			(s.cfg.ForbidNonNilSeedStructPtrCompare && typeMentionsSeedStruct(r.Type, s.isSeedStruct)) ||
			(len(s.propagatedStructs) > 0 && typeMentionsSeedStruct(r.Type, s.isPropagatedStruct)) {
			return s.reject(valPos(r), "closure return mentions protected struct")
		}
		if len(op.Results) == 1 {
			if tup, isTup := r.Type.(*types.Tuple); isTup {
				for ti := 0; ti < tup.Len(); ti++ {
					st := tup.At(ti).Type()
					if _, sCar := s.classifyMultiReturnSlot(r, ti, st); !sCar {
						continue
					}
					if !s.canPropagateReturn(enclFunc) {
						return s.reject(valPos(r), "disallowed tuple return of tainted value")
					}
					res := enclFunc.Signature().Results()
					if ti >= res.Len() || assignErasesTaint(res.At(ti).Type(), st) {
						return s.reject(valPos(r), "tuple return erases taint")
					}
				}
				continue
			}
		}
		if _, rCar := s.classifyValue(r); !rCar {
			continue
		}
		if !s.canPropagateReturn(enclFunc) {
			return s.reject(valPos(r), "disallowed return of tainted value")
		}
		res := enclFunc.Signature().Results()
		if ri >= res.Len() || assignErasesTaint(res.At(ri).Type(), r.Type) {
			return s.reject(valPos(r), "return erases taint")
		}
	}
	return true
}

func (s *refConfinementSolver) checkBodyOpsOK(b *flowir.Body, enclFunc *types.Func, inSyncAllowed bool) bool {
	for i := range b.Ops {
		op := &b.Ops[i]
		switch op.Kind {
		case flowir.OpAssign:
			if !s.checkAssignOpOK(op, inSyncAllowed) {
				return false
			}

		case flowir.OpTypeSwitchBind:
			if !s.checkValueOK(op.SwitchSrc, inSyncAllowed) {
				return false
			}
			if _, sCar := s.classifyValue(op.SwitchSrc); sCar {
				return s.reject(valPos(op.SwitchSrc), "type switch on tainted value")
			}
			if s.cfg.ForbidNonNilSeedStructPtrCompare && op.SwitchAST != nil && op.SwitchAST.Body != nil {
				for _, raw := range op.SwitchAST.Body.List {
					if cc, okCC := raw.(*ast.CaseClause); okCC {
						for _, ce := range cc.List {
							if !syntaxutil.IsNilIdent(s.info, ce) && s.isPtrToSeedStruct(s.info.TypeOf(ce)) {
								return s.reject(ce.Pos(), "type switch case on pointer to seed struct")
							}
						}
					}
				}
			}

		case flowir.OpChanSend:
			if !op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool { return s.checkValueOK(cv, inSyncAllowed) }) ||
				!s.checkValueOK(op.ChanVal, inSyncAllowed) || !s.checkValueOK(op.SendVal, inSyncAllowed) {
				return false
			}
			if op.ChanVal != nil && op.SendVal != nil {
				if ch, isCh := syntaxutil.UnderlyingType(op.ChanVal.Type).(*types.Chan); isCh {
					if s.seedStructTypeViolated(ch.Elem(), op.SendVal.Type) {
						return s.reject(valPos(op.SendVal), "channel send seed struct violation")
					}
				} else if (s.cfg.ForbidNonNilSeedStructPtrCompare && typeMentionsSeedStruct(op.SendVal.Type, s.isSeedStruct)) ||
					(len(s.propagatedStructs) > 0 && typeMentionsSeedStruct(op.SendVal.Type, s.isPropagatedStruct)) {
					return s.reject(valPos(op.SendVal), "channel send mentions protected struct")
				}
			}
			if _, chCar := s.classifyValue(op.ChanVal); chCar {
				return s.reject(valPos(op.ChanVal), "send on tainted channel")
			}
			if _, vCar := s.classifyValue(op.SendVal); vCar {
				return s.reject(valPos(op.SendVal), "send of tainted value")
			}

		case flowir.OpReturn:
			if !s.checkReturnOpOK(op, enclFunc, inSyncAllowed) {
				return false
			}

		case flowir.OpDefer:
			if !s.checkValueOK(op.Call, inSyncAllowed) {
				return false
			}

		case flowir.OpGo:
			if !s.checkValueOK(op.Call, !s.cfg.ForbidNonNilSeedStructPtrCompare) {
				return false
			}

		case flowir.OpExpr:
			if s.cfg.ForbidNonNilSeedStructPtrCompare {
				switch st := op.StmtAST.(type) {
				case *ast.CaseClause:
					if op.Expr != nil && !op.Expr.IsNil && s.isPtrToSeedStruct(op.Expr.Type) {
						return s.reject(valPos(op.Expr), "switch case on pointer to seed struct")
					}
				case *ast.SwitchStmt:
					if op.Expr != nil && s.isPtrToSeedStruct(op.Expr.Type) && st.Body != nil {
						for _, raw := range st.Body.List {
							if cc, okCC := raw.(*ast.CaseClause); okCC {
								for _, ce := range cc.List {
									if !syntaxutil.IsNilIdent(s.info, ce) {
										return s.reject(ce.Pos(), "switch on pointer to seed struct with non-nil case")
									}
								}
							}
						}
					}
				}
			}
			if !s.checkValueOK(op.Expr, inSyncAllowed) {
				return false
			}
		}
	}
	return true
}
