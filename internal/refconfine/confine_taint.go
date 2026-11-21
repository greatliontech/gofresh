package refconfine

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (s *refConfinementSolver) checkSeedExpr(expr ast.Expr) (bool, bool, bool) {
	if s.cfg.SeedExpr == nil || expr == nil {
		return false, false, false
	}
	unp := ast.Unparen(expr)
	if sRef, sCar := s.cfg.SeedExpr(unp); sRef || sCar {
		return sRef, sRef || sCar, true
	}
	return false, false, false
}

func (s *refConfinementSolver) isAllowedPropagatedCompositeLit(v *flowir.Value, cl *ast.CompositeLit) bool {
	if cl == nil || !s.cfg.AllowCompositeLitFieldPropagation || len(s.propagatedStructs) == 0 {
		return false
	}
	st := syntaxutil.DerefNamedStruct(s.info.TypeOf(cl))
	if st == nil || !s.propagatedStructs[st.Origin()] {
		return false
	}
	for i := range v.CompositeElts {
		elt := &v.CompositeElts[i]
		if _, vCar := s.classifyValue(elt.Value); vCar {
			if elt.Field == nil || !s.propagatedFields[elt.Field.Origin()] {
				return false
			}
		}
	}
	return true
}

func (s *refConfinementSolver) isAllowedStructCompositeLit(v *flowir.Value) bool {
	cl := allocCompositeLitAST(v)
	return s.isAllowedSeedStructCompositeLit(cl) || s.isAllowedPropagatedCompositeLit(v, cl)
}

func (s *refConfinementSolver) classifyPlacePrefix(pl flowir.Place, projCount int) (bool, bool) {
	var curRef, curCar bool
	prevRaw := pl.RootRaw
	if sRef, sCar, ok := s.checkSeedExpr(pl.RootRaw); ok {
		curRef, curCar = sRef, sCar
	} else if projCount == 0 && pl.Raw != nil && ast.Unparen(pl.Raw) != pl.RootRaw {
		if sRef, sCar, ok := s.checkSeedExpr(pl.Raw); ok {
			return sRef, sCar
		}
	}
	if !curRef && !curCar {
		switch pl.Root {
		case flowir.RootLocal, flowir.RootParam, flowir.RootRecv, flowir.RootResult, flowir.RootOuterVar, flowir.RootPkgGlobal:
			if pl.Obj != nil {
				curRef = s.taintedRef[pl.Obj]
				curCar = curRef || s.taintedCarrier[pl.Obj]
			}
		case flowir.RootTransient:
			if pl.Base != nil {
				curRef, curCar = s.classifyValue(pl.Base)
				if pl.Base.Raw != nil {
					prevRaw = ast.Unparen(pl.Base.Raw)
				}
			}
		}
	}
	for i := 0; i < projCount; i++ {
		pr := pl.Projs[i]
		if sRef, sCar, ok := s.checkSeedExpr(pr.Raw); ok {
			curRef, curCar = sRef, sCar
			prevRaw = pr.Raw
			continue
		}
		prefix := pl
		prefix.Projs = pl.Projs[:i+1]
		prefix.Type = pr.Type
		prefix.Raw = pr.Raw
		switch pr.Kind {
		case flowir.ProjField:
			if pr.Selection != nil && pr.Selection.Kind() == types.FieldVal {
				if s.cfg.IsExemptField != nil && !syntaxutil.SelectionCrossesEmbeddedPointer(pr.Selection) {
					if fv, isFV := pr.Selection.Obj().(*types.Var); isFV && s.cfg.IsExemptField(fv) {
						curRef, curCar = false, false
						prevRaw = pr.Raw
						continue
					}
				}
				ft := pr.Selection.Type()
				if s.placeChainHitsPropagatedField(prefix) {
					curRef, curCar = s.projectedClassify(ft, prevRaw)
				} else {
					seeded := false
					if s.placeChainHitsSeedStruct(prefix) {
						if s.isDirectRef(ft) {
							curRef, curCar = true, true
							seeded = true
						} else if s.carriesRef(ft) {
							curRef, curCar = false, true
							seeded = true
						}
					}
					if !seeded {
						if curCar {
							curRef, curCar = s.projectedClassify(ft, prevRaw)
						} else {
							curRef, curCar = false, false
						}
					}
				}
			} else {
				curRef, curCar = false, false
			}
		case flowir.ProjIndex:
			if curCar {
				curRef, curCar = s.projectedClassify(indexValueTypeFromType(pr.Type), prevRaw)
			} else {
				curRef, curCar = false, false
			}
		case flowir.ProjSlice:
			if curRef {
				curRef, curCar = true, true
			} else if curCar {
				curRef, curCar = false, true
			} else {
				curRef, curCar = false, false
			}
		case flowir.ProjDeref:
			if curCar {
				curRef, curCar = s.projectedClassify(pr.Type, prevRaw)
			} else {
				curRef, curCar = false, false
			}
		}
		prevRaw = pr.Raw
	}
	return curRef, curCar
}

func (s *refConfinementSolver) classifyPlace(pl flowir.Place) (bool, bool) {
	return s.classifyPlacePrefix(pl, len(pl.Projs))
}

func (s *refConfinementSolver) placeMutatesTaintedTarget(pl flowir.Place) bool {
	for i := len(pl.Projs) - 1; i >= 0; i-- {
		pr := pl.Projs[i]
		switch pr.Kind {
		case flowir.ProjDeref:
			if bRef, _ := s.classifyPlacePrefix(pl, i); bRef {
				return true
			}
		case flowir.ProjIndex:
			if pr.BaseType != nil {
				switch types.Unalias(pr.BaseType).Underlying().(type) {
				case *types.Slice, *types.Map, *types.Pointer:
					if bRef, _ := s.classifyPlacePrefix(pl, i); bRef {
						return true
					}
				}
			}
		case flowir.ProjField:
			if pr.Selection != nil && pr.Selection.Kind() == types.FieldVal {
				if pr.BaseType != nil {
					if _, isPtr := types.Unalias(pr.BaseType).Underlying().(*types.Pointer); isPtr {
						if bRef, _ := s.classifyPlacePrefix(pl, i); bRef {
							return true
						}
					}
				}
				if syntaxutil.SelectionCrossesEmbeddedPointer(pr.Selection) {
					if _, bCar := s.classifyPlacePrefix(pl, i); bCar {
						return true
					}
				}
			}
		case flowir.ProjSlice:
		}
	}
	if pl.Root == flowir.RootTransient && pl.Base != nil {
		if pl.Base.Kind == flowir.ValPlace {
			return s.placeMutatesTaintedTarget(pl.Base.Place)
		}
		if pl.Base.Kind == flowir.ValAddrOf && pl.Base.IsArraySlice {
			return s.placeMutatesTaintedTarget(pl.Base.AddrPlace)
		}
	}
	return false
}

func (s *refConfinementSolver) valueMutatesTaintedTarget(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	if v.Kind == flowir.ValPlace {
		return s.placeMutatesTaintedTarget(v.Place)
	}
	if v.Kind == flowir.ValAddrOf && v.IsArraySlice {
		return s.placeMutatesTaintedTarget(v.AddrPlace)
	}
	return false
}

func (s *refConfinementSolver) methodValHasTaintedOrSeedRecv(v *flowir.Value) (xRef, xCar, mutX, seedX bool) {
	if v == nil || v.Recv == nil {
		return false, false, false, false
	}
	xRef, xCar = s.classifyValue(v.Recv)
	if v.HasRecvPlace {
		mutX = s.placeMutatesTaintedTarget(v.RecvPlace)
	} else {
		mutX = s.valueMutatesTaintedTarget(v.Recv)
	}
	rxSt := syntaxutil.DerefNamedStruct(v.Recv.Type)
	seedX = s.isSeedStruct(rxSt) || s.isPropagatedStruct(rxSt)
	if !seedX && v.HasRecvPlace {
		seedX = s.placeChainHitsSeedStruct(v.RecvPlace) || s.placeChainHitsPropagatedField(v.RecvPlace)
	}
	return xRef, xCar, mutX, seedX
}

func (s *refConfinementSolver) classifyValue(v *flowir.Value) (bool, bool) {
	if v == nil {
		return false, false
	}
	if sRef, sCar, ok := s.checkSeedExpr(v.Raw); ok {
		return sRef, sCar
	}
	switch v.Kind {
	case flowir.ValPlace:
		return s.classifyPlace(v.Place)

	case flowir.ValMethodVal:
		_, xCar, mutX, seedX := s.methodValHasTaintedOrSeedRecv(v)
		if xCar || mutX || seedX {
			if _, okM := s.boundPkgMethodRecvVal(v); !okM {
				return true, true
			}
		}
		return false, false

	case flowir.ValAddrOf:
		bRef, bCar := s.classifyPlace(v.AddrPlace)
		if v.IsArraySlice {
			if bRef {
				return true, true
			}
			if bCar {
				return false, true
			}
			return false, false
		}
		if s.placeMutatesTaintedTarget(v.AddrPlace) {
			return true, true
		}
		if bRef || bCar {
			return false, true
		}
		return false, false

	case flowir.ValChanRecv:
		if _, cCar := s.classifyValue(v.Chan); cCar {
			et := indexValueTypeFromType(v.Type)
			return s.isDirectRef(et), true
		}
		return false, false

	case flowir.ValAllocFresh:
		switch v.AllocKind {
		case flowir.AllocMake, flowir.AllocBuiltinNewType:
			return false, false
		case flowir.AllocBuiltinNewExpr:
			if len(v.Args) == 1 {
				if _, aCar := s.classifyValue(v.Args[0]); aCar {
					return false, true
				}
			}
			return false, false
		case flowir.AllocCompositeLit:
			if s.isAllowedStructCompositeLit(v) {
				return false, false
			}
			for i := range v.CompositeElts {
				elt := &v.CompositeElts[i]
				if elt.MapKey != nil {
					if _, kCar := s.classifyValue(elt.MapKey); kCar {
						return false, true
					}
				}
				if _, vCar := s.classifyValue(elt.Value); vCar {
					return false, true
				}
			}
			return false, false
		}
		return false, false

	case flowir.ValConvert:
		if v.IsTypeAssert {
			if _, xCar := s.classifyValue(v.Arg); xCar {
				return true, true
			}
			return false, false
		}
		aRef, aCar := s.classifyValue(v.Arg)
		if !aCar {
			return false, false
		}
		if !s.elemHasHandle(v.Type) && !syntaxutil.ContainsUintptr(v.Type) {
			return false, false
		}
		return aRef || s.isDirectRef(v.Type), true

	case flowir.ValCall:
		if v.CallKind == flowir.CallBuiltin {
			if v.BuiltinName == "append" && len(v.Args) > 0 {
				dRef, dCar := s.classifyValue(v.Args[0])
				elemTainted := false
				var slElem types.Type
				if sl, ok := syntaxutil.UnderlyingType(v.Type).(*types.Slice); ok {
					slElem = sl.Elem()
				}
				for _, arg := range v.Args[1:] {
					_, aCar := s.classifyValue(arg)
					if !aCar {
						continue
					}
					if v.Ellipsis {
						if s.elemHasHandle(slElem) {
							elemTainted = true
						}
					} else {
						elemTainted = true
					}
				}
				return dRef, dRef || dCar || elemTainted
			}
			return false, false
		}
		if callee := s.resolveConcretePkgCalleeVal(v); callee != nil {
			if s.taintedRetAnyRef[callee] || s.taintedRetAnyCarrier[callee] {
				return s.taintedRetAnyRef[callee], true
			}
			return false, false
		}
		return false, false

	case flowir.ValCompositeExpr:
		hit := false
		for _, a := range v.Args {
			if _, aCar := s.classifyValue(a); aCar {
				hit = true
				break
			}
		}
		if hit {
			if v.Type == nil || s.isDirectRef(v.Type) || types.IsInterface(v.Type) {
				return true, true
			}
			if s.carriesRefOrIface(v.Type) {
				return false, true
			}
		}
		return false, false

	default:
		return false, false
	}
}

func (s *refConfinementSolver) classifyMultiReturnSlot(rhs *flowir.Value, slot int, slotType types.Type) (bool, bool) {
	if rhs == nil {
		return false, false
	}
	if rhs.Kind == flowir.ValCall && rhs.CallAST != nil {
		if _, sCar, ok := s.checkSeedExpr(rhs.CallAST); ok && sCar {
			if s.isDirectRef(slotType) {
				return true, true
			}
			if s.carriesRef(slotType) {
				return false, true
			}
			if s.isOpaqueIfaceOrTP(slotType) && !types.Identical(slotType, s.errorType) {
				return true, true
			}
			return false, false
		}
		if callee := s.resolveConcretePkgCalleeVal(rhs); callee != nil {
			rk := retSlot{fn: callee, idx: slot}
			return s.taintedRetRef[rk], s.taintedRetRef[rk] || s.taintedRetCarrier[rk]
		}
		return false, false
	}
	if _, rCar := s.classifyValue(rhs); !rCar || slot != 0 {
		return false, false
	}
	if rhs.Kind == flowir.ValPlace && len(rhs.Place.Projs) > 0 {
		lastIdx := len(rhs.Place.Projs) - 1
		if rhs.Place.Projs[lastIdx].Kind == flowir.ProjIndex {
			containerRaw := rhs.Place.RootRaw
			if lastIdx > 0 {
				containerRaw = rhs.Place.Projs[lastIdx-1].Raw
			}
			return s.projectedClassify(slotType, containerRaw)
		}
	}
	return s.projectedClassify(slotType, nil)
}

func (s *refConfinementSolver) markVarTaint(v *types.Var, addRef, addCar bool) bool {
	if v == nil || !addCar {
		return false
	}
	progressed := false
	if !s.taintedCarrier[v] {
		s.taintedCarrier[v] = true
		progressed = true
	}
	if addRef && !s.taintedRef[v] {
		s.taintedRef[v] = true
		progressed = true
	}
	return progressed
}

func (s *refConfinementSolver) markContainerIndexWrite(dst flowir.Place) bool {
	if dst.Obj == nil || len(dst.Projs) != 1 || dst.Projs[0].Kind != flowir.ProjIndex {
		return false
	}
	return s.markVarTaint(dst.Obj, false, true)
}

func (s *refConfinementSolver) isEligibleCapsule(orig *types.Named) bool {
	if orig == nil || orig.Obj() == nil || orig.Obj().Pkg() != s.p.Types || orig.Obj().Exported() || orig.TypeParams().Len() > 0 {
		return false
	}
	st, isSt := orig.Underlying().(*types.Struct)
	return isSt && structHasNoExportedFieldsDeep(st)
}

func (s *refConfinementSolver) solveTaintAndCapsules() {
	for {
		clear(s.taintedRef)
		clear(s.taintedCarrier)
		clear(s.taintedRetRef)
		clear(s.taintedRetCarrier)
		clear(s.taintedRetAnyRef)
		clear(s.taintedRetAnyCarrier)

		for changed := true; changed; {
			changed = false
			taintVal := func(v *flowir.Value) {
				if v == nil {
					return
				}
				v.WalkValues(func(cur *flowir.Value) bool {
					switch cur.Kind {
					case flowir.ValMethodVal:
						xRef, xCar, mutX, seedX := s.methodValHasTaintedOrSeedRecv(cur)
						if xCar || mutX || seedX {
							if rv, okM := s.boundPkgMethodRecvVal(cur); okM {
								_, recvIsPtr := types.Unalias(rv.Type()).(*types.Pointer)
								addRef := xRef || mutX || recvIsPtr || s.isDirectRef(rv.Type())
								if s.markVarTaint(rv, addRef, true) {
									changed = true
								}
							}
						}
					case flowir.ValCall:
						if cur.CallKind == flowir.CallBuiltin && cur.BuiltinName == "copy" && len(cur.Args) == 2 {
							if _, srcCar := s.classifyValue(cur.Args[1]); srcCar {
								if cur.Args[0] != nil && cur.Args[0].Kind == flowir.ValPlace && cur.Args[0].Place.Obj != nil {
									if s.markVarTaint(cur.Args[0].Place.Obj, false, true) {
										changed = true
									}
								}
							}
							return true
						}
						callee := s.resolveConcretePkgCalleeVal(cur)
						if callee == nil {
							return true
						}
						sig, ok := callee.Type().(*types.Signature)
						if !ok {
							return true
						}
						if cur.CallKind == flowir.CallMethod && !cur.IsMethodExprCall && sig.Recv() != nil && cur.Recv != nil {
							rv := sig.Recv()
							xRef, xCar := s.classifyValue(cur.Recv)
							if xCar {
								mutRecv := false
								if cur.HasRecvPlace {
									mutRecv = s.placeMutatesTaintedTarget(cur.RecvPlace)
								} else {
									mutRecv = s.valueMutatesTaintedTarget(cur.Recv)
								}
								addRef := xRef || cur.AutoAddrRecv || (s.isDirectRef(rv.Type()) && mutRecv)
								if s.markVarTaint(rv, addRef, true) {
									changed = true
								}
							}
						}
						isTupleUnpack := len(cur.Args) == 1 && !cur.Ellipsis && cur.Args[0] != nil && cur.Args[0].Type != nil
						if isTupleUnpack {
							_, isTupleUnpack = types.Unalias(cur.Args[0].Type).(*types.Tuple)
						}
						cur.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, slotIdx int, paramIdx int, okP bool, packedVariadic bool) bool {
							if !okP {
								return true
							}
							var aRef, aCar bool
							if isTupleUnpack {
								aRef, aCar = s.classifyMultiReturnSlot(arg, slotIdx, slotType)
							} else {
								aRef, aCar = s.classifyValue(arg)
							}
							if !aCar {
								return true
							}
							pv := sig.Params().At(paramIdx)
							if packedVariadic {
								if s.markVarTaint(pv, false, true) {
									changed = true
								}
							} else {
								addRef := aRef || (s.cfg.AllowIntraPkgInterfaceParam && types.IsInterface(pv.Type()))
								if s.markVarTaint(pv, addRef, true) {
									changed = true
								}
							}
							return true
						})
					}
					return true
				})
			}

			s.walkAllBodies(func(b *flowir.Body, enclFunc *types.Func, _ bool) bool {
				for i := range b.Ops {
					op := &b.Ops[i]
					op.ForEachValue(func(v *flowir.Value) bool { taintVal(v); return true })
					switch op.Kind {
					case flowir.OpAssign:
						switch op.AssignKind {
						case flowir.AssignPlain:
							op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
								rRef, rCar := s.classifyValue(src)
								if !rCar {
									return true
								}
								if dst.IsBareVar() {
									if s.markVarTaint(dst.Obj, rRef, true) {
										changed = true
									}
								} else if s.markContainerIndexWrite(dst) {
									changed = true
								}
								return true
							})
						case flowir.AssignMulti:
							if len(op.Srcs) == 1 && op.Srcs[0] != nil {
								rhs := op.Srcs[0]
								rhsTup, _ := rhs.Type.(*types.Tuple)
								for idxDst, dst := range op.Dsts {
									if !dst.IsBareVar() {
										continue
									}
									slotT := dst.Type
									if rhsTup != nil && idxDst < rhsTup.Len() {
										slotT = rhsTup.At(idxDst).Type()
									}
									pRef, pCar := s.classifyMultiReturnSlot(rhs, idxDst, slotT)
									if !pCar {
										continue
									}
									addRef := pRef || s.isOpaqueIfaceOrTP(dst.Obj.Type())
									if s.markVarTaint(dst.Obj, addRef, true) {
										changed = true
									}
								}
							}
						case flowir.AssignRange:
							if len(op.Srcs) == 1 && op.Srcs[0] != nil {
								rngX := op.Srcs[0]
								if _, xCar := s.classifyValue(rngX); xCar {
									for _, dst := range op.Dsts {
										if !dst.IsBareVar() {
											continue
										}
										pRef, pCar := s.projectedClassify(dst.Type, rngX.Raw)
										if pCar && s.markVarTaint(dst.Obj, pRef, true) {
											changed = true
										}
									}
								}
							}
						}

					case flowir.OpTypeSwitchBind:
						if op.SwitchDst != nil {
							if _, sCar := s.classifyValue(op.SwitchSrc); sCar {
								if s.markVarTaint(op.SwitchDst, true, true) {
									changed = true
								}
							}
						}

					case flowir.OpReturn:
						if !s.canPropagateReturn(enclFunc) {
							continue
						}
						markRetSlot := func(ri int, rRef, rCar bool) {
							rk := retSlot{fn: enclFunc, idx: ri}
							if rCar && !s.taintedRetCarrier[rk] {
								s.taintedRetCarrier[rk] = true
								s.taintedRetAnyCarrier[enclFunc] = true
								changed = true
							}
							if rRef && !s.taintedRetRef[rk] {
								s.taintedRetRef[rk] = true
								s.taintedRetAnyRef[enclFunc] = true
								changed = true
							}
						}
						if op.IsNaked {
							sig := enclFunc.Signature()
							for ri := 0; ri < sig.Results().Len(); ri++ {
								rv := sig.Results().At(ri)
								markRetSlot(ri, s.taintedRef[rv], s.taintedCarrier[rv])
							}
						} else if len(op.Results) == 1 && op.Results[0] != nil {
							if tup, isTup := op.Results[0].Type.(*types.Tuple); isTup {
								for ri := 0; ri < tup.Len(); ri++ {
									rRef, rCar := s.classifyMultiReturnSlot(op.Results[0], ri, tup.At(ri).Type())
									markRetSlot(ri, rRef, rCar)
								}
								continue
							}
							rRef, rCar := s.classifyValue(op.Results[0])
							markRetSlot(0, rRef, rCar)
						} else {
							for ri, r := range op.Results {
								rRef, rCar := s.classifyValue(r)
								markRetSlot(ri, rRef, rCar)
							}
						}
					}
				}
				return true
			})
		}

		promoted := false
		if (s.cfg.AllowCompositeLitIntoSeedStruct && s.cfg.CanBeSeedStructCapsule != nil) || s.cfg.AllowCompositeLitFieldPropagation {
			promoteVal := func(v *flowir.Value) {
				if v == nil {
					return
				}
				v.WalkValues(func(cur *flowir.Value) bool {
					cl := allocCompositeLitAST(cur)
					if cl == nil {
						return true
					}
					st := syntaxutil.DerefNamedStruct(s.info.TypeOf(cl))
					if st == nil {
						return true
					}
					orig := st.Origin()
					if s.isSeedStruct(orig) || !s.isEligibleCapsule(orig) {
						return true
					}
					if s.cfg.AllowCompositeLitIntoSeedStruct && s.cfg.CanBeSeedStructCapsule != nil && s.cfg.CanBeSeedStructCapsule(orig) {
						for i := range cur.CompositeElts {
							if _, vCar := s.classifyValue(cur.CompositeElts[i].Value); vCar {
								s.capsuleStructs[orig] = true
								promoted = true
								break
							}
						}
					}
					if s.cfg.AllowCompositeLitFieldPropagation && !s.isSeedStruct(orig) {
						for i := range cur.CompositeElts {
							elt := &cur.CompositeElts[i]
							if _, vCar := s.classifyValue(elt.Value); vCar && elt.Field != nil {
								if !s.propagatedStructs[orig] {
									s.propagatedStructs[orig] = true
									promoted = true
								}
								if !s.propagatedFields[elt.Field.Origin()] {
									s.propagatedFields[elt.Field.Origin()] = true
									promoted = true
								}
							}
						}
					}
					return true
				})
			}
			s.walkAllBodies(func(b *flowir.Body, _ *types.Func, _ bool) bool {
				for i := range b.Ops {
					b.Ops[i].ForEachValue(func(v *flowir.Value) bool { promoteVal(v); return true })
				}
				return true
			})
		}
		if !promoted {
			break
		}
	}
}

func (s *refConfinementSolver) discoverLocalFreshContainers() {
	freshCand := map[*types.Var]bool{}
	freshDisq := map[*types.Var]bool{}
	isFreshContainerInit := func(v *types.Var, src *flowir.Value) bool {
		if src == nil || src.IsNil {
			return true
		}
		if src.Kind == flowir.ValAllocFresh {
			if src.AllocKind == flowir.AllocMake {
				return true
			}
			if src.AllocKind == flowir.AllocCompositeLit && src.Type != nil {
				switch types.Unalias(src.Type).Underlying().(type) {
				case *types.Slice, *types.Array, *types.Map:
					return true
				}
			}
		}
		if src.Kind == flowir.ValCall && src.CallKind == flowir.CallBuiltin && src.BuiltinName == "append" &&
			len(src.Args) > 0 && src.Args[0] != nil && src.Args[0].Kind == flowir.ValPlace &&
			src.Args[0].Place.IsBareVar() && src.Args[0].Place.Obj == v {
			return true
		}
		return false
	}
	scanFreshVal := func(v *flowir.Value) {
		if v == nil {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			switch cur.Kind {
			case flowir.ValAddrOf:
				if !cur.IsArraySlice && cur.AddrPlace.Obj != nil {
					freshDisq[cur.AddrPlace.Obj] = true
				}
			case flowir.ValCall:
				if cur.AutoAddrRecv && cur.HasRecvPlace && cur.RecvPlace.Obj != nil {
					freshDisq[cur.RecvPlace.Obj] = true
				}
			case flowir.ValMethodVal:
				if cur.AutoAddr && cur.HasRecvPlace && cur.RecvPlace.Obj != nil {
					freshDisq[cur.RecvPlace.Obj] = true
				}
			}
			return true
		})
	}
	s.walkAllBodies(func(b *flowir.Body, _ *types.Func, _ bool) bool {
		for i := range b.Ops {
			op := &b.Ops[i]
			op.ForEachValue(func(v *flowir.Value) bool { scanFreshVal(v); return true })
			switch op.Kind {
			case flowir.OpAssign:
				switch op.AssignKind {
				case flowir.AssignZeroDecl:
					for _, dst := range op.Dsts {
						if dst.IsBareVar() && dst.Obj != nil {
							if dst.Root == flowir.RootLocal {
								freshCand[dst.Obj] = true
							} else {
								freshDisq[dst.Obj] = true
							}
						}
					}
				case flowir.AssignPlain:
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
						if dst.IsBareVar() && dst.Obj != nil {
							if dst.Root != flowir.RootLocal {
								freshDisq[dst.Obj] = true
								return true
							}
							freshCand[dst.Obj] = true
							if !isFreshContainerInit(dst.Obj, src) {
								freshDisq[dst.Obj] = true
							}
						}
						return true
					})
				case flowir.AssignMulti, flowir.AssignCompound, flowir.AssignIncDec, flowir.AssignRange:
					for _, dst := range op.Dsts {
						if dst.IsBareVar() && dst.Obj != nil {
							freshDisq[dst.Obj] = true
						}
					}
				}
			case flowir.OpTypeSwitchBind:
				if op.SwitchDst != nil {
					freshDisq[op.SwitchDst] = true
				}
			}
		}
		return true
	})
	for v := range freshCand {
		if !freshDisq[v] && !s.taintedRef[v] {
			s.localFreshContainer[v] = true
		}
	}

	s.walkAllBodies(func(b *flowir.Body, _ *types.Func, _ bool) bool {
		for i := range b.Ops {
			op := &b.Ops[i]
			if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignPlain &&
				len(op.Dsts) == 1 && len(op.Srcs) == 1 && len(op.DstDefs) == 1 && !op.DstDefs[0] &&
				op.Dsts[0].IsBareVar() && s.localFreshContainer[op.Dsts[0].Obj] {
				src := op.Srcs[0]
				if src != nil && src.Kind == flowir.ValCall && src.CallKind == flowir.CallBuiltin &&
					src.BuiltinName == "append" && src.CallAST != nil && len(src.Args) > 0 &&
					src.Args[0] != nil && src.Args[0].Kind == flowir.ValPlace &&
					src.Args[0].Place.IsBareVar() && src.Args[0].Place.Obj == op.Dsts[0].Obj {
					s.selfAssignedAppendCalls[src.CallAST] = true
				}
			}
		}
		return true
	})
}
