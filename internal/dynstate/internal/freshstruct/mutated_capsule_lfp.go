package freshstruct

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (wpd *wrapperPtrDiscipline) runProvenanceLFP() bool {

	fc := wpd.idx.FlowCache(wpd.p)
	if fc == nil {
		return false
	}
	forEachPkgFlowOp(wpd.p, fc, func(_ *types.Func, _ *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
		op.ForEachValue(func(root *flowir.Value) bool {
			root.WalkValues(func(v *flowir.Value) bool {
				if v == nil {
					return false
				}
				switch v.Kind {
				case flowir.ValAddrOf:
					wpd.taintAddrTakenPlace(v.AddrPlace)
				case flowir.ValMethodVal:
					if v.AutoAddr && v.HasRecvPlace {
						wpd.taintAddrTakenPlace(v.RecvPlace)
					}
				case flowir.ValCall:
					if v.AutoAddrRecv && v.HasRecvPlace {
						wpd.taintAddrTakenPlace(v.RecvPlace)
					}
				}
				return true
			})
			return true
		})
		return true
	})

	for changed := true; changed; {
		changed = false
		forEachPkgFlowOp(wpd.p, fc, func(fn *types.Func, fl *ast.FuncLit, declBody *flowir.Body, op *flowir.Op) bool {
			switch op.Kind {
			case flowir.OpAssign:
				switch op.AssignKind {
				case flowir.AssignZeroDecl:
					// Zero-initialized variable declaration adds no provenance bits.
				case flowir.AssignPlain:
					if len(op.Dsts) == len(op.Srcs) {
						for i, dst := range op.Dsts {
							if wpd.assignPlaceFromValue(dst, op.Srcs[i]) {
								changed = true
							}
						}
					} else {
						for _, dst := range op.Dsts {
							if wpd.taintRawPlace(dst) {
								changed = true
							}
						}
					}
				case flowir.AssignMulti:
					handledCall := false
					if len(op.Srcs) == 1 && op.Srcs[0] != nil && op.Srcs[0].Kind == flowir.ValCall &&
						op.Srcs[0].CallAST != nil && op.Srcs[0].CalleeSig != nil && op.Srcs[0].CalleeSig.Results() != nil {
						rc := op.Srcs[0].CallAST
						resTup := op.Srcs[0].CalleeSig.Results()
						for ri := 0; ri < resTup.Len() && ri < len(op.Dsts); ri++ {
							if wpd.assignPlaceTupleSlot(op.Dsts[ri], rc, ri, resTup.At(ri).Type()) {
								changed = true
							}
						}
						handledCall = true
					}
					if !handledCall {
						for _, dst := range op.Dsts {
							if wpd.taintRawPlace(dst) {
								changed = true
							}
						}
					}
				case flowir.AssignCompound, flowir.AssignIncDec:
					for _, dst := range op.Dsts {
						if wpd.taintRawPlace(dst) {
							changed = true
						}
					}
				case flowir.AssignRange:
					if len(op.Dsts) >= 1 && wpd.taintRawPlace(op.Dsts[0]) {
						changed = true
					}
					if len(op.Dsts) >= 2 {
						valDst := op.Dsts[1]
						if len(op.Srcs) == 1 && op.Srcs[0] != nil && op.Srcs[0].Raw != nil &&
							valDst.Type != nil && types.Identical(types.Unalias(valDst.Type), wpd.dstOwner) &&
							wpd.isOwnerSliceType(op.Srcs[0].Type) {
							if wpd.assignOwnerPlace(valDst, wpd.sliceExprProv(op.Srcs[0].Raw)) {
								changed = true
							}
						} else if wpd.taintRawPlace(valDst) {
							changed = true
						}
					}
				}
			case flowir.OpTypeSwitchBind:
				if wpd.taintRawVar(op.SwitchDst) {
					changed = true
				}
			case flowir.OpReturn:
				if fl == nil && fn != nil && wpd.contextSensitiveFuncs[fn] {
					break
				}
				if declBody == nil {
					break
				}
				nres := len(declBody.ResultTypes)
				if nres == 0 {
					break
				}
				if len(op.Results) == nres {
					for ri, res := range op.Results {
						if !types.Identical(types.Unalias(declBody.ResultTypes[ri]), wpd.dstOwner) {
							continue
						}
						pr := provRaw
						if res != nil && res.Raw != nil {
							pr = wpd.exprProv(res.Raw)
						}
						if fn != nil && wpd.addFnRetProv(fn, ri, nres, pr) {
							changed = true
						}
						if fl != nil && wpd.addLitRetProv(fl, ri, nres, pr) {
							changed = true
						}
					}
				} else if op.IsNaked && len(declBody.Results) == nres {
					for ri, rv := range declBody.Results {
						if rv != nil && types.Identical(types.Unalias(declBody.ResultTypes[ri]), wpd.dstOwner) {
							pr := wpd.varProv[rv]
							if fn != nil && wpd.addFnRetProv(fn, ri, nres, pr) {
								changed = true
							}
							if fl != nil && wpd.addLitRetProv(fl, ri, nres, pr) {
								changed = true
							}
						}
					}
				} else if len(op.Results) == 1 && op.Results[0] != nil && op.Results[0].Kind == flowir.ValCall && op.Results[0].CallAST != nil {
					rc := op.Results[0].CallAST
					for ri := 0; ri < nres; ri++ {
						if !types.Identical(types.Unalias(declBody.ResultTypes[ri]), wpd.dstOwner) {
							continue
						}
						pr := wpd.callTupleSlotProv(rc, ri)
						if fn != nil && wpd.addFnRetProv(fn, ri, nres, pr) {
							changed = true
						}
						if fl != nil && wpd.addLitRetProv(fl, ri, nres, pr) {
							changed = true
						}
					}
				}
			}
			op.ForEachValue(func(root *flowir.Value) bool {
				root.WalkValues(func(v *flowir.Value) bool {
					if v == nil {
						return false
					}
					switch v.Kind {
					case flowir.ValAllocFresh:
						if v.AllocKind == flowir.AllocCompositeLit {
							for i := range v.CompositeElts {
								elt := &v.CompositeElts[i]
								if elt.Field != nil && elt.Value != nil && elt.Value.Raw != nil &&
									types.Identical(types.Unalias(elt.Field.Type()), wpd.dstOwner) {
									if wpd.addFieldProv(elt.Field, wpd.exprProv(elt.Value.Raw)) {
										changed = true
									}
								}
							}
						}
					case flowir.ValConvert:
						if !v.IsTypeAssert && v.Type != nil && v.Arg != nil && v.Arg.Type != nil {
							if wpd.equateConvertedStructFields(v.Type, v.Arg.Type) {
								changed = true
							}
						}
					case flowir.ValCall:
						if v.CallKind == flowir.CallBuiltin || v.CallAST == nil {
							return true
						}
						x := v.CallAST
						callee := v.CalleeFunc
						if callee != nil && wpd.idx.FuncDecls[callee] != nil {
							if sig, okS := callee.Type().(*types.Signature); okS {
								if !v.IsMethodExprCall && sig.Recv() != nil && (!wpd.ownerMethods[callee] || wpd.methodClass[callee] == ptrMethodRawDeref) &&
									v.Recv != nil && v.Recv.Raw != nil {
									if wpd.propagateVarArg(sig.Recv(), v.Recv.Raw, false, false) {
										changed = true
									}
								}
								if !wpd.contextSensitiveFuncs[callee] && wpd.propagateCallArgsToSig(sig, x, v.IsMethodExprCall) {
									changed = true
								}
							}
						} else if callee == nil {
							if v.CallKind == flowir.CallIIFE && v.CalleeSig != nil {
								if wpd.propagateCallArgsToSig(v.CalleeSig, x, false) {
									changed = true
								}
							} else if v.Callee != nil && v.Callee.Kind == flowir.ValPlace {
								cp := v.Callee.Place
								if cp.IsBareVar() && cp.Obj != nil {
									lv := cp.Obj
									for _, fl := range wpd.funcLitsForLocal[lv] {
										if sig, okS := wpd.p.TypesInfo.TypeOf(fl).(*types.Signature); okS && wpd.propagateCallArgsToSig(sig, x, false) {
											changed = true
										}
									}
									for _, tfn := range wpd.funcObjsForLocal[lv] {
										if sig, okS := tfn.Type().(*types.Signature); okS && wpd.propagateCallArgsToSig(sig, x, false) {
											changed = true
										}
									}
								} else if len(cp.Projs) > 0 {
									last := cp.Projs[len(cp.Projs)-1]
									if last.Kind == flowir.ProjField && last.Field != nil {
										fobj := last.Field
										for _, fl := range wpd.funcLitsForField[fobj] {
											if sig, okS := wpd.p.TypesInfo.TypeOf(fl).(*types.Signature); okS && wpd.propagateCallArgsToSig(sig, x, false) {
												changed = true
											}
										}
										for _, tfn := range wpd.funcObjsForField[fobj] {
											if sig, okS := tfn.Type().(*types.Signature); okS && wpd.propagateCallArgsToSig(sig, x, false) {
												changed = true
											}
										}
									}
								}
							}
						}
					}
					return true
				})
				return true
			})
			return true
		})
	}

	return true
}

func (wpd *wrapperPtrDiscipline) assignOwnerPlace(dst flowir.Place, pr ptrProv) bool {
	if dst.IsBlank() {
		return false
	}
	if dst.IsBareVar() {
		return wpd.addVarProv(dst.Obj, pr)
	}
	if len(dst.Projs) > 0 {
		last := dst.Projs[len(dst.Projs)-1]
		if last.Kind == flowir.ProjField && last.Field != nil {
			return wpd.addFieldProv(last.Field, pr)
		}
		if len(dst.Projs) == 1 && last.Kind == flowir.ProjIndex && dst.Obj != nil && wpd.isOwnerSliceType(types.Unalias(dst.Obj.Type())) {
			return wpd.addSliceVarProv(dst.Obj, pr)
		}
	}
	return false
}

func (wpd *wrapperPtrDiscipline) taintRawVar(v *types.Var) bool {
	if v == nil {
		return false
	}
	vt := types.Unalias(v.Type())
	if types.Identical(vt, wpd.dstOwner) {
		return wpd.addVarProv(v, provRaw)
	}
	if wpd.isOwnerSliceType(vt) {
		return wpd.addSliceVarProv(v, provRaw)
	}
	if syntaxutil.IsNamedInPkg(vt, "reflect", "Value") {
		return wpd.addRVVarProv(v, rvRaw)
	}
	return false
}

func (wpd *wrapperPtrDiscipline) taintRawPlace(dst flowir.Place) bool {
	if dst.Type == nil || dst.IsBlank() {
		return false
	}
	dstU := types.Unalias(dst.Type)
	if types.Identical(dstU, wpd.dstOwner) {
		return wpd.assignOwnerPlace(dst, provRaw)
	}
	if dst.IsBareVar() {
		return wpd.taintRawVar(dst.Obj)
	}
	return false
}

func (wpd *wrapperPtrDiscipline) assignPlaceTupleSlot(dst flowir.Place, rc *ast.CallExpr, ri int, slotT types.Type) bool {
	rt := types.Unalias(slotT)
	if types.Identical(rt, wpd.dstOwner) {
		return wpd.assignOwnerPlace(dst, wpd.callTupleSlotProv(rc, ri))
	}
	if wpd.isOwnerSliceType(rt) || syntaxutil.IsNamedInPkg(rt, "reflect", "Value") {
		return wpd.taintRawPlace(dst)
	}
	return false
}

func (wpd *wrapperPtrDiscipline) propagateVarArg(pv *types.Var, arg ast.Expr, isVariadicElem bool, isEllipsisSlice bool) bool {
	if pv == nil {
		return false
	}
	pt := types.Unalias(pv.Type())
	if types.Identical(pt, wpd.dstOwner) {
		if isEllipsisSlice {
			return wpd.addVarProv(pv, provRaw)
		}
		return wpd.addVarProv(pv, wpd.exprProv(arg))
	}
	if wpd.isOwnerSliceType(pt) {
		if isVariadicElem && !isEllipsisSlice && types.Identical(types.Unalias(wpd.p.TypesInfo.TypeOf(arg)), wpd.dstOwner) {
			return wpd.addSliceVarProv(pv, wpd.exprProv(arg))
		}
		return wpd.addSliceVarProv(pv, wpd.sliceExprProv(arg))
	}
	if syntaxutil.IsNamedInPkg(pt, "reflect", "Value") {
		if isEllipsisSlice {
			return wpd.addRVVarProv(pv, rvRaw)
		}
		return wpd.addRVVarProv(pv, wpd.evalRVProv(arg))
	}
	return false
}

func (wpd *wrapperPtrDiscipline) propagateTupleVarSlot(pv *types.Var, rc *ast.CallExpr, isRC bool, ti int, directTupleMatch bool) bool {
	if pv == nil {
		return false
	}
	pt := types.Unalias(pv.Type())
	if types.Identical(pt, wpd.dstOwner) {
		pr := provRaw
		if isRC && directTupleMatch {
			pr = wpd.callTupleSlotProv(rc, ti)
		}
		return wpd.addVarProv(pv, pr)
	}
	if wpd.isOwnerSliceType(pt) {
		return wpd.addSliceVarProv(pv, provRaw)
	}
	if syntaxutil.IsNamedInPkg(pt, "reflect", "Value") {
		return wpd.addRVVarProv(pv, rvRaw)
	}
	return false
}

func (wpd *wrapperPtrDiscipline) propagateCallArgsToSig(sig *types.Signature, x *ast.CallExpr, isMethodExprCall bool) bool {
	if sig == nil || x == nil {
		return false
	}
	stepChanged := false
	hasEllipsis := x.Ellipsis.IsValid()
	if len(x.Args) == 1 && !hasEllipsis {
		if tup, isTup := wpd.p.TypesInfo.TypeOf(x.Args[0]).(*types.Tuple); isTup {
			rc, isRC := ast.Unparen(x.Args[0]).(*ast.CallExpr)
			wantSlots := sig.Params().Len()
			if isMethodExprCall {
				wantSlots++
			}
			directTupleMatch := !sig.Variadic() && tup.Len() == wantSlots
			for ti := 0; ti < tup.Len(); ti++ {
				if isMethodExprCall {
					if ti == 0 {
						if sig.Recv() != nil && wpd.propagateTupleVarSlot(sig.Recv(), rc, isRC, 0, directTupleMatch) {
							stepChanged = true
						}
						continue
					}
					pi := ti - 1
					if sig.Variadic() && pi >= sig.Params().Len()-1 {
						pi = sig.Params().Len() - 1
					}
					if pi >= 0 && pi < sig.Params().Len() && wpd.propagateTupleVarSlot(sig.Params().At(pi), rc, isRC, ti, directTupleMatch) {
						stepChanged = true
					}
					continue
				}
				pi := ti
				if sig.Variadic() && ti >= sig.Params().Len()-1 {
					pi = sig.Params().Len() - 1
				}
				if pi >= 0 && pi < sig.Params().Len() && wpd.propagateTupleVarSlot(sig.Params().At(pi), rc, isRC, ti, directTupleMatch) {
					stepChanged = true
				}
			}
			return stepChanged
		}
	}
	for ai, arg := range x.Args {
		isEllipsisLast := hasEllipsis && ai == len(x.Args)-1
		if isMethodExprCall {
			if ai == 0 {
				if sig.Recv() != nil && wpd.propagateVarArg(sig.Recv(), arg, false, isEllipsisLast) {
					stepChanged = true
				}
				continue
			}
			pi := ai - 1
			if sig.Variadic() && pi >= sig.Params().Len()-1 {
				pi = sig.Params().Len() - 1
			}
			if pi >= 0 && pi < sig.Params().Len() {
				isVarElem := sig.Variadic() && pi == sig.Params().Len()-1
				if wpd.propagateVarArg(sig.Params().At(pi), arg, isVarElem, isEllipsisLast) {
					stepChanged = true
				}
			}
			continue
		}
		pi := ai
		if sig.Variadic() && ai >= sig.Params().Len()-1 {
			pi = sig.Params().Len() - 1
		}
		if pi >= 0 && pi < sig.Params().Len() {
			isVarElem := sig.Variadic() && pi == sig.Params().Len()-1
			if wpd.propagateVarArg(sig.Params().At(pi), arg, isVarElem, isEllipsisLast) {
				stepChanged = true
			}
		}
	}
	return stepChanged
}

func (wpd *wrapperPtrDiscipline) equateConvertedStructFields(dstRoot, srcRoot types.Type) bool {
	type typePair struct{ a, b types.Type }
	seenPairs := map[typePair]bool{}
	stepChanged := false
	var walk func(dt, st types.Type)
	walk = func(dt, st types.Type) {
		if dt == nil || st == nil {
			return
		}
		dt = types.Unalias(dt)
		st = types.Unalias(st)
		if types.Identical(dt, st) {
			return
		}
		pk := typePair{a: dt, b: st}
		if seenPairs[pk] {
			return
		}
		seenPairs[pk] = true
		switch du := dt.Underlying().(type) {
		case *types.Pointer:
			if su, ok := st.Underlying().(*types.Pointer); ok {
				walk(du.Elem(), su.Elem())
			}
		case *types.Slice:
			if su, ok := st.Underlying().(*types.Slice); ok {
				walk(du.Elem(), su.Elem())
			}
		case *types.Array:
			if su, ok := st.Underlying().(*types.Array); ok && du.Len() == su.Len() {
				walk(du.Elem(), su.Elem())
			}
		case *types.Map:
			if su, ok := st.Underlying().(*types.Map); ok {
				walk(du.Key(), su.Key())
				walk(du.Elem(), su.Elem())
			}
		case *types.Chan:
			if su, ok := st.Underlying().(*types.Chan); ok {
				walk(du.Elem(), su.Elem())
			}
		case *types.Struct:
			if su, ok := st.Underlying().(*types.Struct); ok && du.NumFields() == su.NumFields() {
				for i := 0; i < du.NumFields(); i++ {
					df := du.Field(i)
					sf := su.Field(i)
					if du != su {
						if wpd.addFieldProv(df, wpd.fieldProv[sf]) {
							stepChanged = true
						}
						if wpd.addFieldProv(sf, wpd.fieldProv[df]) {
							stepChanged = true
						}
					}
					walk(df.Type(), sf.Type())
				}
			}
		}
	}
	walk(dstRoot, srcRoot)
	return stepChanged
}

func (wpd *wrapperPtrDiscipline) assignPlaceFromValue(dst flowir.Place, src *flowir.Value) bool {
	if dst.Type == nil || dst.IsBlank() {
		return false
	}
	if src == nil || src.Raw == nil {
		return wpd.taintRawPlace(dst)
	}
	dstU := types.Unalias(dst.Type)
	if types.Identical(dstU, wpd.dstOwner) {
		return wpd.assignOwnerPlace(dst, wpd.exprProv(src.Raw))
	}
	if dst.IsBareVar() {
		if wpd.isOwnerSliceType(dstU) {
			return wpd.addSliceVarProv(dst.Obj, wpd.sliceExprProv(src.Raw))
		}
		if syntaxutil.IsNamedInPkg(dstU, "reflect", "Value") {
			return wpd.addRVVarProv(dst.Obj, wpd.evalRVProv(src.Raw))
		}
	}
	return false
}

func (wpd *wrapperPtrDiscipline) taintAddrTakenPlace(pl flowir.Place) {
	if pl.IsBareVar() {
		wpd.taintRawVar(pl.Obj)
		return
	}
	if len(pl.Projs) > 0 {
		last := pl.Projs[len(pl.Projs)-1]
		if last.Kind == flowir.ProjField && last.Field != nil && types.Identical(types.Unalias(last.Field.Type()), wpd.dstOwner) {
			wpd.fieldProv[last.Field] |= provRaw
		}
	}
}

func (wpd *wrapperPtrDiscipline) isInterfaceToPtrOnAnyParam(expr ast.Expr) bool {
	c, isC := ast.Unparen(expr).(*ast.CallExpr)
	if !isC || len(c.Args) != 1 || c.Ellipsis.IsValid() {
		return false
	}
	cfn := syntaxutil.ResolveCalledFuncObj(wpd.p, c.Fun)
	if cfn == nil || !wpd.ptrCtorInterfaceToPtr[cfn] {
		return false
	}
	uand, isUA := ast.Unparen(c.Args[0]).(*ast.UnaryExpr)
	if !isUA || uand.Op != token.AND {
		return false
	}
	pid, isPID := ast.Unparen(uand.X).(*ast.Ident)
	if !isPID {
		return false
	}
	pv, _ := wpd.p.TypesInfo.Uses[pid].(*types.Var)
	fd := wpd.idx.EnclFunc[c]
	if pv == nil || fd == nil || fd.Name == nil || !isEmptyInterfaceType(pv.Type()) {
		return false
	}
	fnObj, _ := wpd.p.TypesInfo.Defs[fd.Name].(*types.Func)
	if fnObj == nil {
		return false
	}
	sig, okS := fnObj.Type().(*types.Signature)
	if !okS {
		return false
	}
	isParam := false
	for pi := 0; pi < sig.Params().Len(); pi++ {
		if sig.Params().At(pi) == pv {
			isParam = true
			break
		}
	}
	if !isParam {
		return false
	}
	for _, uid := range wpd.idx.UsesOf[pv] {
		if uid != pid && identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, pv, uid) {
			return false
		}
	}
	return true
}

func (wpd *wrapperPtrDiscipline) isReadOnlyReflectValueExpr(expr ast.Expr, visiting map[*types.Var]bool) bool {
	if expr == nil {
		return false
	}
	par := wpd.idx.ParentUnparen(expr)
	switch pn := par.(type) {
	case *ast.SelectorExpr:
		if ast.Unparen(pn.X) != expr || pn.Sel == nil {
			return false
		}
		pc, isPC := wpd.idx.ParentUnparen(pn).(*ast.CallExpr)
		if !isPC || ast.Unparen(pc.Fun) != pn || pc.Ellipsis.IsValid() {
			return false
		}
		switch pn.Sel.Name {
		case "IsNil", "Type", "Kind":
			return len(pc.Args) == 0
		case "Interface":
			if len(pc.Args) != 0 {
				return false
			}
			if ta, isTA := wpd.idx.ParentUnparen(pc).(*ast.TypeAssertExpr); isTA && ta.Type != nil &&
				!types.IsInterface(wpd.p.TypesInfo.TypeOf(ta.Type)) {
				return false
			}
			return true
		case "Elem":
			return len(pc.Args) == 0 && wpd.isReadOnlyReflectValueExpr(pc, visiting)
		case "Set":
			if len(pc.Args) != 1 {
				return false
			}
			zc, isZC := ast.Unparen(pc.Args[0]).(*ast.CallExpr)
			if !isZC || len(zc.Args) != 1 || zc.Ellipsis.IsValid() {
				return false
			}
			zfn := syntaxutil.ResolveCalledFuncObj(wpd.p, zc.Fun)
			return zfn != nil && zfn.Pkg() != nil && zfn.Pkg().Path() == "reflect" && zfn.Name() == "Zero"
		default:
			return false
		}
	case *ast.KeyValueExpr, *ast.CompositeLit:
		var cl *ast.CompositeLit
		var fv *types.Var
		if kv, isKV := pn.(*ast.KeyValueExpr); isKV {
			if ast.Unparen(kv.Value) != expr {
				return false
			}
			cl, _ = wpd.idx.ParentUnparen(kv).(*ast.CompositeLit)
			if kid, isKID := ast.Unparen(kv.Key).(*ast.Ident); isKID {
				fv, _ = wpd.p.TypesInfo.Uses[kid].(*types.Var)
			}
		} else {
			cl, _ = pn.(*ast.CompositeLit)
			if st, isSt := syntaxutil.UnderlyingType(wpd.p.TypesInfo.TypeOf(cl)).(*types.Struct); isSt {
				for i, elt := range cl.Elts {
					if ast.Unparen(elt) == expr && i < st.NumFields() {
						fv = st.Field(i)
						break
					}
				}
			}
		}
		ownerN := syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(cl))
		if cl == nil || ownerN == nil || ownerN.Obj() == nil || ownerN.Obj().Pkg() != wpd.p.Types || ownerN.Obj().Exported() ||
			fv == nil || !fv.IsField() || fv.Exported() {
			return false
		}
		if visiting[fv] {
			return true
		}
		visiting[fv] = true
		for _, fuid := range wpd.idx.UsesOf[fv] {
			if kv, isKV := wpd.idx.ParentUnparen(fuid).(*ast.KeyValueExpr); isKV && ast.Unparen(kv.Key) == fuid {
				continue
			}
			fsel, isFS := wpd.idx.ParentMap[fuid].(*ast.SelectorExpr)
			if !isFS || fsel.Sel != fuid || identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, fv, fuid) || !wpd.isReadOnlyReflectValueExpr(fsel, visiting) {
				delete(visiting, fv)
				return false
			}
		}
		delete(visiting, fv)
		return true
	case *ast.AssignStmt:
		if pn.Tok != token.DEFINE || len(pn.Lhs) != 1 || len(pn.Rhs) != 1 || ast.Unparen(pn.Rhs[0]) != expr {
			return false
		}
		lid, isLID := ast.Unparen(pn.Lhs[0]).(*ast.Ident)
		if !isLID {
			return false
		}
		lv, _ := wpd.p.TypesInfo.Defs[lid].(*types.Var)
		if lv == nil || wpd.idx.DefCounts[lv] != 1 {
			return false
		}
		if visiting[lv] {
			return true
		}
		visiting[lv] = true
		for _, luid := range wpd.idx.UsesOf[lv] {
			if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, lv, luid) || !wpd.isReadOnlyReflectValueExpr(luid, visiting) {
				delete(visiting, lv)
				return false
			}
		}
		delete(visiting, lv)
		return true
	case *ast.CallExpr:
		if pn.Ellipsis.IsValid() || ast.Unparen(pn.Fun) == expr {
			return false
		}
		callee := syntaxutil.ResolveCalledFuncObj(wpd.p, pn.Fun)
		if callee == nil || callee.Pkg() != wpd.p.Types {
			return false
		}
		sig, okS := callee.Type().(*types.Signature)
		if !okS {
			return false
		}
		if sig.Recv() != nil && types.IsInterface(sig.Recv().Type()) {
			return true
		}
		if callee.Exported() || wpd.idx.FuncDecls[callee] == nil {
			return false
		}
		for ai, arg := range pn.Args {
			if ast.Unparen(arg) == expr {
				if ai >= sig.Params().Len() {
					return false
				}
				pv := sig.Params().At(ai)
				if visiting[pv] {
					return true
				}
				visiting[pv] = true
				for _, puid := range wpd.idx.UsesOf[pv] {
					if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, pv, puid) || !wpd.isReadOnlyReflectValueExpr(puid, visiting) {
						delete(visiting, pv)
						return false
					}
				}
				delete(visiting, pv)
				return true
			}
		}
	}
	return false
}

func (wpd *wrapperPtrDiscipline) isDeadSelfRecvDelegation(mc *ast.CallExpr, recvX ast.Expr) bool {
	enclFn, enclFL := wpd.enclCallable(mc)
	if enclFL != nil || enclFn == nil || !wpd.ownerMethods[enclFn] || len(wpd.idx.UsesOf[enclFn]) > 0 {
		return false
	}
	mfd := wpd.idx.FuncDecls[enclFn]
	if mfd == nil || mfd.Recv == nil || len(mfd.Recv.List) != 1 || len(mfd.Recv.List[0].Names) != 1 {
		return false
	}
	rv, _ := wpd.p.TypesInfo.Defs[mfd.Recv.List[0].Names[0]].(*types.Var)
	rid, isRID := ast.Unparen(recvX).(*ast.Ident)
	return rv != nil && isRID && wpd.p.TypesInfo.Uses[rid] == rv
}

func (wpd *wrapperPtrDiscipline) isZeroOwnerExpr(expr ast.Expr) bool {
	if expr == nil {
		return true
	}
	cl, isCL := ast.Unparen(expr).(*ast.CompositeLit)
	return isCL && len(cl.Elts) == 0 && types.Identical(types.Unalias(wpd.p.TypesInfo.TypeOf(cl)), wpd.dstOwner)
}

func (wpd *wrapperPtrDiscipline) isGuardedIfacePtrExprInFunc(expr ast.Expr, wantFD *ast.FuncDecl) bool {
	if expr == nil || wantFD == nil || wantFD.Body == nil {
		return false
	}
	expr = ast.Unparen(expr)
	checkPtrCall := func(ce *ast.CallExpr) bool {
		if ce == nil || len(ce.Args) != 1 || ce.Ellipsis.IsValid() || wpd.idx.EnclFunc[ce] != wantFD {
			return false
		}
		cfn := syntaxutil.ResolveCalledFuncObj(wpd.p, ce.Fun)
		return cfn != nil && wpd.ptrCtorOfIface[cfn] && wpd.isTypeGuardedIfaceArg(ce, ce.Args[0])
	}
	if ce, isCE := expr.(*ast.CallExpr); isCE {
		return checkPtrCall(ce)
	}
	id, isID := expr.(*ast.Ident)
	if !isID {
		return false
	}
	lv, _ := wpd.p.TypesInfo.Uses[id].(*types.Var)
	if lv == nil || lv.Parent() == wpd.p.Types.Scope() || wpd.idx.DefCounts[lv] != 1 {
		return false
	}
	for _, uid := range wpd.idx.UsesOf[lv] {
		if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, lv, uid) {
			return false
		}
	}
	matched := false
	ast.Inspect(wantFD.Body, func(bn ast.Node) bool {
		if matched || bn == nil {
			return false
		}
		switch x := bn.(type) {
		case *ast.ValueSpec:
			for i, nm := range x.Names {
				if wpd.p.TypesInfo.Defs[nm] == lv && len(x.Names) == len(x.Values) && i < len(x.Values) {
					if ce, isCE := ast.Unparen(x.Values[i]).(*ast.CallExpr); isCE && checkPtrCall(ce) {
						matched = true
						return false
					}
				}
			}
		case *ast.AssignStmt:
			if x.Tok == token.DEFINE && len(x.Lhs) == 1 && len(x.Rhs) == 1 {
				if lid, isLID := ast.Unparen(x.Lhs[0]).(*ast.Ident); isLID && wpd.p.TypesInfo.Defs[lid] == lv {
					if ce, isCE := ast.Unparen(x.Rhs[0]).(*ast.CallExpr); isCE && checkPtrCall(ce) {
						matched = true
						return false
					}
				}
			}
		}
		return true
	})
	return matched
}

func (wpd *wrapperPtrDiscipline) isVerifiedCapsulePairStruct(wNamed *types.Named, ptrFld, capFld *types.Var, capNamed *types.Named) bool {
	if wNamed == nil || wNamed.Obj() == nil || wNamed.Obj().Pkg() != wpd.p.Types || wNamed.Obj().Exported() ||
		ptrFld == nil || capFld == nil || ptrFld == capFld || ptrFld.Exported() || capFld.Exported() || capNamed == nil {
		return false
	}
	wSt, isSt := wNamed.Underlying().(*types.Struct)
	if !isSt || wSt.NumFields() != 2 ||
		!types.Identical(types.Unalias(ptrFld.Type()), wpd.dstOwner) ||
		!types.Identical(types.Unalias(capFld.Type()), types.NewPointer(capNamed)) {
		return false
	}
	if (wSt.Field(0) != ptrFld || wSt.Field(1) != capFld) && (wSt.Field(0) != capFld || wSt.Field(1) != ptrFld) {
		return false
	}
	isSamePairFamily := func(t types.Type) bool {
		sn := syntaxutil.DerefNamedStruct(t)
		return sn != nil && sn.Obj() != nil && sn.Obj().Pkg() == wpd.p.Types && !sn.Obj().Exported() && sn.Underlying() == wSt
	}
	for _, fld := range []*types.Var{ptrFld, capFld} {
		for _, uid := range wpd.idx.UsesOf[fld] {
			if parSel, isPS := wpd.idx.ParentUnparen(uid).(*ast.SelectorExpr); isPS && parSel.Sel == uid {
				par := wpd.idx.ParentUnparen(parSel)
				if u, isU := par.(*ast.UnaryExpr); isU && u.Op == token.AND {
					return false
				}
				if _, isInc := par.(*ast.IncDecStmt); isInc {
					return false
				}
			} else if u, isU := wpd.idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND {
				return false
			}
		}
	}
	okPair := true
	for _, ffile := range wpd.p.Syntax {
		ast.Inspect(ffile, func(bn ast.Node) bool {
			if !okPair || bn == nil {
				return false
			}
			switch x := bn.(type) {
			case *ast.CallExpr:
				tv := wpd.p.TypesInfo.Types[ast.Unparen(x.Fun)]
				if tv.IsType() && len(x.Args) == 1 && !syntaxutil.IsNilIdent(wpd.p.TypesInfo, x.Args[0]) {
					_, dstSt := syntaxutil.DerefAnyStructType(tv.Type)
					_, srcSt := syntaxutil.DerefAnyStructType(wpd.p.TypesInfo.TypeOf(x.Args[0]))
					if dstSt != nil && srcSt != nil {
						dstMatch := isSamePairFamily(tv.Type)
						srcMatch := isSamePairFamily(wpd.p.TypesInfo.TypeOf(x.Args[0]))
						if dstMatch != srcMatch {
							okPair = false
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if lsel, isS := ast.Unparen(lhs).(*ast.SelectorExpr); isS && lsel.Sel != nil {
						uobj := wpd.p.TypesInfo.Uses[lsel.Sel]
						if uobj == ptrFld || uobj == capFld {
							okPair = false
							return false
						}
					}
				}
			case *ast.CompositeLit:
				if !isSamePairFamily(wpd.p.TypesInfo.TypeOf(x)) || len(x.Elts) == 0 {
					return true
				}
				var hasPtr, hasCap bool
				var ptrVal, capVal ast.Expr
				if _, isKV0 := x.Elts[0].(*ast.KeyValueExpr); isKV0 {
					for _, elt := range x.Elts {
						kv, isKV := elt.(*ast.KeyValueExpr)
						if !isKV {
							okPair = false
							return false
						}
						kid, isID := ast.Unparen(kv.Key).(*ast.Ident)
						if !isID {
							okPair = false
							return false
						}
						if wpd.p.TypesInfo.Uses[kid] == ptrFld {
							hasPtr = true
							ptrVal = kv.Value
						} else if wpd.p.TypesInfo.Uses[kid] == capFld {
							hasCap = true
							capVal = kv.Value
						}
					}
				} else {
					for i, elt := range x.Elts {
						if i >= wSt.NumFields() {
							break
						}
						if wSt.Field(i) == ptrFld {
							hasPtr = true
							ptrVal = elt
						} else if wSt.Field(i) == capFld {
							hasCap = true
							capVal = elt
						}
					}
				}
				if !hasPtr || wpd.isZeroOwnerExpr(ptrVal) {
					return true
				}
				if !hasCap {
					okPair = false
					return false
				}
				enclFD := wpd.idx.EnclFunc[x]
				if enclFD == nil || enclFD.Recv == nil || len(enclFD.Recv.List) != 1 || len(enclFD.Recv.List[0].Names) != 1 {
					okPair = false
					return false
				}
				miRecv, _ := wpd.p.TypesInfo.Defs[enclFD.Recv.List[0].Names[0]].(*types.Var)
				if miRecv == nil || !types.Identical(types.Unalias(miRecv.Type()), types.NewPointer(capNamed)) {
					okPair = false
					return false
				}
				for _, ruid := range wpd.idx.UsesOf[miRecv] {
					if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, miRecv, ruid) {
						okPair = false
						return false
					}
				}
				capID, isCID := ast.Unparen(capVal).(*ast.Ident)
				if !isCID || wpd.p.TypesInfo.Uses[capID] != miRecv || !wpd.isGuardedIfacePtrExprInFunc(ptrVal, enclFD) {
					okPair = false
					return false
				}
			}
			return true
		})
	}
	return okPair
}
