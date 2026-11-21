package structmut

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (wpd *wrapperPtrDiscipline) classifyCallableSourcesAndConstructors() bool {
	wpd.funcLitsForField = map[types.Object][]*ast.FuncLit{}
	wpd.funcObjsForField = map[types.Object][]*types.Func{}
	wpd.funcLitsForLocal = map[*types.Var][]*ast.FuncLit{}
	wpd.funcObjsForLocal = map[*types.Var][]*types.Func{}
	wpd.unknownSourceFields = map[types.Object]bool{}
	wpd.unknownSourceLocals = map[*types.Var]bool{}
	for _, file := range wpd.p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if id, isID := ast.Unparen(x.X).(*ast.Ident); isID {
						if lv, okLV := wpd.p.TypesInfo.Uses[id].(*types.Var); okLV && lv != nil && wpd.sigMentionsOwner(lv.Type()) {
							wpd.unknownSourceLocals[lv] = true
						}
					} else if sel, isS := ast.Unparen(x.X).(*ast.SelectorExpr); isS {
						if sInfo := wpd.p.TypesInfo.Selections[sel]; sInfo != nil && sInfo.Kind() == types.FieldVal && wpd.sigMentionsOwner(sInfo.Obj().Type()) {
							wpd.unknownSourceFields[sInfo.Obj()] = true
						}
					}
				}
			case *ast.ValueSpec:
				for i, nm := range x.Names {
					lv, _ := wpd.p.TypesInfo.Defs[nm].(*types.Var)
					if lv != nil && wpd.sigMentionsOwner(lv.Type()) && i < len(x.Values) {
						lits, fns, okS := wpd.collectFuncValueSources(x.Values[i])
						if !okS || (len(lits) == 0 && len(fns) == 0) {
							wpd.unknownSourceLocals[lv] = true
						} else {
							wpd.funcLitsForLocal[lv] = append(wpd.funcLitsForLocal[lv], lits...)
							wpd.funcObjsForLocal[lv] = append(wpd.funcObjsForLocal[lv], fns...)
						}
					}
				}
			case *ast.AssignStmt:
				if len(x.Lhs) == len(x.Rhs) {
					for i, lhs := range x.Lhs {
						lid, isID := ast.Unparen(lhs).(*ast.Ident)
						if !isID {
							continue
						}
						lv, _ := wpd.p.TypesInfo.Defs[lid].(*types.Var)
						if lv == nil {
							lv, _ = wpd.p.TypesInfo.Uses[lid].(*types.Var)
						}
						if lv != nil && wpd.sigMentionsOwner(lv.Type()) {
							lits, fns, okS := wpd.collectFuncValueSources(x.Rhs[i])
							if !okS || (len(lits) == 0 && len(fns) == 0) {
								wpd.unknownSourceLocals[lv] = true
							} else {
								wpd.funcLitsForLocal[lv] = append(wpd.funcLitsForLocal[lv], lits...)
								wpd.funcObjsForLocal[lv] = append(wpd.funcObjsForLocal[lv], fns...)
							}
						}
					}
				} else {
					for _, lhs := range x.Lhs {
						if lid, isID := ast.Unparen(lhs).(*ast.Ident); isID {
							lv, _ := wpd.p.TypesInfo.Defs[lid].(*types.Var)
							if lv == nil {
								lv, _ = wpd.p.TypesInfo.Uses[lid].(*types.Var)
							}
							if lv != nil && wpd.sigMentionsOwner(lv.Type()) {
								wpd.unknownSourceLocals[lv] = true
							}
						}
					}
				}
			}
			return true
		})
	}
	for _, file := range wpd.p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.CompositeLit:
				if st, isSt := syntaxutil.UnderlyingType(wpd.p.TypesInfo.TypeOf(x)).(*types.Struct); isSt && len(x.Elts) > 0 {
					if _, isKV0 := x.Elts[0].(*ast.KeyValueExpr); !isKV0 {
						for i, elt := range x.Elts {
							if i < st.NumFields() {
								fobj := st.Field(i)
								if wpd.sigMentionsOwner(fobj.Type()) {
									lits, fns, okS := wpd.collectFuncValueSources(elt)
									if !okS {
										wpd.unknownSourceFields[fobj] = true
									} else {
										wpd.funcLitsForField[fobj] = append(wpd.funcLitsForField[fobj], lits...)
										wpd.funcObjsForField[fobj] = append(wpd.funcObjsForField[fobj], fns...)
									}
								}
							}
						}
					}
				}
			case *ast.KeyValueExpr:
				if kid, isID := ast.Unparen(x.Key).(*ast.Ident); isID {
					if fobj := wpd.p.TypesInfo.Uses[kid]; fobj != nil && wpd.sigMentionsOwner(fobj.Type()) {
						lits, fns, okS := wpd.collectFuncValueSources(x.Value)
						if !okS {
							wpd.unknownSourceFields[fobj] = true
						} else {
							wpd.funcLitsForField[fobj] = append(wpd.funcLitsForField[fobj], lits...)
							wpd.funcObjsForField[fobj] = append(wpd.funcObjsForField[fobj], fns...)
						}
					}
				}
			case *ast.AssignStmt:
				if len(x.Lhs) == len(x.Rhs) {
					for i, lhs := range x.Lhs {
						lhs = ast.Unparen(lhs)
						if sel, isS := lhs.(*ast.SelectorExpr); isS {
							if sInfo := wpd.p.TypesInfo.Selections[sel]; sInfo != nil && sInfo.Kind() == types.FieldVal && wpd.sigMentionsOwner(sInfo.Obj().Type()) {
								lits, fns, okS := wpd.collectFuncValueSources(x.Rhs[i])
								if !okS {
									wpd.unknownSourceFields[sInfo.Obj()] = true
								} else {
									wpd.funcLitsForField[sInfo.Obj()] = append(wpd.funcLitsForField[sInfo.Obj()], lits...)
									wpd.funcObjsForField[sInfo.Obj()] = append(wpd.funcObjsForField[sInfo.Obj()], fns...)
								}
							}
						}
					}
				} else {
					for _, lhs := range x.Lhs {
						if sel, isS := ast.Unparen(lhs).(*ast.SelectorExpr); isS {
							if sInfo := wpd.p.TypesInfo.Selections[sel]; sInfo != nil && sInfo.Kind() == types.FieldVal && wpd.sigMentionsOwner(sInfo.Obj().Type()) {
								wpd.unknownSourceFields[sInfo.Obj()] = true
							}
						}
					}
				}
			}
			return true
		})
	}

	wpd.seedBaseMethods = map[*types.Func]bool{wpd.seedFn: true}
	wpd.ptrCtorOfValue = map[*types.Func]bool{}
	wpd.ptrCtorOfIface = map[*types.Func]bool{}
	wpd.ptrCtorInterfaceToPtr = map[*types.Func]bool{}
	for fn, fd := range wpd.idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || fn.Pkg() != wpd.p.Types {
			continue
		}
		sig, okS := fn.Type().(*types.Signature)
		if !okS || sig.Results().Len() != 1 || !types.Identical(types.Unalias(sig.Results().At(0).Type()), wpd.dstOwner) {
			continue
		}
		if sig.Recv() != nil {
			if sig.Params().Len() == 0 && len(fd.Body.List) == 1 && fd.Recv != nil && len(fd.Recv.List) == 1 && len(fd.Recv.List[0].Names) == 1 {
				rv, _ := wpd.p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
				rPtr, isRP := types.Unalias(sig.Recv().Type()).(*types.Pointer)
				if rv != nil && isRP {
					if rNamed, isRN := types.Unalias(rPtr.Elem()).(*types.Named); isRN && rNamed.Obj() != nil &&
						rNamed.Obj().Pkg() == wpd.p.Types && !rNamed.Obj().Exported() && !wpd.instantiatedNamed[rNamed] {
						if rSt, isRS := rNamed.Underlying().(*types.Struct); isRS {
							hasForeign := false
							for fi := 0; fi < rSt.NumFields(); fi++ {
								if wpd.foreignReflectFields[rSt.Field(fi)] {
									hasForeign = true
									break
								}
							}
							if hasForeign {
								if ret, isRet := fd.Body.List[0].(*ast.ReturnStmt); isRet && len(ret.Results) == 1 {
									if valE, okL := wpd.isOwnerSingleFieldLit(ret.Results[0]); okL {
										if uc, isUC := valE.(*ast.CallExpr); isUC && len(uc.Args) == 1 && !uc.Ellipsis.IsValid() {
											utv := wpd.p.TypesInfo.Types[ast.Unparen(uc.Fun)]
											if utv.IsType() && syntaxutil.IsUnsafePointerType(utv.Type) {
												if rid, isRID := ast.Unparen(uc.Args[0]).(*ast.Ident); isRID && wpd.p.TypesInfo.Uses[rid] == rv {
													wpd.seedBaseMethods[fn] = true
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			continue
		}
		if fn.Exported() || sig.Params().Len() != 1 {
			continue
		}
		p0 := sig.Params().At(0)
		p0T := types.Unalias(p0.Type())
		if syntaxutil.IsNamedInPkg(p0T, "reflect", "Value") && len(fd.Body.List) == 1 {
			if ret, isRet := fd.Body.List[0].(*ast.ReturnStmt); isRet && len(ret.Results) == 1 {
				if valE, okL := wpd.isOwnerSingleFieldLit(ret.Results[0]); okL {
					if uc, isUC := valE.(*ast.CallExpr); isUC && len(uc.Args) == 1 && !uc.Ellipsis.IsValid() {
						utv := wpd.p.TypesInfo.Types[ast.Unparen(uc.Fun)]
						if utv.IsType() && syntaxutil.IsUnsafePointerType(utv.Type) {
							if pc, isPC := ast.Unparen(uc.Args[0]).(*ast.CallExpr); isPC && len(pc.Args) == 0 {
								pfn := syntaxutil.ResolveCalledFuncObj(wpd.p, pc.Fun)
								if pfn != nil && pfn.Pkg() != nil && pfn.Pkg().Path() == "reflect" && pfn.Name() == "Pointer" {
									if psel, isPS := ast.Unparen(pc.Fun).(*ast.SelectorExpr); isPS {
										if pid, isPID := ast.Unparen(psel.X).(*ast.Ident); isPID && wpd.p.TypesInfo.Uses[pid] == p0 {
											wpd.ptrCtorOfValue[fn] = true
										}
									}
								}
							}
						}
					}
				}
			}
		} else if isEmptyInterfaceType(p0T) && (len(fd.Body.List) == 1 || len(fd.Body.List) == 2) {
			stmt0OK := true
			if len(fd.Body.List) == 2 {
				ds, isDS := fd.Body.List[0].(*ast.DeclStmt)
				gd, isGD := (*ast.GenDecl)(nil), false
				if isDS {
					gd, isGD = ds.Decl.(*ast.GenDecl)
				}
				stmt0OK = isGD && gd.Tok == token.TYPE
			}
			ret, isRet := fd.Body.List[len(fd.Body.List)-1].(*ast.ReturnStmt)
			if stmt0OK && isRet && len(ret.Results) == 1 {
				if valE, okL := wpd.isOwnerSingleFieldLit(ret.Results[0]); okL {
					if dsel, isDS := valE.(*ast.SelectorExpr); isDS {
						if sInfo := wpd.p.TypesInfo.Selections[dsel]; sInfo != nil && sInfo.Kind() == types.FieldVal && len(sInfo.Index()) == 1 && sInfo.Index()[0] == 1 {
							if hcc, isHCC := ast.Unparen(dsel.X).(*ast.CallExpr); isHCC && len(hcc.Args) == 1 && !hcc.Ellipsis.IsValid() {
								htv := wpd.p.TypesInfo.Types[ast.Unparen(hcc.Fun)]
								if htv.IsType() && htv.Type != nil {
									if hPtr, isHP := types.Unalias(htv.Type).Underlying().(*types.Pointer); isHP {
										if hSt, isHS := types.Unalias(hPtr.Elem()).Underlying().(*types.Struct); isHS && hSt.NumFields() == 2 &&
											syntaxutil.IsUnsafePointerType(hSt.Field(0).Type()) && syntaxutil.IsUnsafePointerType(hSt.Field(1).Type()) {
											if ucc, isUCC := ast.Unparen(hcc.Args[0]).(*ast.CallExpr); isUCC && len(ucc.Args) == 1 {
												if uand, isUA := ast.Unparen(ucc.Args[0]).(*ast.UnaryExpr); isUA && uand.Op == token.AND {
													if pid, isPID := ast.Unparen(uand.X).(*ast.Ident); isPID && wpd.p.TypesInfo.Uses[pid] == p0 {
														wpd.ptrCtorOfIface[fn] = true
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		} else if p0Ptr, isPP := p0T.(*types.Pointer); isPP && isEmptyInterfaceType(p0Ptr.Elem()) && len(fd.Body.List) == 1 {
			if ret, isRet := fd.Body.List[0].(*ast.ReturnStmt); isRet && len(ret.Results) == 1 {
				if valE, okL := wpd.isOwnerSingleFieldLit(ret.Results[0]); okL {
					if ix, isIX := valE.(*ast.IndexExpr); isIX {
						if itv := wpd.p.TypesInfo.Types[ix.Index]; itv.Value != nil && itv.Value.Kind() == constant.Int {
							if iv, okIV := constant.Int64Val(itv.Value); okIV && iv == 1 {
								if acc, isACC := ast.Unparen(ix.X).(*ast.CallExpr); isACC && len(acc.Args) == 1 {
									atv := wpd.p.TypesInfo.Types[ast.Unparen(acc.Fun)]
									if atv.IsType() && atv.Type != nil {
										if aPtr, isAP := types.Unalias(atv.Type).Underlying().(*types.Pointer); isAP {
											if aArr, isAA := types.Unalias(aPtr.Elem()).Underlying().(*types.Array); isAA && aArr.Len() == 2 && syntaxutil.IsUnsafePointerType(aArr.Elem()) {
												if ucc, isUCC := ast.Unparen(acc.Args[0]).(*ast.CallExpr); isUCC && len(ucc.Args) == 1 {
													if pid, isPID := ast.Unparen(ucc.Args[0]).(*ast.Ident); isPID && wpd.p.TypesInfo.Uses[pid] == p0 {
														wpd.ptrCtorInterfaceToPtr[fn] = true
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	wpd.contextSensitiveFuncs = map[*types.Func]bool{}
	for fn := range wpd.seedBaseMethods {
		wpd.contextSensitiveFuncs[fn] = true
	}
	for fn := range wpd.ptrCtorOfValue {
		wpd.contextSensitiveFuncs[fn] = true
	}
	for fn := range wpd.ptrCtorOfIface {
		wpd.contextSensitiveFuncs[fn] = true
	}
	for fn := range wpd.ptrCtorInterfaceToPtr {
		wpd.contextSensitiveFuncs[fn] = true
	}
	wpd.ownerMethods = map[*types.Func]bool{}
	for mi := 0; mi < wpd.mset.Len(); mi++ {
		mfn, _ := wpd.mset.At(mi).Obj().(*types.Func)
		if mfn == nil || mfn.Pkg() != wpd.p.Types {
			continue
		}
		wpd.ownerMethods[mfn] = true
		if wpd.methodClass[mfn] != ptrMethodRawDeref {
			wpd.contextSensitiveFuncs[mfn] = true
		}
	}
	for cfn := range wpd.contextSensitiveFuncs {
		for _, uid := range wpd.idx.UsesOf[cfn] {
			if refconfine.EnclosingCallOfCalleeIdent(wpd.idx, uid) == nil {
				return false
			}
		}
	}
	for mfn := range wpd.ownerMethods {
		for _, uid := range wpd.idx.UsesOf[mfn] {
			sel, isS := wpd.idx.ParentMap[uid].(*ast.SelectorExpr)
			if !isS || sel.Sel != uid {
				return false
			}
			if sInfo := wpd.p.TypesInfo.Selections[sel]; sInfo == nil || sInfo.Kind() != types.MethodVal {
				return false
			}
			mc, isMC := wpd.idx.ParentUnparen(sel).(*ast.CallExpr)
			if !isMC || ast.Unparen(mc.Fun) != sel {
				return false
			}
		}
	}
	return true
}

func (wpd *wrapperPtrDiscipline) isNonMethodExprFuncRef(e ast.Expr) *types.Func {
	fnObj := syntaxutil.ResolveCalledFuncObj(wpd.p, e)
	if fnObj == nil || wpd.idx.FuncDecls[fnObj] == nil {
		return nil
	}
	if sig, okS := fnObj.Type().(*types.Signature); !okS || sig.Recv() != nil {
		return nil
	}
	return fnObj
}

func (wpd *wrapperPtrDiscipline) collectFuncValueSources(rhs ast.Expr) ([]*ast.FuncLit, []*types.Func, bool) {
	rhs = ast.Unparen(rhs)
	if syntaxutil.IsNilIdent(wpd.p.TypesInfo, rhs) {
		return nil, nil, true
	}
	if fl, isFL := rhs.(*ast.FuncLit); isFL {
		return []*ast.FuncLit{fl}, nil, true
	}
	if rid, isRID := rhs.(*ast.Ident); isRID {
		if lv, okLV := wpd.p.TypesInfo.Uses[rid].(*types.Var); okLV && lv != nil && !lv.IsField() && lv.Parent() != wpd.p.Types.Scope() {
			if !wpd.unknownSourceLocals[lv] && (len(wpd.funcLitsForLocal[lv]) > 0 || len(wpd.funcObjsForLocal[lv]) > 0) {
				return wpd.funcLitsForLocal[lv], wpd.funcObjsForLocal[lv], true
			}
			return nil, nil, false
		}
	}
	if fnObj := wpd.isNonMethodExprFuncRef(rhs); fnObj != nil {
		return nil, []*types.Func{fnObj}, true
	}
	if call, isC := rhs.(*ast.CallExpr); isC {
		callee := syntaxutil.ResolveCalledFuncObj(wpd.p, call.Fun)
		if callee != nil && wpd.idx.FuncDecls[callee] != nil && wpd.idx.FuncDecls[callee].Body != nil {
			var lits []*ast.FuncLit
			var fns []*types.Func
			okRet := true
			ast.Inspect(wpd.idx.FuncDecls[callee].Body, func(rn ast.Node) bool {
				if !okRet || rn == nil {
					return false
				}
				if _, isNested := rn.(*ast.FuncLit); isNested {
					return false
				}
				ret, isR := rn.(*ast.ReturnStmt)
				if !isR || len(ret.Results) != 1 {
					return true
				}
				r0 := ast.Unparen(ret.Results[0])
				if syntaxutil.IsNilIdent(wpd.p.TypesInfo, r0) {
					return true
				}
				if fl, isFL := r0.(*ast.FuncLit); isFL {
					lits = append(lits, fl)
				} else if rfn := wpd.isNonMethodExprFuncRef(r0); rfn != nil {
					fns = append(fns, rfn)
				} else {
					okRet = false
				}
				return false
			})
			if okRet {
				return lits, fns, true
			}
		}
	}
	return nil, nil, false
}

func (wpd *wrapperPtrDiscipline) sigMentionsOwner(t types.Type) bool {
	sig, isS := types.Unalias(t).(*types.Signature)
	if !isS {
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if types.Identical(types.Unalias(sig.Params().At(i).Type()), wpd.dstOwner) {
			return true
		}
	}
	for i := 0; i < sig.Results().Len(); i++ {
		if types.Identical(types.Unalias(sig.Results().At(i).Type()), wpd.dstOwner) {
			return true
		}
	}
	return false
}
