package capsule

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func isReflectZeroInterfaceCall(p *packages.Package, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Interface" {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "reflect" {
		return false
	}
	zCall, ok := ast.Unparen(sel.X).(*ast.CallExpr)
	if !ok || len(zCall.Args) != 1 {
		return false
	}
	zSel, ok := ast.Unparen(zCall.Fun).(*ast.SelectorExpr)
	if !ok || zSel.Sel == nil {
		return false
	}
	zFn, ok := p.TypesInfo.Uses[zSel.Sel].(*types.Func)
	return ok && zFn.Pkg() != nil && zFn.Pkg().Path() == "reflect" && zFn.Name() == "Zero"
}

func isSafeProtectedIfaceElemValue(
	p *packages.Package,
	val ast.Expr,
	allProtected map[*types.Named]bool,
	isImmPtr func(types.Type) bool,
) bool {
	if syntaxutil.IsNilIdent(p.TypesInfo, val) || isReflectZeroInterfaceCall(p, val) {
		return true
	}
	valT := p.TypesInfo.TypeOf(val)
	if valT == nil {
		return false
	}
	if types.IsInterface(valT) {
		ix, isIX := ast.Unparen(val).(*ast.IndexExpr)
		if !isIX {
			return false
		}
		hitSt, fld := lhsRootFamilyField(p, ix.X, allProtected)
		return hitSt != nil && fld != nil && !fld.Exported()
	}
	return !refconfine.TypeCarriesMutableRefWith(valT, isImmPtr)
}

func verifyLockedStructFamilyDiscipline(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshstruct.FreshLocalsCache,
	rootNamed *types.Named,
	family map[*types.Named]bool,
	childProtected map[*types.Named]bool,
	casHelperStructs map[*types.Named]*ast.FuncDecl,
	verifiedCapsuleRoots map[*types.Named]bool,
	muField, flagField *types.Var,
	onceFn *types.Func,
	onceCone map[*types.Func]bool,
	builderInitFn *types.Func,
	exempt map[ast.Node]bool,
	builderExempt map[ast.Node]bool,
) ([]syntaxutil.TypeRef, []string, string, ast.Node, bool) {
	allProtected := map[*types.Named]bool{}
	for st := range family {
		allProtected[st] = true
		if len(casHelperStructs) > 0 {
			if uSt, okSt := st.Underlying().(*types.Struct); okSt {
				for i := 0; i < uSt.NumFields(); i++ {
					f := uSt.Field(i)
					casSt, isN := types.Unalias(f.Type()).(*types.Named)
					if !isN || casHelperStructs[casSt] == nil {
						continue
					}
					if f.Exported() {
						return nil, nil, "exported_cas_helper_field", nil, false
					}
					for _, id := range idx.UsesOf[f] {
						sel, isSel := idx.ParentUnparen(id).(*ast.SelectorExpr)
						if !isSel || sel.Sel != id {
							return nil, nil, "invalid_cas_helper_use", id, false
						}
						msel, isMS := idx.ParentUnparen(sel).(*ast.SelectorExpr)
						if !isMS || ast.Unparen(msel.X) != sel {
							return nil, nil, "invalid_cas_helper_use", id, false
						}
						call, isCall := idx.ParentUnparen(msel).(*ast.CallExpr)
						if !isCall || ast.Unparen(call.Fun) != msel {
							return nil, nil, "invalid_cas_helper_use", id, false
						}
					}
				}
			}
		}
	}
	for st := range childProtected {
		allProtected[st] = true
	}
	isImmPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		elem, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && (allProtected[elem] || verifiedCapsuleRoots[elem])
	}

	for _, id := range idx.UsesOf[muField] {
		encl := idx.SyncEnclFuncDecl(id)
		if encl == nil {
			return nil, nil, "mutex_use_outside_once_cone", id, false
		}
		fn, _ := p.TypesInfo.Defs[encl.Name].(*types.Func)
		if fn == nil || !onceCone[fn] {
			return nil, nil, "mutex_use_outside_once_cone", id, false
		}
		sel, isSel := idx.ParentUnparen(id).(*ast.SelectorExpr)
		if !isSel || sel.Sel != id {
			return nil, nil, "invalid_mutex_field_use", id, false
		}
		msel, isMSel := idx.ParentUnparen(sel).(*ast.SelectorExpr)
		if !isMSel || ast.Unparen(msel.X) != sel || (msel.Sel.Name != "Lock" && msel.Sel.Name != "Unlock") {
			return nil, nil, "invalid_mutex_field_use", id, false
		}
		call, isCall := idx.ParentUnparen(msel).(*ast.CallExpr)
		if !isCall || ast.Unparen(call.Fun) != msel {
			return nil, nil, "invalid_mutex_field_use", id, false
		}
	}

	if freshCache == nil {
		freshCache = freshstruct.NewFreshLocalsCache(p, idx)
	}
	expGuardFields, guardedExpLHS, badExpNode, okExpGuards := deriveOnceExportedWriteGuardFields(
		p, idx, freshCache, rootNamed, family, onceFn, onceCone, builderExempt,
	)
	if !okExpGuards {
		return nil, nil, "unguarded_exported_field_write_in_once_cone", badExpNode, false
	}

	fastInitMethods := collectFastOnceWrapperMethods(p, idx, rootNamed, onceFn, flagField)
	guardSet := map[syntaxutil.TypeRef]bool{}
	seenValContained := map[types.Type]bool{}
	var addValueContainedGuards func(t types.Type) bool
	addValueContainedGuards = func(t types.Type) bool {
		if t == nil {
			return true
		}
		t = types.Unalias(t)
		if seenValContained[t] {
			return true
		}
		seenValContained[t] = true
		if vtNamed, isN := t.(*types.Named); isN {
			if vtNamed.Obj() == nil || vtNamed.Obj().Pkg() != p.Types || casHelperStructs[vtNamed] != nil {
				return true
			}
			if vtNamed != rootNamed && !vtNamed.Obj().Exported() {
				vRef, _, vSt, okV := syntaxutil.TypeRefOfStructFull(vtNamed)
				if okV && vSt.NumFields() > 0 {
					if !vRef.Valid() {
						return false
					}
					guardSet[vRef] = true
				}
			}
		} else if _, isSt := t.Underlying().(*types.Struct); isSt {
			if vRef, _, vSt, okV := syntaxutil.TypeRefOfStructFull(t); okV && vSt.NumFields() > 0 {
				if !vRef.Valid() {
					return false
				}
				guardSet[vRef] = true
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if !addValueContainedGuards(u.Field(i).Type()) {
					return false
				}
			}
		case *types.Array:
			return addValueContainedGuards(u.Elem())
		}
		return true
	}
	for st := range allProtected {
		if st.Obj() == nil {
			continue
		}
		if st != rootNamed {
			ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: st.Obj().Name()}
			if !ref.Valid() {
				return nil, nil, "invalid_guard_type_ref", nil, false
			}
			guardSet[ref] = true
		}
		if !addValueContainedGuards(st) {
			return nil, nil, "invalid_guard_type_ref", nil, false
		}
	}

	checkFamilyWriteExpr := func(expr ast.Expr, inAllowedWriter bool, freshVars map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) bool {
		if star, isStar := ast.Unparen(expr).(*ast.StarExpr); isStar {
			if st := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(star.X)); st != nil {
				if family[st] {
					return false
				}
				if childProtected[st] {
					return inAllowedWriter || freshstruct.IsRootedAtFreshLocal(p, star.X, freshVars, freshEsc)
				}
			}
		}
		hitSt, fld := lhsRootFamilyField(p, expr, allProtected)
		if hitSt == nil {
			return true
		}
		if freshstruct.IsRootedAtFreshLocal(p, expr, freshVars, freshEsc) {
			return true
		}
		if !inAllowedWriter {
			return false
		}
		if family[hitSt] && fld != nil && fld.Exported() && !guardedExpLHS[ast.Unparen(expr)] {
			return false
		}
		return true
	}

	valid := true
	rejReason := ""
	var rejNode ast.Node
	failWith := func(reason string, at ast.Node) {
		if valid {
			valid = false
			rejReason = reason
			rejNode = at
		}
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !valid || n == nil {
				return false
			}
			syncEncl := idx.SyncEnclFuncDecl(n)
			var enclFn *types.Func
			if syncEncl != nil {
				enclFn, _ = p.TypesInfo.Defs[syncEncl.Name].(*types.Func)
			}
			inAllowedWriter := enclFn != nil && (onceCone[enclFn] || enclFn == builderInitFn)
			freshVars, freshEsc := freshCache.Get(syncEncl)

			switch x := n.(type) {
			case *ast.AssignStmt:
				if builderExempt[x] {
					return true
				}
				for li, lhs := range x.Lhs {
					if !checkFamilyWriteExpr(lhs, inAllowedWriter, freshVars, freshEsc) {
						failWith("family_mutation_outside_once_cone", x)
						return false
					}
					if ix, isIX := ast.Unparen(lhs).(*ast.IndexExpr); isIX && !freshstruct.IsRootedAtFreshLocal(p, ix, freshVars, freshEsc) {
						if hitSt, _ := lhsRootFamilyField(p, ix, allProtected); hitSt != nil {
							if elemT := p.TypesInfo.TypeOf(ix); elemT != nil && types.IsInterface(elemT) {
								if len(x.Lhs) != len(x.Rhs) || !isSafeProtectedIfaceElemValue(p, x.Rhs[li], allProtected, isImmPtr) {
									failWith("unsafe_iface_container_elem_write", x)
									return false
								}
							}
						}
					}
				}
			case *ast.IncDecStmt:
				if !checkFamilyWriteExpr(x.X, inAllowedWriter, freshVars, freshEsc) {
					failWith("family_mutation_outside_once_cone", x)
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && !checkFamilyWriteExpr(x.Key, inAllowedWriter, freshVars, freshEsc)) ||
						(x.Value != nil && !checkFamilyWriteExpr(x.Value, inAllowedWriter, freshVars, freshEsc)) {
						failWith("family_mutation_outside_once_cone", x)
						return false
					}
					for _, be := range []ast.Expr{x.Key, x.Value} {
						if ix, isIX := ast.Unparen(be).(*ast.IndexExpr); isIX && !freshstruct.IsRootedAtFreshLocal(p, ix, freshVars, freshEsc) {
							if hitSt, _ := lhsRootFamilyField(p, ix, allProtected); hitSt != nil {
								if elemT := p.TypesInfo.TypeOf(ix); elemT != nil && types.IsInterface(elemT) {
									failWith("unsafe_iface_container_elem_write", x)
									return false
								}
							}
						}
					}
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if !checkFamilyWriteExpr(x.Args[0], inAllowedWriter, freshVars, freshEsc) {
								failWith("family_mutation_outside_once_cone", x)
								return false
							}
							if (b.Name() == "append" || b.Name() == "copy") && !freshstruct.IsRootedAtFreshLocal(p, x.Args[0], freshVars, freshEsc) {
								if hitSt, _ := lhsRootFamilyField(p, x.Args[0], allProtected); hitSt != nil {
									if sl, isSl := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(x.Args[0])).(*types.Slice); isSl && types.IsInterface(sl.Elem()) {
										if b.Name() == "copy" {
											if len(x.Args) < 2 {
												failWith("unsafe_iface_container_elem_write", x)
												return false
											}
											if srcHit, srcFld := lhsRootFamilyField(p, x.Args[1], allProtected); srcHit == nil || srcFld == nil || srcFld.Exported() {
												failWith("unsafe_iface_container_elem_write", x)
												return false
											}
										} else if x.Ellipsis.IsValid() {
											if len(x.Args) != 2 {
												failWith("unsafe_iface_container_elem_write", x)
												return false
											}
											srcHit, srcFld := lhsRootFamilyField(p, x.Args[1], allProtected)
											if srcHit == nil || srcFld == nil || srcFld.Exported() {
												failWith("unsafe_iface_container_elem_write", x)
												return false
											}
										} else {
											for _, elemArg := range x.Args[1:] {
												if !isSafeProtectedIfaceElemValue(p, elemArg, allProtected, isImmPtr) {
													failWith("unsafe_iface_container_elem_write", x)
													return false
												}
											}
										}
									}
								}
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if x.Op != token.AND {
					return true
				}
				if builderExempt[x] || freshstruct.IsRootedAtFreshLocal(p, x.X, freshVars, freshEsc) {
					return true
				}
				if sel, isSel := ast.Unparen(x.X).(*ast.SelectorExpr); isSel {
					if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal && !syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
						hitFamily := false
						syntaxutil.ForEachSelectionHopStruct(selInfo, func(st *types.Named) {
							if family[st] {
								hitFamily = true
							}
						})
						if hitFamily {
							fld, _ := selInfo.Obj().(*types.Var)
							if fld == flagField {
								call, isCall := idx.ParentUnparen(x).(*ast.CallExpr)
								if !isCall || len(call.Args) == 0 || ast.Unparen(call.Args[0]) != x {
									failWith("illegal_once_flag_addr", x)
									return false
								}
								if isAtomicUint32Call(p, call, "LoadUint32") {
									if exempt != nil {
										exempt[x] = true
									}
									return true
								}
								if inAllowedWriter && isAtomicUint32Call(p, call, "StoreUint32") {
									if exempt != nil {
										exempt[x] = true
									}
									return true
								}
								failWith("illegal_once_flag_addr", x)
								return false
							}
							if fld != nil && !fld.Exported() && !inAllowedWriter &&
								syncEncl != nil && !idx.InFuncLit[x] && !idx.InGoStmt[x] {
								if fldNamed, isFN := types.Unalias(fld.Type()).(*types.Named); isFN && casHelperStructs[fldNamed] != nil {
									failWith("illegal_cas_helper_addr", x)
									return false
								}
								if _, isPtr := types.Unalias(fld.Type()).(*types.Pointer); !isPtr {
									if subRef, _, subSt, okSub := syntaxutil.TypeRefOfStructFull(fld.Type()); okSub && subRef.Valid() && subSt.NumFields() > 0 {
										if !localPtrDominatedByOnceInit(p, idx, syncEncl, sel.X, x.Pos(), rootNamed, flagField, onceFn, fastInitMethods) {
											failWith("substruct_addr_not_dominated_by_once_init", x)
											return false
										}
										guardOK := true
										syntaxutil.ForEachValueContainedStructType(fld.Type(), func(vt types.Type) {
											if vRef, _, vSt, okV := syntaxutil.TypeRefOfStructFull(vt); okV && vSt.NumFields() > 0 {
												if !vRef.Valid() {
													guardOK = false
													return
												}
												guardSet[vRef] = true
											}
										})
										if guardOK {
											guardSet[subRef] = true
											if exempt != nil {
												exempt[x] = true
											}
											return true
										}
									}
								}
							}
							failWith("illegal_family_field_addr", x)
							return false
						}
					}
				}
				if hitSt, _ := lhsRootFamilyField(p, x.X, allProtected); hitSt != nil {
					failWith("illegal_family_field_addr", x)
					return false
				}
			}
			return true
		})
	}
	if !valid {
		return nil, nil, rejReason, rejNode, false
	}

	if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
		Index:                         idx,
		IsImmutablePtr:                isImmPtr,
		AllowReturnFromUnexportedFunc: true,
		AllowImmutableInterfaceElem: func(containerExpr ast.Expr) bool {
			hitSt, fld := lhsRootFamilyField(p, containerExpr, allProtected)
			return hitSt != nil && fld != nil && !fld.Exported()
		},
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
			if !isSel {
				return false, false
			}
			selInfo := p.TypesInfo.Selections[sel]
			if selInfo == nil || selInfo.Kind() != types.FieldVal {
				return false, false
			}
			if refconfine.IsInsideExemptWriteOrAddr(idx, sel, builderExempt) || guardedExpLHS[sel] {
				return false, false
			}
			syncEncl := idx.SyncEnclFuncDecl(sel)
			freshVars, freshEsc := freshCache.Get(syncEncl)
			if freshstruct.IsRootedAtFreshLocal(p, sel, freshVars, freshEsc) {
				return false, false
			}
			var enclFn *types.Func
			if syncEncl != nil {
				enclFn, _ = p.TypesInfo.Defs[syncEncl.Name].(*types.Func)
			}
			inAllowedWriter := enclFn != nil && (onceCone[enclFn] || enclFn == builderInitFn)
			fld, _ := selInfo.Obj().(*types.Var)
			hitProtected := false
			hitExportedFamily := false
			syntaxutil.ForEachSelectionHopStruct(selInfo, func(hop *types.Named) {
				if allProtected[hop] {
					hitProtected = true
				}
				if family[hop] && fld != nil && fld.Exported() {
					hitExportedFamily = true
				}
			})
			if !hitProtected {
				return false, false
			}
			if inAllowedWriter && !hitExportedFamily {
				return false, false
			}
			ft := selInfo.Type()
			if fn, isFN := types.Unalias(ft).(*types.Named); isFN && casHelperStructs[fn] != nil {
				return false, false
			}
			if refconfine.IsDirectMutableRefWith(ft, isImmPtr) {
				return true, true
			}
			if refconfine.TypeCarriesMutableRefWith(ft, isImmPtr) {
				return false, true
			}
			return false, false
		},
		AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
			return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && syntaxutil.IsReflectTypeOfCall(p, call)
		},
	}) {
		return nil, nil, "unconfined_family_ref_read", nil, false
	}
	var guardTypes []syntaxutil.TypeRef
	if len(guardSet) > 0 {
		guardTypes = make([]syntaxutil.TypeRef, 0, len(guardSet))
		for g := range guardSet {
			guardTypes = append(guardTypes, g)
		}
		sort.Slice(guardTypes, func(i, j int) bool { return guardTypes[i].Key() < guardTypes[j].Key() })
	}
	return guardTypes, expGuardFields, "", nil, true
}

func lhsRootFamilyField(p *packages.Package, expr ast.Expr, family map[*types.Named]bool) (*types.Named, *types.Var) {
	cur := ast.Unparen(expr)
	for {
		switch e := cur.(type) {
		case *ast.SelectorExpr:
			if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				var matched *types.Named
				syntaxutil.ForEachSelectionHopStruct(selInfo, func(st *types.Named) {
					if matched == nil && family[st] {
						matched = st
					}
				})
				if matched != nil {
					fld, _ := selInfo.Obj().(*types.Var)
					return matched, fld
				}
			}
			cur = ast.Unparen(e.X)
		case *ast.IndexExpr:
			cur = ast.Unparen(e.X)
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
		default:
			return nil, nil
		}
	}
}

