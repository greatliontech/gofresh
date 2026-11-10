package freshstruct

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// CollectMutatedStructTypes summarizes every non-exempted struct/container
// mutation and conditional struct mutation across p.Syntax.
func CollectMutatedStructTypes(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	exempted map[ast.Node]bool,
	exemptFamilyByFunc map[*ast.FuncDecl]map[*types.Named]bool,
	exemptReadFields map[*types.Var]bool,
) ([]syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation) {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return nil, nil
	}
	if freshCache == nil {
		freshCache = NewFreshLocalsCache(p, idx)
	}
	seen := map[syntaxutil.TypeRef]bool{}
	condSeen := map[syntaxutil.ConditionalStructMutation]bool{}
	recordStructAt := func(at ast.Node, t types.Type) {
		ref, named, st, ok := syntaxutil.TypeRefOfStructFull(t)
		if !ok || st == nil || (named == nil && st.NumFields() == 0) || !ref.Valid() {
			return
		}
		if named != nil {
			if syncFD := idx.SyncEnclFuncDecl(at); syncFD != nil && exemptFamilyByFunc[syncFD][named] {
				return
			}
		}
		seen[ref] = true
	}
	recordNamedContainerAt := func(_ ast.Node, t types.Type) {
		if t == nil {
			return
		}
		n, isN := types.Unalias(t).(*types.Named)
		if !isN || n.Obj() == nil || n.Obj().Pkg() == nil || n.Obj().Parent() != n.Obj().Pkg().Scope() {
			return
		}
		switch n.Underlying().(type) {
		case *types.Slice, *types.Map:
			ref := syntaxutil.TypeRef{Pkg: n.Obj().Pkg().Path(), Name: n.Obj().Name()}
			if ref.Valid() {
				seen[ref] = true
			}
		}
	}
	recordEscapedArgTypes := func(at ast.Node, root types.Type, includeUnexportedFields bool) {
		syncFD := idx.SyncEnclFuncDecl(at)
		type visitKey struct {
			t           types.Type
			addressable bool
		}
		visited := map[visitKey]bool{}
		var walk func(t types.Type, addressable bool)
		walk = func(t types.Type, addressable bool) {
			if t == nil {
				return
			}
			t = types.Unalias(t)
			if named, isNamed := t.(*types.Named); isNamed && syncFD != nil && exemptFamilyByFunc[syncFD][named] {
				return
			}
			vk := visitKey{t: t, addressable: addressable}
			if visited[vk] {
				return
			}
			visited[vk] = true
			if addressable {
				if _, isSt := t.Underlying().(*types.Struct); isSt {
					recordStructAt(at, t)
				}
			}
			switch u := t.Underlying().(type) {
			case *types.Pointer:
				walk(u.Elem(), true)
			case *types.Slice:
				recordNamedContainerAt(at, t)
				walk(u.Elem(), true)
			case *types.Map:
				recordNamedContainerAt(at, t)
				walk(u.Key(), false)
				walk(u.Elem(), true)
			case *types.Chan:
				walk(u.Elem(), false)
			case *types.Array:
				walk(u.Elem(), addressable)
			case *types.Struct:
				for i := 0; i < u.NumFields(); i++ {
					f := u.Field(i)
					if !includeUnexportedFields && !f.Exported() && !f.Embedded() {
						if addressable {
							syntaxutil.ForEachValueContainedStructType(f.Type(), func(vt types.Type) {
								recordStructAt(at, vt)
							})
						} else if refconfine.TypeCarriesMutableRef(f.Type()) {
							if tNamed, isTN := t.(*types.Named); isTN && tNamed.Obj() != nil && !tNamed.Obj().Exported() {
								recordStructAt(at, t)
							}
						}
						continue
					}
					walk(f.Type(), addressable)
				}
			}
		}
		walk(root, false)
	}
	recordReflectiveArgTypes := func(at ast.Node, root types.Type) {
		recordEscapedArgTypes(at, root, false)
	}
	recordGenericArgTypes := func(at ast.Node, root types.Type) {
		recordEscapedArgTypes(at, root, true)
	}

	pkgFresh := ComputePackageFreshConstructors(p, idx, confinedCacheMaps)
	for cm := range pkgFresh.condGuards {
		if cm.Valid() {
			condSeen[cm] = true
		}
	}

	getFresh := func(fd *ast.FuncDecl) (map[*types.Var]bool, map[*types.Var]token.Pos) {
		return freshCache.Get(fd)
	}
	isFreshMutTarget := func(fd *ast.FuncDecl, expr ast.Expr, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) bool {
		if IsRootedAtFreshLocal(p, expr, fresh, freshEsc) {
			return true
		}
		return pkgFresh.IsFreshMutationTarget(fd, expr)
	}
	isFreshAddrTarget := func(fd *ast.FuncDecl, inner ast.Expr, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) bool {
		if IsRootedAtFreshLocal(p, inner, fresh, freshEsc) {
			return true
		}
		return pkgFresh.IsFreshAddrOrValue(fd, inner)
	}

	recordMutatedExpr := func(at ast.Node, expr ast.Expr, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) {
		syncFD := idx.SyncEnclFuncDecl(at)
		if isFreshMutTarget(syncFD, expr, fresh, freshEsc) {
			return
		}
		if syncFD != nil && refconfine.IsByValueFieldChainOnExemptFamily(p, expr, exemptFamilyByFunc[syncFD]) {
			return
		}
		cur := ast.Unparen(expr)
		first := true
		for {
			switch e := cur.(type) {
			case *ast.StarExpr:
				if first {
					syntaxutil.ForEachValueContainedStructType(p.TypesInfo.TypeOf(e.X), func(vt types.Type) {
						recordStructAt(at, vt)
					})
					if ptr, isPtr := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(e.X)).(*types.Pointer); isPtr {
						elem := types.Unalias(ptr.Elem())
						syntaxutil.ForEachValueContainedStructType(elem, func(vt types.Type) {
							recordStructAt(at, vt)
						})
						if sl, isSl := elem.Underlying().(*types.Slice); isSl {
							syntaxutil.ForEachValueContainedStructType(sl.Elem(), func(vt types.Type) {
								recordStructAt(at, vt)
							})
						}
					}
				}
				return
			case *ast.SelectorExpr:
				if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
					syntaxutil.ForEachSelectionHopStructType(selInfo, func(vt types.Type) {
						recordStructAt(at, vt)
					})
					if first {
						syntaxutil.ForEachValueContainedStructType(selInfo.Type(), func(vt types.Type) {
							recordStructAt(at, vt)
						})
					}
					if syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
						return
					}
					if _, isPtr := types.Unalias(p.TypesInfo.TypeOf(e.X)).(*types.Pointer); isPtr {
						return
					}
					cur = ast.Unparen(e.X)
					first = false
					continue
				}
				if v, ok := p.TypesInfo.Uses[e.Sel].(*types.Var); ok && v != nil && !v.IsField() {
					if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr {
						recordNamedContainerAt(at, v.Type())
						syntaxutil.ForEachValueContainedStructType(v.Type(), func(vt types.Type) {
							recordStructAt(at, vt)
						})
					}
				}
				return
			case *ast.Ident:
				if v, ok := p.TypesInfo.Uses[e].(*types.Var); ok && v != nil && !v.IsField() &&
					v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
					if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr {
						recordNamedContainerAt(at, v.Type())
						syntaxutil.ForEachValueContainedStructType(v.Type(), func(vt types.Type) {
							recordStructAt(at, vt)
						})
					}
				}
				return
			case *ast.IndexExpr:
				if first {
					syntaxutil.ForEachValueContainedStructType(p.TypesInfo.TypeOf(e), func(vt types.Type) {
						recordStructAt(at, vt)
					})
				}
				recordNamedContainerAt(at, p.TypesInfo.TypeOf(e.X))
				cur = ast.Unparen(e.X)
				first = false
				continue
			case *ast.SliceExpr:
				recordNamedContainerAt(at, p.TypesInfo.TypeOf(e.X))
				cur = ast.Unparen(e.X)
				first = false
				continue
			default:
				return
			}
		}
	}

	recordUnsafeSliceArg := func(at ast.Node, arg ast.Expr) {
		argT := p.TypesInfo.TypeOf(arg)
		recordStructAt(at, argT)
		if ptr, isPtr := syntaxutil.UnderlyingType(argT).(*types.Pointer); isPtr {
			syntaxutil.ForEachValueContainedStructType(ptr.Elem(), func(vt types.Type) {
				recordStructAt(at, vt)
			})
		}
	}

	unexportedForeignRecvStruct := func(callee *types.Func) *types.Named {
		if callee == nil {
			return nil
		}
		orig := callee.Origin()
		if orig.Pkg() == nil || orig.Pkg() == p.Types {
			return nil
		}
		sig, okSig := orig.Type().(*types.Signature)
		if !okSig || sig.Recv() == nil {
			return nil
		}
		ptr, isPtr := types.Unalias(sig.Recv().Type()).(*types.Pointer)
		if !isPtr {
			return nil
		}
		named, isN := types.Unalias(ptr.Elem()).(*types.Named)
		if !isN || named.Obj() == nil || named.Obj().Exported() {
			return nil
		}
		if _, isSt := named.Underlying().(*types.Struct); !isSt {
			return nil
		}
		return named
	}

	directCallFuns := map[ast.Node]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			if call, ok := n.(*ast.CallExpr); ok {
				cur := ast.Unparen(call.Fun)
				directCallFuns[cur] = true
				switch e := cur.(type) {
				case *ast.IndexExpr:
					directCallFuns[ast.Unparen(e.X)] = true
				case *ast.IndexListExpr:
					directCallFuns[ast.Unparen(e.X)] = true
				}
			}
			if exempted[n] {
				return true
			}
			syncEncl := idx.SyncEnclFuncDecl(n)
			fresh, freshEsc := getFresh(syncEncl)

			switch x := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					recordMutatedExpr(x, lhs, fresh, freshEsc)
					if (syncEncl == nil || syncEncl.Name == nil || syncEncl.Name.Name != "init") && syntaxutil.RootPkgScopeVar(p, lhs) != nil {
						if len(x.Lhs) == len(x.Rhs) && i < len(x.Rhs) {
							rhs := x.Rhs[i]
							if !isFreshAddrTarget(syncEncl, rhs, fresh, freshEsc) && !syntaxutil.IsNilIdent(p.TypesInfo, rhs) && !syntaxutil.IsTypedNilSliceConv(p, rhs) {
								recordNamedContainerAt(x, p.TypesInfo.TypeOf(rhs))
							}
						}
					}
				}
			case *ast.IncDecStmt:
				recordMutatedExpr(x, x.X, fresh, freshEsc)
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if x.Key != nil {
						recordMutatedExpr(x, x.Key, fresh, freshEsc)
					}
					if x.Value != nil {
						recordMutatedExpr(x, x.Value, fresh, freshEsc)
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND && !isFreshAddrTarget(syncEncl, x.X, fresh, freshEsc) {
					inner := ast.Unparen(x.X)
					switch in := inner.(type) {
					case *ast.SelectorExpr:
						if selInfo := p.TypesInfo.Selections[in]; selInfo != nil && selInfo.Kind() == types.FieldVal {
							_, _, subSt, isSubStruct := syntaxutil.TypeRefOfStructFull(selInfo.Type())
							if !(isSubStruct && subSt.NumFields() > 0 && !selInfo.Obj().Exported()) && !refconfine.IsPureAtomicLoadArg(p, idx, x) {
								recordMutatedExpr(x, in, fresh, freshEsc)
							}
						}
					case *ast.IndexExpr:
						_, _, elemSt, isElemStruct := syntaxutil.TypeRefOfStructFull(p.TypesInfo.TypeOf(in))
						if !(isElemStruct && elemSt.NumFields() > 0) {
							recordMutatedExpr(x, in, fresh, freshEsc)
						}
					}
				}
			case *ast.CallExpr:
				if tv := p.TypesInfo.Types[x.Fun]; tv.IsType() && len(x.Args) == 1 {
					dstT := types.Unalias(tv.Type)
					srcT := types.Unalias(p.TypesInfo.TypeOf(x.Args[0]))
					if _, isSrcNamed := srcT.(*types.Named); isSrcNamed && !types.Identical(dstT, srcT) &&
						!isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) && !syntaxutil.IsNilIdent(p.TypesInfo, x.Args[0]) && !syntaxutil.IsTypedNilSliceConv(p, x.Args[0]) {
						recordNamedContainerAt(x, srcT)
					}
					if syntaxutil.IsUnsafePointerType(dstT) {
						if !refconfine.IsSafeAtomicPointerValueArg(p, idx, x) && !refconfine.IsPureAtomicLoadInnerConv(p, idx, x) && !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) {
							if ptr, isPtr := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(x.Args[0])).(*types.Pointer); isPtr {
								syntaxutil.ForEachValueContainedStructType(ptr.Elem(), func(vt types.Type) {
									recordStructAt(x, vt)
								})
							}
						}
					} else if dstPtr, isDstPtr := dstT.Underlying().(*types.Pointer); isDstPtr {
						if srcPtr, isSrcPtr := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(x.Args[0])).(*types.Pointer); isSrcPtr {
							dstElem := types.Unalias(dstPtr.Elem())
							srcElem := types.Unalias(srcPtr.Elem())
							if !types.Identical(dstElem, srcElem) && !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) {
								if _, isSt := srcElem.Underlying().(*types.Struct); isSt {
									syntaxutil.ForEachValueContainedStructType(srcElem, func(vt types.Type) {
										recordStructAt(x, vt)
									})
								}
							}
						}
					}
					return true
				}
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if len(x.Args) > 0 {
								recordMutatedExpr(x, x.Args[0], fresh, freshEsc)
								if !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) && !syntaxutil.IsNilIdent(p.TypesInfo, x.Args[0]) && !syntaxutil.IsTypedNilSliceConv(p, x.Args[0]) {
									recordNamedContainerAt(x, p.TypesInfo.TypeOf(x.Args[0]))
								}
								if (b.Name() == "clear" || b.Name() == "copy" || b.Name() == "append") && !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) {
									if sl, isSl := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(x.Args[0])).(*types.Slice); isSl {
										syntaxutil.ForEachValueContainedStructType(sl.Elem(), func(vt types.Type) {
											recordStructAt(x, vt)
										})
									}
								}
							}
						case "SliceData":
							if len(x.Args) > 0 && !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) && !syntaxutil.IsNilIdent(p.TypesInfo, x.Args[0]) && !syntaxutil.IsTypedNilSliceConv(p, x.Args[0]) {
								recordNamedContainerAt(x, p.TypesInfo.TypeOf(x.Args[0]))
							}
						case "Slice":
							if len(x.Args) > 0 {
								recordUnsafeSliceArg(x, x.Args[0])
							}
						}
						return true
					}
				} else if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
					if b, isB := p.TypesInfo.Uses[sel.Sel].(*types.Builtin); isB && len(x.Args) > 0 {
						switch b.Name() {
						case "Slice":
							recordUnsafeSliceArg(x, x.Args[0])
							return true
						case "SliceData":
							if !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) && !syntaxutil.IsNilIdent(p.TypesInfo, x.Args[0]) && !syntaxutil.IsTypedNilSliceConv(p, x.Args[0]) {
								recordNamedContainerAt(x, p.TypesInfo.TypeOf(x.Args[0]))
							}
							return true
						}
					}
				}
				if callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun); callee != nil {
					if recvSt := unexportedForeignRecvStruct(callee); recvSt != nil {
						if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
							if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil {
								switch selInfo.Kind() {
								case types.MethodVal:
									if !isFreshAddrTarget(syncEncl, sel.X, fresh, freshEsc) {
										recordStructAt(x, recvSt)
										recordMutatedExpr(x, sel.X, fresh, freshEsc)
									}
								case types.MethodExpr:
									if len(x.Args) == 0 || !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) {
										recordStructAt(x, recvSt)
										if len(x.Args) > 0 {
											recordMutatedExpr(x, x.Args[0], fresh, freshEsc)
										}
									}
								}
							}
						}
					}
					if callee.Pkg() != nil && callee.Pkg().Path() == "reflect" && callee.Name() == "ValueOf" && len(x.Args) == 1 {
						if !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) {
							recordReflectiveArgTypes(x, p.TypesInfo.TypeOf(x.Args[0]))
						}
					} else {
						origSig, _ := callee.Type().(*types.Signature)
						isGeneric := origSig != nil && (origSig.TypeParams().Len() > 0 || origSig.RecvTypeParams().Len() > 0)
						isCmp := callee.Pkg() != nil && callee.Pkg().Path() == "cmp"
						if sig, okSig := p.TypesInfo.TypeOf(x.Fun).(*types.Signature); okSig {
							type argEntry struct {
								expr ast.Expr
								typ  types.Type
							}
							var argEntries []argEntry
							if len(x.Args) == 1 {
								if tup, isTup := p.TypesInfo.TypeOf(x.Args[0]).(*types.Tuple); isTup {
									for ti := 0; ti < tup.Len(); ti++ {
										argEntries = append(argEntries, argEntry{typ: tup.At(ti).Type()})
									}
								}
							}
							if argEntries == nil {
								for _, arg := range x.Args {
									argEntries = append(argEntries, argEntry{expr: arg, typ: p.TypesInfo.TypeOf(arg)})
								}
							}
							for ai, ae := range argEntries {
								if ae.expr != nil && isFreshAddrTarget(syncEncl, ae.expr, fresh, freshEsc) {
									continue
								}
								pi := ai
								if sig.Variadic() && ai >= sig.Params().Len()-1 {
									pi = sig.Params().Len() - 1
								}
								if pi < sig.Params().Len() {
									pt := types.Unalias(sig.Params().At(pi).Type())
									if sig.Variadic() && ai >= sig.Params().Len()-1 && !x.Ellipsis.IsValid() {
										if sl, isSl := pt.Underlying().(*types.Slice); isSl {
											pt = types.Unalias(sl.Elem())
										}
									}
									if isGeneric && !isCmp && origSig != nil && pi < origSig.Params().Len() {
										origPT := types.Unalias(origSig.Params().At(pi).Type())
										if origSig.Variadic() && ai >= origSig.Params().Len()-1 && !x.Ellipsis.IsValid() {
											if sl, isSl := origPT.Underlying().(*types.Slice); isSl {
												origPT = types.Unalias(sl.Elem())
											}
										}
										if syntaxutil.TypeMentionsTypeParam(origPT) {
											recordGenericArgTypes(x, ae.typ)
											continue
										}
									}
									if !syntaxutil.IsReadOnlyEmptyInterfaceCallee(callee) {
										if iface, isIf := pt.Underlying().(*types.Interface); isIf && iface.NumMethods() == 0 {
											recordReflectiveArgTypes(x, ae.typ)
										}
									}
								}
							}
						}
					}
				}
			}
			return true
		})
	}

	for id, inst := range p.TypesInfo.Instances {
		if directCallFuns[id] {
			continue
		}
		fnObj, ok := p.TypesInfo.Uses[id].(*types.Func)
		if !ok || fnObj == nil {
			continue
		}
		orig := fnObj.Origin()
		if orig.Pkg() != nil && orig.Pkg().Path() == "cmp" {
			continue
		}
		instSig, okInst := syntaxutil.UnderlyingType(inst.Type).(*types.Signature)
		origSig, okOrig := orig.Type().(*types.Signature)
		if !okInst || !okOrig {
			continue
		}
		for pi := 0; pi < instSig.Params().Len() && pi < origSig.Params().Len(); pi++ {
			if syntaxutil.TypeMentionsTypeParam(origSig.Params().At(pi).Type()) {
				recordGenericArgTypes(id, instSig.Params().At(pi).Type())
			}
		}
	}
	for selExpr, selInfo := range p.TypesInfo.Selections {
		if directCallFuns[selExpr] || selInfo == nil || (selInfo.Kind() != types.MethodVal && selInfo.Kind() != types.MethodExpr) {
			continue
		}
		fnObj, ok := selInfo.Obj().(*types.Func)
		if !ok || fnObj == nil {
			continue
		}
		if recvSt := unexportedForeignRecvStruct(fnObj); recvSt != nil {
			syncEncl := idx.SyncEnclFuncDecl(selExpr)
			fresh, freshEsc := getFresh(syncEncl)
			recordStructAt(selExpr, recvSt)
			if selInfo.Kind() == types.MethodVal {
				recordMutatedExpr(selExpr, selExpr.X, fresh, freshEsc)
			}
		}
		orig := fnObj.Origin()
		origSig, okOrig := orig.Type().(*types.Signature)
		instSig, okInst := syntaxutil.UnderlyingType(selInfo.Type()).(*types.Signature)
		if !okOrig || !okInst || origSig.RecvTypeParams().Len() == 0 {
			continue
		}
		offset := 0
		if selInfo.Kind() == types.MethodExpr {
			offset = 1
		}
		for pi := 0; pi < origSig.Params().Len() && pi+offset < instSig.Params().Len(); pi++ {
			if syntaxutil.TypeMentionsTypeParam(origSig.Params().At(pi).Type()) {
				recordGenericArgTypes(selExpr, instSig.Params().At(pi+offset).Type())
			}
		}
	}

	exportedRefSelsByOwner := map[syntaxutil.TypeRef]map[*ast.SelectorExpr]bool{}
	isStructTrackedPtr := func(t types.Type) bool {
		if t == nil {
			return false
		}
		ptr, isP := types.Unalias(t).(*types.Pointer)
		if !isP {
			return false
		}
		_, _, st, ok := syntaxutil.TypeRefOfStructFull(ptr.Elem())
		return ok && st != nil && st.NumFields() > 0
	}
	isNonEmptyStructElemSeq := func(t types.Type) bool {
		switch u := syntaxutil.UnderlyingType(t).(type) {
		case *types.Slice:
			_, _, elemSt, isSt := syntaxutil.TypeRefOfStructFull(u.Elem())
			return isSt && elemSt.NumFields() > 0
		case *types.Array:
			_, _, elemSt, isSt := syntaxutil.TypeRefOfStructFull(u.Elem())
			return isSt && elemSt.NumFields() > 0
		}
		return false
	}
	for selExpr, selInfo := range p.TypesInfo.Selections {
		if selInfo == nil || selInfo.Kind() != types.FieldVal || selInfo.Obj() == nil || !selInfo.Obj().Exported() {
			continue
		}
		if fv, isFV := selInfo.Obj().(*types.Var); isFV && exemptReadFields[fv] {
			continue
		}
		ft := selInfo.Type()
		if !refconfine.TypeCarriesMutableRefWith(ft, isStructTrackedPtr) || isNonEmptyStructElemSeq(ft) {
			continue
		}
		if refconfine.IsInsideExemptWriteOrAddr(idx, selExpr, exempted) {
			continue
		}
		if parAs, isAs := idx.ParentUnparen(selExpr).(*ast.AssignStmt); isAs {
			onLHS := false
			for _, lhs := range parAs.Lhs {
				if ast.Unparen(lhs) == selExpr {
					onLHS = true
					break
				}
			}
			if onLHS {
				continue
			}
		}
		syncEncl := idx.SyncEnclFuncDecl(selExpr)
		fresh, freshEsc := getFresh(syncEncl)
		if isFreshAddrTarget(syncEncl, selExpr, fresh, freshEsc) {
			continue
		}
		syntaxutil.ForEachSelectionHopStruct(selInfo, func(hop *types.Named) {
			if hop == nil || (syncEncl != nil && exemptFamilyByFunc[syncEncl][hop]) {
				return
			}
			ref, _, hopSt, okHop := syntaxutil.TypeRefOfStructFull(hop)
			if !okHop || !ref.Valid() || hopSt.NumFields() == 0 || seen[ref] {
				return
			}
			if exportedRefSelsByOwner[ref] == nil {
				exportedRefSelsByOwner[ref] = map[*ast.SelectorExpr]bool{}
			}
			exportedRefSelsByOwner[ref][selExpr] = true
		})
	}
	for ownerRef, selSet := range exportedRefSelsByOwner {
		if seen[ownerRef] {
			continue
		}
		var pendingConds []syntaxutil.ConditionalStructMutation
		if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
			Index:                         idx,
			IsImmutablePtr:                isStructTrackedPtr,
			AllowReturnFromUnexportedFunc: true,
			IsExemptField: func(fv *types.Var) bool {
				return fv != nil && exemptReadFields[fv]
			},
			AllowImmutableInterfaceElem: func(containerExpr ast.Expr) bool {
				ct := p.TypesInfo.TypeOf(containerExpr)
				if ct == nil {
					return false
				}
				var elemT types.Type
				switch u := syntaxutil.UnderlyingType(ct).(type) {
				case *types.Slice:
					elemT = u.Elem()
				case *types.Array:
					elemT = u.Elem()
				case *types.Map:
					elemT = u.Elem()
				default:
					return false
				}
				iface, okI := syntaxutil.UnderlyingType(elemT).(*types.Interface)
				return okI && iface.NumMethods() > 0
			},
			AllowMethodRecv: func(call *ast.CallExpr, callee *types.Func, _ ast.Expr) bool {
				if callee == nil || call.Ellipsis.IsValid() {
					return false
				}
				orig := callee.Origin()
				sig, okSig := orig.Type().(*types.Signature)
				if !okSig || sig.Recv() == nil {
					return false
				}
				recvT := types.Unalias(sig.Recv().Type())
				if _, isPtr := recvT.(*types.Pointer); isPtr {
					return false
				}
				rn, isRN := recvT.(*types.Named)
				if !isRN || rn.Obj() == nil || rn.Obj().Pkg() == nil {
					return false
				}
				if _, isSl := rn.Underlying().(*types.Slice); !isSl {
					return false
				}
				for _, a := range call.Args {
					at := p.TypesInfo.TypeOf(a)
					if refconfine.TypeContainsRefOrPointerWith(at, isStructTrackedPtr) && !types.Identical(types.Unalias(at), rn) {
						return false
					}
				}
				for ri := 0; ri < sig.Results().Len(); ri++ {
					if refconfine.TypeContainsRefOrPointerWith(sig.Results().At(ri).Type(), isStructTrackedPtr) {
						return false
					}
				}
				sliceRef := syntaxutil.TypeRef{Pkg: rn.Obj().Pkg().Path(), Name: rn.Obj().Name()}
				if !sliceRef.Valid() {
					return false
				}
				guardPkg := ""
				if orig.Pkg() != nil {
					guardPkg = orig.Pkg().Path()
				}
				pendingConds = append(pendingConds, syntaxutil.ConditionalStructMutation{
					Struct:      ownerRef,
					GuardPkg:    guardPkg,
					GuardStruct: sliceRef,
				})
				return true
			},
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
				if !isSel || !selSet[sel] {
					return false, false
				}
				ft := p.TypesInfo.TypeOf(sel)
				return refconfine.IsDirectMutableRefWith(ft, isStructTrackedPtr), true
			},
			AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
				return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && syntaxutil.IsReflectTypeOfCall(p, call)
			},
			AllowAssignTarget: func(lhs, _ ast.Expr, rhsIsRef bool) bool {
				if rhsIsRef {
					return false
				}
				sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
				if !isSel {
					return false
				}
				selInfo := p.TypesInfo.Selections[sel]
				if selInfo == nil || selInfo.Kind() != types.FieldVal {
					return false
				}
				syncEncl := idx.SyncEnclFuncDecl(lhs)
				fresh, freshEsc := getFresh(syncEncl)
				if !isFreshMutTarget(syncEncl, lhs, fresh, freshEsc) {
					return false
				}
				stNamed, isN := types.Unalias(p.TypesInfo.TypeOf(lhs)).(*types.Named)
				if !isN || !isOpaqueUnexportedForeignStruct(p.Types, stNamed) {
					return false
				}
				guardRef := syntaxutil.TypeRef{Pkg: stNamed.Obj().Pkg().Path(), Name: stNamed.Obj().Name()}
				if !guardRef.Valid() {
					return false
				}
				pendingConds = append(pendingConds, syntaxutil.ConditionalStructMutation{
					Struct:                  ownerRef,
					GuardStruct:             guardRef,
					RequireDescBuilderGuard: true,
				})
				return true
			},
		}) {
			seen[ownerRef] = true
		} else {
			for _, cm := range pendingConds {
				if cm.Valid() {
					condSeen[cm] = true
				}
			}
		}
	}

	var out []syntaxutil.TypeRef
	if len(seen) > 0 {
		out = make([]syntaxutil.TypeRef, 0, len(seen))
		for ref := range seen {
			out = append(out, ref)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	}
	var condOut []syntaxutil.ConditionalStructMutation
	if len(condSeen) > 0 {
		condOut = make([]syntaxutil.ConditionalStructMutation, 0, len(condSeen))
		for cm := range condSeen {
			if !seen[cm.Struct] {
				condOut = append(condOut, cm)
			}
		}
		if len(condOut) == 0 {
			condOut = nil
		} else {
			slices.SortFunc(condOut, syntaxutil.ConditionalStructMutation.Compare)
		}
	}
	return out, condOut
}

func isOpaqueUnexportedForeignStruct(curPkg *types.Package, named *types.Named) bool {
	if named == nil || named.Obj() == nil || named.Obj().Exported() ||
		named.Obj().Pkg() == nil || named.Obj().Pkg() == curPkg {
		return false
	}
	st, isSt := named.Underlying().(*types.Struct)
	if !isSt || st.NumFields() == 0 {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Exported() || f.Embedded() {
			return false
		}
	}
	mset := types.NewMethodSet(types.NewPointer(named))
	for i := 0; i < mset.Len(); i++ {
		if mset.At(i).Obj().Exported() {
			return false
		}
	}
	return true
}
