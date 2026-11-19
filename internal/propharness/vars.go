package propharness

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func verifyHarnessPackageVars(audited bool, g *harnessGraph) (map[*types.Var]bool, string) {
	if len(g.pkgVars) == 0 {
		return nil, ""
	}
	pkg := g.pkg
	info := g.info
	pkgTypes := g.pkgTypes
	sc := g.screen

	categoryA := map[*types.Var]bool{}
	categorySyncMap := map[*types.Var]bool{}
	categoryImmutable := map[*types.Var]bool{}
	needsGeneratorImmutability := false

	for _, entry := range g.pkgVars {
		v := entry.v
		vt := v.Type()
		switch {
		case isSyncMapType(vt):
			if entry.val != nil {
				cl, ok := ast.Unparen(entry.val).(*ast.CompositeLit)
				if !ok || len(cl.Elts) != 0 {
					return nil, "non-empty sync.Map initializer"
				}
			}
			categorySyncMap[v] = true
		case !refconfine.TypeMayCarryUnknownDynamic(audited, vt):
			if containsSyncPrimitive(vt, map[types.Type]bool{}) {
				return nil, "sync primitive global"
			}
			categoryA[v] = true
		default:
			if entry.val == nil {
				return nil, "uninitialized category 3C global"
			}
			if _, isSig := types.Unalias(vt).Underlying().(*types.Signature); isSig {
				if !isClosedHarnessFuncInit(info, pkgTypes, entry.val) {
					return nil, "open func global init"
				}
				categoryImmutable[v] = true
			} else if isTemplatePtrType(vt) {
				categoryImmutable[v] = true
			} else if sc.isCarrierFreeGeneratorPtrType(audited, vt) {
				needsGeneratorImmutability = true
				categoryImmutable[v] = true
			} else {
				return nil, "disallowed category 3C global type"
			}
		}
	}

	carrierFreeParam := map[*types.Var]bool{}
	for fn := range g.declFuncs {
		if fn.Exported() || g.isFuncValueTaken(fn) || fn.Signature().Variadic() {
			continue
		}
		sites := g.callSitesByFunc[fn]
		if len(sites) == 0 {
			continue
		}
		params := fn.Signature().Params()
		for pIdx := 0; pIdx < params.Len(); pIdx++ {
			pv := params.At(pIdx)
			if !refconfine.TypeMayCarryUnknownDynamic(audited, pv.Type()) {
				carrierFreeParam[pv] = true
				continue
			}
			allCF := true
			for _, site := range sites {
				if site.Ellipsis.IsValid() || pIdx >= len(site.Args) {
					allCF = false
					break
				}
				argType := info.TypeOf(site.Args[pIdx])
				if argType == nil || refconfine.TypeMayCarryUnknownDynamic(audited, argType) {
					allCF = false
					break
				}
			}
			if allCF {
				carrierFreeParam[pv] = true
			}
		}
	}

	mutatedNamedStructs := g.mutatedNamedStructs
	syncMapFuncs := map[*types.Func]bool{}
	syncMapRefFuncs := map[*types.Func]bool{}
	syncMapTypeAsserts := map[*ast.TypeAssertExpr]bool{}
	syncMapStoredVars := map[*types.Var]bool{}
	nonInitCategoryAUses := map[*ast.Ident]bool{}

	okVars := true
	checkVarUses := func(root ast.Node, inInitRoot bool, enclosingFn *types.Func) {
		approvedSyncMapIdents := map[*ast.Ident]bool{}
		approvedTemplateIdents := map[*ast.Ident]bool{}

		var walk func(n ast.Node, inInitExec bool, inLit bool)
		walk = func(n ast.Node, inInitExec bool, inLit bool) {
			if !okVars || n == nil {
				return
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				walk(x.Type, false, true)
				walk(x.Body, false, true)
				return
			case *ast.GoStmt:
				walk(x.Call, false, true)
				return
			case *ast.Ident:
				if v, ok := info.Uses[x].(*types.Var); ok && v != nil {
					if !inInitExec && categoryA[v] {
						nonInitCategoryAUses[x] = true
					}
					if categorySyncMap[v] && !approvedSyncMapIdents[x] {
						okVars = false
						return
					}
					if categoryImmutable[v] && isTemplatePtrType(v.Type()) && !approvedTemplateIdents[x] {
						okVars = false
						return
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if rootVar := rootPkgVar(info, lhs, g.pkgVarSet); rootVar != nil && (!categoryA[rootVar] || !inInitExec) {
						okVars = false
						return
					}
				}
			case *ast.IncDecStmt:
				if rootVar := rootPkgVar(info, x.X, g.pkgVarSet); rootVar != nil && (!categoryA[rootVar] || !inInitExec) {
					okVars = false
					return
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					for _, be := range []ast.Expr{x.Key, x.Value} {
						if be != nil {
							if rootVar := rootPkgVar(info, be, g.pkgVarSet); rootVar != nil && (!categoryA[rootVar] || !inInitExec) {
								okVars = false
								return
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if rootVar := rootPkgVar(info, x.X, g.pkgVarSet); rootVar != nil {
						allowedFlagAddr := false
						if categoryA[rootVar] && inInitExec && g.idx != nil {
							if call, isC := g.idx.ParentUnparen(x).(*ast.CallExpr); isC && len(call.Args) > 0 && ast.Unparen(call.Args[0]) == x {
								if callee := resolveHarnessFuncExpr(info, call.Fun); callee != nil && callee.Pkg() != nil && callee.Pkg().Path() == "flag" {
									allowedFlagAddr = true
								}
							}
						}
						if !allowedFlagAddr {
							okVars = false
							return
						}
					}
				}
			case *ast.CallExpr:
				if arg0, ok := mutatingBuiltinFirstArg(info, x); ok {
					if rootVar := rootPkgVar(info, arg0, g.pkgVarSet); rootVar != nil && (!categoryA[rootVar] || !inInitExec) {
						okVars = false
						return
					}
				}
				if sel, ok := syntaxutil.UnwrapCallee(x.Fun).(*ast.SelectorExpr); ok && sel.Sel != nil {
					if baseID, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
						if v, ok := info.Uses[baseID].(*types.Var); ok && v != nil {
							if categorySyncMap[v] {
								mName := sel.Sel.Name
								if inLit || enclosingFn == nil || enclosingFn.Exported() || g.isFuncValueTaken(enclosingFn) {
									okVars = false
									return
								}
								if mName != "Load" && mName != "Store" {
									okVars = false
									return
								}
								wantArgs := 1
								if mName == "Store" {
									wantArgs = 2
								}
								if x.Ellipsis.IsValid() || len(x.Args) != wantArgs {
									okVars = false
									return
								}
								for pIdx := 0; pIdx < enclosingFn.Signature().Params().Len(); pIdx++ {
									if !carrierFreeParam[enclosingFn.Signature().Params().At(pIdx)] {
										okVars = false
										return
									}
								}
								if !isCarrierFreeSyncMapKey(audited, info, x.Args[0], carrierFreeParam) {
									okVars = false
									return
								}
								if mName == "Store" {
									sawMutableRef := false
									if !isImmutableHarnessCachedType(audited, g, info.TypeOf(x.Args[1]), mutatedNamedStructs, &needsGeneratorImmutability, &sawMutableRef, map[types.Type]bool{}) {
										okVars = false
										return
									}
									if sawMutableRef {
										fd := g.declFuncs[enclosingFn]
										storedVars, okFresh := verifyFreshUnaliasedLocalAtStore(g, fd, x.Args[1], x)
										if !okFresh {
											okVars = false
											return
										}
										syncMapRefFuncs[enclosingFn] = true
										for _, sv := range storedVars {
											if sv != nil && isRegexpOrSyntaxRegexpPtr(sv.Type()) {
												syncMapStoredVars[sv] = true
											}
										}
									}
								}
								syncMapFuncs[enclosingFn] = true
								approvedSyncMapIdents[baseID] = true
							} else if categoryImmutable[v] && isTemplatePtrType(v.Type()) {
								if sel.Sel.Name != "Execute" {
									okVars = false
									return
								}
								approvedTemplateIdents[baseID] = true
							}
						}
					}
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if !okVars || child == nil {
					return false
				}
				if child == n {
					return true
				}
				walk(child, inInitExec, inLit)
				return false
			})
		}
		walk(root, inInitRoot, false)
	}

	for _, af := range pkg.Syntax {
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == "init" {
					checkVarUses(d.Body, true, nil)
				} else if d.Recv == nil {
					var orig *types.Func
					if fn, ok := info.Defs[d.Name].(*types.Func); ok && fn != nil {
						orig = fn.Origin()
					}
					checkVarUses(d.Body, orig != nil && g.initOnly[orig], orig)
				} else {
					checkVarUses(d.Body, false, nil)
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					checkVarUses(d, true, nil)
					break
				}
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						for _, val := range vs.Values {
							checkVarUses(val, true, nil)
						}
					}
				}
			}
			if !okVars {
				return nil, "checkVarUses failed"
			}
		}
	}

	for fn := range syncMapFuncs {
		fd := g.declFuncs[fn]
		if fd == nil || fd.Body == nil {
			return nil, "missing syncMapFunc body"
		}
		res := fn.Signature().Results()
		for i := 0; i < res.Len(); i++ {
			rt := res.At(i).Type()
			if isErrorOrBoolType(rt) {
				continue
			}
			sawMutableRef := false
			if !isImmutableHarnessCachedType(audited, g, rt, mutatedNamedStructs, &needsGeneratorImmutability, &sawMutableRef, map[types.Type]bool{}) {
				return nil, "mutable syncMapFunc result"
			}
			if sawMutableRef {
				syncMapRefFuncs[fn] = true
			}
		}
		okAssert := true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !okAssert || n == nil {
				return false
			}
			ta, ok := n.(*ast.TypeAssertExpr)
			if !ok || ta.Type == nil {
				return true
			}
			sawMutableRef := false
			if !isImmutableHarnessCachedType(audited, g, info.TypeOf(ta.Type), mutatedNamedStructs, &needsGeneratorImmutability, &sawMutableRef, map[types.Type]bool{}) {
				okAssert = false
				return false
			}
			if sawMutableRef {
				syncMapRefFuncs[fn] = true
				syncMapTypeAsserts[ta] = true
			}
			return true
		})
		if !okAssert {
			return nil, "mutable syncMapFunc type assert"
		}
	}

	var checkedGenStructs map[*types.Named]bool
	if needsGeneratorImmutability {
		if !g.generatorFieldsWriteOnceOK {
			return nil, "generatorFieldsWriteOnceOK false"
		}
		var okGenImpl bool
		checkedGenStructs, okGenImpl = verifyCachedAndGlobalGeneratorImplsImmutable(g, categoryImmutable, syncMapFuncs)
		if !okGenImpl {
			return nil, "verifyCachedAndGlobalGeneratorImplsImmutable failed"
		}
	}

	isGenPtr := sc.isGeneratorPtrType
	var rejectDetail string
	if !refconfine.VerifyReadOnlyRefConfinement(pkg, refconfine.Config{
		Index: g.idx,
		OnReject: func(pos token.Pos, clause string) {
			if rejectDetail == "" {
				if pos.IsValid() && pkg.Fset != nil {
					rejectDetail = pkg.Fset.Position(pos).String() + ": " + clause
				} else {
					rejectDetail = clause
				}
			}
		},
		IsImmutablePtr: isGenPtr,
		SeedStructOrigin: func(orig *types.Named) bool {
			return orig != nil && orig.Obj() != nil && !orig.Obj().Exported() && checkedGenStructs[orig]
		},
		CanBeSeedStructCapsule: func(orig *types.Named) bool {
			return orig != nil && !mutatedNamedStructs[orig]
		},
		AllowCompositeLitIntoSeedStruct: true,
		AllowReturnFromUnexportedFunc:   true,
		AllowIntraPkgInterfaceParam:     true,
		AllowScalarTypeParamProjection:  true,
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			switch e := ast.Unparen(expr).(type) {
			case *ast.Ident:
				if nonInitCategoryAUses[e] {
					vt := info.TypeOf(e)
					if refconfine.IsDirectMutableRefWith(vt, isGenPtr) {
						return true, true
					}
					if refconfine.TypeCarriesMutableRefWith(vt, isGenPtr) {
						return false, true
					}
					return false, false
				}
				if v, ok := info.Uses[e].(*types.Var); ok && syncMapStoredVars[v] {
					return true, true
				}
			case *ast.TypeAssertExpr:
				if syncMapTypeAsserts[e] && e.Type != nil {
					et := info.TypeOf(e.Type)
					if refconfine.TypeCarriesMutableRefWith(et, isGenPtr) {
						return refconfine.IsDirectMutableRefWith(et, isGenPtr), true
					}
				}
			case *ast.CallExpr:
				if callee := resolveHarnessFuncExpr(info, e.Fun); callee != nil && syncMapRefFuncs[callee.Origin()] {
					ct := info.TypeOf(e)
					if tup, isTup := ct.(*types.Tuple); isTup {
						for ti := 0; ti < tup.Len(); ti++ {
							if refconfine.TypeCarriesMutableRefWith(tup.At(ti).Type(), isGenPtr) {
								return false, true
							}
						}
						return false, false
					}
					if refconfine.TypeCarriesMutableRefWith(ct, isGenPtr) {
						return refconfine.IsDirectMutableRefWith(ct, isGenPtr), true
					}
				}
			}
			return false, false
		},
		AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
			if call.Ellipsis.IsValid() {
				return false
			}
			sel, isSel := syntaxutil.UnwrapCallee(call.Fun).(*ast.SelectorExpr)
			if !isSel || sel.Sel == nil {
				return false
			}
			baseID, isID := ast.Unparen(sel.X).(*ast.Ident)
			if !isID {
				return false
			}
			v, isV := info.Uses[baseID].(*types.Var)
			if !isV || !categorySyncMap[v] {
				return false
			}
			switch sel.Sel.Name {
			case "Load":
				return len(call.Args) == 1 && argIdx == 0
			case "Store":
				return len(call.Args) == 2 && (argIdx == 0 || argIdx == 1)
			}
			return false
		},
		AllowMethodRecv: func(call *ast.CallExpr, callee *types.Func, _ ast.Expr) bool {
			if call.Ellipsis.IsValid() || callee == nil || callee.Pkg() == nil {
				return false
			}
			switch callee.Pkg().Path() {
			case "regexp":
				return callee.Name() == "Match" || callee.Name() == "MatchString" || callee.Name() == "String"
			case "regexp/syntax":
				return callee.Name() == "String"
			}
			return false
		},
	}) {
		if rejectDetail != "" {
			return nil, "refconfine: " + rejectDetail
		}
		return nil, "refconfine rejected"
	}

	return categoryA, ""
}

func (sc *harnessScreen) isCarrierFreeGeneratorPtrType(audited bool, t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || !sc.generatorOrigins[named.Origin()] {
		return false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || !StructHasNoExportedFields(st) {
		return false
	}
	if targs := named.TypeArgs(); targs != nil {
		for i := 0; i < targs.Len(); i++ {
			if refconfine.TypeMayCarryUnknownDynamic(audited, targs.At(i)) {
				return false
			}
		}
	}
	return true
}

func (g *harnessGraph) noteMutationLHS(e ast.Expr, isDefStmt, inOnceDo, isPlainAssign bool) {
	info := g.info
	for cur := e; cur != nil; {
		switch x := ast.Unparen(cur).(type) {
		case *ast.SelectorExpr:
			if sel := info.Selections[x]; sel != nil && sel.Kind() == types.FieldVal {
				syntaxutil.ForEachSelectionHopStruct(sel, func(st *types.Named) {
					g.mutatedNamedStructs[st.Origin()] = true
				})
			}
			cur = x.X
		case *ast.IndexExpr:
			cur = x.X
		case *ast.SliceExpr:
			cur = x.X
		case *ast.StarExpr:
			if named := syntaxutil.DerefNamedStruct(info.TypeOf(x.X)); named != nil {
				g.mutatedNamedStructs[named.Origin()] = true
			}
			cur = x.X
		default:
			cur = nil
		}
	}
	if id, isID := ast.Unparen(e).(*ast.Ident); isID {
		if v, isV := info.Uses[id].(*types.Var); isV && v != nil {
			g.mutatedOrAddrLocals[v] = true
		}
	} else if !isDefStmt {
		if v := rootPlaceVar(info, e, func(v *types.Var) bool { return !v.IsField() }); v != nil {
			g.mutatedOrAddrLocals[v] = true
		}
	}
	if g.generatorFieldsWriteOnceOK {
		if hit, directStr := g.exprChainHitsGen(e); hit && (!inOnceDo || !directStr || !isPlainAssign) {
			g.generatorFieldsWriteOnceOK = false
		}
	}
}

func (g *harnessGraph) noteMutatingBuiltin(call *ast.CallExpr) {
	if arg0, ok := mutatingBuiltinFirstArg(g.info, call); ok {
		g.noteMutationLHS(arg0, false, false, false)
	}
}

func (g *harnessGraph) exprChainHitsGen(e ast.Expr) (hit bool, directStringField bool) {
	info, sc := g.info, g.screen
	if sel, isSel := ast.Unparen(e).(*ast.SelectorExpr); isSel && sc.isGeneratorType(info.TypeOf(sel.X)) {
		if ft := info.TypeOf(sel); ft != nil {
			if basic, isB := types.Unalias(ft).Underlying().(*types.Basic); isB && basic.Kind() == types.String {
				return true, true
			}
		}
		return true, false
	}
	for e != nil {
		switch x := ast.Unparen(e).(type) {
		case *ast.SelectorExpr:
			if sc.isGeneratorType(info.TypeOf(x.X)) {
				return true, false
			}
			if selInfo := info.Selections[x]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				hitHop := false
				syntaxutil.ForEachSelectionHopStruct(selInfo, func(st *types.Named) {
					if sc.isGeneratorType(st) {
						hitHop = true
					}
				})
				if hitHop {
					return true, false
				}
			}
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.StarExpr:
			if sc.isGeneratorType(info.TypeOf(x.X)) {
				return true, false
			}
			e = x.X
		default:
			return false, false
		}
	}
	return false, false
}

func mutatingBuiltinFirstArg(info *types.Info, call *ast.CallExpr) (ast.Expr, bool) {
	if call == nil || len(call.Args) == 0 {
		return nil, false
	}
	b := syntaxutil.LookupBuiltin(info, syntaxutil.UnwrapCallee(call.Fun))
	if b == nil {
		return nil, false
	}
	switch b.Name() {
	case "delete", "clear", "copy", "append":
		return call.Args[0], true
	}
	return nil, false
}

func rootPlaceVar(info *types.Info, e ast.Expr, match func(*types.Var) bool) *types.Var {
	for e != nil {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			if v, ok := info.Uses[x].(*types.Var); ok && v != nil && match(v) {
				return v
			}
			return nil
		case *ast.SelectorExpr:
			if x.Sel != nil {
				if v, ok := info.Uses[x.Sel].(*types.Var); ok && v != nil && !v.IsField() && match(v) {
					return v
				}
			}
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		default:
			return nil
		}
	}
	return nil
}

func rootImportedVar(info *types.Info, e ast.Expr, curPkg *types.Package) *types.Var {
	return rootPlaceVar(info, e, func(v *types.Var) bool {
		return !v.IsField() && v.Pkg() != nil && v.Pkg() != curPkg
	})
}

func rootPkgVar(info *types.Info, e ast.Expr, pkgVarSet map[*types.Var]harnessVarEntry) *types.Var {
	return rootPlaceVar(info, e, func(v *types.Var) bool {
		_, exists := pkgVarSet[v]
		return exists
	})
}

func lookupLocalVar(info *types.Info, pkgScope *types.Scope, e ast.Expr) *types.Var {
	id, ok := ast.Unparen(e).(*ast.Ident)
	if !ok {
		return nil
	}
	if v, ok := info.Defs[id].(*types.Var); ok && v != nil && v.Parent() != pkgScope {
		return v
	}
	if v, ok := info.Uses[id].(*types.Var); ok && v != nil && v.Parent() != pkgScope {
		return v
	}
	return nil
}

func usedIdentAndObject(info *types.Info, e ast.Expr) (*ast.Ident, types.Object) {
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		return x, info.Uses[x]
	case *ast.SelectorExpr:
		if x.Sel != nil {
			return x.Sel, info.Uses[x.Sel]
		}
	}
	return nil, nil
}

func osStdoutIdent(info *types.Info, e ast.Expr) *ast.Ident {
	id, obj := usedIdentAndObject(info, e)
	if v, ok := obj.(*types.Var); ok && v.Pkg() != nil && v.Pkg().Path() == "os" && v.Name() == "Stdout" {
		return id
	}
	return nil
}

func osEnvLookupIdent(info *types.Info, e ast.Expr) *ast.Ident {
	id, obj := usedIdentAndObject(info, e)
	if fn, ok := obj.(*types.Func); ok && fn.Pkg() != nil && fn.Pkg().Path() == "os" && (fn.Name() == "LookupEnv" || fn.Name() == "Getenv") {
		return id
	}
	return nil
}

func isAddrOfCarrierFreeFlagField(audited bool, info *types.Info, e ast.Expr, pkgVarSet map[*types.Var]harnessVarEntry) bool {
	un, ok := ast.Unparen(e).(*ast.UnaryExpr)
	if !ok || un.Op != token.AND {
		return false
	}
	sel, ok := ast.Unparen(un.X).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	baseID, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := info.Uses[baseID].(*types.Var)
	if !ok || v == nil {
		return false
	}
	if _, exists := pkgVarSet[v]; !exists || refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
		return false
	}
	_, isStruct := types.Unalias(v.Type()).Underlying().(*types.Struct)
	return isStruct
}

func isSyncMapType(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "sync" && named.Obj().Name() == "Map"
}

func isTemplatePtrType(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "html/template" && named.Obj().Name() == "Template"
}

func containsSyncPrimitive(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	if named, ok := t.(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
		p := named.Obj().Pkg().Path()
		if p == "sync" || p == "sync/atomic" {
			return true
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Chan:
		return true
	case *types.Pointer:
		return containsSyncPrimitive(u.Elem(), seen)
	case *types.Array:
		return containsSyncPrimitive(u.Elem(), seen)
	case *types.Slice:
		return containsSyncPrimitive(u.Elem(), seen)
	case *types.Map:
		return containsSyncPrimitive(u.Key(), seen) || containsSyncPrimitive(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if containsSyncPrimitive(u.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func isRegexpOrSyntaxRegexpPtr(t types.Type) bool {
	if t == nil {
		return false
	}
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Name() != "Regexp" {
		return false
	}
	p := named.Obj().Pkg().Path()
	return p == "regexp" || p == "regexp/syntax"
}

func isClosedHarnessFuncInit(info *types.Info, pkgTypes *types.Package, e ast.Expr) bool {
	switch x := syntaxutil.UnwrapCallee(e).(type) {
	case *ast.Ident:
		fn, ok := info.Uses[x].(*types.Func)
		return ok && fn != nil && fn.Pkg() == pkgTypes
	case *ast.FuncLit:
		okLit := true
		ast.Inspect(x.Body, func(n ast.Node) bool {
			if !okLit || n == nil {
				return false
			}
			if id, ok := n.(*ast.Ident); ok {
				if v, ok := info.Uses[id].(*types.Var); ok && v != nil && !v.IsField() && v.Pkg() == pkgTypes && v.Parent() == pkgTypes.Scope() {
					okLit = false
					return false
				}
			}
			return true
		})
		return okLit
	}
	return false
}

func isCarrierFreeSyncMapKey(audited bool, info *types.Info, keyExpr ast.Expr, carrierFreeParam map[*types.Var]bool) bool {
	kt := info.TypeOf(keyExpr)
	if kt == nil {
		return false
	}
	if !refconfine.TypeMayCarryUnknownDynamic(audited, kt) {
		return true
	}
	if id, ok := ast.Unparen(keyExpr).(*ast.Ident); ok {
		if pv, ok := info.Uses[id].(*types.Var); ok && carrierFreeParam[pv] {
			return true
		}
	}
	return false
}
