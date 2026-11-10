package propharness

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate"
)

func verifyHarnessPackageVars(audited bool, idx *harnessPkgIndex) (map[*types.Var]bool, bool) {
	if len(idx.pkgVars) == 0 {
		return nil, true
	}
	pkg := idx.pkg
	info := idx.info
	pkgTypes := idx.pkgTypes

	categoryA := map[*types.Var]bool{}
	categorySyncMap := map[*types.Var]bool{}
	categoryImmutable := map[*types.Var]bool{}
	needsGeneratorImmutability := false

	for _, entry := range idx.pkgVars {
		v := entry.v
		vt := v.Type()
		switch {
		case isSyncMapType(vt):
			if entry.val != nil {
				cl, ok := ast.Unparen(entry.val).(*ast.CompositeLit)
				if !ok || len(cl.Elts) != 0 {
					return nil, false
				}
			}
			categorySyncMap[v] = true
		case !dynstate.TypeMayCarryUnknownDynamic(audited, vt):
			// Disallow package-scope mutexes, atomics, or Once primitives.
			if containsSyncPrimitive(vt, map[types.Type]bool{}) {
				return nil, false
			}
			categoryA[v] = true
		default:
			// Category 3C: must have an explicit var-spec initializer and be one of:
			// (1) function signature bound to a package-local function or closed literal,
			// (2) *html/template.Template, or
			// (3) *Generator with carrier-free type args and unexported fields.
			if entry.val == nil {
				return nil, false
			}
			if _, isSig := types.Unalias(vt).Underlying().(*types.Signature); isSig {
				if !isClosedHarnessFuncInit(info, pkgTypes, entry.val) {
					return nil, false
				}
				categoryImmutable[v] = true
			} else if isTemplatePtrType(vt) {
				categoryImmutable[v] = true
			} else if _, ok := isCarrierFreeGeneratorPtrType(audited, pkgTypes, vt); ok {
				needsGeneratorImmutability = true
				categoryImmutable[v] = true
			} else {
				return nil, false
			}
		}
	}

	// Precompute carrier-free-at-all-callsites parameters for unexported non-value-taken functions.
	carrierFreeParam := map[*types.Var]bool{}
	for fn := range idx.declFuncs {
		if fn.Exported() || idx.funcValueTaken[fn] || fn.Signature().Variadic() {
			continue
		}
		sites := idx.callSitesByFunc[fn]
		if len(sites) == 0 {
			continue
		}
		params := fn.Signature().Params()
		for pIdx := 0; pIdx < params.Len(); pIdx++ {
			pv := params.At(pIdx)
			if !dynstate.TypeMayCarryUnknownDynamic(audited, pv.Type()) {
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
				if argType == nil || dynstate.TypeMayCarryUnknownDynamic(audited, argType) {
					allCF = false
					break
				}
			}
			if allCF {
				carrierFreeParam[pv] = true
			}
		}
	}

	// Verify usage of every package-scope variable across all AST declarations.
	mutatedNamedStructs := idx.mutatedNamedStructs
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
					if rootVar := rootPkgVar(info, lhs, idx.pkgVarSet); rootVar != nil {
						if !categoryA[rootVar] || !inInitExec {
							okVars = false
							return
						}
					}
				}
			case *ast.IncDecStmt:
				if rootVar := rootPkgVar(info, x.X, idx.pkgVarSet); rootVar != nil {
					if !categoryA[rootVar] || !inInitExec {
						okVars = false
						return
					}
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					for _, be := range []ast.Expr{x.Key, x.Value} {
						if be == nil {
							continue
						}
						if rootVar := rootPkgVar(info, be, idx.pkgVarSet); rootVar != nil {
							if !categoryA[rootVar] || !inInitExec {
								okVars = false
								return
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if rootVar := rootPkgVar(info, x.X, idx.pkgVarSet); rootVar != nil {
						if !categoryA[rootVar] || !inInitExec {
							okVars = false
							return
						}
					}
				}
			case *ast.CallExpr:
				// Builtin delete/clear/copy/append on package-scope slice/map globals.
				if arg0, ok := mutatingBuiltinFirstArg(info, x); ok {
					if rootVar := rootPkgVar(info, arg0, idx.pkgVarSet); rootVar != nil {
						if !categoryA[rootVar] || !inInitExec {
							okVars = false
							return
						}
					}
				}
				// sync.Map Load/Store and *template.Template Execute discipline.
				if sel, ok := peelHarnessCallee(x.Fun).(*ast.SelectorExpr); ok && sel.Sel != nil {
					if baseId, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
						if v, ok := info.Uses[baseId].(*types.Var); ok && v != nil {
							if categorySyncMap[v] {
								mName := sel.Sel.Name
								if inLit || enclosingFn == nil || enclosingFn.Exported() || idx.funcValueTaken[enclosingFn] {
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
									if !isImmutableHarnessCachedType(audited, pkgTypes, info.TypeOf(x.Args[1]), mutatedNamedStructs, &needsGeneratorImmutability, &sawMutableRef, map[types.Type]bool{}) {
										okVars = false
										return
									}
									if sawMutableRef {
										fd := idx.declFuncs[enclosingFn]
										storedVars, okFresh := verifyFreshUnaliasedLocalAtStore(info, pkgTypes, fd, x.Args[1], x)
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
								approvedSyncMapIdents[baseId] = true
							} else if categoryImmutable[v] && isTemplatePtrType(v.Type()) {
								if sel.Sel.Name != "Execute" {
									okVars = false
									return
								}
								approvedTemplateIdents[baseId] = true
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
					fn, _ := info.Defs[d.Name].(*types.Func)
					checkVarUses(d.Body, fn != nil && idx.initOnly[fn], fn)
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
				return nil, false
			}
		}
	}

	for fn := range syncMapFuncs {
		fd := idx.declFuncs[fn]
		if fd == nil || fd.Body == nil {
			return nil, false
		}
		res := fn.Signature().Results()
		for i := 0; i < res.Len(); i++ {
			rt := res.At(i).Type()
			if isErrorOrBoolType(rt) {
				continue
			}
			sawMutableRef := false
			if !isImmutableHarnessCachedType(audited, pkgTypes, rt, mutatedNamedStructs, &needsGeneratorImmutability, &sawMutableRef, map[types.Type]bool{}) {
				return nil, false
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
			if !isImmutableHarnessCachedType(audited, pkgTypes, info.TypeOf(ta.Type), mutatedNamedStructs, &needsGeneratorImmutability, &sawMutableRef, map[types.Type]bool{}) {
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
			return nil, false
		}
	}

	var checkedGenStructs map[*types.Named]bool
	if needsGeneratorImmutability {
		if !idx.generatorFieldsWriteOnceOK {
			return nil, false
		}
		var okGenImpl bool
		checkedGenStructs, okGenImpl = verifyCachedAndGlobalGeneratorImplsImmutable(audited, idx, categoryImmutable, syncMapFuncs)
		if !okGenImpl {
			return nil, false
		}
	}

	isGenPtr := func(t types.Type) bool {
		return isAnyGeneratorPtrType(pkgTypes, t)
	}
	if !dynstate.VerifyReadOnlyRefConfinement(pkg, dynstate.RefConfineConfig{
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
					if dynstate.IsDirectMutableRefWith(vt, isGenPtr) {
						return true, true
					}
					if dynstate.TypeCarriesMutableRefWith(vt, isGenPtr) {
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
					if dynstate.TypeCarriesMutableRefWith(et, isGenPtr) {
						return dynstate.IsDirectMutableRefWith(et, isGenPtr), true
					}
				}
			case *ast.CallExpr:
				if callee := resolveHarnessFuncExpr(info, e.Fun); callee != nil && syncMapRefFuncs[callee.Origin()] {
					ct := info.TypeOf(e)
					if tup, isTup := ct.(*types.Tuple); isTup {
						for ti := 0; ti < tup.Len(); ti++ {
							if dynstate.TypeCarriesMutableRefWith(tup.At(ti).Type(), isGenPtr) {
								return false, true
							}
						}
						return false, false
					}
					if dynstate.TypeCarriesMutableRefWith(ct, isGenPtr) {
						return dynstate.IsDirectMutableRefWith(ct, isGenPtr), true
					}
				}
			}
			return false, false
		},
		AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
			if call.Ellipsis.IsValid() {
				return false
			}
			sel, isSel := peelHarnessCallee(call.Fun).(*ast.SelectorExpr)
			if !isSel || sel.Sel == nil {
				return false
			}
			baseId, isID := ast.Unparen(sel.X).(*ast.Ident)
			if !isID {
				return false
			}
			v, isV := info.Uses[baseId].(*types.Var)
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
		return nil, false
	}

	return categoryA, true
}

func isAddrOfCarrierFreeFlagField(
	audited bool,
	info *types.Info,
	e ast.Expr,
	pkgVarSet map[*types.Var]harnessVarSpecEntry,
) bool {
	un, ok := ast.Unparen(e).(*ast.UnaryExpr)
	if !ok || un.Op != token.AND {
		return false
	}
	sel, ok := ast.Unparen(un.X).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	baseId, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := info.Uses[baseId].(*types.Var)
	if !ok || v == nil {
		return false
	}
	if _, exists := pkgVarSet[v]; !exists {
		return false
	}
	if dynstate.TypeMayCarryUnknownDynamic(audited, v.Type()) {
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

func isCarrierFreeGeneratorPtrType(audited bool, pkgTypes *types.Package, t types.Type) (*types.Named, bool) {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return nil, false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() != pkgTypes || named.Obj().Name() != "Generator" {
		return nil, false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return nil, false
	}
	for i := 0; i < st.NumFields(); i++ {
		if st.Field(i).Exported() {
			return nil, false
		}
	}
	if targs := named.TypeArgs(); targs != nil {
		for i := 0; i < targs.Len(); i++ {
			if dynstate.TypeMayCarryUnknownDynamic(audited, targs.At(i)) {
				return nil, false
			}
		}
	}
	return named.Origin(), true
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

func isAnyGeneratorPtrType(pkgTypes *types.Package, t types.Type) bool {
	if pkgTypes == nil || t == nil {
		return false
	}
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() == pkgTypes && named.Obj().Name() == "Generator"
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
	switch x := peelHarnessCallee(e).(type) {
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
	if !dynstate.TypeMayCarryUnknownDynamic(audited, kt) {
		return true
	}
	if id, ok := ast.Unparen(keyExpr).(*ast.Ident); ok {
		if pv, ok := info.Uses[id].(*types.Var); ok && carrierFreeParam[pv] {
			return true
		}
	}
	return false
}

func verifyCachedAndGlobalGeneratorImplsImmutable(
	audited bool,
	idx *harnessPkgIndex,
	categoryImmutable map[*types.Var]bool,
	syncMapFuncs map[*types.Func]bool,
) (map[*types.Named]bool, bool) {
	if idx.generatorOrigin == nil {
		return nil, false
	}
	info := idx.info
	pkgTypes := idx.pkgTypes
	genOrigin := idx.generatorOrigin
	allDecls := idx.allDecls
	mutatedOrAddrLocals := idx.mutatedOrAddrLocals
	mutatedNamedStructs := idx.mutatedNamedStructs
	isGenPtr := func(t types.Type) bool {
		return isAnyGeneratorPtrType(pkgTypes, t)
	}

	checkedStructs := map[*types.Named]bool{}
	var verifyConstructedStruct func(named *types.Named) bool
	var verifyFieldType func(ft types.Type, seen map[types.Type]bool) bool

	verifyFieldType = func(ft types.Type, seen map[types.Type]bool) bool {
		if ft == nil {
			return false
		}
		ft = types.Unalias(ft)
		if _, isTP := ft.(*types.TypeParam); isTP {
			return true
		}
		if isGenPtr(ft) {
			return true
		}
		if seen[ft] {
			return true
		}
		seen[ft] = true
		if fnamed, isN := ft.(*types.Named); isN && fnamed.Obj() != nil {
			if fnamed.Obj().Pkg() == pkgTypes {
				if fnamed.Origin() == genOrigin {
					return true
				}
				if _, isSubSt := fnamed.Underlying().(*types.Struct); isSubSt {
					return verifyConstructedStruct(fnamed)
				}
			} else if fnamed.Obj().Pkg() != nil {
				p := fnamed.Obj().Pkg().Path()
				if p == "sync" || p == "sync/atomic" {
					return false
				}
			}
		}
		switch u := ft.Underlying().(type) {
		case *types.Basic:
			return u.Kind() != types.UnsafePointer && u.Kind() != types.Invalid
		case *types.Pointer:
			elem := types.Unalias(u.Elem())
			enamed, isEN := elem.(*types.Named)
			if !isEN || enamed.Obj() == nil {
				return false
			}
			if enamed.Obj().Pkg() == pkgTypes {
				if enamed.Origin() == genOrigin {
					return true
				}
				if _, isSubSt := enamed.Underlying().(*types.Struct); isSubSt && !enamed.Obj().Exported() {
					return verifyConstructedStruct(enamed)
				}
				return false
			}
			if enamed.Obj().Pkg() != nil {
				p, n := enamed.Obj().Pkg().Path(), enamed.Obj().Name()
				if ((p == "regexp" && n == "Regexp") || (p == "regexp/syntax" && n == "Regexp") || (p == "unicode" && n == "RangeTable")) && !mutatedNamedStructs[enamed.Origin()] {
					return true
				}
			}
			return false
		case *types.Slice:
			return verifyFieldType(u.Elem(), seen)
		case *types.Array:
			return verifyFieldType(u.Elem(), seen)
		case *types.Map, *types.Chan, *types.Interface:
			return false
		case *types.Struct:
			if _, isN := ft.(*types.Named); !isN && u.NumFields() > 0 {
				return false
			}
			for i := 0; i < u.NumFields(); i++ {
				if !verifyFieldType(u.Field(i).Type(), seen) {
					return false
				}
			}
		}
		return true
	}

	verifyConstructedStruct = func(named *types.Named) bool {
		if named == nil || named.Obj() == nil || named.Obj().Pkg() != pkgTypes {
			return false
		}
		orig := named.Origin()
		if orig == genOrigin {
			return true
		}
		if orig.Obj().Exported() || mutatedNamedStructs[orig] {
			return false
		}
		if checkedStructs[orig] {
			return true
		}
		checkedStructs[orig] = true
		st, isSt := orig.Underlying().(*types.Struct)
		if !isSt {
			return false
		}
		for i := 0; i < st.NumFields(); i++ {
			if !verifyFieldType(st.Field(i).Type(), map[types.Type]bool{}) {
				return false
			}
		}
		return true
	}

	var roots []ast.Node
	visitedFuncs := map[*types.Func]bool{}
	var queue []*types.Func
	enqueueFn := func(fn *types.Func) {
		if fn == nil {
			return
		}
		orig := fn.Origin()
		if allDecls[orig] != nil && !visitedFuncs[orig] {
			visitedFuncs[orig] = true
			queue = append(queue, orig)
		}
	}

	for _, entry := range idx.pkgVars {
		if categoryImmutable[entry.v] && entry.val != nil {
			if _, okGen := isCarrierFreeGeneratorPtrType(audited, pkgTypes, entry.v.Type()); okGen {
				roots = append(roots, entry.val)
			}
		}
	}
	for fn := range syncMapFuncs {
		enqueueFn(fn)
	}

	hasIfaceRecv := func(fn *types.Func) bool {
		sig := fn.Signature()
		if sig == nil || sig.Recv() == nil {
			return false
		}
		_, okIf := sig.Recv().Type().Underlying().(*types.Interface)
		return okIf
	}

	checkSubtree := func(root ast.Node) bool {
		okNode := true
		ast.Inspect(root, func(n ast.Node) bool {
			if !okNode || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.Ident:
				if inst, hasInst := info.Instances[x]; hasInst && inst.TypeArgs != nil {
					for ti := 0; ti < inst.TypeArgs.Len(); ti++ {
						targ := types.Unalias(inst.TypeArgs.At(ti))
						if _, isTP := targ.(*types.TypeParam); isTP {
							continue
						}
						if dynstate.TypeCarriesMutableRefWith(targ, isGenPtr) || types.IsInterface(targ) || !verifyFieldType(targ, map[types.Type]bool{}) {
							okNode = false
							return false
						}
					}
				}
				if fn, isFn := info.Uses[x].(*types.Func); isFn && fn != nil && fn.Pkg() == pkgTypes {
					if hasIfaceRecv(fn) {
						okNode = false
						return false
					}
					enqueueFn(fn)
				}
			case *ast.CompositeLit:
				lt := info.TypeOf(x)
				if lt != nil {
					lt = types.Unalias(lt)
					if ptr, isP := lt.(*types.Pointer); isP {
						lt = types.Unalias(ptr.Elem())
					}
					if named, isN := lt.(*types.Named); isN {
						if _, isSt := named.Underlying().(*types.Struct); isSt {
							if named.Obj() != nil && named.Obj().Pkg() != pkgTypes {
								p, nm := "", named.Obj().Name()
								if named.Obj().Pkg() != nil {
									p = named.Obj().Pkg().Path()
								}
								if !(p == "unicode" && (nm == "RangeTable" || nm == "Range16" || nm == "Range32")) {
									okNode = false
									return false
								}
							} else if !verifyConstructedStruct(named) {
								okNode = false
								return false
							}
						}
					} else if stUnder, isSt := lt.Underlying().(*types.Struct); isSt && stUnder.NumFields() > 0 {
						okNode = false
						return false
					}
				}
			case *ast.CallExpr:
				base := peelHarnessCallee(x.Fun)
				if info.Types[base].IsType() {
					return true
				}
				if id, isID := base.(*ast.Ident); isID {
					if b, isB := info.Uses[id].(*types.Builtin); isB {
						if b.Name() == "new" && len(x.Args) == 1 {
							nt := types.Unalias(info.TypeOf(x.Args[0]))
							named, isN := nt.(*types.Named)
							if !isN || !verifyConstructedStruct(named) {
								okNode = false
								return false
							}
						}
						return true
					}
				}
				callee := resolveHarnessFuncExpr(info, x.Fun)
				if callee == nil {
					okNode = false
					return false
				}
				if callee.Pkg() == pkgTypes {
					if hasIfaceRecv(callee) {
						okNode = false
						return false
					}
					enqueueFn(callee)
				}
			case *ast.FuncLit:
				// Any outer local variable captured by a closure constructed in this cone
				// must be immutable and carry zero mutable references.
				localDefs := map[*types.Var]bool{}
				ast.Inspect(x, func(cn ast.Node) bool {
					if id, isID := cn.(*ast.Ident); isID {
						if dv, isV := info.Defs[id].(*types.Var); isV && dv != nil {
							localDefs[dv] = true
						}
					}
					return true
				})
				ast.Inspect(x.Body, func(cn ast.Node) bool {
					if !okNode || cn == nil {
						return false
					}
					if id, isID := cn.(*ast.Ident); isID {
						if uv, isV := info.Uses[id].(*types.Var); isV && uv != nil && !uv.IsField() &&
							uv.Pkg() == pkgTypes && uv.Parent() != pkgTypes.Scope() && !localDefs[uv] {
							if mutatedOrAddrLocals[uv] || dynstate.TypeCarriesMutableRefWith(uv.Type(), isGenPtr) || !verifyFieldType(uv.Type(), map[types.Type]bool{}) {
								okNode = false
								return false
							}
						}
					}
					return true
				})
			}
			return true
		})
		return okNode
	}

	for _, r := range roots {
		if !checkSubtree(r) {
			return nil, false
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		fd := allDecls[cur]
		if fd == nil || fd.Body == nil || !checkSubtree(fd.Body) {
			return nil, false
		}
	}
	return checkedStructs, true
}

func isErrorOrBoolType(t types.Type) bool {
	if t == nil {
		return false
	}
	if types.Identical(t, types.Universe.Lookup("error").Type()) {
		return true
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && b.Kind() == types.Bool
}

func isImmutableHarnessCachedType(
	audited bool,
	pkgTypes *types.Package,
	t types.Type,
	mutatedStructs map[*types.Named]bool,
	needsGenImmut *bool,
	sawMutableRef *bool,
	seen map[types.Type]bool,
) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return true
	}
	seen[t] = true

	if _, ok := isCarrierFreeGeneratorPtrType(audited, pkgTypes, t); ok {
		if needsGenImmut != nil {
			*needsGenImmut = true
		}
		return true
	}
	if ptr, ok := t.(*types.Pointer); ok {
		if named, ok := types.Unalias(ptr.Elem()).(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
			p, n := named.Obj().Pkg().Path(), named.Obj().Name()
			if ((p == "regexp" && n == "Regexp") || (p == "regexp/syntax" && n == "Regexp")) && !mutatedStructs[named.Origin()] {
				if sawMutableRef != nil {
					*sawMutableRef = true
				}
				return true
			}
		}
		return false
	}
	if named, ok := t.(*types.Named); ok {
		if _, isSt := named.Underlying().(*types.Struct); isSt {
			if named.Obj() == nil || named.Obj().Pkg() != pkgTypes || named.Obj().Exported() || mutatedStructs[named.Origin()] {
				return false
			}
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() != types.UnsafePointer && u.Kind() != types.Invalid
	case *types.Array:
		return isImmutableHarnessCachedType(audited, pkgTypes, u.Elem(), mutatedStructs, needsGenImmut, sawMutableRef, seen)
	case *types.Slice:
		elemBasic, ok := types.Unalias(u.Elem()).Underlying().(*types.Basic)
		if !ok || elemBasic.Kind() == types.UnsafePointer || elemBasic.Kind() == types.Invalid {
			return false
		}
		if sawMutableRef != nil {
			*sawMutableRef = true
		}
		return true
	case *types.Struct:
		if _, isNamed := t.(*types.Named); !isNamed && u.NumFields() > 0 {
			return false
		}
		for i := 0; i < u.NumFields(); i++ {
			if !isImmutableHarnessCachedType(audited, pkgTypes, u.Field(i).Type(), mutatedStructs, needsGenImmut, sawMutableRef, seen) {
				return false
			}
		}
		return true
	}
	return false
}

// verifyFreshUnaliasedLocalAtStore verifies that a mutable-ref-carrying value
// stored into a Category 3B sync.Map (`storeCall.Args[1]`) originates from
// unaliased local construction inside fd.Body before storeCall.Pos(), never
// aliases a parameter or package global, is not declared outside any loop
// enclosing storeCall, and (for local slices) is never mutated or aliased at
// or after storeCall.Pos(). Any *regexp.Regexp / *regexp/syntax.Regexp local
// variables feeding storeArg are returned so VerifyReadOnlyRefConfinement seeds
// and confines them across the entire function and package.
func verifyFreshUnaliasedLocalAtStore(
	info *types.Info,
	pkgTypes *types.Package,
	fd *ast.FuncDecl,
	storeArg ast.Expr,
	storeCall *ast.CallExpr,
) ([]*types.Var, bool) {
	if info == nil || pkgTypes == nil || fd == nil || fd.Body == nil || storeArg == nil || storeCall == nil {
		return nil, false
	}
	body := fd.Body
	storePos := storeCall.Pos()

	// Single-pass pre-index of body: detect outer goto, record local variable
	// definition counts/positions, and collect all ForStmt/RangeStmt loop spans.
	hasGoto := false
	defCounts := map[*types.Var]int{}
	declPosByVar := map[*types.Var]token.Pos{}
	var loops []ast.Node
	var indexBody func(n ast.Node, inLit bool)
	indexBody = func(n ast.Node, inLit bool) {
		if hasGoto || n == nil {
			return
		}
		switch x := n.(type) {
		case *ast.FuncLit:
			if x.Type != nil {
				indexBody(x.Type, true)
			}
			if x.Body != nil {
				indexBody(x.Body, true)
			}
			return
		case *ast.BranchStmt:
			if !inLit && x.Tok == token.GOTO {
				hasGoto = true
				return
			}
		case *ast.ForStmt, *ast.RangeStmt:
			loops = append(loops, x)
		case *ast.Ident:
			if v, ok := info.Defs[x].(*types.Var); ok && v != nil {
				defCounts[v]++
				declPosByVar[v] = x.Pos()
			}
		}
		ast.Inspect(n, func(child ast.Node) bool {
			if hasGoto || child == nil {
				return false
			}
			if child == n {
				return true
			}
			indexBody(child, inLit)
			return false
		})
	}
	indexBody(body, false)
	if hasGoto {
		return nil, false
	}

	// Collect parameters/receivers/results so they are never accepted as fresh locals.
	sigVars := map[*types.Var]bool{}
	recordFL := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, nm := range f.Names {
				if v, ok := info.Defs[nm].(*types.Var); ok && v != nil {
					sigVars[v] = true
				}
			}
		}
	}
	recordFL(fd.Recv)
	if fd.Type != nil {
		recordFL(fd.Type.Params)
		recordFL(fd.Type.Results)
	}

	isDeclaredInBodyBefore := func(v *types.Var, limitPos token.Pos, forbidOuterLoopOf ast.Node) (token.Pos, bool) {
		if v == nil || sigVars[v] || v.IsField() || v.Pkg() != pkgTypes || v.Parent() == pkgTypes.Scope() {
			return token.NoPos, false
		}
		declPos := declPosByVar[v]
		if defCounts[v] != 1 || declPos == token.NoPos || declPos >= limitPos {
			return token.NoPos, false
		}
		// Reject variables declared outside any loop enclosing forbidOuterLoopOf.
		targetPos, targetEnd := forbidOuterLoopOf.Pos(), forbidOuterLoopOf.End()
		for _, lp := range loops {
			if lp.Pos() <= targetPos && targetEnd <= lp.End() {
				if !(lp.Pos() <= declPos && declPos <= lp.End()) {
					return token.NoPos, false
				}
			}
		}
		return declPos, true
	}

	isScalarType := func(t types.Type) bool {
		if t == nil {
			return false
		}
		b, ok := types.Unalias(t).Underlying().(*types.Basic)
		return ok && b.Kind() != types.UnsafePointer && b.Kind() != types.Invalid
	}

	verifyFreshSliceLocal := func(v *types.Var, freezeNode ast.Node, allowPostReturn bool) bool {
		freezePos := freezeNode.Pos()
		if _, ok := isDeclaredInBodyBefore(v, freezePos, freezeNode); !ok {
			return false
		}
		sl, ok := types.Unalias(v.Type()).Underlying().(*types.Slice)
		if !ok || !isScalarType(sl.Elem()) {
			return false
		}

		approvedUses := map[*ast.Ident]bool{}
		okSlice := true

		isFreshSliceInitRHS := func(rhs ast.Expr) bool {
			rhs = ast.Unparen(rhs)
			if id, isID := rhs.(*ast.Ident); isID {
				_, isNil := info.Uses[id].(*types.Nil)
				return isNil
			}
			switch r := rhs.(type) {
			case *ast.CompositeLit:
				if !types.Identical(types.Unalias(info.TypeOf(r)), types.Unalias(v.Type())) {
					return false
				}
				for _, elt := range r.Elts {
					val := elt
					if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
						val = kv.Value
					}
					if !isScalarType(info.TypeOf(val)) {
						return false
					}
				}
				return true
			case *ast.CallExpr:
				if bid, isID := peelHarnessCallee(r.Fun).(*ast.Ident); isID {
					if b, isB := info.Uses[bid].(*types.Builtin); isB {
						if b.Name() == "make" && len(r.Args) >= 2 && len(r.Args) <= 3 {
							return true
						}
						if b.Name() == "append" && !r.Ellipsis.IsValid() && len(r.Args) >= 2 {
							if aid, isAID := ast.Unparen(r.Args[0]).(*ast.Ident); isAID && info.Uses[aid] == v {
								approvedUses[aid] = true
								return true
							}
						}
					}
				}
			}
			return false
		}

		ast.Inspect(body, func(n ast.Node) bool {
			if !okSlice || n == nil {
				return false
			}
			switch s := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				ast.Inspect(s, func(cn ast.Node) bool {
					if id, isID := cn.(*ast.Ident); isID && (info.Uses[id] == v || info.Defs[id] == v) {
						okSlice = false
						return false
					}
					return true
				})
				return false
			case *ast.ValueSpec:
				for i, nm := range s.Names {
					if info.Defs[nm] == v {
						if s.End() > freezePos {
							okSlice = false
							return false
						}
						if i < len(s.Values) && !isFreshSliceInitRHS(s.Values[i]) {
							okSlice = false
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range s.Lhs {
					if lid, isID := ast.Unparen(lhs).(*ast.Ident); isID && (info.Defs[lid] == v || info.Uses[lid] == v) {
						if s.End() > freezePos || len(s.Lhs) != len(s.Rhs) || !isFreshSliceInitRHS(s.Rhs[i]) {
							okSlice = false
							return false
						}
						if info.Uses[lid] == v {
							approvedUses[lid] = true
						}
					} else if idx, isIX := ast.Unparen(lhs).(*ast.IndexExpr); isIX {
						if bid, isBID := ast.Unparen(idx.X).(*ast.Ident); isBID && info.Uses[bid] == v {
							if s.End() > freezePos || !isScalarType(info.TypeOf(idx)) {
								okSlice = false
								return false
							}
							approvedUses[bid] = true
						}
					}
				}
			case *ast.IncDecStmt:
				if idx, isIX := ast.Unparen(s.X).(*ast.IndexExpr); isIX {
					if bid, isBID := ast.Unparen(idx.X).(*ast.Ident); isBID && info.Uses[bid] == v {
						if s.End() > freezePos {
							okSlice = false
							return false
						}
						approvedUses[bid] = true
					}
				}
			case *ast.CallExpr:
				if s == storeCall && freezeNode == storeCall && len(s.Args) == 2 {
					if aid, isID := ast.Unparen(s.Args[1]).(*ast.Ident); isID && info.Uses[aid] == v {
						approvedUses[aid] = true
					}
				}
				if bid, isID := peelHarnessCallee(s.Fun).(*ast.Ident); isID {
					if b, isB := info.Uses[bid].(*types.Builtin); isB && (b.Name() == "len" || b.Name() == "cap") && len(s.Args) == 1 {
						if aid, isAID := ast.Unparen(s.Args[0]).(*ast.Ident); isAID && info.Uses[aid] == v {
							approvedUses[aid] = true
						}
					}
				}
			case *ast.ReturnStmt:
				if allowPostReturn && s.Pos() > freezePos {
					for _, res := range s.Results {
						if rid, isID := ast.Unparen(res).(*ast.Ident); isID && info.Uses[rid] == v {
							approvedUses[rid] = true
						}
					}
				}
			case *ast.Ident:
				if info.Uses[s] == v && !approvedUses[s] {
					okSlice = false
					return false
				}
			}
			return true
		})
		return okSlice
	}

	verifyFreshRegexpLocal := func(v *types.Var, limitNode ast.Node) bool {
		if _, ok := isDeclaredInBodyBefore(v, limitNode.Pos(), limitNode); !ok {
			return false
		}
		if !isRegexpOrSyntaxRegexpPtr(v.Type()) {
			return false
		}
		initCalls := 0
		reassignedOrAddr := false
		isStdRegexpConstructor := func(rhs ast.Expr) bool {
			call, ok := ast.Unparen(rhs).(*ast.CallExpr)
			if !ok {
				return false
			}
			callee := resolveHarnessFuncExpr(info, call.Fun)
			if callee == nil || callee.Pkg() == nil || callee.Signature().Recv() != nil {
				return false
			}
			p := callee.Pkg().Path()
			return p == "regexp" || p == "regexp/syntax"
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if reassignedOrAddr || n == nil {
				return false
			}
			switch s := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				ast.Inspect(s, func(cn ast.Node) bool {
					if id, isID := cn.(*ast.Ident); isID && (info.Uses[id] == v || info.Defs[id] == v) {
						reassignedOrAddr = true
						return false
					}
					return true
				})
				return false
			case *ast.ValueSpec:
				for i, nm := range s.Names {
					if info.Defs[nm] == v {
						if len(s.Values) == 1 && len(s.Names) >= 1 && isStdRegexpConstructor(s.Values[0]) {
							initCalls++
						} else if i < len(s.Values) && len(s.Names) == len(s.Values) && isStdRegexpConstructor(s.Values[i]) {
							initCalls++
						} else {
							reassignedOrAddr = true
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range s.Lhs {
					lid, isID := ast.Unparen(lhs).(*ast.Ident)
					if !isID {
						continue
					}
					if info.Defs[lid] == v {
						if len(s.Rhs) == 1 && isStdRegexpConstructor(s.Rhs[0]) {
							initCalls++
						} else if i < len(s.Rhs) && len(s.Lhs) == len(s.Rhs) && isStdRegexpConstructor(s.Rhs[i]) {
							initCalls++
						} else {
							reassignedOrAddr = true
							return false
						}
					} else if info.Uses[lid] == v {
						reassignedOrAddr = true
						return false
					}
				}
			case *ast.UnaryExpr:
				if s.Op == token.AND {
					if id, isID := ast.Unparen(s.X).(*ast.Ident); isID && info.Uses[id] == v {
						reassignedOrAddr = true
						return false
					}
				}
			}
			return true
		})
		return !reassignedOrAddr && initCalls == 1
	}

	var regexpVars []*types.Var
	var verifyCompositeExpr func(expr ast.Expr, freezeNode ast.Node, isTopStoreArg bool) bool
	verifyCompositeExpr = func(expr ast.Expr, freezeNode ast.Node, isTopStoreArg bool) bool {
		if expr == nil {
			return false
		}
		expr = ast.Unparen(expr)
		et := info.TypeOf(expr)
		if et == nil {
			return false
		}
		if isScalarType(et) {
			return true
		}
		if _, ok := isCarrierFreeGeneratorPtrType(true, pkgTypes, et); ok {
			return true
		}
		if isRegexpOrSyntaxRegexpPtr(et) {
			id, ok := expr.(*ast.Ident)
			if !ok {
				return false
			}
			v, ok := info.Uses[id].(*types.Var)
			if !ok || !verifyFreshRegexpLocal(v, freezeNode) {
				return false
			}
			regexpVars = append(regexpVars, v)
			return true
		}
		if _, isSl := types.Unalias(et).Underlying().(*types.Slice); isSl {
			id, ok := expr.(*ast.Ident)
			if !ok {
				return false
			}
			v, ok := info.Uses[id].(*types.Var)
			if !ok {
				return false
			}
			return verifyFreshSliceLocal(v, freezeNode, isTopStoreArg)
		}

		// Struct or array value (either direct CompositeLit or single-assignment local var).
		if cl, isCL := expr.(*ast.CompositeLit); isCL {
			for _, elt := range cl.Elts {
				val := elt
				if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
					val = kv.Value
				}
				if !verifyCompositeExpr(val, cl, false) {
					return false
				}
			}
			return true
		}

		id, isID := expr.(*ast.Ident)
		if !isID {
			return false
		}
		v, isV := info.Uses[id].(*types.Var)
		if !isV || v == nil {
			return false
		}
		if _, ok := isDeclaredInBodyBefore(v, freezeNode.Pos(), freezeNode); !ok {
			return false
		}
		// Find single CompositeLit initializer for v and verify zero mutations/escapes of v.
		var initCL *ast.CompositeLit
		assigns := 0
		badUse := false
		approvedStructUses := map[*ast.Ident]bool{}
		if isTopStoreArg && len(storeCall.Args) == 2 {
			if aid, ok := ast.Unparen(storeCall.Args[1]).(*ast.Ident); ok && info.Uses[aid] == v {
				approvedStructUses[aid] = true
			}
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if badUse || n == nil {
				return false
			}
			switch s := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				ast.Inspect(s, func(cn ast.Node) bool {
					if cid, ok := cn.(*ast.Ident); ok && (info.Uses[cid] == v || info.Defs[cid] == v) {
						badUse = true
						return false
					}
					return true
				})
				return false
			case *ast.ValueSpec:
				for i, nm := range s.Names {
					if info.Defs[nm] == v {
						assigns++
						if i < len(s.Values) && len(s.Names) == len(s.Values) && s.End() <= freezeNode.Pos() {
							initCL, _ = ast.Unparen(s.Values[i]).(*ast.CompositeLit)
						}
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range s.Lhs {
					if lid, ok := ast.Unparen(lhs).(*ast.Ident); ok {
						if info.Defs[lid] == v {
							assigns++
							if i < len(s.Rhs) && len(s.Lhs) == len(s.Rhs) && s.End() <= freezeNode.Pos() {
								initCL, _ = ast.Unparen(s.Rhs[i]).(*ast.CompositeLit)
							}
						} else if info.Uses[lid] == v {
							badUse = true
							return false
						}
					}
				}
			case *ast.ReturnStmt:
				if isTopStoreArg && s.Pos() > storePos {
					for _, res := range s.Results {
						if rid, ok := ast.Unparen(res).(*ast.Ident); ok && info.Uses[rid] == v {
							approvedStructUses[rid] = true
						}
					}
				}
			case *ast.Ident:
				if info.Uses[s] == v && !approvedStructUses[s] {
					badUse = true
					return false
				}
			}
			return true
		})
		if badUse || assigns != 1 || initCL == nil {
			return false
		}
		return verifyCompositeExpr(initCL, initCL, false)
	}

	if !verifyCompositeExpr(storeArg, storeCall, true) {
		return nil, false
	}
	return regexpVars, true
}
