// Package propharness mechanically verifies that a candidate property-testing
// harness package (pgregory.net/rapid) satisfies the closed property-harness
// protocol over its Go AST and type information
// (REQ-closure-observability-property-harness).
package propharness

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"

	"github.com/greatliontech/gofresh/internal/auditset"
)

// ModulePath is the property-testing harness import path.
const ModulePath = "pgregory.net/rapid"

// IsHarnessPath reports whether pkgPath is the property-testing harness
// package (pgregory.net/rapid).
func IsHarnessPath(pkgPath string) bool {
	return pkgPath == ModulePath
}

// StructHasNoExportedFields reports whether st and all its embedded struct
// fields declare zero exported fields.
func StructHasNoExportedFields(st *types.Struct) bool {
	if st == nil {
		return false
	}
	seen := map[*types.Struct]bool{}
	var walk func(*types.Struct) bool
	walk = func(cur *types.Struct) bool {
		if cur == nil {
			return false
		}
		if seen[cur] {
			return true
		}
		seen[cur] = true
		for i := 0; i < cur.NumFields(); i++ {
			f := cur.Field(i)
			if f.Exported() {
				return false
			}
			if f.Embedded() {
				ft := types.Unalias(f.Type())
				if ptr, ok := ft.(*types.Pointer); ok {
					ft = types.Unalias(ptr.Elem())
				}
				if embSt, ok := ft.Underlying().(*types.Struct); ok && !walk(embSt) {
					return false
				}
			}
		}
		return true
	}
	return walk(st)
}

// VerifyPackage mechanically checks that pkg satisfies the closed
// property-harness protocol invariants over its selected Go syntax and type
// information (REQ-closure-observability-property-harness).
func VerifyPackage(audited bool, pkg *packages.Package) bool {
	ok, _ := VerifyPackageWithReason(audited, pkg)
	return ok
}

// VerifyPackageWithReason mechanically checks that pkg satisfies the closed
// property-harness protocol invariants and returns a diagnostic refusal reason
// when verification fails.
func VerifyPackageWithReason(audited bool, pkg *packages.Package) (bool, string) {
	if !audited || pkg == nil || !IsHarnessPath(pkg.PkgPath) {
		return false, "unaudited or non-harness pkg"
	}
	if len(pkg.Errors) > 0 || pkg.Types == nil || pkg.TypesInfo == nil || len(pkg.Syntax) == 0 {
		return false, "errors or missing syntax/types"
	}
	if len(pkg.OtherFiles) > 0 || len(pkg.EmbedFiles) > 0 || len(pkg.EmbedPatterns) > 0 {
		return false, "other/embed files present"
	}
	if len(pkg.CompiledGoFiles) > 0 && len(pkg.CompiledGoFiles) != len(pkg.GoFiles) {
		return false, "compiled go files mismatch"
	}
	if pkg.Imports["C"] != nil || pkg.Imports["runtime/cgo"] != nil || pkg.Imports["unsafe"] != nil {
		return false, "forbidden cgo/unsafe import"
	}
	for impPath := range pkg.Imports {
		if !harnessPureStdImports[impPath] && !harnessProtocolStdImports[impPath] {
			return false, "disallowed import: " + impPath
		}
	}

	idx, errReason := buildHarnessPkgIndex(pkg)
	if errReason != "" {
		return false, errReason
	}

	// Gate 2: Protocol stdlib symbol discipline across TypesInfo.Uses & Selections.
	for ident, obj := range pkg.TypesInfo.Uses {
		if ident == nil || obj == nil || obj.Pkg() == nil || obj.Pkg() == pkg.Types {
			continue
		}
		impPath := obj.Pkg().Path()
		if harnessPureStdImports[impPath] {
			if !checkHarnessPureStdObjectUse(impPath, obj) {
				return false, "disallowed pure std use: " + impPath + "." + obj.Name()
			}
			continue
		}
		if !harnessProtocolStdImports[impPath] {
			return false, "disallowed use pkg: " + impPath + "." + obj.Name()
		}
		if !checkHarnessProtocolObjectAllowed(impPath, obj) {
			return false, "disallowed protocol use: " + impPath + "." + obj.Name()
		}
	}
	for _, sel := range pkg.TypesInfo.Selections {
		if sel == nil || sel.Obj() == nil || sel.Obj().Pkg() == nil || sel.Obj().Pkg() == pkg.Types {
			continue
		}
		obj := sel.Obj()
		impPath := obj.Pkg().Path()
		if harnessPureStdImports[impPath] {
			if !checkHarnessPureStdObjectUse(impPath, obj) {
				return false, "disallowed pure std selection: " + impPath + "." + obj.Name()
			}
			continue
		}
		if !harnessProtocolStdImports[impPath] || !checkHarnessProtocolObjectAllowed(impPath, obj) {
			return false, "disallowed protocol selection: " + impPath + "." + obj.Name()
		}
	}

	// Gate 2: Closed package-scope variable categories (returning init-only Category 3A vars).
	categoryA, okVars := verifyHarnessPackageVars(audited, idx)
	if !okVars {
		return false, "verifyHarnessPackageVars failed"
	}

	// Gate 3: Contextual AST protocol checks (flag.*Var, os.LookupEnv/Getenv, os.Stdout,
	// failfile/debugvis os & filepath.Glob provenance, joined synctest GoStmt,
	// non-value-taken reflect/protocol funcs, and TB.Logf witness).
	if okCtx, reasonCtx := verifyHarnessProtocolCallContexts(audited, idx, categoryA); !okCtx {
		return false, "verifyHarnessProtocolCallContexts: " + reasonCtx
	}

	// Gate 4: Exported handle T, Check/MakeCheck entrypoints, and closed exported return types.
	if !verifyHarnessExportedSurface(audited, idx) {
		return false, "verifyHarnessExportedSurface failed"
	}
	return true, ""
}

type harnessVarSpecEntry struct {
	v    *types.Var
	spec *ast.ValueSpec
	val  ast.Expr
}

type harnessParamKey struct {
	fn  *types.Func
	idx int
}

// harnessPkgIndex holds the precomputed declaration, call-graph, parameter,
// and mutation summaries built in a single pass over pkg.Syntax.
type harnessPkgIndex struct {
	pkg                        *packages.Package
	info                       *types.Info
	pkgTypes                   *types.Package
	declFuncs                  map[*types.Func]*ast.FuncDecl
	allDecls                   map[*types.Func]*ast.FuncDecl
	paramIndex                 map[*types.Var]harnessParamKey
	pkgVars                    []harnessVarSpecEntry
	pkgVarSet                  map[*types.Var]harnessVarSpecEntry
	initOnly                   map[*types.Func]bool
	funcValueTaken             map[*types.Func]bool
	callSitesByFunc            map[*types.Func][]*ast.CallExpr
	allCallersOf               map[*types.Func]map[*types.Func]bool
	anyValueTaken              map[*types.Func]bool
	maphashSeeds               map[*types.Func]bool
	maphashInInitOrGlobal      bool
	mutatedNamedStructs        map[*types.Named]bool
	mutatedOrAddrLocals        map[*types.Var]bool
	reassignedParams           map[*types.Var]bool
	generatorOrigin            *types.Named
	generatorFieldsWriteOnceOK bool
}

func (idx *harnessPkgIndex) findFuncParamIndex(paramObj *types.Var) (*types.Func, int) {
	if paramObj == nil {
		return nil, -1
	}
	if k, ok := idx.paramIndex[paramObj]; ok {
		return k.fn, k.idx
	}
	return nil, -1
}

func buildHarnessPkgIndex(pkg *packages.Package) (*harnessPkgIndex, string) {
	info := pkg.TypesInfo
	pkgTypes := pkg.Types
	idx := &harnessPkgIndex{
		pkg:                 pkg,
		info:                info,
		pkgTypes:            pkgTypes,
		declFuncs:           map[*types.Func]*ast.FuncDecl{},
		allDecls:            map[*types.Func]*ast.FuncDecl{},
		paramIndex:          map[*types.Var]harnessParamKey{},
		pkgVarSet:           map[*types.Var]harnessVarSpecEntry{},
		initOnly:            map[*types.Func]bool{},
		funcValueTaken:      map[*types.Func]bool{},
		callSitesByFunc:     map[*types.Func][]*ast.CallExpr{},
		allCallersOf:        map[*types.Func]map[*types.Func]bool{},
		anyValueTaken:       map[*types.Func]bool{},
		maphashSeeds:        map[*types.Func]bool{},
		mutatedNamedStructs: map[*types.Named]bool{},
		mutatedOrAddrLocals: map[*types.Var]bool{},
		reassignedParams:    map[*types.Var]bool{},
	}

	if genObj, ok := pkgTypes.Scope().Lookup("Generator").(*types.TypeName); ok && genObj != nil {
		if named, ok := genObj.Type().(*types.Named); ok {
			idx.generatorOrigin = named.Origin()
			idx.generatorFieldsWriteOnceOK = true
		}
	}

	// Pass 1 over top-level syntax headers (comments, imports, and declaration headers).
	for _, af := range pkg.Syntax {
		if af == nil {
			return nil, "nil ast.File"
		}
		for _, cg := range af.Comments {
			for _, c := range cg.List {
				if hasHarnessForbiddenDirective(c.Text) {
					return nil, "forbidden directive: " + c.Text
				}
			}
		}
		for _, imp := range af.Imports {
			if imp == nil || imp.Path == nil {
				return nil, "nil import spec"
			}
			impPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil || (!harnessPureStdImports[impPath] && !harnessProtocolStdImports[impPath]) {
				return nil, "disallowed syntax import: " + imp.Path.Value
			}
			if imp.Name != nil && imp.Name.Name == "." {
				return nil, "dot import: " + impPath
			}
		}
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil || d.Name == nil {
					return nil, "bodyless func decl"
				}
				if d.Recv == nil && d.Name.Name == "init" {
					continue
				}
				fn, ok := info.Defs[d.Name].(*types.Func)
				if !ok || fn == nil {
					if d.Recv == nil {
						return nil, "unresolved func decl: " + d.Name.Name
					}
					continue
				}
				idx.allDecls[fn.Origin()] = d
				if d.Recv == nil {
					idx.declFuncs[fn] = d
					params := fn.Signature().Params()
					for i := 0; i < params.Len(); i++ {
						idx.paramIndex[params.At(i)] = harnessParamKey{fn: fn, idx: i}
					}
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						return nil, "non-ValueSpec var"
					}
					if len(vs.Values) > 0 && len(vs.Values) != len(vs.Names) {
						return nil, "multi-value var spec"
					}
					for i, nameIdent := range vs.Names {
						if nameIdent == nil || nameIdent.Name == "_" {
							return nil, "blank var decl"
						}
						v, ok := info.Defs[nameIdent].(*types.Var)
						if !ok || v == nil || v.Exported() {
							return nil, "exported or unresolved var: " + nameIdent.Name
						}
						var initVal ast.Expr
						if i < len(vs.Values) {
							initVal = vs.Values[i]
						}
						entry := harnessVarSpecEntry{v: v, spec: vs, val: initVal}
						idx.pkgVars = append(idx.pkgVars, entry)
						idx.pkgVarSet[v] = entry
					}
				}
			}
		}
	}

	calledFromInit := map[*types.Func]bool{}
	calledFromOther := map[*types.Func]bool{}
	declCallersOf := map[*types.Func]map[*types.Func]bool{}

	isGenType := func(t types.Type) bool {
		if idx.generatorOrigin == nil || t == nil {
			return false
		}
		if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
			t = ptr.Elem()
		}
		named, ok := types.Unalias(t).(*types.Named)
		return ok && named.Origin() == idx.generatorOrigin
	}

	exprChainHitsGen := func(e ast.Expr) (hit bool, directStringField bool) {
		if idx.generatorOrigin == nil {
			return false, false
		}
		if sel, isSel := ast.Unparen(e).(*ast.SelectorExpr); isSel && isGenType(info.TypeOf(sel.X)) {
			ft := info.TypeOf(sel)
			if ft != nil {
				if basic, isB := types.Unalias(ft).Underlying().(*types.Basic); isB && basic.Kind() == types.String {
					return true, true
				}
			}
			return true, false
		}
		for e != nil {
			switch x := ast.Unparen(e).(type) {
			case *ast.SelectorExpr:
				if isGenType(info.TypeOf(x.X)) {
					return true, false
				}
				if selInfo := info.Selections[x]; selInfo != nil && selInfo.Kind() == types.FieldVal {
					selIdx := selInfo.Index()
					cur := types.Unalias(selInfo.Recv())
					if ptr, isP := cur.(*types.Pointer); isP {
						cur = types.Unalias(ptr.Elem())
					}
					for step := 0; step < len(selIdx)-1; step++ {
						st, isSt := cur.Underlying().(*types.Struct)
						if !isSt || selIdx[step] >= st.NumFields() {
							break
						}
						cur = types.Unalias(st.Field(selIdx[step]).Type())
						if ptr, isP := cur.(*types.Pointer); isP {
							cur = types.Unalias(ptr.Elem())
						}
						if isGenType(cur) {
							return true, false
						}
					}
				}
				e = x.X
			case *ast.IndexExpr:
				e = x.X
			case *ast.SliceExpr:
				e = x.X
			case *ast.StarExpr:
				if isGenType(info.TypeOf(x.X)) {
					return true, false
				}
				e = x.X
			default:
				return false, false
			}
		}
		return false, false
	}

	markFieldOwner := func(e ast.Expr) {
		for e != nil {
			switch x := ast.Unparen(e).(type) {
			case *ast.SelectorExpr:
				if sel := info.Selections[x]; sel != nil && sel.Kind() == types.FieldVal {
					cur := types.Unalias(sel.Recv())
					if ptr, ok := cur.(*types.Pointer); ok {
						cur = types.Unalias(ptr.Elem())
					}
					if named, ok := cur.(*types.Named); ok {
						idx.mutatedNamedStructs[named.Origin()] = true
					}
					selIdx := sel.Index()
					for step := 0; step < len(selIdx)-1; step++ {
						st, ok := cur.Underlying().(*types.Struct)
						if !ok || selIdx[step] >= st.NumFields() {
							break
						}
						cur = types.Unalias(st.Field(selIdx[step]).Type())
						if ptr, ok := cur.(*types.Pointer); ok {
							cur = types.Unalias(ptr.Elem())
						}
						if named, ok := cur.(*types.Named); ok {
							idx.mutatedNamedStructs[named.Origin()] = true
						}
					}
				}
				e = x.X
			case *ast.IndexExpr:
				e = x.X
			case *ast.SliceExpr:
				e = x.X
			case *ast.StarExpr:
				rt := types.Unalias(info.TypeOf(x.X))
				if ptr, ok := rt.(*types.Pointer); ok {
					if named, ok := types.Unalias(ptr.Elem()).(*types.Named); ok {
						idx.mutatedNamedStructs[named.Origin()] = true
					}
				}
				e = x.X
			default:
				return
			}
		}
	}

	markLocalChain := func(e ast.Expr, isDefStmt bool) {
		if id, isID := ast.Unparen(e).(*ast.Ident); isID {
			if v, isV := info.Uses[id].(*types.Var); isV && v != nil {
				idx.mutatedOrAddrLocals[v] = true
			}
			return
		}
		if isDefStmt {
			return
		}
		if v := rootPlaceVar(info, e, func(v *types.Var) bool { return !v.IsField() }); v != nil {
			idx.mutatedOrAddrLocals[v] = true
		}
	}

	// Single AST walk over all package declarations.
	walkDecl := func(root ast.Node, inInitRoot bool, declCallerFn *types.Func, ownerOrig *types.Func, paramSet map[*types.Var]bool) {
		calleeIdents := map[*ast.Ident]bool{}
		allCalleeIdents := map[*ast.Ident]bool{}

		var walk func(n ast.Node, inFuncLit bool, inOnceDo bool)
		walk = func(n ast.Node, inFuncLit bool, inOnceDo bool) {
			if n == nil {
				return
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				if x.Type != nil {
					walk(x.Type, true, false)
				}
				if x.Body != nil {
					walk(x.Body, true, inOnceDo)
				}
				return
			case *ast.GoStmt:
				walk(x.Call, true, false)
				return
			case *ast.AssignStmt:
				isDef := x.Tok == token.DEFINE
				for _, lhs := range x.Lhs {
					markFieldOwner(lhs)
					markLocalChain(lhs, isDef)
					if paramSet != nil {
						if v := lookupLocalVar(info, pkgTypes.Scope(), lhs); v != nil && paramSet[v] {
							idx.reassignedParams[v] = true
						}
					}
					if idx.generatorFieldsWriteOnceOK {
						if hit, directStr := exprChainHitsGen(lhs); hit {
							if !inOnceDo || !directStr || x.Tok != token.ASSIGN {
								idx.generatorFieldsWriteOnceOK = false
							}
						}
					}
				}
			case *ast.IncDecStmt:
				markFieldOwner(x.X)
				markLocalChain(x.X, false)
				if idx.generatorFieldsWriteOnceOK {
					if hit, _ := exprChainHitsGen(x.X); hit {
						idx.generatorFieldsWriteOnceOK = false
					}
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					for _, be := range []ast.Expr{x.Key, x.Value} {
						if be == nil {
							continue
						}
						markFieldOwner(be)
						markLocalChain(be, false)
						if idx.generatorFieldsWriteOnceOK {
							if hit, _ := exprChainHitsGen(be); hit {
								idx.generatorFieldsWriteOnceOK = false
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					markFieldOwner(x.X)
					markLocalChain(x.X, false)
					if paramSet != nil {
						if v := lookupLocalVar(info, pkgTypes.Scope(), x.X); v != nil && paramSet[v] {
							idx.reassignedParams[v] = true
						}
					}
					if idx.generatorFieldsWriteOnceOK {
						if hit, _ := exprChainHitsGen(x.X); hit {
							idx.generatorFieldsWriteOnceOK = false
						}
					}
				}
			case *ast.CallExpr:
				if arg0, ok := mutatingBuiltinFirstArg(info, x); ok {
					markFieldOwner(arg0)
					markLocalChain(arg0, false)
					if idx.generatorFieldsWriteOnceOK {
						if hit, _ := exprChainHitsGen(arg0); hit {
							idx.generatorFieldsWriteOnceOK = false
						}
					}
				}
				baseFun := peelHarnessCallee(x.Fun)
				switch bf := baseFun.(type) {
				case *ast.Ident:
					allCalleeIdents[bf] = true
					if fn, ok := info.Uses[bf].(*types.Func); ok && idx.declFuncs[fn] != nil {
						calleeIdents[bf] = true
						idx.callSitesByFunc[fn] = append(idx.callSitesByFunc[fn], x)
						if inInitRoot && !inFuncLit {
							calledFromInit[fn] = true
						} else if declCallerFn != nil && !inFuncLit {
							if declCallersOf[fn] == nil {
								declCallersOf[fn] = map[*types.Func]bool{}
							}
							declCallersOf[fn][declCallerFn] = true
						} else {
							calledFromOther[fn] = true
						}
					}
				case *ast.SelectorExpr:
					if bf.Sel != nil {
						allCalleeIdents[bf.Sel] = true
					}
				}
				callee := resolveHarnessFuncExpr(info, x.Fun)
				if callee != nil {
					orig := callee.Origin()
					if idx.allDecls[orig] != nil {
						if idx.allCallersOf[orig] == nil {
							idx.allCallersOf[orig] = map[*types.Func]bool{}
						}
						idx.allCallersOf[orig][ownerOrig] = true
					}
					if callee.Name() == "Do" {
						if rPkg, rName := recvNamedTypeName(callee.Signature()); rPkg == "sync" && rName == "Once" && len(x.Args) == 1 {
							walk(x.Fun, inFuncLit, inOnceDo)
							walk(x.Args[0], inFuncLit, true)
							return
						}
					}
				}
			case *ast.Ident:
				if !calleeIdents[x] {
					if fn, ok := info.Uses[x].(*types.Func); ok && idx.declFuncs[fn] != nil {
						idx.funcValueTaken[fn] = true
						idx.anyValueTaken[fn.Origin()] = true
					}
				}
				if !allCalleeIdents[x] {
					if fn, ok := info.Uses[x].(*types.Func); ok && fn != nil && idx.allDecls[fn.Origin()] != nil {
						idx.anyValueTaken[fn.Origin()] = true
					}
				}
				if obj := info.Uses[x]; obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "hash/maphash" {
					if ownerOrig == nil {
						idx.maphashInInitOrGlobal = true
					} else {
						idx.maphashSeeds[ownerOrig] = true
					}
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if child == nil || child == n {
					return true
				}
				walk(child, inFuncLit, inOnceDo)
				return false
			})
		}
		walk(root, false, false)
	}

	for _, af := range pkg.Syntax {
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == "init" {
					walkDecl(d.Body, true, nil, nil, nil)
				} else if fn, ok := info.Defs[d.Name].(*types.Func); ok && fn != nil {
					var declCaller *types.Func
					var paramSet map[*types.Var]bool
					if d.Recv == nil {
						if !fn.Exported() {
							declCaller = fn
						}
						params := fn.Signature().Params()
						if params.Len() > 0 {
							paramSet = make(map[*types.Var]bool, params.Len())
							for i := 0; i < params.Len(); i++ {
								paramSet[params.At(i)] = true
							}
						}
					}
					walkDecl(d.Body, false, declCaller, fn.Origin(), paramSet)
				} else {
					walkDecl(d.Body, false, nil, nil, nil)
				}
			case *ast.GenDecl:
				walkDecl(d, true, nil, nil, nil)
			}
		}
	}

	for fn := range idx.declFuncs {
		if !fn.Exported() && !idx.funcValueTaken[fn] && !calledFromOther[fn] && (calledFromInit[fn] || len(declCallersOf[fn]) > 0) {
			idx.initOnly[fn] = true
		}
	}
	changed := true
	for changed {
		changed = false
		for fn := range idx.initOnly {
			hasInitCaller := calledFromInit[fn]
			for caller := range declCallersOf[fn] {
				if !idx.initOnly[caller] {
					delete(idx.initOnly, fn)
					changed = true
					hasInitCaller = false
					break
				}
				hasInitCaller = true
			}
			if idx.initOnly[fn] && !hasInitCaller {
				delete(idx.initOnly, fn)
				changed = true
			}
		}
	}

	return idx, ""
}

func hasHarnessForbiddenDirective(text string) bool {
	trimmed := strings.TrimSpace(strings.TrimPrefix(text, "//"))
	trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "/*"))
	trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, "*/"))
	for _, dir := range []string{"go:linkname", "go:linknamestd", "go:wasmimport", "go:cgo_"} {
		if strings.HasPrefix(trimmed, dir) {
			if dir == "go:cgo_" || trimmed == dir {
				return true
			}
			if _, ok := auditset.BoundedToken(trimmed, dir, " \t"); ok {
				return true
			}
		}
	}
	return false
}

func peelHarnessCallee(e ast.Expr) ast.Expr {
	for e != nil {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		default:
			return e
		}
	}
	return nil
}

func resolveHarnessFuncExpr(info *types.Info, e ast.Expr) *types.Func {
	e = peelHarnessCallee(e)
	switch x := e.(type) {
	case *ast.Ident:
		fn, _ := info.Uses[x].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		if sel := info.Selections[x]; sel != nil {
			fn, _ := sel.Obj().(*types.Func)
			return fn
		}
		if x.Sel != nil {
			fn, _ := info.Uses[x.Sel].(*types.Func)
			return fn
		}
	}
	return nil
}

func mutatingBuiltinFirstArg(info *types.Info, call *ast.CallExpr) (ast.Expr, bool) {
	if call == nil || len(call.Args) == 0 {
		return nil, false
	}
	id, ok := peelHarnessCallee(call.Fun).(*ast.Ident)
	if !ok {
		return nil, false
	}
	b, isB := info.Uses[id].(*types.Builtin)
	if !isB || b == nil {
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

func rootPkgVar(info *types.Info, e ast.Expr, pkgVarSet map[*types.Var]harnessVarSpecEntry) *types.Var {
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

func underlyingType(t types.Type) types.Type {
	if t = types.Unalias(t); t != nil {
		return t.Underlying()
	}
	return nil
}

func recvNamedTypeName(sig *types.Signature) (pkgPath, typeName string) {
	if sig == nil || sig.Recv() == nil {
		return "", ""
	}
	rt := types.Unalias(sig.Recv().Type())
	if ptr, ok := rt.(*types.Pointer); ok {
		rt = types.Unalias(ptr.Elem())
	}
	named, ok := rt.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return "", ""
	}
	return named.Obj().Pkg().Path(), named.Obj().Name()
}

func constStringPrefix(info *types.Info, e ast.Expr, prefix string) bool {
	if info == nil || e == nil {
		return false
	}
	tv, ok := info.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	return strings.HasPrefix(constant.StringVal(tv.Value), prefix)
}

func constStringEq(info *types.Info, e ast.Expr, want string) bool {
	if info == nil || e == nil {
		return false
	}
	tv, ok := info.Types[e]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.String && constant.StringVal(tv.Value) == want
}
