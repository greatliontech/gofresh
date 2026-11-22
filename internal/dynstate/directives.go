// Package dynstate derives per-package dynamic-state facts (FactOf,
// FactOfWithHooks) over a single precomputed refconfine.PkgIndex and composes
// them across test-binary dependency cones (AnalyzeCone, Compose,
// NonVouchDischargedVars, NewDeferralResolution, ResolveEnvAudit,
// CarrierLinkGraph).
package dynstate

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// MethodDirectives resolves a promoted method's purity and externality
// directives from its declaring package's fact inside the view package's
// own cone — the declaration keys, empty when absent.
func MethodDirectives(cones map[string]map[string][]Fact, viewPackage string, m *types.Func) (pureKey, externalKey string) {
	if cones == nil || m == nil || m.Pkg() == nil {
		return "", ""
	}
	recvName := syntaxutil.MethodRecvNamedTypeName(m)
	if recvName == "" {
		return "", ""
	}
	return memberDirectivesInCone(cones, viewPackage, m.Pkg().Path(), recvName+"."+m.Name())
}

func memberDirectivesInCone(cones map[string]map[string][]Fact, viewPackage, declPkg, key string) (pureKey, externalKey string) {
	if cones == nil || declPkg == "" || key == "" {
		return "", ""
	}
	for _, fact := range cones[viewPackage][declPkg] {
		if pureKey == "" {
			pureKey = fact.PureMethods[key]
		}
		if externalKey == "" {
			externalKey = fact.ExternalMethods[key]
		}
	}
	return pureKey, externalKey
}

type localMemberDir struct {
	pureKey     string
	externalKey string
}

// ScannedSymbol is one symbol sighting emitted by WalkLoadedSubjects.
// Callable distinguishes executable functions and concrete methods from
// non-callable static declarations (type, const, var, Type.Field, Iface.Method).
type ScannedSymbol struct {
	Package     string
	Symbol      string
	Declaration string
	Callable    bool
	Pure        bool
	External    bool
	OpenWorld   string
}

// WalkLoadedSubjects enumerates every addressable Go declaration — callable
// functions, positional init functions, concrete methods, top-level types,
// constants, variables, struct fields (including unambiguously promoted
// fields), and interface method specifications — across pkgs for the requested
// pkgPaths, checking directive conflicts and computing open-world signature
// terms on callables when computeOpenWorld is true (REQ-fresh-coherent-view,
// REQ-purity-directive, REQ-external-precedence).
func WalkLoadedSubjects(audited, computeOpenWorld bool, pkgs []*packages.Package, cones map[string]map[string][]Fact, pkgPaths []string, visit func(ScannedSymbol)) error {
	requestedPackages := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		requestedPackages[pkgPath] = true
	}
	var scanErr error
	checkConflict := func(isPure, isExternal bool, declKey string) {
		if isPure && isExternal && scanErr == nil {
			scanErr = fmt.Errorf("gofresh: %s carries both //gofresh:pure and //gofresh:external", declKey)
		}
	}
	for _, p := range pkgs {
		if p == nil {
			continue
		}
		pkgPath := p.PkgPath
		if p.ForTest != "" && (p.PkgPath == p.ForTest || p.PkgPath == p.ForTest+"_test") {
			pkgPath = p.ForTest
		}
		if !requestedPackages[pkgPath] {
			continue
		}
		var localDirs map[types.Object]localMemberDir
		for _, f := range p.Syntax {
			if f == nil {
				continue
			}
			initOrdinal := 0
			for _, decl := range f.Decls {
				switch d := decl.(type) {
				case *ast.FuncDecl:
					if d.Name == nil || d.Name.Name == "_" {
						continue
					}
					sym := d.Name.Name
					if recv := syntaxutil.RecvTypeName(d); recv != "" {
						sym = recv + "." + sym
					} else if d.Recv != nil {
						continue
					} else if sym == "init" {
						if p.Fset == nil {
							continue
						}
						sym = fmt.Sprintf("init#%s#%d", filepath.Base(p.Fset.PositionFor(f.Pos(), false).Filename), initOrdinal)
						initOrdinal++
					}
					declKey := syntaxutil.NodeDeclarationKey(p, d.Name)
					isPure := syntaxutil.HasDirective(d.Doc, "//gofresh:pure")
					isExternal := syntaxutil.HasDirective(d.Doc, "//gofresh:external")
					checkConflict(isPure, isExternal, declKey)
					var term string
					if computeOpenWorld && p.TypesInfo != nil && p.TypesInfo.Defs != nil {
						if fn, ok := p.TypesInfo.Defs[d.Name].(*types.Func); ok {
							if sig, ok := fn.Type().(*types.Signature); ok {
								term = refconfine.OpenWorldTerm(audited, sig)
							}
						}
					}
					visit(ScannedSymbol{
						Package:     pkgPath,
						Symbol:      sym,
						Declaration: declKey,
						Callable:    true,
						Pure:        isPure,
						External:    isExternal,
						OpenWorld:   term,
					})
				case *ast.GenDecl:
					switch d.Tok {
					case token.TYPE:
						gdPure := syntaxutil.HasDirective(d.Doc, "//gofresh:pure")
						gdExt := syntaxutil.HasDirective(d.Doc, "//gofresh:external")
						for _, spec := range d.Specs {
							ts, ok := spec.(*ast.TypeSpec)
							if !ok || ts.Name == nil {
								continue
							}
							collectASTMemberDirectives(p, ts, &localDirs, checkConflict)
							if ts.Name.Name == "_" {
								continue
							}
							declKey := syntaxutil.NodeDeclarationKey(p, ts.Name)
							isPure := gdPure || syntaxutil.HasDirective(ts.Doc, "//gofresh:pure")
							isExternal := gdExt || syntaxutil.HasDirective(ts.Doc, "//gofresh:external")
							checkConflict(isPure, isExternal, declKey)
							visit(ScannedSymbol{
								Package:     pkgPath,
								Symbol:      ts.Name.Name,
								Declaration: declKey,
								Callable:    false,
								Pure:        isPure,
								External:    isExternal,
							})
						}
					case token.CONST, token.VAR:
						gdPure := syntaxutil.HasDirective(d.Doc, "//gofresh:pure")
						gdExt := syntaxutil.HasDirective(d.Doc, "//gofresh:external")
						for _, spec := range d.Specs {
							vs, ok := spec.(*ast.ValueSpec)
							if !ok {
								continue
							}
							isPure := gdPure || syntaxutil.HasDirective(vs.Doc, "//gofresh:pure")
							isExternal := gdExt || syntaxutil.HasDirective(vs.Doc, "//gofresh:external")
							for _, ident := range vs.Names {
								if ident == nil || ident.Name == "_" {
									continue
								}
								declKey := syntaxutil.NodeDeclarationKey(p, ident)
								checkConflict(isPure, isExternal, declKey)
								visit(ScannedSymbol{
									Package:     pkgPath,
									Symbol:      ident.Name,
									Declaration: declKey,
									Callable:    false,
									Pure:        isPure,
									External:    isExternal,
								})
							}
						}
					}
				}
			}
		}
		if p.Types == nil {
			continue
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			if name == "_" {
				continue
			}
			typeName, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			typ := typeName.Type()
			_, isIface := typ.Underlying().(*types.Interface)
			var methodSets []*types.MethodSet
			if isIface {
				methodSets = []*types.MethodSet{types.NewMethodSet(typ)}
			} else {
				methodSets = []*types.MethodSet{
					types.NewMethodSet(types.NewPointer(typ)),
					types.NewMethodSet(typ),
				}
			}
			seenMethods := map[string]bool{}
			for _, methods := range methodSets {
				for i := 0; i < methods.Len(); i++ {
					method, ok := methods.At(i).Obj().(*types.Func)
					if !ok || method.Name() == "_" || seenMethods[method.Name()] {
						continue
					}
					seenMethods[method.Name()] = true
					orig := method.Origin()
					if isIface {
						pureKey, externalKey := resolveMemberDirective(cones, pkgPath, p.Types, orig, localDirs)
						checkConflict(pureKey != "", externalKey != "", pureKey)
						visit(ScannedSymbol{
							Package:     pkgPath,
							Symbol:      name + "." + method.Name(),
							Declaration: syntaxutil.ObjectDeclarationKey(p, orig),
							Callable:    false,
							Pure:        pureKey != "",
							External:    externalKey != "",
						})
						continue
					}
					var term string
					if computeOpenWorld {
						if sig, ok := method.Type().(*types.Signature); ok {
							term = refconfine.OpenWorldTerm(audited, sig)
						}
					}
					pureKey, externalKey := MethodDirectives(cones, pkgPath, method)
					if pureKey == "" && externalKey == "" {
						pureKey, externalKey = resolveMemberDirective(cones, pkgPath, p.Types, orig, localDirs)
					}
					checkConflict(pureKey != "", externalKey != "", pureKey)
					visit(ScannedSymbol{
						Package:     pkgPath,
						Symbol:      name + "." + method.Name(),
						Declaration: syntaxutil.ObjectDeclarationKey(p, orig),
						Callable:    true,
						Pure:        pureKey != "",
						External:    externalKey != "",
						OpenWorld:   term,
					})
				}
			}
			if _, isStruct := typ.Underlying().(*types.Struct); isStruct {
				for _, candName := range collectStructFieldCandidates(typ) {
					fieldObj, _, _ := types.LookupFieldOrMethod(typ, true, p.Types, candName)
					v, ok := fieldObj.(*types.Var)
					if !ok || !v.IsField() {
						continue
					}
					orig := v.Origin()
					pureKey, externalKey := resolveMemberDirective(cones, pkgPath, p.Types, orig, localDirs)
					checkConflict(pureKey != "", externalKey != "", pureKey)
					visit(ScannedSymbol{
						Package:     pkgPath,
						Symbol:      name + "." + candName,
						Declaration: syntaxutil.ObjectDeclarationKey(p, orig),
						Callable:    false,
						Pure:        pureKey != "",
						External:    externalKey != "",
					})
				}
			}
		}
	}
	return scanErr
}

func objectOrigin(obj types.Object) types.Object {
	switch o := obj.(type) {
	case *types.Var:
		return o.Origin()
	case *types.Func:
		return o.Origin()
	default:
		return obj
	}
}

func embeddedFieldIdent(expr ast.Expr) *ast.Ident {
	for expr != nil {
		switch e := ast.Unparen(expr).(type) {
		case *ast.StarExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.IndexListExpr:
			expr = e.X
		case *ast.Ident:
			return e
		case *ast.SelectorExpr:
			return e.Sel
		default:
			return nil
		}
	}
	return nil
}

func recordASTMemberIdent(p *packages.Package, ident *ast.Ident, isPure, isExternal bool, out *map[types.Object]localMemberDir, checkConflict func(bool, bool, string)) {
	if ident == nil || ident.Name == "_" || (!isPure && !isExternal) {
		return
	}
	declKey := syntaxutil.NodeDeclarationKey(p, ident)
	if checkConflict != nil {
		checkConflict(isPure, isExternal, declKey)
	}
	if out == nil || p.TypesInfo == nil || p.TypesInfo.Defs == nil {
		return
	}
	obj := p.TypesInfo.Defs[ident]
	if obj == nil {
		return
	}
	if *out == nil {
		*out = map[types.Object]localMemberDir{}
	}
	var d localMemberDir
	if isPure {
		d.pureKey = declKey
	}
	if isExternal {
		d.externalKey = declKey
	}
	(*out)[objectOrigin(obj)] = d
}

func walkTypeExprMemberDirectives(p *packages.Package, expr ast.Expr, out *map[types.Object]localMemberDir, checkConflict func(bool, bool, string)) {
	if expr == nil {
		return
	}
	var fields *ast.FieldList
	isStruct := false
	switch t := ast.Unparen(expr).(type) {
	case *ast.StructType:
		fields = t.Fields
		isStruct = true
	case *ast.InterfaceType:
		fields = t.Methods
	default:
		return
	}
	if fields == nil {
		return
	}
	for _, fld := range fields.List {
		if fld.Doc != nil {
			isPure := syntaxutil.HasDirective(fld.Doc, "//gofresh:pure")
			isExternal := syntaxutil.HasDirective(fld.Doc, "//gofresh:external")
			if isPure || isExternal {
				if len(fld.Names) == 0 {
					if isStruct {
						recordASTMemberIdent(p, embeddedFieldIdent(fld.Type), isPure, isExternal, out, checkConflict)
					}
				} else {
					for _, ident := range fld.Names {
						recordASTMemberIdent(p, ident, isPure, isExternal, out, checkConflict)
					}
				}
			}
		}
		walkTypeExprMemberDirectives(p, fld.Type, out, checkConflict)
	}
}

func collectASTMemberDirectives(p *packages.Package, ts *ast.TypeSpec, out *map[types.Object]localMemberDir, checkConflict func(bool, bool, string)) {
	if p == nil || ts == nil {
		return
	}
	walkTypeExprMemberDirectives(p, ts.Type, out, checkConflict)
}

func resolveMemberDirective(cones map[string]map[string][]Fact, viewPackage string, curPkg *types.Package, orig types.Object, localDirs map[types.Object]localMemberDir) (pureKey, externalKey string) {
	if orig == nil {
		return "", ""
	}
	if local, ok := localDirs[orig]; ok {
		return local.pureKey, local.externalKey
	}
	if cones == nil || orig.Pkg() == nil || orig.Pkg() == curPkg {
		return "", ""
	}
	ownerName := foreignMemberOwnerName(orig)
	if ownerName == "" {
		return "", ""
	}
	return memberDirectivesInCone(cones, viewPackage, orig.Pkg().Path(), ownerName+"."+orig.Name())
}

func foreignMemberOwnerName(orig types.Object) string {
	pkg := orig.Pkg()
	if pkg == nil || pkg.Scope() == nil {
		return ""
	}
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		if name == "_" {
			continue
		}
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		obj, _, _ := types.LookupFieldOrMethod(tn.Type(), true, pkg, orig.Name())
		if obj != nil && objectOrigin(obj) == orig {
			return name
		}
	}
	return ""
}

func collectStructFieldCandidates(root types.Type) []string {
	seenNames := map[string]bool{}
	visited := map[types.Type]bool{}
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil {
			return
		}
		u := types.Unalias(t)
		if ptr, ok := u.(*types.Pointer); ok {
			u = types.Unalias(ptr.Elem())
		}
		if visited[u] {
			return
		}
		visited[u] = true
		st, ok := u.Underlying().(*types.Struct)
		if !ok {
			return
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f == nil {
				continue
			}
			if f.Name() != "_" {
				seenNames[f.Name()] = true
			}
			if f.Embedded() {
				walk(f.Type())
			}
		}
	}
	walk(root)
	names := make([]string, 0, len(seenNames))
	for n := range seenNames {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
