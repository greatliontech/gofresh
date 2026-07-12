package gofresh

import (
	"context"
	"fmt"
	"go/ast"
	"go/types"
	"os"

	"github.com/greatliontech/gofresh/internal/buildflags"
	"github.com/greatliontech/gofresh/internal/processenv"
	"golang.org/x/tools/go/packages"
)

// ScanPureDirectives loads pkgPaths and returns a purity predicate marking every
// symbol whose declaration carries a //gofresh:pure directive (REQ-purity-directive).
// It is the durable, in-code form of a purity assertion — written once and honored
// automatically by every consumer of the engine. The returned predicate is for
// inspection; callers use WithAssumePure only for additional caller-owned assertions.
// gofresh never infers purity from behavior (REQ-purity-responsibility).
//
// A symbol is named as the closure engine resolves it: a function by its name, a
// method as "Type.Method" with the receiver's pointer star and generics dropped.
func ScanPureDirectives(pkgPaths ...string) (func(Subject) bool, error) {
	return ScanPureDirectivesInWithBuildFlags("", nil, pkgPaths...)
}

// ScanPureDirectivesIn scans under an explicit tree root ("" = the process
// working directory), for callers fingerprinting a tree they do not run
// inside.
func ScanPureDirectivesIn(dir string, pkgPaths ...string) (func(Subject) bool, error) {
	return ScanPureDirectivesInWithBuildFlags(dir, nil, pkgPaths...)
}

// ScanPureDirectivesWithBuildFlags scans the packages selected by buildFlags under
// the process working directory. The flags must match the producing build, so a
// directive in a mutually exclusive unselected file cannot confer purity on the
// selected declaration (REQ-purity-directive, REQ-guard-buildconfig).
func ScanPureDirectivesWithBuildFlags(buildFlags []string, pkgPaths ...string) (func(Subject) bool, error) {
	return ScanPureDirectivesInWithBuildFlags("", buildFlags, pkgPaths...)
}

// ScanPureDirectivesInWithBuildFlags scans under an explicit tree root and the
// producing build's executable flags.
func ScanPureDirectivesInWithBuildFlags(dir string, buildFlags []string, pkgPaths ...string) (func(Subject) bool, error) {
	pure, _, _, err := scanSubjectsInWithBuildFlags(context.Background(), dir, buildFlags, pkgPaths...)
	return pure, err
}

func scanSubjectsInWithBuildFlags(ctx context.Context, dir string, buildFlags []string, pkgPaths ...string) (func(Subject) bool, map[Subject]bool, map[Subject]bool, error) {
	return scanSubjectsInWithBuildFlagsEnv(ctx, dir, os.Environ(), buildFlags, pkgPaths...)
}

func scanSubjectsInWithBuildFlagsEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (func(Subject) bool, map[Subject]bool, map[Subject]bool, error) {
	packageEnv, err := processenv.ForGoPackages(env)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("gofresh: %w", err)
	}
	if err := buildflags.ValidateEnv(dir, env, buildFlags); err != nil {
		return nil, nil, nil, err
	}
	cfg := &packages.Config{
		Context:    ctx,
		Mode:       packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps | packages.NeedModule | packages.NeedForTest,
		Tests:      true,
		Dir:        dir,
		Env:        append([]string(nil), packageEnv...),
		BuildFlags: append([]string(nil), buildFlags...),
	}
	pkgs, err := packages.Load(cfg, pkgPaths...)
	if err != nil {
		return nil, nil, nil, err
	}
	pure := map[Subject]bool{}
	known := map[Subject]bool{}
	openWorld := map[Subject]bool{}
	packageOpenWorld := map[string]bool{}
	requestedPackages := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		requestedPackages[pkgPath] = true
	}
	declarations := map[Subject]string{}
	var scanErr error
	record := func(subject Subject, declaration string) {
		if scanErr != nil {
			return
		}
		if previous := declarations[subject]; previous != "" && previous != declaration {
			scanErr = fmt.Errorf("gofresh: ambiguous subject %s.%s resolves to %s and %s", subject.Package, subject.Symbol, previous, declaration)
			return
		}
		declarations[subject] = declaration
		known[subject] = true
	}
	pureMethods := map[*types.Func]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, file := range p.Syntax {
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || !hasPureDirective(function.Doc) {
					continue
				}
				if method, ok := p.TypesInfo.Defs[function.Name].(*types.Func); ok && method.Type().(*types.Signature).Recv() != nil {
					pureMethods[method] = true
				}
			}
		}
	})
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		// A subject's package is the import path the engine resolves it under. A
		// test variant (in-package or external "pkg_test") declares subjects of the
		// package under test, so key by ForTest there — keying by the variant's own
		// PkgPath would silently drop a directive on an external-test-file subject
		// (REQ-purity-directive).
		pkgPath := p.PkgPath
		if p.ForTest != "" {
			pkgPath = p.ForTest
		}
		if requestedPackages[pkgPath] {
			for _, f := range p.Syntax {
				for _, decl := range f.Decls {
					fd, ok := decl.(*ast.FuncDecl)
					if !ok {
						continue
					}
					sym := fd.Name.Name
					if recv := recvTypeName(fd); recv != "" {
						sym = recv + "." + sym
					}
					subject := Subject{Package: pkgPath, Symbol: sym}
					record(subject, nodeDeclarationKey(p, fd.Name))
					if hasPureDirective(fd.Doc) {
						pure[subject] = true
					}
					if fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func); ok && signatureMayReceiveUnknownDynamic(fn.Type().(*types.Signature)) {
						openWorld[subject] = true
					}
				}
			}
		}
		if p.Types == nil {
			return
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			if variable, ok := scope.Lookup(name).(*types.Var); ok && p.Module != nil && typeMayCarryUnknownDynamic(variable.Type(), make(map[types.Type]bool)) {
				packageOpenWorld[p.PkgPath] = true
			}
		}
		if !requestedPackages[pkgPath] {
			return
		}
		for _, name := range scope.Names() {
			typeName, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			for _, methods := range []*types.MethodSet{
				types.NewMethodSet(types.NewPointer(typeName.Type())),
				types.NewMethodSet(typeName.Type()),
			} {
				for i := 0; i < methods.Len(); i++ {
					method, ok := methods.At(i).Obj().(*types.Func)
					if !ok {
						continue
					}
					subject := Subject{Package: pkgPath, Symbol: name + "." + method.Name()}
					record(subject, objectDeclarationKey(p, method))
					if sig, ok := method.Type().(*types.Signature); ok && signatureMayReceiveUnknownDynamic(sig) {
						openWorld[subject] = true
					}
					if pureMethods[method] {
						pure[subject] = true
					}
				}
			}
		}
	})
	if scanErr != nil {
		return nil, nil, nil, scanErr
	}
	for _, root := range pkgs {
		rootPath := root.PkgPath
		if root.ForTest != "" {
			rootPath = root.ForTest
		}
		if packageGraphHasOpenWorld(root, packageOpenWorld, make(map[string]bool)) {
			for subject := range known {
				if subject.Package == rootPath {
					openWorld[subject] = true
				}
			}
		}
	}
	return func(s Subject) bool { return pure[s] }, known, openWorld, nil
}

func packageGraphHasOpenWorld(pkg *packages.Package, openWorld, seen map[string]bool) bool {
	if pkg == nil || seen[pkg.ID] {
		return false
	}
	seen[pkg.ID] = true
	if openWorld[pkg.PkgPath] {
		return true
	}
	for _, imported := range pkg.Imports {
		if packageGraphHasOpenWorld(imported, openWorld, seen) {
			return true
		}
	}
	return false
}

func signatureMayReceiveUnknownDynamic(sig *types.Signature) bool {
	if sig == nil {
		return true
	}
	if isHarnessSignature(sig) {
		return false
	}
	seen := make(map[types.Type]bool)
	if recv := sig.Recv(); recv != nil && typeMayCarryUnknownDynamic(recv.Type(), seen) {
		return true
	}
	params := sig.Params()
	for i := 0; params != nil && i < params.Len(); i++ {
		if typeMayCarryUnknownDynamic(params.At(i).Type(), seen) {
			return true
		}
	}
	return false
}

func isHarnessSignature(sig *types.Signature) bool {
	if sig == nil || sig.Recv() != nil || sig.Params().Len() != 1 {
		return false
	}
	pointer, ok := sig.Params().At(0).Type().(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return false
	}
	switch named.Obj().Name() {
	case "T", "B", "F", "M":
		return true
	default:
		return false
	}
}

func typeMayCarryUnknownDynamic(t types.Type, seen map[types.Type]bool) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true
	switch t := types.Unalias(t).(type) {
	case *types.Basic:
		return t.Kind() == types.UnsafePointer
	case *types.Interface, *types.Signature:
		return true
	case *types.TypeParam:
		return typeMayCarryUnknownDynamic(t.Constraint(), seen)
	case *types.Named:
		return typeMayCarryUnknownDynamic(t.Underlying(), seen)
	case *types.Pointer:
		return typeMayCarryUnknownDynamic(t.Elem(), seen)
	case *types.Slice:
		return typeMayCarryUnknownDynamic(t.Elem(), seen)
	case *types.Array:
		return typeMayCarryUnknownDynamic(t.Elem(), seen)
	case *types.Map:
		return typeMayCarryUnknownDynamic(t.Key(), seen) || typeMayCarryUnknownDynamic(t.Elem(), seen)
	case *types.Chan:
		return typeMayCarryUnknownDynamic(t.Elem(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if typeMayCarryUnknownDynamic(t.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if typeMayCarryUnknownDynamic(t.At(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func nodeDeclarationKey(pkg *packages.Package, node ast.Node) string {
	if pkg != nil && pkg.Fset != nil && node != nil {
		position := pkg.Fset.PositionFor(node.Pos(), false)
		if position.Filename != "" {
			return fmt.Sprintf("%s:%d", position.Filename, position.Offset)
		}
	}
	return fmt.Sprintf("%s:%d", pkg.ID, node.Pos())
}

func objectDeclarationKey(pkg *packages.Package, obj types.Object) string {
	if pkg != nil && pkg.Fset != nil && obj != nil {
		position := pkg.Fset.PositionFor(obj.Pos(), false)
		if position.Filename != "" {
			return fmt.Sprintf("%s:%d", position.Filename, position.Offset)
		}
	}
	if obj != nil && obj.Pkg() != nil {
		return obj.Pkg().Path() + "." + obj.Name()
	}
	return fmt.Sprintf("%s:%v", pkg.ID, obj)
}

// hasPureDirective reports whether a doc comment group carries the //gofresh:pure
// directive — a comment line whose text (after the slashes) is exactly gofresh:pure,
// the Go directive form with no leading space.
func hasPureDirective(doc *ast.CommentGroup) bool {
	if doc == nil {
		return false
	}
	for _, c := range doc.List {
		if c.Text == "//gofresh:pure" {
			return true
		}
	}
	return false
}

// recvTypeName is a method's receiver type name with the leading pointer star and
// any generic parameters stripped — "" for a plain function or an unnameable
// receiver. It matches stipulator's Go backend, so a method is named identically
// going into a bind and resolving here.
func recvTypeName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if idx, ok := t.(*ast.IndexExpr); ok { // Recv[T]
		t = idx.X
	}
	if idx, ok := t.(*ast.IndexListExpr); ok { // Recv[T, U]
		t = idx.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}
