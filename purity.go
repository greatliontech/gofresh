package gofresh

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/internal/gotool"
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
	pure, _, _, _, err := scanSubjectsInWithBuildFlags(context.Background(), dir, buildFlags, pkgPaths...)
	return pure, err
}

func scanSubjectsInWithBuildFlags(ctx context.Context, dir string, buildFlags []string, pkgPaths ...string) (func(Subject) bool, map[Subject]bool, map[Subject]bool, map[Subject]bool, error) {
	return scanSubjectsInWithBuildFlagsEnv(ctx, dir, os.Environ(), buildFlags, pkgPaths...)
}

func scanSubjectsInWithBuildFlagsEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (func(Subject) bool, map[Subject]bool, map[Subject]bool, map[Subject]bool, error) {
	hasher, err := closure.NewAtContextEnv(ctx, dir, env, buildFlags...)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pure, known, openWorld, external, _, err := scanViewSubjects(ctx, hasher, "", dir, env, buildFlags, nil, pkgPaths...)
	return pure, known, openWorld, external, err
}

// scanViewSubjects performs one observation pass's whole subject scan: the
// metadata graph names every node and its mutability class, one typed load
// covers the view packages' variants and every mutable-local graph package,
// the dynamic-state derivation serves version-pinned facts from the memo, and
// the subject walk reads that one load (REQ-fresh-coherent-view). The typed
// load is installed on the hasher for the pass's sibling consumers. An empty
// factScope disables fact persistence, never the derivation.
func scanViewSubjects(ctx context.Context, hasher *closure.Hasher, factScope, dir string, env, buildFlags []string, snapshot *gotool.EnvSnapshot, pkgPaths ...string) (func(Subject) bool, map[Subject]bool, map[Subject]bool, map[Subject]bool, *closure.ViewLoad, error) {
	meta, err := hasher.GraphMetadata(pkgPaths...)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	requested := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		requested[pkgPath] = true
	}
	patterns := append([]string(nil), pkgPaths...)
	seenPattern := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		seenPattern[pkgPath] = true
	}
	for _, node := range meta {
		// Plain mutable-local graph packages load as patterns; test
		// variants of the view packages load through the view patterns, and
		// an intermediate recompilation ("r [a.test]") is scanned from its
		// own compilation via the dependency-expanded fallback load in
		// deriveViewDynamicState — a plain stand-in would miss variant-only
		// resolution and need not even compile.
		if node.Class != closure.MutableLocalPackage || node.TestMain || node.ForTest != "" || seenPattern[node.PkgPath] {
			continue
		}
		seenPattern[node.PkgPath] = true
		patterns = append(patterns, node.PkgPath)
	}
	load, err := closure.LoadViewPackagesEnvSnapshot(ctx, dir, env, buildFlags, snapshot, patterns...)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	hasher.UseViewLoad(load)
	state, err := deriveViewDynamicState(ctx, hasher, factScope, dir, env, buildFlags, load, pkgPaths)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	pure, known, openWorld, external, err := scanSubjectsFromLoaded(load.Packages(), state, pkgPaths...)
	return pure, known, openWorld, external, load, err
}

// scanSubjectsFromLoaded derives the subject walk — subject enumeration,
// directives, per-subject dynamic-signature marks — from an observation
// pass's already-loaded packages, applying the pass's dynamic-state
// derivation for the shared-dynamic-state downgrade and promoted-method
// directives (REQ-fresh-coherent-view, REQ-closure-shared-dynamic-state).
func scanSubjectsFromLoaded(pkgs []*packages.Package, state *viewDynamicState, pkgPaths ...string) (func(Subject) bool, map[Subject]bool, map[Subject]bool, map[Subject]bool, error) {
	pure := map[Subject]bool{}
	external := map[Subject]bool{}
	known := map[Subject]bool{}
	openWorld := map[Subject]bool{}
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
	for _, p := range pkgs {
		// A subject's package is the import path the engine resolves it under. The
		// package under test's own test variants declare subjects of the package
		// under test, so key those by ForTest — keying by the variant's own PkgPath
		// would silently drop a directive on an external-test-file subject
		// (REQ-purity-directive). But ForTest alone is not that discriminator: the
		// go tool sets it on every package recompiled into the test binary,
		// including intermediate dependencies (r imports a, a's external test
		// imports r → "r [a.test]" carries ForTest=a). Only the in-package variant
		// (PkgPath == ForTest) and the external test package (PkgPath is the tested
		// path + "_test", the go tool's naming for it) declare the tested package's
		// subjects; a recompiled dependency keeps its own PkgPath identity —
		// otherwise its declarations enter the scan as subjects of the tested
		// package and a shared top-level name fails the whole request as an
		// ambiguous subject.
		pkgPath := p.PkgPath
		if p.ForTest != "" && (p.PkgPath == p.ForTest || p.PkgPath == p.ForTest+"_test") {
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
					isPure, isExternal := hasDirective(fd.Doc, "//gofresh:pure"), hasDirective(fd.Doc, "//gofresh:external")
					if isPure && isExternal && scanErr == nil {
						// The declarations contradict: pure vouches reuse,
						// external forbids it (REQ-external-precedence). The
						// refusal is scoped to declarations yielding this
						// scan's subjects — a conflicted declaration deeper
						// in the loaded graph is its own package's defect,
						// surfacing when that package is scanned.
						scanErr = fmt.Errorf("gofresh: %s carries both //gofresh:pure and //gofresh:external", nodeDeclarationKey(p, fd.Name))
					}
					if isPure {
						pure[subject] = true
					}
					if isExternal {
						external[subject] = true
					}
					if fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func); ok && signatureMayReceiveUnknownDynamic(fn.Type().(*types.Signature)) {
						openWorld[subject] = true
					}
				}
			}
		}
		if p.Types == nil || !requestedPackages[pkgPath] {
			continue
		}
		scope := p.Types.Scope()
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
					pureKey, externalKey := state.methodDirectives(method)
					if pureKey != "" && externalKey != "" && scanErr == nil {
						scanErr = fmt.Errorf("gofresh: %s carries both //gofresh:pure and //gofresh:external", pureKey)
					}
					if pureKey != "" {
						pure[subject] = true
					}
					if externalKey != "" {
						external[subject] = true
					}
				}
			}
		}
	}
	if scanErr != nil {
		return nil, nil, nil, nil, scanErr
	}
	// The shared-dynamic-state downgrade: every subject of a package whose
	// graph carries mutated shared dynamic state is unverifiable
	// (REQ-closure-shared-dynamic-state); the reachability came from the
	// pass's dynamic-state derivation over the metadata graph.
	for subject := range known {
		if state.downgraded[subject.Package] {
			openWorld[subject] = true
		}
	}
	return func(s Subject) bool { return pure[s] }, known, openWorld, external, nil
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

// nodeDeclarationKey and objectDeclarationKey derive the identity the
// ambiguous-subject refusal compares: one declaration must yield one key no
// matter which build variant sights it. Under Tests: true the same source
// package is visited once per variant with distinct pkg.IDs ("p" and
// "p [p.test]"), so no key may incorporate the sighting variant's identity —
// a variant-dependent key manufactures ambiguity for a single declaration and
// fails the whole package.
func nodeDeclarationKey(pkg *packages.Package, node ast.Node) string {
	if pkg != nil && pkg.Fset != nil && node != nil {
		position := pkg.Fset.PositionFor(node.Pos(), false)
		if position.Filename != "" {
			return fmt.Sprintf("%s:%d", position.Filename, position.Offset)
		}
	}
	return fmt.Sprintf("%s:%d", pkg.PkgPath, node.Pos())
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
	// Position-less and package-less means a universe declaration — the
	// canonical case is error's Error method promoted through embedding. The
	// object's own description identifies it fully; genuinely distinct
	// declarations never reach this branch (real declarations carry a position
	// or a defining package).
	return fmt.Sprintf("universe:%v", obj)
}

// hasDirective reports whether a doc comment group carries the named gofresh
// directive — a comment line whose text is exactly the directive, the Go
// directive form with no leading space.
func hasDirective(doc *ast.CommentGroup, directive string) bool {
	if doc == nil {
		return false
	}
	for _, c := range doc.List {
		if c.Text == directive {
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

// dynamicVarKey identifies a package-level variable stably across the
// test-variant recompilations packages.Load produces: variant type
// objects differ per graph, the (package path, name) pair does not. A
// mutation recorded under any variant marks the name for all — the
// conservative direction.
func dynamicVarKey(variable *types.Var) string {
	if variable.Pkg() == nil {
		return variable.Name()
	}
	return variable.Pkg().Path() + "." + variable.Name()
}

// recordDynamicGlobalMutations walks one package's syntax for
// post-initialization mutation of package-level dynamic-capable
// variables anywhere in the program, judged fail-closed by carrier
// shape (REQ-closure-shared-dynamic-state). By-value carriers mutate
// exactly by a write (assignment, inc/dec, range target, send), an
// address capture, or a pointer-receiver method use — at bind or call
// position alike. Alias-handing carriers (interface values, channels,
// pointers/maps/slices reaching a dynamic carrier, unsafe pointers)
// hand shared mutable access to every reader, so any use at all marks
// them. init functions are exempt — startup flow is deterministic,
// source-determined state — but function bodies nested in package-level
// declarations are program code and are walked.
func recordDynamicGlobalMutations(p *packages.Package, mutated map[string]bool) {
	if p == nil || p.TypesInfo == nil {
		return
	}
	dynamicPackageVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		if !typeMayCarryUnknownDynamic(variable.Type(), make(map[types.Type]bool)) {
			return nil, false
		}
		return variable, true
	}
	resolve := func(ident *ast.Ident) (types.Object, bool) {
		if obj, ok := p.TypesInfo.Uses[ident]; ok {
			return obj, true
		}
		if obj, ok := p.TypesInfo.Defs[ident]; ok && obj != nil {
			return obj, true
		}
		return nil, false
	}
	// markTargets marks every dynamic-capable package variable an
	// expression subtree reaches — deliberately over-approximate: a
	// spurious mark only keeps a variable's current conservative
	// disposition.
	markTargets := func(expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if obj, ok := resolve(ident); ok {
				if variable, ok := dynamicPackageVar(obj); ok {
					mutated[dynamicVarKey(variable)] = true
				}
			}
			return true
		})
	}
	walkBody := func(body ast.Node) {
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					markTargets(lhs)
				}
			case *ast.IncDecStmt:
				markTargets(n.X)
			case *ast.RangeStmt:
				if n.Key != nil {
					markTargets(n.Key)
				}
				if n.Value != nil {
					markTargets(n.Value)
				}
			case *ast.SendStmt:
				markTargets(n.Chan)
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					markTargets(n.X)
				}
			case *ast.SelectorExpr:
				// A pointer-receiver method USE — bind or call alike —
				// is an implicit address capture of its receiver chain.
				if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
					if fn, ok := selection.Obj().(*types.Func); ok {
						if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
							if _, pointer := types.Unalias(sig.Recv().Type()).(*types.Pointer); pointer {
								markTargets(n.X)
							}
						}
					}
				}
			case *ast.Ident:
				// Alias-handing carriers: any use hands shared mutable
				// access, so any use is mutation-equivalent.
				if obj, ok := resolve(n); ok {
					if variable, ok := dynamicPackageVar(obj); ok && typeHandsOutDynamicAlias(variable.Type(), make(map[types.Type]bool)) {
						mutated[dynamicVarKey(variable)] = true
					}
				}
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Recv == nil && decl.Name != nil && decl.Name.Name == "init" {
					continue
				}
				if decl.Body != nil {
					walkBody(decl.Body)
				}
			default:
				// The declaration itself is initialization, but a
				// function literal nested in it is callable program
				// code — a package-level `var rebind = func() {...}`
				// mutator must be walked.
				ast.Inspect(decl, func(n ast.Node) bool {
					if lit, ok := n.(*ast.FuncLit); ok && lit.Body != nil {
						walkBody(lit.Body)
						return false
					}
					return true
				})
			}
		}
	}
}

// typeHandsOutDynamicAlias reports whether reading the type hands out
// shared mutable access to dynamic state: an interface value (its
// concrete object is shared), a channel, a pointer, map, or slice
// reaching a dynamic carrier, or an unsafe pointer. Function values
// and by-value composites of them are copies — reading them cannot
// reach the shared cell (REQ-closure-shared-dynamic-state).
func typeHandsOutDynamicAlias(t types.Type, seen map[types.Type]bool) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true
	switch t := types.Unalias(t).(type) {
	case *types.Basic:
		return t.Kind() == types.UnsafePointer
	case *types.Interface:
		return true
	case *types.Chan:
		return typeMayCarryUnknownDynamic(t.Elem(), make(map[types.Type]bool))
	case *types.Pointer:
		return typeMayCarryUnknownDynamic(t.Elem(), make(map[types.Type]bool))
	case *types.Map:
		return typeMayCarryUnknownDynamic(t.Key(), make(map[types.Type]bool)) || typeMayCarryUnknownDynamic(t.Elem(), make(map[types.Type]bool))
	case *types.Slice:
		return typeMayCarryUnknownDynamic(t.Elem(), make(map[types.Type]bool))
	case *types.Named:
		return typeHandsOutDynamicAlias(t.Underlying(), seen)
	case *types.TypeParam:
		return typeHandsOutDynamicAlias(t.Constraint(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if typeHandsOutDynamicAlias(t.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Array:
		return typeHandsOutDynamicAlias(t.Elem(), seen)
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if typeHandsOutDynamicAlias(t.At(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}
