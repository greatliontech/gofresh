// Package program loads one package test binary's whole-program SSA and
// indexes its subject roots by name (REQ-closure-analysis).
package program

import (
	"context"
	"fmt"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Program is one package test binary's whole-program SSA with its
// name-indexed subject roots (REQ-closure-analysis). The caller owns any
// memoization; loading is the analyses' dominant cost.
type Program struct {
	PkgPath string
	Prog    *ssa.Program
	Pkgs    []*packages.Package
	Roots   map[string]*ssa.Function // benchmark function name → its SSA function
	// ambiguous names two distinct top-level functions (the in-package
	// and external test packages may legally share a name): the root is
	// tombstoned and a subject requesting the name degrades to
	// unavailable evidence for that subject alone.
	Ambiguous map[string]bool
	TestMain  *ssa.Function
}

func loadConfigEnv(ctx context.Context, dir string, env []string, buildFlags ...string) *packages.Config {
	return &packages.Config{
		Context:    ctx,
		Mode:       packages.LoadAllSyntax | packages.NeedForTest,
		Tests:      true,
		Dir:        dir,
		Env:        append([]string(nil), env...),
		BuildFlags: append([]string(nil), buildFlags...),
	}
}

// Load builds pkgPath's test-binary Program.
func Load(ctx context.Context, dir string, env, buildFlags []string, pkgPath string) (*Program, error) {
	roots, err := packages.Load(loadConfigEnv(ctx, dir, env, buildFlags...), pkgPath)
	if err != nil {
		return nil, fmt.Errorf("closure: load %s: %w", pkgPath, err)
	}
	return build(ctx, pkgPath, roots)
}

// build builds whole-program SSA for one package's test binary from its
// root packages (generics instantiated, so RTA traverses real edges through std
// and dispatches generic instantiations concretely). A load error is fatal — a
// partial program could miss reachable code and report a stale result valid
// (REQ-fresh-sound).
func build(ctx context.Context, pkgPath string, roots []*packages.Package) (*Program, error) {
	var errs []string
	var all []*packages.Package
	seen := map[*packages.Package]bool{}
	packages.Visit(roots, nil, func(p *packages.Package) {
		if seen[p] {
			return
		}
		seen[p] = true
		all = append(all, p)
		for _, e := range p.Errors {
			errs = append(errs, e.Error())
		}
	})
	if len(errs) > 0 {
		return nil, fmt.Errorf("closure: load %s: %s", pkgPath, strings.Join(errs, "; "))
	}

	prog, _ := ssautil.AllPackages(roots, ssa.InstantiateGenerics)
	ssaPackages := prog.AllPackages()
	sort.Slice(ssaPackages, func(i, j int) bool {
		return ssaPackages[i].Pkg.Path() < ssaPackages[j].Pkg.Path()
	})
	for _, ssaPackage := range ssaPackages {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("closure: analysis cancelled during SSA construction: %w", err)
		}
		ssaPackage.Build()
	}

	// Index every top-level function as a candidate root, keyed by name, so any
	// subject — a benchmark, a test, or a production function — is rootable by name
	// (§ closure REQ-closure-analysis). Collect from the package's own test-variant
	// packages: each compiles the package WITH its test files, so it holds both the
	// production symbols and the test/benchmark symbols. Fall back to the plain
	// package only when no test variant exists — collecting a production symbol from
	// both the plain package and its test variant would key one name to two distinct
	// ssa.Functions and read as an ambiguous root. ForTest alone does not identify
	// the package's own variants: the go tool sets it on every package recompiled
	// into the test binary, including intermediate dependencies (r imports a, a's
	// external test imports r → "r [a.test]" carries ForTest=a), and `all` here
	// spans the full dependency graph. Only the in-package variant (PkgPath ==
	// pkgPath) and the external test package (PkgPath is the tested path + "_test",
	// the go tool's naming for it) declare this package's subjects; admitting a
	// recompiled dependency would root a dependency's function under a name the
	// package never declares — a shared top-level name reads as an ambiguous root,
	// and an unshared one silently resolves a subject to the dependency's closure.
	funcRoots := map[string]*ssa.Function{}
	ambiguousRoots := map[string]bool{}
	var testMain *ssa.Function
	var rootPkgs []*packages.Package
	for _, p := range all {
		if p.ForTest == pkgPath && (p.PkgPath == pkgPath || p.PkgPath == pkgPath+"_test") {
			rootPkgs = append(rootPkgs, p)
		}
	}
	if len(rootPkgs) == 0 {
		for _, p := range all {
			if p.PkgPath == pkgPath {
				rootPkgs = append(rootPkgs, p)
			}
		}
	}
	addRoot := func(key string, f *ssa.Function) {
		if ambiguousRoots[key] {
			return
		}
		if prev := funcRoots[key]; prev != nil && prev != f {
			// Two distinct functions under one root name — legal Go: the
			// in-package and external test packages may share a top-level
			// name. The collision is subject-local: tombstone the name so
			// a subject requesting it degrades to unavailable evidence
			// with the naming diagnosis, while every other subject of the
			// package analyzes normally (REQ-closure-batch-equivalence's
			// per-subject norm; a package-wide refusal would make the
			// package unmeasurable over a name no caller may request).
			delete(funcRoots, key)
			ambiguousRoots[key] = true
			return
		}
		funcRoots[key] = f
	}
	for _, p := range rootPkgs {
		if p.Types == nil {
			continue
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			switch obj := scope.Lookup(name).(type) {
			case *types.Func:
				f := prog.FuncValue(obj)
				if f == nil {
					continue
				}
				if name == "TestMain" && isTestMainHarness(p, obj) {
					// Two distinct TestMain harnesses cannot coexist in a
					// compiling test binary, so this arm is unreachable
					// past a successful load; the whole-program refusal is
					// the belt — a nil test main would silently under-root
					// every test subject (REQ-fresh-sound).
					if testMain != nil && testMain != f {
						return nil, fmt.Errorf("closure: conflicting TestMain harnesses in %s", pkgPath)
					}
					testMain = f
				}
				addRoot(name, f)
			case *types.TypeName:
				// Index this type's methods as subjects keyed "Type.Method", matching
				// the consumer symbol grammar (stipulator's Go backend): the receiver
				// generics and pointer star are dropped from the type name, and the
				// pointer method set — value and pointer receivers, plus promoted
				// methods — is preferred, falling back to the value set for interfaces.
				// A value-receiver method appears in both sets with the same
				// ssa.Function, which addRoot treats as one root, not a collision.
				methodSets := []*types.MethodSet{types.NewMethodSet(types.NewPointer(obj.Type()))}
				if methodSets[0].Len() == 0 {
					methodSets[0] = types.NewMethodSet(obj.Type())
				}
				for _, ms := range methodSets {
					for i := 0; i < ms.Len(); i++ {
						selection := ms.At(i)
						m, ok := selection.Obj().(*types.Func)
						if !ok {
							continue
						}
						f := prog.FuncValue(m)
						if len(selection.Index()) > 1 {
							f = prog.MethodValue(selection)
						}
						if f == nil {
							continue
						}
						addRoot(name+"."+m.Name(), f)
					}
				}
			}
		}
	}
	return &Program{PkgPath: pkgPath, Prog: prog, Pkgs: all, Roots: funcRoots, Ambiguous: ambiguousRoots, TestMain: testMain}, nil
}

func isTestMainHarness(pkg *packages.Package, function *types.Func) bool {
	if pkg == nil || pkg.Fset == nil || function == nil {
		return false
	}
	signature, ok := function.Type().(*types.Signature)
	if !ok || signature.Recv() != nil || signature.Params().Len() != 1 || signature.Results().Len() != 0 || signature.Variadic() {
		return false
	}
	if filename := pkg.Fset.PositionFor(function.Pos(), false).Filename; !strings.HasSuffix(filename, "_test.go") {
		return false
	}
	pointer, ok := types.Unalias(signature.Params().At(0).Type()).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(pointer.Elem()).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "testing" && named.Obj().Name() == "M"
}
