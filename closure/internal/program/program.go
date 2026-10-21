// Package program loads one package test binary's whole-program SSA and
// indexes its subject roots by name (REQ-closure-analysis).
package program

import (
	"context"
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/closure/internal/compartment"
	"github.com/greatliontech/gofresh/closure/internal/listing"
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
	// PkgScopeProbe memoizes the package-scope discriminator's verdict
	// per harness inclusion: the shared roots are batch-invariant, so
	// one probe per program (and per harness arm) serves every failing
	// batch.
	PkgScopeProbe map[bool]error
}

func loadConfigEnv(ctx context.Context, dir string, env []string, buildFlags ...string) *packages.Config {
	return &packages.Config{
		Context:    ctx,
		Mode:       packages.LoadAllSyntax | packages.NeedForTest | packages.NeedModule,
		Tests:      true,
		Dir:        dir,
		Env:        append([]string(nil), env...),
		BuildFlags: append([]string(nil), buildFlags...),
	}
}

// Load builds pkgPath's test-binary Program.
func Load(ctx context.Context, dir string, env, buildFlags []string, pkgPath string) (*Program, error) {
	roots, err := load(ctx, dir, env, buildFlags, []string{pkgPath})
	if err != nil {
		return nil, fmt.Errorf("closure: load %s: %w", pkgPath, err)
	}
	return build(ctx, pkgPath, roots)
}

// Prepared holds one source/type generation for an explicit roster of package
// import paths. Its private initial-root partitions retain the loader's exact
// dependency instances; no SSA or analysis results are shared between builds.
// The caller keeps source and effective build configuration quiescent from
// preparation through the last consumer, and treats all returned syntax/types
// as read-only. A new generation requires a new Prepare. Owners and consumers
// are sequential, including analysis that lazily constructs generic methods.
type Prepared struct {
	roots map[string][]*packages.Package
	errs  map[string]error
}

// Prepare loads the roster and its dependencies once, under the complete env
// and ordered buildFlags. Input containers are copied before invoking ctx.
// Package errors remain local to each Build's dependency closure. Load-wide
// operational errors (including caller cancellation) refuse preparation; an
// empty roster is invalid.
func Prepare(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*Prepared, error) {
	pkgPaths = append([]string(nil), pkgPaths...)
	if len(pkgPaths) == 0 {
		return nil, fmt.Errorf("closure: prepare requires an explicit package roster")
	}
	roots, err := load(ctx, dir, env, buildFlags, pkgPaths)
	if err != nil {
		return nil, fmt.Errorf("closure: prepare: %w", err)
	}
	p := &Prepared{roots: map[string][]*packages.Package{}, errs: map[string]error{}}
	requested := make(map[string]bool, len(pkgPaths))
	for _, path := range pkgPaths {
		requested[path] = true
	}
	for _, path := range pkgPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if p.errs[path] != nil {
			continue
		}
		var base *packages.Package
		for _, root := range roots {
			if root.ID == path && root.ForTest == "" {
				base = root
				break
			}
		}
		if base == nil {
			p.errs[path] = fmt.Errorf("closure: prepare %s: ordinary initial root absent", path)
			continue
		}
		// A test-only package's ordinary root can have no GoFiles. Dir is
		// loader metadata, never inferred from an optional source member.
		if base.Dir == "" && len(base.Errors) == 0 {
			p.errs[path] = fmt.Errorf("closure: prepare %s: ordinary root directory absent", path)
			continue
		}
		ownVariants := map[string]*packages.Package{}
		for _, root := range roots {
			meta := listing.Package{ImportPath: root.ID, Name: root.Name, Dir: root.Dir, ForTest: root.ForTest}
			if compartment.OwnVariantOf(meta, path, base.Dir) {
				ownVariants[root.ID] = root
			}
		}
		// An explicitly requested ordinary command can have the same ID as
		// this target's generated main. The loader may refuse that collision
		// globally; if it returned one graph, do not invent which request owns
		// the merged identity. Neither affected root can safely be built.
		if len(ownVariants) > 0 && requested[path+".test"] {
			err := fmt.Errorf("closure: prepare %s: generated main identity collides with requested package %s.test", path, path)
			p.errs[path], p.errs[path+".test"] = err, err
			delete(p.roots, path+".test")
			continue
		}
		var selected []*packages.Package
		var main bool
		for _, root := range roots {
			meta := listing.Package{ImportPath: root.ID, Name: root.Name, Dir: root.Dir, ForTest: root.ForTest}
			generated := false
			if meta.IsGeneratedTestMainFor(path) {
				// Name and ID only locate a candidate in a multi-root load.
				// Actual generated mains import a target-owned test variant;
				// an ordinary q.test command importing plain q does not.
				for _, imported := range root.Imports {
					if ownVariants[imported.ID] == imported {
						generated = true
						break
					}
				}
			}
			if root == base || ownVariants[root.ID] == root || generated {
				selected = append(selected, root)
			}
			main = main || generated
		}
		if len(ownVariants) > 0 && !main {
			p.errs[path] = fmt.Errorf("closure: prepare %s: generated test main absent", path)
			continue
		}
		p.roots[path] = selected
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p, nil
}

// Build constructs a fresh SSA program for a registered package, using only its
// initial roots and their dependency closure. It retains Prepare's generation;
// it does not re-observe files or configuration. Returned typed inputs remain
// borrowed read-only data; SSA and analysis state belong to this build alone.
func (p *Prepared) Build(ctx context.Context, pkgPath string) (*Program, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p != nil {
		if err := p.errs[pkgPath]; err != nil {
			return nil, err
		}
		if roots, ok := p.roots[pkgPath]; ok {
			return build(ctx, pkgPath, roots)
		}
	}
	return nil, fmt.Errorf("closure: package %s was not prepared", pkgPath)
}

func load(ctx context.Context, dir string, env, flags, paths []string) ([]*packages.Package, error) {
	cfg := loadConfigEnv(ctx, dir, env, flags...)
	paths = append([]string(nil), paths...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	roots, err := packages.Load(cfg, paths...)
	if cancelled := ctx.Err(); cancelled != nil {
		return nil, cancelled
	}
	return roots, err
}

// build builds whole-program SSA for one package's test binary from its
// root packages (generics instantiated, so RTA traverses real edges through std
// and dispatches generic instantiations concretely). A load error is fatal — a
// partial program could miss reachable code and report a stale result valid
// (REQ-fresh-sound).
func build(ctx context.Context, pkgPath string, roots []*packages.Package) (*Program, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	// Init functions are unaddressable by name - package scope omits them -
	// so they root positionally: init#<file>#<ordinal>, the declaration
	// ledger's init identity (file base name, 0-based ordinal within the
	// file in declaration order). The ordinal advances on every init
	// declaration whether or not the object resolves, so a resolution gap
	// never shifts a sibling's identity. Filenames are unique within the
	// package directory, so the key cannot collide across the in-package
	// and external test variants; addRoot's tombstone still guards.
	for _, p := range rootPkgs {
		if p.Types == nil || p.TypesInfo == nil || p.Fset == nil {
			continue
		}
		for _, f := range p.Syntax {
			ordinal := 0
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Recv != nil || fd.Name.Name != "init" {
					continue
				}
				key := fmt.Sprintf("init#%s#%d", filepath.Base(p.Fset.PositionFor(f.Pos(), false).Filename), ordinal)
				ordinal++
				obj, ok := p.TypesInfo.Defs[fd.Name].(*types.Func)
				if !ok {
					continue
				}
				fn := prog.FuncValue(obj)
				if fn == nil {
					continue
				}
				addRoot(key, fn)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
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
