// Package observability computes Tier-2 whole-program SSA reachability,
// observability proofs, and post-initialization rooted-flow inventories
// (REQ-closure-observability-analysis, REQ-closure-shared-dynamic-state-reachability).
package observability

import (
	"context"
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/internal/asmverify"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/trace"
)

type programSummaries struct {
	verifiedAsm             map[string]*asmverify.VerifiedPackage
	asmExternalGlobals      map[asmverify.ExternalSBRef]asmExternalGlobalVerdict
	instancesByOrigin       map[*ssa.Function][]*ssa.Function
	baseStartupReach        [4]*baseStartupReachSummary
	verifiedHarnesses       *verifiedHarnessesSummary
	initSettledGlobals      *initSettledGlobalsSummary
	callerRefs              map[string]*callerReferenceSummary
	nonReadOnlyGlobals      map[*ssa.Global]bool
	verifiedSentinelGlobals map[*ssa.Global]bool
	nonSSAGlobalHazards     [2]*nonSSAGlobalHazardSummary
}

// Program is one package test binary's whole-program SSA with its
// name-indexed subject roots (REQ-closure-analysis). The caller owns any
// memoization; loading is the analyses' dominant cost.
type Program struct {
	PkgPath string
	Prog    *ssa.Program
	Pkgs    []*packages.Package
	Roots   map[string]*ssa.Function // benchmark/test/function name → its SSA function
	// Ambiguous names two distinct top-level functions (the in-package
	// and external test packages may legally share a name): the root is
	// tombstoned and a subject requesting the name degrades to
	// unavailable evidence for that subject alone.
	Ambiguous map[string]bool
	TestMain  *ssa.Function
	// PkgScopeProbe memoizes the package-scope discriminator's verdict
	// per harness inclusion: the shared roots are batch-invariant, so
	// one probe per program (and per harness arm) serves every failing
	// batch.
	PkgScopeProbe    map[bool]error
	AllFunctions     map[*ssa.Function]bool
	OrderedFunctions []*ssa.Function
	MutatedGlobals   map[*ssa.Global]bool
	// GOARCH names the effective target architecture under which this program
	// was selected and analyzed; empty fails closed on ISA-dependent checks.
	GOARCH string
	// Source binds this program's non-Go source reads (.s and .h assembly files)
	// to the owning pass's closure Hasher content snapshot.
	Source *closure.Hasher
	// SourceSnapshot overrides non-Go source bytes by file path for hermetic
	// unit tests without mutating disk files.
	SourceSnapshot map[string][]byte
	summaries      programSummaries
}

func (p *Program) resetSummaries() {
	if p != nil {
		p.summaries = programSummaries{}
	}
}

func (p *Program) readSourceFileWithHasher(h *closure.Hasher, dir, fullPath string) ([]byte, error) {
	if p != nil && p.SourceSnapshot != nil {
		if b, ok := p.SourceSnapshot[fullPath]; ok {
			return b, nil
		}
		if b, ok := p.SourceSnapshot[filepath.Clean(fullPath)]; ok {
			return b, nil
		}
	}
	if p != nil && p.Source != nil {
		return p.Source.ReadSourceFile(dir, fullPath)
	}
	if h != nil {
		return h.ReadSourceFile(dir, fullPath)
	}
	return os.ReadFile(fullPath)
}

func (p *Program) readSourceFile(dir, fullPath string) ([]byte, error) {
	return p.readSourceFileWithHasher(nil, dir, fullPath)
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
		if base.Dir == "" && len(base.Errors) == 0 {
			p.errs[path] = fmt.Errorf("closure: prepare %s: ordinary root directory absent", path)
			continue
		}
		ownVariants := map[string]*packages.Package{}
		for _, root := range roots {
			meta := gotool.ListedPackage{ImportPath: root.ID, Name: root.Name, Dir: root.Dir, ForTest: root.ForTest}
			if meta.OwnVariantOf(path, base.Dir) {
				ownVariants[root.ID] = root
			}
		}
		if len(ownVariants) > 0 && requested[path+".test"] {
			err := fmt.Errorf("closure: prepare %s: generated main identity collides with requested package %s.test", path, path)
			p.errs[path], p.errs[path+".test"] = err, err
			delete(p.roots, path+".test")
			continue
		}
		var selected []*packages.Package
		var main bool
		for _, root := range roots {
			meta := gotool.ListedPackage{ImportPath: root.ID, Name: root.Name, Dir: root.Dir, ForTest: root.ForTest}
			generated := false
			if meta.IsGeneratedTestMainFor(path) {
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
// initial roots and their dependency closure.
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

// HasRoots reports whether Prepare selected an initial-root partition for pkgPath.
func (p *Prepared) HasRoots(pkgPath string) bool {
	if p == nil {
		return false
	}
	_, ok := p.roots[pkgPath]
	return ok
}

// Release drops pkgPath's retained root slice once its SSA program has been built.
func (p *Prepared) Release(pkgPath string) {
	if p != nil {
		delete(p.roots, pkgPath)
	}
}

func load(ctx context.Context, dir string, env, flags, paths []string) ([]*packages.Package, error) {
	return gotool.LoadPackages(
		ctx,
		packages.LoadAllSyntax|packages.NeedForTest|packages.NeedModule|packages.NeedEmbedFiles|packages.NeedEmbedPatterns,
		dir,
		env,
		flags,
		paths...,
	)
}

// FromPackages builds whole-program SSA for one package's test binary directly
// from pre-constructed or pre-loaded root packages.
func FromPackages(ctx context.Context, pkgPath string, roots []*packages.Package) (*Program, error) {
	return build(ctx, pkgPath, roots)
}

func build(ctx context.Context, pkgPath string, roots []*packages.Package) (*Program, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tracing := trace.Enabled(ctx, trace.DomainClosure, pkgPath)
	var start time.Time
	if tracing {
		start = time.Now()
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
		if li, lj := len(ssaPackages[i].Members), len(ssaPackages[j].Members); li != lj {
			return li > lj
		}
		return ssaPackages[i].Pkg.Path() < ssaPackages[j].Pkg.Path()
	})
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled during SSA construction: %w", err)
	}
	workers := min(len(ssaPackages), max(1, runtime.GOMAXPROCS(0)))
	if workers <= 1 {
		for _, ssaPackage := range ssaPackages {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("closure: analysis cancelled during SSA construction: %w", err)
			}
			ssaPackage.Build()
		}
	} else {
		var next atomic.Int32
		var cancelMu sync.Mutex
		var cancelErr error
		var wg sync.WaitGroup
		wg.Add(workers)
		for range workers {
			go func() {
				defer wg.Done()
				for {
					if err := ctx.Err(); err != nil {
						cancelMu.Lock()
						if cancelErr == nil {
							cancelErr = err
						}
						cancelMu.Unlock()
						return
					}
					idx := int(next.Add(1) - 1)
					if idx >= len(ssaPackages) {
						return
					}
					ssaPackages[idx].Build()
				}
			}()
		}
		wg.Wait()
		if cancelErr != nil {
			return nil, fmt.Errorf("closure: analysis cancelled during SSA construction: %w", cancelErr)
		}
	}

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
					if testMain != nil && testMain != f {
						return nil, fmt.Errorf("closure: conflicting TestMain harnesses in %s", pkgPath)
					}
					testMain = f
				}
				addRoot(name, f)
			case *types.TypeName:
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
	if tracing {
		trace.Emit(ctx, trace.DomainClosure, "program.build.done", pkgPath,
			trace.Int("packages", len(all)),
			trace.Int("ssa_packages", len(ssaPackages)),
			trace.Int("roots", len(funcRoots)),
			trace.Int64("elapsed_ns", time.Since(start).Nanoseconds()),
		)
	}
	return &Program{PkgPath: pkgPath, Prog: prog, Pkgs: all, Roots: funcRoots, Ambiguous: ambiguousRoots, TestMain: testMain}, nil
}

func isTestMainHarness(pkg *packages.Package, function *types.Func) bool {
	if pkg == nil || pkg.Fset == nil || function == nil {
		return false
	}
	signature, ok := function.Type().(*types.Signature)
	if !ok || signature.Recv() != nil || signature.TypeParams().Len() != 0 || signature.Params().Len() != 1 || signature.Results().Len() != 0 || signature.Variadic() {
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
