package closure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/internal/buildflags"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type asmMacro struct {
	funcLike bool
	params   []string
	body     string
}

// program is the loaded whole-program SSA for one package's test binary, cached
// so per-benchmark Compute calls amortize the dominant load cost (REQ-closure-analysis).
type program struct {
	pkgPath  string
	prog     *ssa.Program
	pkgs     []*packages.Package
	roots    map[string]*ssa.Function // benchmark function name → its SSA function
	testMain *ssa.Function
}

// loadCached loads (once) and returns the whole-program SSA for pkgPath.
func (h *Hasher) loadCached(pkgPath string) (*program, error) {
	if p, ok := h.progs[pkgPath]; ok {
		return p, nil
	}
	p, err := load(h.ctx, h.dir, h.buildFlags, pkgPath)
	if err != nil {
		return nil, err
	}
	h.progs[pkgPath] = p
	return p, nil
}

// loadConfig is the shared packages.Config for both the single-package load and
// the batched Prime: all-dependency syntax (stdlib bodies included, REQ-closure-analysis) with the
// ForTest linkage needed to distinguish a package's test-binary variants.
func loadConfig(ctx context.Context, dir string, buildFlags ...string) *packages.Config {
	return &packages.Config{
		Context:    ctx,
		Mode:       packages.LoadAllSyntax | packages.NeedForTest,
		Tests:      true,
		Dir:        dir,
		BuildFlags: append([]string(nil), buildFlags...),
	}
}

// load builds whole-program SSA for pkgPath's test binary from a single-package
// packages.Load. It is the fallback path (and the exact behavior Prime reproduces
// per package); Prime shares one Load across many packages but each still gets its
// own program from only its own roots. A load error is fatal — analyzing a partial
// program could miss reachable code and report a stale result valid (REQ-fresh-sound).
func load(ctx context.Context, dir string, buildFlags []string, pkgPath string) (*program, error) {
	roots, err := packages.Load(loadConfig(ctx, dir, buildFlags...), pkgPath)
	if err != nil {
		return nil, fmt.Errorf("closure: load %s: %w", pkgPath, err)
	}
	return buildProgram(ctx, pkgPath, roots)
}

// Prime warms the per-package SSA cache for pkgPaths with one shared
// packages.Load, so the stdlib and shared dependencies are parsed and
// type-checked once for the whole set rather than once per package (REQ-closure-analysis — the
// dominant residual cost of a a multi-package run). Each package still gets
// its own ssa.Program built from only its own test-binary roots (rootsForBinary),
// so the analysis — including the per-binary init-root set RTA depends on (see the
// roots loop in tier2) — is byte-identical to the single-package load; Prime
// shares only the parse/type-check front-end, never the SSA program.
//
// It is best-effort: a batch-load failure, or a package whose closure fails to
// build, leaves that package uncached, and its first Compute falls back to a
// single load — preserving both per-package error isolation and the exact
// single-load result. Already-cached packages are skipped. Equivalence to the
// per-package load is pinned by TestBatchLoadMatchesPerPackage.
func (h *Hasher) Prime(pkgPaths []string) {
	var need []string
	seen := map[string]bool{}
	for _, p := range pkgPaths {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if _, ok := h.progs[p]; !ok {
			need = append(need, p)
		}
	}
	if len(need) == 0 {
		return
	}
	roots, err := packages.Load(loadConfig(h.ctx, h.dir, h.buildFlags...), need...)
	if err != nil {
		return // fall back to lazy single loads; the error resurfaces there
	}
	for _, p := range need {
		prog, err := buildProgram(h.ctx, p, rootsForBinary(roots, p))
		if err != nil {
			continue // leave uncached; loadCached single-loads and surfaces the error
		}
		h.progs[p] = prog
	}
}

// rootsForBinary selects, from a batched packages.Load result, exactly the root
// packages a single packages.Load(pkgPath) with Tests returns: the package and its
// in-package/external test variants (ForTest==pkgPath) plus the generated
// test-main (PkgPath==pkgPath+".test"). Feeding exactly these to
// ssautil.AllPackages reproduces the per-package program's package set, so RTA's
// per-binary init roots (tier2) are unchanged. Selecting too few would shrink that
// set and under-cover the closure (REQ-fresh-sound) — this must match the single-load root
// set exactly, which TestBatchLoadMatchesPerPackage pins over real fixtures.
func rootsForBinary(all []*packages.Package, pkgPath string) []*packages.Package {
	var rs []*packages.Package
	for _, p := range all {
		if p.PkgPath == pkgPath || p.ForTest == pkgPath || p.PkgPath == pkgPath+".test" {
			rs = append(rs, p)
		}
	}
	return rs
}

// buildProgram builds whole-program SSA for one package's test binary from its
// root packages (generics instantiated, so RTA traverses real edges through std
// and dispatches generic instantiations concretely). A load error is fatal — a
// partial program could miss reachable code and report a stale result valid
// (REQ-fresh-sound).
func buildProgram(ctx context.Context, pkgPath string, roots []*packages.Package) (*program, error) {
	var errs []string
	var rootErrs []string
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
	// (§ closure REQ-closure-analysis). Collect from the test-variant packages
	// (ForTest == pkgPath): each compiles the package WITH its test files, so it
	// holds both the production symbols and the test/benchmark symbols. Fall back to
	// the plain package only when no test variant exists — collecting a production
	// symbol from both the plain package and its test variant would key one name to
	// two distinct ssa.Functions and read as an ambiguous root.
	funcRoots := map[string]*ssa.Function{}
	var testMain *ssa.Function
	var rootPkgs []*packages.Package
	for _, p := range all {
		if p.ForTest == pkgPath {
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
		if prev := funcRoots[key]; prev != nil && prev != f {
			rootErrs = append(rootErrs, key)
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
						rootErrs = append(rootErrs, name)
						continue
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
	if len(rootErrs) > 0 {
		return nil, fmt.Errorf("closure: ambiguous subject roots in %s: %s", pkgPath, strings.Join(rootErrs, ", "))
	}
	return &program{pkgPath: pkgPath, prog: prog, pkgs: all, roots: funcRoots, testMain: testMain}, nil
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

// subjectRunsThroughHarness reports whether fn executes through the Go test harness
// — after TestMain setup — which is true exactly when fn is declared in a _test.go
// file. A production function (any non-test file) never runs through TestMain, so
// the test main is not part of its closure (REQ-closure-analysis); a test subject
// runs after TestMain setup, so it is. On an unknown source position the safe
// over-approximation is to include the test main.
func subjectRunsThroughHarness(prog *program, fn *ssa.Function) bool {
	if fn == nil || fn.Pos() == token.NoPos {
		return true
	}
	return strings.HasSuffix(prog.prog.Fset.Position(fn.Pos()).Filename, "_test.go")
}

// Subject identifies a function or method whose source closure is requested.
type Subject struct {
	Package string
	Symbol  string
}

const maxAttributedSubjects = 64

// Compute returns the source closure for one subject of pkgPath. It is the
// one-subject form of ComputeBatch.
func (h *Hasher) Compute(pkgPath, symbol string) (Closure, error) {
	subject := Subject{Package: pkgPath, Symbol: symbol}
	closures, err := h.ComputeBatch([]Subject{subject})
	if err != nil {
		return Closure{}, err
	}
	return closures[subject], nil
}

// ComputeBatch returns each distinct subject's source closure. Reachability is
// shared in package-local batches while retaining independent subject results.
// Empty input returns an empty map.
func (h *Hasher) ComputeBatch(subjects []Subject) (map[Subject]Closure, error) {
	results := make(map[Subject]Closure)
	if len(subjects) == 0 {
		return results, nil
	}
	if err := h.ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}

	type packageBatch struct {
		path     string
		subjects []Subject
	}
	var groups []*packageBatch
	byPackage := make(map[string]*packageBatch)
	seen := make(map[Subject]bool)
	for _, subject := range subjects {
		if seen[subject] {
			continue
		}
		seen[subject] = true
		group := byPackage[subject.Package]
		if group == nil {
			group = &packageBatch{path: subject.Package}
			byPackage[subject.Package] = group
			groups = append(groups, group)
		}
		group.subjects = append(group.subjects, subject)
	}

	for _, group := range groups {
		if err := h.ctx.Err(); err != nil {
			return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		// A batch view retains only final closures. Explicitly primed programs
		// remain caller-owned; otherwise load one package program at a time and
		// release it after this group so peak SSA memory is bounded by the largest
		// package test binary rather than the total subject set.
		prog := h.progs[group.path]
		if prog == nil {
			var err error
			prog, err = load(h.ctx, h.dir, h.buildFlags, group.path)
			if err != nil {
				return nil, err
			}
		}
		// Resolve every root before listing or analyzing, preserving the clear
		// one-subject error for a symbol that does not exist.
		for _, subject := range group.subjects {
			if prog.roots[subject.Symbol] == nil {
				return nil, fmt.Errorf("closure: subject %s not found in %s", subject.Symbol, group.path)
			}
		}
		_, retainList := h.lists[group.path]
		metas, err := h.list(group.path)
		if err != nil {
			return nil, err
		}
		base := newTier2Base(h, prog, metas)
		for start := 0; start < len(group.subjects); start += maxAttributedSubjects {
			if err := h.ctx.Err(); err != nil {
				return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
			}
			end := min(start+maxAttributedSubjects, len(group.subjects))
			batch := group.subjects[start:end]
			reachable, err := attributedReachableSets(h.ctx, prog, batch)
			if err != nil {
				return nil, err
			}
			for i, subject := range batch {
				if err := h.ctx.Err(); err != nil {
					return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
				}
				tr, err := h.tier2Reachable(base, reachable[i])
				if err != nil {
					return nil, err
				}
				closure, err := h.closureFromTier2(group.path, tr)
				if err != nil {
					return nil, err
				}
				results[subject] = closure
			}
		}
		if !retainList {
			delete(h.lists, group.path)
		}
	}
	if err := h.ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	return results, nil
}

func (h *Hasher) closureFromTier2(pkgPath string, tr tier2Result) (Closure, error) {
	var hash string
	var err error
	if tr.widen {
		hash, err = h.maximalHash(pkgPath)
	} else {
		hash, err = hashContributions(pkgPath, tr.contribs)
	}
	if err != nil {
		return Closure{}, err
	}
	return Closure{Hash: hash, Unverifiable: tr.unverifiable, Reason: tr.reason, Widened: tr.widen}, nil
}

type tier2Result struct {
	contribs     []string
	widen        bool
	widenReason  string
	unverifiable bool
	reason       string
}

func (h *Hasher) tier2Contributions(pkgPath, bench string) ([]string, bool, error) {
	tr, err := h.tier2(pkgPath, bench)
	if err != nil {
		return nil, false, err
	}
	return tr.contribs, tr.widen, nil
}

func (h *Hasher) tier2(pkgPath, bench string) (tier2Result, error) {
	prog, err := h.loadCached(pkgPath)
	if err != nil {
		return tier2Result{}, err
	}
	root := prog.roots[bench]
	if root == nil {
		return tier2Result{}, fmt.Errorf("closure: subject %s not found in %s", bench, pkgPath)
	}
	metas, err := h.list(pkgPath)
	if err != nil {
		return tier2Result{}, err
	}
	reachable, err := attributedReachableSets(h.ctx, prog, []Subject{{Package: pkgPath, Symbol: bench}})
	if err != nil {
		return tier2Result{}, err
	}
	return h.tier2Reachable(newTier2Base(h, prog, metas), reachable[0])
}

type attributedReachability struct {
	functions      map[*ssa.Function]bool
	resolved       map[ssa.CallInstruction]bool
	dynamicTargets map[ssa.CallInstruction]map[*ssa.Function]bool
	openWorld      bool
}

// attributedReachableSets runs package-local RTA once and projects its masks
// back into the reachable set expected by the existing per-subject analyzer.
func attributedReachableSets(ctx context.Context, prog *program, subjects []Subject) ([]attributedReachability, error) {
	roots := make(map[*ssa.Function]uint64)
	allMasks := ^uint64(0)
	if len(subjects) < 64 {
		allMasks = 1<<len(subjects) - 1
	}
	var testMasks uint64
	for i, subject := range subjects {
		mask := uint64(1) << i
		root := prog.roots[subject.Symbol]
		roots[root] |= mask
		if subjectRunsThroughHarness(prog, root) {
			testMasks |= mask
		}
	}
	if prog.testMain != nil {
		roots[prog.testMain] |= testMasks
	}
	for _, p := range prog.prog.AllPackages() {
		if isGeneratedTestMainPackage(prog, p) {
			continue
		}
		if init := p.Func("init"); init != nil {
			roots[init] |= allMasks
		}
	}
	res, err := analyzeAttributed(ctx, roots)
	if err != nil {
		return nil, err
	}
	reachable := make([]attributedReachability, len(subjects))
	for i := range reachable {
		reachable[i] = attributedReachability{
			functions:      make(map[*ssa.Function]bool),
			resolved:       make(map[ssa.CallInstruction]bool),
			dynamicTargets: make(map[ssa.CallInstruction]map[*ssa.Function]bool),
			openWorld:      rootMayReceiveUnknownDynamic(prog, prog.roots[subjects[i].Symbol]),
		}
		mask := uint64(1) << i
		for fn, masks := range res.Reachable {
			if masks&mask != 0 {
				reachable[i].functions[fn] = true
			}
		}
		for site, masks := range res.Resolved {
			if masks&mask != 0 {
				reachable[i].resolved[site] = true
			}
		}
		for site, targets := range res.Targets {
			for target, masks := range targets {
				if masks&mask != 0 {
					projected := reachable[i].dynamicTargets[site]
					if projected == nil {
						projected = make(map[*ssa.Function]bool)
						reachable[i].dynamicTargets[site] = projected
					}
					projected[target] = true
				}
			}
		}
	}
	return reachable, nil
}

func rootMayReceiveUnknownDynamic(prog *program, root *ssa.Function) bool {
	if root == nil || root.Signature == nil {
		return true
	}
	if subjectRunsThroughHarness(prog, root) && isHarnessSubjectSignature(root.Signature) {
		return false
	}
	seen := make(map[types.Type]bool)
	if recv := root.Signature.Recv(); recv != nil && typeMayCarryDynamic(recv.Type(), seen) {
		return true
	}
	params := root.Signature.Params()
	for i := 0; params != nil && i < params.Len(); i++ {
		if typeMayCarryDynamic(params.At(i).Type(), seen) {
			return true
		}
	}
	return false
}

func isHarnessSubjectSignature(sig *types.Signature) bool {
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

func typeMayCarryDynamic(t types.Type, seen map[types.Type]bool) bool {
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
		return typeMayCarryDynamic(t.Constraint(), seen)
	case *types.Named:
		return typeMayCarryDynamic(t.Underlying(), seen)
	case *types.Pointer:
		return typeMayCarryDynamic(t.Elem(), seen)
	case *types.Slice:
		return typeMayCarryDynamic(t.Elem(), seen)
	case *types.Array:
		return typeMayCarryDynamic(t.Elem(), seen)
	case *types.Map:
		return typeMayCarryDynamic(t.Key(), seen) || typeMayCarryDynamic(t.Elem(), seen)
	case *types.Chan:
		return typeMayCarryDynamic(t.Elem(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if typeMayCarryDynamic(t.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if typeMayCarryDynamic(t.At(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func isGeneratedTestMainPackage(prog *program, pkg *ssa.Package) bool {
	return prog != nil && pkg != nil && pkg.Pkg != nil && pkg.Pkg.Name() == "main" && pkg.Pkg.Path() == prog.pkgPath+".test"
}

// tier2Reachable performs declaration, source, widening, and unverifiability
// analysis over a supplied per-subject RTA set. Its behavior is otherwise the
// same as the former one-subject tier2 path.
func (h *Hasher) tier2Reachable(base *tier2Base, reachable attributedReachability) (tier2Result, error) {
	a := base.analyzer()
	a.rtaResolved = reachable.resolved
	a.openWorld = reachable.openWorld
	if err := a.addLinkedCacheModules(); err != nil {
		return tier2Result{}, err
	}
	for site, targets := range reachable.dynamicTargets {
		callerIdx := a.idxForFunction(site.Parent())
		if callerIdx == nil || callerIdx.std || callerIdx.testMain {
			continue
		}
		for target := range targets {
			idx := a.idxForFunction(target)
			if idx == nil || !idx.std {
				continue
			}
			reason := classBReasonForFunction(target)
			if reason == "" && !isSourceOnlyStandardPackage(idx.path) {
				reason = "reaches unaudited standard operation " + idx.path + "." + target.Name()
			}
			if reason != "" {
				a.markUnverifiable(reason)
			}
		}
	}
	for fn := range reachable.functions {
		if err := a.contextErr(); err != nil {
			return tier2Result{}, err
		}
		a.rtaReach[fn] = true
	}
	for fn := range reachable.functions {
		if err := a.contextErr(); err != nil {
			return tier2Result{}, err
		}
		a.addFunction(fn)
		if idx := a.idxForFunction(fn); idx != nil && idx.std {
			continue
		}
		a.scanFunction(fn)
		if err := a.contextErr(); err != nil {
			return tier2Result{}, err
		}
	}
	if err := a.drainObjects(); err != nil {
		return tier2Result{}, err
	}
	for {
		if err := a.contextErr(); err != nil {
			return tier2Result{}, err
		}
		pkgCount := len(a.filePkgs)
		if err := a.addReachedPackageFiles(); err != nil {
			return tier2Result{}, err
		}
		if err := a.drainObjects(); err != nil {
			return tier2Result{}, err
		}
		if len(a.filePkgs) == pkgCount {
			break
		}
	}
	return a.result(), nil
}

type pkgIndex struct {
	pkg            *packages.Package
	ssa            *ssa.Package
	meta           *listPkg
	id             string
	path           string
	dir            string
	std            bool
	testMain       bool
	cache          bool
	mutable        bool
	decls          map[types.Object]ast.Node
	vars           []ast.Node
	inits          []ast.Node
	imports        []ast.Node
	wasmImport     bool
	linknames      map[types.Object]string
	linknameByName map[string]string
	linknameDocs   map[types.Object]ast.Node
}

// tier2Base is the immutable package/source index shared by every subject in
// one package analysis view. The AST, type, linkname, and package lookup maps
// are expensive to build but independent of a subject's reachable set.
type tier2Base struct {
	h                *Hasher
	buildFlags       []string
	prog             *program
	metas            []listPkg
	metaByPath       map[string]*listPkg
	idxByTypes       map[*types.Package]*pkgIndex
	idxByPath        map[string]*pkgIndex
	objByName        map[string]types.Object
	objsByLinkTarget map[string][]types.Object
}

type tier2Analyzer struct {
	h                *Hasher
	buildFlags       []string
	prog             *program
	metas            []listPkg
	metaByPath       map[string]*listPkg
	idxByTypes       map[*types.Package]*pkgIndex
	idxByPath        map[string]*pkgIndex
	objByName        map[string]types.Object
	objsByLinkTarget map[string][]types.Object

	seenObjects map[types.Object]bool
	objectQueue []types.Object
	seenTypes   map[string]bool
	seenDecls   map[string]bool
	seenPkgs    map[*pkgIndex]bool
	filePkgs    map[*pkgIndex]bool
	rtaReach    map[*ssa.Function]bool
	rtaResolved map[ssa.CallInstruction]bool
	openWorld   bool
	scanned     map[*ssa.Function]bool
	seenContrib map[string]bool
	contribs    []string

	widen        bool
	widenReason  string
	unverifiable bool
	reason       string
}

func newTier2Base(h *Hasher, prog *program, metas []listPkg) *tier2Base {
	a := &tier2Analyzer{
		h:                h,
		buildFlags:       append([]string(nil), h.buildFlags...),
		prog:             prog,
		metas:            metas,
		metaByPath:       map[string]*listPkg{},
		idxByTypes:       map[*types.Package]*pkgIndex{},
		idxByPath:        map[string]*pkgIndex{},
		objByName:        map[string]types.Object{},
		objsByLinkTarget: map[string][]types.Object{},
	}
	for i := range metas {
		m := &metas[i]
		a.metaByPath[m.ImportPath] = m
	}
	for _, p := range prog.pkgs {
		idx := a.buildIndex(p)
		if idx == nil {
			continue
		}
		if p.Types != nil {
			a.idxByTypes[p.Types] = idx
		}
		a.idxByPath[idx.id] = idx
		if idx.path != "" {
			a.idxByPath[idx.path] = idx
		}
		for obj := range idx.decls {
			if obj == nil || obj.Pkg() == nil || obj.Name() == "" {
				continue
			}
			a.objByName[obj.Pkg().Path()+"."+obj.Name()] = obj
		}
		for obj, target := range idx.linknames {
			a.addReverseLinkname(target, obj)
		}
		if idx.pkg != nil && idx.pkg.Types != nil {
			for name, target := range idx.linknameByName {
				if obj := idx.pkg.Types.Scope().Lookup(name); obj != nil {
					a.addReverseLinkname(target, obj)
				}
			}
		}
	}
	return &tier2Base{
		h:                h,
		buildFlags:       a.buildFlags,
		prog:             prog,
		metas:            metas,
		metaByPath:       a.metaByPath,
		idxByTypes:       a.idxByTypes,
		idxByPath:        a.idxByPath,
		objByName:        a.objByName,
		objsByLinkTarget: a.objsByLinkTarget,
	}
}

func (b *tier2Base) analyzer() *tier2Analyzer {
	return &tier2Analyzer{
		h:                b.h,
		buildFlags:       b.buildFlags,
		prog:             b.prog,
		metas:            b.metas,
		metaByPath:       b.metaByPath,
		idxByTypes:       b.idxByTypes,
		idxByPath:        b.idxByPath,
		objByName:        b.objByName,
		objsByLinkTarget: b.objsByLinkTarget,
		seenObjects:      map[types.Object]bool{},
		seenTypes:        map[string]bool{},
		seenDecls:        map[string]bool{},
		seenPkgs:         map[*pkgIndex]bool{},
		filePkgs:         map[*pkgIndex]bool{},
		rtaReach:         map[*ssa.Function]bool{},
		rtaResolved:      map[ssa.CallInstruction]bool{},
		scanned:          map[*ssa.Function]bool{},
		seenContrib:      map[string]bool{},
	}
}

func newTier2Analyzer(h *Hasher, prog *program, metas []listPkg) *tier2Analyzer {
	return newTier2Base(h, prog, metas).analyzer()
}

func (a *tier2Analyzer) addReverseLinkname(target string, obj types.Object) {
	if target == "" || obj == nil {
		return
	}
	for _, existing := range a.objsByLinkTarget[target] {
		if existing == obj {
			return
		}
	}
	a.objsByLinkTarget[target] = append(a.objsByLinkTarget[target], obj)
}

func (a *tier2Analyzer) buildIndex(p *packages.Package) *pkgIndex {
	if p == nil || p.Types == nil {
		return nil
	}
	meta := a.metaForPackage(p)
	path := p.Types.Path()
	std := p.Module == nil && isStdImportPath(path)
	if meta != nil {
		std = meta.Standard
	}
	idx := &pkgIndex{
		pkg:            p,
		ssa:            a.prog.prog.Package(p.Types),
		meta:           meta,
		id:             p.ID,
		path:           path,
		dir:            p.Dir,
		std:            std,
		testMain:       p.Name == "main" && path == a.prog.pkgPath+".test",
		decls:          map[types.Object]ast.Node{},
		linknames:      map[types.Object]string{},
		linknameByName: map[string]string{},
		linknameDocs:   map[types.Object]ast.Node{},
	}
	if meta != nil {
		idx.dir = meta.Dir
		idx.cache = meta.Module != nil && !meta.Module.Main && a.h.underCache(meta.Dir)
	} else if p.Module != nil {
		idx.cache = !p.Module.Main && a.h.underCache(p.Dir)
	}
	idx.mutable = !idx.std && !idx.testMain && !idx.cache
	if idx.id == "" {
		idx.id = path
	}

	for _, f := range p.Syntax {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
				text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))
				text = strings.TrimSpace(strings.TrimSuffix(text, "*/"))
				fields := strings.Fields(text)
				if len(fields) >= 3 && fields[0] == "go:linkname" {
					idx.linknameByName[fields[1]] = fields[2]
				}
				if len(fields) >= 2 && fields[0] == "go:linkname" {
					if obj := p.Types.Scope().Lookup(fields[1]); obj != nil {
						idx.linknameDocs[obj] = cg
					}
				}
				if strings.HasPrefix(text, "go:wasmimport") {
					idx.wasmImport = true
				}
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name.Name == "init" {
					idx.inits = append(idx.inits, d)
				}
				if obj := p.TypesInfo.Defs[d.Name]; obj != nil {
					idx.decls[obj] = d
				}
				for local, target := range linknamesFromDoc(d.Doc) {
					if obj := p.Types.Scope().Lookup(local); obj != nil {
						idx.linknames[obj] = target
					}
				}
			case *ast.GenDecl:
				if d.Tok == token.IMPORT {
					idx.imports = append(idx.imports, d)
				}
				genLinknames := linknamesFromDoc(d.Doc)
				for local, target := range genLinknames {
					if obj := p.Types.Scope().Lookup(local); obj != nil {
						idx.linknames[obj] = target
					}
				}
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						specLinknames := linknamesFromDoc(s.Doc)
						for local, target := range specLinknames {
							if obj := p.Types.Scope().Lookup(local); obj != nil {
								idx.linknames[obj] = target
							}
						}
						node := ast.Node(s)
						if d.Tok == token.CONST {
							// A later const spec can inherit expression/type/iota context from
							// earlier specs, so a used const hashes the whole group.
							node = d
						}
						if d.Tok == token.VAR {
							idx.vars = append(idx.vars, s)
							if len(genLinknames) > 0 {
								node = d
							}
						}
						for _, name := range s.Names {
							if obj := p.TypesInfo.Defs[name]; obj != nil {
								idx.decls[obj] = node
							}
						}
					case *ast.TypeSpec:
						if obj := p.TypesInfo.Defs[s.Name]; obj != nil {
							addTypeDeclaration(idx, obj, s)
						}
					}
				}
			}
		}
	}
	return idx
}

func addTypeDeclaration(idx *pkgIndex, obj types.Object, node ast.Node) {
	if idx == nil || obj == nil || node == nil {
		return
	}
	idx.decls[obj] = node
	underlying := obj.Type().Underlying()
	iface, ok := underlying.(*types.Interface)
	if !ok {
		return
	}
	iface.Complete()
	for i := 0; i < iface.NumExplicitMethods(); i++ {
		idx.decls[iface.ExplicitMethod(i)] = node
	}
}

func (a *tier2Analyzer) metaForPackage(p *packages.Package) *listPkg {
	for _, key := range []string{p.ID, p.PkgPath} {
		if key == "" {
			continue
		}
		if m := a.metaByPath[key]; m != nil {
			return m
		}
	}
	if p.Types != nil {
		if m := a.metaByPath[p.Types.Path()]; m != nil {
			return m
		}
	}
	return nil
}

func (a *tier2Analyzer) addLinkedCacheModules() error {
	for _, p := range a.metas {
		if p.Standard || p.Module == nil || p.Module.Main || !a.h.underCache(p.Dir) {
			continue
		}
		rel := strings.TrimPrefix(filepath.Clean(p.Module.Dir), a.h.modCache+string(filepath.Separator))
		a.addContribution("cache:" + filepath.ToSlash(rel))
	}
	return nil
}

func (a *tier2Analyzer) addFunction(fn *ssa.Function) {
	if fn == nil {
		return
	}
	if origin := fn.Origin(); origin != nil {
		fn = origin
	}
	idx := a.idxForFunction(fn)
	if idx == nil || idx.std || idx.cache || idx.testMain {
		return
	}
	if fn.Synthetic == "package initializer" || (fn.Name() == "init" && fn.Object() == nil) {
		a.addStartupPackage(idx)
		return
	}
	if obj := fn.Object(); obj != nil {
		a.enqueueObject(obj)
		return
	}
	if parent := fn.Parent(); parent != nil {
		a.addFunction(parent)
	}
}

func (a *tier2Analyzer) addStartupPackage(idx *pkgIndex) {
	if idx == nil || !idx.mutable {
		return
	}
	a.markPackage(idx)
	for _, n := range idx.vars {
		a.addDecl(idx, "startup-var", n)
		a.scanNodeRefs(idx, n)
	}
	for _, n := range idx.inits {
		a.addDecl(idx, "init", n)
		a.scanNodeRefs(idx, n)
	}
}

func (a *tier2Analyzer) scanFunction(fn *ssa.Function) {
	if fn == nil {
		return
	}
	idx := a.idxForFunction(fn)
	if idx == nil || idx.testMain {
		return
	}
	if !idx.std {
		a.markFilePackage(idx)
		if obj := fn.Object(); obj != nil {
			if target := a.linknameTarget(idx, obj); target != "" {
				a.addLinknameTarget(target)
			}
		}
	}
	if len(fn.Blocks) == 0 {
		return
	}
	if a.scanned[fn] {
		return
	}
	a.scanned[fn] = true
	suppressNestedFileIO := idx.std && isFileIOReason(classBReasonForFunction(fn))
	if !idx.std && idx.wasmImport {
		a.markUnverifiable("reaches go:wasmimport")
	}
	if idx.cache && hasExternalCgoMeta(idx.meta) {
		a.markUnverifiable("reaches cgo external library")
	}
	if idx.cache {
		a.scanCacheFunctionRefs(idx, fn)
	}
	if idx.std && isFileIOReason(classBReasonForFunction(fn)) {
		return
	}
	var ops [16]*ssa.Value
	for _, block := range fn.Blocks {
		if a.contextErr() != nil {
			return
		}
		for _, instr := range block.Instrs {
			if v, ok := instr.(ssa.Value); ok {
				a.addType(v.Type())
				if !idx.std && typeUsesUnsafePointer(v.Type()) {
					a.requestWiden("unsafe pointer reachable in " + idx.id)
				}
			}
			for _, op := range instr.Operands(ops[:0]) {
				if op == nil || *op == nil {
					continue
				}
				a.scanValue(idx, *op)
			}
			fromRTA := a.rtaReach[fn]
			if idx.std {
				fromRTA = false
			}
			a.scanInstruction(idx, fn, instr, fromRTA, suppressNestedFileIO)
		}
	}
}

func (a *tier2Analyzer) scanCacheFunctionRefs(idx *pkgIndex, fn *ssa.Function) {
	if idx == nil || fn == nil {
		return
	}
	if origin := fn.Origin(); origin != nil {
		fn = origin
	}
	obj := fn.Object()
	if obj == nil {
		if fn.Synthetic == "package initializer" || fn.Name() == "init" {
			for _, n := range idx.vars {
				a.scanNodeRefs(idx, n)
			}
			for _, n := range idx.inits {
				a.scanNodeRefs(idx, n)
			}
		}
		return
	}
	obj = originObject(obj)
	node := idx.decls[obj]
	if node == nil {
		a.requestWiden("missing cache function declaration for " + obj.String())
		return
	}
	a.scanNodeRefs(idx, node)
}

func (a *tier2Analyzer) scanValue(callerIdx *pkgIndex, v ssa.Value) {
	if v == nil {
		return
	}
	a.addType(v.Type())
	if typeUsesUnsafePointer(v.Type()) {
		if idx := a.idxForFunction(v.Parent()); idx != nil && !idx.std {
			a.requestWiden("unsafe pointer reachable in " + idx.id)
		}
	}
	switch x := v.(type) {
	case *ssa.Global:
		if obj := x.Object(); obj != nil {
			if callerIdx != nil && !callerIdx.std && obj.Pkg() != nil && isStdImportPath(obj.Pkg().Path()) {
				a.markUnverifiable("reaches standard global " + obj.Pkg().Path() + "." + obj.Name())
			}
			a.enqueueObject(obj)
		}
	case *ssa.Function:
		a.addFunction(x)
	}
}

func (a *tier2Analyzer) scanInstruction(idx *pkgIndex, caller *ssa.Function, instr ssa.Instruction, fromRTA, suppressNestedFileIO bool) {
	switch x := instr.(type) {
	case ssa.CallInstruction:
		a.scanCall(idx, caller, x, fromRTA, suppressNestedFileIO)
	case *ssa.MakeInterface:
		a.addInterfaceMethodSet(x.X.Type())
	case *ssa.Field:
		if reason := testingRuntimeFieldReason(x.X.Type(), x.Field); reason != "" {
			a.markUnverifiable(reason)
		}
	case *ssa.FieldAddr:
		if reason := testingRuntimeFieldReason(x.X.Type(), x.Field); reason != "" {
			a.markUnverifiable(reason)
		}
	}
}

func testingRuntimeFieldReason(t types.Type, index int) string {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return ""
	}
	structure, ok := named.Underlying().(*types.Struct)
	if !ok || index < 0 || index >= structure.NumFields() {
		return ""
	}
	if name := structure.Field(index).Name(); name == "N" {
		return "reaches testing.B.N (test runtime configuration)"
	}
	return ""
}

func (a *tier2Analyzer) scanCall(callerIdx *pkgIndex, caller *ssa.Function, site ssa.CallInstruction, fromRTA, suppressNestedFileIO bool) {
	c := site.Common()
	if c == nil {
		return
	}
	callerStd := callerIdx != nil && callerIdx.std
	resolved := fromRTA && a.rtaResolved[site] && !a.openWorld && locallyClosedDynamicValue(c.Value, make(map[ssa.Value]bool))
	if c.IsInvoke() && !resolved && !callerStd {
		a.requestWiden("interface invoke outside RTA")
	}
	if !c.IsInvoke() && c.StaticCallee() == nil {
		if _, ok := c.Value.(*ssa.Builtin); !ok && !callerStd && !resolved {
			a.requestWiden("computed function call in " + caller.String())
		}
	}
	callee := c.StaticCallee()
	if callee == nil {
		return
	}
	pkgPath := funcPkgPath(callee)
	name := callee.Name()
	if obj := callee.Object(); obj != nil {
		name = obj.Name()
	}
	reason := classBReason(pkgPath, name)
	calleeIdx := a.idxForFunction(callee)
	if reason == "" && name != "init" && !callerStd && calleeIdx != nil && calleeIdx.std && !isRefinementSourceOnlyStandardPackage(pkgPath) {
		reason = "reaches unaudited standard operation " + pkgPath + "." + name
	}
	if osOpenFileMayMutate(callee, pkgPath, name, c) {
		reason = "reaches os.OpenFile (filesystem mutation)"
	}
	if reason == "" && syscallOpenMayCreate(pkgPath, name, c) {
		reason = "reaches " + pkgPath + "." + name + " (filesystem mutation)"
	}
	if reason != "" {
		if callerStd && isFilesystemMutationReason(reason) {
			return
		}
		if !(suppressNestedFileIO && isFileIOReason(reason)) {
			a.markUnverifiable(reason)
		}
	}
	calleeStd := isStdImportPath(pkgPath)
	if !fromRTA || (!callerStd && calleeStd && !isBenchmarkHarnessPath(pkgPath)) {
		a.scanFunction(callee)
	}
	if !callerStd && pkgPath == "reflect" && (name == "Call" || name == "CallSlice" || name == "MakeFunc" || name == "MethodByName") {
		a.requestWiden("reflect dispatch")
	}
}

func locallyClosedDynamicValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Function, *ssa.Builtin, *ssa.Const, *ssa.MakeClosure:
		return true
	case *ssa.MakeInterface:
		return true
	case *ssa.ChangeInterface:
		return locallyClosedDynamicValue(value.X, seen)
	case *ssa.ChangeType:
		return locallyClosedDynamicValue(value.X, seen)
	case *ssa.Convert:
		return locallyClosedDynamicValue(value.X, seen)
	case *ssa.Phi:
		if len(value.Edges) == 0 {
			return false
		}
		for _, edge := range value.Edges {
			if !locallyClosedDynamicValue(edge, seen) {
				return false
			}
		}
		return true
	case *ssa.Extract:
		return locallyClosedDynamicValue(value.Tuple, seen)
	default:
		return false
	}
}

func (a *tier2Analyzer) addInterfaceMethodSet(t types.Type) {
	if !a.hasNonStdNamedType(t) {
		return
	}
	for _, mt := range []types.Type{t, types.NewPointer(t)} {
		set := types.NewMethodSet(mt)
		for i := 0; i < set.Len(); i++ {
			if fn, ok := set.At(i).Obj().(*types.Func); ok {
				a.enqueueObject(fn)
			}
		}
	}
}

func (a *tier2Analyzer) hasNonStdNamedType(t types.Type) bool {
	found := false
	seen := map[string]bool{}
	var walk func(types.Type)
	walk = func(t types.Type) {
		if t == nil || found {
			return
		}
		t = types.Unalias(t)
		key := types.TypeString(t, nil)
		if seen[key] {
			return
		}
		seen[key] = true
		switch tt := t.(type) {
		case *types.Named:
			if obj := tt.Obj(); obj != nil && obj.Pkg() != nil {
				if idx := a.idxByTypes[obj.Pkg()]; idx != nil {
					if !idx.std {
						found = true
						return
					}
				} else if !isStdImportPath(obj.Pkg().Path()) {
					found = true
					return
				}
			}
			walk(tt.Underlying())
		case *types.Pointer:
			walk(tt.Elem())
		case *types.Slice:
			walk(tt.Elem())
		case *types.Array:
			walk(tt.Elem())
		case *types.Map:
			walk(tt.Key())
			walk(tt.Elem())
		case *types.Chan:
			walk(tt.Elem())
		case *types.Signature:
			for _, tuple := range []*types.Tuple{tt.Params(), tt.Results()} {
				for i := 0; tuple != nil && i < tuple.Len(); i++ {
					walk(tuple.At(i).Type())
				}
			}
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				walk(tt.Field(i).Type())
			}
		}
	}
	walk(t)
	return found
}

func (a *tier2Analyzer) drainObjects() error {
	for len(a.objectQueue) > 0 {
		if err := a.contextErr(); err != nil {
			return err
		}
		obj := a.objectQueue[0]
		a.objectQueue = a.objectQueue[1:]
		a.addObject(obj)
	}
	return nil
}

func (a *tier2Analyzer) contextErr() error {
	if a == nil || a.h == nil || a.h.ctx == nil {
		return nil
	}
	return a.h.contextErr()
}

func (a *tier2Analyzer) enqueueObject(obj types.Object) {
	if obj == nil || obj.Pkg() == nil || a.seenObjects[obj] {
		return
	}
	a.seenObjects[obj] = true
	a.objectQueue = append(a.objectQueue, obj)
}

func (a *tier2Analyzer) addObject(obj types.Object) {
	if obj == nil || obj.Pkg() == nil {
		return
	}
	idx := a.idxByTypes[obj.Pkg()]
	if idx == nil {
		if !isStdImportPath(obj.Pkg().Path()) {
			a.requestWiden("missing source metadata for " + obj.Pkg().Path())
		}
		return
	}
	a.addReverseLinknameTargets(obj)
	if fn, ok := obj.(*types.Func); ok {
		if reason := classBReason(obj.Pkg().Path(), obj.Name()); reason != "" {
			a.markUnverifiable(reason)
		}
		if ssaFn := a.prog.prog.FuncValue(fn); ssaFn != nil {
			a.scanFunction(ssaFn)
		}
	}
	if !idx.std {
		if target := a.linknameTarget(idx, obj); target != "" {
			a.addLinknameTarget(target)
		}
	}
	if idx.std || idx.testMain {
		return
	}
	if !isPackageLevelObject(obj) {
		return
	}
	node := idx.decls[originObject(obj)]
	if idx.cache {
		a.addType(obj.Type())
		if node != nil {
			a.scanNodeRefs(idx, node)
		} else if _, ok := obj.(*types.Func); !ok {
			a.requestWiden("missing declaration for " + obj.String())
		}
		if fn, ok := obj.(*types.Func); ok {
			if ssaFn := a.prog.prog.FuncValue(fn); ssaFn != nil {
				a.scanFunction(ssaFn)
			}
		}
		return
	}
	if node == nil {
		if _, ok := obj.(*types.Func); ok {
			// A func object with no source decl node is source-free: buildIndex
			// records a decl for every FuncDecl (incl. asm bodies and generic
			// origins), so this is a synthetic/instantiated func whose real body,
			// if any, is hashed through RTA (addFunction resolves fn.Origin() for
			// every reachable instantiation — incl. methods RTA marks reachable
			// when their concrete type is converted to an interface). Hashing its
			// signature suffices; widening here would only lose precision. A
			// non-func with no node is genuinely missing source → widen.
			a.addType(obj.Type())
			return
		}
		a.requestWiden("missing declaration for " + obj.String())
		return
	}
	a.markPackage(idx)
	if linkDoc := idx.linknameDocs[obj]; linkDoc != nil {
		a.addDecl(idx, "linkname "+obj.String(), linkDoc)
	}
	a.addDecl(idx, obj.String(), node)
	a.addType(obj.Type())
	a.scanNodeRefs(idx, node)
	if fn, ok := obj.(*types.Func); ok {
		if ssaFn := a.prog.prog.FuncValue(fn); ssaFn != nil {
			a.scanFunction(ssaFn)
		}
	}
}

func originObject(obj types.Object) types.Object {
	fn, ok := obj.(*types.Func)
	if !ok {
		return obj
	}
	if origin := fn.Origin(); origin != nil {
		return origin
	}
	return obj
}

func (a *tier2Analyzer) addReverseLinknameTargets(obj types.Object) {
	if obj == nil || obj.Pkg() == nil {
		return
	}
	key := obj.Pkg().Path() + "." + obj.Name()
	for _, linked := range a.objsByLinkTarget[key] {
		if linked != obj {
			a.enqueueObject(linked)
		}
	}
}

func (a *tier2Analyzer) linknameTarget(idx *pkgIndex, obj types.Object) string {
	if idx == nil || obj == nil {
		return ""
	}
	if target := idx.linknames[obj]; target != "" {
		return target
	}
	return idx.linknameByName[obj.Name()]
}

func (a *tier2Analyzer) addLinknameTarget(target string) {
	lastDot := strings.LastIndexByte(target, '.')
	if lastDot < 0 {
		a.requestWiden("unresolved go:linkname target " + target)
		return
	}
	pkgPath, name := target[:lastDot], target[lastDot+1:]
	reason := classBReason(pkgPath, name)
	if reason == "" && isStdImportPath(pkgPath) {
		reason = "reaches standard linkname target " + target
	}
	if reason != "" {
		a.markUnverifiable(reason)
	}
	obj := a.objByName[pkgPath+"."+name]
	if obj == nil {
		a.requestWiden("unresolved go:linkname target " + target)
		return
	}
	a.enqueueObject(obj)
}

func (a *tier2Analyzer) addType(t types.Type) {
	if t == nil {
		return
	}
	key := types.TypeString(t, nil)
	if a.seenTypes[key] {
		return
	}
	a.seenTypes[key] = true
	switch tt := t.(type) {
	case *types.Named:
		a.enqueueObject(tt.Obj())
		for i := 0; i < tt.TypeArgs().Len(); i++ {
			a.addType(tt.TypeArgs().At(i))
		}
		a.addType(tt.Underlying())
	case *types.Pointer:
		a.addType(tt.Elem())
	case *types.Slice:
		a.addType(tt.Elem())
	case *types.Array:
		a.addType(tt.Elem())
	case *types.Map:
		a.addType(tt.Key())
		a.addType(tt.Elem())
	case *types.Chan:
		a.addType(tt.Elem())
	case *types.Signature:
		a.addTuple(tt.Params())
		a.addTuple(tt.Results())
	case *types.Struct:
		for i := 0; i < tt.NumFields(); i++ {
			a.addType(tt.Field(i).Type())
		}
	}
}

func (a *tier2Analyzer) addTuple(t *types.Tuple) {
	if t == nil {
		return
	}
	for i := 0; i < t.Len(); i++ {
		a.addType(t.At(i).Type())
	}
}

func (a *tier2Analyzer) scanNodeRefs(idx *pkgIndex, node ast.Node) {
	if idx == nil || node == nil || idx.pkg.TypesInfo == nil {
		return
	}
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			if obj := idx.pkg.TypesInfo.Uses[x]; obj != nil {
				a.enqueueObject(obj)
				a.addType(obj.Type())
			}
		case *ast.SelectorExpr:
			if sel := idx.pkg.TypesInfo.Selections[x]; sel != nil {
				a.enqueueObject(sel.Obj())
				a.addType(sel.Recv())
			}
		}
		return true
	})
}

func (a *tier2Analyzer) markPackage(idx *pkgIndex) {
	if idx != nil && idx.mutable {
		a.seenPkgs[idx] = true
		a.filePkgs[idx] = true
	}
}

func (a *tier2Analyzer) markFilePackage(idx *pkgIndex) {
	if idx != nil && (idx.mutable || idx.cache) {
		a.filePkgs[idx] = true
	}
}

func (a *tier2Analyzer) addReachedPackageFiles() error {
	pkgs := make([]*pkgIndex, 0, len(a.filePkgs))
	for idx := range a.filePkgs {
		pkgs = append(pkgs, idx)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].id < pkgs[j].id })
	for _, idx := range pkgs {
		if err := a.contextErr(); err != nil {
			return err
		}
		if idx.meta == nil {
			a.requestWiden("missing file metadata for " + idx.id)
			continue
		}
		if idx.wasmImport {
			a.markUnverifiable("reaches go:wasmimport")
		}
		if idx.mutable {
			for _, n := range idx.imports {
				a.addDecl(idx, "imports", n)
			}
		}
		if hasExternalCgoMeta(idx.meta) {
			a.markUnverifiable("reaches cgo external library")
		}
		if idx.mutable {
			if hasCgoCallbackBlindspot(idx.meta) {
				modCache := ""
				if a.h != nil {
					modCache = a.h.modCache
				}
				if root := cgoIncludeRootOutsideDir(idx.meta, modCache); root != "" {
					return fmt.Errorf("closure: cgo include root outside package dir: %s", root)
				}
				a.requestWiden("cgo callback source in " + idx.id)
			}
			if err := a.addRelFiles(idx, "embed", idx.meta.EmbedFiles); err != nil {
				return err
			}
			nonGo := append([]string{}, idx.meta.CgoFiles...)
			for _, set := range [][]string{
				idx.meta.CFiles, idx.meta.CXXFiles, idx.meta.MFiles, idx.meta.HFiles, idx.meta.FFiles,
				idx.meta.SFiles, idx.meta.SwigFiles, idx.meta.SwigCXXFiles, idx.meta.SysoFiles,
			} {
				nonGo = append(nonGo, set...)
			}
			if hasCgoCallbackBlindspot(idx.meta) {
				all, err := allPackageFiles(idx.meta.Dir)
				if err != nil {
					return err
				}
				if include, err := cgoEscapingInclude(idx.meta, all); err != nil {
					return err
				} else if include != "" {
					return fmt.Errorf("closure: cgo include escapes package dir: %s", include)
				}
				if err := a.addRelFiles(idx, "file", all); err != nil {
					return err
				}
			} else {
				if err := a.addRelFiles(idx, "file", nonGo); err != nil {
					return err
				}
			}
			generated, err := hasGeneratedASMInclude(idx.meta.Dir, idx.meta.SFiles)
			if err != nil {
				return err
			}
			if generated {
				// go_asm.h contains only constants and struct sizes/offsets derived
				// from selected Go declarations. Hash the selected package whole so
				// those generated values cannot move outside the refined closure.
				if err := a.addRelFiles(idx, "generated-asm-input", idx.meta.sourceFiles()); err != nil {
					return err
				}
			}
		}
		var externalASMReason string
		asmCalls, computed, opaque, includes, err := asmCallTargetsObserved(&externalASMReason, idx.meta.Dir, idx.meta.SFiles, a.buildFlags...)
		if err != nil {
			return err
		}
		if idx.mutable {
			if err := a.addAbsFiles(idx, "include", includes); err != nil {
				return err
			}
		}
		if computed {
			a.requestWiden("computed asm call in " + idx.id)
		}
		if opaque {
			a.requestWiden("opaque asm preprocessing in " + idx.id)
		}
		if !idx.std && externalASMReason != "" {
			a.markUnverifiable(externalASMReason)
		}
		for _, target := range asmCalls {
			a.addASMTarget(idx, target)
		}
	}
	return nil
}

func asmExternalStateReason(dir string, files []string) (string, error) {
	for _, name := range files {
		filename := name
		if !filepath.IsAbs(filename) {
			filename = filepath.Join(dir, filename)
		}
		content, err := os.ReadFile(filename)
		if err != nil {
			return "", err
		}
		for _, line := range stripASMBlockComments(strings.Split(string(content), "\n")) {
			line = strings.TrimSpace(strings.SplitN(line, "//", 2)[0])
			opcode := asmOpcodeFromFields(strings.Fields(line))
			if asmOpcodeReadsExternalState(opcode) {
				return "reaches assembly instruction " + opcode + " (external runtime state)", nil
			}
		}
	}
	return "", nil
}

func asmOpcodeFromFields(fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	i := 0
	if strings.HasSuffix(fields[0], ":") {
		i++
	}
	if i >= len(fields) {
		return ""
	}
	return strings.Trim(strings.ToUpper(fields[i]), ",;:")
}

func asmOpcodeReadsExternalState(opcode string) bool {
	switch opcode {
	case "CPUID", "XGETBV", "XSETBV", "SYSCALL", "SYSRET", "SYSENTER", "SYSEXIT", "INT", "IN", "OUT", "HLT",
		"MONITOR", "MWAIT", "UMONITOR", "UMWAIT", "TPAUSE",
		"MRS", "MSR", "SYS", "SYSL", "SVC", "HVC", "SMC",
		"MFSPR", "MTSPR", "MFTB", "MFTBU",
		"ECALL", "EBREAK", "RDCYCLE", "RDCYCLEH", "RDTIME", "RDTIMEH", "RDINSTRET", "RDINSTRETH":
		return true
	}
	return strings.HasPrefix(opcode, "RD") || strings.HasPrefix(opcode, "WR") || strings.HasPrefix(opcode, "CSR")
}

func (a *tier2Analyzer) addASMTarget(idx *pkgIndex, target string) {
	name := target
	prefix := ""
	if i := strings.LastIndex(name, "·"); i >= 0 {
		prefix = name[:i]
		name = name[i+len("·"):]
	}
	name = strings.TrimPrefix(name, "·")
	name = strings.TrimPrefix(name, "*")
	if i := strings.IndexByte(name, '<'); i >= 0 {
		name = name[:i]
	}
	obj := a.lookupASMTarget(idx, prefix, name)
	if obj == nil {
		a.requestWiden("unresolved asm call target " + target)
		return
	}
	if reason := standardASMTargetReason(obj); reason != "" {
		a.markUnverifiable(reason)
	}
	a.enqueueObject(obj)
}

func standardASMTargetReason(obj types.Object) string {
	if obj == nil || obj.Pkg() == nil || !isStdImportPath(obj.Pkg().Path()) {
		return ""
	}
	if reason := classBReason(obj.Pkg().Path(), obj.Name()); reason != "" {
		return reason
	}
	return "reaches standard assembly target " + obj.Pkg().Path() + "." + obj.Name()
}

func (a *tier2Analyzer) lookupASMTarget(idx *pkgIndex, prefix, name string) types.Object {
	if idx == nil || idx.pkg == nil || idx.pkg.Types == nil {
		return nil
	}
	if prefix == "" || prefix == idx.pkg.Name {
		return idx.pkg.Types.Scope().Lookup(name)
	}
	if cand := a.idxByPath[prefix]; cand != nil && cand.pkg != nil && cand.pkg.Types != nil {
		return cand.pkg.Types.Scope().Lookup(name)
	}
	var found types.Object
	seen := map[*pkgIndex]bool{}
	for _, cand := range a.idxByTypes {
		if cand == nil || seen[cand] || cand.pkg == nil || cand.pkg.Types == nil || cand.pkg.Name != prefix {
			continue
		}
		seen[cand] = true
		obj := cand.pkg.Types.Scope().Lookup(name)
		if obj == nil {
			continue
		}
		if found != nil && found != obj {
			return nil
		}
		found = obj
	}
	return found
}

func (a *tier2Analyzer) addRelFiles(idx *pkgIndex, kind string, files []string) error {
	sort.Strings(files)
	for _, f := range files {
		h, err := hashFile(filepath.Join(idx.meta.Dir, f))
		if err != nil {
			return err
		}
		a.addContribution(fmt.Sprintf("%s:%s:%s=%s", kind, idx.id, filepath.ToSlash(f), h))
	}
	return nil
}

func (a *tier2Analyzer) addAbsFiles(idx *pkgIndex, kind string, files []string) error {
	sort.Strings(files)
	for _, path := range files {
		h, err := hashFile(path)
		if err != nil {
			return err
		}
		rel := path
		if idx.meta != nil && idx.meta.Dir != "" {
			if r, err := filepath.Rel(idx.meta.Dir, path); err == nil && !strings.HasPrefix(r, "..") {
				rel = r
			}
		}
		a.addContribution(fmt.Sprintf("%s:%s:%s=%s", kind, idx.id, filepath.ToSlash(rel), h))
	}
	return nil
}

func (a *tier2Analyzer) addDecl(idx *pkgIndex, label string, node ast.Node) {
	if node == nil || idx == nil || idx.pkg.Fset == nil {
		a.requestWiden("missing declaration source")
		return
	}
	pos := nodeStart(node)
	end := node.End()
	file := idx.pkg.Fset.File(pos)
	if file == nil || end == token.NoPos {
		a.requestWiden("missing declaration position")
		return
	}
	startOff := file.Offset(pos)
	endOff := file.Offset(end)
	if endOff < startOff {
		a.requestWiden("invalid declaration range")
		return
	}
	if names := declarationNames(node); names != "" {
		label += " " + names
	}
	key := fmt.Sprintf("%s:%s:%d:%d:%s", idx.id, file.Name(), startOff, endOff, label)
	if a.seenDecls[key] {
		return
	}
	a.seenDecls[key] = true
	content, err := os.ReadFile(file.Name())
	if err != nil {
		a.requestWiden("cannot read declaration source")
		return
	}
	if startOff > len(content) || endOff > len(content) {
		a.requestWiden("declaration range outside file")
		return
	}
	sum := sha256.Sum256(content[startOff:endOff])
	rel := file.Name()
	if idx.dir != "" {
		if r, err := filepath.Rel(idx.dir, file.Name()); err == nil && !strings.HasPrefix(r, "..") {
			rel = r
		}
	}
	a.addContribution(fmt.Sprintf("decl:%s:%s:%d:%s=%s", idx.id, filepath.ToSlash(rel), startOff, label, hex.EncodeToString(sum[:])[:32]))
}

func declarationNames(node ast.Node) string {
	var names []string
	switch n := node.(type) {
	case *ast.GenDecl:
		for _, spec := range n.Specs {
			switch s := spec.(type) {
			case *ast.ValueSpec:
				for _, name := range s.Names {
					names = append(names, name.Name)
				}
			case *ast.TypeSpec:
				names = append(names, s.Name.Name)
			}
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return "[" + strings.Join(names, ",") + "]"
}

func (a *tier2Analyzer) addContribution(c string) {
	if c == "" || a.seenContrib[c] {
		return
	}
	a.seenContrib[c] = true
	a.contribs = append(a.contribs, c)
}

func (a *tier2Analyzer) requestWiden(reason string) {
	if !a.widen {
		a.widen = true
		a.widenReason = reason
	}
}

func (a *tier2Analyzer) markUnverifiable(reason string) {
	// Prefer a non-file-I/O reason when several apply: file I/O is the most common
	// and least specific external dependence, so a network/plugin/cgo cause is the
	// more informative one to surface.
	currentRank := unverifiableReasonRank(a.reason)
	newRank := unverifiableReasonRank(reason)
	if !a.unverifiable || newRank > currentRank || (newRank == currentRank && reason < a.reason) {
		a.reason = reason
	}
	a.unverifiable = true
}

func unverifiableReasonRank(reason string) int {
	switch {
	case strings.Contains(reason, "unaudited standard operation"), strings.Contains(reason, "test runtime configuration"), strings.Contains(reason, "test runtime execution"), strings.Contains(reason, "standard assembly target"):
		return 0
	case strings.Contains(reason, "formatted output"), strings.Contains(reason, "assembly operand"), strings.Contains(reason, "environment input"):
		return 1
	case isFileIOReason(reason):
		return 3
	default:
		return 4
	}
}

func isRefinementSourceOnlyStandardPackage(pkgPath string) bool {
	// The testing harness itself is selected infrastructure. Its externally
	// observable helpers are classified before this fallback.
	return pkgPath == "testing" || isSourceOnlyStandardPackage(pkgPath)
}

func (a *tier2Analyzer) result() tier2Result {
	sort.Strings(a.contribs)
	return tier2Result{contribs: a.contribs, widen: a.widen, widenReason: a.widenReason, unverifiable: a.unverifiable, reason: a.reason}
}

func isFileIOReason(reason string) bool {
	return strings.Contains(reason, "file I/O")
}

func isFilesystemMutationReason(reason string) bool {
	return strings.Contains(reason, "mutation")
}

func classBReasonForFunction(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	pkgPath := funcPkgPath(fn)
	name := fn.Name()
	if obj := fn.Object(); obj != nil {
		name = obj.Name()
	}
	return classBReason(pkgPath, name)
}

func osOpenFileMayMutate(callee *ssa.Function, pkgPath, name string, c *ssa.CallCommon) bool {
	if pkgPath != "os" || name != "OpenFile" {
		return false
	}
	flagArg := 1
	if callee != nil && callee.Signature != nil && callee.Signature.Recv() != nil {
		flagArg = 2
	}
	if c == nil || len(c.Args) <= flagArg {
		return true
	}
	v, ok := c.Args[flagArg].(*ssa.Const)
	if !ok {
		return true
	}
	if v.Value.Kind() != constant.Int {
		return true
	}
	flags, ok := constant.Int64Val(v.Value)
	if !ok {
		return true
	}
	const mutatingFlags = int64(os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREATE | os.O_TRUNC)
	return flags&mutatingFlags != 0
}

func syscallOpenMayCreate(pkgPath, name string, c *ssa.CallCommon) bool {
	if pkgPath != "syscall" && pkgPath != "golang.org/x/sys/unix" {
		return false
	}
	flagArg := -1
	switch name {
	case "Open":
		flagArg = 1
	case "Openat":
		flagArg = 2
	default:
		return false
	}
	if c == nil || flagArg >= len(c.Args) {
		return true
	}
	v, ok := c.Args[flagArg].(*ssa.Const)
	if !ok {
		return true
	}
	flags, ok := constant.Int64Val(v.Value)
	if !ok {
		return true
	}
	return flags&int64(os.O_CREATE) != 0
}

func (a *tier2Analyzer) idxForFunction(fn *ssa.Function) *pkgIndex {
	for f := fn; f != nil; f = f.Parent() {
		if f.Pkg != nil && f.Pkg.Pkg != nil {
			return a.idxByTypes[f.Pkg.Pkg]
		}
		if obj := f.Object(); obj != nil && obj.Pkg() != nil {
			return a.idxByTypes[obj.Pkg()]
		}
	}
	return nil
}

func funcPkgPath(fn *ssa.Function) string {
	for f := fn; f != nil; f = f.Parent() {
		if f.Pkg != nil && f.Pkg.Pkg != nil {
			return f.Pkg.Pkg.Path()
		}
		if obj := f.Object(); obj != nil && obj.Pkg() != nil {
			return obj.Pkg().Path()
		}
	}
	return ""
}

func isPackageLevelObject(obj types.Object) bool {
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	if obj.Parent() == obj.Pkg().Scope() {
		return true
	}
	_, isFunc := obj.(*types.Func)
	return isFunc
}

func nodeStart(n ast.Node) token.Pos {
	switch x := n.(type) {
	case *ast.FuncDecl:
		if x.Doc != nil {
			return x.Doc.Pos()
		}
	case *ast.ValueSpec:
		if x.Doc != nil {
			return x.Doc.Pos()
		}
	case *ast.TypeSpec:
		if x.Doc != nil {
			return x.Doc.Pos()
		}
	case *ast.GenDecl:
		if x.Doc != nil {
			return x.Doc.Pos()
		}
	}
	return n.Pos()
}

func linknamesFromDoc(doc *ast.CommentGroup) map[string]string {
	out := map[string]string{}
	if doc == nil {
		return out
	}
	for _, c := range doc.List {
		text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		fields := strings.Fields(text)
		if len(fields) >= 3 && fields[0] == "go:linkname" {
			out[fields[1]] = fields[2]
		}
	}
	return out
}

func typeUsesUnsafePointer(t types.Type) bool {
	found := false
	seen := map[string]bool{}
	var walk func(types.Type)
	walk = func(t types.Type) {
		if t == nil || found {
			return
		}
		t = types.Unalias(t)
		key := types.TypeString(t, nil)
		if seen[key] {
			return
		}
		seen[key] = true
		if basic, ok := t.(*types.Basic); ok && basic.Kind() == types.UnsafePointer {
			found = true
			return
		}
		if n, ok := t.(*types.Named); ok {
			if obj := n.Obj(); obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "unsafe" && obj.Name() == "Pointer" {
				found = true
				return
			}
		}
		switch tt := t.(type) {
		case *types.Named:
			walk(tt.Underlying())
		case *types.Pointer:
			walk(tt.Elem())
		case *types.Slice:
			walk(tt.Elem())
		case *types.Array:
			walk(tt.Elem())
		case *types.Map:
			walk(tt.Key())
			walk(tt.Elem())
		case *types.Chan:
			walk(tt.Elem())
		case *types.Signature:
			for _, tuple := range []*types.Tuple{tt.Params(), tt.Results()} {
				for i := 0; tuple != nil && i < tuple.Len(); i++ {
					walk(tuple.At(i).Type())
				}
			}
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				walk(tt.Field(i).Type())
			}
		}
	}
	walk(t)
	return found
}

func classBReason(pkgPath, name string) string {
	if pkgPath == "fmt" {
		switch name {
		case "Scan", "Scanf", "Scanln", "Fscan", "Fscanf", "Fscanln":
			return "reaches fmt." + name + " (standard input)"
		case "Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln":
			return "reaches fmt." + name + " (formatted output)"
		}
	}
	if pkgPath == "os" {
		switch name {
		case "Getenv", "LookupEnv", "Environ", "ExpandEnv":
			return "reaches os." + name + " (environment input)"
		case "Open", "OpenFile", "ReadFile", "ReadDir", "Stat", "Lstat":
			return "reaches os." + name + " (file I/O)"
		case "Create", "CreateTemp", "WriteFile":
			return "reaches os." + name + " (filesystem mutation)"
		case "CopyFS", "Link", "Mkdir", "MkdirAll", "MkdirTemp", "Remove", "RemoveAll", "Rename", "Symlink":
			return "reaches os." + name + " (path mutation)"
		}
	}
	if pkgPath == "syscall" || pkgPath == "golang.org/x/sys/unix" {
		switch name {
		case "Creat":
			return "reaches " + pkgPath + "." + name + " (filesystem mutation)"
		case "Link", "Linkat", "Mkdir", "Mkdirat", "Rename", "Renameat", "Renameat2", "Rmdir", "Symlink", "Symlinkat", "Unlink", "Unlinkat":
			return "reaches " + pkgPath + "." + name + " (path mutation)"
		}
	}
	if pkgPath == "testing" {
		switch name {
		case "TempDir", "Chdir", "Setenv":
			return "reaches testing." + name + " (process or path mutation)"
		case "Short", "Verbose", "Testing", "CoverMode", "Coverage", "Deadline", "N", "Loop", "Parallel", "ArtifactDir", "Context":
			return "reaches testing." + name + " (test runtime configuration)"
		case "Run", "Fuzz", "RunParallel", "Elapsed", "Result", "AllocsPerRun", "Benchmark", "RunBenchmarks", "RunExamples", "RunTests", "Main", "MainStart":
			return "reaches testing." + name + " (test runtime execution)"
		}
	}
	if pkgPath == "net" {
		switch name {
		case "Dial", "DialContext", "DialTCP", "DialUDP", "DialIP", "Listen", "ListenTCP", "ListenUDP", "ListenIP", "ListenPacket":
			return "reaches net." + name + " (network I/O)"
		}
	}
	if pkgPath == "net/http" {
		switch name {
		case "Get", "Head", "Post", "PostForm", "Do", "ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS":
			return "reaches net/http." + name + " (network I/O)"
		}
	}
	if pkgPath == "html/template" || pkgPath == "text/template" {
		switch name {
		case "ParseFiles", "ParseGlob":
			return "reaches " + pkgPath + "." + name + " (file I/O)"
		}
	}
	if pkgPath == "plugin" && (name == "Open" || name == "Lookup") {
		return "reaches plugin." + name
	}
	return ""
}

func hasExternalCgo(flags []string) bool {
	for _, f := range flags {
		for _, tok := range expandLinkerFlag(f) {
			if isExternalLinkToken(tok) {
				return true
			}
		}
	}
	return false
}

// expandLinkerFlag splits a linker pass-through flag into its sub-arguments. gcc
// carries multiple linker arguments in one comma-joined token (`-Wl,-Bstatic,-lfoo,
// -Bdynamic`), so a `-l` element can hide inside a single whitespace token; without
// expanding it, an external library links unseen and the closure reports `valid`
// while that library changes (REQ-closure-blindspot, REQ-fresh-verdict). `-Xlinker <arg>` needs no expansion —
// go list already emits its argument as a separate token.
func expandLinkerFlag(f string) []string {
	if rest, ok := strings.CutPrefix(f, "-Wl,"); ok {
		return strings.Split(rest, ",")
	}
	return []string{f}
}

func isExternalLinkToken(f string) bool {
	return strings.HasPrefix(f, "-l") || f == "-framework" || strings.Contains(f, "-framework") || strings.HasSuffix(f, ".a") || strings.HasSuffix(f, ".dylib") || strings.HasSuffix(f, ".so") || strings.Contains(f, ".dylib.") || strings.Contains(f, ".so.")
}

func hasExternalCgoMeta(p *listPkg) bool {
	return p != nil && (hasExternalCgo(p.CgoLDFLAGS) || len(p.CgoPkgConfig) > 0)
}

func hasCgoCallbackBlindspot(p *listPkg) bool {
	if p == nil {
		return false
	}
	for _, files := range [][]string{
		p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles,
		p.SwigFiles, p.SwigCXXFiles, p.SysoFiles,
	} {
		if len(files) > 0 {
			return true
		}
	}
	return false
}

func asmCallTargets(dir string, files []string, buildFlags ...string) ([]string, bool, bool, []string, error) {
	return asmCallTargetsObserved(nil, dir, files, buildFlags...)
}

func asmCallTargetsObserved(externalReason *string, dir string, files []string, buildFlags ...string) ([]string, bool, bool, []string, error) {
	var targets []string
	var includes []string
	computed := false
	opaque := false
	goFlags, err := buildflags.EffectiveGOFLAGS(dir)
	if err != nil {
		return nil, false, false, nil, err
	}
	externalDefines := asmExternalDefinesMayRewriteSymbols(buildFlags, goFlags)
	for _, f := range files {
		content, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return nil, false, false, nil, fmt.Errorf("closure: read asm %s: %w", filepath.Join(dir, f), err)
		}
		lines, includeOpaque, localIncludes, err := asmExpandedLines(dir, stripASMBlockComments(strings.Split(string(content), "\n")), map[string]bool{})
		if err != nil {
			return nil, false, false, nil, err
		}
		opaque = opaque || includeOpaque
		includes = append(includes, localIncludes...)
		macros := map[string]asmMacro{}
		var scanLines func([]string, map[string]bool) error
		scanLines = func(lines []string, stack map[string]bool) error {
			labels := asmLabels(lines)
			for _, raw := range lines {
				for _, line := range asmStatements(raw) {
					fields := normalizeASMPreprocessorFields(strings.Fields(line))
					macroUpdated, macroOpaque := updateASMMacros(fields, macros)
					opaque = opaque || macroOpaque
					if macroUpdated && !asmIncludeNeedsExpansion(fields) {
						continue
					}
					var expandOpaque bool
					fields, expandOpaque = expandASMFields(fields, macros)
					opaque = opaque || expandOpaque
					includeHandled, err := scanExpandedASMInclude(dir, fields, stack, func(path string) {
						includes = append(includes, path)
					}, func(expanded []string, stack map[string]bool) error {
						return scanLines(expanded, stack)
					}, func() {
						opaque = true
					})
					if err != nil {
						return err
					}
					if includeHandled {
						continue
					}
					macroUpdated, macroOpaque = updateASMMacros(fields, macros)
					opaque = opaque || macroOpaque
					if macroUpdated {
						continue
					}
					for _, stmt := range asmStatements(strings.Join(fields, " ")) {
						stmtFields := strings.Fields(stmt)
						if externalReason != nil && *externalReason == "" {
							opcode := asmOpcodeFromFields(stmtFields)
							if asmOpcodeReadsExternalState(opcode) {
								*externalReason = "reaches assembly instruction " + opcode + " (external runtime state)"
							} else if operand := asmExternalStateOperand(stmtFields); operand != "" {
								*externalReason = "reaches assembly operand " + operand + " (external runtime state)"
							}
						}
						target, isComputed, ok := asmTargetFromFields(stmtFields, labels, externalDefines)
						computed = computed || isComputed
						if ok {
							targets = append(targets, target)
						}
					}
				}
			}
			return nil
		}
		if err := scanLines(lines, map[string]bool{}); err != nil {
			return nil, false, false, nil, err
		}
	}
	return targets, computed, opaque, includes, nil
}

func asmExternalStateOperand(fields []string) string {
	if len(fields) < 2 {
		return ""
	}
	for _, field := range fields[1:] {
		upper := strings.ToUpper(strings.Trim(field, ",;"))
		for _, marker := range []string{"TLS", "FS", "GS"} {
			if upper == marker || strings.Contains(upper, "("+marker+")") {
				return marker
			}
		}
		open := strings.IndexByte(upper, '(')
		close := strings.IndexByte(upper, ')')
		if open >= 0 && close > open {
			base := upper[open+1 : close]
			if base == "SB" && strings.HasPrefix(upper, "$") && strings.Contains(upper, "·") {
				return "SB symbol address"
			}
			if base == "SB" {
				symbol := strings.TrimPrefix(upper[:open], "$")
				if dot := strings.Index(symbol, "·"); dot > 0 {
					return "cross-package SB symbol"
				}
			}
			switch base {
			case "SP", "FP", "SB", "PC":
				// Stack, frame, static, and program-relative addressing is
				// backed by source/runtime inputs already in the closure.
			default:
				return base
			}
		}
	}
	return ""
}

func scanExpandedASMInclude(dir string, fields []string, stack map[string]bool, addInclude func(string), scan func([]string, map[string]bool) error, markOpaque func()) (bool, error) {
	fields = normalizeASMPreprocessorFields(fields)
	if len(fields) == 0 || fields[0] != "#include" {
		return false, nil
	}
	if len(fields) < 2 || !asmIncludeOperandQuoted(fields) {
		return true, fmt.Errorf("closure: unresolved asm include in %s", dir)
	}
	path, local, ok := asmIncludePath(dir, strings.Trim(fields[1], "\""))
	if !ok {
		if isGeneratedASMInclude(strings.Trim(fields[1], "\"")) {
			return true, nil
		}
		return true, fmt.Errorf("closure: unresolved asm include %s", fields[1])
	}
	if local {
		addInclude(path)
	}
	if stack[path] {
		markOpaque()
		return true, nil
	}
	stack[path] = true
	content, err := os.ReadFile(path)
	if err != nil {
		delete(stack, path)
		markOpaque()
		return true, nil
	}
	expanded, childOpaque, childIncludes, err := asmExpandedLines(dir, stripASMBlockComments(strings.Split(string(content), "\n")), stack)
	if err != nil {
		delete(stack, path)
		return true, err
	}
	if childOpaque {
		markOpaque()
	}
	for _, child := range childIncludes {
		addInclude(child)
	}
	err = scan(expanded, stack)
	delete(stack, path)
	return true, err
}

func asmIncludeNeedsExpansion(fields []string) bool {
	return len(fields) >= 2 && fields[0] == "#include" && !asmIncludeOperandQuoted(fields)
}

func asmIncludeOperandQuoted(fields []string) bool {
	return len(fields) >= 2 && strings.HasPrefix(fields[1], "\"") && strings.HasSuffix(fields[1], "\"")
}

func asmTargetFromFields(fields []string, labels map[string]bool, externalDefines bool) (string, bool, bool) {
	fields = trimASMLabels(fields)
	if len(fields) < 2 {
		if asmSingleOpMayHideCall(fields) {
			return "", true, false
		}
		return "", false, false
	}
	if isASMIndirectCallOp(fields[0]) {
		// Register/computed-target call or jump (e.g. riscv64 `JALR RA, 0(T0)`,
		// mips `JR R5`): the callee is a runtime register value, never a parseable
		// symbol, so it is a computed call → widen to the maximal closure
		// (REQ-closure-blindspot). Without this, a ≥3-field indirect mnemonic falls through
		// asmUnknownOpMayHideCall's leaf return and its Go-function-pointer target
		// changes unhashed → false-valid.
		return "", true, false
	}
	if !isASMCallOp(fields[0]) {
		if asmUnknownOpMayHideCall(fields) {
			return "", true, false
		}
		return "", false, false
	}
	target := strings.TrimRight(fields[1], ",")
	sb := strings.Index(target, "(SB)")
	if sb < 0 {
		return "", !isLocalASMTarget(target, labels), false
	}
	if strings.HasPrefix(target, "*") || target[sb+len("(SB)"):] != "" {
		return "", true, false
	}
	target = strings.TrimSuffix(target[:sb], "+0")
	if strings.Contains(target, "+") {
		return "", true, false
	}
	if asmSymbolHasMacroLikeComponent(target, externalDefines) {
		return "", true, false
	}
	return target, false, true
}

func asmSymbolHasMacroLikeComponent(target string, externalDefines bool) bool {
	if i := strings.LastIndex(target, "·"); i >= 0 {
		if asmTokenLooksMacroLike(target[:i]) || asmExternalDefineMayRewriteSymbol(target[:i], externalDefines) {
			return true
		}
		target = target[i+len("·"):]
	}
	return asmTokenLooksMacroLike(target) || asmExternalDefineMayRewriteSymbol(target, externalDefines)
}

func asmExternalDefineMayRewriteSymbol(target string, externalDefines bool) bool {
	return externalDefines && asmTokenCanBeMacroName(target)
}

func asmExternalDefinesMayRewriteSymbols(buildFlags []string, goFlags string) bool {
	flags := strings.TrimSpace(strings.Join(buildFlags, " ") + " " + goFlags)
	return strings.Contains(flags, "-asmflags") && strings.Contains(flags, "-D")
}

func asmTokenCanBeMacroName(target string) bool {
	if target == "" {
		return false
	}
	for i, r := range target {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func asmTokenLooksMacroLike(target string) bool {
	if target == "" {
		return false
	}
	hasUpper := false
	for _, r := range target {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return hasUpper
}

func asmSingleOpMayHideCall(fields []string) bool {
	if len(fields) != 1 {
		return false
	}
	op := fields[0]
	if op == "" || strings.HasPrefix(op, "#") || isASMPseudoOp(op) || isASMKnownZeroOp(op) {
		return false
	}
	return true
}

func asmUnknownOpMayHideCall(fields []string) bool {
	if len(fields) < 2 || isASMPseudoOp(fields[0]) {
		return false
	}
	if len(fields) == 2 {
		return true
	}
	if strings.Contains(fields[0], "_") {
		return true
	}
	for _, field := range fields[1:] {
		if strings.Contains(strings.TrimRight(field, ","), "(SB)") {
			return true
		}
	}
	return false
}

func isASMKnownZeroOp(op string) bool {
	if i := strings.IndexByte(op, '.'); i >= 0 {
		op = op[:i]
	}
	switch op {
	case "RET", "NOP":
		return true
	}
	return false
}

func isASMPseudoOp(op string) bool {
	if i := strings.IndexByte(op, '.'); i >= 0 {
		op = op[:i]
	}
	switch op {
	case "TEXT", "DATA", "GLOBL", "FUNCDATA", "PCDATA":
		return true
	}
	return false
}

func trimASMLabels(fields []string) []string {
	for len(fields) > 0 {
		first := fields[0]
		if strings.HasSuffix(first, ":") {
			fields = fields[1:]
			continue
		}
		if i := strings.IndexByte(first, ':'); i > 0 {
			fields[0] = first[i+1:]
			if fields[0] == "" {
				fields = fields[1:]
			}
		}
		return fields
	}
	return fields
}

func isASMCallOp(op string) bool {
	if i := strings.IndexByte(op, '.'); i >= 0 {
		op = op[:i]
	}
	switch op {
	case "CALL", "JMP", "BL", "JAL", "B", "BR":
		return true
	}
	return false
}

// isASMIndirectCallOp reports whether op transfers control through a register or
// otherwise computed target across Go's target architectures. Such a mnemonic's
// callee is never a parseable symbol, so any occurrence is a computed call that
// must widen to the maximal closure (REQ-closure-blindspot) — listing them explicitly keeps
// ordinary data-processing instructions (which also carry register operands)
// precise instead of blanket-widening on every register operand.
func isASMIndirectCallOp(op string) bool {
	if i := strings.IndexByte(op, '.'); i >= 0 {
		op = op[:i]
	}
	switch op {
	case "JALR", "JIRL", "JR", "BLR", "BCTRL", "BCTR", "BX", "BLX", "BAL", "CALLIND":
		return true
	}
	return false
}

func asmStatements(line string) []string {
	line = strings.TrimSpace(stripASMLineComment(line))
	if line == "" || strings.HasPrefix(line, "#") {
		return []string{line}
	}
	parts := splitASMStatements(line)
	stmts := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			stmts = append(stmts, part)
		}
	}
	return stmts
}

func splitASMStatements(line string) []string {
	var parts []string
	inString := false
	escaped := false
	start := 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		if c == ';' {
			parts = append(parts, line[start:i])
			start = i + 1
		}
	}
	parts = append(parts, line[start:])
	return parts
}

func stripASMLineComment(line string) string {
	inString := false
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		if i+1 < len(line) && line[i:i+2] == "//" {
			return line[:i]
		}
	}
	return line
}

func asmExpandedLines(dir string, lines []string, stack map[string]bool) ([]string, bool, []string, error) {
	out := make([]string, 0, len(lines))
	var includes []string
	opaque := false
	for _, line := range lines {
		out = append(out, line)
		fields := normalizeASMPreprocessorFields(strings.Fields(strings.TrimSpace(stripASMLineComment(line))))
		if len(fields) < 2 || fields[0] != "#include" || !strings.HasPrefix(fields[1], "\"") || !strings.HasSuffix(fields[1], "\"") {
			continue
		}
		path, local, ok := asmIncludePath(dir, strings.Trim(fields[1], "\""))
		if !ok {
			if isGeneratedASMInclude(strings.Trim(fields[1], "\"")) {
				continue
			}
			return nil, false, nil, fmt.Errorf("closure: unresolved asm include %s", fields[1])
		}
		if local {
			includes = append(includes, path)
		}
		if stack[path] {
			opaque = true
			continue
		}
		stack[path] = true
		content, err := os.ReadFile(path)
		if err != nil {
			delete(stack, path)
			return nil, false, nil, fmt.Errorf("closure: read asm include %s: %w", path, err)
		}
		included, childOpaque, childIncludes, err := asmExpandedLines(dir, stripASMBlockComments(strings.Split(string(content), "\n")), stack)
		if err != nil {
			delete(stack, path)
			return nil, false, nil, err
		}
		opaque = opaque || childOpaque
		out = append(out, included...)
		includes = append(includes, childIncludes...)
		delete(stack, path)
	}
	return out, opaque, includes, nil
}

func stripASMBlockComments(lines []string) []string {
	out := make([]string, 0, len(lines))
	inComment := false
	for _, line := range lines {
		var b strings.Builder
		inString := false
		escaped := false
		for i := 0; i < len(line); {
			if inComment {
				end := strings.Index(line[i:], "*/")
				if end < 0 {
					break
				}
				i += end + len("*/")
				inComment = false
				continue
			}
			c := line[i]
			if inString {
				b.WriteByte(c)
				i++
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if c == '"' {
					inString = false
				}
				continue
			}
			if c == '"' {
				inString = true
				b.WriteByte(c)
				i++
				continue
			}
			if i+1 < len(line) && line[i:i+2] == "/*" {
				b.WriteByte(' ')
				inComment = true
				i += len("/*")
				continue
			}
			b.WriteByte(c)
			i++
		}
		out = append(out, b.String())
	}
	return out
}

func isGeneratedASMInclude(name string) bool {
	return name == "go_asm.h"
}

func hasGeneratedASMInclude(dir string, files []string) (bool, error) {
	for _, name := range files {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return false, fmt.Errorf("closure: read asm %s: %w", filepath.Join(dir, name), err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			fields := normalizeASMPreprocessorFields(strings.Fields(strings.TrimSpace(stripASMLineComment(line))))
			if len(fields) >= 2 && fields[0] == "#include" && asmIncludeOperandQuoted(fields) && isGeneratedASMInclude(strings.Trim(fields[1], "\"")) {
				return true, nil
			}
		}
	}
	return false, nil
}

func asmIncludePath(dir, name string) (string, bool, bool) {
	if symlinkDirInPath(name, dir) != "" {
		return "", false, false
	}
	if filepath.IsAbs(name) {
		if _, err := os.Stat(name); err == nil {
			return name, true, true
		}
		return "", false, false
	}
	local := filepath.Join(dir, name)
	if _, err := os.Stat(local); err == nil {
		return local, true, true
	}
	goroot := filepath.Join(runtime.GOROOT(), "pkg", "include", name)
	if _, err := os.Stat(goroot); err == nil {
		return goroot, false, true
	}
	return "", false, false
}

func parseASMMacroSpec(spec string) (string, bool, []string) {
	if i := strings.IndexByte(spec, '('); i >= 0 && strings.HasSuffix(spec, ")") {
		name := spec[:i]
		if name == "" {
			return "", false, nil
		}
		raw := strings.TrimSuffix(spec[i+1:], ")")
		if raw == "" {
			return name, true, nil
		}
		parts := strings.Split(raw, ",")
		params := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				return "", false, nil
			}
			params = append(params, p)
		}
		return name, true, params
	}
	if strings.ContainsAny(spec, "()") {
		return "", false, nil
	}
	return spec, false, nil
}

func updateASMMacros(fields []string, macros map[string]asmMacro) (bool, bool) {
	if len(fields) == 0 {
		return false, false
	}
	switch fields[0] {
	case "#define":
		if len(fields) >= 2 {
			if fields[len(fields)-1] == "\\" {
				return true, true
			}
			name, funcLike, params := parseASMMacroSpec(fields[1])
			if name != "" {
				macros[name] = asmMacro{funcLike: funcLike, params: params, body: strings.Join(fields[2:], " ")}
			} else {
				return true, true
			}
		}
		return true, false
	case "#undef":
		if len(fields) >= 2 {
			delete(macros, fields[1])
		}
		return true, false
	case "#include":
		return true, false
	case "#if", "#ifdef", "#ifndef", "#elif", "#else", "#endif":
		return true, true
	}
	return false, false
}

func normalizeASMPreprocessorFields(fields []string) []string {
	if len(fields) >= 2 && fields[0] == "#" {
		out := make([]string, 0, len(fields)-1)
		out = append(out, "#"+fields[1])
		out = append(out, fields[2:]...)
		return out
	}
	return fields
}

func expandASMMacro(token string, macros map[string]asmMacro) (string, bool, bool) {
	if m, ok := macros[token]; ok && !m.funcLike {
		return m.body, true, false
	}
	open := strings.IndexByte(token, '(')
	if open < 0 || !strings.HasSuffix(token, ")") {
		return "", false, false
	}
	m, ok := macros[token[:open]]
	if !ok || !m.funcLike {
		return "", false, false
	}
	raw := strings.TrimSuffix(token[open+1:], ")")
	args, ok := parseASMMacroArgs(raw)
	if !ok {
		return "", false, true
	}
	if len(args) != len(m.params) {
		return "", false, true
	}
	body := m.body
	for i, p := range m.params {
		body = replaceASMMacroParam(body, p, strings.TrimSpace(args[i]))
	}
	return body, true, false
}

func parseASMMacroArgs(raw string) ([]string, bool) {
	if raw == "" {
		return nil, true
	}
	var args []string
	depth := 0
	start := 0
	for i, r := range raw {
		switch r {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return nil, false
			}
			depth--
		case ',':
			if depth == 0 {
				args = append(args, raw[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, false
	}
	args = append(args, raw[start:])
	return args, true
}

func expandASMFields(fields []string, macros map[string]asmMacro) ([]string, bool) {
	for depth := 0; depth < 64; depth++ {
		expanded := false
		for i := range fields {
			repl, consumed, ok, macroOpaque := expandASMMacroAt(fields, i, macros)
			if macroOpaque {
				return fields, true
			}
			if !ok {
				continue
			}
			replFields := strings.Fields(repl)
			next := make([]string, 0, len(fields)+len(replFields)-consumed)
			next = append(next, fields[:i]...)
			next = append(next, replFields...)
			next = append(next, fields[i+consumed:]...)
			fields = next
			expanded = true
			break
		}
		if !expanded {
			return fields, false
		}
	}
	return fields, true
}

func expandASMMacroAt(fields []string, i int, macros map[string]asmMacro) (string, int, bool, bool) {
	if repl, ok, opaque := expandASMMacro(fields[i], macros); opaque {
		return "", 0, false, true
	} else if ok {
		return repl, 1, true, false
	}
	if repl, ok, opaque := expandASMSymbolMacro(fields[i], macros); opaque {
		return "", 0, false, true
	} else if ok {
		return repl, 1, true, false
	}
	token := fields[i]
	consumed := 1
	if !strings.Contains(token, "(") && i+1 < len(fields) && strings.HasPrefix(fields[i+1], "(") {
		token += fields[i+1]
		consumed = 2
	}
	for strings.Contains(token, "(") && !strings.HasSuffix(token, ")") && i+consumed < len(fields) {
		token += fields[i+consumed]
		consumed++
	}
	if repl, ok, opaque := expandASMMacro(token, macros); opaque {
		return "", 0, false, true
	} else if ok {
		return repl, consumed, true, false
	}
	return "", 0, false, false
}

func expandASMSymbolMacro(field string, macros map[string]asmMacro) (string, bool, bool) {
	suffix := ""
	if strings.HasSuffix(field, ",") {
		suffix = ","
		field = strings.TrimSuffix(field, ",")
	}
	i := strings.LastIndex(field, "·")
	sb := strings.Index(field, "(SB)")
	if i < 0 || sb < 0 || i > sb {
		return "", false, false
	}
	if repl, ok, opaque := expandASMSymbolPrefixMacro(field, i, macros); opaque {
		return "", false, true
	} else if ok {
		return repl + suffix, true, false
	}
	name := field[i+len("·") : sb]
	if strings.ContainsAny(name, "+<") {
		return "", false, false
	}
	m, ok := macros[name]
	if !ok {
		return "", false, false
	}
	if m.funcLike {
		return "", false, true
	}
	body := strings.Fields(m.body)
	if len(body) != 1 || strings.ContainsAny(body[0], "·()+<>,") {
		return "", false, true
	}
	return field[:i+len("·")] + body[0] + field[sb:] + suffix, true, false
}

func expandASMSymbolPrefixMacro(field string, dot int, macros map[string]asmMacro) (string, bool, bool) {
	prefix := field[:dot]
	if prefix == "" || strings.ContainsAny(prefix, "*()+<>,") {
		return "", false, false
	}
	m, ok := macros[prefix]
	if !ok {
		return "", false, false
	}
	if m.funcLike {
		return "", false, true
	}
	body := strings.Fields(m.body)
	if len(body) != 1 || strings.ContainsAny(body[0], "·()+<>,") {
		return "", false, true
	}
	return body[0] + field[dot:], true, false
}

func replaceASMMacroParam(body, param, arg string) string {
	fields := strings.Fields(body)
	for i, field := range fields {
		fields[i] = replaceASMMacroParamField(field, param, arg)
	}
	return strings.Join(fields, " ")
}

func replaceASMMacroParamField(field, param, arg string) string {
	suffix := ""
	if strings.HasSuffix(field, ",") {
		suffix = ","
		field = strings.TrimSuffix(field, ",")
	}
	if field == param {
		return arg + suffix
	}
	if open := strings.IndexByte(field, '('); open > 0 && strings.HasSuffix(field, ")") {
		inner := strings.TrimSuffix(field[open+1:], ")")
		if inner == param {
			return field[:open+1] + arg + ")" + suffix
		}
	}
	if i := strings.LastIndex(field, "·"); i >= 0 {
		if field[:i] == param {
			return arg + field[i:] + suffix
		}
		rest := field[i+len("·"):]
		if end := strings.Index(rest, "(SB)"); end >= 0 {
			name := rest[:end]
			if name == param {
				return field[:i+len("·")] + arg + rest[end:] + suffix
			}
			if strings.HasPrefix(name, param+"+") {
				return field[:i+len("·")] + arg + name[len(param):] + rest[end:] + suffix
			}
		}
	}
	if end := strings.Index(field, "(SB)"); end > 0 {
		if field[:end] == param {
			return arg + field[end:] + suffix
		}
	}
	return field + suffix
}

func asmLabels(lines []string) map[string]bool {
	labels := map[string]bool{}
	for _, line := range lines {
		line = strings.TrimSpace(stripASMLineComment(line))
		if i := strings.IndexByte(line, ':'); i > 0 {
			label := strings.TrimSpace(line[:i])
			if label != "" && !strings.ContainsAny(label, " \t") {
				labels[label] = true
			}
		}
	}
	return labels
}

func isLocalASMTarget(target string, labels map[string]bool) bool {
	if labels[target] || strings.HasSuffix(target, "(PC)") {
		return true
	}
	if target == "" {
		return false
	}
	if last := target[len(target)-1]; last == 'b' || last == 'f' {
		target = target[:len(target)-1]
	}
	if target == "" {
		return false
	}
	for _, r := range target {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isStdImportPath(path string) bool {
	if path == "" || path == "C" {
		return false
	}
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	return !strings.Contains(first, ".")
}

func isBenchmarkHarnessPath(path string) bool {
	return path == "testing" || strings.HasPrefix(path, "testing/")
}
