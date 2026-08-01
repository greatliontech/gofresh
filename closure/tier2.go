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
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// program is the loaded whole-program SSA for one package's test binary, cached
// so per-benchmark Compute calls amortize the dominant load cost (REQ-closure-analysis).
type program struct {
	pkgPath string
	prog    *ssa.Program
	pkgs    []*packages.Package
	roots   map[string]*ssa.Function // benchmark function name → its SSA function
	// ambiguous names two distinct top-level functions (the in-package
	// and external test packages may legally share a name): the root is
	// tombstoned and a subject requesting the name degrades to
	// unavailable evidence for that subject alone.
	ambiguous map[string]bool
	testMain  *ssa.Function
}

// parameterizedBody reports whether fn's body is generic (uninstantiated):
// its types are open over type parameters, so it is not a runtime dispatch
// surface the attributed walk can visit (REQ-closure-analysis: each
// instantiation dispatches concretely). The RecvTypeParams arm is deliberate
// redundancy: ssa.Function.TypeParams covers method origins today, and the
// belt guards an upstream representation change - the generic-method row
// pins the behavior either way.
func parameterizedBody(fn *ssa.Function) bool {
	return fn != nil && (fn.TypeParams().Len() > 0 || (fn.Signature != nil && fn.Signature.RecvTypeParams() != nil))
}

// loadCached loads (once) and returns the whole-program SSA for pkgPath. Load
// failures are memoized for the Hasher's lifetime alongside successes: one
// analysis observes one load outcome per package, so retrying subjects of a
// failing package never repeats its failing load.
func (h *Hasher) loadCached(pkgPath string) (*program, error) {
	if p, ok := h.progs[pkgPath]; ok {
		return p, nil
	}
	if err, ok := h.progErrs[pkgPath]; ok {
		return nil, err
	}
	h.emitProgress("load", pkgPath)
	p, err := loadEnv(h.ctx, h.dir, h.packageEnv, h.buildFlags, pkgPath)
	if err != nil {
		if h.ctx.Err() == nil {
			h.progErrs[pkgPath] = err
		}
		return nil, err
	}
	h.progs[pkgPath] = p
	return p, nil
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

func loadEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPath string) (*program, error) {
	roots, err := packages.Load(loadConfigEnv(ctx, dir, env, buildFlags...), pkgPath)
	if err != nil {
		return nil, fmt.Errorf("closure: load %s: %w", pkgPath, err)
	}
	return buildProgram(ctx, pkgPath, roots)
}

// buildProgram builds whole-program SSA for one package's test binary from its
// root packages (generics instantiated, so RTA traverses real edges through std
// and dispatches generic instantiations concretely). A load error is fatal — a
// partial program could miss reachable code and report a stale result valid
// (REQ-fresh-sound).
func buildProgram(ctx context.Context, pkgPath string, roots []*packages.Package) (*program, error) {
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
	return &program{pkgPath: pkgPath, prog: prog, pkgs: all, roots: funcRoots, ambiguous: ambiguousRoots, testMain: testMain}, nil
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

// Observability is the complete subject-tier disposition for runtime-input
// observation. Observable is true only when every reachable effect is admitted.
type Observability struct {
	Observable bool
	Reason     string
}

const maxAttributedSubjects = 64

// packageBatch groups one package's requested subjects for shared analysis.
type packageBatch struct {
	path     string
	subjects []Subject
}

// ComputeObservabilityBatch computes caller-selected per-subject observation
// proofs, sharing the loaded program, attributed reachability masks, and
// package effect scans across each package's subjects. Every disposition
// equals independent per-subject analysis
// (REQ-closure-observability-batch-equivalence).
func (h *Hasher) ComputeObservabilityBatch(subjects []Subject) (map[Subject]Observability, error) {
	results := make(map[Subject]Observability, len(subjects))
	byPackage := map[string]*packageBatch{}
	var groups []*packageBatch
	seen := map[Subject]bool{}
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
		// Memoized proofs serve before any program load: the proof is a
		// pure function of (scope, package test-binary closure), so a hit
		// under the complete key is byte-equivalent to recomputation
		// (REQ-closure-observability-memo). A full-group hit skips the
		// SSA build entirely.
		closureHash, memoized := h.groupMemo(group.path)
		if len(memoized) > 0 {
			remaining := group.subjects[:0:0]
			for _, subject := range group.subjects {
				if proof, ok := memoized[subject.Symbol]; ok {
					results[subject] = proof
					continue
				}
				remaining = append(remaining, subject)
			}
			group.subjects = remaining
			if len(group.subjects) == 0 {
				continue
			}
		}
		h.emitProgress("prove", group.path)
		prog, err := h.loadCached(group.path)
		if err != nil {
			return nil, err
		}
		// A symbol absent from the loaded program's roots is a subject-local
		// fact — a production symbol can be unreachable as a root of its
		// external-test binary — so it degrades to an unavailable proof for
		// that subject alone and never denies a sibling's analysis.
		unrooted := map[string]Observability{}
		rooted := group.subjects[:0:0]
		for _, subject := range group.subjects {
			if prog.roots[subject.Symbol] == nil {
				reason := fmt.Sprintf("observation analysis unavailable: subject %s not found in %s", subject.Symbol, group.path)
				if prog.ambiguous[subject.Symbol] {
					reason = fmt.Sprintf("observation analysis unavailable: subject name %s is ambiguous in %s (declared by both the package and its external test package)", subject.Symbol, group.path)
				}
				proof := Observability{Reason: reason}
				results[subject] = proof
				unrooted[subject.Symbol] = proof
				continue
			}
			rooted = append(rooted, subject)
		}
		group.subjects = rooted
		if len(group.subjects) == 0 {
			if h.memoScope != "" && closureHash != "" {
				storeMemo(h.memoScope, closureHash, unrooted)
			}
			continue
		}
		metas, err := h.list(group.path)
		if err != nil {
			return nil, err
		}
		base := newTier2Base(h, prog, metas)
		computed := unrooted
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
				result, err := h.observabilityFromReachability(base, subject.Package, reachable[i])
				if err != nil {
					return nil, err
				}
				results[subject] = result
				computed[subject.Symbol] = result
			}
		}
		if h.memoScope != "" && closureHash != "" {
			storeMemo(h.memoScope, closureHash, computed)
		}
	}
	if err := h.ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	return results, nil
}

// observabilityFromReachability classifies one subject's attributed
// reachability exactly as independent analysis would: startup effects, then
// closure of the subject world, then package-level blockers, then the
// subject's own effect set (REQ-closure-observability-analysis).
func (h *Hasher) observabilityFromReachability(base *tier2Base, pkgPath string, reach attributedReachability) (Observability, error) {
	subjectReach := reach
	subjectReach.functions = subjectReach.subjectFunctions
	subjectResult, err := h.tier2ReachableWithFresh(base, subjectReach, true)
	if err != nil {
		return Observability{}, err
	}
	startupReach := reach
	startupReach.functions = nonStandardFunctions(startupReach.startupFunctions)
	startupResult := directExternalEffects(base, startupReach)
	if startupResult.unverifiable {
		reason := startupResult.reason
		if reason == "" {
			reason = "external dependence"
		}
		return Observability{Reason: "startup effect: " + reason}, nil
	}
	if subjectResult.widen || subjectReach.openWorld {
		reason := subjectResult.widenReason
		if reason == "" {
			reason = "open subject world"
		}
		return Observability{Reason: "subject reachability is not closed: " + reason}, nil
	}
	maximalEffects, _, err := h.maximalExternalEffects(pkgPath)
	if err != nil {
		return Observability{}, err
	}
	for _, effect := range maximalEffects {
		if maximalObservabilityBlocker(effect) {
			// The tier names itself: a package-scan block is the
			// whole-package negative backstop, not the subject's own
			// attributed flow — measurably distinct, so a corpus can
			// tell how often the backstop alone costs a proof the walk
			// would grant.
			return Observability{Reason: "package scan: " + effect.reason}, nil
		}
	}
	for _, effect := range subjectResult.effects {
		if !effect.observable {
			return Observability{Reason: effect.reason}, nil
		}
	}
	return Observability{Observable: true}, nil
}

func directExternalEffects(base *tier2Base, reachable attributedReachability) tier2Result {
	analyzer := base.analyzer()
	for function := range reachable.functions {
		idx := analyzer.idxForFunction(function)
		if idx == nil || idx.std || idx.testMain {
			continue
		}
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				callee := site.Common().StaticCallee()
				if callee != nil {
					recordDirectCallEffect(analyzer, callee, site)
				}
				for target := range reachable.dynamicTargets[site] {
					if observableDirEntryCall(site) {
						continue
					}
					recordDirectCallEffect(analyzer, target, site)
				}
			}
		}
	}
	return analyzer.result()
}

func recordDirectCallEffect(analyzer *tier2Analyzer, callee *ssa.Function, site ssa.CallInstruction) {
	if analyzer == nil || callee == nil || observableFileMethod(callee) || observableDirEntryCall(site) || isTestingMRun(callee) {
		return
	}
	pkgPath := funcPkgPath(callee)
	name := callee.Name()
	if object := callee.Object(); object != nil {
		name = object.Name()
	}
	effect, classified := classBEffect(pkgPath, name)
	calleeIdx := analyzer.idxForFunction(callee)
	if !classified && name != "init" && calleeIdx != nil && calleeIdx.std && !isRefinementSourceOnlyStandardPackage(pkgPath) && !classBPureStandard(pkgPath, name) {
		effect = symbolExternalEffect(externalEffectUnauditedStandard, pkgPath, name, "reaches unaudited standard operation "+pkgPath+"."+name)
		classified = true
	}
	if osOpenFileMayMutate(callee, pkgPath, name, site.Common()) {
		effect = symbolExternalEffect(externalEffectFilesystemMutation, pkgPath, name, "reaches os.OpenFile (filesystem mutation)")
		classified = true
	}
	if !classified && syscallOpenMayCreate(pkgPath, name, site.Common()) {
		effect = symbolExternalEffect(externalEffectFilesystemMutation, pkgPath, name, "reaches "+pkgPath+"."+name+" (filesystem mutation)")
		classified = true
	}
	if classified {
		analyzer.recordExternalEffect(effect)
	}
}

func nonStandardFunctions(functions map[*ssa.Function]bool) map[*ssa.Function]bool {
	filtered := make(map[*ssa.Function]bool)
	for function := range functions {
		if !isStdImportPath(funcPkgPath(function)) {
			filtered[function] = true
		}
	}
	return filtered
}

func maximalObservabilityBlocker(effect externalEffect) bool {
	if effect.packagePath == "testing" && effect.symbol == "Run" {
		return false
	}
	// The subject tier classifies the guard-pinned toolchain accessor
	// precisely; the maximal AST scan must not pre-block it.
	if effect.packagePath == "runtime" && effect.symbol == "GOROOT" {
		return false
	}
	if effect.packagePath == "testing" && effect.symbol == "TempDir" {
		return false
	}
	if effect.packagePath == "path/filepath" && effect.symbol == "Join" {
		return false
	}
	if effect.packagePath == "os" && isOpenFlagSymbol(effect.symbol) {
		return false
	}
	if effect.packagePath == "os" {
		switch effect.symbol {
		case "Getenv", "LookupEnv", "Open", "OpenFile", "ReadFile", "ReadDir", "WriteFile", "Remove", "RemoveAll":
			return false
		}
	}
	return true
}

func isOpenFlagSymbol(symbol string) bool {
	switch symbol {
	case "O_RDONLY", "O_WRONLY", "O_RDWR", "O_APPEND", "O_CREATE", "O_EXCL", "O_SYNC", "O_TRUNC":
		return true
	default:
		return false
	}
}

type tier2Result struct {
	contribs     []string
	effects      []externalEffect
	widen        bool
	widenReason  string
	unverifiable bool
	reason       string
}

type attributedReachability struct {
	functions        map[*ssa.Function]bool
	subjectFunctions map[*ssa.Function]bool
	startupFunctions map[*ssa.Function]bool
	resolved         map[ssa.CallInstruction]bool
	dynamicTargets   map[ssa.CallInstruction]map[*ssa.Function]bool
	// instantiatedOrigins marks parameterized origins whose materialized
	// instantiations were rooted for this subject: the origin's body
	// scan yields to theirs.
	instantiatedOrigins map[*ssa.Function]bool
	openWorld           bool
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
	var allFunctions map[*ssa.Function]bool
	instantiated := map[uint64]map[*ssa.Function]bool{}
	for i, subject := range subjects {
		mask := uint64(1) << i
		root := prog.roots[subject.Symbol]
		// A parameterized body is open over type parameters and cannot
		// enter the runtime-type walk (REQ-closure-analysis): it is never
		// a traversal root itself. A constraint-bounded generic instead
		// roots every materialized instantiation - each dispatches
		// concretely, so instantiation-reached content enters the
		// subject's reachable set (and through it the observability
		// effect walk). An unbounded generic roots
		// nothing: its signature reads open-world and
		// observability refuses; either way the origin fold below keeps
		// the declaration in the subject's content.
		switch {
		case !parameterizedBody(root):
			roots[root] |= mask
		case !rootMayReceiveUnknownDynamic(prog, root):
			if allFunctions == nil {
				allFunctions = ssautil.AllFunctions(prog.prog)
			}
			for fn := range allFunctions {
				if fn != nil && fn != root && fn.Origin() == root {
					roots[fn] |= mask
					// The origin's own body scan yields to the rooted
					// instantiations': each dispatches concretely, so
					// scanning the open-over-T origin beside them would
					// re-widen exactly the sites the rooting resolves.
					if instantiated[mask] == nil {
						instantiated[mask] = map[*ssa.Function]bool{}
					}
					instantiated[mask][root] = true
				}
			}
		}
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
	// Fold each parameterized origin into the result under its subject's
	// mask: its declaration is the subject's own source — the subject's
	// content must move when the generic body moves — while its body was
	// never traversed.
	for i, subject := range subjects {
		if origin := prog.roots[subject.Symbol]; parameterizedBody(origin) {
			res.Reachable[origin] |= uint64(1) << i
		}
	}
	reachable := make([]attributedReachability, len(subjects))
	for i := range reachable {
		reachable[i] = attributedReachability{
			functions:           make(map[*ssa.Function]bool),
			resolved:            make(map[ssa.CallInstruction]bool),
			dynamicTargets:      make(map[ssa.CallInstruction]map[*ssa.Function]bool),
			instantiatedOrigins: instantiated[uint64(1)<<i],
			openWorld:           rootMayReceiveUnknownDynamic(prog, prog.roots[subjects[i].Symbol]),
		}
		mask := uint64(1) << i
		subjectRoot := prog.roots[subjects[i].Symbol]
		startupRoots := make([]*ssa.Function, 0, len(prog.prog.AllPackages())+1)
		if prog.testMain != nil && subjectRunsThroughHarness(prog, subjectRoot) {
			startupRoots = append(startupRoots, prog.testMain)
		}
		for _, p := range prog.prog.AllPackages() {
			if isGeneratedTestMainPackage(prog, p) {
				continue
			}
			if init := p.Func("init"); init != nil {
				startupRoots = append(startupRoots, init)
			}
		}
		// The subject's provenance roots are exactly the roots its mask
		// was given: for a bounded generic those are its materialized
		// instantiations, so the effect walk sees every dispatch-reached
		// site the subject's reachable set carries — granting observability from
		// the origin alone would answer without ever seeing them
		// (REQ-closure-analysis's parameterized-subject arm,
		// REQ-closure-observability-analysis).
		subjectProvenance := []*ssa.Function{subjectRoot}
		if len(instantiated[mask]) > 0 {
			subjectProvenance = subjectProvenance[:0]
			for fn := range allFunctions {
				if fn != nil && fn != subjectRoot && fn.Origin() == subjectRoot {
					subjectProvenance = append(subjectProvenance, fn)
				}
			}
		}
		reachable[i].subjectFunctions, err = provenanceReachable(ctx, subjectProvenance, mask, res)
		if err != nil {
			return nil, err
		}
		reachable[i].startupFunctions, err = provenanceReachable(ctx, startupRoots, mask, res)
		if err != nil {
			return nil, err
		}
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
			callee := site.Common().StaticCallee()
			if !reachable[i].functions[site.Parent()] || callee != nil && funcPkgPath(callee) == "testing" {
				continue
			}
			for target, masks := range targets {
				if masks&mask != 0 && reachable[i].functions[target] {
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

func provenanceReachable(ctx context.Context, roots []*ssa.Function, mask uint64, result *attributedRTAResult) (map[*ssa.Function]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reachable := make(map[*ssa.Function]bool)
	scanned := make(map[*ssa.Function]bool)
	queue := append([]*ssa.Function(nil), roots...)
	for len(queue) != 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fn := queue[0]
		queue = queue[1:]
		if fn == nil || scanned[fn] || result.Reachable[fn]&mask == 0 {
			continue
		}
		scanned[fn] = true
		testingFunction := funcPkgPath(fn) == "testing"
		if !testingFunction {
			reachable[fn] = true
		}
		for _, block := range fn.Blocks {
			for _, instruction := range block.Instrs {
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				callee := site.Common().StaticCallee()
				if isTestingMRun(callee) {
					continue
				}
				if callee != nil {
					calleeTesting := funcPkgPath(callee) == "testing"
					if !testingFunction || calleeTesting {
						queue = append(queue, callee)
					}
					if calleeTesting && !testingFunction {
						continue
					}
				}
				for target, targetMask := range result.Targets[site] {
					if targetMask&mask == 0 || isTestingMRun(target) {
						continue
					}
					targetTesting := funcPkgPath(target) == "testing"
					if !testingFunction || targetTesting || !isStdImportPath(funcPkgPath(target)) {
						queue = append(queue, target)
					}
				}
			}
		}
	}
	return reachable, nil
}

func isTestingMRun(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	if strings.Contains(fn.String(), "testing.M).Run") {
		return true
	}
	if fn.Signature == nil || fn.Signature.Recv() == nil {
		return false
	}
	if funcPkgPath(fn) != "testing" || fn.Name() != "Run" {
		return false
	}
	return strings.Contains(types.TypeString(fn.Signature.Recv().Type(), nil), "testing.M")
}

func rootMayReceiveUnknownDynamic(prog *program, root *ssa.Function) bool {
	if root == nil || root.Signature == nil {
		return true
	}
	// A parameterized subject's openness is decided by its constraints,
	// consulted on the type-parameter list itself - a zero-parameter
	// generic (func Value[T any]() int) reads closed through Params
	// alone, so the params walk below can never be the whole answer. A
	// constraint that provably bounds its type set away from dynamic
	// carriers closes the caller's instantiation choice: every in-binary
	// instantiation then dispatches concretely and roots the walk.
	// Anything unbounded (any, comparable, a method-bearing constraint)
	// keeps the forced open world
	// (REQ-closure-analysis's parameterized-subject arm).
	if parameterizedBody(root) && !typeParamListsBoundAwayFromDynamic(root) {
		return true
	}
	if subjectRunsThroughHarness(prog, root) && isHarnessSubjectSignature(root.Signature) {
		return false
	}
	// One fresh map per parameter: sharing across parameters would let
	// one walk's marks short-circuit another's (a constraint interface
	// marked by a bounding evaluation reading clean as a later value
	// type); within one parameter's evaluation the map is shared - the
	// cycle guard for recursive constraints.
	if recv := root.Signature.Recv(); recv != nil && typeMayCarryDynamic(recv.Type(), make(map[types.Type]bool)) {
		return true
	}
	params := root.Signature.Params()
	for i := 0; params != nil && i < params.Len(); i++ {
		if typeMayCarryDynamic(params.At(i).Type(), make(map[types.Type]bool)) {
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
		// The evaluation's own map is shared into the bounding walk: the
		// marks placed at each walk's entry are the cycle guards for
		// self- and mutually-referential constraints (~[]A on A is legal
		// Go). The interface-mark cut decides the recursive cases -
		// pessimistically, not-bounded, so a recursive constraint reads
		// open; the type-parameter mark's clean cut only governs term
		// structure inside one evaluation, where a carrier-free cycle
		// path adds no carrier. Cross-parameter decoupling lives at the
		// walk entries, which hand each parameter a fresh map.
		return !constraintBoundsAwayFromDynamic(t.Constraint(), seen)
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

// TypeParamBoundsAwayFromDynamic reports whether one type parameter's
// constraint provably bounds its type set away from dynamic carriers -
// the openness question a parameterized subject asks per parameter,
// shared with the view tier so both tiers give one answer
// (REQ-closure-analysis's parameterized-subject arm).
func TypeParamBoundsAwayFromDynamic(tp *types.TypeParam) bool {
	if tp == nil {
		return false
	}
	return constraintBoundsAwayFromDynamic(tp.Constraint(), make(map[types.Type]bool))
}

// typeParamListsBoundAwayFromDynamic reports whether every type parameter
// of fn (function and receiver lists both) carries a constraint that
// provably bounds its type set away from dynamic carriers.
func typeParamListsBoundAwayFromDynamic(fn *ssa.Function) bool {
	for _, list := range []*types.TypeParamList{fn.TypeParams(), fn.Signature.RecvTypeParams()} {
		for i := 0; list != nil && i < list.Len(); i++ {
			if !constraintBoundsAwayFromDynamic(list.At(i).Constraint(), make(map[types.Type]bool)) {
				return false
			}
		}
	}
	return true
}

// constraintBoundsAwayFromDynamic reports whether a type parameter's
// constraint provably bounds its type set away from dynamic carriers: the
// complete interface is methodless (a constraint method is a dispatch
// surface this analysis does not narrow), and at least one embedded
// element bounds the set - a union or specific type whose every term is
// free of interface, function, channel, and unsafe reach, or an embedded
// interface that itself bounds. Intersection semantics make one clean
// bounded element sufficient: the type set is the intersection of every
// element's set, so a dirty sibling only shrinks a clean bound, never
// widens it. `any` and `comparable` embed nothing and bound nothing.
func constraintBoundsAwayFromDynamic(constraint types.Type, seen map[types.Type]bool) bool {
	iface, ok := types.Unalias(constraint).Underlying().(*types.Interface)
	if !ok {
		return false
	}
	return interfaceBoundsAwayFromDynamic(iface, seen)
}

func interfaceBoundsAwayFromDynamic(iface *types.Interface, seen map[types.Type]bool) bool {
	if iface == nil || iface.NumMethods() > 0 {
		return false
	}
	if seen[iface] {
		return false
	}
	seen[iface] = true
	bounded := false
	for i := 0; i < iface.NumEmbeddeds(); i++ {
		switch e := types.Unalias(iface.EmbeddedType(i)).(type) {
		case *types.Union:
			clean := true
			for j := 0; j < e.Len(); j++ {
				// A tilde term (~T) admits every type whose underlying
				// is T's underlying: structurally identical carriers, so
				// the structural walk of the term type answers for the
				// whole approximation set. Extra methods on a defined
				// type in that set are unreachable through a methodless
				// constraint.
				if typeMayCarryDynamic(e.Term(j).Type(), seen) {
					clean = false
					break
				}
			}
			if clean {
				bounded = true
			}
		default:
			if under, ok := types.Unalias(e).Underlying().(*types.Interface); ok {
				if interfaceBoundsAwayFromDynamic(under, seen) {
					bounded = true
				}
				continue
			}
			// A single specific-type element (interface{ int }).
			if !typeMayCarryDynamic(e, seen) {
				bounded = true
			}
		}
	}
	return bounded
}

func isGeneratedTestMainPackage(prog *program, pkg *ssa.Package) bool {
	return prog != nil && pkg != nil && pkg.Pkg != nil && pkg.Pkg.Name() == "main" && pkg.Pkg.Path() == prog.pkgPath+".test"
}

// tier2ReachableWithFresh optionally carries the cross-boundary
// fresh-path analysis: only the observability walk consults
// effect.observable, so withFresh=false skips the sweep (a
// test-driver configuration; every production proof passes true).
func (h *Hasher) tier2ReachableWithFresh(base *tier2Base, reachable attributedReachability, withFresh bool) (tier2Result, error) {
	a := base.analyzer()
	a.rtaResolved = reachable.resolved
	a.skipOriginScan = reachable.instantiatedOrigins
	a.openWorld = reachable.openWorld
	if withFresh {
		a.fresh = newFreshParamAnalysis(reachable)
	}
	if err := a.addLinkedCacheModules(); err != nil {
		return tier2Result{}, err
	}
	for site, targets := range reachable.dynamicTargets {
		if !reachable.functions[site.Parent()] {
			continue
		}
		callerIdx := a.idxForFunction(site.Parent())
		if callerIdx == nil || callerIdx.testMain {
			continue
		}
		for target := range targets {
			if observableDirEntryCall(site) {
				continue
			}
			idx := a.idxForFunction(target)
			if idx == nil || !idx.std {
				continue
			}
			effect, ok := classBEffectForFunction(target)
			if !ok && !callerIdx.std && !isSourceOnlyStandardPackage(idx.path) {
				effect = symbolExternalEffect(externalEffectUnauditedStandard, idx.path, target.Name(), "reaches unaudited standard operation "+idx.path+"."+target.Name())
				ok = true
			}
			if ok {
				a.recordExternalEffect(effect)
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
	objByName        map[string]types.Object
	objsByLinkTarget map[string][]types.Object
}

type tier2Analyzer struct {
	h          *Hasher
	buildFlags []string
	prog       *program
	metas      []listPkg
	metaByPath map[string]*listPkg
	// skipOriginScan marks parameterized origins whose rooted
	// instantiations carry the concrete forms of every site: the
	// open-over-T origin body is never scanned, whatever path reaches it
	// (the reach loop, the object drain, a static-callee walk) - its
	// declaration still contributes.
	skipOriginScan   map[*ssa.Function]bool
	idxByTypes       map[*types.Package]*pkgIndex
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
	// fresh carries the subject's cross-boundary fresh-path analysis;
	// nil outside per-subject reachability walks (maximal tier,
	// startup effects), where the intraprocedural grammar alone applies.
	fresh       *freshParamAnalysis
	openWorld   bool
	scanned     map[*ssa.Function]bool
	seenContrib map[string]bool
	contribs    []string
	effects     []externalEffect

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
	if fn == nil || a.skipOriginScan[fn] {
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
	classified, classifiedOK := classBEffectForFunction(fn)
	suppressNestedFileIO := idx.std && classifiedOK && classified.kind == externalEffectFileIO
	if !idx.std && idx.wasmImport {
		effect := opaqueExternalEffect(externalEffectLinkage, "reaches go:wasmimport")
		effect.unrefinable = true
		a.recordExternalEffect(effect)
	}
	if idx.cache && hasExternalCgoMeta(idx.meta) {
		effect := opaqueExternalEffect(externalEffectNative, "reaches cgo external library")
		effect.unrefinable = true
		a.recordExternalEffect(effect)
	}
	if idx.cache {
		a.scanCacheFunctionRefs(idx, fn)
	}
	if idx.std && (classifiedOK && classified.kind == externalEffectFileIO || atomicObservabilityOperation(fn)) {
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
				if !idx.std && typeUsesUnsafePointer(v.Type()) && !isOSFileType(v.Type()) {
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

func atomicObservabilityOperation(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	pkgPath, name := funcPkgPath(fn), fn.Name()
	if object := fn.Object(); object != nil {
		name = object.Name()
	}
	if pkgPath == "testing" && name == "TempDir" || pkgPath == "path/filepath" && name == "Join" {
		return true
	}
	if pkgPath == "os" {
		switch name {
		case "WriteFile", "Remove", "RemoveAll":
			return true
		}
	}
	return false
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
	if typeUsesUnsafePointer(v.Type()) && !isOSFileType(v.Type()) {
		if idx := a.idxForFunction(v.Parent()); idx != nil && !idx.std {
			a.requestWiden("unsafe pointer reachable in " + idx.id)
		}
	}
	switch x := v.(type) {
	case *ssa.Global:
		if obj := x.Object(); obj != nil {
			// No source-only exemption here, deliberately: the
			// audited-pure packages (io, encoding/xml, ...) depend on
			// this arm flagging their exported mutable vars (io.EOF,
			// xml.HTMLEntity) - exempting them would unsound the
			// audited set.
			if callerIdx != nil && !callerIdx.std && obj.Pkg() != nil && isStdImportPath(obj.Pkg().Path()) {
				a.recordExternalEffect(symbolExternalEffect(externalEffectUnauditedStandard, obj.Pkg().Path(), obj.Name(), "reaches standard global "+obj.Pkg().Path()+"."+obj.Name()))
			}
			a.enqueueObject(obj)
		}
	case *ssa.Function:
		a.addFunction(x)
	}
}

func isOSFileType(t types.Type) bool {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "os" && named.Obj().Name() == "File"
}

func (a *tier2Analyzer) scanInstruction(idx *pkgIndex, caller *ssa.Function, instr ssa.Instruction, fromRTA, suppressNestedFileIO bool) {
	switch x := instr.(type) {
	case ssa.CallInstruction:
		a.scanCall(idx, caller, x, fromRTA, suppressNestedFileIO)
	case *ssa.MakeInterface:
		a.addInterfaceMethodSet(x.X.Type())
	case *ssa.Field:
		if effect, ok := testingRuntimeFieldEffect(x.X.Type(), x.Field); ok {
			a.recordExternalEffect(effect)
		}
	case *ssa.FieldAddr:
		if effect, ok := testingRuntimeFieldEffect(x.X.Type(), x.Field); ok {
			a.recordExternalEffect(effect)
		}
	}
}

func testingRuntimeFieldReason(t types.Type, index int) string {
	effect, ok := testingRuntimeFieldEffect(t, index)
	if !ok {
		return ""
	}
	return effect.reason
}

func testingRuntimeFieldEffect(t types.Type, index int) (externalEffect, bool) {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return externalEffect{}, false
	}
	structure, ok := named.Underlying().(*types.Struct)
	if !ok || index < 0 || index >= structure.NumFields() {
		return externalEffect{}, false
	}
	if name := structure.Field(index).Name(); name == "N" {
		return symbolExternalEffect(externalEffectTestRuntime, "testing", "B.N", "reaches testing.B.N (test runtime configuration)"), true
	}
	return externalEffect{}, false
}

func (a *tier2Analyzer) scanCall(callerIdx *pkgIndex, caller *ssa.Function, site ssa.CallInstruction, fromRTA, suppressNestedFileIO bool) {
	c := site.Common()
	if c == nil {
		return
	}
	callerStd := callerIdx != nil && callerIdx.std
	if c.IsInvoke() && observableDirEntryCall(site) {
		return
	}
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
	if observableFileMethod(callee) {
		if len(c.Args) != 0 && fileValueFromAdmittedOpen(c.Args[0], make(map[ssa.Value]bool)) {
			return
		}
		a.recordExternalEffect(symbolExternalEffect(externalEffectFileIO, "os", "File."+name, "reaches os.File."+name+" on an unattributed file handle (file I/O)"))
		return
	}
	effect, classified := classBEffect(pkgPath, name)
	calleeIdx := a.idxForFunction(callee)
	if !classified && name != "init" && !callerStd && calleeIdx != nil && calleeIdx.std && !isRefinementSourceOnlyStandardPackage(pkgPath) && !classBPureStandard(pkgPath, name) {
		effect = symbolExternalEffect(externalEffectUnauditedStandard, pkgPath, name, "reaches unaudited standard operation "+pkgPath+"."+name)
		classified = true
	}
	if osOpenFileMayMutate(callee, pkgPath, name, c) {
		effect = symbolExternalEffect(externalEffectFilesystemMutation, pkgPath, name, "reaches os.OpenFile (filesystem mutation)")
		classified = true
	}
	if !classified && syscallOpenMayCreate(pkgPath, name, c) {
		effect = symbolExternalEffect(externalEffectFilesystemMutation, pkgPath, name, "reaches "+pkgPath+"."+name+" (filesystem mutation)")
		classified = true
	}
	if classified {
		effect.observable = observableCallEffect(effect, c, site, a.fresh)
		if callerStd && (effect.kind == externalEffectFilesystemMutation || effect.kind == externalEffectPathMutation) {
			return
		}
		if !(suppressNestedFileIO && effect.kind == externalEffectFileIO) {
			a.recordExternalEffect(effect)
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

func observableCallEffect(effect externalEffect, call *ssa.CallCommon, site ssa.CallInstruction, fp *freshParamAnalysis) bool {
	if call == nil {
		return false
	}
	// The toolchain accessor is guard-pinned: its value is fixed by the
	// toolchain guard the fingerprint already carries, so branching on
	// it observes nothing the record does not pin. The audited carve-out
	// is this exact symbol — never the runtime package, whose other
	// surfaces stay unaudited; the enforcing precision gate is the
	// maximal tier's exact-GOROOT exemption (the AST scan covers the
	// whole source closure, so any other runtime selector blocks there
	// regardless of this condition — which is why widening this exact
	// match alone is not test-distinguishable).
	if effect.packagePath == "runtime" && effect.symbol == "GOROOT" {
		return true
	}
	if effect.packagePath == "testing" && effect.symbol == "TempDir" {
		return observableFreshPathResult(site, fp)
	}
	if effect.packagePath == "path/filepath" && effect.symbol == "Join" {
		return observableFreshPathResult(site, fp) || observablePinnedPathResult(site)
	}
	if effect.packagePath != "os" {
		return false
	}
	switch effect.symbol {
	case "Getenv", "LookupEnv":
		return observableIdentityArgument(effect, call)
	case "Open":
		return (observableIdentityArgument(effect, call) || guardPinnedPathArgument(call)) && observableOpenResult(site)
	case "OpenFile":
		flags, known := openFileFlags(call)
		if !known || !recognizedOpenFileFlags(call.StaticCallee(), flags) {
			return false
		}
		pathFresh := len(call.Args) != 0 && freshPathValue(call.Args[0], make(map[ssa.Value]bool), fp, nil)
		if !pathFresh && (!ordinaryOpenFileFlagsObservable(flags) || !observableIdentityArgument(effect, call)) {
			return false
		}
		if pathFresh && !freshOpenFileTargetObservable(flags, call.Args[0], site) {
			return false
		}
		return observableOpenResult(site) && observableTupleError(site)
	case "ReadFile":
		return observableIdentityArgument(effect, call) || guardPinnedPathArgument(call) || len(call.Args) != 0 && freshPathValue(call.Args[0], make(map[ssa.Value]bool), fp, nil) && freshReadableTargetObservable(call.Args[0], site)
	case "ReadDir":
		return (observableIdentityArgument(effect, call) || guardPinnedPathArgument(call)) && observableReadDirResult(site)
	case "WriteFile":
		return len(call.Args) >= 2 && freshPathValue(call.Args[0], make(map[ssa.Value]bool), fp, nil) && guardedWriteBytes(call.Args[1], make(map[ssa.Value]bool)) && observableErrorResult(site)
	case "Remove", "RemoveAll":
		return len(call.Args) != 0 && freshPathValue(call.Args[0], make(map[ssa.Value]bool), fp, nil) && freshTargetCreatedBefore(call.Args[0], site) && observableErrorResult(site)
	default:
		return false
	}
}

func observableIdentityArgument(effect externalEffect, call *ssa.CallCommon) bool {
	if call == nil || len(call.Args) == 0 {
		return false
	}
	value, ok := call.Args[0].(*ssa.Const)
	if !ok || value.Value == nil || value.Value.Kind() != constant.String {
		return false
	}
	identity := constant.StringVal(value.Value)
	// The admission proves testlog representability alone: non-empty,
	// valid UTF-8, newline-free. Resolvability — a ".."-carrying identity
	// included — is the runtime observation's obligation: ingest either
	// discharges the traversal's congruence and records the resolved
	// identity, or seals the observation fail-closed
	// (REQ-inputs-path-congruence), so no admitted effect's identity can
	// serve unresolved.
	return identity != "" && utf8.ValidString(identity) && !strings.ContainsAny(identity, "\x00\r\n")
}

func observableFreshPathResult(site ssa.CallInstruction, fp *freshParamAnalysis) bool {
	value, ok := site.(ssa.Value)
	return ok && !blockInCycle(site.Block()) && freshPathValue(value, make(map[ssa.Value]bool), fp, nil) && observableFreshPathUses(value, make(map[ssa.Value]bool), fp, nil)
}

// guardPinnedPathArgument reports whether the call's path argument is a
// guard-pinned toolchain path: the value the read observes is fixed by
// the toolchain guard the fingerprint carries, so the read is inside
// the admitted observation set for READ positions only — mutation
// admissions never accept pinned paths (freshness licenses mutation;
// pinning never does), so a write through such a path blocks on its own
// effect.
func guardPinnedPathArgument(call *ssa.CallCommon) bool {
	return call != nil && len(call.Args) != 0 && guardPinnedPathValue(call.Args[0], make(map[ssa.Value]bool))
}

// guardPinnedPathValue admits exactly the toolchain accessor's result
// and filepath.Join chains rooted at it with safe constant components —
// the same grammar as freshPathValue with the pinned accessor as the
// one root. Any other shape, including a component that is not a safe
// constant, refuses.
func guardPinnedPathValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	call, ok := value.(*ssa.Call)
	if !ok {
		return false
	}
	callee := call.Common().StaticCallee()
	if callee == nil {
		return false
	}
	pkgPath, name := funcPkgPath(callee), callee.Name()
	if object := callee.Object(); object != nil {
		name = object.Name()
	}
	if pkgPath == "runtime" && name == "GOROOT" {
		return true
	}
	if pkgPath != "path/filepath" || name != "Join" {
		return false
	}
	args, ok := fixedVariadicArgs(call)
	if !ok || len(args) < 2 || !guardPinnedPathValue(args[0], seen) {
		return false
	}
	for _, arg := range args[1:] {
		if !safeFreshPathComponent(arg) {
			return false
		}
	}
	return true
}

// observablePinnedPathResult admits a filepath.Join whose result is a
// guard-pinned path. Unlike fresh paths, no consumer walk is needed:
// every consumer site classifies its own effect independently, and no
// mutation admission accepts a pinned path, so an escaping write blocks
// there.
func observablePinnedPathResult(site ssa.CallInstruction) bool {
	value, ok := site.(ssa.Value)
	return ok && guardPinnedPathValue(value, make(map[ssa.Value]bool))
}

func freshPathValue(value ssa.Value, seen map[ssa.Value]bool, fp *freshParamAnalysis, inProgress map[freshParamKey]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	if inProgress == nil {
		inProgress = map[freshParamKey]bool{}
	}
	switch value := value.(type) {
	case *ssa.Parameter:
		// A parameter holds a fresh capability when every attributed
		// call site of its function passes one at this position
		// (REQ-inputs-fresh-mutation's boundary extension); its own
		// uses are audited from each origin's uses walk.
		if fp == nil {
			return false
		}
		fn := value.Parent()
		for i, param := range fn.Params {
			if param == value {
				return fp.paramArgFreshMemo(freshParamKey{fn: fn, idx: i}, inProgress)
			}
		}
		return false
	case *ssa.Call:
		callee := value.Common().StaticCallee()
		if callee == nil {
			return false
		}
		pkgPath, name := funcPkgPath(callee), callee.Name()
		if object := callee.Object(); object != nil {
			name = object.Name()
		}
		if pkgPath == "testing" && name == "TempDir" {
			return true
		}
		if pkgPath != "path/filepath" || name != "Join" {
			return false
		}
		args, ok := fixedVariadicArgs(value)
		if !ok || len(args) < 2 || !freshPathValue(args[0], seen, fp, inProgress) {
			return false
		}
		for _, arg := range args[1:] {
			if !safeFreshPathComponent(arg) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func observableFreshPathUses(value ssa.Value, seen map[ssa.Value]bool, fp *freshParamAnalysis, inProgress map[freshParamKey]bool) bool {
	if value == nil || seen[value] || value.Referrers() == nil {
		return value != nil
	}
	seen[value] = true
	joinStores := 0
	for _, ref := range *value.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			joinStores++
			if joinStores > 1 {
				return false
			}
			if ref.Val != value || !freshPathStoreFeedsJoin(ref, value, seen, fp, inProgress) {
				return false
			}
		case ssa.CallInstruction:
			if !observableFreshPathConsumer(ref, value, fp, inProgress) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func observableFreshPathConsumer(site ssa.CallInstruction, pathValue ssa.Value, fp *freshParamAnalysis, inProgress map[freshParamKey]bool) bool {
	if site == nil || site.Common() == nil || site.Common().StaticCallee() == nil {
		return false
	}
	if _, concurrent := site.(*ssa.Go); concurrent {
		return false
	}
	if blockInCycle(site.Block()) {
		return false
	}
	call := site.Common()
	callee := call.StaticCallee()
	pkgPath, name := funcPkgPath(callee), callee.Name()
	if object := callee.Object(); object != nil {
		name = object.Name()
	}
	// Crossing into a static user function is admitted when every
	// attributed call site of the callee passes fresh at the value's
	// positions and the parameter's uses stay within the graph
	// (REQ-inputs-fresh-mutation's boundary extension).
	if fp.boundaryCrossingObservable(site, pathValue, inProgress) {
		return true
	}
	if pkgPath != "os" || len(call.Args) == 0 || call.Args[0] != pathValue {
		return false
	}
	switch name {
	case "ReadFile":
		return freshReadableTargetObservable(pathValue, site)
	case "WriteFile":
		return len(call.Args) >= 2 && guardedWriteBytes(call.Args[1], make(map[ssa.Value]bool)) && observableErrorResult(site)
	case "Remove", "RemoveAll":
		return observableErrorResult(site)
	case "OpenFile":
		flags, known := openFileFlags(call)
		return known && recognizedOpenFileFlags(call.StaticCallee(), flags) && freshOpenFileTargetObservable(flags, pathValue, site) && observableOpenResult(site) && observableTupleError(site)
	default:
		return false
	}
}

func freshPathStoreFeedsJoin(store *ssa.Store, pathValue ssa.Value, seen map[ssa.Value]bool, fp *freshParamAnalysis, inProgress map[freshParamKey]bool) bool {
	address, ok := store.Addr.(*ssa.IndexAddr)
	if !ok {
		return false
	}
	alloc, ok := address.X.(*ssa.Alloc)
	if !ok || alloc.Referrers() == nil {
		return false
	}
	for _, allocRef := range *alloc.Referrers() {
		slice, ok := allocRef.(*ssa.Slice)
		if !ok || slice.Referrers() == nil {
			continue
		}
		for _, sliceRef := range *slice.Referrers() {
			call, ok := sliceRef.(*ssa.Call)
			if !ok || call.Common().StaticCallee() == nil || funcPkgPath(call.Common().StaticCallee()) != "path/filepath" || call.Common().StaticCallee().Name() != "Join" {
				continue
			}
			args, exact := fixedVariadicArgs(call)
			if !exact || len(args) < 2 || args[0] != pathValue {
				continue
			}
			valid := true
			for _, arg := range args[1:] {
				valid = valid && safeFreshPathComponent(arg)
			}
			if valid && observableFreshPathUses(call, seen, fp, inProgress) {
				return true
			}
		}
	}
	return false
}

func fixedVariadicArgs(site *ssa.Call) ([]ssa.Value, bool) {
	if site == nil || site.Common() == nil || len(site.Common().Args) != 1 {
		return nil, false
	}
	slice, ok := site.Common().Args[0].(*ssa.Slice)
	if !ok || slice.X == nil {
		return nil, false
	}
	alloc, ok := slice.X.(*ssa.Alloc)
	if !ok || alloc.Referrers() == nil {
		return nil, false
	}
	pointer, ok := alloc.Type().Underlying().(*types.Pointer)
	if !ok {
		return nil, false
	}
	array, ok := pointer.Elem().Underlying().(*types.Array)
	if !ok || array.Len() < 1 || array.Len() > 64 {
		return nil, false
	}
	args := make([]ssa.Value, int(array.Len()))
	for _, ref := range *alloc.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Slice:
			if ref != slice {
				return nil, false
			}
		case *ssa.IndexAddr:
			index, ok := constInt(ref.Index)
			if !ok || index < 0 || index >= int64(len(args)) || args[index] != nil || ref.Referrers() == nil {
				return nil, false
			}
			var stored ssa.Value
			for _, addressRef := range *ref.Referrers() {
				switch addressRef := addressRef.(type) {
				case *ssa.DebugRef:
				case *ssa.Store:
					if stored != nil || addressRef.Addr != ref {
						return nil, false
					}
					stored = addressRef.Val
				default:
					return nil, false
				}
			}
			if stored == nil {
				return nil, false
			}
			args[index] = stored
		default:
			return nil, false
		}
	}
	for _, arg := range args {
		if arg == nil {
			return nil, false
		}
	}
	if slice.Referrers() == nil {
		return nil, false
	}
	for _, ref := range *slice.Referrers() {
		if call, ok := ref.(*ssa.Call); !ok || call != site {
			if _, debug := ref.(*ssa.DebugRef); !debug {
				return nil, false
			}
		}
	}
	return args, true
}

func safeFreshPathComponent(value ssa.Value) bool {
	constantValue, ok := value.(*ssa.Const)
	if !ok || constantValue.Value == nil || constantValue.Value.Kind() != constant.String {
		return false
	}
	component := constant.StringVal(constantValue.Value)
	if component == "" || component == "." || component == ".." || !utf8.ValidString(component) || strings.TrimRight(component, " .") != component || strings.ContainsAny(component, "\x00\r\n/\\<>:\"|?*") || filepath.VolumeName(component) != "" {
		return false
	}
	for _, r := range component {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	device := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
	switch device {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return false
	}
	return !(len(device) == 4 && (strings.HasPrefix(device, "COM") || strings.HasPrefix(device, "LPT")) && device[3] >= '1' && device[3] <= '9')
}

func freshTargetCreatedBefore(pathValue ssa.Value, site ssa.CallInstruction) bool {
	if freshRootPathValue(pathValue, make(map[ssa.Value]bool)) {
		return true
	}
	return guardedWriteCreatedBefore(pathValue, site)
}

func guardedWriteCreatedBefore(pathValue ssa.Value, site ssa.CallInstruction) bool {
	if pathValue == nil || pathValue.Referrers() == nil || site == nil {
		return false
	}
	for _, ref := range *pathValue.Referrers() {
		call, ok := ref.(*ssa.Call)
		if !ok || call == site || call.Common().StaticCallee() == nil || funcPkgPath(call.Common().StaticCallee()) != "os" || call.Common().StaticCallee().Name() != "WriteFile" {
			continue
		}
		if len(call.Common().Args) >= 2 && call.Common().Args[0] == pathValue && guardedWriteBytes(call.Common().Args[1], make(map[ssa.Value]bool)) && successfulErrorResultDominates(call, site) && noMutationBeforeFreshUse(pathValue, call, site) {
			return true
		}
	}
	return false
}

func freshOpenFileTargetObservable(_ int64, pathValue ssa.Value, site ssa.CallInstruction) bool {
	return guardedWriteCreatedBefore(pathValue, site)
}

func freshReadableTargetObservable(pathValue ssa.Value, site ssa.CallInstruction) bool {
	return guardedWriteCreatedBefore(pathValue, site)
}

func noMutationBeforeFreshUse(pathValue ssa.Value, creator *ssa.Call, use ssa.CallInstruction) bool {
	if pathValue == nil || pathValue.Referrers() == nil || creator == nil || use == nil {
		return false
	}
	values := append([]ssa.Value{pathValue}, freshPathAncestors(pathValue)...)
	for _, value := range values {
		if value == nil || value.Referrers() == nil {
			return false
		}
		for _, ref := range *value.Referrers() {
			call, ok := ref.(ssa.CallInstruction)
			if !ok || call == creator || call == use || !freshPathMutationCall(call) {
				continue
			}
			if !instructionDominates(use, call) {
				return false
			}
		}
	}
	return true
}

func freshPathAncestors(value ssa.Value) []ssa.Value {
	call, ok := value.(*ssa.Call)
	if !ok || call.Common().StaticCallee() == nil || funcPkgPath(call.Common().StaticCallee()) != "path/filepath" || call.Common().StaticCallee().Name() != "Join" {
		return nil
	}
	args, ok := fixedVariadicArgs(call)
	if !ok || len(args) < 2 {
		return nil
	}
	return append([]ssa.Value{args[0]}, freshPathAncestors(args[0])...)
}

func freshPathMutationCall(site ssa.CallInstruction) bool {
	if site == nil || site.Common() == nil || site.Common().StaticCallee() == nil || funcPkgPath(site.Common().StaticCallee()) != "os" {
		return false
	}
	switch site.Common().StaticCallee().Name() {
	case "WriteFile", "Remove", "RemoveAll":
		return true
	case "OpenFile":
		flags, known := openFileFlags(site.Common())
		return !known || flags != 0
	default:
		return false
	}
}

func instructionDominates(before, after ssa.Instruction) bool {
	if before == nil || after == nil || before.Block() == nil || after.Block() == nil {
		return false
	}
	if before.Block() != after.Block() {
		return before.Block().Dominates(after.Block())
	}
	for _, instruction := range before.Block().Instrs {
		if instruction == before {
			return true
		}
		if instruction == after {
			return false
		}
	}
	return false
}

func freshRootPathValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Call:
		callee := value.Common().StaticCallee()
		if callee == nil {
			return false
		}
		name := callee.Name()
		if object := callee.Object(); object != nil {
			name = object.Name()
		}
		return funcPkgPath(callee) == "testing" && name == "TempDir"
	default:
		return false
	}
}

func blockInCycle(block *ssa.BasicBlock) bool {
	if block == nil {
		return true
	}
	seen := make(map[*ssa.BasicBlock]bool)
	queue := append([]*ssa.BasicBlock(nil), block.Succs...)
	for len(queue) != 0 {
		current := queue[0]
		queue = queue[1:]
		if current == block {
			return true
		}
		if current == nil || seen[current] {
			continue
		}
		seen[current] = true
		queue = append(queue, current.Succs...)
	}
	return false
}

func successfulErrorResultDominates(value ssa.Value, use ssa.Instruction) bool {
	if value == nil || value.Referrers() == nil || use == nil || use.Block() == nil {
		return false
	}
	for _, ref := range *value.Referrers() {
		comparison, ok := ref.(*ssa.BinOp)
		if !ok || (comparison.Op != token.EQL && comparison.Op != token.NEQ) || !isNilComparison(comparison, value) || comparison.Referrers() == nil {
			continue
		}
		for _, comparisonRef := range *comparison.Referrers() {
			branch, ok := comparisonRef.(*ssa.If)
			if !ok || len(branch.Block().Succs) != 2 {
				continue
			}
			success := branch.Block().Succs[0]
			if comparison.Op == token.NEQ {
				success = branch.Block().Succs[1]
			}
			if success == use.Block() || success.Dominates(use.Block()) {
				return true
			}
		}
	}
	return false
}

func guardedWriteBytes(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Convert:
		constantValue, ok := value.X.(*ssa.Const)
		return ok && constantValue.Value != nil && constantValue.Value.Kind() == constant.String
	case *ssa.Slice:
		return guardedWriteBytes(value.X, seen)
	case *ssa.Phi:
		if len(value.Edges) == 0 {
			return false
		}
		for _, edge := range value.Edges {
			if !guardedWriteBytes(edge, cloneValueSet(seen)) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func observableErrorResult(site ssa.CallInstruction) bool {
	value, ok := site.(ssa.Value)
	return ok && boundedErrorValue(value)
}

func observableTupleError(site ssa.CallInstruction) bool {
	value, ok := site.(ssa.Value)
	if !ok || value.Referrers() == nil {
		return false
	}
	for _, ref := range *value.Referrers() {
		extract, ok := ref.(*ssa.Extract)
		if !ok {
			if _, debug := ref.(*ssa.DebugRef); !debug {
				return false
			}
			continue
		}
		if extract.Index == 1 && !boundedErrorValue(extract) {
			return false
		}
	}
	return true
}

func boundedErrorValue(value ssa.Value) bool {
	if value == nil || value.Referrers() == nil {
		return value != nil
	}
	for _, ref := range *value.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.BinOp:
			if ref.Op != token.EQL && ref.Op != token.NEQ || !isNilComparison(ref, value) || !boundedBoolValue(ref) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func boundedBoolValue(value ssa.Value) bool {
	if value == nil || value.Referrers() == nil {
		return false
	}
	for _, ref := range *value.Referrers() {
		switch ref.(type) {
		case *ssa.DebugRef, *ssa.If:
		default:
			return false
		}
	}
	return true
}

func isNilComparison(operation *ssa.BinOp, value ssa.Value) bool {
	if operation == nil {
		return false
	}
	other := operation.X
	if other == value {
		other = operation.Y
	} else if operation.Y != value {
		return false
	}
	constantValue, ok := other.(*ssa.Const)
	return ok && constantValue.IsNil()
}

func constInt(value ssa.Value) (int64, bool) {
	constantValue, ok := value.(*ssa.Const)
	if !ok || constantValue.Value == nil || constantValue.Value.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(constantValue.Value)
}

func cloneValueSet(values map[ssa.Value]bool) map[ssa.Value]bool {
	clone := make(map[ssa.Value]bool, len(values))
	for value := range values {
		clone[value] = true
	}
	return clone
}

func fileValueFromAdmittedOpen(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Extract:
		if value.Index != 0 {
			return false
		}
		call, ok := value.Tuple.(ssa.CallInstruction)
		if !ok || call.Common() == nil || call.Common().StaticCallee() == nil {
			return false
		}
		effect, classified := classBEffect(funcPkgPath(call.Common().StaticCallee()), call.Common().StaticCallee().Name())
		if !classified || effect.packagePath != "os" {
			return false
		}
		switch effect.symbol {
		case "Open":
			return observableIdentityArgument(effect, call.Common()) || guardPinnedPathArgument(call.Common())
		case "OpenFile":
			flags, known := openFileFlags(call.Common())
			if !known || !recognizedOpenFileFlags(call.Common().StaticCallee(), flags) || len(call.Common().Args) == 0 {
				return false
			}
			pathFresh := freshPathValue(call.Common().Args[0], make(map[ssa.Value]bool), nil, nil)
			return pathFresh && freshOpenFileTargetObservable(flags, call.Common().Args[0], call) || ordinaryOpenFileFlagsObservable(flags) && observableIdentityArgument(effect, call.Common())
		default:
			return false
		}
	case *ssa.Phi:
		if len(value.Edges) == 0 {
			return false
		}
		for _, edge := range value.Edges {
			if !fileValueFromAdmittedOpen(edge, seen) {
				return false
			}
		}
		return true
	case *ssa.ChangeType:
		return fileValueFromAdmittedOpen(value.X, seen)
	case *ssa.Convert:
		return fileValueFromAdmittedOpen(value.X, seen)
	default:
		return false
	}
}

func observableOpenResult(site ssa.CallInstruction) bool {
	value, ok := site.(ssa.Value)
	if !ok || value.Referrers() == nil {
		return false
	}
	for _, ref := range *value.Referrers() {
		extract, ok := ref.(*ssa.Extract)
		if !ok {
			if _, debug := ref.(*ssa.DebugRef); !debug {
				return false
			}
			continue
		}
		if extract.Index == 0 && !observableFileValue(extract, make(map[ssa.Value]bool)) {
			return false
		}
	}
	return true
}

func observableReadDirResult(site ssa.CallInstruction) bool {
	value, ok := site.(ssa.Value)
	if !ok || value.Referrers() == nil {
		return false
	}
	for _, ref := range *value.Referrers() {
		extract, ok := ref.(*ssa.Extract)
		if !ok {
			if _, debug := ref.(*ssa.DebugRef); !debug {
				return false
			}
			continue
		}
		if extract.Index == 0 && !observableDirEntriesValue(extract, make(map[ssa.Value]bool)) {
			return false
		}
	}
	return true
}

func observableDirEntriesValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] || value.Referrers() == nil {
		return value != nil
	}
	seen[value] = true
	for _, ref := range *value.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Index:
			if !observableDirEntryValue(ref, make(map[ssa.Value]bool)) {
				return false
			}
		case *ssa.IndexAddr:
			if !observableDirEntryAddress(ref) {
				return false
			}
		case *ssa.Slice:
			if !observableDirEntriesValue(ref, seen) {
				return false
			}
		case *ssa.Phi:
			if !observableDirEntriesValue(ref, seen) {
				return false
			}
		case ssa.CallInstruction:
			if _, concurrent := ref.(*ssa.Go); concurrent {
				return false
			}
			common := ref.Common()
			if common == nil {
				return false
			}
			builtin, ok := common.Value.(*ssa.Builtin)
			if !ok || builtin.Name() != "len" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func observableDirEntryAddress(value ssa.Value) bool {
	if value == nil || value.Referrers() == nil {
		return false
	}
	for _, ref := range *value.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.UnOp:
			if ref.Op != token.MUL || !observableDirEntryValue(ref, make(map[ssa.Value]bool)) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func observableDirEntryValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] || value.Referrers() == nil {
		return value != nil
	}
	seen[value] = true
	for _, ref := range *value.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.MakeInterface:
			if !observableDirEntryValue(ref, seen) {
				return false
			}
		case *ssa.ChangeInterface:
			if !observableDirEntryValue(ref, seen) {
				return false
			}
		case *ssa.Phi:
			if !observableDirEntryValue(ref, seen) {
				return false
			}
		case ssa.CallInstruction:
			if !observableDirEntryCall(ref) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func observableDirEntryCall(site ssa.CallInstruction) bool {
	if site == nil || site.Common() == nil || !site.Common().IsInvoke() || site.Common().Method == nil {
		return false
	}
	switch site.Common().Method.Name() {
	case "Name", "IsDir", "Type":
		return dirEntryValueFromAdmittedReadDir(site.Common().Value, make(map[ssa.Value]bool))
	default:
		return false
	}
}

func dirEntryValueFromAdmittedReadDir(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.MakeInterface:
		return dirEntryValueFromAdmittedReadDir(value.X, seen)
	case *ssa.ChangeInterface:
		return dirEntryValueFromAdmittedReadDir(value.X, seen)
	case *ssa.Index:
		return dirEntriesValueFromAdmittedReadDir(value.X, seen)
	case *ssa.UnOp:
		if value.Op != token.MUL {
			return false
		}
		address, ok := value.X.(*ssa.IndexAddr)
		return ok && dirEntriesValueFromAdmittedReadDir(address.X, seen)
	case *ssa.Phi:
		if len(value.Edges) == 0 {
			return false
		}
		for _, edge := range value.Edges {
			if !dirEntryValueFromAdmittedReadDir(edge, seen) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func dirEntriesValueFromAdmittedReadDir(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Extract:
		if value.Index != 0 {
			return false
		}
		call, ok := value.Tuple.(ssa.CallInstruction)
		if !ok || call.Common() == nil || call.Common().StaticCallee() == nil {
			return false
		}
		effect, classified := classBEffect(funcPkgPath(call.Common().StaticCallee()), call.Common().StaticCallee().Name())
		if !classified || effect.packagePath != "os" || effect.symbol != "ReadDir" {
			return false
		}
		return observableIdentityArgument(effect, call.Common()) || guardPinnedPathArgument(call.Common())
	case *ssa.Slice:
		return dirEntriesValueFromAdmittedReadDir(value.X, seen)
	case *ssa.Phi:
		if len(value.Edges) == 0 {
			return false
		}
		for _, edge := range value.Edges {
			if !dirEntriesValueFromAdmittedReadDir(edge, seen) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func observableFileValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] || value.Referrers() == nil {
		return value != nil
	}
	seen[value] = true
	for _, ref := range *value.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
			continue
		case *ssa.Phi:
			if !observableFileValue(ref, seen) {
				return false
			}
		case *ssa.BinOp:
			if (ref.Op != token.EQL && ref.Op != token.NEQ) || !isNilComparison(ref, value) || !boundedBoolValue(ref) {
				return false
			}
		case ssa.CallInstruction:
			if _, concurrent := ref.(*ssa.Go); concurrent {
				return false
			}
			common := ref.Common()
			if common == nil || len(common.Args) == 0 || common.Args[0] != value || !observableFileMethod(common.StaticCallee()) {
				return false
			}
			if common.StaticCallee().Name() == "Name" && fileValueFromFreshOpenFile(value, make(map[ssa.Value]bool)) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func fileValueFromFreshOpenFile(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Extract:
		if value.Index != 0 {
			return false
		}
		call, ok := value.Tuple.(ssa.CallInstruction)
		if !ok || call.Common() == nil || call.Common().StaticCallee() == nil || funcPkgPath(call.Common().StaticCallee()) != "os" || call.Common().StaticCallee().Name() != "OpenFile" || len(call.Common().Args) == 0 {
			return false
		}
		return freshPathValue(call.Common().Args[0], make(map[ssa.Value]bool), nil, nil)
	case *ssa.Phi:
		if len(value.Edges) == 0 {
			return false
		}
		for _, edge := range value.Edges {
			if !fileValueFromFreshOpenFile(edge, cloneValueSet(seen)) {
				return false
			}
		}
		return true
	case *ssa.ChangeType:
		return fileValueFromFreshOpenFile(value.X, seen)
	case *ssa.Convert:
		return fileValueFromFreshOpenFile(value.X, seen)
	default:
		return false
	}
}

func observableFileMethod(fn *ssa.Function) bool {
	if fn == nil || funcPkgPath(fn) != "os" || fn.Signature == nil || fn.Signature.Recv() == nil {
		return false
	}
	receiver := types.TypeString(fn.Signature.Recv().Type(), nil)
	if !strings.Contains(receiver, "os.File") {
		return false
	}
	switch fn.Name() {
	case "Close", "Name", "Read", "ReadAt", "Seek":
		return true
	default:
		return false
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
	case *ssa.TypeAssert:
		// Asserting narrows the dynamic-type set of X, never widens it:
		// the asserted value is closed exactly when its operand is.
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
	effect, classified := classBEffect(pkgPath, name)
	if !classified && isStdImportPath(pkgPath) {
		effect = symbolExternalEffect(externalEffectLinkage, pkgPath, name, "reaches standard linkname target "+target)
		classified = true
	}
	if classified {
		a.recordExternalEffect(effect)
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
			effect := opaqueExternalEffect(externalEffectLinkage, "reaches go:wasmimport")
			effect.unrefinable = true
			a.recordExternalEffect(effect)
		}
		if idx.mutable {
			for _, n := range idx.imports {
				a.addDecl(idx, "imports", n)
			}
		}
		if hasExternalCgoMeta(idx.meta) {
			effect := opaqueExternalEffect(externalEffectNative, "reaches cgo external library")
			effect.unrefinable = true
			a.recordExternalEffect(effect)
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
		}
		if len(idx.meta.SFiles) == 0 {
			continue
		}
		// Assembly is never an analysis surface (REQ-closure-blindspot):
		// the package's effect blocks the observability proof and the
		// subject widens to the maximal closure, whose hash covers the
		// package directory whole. Only mutable-local and cache packages
		// enter this loop — toolchain assembly rides the toolchain guard.
		a.recordExternalEffect(opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly"))
		a.requestWiden("non-toolchain assembly in " + idx.id)
	}
	return nil
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
	a.recordExternalEffect(opaqueExternalEffect(externalEffectOpaque, reason))
}

func (a *tier2Analyzer) recordExternalEffect(effect externalEffect) {
	a.collectExternalEffect(effect)
	reason := effect.reason
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

func (a *tier2Analyzer) collectExternalEffect(effect externalEffect) bool {
	before := len(a.effects)
	a.effects = appendExternalEffect(a.effects, effect)
	return len(a.effects) != before
}

func unverifiableReasonRank(reason string) int {
	switch {
	case strings.Contains(reason, "unaudited standard operation"), strings.Contains(reason, "test runtime configuration"), strings.Contains(reason, "test runtime execution"):
		return 0
	case strings.Contains(reason, "formatted output"), strings.Contains(reason, "environment input"):
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
	return tier2Result{contribs: a.contribs, effects: append([]externalEffect(nil), a.effects...), widen: a.widen, widenReason: a.widenReason, unverifiable: a.unverifiable, reason: a.reason}
}

func isFileIOReason(reason string) bool {
	return strings.Contains(reason, "file I/O")
}

func isFilesystemMutationReason(reason string) bool {
	return strings.Contains(reason, "mutation")
}

func classBEffectForFunction(fn *ssa.Function) (externalEffect, bool) {
	if fn == nil {
		return externalEffect{}, false
	}
	pkgPath := funcPkgPath(fn)
	name := fn.Name()
	if obj := fn.Object(); obj != nil {
		name = obj.Name()
	}
	return classBEffect(pkgPath, name)
}

func classBReasonForFunction(fn *ssa.Function) string {
	effect, ok := classBEffectForFunction(fn)
	if !ok {
		return ""
	}
	return effect.reason
}

func osOpenFileMayMutate(callee *ssa.Function, pkgPath, name string, c *ssa.CallCommon) bool {
	if pkgPath != "os" || name != "OpenFile" {
		return false
	}
	flags, known := openFileFlagsForCallee(callee, c)
	return !known || openFileFlagsMutate(flags)
}

func openFileFlags(c *ssa.CallCommon) (int64, bool) {
	if c == nil {
		return 0, false
	}
	return openFileFlagsForCallee(c.StaticCallee(), c)
}

func openFileFlagsForCallee(callee *ssa.Function, c *ssa.CallCommon) (int64, bool) {
	flagArg := 1
	if callee != nil && callee.Signature != nil && callee.Signature.Recv() != nil {
		flagArg = 2
	}
	if c == nil || len(c.Args) <= flagArg {
		return 0, false
	}
	return constInt(c.Args[flagArg])
}

func openFileFlagsMutate(flags int64) bool {
	const mutatingFlags = int64(os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREATE | os.O_TRUNC)
	return flags&mutatingFlags != 0
}

func ordinaryOpenFileFlagsObservable(flags int64) bool {
	return flags == 0
}

func recognizedOpenFileFlags(callee *ssa.Function, flags int64) bool {
	if callee == nil || callee.Object() == nil || callee.Object().Pkg() == nil {
		return false
	}
	scope := callee.Object().Pkg().Scope()
	var mask int64
	var writeOnly, readWrite int64
	for _, name := range []string{"O_WRONLY", "O_RDWR", "O_APPEND", "O_CREATE", "O_EXCL", "O_SYNC", "O_TRUNC"} {
		object, ok := scope.Lookup(name).(*types.Const)
		if !ok {
			return false
		}
		value, ok := constant.Int64Val(object.Val())
		if !ok {
			return false
		}
		mask |= value
		if name == "O_WRONLY" {
			writeOnly = value
		}
		if name == "O_RDWR" {
			readWrite = value
		}
	}
	access := flags & (writeOnly | readWrite)
	return flags&^mask == 0 && (access == 0 || access == writeOnly || access == readWrite)
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
