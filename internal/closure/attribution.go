package closure

import (
	"context"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"sort"
	"strings"
	"unsafe"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/internal/closure/internal/asmverify"
	"github.com/greatliontech/gofresh/internal/closure/internal/propharness"
	"github.com/greatliontech/gofresh/internal/closure/internal/rta"
	"github.com/greatliontech/gofresh/internal/dynstate"
)

type attributedReachability struct {
	// unavailable carries a per-subject analysis failure the bisection
	// isolated: the subject's evidence is unavailable (fail-closed at
	// every consumer) while its batch siblings keep theirs.
	unavailable      string
	functions        map[*ssa.Function]bool
	rtaFunctions     map[*ssa.Function]bool
	subjectFunctions map[*ssa.Function]bool
	startupFunctions map[*ssa.Function]bool
	// baseStartup marks a subject whose startupFunctions and
	// startupDynamicTargets equal the program's unmodified init-only
	// startup reachability (no cleanup roots and no unclosed cleanup).
	baseStartup bool
	// testMainFunctions is the user-TestMain-flow slice of the startup
	// provenance: the one startup flow that can dispatch a test-planted
	// value (after m.Run), so the one whose unattributed invokes widen.
	testMainFunctions     map[*ssa.Function]bool
	cleanupFunctions      map[*ssa.Function]bool
	rootedExtraFunctions  map[*ssa.Function]bool
	rootedIncomplete      bool
	resolved              map[ssa.CallInstruction]bool
	dynamicTargets        map[ssa.CallInstruction]map[*ssa.Function]bool
	startupDynamicTargets map[ssa.CallInstruction]map[*ssa.Function]bool
	// instantiatedOrigins marks parameterized origins whose materialized
	// instantiations were rooted for this subject: the origin's body
	// scan yields to theirs.
	instantiatedOrigins map[*ssa.Function]bool
	openWorld           bool
	enumeratedRoot      bool
	// enumeratedRootSites is the subject root's whole-view caller
	// enumeration when its dynamic-carrying signature closed by it:
	// the sites the closed-value walk crosses to when judging the
	// root's own parameters. Nil for every other subject; subjectRoot
	// names the function the sites call.
	enumeratedRootSites    []ssa.CallInstruction
	enumeratedTypes        []types.Type
	initBoxedTypes         []types.Type
	enumeratedFieldStores  map[int][]ssa.Value
	structFieldStores      map[structFieldKey][]ssa.Value
	structWholeStores      map[*types.Named][]ssa.Value
	structPoisoned         map[structFieldKey]bool
	structReferencedByType map[*types.Named]bool
	programSites           map[*ssa.Function][]ssa.CallInstruction
	programValueRef        map[*ssa.Function]bool
	programFunctions       map[*ssa.Function]bool
	userPaths              map[string]bool
	subjectRoot            *ssa.Function
	prog                   *program
	summary                *callerReferenceSummary
	// propertyHarnessAudited carries the program-level audit verdict for
	// the property harness into the per-subject walks: the closed-value
	// arms consult it so no admission outlives the audit.
	propertyHarnessAudited bool
}

// defaultProbePackageScope is the package-scope discriminator: it
// analyzes the roots every sub-batch SHARES - the package inits, and
// the harness main only when some subject in the batch actually runs
// through the harness (the worker roots TestMain under testMasks, so
// a batch of production subjects never walks it). A provocation in the
// shared roots explains every subject's failure directly; a subject-scoped
// shape can never satisfy the probe. A non-nil result is the package-scoped
// failure, correctly attributed to every subject. Results memoize per
// (program, harness inclusion): the shared roots are batch-invariant.
func defaultProbePackageScope(ctx context.Context, prog *program, subjects []Subject) error {
	includeHarness := false
	if prog.TestMain != nil {
		for _, subject := range subjects {
			if root := prog.Roots[subject.Symbol]; root != nil && subjectRunsThroughHarness(prog, root) {
				includeHarness = true
				break
			}
		}
	}
	if cached, ok := prog.PkgScopeProbe[includeHarness]; ok {
		return cached
	}
	roots := make(map[*ssa.Function]uint64)
	for _, p := range prog.Prog.AllPackages() {
		if isGeneratedTestMainPackage(prog, p) {
			continue
		}
		if init := p.Func("init"); init != nil {
			roots[init] |= 1
		}
	}
	if includeHarness {
		roots[prog.TestMain] |= 1
	}
	var result error
	if _, err := rta.Analyze(ctx, roots, nil); err != nil && strings.Contains(err.Error(), "unsupported analysis shape") {
		result = err
	}
	if prog.PkgScopeProbe == nil {
		prog.PkgScopeProbe = map[bool]error{}
	}
	prog.PkgScopeProbe[includeHarness] = result
	return result
}

// subjectMask attributes one reachability fact to the subjects of a
// slice, one bit per subject; subjectMaskBits is therefore the widest
// slice an attributed walk can serve, and maxAttributedSubjects derives
// from it.
type subjectMask = uint64

const subjectMaskBits = int(unsafe.Sizeof(subjectMask(0))) * 8

func shapeFailure(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unsupported analysis shape")
}

// attributedReachableSets computes per-subject attributed reachability.
// An unsupported-analysis-shape failure isolates: a package-scoped
// provocation (the shared init/harness roots themselves) degrades
// every subject at once with the probe's own error; a subject-scoped
// one bisects until each offender degrades alone, its row carrying its
// own batch's failure, while every sound sibling keeps its result
// (REQ-closure-analysis). Other failure classes stay batch-wide.
func attributedReachableSets(ctx context.Context, audited bool, pureDelegates map[string]bool, prog *program, subjects []Subject) ([]attributedReachability, error) {
	res, err := runAnalyzeAttributedBatch(ctx, audited, pureDelegates, prog, subjects)
	if err == nil || ctx.Err() != nil || !shapeFailure(err) {
		return res, err
	}
	if pkgErr := runProbePackageScope(ctx, prog, subjects); pkgErr != nil {
		rows := make([]attributedReachability, len(subjects))
		for i := range rows {
			rows[i] = attributedReachability{unavailable: pkgErr.Error()}
		}
		return rows, nil
	}
	return splitAttributed(ctx, audited, pureDelegates, prog, subjects, err)
}

// splitAttributed bisects a shape-failing batch whose provocation is
// subject-scoped: each half runs the worker once per level (never
// re-analyzing a half the caller already ran), a failing single
// subject degrades with its own batch's error, and a non-shape
// failure anywhere propagates batch-wide.
func splitAttributed(ctx context.Context, audited bool, pureDelegates map[string]bool, prog *program, subjects []Subject, batchErr error) ([]attributedReachability, error) {
	if len(subjects) == 1 {
		return []attributedReachability{{unavailable: batchErr.Error()}}, nil
	}
	mid := len(subjects) / 2
	resolve := func(half []Subject) ([]attributedReachability, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, err := runAnalyzeAttributedBatch(ctx, audited, pureDelegates, prog, half)
		if err == nil {
			return res, nil
		}
		if !shapeFailure(err) {
			return nil, err
		}
		return splitAttributed(ctx, audited, pureDelegates, prog, half, err)
	}
	left, err := resolve(subjects[:mid])
	if err != nil {
		return nil, err
	}
	right, err := resolve(subjects[mid:])
	if err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

func attributedReachableSetsOnce(ctx context.Context, audited bool, pureDelegates map[string]bool, prog *program, subjects []Subject) ([]attributedReachability, error) {
	roots := make(map[*ssa.Function]uint64)
	allMasks := ^uint64(0)
	if len(subjects) < subjectMaskBits {
		allMasks = 1<<len(subjects) - 1
	}
	var testMasks uint64
	var allFunctions map[*ssa.Function]bool
	instantiated := map[uint64]map[*ssa.Function]bool{}
	for i, subject := range subjects {
		mask := subjectMask(1) << i
		root := prog.Roots[subject.Symbol]
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
		case !rootMayReceiveUnknownDynamic(audited, prog, root):
			if allFunctions == nil {
				allFunctions = progAllFunctions(prog)
			}
			for fn := range allFunctions {
				if fn != nil && fn != root && fn.Origin() == root {
					if args := fn.TypeArgs(); len(args) > 0 {
						parameterized := false
						for _, arg := range args {
							if rta.ContainsTypeParam(arg, make(map[types.Type]bool)) {
								parameterized = true
								break
							}
						}
						if parameterized {
							// A parameterized instance (type arguments
							// still mentioning type parameters, created
							// inside another origin's body) is not a
							// concrete dispatch surface: its coverage
							// arrives through the fully concrete
							// instances, and rooting it would walk a
							// parameterized body.
							continue
						}
					}
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
	if prog.TestMain != nil {
		roots[prog.TestMain] |= testMasks
	}
	harnessAudited := propertyHarnessAuditedProg(audited, prog)
	userPaths := userModulePaths(prog.Pkgs)
	// The init-root set is subject-independent; only the test-main prepend
	// varies by harness. One derivation serves the RTA roots and every
	// subject's startup provenance, isolating stdlib packages imported
	// exclusively by a verified property harness onto the harness-stdlib plane.
	initRoots, harnessStdInitRoots := partitionHarnessInitRoots(prog, harnessAudited, userPaths)
	for _, init := range initRoots {
		roots[init] |= allMasks
	}
	// Whole-view caller enumeration for signature-open subjects
	// (REQ-closure-analysis): one deterministic pass collects every
	// candidate's references; a subject whose only references are direct
	// static calls with caller-frame-closed dynamic arguments analyzes
	// closed, its enumerated candidates seeded into the walk. Everything
	// else keeps the open world.
	enumClosed := map[int]enumerationClosure{}
	var seeds *rta.Seeds
	if harnessAudited {
		seeds = newHarnessRTASeeds(userPaths, harnessStdInitRoots, allMasks)
	}
	openCandidates := map[*ssa.Function]int{}
	for i, subject := range subjects {
		root := prog.Roots[subject.Symbol]
		if root == nil || parameterizedBody(root) || !rootMayReceiveUnknownDynamic(audited, prog, root) {
			continue
		}
		openCandidates[root] = i
	}
	var valueRefOutsideInit map[*ssa.Function]bool
	var summary *callerReferenceSummary
	if audited || len(openCandidates) > 0 {
		summary = enumerateCallerReferencesForProgram(prog, audited, pureDelegates, userPaths, allFunctions)
		allFunctions = summary.allFunctions
		valueRefOutsideInit = summary.valueRefOutsideInit
		var openRoots []*ssa.Function
		for root := range openCandidates {
			openRoots = append(openRoots, root)
		}
		sort.Slice(openRoots, func(i, j int) bool { return openRoots[i].String() < openRoots[j].String() })
		for _, root := range openRoots {
			i := openCandidates[root]
			enc, ok := subjectEnumerationClosure(audited, pureDelegates, userPaths, root, summary)
			if !ok {
				continue
			}
			mask := uint64(1) << i
			if seeds == nil {
				seeds = &rta.Seeds{AddrTaken: map[*ssa.Function]uint64{}}
			} else if seeds.AddrTaken == nil {
				seeds.AddrTaken = map[*ssa.Function]uint64{}
			}
			for fn := range enc.addrTaken {
				seeds.AddrTaken[fn] |= mask
			}
			for _, t := range enc.types {
				seeds.RuntimeTypes = append(seeds.RuntimeTypes, rta.TypeSeed{Type: t, Masks: mask})
			}
			enumClosed[i] = enc
		}
	}
	cancelCtxMasks := testMasks
	if harnessAudited {
		cancelCtxMasks = allMasks
	}
	if audited && cancelCtxMasks != 0 {
		if ct := programCancelCtxType(prog.Prog); ct != nil {
			if seeds == nil {
				seeds = &rta.Seeds{}
			}
			seeds.RuntimeTypes = append(seeds.RuntimeTypes, rta.TypeSeed{Type: ct, Masks: cancelCtxMasks})
		}
	}
	baseStartup, err := cachedBaseStartupReachability(ctx, audited, prog, initRoots, harnessStdInitRoots, harnessAudited, userPaths)
	if err != nil {
		return nil, err
	}
	cleanupRoots := make([][]*ssa.Function, len(subjects))
	fuzzRoots := make([][]*ssa.Function, len(subjects))
	unclosedCleanup := make([]bool, len(subjects))
	unclosedFuzz := make([]bool, len(subjects))
	rootedCallbacks := make([]map[*ssa.Function]bool, len(subjects))
	var res *rta.Result
	for {
		res, err = rta.Analyze(ctx, roots, seeds)
		if err != nil {
			return nil, err
		}
		addedAny := false
		for i, subject := range subjects {
			mask := uint64(1) << i
			subjectRoot := prog.Roots[subject.Symbol]
			if subjectRoot == nil {
				continue
			}
			provRoots := []*ssa.Function{subjectRoot}
			if len(instantiated[mask]) > 0 {
				provRoots = provRoots[:0]
				for fn := range allFunctions {
					if fn != nil && fn != subjectRoot && fn.Origin() == subjectRoot {
						provRoots = append(provRoots, fn)
					}
				}
			}
			if prog.TestMain != nil && subjectRunsThroughHarness(prog, subjectRoot) {
				provRoots = append(provRoots, prog.TestMain)
			}
			provRoots = append(provRoots, cleanupRoots[i]...)
			provRoots = append(provRoots, fuzzRoots[i]...)
			enc, enumerated := enumClosed[i]
			prov, _, err := provenanceReachableWithCandidates(ctx, prog, provRoots, mask, res, harnessAudited, userPaths, nil, enc.types, baseStartup.initBoxedTypes)
			if err != nil {
				return nil, err
			}
			cbs, unclosedCB, fbs, unclosedFB := collectTestingHarnessCallbacks(audited, harnessAudited, pureDelegates, userPaths, summary, subjectRoot, enumerated, enc, prov, mask, res)
			unclosedCleanup[i] = unclosedCleanup[i] || unclosedCB
			unclosedFuzz[i] = unclosedFuzz[i] || unclosedFB
			for _, cb := range cbs {
				if rootedCallbacks[i] == nil {
					rootedCallbacks[i] = map[*ssa.Function]bool{}
				}
				if !rootedCallbacks[i][cb] {
					rootedCallbacks[i][cb] = true
					cleanupRoots[i] = append(cleanupRoots[i], cb)
					roots[cb] |= mask
					addedAny = true
				}
			}
			for _, fb := range fbs {
				if rootedCallbacks[i] == nil {
					rootedCallbacks[i] = map[*ssa.Function]bool{}
				}
				if !rootedCallbacks[i][fb] {
					rootedCallbacks[i][fb] = true
					fuzzRoots[i] = append(fuzzRoots[i], fb)
					roots[fb] |= mask
					if len(fb.Params) > 0 && isHarnessPointerType(fb.Params[0].Type()) && paramHasMakeInterface(fb.Params[0], make(map[*ssa.Parameter]bool)) {
						if seeds == nil {
							seeds = &rta.Seeds{}
						}
						seeds.RuntimeTypes = append(seeds.RuntimeTypes, rta.TypeSeed{Type: fb.Params[0].Type(), Masks: mask})
					}
					addedAny = true
				}
			}
		}
		if !addedAny {
			break
		}
	}
	// Fold each parameterized origin into the result under its subject's
	// mask: its declaration is the subject's own source — the subject's
	// content must move when the generic body moves — while its body was
	// never traversed.
	for i, subject := range subjects {
		if origin := prog.Roots[subject.Symbol]; parameterizedBody(origin) {
			res.Reachable[origin] |= uint64(1) << i
		}
	}
	reachable := make([]attributedReachability, len(subjects))
	for i := range reachable {
		enc, enumerated := enumClosed[i]
		var structFieldStores map[structFieldKey][]ssa.Value
		var structWholeStores map[*types.Named][]ssa.Value
		var structPoisoned map[structFieldKey]bool
		var structReferencedByType map[*types.Named]bool
		var programSites map[*ssa.Function][]ssa.CallInstruction
		var programValueRef map[*ssa.Function]bool
		var programFunctions map[*ssa.Function]bool
		if summary != nil {
			structFieldStores = summary.structFieldStores
			structWholeStores = summary.structWholeStores
			structPoisoned = summary.structPoisoned
			structReferencedByType = summary.structReferencedByType
			programSites = summary.sites
			programValueRef = summary.valueRef
			programFunctions = summary.allFunctions
		}
		rtaFns := make(map[*ssa.Function]bool, len(res.Reachable))
		reachable[i] = attributedReachability{
			functions:              rtaFns,
			rtaFunctions:           rtaFns,
			resolved:               make(map[ssa.CallInstruction]bool, len(res.Resolved)),
			dynamicTargets:         make(map[ssa.CallInstruction]map[*ssa.Function]bool),
			instantiatedOrigins:    instantiated[uint64(1)<<i],
			openWorld:              (!enumerated && rootMayReceiveUnknownDynamic(audited, prog, prog.Roots[subjects[i].Symbol])) || unclosedCleanup[i],
			enumeratedRoot:         enumerated,
			enumeratedRootSites:    enc.sites,
			enumeratedTypes:        enc.types,
			enumeratedFieldStores:  enc.fieldStores,
			structFieldStores:      structFieldStores,
			structWholeStores:      structWholeStores,
			structPoisoned:         structPoisoned,
			structReferencedByType: structReferencedByType,
			programSites:           programSites,
			programValueRef:        programValueRef,
			programFunctions:       programFunctions,
			userPaths:              userPaths,
			subjectRoot:            prog.Roots[subjects[i].Symbol],
			prog:                   prog,
			summary:                summary,
			propertyHarnessAudited: harnessAudited,
		}
		mask := uint64(1) << i
		subjectRoot := prog.Roots[subjects[i].Symbol]
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
		var dropCollided func(site ssa.CallInstruction, target *ssa.Function) bool
		droppedAny := false
		if enumerated {
			pinned := enc.addrTaken
			dropCollided = func(site ssa.CallInstruction, target *ssa.Function) bool {
				if site.Common().IsInvoke() {
					return false
				}
				framePath := funcPkgPath(site.Parent())
				if isStdImportPath(framePath) && !userPaths[framePath] {
					return false
				}
				if !pinned[target] && !valueRefOutsideInit[target] {
					droppedAny = true
					return true
				}
				return false
			}
		}
		var usedInitBoxed bool
		reachable[i].subjectFunctions, usedInitBoxed, err = provenanceReachableWithCandidates(ctx, prog, subjectProvenance, mask, res, harnessAudited, userPaths, dropCollided, enc.types, baseStartup.initBoxedTypes)
		if err != nil {
			return nil, err
		}
		if usedInitBoxed {
			reachable[i].initBoxedTypes = baseStartup.initBoxedTypes
		}
		if droppedAny || len(fuzzRoots[i]) > 0 {
			extraRoots := make([]*ssa.Function, 0, len(subjectProvenance)+len(fuzzRoots[i]))
			extraRoots = append(extraRoots, subjectProvenance...)
			extraRoots = append(extraRoots, fuzzRoots[i]...)
			var extraUsedInitBoxed bool
			reachable[i].rootedExtraFunctions, extraUsedInitBoxed, err = provenanceReachableWithCandidates(ctx, prog, extraRoots, mask, res, harnessAudited, userPaths, nil, enc.types, baseStartup.initBoxedTypes)
			if err != nil {
				return nil, err
			}
			if extraUsedInitBoxed {
				reachable[i].initBoxedTypes = baseStartup.initBoxedTypes
			}
		}
		if prog.TestMain != nil && subjectRunsThroughHarness(prog, subjectRoot) {
			var tmUsedInitBoxed bool
			reachable[i].testMainFunctions, tmUsedInitBoxed, err = provenanceReachableWithCandidates(ctx, prog, []*ssa.Function{prog.TestMain}, mask, res, harnessAudited, userPaths, nil, nil, baseStartup.initBoxedTypes)
			if err != nil {
				return nil, err
			}
			if tmUsedInitBoxed {
				reachable[i].initBoxedTypes = baseStartup.initBoxedTypes
			}
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
					if dropCollided != nil && dropCollided(site, target) {
						continue
					}
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
	for i := range reachable {
		mask := uint64(1) << i
		if !unclosedCleanup[i] && len(cleanupRoots[i]) == 0 {
			reachable[i].baseStartup = true
			reachable[i].startupFunctions = baseStartup.startupFunctions
			reachable[i].startupDynamicTargets = baseStartup.startupDynamicTargets
		} else if !unclosedCleanup[i] {
			reachable[i].startupFunctions = maps.Clone(baseStartup.startupFunctions)
			reachable[i].startupDynamicTargets = cloneDynamicTargetMap(baseStartup.startupDynamicTargets)
		} else {
			reachable[i].startupDynamicTargets = make(map[ssa.CallInstruction]map[*ssa.Function]bool)
			reachable[i].startupFunctions, err = provenanceReachableStartup(ctx, audited, prog, initRoots, mask, res, harnessAudited, userPaths)
			if err != nil {
				return nil, err
			}
			for site, targets := range res.Targets {
				callee := site.Common().StaticCallee()
				if res.Reachable[site.Parent()]&mask == 0 || callee != nil && funcPkgPath(callee) == "testing" {
					continue
				}
				for target, masks := range targets {
					if masks&mask != 0 && res.Reachable[target]&mask != 0 {
						projected := reachable[i].startupDynamicTargets[site]
						if projected == nil {
							projected = make(map[*ssa.Function]bool)
							reachable[i].startupDynamicTargets[site] = projected
						}
						projected[target] = true
					}
				}
			}
		}
		if len(cleanupRoots[i]) > 0 {
			reachable[i].cleanupFunctions, err = provenanceReachableStartup(ctx, audited, prog, cleanupRoots[i], mask, res, harnessAudited, userPaths)
			if err != nil {
				return nil, err
			}
			for fn := range reachable[i].cleanupFunctions {
				reachable[i].startupFunctions[fn] = true
			}
			for site, targets := range res.Targets {
				callee := site.Common().StaticCallee()
				if !reachable[i].cleanupFunctions[site.Parent()] || callee != nil && funcPkgPath(callee) == "testing" {
					continue
				}
				for target, masks := range targets {
					if masks&mask != 0 && res.Reachable[target]&mask != 0 {
						projected := reachable[i].startupDynamicTargets[site]
						if projected == nil {
							projected = make(map[*ssa.Function]bool)
							reachable[i].startupDynamicTargets[site] = projected
						}
						projected[target] = true
					}
				}
			}
		}
		reachable[i].rootedIncomplete = unclosedFuzz[i] || rootedProvenanceIncomplete(audited, harnessAudited, prog, userPaths, reachable[i].subjectFunctions, reachable[i].rootedExtraFunctions, reachable[i].testMainFunctions, reachable[i].cleanupFunctions)
	}
	return reachable, nil
}

type baseStartupReachSummary struct {
	startupFunctions      map[*ssa.Function]bool
	startupDynamicTargets map[ssa.CallInstruction]map[*ssa.Function]bool
	initBoxedTypes        []types.Type
	userTouchedStdGlobals map[*ssa.Global]bool
}

func cloneDynamicTargetMap(src map[ssa.CallInstruction]map[*ssa.Function]bool) map[ssa.CallInstruction]map[*ssa.Function]bool {
	out := make(map[ssa.CallInstruction]map[*ssa.Function]bool, len(src))
	for site, targets := range src {
		out[site] = maps.Clone(targets)
	}
	return out
}

func cachedBaseStartupReachability(ctx context.Context, audited bool, prog *program, initRoots, harnessStdInitRoots []*ssa.Function, harnessAudited bool, userPaths map[string]bool) (*baseStartupReachSummary, error) {
	cacheKey := "baseStartupReach:0:0"
	switch {
	case audited && harnessAudited:
		cacheKey = "baseStartupReach:1:1"
	case audited:
		cacheKey = "baseStartupReach:1:0"
	case harnessAudited:
		cacheKey = "baseStartupReach:0:1"
	}
	if prog != nil {
		if cached, ok := prog.Summaries[cacheKey].(*baseStartupReachSummary); ok && cached != nil {
			return cached, nil
		}
	}
	const startupMask uint64 = 1
	initMaskRoots := make(map[*ssa.Function]uint64, len(initRoots))
	for _, fn := range initRoots {
		initMaskRoots[fn] = startupMask
	}
	var initSeeds *rta.Seeds
	if harnessAudited {
		initSeeds = newHarnessRTASeeds(userPaths, harnessStdInitRoots, startupMask)
	}
	initRes, err := rta.Analyze(ctx, initMaskRoots, initSeeds)
	if err != nil {
		return nil, err
	}
	startupFns, err := provenanceReachableStartup(ctx, audited, prog, initRoots, startupMask, initRes, harnessAudited, userPaths)
	if err != nil {
		return nil, err
	}
	startupTargets := make(map[ssa.CallInstruction]map[*ssa.Function]bool)
	for site, targets := range initRes.Targets {
		callee := site.Common().StaticCallee()
		if initRes.Reachable[site.Parent()]&startupMask == 0 || callee != nil && funcPkgPath(callee) == "testing" {
			continue
		}
		for target, masks := range targets {
			if masks&startupMask != 0 && initRes.Reachable[target]&startupMask != 0 {
				projected := startupTargets[site]
				if projected == nil {
					projected = make(map[*ssa.Function]bool)
					startupTargets[site] = projected
				}
				projected[target] = true
			}
		}
	}
	var initBoxedTypes []types.Type
	var userTouchedStdGlobals map[*ssa.Global]bool
	if harnessAudited {
		orderedStartup := make([]*ssa.Function, 0, len(startupFns))
		for fn := range startupFns {
			if fn != nil {
				orderedStartup = append(orderedStartup, fn)
			}
		}
		sort.Slice(orderedStartup, func(i, j int) bool { return lessSSAFunctionOrder(orderedStartup[i], orderedStartup[j]) })
		seenBoxed := map[types.Type]bool{}
		for _, fn := range orderedStartup {
			fp := funcPkgPath(fn)
			if isStdPkgPath(userPaths, fp) || fp == "testing" || propharness.IsHarnessPath(fp) {
				continue
			}
			for _, b := range fn.Blocks {
				for _, instr := range b.Instrs {
					if mi, isMI := instr.(*ssa.MakeInterface); isMI && mi.X != nil && mi.X.Type() != nil {
						xt := mi.X.Type()
						if !seenBoxed[xt] {
							seenBoxed[xt] = true
							initBoxedTypes = append(initBoxedTypes, xt)
						}
					}
				}
			}
		}
		if len(initBoxedTypes) > 0 {
			var opsBuf [8]*ssa.Value
			for _, fn := range orderedStartup {
				fp := funcPkgPath(fn)
				isOwnInit := initFlowFrame(fn)
				for _, b := range fn.Blocks {
					for _, instr := range b.Instrs {
						for _, op := range instr.Operands(opsBuf[:0]) {
							if op == nil {
								continue
							}
							g, ok := (*op).(*ssa.Global)
							if !ok || g == nil || g.Pkg == nil || g.Pkg.Pkg == nil {
								continue
							}
							gPkg := g.Pkg.Pkg.Path()
							if !isStdPkgPath(userPaths, gPkg) || (isOwnInit && fp == gPkg) {
								continue
							}
							if userTouchedStdGlobals == nil {
								userTouchedStdGlobals = make(map[*ssa.Global]bool)
							}
							userTouchedStdGlobals[g] = true
						}
					}
				}
			}
		}
	}
	summary := &baseStartupReachSummary{
		startupFunctions:      startupFns,
		startupDynamicTargets: startupTargets,
		initBoxedTypes:        initBoxedTypes,
		userTouchedStdGlobals: userTouchedStdGlobals,
	}
	if prog != nil && ctx.Err() == nil {
		if prog.Summaries == nil {
			prog.Summaries = make(map[string]any, 4)
		}
		prog.Summaries[cacheKey] = summary
	}
	return summary, nil
}

func partitionHarnessInitRoots(prog *program, harnessAudited bool, userPaths map[string]bool) (initRoots, harnessStdInitRoots []*ssa.Function) {
	if prog == nil || prog.Prog == nil {
		return nil, nil
	}
	var nonHarnessReachable map[*types.Package]bool
	if harnessAudited {
		nonHarnessReachable = make(map[*types.Package]bool)
		if len(prog.Pkgs) > 0 {
			var nonHarnessRoots []*packages.Package
			for _, pkg := range prog.Pkgs {
				if pkg == nil || propharness.IsHarnessPath(pkg.PkgPath) {
					continue
				}
				if pkg.Module != nil || !isStdPkgPath(userPaths, pkg.PkgPath) || pkg.PkgPath == prog.PkgPath || pkg.PkgPath == prog.PkgPath+"_test" || pkg.ForTest == prog.PkgPath || (pkg.Name == "main" && pkg.PkgPath == prog.PkgPath+".test") {
					nonHarnessRoots = append(nonHarnessRoots, pkg)
				}
			}
			packages.Visit(nonHarnessRoots, func(pkg *packages.Package) bool {
				if pkg == nil || propharness.IsHarnessPath(pkg.PkgPath) {
					return false
				}
				if pkg.Types != nil {
					nonHarnessReachable[pkg.Types] = true
				}
				return true
			}, nil)
		} else {
			var queue []*types.Package
			enqueue := func(tp *types.Package) {
				if tp == nil || nonHarnessReachable[tp] || propharness.IsHarnessPath(tp.Path()) {
					return
				}
				nonHarnessReachable[tp] = true
				queue = append(queue, tp)
			}
			for _, sp := range prog.Prog.AllPackages() {
				if sp == nil || sp.Pkg == nil {
					continue
				}
				p := sp.Pkg.Path()
				if isGeneratedTestMainPackage(prog, sp) || p == prog.PkgPath || p == prog.PkgPath+"_test" || (!propharness.IsHarnessPath(p) && !isStdPkgPath(userPaths, p)) {
					enqueue(sp.Pkg)
				}
			}
			for len(queue) > 0 {
				cur := queue[0]
				queue = queue[1:]
				for _, imp := range cur.Imports() {
					enqueue(imp)
				}
			}
		}
	}
	for _, p := range prog.Prog.AllPackages() {
		if isGeneratedTestMainPackage(prog, p) {
			continue
		}
		init := p.Func("init")
		if init == nil {
			continue
		}
		if harnessAudited && p.Pkg != nil && !propharness.IsHarnessPath(p.Pkg.Path()) && !nonHarnessReachable[p.Pkg] {
			harnessStdInitRoots = append(harnessStdInitRoots, init)
			continue
		}
		initRoots = append(initRoots, init)
	}
	return initRoots, harnessStdInitRoots
}

func newHarnessRTASeeds(userPaths map[string]bool, harnessStdInitRoots []*ssa.Function, masks uint64) *rta.Seeds {
	var stdRoots map[*ssa.Function]uint64
	if len(harnessStdInitRoots) > 0 && masks != 0 {
		stdRoots = make(map[*ssa.Function]uint64, len(harnessStdInitRoots))
		for _, fn := range harnessStdInitRoots {
			stdRoots[fn] |= masks
		}
	}
	return &rta.Seeds{
		HarnessPkg:      propharness.ModulePath,
		UserPkgs:        userPaths,
		HarnessStdRoots: stdRoots,
	}
}

// binaryReachableUnion computes the binary-wide union of every harness root's
// post-initialization attributed reach in a single all-roots RTA and provenance
// walk (REQ-closure-shared-dynamic-state-reachability).
func binaryReachableUnion(ctx context.Context, audited bool, pureDelegates map[string]bool, prog *program, subjects []Subject) (RootedFunctions, error) {
	if len(subjects) == 0 {
		return RootedFunctions{Fns: map[string]bool{}, Complete: true}, nil
	}
	const unionMask uint64 = 1
	harnessAudited := propertyHarnessAuditedProg(audited, prog)
	userPaths := userModulePaths(prog.Pkgs)
	roots := make(map[*ssa.Function]uint64)
	var subjectProvenance []*ssa.Function
	includeTestMain := false
	var allFunctions map[*ssa.Function]bool
	openCandidates := map[*ssa.Function]bool{}
	for _, subject := range subjects {
		root := prog.Roots[subject.Symbol]
		if root == nil {
			return RootedFunctions{}, nil
		}
		switch {
		case !parameterizedBody(root):
			roots[root] |= unionMask
			subjectProvenance = append(subjectProvenance, root)
			if rootMayReceiveUnknownDynamic(audited, prog, root) {
				openCandidates[root] = true
			}
		case !rootMayReceiveUnknownDynamic(audited, prog, root):
			if allFunctions == nil {
				allFunctions = progAllFunctions(prog)
			}
			instantiatedAny := false
			for fn := range allFunctions {
				if fn != nil && fn != root && fn.Origin() == root {
					if args := fn.TypeArgs(); len(args) > 0 {
						parameterized := false
						for _, arg := range args {
							if rta.ContainsTypeParam(arg, make(map[types.Type]bool)) {
								parameterized = true
								break
							}
						}
						if parameterized {
							continue
						}
					}
					roots[fn] |= unionMask
					subjectProvenance = append(subjectProvenance, fn)
					instantiatedAny = true
				}
			}
			if !instantiatedAny {
				subjectProvenance = append(subjectProvenance, root)
			}
		default:
			return RootedFunctions{}, nil
		}
		if subjectRunsThroughHarness(prog, root) {
			includeTestMain = true
		}
	}
	initRoots, harnessStdInitRoots := partitionHarnessInitRoots(prog, harnessAudited, userPaths)
	var seeds *rta.Seeds
	if harnessAudited {
		seeds = newHarnessRTASeeds(userPaths, harnessStdInitRoots, unionMask)
	}
	var summary *callerReferenceSummary
	var enumCandidateTypes []types.Type
	if audited || len(openCandidates) > 0 {
		summary = enumerateCallerReferencesForProgram(prog, audited, pureDelegates, userPaths, allFunctions)
		allFunctions = summary.allFunctions
		for root := range openCandidates {
			enc, ok := subjectEnumerationClosure(audited, pureDelegates, userPaths, root, summary)
			if !ok {
				return RootedFunctions{}, nil
			}
			if seeds == nil {
				seeds = &rta.Seeds{AddrTaken: map[*ssa.Function]uint64{}}
			} else if seeds.AddrTaken == nil {
				seeds.AddrTaken = map[*ssa.Function]uint64{}
			}
			for fn := range enc.addrTaken {
				seeds.AddrTaken[fn] |= unionMask
			}
			for _, t := range enc.types {
				seeds.RuntimeTypes = append(seeds.RuntimeTypes, rta.TypeSeed{Type: t, Masks: unionMask})
				enumCandidateTypes = append(enumCandidateTypes, t)
			}
		}
	}
	if audited && (includeTestMain || harnessAudited) {
		if ct := programCancelCtxType(prog.Prog); ct != nil {
			if seeds == nil {
				seeds = &rta.Seeds{}
			}
			seeds.RuntimeTypes = append(seeds.RuntimeTypes, rta.TypeSeed{Type: ct, Masks: unionMask})
		}
	}
	if prog.TestMain != nil && includeTestMain {
		roots[prog.TestMain] |= unionMask
		subjectProvenance = append(subjectProvenance, prog.TestMain)
	}
	for _, init := range initRoots {
		roots[init] |= unionMask
	}
	var initBoxedTypes []types.Type
	if harnessAudited {
		baseStartup, err := cachedBaseStartupReachability(ctx, audited, prog, initRoots, harnessStdInitRoots, harnessAudited, userPaths)
		if err != nil {
			return RootedFunctions{}, err
		}
		initBoxedTypes = baseStartup.initBoxedTypes
	}
	rootedCallbacks := map[*ssa.Function]bool{}
	var res *rta.Result
	var provenance map[*ssa.Function]bool
	for {
		var err error
		res, err = rta.Analyze(ctx, roots, seeds)
		if err != nil {
			if ctx.Err() != nil {
				return RootedFunctions{}, err
			}
			if shapeFailure(err) {
				return RootedFunctions{}, nil
			}
			return RootedFunctions{}, err
		}
		for _, subject := range subjects {
			if origin := prog.Roots[subject.Symbol]; parameterizedBody(origin) {
				res.Reachable[origin] |= unionMask
			}
		}
		provenance, _, err = provenanceReachableWithCandidates(ctx, prog, subjectProvenance, unionMask, res, harnessAudited, userPaths, nil, enumCandidateTypes, initBoxedTypes)
		if err != nil {
			return RootedFunctions{}, err
		}
		cbs, unclosedCB, fbs, unclosedFB := collectTestingHarnessCallbacks(audited, harnessAudited, pureDelegates, userPaths, summary, nil, false, enumerationClosure{}, provenance, unionMask, res)
		if unclosedCB || unclosedFB {
			return RootedFunctions{}, nil
		}
		addedAny := false
		for _, cb := range cbs {
			if !rootedCallbacks[cb] {
				rootedCallbacks[cb] = true
				roots[cb] |= unionMask
				subjectProvenance = append(subjectProvenance, cb)
				addedAny = true
			}
		}
		for _, fb := range fbs {
			if !rootedCallbacks[fb] {
				rootedCallbacks[fb] = true
				roots[fb] |= unionMask
				subjectProvenance = append(subjectProvenance, fb)
				if len(fb.Params) > 0 && isHarnessPointerType(fb.Params[0].Type()) && paramHasMakeInterface(fb.Params[0], make(map[*ssa.Parameter]bool)) {
					if seeds == nil {
						seeds = &rta.Seeds{}
					}
					seeds.RuntimeTypes = append(seeds.RuntimeTypes, rta.TypeSeed{Type: fb.Params[0].Type(), Masks: unionMask})
				}
				addedAny = true
			}
		}
		if !addedAny {
			break
		}
	}
	if rootedProvenanceIncomplete(audited, harnessAudited, prog, userPaths, provenance) {
		return RootedFunctions{}, nil
	}
	fns := make(map[string]bool, len(provenance))
	for fn := range provenance {
		if key := rootedFunctionKey(fn); key != "" {
			fns[key] = true
		}
	}
	if err := ctx.Err(); err != nil {
		return RootedFunctions{}, err
	}
	return RootedFunctions{Fns: fns, Complete: true}, nil
}

func isTestingMRun(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	// The disjunction is order-free; the structural arm is checked first
	// because it needs no rendering, and only a non-testing-package name
	// pays the RelString render for the wrapper/thunk forms the string
	// arm exists to catch.
	if fn.Signature != nil && fn.Signature.Recv() != nil && funcPkgPath(fn) == "testing" && fn.Name() == "Run" &&
		strings.Contains(types.TypeString(fn.Signature.Recv().Type(), nil), "testing.M") {
		return true
	}
	// "testing.M).Run" in the rendered string always begins inside the
	// name portion (the receiver ends at ")."), so a name without "Run"
	// can never match — synthetic wrappers ("Run$bound", "Run$thunk")
	// keep it, and they may lack package identity, so the name is the
	// only allocation-free gate that loses nothing.
	if !strings.Contains(fn.Name(), "Run") {
		return false
	}
	return strings.Contains(fn.String(), "testing.M).Run")
}

func isTestingBLaunch(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	if p := fn.Parent(); p != nil && p.Signature != nil && p.Signature.Recv() != nil &&
		funcPkgPath(p) == "testing" && p.Name() == "run1" &&
		strings.Contains(types.TypeString(p.Signature.Recv().Type(), nil), "testing.B") {
		return true
	}
	if fn.Signature != nil && fn.Signature.Recv() != nil && funcPkgPath(fn) == "testing" && fn.Name() == "launch" &&
		strings.Contains(types.TypeString(fn.Signature.Recv().Type(), nil), "testing.B") {
		return true
	}
	if !strings.Contains(fn.Name(), "launch") {
		return false
	}
	return strings.Contains(fn.String(), "testing.B).launch")
}

// auditedHarnessSubtestDriver reports whether a function is the
// harness's subtest driver - exactly (*testing.T).Run and
// (*testing.B).Run, matched by receiver and name. The driver allocates
// a child harness handle, prints run-boundary bytes into the recorded
// output, keeps write-only harness bookkeeping no testing API hands
// back, consults run-filter state that shapes selection and
// recorded-output bytes only, and runs the caller-supplied callback -
// whose body is walked and classified at its own sites - on a
// harness-managed goroutine it waits for, returning only an outcome
// bit. Receiver discrimination is load-bearing: (*testing.M).Run is
// the test-main driver and (*testing.F).Fuzz dispatches its target
// reflectively over corpus files - both keep their classifications
// (REQ-closure-observability-subtest-driver).
func auditedHarnessSubtestDriver(audited bool, fn *ssa.Function) bool {
	_, ok := harnessCalleeEffect(audited, fn, false)
	return ok && functionSymbolName(fn) == "Run"
}

// enumerationClosure is one signature-open subject's whole-view caller
// closure (REQ-closure-analysis): the direct static call sites that are
// its only references, plus the dispatch candidates those sites pass —
// closed function values seeded address-taken, materialized concrete
// types seeded into the runtime-type walk — so everything an enumerable
// caller can hand the subject is analyzed view content.
type enumerationClosure struct {
	sites       []ssa.CallInstruction
	addrTaken   map[*ssa.Function]bool
	types       []types.Type
	fieldStores map[int][]ssa.Value
}

type structFieldKey struct {
	named *types.Named
	field int
}

type dynamicSeedEntry struct {
	types []types.Type
	funcs []*ssa.Function
}

type callerReferenceSummary struct {
	sites                  map[*ssa.Function][]ssa.CallInstruction
	valueRef               map[*ssa.Function]bool
	directValueRef         map[*ssa.Function]bool
	valueRefOutsideInit    map[*ssa.Function]bool
	closureRefs            map[*ssa.Function][]*ssa.MakeClosure
	nonClosureRef          map[*ssa.Function]bool
	structRefFirstFn       map[*types.Named]*ssa.Function
	structRefMultiFn       map[*types.Named]bool
	structReferencedByType map[*types.Named]bool
	structPoisoned         map[structFieldKey]bool
	structFieldStores      map[structFieldKey][]ssa.Value
	structWholeStores      map[*types.Named][]ssa.Value
	structBoxedValues      map[*types.Named][]ssa.Value
	structFieldReads       map[structFieldKey][]ssa.Value
	namedSigSources        map[*types.Named][]ssa.Value
	namedSigPoisoned       map[*types.Named]bool
	allFunctions           map[*ssa.Function]bool
	userPaths              map[string]bool

	progClosedDone    map[ssa.Value]bool
	enumClosedDone    map[ssa.Value]bool
	progTypesMemo     map[ssa.Value][]types.Type
	progTypesFailed   map[ssa.Value]bool
	enumTypesMemo     map[ssa.Value][]types.Type
	enumTypesFailed   map[ssa.Value]bool
	progFuncsMemo     map[ssa.Value][]*ssa.Function
	progFuncsFailed   map[ssa.Value]bool
	progInvokeTargets map[ssa.CallInstruction]map[*ssa.Function]bool
	progInvokeFailed  map[ssa.CallInstruction]bool
	enumInvokeTargets map[ssa.CallInstruction]map[*ssa.Function]bool
	enumInvokeFailed  map[ssa.CallInstruction]bool
	enumSeedsMemo     map[ssa.Value]dynamicSeedEntry
	enumStructClosed  map[*types.Named]bool
	prog              *program
}

func (s *callerReferenceSummary) isStructReferencedOutside(named *types.Named, root *ssa.Function) bool {
	if s == nil || named == nil {
		return false
	}
	first, ok := s.structRefFirstFn[named]
	return ok && (first != root || s.structRefMultiFn[named])
}

func summaryCacheKeyFor(audited bool, pureDelegates map[string]bool) string {
	prefix := "0"
	if audited {
		prefix = "1"
	}
	if len(pureDelegates) == 0 {
		return prefix
	}
	keys := make([]string, 0, len(pureDelegates))
	for k, ok := range pureDelegates {
		if ok {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return prefix
	}
	slices.Sort(keys)
	return prefix + ":" + strings.Join(keys, ",")
}

func lessSSAFunctionOrder(a, b *ssa.Function) bool {
	if a == b {
		return false
	}
	if a.Name() != b.Name() {
		return a.Name() < b.Name()
	}
	pa, pb := funcPkgPath(a), funcPkgPath(b)
	if pa != pb {
		return pa < pb
	}
	if a.Pos() != b.Pos() {
		return a.Pos() < b.Pos()
	}
	return a.String() < b.String()
}

func progAllFunctions(p *program) map[*ssa.Function]bool {
	if p == nil || p.Prog == nil {
		return nil
	}
	if p.AllFunctions != nil {
		return p.AllFunctions
	}
	p.AllFunctions = ssautil.AllFunctions(p.Prog)
	return p.AllFunctions
}

type orderedFuncKey struct {
	fn      *ssa.Function
	name    string
	pkgPath string
	pos     token.Pos
}

func progOrderedFunctions(p *program) []*ssa.Function {
	if p == nil || p.Prog == nil {
		return nil
	}
	if p.OrderedFunctions != nil {
		return p.OrderedFunctions
	}
	p.OrderedFunctions = orderedFunctionsForProgram(progAllFunctions(p))
	return p.OrderedFunctions
}

func orderedFunctionsForProgram(all map[*ssa.Function]bool) []*ssa.Function {
	keys := make([]orderedFuncKey, 0, len(all))
	for fn := range all {
		if fn != nil {
			keys = append(keys, orderedFuncKey{
				fn:      fn,
				name:    fn.Name(),
				pkgPath: funcPkgPath(fn),
				pos:     fn.Pos(),
			})
		}
	}
	slices.SortFunc(keys, func(a, b orderedFuncKey) int {
		if a.fn == b.fn {
			return 0
		}
		if a.name != b.name {
			if a.name < b.name {
				return -1
			}
			return 1
		}
		if a.pkgPath != b.pkgPath {
			if a.pkgPath < b.pkgPath {
				return -1
			}
			return 1
		}
		if a.pos != b.pos {
			if a.pos < b.pos {
				return -1
			}
			return 1
		}
		sa, sb := a.fn.String(), b.fn.String()
		if sa < sb {
			return -1
		}
		if sa > sb {
			return 1
		}
		return 0
	})
	ordered := make([]*ssa.Function, len(keys))
	for i := range keys {
		ordered[i] = keys[i].fn
	}
	return ordered
}

func isPromotedWrapper(fn *ssa.Function) bool {
	return fn != nil && strings.HasPrefix(fn.Synthetic, "wrapper for ")
}

func isUnnamedStructPromotedWrapper(fn *ssa.Function) bool {
	if !isPromotedWrapper(fn) || fn.Pkg != nil || fn.Signature == nil || fn.Signature.Recv() == nil {
		return false
	}
	t := types.Unalias(fn.Signature.Recv().Type())
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	_, ok := t.(*types.Struct)
	return ok
}

func unnamedWrapperDeclaringPkg(fn *ssa.Function) *types.Package {
	if !isUnnamedStructPromotedWrapper(fn) {
		return nil
	}
	t := types.Unalias(fn.Signature.Recv().Type())
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	st, ok := t.(*types.Struct)
	if !ok {
		return nil
	}
	for i := 0; i < st.NumFields(); i++ {
		if pkg := st.Field(i).Pkg(); pkg != nil {
			return pkg
		}
	}
	return nil
}

func isAnalyzableUnnamedWrapper(fn *ssa.Function) bool {
	return isUnnamedStructPromotedWrapper(fn) && len(fn.Blocks) > 0
}

func isStdPkgPath(userPaths map[string]bool, pkgPath string) bool {
	return pkgPath != "" && !userPaths[pkgPath] && isStdImportPath(pkgPath)
}

func isBoundMethodWrapper(fn *ssa.Function) bool {
	return fn != nil && strings.HasPrefix(fn.Synthetic, "bound method wrapper for ")
}

// enumerateCallerReferences makes one deterministic pass over the whole
// analyzed program, collecting for each candidate root its direct static
// call sites and whether any other reference exists — an address
// capture, a stored value, a dynamic use, or a call held by a body the
// enumeration cannot judge as a caller. The same pass records, for EVERY
// function value in the program, whether any address-taking reference to
// it lies outside initializer flow: a value with none is init-planted —
// whatever its shape (an init-parented anonymous closure, a synthetic
// method-value wrapper materialized by an initializer, a named function
// registered there) — and feeds the enumeration-target narrowing.
// Function order is sorted so site order, and every judgment derived
// from it, is run-to-run stable.
func enumerateCallerReferencesForProgram(prog *program, audited bool, pureDelegates map[string]bool, userPaths map[string]bool, all map[*ssa.Function]bool) *callerReferenceSummary {
	key := summaryCacheKeyFor(audited, pureDelegates)
	var ordered []*ssa.Function
	if prog != nil {
		if cached, ok := prog.Summaries[key].(*callerReferenceSummary); ok && cached != nil {
			return cached
		}
		if all == nil {
			all = progAllFunctions(prog)
		}
		if len(all) == len(progAllFunctions(prog)) {
			ordered = progOrderedFunctions(prog)
		}
	}
	res := enumerateCallerReferencesWithOrdered(audited, userPaths, all, ordered)
	res.prog = prog
	if prog != nil {
		if prog.Summaries == nil {
			prog.Summaries = make(map[string]any, 2)
		}
		prog.Summaries[key] = res
	}
	return res
}

func enumerateCallerReferences(audited bool, userPaths map[string]bool, all map[*ssa.Function]bool) *callerReferenceSummary {
	return enumerateCallerReferencesWithOrdered(audited, userPaths, all, nil)
}

func enumerateCallerReferencesWithOrdered(audited bool, userPaths map[string]bool, all map[*ssa.Function]bool, ordered []*ssa.Function) *callerReferenceSummary {
	if ordered == nil {
		ordered = orderedFunctionsForProgram(all)
	}
	largeCap := max(len(ordered)/4, 16)
	smallCap := max(len(ordered)/16, 16)
	summary := callerReferenceSummary{
		sites:                  make(map[*ssa.Function][]ssa.CallInstruction, largeCap),
		valueRef:               make(map[*ssa.Function]bool, smallCap),
		directValueRef:         make(map[*ssa.Function]bool, smallCap),
		valueRefOutsideInit:    make(map[*ssa.Function]bool, smallCap),
		closureRefs:            make(map[*ssa.Function][]*ssa.MakeClosure),
		nonClosureRef:          make(map[*ssa.Function]bool, largeCap),
		structRefFirstFn:       make(map[*types.Named]*ssa.Function),
		structRefMultiFn:       make(map[*types.Named]bool),
		structReferencedByType: make(map[*types.Named]bool),
		structPoisoned:         make(map[structFieldKey]bool),
		structFieldStores:      make(map[structFieldKey][]ssa.Value),
		structWholeStores:      make(map[*types.Named][]ssa.Value),
		structBoxedValues:      make(map[*types.Named][]ssa.Value),
		structFieldReads:       make(map[structFieldKey][]ssa.Value),
		namedSigSources:        make(map[*types.Named][]ssa.Value),
		namedSigPoisoned:       make(map[*types.Named]bool),
		allFunctions:           all,
		userPaths:              userPaths,
		progClosedDone:         make(map[ssa.Value]bool),
		enumClosedDone:         make(map[ssa.Value]bool),
		progTypesMemo:          make(map[ssa.Value][]types.Type),
		progTypesFailed:        make(map[ssa.Value]bool),
		enumTypesMemo:          make(map[ssa.Value][]types.Type),
		enumTypesFailed:        make(map[ssa.Value]bool),
		progFuncsMemo:          make(map[ssa.Value][]*ssa.Function),
		progFuncsFailed:        make(map[ssa.Value]bool),
		progInvokeTargets:      make(map[ssa.CallInstruction]map[*ssa.Function]bool),
		progInvokeFailed:       make(map[ssa.CallInstruction]bool),
		enumInvokeTargets:      make(map[ssa.CallInstruction]map[*ssa.Function]bool),
		enumInvokeFailed:       make(map[ssa.CallInstruction]bool),
		enumSeedsMemo:          make(map[ssa.Value]dynamicSeedEntry),
		enumStructClosed:       make(map[*types.Named]bool),
	}
	recordStructRef := func(named *types.Named, fn *ssa.Function) {
		summary.structReferencedByType[named] = true
		if first, ok := summary.structRefFirstFn[named]; !ok {
			summary.structRefFirstFn[named] = fn
		} else if first != fn {
			summary.structRefMultiFn[named] = true
		}
	}
	namedSigReferenced := make(map[*types.Named]bool)
	recordNamedSigRef := func(ns *types.Named) {
		if ns != nil {
			namedSigReferenced[ns] = true
		}
	}
	structFieldReads := summary.structFieldReads
	closureRefs := make(map[*ssa.Function][]*ssa.MakeClosure)
	storeRefs := make(map[*ssa.Function][]*ssa.Store)
	callArgRefs := make(map[*ssa.Function][]ssa.CallInstruction)
	methodsByName := make(map[string][]*ssa.Function)
	instantiatedOrigins := make(map[*ssa.Function]bool)
	if audited {
		for _, fn := range ordered {
			if orig := fn.Origin(); orig != nil && !parameterizedBody(fn) {
				instantiatedOrigins[orig] = true
			}
			fnPkg := funcPkgPath(fn)
			if isStdPkgPath(userPaths, fnPkg) {
				continue
			}
			if fn.Signature == nil || fn.Signature.Recv() == nil || (fn.Synthetic != "" && !isPromotedWrapper(fn) && !(audited && fn.Origin() != nil)) || parameterizedBody(fn) || len(fn.Params) == 0 {
				continue
			}
			hasDynamicParam := false
			if recv := fn.Params[0]; recv != nil && derefNamedStruct(userPaths, recv.Type()) == nil && derefNamedSignature(userPaths, recv.Type()) == nil && typeMayCarryDynamicTop(audited, recv.Type()) {
				hasDynamicParam = true
			}
			if !hasDynamicParam {
				for _, param := range fn.Params[1:] {
					if param != nil && typeMayCarryDynamicTop(audited, param.Type()) {
						hasDynamicParam = true
						break
					}
				}
			}
			if hasDynamicParam {
				methodsByName[fn.Name()] = append(methodsByName[fn.Name()], fn)
			}
		}
	}
	poisonStruct := func(named *types.Named, field int) {
		if named == nil {
			return
		}
		if field < 0 {
			summary.structPoisoned[structFieldKey{named: named, field: -1}] = true
			if st, ok := named.Underlying().(*types.Struct); ok {
				for i := 0; i < st.NumFields(); i++ {
					summary.structPoisoned[structFieldKey{named: named, field: i}] = true
				}
			}
			return
		}
		summary.structPoisoned[structFieldKey{named: named, field: field}] = true
	}
	poisonContainedTypes := func(t types.Type, refFn *ssa.Function) {
		walkTypeGraph(t, true, map[types.Type]bool{}, func(sub types.Type) bool {
			if named := derefNamedStruct(userPaths, sub); named != nil {
				if refFn != nil {
					recordStructRef(named, refFn)
				}
				poisonStruct(named, -1)
			} else if ns := derefNamedSignature(userPaths, sub); ns != nil {
				recordNamedSigRef(ns)
				summary.namedSigPoisoned[ns] = true
			}
			return true
		})
	}
	poisonEmbeddedCarriers := func(recvOrBoxed types.Type, topNamed *types.Named, refFn *ssa.Function) {
		if recvOrBoxed == nil {
			return
		}
		baseT := types.Unalias(recvOrBoxed)
		if ptr, ok := baseT.(*types.Pointer); ok {
			baseT = types.Unalias(ptr.Elem())
		}
		st, ok := baseT.Underlying().(*types.Struct)
		if !ok {
			return
		}
		seenEmbed := make(map[*types.Struct]bool)
		var walkEmbed func(*types.Struct)
		walkEmbed = func(cur *types.Struct) {
			if cur == nil || seenEmbed[cur] {
				return
			}
			seenEmbed[cur] = true
			for i := 0; i < cur.NumFields(); i++ {
				fld := cur.Field(i)
				if !fld.Embedded() {
					continue
				}
				ft := fld.Type()
				if inner := derefNamedStruct(userPaths, ft); inner != nil {
					if refFn != nil {
						recordStructRef(inner, refFn)
					}
					poisonStruct(inner, -1)
				}
				if ns := derefNamedSignature(userPaths, ft); ns != nil {
					recordNamedSigRef(ns)
					summary.namedSigPoisoned[ns] = true
				}
				ftElem := types.Unalias(ft)
				if ptr, ok := ftElem.(*types.Pointer); ok {
					ftElem = types.Unalias(ptr.Elem())
				}
				switch sub := ftElem.Underlying().(type) {
				case *types.Struct:
					walkEmbed(sub)
				case *types.Interface:
				default:
					if topNamed != nil && typeMayCarryDynamicTop(audited, ftElem) {
						poisonStruct(topNamed, -1)
					}
				}
			}
		}
		walkEmbed(st)
	}
	type candIfaceKey struct {
		cand  *ssa.Function
		iface *types.Interface
	}
	var implMemo map[candIfaceKey]bool
	sawReflectMutation := false
	var space [16]*ssa.Value
	for _, fn := range ordered {
		if audited && parameterizedBody(fn) {
			orig := fn
			if fn.Origin() != nil {
				orig = fn.Origin()
			}
			if instantiatedOrigins[orig] {
				continue
			}
		}
		// A body the enumeration cannot judge as a caller — a synthetic
		// function (other than a promoted-method forwarding wrapper) or a
		// parameterized origin (open over type parameters) — makes any
		// call it holds a refusing reference, exactly like a value
		// capture: its arguments are never judged, so they must never
		// count as an enumerated site.
		fnIsPromotedWrapper := isPromotedWrapper(fn)
		fnIsBoundWrapper := isBoundMethodWrapper(fn)
		fnRecordCallSite := !fnIsPromotedWrapper && !(audited && fnIsBoundWrapper)
		fnRecordInvokeSite := !fnIsPromotedWrapper && !fnIsBoundWrapper
		judgeable := (fn.Synthetic == "" || fnIsPromotedWrapper || (audited && fn.Origin() != nil)) && !parameterizedBody(fn)
		structJudgeable := fn.Synthetic == "" || fnIsPromotedWrapper || (audited && fn.Origin() != nil)
		fnPkg := funcPkgPath(fn)
		nonStdFrame := !isStdPkgPath(userPaths, fnPkg)
		hasUserTypes := nonStdFrame
		if !hasUserTypes {
			for cur := fn; cur != nil; cur = cur.Parent() {
				if len(cur.TypeArgs()) > 0 {
					hasUserTypes = true
					break
				}
			}
		}
		initFrame := initFlowFrame(fn)
		if audited && hasUserTypes {
			hasRecv := fn.Signature != nil && fn.Signature.Recv() != nil
			for pIdx, param := range fn.Params {
				if param == nil || param.Type() == nil {
					continue
				}
				if named := derefNamedStruct(userPaths, param.Type()); named != nil {
					recordStructRef(named, fn)
					if !structJudgeable {
						poisonStruct(named, -1)
					}
				} else if namedSig := derefNamedSignature(userPaths, param.Type()); namedSig != nil {
					recordNamedSigRef(namedSig)
					if hasRecv && pIdx == 0 {
						continue
					}
					if !structJudgeable {
						summary.namedSigPoisoned[namedSig] = true
					} else if _, isPtr := types.Unalias(param.Type()).(*types.Pointer); !isPtr {
						summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], param)
					} else {
						summary.namedSigPoisoned[namedSig] = true
					}
				}
			}
		}
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if audited && hasUserTypes {
					if v, ok := instr.(ssa.Value); ok && v.Type() != nil {
						if named := derefNamedStruct(userPaths, v.Type()); named != nil {
							recordStructRef(named, fn)
							poison := !structJudgeable
							switch instr.(type) {
							case *ssa.Convert, *ssa.ChangeType:
								poison = true
							case ssa.CallInstruction:
								if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
									if callee := site.Common().StaticCallee(); callee != nil && len(callee.Blocks) == 0 {
										poison = true
									}
								}
							}
							if poison {
								poisonStruct(named, -1)
							}
						} else if namedSig := derefNamedSignature(userPaths, v.Type()); namedSig != nil {
							recordNamedSigRef(namedSig)
							if isPromotedWrapper(fn) && fn.Signature != nil && fn.Signature.Recv() != nil && derefNamedSignature(userPaths, fn.Signature.Recv().Type()) == namedSig {
								// Synthetic pointer-method-table wrapper (*NamedSig).M:
								// boxing *NamedSig via MakeInterface or referencing w
								// directly poisons namedSig below; value MakeInterface
								// already records the boxed NamedSig operand.
							} else if !structJudgeable {
								summary.namedSigPoisoned[namedSig] = true
							} else if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr {
								switch x := instr.(type) {
								case *ssa.Phi:
								case *ssa.ChangeType:
									if x.X == nil {
										summary.namedSigPoisoned[namedSig] = true
									} else {
										summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], x.X)
									}
								case *ssa.MakeClosure:
									summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], v)
								case *ssa.TypeAssert, *ssa.Extract, *ssa.Lookup, *ssa.Index, *ssa.Field, *ssa.UnOp:
									summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], v)
								case ssa.CallInstruction:
									if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
										if callee := site.Common().StaticCallee(); callee != nil && len(callee.Blocks) == 0 {
											summary.namedSigPoisoned[namedSig] = true
										} else {
											summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], v)
										}
									}
								default:
									summary.namedSigPoisoned[namedSig] = true
								}
							} else if v.Referrers() == nil {
								summary.namedSigPoisoned[namedSig] = true
							} else {
								for _, ref := range *v.Referrers() {
									switch r := ref.(type) {
									case *ssa.DebugRef:
									case *ssa.UnOp:
										if r.Op != token.MUL || r.X != v {
											summary.namedSigPoisoned[namedSig] = true
										}
									case *ssa.Store:
										if r.Addr != v || r.Val == nil {
											summary.namedSigPoisoned[namedSig] = true
										} else if _, isInstr := r.Val.(ssa.Instruction); !isInstr {
											summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], r.Val)
										}
									default:
										summary.namedSigPoisoned[namedSig] = true
									}
								}
							}
						}
					}
					switch x := instr.(type) {
					case *ssa.Convert:
						if x.X != nil {
							poisonContainedTypes(x.X.Type(), fn)
						}
						if x.Type() != nil {
							poisonContainedTypes(x.Type(), fn)
						}
					case *ssa.ChangeType:
						if x.X != nil {
							if named := derefNamedStruct(userPaths, x.X.Type()); named != nil {
								poisonStruct(named, -1)
							}
						}
					case *ssa.MakeInterface:
						if x.X != nil && x.X.Type() != nil {
							elemT := x.X.Type()
							_, isPtr := types.Unalias(elemT).(*types.Pointer)
							if ptr, ok := types.Unalias(elemT).(*types.Pointer); ok {
								elemT = ptr.Elem()
							}
							if ns := derefNamedSignature(userPaths, x.X.Type()); ns != nil {
								recordNamedSigRef(ns)
								if !structJudgeable || isPtr {
									summary.namedSigPoisoned[ns] = true
								} else {
									summary.namedSigSources[ns] = append(summary.namedSigSources[ns], x.X)
								}
							}
							topNamed := derefNamedStruct(userPaths, x.X.Type())
							for _, inner := range collectValueContainedUserStructs(userPaths, elemT) {
								recordStructRef(inner, fn)
								if structJudgeable && topNamed != nil {
									if inner == topNamed {
										summary.structBoxedValues[inner] = append(summary.structBoxedValues[inner], x.X)
									}
								} else {
									poisonStruct(inner, -1)
								}
							}
							poisonEmbeddedCarriers(x.X.Type(), topNamed, fn)
						}
					}
					if f, ok := instr.(*ssa.Field); ok && f.X != nil {
						if named := derefNamedStruct(userPaths, f.X.Type()); named != nil {
							if !structJudgeable {
								poisonStruct(named, f.Field)
							} else {
								key := structFieldKey{named: named, field: f.Field}
								structFieldReads[key] = append(structFieldReads[key], f)
							}
						}
					}
					if fa, ok := instr.(*ssa.FieldAddr); ok && fa.X != nil {
						if named := derefNamedStruct(userPaths, fa.X.Type()); named != nil {
							recordStructRef(named, fn)
							innerNamed := derefNamedStruct(userPaths, fa.Type())
							if innerNamed != nil {
								recordStructRef(innerNamed, fn)
							}
							if !structJudgeable || fa.Referrers() == nil {
								poisonStruct(named, fa.Field)
							} else {
								for _, ref := range *fa.Referrers() {
									switch r := ref.(type) {
									case *ssa.DebugRef:
									case *ssa.UnOp:
										if r.Op != token.MUL || r.X != fa {
											poisonStruct(named, fa.Field)
										} else {
											key := structFieldKey{named: named, field: fa.Field}
											structFieldReads[key] = append(structFieldReads[key], r)
										}
									case *ssa.Store:
										if r.Addr != fa {
											poisonStruct(named, fa.Field)
										} else {
											key := structFieldKey{named: named, field: fa.Field}
											summary.structFieldStores[key] = append(summary.structFieldStores[key], r.Val)
										}
									case *ssa.FieldAddr:
										if innerNamed == nil || r.X != fa {
											poisonStruct(named, fa.Field)
										}
									case ssa.CallInstruction:
										_, isGo := r.(*ssa.Go)
										okCall := false
										if !isGo && innerNamed != nil && r.Common() != nil && !r.Common().IsInvoke() {
											if callee := r.Common().StaticCallee(); callee != nil && len(callee.Blocks) > 0 && (callee.Synthetic == "" || isPromotedWrapper(callee) || (audited && callee.Origin() != nil)) && !parameterizedBody(callee) && len(r.Common().Args) == len(callee.Params) {
												okCall = true
												for i, arg := range r.Common().Args {
													if arg == fa && derefNamedStruct(userPaths, callee.Params[i].Type()) != innerNamed {
														okCall = false
														break
													}
												}
											}
										}
										if !okCall {
											poisonStruct(named, fa.Field)
										}
									default:
										poisonStruct(named, fa.Field)
									}
								}
							}
						}
					}
					if st, ok := instr.(*ssa.Store); ok && st.Val != nil && st.Val.Type() != nil {
						c, isConst := st.Val.(*ssa.Const)
						isZero := isConst && c.Value == nil
						if !isZero {
							var topNamed *types.Named
							if _, isPtr := types.Unalias(st.Val.Type()).(*types.Pointer); !isPtr {
								topNamed = derefNamedStruct(userPaths, st.Val.Type())
							}
							for _, inner := range collectValueContainedUserStructs(userPaths, st.Val.Type()) {
								recordStructRef(inner, fn)
								if structJudgeable && topNamed != nil {
									if inner == topNamed {
										summary.structWholeStores[inner] = append(summary.structWholeStores[inner], st.Val)
									}
								} else {
									poisonStruct(inner, -1)
								}
							}
						}
					}
					if nonStdFrame {
						if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
							c := site.Common()
							if c.IsInvoke() {
								if c.Method != nil && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "reflect" && isReflectMutationSymbol(c.Method.Name()) {
									sawReflectMutation = true
								}
							} else if callee := c.StaticCallee(); callee != nil {
								calleePkg := funcPkgPath(callee)
								calleeSym := strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(callee), "$bound"), "$thunk")
								if calleePkg == "reflect" && isReflectMutationSymbol(calleeSym) {
									sawReflectMutation = true
								}
								calleeNonStd := !isStdPkgPath(userPaths, calleePkg)
								if (calleeNonStd && len(callee.Blocks) == 0 && callee.Synthetic == "" && !parameterizedBody(callee)) || isStdDeserializerCall(calleePkg, calleeSym) {
									for _, arg := range c.Args {
										if arg != nil {
											poisonContainedTypes(arg.Type(), fn)
										}
									}
									if val := site.Value(); val != nil {
										poisonContainedTypes(val.Type(), fn)
									}
									for _, ta := range callee.TypeArgs() {
										poisonContainedTypes(ta, fn)
									}
								}
							}
						}
					}
				}
				rands := instr.Operands(space[:0])
				if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
					if callee := site.Common().StaticCallee(); callee != nil {
						summary.nonClosureRef[callee] = true
						if fnRecordCallSite {
							if judgeable {
								summary.sites[callee] = append(summary.sites[callee], site)
							} else {
								summary.valueRef[callee] = true
								summary.directValueRef[callee] = true
							}
						}
					} else if audited && len(methodsByName) > 0 && site.Common().IsInvoke() && site.Common().Method != nil {
						if cands := methodsByName[site.Common().Method.Name()]; len(cands) > 0 {
							iface, _ := types.Unalias(site.Common().Value.Type()).Underlying().(*types.Interface)
							if iface != nil {
								for _, cand := range cands {
									if cand == fn {
										continue
									}
									key := candIfaceKey{cand: cand, iface: iface}
									impl, cached := implMemo[key]
									if !cached {
										recvType := cand.Signature.Recv().Type()
										impl = types.Implements(recvType, iface) || types.Implements(types.NewPointer(recvType), iface)
										if implMemo == nil {
											implMemo = make(map[candIfaceKey]bool, 16)
										}
										implMemo[key] = impl
									}
									if impl && fnRecordInvokeSite {
										if judgeable {
											summary.sites[cand] = append(summary.sites[cand], site)
										} else {
											summary.valueRef[cand] = true
											summary.directValueRef[cand] = true
										}
									}
								}
							}
						}
					}
					if !site.Common().IsInvoke() {
						// The callee operand is the call itself, not a
						// value reference.
						rands = rands[1:]
					}
				}
				for _, op := range rands {
					if audited && hasUserTypes && op != nil && *op != nil && (*op).Type() != nil {
						if named := derefNamedStruct(userPaths, (*op).Type()); named != nil {
							recordStructRef(named, fn)
						} else if g, isGlob := (*op).(*ssa.Global); isGlob {
							if ns := derefNamedSignature(userPaths, g.Type()); ns != nil {
								recordNamedSigRef(ns)
								unopLoad := false
								if u, ok := instr.(*ssa.UnOp); ok && u.Op == token.MUL && u.X == g {
									unopLoad = true
								}
								storeAddr := false
								if st, ok := instr.(*ssa.Store); ok && st.Addr == g && st.Val != g {
									storeAddr = true
								}
								if !structJudgeable || (!unopLoad && !storeAddr) {
									summary.namedSigPoisoned[ns] = true
								}
							}
						}
					}
					if g, ok := (*op).(*ssa.Function); ok {
						if audited && nonStdFrame && funcPkgPath(g) == "reflect" && isReflectMutationSymbol(strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(g), "$bound"), "$thunk")) {
							sawReflectMutation = true
						}
						summary.directValueRef[g] = true
						if !initFrame {
							summary.valueRefOutsideInit[g] = true
						}
						if audited && judgeable && !fnIsPromotedWrapper {
							if mc, ok := instr.(*ssa.MakeClosure); ok && mc.Fn == g && !slices.Contains(mc.Bindings, ssa.Value(g)) {
								closureRefs[g] = append(closureRefs[g], mc)
								summary.closureRefs[g] = closureRefs[g]
								continue
							}
							summary.nonClosureRef[g] = true
							if st, ok := instr.(*ssa.Store); ok && st.Val == g && st.Addr != g {
								storeRefs[g] = append(storeRefs[g], st)
								continue
							}
							if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil && !site.Common().IsInvoke() && site.Common().StaticCallee() != nil {
								callArgRefs[g] = append(callArgRefs[g], site)
								continue
							}
						}
						summary.nonClosureRef[g] = true
						summary.valueRef[g] = true
					}
				}
			}
		}
	}
	if audited {
		for _, w := range ordered {
			if !isPromotedWrapper(w) || w.Signature == nil || w.Signature.Recv() == nil {
				continue
			}
			hasDirectCall := false
			for _, s := range summary.sites[w] {
				if s != nil && s.Common() != nil && !s.Common().IsInvoke() {
					hasDirectCall = true
					break
				}
			}
			if !hasDirectCall && !summary.valueRef[w] && !summary.directValueRef[w] {
				continue
			}
			if ns := derefNamedSignature(userPaths, w.Signature.Recv().Type()); ns != nil {
				summary.namedSigPoisoned[ns] = true
			}
			wTopNamed := derefNamedStruct(userPaths, w.Signature.Recv().Type())
			poisonEmbeddedCarriers(w.Signature.Recv().Type(), wTopNamed, w)
		}
		if sawReflectMutation {
			for named := range summary.structReferencedByType {
				poisonStruct(named, -1)
			}
			for ns := range namedSigReferenced {
				summary.namedSigPoisoned[ns] = true
			}
		}
		var collectFuncValueCallSites func(val ssa.Value, seen map[ssa.Value]bool) ([]ssa.CallInstruction, bool)
		var collectStoreTargetCallSites func(addr ssa.Value, seen map[ssa.Value]bool) ([]ssa.CallInstruction, bool)
		collectStoreTargetCallSites = func(addr ssa.Value, seen map[ssa.Value]bool) ([]ssa.CallInstruction, bool) {
			if fa, ok := addr.(*ssa.FieldAddr); ok && fa.X != nil {
				if named := derefNamedStruct(userPaths, fa.X.Type()); named != nil {
					key := structFieldKey{named: named, field: fa.Field}
					if summary.structPoisoned[key] {
						return nil, false
					}
					reads := structFieldReads[key]
					if len(reads) == 0 {
						return nil, false
					}
					var sites []ssa.CallInstruction
					for _, rd := range reads {
						sub, ok := collectFuncValueCallSites(rd, seen)
						if !ok {
							return nil, false
						}
						sites = append(sites, sub...)
					}
					return sites, true
				}
			}
			if alloc, ok := addr.(*ssa.Alloc); ok {
				if seen[alloc] {
					return nil, true
				}
				seen[alloc] = true
				if alloc.Referrers() == nil {
					return nil, false
				}
				var sites []ssa.CallInstruction
				for _, ref := range *alloc.Referrers() {
					switch r := ref.(type) {
					case *ssa.DebugRef:
					case *ssa.Store:
						if r.Addr != alloc {
							return nil, false
						}
					case *ssa.UnOp:
						if r.Op != token.MUL || r.X != alloc {
							return nil, false
						}
						sub, ok := collectFuncValueCallSites(r, seen)
						if !ok {
							return nil, false
						}
						sites = append(sites, sub...)
					case *ssa.MakeClosure:
						cFn, ok := r.Fn.(*ssa.Function)
						if !ok || len(cFn.Blocks) == 0 || len(r.Bindings) != len(cFn.FreeVars) {
							return nil, false
						}
						for i, b := range r.Bindings {
							if b == alloc {
								sub, ok := collectFuncValueCallSites(cFn.FreeVars[i], seen)
								if !ok {
									return nil, false
								}
								sites = append(sites, sub...)
							}
						}
					default:
						return nil, false
					}
				}
				return sites, true
			}
			return nil, false
		}
		collectFuncValueCallSites = func(val ssa.Value, seen map[ssa.Value]bool) ([]ssa.CallInstruction, bool) {
			if val == nil {
				return nil, false
			}
			if seen[val] {
				return nil, true
			}
			seen[val] = true
			refs := val.Referrers()
			if refs == nil {
				return nil, false
			}
			var sites []ssa.CallInstruction
			for _, ref := range *refs {
				switch r := ref.(type) {
				case *ssa.DebugRef:
				case *ssa.BinOp:
					if r.Op != token.EQL && r.Op != token.NEQ {
						return nil, false
					}
				case *ssa.Phi:
					sub, ok := collectFuncValueCallSites(r, seen)
					if !ok {
						return nil, false
					}
					sites = append(sites, sub...)
				case *ssa.ChangeType:
					if r.X != val {
						return nil, false
					}
					sub, ok := collectFuncValueCallSites(r, seen)
					if !ok {
						return nil, false
					}
					sites = append(sites, sub...)
				case *ssa.UnOp:
					if r.Op != token.MUL || r.X != val {
						return nil, false
					}
					sub, ok := collectFuncValueCallSites(r, seen)
					if !ok {
						return nil, false
					}
					sites = append(sites, sub...)
				case *ssa.MakeClosure:
					cFn, ok := r.Fn.(*ssa.Function)
					if !ok || len(cFn.Blocks) == 0 || len(r.Bindings) != len(cFn.FreeVars) {
						return nil, false
					}
					for i, b := range r.Bindings {
						if b == val {
							sub, ok := collectFuncValueCallSites(cFn.FreeVars[i], seen)
							if !ok {
								return nil, false
							}
							sites = append(sites, sub...)
						}
					}
				case *ssa.Store:
					if r.Val != val || r.Addr == val {
						return nil, false
					}
					sub, ok := collectStoreTargetCallSites(r.Addr, seen)
					if !ok {
						return nil, false
					}
					sites = append(sites, sub...)
				case ssa.CallInstruction:
					if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil {
						return nil, false
					}
					caller := r.Parent()
					if caller == nil || (caller.Synthetic != "" && !isPromotedWrapper(caller) && caller.Origin() == nil) || parameterizedBody(caller) {
						return nil, false
					}
					passedAsArg := false
					for i, arg := range r.Common().Args {
						if arg == val {
							passedAsArg = true
							callee := r.Common().StaticCallee()
							if r.Common().IsInvoke() || callee == nil || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && callee.Origin() == nil) || parameterizedBody(callee) || len(r.Common().Args) != len(callee.Params) {
								return nil, false
							}
							sub, ok := collectFuncValueCallSites(callee.Params[i], seen)
							if !ok {
								return nil, false
							}
							sites = append(sites, sub...)
						}
					}
					if !r.Common().IsInvoke() && r.Common().Value == val {
						sites = append(sites, r)
					} else if !passedAsArg {
						return nil, false
					}
				default:
					return nil, false
				}
			}
			return sites, true
		}
		for _, g := range ordered {
			if summary.valueRef[g] {
				continue
			}
			mcs := closureRefs[g]
			sts := storeRefs[g]
			cas := callArgRefs[g]
			if len(mcs) == 0 && len(sts) == 0 && len(cas) == 0 {
				continue
			}
			var extraSites []ssa.CallInstruction
			okAll := true
			for _, mc := range mcs {
				sub, ok := collectFuncValueCallSites(mc, make(map[ssa.Value]bool))
				if !ok || len(sub) == 0 {
					okAll = false
					break
				}
				extraSites = append(extraSites, sub...)
			}
			for _, st := range sts {
				if !okAll {
					break
				}
				sub, ok := collectStoreTargetCallSites(st.Addr, make(map[ssa.Value]bool))
				if !ok || len(sub) == 0 {
					okAll = false
					break
				}
				extraSites = append(extraSites, sub...)
			}
			for _, site := range cas {
				if !okAll {
					break
				}
				callee := site.Common().StaticCallee()
				if callee == nil || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && callee.Origin() == nil) || parameterizedBody(callee) || len(site.Common().Args) != len(callee.Params) {
					okAll = false
					break
				}
				for i, arg := range site.Common().Args {
					if arg == g {
						sub, ok := collectFuncValueCallSites(callee.Params[i], make(map[ssa.Value]bool))
						if !ok || len(sub) == 0 {
							okAll = false
							break
						}
						extraSites = append(extraSites, sub...)
					}
				}
			}
			if !okAll {
				summary.valueRef[g] = true
			} else {
				summary.sites[g] = append(summary.sites[g], extraSites...)
			}
		}
	}
	dedupCallSites := func(sites []ssa.CallInstruction) []ssa.CallInstruction {
		if len(sites) <= 1 {
			return sites
		}
		seenSite := make(map[ssa.CallInstruction]bool, len(sites))
		dedup := sites[:0]
		for _, s := range sites {
			if !seenSite[s] {
				seenSite[s] = true
				dedup = append(dedup, s)
			}
		}
		return dedup
	}
	for _, w := range ordered {
		if audited && isBoundMethodWrapper(w) {
			wsites := dedupCallSites(summary.sites[w])
			summary.sites[w] = wsites
			wval := summary.valueRef[w]
			wdval := summary.directValueRef[w]
			if len(wsites) == 0 && !wval && !wdval {
				continue
			}
			for _, b := range w.Blocks {
				for _, instr := range b.Instrs {
					if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
						if callee := site.Common().StaticCallee(); callee != nil {
							summary.directValueRef[callee] = true
							if wval || len(wsites) == 0 {
								summary.valueRef[callee] = true
							} else {
								summary.sites[callee] = append(summary.sites[callee], site)
							}
						} else if site.Common().IsInvoke() && site.Common().Method != nil {
							mname := site.Common().Method.Name()
							iface, _ := types.Unalias(site.Common().Value.Type()).Underlying().(*types.Interface)
							if iface != nil {
								for _, cand := range methodsByName[mname] {
									if cand == w {
										continue
									}
									recvType := cand.Signature.Recv().Type()
									if types.Implements(recvType, iface) || types.Implements(types.NewPointer(recvType), iface) {
										summary.directValueRef[cand] = true
										if wval || len(wsites) == 0 {
											summary.valueRef[cand] = true
										} else {
											summary.sites[cand] = append(summary.sites[cand], site)
										}
									}
								}
							}
						}
					}
				}
			}
			continue
		}
		if !isPromotedWrapper(w) {
			continue
		}
		wsites := dedupCallSites(summary.sites[w])
		summary.sites[w] = wsites
		wval := summary.valueRef[w]
		wdval := summary.directValueRef[w]
		if len(wsites) == 0 && !wval && !wdval {
			continue
		}
		for _, b := range w.Blocks {
			for _, instr := range b.Instrs {
				if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
					if callee := site.Common().StaticCallee(); callee != nil {
						if wval {
							summary.valueRef[callee] = true
						}
						if wdval {
							summary.directValueRef[callee] = true
						}
						if len(wsites) > 0 {
							summary.sites[callee] = append(summary.sites[callee], wsites...)
						}
					} else if audited && site.Common().IsInvoke() && site.Common().Method != nil {
						mname := site.Common().Method.Name()
						iface, _ := types.Unalias(site.Common().Value.Type()).Underlying().(*types.Interface)
						if iface != nil {
							for _, cand := range methodsByName[mname] {
								if cand == w {
									continue
								}
								recvType := cand.Signature.Recv().Type()
								if types.Implements(recvType, iface) || types.Implements(types.NewPointer(recvType), iface) {
									if wval {
										summary.valueRef[cand] = true
									}
									if wdval {
										summary.directValueRef[cand] = true
									}
									if len(wsites) > 0 {
										summary.sites[cand] = append(summary.sites[cand], wsites...)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	for key := range summary.structPoisoned {
		delete(summary.structFieldStores, key)
		if key.field < 0 {
			delete(summary.structWholeStores, key.named)
			delete(summary.structBoxedValues, key.named)
		}
	}
	for fn, sites := range summary.sites {
		summary.sites[fn] = dedupCallSites(sites)
	}
	return &summary
}

// subjectEnumerationClosure judges one open-signature root against its
// collected references: closed when references are direct static calls
// (or closed struct-receiver uses) with at least one reference in the
// program, and every dynamic-reaching argument or receiver field position
// closes in the caller's or constructor's own frame.
func subjectEnumerationClosure(audited bool, pureDelegates map[string]bool, userPaths map[string]bool, root *ssa.Function, summary *callerReferenceSummary) (enumerationClosure, bool) {
	sites := summary.sites[root]
	valueRef := summary.directValueRef[root]
	hasExternalSite := false
	for _, site := range sites {
		if site != nil && site.Parent() != root {
			hasExternalSite = true
			break
		}
	}
	fp := newEnumFreshParamAnalysis(audited, pureDelegates, userPaths, root, sites, summary)
	if root.Signature != nil && root.Signature.Recv() != nil {
		if !audited || valueRef || len(root.Blocks) == 0 || root.Synthetic != "" || parameterizedBody(root) || len(root.Params) == 0 {
			return enumerationClosure{}, false
		}
		for _, list := range []*types.TypeParamList{root.TypeParams(), root.Signature.TypeParams(), root.Signature.RecvTypeParams()} {
			for i := 0; list != nil && i < list.Len(); i++ {
				if !typeParamBoundsAwayFromDynamic(audited, list.At(i)) {
					return enumerationClosure{}, false
				}
			}
		}
		hasDynamicExtraParam := false
		for _, param := range root.Params[1:] {
			if typeMayCarryDynamicTop(audited, param.Type()) && paramMaySupplyDynamic(audited, userPaths, param) {
				if _, isSig := types.Unalias(param.Type()).Underlying().(*types.Signature); isSig {
					return enumerationClosure{}, false
				}
				hasDynamicExtraParam = true
			}
		}
		if hasDynamicExtraParam && !hasExternalSite {
			return enumerationClosure{}, false
		}
		named := derefNamedStruct(userPaths, root.Signature.Recv().Type())
		recvMaySupply := paramMaySupplyDynamic(audited, userPaths, root.Params[0])
		if recvMaySupply && named == nil {
			return enumerationClosure{}, false
		}
		if !hasExternalSite && (named == nil || !summary.isStructReferencedOutside(named, root)) {
			return enumerationClosure{}, false
		}
		enc := enumerationClosure{
			sites:       sites,
			addrTaken:   map[*ssa.Function]bool{},
			fieldStores: map[int][]ssa.Value{},
		}
		seedSeen := map[ssa.Value]bool{}
		if hasDynamicExtraParam {
			for _, site := range sites {
				siteArgs := site.Common().Args
				offset := 0
				if site.Common().IsInvoke() {
					offset = -1
				}
				for i := 1; i < len(root.Params); i++ {
					param := root.Params[i]
					if !typeMayCarryDynamicTop(audited, param.Type()) || !paramMaySupplyDynamic(audited, userPaths, param) {
						continue
					}
					argIdx := i + offset
					if argIdx < 0 || argIdx >= len(siteArgs) {
						return enumerationClosure{}, false
					}
					arg := siteArgs[argIdx]
					if !walkDynamicValue(arg, nil, make(map[ssa.Value]bool), nil, fp) {
						return enumerationClosure{}, false
					}
					collectClosedDynamicSeeds(arg, &enc, seedSeen, fp)
				}
			}
		}
		if !recvMaySupply {
			if paramHasMakeInterface(root.Params[0], make(map[*ssa.Parameter]bool)) {
				enc.types = append(enc.types, root.Params[0].Type())
			}
			return enc, true
		}
		if summary.structPoisoned[structFieldKey{named: named, field: -1}] {
			return enumerationClosure{}, false
		}
		_, neededFields, ok := recvStructFieldTargets(audited, userPaths, root)
		if !ok {
			return enumerationClosure{}, false
		}
		fp.enumRecvNamed = named
		for _, site := range sites {
			if site.Common().IsInvoke() && len(summary.structBoxedValues[named]) > 0 {
				continue
			}
			var recvArg ssa.Value
			if site.Common().IsInvoke() {
				recvArg = site.Common().Value
			} else {
				if len(site.Common().Args) == 0 {
					return enumerationClosure{}, false
				}
				recvArg = site.Common().Args[0]
			}
			if !walkDynamicValue(recvArg, nil, make(map[ssa.Value]bool), nil, fp) {
				return enumerationClosure{}, false
			}
		}
		for _, bv := range summary.structBoxedValues[named] {
			if !walkDynamicValue(bv, nil, make(map[ssa.Value]bool), nil, fp) {
				return enumerationClosure{}, false
			}
		}
		if paramHasMakeInterface(root.Params[0], make(map[*ssa.Parameter]bool)) {
			enc.types = append(enc.types, root.Params[0].Type())
		}
		fieldSeedSeen := map[ssa.Value]bool{}
		if wholeStores := summary.structWholeStores[named]; len(wholeStores) > 0 {
			wholeFP := *fp
			wholeFP.inProgramSites = true
			wholeFP.inFieldStore = true
			for _, wv := range wholeStores {
				if !walkDynamicValue(wv, nil, make(map[ssa.Value]bool), nil, &wholeFP) {
					return enumerationClosure{}, false
				}
				collectClosedDynamicSeeds(wv, &enc, fieldSeedSeen, &wholeFP)
			}
		}
		var fieldIdxs []int
		for idx := range neededFields {
			fieldIdxs = append(fieldIdxs, idx)
		}
		sort.Ints(fieldIdxs)
		fieldFP := *fp
		fieldFP.inFieldStore = true
		st, _ := named.Underlying().(*types.Struct)
		for _, idx := range fieldIdxs {
			key := structFieldKey{named: named, field: idx}
			if summary.structPoisoned[key] {
				return enumerationClosure{}, false
			}
			if st != nil && idx >= 0 && idx < st.NumFields() {
				fType := st.Field(idx).Type()
				if _, isPtr := types.Unalias(fType).(*types.Pointer); !isPtr {
					if innerNamed := derefNamedStruct(userPaths, fType); innerNamed != nil && typeMayCarryDynamicTop(audited, innerNamed) {
						if !enumUserStructClosed(innerNamed, &fieldFP) {
							return enumerationClosure{}, false
						}
						typesMap := map[types.Type]bool{}
						if enc.addrTaken == nil {
							enc.addrTaken = map[*ssa.Function]bool{}
						}
						collectUserStructSeeds(innerNamed, &dynamicValueCollector{
							types: typesMap,
							funcs: enc.addrTaken,
							seeds: true,
						}, &fieldFP)
						for t := range typesMap {
							enc.types = append(enc.types, t)
						}
					}
				}
			}
			stores := summary.structFieldStores[key]
			for _, val := range stores {
				if !walkDynamicValue(val, nil, make(map[ssa.Value]bool), nil, &fieldFP) {
					return enumerationClosure{}, false
				}
				collectClosedDynamicSeeds(val, &enc, fieldSeedSeen, &fieldFP)
			}
			enc.fieldStores[idx] = stores
		}
		return enc, true
	}
	if valueRef || !hasExternalSite {
		return enumerationClosure{}, false
	}
	enc := enumerationClosure{sites: sites, addrTaken: map[*ssa.Function]bool{}}
	seedSeen := map[ssa.Value]bool{}
	for _, site := range sites {
		args := site.Common().Args
		if len(args) != len(root.Params) {
			return enumerationClosure{}, false
		}
		for i, param := range root.Params {
			if !typeMayCarryDynamicTop(audited, param.Type()) {
				continue
			}
			if audited && len(root.Blocks) > 0 && root.Synthetic == "" && !parameterizedBody(root) && !paramMaySupplyDynamic(audited, userPaths, param) {
				continue
			}
			if !walkDynamicValue(args[i], nil, make(map[ssa.Value]bool), nil, fp) {
				return enumerationClosure{}, false
			}
			collectClosedDynamicSeeds(args[i], &enc, seedSeen, fp)
		}
	}
	return enc, true
}

func derefNamedStruct(userPaths map[string]bool, t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || isStdPkgPath(userPaths, named.Obj().Pkg().Path()) {
		return nil
	}
	if _, ok := named.Underlying().(*types.Struct); !ok {
		return nil
	}
	return named
}

func derefNamedSignature(userPaths map[string]bool, t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || isStdPkgPath(userPaths, named.Obj().Pkg().Path()) {
		return nil
	}
	if _, ok := named.Underlying().(*types.Signature); !ok {
		return nil
	}
	return named
}

func paramMaySupplyDynamic(audited bool, userPaths map[string]bool, param *ssa.Parameter) bool {
	if param == nil {
		return false
	}
	return paramMaySupplyDynamicSeen(audited, userPaths, param, param.Parent(), make(map[*ssa.Parameter]bool))
}

func paramMaySupplyDynamicSeen(audited bool, userPaths map[string]bool, param *ssa.Parameter, root *ssa.Function, seen map[*ssa.Parameter]bool) bool {
	if param == nil {
		return false
	}
	if seen[param] {
		return false
	}
	seen[param] = true
	refs := param.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return true
			}
		case *ssa.FieldAddr:
			if r.X != param || !carrierFreeFieldAddr(audited, r, root) {
				return true
			}
		case *ssa.IndexAddr:
			if r.X != param || !carrierFreeReadOnlyAddr(audited, r, root) {
				return true
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != param || !carrierFreeValueUses(audited, r, root) {
				return true
			}
		case *ssa.Field:
			if r.X != param || !carrierFreeValueUses(audited, r, root) {
				return true
			}
		case *ssa.Index:
			if r.X != param || !carrierFreeValueUses(audited, r, root) {
				return true
			}
		case *ssa.MakeInterface:
			if r.X != param {
				return true
			}
			named := derefNamedStruct(userPaths, param.Type())
			if named == nil || param.Parent() == nil || param.Parent().Prog == nil {
				return true
			}
			needed := make(map[int]bool)
			if !interfaceValueStructFieldTargets(audited, userPaths, named, param.Type(), param.Parent().Prog, r, root, needed, seen, make(map[ssa.Value]bool)) || len(needed) > 0 {
				return true
			}
		case ssa.CallInstruction:
			if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil || r.Common().IsInvoke() {
				return true
			}
			callee := r.Common().StaticCallee()
			if callee == nil || (root != nil && callee == root) || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && !(audited && callee.Origin() != nil)) || parameterizedBody(callee) || len(r.Common().Args) != len(callee.Params) {
				return true
			}
			for i, arg := range r.Common().Args {
				if arg == param && paramMaySupplyDynamicSeen(audited, userPaths, callee.Params[i], root, seen) {
					return true
				}
			}
		default:
			return true
		}
	}
	return false
}

func carrierFreeFieldAddr(audited bool, fa *ssa.FieldAddr, root *ssa.Function) bool {
	if fa == nil || fa.Type() == nil {
		return false
	}
	ptr, ok := types.Unalias(fa.Type()).Underlying().(*types.Pointer)
	if !ok {
		return false
	}
	if !typeMayCarryDynamic(audited, ptr.Elem(), make(map[types.Type]bool)) {
		return true
	}
	return carrierFreeReadOnlyAddr(audited, fa, root)
}

func carrierFreeReadOnlyAddr(audited bool, addr ssa.Value, root *ssa.Function) bool {
	if addr == nil || addr.Type() == nil || addr.Referrers() == nil {
		return false
	}
	ptr, ok := types.Unalias(addr.Type()).Underlying().(*types.Pointer)
	if !ok {
		return false
	}
	elemCarries := typeMayCarryDynamic(audited, ptr.Elem(), make(map[types.Type]bool))
	for _, ref := range *addr.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != addr {
				return false
			}
			if elemCarries && !carrierFreeValueUses(audited, r, root) {
				return false
			}
		case *ssa.FieldAddr:
			if r.X != addr || !carrierFreeFieldAddr(audited, r, root) {
				return false
			}
		case *ssa.IndexAddr:
			if r.X != addr || !carrierFreeReadOnlyAddr(audited, r, root) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func carrierFreeValueUses(audited bool, val ssa.Value, root *ssa.Function) bool {
	return carrierFreeValueUsesSeen(audited, val, root, make(map[ssa.Value]bool))
}

func carrierFreeValueUsesSeen(audited bool, val ssa.Value, root *ssa.Function, seen map[ssa.Value]bool) bool {
	if val == nil || val.Type() == nil {
		return false
	}
	if seen[val] {
		return true
	}
	seen[val] = true
	if !typeMayCarryDynamic(audited, val.Type(), make(map[types.Type]bool)) {
		return true
	}
	refs := val.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Return:
			if root == nil || r.Parent() != root {
				return false
			}
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return false
			}
		case *ssa.Field:
			if r.X != val || !carrierFreeValueUsesSeen(audited, r, root, seen) {
				return false
			}
		case *ssa.Index:
			if r.X != val || !carrierFreeValueUsesSeen(audited, r, root, seen) {
				return false
			}
		case *ssa.Phi:
			if !carrierFreeValueUsesSeen(audited, r, root, seen) {
				return false
			}
		case *ssa.MakeInterface:
			if !audited || r.X != val || !makeInterfaceOnlyReturned(r, root) {
				return false
			}
			if _, isIface := types.Unalias(val.Type()).Underlying().(*types.Interface); isIface {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func makeInterfaceOnlyReturned(mi *ssa.MakeInterface, root *ssa.Function) bool {
	if mi == nil || mi.Referrers() == nil || root == nil {
		return false
	}
	sawReturn := false
	for _, ref := range *mi.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Return:
			if r.Parent() != root {
				return false
			}
			sawReturn = true
		default:
			return false
		}
	}
	return sawReturn
}

func recvStructFieldTargets(audited bool, userPaths map[string]bool, root *ssa.Function) (*types.Named, map[int]bool, bool) {
	if !audited || root == nil || root.Signature == nil || root.Signature.Recv() == nil || len(root.Blocks) == 0 || root.Synthetic != "" || parameterizedBody(root) || len(root.Params) == 0 {
		return nil, nil, false
	}
	named := derefNamedStruct(userPaths, root.Signature.Recv().Type())
	if named == nil {
		return nil, nil, false
	}
	needed := make(map[int]bool)
	if !collectParamStructFieldTargets(audited, userPaths, named, root.Params[0], root, needed, make(map[*ssa.Parameter]bool)) {
		return nil, nil, false
	}
	return named, needed, true
}

func collectParamStructFieldTargets(audited bool, userPaths map[string]bool, named *types.Named, param *ssa.Parameter, root *ssa.Function, needed map[int]bool, seen map[*ssa.Parameter]bool) bool {
	if param == nil {
		return false
	}
	return collectStructCarrierFieldTargets(audited, userPaths, named, param, nil, root, needed, seen, make(map[ssa.Value]bool))
}

func collectStructCarrierFieldTargets(audited bool, userPaths map[string]bool, named *types.Named, val ssa.Value, initStore *ssa.Store, root *ssa.Function, needed map[int]bool, seen map[*ssa.Parameter]bool, valSeen map[ssa.Value]bool) bool {
	if val == nil {
		return false
	}
	if param, ok := val.(*ssa.Parameter); ok {
		if seen[param] {
			return true
		}
		seen[param] = true
	} else {
		if valSeen[val] {
			return true
		}
		valSeen[val] = true
	}
	refs := val.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return false
			}
		case *ssa.Store:
			if r == initStore {
				continue
			}
			if r.Val == val && r.Addr != val {
				alloc, ok := r.Addr.(*ssa.Alloc)
				if !ok || derefNamedStruct(userPaths, alloc.Type()) != named {
					return false
				}
				if !collectStructCarrierFieldTargets(audited, userPaths, named, alloc, r, root, needed, seen, valSeen) {
					return false
				}
				continue
			}
			return false
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok || fn == nil || len(fn.Blocks) == 0 || len(r.Bindings) != len(fn.FreeVars) {
				return false
			}
			for i, b := range r.Bindings {
				if b == val {
					if derefNamedStruct(userPaths, fn.FreeVars[i].Type()) != named ||
						!collectStructCarrierFieldTargets(audited, userPaths, named, fn.FreeVars[i], nil, root, needed, seen, valSeen) {
						return false
					}
				}
			}
		case *ssa.Field:
			if r.X != val {
				return false
			}
			if carrierFreeValueUses(audited, r, root) {
				continue
			}
			needed[r.Field] = true
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != val || r.Referrers() == nil {
				return false
			}
			for _, uref := range *r.Referrers() {
				switch ur := uref.(type) {
				case *ssa.DebugRef:
				case *ssa.Field:
					if ur.X != r {
						return false
					}
					if carrierFreeValueUses(audited, ur, root) {
						continue
					}
					needed[ur.Field] = true
				case *ssa.Store:
					if ur.Val == r && ur.Addr != r {
						if alloc, ok := ur.Addr.(*ssa.Alloc); ok && derefNamedStruct(userPaths, alloc.Type()) == named {
							if !collectStructCarrierFieldTargets(audited, userPaths, named, alloc, ur, root, needed, seen, valSeen) {
								return false
							}
							continue
						}
					}
					return false
				default:
					return false
				}
			}
		case *ssa.FieldAddr:
			if r.X != val {
				return false
			}
			if carrierFreeFieldAddr(audited, r, root) {
				continue
			}
			if r.Referrers() == nil {
				return false
			}
			hasLoad := false
			allDerefOrStore := true
			for _, fref := range *r.Referrers() {
				switch fr := fref.(type) {
				case *ssa.DebugRef:
				case *ssa.UnOp:
					if fr.Op != token.MUL || fr.X != r {
						allDerefOrStore = false
					} else {
						hasLoad = true
					}
				case *ssa.Store:
					if fr.Addr != r || fr.Val == r {
						allDerefOrStore = false
					}
				default:
					allDerefOrStore = false
				}
			}
			if !allDerefOrStore {
				innerNamed := derefNamedStruct(userPaths, r.Type())
				if innerNamed == nil || !collectStructCarrierFieldTargets(audited, userPaths, innerNamed, r, nil, root, make(map[int]bool), seen, valSeen) {
					return false
				}
				needed[r.Field] = true
			} else if hasLoad {
				needed[r.Field] = true
			}
		case *ssa.MakeInterface:
			if r.X != val {
				return false
			}
			if val.Parent() != nil && val.Parent().Prog != nil &&
				interfaceValueStructFieldTargets(audited, userPaths, named, val.Type(), val.Parent().Prog, r, root, needed, seen, make(map[ssa.Value]bool)) {
				continue
			}
			st, ok := named.Underlying().(*types.Struct)
			if !ok {
				return false
			}
			for i := 0; i < st.NumFields(); i++ {
				if typeMayCarryDynamic(audited, st.Field(i).Type(), make(map[types.Type]bool)) {
					needed[i] = true
				}
			}
		case ssa.CallInstruction:
			if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil || r.Common().IsInvoke() {
				return false
			}
			callee := r.Common().StaticCallee()
			if callee == nil || (root != nil && callee == root) || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && !(audited && callee.Origin() != nil)) || parameterizedBody(callee) || len(r.Common().Args) != len(callee.Params) {
				return false
			}
			for i, arg := range r.Common().Args {
				if arg == val {
					if derefNamedStruct(userPaths, callee.Params[i].Type()) != named {
						return false
					}
					if paramMaySupplyDynamicSeen(audited, userPaths, callee.Params[i], root, make(map[*ssa.Parameter]bool)) {
						if !collectStructCarrierFieldTargets(audited, userPaths, named, callee.Params[i], nil, root, needed, seen, valSeen) {
							return false
						}
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

func paramHasMakeInterface(param *ssa.Parameter, seen map[*ssa.Parameter]bool) bool {
	if param == nil || seen[param] {
		return false
	}
	seen[param] = true
	refs := param.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.MakeInterface:
			if r.X == param {
				return true
			}
		case ssa.CallInstruction:
			if r.Common() == nil || r.Common().IsInvoke() {
				continue
			}
			callee := r.Common().StaticCallee()
			if callee == nil || len(r.Common().Args) != len(callee.Params) {
				continue
			}
			for i, arg := range r.Common().Args {
				if arg == param && paramHasMakeInterface(callee.Params[i], seen) {
					return true
				}
			}
		}
	}
	return false
}

func interfaceValueStructFieldTargets(audited bool, userPaths map[string]bool, named *types.Named, concreteType types.Type, prog *ssa.Program, val ssa.Value, root *ssa.Function, needed map[int]bool, paramSeen map[*ssa.Parameter]bool, valSeen map[ssa.Value]bool) bool {
	if val == nil || prog == nil {
		return false
	}
	if valSeen[val] {
		return true
	}
	valSeen[val] = true
	refs := val.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Return:
			if root == nil || r.Parent() != root {
				return false
			}
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return false
			}
		case *ssa.ChangeInterface:
			if r.X != val || !interfaceValueStructFieldTargets(audited, userPaths, named, concreteType, prog, r, root, needed, paramSeen, valSeen) {
				return false
			}
		case *ssa.TypeAssert:
			if r.X != val {
				return false
			}
			iface, ok := types.Unalias(r.AssertedType).Underlying().(*types.Interface)
			if !ok {
				return false
			}
			if !types.Implements(concreteType, iface) {
				continue
			}
			if !r.CommaOk {
				if !interfaceValueStructFieldTargets(audited, userPaths, named, concreteType, prog, r, root, needed, paramSeen, valSeen) {
					return false
				}
				continue
			}
			if r.Referrers() == nil {
				return false
			}
			for _, er := range *r.Referrers() {
				switch ex := er.(type) {
				case *ssa.DebugRef:
				case *ssa.Extract:
					if ex.Tuple != r {
						return false
					}
					if ex.Index == 0 && !interfaceValueStructFieldTargets(audited, userPaths, named, concreteType, prog, ex, root, needed, paramSeen, valSeen) {
						return false
					}
				default:
					return false
				}
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok || len(fn.Blocks) == 0 {
				return false
			}
			for i, b := range r.Bindings {
				if b == val {
					if i >= len(fn.FreeVars) || !interfaceValueStructFieldTargets(audited, userPaths, named, concreteType, prog, fn.FreeVars[i], root, needed, paramSeen, valSeen) {
						return false
					}
				}
			}
		case ssa.CallInstruction:
			if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil {
				return false
			}
			if r.Common().IsInvoke() {
				for _, arg := range r.Common().Args {
					if arg == val {
						return false
					}
				}
				if r.Common().Value != val || r.Common().Method == nil {
					return false
				}
				cmethod := prog.LookupMethod(concreteType, r.Common().Method.Pkg(), r.Common().Method.Name())
				if cmethod == nil || (root != nil && cmethod == root) || len(cmethod.Blocks) == 0 || len(cmethod.Params) == 0 {
					return false
				}
				if paramMaySupplyDynamicSeen(audited, userPaths, cmethod.Params[0], root, make(map[*ssa.Parameter]bool)) {
					if !collectParamStructFieldTargets(audited, userPaths, named, cmethod.Params[0], root, needed, paramSeen) {
						return false
					}
				}
				continue
			}
			callee := r.Common().StaticCallee()
			if callee == nil || (root != nil && callee == root) || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && !(audited && callee.Origin() != nil)) || parameterizedBody(callee) || len(r.Common().Args) != len(callee.Params) {
				return false
			}
			for i, arg := range r.Common().Args {
				if arg == val && !interfaceValueStructFieldTargets(audited, userPaths, named, concreteType, prog, callee.Params[i], root, needed, paramSeen, valSeen) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// collectClosedDynamicSeeds walks an already-closed argument value and
// gathers what it can hand the subject: function values become dispatch
// candidates, materialized concrete types enter the runtime-type walk.
// It delegates to walkDynamicValue in seeds mode so closedness checking
// and RTA seed collection share a single SSA shape ladder.
func collectClosedDynamicSeeds(value ssa.Value, enc *enumerationClosure, seen map[ssa.Value]bool, fp *freshParamAnalysis) {
	if value == nil || enc == nil {
		return
	}
	if seen == nil {
		seen = map[ssa.Value]bool{}
	}
	typesMap := map[types.Type]bool{}
	if enc.addrTaken == nil {
		enc.addrTaken = map[*ssa.Function]bool{}
	}
	collector := &dynamicValueCollector{
		types: typesMap,
		funcs: enc.addrTaken,
		seeds: true,
	}
	walkDynamicValue(value, collector, seen, nil, fp)
	if _, isConst := value.(*ssa.Const); !isConst && value.Type() != nil && fp != nil && fp.selectionAudited {
		if named := derefNamedStruct(fp.userPkgPaths(), value.Type()); named != nil && typeMayCarryDynamicTop(fp.selectionAudited, named) {
			collectUserStructSeeds(named, collector, fp)
		}
	}
	for t := range typesMap {
		enc.types = append(enc.types, t)
	}
}

func rootMayReceiveUnknownDynamic(audited bool, prog *program, root *ssa.Function) bool {
	if root == nil || root.Signature == nil {
		return true
	}
	var extraTypeParams *types.TypeParamList
	if root.Signature.TypeParams() == nil {
		extraTypeParams = root.TypeParams()
	}
	return signatureOpenWorldTerm(audited, root.Signature, extraTypeParams, subjectRunsThroughHarness(prog, root), carrierPolicyClosure) != ""
}

type carrierWalkPolicy = dynstate.CarrierWalkPolicy

const (
	carrierPolicyClosure  = dynstate.CarrierPolicyClosure
	carrierPolicyConsumer = dynstate.CarrierPolicyConsumer
	carrierPolicyAlias    = dynstate.CarrierPolicyAlias
)

func signatureOpenWorldTerm(audited bool, sig *types.Signature, extraTypeParams *types.TypeParamList, allowHarnessSignature bool, policy carrierWalkPolicy) string {
	return dynstate.SignatureOpenWorldTerm(audited, sig, extraTypeParams, allowHarnessSignature, policy)
}

func auditedAtomicPointerElem(audited bool, t *types.Named) (types.Type, bool) {
	return dynstate.AuditedAtomicPointerElem(audited, t)
}

func walkDynamicCarrier(audited bool, t types.Type, seen map[types.Type]bool, policy carrierWalkPolicy) bool {
	return dynstate.WalkDynamicCarrier(audited, t, seen, policy)
}

func typeMayCarryDynamic(audited bool, t types.Type, seen map[types.Type]bool) bool {
	return walkDynamicCarrier(audited, t, seen, carrierPolicyClosure)
}

func typeMayCarryDynamicTop(audited bool, t types.Type) bool {
	if t == nil {
		return false
	}
	switch u := types.Unalias(t).(type) {
	case *types.Basic:
		return u.Kind() == types.UnsafePointer
	case *types.Interface, *types.Signature:
		return true
	}
	return walkDynamicCarrier(audited, t, make(map[types.Type]bool), carrierPolicyClosure)
}

func typeParamBoundsAwayFromDynamic(audited bool, tp *types.TypeParam) bool {
	return dynstate.TypeParamBoundsAwayFromDynamic(audited, tp)
}

func isGeneratedTestMainPackage(prog *program, pkg *ssa.Package) bool {
	return prog != nil && pkg != nil && pkg.Pkg != nil && pkg.Pkg.Name() == "main" && pkg.Pkg.Path() == prog.PkgPath+".test"
}

func provenanceReachableStartup(ctx context.Context, audited bool, prog *program, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool) (map[*ssa.Function]bool, error) {
	return provenanceBFS(ctx, audited, prog, roots, mask, result, harnessAudited, userPaths, true, nil)
}

func collectTestingHarnessCallbacks(audited, harnessAudited bool, pureDelegates map[string]bool, userPaths map[string]bool, summary *callerReferenceSummary, subjectRoot *ssa.Function, enumerated bool, enc enumerationClosure, prov map[*ssa.Function]bool, mask uint64, res *rta.Result) (cleanupOut []*ssa.Function, unclosedCleanup bool, fuzzOut []*ssa.Function, unclosedFuzz bool) {
	seenCleanup := make(map[*ssa.Function]bool)
	seenFuzz := make(map[*ssa.Function]bool)
	var lazyFP *freshParamAnalysis
	getFP := func() *freshParamAnalysis {
		if lazyFP != nil {
			return lazyFP
		}
		functions := make(map[*ssa.Function]bool, len(prov))
		dynamicTargets := make(map[ssa.CallInstruction]map[*ssa.Function]bool)
		if res != nil {
			for fn, m := range res.Reachable {
				if m&mask != 0 {
					functions[fn] = true
				}
			}
			for site, targets := range res.Targets {
				if !functions[site.Parent()] {
					continue
				}
				for t, m := range targets {
					if m&mask != 0 && functions[t] {
						proj := dynamicTargets[site]
						if proj == nil {
							proj = make(map[*ssa.Function]bool)
							dynamicTargets[site] = proj
						}
						proj[t] = true
					}
				}
			}
		} else {
			for fn := range prov {
				functions[fn] = true
			}
		}
		var reach attributedReachability
		reach.functions = functions
		reach.dynamicTargets = dynamicTargets
		reach.subjectRoot = subjectRoot
		reach.enumeratedRoot = enumerated
		reach.enumeratedRootSites = enc.sites
		reach.enumeratedFieldStores = enc.fieldStores
		reach.propertyHarnessAudited = harnessAudited
		reach.userPaths = userPaths
		if summary != nil {
			reach.prog = summary.prog
			reach.summary = summary
			reach.structFieldStores = summary.structFieldStores
			reach.structWholeStores = summary.structWholeStores
			reach.structPoisoned = summary.structPoisoned
			reach.structReferencedByType = summary.structReferencedByType
			reach.programSites = summary.sites
			reach.programValueRef = summary.valueRef
			reach.programFunctions = summary.allFunctions
		}
		lazyFP = newFreshParamAnalysis(audited, pureDelegates, reach, func(fn *ssa.Function) bool {
			return isStdPkgPath(userPaths, funcPkgPath(fn))
		})
		return lazyFP
	}
	checkFuzzSig := func(fb *ssa.Function) bool {
		if fb == nil {
			return false
		}
		for idx, p := range fb.Params {
			if p == nil {
				continue
			}
			if idx == 0 && isHarnessPointerType(p.Type()) {
				continue
			}
			if typeMayCarryDynamicTop(audited, p.Type()) {
				return false
			}
		}
		return true
	}
	markUnclosed := func(kind string) {
		if kind == "Fuzz" {
			unclosedFuzz = true
		} else {
			unclosedCleanup = true
		}
	}
	addCallback := func(kind string, cb *ssa.Function) {
		if cb == nil {
			return
		}
		if cb.Parent() == nil && propharness.IsHarnessPath(funcPkgPath(cb)) {
			markUnclosed(kind)
			return
		}
		if kind == "Fuzz" {
			if !checkFuzzSig(cb) {
				unclosedFuzz = true
				return
			}
			if !seenFuzz[cb] {
				seenFuzz[cb] = true
				fuzzOut = append(fuzzOut, cb)
			}
			return
		}
		if !seenCleanup[cb] {
			seenCleanup[cb] = true
			cleanupOut = append(cleanupOut, cb)
		}
	}
	unwrapIface := func(v ssa.Value) ssa.Value {
		for v != nil {
			switch u := v.(type) {
			case *ssa.MakeInterface:
				v = u.X
			case *ssa.ChangeInterface:
				v = u.X
			default:
				return v
			}
		}
		return nil
	}
	ordered := make([]*ssa.Function, 0, len(prov))
	for fn := range prov {
		if fn != nil {
			ordered = append(ordered, fn)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return lessSSAFunctionOrder(ordered[i], ordered[j]) })
	for _, fn := range ordered {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				site, ok := instr.(ssa.CallInstruction)
				if !ok {
					continue
				}
				rawArg, kind := testingHarnessCallArg(site, mask, res)
				if kind == "" {
					continue
				}
				arg := unwrapIface(rawArg)
				if arg == nil {
					markUnclosed(kind)
					continue
				}
				switch x := arg.(type) {
				case *ssa.Function:
					addCallback(kind, x)
				case *ssa.MakeClosure:
					cb, ok := x.Fn.(*ssa.Function)
					if !ok || cb == nil {
						markUnclosed(kind)
						continue
					}
					if isBoundMethodWrapper(cb) && len(x.Bindings) > 0 && typeMayCarryDynamicTop(audited, x.Bindings[0].Type()) {
						if !subjectClosedDynamicValue(x.Bindings[0], make(map[ssa.Value]bool), getFP()) {
							markUnclosed(kind)
							continue
						}
					}
					addCallback(kind, cb)
				default:
					targets, closed := closedDynamicTargets(rawArg, getFP())
					if !closed || len(targets) == 0 {
						markUnclosed(kind)
						continue
					}
					for cb := range targets {
						addCallback(kind, cb)
					}
				}
			}
		}
	}
	sort.Slice(cleanupOut, func(i, j int) bool { return cleanupOut[i].String() < cleanupOut[j].String() })
	sort.Slice(fuzzOut, func(i, j int) bool { return fuzzOut[i].String() < fuzzOut[j].String() })
	return cleanupOut, unclosedCleanup, fuzzOut, unclosedFuzz
}

func testingHarnessCallArg(site ssa.CallInstruction, mask uint64, res *rta.Result) (ssa.Value, string) {
	if site == nil || site.Common() == nil {
		return nil, ""
	}
	c := site.Common()
	if len(c.Args) == 0 {
		return nil, ""
	}
	matchTarget := func(fn *ssa.Function) string {
		if fn == nil || funcPkgPath(fn) != "testing" {
			return ""
		}
		base := strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(fn), "$bound"), "$thunk")
		if base == "Cleanup" || base == "Fuzz" {
			return base
		}
		return ""
	}
	if c.IsInvoke() && c.Method != nil && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "testing" {
		if c.Method.Name() == "Cleanup" || c.Method.Name() == "Fuzz" {
			return c.Args[len(c.Args)-1], c.Method.Name()
		}
	}
	if callee := c.StaticCallee(); callee != nil {
		if kind := matchTarget(callee); kind != "" {
			return c.Args[len(c.Args)-1], kind
		}
		return nil, ""
	}
	if res == nil {
		return nil, ""
	}
	for target, tmask := range res.Targets[site] {
		if tmask&mask != 0 {
			if kind := matchTarget(target); kind != "" {
				return c.Args[len(c.Args)-1], kind
			}
		}
	}
	return nil, ""
}

func isVerifiedPureRootedAsmStub(audited bool, prog *program, fn *ssa.Function) bool {
	if !audited || prog == nil || fn == nil || len(fn.Blocks) != 0 || fn.Synthetic != "" || parameterizedBody(fn) {
		return false
	}
	if fn.Signature == nil || fn.Signature.Recv() != nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	if !asmverify.SignatureCarrierFree(fn.Signature) {
		return false
	}
	pkgPath := fn.Pkg.Pkg.Path()
	hazards := nonSSAGlobalHazardsSummary(audited, prog)
	if hazards == nil || hazards.blockedPkgs[pkgPath] || hazards.linknamedVars[pkgVarKey{pkgPath: pkgPath, name: fn.Name()}] {
		return false
	}
	vp := hazards.verifiedAsm[pkgPath]
	if vp == nil || !vp.OK {
		return false
	}
	sum, ok := vp.Funcs[fn.Name()]
	return ok && sum.ImpureKind == ""
}

func rootedProvenanceIncomplete(audited, harnessAudited bool, prog *program, userPaths map[string]bool, sets ...map[*ssa.Function]bool) bool {
	var space [16]*ssa.Value
	for _, set := range sets {
		for fn := range set {
			if fn == nil {
				continue
			}
			pkgPath := funcPkgPath(fn)
			if isStdPkgPath(userPaths, pkgPath) {
				continue
			}
			if len(fn.Blocks) == 0 {
				if fn.Synthetic == "" && !parameterizedBody(fn) && !isVerifiedPureRootedAsmStub(audited, prog, fn) {
					return true
				}
				continue
			}
			for _, p := range fn.Params {
				if p != nil && nonStdTypeUsesUnsafePointer(audited, harnessAudited, userPaths, p.Type()) {
					return true
				}
			}
			for _, b := range fn.Blocks {
				for _, instr := range b.Instrs {
					if v, ok := instr.(ssa.Value); ok && nonStdTypeUsesUnsafePointer(audited, harnessAudited, userPaths, v.Type()) {
						return true
					}
					for _, op := range instr.Operands(space[:0]) {
						if op == nil || *op == nil {
							continue
						}
						if nonStdTypeUsesUnsafePointer(audited, harnessAudited, userPaths, (*op).Type()) {
							return true
						}
						if g, ok := (*op).(*ssa.Function); ok {
							gPkg := funcPkgPath(g)
							gSym := strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(g), "$bound"), "$thunk")
							if isUnattributableRootedStdSymbol(gPkg, gSym) {
								return true
							}
						}
					}
					site, ok := instr.(ssa.CallInstruction)
					if !ok || site.Common() == nil {
						continue
					}
					c := site.Common()
					if c.IsInvoke() {
						if c.Method != nil && c.Method.Pkg() != nil && isUnattributableRootedStdSymbol(c.Method.Pkg().Path(), c.Method.Name()) {
							return true
						}
						continue
					}
					if b, ok := c.Value.(*ssa.Builtin); ok {
						switch b.Name() {
						case "Add", "Slice", "SliceData", "String", "StringData":
							return true
						}
						continue
					}
					if callee := c.StaticCallee(); callee != nil {
						cPkg := funcPkgPath(callee)
						cSym := strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(callee), "$bound"), "$thunk")
						if isUnattributableRootedStdSymbol(cPkg, cSym) {
							return true
						}
						if (userPaths[cPkg] || !isStdImportPath(cPkg)) && len(callee.Blocks) == 0 && callee.Synthetic == "" && !parameterizedBody(callee) && !isVerifiedPureRootedAsmStub(audited, prog, callee) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func isReflectMutationSymbol(name string) bool {
	switch name {
	case "Set", "SetZero", "SetInt", "SetUint", "SetFloat", "SetComplex", "SetBool",
		"SetBytes", "SetString", "SetPointer", "SetMapIndex", "SetIterKey", "SetIterValue",
		"SetLen", "SetCap", "Addr", "UnsafeAddr", "Pointer", "NewAt", "Copy",
		"Append", "AppendSlice", "Grow", "Clear":
		return true
	default:
		return false
	}
}

func isStdDeserializerCall(pkgPath, sym string) bool {
	switch pkgPath {
	case "encoding/json", "encoding/json/v2", "encoding/json/jsontext",
		"encoding/xml", "encoding/gob", "encoding/binary", "encoding/asn1":
		return true
	case "fmt":
		return strings.HasPrefix(sym, "Scan") || strings.HasPrefix(sym, "Fscan") || strings.HasPrefix(sym, "Sscan")
	default:
		return false
	}
}

func isUnattributableRootedStdSymbol(pkgPath, sym string) bool {
	switch pkgPath {
	case "plugin", "testing/quick", "text/template", "html/template", "net/rpc", "net/rpc/jsonrpc":
		return true
	case "reflect":
		if isReflectMutationSymbol(sym) {
			return true
		}
		switch sym {
		case "Call", "CallSlice", "MakeFunc", "MethodByName", "Method":
			return true
		}
	}
	return false
}

func isOpaqueStructNamed(n *types.Named) bool {
	if n == nil {
		return false
	}
	st, ok := n.Underlying().(*types.Struct)
	return ok && propharness.StructHasNoExportedFields(st)
}

func nonStdTypeUsesUnsafePointer(audited, harnessAudited bool, userPaths map[string]bool, t types.Type) bool {
	seen := make(map[types.Type]bool)
	var walk func(types.Type) bool
	walk = func(cur types.Type) bool {
		if cur == nil {
			return false
		}
		cur = types.Unalias(cur)
		if ssaOpaqueHandle(cur) || seen[cur] {
			return false
		}
		seen[cur] = true
		switch tt := cur.(type) {
		case *types.Basic:
			return tt.Kind() == types.UnsafePointer
		case *types.Named:
			obj := tt.Obj()
			if obj != nil && obj.Pkg() != nil {
				pkgPath := obj.Pkg().Path()
				if pkgPath == "unsafe" && obj.Name() == "Pointer" {
					return true
				}
				if elem, ok := auditedAtomicPointerElem(audited, tt); ok {
					return walk(elem)
				}
				if (isStdImportPath(pkgPath) && !userPaths[pkgPath]) ||
					(harnessAudited && propharness.IsHarnessPath(pkgPath) && isOpaqueStructNamed(tt)) {
					for i := 0; i < tt.TypeArgs().Len(); i++ {
						if walk(tt.TypeArgs().At(i)) {
							return true
						}
					}
					return false
				}
			}
			for i := 0; i < tt.TypeArgs().Len(); i++ {
				if walk(tt.TypeArgs().At(i)) {
					return true
				}
			}
			return walk(tt.Underlying())
		case *types.Pointer:
			return walk(tt.Elem())
		case *types.Slice:
			return walk(tt.Elem())
		case *types.Array:
			return walk(tt.Elem())
		case *types.Chan:
			return walk(tt.Elem())
		case *types.Map:
			return walk(tt.Key()) || walk(tt.Elem())
		case *types.Signature:
			for _, tuple := range []*types.Tuple{tt.Params(), tt.Results()} {
				for i := 0; tuple != nil && i < tuple.Len(); i++ {
					if walk(tuple.At(i).Type()) {
						return true
					}
				}
			}
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				if walk(tt.Field(i).Type()) {
					return true
				}
			}
		case *types.Tuple:
			for i := 0; i < tt.Len(); i++ {
				if walk(tt.At(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	return walk(t)
}

func collectValueContainedUserStructs(userPaths map[string]bool, t types.Type) []*types.Named {
	var out []*types.Named
	seen := make(map[types.Type]bool)
	seenNamed := make(map[*types.Named]bool)
	var walk func(types.Type)
	walk = func(cur types.Type) {
		if cur == nil {
			return
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return
		}
		seen[cur] = true
		switch tt := cur.(type) {
		case *types.Named:
			if _, isPtr := tt.Underlying().(*types.Pointer); isPtr {
				return
			}
			if named := derefNamedStruct(userPaths, tt); named != nil && !seenNamed[named] {
				seenNamed[named] = true
				out = append(out, named)
			}
			walk(tt.Underlying())
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				walk(tt.Field(i).Type())
			}
		case *types.Array:
			walk(tt.Elem())
		}
	}
	walk(t)
	return out
}

func isTestingCleanupCallback(fn *ssa.Function) bool {
	if fn == nil || fn.Parent() == nil {
		return false
	}
	for _, b := range fn.Parent().Blocks {
		for _, instr := range b.Instrs {
			switch x := instr.(type) {
			case *ssa.MakeClosure:
				if x.Fn == fn && x.Referrers() != nil {
					for _, ref := range *x.Referrers() {
						if site, ok := ref.(ssa.CallInstruction); ok && isTestingCleanupCall(site, x) {
							return true
						}
					}
				}
			case ssa.CallInstruction:
				if isTestingCleanupCall(x, fn) {
					return true
				}
			}
		}
	}
	return false
}

func isTestingCleanupCall(site ssa.CallInstruction, arg ssa.Value) bool {
	if site == nil || site.Common() == nil {
		return false
	}
	c := site.Common()
	hasArg := false
	for _, a := range c.Args {
		if a == arg {
			hasArg = true
			break
		}
	}
	if !hasArg {
		return false
	}
	if c.IsInvoke() {
		return c.Method != nil && c.Method.Name() == "Cleanup"
	}
	callee := c.StaticCallee()
	return callee != nil && funcPkgPath(callee) == "testing" && functionSymbolName(callee) == "Cleanup"
}

func provenanceReachable(ctx context.Context, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool) (map[*ssa.Function]bool, error) {
	reach, _, err := provenanceBFSWithCandidates(ctx, false, nil, roots, mask, result, harnessAudited, userPaths, false, dropTarget, nil, nil)
	return reach, err
}

func provenanceReachableWithCandidates(ctx context.Context, prog *program, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool, candidateTypes, initBoxedTypes []types.Type) (map[*ssa.Function]bool, bool, error) {
	return provenanceBFSWithCandidates(ctx, false, prog, roots, mask, result, harnessAudited, userPaths, false, dropTarget, candidateTypes, initBoxedTypes)
}

func provenanceBFS(ctx context.Context, audited bool, prog *program, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, deferUnscannedClosures bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool) (map[*ssa.Function]bool, error) {
	reach, _, err := provenanceBFSWithCandidates(ctx, audited, prog, roots, mask, result, harnessAudited, userPaths, deferUnscannedClosures, dropTarget, nil, nil)
	return reach, err
}

func lookupCachedBaseStartup(prog *program) *baseStartupReachSummary {
	if prog == nil || prog.Summaries == nil {
		return nil
	}
	if s, ok := prog.Summaries["baseStartupReach:1:1"].(*baseStartupReachSummary); ok && s != nil {
		return s
	}
	if s, ok := prog.Summaries["baseStartupReach:0:1"].(*baseStartupReachSummary); ok && s != nil {
		return s
	}
	return nil
}

func hasStartupAncestor(fn *ssa.Function, startupFns map[*ssa.Function]bool) bool {
	if fn == nil || fn.Parent() == nil {
		return false
	}
	if initFlowFrame(fn) {
		return true
	}
	if len(startupFns) == 0 {
		return false
	}
	for p := fn.Parent(); p != nil; p = p.Parent() {
		if startupFns[p] {
			return true
		}
	}
	return false
}

func typeCanCarryAnyInitBoxed(t types.Type, initBoxed []types.Type) bool {
	if t == nil || len(initBoxed) == 0 {
		return false
	}
	found := false
	walkTypeGraph(t, true, map[types.Type]bool{}, func(cur types.Type) bool {
		iface, ok := cur.(*types.Interface)
		if !ok {
			return true
		}
		if rta.ContainsTypeParam(iface, map[types.Type]bool{}) {
			found = true
			return false
		}
		for _, bt := range initBoxed {
			if bt == nil {
				continue
			}
			if rta.ContainsTypeParam(bt, map[types.Type]bool{}) || types.Implements(bt, iface) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func provenanceBFSWithCandidates(ctx context.Context, audited bool, prog *program, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, deferUnscannedClosures bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool, candidateTypes, initBoxedTypes []types.Type) (map[*ssa.Function]bool, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	reachable := make(map[*ssa.Function]bool)
	scanned := make(map[*ssa.Function]bool)
	var pendingByParent map[*ssa.Function][]*ssa.Function
	if deferUnscannedClosures {
		pendingByParent = make(map[*ssa.Function][]*ssa.Function)
	}
	queue := append([]*ssa.Function(nil), roots...)
	var rootSSAProg *ssa.Program
	if prog != nil {
		rootSSAProg = prog.Prog
	}
	for _, r := range roots {
		if rootSSAProg == nil && r != nil {
			rootSSAProg = r.Prog
		}
	}
	var syncZeroGlobals, wholeZeroGlobals map[*ssa.Global]bool
	var asyncStartup map[*ssa.Function]bool
	var wholeComputed bool
	if deferUnscannedClosures && len(roots) > 0 && initFlowFrame(roots[0]) {
		syncZeroGlobals = rtaUnmutatedZeroGlobals(audited, prog, result, mask, userPaths)
		if len(syncZeroGlobals) > 0 {
			asyncStartup = computeRTAAsyncStartupFunctions(result, mask)
		}
	}
	var sawHarnessCall bool
	var dispatchedTargets map[*ssa.Function]bool
	var harnessCandidateTargets map[*ssa.Function]bool
	var seenCandidateTypes map[types.Type]bool
	var pendingCandidateTypes []types.Type
	enqueueDispatchedMethodsOfType := func(ssaProg *ssa.Program, rootType types.Type) {
		if ssaProg == nil || rootType == nil || len(dispatchedTargets) == 0 {
			return
		}
		walkTypeGraph(rootType, true, seenCandidateTypes, func(cur types.Type) bool {
			named, ok := cur.(*types.Named)
			if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
				return true
			}
			pkgPath := named.Obj().Pkg().Path()
			if isStdPkgPath(userPaths, pkgPath) || pkgPath == "testing" || (harnessAudited && propharness.IsHarnessPath(pkgPath)) {
				return true
			}
			for _, mt := range []types.Type{named, types.NewPointer(named)} {
				mset := ssaProg.MethodSets.MethodSet(mt)
				for i, n := 0, mset.Len(); i < n; i++ {
					sel := mset.At(i)
					if sel.Obj() == nil {
						continue
					}
					if cm := ssaProg.MethodValue(sel); cm != nil && dispatchedTargets[cm] {
						if harnessCandidateTargets == nil {
							harnessCandidateTargets = make(map[*ssa.Function]bool)
						}
						harnessCandidateTargets[cm] = true
						queue = append(queue, cm)
					}
				}
			}
			return true
		})
	}
	noteHarnessCandidateType := func(ssaProg *ssa.Program, t types.Type) {
		if result == nil || t == nil {
			return
		}
		if !sawHarnessCall {
			pendingCandidateTypes = append(pendingCandidateTypes, t)
			return
		}
		enqueueDispatchedMethodsOfType(ssaProg, t)
	}
	activateHarnessDispatchedMethods := func(ssaProg *ssa.Program) {
		if sawHarnessCall || result == nil {
			return
		}
		sawHarnessCall = true
		dispatchedTargets = make(map[*ssa.Function]bool)
		for _, targets := range result.Targets {
			for target, targetMask := range targets {
				if targetMask&mask != 0 && !isTestingMRun(target) && !isTestingBLaunch(target) {
					dispatchedTargets[target] = true
				}
			}
		}
		for _, targets := range result.HarnessStdTargets {
			for target, targetMask := range targets {
				if targetMask&mask != 0 && !isTestingMRun(target) && !isTestingBLaunch(target) {
					dispatchedTargets[target] = true
				}
			}
		}
		seenCandidateTypes = make(map[types.Type]bool)
		for _, pt := range pendingCandidateTypes {
			enqueueDispatchedMethodsOfType(ssaProg, pt)
		}
		pendingCandidateTypes = nil
	}
	for _, ct := range candidateTypes {
		noteHarnessCandidateType(rootSSAProg, ct)
	}
	var usedInitBoxed bool
	var baseStartup *baseStartupReachSummary
	var checkedGlobalCarrier map[*ssa.Global]bool
	if len(initBoxedTypes) > 0 {
		baseStartup = lookupCachedBaseStartup(prog)
	}
	seedInitBoxedTypes := func(ssaProg *ssa.Program) {
		if usedInitBoxed {
			return
		}
		usedInitBoxed = true
		for _, bt := range initBoxedTypes {
			noteHarnessCandidateType(ssaProg, bt)
		}
	}
	var opsBuf [8]*ssa.Value
	for len(queue) != 0 {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		fn := queue[0]
		queue = queue[1:]
		if fn == nil || scanned[fn] || result.Reachable[fn]&mask == 0 {
			continue
		}
		scanned[fn] = true
		if deferUnscannedClosures {
			if pending := pendingByParent[fn]; len(pending) > 0 {
				delete(pendingByParent, fn)
				queue = append(queue, pending...)
			}
		}
		// A harness frame - the standard testing package or an audited
		// property harness - is never subject content; its dispatch
		// targets still traverse, so the caller-supplied callbacks it
		// runs stay subject flow (REQ-closure-observability-analysis).
		harnessFrame := funcPkgPath(fn) == "testing" || harnessAudited && propharness.IsHarnessPath(funcPkgPath(fn))
		if !harnessFrame {
			reachable[fn] = true
			if !usedInitBoxed && len(initBoxedTypes) > 0 && len(fn.FreeVars) > 0 &&
				(baseStartup == nil || hasStartupAncestor(fn, baseStartup.startupFunctions)) {
				for _, fv := range fn.FreeVars {
					if fv != nil && typeCanCarryAnyInitBoxed(fv.Type(), initBoxedTypes) {
						seedInitBoxedTypes(fn.Prog)
						break
					}
				}
			}
		}
		fnZeroGlobals := syncZeroGlobals
		if len(syncZeroGlobals) > 0 && asyncStartup[fn] {
			if !wholeComputed {
				wholeComputed = true
				if prog != nil {
					wholeZeroGlobals = unmutatedZeroGlobalsForFunctions(audited, prog, userPaths, progAllFunctions(prog))
				}
			}
			fnZeroGlobals = wholeZeroGlobals
		}
		for _, block := range liveBlocks(fn, fnZeroGlobals) {
			for _, instruction := range block.Instrs {
				if !harnessFrame {
					if !usedInitBoxed && len(initBoxedTypes) > 0 {
						for _, op := range instruction.Operands(opsBuf[:0]) {
							if op == nil {
								continue
							}
							g, ok := (*op).(*ssa.Global)
							if !ok || g == nil || checkedGlobalCarrier[g] {
								continue
							}
							if checkedGlobalCarrier == nil {
								checkedGlobalCarrier = make(map[*ssa.Global]bool)
							}
							checkedGlobalCarrier[g] = true
							var gPkg string
							if g.Pkg != nil && g.Pkg.Pkg != nil {
								gPkg = g.Pkg.Pkg.Path()
							}
							if gPkg == "testing" || (harnessAudited && propharness.IsHarnessPath(gPkg)) {
								continue
							}
							if isStdPkgPath(userPaths, gPkg) && baseStartup != nil && !baseStartup.userTouchedStdGlobals[g] {
								continue
							}
							if typeCanCarryAnyInitBoxed(g.Type(), initBoxedTypes) {
								seedInitBoxedTypes(fn.Prog)
								break
							}
						}
					}
					if mi, isMI := instruction.(*ssa.MakeInterface); isMI && mi.X != nil {
						noteHarnessCandidateType(fn.Prog, mi.X.Type())
						continue
					}
				}
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				callee := site.Common().StaticCallee()
				if isTestingMRun(callee) {
					continue
				}
				if callee != nil {
					calleePath := funcPkgPath(callee)
					calleeHarness := calleePath == "testing" || harnessAudited && propharness.IsHarnessPath(calleePath)
					if !harnessFrame || calleeHarness {
						queue = append(queue, callee)
					}
					if calleeHarness && !harnessFrame && !initFlowFrame(callee) {
						activateHarnessDispatchedMethods(fn.Prog)
						if mc, ok := site.Common().Value.(*ssa.MakeClosure); ok {
							for _, b := range mc.Bindings {
								if b != nil {
									noteHarnessCandidateType(fn.Prog, b.Type())
								}
							}
						}
						for _, arg := range site.Common().Args {
							if arg != nil {
								noteHarnessCandidateType(fn.Prog, arg.Type())
							}
						}
						for _, ta := range callee.TypeArgs() {
							noteHarnessCandidateType(fn.Prog, ta)
						}
						continue
					}
				}
				enqueueSiteTargets := func(targets map[*ssa.Function]uint64) {
					for target, targetMask := range targets {
						if targetMask&mask == 0 || isTestingMRun(target) || isTestingBLaunch(target) {
							continue
						}
						if dropTarget != nil && !harnessCandidateTargets[target] && dropTarget(site, target) {
							continue
						}
						targetPath := funcPkgPath(target)
						targetHarness := targetPath == "testing" || harnessAudited && propharness.IsHarnessPath(targetPath)
						// User callbacks dispatched from harness frames stay
						// in the walk by the load's module facts, never by
						// path shape: a dotless user module's callback
						// classified standard here silently vanished from
						// the startup and test-main walks - the
						// dotless-module soundness family.
						if !harnessFrame || targetHarness || !isStdPkgPath(userPaths, targetPath) {
							if deferUnscannedClosures && target.Parent() != nil && target.Synthetic == "" && !scanned[target.Parent()] && !isTestingCleanupCallback(target) {
								pendingByParent[target.Parent()] = append(pendingByParent[target.Parent()], target)
								continue
							}
							queue = append(queue, target)
						}
					}
				}
				enqueueSiteTargets(result.Targets[site])
				if harnessFrame && !initFlowFrame(fn) && len(result.HarnessStdTargets) > 0 {
					enqueueSiteTargets(result.HarnessStdTargets[site])
				}
			}
		}
	}
	return reachable, usedInitBoxed, nil
}

// userModulePaths collects every loaded package path the module graph
// proves user code: both load configs request NeedModule, so in module
// mode a nil Module is exactly the standard library, and these paths
// are the code no path-shape heuristic may classify standard - a user
// module is legally named without a dot (the dotless-module soundness
// family).
func userModulePaths(pkgs []*packages.Package) map[string]bool {
	user := map[string]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Module != nil {
			user[p.PkgPath] = true
		}
	})
	return user
}

// initFlowFrame reports whether a frame is initializer flow: the
// synthetic package initializer, a compiler-numbered user init body, or
// a function transitively parented under one. A function value whose
// every address-taking reference lies in such frames is init-planted -
// address-taken under every mask by the init roots, the one provenance
// an enumeration-closed subject's pinned operand set can never
// legitimately carry. Init-flow qualified helpers keep their masks -
// the boundary is the initializer itself.
func initFlowFrame(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	top := fn
	for top.Parent() != nil {
		top = top.Parent()
	}
	// A method named init is an ordinary function: only the synthetic
	// package initializer and the compiler-numbered user init bodies
	// qualify - classifying any other frame as initializer flow would
	// let the narrowing drop legitimate subject content, the unsound
	// direction.
	if top.Signature != nil && top.Signature.Recv() != nil {
		return false
	}
	name := top.Name()
	if name == "init" {
		return top.Synthetic == "package initializer"
	}
	if rest, ok := strings.CutPrefix(name, "init#"); ok {
		for _, r := range rest {
			if r < '0' || r > '9' {
				return false
			}
		}
		return rest != ""
	}
	return false
}
