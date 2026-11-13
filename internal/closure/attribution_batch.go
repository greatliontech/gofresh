package closure

import (
	"context"
	"go/token"
	"go/types"
	"maps"
	"math/bits"
	"slices"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/internal/closure/internal/propharness"
	"github.com/greatliontech/gofresh/internal/closure/internal/rta"
	"github.com/greatliontech/gofresh/internal/trace"
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

type openCandidateSpec struct {
	idx  int
	mask uint64
}

type preparedProgramRTA struct {
	harnessAudited      bool
	userPaths           map[string]bool
	initRoots           []*ssa.Function
	harnessStdInitRoots []*ssa.Function
	summary             *callerReferenceSummary
	provFP              *freshParamAnalysis
	enumClosed          map[int]enumerationClosure
	enumCandidateTypes  []types.Type
	baseStartup         *baseStartupReachSummary
	initBoxedTypes      []types.Type
	res                 *rta.Result
}

func materializedConcreteInstances(instances []*ssa.Function) []*ssa.Function {
	var out []*ssa.Function
	for _, fn := range instances {
		if args := fn.TypeArgs(); len(args) > 0 {
			parameterized := false
			for _, arg := range args {
				if rta.ContainsTypeParam(arg, nil) {
					parameterized = true
					break
				}
			}
			if parameterized {
				continue
			}
		}
		out = append(out, fn)
	}
	return out
}

func addFuzzCallbackTypeSeed(deltaSeeds **rta.Seeds, fb *ssa.Function, mask uint64) {
	if len(fb.Params) > 0 && isHarnessPointerType(fb.Params[0].Type()) && paramHasMakeInterface(fb.Params[0], make(map[*ssa.Parameter]bool)) {
		if *deltaSeeds == nil {
			*deltaSeeds = &rta.Seeds{}
		}
		(*deltaSeeds).RuntimeTypes = append((*deltaSeeds).RuntimeTypes, rta.TypeSeed{Type: fb.Params[0].Type(), Masks: mask})
	}
}

func prepareProgramRTA(
	ctx context.Context,
	audited bool,
	pureDelegates map[string]bool,
	prog *program,
	roots map[*ssa.Function]uint64,
	allMasks uint64,
	testMasks uint64,
	openCandidates map[*ssa.Function]openCandidateSpec,
	requireAllOpenClosed bool,
	needFullBaseStartup bool,
	collectStepCallbacks func(res *rta.Result, p *preparedProgramRTA) (deltaRoots map[*ssa.Function]uint64, deltaSeeds *rta.Seeds, abort bool, err error),
) (preparedProgramRTA, bool, error) {
	var p preparedProgramRTA
	p.harnessAudited = propertyHarnessAuditedProg(audited, prog)
	p.userPaths = userModulePaths(prog.Pkgs)
	// The init-root set is subject-independent; only the test-main prepend
	// varies by harness. One derivation serves the RTA roots and every
	// subject's startup provenance, isolating stdlib packages imported
	// exclusively by a verified property harness onto the harness-stdlib plane.
	p.initRoots, p.harnessStdInitRoots = partitionHarnessInitRoots(prog, p.harnessAudited, p.userPaths)
	for _, init := range p.initRoots {
		roots[init] |= allMasks
	}
	p.enumClosed = map[int]enumerationClosure{}
	var seeds *rta.Seeds
	if p.harnessAudited {
		seeds = newHarnessRTASeeds(p.userPaths, p.harnessStdInitRoots, allMasks)
	}
	// Populate the whole-program caller-reference summary and shared
	// subject-independent provenance analysis unconditionally so solo and
	// batched evaluations share identical program-wide call sites and memos.
	p.summary = enumerateCallerReferencesForProgram(prog, audited, pureDelegates, p.userPaths, nil)
	p.provFP = newProvenanceFP(audited, p.harnessAudited, pureDelegates, prog, p.summary, p.userPaths)
	if len(openCandidates) > 0 {
		openRoots := make([]*ssa.Function, 0, len(openCandidates))
		for root := range openCandidates {
			openRoots = append(openRoots, root)
		}
		sort.Slice(openRoots, func(i, j int) bool { return openRoots[i].String() < openRoots[j].String() })
		for _, root := range openRoots {
			spec := openCandidates[root]
			enc, ok := subjectEnumerationClosure(audited, pureDelegates, p.userPaths, root, p.summary)
			if !ok {
				if requireAllOpenClosed {
					return preparedProgramRTA{}, false, nil
				}
				continue
			}
			if seeds == nil {
				seeds = &rta.Seeds{AddrTaken: map[*ssa.Function]uint64{}}
			} else if seeds.AddrTaken == nil {
				seeds.AddrTaken = map[*ssa.Function]uint64{}
			}
			for fn := range enc.addrTaken {
				seeds.AddrTaken[fn] |= spec.mask
			}
			for _, t := range enc.types {
				seeds.RuntimeTypes = append(seeds.RuntimeTypes, rta.TypeSeed{Type: t, Masks: spec.mask})
				p.enumCandidateTypes = append(p.enumCandidateTypes, t)
			}
			if spec.idx >= 0 {
				p.enumClosed[spec.idx] = enc
			}
		}
	}
	cancelCtxMasks := testMasks
	if p.harnessAudited {
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
	if needFullBaseStartup || p.harnessAudited {
		baseStartup, err := cachedBaseStartupReachability(ctx, audited, prog, p.initRoots, p.harnessStdInitRoots, p.harnessAudited, p.userPaths)
		if err != nil {
			return preparedProgramRTA{}, false, err
		}
		p.baseStartup = baseStartup
		p.initBoxedTypes = baseStartup.initBoxedTypes
	}
	analyzer := rta.NewAnalyzer()
	stepRoots := roots
	stepSeeds := seeds
	for {
		res, err := analyzer.Extend(ctx, stepRoots, stepSeeds)
		if err != nil {
			return preparedProgramRTA{}, false, err
		}
		p.res = res
		deltaRoots, deltaSeeds, abort, err := collectStepCallbacks(res, &p)
		if err != nil {
			return preparedProgramRTA{}, false, err
		}
		if abort {
			return preparedProgramRTA{}, false, nil
		}
		if len(deltaRoots) == 0 && deltaSeeds == nil {
			break
		}
		stepRoots = deltaRoots
		stepSeeds = deltaSeeds
	}
	return p, true, nil
}

func attributedReachableSetsOnce(ctx context.Context, audited bool, pureDelegates map[string]bool, prog *program, subjects []Subject) ([]attributedReachability, error) {
	var pkgPath string
	if prog != nil {
		pkgPath = prog.PkgPath
	}
	tracing := trace.Enabled(ctx, trace.DomainClosure, pkgPath)
	var start time.Time
	if tracing {
		start = time.Now()
	}
	roots := make(map[*ssa.Function]uint64)
	allMasks := ^uint64(0)
	if len(subjects) < subjectMaskBits {
		allMasks = 1<<len(subjects) - 1
	}
	var testMasks uint64
	var instancesByOrigin map[*ssa.Function][]*ssa.Function
	instantiated := map[uint64]map[*ssa.Function]bool{}
	openCandidates := map[*ssa.Function]openCandidateSpec{}
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
			if root != nil && rootMayReceiveUnknownDynamic(audited, prog, root) {
				openCandidates[root] = openCandidateSpec{idx: i, mask: mask}
			}
		case !rootMayReceiveUnknownDynamic(audited, prog, root):
			if instancesByOrigin == nil {
				instancesByOrigin = progInstancesByOrigin(prog)
			}
			// Parameterized instances (type arguments still mentioning type
			// parameters, created inside another origin's body) are excluded:
			// only concrete instantiations enter RTA roots while the origin's
			// own body yields to them.
			for _, fn := range materializedConcreteInstances(instancesByOrigin[root]) {
				roots[fn] |= mask
				if instantiated[mask] == nil {
					instantiated[mask] = map[*ssa.Function]bool{}
				}
				instantiated[mask][root] = true
			}
		}
		if subjectRunsThroughHarness(prog, root) {
			testMasks |= mask
		}
	}
	if prog.TestMain != nil {
		roots[prog.TestMain] |= testMasks
	}
	cleanupRoots := make([][]*ssa.Function, len(subjects))
	fuzzRoots := make([][]*ssa.Function, len(subjects))
	unclosedCleanup := make([]bool, len(subjects))
	unclosedFuzz := make([]bool, len(subjects))
	rootedCallbacks := make([]map[*ssa.Function]bool, len(subjects))
	prep, _, err := prepareProgramRTA(
		ctx,
		audited,
		pureDelegates,
		prog,
		roots,
		allMasks,
		testMasks,
		openCandidates,
		false,
		true,
		func(res *rta.Result, p *preparedProgramRTA) (map[*ssa.Function]uint64, *rta.Seeds, bool, error) {
			var deltaRoots map[*ssa.Function]uint64
			var deltaSeeds *rta.Seeds
			for i, subject := range subjects {
				mask := uint64(1) << i
				subjectRoot := prog.Roots[subject.Symbol]
				if subjectRoot == nil {
					continue
				}
				provRoots := []*ssa.Function{subjectRoot}
				if len(instantiated[mask]) > 0 {
					if instancesByOrigin == nil {
						instancesByOrigin = progInstancesByOrigin(prog)
					}
					provRoots = append(provRoots[:0], instancesByOrigin[subjectRoot]...)
				}
				if prog.TestMain != nil && subjectRunsThroughHarness(prog, subjectRoot) {
					provRoots = append(provRoots, prog.TestMain)
				}
				provRoots = append(provRoots, cleanupRoots[i]...)
				provRoots = append(provRoots, fuzzRoots[i]...)
				enc, enumerated := p.enumClosed[i]
				prov, _, err := provenanceReachableWithCandidates(ctx, audited, prog, provRoots, mask, res, p.harnessAudited, p.userPaths, nil, enc.types, p.initBoxedTypes, p.provFP)
				if err != nil {
					return nil, nil, false, err
				}
				cbs, unclosedCB, fbs, unclosedFB := collectTestingHarnessCallbacks(audited, p.harnessAudited, pureDelegates, p.userPaths, p.summary, subjectRoot, enumerated, enc, prov, mask, res)
				unclosedCleanup[i] = unclosedCleanup[i] || unclosedCB
				unclosedFuzz[i] = unclosedFuzz[i] || unclosedFB
				for _, cb := range cbs {
					if rootedCallbacks[i] == nil {
						rootedCallbacks[i] = map[*ssa.Function]bool{}
					}
					if !rootedCallbacks[i][cb] {
						rootedCallbacks[i][cb] = true
						cleanupRoots[i] = append(cleanupRoots[i], cb)
						if deltaRoots == nil {
							deltaRoots = make(map[*ssa.Function]uint64)
						}
						deltaRoots[cb] |= mask
					}
				}
				for _, fb := range fbs {
					if rootedCallbacks[i] == nil {
						rootedCallbacks[i] = map[*ssa.Function]bool{}
					}
					if !rootedCallbacks[i][fb] {
						rootedCallbacks[i][fb] = true
						fuzzRoots[i] = append(fuzzRoots[i], fb)
						if deltaRoots == nil {
							deltaRoots = make(map[*ssa.Function]uint64)
						}
						deltaRoots[fb] |= mask
						addFuzzCallbackTypeSeed(&deltaSeeds, fb, mask)
					}
				}
			}
			return deltaRoots, deltaSeeds, false, nil
		},
	)
	if err != nil {
		return nil, err
	}
	res := prep.res
	summary := prep.summary
	harnessAudited := prep.harnessAudited
	userPaths := prep.userPaths
	initRoots := prep.initRoots
	baseStartup := prep.baseStartup
	enumClosed := prep.enumClosed
	valueRefOutsideInit := summary.valueRefOutsideInit
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
	dropCollidedFuncs := make([]func(ssa.CallInstruction, *ssa.Function) bool, len(subjects))
	for i := range reachable {
		enc, enumerated := enumClosed[i]
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
			structFieldStores:      summary.structFieldStores,
			structWholeStores:      summary.structWholeStores,
			structPoisoned:         summary.structPoisoned,
			structReferencedByType: summary.structReferencedByType,
			programSites:           summary.sites,
			programValueRef:        summary.valueRef,
			programFunctions:       summary.allFunctions,
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
			if instancesByOrigin == nil {
				instancesByOrigin = progInstancesByOrigin(prog)
			}
			subjectProvenance = append(subjectProvenance[:0], instancesByOrigin[subjectRoot]...)
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
			dropCollidedFuncs[i] = dropCollided
		}
		var usedInitBoxed bool
		reachable[i].subjectFunctions, usedInitBoxed, err = provenanceReachableWithCandidates(ctx, audited, prog, subjectProvenance, mask, res, harnessAudited, userPaths, dropCollided, enc.types, baseStartup.initBoxedTypes, prep.provFP)
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
			reachable[i].rootedExtraFunctions, extraUsedInitBoxed, err = provenanceReachableWithCandidates(ctx, audited, prog, extraRoots, mask, res, harnessAudited, userPaths, nil, enc.types, baseStartup.initBoxedTypes, prep.provFP)
			if err != nil {
				return nil, err
			}
			if extraUsedInitBoxed {
				reachable[i].initBoxedTypes = baseStartup.initBoxedTypes
			}
		}
		if prog.TestMain != nil && subjectRunsThroughHarness(prog, subjectRoot) {
			var tmUsedInitBoxed bool
			reachable[i].testMainFunctions, tmUsedInitBoxed, err = provenanceReachableWithCandidates(ctx, audited, prog, []*ssa.Function{prog.TestMain}, mask, res, harnessAudited, userPaths, nil, nil, baseStartup.initBoxedTypes, prep.provFP)
			if err != nil {
				return nil, err
			}
			if tmUsedInitBoxed {
				reachable[i].initBoxedTypes = baseStartup.initBoxedTypes
			}
		}
	}
	for fn, masks := range res.Reachable {
		for m := masks & allMasks; m != 0; m &= m - 1 {
			idx := bits.TrailingZeros64(m)
			reachable[idx].functions[fn] = true
		}
	}
	for site, masks := range res.Resolved {
		for m := masks & allMasks; m != 0; m &= m - 1 {
			idx := bits.TrailingZeros64(m)
			reachable[idx].resolved[site] = true
		}
	}
	for site, targets := range res.Targets {
		callee := site.Common().StaticCallee()
		if callee != nil && funcPkgPath(callee) == "testing" {
			continue
		}
		parentMasks := res.Reachable[site.Parent()] & allMasks
		if parentMasks == 0 {
			continue
		}
		for target, masks := range targets {
			active := masks & parentMasks & res.Reachable[target]
			for m := active; m != 0; m &= m - 1 {
				idx := bits.TrailingZeros64(m)
				if dropCollidedFuncs[idx] != nil && dropCollidedFuncs[idx](site, target) {
					continue
				}
				projected := reachable[idx].dynamicTargets[site]
				if projected == nil {
					projected = make(map[*ssa.Function]bool)
					reachable[idx].dynamicTargets[site] = projected
				}
				projected[target] = true
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
				if !reachable[i].startupFunctions[site.Parent()] || callee != nil && funcPkgPath(callee) == "testing" {
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
	if tracing {
		trace.Emit(ctx, trace.DomainClosure, "attribution.batch.done", pkgPath,
			trace.Int("subjects", len(subjects)),
			trace.Int("reachable_fns", len(res.Reachable)),
			trace.Int("resolved_sites", len(res.Resolved)),
			trace.Int64("elapsed_ns", time.Since(start).Nanoseconds()),
		)
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
		if !startupFns[site.Parent()] || callee != nil && funcPkgPath(callee) == "testing" {
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
			userStartupFns := make(map[*ssa.Function]bool)
			var uQueue []*ssa.Function
			for _, fn := range orderedStartup {
				fp := funcPkgPath(fn)
				if !isStdPkgPath(userPaths, fp) && fp != "testing" && !propharness.IsHarnessPath(fp) {
					userStartupFns[fn] = true
					uQueue = append(uQueue, fn)
				}
			}
			for len(uQueue) > 0 {
				cur := uQueue[0]
				uQueue = uQueue[1:]
				for _, b := range cur.Blocks {
					for _, instr := range b.Instrs {
						site, ok := instr.(ssa.CallInstruction)
						if !ok || site.Common() == nil {
							continue
						}
						if callee := site.Common().StaticCallee(); callee != nil {
							if startupFns[callee] && !userStartupFns[callee] {
								userStartupFns[callee] = true
								uQueue = append(uQueue, callee)
							}
						} else {
							for t := range startupTargets[site] {
								if startupFns[t] && !userStartupFns[t] {
									userStartupFns[t] = true
									uQueue = append(uQueue, t)
								}
							}
						}
					}
				}
			}
			var opsBuf [8]*ssa.Value
			for _, fn := range orderedStartup {
				if !userStartupFns[fn] {
					continue
				}
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
	roots := make(map[*ssa.Function]uint64)
	var subjectProvenance []*ssa.Function
	includeTestMain := false
	var instancesByOrigin map[*ssa.Function][]*ssa.Function
	openCandidates := map[*ssa.Function]openCandidateSpec{}
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
				openCandidates[root] = openCandidateSpec{idx: -1, mask: unionMask}
			}
		case !rootMayReceiveUnknownDynamic(audited, prog, root):
			if instancesByOrigin == nil {
				instancesByOrigin = progInstancesByOrigin(prog)
			}
			concrete := materializedConcreteInstances(instancesByOrigin[root])
			for _, fn := range concrete {
				roots[fn] |= unionMask
				subjectProvenance = append(subjectProvenance, fn)
			}
			if len(concrete) == 0 {
				subjectProvenance = append(subjectProvenance, root)
			}
		default:
			return RootedFunctions{}, nil
		}
		if subjectRunsThroughHarness(prog, root) {
			includeTestMain = true
		}
	}
	var testMasks uint64
	if includeTestMain {
		testMasks = unionMask
		if prog.TestMain != nil {
			roots[prog.TestMain] |= unionMask
			subjectProvenance = append(subjectProvenance, prog.TestMain)
		}
	}
	rootedCallbacks := map[*ssa.Function]bool{}
	var provenance map[*ssa.Function]bool
	prep, ok, err := prepareProgramRTA(
		ctx,
		audited,
		pureDelegates,
		prog,
		roots,
		unionMask,
		testMasks,
		openCandidates,
		true,
		false,
		func(res *rta.Result, p *preparedProgramRTA) (map[*ssa.Function]uint64, *rta.Seeds, bool, error) {
			for _, subject := range subjects {
				if origin := prog.Roots[subject.Symbol]; parameterizedBody(origin) {
					res.Reachable[origin] |= unionMask
				}
			}
			var err error
			provenance, _, err = provenanceReachableWithCandidates(ctx, audited, prog, subjectProvenance, unionMask, res, p.harnessAudited, p.userPaths, nil, p.enumCandidateTypes, p.initBoxedTypes, p.provFP)
			if err != nil {
				return nil, nil, false, err
			}
			cbs, unclosedCB, fbs, unclosedFB := collectTestingHarnessCallbacks(audited, p.harnessAudited, pureDelegates, p.userPaths, p.summary, nil, false, enumerationClosure{}, provenance, unionMask, res)
			if unclosedCB || unclosedFB {
				return nil, nil, true, nil
			}
			var deltaRoots map[*ssa.Function]uint64
			var deltaSeeds *rta.Seeds
			for _, cb := range cbs {
				if !rootedCallbacks[cb] {
					rootedCallbacks[cb] = true
					if deltaRoots == nil {
						deltaRoots = make(map[*ssa.Function]uint64)
					}
					deltaRoots[cb] |= unionMask
					subjectProvenance = append(subjectProvenance, cb)
				}
			}
			for _, fb := range fbs {
				if !rootedCallbacks[fb] {
					rootedCallbacks[fb] = true
					if deltaRoots == nil {
						deltaRoots = make(map[*ssa.Function]uint64)
					}
					deltaRoots[fb] |= unionMask
					subjectProvenance = append(subjectProvenance, fb)
					addFuzzCallbackTypeSeed(&deltaSeeds, fb, unionMask)
				}
			}
			return deltaRoots, deltaSeeds, false, nil
		},
	)
	if err != nil {
		if ctx.Err() != nil {
			return RootedFunctions{}, err
		}
		if shapeFailure(err) {
			return RootedFunctions{}, nil
		}
		return RootedFunctions{}, err
	}
	if !ok {
		return RootedFunctions{}, nil
	}
	if rootedProvenanceIncomplete(audited, prep.harnessAudited, prog, prep.userPaths, provenance) {
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

func progInstancesByOrigin(p *program) map[*ssa.Function][]*ssa.Function {
	if p == nil || p.Prog == nil {
		return nil
	}
	if p.Summaries != nil {
		if cached, ok := p.Summaries["instancesByOrigin"].(map[*ssa.Function][]*ssa.Function); ok && cached != nil {
			return cached
		}
	}
	out := make(map[*ssa.Function][]*ssa.Function)
	for _, fn := range progOrderedFunctions(p) {
		if fn != nil && fn.Origin() != nil && fn.Origin() != fn {
			orig := fn.Origin()
			out[orig] = append(out[orig], fn)
		}
	}
	if p.Summaries == nil {
		p.Summaries = make(map[string]any, 4)
	}
	p.Summaries["instancesByOrigin"] = out
	return out
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
