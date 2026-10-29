package closure

import (
	"context"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/closure/internal/rta"
)

type attributedReachability struct {
	// unavailable carries a per-subject analysis failure the bisection
	// isolated: the subject's evidence is unavailable (fail-closed at
	// every consumer) while its batch siblings keep theirs.
	unavailable      string
	functions        map[*ssa.Function]bool
	subjectFunctions map[*ssa.Function]bool
	startupFunctions map[*ssa.Function]bool
	// testMainFunctions is the user-TestMain-flow slice of the startup
	// provenance: the one startup flow that can dispatch a test-planted
	// value (after m.Run), so the one whose unattributed invokes widen.
	testMainFunctions     map[*ssa.Function]bool
	resolved              map[ssa.CallInstruction]bool
	dynamicTargets        map[ssa.CallInstruction]map[*ssa.Function]bool
	startupDynamicTargets map[ssa.CallInstruction]map[*ssa.Function]bool
	// instantiatedOrigins marks parameterized origins whose materialized
	// instantiations were rooted for this subject: the origin's body
	// scan yields to theirs.
	instantiatedOrigins map[*ssa.Function]bool
	openWorld           bool
	// enumeratedRootSites is the subject root's whole-view caller
	// enumeration when its dynamic-carrying signature closed by it:
	// the sites the closed-value walk crosses to when judging the
	// root's own parameters. Nil for every other subject; subjectRoot
	// names the function the sites call.
	enumeratedRootSites    []ssa.CallInstruction
	enumeratedFieldStores  map[int][]ssa.Value
	structFieldStores      map[structFieldKey][]ssa.Value
	structPoisoned         map[structFieldKey]bool
	structReferencedByType map[*types.Named]bool
	programSites           map[*ssa.Function][]ssa.CallInstruction
	programValueRef        map[*ssa.Function]bool
	programFunctions       map[*ssa.Function]bool
	subjectRoot            *ssa.Function
	summary                *callerReferenceSummary
	// propertyHarnessAudited carries the program-level audit verdict for
	// the property harness into the per-subject walks: the closed-value
	// arms consult it so no admission outlives the audit.
	propertyHarnessAudited bool
}

// attributedReachableSets runs package-local RTA once and projects its masks
// back into the reachable set expected by the existing per-subject analyzer.
// analyzeAttributedBatch is the swappable batch worker - a var so the
// isolation behavior is testable without a shape that defeats the
// analysis (the walk guard removes the known one).
var analyzeAttributedBatch = attributedReachableSetsOnce

// probePackageScope is the swappable package-scope discriminator: it
// analyzes the roots every sub-batch SHARES - the package inits, and
// the harness main only when some subject in the batch actually runs
// through the harness (the worker roots TestMain under testMasks, so
// a batch of production subjects never walks it; probing it anyway
// once classified a harness-borne subject-scoped shape as
// package-scoped and darkened every sound sibling - the chunk-132
// review's round-3 M2). A provocation in the shared roots explains
// every subject's failure directly; a subject-scoped shape can never
// satisfy the probe. A non-nil result is the package-scoped failure,
// correctly attributed to every subject. Results memoize per
// (program, harness inclusion): the shared roots are batch-invariant.
var probePackageScope = func(ctx context.Context, prog *program, subjects []Subject) error {
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
func attributedReachableSets(ctx context.Context, audited bool, prog *program, subjects []Subject) ([]attributedReachability, error) {
	res, err := analyzeAttributedBatch(ctx, audited, prog, subjects)
	if err == nil || ctx.Err() != nil || !shapeFailure(err) {
		return res, err
	}
	if pkgErr := probePackageScope(ctx, prog, subjects); pkgErr != nil {
		rows := make([]attributedReachability, len(subjects))
		for i := range rows {
			rows[i] = attributedReachability{unavailable: pkgErr.Error()}
		}
		return rows, nil
	}
	return splitAttributed(ctx, audited, prog, subjects, err)
}

// splitAttributed bisects a shape-failing batch whose provocation is
// subject-scoped: each half runs the worker once per level (never
// re-analyzing a half the caller already ran), a failing single
// subject degrades with its own batch's error, and a non-shape
// failure anywhere propagates batch-wide.
func splitAttributed(ctx context.Context, audited bool, prog *program, subjects []Subject, batchErr error) ([]attributedReachability, error) {
	if len(subjects) == 1 {
		return []attributedReachability{{unavailable: batchErr.Error()}}, nil
	}
	mid := len(subjects) / 2
	resolve := func(half []Subject) ([]attributedReachability, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, err := analyzeAttributedBatch(ctx, audited, prog, half)
		if err == nil {
			return res, nil
		}
		if !shapeFailure(err) {
			return nil, err
		}
		return splitAttributed(ctx, audited, prog, half, err)
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

func attributedReachableSetsOnce(ctx context.Context, audited bool, prog *program, subjects []Subject) ([]attributedReachability, error) {
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
				allFunctions = ssautil.AllFunctions(prog.Prog)
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
	// The init-root set is subject-independent; only the test-main prepend
	// varies by harness. One derivation serves the RTA roots and every
	// subject's startup provenance.
	initRoots := make([]*ssa.Function, 0, len(prog.Prog.AllPackages()))
	for _, p := range prog.Prog.AllPackages() {
		if isGeneratedTestMainPackage(prog, p) {
			continue
		}
		if init := p.Func("init"); init != nil {
			initRoots = append(initRoots, init)
		}
	}
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
		if allFunctions == nil {
			allFunctions = ssautil.AllFunctions(prog.Prog)
		}
		summary = enumerateCallerReferences(audited, nil, allFunctions)
		valueRefOutsideInit = summary.valueRefOutsideInit
		var openRoots []*ssa.Function
		for root := range openCandidates {
			openRoots = append(openRoots, root)
		}
		sort.Slice(openRoots, func(i, j int) bool { return openRoots[i].String() < openRoots[j].String() })
		for _, root := range openRoots {
			i := openCandidates[root]
			enc, ok := subjectEnumerationClosure(audited, root, summary)
			if !ok {
				continue
			}
			mask := uint64(1) << i
			if seeds == nil {
				seeds = &rta.Seeds{AddrTaken: map[*ssa.Function]uint64{}}
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
	if audited && testMasks != 0 {
		if ct := programCancelCtxType(prog.Prog); ct != nil {
			if seeds == nil {
				seeds = &rta.Seeds{}
			}
			seeds.RuntimeTypes = append(seeds.RuntimeTypes, rta.TypeSeed{Type: ct, Masks: testMasks})
		}
	}
	res, err := rta.Analyze(ctx, roots, seeds)
	if err != nil {
		return nil, err
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
	harnessAudited := propertyHarnessAuditedProg(prog)
	userPaths := userModulePaths(prog.Pkgs)
	initMaskRoots := make(map[*ssa.Function]uint64, len(initRoots))
	for _, fn := range initRoots {
		initMaskRoots[fn] |= allMasks
	}
	cleanupRoots := make([][]*ssa.Function, len(subjects))
	unclosedCleanup := make([]bool, len(subjects))
	for i := range reachable {
		enc, enumerated := enumClosed[i]
		var structFieldStores map[structFieldKey][]ssa.Value
		var structPoisoned map[structFieldKey]bool
		var structReferencedByType map[*types.Named]bool
		var programSites map[*ssa.Function][]ssa.CallInstruction
		var programValueRef map[*ssa.Function]bool
		var programFunctions map[*ssa.Function]bool
		if summary != nil {
			structFieldStores = summary.structFieldStores
			structPoisoned = summary.structPoisoned
			structReferencedByType = summary.structReferencedByType
			programSites = summary.sites
			programValueRef = summary.valueRef
			programFunctions = summary.allFunctions
		}
		reachable[i] = attributedReachability{
			functions:              make(map[*ssa.Function]bool, len(res.Reachable)),
			resolved:               make(map[ssa.CallInstruction]bool, len(res.Resolved)),
			dynamicTargets:         make(map[ssa.CallInstruction]map[*ssa.Function]bool),
			startupDynamicTargets:  make(map[ssa.CallInstruction]map[*ssa.Function]bool),
			instantiatedOrigins:    instantiated[uint64(1)<<i],
			openWorld:              !enumerated && rootMayReceiveUnknownDynamic(audited, prog, prog.Roots[subjects[i].Symbol]),
			enumeratedRootSites:    enc.sites,
			enumeratedFieldStores:  enc.fieldStores,
			structFieldStores:      structFieldStores,
			structPoisoned:         structPoisoned,
			structReferencedByType: structReferencedByType,
			programSites:           programSites,
			programValueRef:        programValueRef,
			programFunctions:       programFunctions,
			subjectRoot:            prog.Roots[subjects[i].Symbol],
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
		// The enumeration-target narrowing applies to the subject walk
		// alone: an init-planted value outside the pinned enumerated
		// set — a value whose every address-taking reference lies in
		// initializer flow, whatever its shape: an init-parented
		// anonymous closure, a synthetic method-value wrapper an
		// initializer materializes (go1.27's encoding/json/v2 plants
		// base32 bound methods this way in every test binary), a named
		// function registered there — can never be a subject-closed
		// operand's value (a shared-state load refuses operand-side),
		// so RTA's matching-signature collision must not drag
		// initializer content into the subject's scan. The startup walk
		// keeps its own judgment of initializer content
		// (REQ-closure-analysis's enumeration design).
		// The drop applies only at function-value dispatch sites in
		// user frames: interface dispatch resolves through runtime-type
		// flow, not function values — the init-planted judgment is a
		// value-provenance argument and claims nothing about it — and
		// the operand-closed proof that anchors the narrowing runs only
		// for non-standard callers (a std frame's computed dispatch
		// never widens and never proves its operand), so invoke sites
		// and std-frame sites keep the whole-mask drag - spurious,
		// never unsound. The site's frame classifies by the load's
		// module facts exactly as the walks do. A value referenced
		// outside init flow anywhere in the program is kept even where
		// this subject's mask carries only the init reference - the
		// conservative direction, refusal over precision.
		var dropCollided func(site ssa.CallInstruction, target *ssa.Function) bool
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
				return !pinned[target] && !valueRefOutsideInit[target]
			}
		}
		reachable[i].subjectFunctions, err = provenanceReachable(ctx, subjectProvenance, mask, res, harnessAudited, userPaths, dropCollided)
		if err != nil {
			return nil, err
		}
		if prog.TestMain != nil && subjectRunsThroughHarness(prog, subjectRoot) {
			reachable[i].testMainFunctions, err = provenanceReachable(ctx, []*ssa.Function{prog.TestMain}, mask, res, harnessAudited, userPaths, nil)
			if err != nil {
				return nil, err
			}
		}
		cbs, unclosed := collectTestingCleanupCallbacks(reachable[i].subjectFunctions, reachable[i].testMainFunctions, mask, res)
		cleanupRoots[i] = cbs
		unclosedCleanup[i] = unclosed
		for _, cb := range cbs {
			initMaskRoots[cb] |= mask
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
					// An enumeration-closed subject's dispatch operands
					// pin their value set exactly - the enumerated
					// caller arguments and subject-local constructions -
					// yet RTA's mask carries every address-taken function
					// of matching signature, and init-flow values are
					// address-taken under every mask. An init-planted
					// value outside the pinned set is that
					// collision: dropping it removes the spurious
					// initializer-content drag (a refusal class, never a
					// false valid - a subject-closed operand can hold an
					// init-planted value only through a shared-state
					// load the closed-value walk refuses)
					// (REQ-closure-analysis's enumeration design).
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
	initRes, err := rta.Analyze(ctx, initMaskRoots, nil)
	if err != nil {
		return nil, err
	}
	for i := range reachable {
		mask := uint64(1) << i
		startupRes := initRes
		if unclosedCleanup[i] {
			startupRes = res
		}
		startupRoots := initRoots
		if len(cleanupRoots[i]) > 0 {
			startupRoots = make([]*ssa.Function, 0, len(initRoots)+len(cleanupRoots[i]))
			startupRoots = append(startupRoots, initRoots...)
			startupRoots = append(startupRoots, cleanupRoots[i]...)
		}
		reachable[i].startupFunctions, err = provenanceReachableStartup(ctx, startupRoots, mask, startupRes, harnessAudited, userPaths)
		if err != nil {
			return nil, err
		}
		for site, targets := range startupRes.Targets {
			callee := site.Common().StaticCallee()
			if startupRes.Reachable[site.Parent()]&mask == 0 || callee != nil && funcPkgPath(callee) == "testing" {
				continue
			}
			for target, masks := range targets {
				if masks&mask != 0 && startupRes.Reachable[target]&mask != 0 {
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
	return reachable, nil
}

// binaryReachableUnion computes the binary-wide union of every harness root's
// post-initialization attributed reach in a single all-roots RTA and provenance
// walk (REQ-closure-shared-dynamic-state-reachability).
func binaryReachableUnion(ctx context.Context, audited bool, prog *program, subjects []Subject) (RootedFunctions, error) {
	if len(subjects) == 0 {
		return RootedFunctions{Fns: map[string]bool{}, Complete: true}, nil
	}
	const unionMask uint64 = 1
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
				allFunctions = ssautil.AllFunctions(prog.Prog)
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
	var seeds *rta.Seeds
	if len(openCandidates) > 0 {
		if allFunctions == nil {
			allFunctions = ssautil.AllFunctions(prog.Prog)
		}
		summary := enumerateCallerReferences(audited, openCandidates, allFunctions)
		for root := range openCandidates {
			enc, ok := subjectEnumerationClosure(audited, root, summary)
			if !ok {
				return RootedFunctions{}, nil
			}
			if seeds == nil {
				seeds = &rta.Seeds{AddrTaken: map[*ssa.Function]uint64{}}
			}
			for fn := range enc.addrTaken {
				seeds.AddrTaken[fn] |= unionMask
			}
			for _, t := range enc.types {
				seeds.RuntimeTypes = append(seeds.RuntimeTypes, rta.TypeSeed{Type: t, Masks: unionMask})
			}
		}
	}
	if prog.TestMain != nil && includeTestMain {
		roots[prog.TestMain] |= unionMask
		subjectProvenance = append(subjectProvenance, prog.TestMain)
	}
	for _, p := range prog.Prog.AllPackages() {
		if isGeneratedTestMainPackage(prog, p) {
			continue
		}
		if init := p.Func("init"); init != nil {
			roots[init] |= unionMask
		}
	}
	res, err := rta.Analyze(ctx, roots, seeds)
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
	provenance, err := provenanceReachable(ctx, subjectProvenance, unionMask, res, propertyHarnessAuditedProg(prog), userModulePaths(prog.Pkgs), nil)
	if err != nil {
		return RootedFunctions{}, err
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
	allFunctions           map[*ssa.Function]bool

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
}

func (s *callerReferenceSummary) isStructReferencedOutside(named *types.Named, root *ssa.Function) bool {
	if s == nil || named == nil {
		return false
	}
	first, ok := s.structRefFirstFn[named]
	return ok && (first != root || s.structRefMultiFn[named])
}

type summaryCacheKey struct {
	prog    *ssa.Program
	audited bool
}

var (
	summaryCacheMu sync.Mutex
	summaryCache   map[summaryCacheKey]*callerReferenceSummary
)

func isPromotedWrapper(fn *ssa.Function) bool {
	return fn != nil && strings.HasPrefix(fn.Synthetic, "wrapper for ")
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
func enumerateCallerReferences(audited bool, _ map[*ssa.Function]bool, all map[*ssa.Function]bool) *callerReferenceSummary {
	var prog *ssa.Program
	for fn := range all {
		if fn != nil && fn.Prog != nil {
			prog = fn.Prog
			break
		}
	}
	if prog != nil {
		summaryCacheMu.Lock()
		if cached, ok := summaryCache[summaryCacheKey{prog: prog, audited: audited}]; ok {
			summaryCacheMu.Unlock()
			return cached
		}
		summaryCacheMu.Unlock()
	}
	ordered := make([]*ssa.Function, 0, len(all))
	for fn := range all {
		if fn != nil {
			ordered = append(ordered, fn)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].String() < ordered[j].String() })
	summary := callerReferenceSummary{
		sites:                  make(map[*ssa.Function][]ssa.CallInstruction),
		valueRef:               make(map[*ssa.Function]bool),
		directValueRef:         make(map[*ssa.Function]bool),
		valueRefOutsideInit:    make(map[*ssa.Function]bool),
		closureRefs:            make(map[*ssa.Function][]*ssa.MakeClosure),
		nonClosureRef:          make(map[*ssa.Function]bool),
		structRefFirstFn:       make(map[*types.Named]*ssa.Function),
		structRefMultiFn:       make(map[*types.Named]bool),
		structReferencedByType: make(map[*types.Named]bool),
		structPoisoned:         make(map[structFieldKey]bool),
		structFieldStores:      make(map[structFieldKey][]ssa.Value),
		allFunctions:           all,
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
	}
	recordStructRef := func(named *types.Named, fn *ssa.Function) {
		summary.structReferencedByType[named] = true
		if first, ok := summary.structRefFirstFn[named]; !ok {
			summary.structRefFirstFn[named] = fn
		} else if first != fn {
			summary.structRefMultiFn[named] = true
		}
	}
	structFieldReads := make(map[structFieldKey][]ssa.Value)
	closureRefs := make(map[*ssa.Function][]*ssa.MakeClosure)
	storeRefs := make(map[*ssa.Function][]*ssa.Store)
	callArgRefs := make(map[*ssa.Function][]ssa.CallInstruction)
	methodsByName := make(map[string][]*ssa.Function)
	if audited {
		for _, fn := range ordered {
			if fn.Signature == nil || fn.Signature.Recv() == nil || (fn.Synthetic != "" && !isPromotedWrapper(fn) && !(audited && fn.Origin() != nil)) || parameterizedBody(fn) || len(fn.Params) <= 1 {
				continue
			}
			hasDynamicExtra := false
			for _, param := range fn.Params[1:] {
				if typeMayCarryDynamicTop(audited, param.Type()) && paramMaySupplyDynamic(audited, param) {
					hasDynamicExtra = true
					break
				}
			}
			if hasDynamicExtra {
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
	var space [16]*ssa.Value
	for _, fn := range ordered {
		// A body the enumeration cannot judge as a caller — a synthetic
		// function (other than a promoted-method forwarding wrapper) or a
		// parameterized origin (open over type parameters) — makes any
		// call it holds a refusing reference, exactly like a value
		// capture: its arguments are never judged, so they must never
		// count as an enumerated site.
		judgeable := (fn.Synthetic == "" || isPromotedWrapper(fn) || (audited && fn.Origin() != nil)) && !parameterizedBody(fn)
		structJudgeable := fn.Synthetic == "" || isPromotedWrapper(fn) || (audited && fn.Origin() != nil)
		initFrame := initFlowFrame(fn)
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if audited {
					if v, ok := instr.(ssa.Value); ok && v.Type() != nil {
						if named := derefNamedStruct(v.Type()); named != nil {
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
						}
					}
					switch x := instr.(type) {
					case *ssa.Convert:
						if x.X != nil {
							if named := derefNamedStruct(x.X.Type()); named != nil {
								poisonStruct(named, -1)
							}
						}
					case *ssa.ChangeType:
						if x.X != nil {
							if named := derefNamedStruct(x.X.Type()); named != nil {
								poisonStruct(named, -1)
							}
						}
					}
					if f, ok := instr.(*ssa.Field); ok && f.X != nil {
						if named := derefNamedStruct(f.X.Type()); named != nil {
							if !structJudgeable {
								poisonStruct(named, f.Field)
							} else {
								key := structFieldKey{named: named, field: f.Field}
								structFieldReads[key] = append(structFieldReads[key], f)
							}
						}
					}
					if fa, ok := instr.(*ssa.FieldAddr); ok && fa.X != nil {
						if named := derefNamedStruct(fa.X.Type()); named != nil {
							recordStructRef(named, fn)
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
									default:
										poisonStruct(named, fa.Field)
									}
								}
							}
						}
					}
					if st, ok := instr.(*ssa.Store); ok && st.Val != nil && st.Val.Type() != nil {
						if named, ok := types.Unalias(st.Val.Type()).(*types.Named); ok && derefNamedStruct(named) != nil {
							c, isConst := st.Val.(*ssa.Const)
							isZero := isConst && c.Value == nil
							_, isLoad := st.Val.(*ssa.UnOp)
							_, isCall := st.Val.(*ssa.Call)
							_, isExtract := st.Val.(*ssa.Extract)
							_, isPhi := st.Val.(*ssa.Phi)
							_, isParam := st.Val.(*ssa.Parameter)
							_, isField := st.Val.(*ssa.Field)
							_, isIndex := st.Val.(*ssa.Index)
							_, isLookup := st.Val.(*ssa.Lookup)
							_, isTypeAssert := st.Val.(*ssa.TypeAssert)
							if !isZero && !isLoad && !isCall && !isExtract && !isPhi && !isParam && !isField && !isIndex && !isLookup && !isTypeAssert {
								poisonStruct(named, -1)
							}
						}
					}
				}
				rands := instr.Operands(space[:0])
				if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
					if callee := site.Common().StaticCallee(); callee != nil {
						summary.nonClosureRef[callee] = true
						if !isPromotedWrapper(fn) && !(audited && isBoundMethodWrapper(fn)) {
							if judgeable {
								summary.sites[callee] = append(summary.sites[callee], site)
							} else {
								summary.valueRef[callee] = true
								summary.directValueRef[callee] = true
							}
						}
					} else if audited && site.Common().IsInvoke() && site.Common().Method != nil && !isStdImportPath(funcPkgPath(fn)) {
						mname := site.Common().Method.Name()
						iface, _ := types.Unalias(site.Common().Value.Type()).Underlying().(*types.Interface)
						if iface != nil {
							for _, cand := range methodsByName[mname] {
								if cand == fn {
									continue
								}
								recvType := cand.Signature.Recv().Type()
								if types.Implements(recvType, iface) || types.Implements(types.NewPointer(recvType), iface) {
									if !isPromotedWrapper(fn) && !isBoundMethodWrapper(fn) {
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
					if audited && op != nil && *op != nil && (*op).Type() != nil {
						if named := derefNamedStruct((*op).Type()); named != nil {
							recordStructRef(named, fn)
						}
					}
					if g, ok := (*op).(*ssa.Function); ok {
						summary.directValueRef[g] = true
						if !initFrame {
							summary.valueRefOutsideInit[g] = true
						}
						if audited && judgeable && !isPromotedWrapper(fn) {
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
		var collectFuncValueCallSites func(val ssa.Value, seen map[ssa.Value]bool) ([]ssa.CallInstruction, bool)
		var collectStoreTargetCallSites func(addr ssa.Value, seen map[ssa.Value]bool) ([]ssa.CallInstruction, bool)
		collectStoreTargetCallSites = func(addr ssa.Value, seen map[ssa.Value]bool) ([]ssa.CallInstruction, bool) {
			if fa, ok := addr.(*ssa.FieldAddr); ok && fa.X != nil {
				if named := derefNamedStruct(fa.X.Type()); named != nil {
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
	}
	for fn, sites := range summary.sites {
		summary.sites[fn] = dedupCallSites(sites)
	}
	res := &summary
	if prog != nil {
		summaryCacheMu.Lock()
		if summaryCache == nil || len(summaryCache) >= 8 {
			summaryCache = make(map[summaryCacheKey]*callerReferenceSummary, 8)
		}
		summaryCache[summaryCacheKey{prog: prog, audited: audited}] = res
		summaryCacheMu.Unlock()
	}
	return res
}

// subjectEnumerationClosure judges one open-signature root against its
// collected references: closed when references are direct static calls
// (or closed struct-receiver uses) with at least one reference in the
// program, and every dynamic-reaching argument or receiver field position
// closes in the caller's or constructor's own frame.
func subjectEnumerationClosure(audited bool, root *ssa.Function, summary *callerReferenceSummary) (enumerationClosure, bool) {
	sites := summary.sites[root]
	valueRef := summary.directValueRef[root]
	fp := &freshParamAnalysis{
		selectionAudited:       audited,
		enumOnly:               true,
		enumRoot:               root,
		subjectRoot:            root,
		enumSites:              sites,
		summary:                summary,
		structFieldStores:      summary.structFieldStores,
		structPoisoned:         summary.structPoisoned,
		structReferencedByType: summary.structReferencedByType,
		programSites:           summary.sites,
		programValueRef:        summary.valueRef,
		programFunctions:       summary.allFunctions,
		isStd:                  func(fn *ssa.Function) bool { return isStdImportPath(funcPkgPath(fn)) },
		closedDone:             map[ssa.Value]bool{},
		typesMemo:              map[ssa.Value][]types.Type{},
		typesFailed:            map[ssa.Value]bool{},
		funcsMemo:              map[ssa.Value][]*ssa.Function{},
		funcsFailed:            map[ssa.Value]bool{},
		invokeTargets:          map[ssa.CallInstruction]map[*ssa.Function]bool{},
		invokeFailed:           map[ssa.CallInstruction]bool{},
	}
	if root.Signature != nil && root.Signature.Recv() != nil {
		if !audited || valueRef || len(root.Blocks) == 0 || root.Synthetic != "" || parameterizedBody(root) || len(root.Params) == 0 {
			return enumerationClosure{}, false
		}
		for _, list := range []*types.TypeParamList{root.TypeParams(), root.Signature.TypeParams(), root.Signature.RecvTypeParams()} {
			for i := 0; list != nil && i < list.Len(); i++ {
				if !TypeParamBoundsAwayFromDynamic(audited, list.At(i)) {
					return enumerationClosure{}, false
				}
			}
		}
		hasDynamicExtraParam := false
		for _, param := range root.Params[1:] {
			if typeMayCarryDynamicTop(audited, param.Type()) && paramMaySupplyDynamic(audited, param) {
				if _, isSig := types.Unalias(param.Type()).Underlying().(*types.Signature); isSig {
					return enumerationClosure{}, false
				}
				hasDynamicExtraParam = true
			}
		}
		if hasDynamicExtraParam && len(sites) == 0 {
			return enumerationClosure{}, false
		}
		named := derefNamedStruct(root.Signature.Recv().Type())
		recvMaySupply := paramMaySupplyDynamic(audited, root.Params[0])
		if recvMaySupply && named == nil {
			return enumerationClosure{}, false
		}
		if len(sites) == 0 && (named == nil || !summary.isStructReferencedOutside(named, root)) {
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
					if !typeMayCarryDynamicTop(audited, param.Type()) || !paramMaySupplyDynamic(audited, param) {
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
		_, neededFields, ok := recvStructFieldTargets(audited, root)
		if !ok {
			return enumerationClosure{}, false
		}
		if paramHasMakeInterface(root.Params[0], make(map[*ssa.Parameter]bool)) {
			enc.types = append(enc.types, root.Params[0].Type())
		}
		var fieldIdxs []int
		for idx := range neededFields {
			fieldIdxs = append(fieldIdxs, idx)
		}
		sort.Ints(fieldIdxs)
		fieldFP := *fp
		fieldFP.inFieldStore = true
		fieldSeedSeen := map[ssa.Value]bool{}
		for _, idx := range fieldIdxs {
			key := structFieldKey{named: named, field: idx}
			if summary.structPoisoned[key] {
				return enumerationClosure{}, false
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
	if valueRef || len(sites) == 0 {
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
			if audited && len(root.Blocks) > 0 && root.Synthetic == "" && !parameterizedBody(root) && !paramMaySupplyDynamic(audited, param) {
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

func derefNamedStruct(t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || isStdImportPath(named.Obj().Pkg().Path()) {
		return nil
	}
	if _, ok := named.Underlying().(*types.Struct); !ok {
		return nil
	}
	return named
}

func paramMaySupplyDynamic(audited bool, param *ssa.Parameter) bool {
	return paramMaySupplyDynamicSeen(audited, param, make(map[*ssa.Parameter]bool))
}

func paramMaySupplyDynamicSeen(audited bool, param *ssa.Parameter, seen map[*ssa.Parameter]bool) bool {
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
			if r.X != param || !carrierFreeFieldAddr(audited, r) {
				return true
			}
		case *ssa.IndexAddr:
			if r.X != param || !carrierFreeReadOnlyAddr(audited, r) {
				return true
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != param || !carrierFreeValueUses(audited, r) {
				return true
			}
		case *ssa.Field:
			if r.X != param || !carrierFreeValueUses(audited, r) {
				return true
			}
		case *ssa.Index:
			if r.X != param || !carrierFreeValueUses(audited, r) {
				return true
			}
		case *ssa.MakeInterface:
			if r.X != param {
				return true
			}
			named := derefNamedStruct(param.Type())
			if named == nil || param.Parent() == nil || param.Parent().Prog == nil {
				return true
			}
			needed := make(map[int]bool)
			if !interfaceValueStructFieldTargets(audited, named, param.Type(), param.Parent().Prog, r, needed, seen, make(map[ssa.Value]bool)) || len(needed) > 0 {
				return true
			}
		case ssa.CallInstruction:
			if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil || r.Common().IsInvoke() {
				return true
			}
			callee := r.Common().StaticCallee()
			if callee == nil || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && !(audited && callee.Origin() != nil)) || parameterizedBody(callee) || len(r.Common().Args) != len(callee.Params) {
				return true
			}
			for i, arg := range r.Common().Args {
				if arg == param && paramMaySupplyDynamicSeen(audited, callee.Params[i], seen) {
					return true
				}
			}
		default:
			return true
		}
	}
	return false
}

func carrierFreeFieldAddr(audited bool, fa *ssa.FieldAddr) bool {
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
	return carrierFreeReadOnlyAddr(audited, fa)
}

func carrierFreeReadOnlyAddr(audited bool, addr ssa.Value) bool {
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
			if elemCarries && !carrierFreeValueUses(audited, r) {
				return false
			}
		case *ssa.FieldAddr:
			if r.X != addr || !carrierFreeFieldAddr(audited, r) {
				return false
			}
		case *ssa.IndexAddr:
			if r.X != addr || !carrierFreeReadOnlyAddr(audited, r) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func carrierFreeValueUses(audited bool, val ssa.Value) bool {
	return carrierFreeValueUsesSeen(audited, val, make(map[ssa.Value]bool))
}

func carrierFreeValueUsesSeen(audited bool, val ssa.Value, seen map[ssa.Value]bool) bool {
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
		case *ssa.DebugRef, *ssa.Return:
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return false
			}
		case *ssa.Field:
			if r.X != val || !carrierFreeValueUsesSeen(audited, r, seen) {
				return false
			}
		case *ssa.Index:
			if r.X != val || !carrierFreeValueUsesSeen(audited, r, seen) {
				return false
			}
		case *ssa.Phi:
			if !carrierFreeValueUsesSeen(audited, r, seen) {
				return false
			}
		case *ssa.MakeInterface:
			if !audited || r.X != val || !makeInterfaceOnlyReturned(r) {
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

func makeInterfaceOnlyReturned(mi *ssa.MakeInterface) bool {
	if mi == nil || mi.Referrers() == nil {
		return false
	}
	sawReturn := false
	for _, ref := range *mi.Referrers() {
		switch ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Return:
			sawReturn = true
		default:
			return false
		}
	}
	return sawReturn
}

func recvStructFieldTargets(audited bool, root *ssa.Function) (*types.Named, map[int]bool, bool) {
	if !audited || root == nil || root.Signature == nil || root.Signature.Recv() == nil || len(root.Blocks) == 0 || root.Synthetic != "" || parameterizedBody(root) || len(root.Params) == 0 {
		return nil, nil, false
	}
	named := derefNamedStruct(root.Signature.Recv().Type())
	if named == nil {
		return nil, nil, false
	}
	needed := make(map[int]bool)
	if !collectParamStructFieldTargets(audited, named, root.Params[0], needed, make(map[*ssa.Parameter]bool)) {
		return nil, nil, false
	}
	return named, needed, true
}

func collectParamStructFieldTargets(audited bool, named *types.Named, param *ssa.Parameter, needed map[int]bool, seen map[*ssa.Parameter]bool) bool {
	if param == nil {
		return false
	}
	return collectStructCarrierFieldTargets(audited, named, param, nil, needed, seen, make(map[ssa.Value]bool))
}

func collectStructCarrierFieldTargets(audited bool, named *types.Named, val ssa.Value, initStore *ssa.Store, needed map[int]bool, seen map[*ssa.Parameter]bool, valSeen map[ssa.Value]bool) bool {
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
				if !ok || derefNamedStruct(alloc.Type()) != named {
					return false
				}
				if !collectStructCarrierFieldTargets(audited, named, alloc, r, needed, seen, valSeen) {
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
					if derefNamedStruct(fn.FreeVars[i].Type()) != named ||
						!collectStructCarrierFieldTargets(audited, named, fn.FreeVars[i], nil, needed, seen, valSeen) {
						return false
					}
				}
			}
		case *ssa.Field:
			if r.X != val {
				return false
			}
			if carrierFreeValueUses(audited, r) {
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
					if carrierFreeValueUses(audited, ur) {
						continue
					}
					needed[ur.Field] = true
				case *ssa.Store:
					if ur.Val == r && ur.Addr != r {
						if alloc, ok := ur.Addr.(*ssa.Alloc); ok && derefNamedStruct(alloc.Type()) == named {
							if !collectStructCarrierFieldTargets(audited, named, alloc, ur, needed, seen, valSeen) {
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
			if carrierFreeFieldAddr(audited, r) {
				continue
			}
			if r.Referrers() == nil {
				return false
			}
			for _, fref := range *r.Referrers() {
				switch fr := fref.(type) {
				case *ssa.DebugRef:
				case *ssa.UnOp:
					if fr.Op != token.MUL || fr.X != r {
						return false
					}
				default:
					return false
				}
			}
			needed[r.Field] = true
		case *ssa.MakeInterface:
			if r.X != val {
				return false
			}
			if val.Parent() != nil && val.Parent().Prog != nil &&
				interfaceValueStructFieldTargets(audited, named, val.Type(), val.Parent().Prog, r, needed, seen, make(map[ssa.Value]bool)) {
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
			if callee == nil || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && !(audited && callee.Origin() != nil)) || parameterizedBody(callee) || len(r.Common().Args) != len(callee.Params) {
				return false
			}
			for i, arg := range r.Common().Args {
				if arg == val {
					if derefNamedStruct(callee.Params[i].Type()) != named {
						return false
					}
					if paramMaySupplyDynamic(audited, callee.Params[i]) {
						if !collectStructCarrierFieldTargets(audited, named, callee.Params[i], nil, needed, seen, valSeen) {
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

func interfaceValueStructFieldTargets(audited bool, named *types.Named, concreteType types.Type, prog *ssa.Program, val ssa.Value, needed map[int]bool, paramSeen map[*ssa.Parameter]bool, valSeen map[ssa.Value]bool) bool {
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
		case *ssa.DebugRef, *ssa.Return:
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return false
			}
		case *ssa.ChangeInterface:
			if r.X != val || !interfaceValueStructFieldTargets(audited, named, concreteType, prog, r, needed, paramSeen, valSeen) {
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
				if !interfaceValueStructFieldTargets(audited, named, concreteType, prog, r, needed, paramSeen, valSeen) {
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
					if ex.Index == 0 && !interfaceValueStructFieldTargets(audited, named, concreteType, prog, ex, needed, paramSeen, valSeen) {
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
					if i >= len(fn.FreeVars) || !interfaceValueStructFieldTargets(audited, named, concreteType, prog, fn.FreeVars[i], needed, paramSeen, valSeen) {
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
				if cmethod == nil || len(cmethod.Blocks) == 0 || len(cmethod.Params) == 0 {
					return false
				}
				if paramMaySupplyDynamicSeen(audited, cmethod.Params[0], make(map[*ssa.Parameter]bool)) {
					if !collectParamStructFieldTargets(audited, named, cmethod.Params[0], needed, paramSeen) {
						return false
					}
				}
				continue
			}
			callee := r.Common().StaticCallee()
			if callee == nil || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && !(audited && callee.Origin() != nil)) || parameterizedBody(callee) || len(r.Common().Args) != len(callee.Params) {
				return false
			}
			for i, arg := range r.Common().Args {
				if arg == val && !interfaceValueStructFieldTargets(audited, named, concreteType, prog, callee.Params[i], needed, paramSeen, valSeen) {
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
// The case set mirrors the closed-value walk that admitted the value;
// bindings of ordinary closures are not collected — a free-variable
// dispatch inside the body refuses per-site when the body is scanned.
func collectClosedDynamicSeeds(value ssa.Value, enc *enumerationClosure, seen map[ssa.Value]bool, fp *freshParamAnalysis) {
	if value == nil {
		return
	}
	if value.Type() != nil && !typeMayCarryDynamicTop(fp != nil && fp.selectionAudited, value.Type()) {
		return
	}
	if fp == nil {
		if seen[value] {
			return
		}
		seen[value] = true
		collectClosedDynamicSeedsUncached(value, enc, seen, nil)
		return
	}
	if fp.usedSubject != nil && value.Parent() != nil && (value.Parent() == fp.enumRoot || value.Parent() == fp.subjectRoot) {
		*fp.usedSubject = true
	}
	outsideCallee := !inActiveCallee(value.Parent(), fp.calleeSeen)
	inProgScope := outsideCallee && value.Parent() != fp.enumRoot && value.Parent() != fp.subjectRoot
	if outsideCallee {
		if inProgScope && fp.summary != nil {
			if entry, ok := fp.summary.enumSeedsMemo[value]; ok {
				enc.types = append(enc.types, entry.types...)
				for _, fn := range entry.funcs {
					enc.addrTaken[fn] = true
				}
				return
			}
		}
		if fp.rootSeen != nil {
			if fp.rootSeen[value] {
				return
			}
			fp.rootSeen[value] = true
			collectClosedDynamicSeedsUncached(value, enc, seen, fp)
			return
		}
		if seen != nil && seen[value] {
			return
		}
		usedSubject := value.Parent() != nil && (value.Parent() == fp.enumRoot || value.Parent() == fp.subjectRoot)
		rootFP := *fp
		rootFP.rootSeen = map[ssa.Value]bool{value: true}
		rootFP.usedSubject = &usedSubject
		subEnc := enumerationClosure{addrTaken: map[*ssa.Function]bool{}}
		collectClosedDynamicSeedsUncached(value, &subEnc, seen, &rootFP)
		if seen != nil {
			seen[value] = true
		}
		if fp.usedSubject != nil && usedSubject {
			*fp.usedSubject = true
		}
		var dedupTypes []types.Type
		if len(subEnc.types) > 0 {
			seenT := make(map[types.Type]bool, len(subEnc.types))
			for _, t := range subEnc.types {
				if !seenT[t] {
					seenT[t] = true
					dedupTypes = append(dedupTypes, t)
				}
			}
		}
		enc.types = append(enc.types, dedupTypes...)
		for fn := range subEnc.addrTaken {
			enc.addrTaken[fn] = true
		}
		if inProgScope && fp.summary != nil && !usedSubject {
			var funcs []*ssa.Function
			if len(subEnc.addrTaken) > 0 {
				funcs = make([]*ssa.Function, 0, len(subEnc.addrTaken))
				for fn := range subEnc.addrTaken {
					funcs = append(funcs, fn)
				}
			}
			fp.summary.enumSeedsMemo[value] = dynamicSeedEntry{
				types: dedupTypes,
				funcs: funcs,
			}
		}
		return
	}
	if seen[value] {
		return
	}
	seen[value] = true
	collectClosedDynamicSeedsUncached(value, enc, seen, fp)
}

func collectClosedDynamicSeedsUncached(value ssa.Value, enc *enumerationClosure, seen map[ssa.Value]bool, fp *freshParamAnalysis) {
	switch v := value.(type) {
	case *ssa.Function:
		enc.addrTaken[v] = true
	case *ssa.MakeClosure:
		if fn, ok := v.Fn.(*ssa.Function); ok {
			if syntheticInterfaceMethodWrapper(fn) && fp != nil && fp.selectionAudited && len(v.Bindings) == 1 && v.Parent() != nil && v.Parent().Prog != nil {
				collectClosedDynamicSeeds(v.Bindings[0], enc, seen, fp)
				if method, ok := fn.Object().(*types.Func); ok && method != nil {
					cts := map[types.Type]bool{}
					subFP := *fp
					subFP.rootSeen = nil
					if walkDynamicValue(v.Bindings[0], &dynamicValueCollector{types: cts}, map[ssa.Value]bool{}, nil, &subFP) {
						if targets, ok := resolveConcreteMethodTargets(v.Parent().Prog, v.Bindings[0].Type(), method, cts, fp); ok {
							for t := range targets {
								enc.addrTaken[t] = true
							}
							return
						}
					}
				}
			}
			enc.addrTaken[fn] = true
		}
	case *ssa.MakeInterface:
		enc.types = append(enc.types, v.X.Type())
		if _, isFunc := types.Unalias(v.X.Type()).Underlying().(*types.Signature); isFunc {
			collectClosedDynamicSeeds(v.X, enc, seen, fp)
		}
	case *ssa.ChangeInterface:
		collectClosedDynamicSeeds(v.X, enc, seen, fp)
	case *ssa.TypeAssert:
		collectClosedDynamicSeeds(v.X, enc, seen, fp)
	case *ssa.ChangeType:
		collectClosedDynamicSeeds(v.X, enc, seen, fp)
	case *ssa.Convert:
		collectClosedDynamicSeeds(v.X, enc, seen, fp)
	case *ssa.MakeSlice:
		if fp != nil && fp.selectionAudited && sliceHasIndexedStore(v) {
			walkMakeSliceIndexedStores(v, map[ssa.Value]bool{}, func(val ssa.Value) bool {
				collectClosedDynamicSeeds(val, enc, seen, fp)
				return true
			})
		}
	case *ssa.MakeMap:
		if fp != nil && fp.selectionAudited {
			walkMakeMapValues(v, map[ssa.Value]bool{}, func(val ssa.Value) bool {
				collectClosedDynamicSeeds(val, enc, seen, fp)
				return true
			})
		}
	case *ssa.Lookup:
		if fp != nil && fp.selectionAudited && v.X != nil {
			collectClosedDynamicSeeds(v.X, enc, seen, fp)
		}
	case *ssa.Slice:
		if v.X != nil {
			if _, isSlice := types.Unalias(v.X.Type()).Underlying().(*types.Slice); isSlice {
				collectClosedDynamicSeeds(v.X, enc, seen, fp)
			} else if alloc, ok := v.X.(*ssa.Alloc); ok && cellOf(alloc, map[ssa.Value]bool{}) != nil {
				walkLoadCellReferrers(alloc, func(val ssa.Value) bool {
					collectClosedDynamicSeeds(val, enc, seen, fp)
					return true
				})
			}
		}
	case *ssa.Alloc:
		if fp != nil && fp.selectionAudited && v.Type() != nil {
			if v.Parent() != nil && fp.isStdFunc(v.Parent()) {
				enc.types = append(enc.types, v.Type())
			} else if named := derefNamedStruct(v.Type()); named != nil && !fp.structPoisoned[structFieldKey{named: named, field: -1}] {
				enc.types = append(enc.types, v.Type())
			}
		}
	case *ssa.Field:
		if fp != nil && v.X != nil {
			if named := derefNamedStruct(v.X.Type()); named != nil {
				fieldFP := *fp
				fieldFP.inFieldStore = true
				fieldFP.callBindings = nil
				fieldFP.calleeSeen = nil
				fieldFP.calleeDepth = nil
				for _, sv := range fp.structFieldStores[structFieldKey{named: named, field: v.Field}] {
					collectClosedDynamicSeeds(sv, enc, seen, &fieldFP)
				}
			}
		}
	case *ssa.Call:
		if b, ok := v.Common().Value.(*ssa.Builtin); ok && b.Name() == "append" {
			for _, arg := range v.Common().Args {
				collectClosedDynamicSeeds(arg, enc, seen, fp)
			}
			return
		}
		collectCallResultSeeds(v, -1, enc, seen, fp)
	case *ssa.Extract:
		if call, ok := v.Tuple.(*ssa.Call); ok {
			collectCallResultSeeds(call, v.Index, enc, seen, fp)
		} else {
			collectClosedDynamicSeeds(v.Tuple, enc, seen, fp)
		}
	case *ssa.Phi:
		for _, edge := range v.Edges {
			collectClosedDynamicSeeds(edge, enc, seen, fp)
		}
	case *ssa.Parameter:
		if fp != nil {
			if bound, ok := fp.callBindings[v]; ok && bound != nil {
				boundFP := fp
				fn := v.Parent()
				if fn != nil && fp.calleeSeen[fn] {
					copied := *fp
					calleeSeen := make(map[*ssa.Function]bool, len(fp.calleeSeen))
					for k, val := range fp.calleeSeen {
						if k != fn {
							calleeSeen[k] = val
						}
					}
					copied.calleeSeen = calleeSeen
					calleeDepth := make(map[*ssa.Function]int, len(fp.calleeDepth))
					for k, val := range fp.calleeDepth {
						if k != fn {
							calleeDepth[k] = val
						}
					}
					copied.calleeDepth = calleeDepth
					bindings := make(map[*ssa.Parameter]ssa.Value, len(fp.callBindings))
					for k, val := range fp.callBindings {
						if k.Parent() != fn {
							bindings[k] = val
						}
					}
					copied.callBindings = bindings
					boundFP = &copied
				}
				collectClosedDynamicSeeds(bound, enc, seen, boundFP)
				return
			}
		}
		if args, usedProgramSites, ok := attributedParameterArgs(v, fp); ok {
			argFP := fp
			if usedProgramSites && fp != nil && (!fp.inProgramSites || len(fp.callBindings) > 0) {
				copied := *fp
				copied.inProgramSites = true
				copied.callBindings = nil
				copied.calleeSeen = nil
				copied.calleeDepth = nil
				argFP = &copied
			}
			for _, arg := range args {
				collectClosedDynamicSeeds(arg, enc, seen, argFP)
			}
		}
	case *ssa.FreeVar:
		if bindings, usedProgramSites, ok := attributedFreeVarBindings(v, fp); ok {
			bindFP := fp
			fn := v.Parent()
			if usedProgramSites && fp != nil && (!fp.inProgramSites || len(fp.callBindings) > 0) {
				copied := *fp
				copied.inProgramSites = true
				copied.callBindings = nil
				copied.calleeSeen = nil
				copied.calleeDepth = nil
				bindFP = &copied
			} else if fp != nil && fn != nil && fp.calleeSeen[fn] {
				copied := *fp
				calleeSeen := make(map[*ssa.Function]bool, len(fp.calleeSeen))
				for k, val := range fp.calleeSeen {
					if k != fn {
						calleeSeen[k] = val
					}
				}
				copied.calleeSeen = calleeSeen
				calleeDepth := make(map[*ssa.Function]int, len(fp.calleeDepth))
				for k, val := range fp.calleeDepth {
					if k != fn {
						calleeDepth[k] = val
					}
				}
				copied.calleeDepth = calleeDepth
				cb := make(map[*ssa.Parameter]ssa.Value, len(fp.callBindings))
				for k, val := range fp.callBindings {
					if k.Parent() != fn {
						cb[k] = val
					}
				}
				copied.callBindings = cb
				bindFP = &copied
			}
			for _, b := range bindings {
				collectClosedDynamicSeeds(b, enc, seen, bindFP)
			}
		}
	case *ssa.UnOp:
		if v.Op == token.MUL {
			if g, ok := v.X.(*ssa.Global); ok && fp != nil && fp.selectionAudited && (isUnmutatedStandardSentinelGlobalAny(g) || isUnmutatedSentinelGlobal(g)) {
				cts := map[types.Type]bool{}
				sentinelGlobalConcreteTypes(g, cts)
				for ct := range cts {
					enc.types = append(enc.types, ct)
				}
			} else if fa, ok := v.X.(*ssa.FieldAddr); ok && fp != nil {
				fieldFP := *fp
				fieldFP.inFieldStore = true
				fieldFP.callBindings = nil
				fieldFP.calleeSeen = nil
				fieldFP.calleeDepth = nil
				if fp.enumRoot != nil && len(fp.enumRoot.Params) > 0 && fa.X == fp.enumRoot.Params[0] && len(fp.enumFieldStores) > 0 {
					for _, sv := range fp.enumFieldStores[fa.Field] {
						collectClosedDynamicSeeds(sv, enc, seen, &fieldFP)
					}
				} else if fa.X != nil {
					if named := derefNamedStruct(fa.X.Type()); named != nil {
						for _, sv := range fp.structFieldStores[structFieldKey{named: named, field: fa.Field}] {
							collectClosedDynamicSeeds(sv, enc, seen, &fieldFP)
						}
					}
				}
			} else if ia, ok := v.X.(*ssa.IndexAddr); ok && ia.X != nil {
				if _, isSlice := types.Unalias(ia.X.Type()).Underlying().(*types.Slice); isSlice {
					collectClosedDynamicSeeds(ia.X, enc, seen, fp)
				} else if cellOf(v.X, map[ssa.Value]bool{}) != nil {
					walkLoadCellReferrers(v.X, func(val ssa.Value) bool {
						collectClosedDynamicSeeds(val, enc, seen, fp)
						return true
					})
				}
			} else if cellOf(v.X, map[ssa.Value]bool{}) != nil {
				walkLoadCellReferrers(v.X, func(val ssa.Value) bool {
					collectClosedDynamicSeeds(val, enc, seen, fp)
					return true
				})
			}
		}
	}
}

func collectCallResultSeeds(call *ssa.Call, tupleIndex int, enc *enumerationClosure, seen map[ssa.Value]bool, fp *freshParamAnalysis) {
	if fp == nil || !fp.selectionAudited || call == nil || call.Common() == nil {
		return
	}
	if tupleIndex <= 0 && isHarnessContextCall(call, map[ssa.Value]bool{}, map[ssa.Value]bool{}, fp) {
		if ct := harnessCancelCtxType(call); ct != nil {
			enc.types = append(enc.types, ct)
		}
		return
	}
	if call.Common().IsInvoke() {
		if fp.invokeSeen[call] {
			if fp.lowlink != nil {
				if d := fp.invokeDepth[call]; d > 0 && (*fp.lowlink == 0 || d < *fp.lowlink) {
					*fp.lowlink = d
				}
			}
			return
		}
		invokeFP := *fp
		invokeSeen := make(map[ssa.CallInstruction]bool, len(fp.invokeSeen)+1)
		for k, v := range fp.invokeSeen {
			invokeSeen[k] = v
		}
		invokeSeen[call] = true
		invokeFP.invokeSeen = invokeSeen
		invokeDepth := make(map[ssa.CallInstruction]int, len(fp.invokeDepth)+1)
		for k, v := range fp.invokeDepth {
			invokeDepth[k] = v
		}
		depth := len(fp.stackDepth)
		if depth == 0 {
			depth = 1
		}
		invokeDepth[call] = depth
		invokeFP.invokeDepth = invokeDepth
		targets, ok := closedInvokeTargets(call, &invokeFP)
		if !ok || len(targets) == 0 {
			return
		}
		for _, arg := range call.Common().Args {
			if arg == nil {
				return
			}
			collectClosedDynamicSeeds(arg, enc, seen, &invokeFP)
		}
		var ordered []*ssa.Function
		for callee := range targets {
			ordered = append(ordered, callee)
		}
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].String() < ordered[j].String() })
		for _, callee := range ordered {
			callArgs := append([]ssa.Value{call.Common().Value}, call.Common().Args...)
			collectCalleeResultSeeds(callee, callArgs, tupleIndex, enc, seen, &invokeFP)
		}
		return
	}
	callee := call.Common().StaticCallee()
	collectCalleeResultSeeds(callee, call.Common().Args, tupleIndex, enc, seen, fp)
}

func collectCalleeResultSeeds(callee *ssa.Function, callArgs []ssa.Value, tupleIndex int, enc *enumerationClosure, seen map[ssa.Value]bool, fp *freshParamAnalysis) {
	if callee == nil || (callee.Synthetic != "" && callee.Origin() == nil && !isPromotedWrapper(callee) && !strings.HasPrefix(callee.Synthetic, "wrapper ")) || len(callee.Blocks) == 0 || !calleeFreeVarsClosed(callee, fp) {
		return
	}
	if fp.calleeSeen[callee] {
		if fp.lowlink != nil {
			if d := fp.calleeDepth[callee]; d > 0 && (*fp.lowlink == 0 || d < *fp.lowlink) {
				*fp.lowlink = d
			}
		}
		return
	}
	if callee == fp.enumRoot || callee == fp.subjectRoot {
		if fp.usedSubject != nil {
			*fp.usedSubject = true
		}
	}
	pkgPath := funcPkgPath(callee)
	if fp.isStdFunc(callee) {
		if !isAuditedStandardOrDelegatePackage(fp.selectionAudited, pkgPath) && !auditedStandardCallee(fp.selectionAudited, pkgPath, functionSymbolName(callee), callee) {
			return
		}
	} else if (!fp.functions[callee] && !fp.programFunctions[callee]) || callee == fp.enumRoot || (callee.Signature.Variadic() && !fp.inFieldStore && !fp.inProgramSites) || propertyHarnessPath(pkgPath) {
		return
	}
	if len(callArgs) != len(callee.Params) {
		return
	}
	for i, arg := range callArgs {
		if arg == nil {
			return
		}
		if i < len(callee.Params) && !calleeParamMayAffectResult(fp.selectionAudited, callee, i) {
			continue
		}
		if !fp.isStdFunc(callee) && derefNamedStruct(arg.Type()) != nil {
			continue
		}
		collectClosedDynamicSeeds(arg, enc, seen, fp)
	}
	calleeFP := *fp
	calleeSeen := make(map[*ssa.Function]bool, len(fp.calleeSeen)+1)
	for k, v := range fp.calleeSeen {
		calleeSeen[k] = v
	}
	calleeSeen[callee] = true
	calleeFP.calleeSeen = calleeSeen
	calleeDepth := make(map[*ssa.Function]int, len(fp.calleeDepth)+1)
	for k, v := range fp.calleeDepth {
		calleeDepth[k] = v
	}
	depth := len(fp.stackDepth)
	if depth == 0 {
		depth = 1
	}
	calleeDepth[callee] = depth
	calleeFP.calleeDepth = calleeDepth
	bindings := make(map[*ssa.Parameter]ssa.Value, len(fp.callBindings)+len(callee.Params))
	for k, v := range fp.callBindings {
		bindings[k] = v
	}
	for i, p := range callee.Params {
		bindings[p] = callArgs[i]
	}
	calleeFP.callBindings = bindings
	calleeSeenMap := make(map[ssa.Value]bool, len(seen))
	for k, v := range seen {
		if v && k != nil && k.Parent() != callee {
			calleeSeenMap[k] = true
		}
	}
	for _, block := range liveCalleeBlocks(callee) {
		for _, instr := range block.Instrs {
			ret, ok := instr.(*ssa.Return)
			if !ok {
				continue
			}
			var res ssa.Value
			if tupleIndex < 0 {
				if len(ret.Results) != 1 {
					continue
				}
				res = ret.Results[0]
			} else if tupleIndex < len(ret.Results) {
				res = ret.Results[tupleIndex]
			}
			if block == callee.Recover && isSyntheticRecoverZeroConst(res) {
				continue
			}
			collectClosedDynamicSeeds(res, enc, calleeSeenMap, &calleeFP)
		}
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
	return SignatureOpenWorldTerm(audited, root.Signature, extraTypeParams, subjectRunsThroughHarness(prog, root), CarrierPolicyClosure) != ""
}

// SignatureOpenWorldTerm names the first term of a signature that confers
// openness on its subject — a type parameter whose constraint does not bound
// its type set away from dynamic carriers, or a receiver or parameter whose
// type carries dynamic reach under policy — and returns "" for a closed
// signature (REQ-closure-analysis, REQ-closure-refusal-channels).
func SignatureOpenWorldTerm(audited bool, sig *types.Signature, extraTypeParams *types.TypeParamList, allowHarnessSignature bool, policy CarrierWalkPolicy) string {
	if sig == nil {
		return "unresolved signature"
	}
	for _, list := range []*types.TypeParamList{extraTypeParams, sig.TypeParams(), sig.RecvTypeParams()} {
		for i := 0; list != nil && i < list.Len(); i++ {
			if param := list.At(i); !TypeParamBoundsAwayFromDynamic(audited, param) {
				return "type parameter " + param.Obj().Name() + " constrained by " + types.TypeString(param.Constraint(), packageNameQualifier)
			}
		}
	}
	if allowHarnessSignature && isHarnessSubjectSignature(sig) {
		return ""
	}
	// One fresh map per parameter: sharing across parameters would let
	// one walk's marks short-circuit another's (a constraint interface
	// marked by a bounding evaluation reading clean as a later value
	// type); within one parameter's evaluation the map is shared - the
	// cycle guard for recursive constraints.
	if recv := sig.Recv(); recv != nil && WalkDynamicCarrier(audited, recv.Type(), make(map[types.Type]bool), policy) {
		return "receiver " + types.TypeString(recv.Type(), packageNameQualifier)
	}
	params := sig.Params()
	for i := 0; params != nil && i < params.Len(); i++ {
		param := params.At(i)
		if WalkDynamicCarrier(audited, param.Type(), make(map[types.Type]bool), policy) {
			name := param.Name()
			if name == "" || name == "_" {
				name = "#" + strconv.Itoa(i+1)
			}
			return "parameter " + name + " " + types.TypeString(param.Type(), packageNameQualifier)
		}
	}
	return ""
}

func packageNameQualifier(pkg *types.Package) string {
	if pkg == nil {
		return ""
	}
	return pkg.Name()
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

// AuditedAtomicPointerElem reports whether t is the toolchain's
// sync/atomic.Pointer[T] instantiation, yielding T: under the audited
// atomic transparency the carrier walks see the type as *T — its
// internal unsafe pointer is an implementation cell the zero-width *T
// field and the whole method set type-pin to *T, never an unsafe
// channel (REQ-closure-shared-dynamic-state). The audit covers exactly
// the toolchain's type: a defined wrapper inherits no methods and its
// cell is reached only through an address conversion the ordinary
// escape rules already mark, so it keeps the fail-closed judgment and
// never matches here (its Obj is not sync/atomic's). One helper for
// every carrier walk, so the tiers cannot diverge on this rule
// (REQ-closure-analysis's one-answer arm).
func AuditedAtomicPointerElem(audited bool, t *types.Named) (types.Type, bool) {
	if !audited {
		return nil, false
	}
	obj := t.Obj()
	if obj == nil || obj.Pkg() == nil ||
		obj.Pkg().Path() != "sync/atomic" || obj.Name() != "Pointer" ||
		t.TypeArgs() == nil || t.TypeArgs().Len() != 1 {
		return nil, false
	}
	return t.TypeArgs().At(0), true
}

// CarrierWalkPolicy parameterizes WalkDynamicCarrier across the three carrier
// walk surfaces:
//   - CarrierPolicyClosure: the closure tier's carries-dynamic walk
//     (typeMayCarryDynamic), sharing seen into TypeParam constraint bounds.
//   - CarrierPolicyConsumer: the consumer tier's carries-dynamic walk
//     (typeMayCarryUnknownDynamic), entering TypeParam constraint bounds with
//     a fresh seen map.
//   - CarrierPolicyAlias: the consumer tier's alias-handing walk
//     (typeHandsOutDynamicAlias), where Signature is not an alias, TypeParam
//     recurses into t.Constraint() with seen, and reference-header elements
//     delegate to CarrierPolicyConsumer with a fresh seen map.
type CarrierWalkPolicy uint8

const (
	CarrierPolicyClosure CarrierWalkPolicy = iota
	CarrierPolicyConsumer
	CarrierPolicyAlias
)

// WalkDynamicCarrier is the one structural carrier walk shared by the closure
// and consumer tiers (REQ-closure-analysis, REQ-closure-shared-dynamic-state).
func WalkDynamicCarrier(audited bool, t types.Type, seen map[types.Type]bool, policy CarrierWalkPolicy) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true
	aliasMode := policy == CarrierPolicyAlias
	refElem := func(elem types.Type) bool {
		if aliasMode {
			return WalkDynamicCarrier(audited, elem, make(map[types.Type]bool), CarrierPolicyConsumer)
		}
		return WalkDynamicCarrier(audited, elem, seen, policy)
	}
	switch t := types.Unalias(t).(type) {
	case *types.Basic:
		return t.Kind() == types.UnsafePointer
	case *types.Interface:
		return true
	case *types.Signature:
		return !aliasMode
	case *types.TypeParam:
		switch policy {
		case CarrierPolicyClosure:
			return !constraintBoundsAwayFromDynamic(audited, t.Constraint(), seen)
		case CarrierPolicyConsumer:
			return !TypeParamBoundsAwayFromDynamic(audited, t)
		case CarrierPolicyAlias:
			return WalkDynamicCarrier(audited, t.Constraint(), seen, policy)
		}
	case *types.Named:
		if elem, ok := AuditedAtomicPointerElem(audited, t); ok {
			return refElem(elem)
		}
		return WalkDynamicCarrier(audited, t.Underlying(), seen, policy)
	case *types.Pointer:
		return refElem(t.Elem())
	case *types.Slice:
		return refElem(t.Elem())
	case *types.Chan:
		return refElem(t.Elem())
	case *types.Map:
		return refElem(t.Key()) || refElem(t.Elem())
	case *types.Array:
		return WalkDynamicCarrier(audited, t.Elem(), seen, policy)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if WalkDynamicCarrier(audited, t.Field(i).Type(), seen, policy) {
				return true
			}
		}
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if WalkDynamicCarrier(audited, t.At(i).Type(), seen, policy) {
				return true
			}
		}
	}
	return false
}

func typeMayCarryDynamic(audited bool, t types.Type, seen map[types.Type]bool) bool {
	return WalkDynamicCarrier(audited, t, seen, CarrierPolicyClosure)
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
	return WalkDynamicCarrier(audited, t, make(map[types.Type]bool), CarrierPolicyClosure)
}

// TypeParamBoundsAwayFromDynamic reports whether one type parameter's
// constraint provably bounds its type set away from dynamic carriers -
// the openness question a parameterized subject asks per parameter,
// shared with the view tier so both tiers give one answer
// (REQ-closure-analysis's parameterized-subject arm).
func TypeParamBoundsAwayFromDynamic(audited bool, tp *types.TypeParam) bool {
	if tp == nil {
		return false
	}
	return constraintBoundsAwayFromDynamic(audited, tp.Constraint(), make(map[types.Type]bool))
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
func constraintBoundsAwayFromDynamic(audited bool, constraint types.Type, seen map[types.Type]bool) bool {
	iface, ok := types.Unalias(constraint).Underlying().(*types.Interface)
	if !ok {
		return false
	}
	return interfaceBoundsAwayFromDynamic(audited, iface, seen)
}

func interfaceBoundsAwayFromDynamic(audited bool, iface *types.Interface, seen map[types.Type]bool) bool {
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
				if typeMayCarryDynamic(audited, e.Term(j).Type(), seen) {
					clean = false
					break
				}
			}
			if clean {
				bounded = true
			}
		default:
			if under, ok := types.Unalias(e).Underlying().(*types.Interface); ok {
				if interfaceBoundsAwayFromDynamic(audited, under, seen) {
					bounded = true
				}
				continue
			}
			// A single specific-type element (interface{ int }).
			if !typeMayCarryDynamic(audited, e, seen) {
				bounded = true
			}
		}
	}
	return bounded
}

func isGeneratedTestMainPackage(prog *program, pkg *ssa.Package) bool {
	return prog != nil && pkg != nil && pkg.Pkg != nil && pkg.Pkg.Name() == "main" && pkg.Pkg.Path() == prog.PkgPath+".test"
}

func provenanceReachableStartup(ctx context.Context, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool) (map[*ssa.Function]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reachable := make(map[*ssa.Function]bool)
	scanned := make(map[*ssa.Function]bool)
	pendingByParent := make(map[*ssa.Function][]*ssa.Function)
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
		if pending := pendingByParent[fn]; len(pending) > 0 {
			delete(pendingByParent, fn)
			queue = append(queue, pending...)
		}
		harnessFrame := funcPkgPath(fn) == "testing" || harnessAudited && propertyHarnessPath(funcPkgPath(fn))
		if !harnessFrame {
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
					calleePath := funcPkgPath(callee)
					calleeHarness := calleePath == "testing" || harnessAudited && propertyHarnessPath(calleePath)
					if !harnessFrame || calleeHarness {
						queue = append(queue, callee)
					}
					if calleeHarness && !harnessFrame {
						continue
					}
				}
				for target, targetMask := range result.Targets[site] {
					if targetMask&mask == 0 || isTestingMRun(target) || isTestingBLaunch(target) {
						continue
					}
					targetPath := funcPkgPath(target)
					targetHarness := targetPath == "testing" || harnessAudited && propertyHarnessPath(targetPath)
					if !harnessFrame || targetHarness || userPaths[targetPath] || !isStdImportPath(targetPath) {
						if target.Parent() != nil && target.Synthetic == "" && !scanned[target.Parent()] && !isTestingCleanupCallback(target) {
							pendingByParent[target.Parent()] = append(pendingByParent[target.Parent()], target)
							continue
						}
						queue = append(queue, target)
					}
				}
			}
		}
	}
	return reachable, nil
}

func collectTestingCleanupCallbacks(subjectFunctions, testMainFunctions map[*ssa.Function]bool, mask uint64, res *rta.Result) ([]*ssa.Function, bool) {
	seen := make(map[*ssa.Function]bool)
	var out []*ssa.Function
	unclosed := false
	scanSet := func(fns map[*ssa.Function]bool) {
		for fn := range fns {
			if fn == nil {
				continue
			}
			for _, b := range fn.Blocks {
				for _, instr := range b.Instrs {
					site, ok := instr.(ssa.CallInstruction)
					if !ok {
						continue
					}
					arg, isCleanup := testingCleanupCallArg(site, mask, res)
					if !isCleanup {
						continue
					}
					switch x := arg.(type) {
					case *ssa.Function:
						if !seen[x] {
							seen[x] = true
							out = append(out, x)
						}
					case *ssa.MakeClosure:
						if cb, ok := x.Fn.(*ssa.Function); ok && !seen[cb] {
							seen[cb] = true
							out = append(out, cb)
						}
					default:
						targets, closed := closedDynamicTargets(arg, nil)
						if !closed || len(targets) == 0 {
							unclosed = true
							continue
						}
						for cb := range targets {
							if cb != nil && !seen[cb] {
								seen[cb] = true
								out = append(out, cb)
							}
						}
					}
				}
			}
		}
	}
	scanSet(subjectFunctions)
	scanSet(testMainFunctions)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, unclosed
}

func testingCleanupCallArg(site ssa.CallInstruction, mask uint64, res *rta.Result) (ssa.Value, bool) {
	if site == nil || site.Common() == nil {
		return nil, false
	}
	c := site.Common()
	if len(c.Args) == 0 {
		return nil, false
	}
	if callee := c.StaticCallee(); callee != nil {
		if funcPkgPath(callee) == "testing" && functionSymbolName(callee) == "Cleanup" {
			return c.Args[len(c.Args)-1], true
		}
		return nil, false
	}
	if res == nil {
		return nil, false
	}
	for target, tmask := range res.Targets[site] {
		if tmask&mask != 0 && funcPkgPath(target) == "testing" && functionSymbolName(target) == "Cleanup" {
			return c.Args[len(c.Args)-1], true
		}
	}
	return nil, false
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

// tier2Reachable analyzes one attributed reachability set: effects,
// widen, and verdict, with the cross-boundary fresh-path analysis always
// in force (only the observability walk consults effect.observable).
func provenanceReachable(ctx context.Context, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool) (map[*ssa.Function]bool, error) {
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
		// A harness frame - the standard testing package or an audited
		// property harness - is never subject content; its dispatch
		// targets still traverse, so the caller-supplied callbacks it
		// runs stay subject flow (REQ-closure-observability-analysis).
		harnessFrame := funcPkgPath(fn) == "testing" || harnessAudited && propertyHarnessPath(funcPkgPath(fn))
		if !harnessFrame {
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
					calleePath := funcPkgPath(callee)
					calleeHarness := calleePath == "testing" || harnessAudited && propertyHarnessPath(calleePath)
					if !harnessFrame || calleeHarness {
						queue = append(queue, callee)
					}
					if calleeHarness && !harnessFrame {
						continue
					}
				}
				for target, targetMask := range result.Targets[site] {
					if targetMask&mask == 0 || isTestingMRun(target) || isTestingBLaunch(target) {
						continue
					}
					if dropTarget != nil && dropTarget(site, target) {
						continue
					}
					targetPath := funcPkgPath(target)
					targetHarness := targetPath == "testing" || harnessAudited && propertyHarnessPath(targetPath)
					// User callbacks dispatched from harness frames stay
					// in the walk by the load's module facts, never by
					// path shape: a dotless user module's callback
					// classified standard here silently vanished from
					// the startup and test-main walks - the
					// dotless-module soundness family.
					if !harnessFrame || targetHarness || userPaths[targetPath] || !isStdImportPath(targetPath) {
						queue = append(queue, target)
					}
				}
			}
		}
	}
	return reachable, nil
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
