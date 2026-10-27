package closure

import (
	"context"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"
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
	testMainFunctions map[*ssa.Function]bool
	resolved          map[ssa.CallInstruction]bool
	dynamicTargets    map[ssa.CallInstruction]map[*ssa.Function]bool
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
	subjectRoot            *ssa.Function
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
	if len(openCandidates) > 0 {
		if allFunctions == nil {
			allFunctions = ssautil.AllFunctions(prog.Prog)
		}
		candidateSet := make(map[*ssa.Function]bool, len(openCandidates))
		for root := range openCandidates {
			candidateSet[root] = true
		}
		summary := enumerateCallerReferences(audited, candidateSet, allFunctions)
		valueRefOutsideInit = summary.valueRefOutsideInit
		for root, i := range openCandidates {
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
	for i := range reachable {
		enc, enumerated := enumClosed[i]
		reachable[i] = attributedReachability{
			functions:              make(map[*ssa.Function]bool, len(res.Reachable)),
			resolved:               make(map[ssa.CallInstruction]bool, len(res.Resolved)),
			dynamicTargets:         make(map[ssa.CallInstruction]map[*ssa.Function]bool),
			instantiatedOrigins:    instantiated[uint64(1)<<i],
			openWorld:              !enumerated && rootMayReceiveUnknownDynamic(audited, prog, prog.Roots[subjects[i].Symbol]),
			enumeratedRootSites:    enc.sites,
			enumeratedFieldStores:  enc.fieldStores,
			subjectRoot:            prog.Roots[subjects[i].Symbol],
			propertyHarnessAudited: harnessAudited,
		}
		mask := uint64(1) << i
		subjectRoot := prog.Roots[subjects[i].Symbol]
		startupRoots := initRoots
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
		reachable[i].startupFunctions, err = provenanceReachable(ctx, startupRoots, mask, res, harnessAudited, userPaths, nil)
		if err != nil {
			return nil, err
		}
		if prog.TestMain != nil && subjectRunsThroughHarness(prog, subjectRoot) {
			reachable[i].testMainFunctions, err = provenanceReachable(ctx, []*ssa.Function{prog.TestMain}, mask, res, harnessAudited, userPaths, nil)
			if err != nil {
				return nil, err
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

type callerReferenceSummary struct {
	sites               map[*ssa.Function][]ssa.CallInstruction
	valueRef            map[*ssa.Function]bool
	valueRefOutsideInit map[*ssa.Function]bool
	structReferenced    map[*ssa.Function]bool
	fieldStores         map[*ssa.Function]map[int][]ssa.Value
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
func enumerateCallerReferences(audited bool, candidates map[*ssa.Function]bool, all map[*ssa.Function]bool) callerReferenceSummary {
	ordered := make([]*ssa.Function, 0, len(all))
	for fn := range all {
		if fn != nil {
			ordered = append(ordered, fn)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].String() < ordered[j].String() })
	summary := callerReferenceSummary{
		sites:               make(map[*ssa.Function][]ssa.CallInstruction),
		valueRef:            make(map[*ssa.Function]bool),
		valueRefOutsideInit: make(map[*ssa.Function]bool),
		structReferenced:    make(map[*ssa.Function]bool),
		fieldStores:         make(map[*ssa.Function]map[int][]ssa.Value),
	}
	structCandidates := make(map[*types.Named][]*ssa.Function)
	neededFieldsByRoot := make(map[*ssa.Function]map[int]bool)
	if audited {
		var candList []*ssa.Function
		for root := range candidates {
			if root != nil && root.Signature != nil && root.Signature.Recv() != nil {
				candList = append(candList, root)
			}
		}
		sort.Slice(candList, func(i, j int) bool { return candList[i].String() < candList[j].String() })
		for _, root := range candList {
			if named := derefNamedStruct(root.Signature.Recv().Type()); named != nil {
				structCandidates[named] = append(structCandidates[named], root)
				if _, needed, ok := recvStructFieldTargets(audited, root); ok {
					neededFieldsByRoot[root] = needed
				}
			}
		}
	}
	var space [16]*ssa.Value
	for _, fn := range ordered {
		// A body the enumeration cannot judge as a caller — a synthetic
		// function (wrapper re-dispatch, package initializer) or a
		// parameterized origin (open over type parameters) — makes any
		// call it holds a refusing reference, exactly like a value
		// capture: its arguments are never judged, so they must never
		// count as an enumerated site.
		judgeable := fn.Synthetic == "" && !parameterizedBody(fn)
		initFrame := initFlowFrame(fn)
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if len(structCandidates) > 0 {
					if v, ok := instr.(ssa.Value); ok && v.Type() != nil {
						if named := derefNamedStruct(v.Type()); named != nil {
							poison := !judgeable
							switch instr := instr.(type) {
							case *ssa.Convert, *ssa.ChangeType, *ssa.TypeAssert, *ssa.Lookup, *ssa.Extract, *ssa.FieldAddr, *ssa.IndexAddr:
								poison = true
							case *ssa.UnOp:
								if instr.Op == token.ARROW {
									poison = true
								}
							}
							for _, root := range structCandidates[named] {
								if fn != root {
									summary.structReferenced[root] = true
								}
								if poison && len(neededFieldsByRoot[root]) > 0 {
									summary.valueRef[root] = true
								}
							}
						}
					}
					switch x := instr.(type) {
					case *ssa.Convert:
						if x.X != nil {
							if named := derefNamedStruct(x.X.Type()); named != nil {
								for _, root := range structCandidates[named] {
									if len(neededFieldsByRoot[root]) > 0 {
										summary.valueRef[root] = true
									}
								}
							}
						}
					case *ssa.ChangeType:
						if x.X != nil {
							if named := derefNamedStruct(x.X.Type()); named != nil {
								for _, root := range structCandidates[named] {
									if len(neededFieldsByRoot[root]) > 0 {
										summary.valueRef[root] = true
									}
								}
							}
						}
					case *ssa.MakeInterface:
						if x.X != nil && x.X.Type() != nil && x.Type() != nil {
							if _, isPtr := types.Unalias(x.X.Type()).(*types.Pointer); isPtr {
								if iface, ok := x.Type().Underlying().(*types.Interface); ok && iface.NumMethods() == 0 {
									if named := derefNamedStruct(x.X.Type()); named != nil {
										for _, root := range structCandidates[named] {
											if len(neededFieldsByRoot[root]) > 0 {
												summary.valueRef[root] = true
											}
										}
									}
								}
							}
						}
					}
					if fa, ok := instr.(*ssa.FieldAddr); ok && fa.X != nil {
						if named := derefNamedStruct(fa.X.Type()); named != nil {
							for _, root := range structCandidates[named] {
								if fn != root {
									summary.structReferenced[root] = true
								}
								if needed := neededFieldsByRoot[root]; needed[fa.Field] {
									if !judgeable || fa.Referrers() == nil {
										summary.valueRef[root] = true
									} else {
										for _, ref := range *fa.Referrers() {
											switch r := ref.(type) {
											case *ssa.DebugRef:
											case *ssa.UnOp:
												if r.Op != token.MUL || r.X != fa {
													summary.valueRef[root] = true
												}
											case *ssa.Store:
												if r.Addr != fa {
													summary.valueRef[root] = true
												} else {
													if summary.fieldStores[root] == nil {
														summary.fieldStores[root] = make(map[int][]ssa.Value)
													}
													summary.fieldStores[root][fa.Field] = append(summary.fieldStores[root][fa.Field], r.Val)
												}
											default:
												summary.valueRef[root] = true
											}
										}
									}
								}
							}
						}
					}
					if st, ok := instr.(*ssa.Store); ok && st.Val != nil && st.Val.Type() != nil {
						if named, ok := types.Unalias(st.Val.Type()).(*types.Named); ok && len(structCandidates[named]) > 0 {
							c, isZero := st.Val.(*ssa.Const)
							if !isZero || c.Value != nil {
								for _, root := range structCandidates[named] {
									if len(neededFieldsByRoot[root]) > 0 {
										summary.valueRef[root] = true
									}
								}
							}
						}
					}
				}
				rands := instr.Operands(space[:0])
				if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
					if callee := site.Common().StaticCallee(); callee != nil && candidates[callee] {
						if judgeable {
							summary.sites[callee] = append(summary.sites[callee], site)
						} else {
							summary.valueRef[callee] = true
						}
					}
					if !site.Common().IsInvoke() {
						// The callee operand is the call itself, not a
						// value reference.
						rands = rands[1:]
					}
				}
				for _, op := range rands {
					if len(structCandidates) > 0 && op != nil && *op != nil && (*op).Type() != nil {
						if named := derefNamedStruct((*op).Type()); named != nil {
							for _, root := range structCandidates[named] {
								if fn != root {
									summary.structReferenced[root] = true
								}
							}
						}
					}
					if g, ok := (*op).(*ssa.Function); ok {
						if candidates[g] {
							summary.valueRef[g] = true
						}
						if !initFrame {
							summary.valueRefOutsideInit[g] = true
						}
					}
				}
			}
		}
	}
	return summary
}

// subjectEnumerationClosure judges one open-signature root against its
// collected references: closed when references are direct static calls
// (or closed struct-receiver uses) with at least one reference in the
// program, and every dynamic-reaching argument or receiver field position
// closes in the caller's or constructor's own frame.
func subjectEnumerationClosure(audited bool, root *ssa.Function, summary callerReferenceSummary) (enumerationClosure, bool) {
	sites := summary.sites[root]
	valueRef := summary.valueRef[root]
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
		for _, param := range root.Params[1:] {
			if typeMayCarryDynamic(audited, param.Type(), make(map[types.Type]bool)) && paramMaySupplyDynamic(audited, param) {
				return enumerationClosure{}, false
			}
		}
		named := derefNamedStruct(root.Signature.Recv().Type())
		if named == nil || (len(sites) == 0 && !summary.structReferenced[root]) {
			return enumerationClosure{}, false
		}
		if !paramMaySupplyDynamic(audited, root.Params[0]) {
			return enumerationClosure{sites: sites, addrTaken: map[*ssa.Function]bool{}}, true
		}
		_, neededFields, ok := recvStructFieldTargets(audited, root)
		if !ok {
			return enumerationClosure{}, false
		}
		enc := enumerationClosure{
			sites:       sites,
			addrTaken:   map[*ssa.Function]bool{},
			fieldStores: map[int][]ssa.Value{},
		}
		fp := &freshParamAnalysis{
			selectionAudited: audited,
			enumRoot:         root,
			enumFieldStores:  summary.fieldStores[root],
			isStd:            func(fn *ssa.Function) bool { return isStdImportPath(funcPkgPath(fn)) },
		}
		var fieldIdxs []int
		for idx := range neededFields {
			fieldIdxs = append(fieldIdxs, idx)
		}
		sort.Ints(fieldIdxs)
		for _, idx := range fieldIdxs {
			stores := summary.fieldStores[root][idx]
			if len(stores) == 0 {
				return enumerationClosure{}, false
			}
			for _, val := range stores {
				if !walkDynamicValue(val, nil, make(map[ssa.Value]bool), map[ssa.Value]bool{}, fp) {
					return enumerationClosure{}, false
				}
				collectClosedDynamicSeeds(val, &enc, map[ssa.Value]bool{}, fp)
			}
			enc.fieldStores[idx] = stores
		}
		return enc, true
	}
	if valueRef || len(sites) == 0 {
		return enumerationClosure{}, false
	}
	enc := enumerationClosure{sites: sites, addrTaken: map[*ssa.Function]bool{}}
	fp := &freshParamAnalysis{
		selectionAudited: audited,
		isStd:            func(fn *ssa.Function) bool { return isStdImportPath(funcPkgPath(fn)) },
	}
	for _, site := range sites {
		args := site.Common().Args
		if len(args) != len(root.Params) {
			return enumerationClosure{}, false
		}
		for i, param := range root.Params {
			if !typeMayCarryDynamic(audited, param.Type(), make(map[types.Type]bool)) {
				continue
			}
			if audited && len(root.Blocks) > 0 && root.Synthetic == "" && !parameterizedBody(root) && !paramMaySupplyDynamic(audited, param) {
				continue
			}
			if !walkDynamicValue(args[i], nil, make(map[ssa.Value]bool), map[ssa.Value]bool{}, fp) {
				return enumerationClosure{}, false
			}
			collectClosedDynamicSeeds(args[i], &enc, map[ssa.Value]bool{}, fp)
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
	if param == nil {
		return false
	}
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
			if r.X != param || !carrierFreeReadOnlyAddr(audited, r) {
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
		default:
			return true
		}
	}
	return false
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
			if r.X != addr || !carrierFreeReadOnlyAddr(audited, r) {
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
		default:
			return false
		}
	}
	return true
}

func recvStructFieldTargets(audited bool, root *ssa.Function) (*types.Named, map[int]bool, bool) {
	if !audited || root == nil || root.Signature == nil || root.Signature.Recv() == nil || len(root.Blocks) == 0 || root.Synthetic != "" || parameterizedBody(root) || len(root.Params) == 0 {
		return nil, nil, false
	}
	named := derefNamedStruct(root.Signature.Recv().Type())
	if named == nil {
		return nil, nil, false
	}
	recv := root.Params[0]
	refs := recv.Referrers()
	if refs == nil {
		return nil, nil, false
	}
	needed := make(map[int]bool)
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return nil, nil, false
			}
		case *ssa.FieldAddr:
			if r.X != recv {
				return nil, nil, false
			}
			if carrierFreeReadOnlyAddr(audited, r) {
				continue
			}
			if r.Referrers() == nil {
				return nil, nil, false
			}
			for _, fref := range *r.Referrers() {
				switch fr := fref.(type) {
				case *ssa.DebugRef:
				case *ssa.UnOp:
					if fr.Op != token.MUL || fr.X != r {
						return nil, nil, false
					}
				default:
					return nil, nil, false
				}
			}
			needed[r.Field] = true
		default:
			return nil, nil, false
		}
	}
	if len(needed) == 0 {
		return nil, nil, false
	}
	return named, needed, true
}

// collectClosedDynamicSeeds walks an already-closed argument value and
// gathers what it can hand the subject: function values become dispatch
// candidates, materialized concrete types enter the runtime-type walk.
// The case set mirrors the closed-value walk that admitted the value;
// bindings of ordinary closures are not collected — a free-variable
// dispatch inside the body refuses per-site when the body is scanned.
func collectClosedDynamicSeeds(value ssa.Value, enc *enumerationClosure, seen map[ssa.Value]bool, fp *freshParamAnalysis) {
	if value == nil || seen[value] {
		return
	}
	seen[value] = true
	switch v := value.(type) {
	case *ssa.Function:
		enc.addrTaken[v] = true
	case *ssa.MakeClosure:
		if fn, ok := v.Fn.(*ssa.Function); ok {
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
	case *ssa.Call:
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
		if args, ok := attributedParameterArgs(v, fp); ok {
			for _, arg := range args {
				collectClosedDynamicSeeds(arg, enc, seen, fp)
			}
		}
	case *ssa.UnOp:
		if v.Op == token.MUL {
			if g, ok := v.X.(*ssa.Global); ok && fp != nil && fp.selectionAudited && isUnmutatedStandardSentinelGlobalAny(g) {
				cts := map[types.Type]bool{}
				sentinelGlobalConcreteTypes(g, cts)
				for ct := range cts {
					enc.types = append(enc.types, ct)
				}
			} else if fa, ok := v.X.(*ssa.FieldAddr); ok && fp != nil && fp.enumRoot != nil && len(fp.enumRoot.Params) > 0 && fa.X == fp.enumRoot.Params[0] {
				for _, sv := range fp.enumFieldStores[fa.Field] {
					collectClosedDynamicSeeds(sv, enc, seen, fp)
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
	if fp == nil || !fp.selectionAudited || call == nil || call.Common() == nil || call.Common().IsInvoke() {
		return
	}
	callee := call.Common().StaticCallee()
	if callee == nil || (callee.Synthetic != "" && callee.Origin() == nil) || len(callee.Blocks) == 0 || len(callee.FreeVars) != 0 {
		return
	}
	pkgPath := funcPkgPath(callee)
	if fp.isStdFunc(callee) {
		if !isAuditedStandardOrDelegatePackage(fp.selectionAudited, pkgPath) && !auditedStandardCallee(fp.selectionAudited, pkgPath, functionSymbolName(callee), callee) {
			return
		}
	} else if !fp.functions[callee] || callee == fp.enumRoot || fp.dynamic[callee] || callee.Signature.Variadic() || propertyHarnessPath(pkgPath) || callee.Recover != nil {
		return
	}
	for _, arg := range call.Common().Args {
		if arg == nil {
			return
		}
		if typeMayCarryDynamic(fp.selectionAudited, arg.Type(), map[types.Type]bool{}) && !walkDynamicValue(arg, nil, map[ssa.Value]bool{}, map[ssa.Value]bool{}, fp) {
			return
		}
		collectClosedDynamicSeeds(arg, enc, seen, fp)
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
			collectClosedDynamicSeeds(res, enc, seen, fp)
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
