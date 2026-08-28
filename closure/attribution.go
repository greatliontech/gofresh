package closure

import (
	"context"
	"go/types"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/closure/internal/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
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
	enumeratedRootSites []ssa.CallInstruction
	subjectRoot         *ssa.Function
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
	if len(subjects) < 64 {
		allMasks = 1<<len(subjects) - 1
	}
	var testMasks uint64
	var allFunctions map[*ssa.Function]bool
	instantiated := map[uint64]map[*ssa.Function]bool{}
	for i, subject := range subjects {
		mask := uint64(1) << i
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
		var callerSites map[*ssa.Function][]ssa.CallInstruction
		var valueRefs map[*ssa.Function]bool
		callerSites, valueRefs, valueRefOutsideInit = enumerateCallerReferences(candidateSet, allFunctions)
		for root, i := range openCandidates {
			enc, ok := subjectEnumerationClosure(audited, root, callerSites[root], valueRefs[root])
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
			subjectRoot:            prog.Roots[subjects[i].Symbol],
			propertyHarnessAudited: harnessAudited,
		}
		mask := uint64(1) << i
		subjectRoot := prog.Roots[subjects[i].Symbol]
		// Startup provenance is package initializers alone: user
		// test-main flow classifies within subject-time observation -
		// the test log installs in the toolchain-generated test-main
		// package's initializer, after every dependency initializer and
		// before the user test main, so user test-main reads are
		// bracketed observation inputs while initializer reads stay
		// genuinely pre-bracket (REQ-closure-observability-analysis).
		// The flow keeps its own slice below for the dispatch widen.
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
// (REQ-closure-observability-analysis).
func auditedHarnessSubtestDriver(audited bool, fn *ssa.Function) bool {
	if !audited || fn == nil || fn.Name() != "Run" || funcPkgPath(fn) != "testing" {
		return false
	}
	if fn.Signature == nil || fn.Signature.Recv() == nil {
		return false
	}
	recv := fn.Signature.Recv().Type()
	if ptr, ok := types.Unalias(recv).(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, ok := types.Unalias(recv).(*types.Named)
	return ok && named.Obj() != nil && (named.Obj().Name() == "T" || named.Obj().Name() == "B")
}

// harnessFuzzDriver reports (*testing.F).Fuzz - never admitted (its
// target dispatches reflectively over corpus files), but its
// harness-internal body is cut from the walk so the refusal names the
// driver itself rather than the harness's own formatting internals
// (REQ-closure-observability-analysis).
func harnessFuzzDriver(fn *ssa.Function) bool {
	if fn == nil || fn.Name() != "Fuzz" || funcPkgPath(fn) != "testing" {
		return false
	}
	if fn.Signature == nil || fn.Signature.Recv() == nil {
		return false
	}
	recv := fn.Signature.Recv().Type()
	if ptr, ok := types.Unalias(recv).(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, ok := types.Unalias(recv).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Name() == "F"
}

// enumerationClosure is one signature-open subject's whole-view caller
// closure (REQ-closure-analysis): the direct static call sites that are
// its only references, plus the dispatch candidates those sites pass —
// closed function values seeded address-taken, materialized concrete
// types seeded into the runtime-type walk — so everything an enumerable
// caller can hand the subject is analyzed view content.
type enumerationClosure struct {
	sites     []ssa.CallInstruction
	addrTaken map[*ssa.Function]bool
	types     []types.Type
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
func enumerateCallerReferences(candidates map[*ssa.Function]bool, all map[*ssa.Function]bool) (map[*ssa.Function][]ssa.CallInstruction, map[*ssa.Function]bool, map[*ssa.Function]bool) {
	ordered := make([]*ssa.Function, 0, len(all))
	for fn := range all {
		if fn != nil {
			ordered = append(ordered, fn)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].String() < ordered[j].String() })
	sites := make(map[*ssa.Function][]ssa.CallInstruction)
	valueRef := make(map[*ssa.Function]bool)
	valueRefOutsideInit := make(map[*ssa.Function]bool)
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
				rands := instr.Operands(space[:0])
				if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
					if callee := site.Common().StaticCallee(); callee != nil && candidates[callee] {
						if judgeable {
							sites[callee] = append(sites[callee], site)
						} else {
							valueRef[callee] = true
						}
					}
					if !site.Common().IsInvoke() {
						// The callee operand is the call itself, not a
						// value reference.
						rands = rands[1:]
					}
				}
				for _, op := range rands {
					if g, ok := (*op).(*ssa.Function); ok {
						if candidates[g] {
							valueRef[g] = true
						}
						if !initFrame {
							valueRefOutsideInit[g] = true
						}
					}
				}
			}
		}
	}
	return sites, valueRef, valueRefOutsideInit
}

// subjectEnumerationClosure judges one open-signature root against its
// collected references: closed exactly when references are direct static
// calls only, at least one exists, and every dynamic-reaching argument
// position closes in the calling function's own frame (the caller-local
// walk — the caller's parameters, loads, and call results refuse).
func subjectEnumerationClosure(audited bool, root *ssa.Function, sites []ssa.CallInstruction, valueRef bool) (enumerationClosure, bool) {
	// Functions only: a method's interface invocability leaves no
	// reference the scan can see (a pointer-receiver invoke synthesizes
	// no wrapper and takes no address), so a receiver-bearing subject
	// keeps its signature-shaped open world.
	if root.Signature != nil && root.Signature.Recv() != nil {
		return enumerationClosure{}, false
	}
	if valueRef || len(sites) == 0 {
		return enumerationClosure{}, false
	}
	enc := enumerationClosure{sites: sites, addrTaken: map[*ssa.Function]bool{}}
	for _, site := range sites {
		args := site.Common().Args
		if len(args) != len(root.Params) {
			return enumerationClosure{}, false
		}
		for i, param := range root.Params {
			if !typeMayCarryDynamic(audited, param.Type(), make(map[types.Type]bool)) {
				continue
			}
			if !locallyClosedDynamicValue(args[i], make(map[ssa.Value]bool)) {
				return enumerationClosure{}, false
			}
			collectClosedDynamicSeeds(args[i], &enc, map[ssa.Value]bool{})
		}
	}
	return enc, true
}

// collectClosedDynamicSeeds walks an already-closed argument value and
// gathers what it can hand the subject: function values become dispatch
// candidates, materialized concrete types enter the runtime-type walk.
// The case set mirrors the closed-value walk that admitted the value;
// bindings of ordinary closures are not collected — a free-variable
// dispatch inside the body refuses per-site when the body is scanned.
func collectClosedDynamicSeeds(value ssa.Value, enc *enumerationClosure, seen map[ssa.Value]bool) {
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
			collectClosedDynamicSeeds(v.X, enc, seen)
		}
	case *ssa.ChangeInterface:
		collectClosedDynamicSeeds(v.X, enc, seen)
	case *ssa.TypeAssert:
		collectClosedDynamicSeeds(v.X, enc, seen)
	case *ssa.ChangeType:
		collectClosedDynamicSeeds(v.X, enc, seen)
	case *ssa.Convert:
		collectClosedDynamicSeeds(v.X, enc, seen)
	case *ssa.Extract:
		collectClosedDynamicSeeds(v.Tuple, enc, seen)
	case *ssa.Phi:
		for _, edge := range v.Edges {
			collectClosedDynamicSeeds(edge, enc, seen)
		}
	}
}

func rootMayReceiveUnknownDynamic(audited bool, prog *program, root *ssa.Function) bool {
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
	if parameterizedBody(root) && !typeParamListsBoundAwayFromDynamic(audited, root) {
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
	if recv := root.Signature.Recv(); recv != nil && typeMayCarryDynamic(audited, recv.Type(), make(map[types.Type]bool)) {
		return true
	}
	params := root.Signature.Params()
	for i := 0; params != nil && i < params.Len(); i++ {
		if typeMayCarryDynamic(audited, params.At(i).Type(), make(map[types.Type]bool)) {
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

func typeMayCarryDynamic(audited bool, t types.Type, seen map[types.Type]bool) bool {
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
		return !constraintBoundsAwayFromDynamic(audited, t.Constraint(), seen)
	case *types.Named:
		if elem, ok := AuditedAtomicPointerElem(audited, t); ok {
			return typeMayCarryDynamic(audited, elem, seen)
		}
		return typeMayCarryDynamic(audited, t.Underlying(), seen)
	case *types.Pointer:
		return typeMayCarryDynamic(audited, t.Elem(), seen)
	case *types.Slice:
		return typeMayCarryDynamic(audited, t.Elem(), seen)
	case *types.Array:
		return typeMayCarryDynamic(audited, t.Elem(), seen)
	case *types.Map:
		return typeMayCarryDynamic(audited, t.Key(), seen) || typeMayCarryDynamic(audited, t.Elem(), seen)
	case *types.Chan:
		return typeMayCarryDynamic(audited, t.Elem(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if typeMayCarryDynamic(audited, t.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if typeMayCarryDynamic(audited, t.At(i).Type(), seen) {
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
func TypeParamBoundsAwayFromDynamic(audited bool, tp *types.TypeParam) bool {
	if tp == nil {
		return false
	}
	return constraintBoundsAwayFromDynamic(audited, tp.Constraint(), make(map[types.Type]bool))
}

// typeParamListsBoundAwayFromDynamic reports whether every type parameter
// of fn (function and receiver lists both) carries a constraint that
// provably bounds its type set away from dynamic carriers.
func typeParamListsBoundAwayFromDynamic(audited bool, fn *ssa.Function) bool {
	for _, list := range []*types.TypeParamList{fn.TypeParams(), fn.Signature.RecvTypeParams()} {
		for i := 0; list != nil && i < list.Len(); i++ {
			if !constraintBoundsAwayFromDynamic(audited, list.At(i).Constraint(), make(map[types.Type]bool)) {
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
					if targetMask&mask == 0 || isTestingMRun(target) {
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
