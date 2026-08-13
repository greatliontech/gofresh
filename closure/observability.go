package closure

import (
	"fmt"
	"go/token"
	"go/types"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	prog "github.com/greatliontech/gofresh/closure/internal/program"
)

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
	p, err := prog.Load(h.ctx, h.dir, h.packageEnv, h.buildFlags, pkgPath)
	if err != nil {
		if h.ctx.Err() == nil {
			h.progErrs[pkgPath] = err
		}
		return nil, err
	}
	h.progs[pkgPath] = p
	return p, nil
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
	return strings.HasSuffix(prog.Prog.Fset.Position(fn.Pos()).Filename, "_test.go")
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
	// One call observes one tree generation; a later call re-observes.
	h.resetCallScope()
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
		memoArmed := h.memoScope != "" && closureHash != ""
		unrooted := map[string]Observability{}
		rooted := group.subjects[:0:0]
		for _, subject := range group.subjects {
			if prog.Roots[subject.Symbol] == nil {
				reason := fmt.Sprintf("observation analysis unavailable: subject %s not found in %s", subject.Symbol, group.path)
				if prog.Ambiguous[subject.Symbol] {
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
			if memoArmed {
				storeMemo(h.memoScope, closureHash, unrooted)
			}
			delete(h.progs, group.path)
			continue
		}
		metas, err := h.list(group.path)
		if err != nil {
			return nil, err
		}
		base := newTier2Base(h, prog, metas)
		// Proofs persist as each attribution slice completes: an analysis
		// deadline expiring mid-group forfeits only the interrupted
		// slice, and the next pass serves every completed slice's proofs
		// from the memo (REQ-closure-observability-memo).
		if memoArmed && len(unrooted) > 0 {
			storeMemo(h.memoScope, closureHash, unrooted)
		}
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
			sliceProofs := make(map[string]Observability, len(batch))
			for i, subject := range batch {
				if err := h.ctx.Err(); err != nil {
					return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
				}
				result, err := h.observabilityFromReachability(base, subject.Package, reachable[i])
				if err != nil {
					return nil, err
				}
				results[subject] = result
				sliceProofs[subject.Symbol] = result
			}
			if memoArmed {
				storeMemo(h.memoScope, closureHash, sliceProofs)
			}
		}
		// Programs are per-package test binaries: no later group can reuse
		// this one, so retaining it would grow peak memory with the batch's
		// package count instead of its largest single binary (measured
		// 10.4 GB against 614 MB on a 33-package set). Load failures stay
		// memoized so the isolation retry never repeats a failing load; a
		// completed group's subjects retry through the full-group memo hit,
		// so only a failed memo write makes a retry reload.
		delete(h.progs, group.path)
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
	subjectResult, err := h.tier2Reachable(base, subjectReach)
	if err != nil {
		return Observability{}, err
	}
	startupReach := reach
	startupReach.functions = nonStandardFunctions(base, startupReach.startupFunctions)
	startupResult := directExternalEffects(base, startupReach)
	if startupResult.unverifiable {
		reason := startupResult.reason
		if reason == "" {
			reason = "external dependence"
		}
		return Observability{Reason: "startup effect: " + reason}, nil
	}
	if startupResult.widen {
		reason := startupResult.widenReason
		if reason == "" {
			reason = "startup dispatch is not closed"
		}
		return Observability{Reason: "startup effect: " + reason}, nil
	}
	// User test-main flow classifies within subject-time observation:
	// the test log installs in the toolchain-generated test-main
	// package's initializer - after every dependency initializer,
	// before the user test main - so a test-main read is a bracketed
	// observation input, honored through the effect classification's
	// own observable flags, while package initializers stay genuinely
	// pre-bracket in the startup walk above. The flow keeps its own
	// dispatch discipline: it is the one flow here that can dispatch a
	// test-planted value after the harness run
	// (REQ-closure-observability-analysis).
	if len(reach.testMainFunctions) > 0 {
		testMainReach := reach
		testMainReach.functions = nonStandardFunctions(base, reach.testMainFunctions)
		testMainResult := testMainObservedEffects(base, testMainReach)
		if testMainResult.widen {
			reason := testMainResult.widenReason
			if reason == "" {
				reason = "test-main dispatch is not closed"
			}
			return Observability{Reason: reason}, nil
		}
		// The refusal names the highest-ranked blocking effect under the
		// shared cause-preference order, exactly as the subject arm does
		// (REQ-closure-observability-analysis's diagnostic clause).
		var blocking *externalEffect
		blockingRank := 0
		for i := range testMainResult.effects {
			effect := &testMainResult.effects[i]
			if effect.observable {
				continue
			}
			if rank := effectCauseRank(*effect); blocking == nil || rank > blockingRank {
				blocking = effect
				blockingRank = rank
			}
		}
		if blocking != nil {
			return Observability{Reason: blocking.reason}, nil
		}
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
	// The registration-sink judgment is the flag admission's soundness
	// belt: registration is admitted by symbol name in the walks and the
	// package scan, so a registration whose registered storage the facts
	// walk cannot trace must block every subject sharing the program -
	// the program is this package's own test binary, so the poisoned
	// package is always in the subject's world
	// (REQ-closure-observability-analysis).
	if _, poisonedPkgs := base.flagRegistrationFacts(); len(poisonedPkgs) != 0 {
		paths := slices.Sorted(maps.Keys(poisonedPkgs))
		return Observability{Reason: poisonedPkgs[paths[0]]}, nil
	}
	// The refusal names the highest-ranked blocking effect under the
	// shared cause-preference order; the projection is already sorted
	// under the total order, so the first max-rank hit is deterministic —
	// among rank-equals the projection order decides, kind first
	// (REQ-closure-observability-analysis's diagnostic clause).
	var blocking *externalEffect
	blockingRank := 0
	for i := range subjectResult.effects {
		effect := &subjectResult.effects[i]
		if effect.observable {
			continue
		}
		if rank := effectCauseRank(*effect); blocking == nil || rank > blockingRank {
			blocking = effect
			blockingRank = rank
		}
	}
	if blocking != nil {
		return Observability{Reason: blocking.reason}, nil
	}
	return Observability{Observable: true}, nil
}

// testMainObservedEffects classifies user test-main flow within
// subject-time observation: effects record through the same direct
// classification the startup walk uses, but the caller honors each
// effect's observable flag instead of blocking uniformly - the test
// log is already installed when this flow runs. Any dispatch whose
// provenance is not locally closed widens: the planted channel is
// always a load from shared mutable state, so an interface invoke or
// computed call alike widens unless its operand is locally closed; a
// static callee is an *ssa.Function, closed by construction, so a
// test-main's own calls and constructions keep their classification
// (REQ-closure-observability-analysis).
func testMainObservedEffects(base *tier2Base, reachable attributedReachability) tier2Result {
	analyzer := base.analyzer()
	analyzer.fresh = newFreshParamAnalysis(reachable)
	for function := range reachable.functions {
		idx := analyzer.idxForFunction(function)
		if idx == nil || idx.std || idx.testMain {
			continue
		}
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				// Test-main flow references registered storage after the
				// implicit flag.Parse inside m.Run can have written it, so
				// a flag-backed reference here is the covert channel's
				// read side exactly as in subject flow - it can steer the
				// harness verdict (an exit-code mask, at minimum) on
				// command-line state the test log cannot audit
				// (REQ-closure-observability-analysis).
				recordFlagBackedReferences(analyzer.flagBacked, analyzer.recordExternalEffect, instruction)
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				if !dispatchProvenanceClosed(site, nil) {
					analyzer.requestWiden("test-main dispatch on unattributable state in " + function.String())
				}
				if callee := site.Common().StaticCallee(); callee != nil {
					recordTestMainCallEffect(analyzer, callee, site)
				}
				for target := range reachable.dynamicTargets[site] {
					recordTestMainCallEffect(analyzer, target, site)
				}
			}
		}
	}
	return analyzer.result()
}

// recordTestMainCallEffect classifies one test-main call exactly as the
// startup walk's direct classification does, then applies the subject
// tier's per-site observation admission: test-main flow runs with the
// test log installed, so an admitted read is a bracketed observation
// input rather than a blocking effect
// (REQ-closure-observability-analysis).
func recordTestMainCallEffect(analyzer *tier2Analyzer, callee *ssa.Function, site ssa.CallInstruction) {
	if analyzer == nil || callee == nil || observableFileMethod(callee) || observableDirEntryCall(site) || isTestingMRun(callee) {
		return
	}
	pkgPath, name := funcPkgPath(callee), functionSymbolName(callee)
	// Static sites only: the facts walk can sink-judge only a statically
	// dispatched registration, so a dynamically dispatched family-named
	// target keeps its classification - fail-closed
	// (REQ-closure-observability-analysis).
	if flagRegistrationSymbol(pkgPath, name) && site.Common().StaticCallee() == callee {
		return
	}
	// The property-harness boundary gate holds in test-main flow
	// exactly as in subject flow: the harness's bodies are unscanned,
	// so a callable crossing here is judged at the boundary or not at
	// all (REQ-closure-observability-analysis).
	if analyzer.propertyHarnessAudited(pkgPath) {
		if site.Common().StaticCallee() != callee {
			analyzer.requestWiden("property harness reached as a dynamic target in test-main flow")
		} else if !propertyHarnessClosedArgs(site.Common(), analyzer.fresh) {
			analyzer.requestWiden("property-harness argument is not locally closed in test-main flow")
		}
		return
	}
	// os.Exit is the canonical test-main epilogue - the harness protocol
	// itself (os.Exit(m.Run())). It runs after every test completed and
	// the log flushed, post-bracket, and adds no input channel to any
	// subject's execution; an exit before m.Run means no measurement
	// ever runs - an execution condition, not an observability leak.
	if pkgPath == "os" && name == "Exit" {
		return
	}
	// The shared ladder, the test-main tier's sixth former copy folded:
	// its os.Exit epilogue admission stays above, and the observable
	// flag is this tier's own consequence.
	effect, classified := analyzer.classifyCalleeEffect(callee, pkgPath, name, site.Common(), false)
	if classified {
		effect.observable = observableCallEffect(effect, site.Common(), site, analyzer.fresh)
		analyzer.recordExternalEffect(effect)
	}
}

func directExternalEffects(base *tier2Base, reachable attributedReachability) tier2Result {
	analyzer := base.analyzer()
	// Startup flow deliberately runs without the cross-boundary
	// fresh-path analysis; the bit-only view carries just the
	// property-harness audit verdict so the boundary gate's
	// call-result admission holds here as the spec's every-flow
	// judgment requires - an initializer composing generators
	// (rapid.Deriv(rapid.Int())) is the same sanctioned crossing as in
	// subject flow. Parameter crossing stays refused exactly as with a
	// nil analysis (REQ-closure-observability-analysis).
	if reachable.propertyHarnessAudited {
		analyzer.fresh = &freshParamAnalysis{propertyHarnessAudited: true}
	}
	for function := range reachable.functions {
		idx := analyzer.idxForFunction(function)
		if idx == nil || idx.std || idx.testMain {
			continue
		}
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				// Startup flow references registered storage too: outside
				// the sanctioned write shapes, a startup reference is at
				// best a read of the unparsed default and at worst an
				// escape of the storage's address into subject-reachable
				// state (q = &registered), an alias the mark cannot
				// follow - both refuse, keeping the admission's guard
				// airtight in every analyzed flow
				// (REQ-closure-observability-analysis).
				recordFlagBackedReferences(analyzer.flagBacked, analyzer.recordExternalEffect, instruction)
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				callee := site.Common().StaticCallee()
				if callee != nil {
					recordDirectCallEffect(analyzer, callee, site)
				}
				for target := range reachable.dynamicTargets[site] {
					recordDirectCallEffect(analyzer, target, site)
				}
			}
		}
	}
	return analyzer.result()
}

// dispatchProvenanceClosed is the one wrapper-aware dispatch-provenance
// judgment: a static call to a synthetic interface-method wrapper is
// judged by its extracted receiver (a thunk's first argument, a bound
// wrapper's operand - the wrapper family's toolchain-attributed bodies
// perform the real dispatch and no walk scans them), every other shape
// by the dispatch operand itself, under the closed-value walk in
// force - fp-aware for subject flow, the local projection (nil) for
// test-main flow, where a user-written closure needs no such check
// because its body stays user-attributed and the walk records its
// effects (the one-site-classifier collapse).
func dispatchProvenanceClosed(site ssa.CallInstruction, fp *freshParamAnalysis) bool {
	c := site.Common()
	if callee := c.StaticCallee(); callee != nil && syntheticInterfaceMethodWrapper(callee) {
		receiver := wrapperReceiver(c, callee)
		return receiver != nil && subjectClosedDynamicValue(receiver, make(map[ssa.Value]bool), fp)
	}
	return subjectClosedDynamicValue(c.Value, make(map[ssa.Value]bool), fp)
}

func recordDirectCallEffect(analyzer *tier2Analyzer, callee *ssa.Function, site ssa.CallInstruction) {
	if analyzer == nil || callee == nil || observableFileMethod(callee) || observableDirEntryCall(site) || isTestingMRun(callee) {
		return
	}
	pkgPath, name := funcPkgPath(callee), functionSymbolName(callee)
	// Static sites only, exactly as the test-main walk: the facts walk
	// cannot sink-judge a dynamically dispatched registration target
	// (REQ-closure-observability-analysis).
	if flagRegistrationSymbol(pkgPath, name) && site.Common().StaticCallee() == callee {
		return
	}
	// The property-harness boundary gate holds in startup flow too: an
	// initializer can create harness values (a package-level MakeCheck
	// callback) whose bindings must be judged where they cross - the
	// anonymous-target admission downstream rests on every flow
	// carrying this gate (REQ-closure-observability-analysis).
	if analyzer.propertyHarnessAudited(pkgPath) {
		if site.Common().StaticCallee() != callee {
			analyzer.requestWiden("property harness reached as a dynamic target in startup flow")
		} else if !propertyHarnessClosedArgs(site.Common(), analyzer.fresh) {
			analyzer.requestWiden("property-harness argument is not locally closed in startup flow")
		}
		return
	}
	// The shared ladder with callerStd=false: the startup walk's callers
	// are user initializers by the non-standard filter. Startup flow
	// carries no subject-attributed parameter analysis, so the ladder's
	// writer-sink leg closes only locally constructed writers - an init
	// formatting into its own buffer is pure value computation.
	effect, classified := analyzer.classifyCalleeEffect(callee, pkgPath, name, site.Common(), false)
	if classified {
		analyzer.recordExternalEffect(effect)
	}
}

// nonStandardFunctions filters the walk to non-standard bodies by the
// listed package metadata: a user module legally named without a dot
// must never classify standard - the path-shape heuristic did, and
// silently disabled every startup refusal for such modules. The
// heuristic remains only for functions no package index covers
// (synthetic and runtime bodies the metadata never lists).
func nonStandardFunctions(base *tier2Base, functions map[*ssa.Function]bool) map[*ssa.Function]bool {
	filtered := make(map[*ssa.Function]bool)
	for function := range functions {
		if idx := base.idxForFunction(function); idx != nil {
			if !idx.std {
				filtered[function] = true
			}
			continue
		}
		if !isStdImportPath(funcPkgPath(function)) {
			filtered[function] = true
		}
	}
	return filtered
}

func maximalObservabilityBlocker(effect externalEffect) bool {
	// The AST scan cannot see the receiver, so testing.Run covers t.Run,
	// b.Run, and m.Run alike, and testing.Fuzz would block every sibling
	// subject in a package declaring one fuzz test; both narrow to
	// diagnostics - the subject tier classifies each reached driver by
	// its receiver, and a fuzz subject still refuses there
	// (REQ-closure-observability-analysis).
	if effect.packagePath == "testing" && (effect.symbol == "Run" || effect.symbol == "Fuzz") {
		return false
	}
	// The property-harness fact keeps the closure verdict unverifiable
	// without blocking observability: the subject tiers judge every
	// harness crossing precisely (REQ-closure-observability-analysis).
	if effect.kind == externalEffectTestRuntime && propertyHarnessPath(effect.packagePath) {
		return false
	}
	// The receiver-escape rejection is package-scan diagnostic, never a
	// package blocker: subject-tier dispatch on an escaped harness value
	// is classified precisely (admitted, widened, or effect-recorded),
	// and user test-main flow — the one startup flow that can dispatch a
	// test-planted value — widens on any invoke the startup walk cannot
	// enumerate (REQ-closure-observability-analysis).
	if effect.reason == "testing runtime value escapes analyzable receiver" {
		return false
	}
	// The subject tier classifies the guard-pinned toolchain accessor
	// precisely; the maximal AST scan must not pre-block it.
	if effect.packagePath == "runtime" && effect.symbol == "GOROOT" {
		return false
	}
	// The subject and startup tiers classify fmt's writer-first print
	// family writer-sensitively; the AST scan cannot see the writer and
	// must not pre-block what those tiers can prove in-memory. Print and
	// the Scan families carry their channel in the symbol and stay.
	if fmtFprintFamily(effect.packagePath, effect.symbol) {
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

// flagRegistrationSymbol reports whether pkg.name is standard flag
// REGISTRATION with a value-shaped sink - a process-local registry
// mutation whose registered storage the registration facts walk can
// trace and guard. The callback families (Var, TextVar, Func,
// BoolFunc) run arbitrary code at Parse and keep the audited-pure
// exclusion. The read side - Parse and every reference to registered
// storage - keeps the exclusion too; this admission is consulted by
// the startup and test-main direct walks and the package-scan
// backstop, and is sound only because flagRegistrationFacts judges
// every call site's sinks program-wide
// (REQ-closure-observability-analysis).
func flagRegistrationSymbol(pkgPath, name string) bool {
	return flagValueRegistration(pkgPath, name) || flagPointerRegistration(pkgPath, name)
}

// flagValueRegistration matches the value families: the registered
// storage is the returned pointer's target.
func flagValueRegistration(pkgPath, name string) bool {
	if pkgPath != "flag" {
		return false
	}
	switch name {
	case "Bool", "Int", "Int64", "Uint", "Uint64", "String", "Float64", "Duration":
		return true
	}
	return false
}

// flagPointerRegistration matches the pointer families: the registered
// storage is the first argument's target.
func flagPointerRegistration(pkgPath, name string) bool {
	if pkgPath != "flag" {
		return false
	}
	switch name {
	case "BoolVar", "IntVar", "Int64Var", "UintVar", "Uint64Var", "StringVar", "Float64Var", "DurationVar":
		return true
	}
	return false
}

// flagRegistrationFacts walks every function body in the program's
// non-standard packages once per base and judges each registration
// call's registered storage: a pointer-family call's first argument
// and every store of a value-family result must trace, through field
// and index selections, to a package-level variable. A traced variable
// is marked - its value changes at flag.Parse, command-line state the
// test log cannot audit, so any later reference in subject or
// test-main flow refuses as the covert channel's read side. A sink the
// judgment cannot trace poisons the whole package: registration is
// admitted by symbol name (direct walks and package scan alike), and
// that admission is sound only because an admitted-but-untraceable
// registration blocks every subject sharing the program. Bodies are
// judged whether or not any walk reaches them - the package scan
// admits registration in flows no walk attributes, so the facts must
// cover exactly what source can express. Standard-library bodies are
// excluded exactly as the direct walks exclude them: the harness's own
// registrations are audited surface
// (REQ-closure-observability-analysis).
func (b *tier2Base) flagRegistrationFacts() (map[*ssa.Global]bool, map[string]string) {
	if b.flagBacked != nil {
		return b.flagBacked, b.flagUntraceable
	}
	backed := map[*ssa.Global]bool{}
	poisoned := map[string]string{}
	poison := func(fn *ssa.Function, instr ssa.Instruction, what string) {
		pkgPath := funcPkgPath(fn)
		if pkgPath == "" {
			return
		}
		pos := ""
		if b.prog != nil && b.prog.Prog != nil && instr.Pos().IsValid() {
			position := b.prog.Prog.Fset.Position(instr.Pos())
			name := position.Filename
			// Module-relative where possible, bare file name otherwise
			// (module-cache dependencies): the reason persists in
			// recorded proofs, and a machine-local absolute path would
			// vary across checkouts of the same tree - the package path
			// in the reason already locates the file.
			relative := ""
			if b.h != nil && b.h.dir != "" {
				if rel, err := filepath.Rel(b.h.dir, name); err == nil && !strings.HasPrefix(rel, "..") {
					relative = rel
				}
			}
			if relative != "" {
				name = relative
			} else {
				name = filepath.Base(name)
			}
			pos = fmt.Sprintf(" at %s:%d:%d", name, position.Line, position.Column)
		}
		reason := "flag registration with untraceable sink in " + pkgPath + " (" + what + ")" + pos + "; blocks every subject sharing the test binary"
		// Lexicographic minimum, not first-wins: the walk iterates a
		// function set in map order, and the recorded reason must not
		// vary run to run.
		if current, ok := poisoned[pkgPath]; !ok || reason < current {
			poisoned[pkgPath] = reason
		}
	}
	userPaths := userModulePaths(b.prog.Pkgs)
	for fn := range ssautil.AllFunctions(b.prog.Prog) {
		pkgPath := funcPkgPath(fn)
		// The skip keys on the load's module facts, never on path shape
		// alone: a dotless user module skipped here would leave its flag
		// registrations unjudged - no traced storage to refuse, no
		// untraceable sink to poison - breaking the admission's stated
		// soundness argument (the dotless-module soundness family).
		if pkgPath == "" || (isStdImportPath(pkgPath) && !userPaths[pkgPath]) {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				site, ok := instr.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				callee := site.Common().StaticCallee()
				if callee == nil {
					continue
				}
				calleePkg, calleeName := funcPkgPath(callee), functionSymbolName(callee)
				args := site.Common().Args
				if callee.Signature != nil && len(args) > 0 &&
					(callee.Signature.Recv() != nil || flagSetReceiverParam(callee.Signature)) {
					// Method form: (*FlagSet).Bool and kin carry the
					// receiver as the first argument - as an ordinary
					// first parameter in the method-expression form,
					// where Recv is nil.
					args = args[1:]
				}
				switch {
				case flagPointerRegistration(calleePkg, calleeName):
					if len(args) == 0 {
						poison(fn, instr, calleeName+" has no pointer argument")
						continue
					}
					if g := packageLevelRoot(args[0]); g != nil {
						backed[g] = true
					} else {
						poison(fn, instr, calleeName+" target is not a package-level variable")
					}
				case flagValueRegistration(calleePkg, calleeName):
					call, ok := instr.(*ssa.Call)
					if !ok {
						// go/defer forms discard the result: nothing to
						// guard beyond Lookup, which keeps the exclusion.
						continue
					}
					refs := call.Referrers()
					if refs == nil {
						continue
					}
					for _, ref := range *refs {
						if _, ok := ref.(*ssa.DebugRef); ok {
							continue
						}
						if store, ok := ref.(*ssa.Store); ok && store.Val == call {
							if g := packageLevelRoot(store.Addr); g != nil {
								backed[g] = true
								continue
							}
						}
						poison(fn, instr, calleeName+" result escapes its registration site")
					}
				}
			}
		}
	}
	b.flagBacked = backed
	b.flagUntraceable = poisoned
	return backed, poisoned
}

// flagSetReceiverParam reports whether the signature carries a
// *flag.FlagSet receiver as its first ordinary parameter - the
// method-expression form of the registration methods, where
// Signature.Recv is nil.
func flagSetReceiverParam(sig *types.Signature) bool {
	if sig == nil || sig.Recv() != nil || sig.Params() == nil || sig.Params().Len() == 0 {
		return false
	}
	ptr, ok := types.Unalias(sig.Params().At(0).Type()).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "flag" && named.Obj().Name() == "FlagSet"
}

// packageLevelRoot resolves an address through field and index
// selections to the package-level variable it roots at, or nil.
func packageLevelRoot(v ssa.Value) *ssa.Global {
	for {
		switch x := v.(type) {
		case *ssa.Global:
			return x
		case *ssa.FieldAddr:
			v = x.X
		case *ssa.IndexAddr:
			v = x.X
		default:
			return nil
		}
	}
}

// flagRegistrationWriteShape reports whether an instruction belongs to
// the sanctioned registration write: the registration call itself, or
// the store of a value-family result. These are the only instructions
// whose reference to registered storage is the write that creates it;
// every other reference is the read side.
func flagRegistrationWriteShape(instr ssa.Instruction) bool {
	switch x := instr.(type) {
	case ssa.CallInstruction:
		if x.Common() == nil {
			return false
		}
		callee := x.Common().StaticCallee()
		return callee != nil && flagRegistrationSymbol(funcPkgPath(callee), functionSymbolName(callee))
	case *ssa.Store:
		call, ok := x.Val.(*ssa.Call)
		if !ok || call.Common() == nil {
			return false
		}
		callee := call.Common().StaticCallee()
		return callee != nil && flagValueRegistration(funcPkgPath(callee), functionSymbolName(callee))
	}
	return false
}

// registrationAddressComputation reports whether every use of an
// address-computation value feeds the sanctioned registration write -
// the &v.field / &v[i] argument shape, or the address a value-family
// result stores through - directly or through further selections. Any
// other use escapes the address and keeps the refusal. The seen map
// only dedups: selection chains are acyclic by SSA dominance (operands
// dominate users; a Phi lands in the default arm), so a revisit is a
// diamond, never a cycle.
func registrationAddressComputation(v ssa.Value, seen map[ssa.Value]bool) bool {
	if seen[v] {
		return true
	}
	seen[v] = true
	refs := v.Referrers()
	if refs == nil || len(*refs) == 0 {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case ssa.CallInstruction:
			if !flagRegistrationWriteShape(r) {
				return false
			}
		case *ssa.FieldAddr:
			if !registrationAddressComputation(r, seen) {
				return false
			}
		case *ssa.IndexAddr:
			if !registrationAddressComputation(r, seen) {
				return false
			}
		case *ssa.Store:
			// The address a value-family result stores through
			// (cfg.V = flag.Bool(...)) is the write's own sink; the
			// address appearing as the stored VALUE is an escape.
			if r.Addr != v || !flagRegistrationWriteShape(r) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// recordFlagBackedReferences refuses every operand reference to a
// marked flag-backed variable outside the registration write shape: a
// load is the covert channel's read side, and an address escaping into
// the flow can only be read or laundered - refusing the reference
// itself is the fail-closed judgment that needs no points-to chase.
// Field and index selections whose every use feeds the registration
// write are that write's own argument computation and pass with it.
func recordFlagBackedReferences(backed map[*ssa.Global]bool, record func(externalEffect), instr ssa.Instruction) {
	if len(backed) == 0 || flagRegistrationWriteShape(instr) {
		return
	}
	switch x := instr.(type) {
	case *ssa.FieldAddr:
		if registrationAddressComputation(x, map[ssa.Value]bool{}) {
			return
		}
	case *ssa.IndexAddr:
		if registrationAddressComputation(x, map[ssa.Value]bool{}) {
			return
		}
	}
	for _, rand := range instr.Operands(nil) {
		if rand == nil || *rand == nil {
			continue
		}
		if g, ok := (*rand).(*ssa.Global); ok && backed[g] {
			record(flagBackedReadEffect(g))
		}
	}
}

// flagBackedReadEffect is the refusal a flag-backed reference records.
// The wording covers every refusing flow: a post-Parse read carries
// command-line state, and a pre-Parse reference is at best a default
// read and at worst an address escape - indistinguishable here.
func flagBackedReadEffect(g *ssa.Global) externalEffect {
	pkgPath := ""
	if g.Pkg != nil && g.Pkg.Pkg != nil {
		pkgPath = g.Pkg.Pkg.Path()
	}
	return symbolExternalEffect(externalEffectEnvironment, pkgPath, g.Name(), "references flag-registered state "+g.String()+" (storage flag.Parse writes from the command line, a channel the test log cannot audit)")
}
