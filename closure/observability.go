package closure

import (
	"fmt"
	"go/token"
	"strings"

	"golang.org/x/tools/go/ssa"

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
	startupReach.functions = nonStandardFunctions(startupReach.startupFunctions)
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
				// User test-main flow is the one startup flow that can
				// dispatch a test-planted value (after m.Run). The planted
				// channel is always a load from shared mutable state, so any
				// dispatch here — interface invoke or computed call alike —
				// widens unless its operand is locally closed; a static
				// callee is an *ssa.Function, closed by construction, so a
				// test-main's own calls and constructions keep today's
				// shape. Initializer flow stays unwidened: nothing is
				// plantable before tests run
				// (REQ-closure-observability-analysis's startup clause).
				if reachable.testMainFunctions[function] && !testMainDispatchClosed(site) {
					analyzer.requestWiden("test-main dispatch on unattributable state in " + function.String())
				}
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

// testMainDispatchClosed reports whether a test-main call site's
// dispatch provenance is the flow's own. A static call to a synthetic
// interface-method wrapper judges the receiver (a thunk's first
// argument, a bound wrapper's operand — whose bindings the closed-value
// walk gates wherever the closure value derives); every other site
// judges the operand. The wrapper family's toolchain-attributed bodies
// perform the real dispatch and no walk scans them; a user-written
// closure needs no such check — its body stays user-attributed and the
// walk records its effects.
func testMainDispatchClosed(site ssa.CallInstruction) bool {
	c := site.Common()
	if callee := c.StaticCallee(); callee != nil && syntheticInterfaceMethodWrapper(callee) {
		receiver := wrapperReceiver(c, callee)
		return receiver != nil && locallyClosedDynamicValue(receiver, make(map[ssa.Value]bool))
	}
	return locallyClosedDynamicValue(c.Value, make(map[ssa.Value]bool))
}

func recordDirectCallEffect(analyzer *tier2Analyzer, callee *ssa.Function, site ssa.CallInstruction) {
	if analyzer == nil || callee == nil || observableFileMethod(callee) || observableDirEntryCall(site) || isTestingMRun(callee) {
		return
	}
	pkgPath, name := funcPkgPath(callee), functionSymbolName(callee)
	effect, classified := classBEffect(pkgPath, name)
	calleeIdx := analyzer.idxForFunction(callee)
	if !classified && name != "init" && calleeIdx != nil && calleeIdx.std && !isStandardFallbackExempt(pkgPath) && !classBPureStandard(pkgPath, name) && !auditedSyncSymbol(pkgPath, name) && !auditedRuntimeTypeSymbol(pkgPath, name) {
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
	// The writer-sink admission applies to the static leg only: a
	// dynamically reached Fprint's site arguments belong to the dynamic
	// signature, not to fmt's writer-first shape, so the writer is not
	// judgeable there and the effect stays. Startup flow carries no
	// subject-attributed parameter analysis, so only locally
	// constructed writers close — an init formatting into its own
	// buffer is pure value computation; anything crossing a boundary
	// keeps the effect.
	if classified && fmtFprintFamily(pkgPath, name) && site.Common().StaticCallee() == callee {
		if args := site.Common().Args; len(args) != 0 &&
			inMemoryFormattedSink(args[0], make(map[ssa.Value]bool), map[ssa.Value]bool{}, analyzer.fresh) {
			classified = false
		}
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
