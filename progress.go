package gofresh

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/guard"
)

// Progress reports the start of one analysis step, or a fact about an
// operation: Phase is "observe" for a view observation pass, "runtime"
// for each runtime-input observation pass (a check's window performs
// two), "list" for a package's dependency listing, "typecheck" for a
// typed load (the view's shared load or a dynamic-state miss load, Total
// its pattern count; or a package's own testing-effect scan load when
// that memo is cold and no shared load covers the package), "load" for
// a package program load, "hash" for a package's closure fold, "prove" for a package's observability batch
// (one event per attribution slice, Index/Total the slice position),
// "served" once per operation per memo class that stood in for a step —
// Served names the class (an observability proof, an effect scan, a
// testing scan, dynamic-state facts, a package scan, a dependency
// listing, a file scan, a compartment parse) and Index counts the distinct
// packages it served from the persistent store; "cancelled" once per
// operation that returns its caller's context error, Detail saying what
// the operation persisted and a rerun serves; "toolchain-unaudited" and
// "analysis-unavailable" carry their diagnostic payload in Detail, as
// does "listing-unmodelled" (a module file this build cannot parse
// leaves a package's listing spawned every pass) and "budget-exhausted"
// (once per proof pass the analysis budget cut, Detail naming the
// budget and the count of subjects it left unproven). Package
// names the package for the per-package phases; Index and Total give the
// unit's position when the pass knows it (1-based; zero when unknown).
// Events are emitted before the step runs — except the facts about an
// operation ("served", "cancelled", "budget-exhausted"), reported when
// they are known — and carry no completion signal; they are keep-alive
// facts about work, never verdict evidence (REQ-fresh-progress).
type Progress struct {
	Phase   string
	Package string
	Index   int
	Total   int
	// Served names the memo class of a "served" summary.
	Served string
	// Detail carries a diagnostic payload for phases that have one -
	// the per-subject analysis-unavailable provenance included, whose
	// walk-order-dependent content must reach the operator without
	// riding any memoized, hashed surface
	// (REQ-closure-observability-memo).
	Detail string
}

// wireProgress routes a Hasher's step, unit, and diagnostic events to
// the session's progress callback as Progress values.
func (s *Session) wireProgress(hasher *closure.Hasher) {
	hasher.OnProgress(func(phase, pkgPath string) {
		s.progress(Progress{Phase: phase, Package: pkgPath})
	})
	hasher.OnDiagnostic(func(phase, pkgPath, detail string) {
		s.progress(Progress{Phase: phase, Package: pkgPath, Detail: detail})
	})
	hasher.OnUnit(func(phase, pkgPath string, index, total int) {
		s.progress(Progress{Phase: phase, Package: pkgPath, Index: index, Total: total})
	})
}

// opAccount accumulates, across every pass an operation performs, what
// its Hashers persisted to the memo store and which packages the store
// served per memo class — the facts the operation's one kept-on-cancel
// report and its one served summary per class carry. It rides the
// operation's context so every pass finds it without a signature.
type opAccount struct {
	proofs, scans int
	served        map[string]map[string]bool
}

type opAccountKey struct{}

// beginOperation opens one operation's accounting on ctx and returns the
// finisher the operation defers: it emits the served summary (one event
// per class) and, when the operation returns its caller's context error,
// the kept-on-cancel report — once per operation, whatever its passes.
func (s *Session) beginOperation(ctx context.Context) (context.Context, func(*error)) {
	refreshTraceFromEnv()
	if s.progress == nil || ctx == nil {
		return ctx, func(*error) {}
	}
	if _, nested := ctx.Value(opAccountKey{}).(*opAccount); nested {
		// A pass inside an already-accounted operation reports through
		// that operation.
		return ctx, func(*error) {}
	}
	acc := &opAccount{served: map[string]map[string]bool{}}
	return context.WithValue(ctx, opAccountKey{}, acc), func(err *error) {
		classes := make([]string, 0, len(acc.served))
		for class := range acc.served {
			classes = append(classes, class)
		}
		sort.Strings(classes)
		for _, class := range classes {
			s.progress(Progress{Phase: "served", Served: class, Index: len(acc.served[class])})
		}
		if err != nil && *err != nil && (errors.Is(*err, context.Canceled) || errors.Is(*err, context.DeadlineExceeded)) {
			s.progress(Progress{Phase: "cancelled", Detail: keptOnCancelDetail(acc.proofs, acc.scans)})
		}
	}
}

// accountPass folds one pass's Hasher into the operation's accounting.
func accountPass(ctx context.Context, hasher *closure.Hasher) {
	if hasher == nil {
		return
	}
	acc, ok := ctx.Value(opAccountKey{}).(*opAccount)
	if !ok {
		return
	}
	proofs, scans := hasher.Persisted()
	acc.proofs += proofs
	acc.scans += scans
	for class, pkgs := range hasher.ServedSummary() {
		if acc.served[class] == nil {
			acc.served[class] = map[string]bool{}
		}
		for p := range pkgs {
			acc.served[class][p] = true
		}
	}
}

// budgetExhausted is the one spelling of an exhausted analysis budget,
// read by the cut proof's reason and the pass's diagnostic alike.
func budgetExhausted(budget time.Duration) string {
	return "analysis budget " + budget.String() + " exhausted"
}

// countNoun renders a count with its noun, pluralized past one.
func countNoun(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// keptOnCancelDetail renders a cancelled operation's kept-on-cancel
// report: what the passes persisted before the cancellation, so a
// rerun's served set is known (REQ-fresh-progress).
func keptOnCancelDetail(proofs, scans int) string {
	return countNoun(proofs, "observability proof slice") + " and " + countNoun(scans, "scan") + " persisted this operation; a rerun serves them"
}

// analysisBound derives the analysis context a precise-analysis phase
// runs under: the operation's own when the budget is zero, a child with
// the budget's deadline otherwise (REQ-fresh-context). The cancel is the
// caller's to defer.
func analysisBound(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	if budget <= 0 {
		return ctx, func() {}
	}
	if boundCtx, cancel, ok := runAnalysisBoundViewHook(ctx, budget); ok {
		return boundCtx, cancel
	}
	return context.WithTimeout(ctx, budget)
}

// reportBudgetCut reports one pass's cut — once, with the count of
// subjects the budget left in the named state — on the progress sink;
// a pass that cut nothing reports nothing (REQ-fresh-progress).
func reportBudgetCut(progress func(Progress), budget time.Duration, cut int, state string) {
	if cut == 0 || progress == nil {
		return
	}
	progress(Progress{Phase: "budget-exhausted", Detail: budgetExhausted(budget) + ": " + countNoun(cut, "subject") + " " + state})
}

// emitUnauditedToolchainNotice announces an unverified toolchain ONCE
// PER ENGINE on the diagnostic channel: one line of each consumer
// run's output points at the refusing axis - the surface packages that
// failed structural verification, or a surface that could not be
// read - without which the degradation surfaces only as a scatter of
// ordinary fail-closed refusals, the exact discovery shape the content
// keying was built to prevent. Per-engine (not per-process) so a long-lived
// server's every campaign log carries it; the once is the caller's,
// so a consumer-less engine's emission is never spent into a void it
// shares with a later consumer.
func emitUnauditedToolchainNotice(once *sync.Once, notice string, emit func(detail string)) {
	if notice == "" {
		return
	}
	once.Do(func() {
		// The owned axis-naming rendering, with the operator-facing
		// source pointer this face has always carried appended as
		// attribution — the same decoration a consumer adds.
		emit(notice + " (closure/toolchainaudit.go)")
	})
}

// viewTestHookSet holds internal observation callbacks and explicitly named
// test controls. Nil or zero disables them.
type viewTestHookSet struct {
	// observe observes every source/guard/purity observation pass — tests
	// pin how many observations an operation performs.
	observe func()
	// runtimeGuards observes or perturbs an execution-side guard sample in
	// binding/closing tests, independently of source/build observation passes.
	runtimeGuards func(*guard.RuntimeGuards)
	// snapshot observes the env snapshot each precise-analysis bracket
	// derives its configuration from — tests pin that the bracket reuses
	// the view's construction snapshot instead of re-reading go env.
	snapshot func(*gotool.EnvSnapshot)
	// dynamicStateMissLoad observes the batched typed load of
	// version-pinned packages whose dynamic-state facts missed the memo.
	dynamicStateMissLoad func(patterns []string)
	// guardDir observes the directory each guard observation captures
	// in — tests pin that an evidence root moves no guard or load off
	// the module directory (REQ-inputs-evidence-root).
	guardDir func(dir string)
	// typedLoad observes every typed package load an observation pass
	// performs; runtimeWindow every runtime-input window a check opens;
	// maximalBatch every maximal-closure fold — tests pin that a
	// preparation refusal fires before each of them.
	typedLoad     func()
	runtimeWindow func()
	maximalBatch  func()
	// beforeAnalysis observes the point a precise analysis is about to
	// start, after its Hasher exists — tests cancel there to pin the
	// kept-on-cancel report.
	beforeAnalysis func()
	// beforeDischarge observes the point the dynamic-state discharges'
	// reachability analysis is about to start — tests cancel there to
	// pin that an operation's cancellation is never read as a budget
	// cut.
	beforeDischarge func()
	// analysisBound replaces only positive-budget deadline construction in
	// tests. A provenance fixture can expire its selected analysis phase
	// deterministically while default-clock tests exercise real deadlines.
	analysisBound func(context.Context, time.Duration) (context.Context, context.CancelFunc)
	// scanMemoOff disables the view scan memo (REQ-closure-scan-memo) so
	// derivation tests that poison the in-process fact cache between two
	// scans — a seam with no production analogue, since a pinned fact
	// moves only when its key does — exercise the derivation itself.
	scanMemoOff bool
	// factScope observes the derived execution-agnostic dynamic-state fact scope,
	// while scanScope observes the execution-attested view scan scope.
	factScope func(scope string)
	scanScope func(scope string)
	// localFactLoad observes session-scoped mutable-local dynstate.Fact lookups.
	localFactLoad func(listing string, hit bool)
}

var (
	viewTestHooksMu sync.Mutex
	viewTestHooks   atomic.Pointer[viewTestHookSet]
)

func withViewTestHooks(hooks viewTestHookSet, fn func()) {
	viewTestHooksMu.Lock()
	defer viewTestHooksMu.Unlock()
	defer viewTestHooks.Store(nil)
	viewTestHooks.Store(&hooks)
	fn()
}

func hasAnyViewTestHook() bool {
	h := viewTestHooks.Load()
	if h == nil {
		return false
	}
	return h.observe != nil || h.runtimeGuards != nil ||
		h.snapshot != nil || h.dynamicStateMissLoad != nil ||
		h.guardDir != nil || h.typedLoad != nil ||
		h.runtimeWindow != nil || h.maximalBatch != nil ||
		h.beforeAnalysis != nil || h.beforeDischarge != nil ||
		h.analysisBound != nil || h.scanMemoOff ||
		h.factScope != nil || h.scanScope != nil ||
		h.localFactLoad != nil
}

func hasScanOverrideViewTestHook() bool {
	h := viewTestHooks.Load()
	return h != nil && (h.dynamicStateMissLoad != nil || h.typedLoad != nil)
}

func emitObserveViewHook() {
	if h := viewTestHooks.Load(); h != nil && h.observe != nil {
		h.observe()
	}
}

func emitRuntimeGuardsViewHook(g *guard.RuntimeGuards) {
	if h := viewTestHooks.Load(); h != nil && h.runtimeGuards != nil {
		h.runtimeGuards(g)
	}
}

func emitSnapshotViewHook(s *gotool.EnvSnapshot) {
	if h := viewTestHooks.Load(); h != nil && h.snapshot != nil {
		h.snapshot(s)
	}
}

func emitDynamicStateMissLoadViewHook(patterns []string) {
	if h := viewTestHooks.Load(); h != nil && h.dynamicStateMissLoad != nil {
		h.dynamicStateMissLoad(patterns)
	}
}

func emitGuardDirViewHook(dir string) {
	if h := viewTestHooks.Load(); h != nil && h.guardDir != nil {
		h.guardDir(dir)
	}
}

func emitTypedLoadViewHook() {
	if h := viewTestHooks.Load(); h != nil && h.typedLoad != nil {
		h.typedLoad()
	}
}

func emitRuntimeWindowViewHook() {
	if h := viewTestHooks.Load(); h != nil && h.runtimeWindow != nil {
		h.runtimeWindow()
	}
}

func emitMaximalBatchViewHook() {
	if h := viewTestHooks.Load(); h != nil && h.maximalBatch != nil {
		h.maximalBatch()
	}
}

func emitBeforeAnalysisViewHook() {
	if h := viewTestHooks.Load(); h != nil && h.beforeAnalysis != nil {
		h.beforeAnalysis()
	}
}

func emitBeforeDischargeViewHook() {
	if h := viewTestHooks.Load(); h != nil && h.beforeDischarge != nil {
		h.beforeDischarge()
	}
}

func runAnalysisBoundViewHook(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc, bool) {
	if h := viewTestHooks.Load(); h != nil && h.analysisBound != nil {
		boundCtx, cancel := h.analysisBound(ctx, budget)
		return boundCtx, cancel, true
	}
	return nil, nil, false
}

func isScanMemoOffViewHook() bool {
	h := viewTestHooks.Load()
	return h != nil && h.scanMemoOff
}

func emitFactScopeViewHook(scope string) {
	if h := viewTestHooks.Load(); h != nil && h.factScope != nil {
		h.factScope(scope)
	}
}

func emitScanScopeViewHook(scope string) {
	if h := viewTestHooks.Load(); h != nil && h.scanScope != nil {
		h.scanScope(scope)
	}
}

func emitLocalFactLoadViewHook(listing string, hit bool) {
	if h := viewTestHooks.Load(); h != nil && h.localFactLoad != nil {
		h.localFactLoad(listing, hit)
	}
}
