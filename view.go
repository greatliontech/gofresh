package gofresh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/observability"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"github.com/greatliontech/gofresh/internal/testvariant"
)

// subjectTxState holds one subject's mutable transaction state on a Snapshot
// (cached Tier-2 observability, captured-proof flag, and attached runtime state).
type subjectTxState struct {
	observable       observability.Observability
	hasObservable    bool
	capturedObserved bool
	attached         runtimeinput.State
	hasAttached      bool
}

// Snapshot is one immutable observation of the source, build, guards, and purity
// behind a caller-supplied subject set. Analysis state never crosses view
// generations; within one generation, derived subset views share this view's
// observation while owning independent unit or checking transactions.
type Snapshot struct {
	mu                sync.RWMutex
	session           *Session
	parent            *Snapshot
	subjects          []Subject
	requests          []closure.Subject
	packages          []string
	moduleDir         string
	kind              Kind
	executionModel    ExecutionModel
	hasExecutionModel bool
	facts             *observationFacts
	runtime           *boundRuntime
	txState           map[Subject]subjectTxState
	sealed            bool
	// cutUnavailable holds a comparison's unavailability that a budget
	// cut alone explains: never returned where it arose — a capture keeps
	// the view's fail-closed facts, a validation runs every other check
	// first — and read by the observed validation's end (REQ-fresh-context).
	cutUnavailable error
	runtimeCurrent func(context.Context, string, string) (runtimeinput.State, error)
	// beforePreciseAnalysis observes the start of drift-forced precise analysis
	// (the observability proof). Tests use it to pin which check paths run
	// analysis and to inject cancellation at the analysis boundary.
	beforePreciseAnalysis func()
	// beforeOutcomeIssue lets lifecycle tests intervene after capture has
	// released its lock and before preparation checks the transaction seal.
	beforeOutcomeIssue func()
}

// observeSnapshot observes one analysis view with the guards applicable to kind
// under the caller's context. Reachability and package loading are shared
// across the requested set, but each subject retains its independent closure
// semantics (REQ-closure-batch-equivalence).
func (s *Session) observeSnapshot(ctx context.Context, subjects []Subject, moduleDir string, kind Kind) (view *Snapshot, opErr error) {
	ctx, done := s.beginOperation(ctx)
	defer done(&opErr)
	if ctx == nil {
		return nil, errors.New("gofresh: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validKind(kind) {
		return nil, fmt.Errorf("gofresh: invalid result kind %d", kind)
	}
	if len(subjects) == 0 {
		return nil, errors.New("gofresh: analysis view requires at least one subject")
	}
	var err error
	moduleDir, err = gotool.CanonicalDir(moduleDir)
	if err != nil {
		return nil, fmt.Errorf("gofresh: resolve guards tree: %w", err)
	}
	if err := s.coherentDir(moduleDir); err != nil {
		return nil, err
	}

	unique, requests, packages, err := scopeSubjects(subjects)
	if err != nil {
		return nil, err
	}

	first, err := s.observeView(ctx, unique, requests, packages, moduleDir, kind)
	if err != nil {
		return nil, err
	}
	second, err := s.observeView(ctx, unique, requests, packages, moduleDir, kind)
	if err != nil {
		return nil, err
	}
	if err := compareObservations(ctx, unique, &first, first.guards, second, true); err != nil {
		return nil, err
	}

	return newSnapshotShell(s, unique, requests, packages, moduleDir, kind, &first), nil
}

func newSnapshotShell(s *Session, subjects []Subject, requests []closure.Subject, packages []string, moduleDir string, kind Kind, facts *observationFacts) *Snapshot {
	var execModel ExecutionModel
	var hasExecModel bool
	if s != nil {
		execModel = s.executionModel
		hasExecModel = true
	}
	return &Snapshot{
		session:           s,
		subjects:          subjects,
		requests:          requests,
		packages:          packages,
		moduleDir:         moduleDir,
		kind:              kind,
		executionModel:    execModel,
		hasExecutionModel: hasExecModel,
		facts:             facts,
		txState:           make(map[Subject]subjectTxState, len(subjects)),
	}
}

func (v *Snapshot) cloneShell(subjects []Subject, requests []closure.Subject, packages []string, facts *observationFacts) *Snapshot {
	shell := newSnapshotShell(v.session, subjects, requests, packages, v.moduleDir, v.kind, facts)
	shell.executionModel = v.executionModel
	shell.hasExecutionModel = v.hasExecutionModel
	shell.parent = v.parent
	shell.runtime = v.runtime
	shell.runtimeCurrent = v.runtimeCurrent
	shell.beforePreciseAnalysis = v.beforePreciseAnalysis
	shell.beforeOutcomeIssue = v.beforeOutcomeIssue
	return shell
}

// Capture returns subject's precomputed fingerprint from this Snapshot. Runtime-input
// evidence belongs to the producing unit and is attached when the unit closes.
func (v *Snapshot) Capture(ctx context.Context, subject Subject) (Fingerprint, error) {
	if ctx == nil {
		return Fingerprint{}, errors.New("gofresh: nil analysis context")
	}
	if v == nil || v.facts == nil {
		return Fingerprint{}, errors.New("gofresh: uninitialized snapshot")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sealed {
		return Fingerprint{}, errViewSealed
	}
	if err := v.requireMembers([]Subject{subject}); err != nil {
		return Fingerprint{}, err
	}
	return v.fingerprintLocked(subject, v.facts.closure(subject)), nil
}

// SourceFiles returns the absolute mutable source paths whose bytes contribute
// to this view's maximal closures. The returned slice is caller-owned.
func (v *Snapshot) SourceFiles() []string {
	if v == nil || v.facts == nil {
		return nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return append([]string(nil), v.facts.sourceFiles...)
}

// SourceFilesFor returns the caller-owned mutable source paths contributing to
// subject's maximal closure in this view.
func (v *Snapshot) SourceFilesFor(subject Subject) ([]string, error) {
	if v == nil || v.facts == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.requireMembers([]Subject{subject}); err != nil {
		return nil, err
	}
	return slices.Clone(v.facts.subjects[subject].sourceFiles), nil
}

// TestVariantLedger returns the declaration ledger over subject's package
// test-variant compartment, as observed by this view: it is derived at view
// construction from the same file reads as the compartment hash the
// fingerprint records, so a caller persists it at capture and diffs it at
// check against exactly the bytes the verdict compared — never a re-read that
// could straddle a later edit (REQ-closure-test-variant-ledger,
// REQ-fresh-coherent-view). The returned value is caller-owned. A package with
// no test files yields an empty ledger.
func (v *Snapshot) TestVariantLedger(subject Subject) (TestVariantLedger, error) {
	if v == nil || v.facts == nil {
		return TestVariantLedger{}, errors.New("gofresh: uninitialized snapshot")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.requireMembers([]Subject{subject}); err != nil {
		return TestVariantLedger{}, err
	}
	return v.facts.testVariantLedgers[subject.Package].Clone(), nil
}

// CaptureBatch captures a fingerprint for every subject in the view,
// sharing the view's batched analysis across the set.
func (v *Snapshot) CaptureBatch(ctx context.Context) (map[Subject]Fingerprint, error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil analysis context")
	}
	if v == nil || v.facts == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sealed {
		return nil, errViewSealed
	}
	result := make(map[Subject]Fingerprint, len(v.subjects))
	for _, subject := range v.subjects {
		cl := v.facts.closure(subject)
		result[subject] = v.fingerprintLocked(subject, cl)
	}
	return result, nil
}

// fingerprintLocked projects the view's immutable producing facts. Callers
// hold the view lock; observed capture adds its independently derived proof.
func (v *Snapshot) fingerprintLocked(subject Subject, cl closure.Closure) Fingerprint {
	if v.kind == SourceResult {
		return Fingerprint{
			MaximalClosure:     cl.Hash,
			TestVariantClosure: cl.TestVariants,
			ToolchainContent:   cl.ToolchainContent,
			AdmissionPolicy:    cl.AdmissionPolicy,
			Guards:             v.guards(),
			ClosureStrategy:    ClosureStrategy,
			ResultKind:         SourceResult,
		}
	}
	entry := v.facts.subjects[subject]
	return Fingerprint{
		MaximalClosure: cl.Hash, TestVariantClosure: cl.TestVariants,
		ToolchainContent: cl.ToolchainContent, AdmissionPolicy: cl.AdmissionPolicy,
		Guards: v.guards(), PurityAssertion: entry.purity,
		DynamicStateVouches:      entry.vouchDischarges,
		SingleSubjectDischarges:  entry.discharges.singleSubject,
		PackageProcessDischarges: entry.discharges.packageProcess,
		DynamicStateStrategy:     DynamicStateStrategy, ClosureStrategy: ClosureStrategy,
		ResultKind: v.kind,
	}
}

// captureObservedBatch captures observation proof evidence for every
// subject, sharing one proof analysis across the set.
func (v *Snapshot) captureObservedBatch(ctx context.Context) (fps map[Subject]Fingerprint, opErr error) {
	if v == nil || v.facts == nil || v.session == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	ctx, done := v.session.beginOperation(ctx)
	defer done(&opErr)
	if err := v.ensureObservable(ctx, v.subjects); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("gofresh: observation proof cancelled: %w", err)
	}
	if v.sealed {
		return nil, errViewSealed
	}
	result := make(map[Subject]Fingerprint, len(v.subjects))
	for _, subject := range v.subjects {
		tx := v.txState[subject]
		tx.capturedObserved = true
		v.txState[subject] = tx
		result[subject] = v.observedFingerprintLocked(subject)
	}
	return result, nil
}

func (v *Snapshot) observedFingerprintLocked(subject Subject) Fingerprint {
	disposition := v.txState[subject].observable
	singleSubject := v.effectiveExecutionModel().singleSubject()
	observable := disposition.Observable
	reason := disposition.Reason
	effectFree := disposition.EffectFree
	reqSingleSubject := disposition.RequiresSingleSubject
	if observable && reqSingleSubject && !singleSubject {
		observable = false
		reason = disposition.SharedProcessUnsafeReason
		if reason == "" {
			reason = "package scan: reaches un-confined unsafe.Pointer"
		}
		effectFree = false
		reqSingleSubject = false
	}
	proof := ObservationProof{
		Strategy:   ObservationRTA,
		Subject:    subject,
		Observable: observable,
		Reason:     reason,
	}
	const assertion = "caller assertion"
	fingerprint := v.fingerprintLocked(subject, v.facts.closure(subject))
	fingerprint.ObservationAssertion, fingerprint.ObservationProof = assertion, proof
	fingerprint.ObservationProof.Evidence = observationProofEvidenceFull(fingerprint, effectFree, reqSingleSubject)
	return fingerprint
}

// attachRuntimeState validates the exact prepared fingerprint even when no
// observation was selected. Nil state supplies no runtime evidence or assertion.
func (v *Snapshot) attachRuntimeState(subject Subject, fingerprint Fingerprint, state *runtimeinput.State, observed bool) (Fingerprint, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sealed {
		return Fingerprint{}, errViewSealed
	}
	if err := v.requireMembers([]Subject{subject}); err != nil {
		return Fingerprint{}, err
	}
	want := v.fingerprintLocked(subject, v.facts.closure(subject))
	if observed {
		want = v.observedFingerprintLocked(subject)
	}
	tx := v.txState[subject]
	if (observed && !tx.capturedObserved) || fingerprint != want {
		return Fingerprint{}, errors.New("gofresh: observation does not match captured subject proof")
	}
	if state == nil {
		return fingerprint, nil
	}
	if tx.hasAttached {
		return Fingerprint{}, errors.New("gofresh: runtime observation already attached for subject")
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	tx.attached = *state
	tx.hasAttached = true
	v.txState[subject] = tx
	return fingerprint, nil
}

func (v *Snapshot) purityMatches(recorded Fingerprint, subject Subject) PurityAuthority {
	var current string
	if v.facts != nil {
		current = v.facts.subjects[subject].purity
	}
	return PurityAuthority{Recorded: purityAttribution(recorded.PurityAssertion), Current: purityAttribution(current)}
}

func (v *Snapshot) currentRuntimeEndpoint(ctx context.Context, recorded Fingerprint, shared map[string]runtimeEval) (runtimeinput.State, error) {
	if err := ctx.Err(); err != nil {
		return runtimeinput.State{}, err
	}
	if recorded.RuntimeInputs == "" {
		return runtimeinput.State{}, nil
	}
	if cached, ok := shared[recorded.RuntimeInputs]; ok {
		return cached.state, nil
	}
	eval, err := v.evaluateRuntimeManifest(ctx, recorded.RuntimeInputs, v.evidenceRoot())
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return runtimeinput.State{}, contextErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return runtimeinput.State{}, err
		}
		eval = runtimeEval{hasMovers: v.runtimeCurrent == nil}
	}
	if err := ctx.Err(); err != nil {
		return runtimeinput.State{}, err
	}
	shared[recorded.RuntimeInputs] = eval
	return eval.state, nil
}

// sibling derives a view over a subset of this view's subjects that
// shares this view's single observation (REQ-fresh-coherent-view,
// REQ-guard-view-lifetime) while owning a fresh transaction.
func (v *Snapshot) sibling(subjects []Subject) (*Snapshot, error) {
	if v == nil || v.facts == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(subjects) == 0 {
		return nil, errors.New("gofresh: sibling view requires at least one subject")
	}
	parent := make(map[Subject]bool, len(v.subjects))
	for _, subject := range v.subjects {
		parent[subject] = true
	}
	if err := requireSubjects(subjects, func(s Subject) bool { return parent[s] }, ParentView); err != nil {
		return nil, err
	}
	unique, requests, packages, err := scopeSubjects(subjects)
	if err != nil {
		return nil, err
	}
	rootParent := v
	if v.parent != nil {
		rootParent = v.parent
	}
	entries := make(map[Subject]subjectEntry, len(unique))
	txState := make(map[Subject]subjectTxState, len(unique))
	ledgers := make(map[string]testvariant.TestVariantLedger, len(packages))
	groups := make([][]string, 0, len(unique))
	hasCachedObservable := false
	for _, subject := range unique {
		entry := v.facts.subjects[subject]
		entries[subject] = entry
		groups = append(groups, entry.sourceFiles)
		if parentTx := v.txState[subject]; parentTx.hasObservable || parentTx.capturedObserved {
			if parentTx.hasObservable {
				hasCachedObservable = true
			}
			txState[subject] = subjectTxState{
				observable:       parentTx.observable,
				hasObservable:    parentTx.hasObservable,
				capturedObserved: parentTx.capturedObserved,
			}
		}
	}
	sourceFiles := sortedUniqueUnion(groups)
	for _, pkg := range packages {
		if ledger, ok := v.facts.testVariantLedgers[pkg]; ok {
			ledgers[pkg] = ledger
		}
	}
	var siblingCut error
	if hasCachedObservable {
		siblingCut = v.cutUnavailable
	}
	shell := v.cloneShell(unique, requests, packages, &observationFacts{
		snapshot:           v.facts.snapshot,
		reader:             v.facts.reader,
		subjects:           entries,
		source:             v.facts.source,
		guards:             v.facts.guards,
		sourceFiles:        sourceFiles,
		fileDigests:        v.facts.fileDigests,
		testVariantLedgers: ledgers,
		modelProjections:   restrictModelProjections(v.facts.modelProjections, v.facts.hasProjection, unique),
		hasProjection:      v.facts.hasProjection,
	})
	shell.parent = rootParent
	shell.txState = txState
	shell.cutUnavailable = siblingCut
	return shell, nil
}

// guards composes the immutable capture without putting execution-specific facts
// in the shared source/build generation.
func (v *Snapshot) guards() guard.Guards {
	g := v.facts.guards
	if v.runtime != nil {
		g.Machine, g.RuntimeConfig = v.runtime.guards.Machine, v.runtime.guards.RuntimeConfig
	}
	return g
}

func (v *Snapshot) evidenceEnv() []string {
	if v.runtime != nil {
		return v.runtime.env
	}
	return v.session.evidenceEnv()
}

// observe is the single comparison-pass entry for closing, seeded validation,
// runtime windows and precise-analysis refinement. It observes compilation under
// the session and runtime guards under the view's immutable binding. The composed
// result is comparison-only; it never replaces shared source facts.
func (v *Snapshot) observe(ctx context.Context) (observationFacts, error) {
	facts, err := v.session.observeViewWithExecution(ctx, v.subjects, v.requests, v.packages, v.moduleDir, v.kind, v.effectiveExecutionModel())
	if err != nil {
		return observationFacts{}, err
	}
	if v.runtime != nil {
		runtime, err := v.runtime.observe(ctx, v.kind)
		if err != nil {
			return observationFacts{}, err
		}
		facts.guards.Machine, facts.guards.RuntimeConfig = runtime.Machine, runtime.RuntimeConfig
	}
	return facts, nil
}

func (v *Snapshot) compareObservationContext(ctx context.Context, observation observationFacts) error {
	return compareObservations(ctx, v.subjects, v.facts, v.guards(), observation, false)
}

// requireMembers judges selection, not whether today's source declares a name.
// The immutable closure inventory is the shared membership authority for every
// projection, attachment and check over a constructed view.
func (v *Snapshot) requireMembers(subjects []Subject) error {
	return requireSubjects(subjects, func(s Subject) bool {
		_, ok := v.facts.subjects[s]
		return ok
	}, SelectedView)
}
