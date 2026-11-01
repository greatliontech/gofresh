package gofresh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/outcome"
	"github.com/greatliontech/gofresh/internal/trace"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// Candidate is one historical recording to judge. Repeated subjects and identical
// recordings remain independent candidates in request order.
type Candidate struct {
	Subject  Subject
	Recorded Fingerprint
}

// InertRequest explicitly licenses extension of an earlier slot's owned record.
// Index belongs to the receiving CheckingUnit. PriorLedger is the caller-trusted
// ledger paired with that record's effective compartment.
type InertRequest struct {
	Index       int
	PriorLedger TestVariantLedger
}

// CheckedExtension carries an applicability endpoint and its companion ledger.
// During a round it is provisional; only successful Close grants use.
type CheckedExtension struct {
	Fingerprint Fingerprint
	Ledger      TestVariantLedger
}

// CheckedCandidate is one candidate judgment in a CheckingUnit. Returned from
// CheckBatch or ExtendInertBatch before Close, it is an advisory provisional
// answer that grants no permission to reuse or publish evidence; returned from
// Close, it is the final judgment after the entire checking unit closes.
// Index is the zero-based operation slot, in append order across all rounds.
// Extension is present only for a valid explicitly requested transformation.
type CheckedCandidate struct {
	Index     int
	Subject   Subject
	Verdict   Verdict
	Extension *CheckedExtension
}

// recordCheck separates per-record historical policy from the subject-shared
// current proof inventory. A prepared refusal needs no runtime observation.
type recordCheck struct {
	Candidate
	observed bool
	refusal  Verdict
}

type recordResult struct {
	verdict     Verdict
	evaluated   bool
	before      runtimeinput.State
	after       runtimeinput.State
	selected    bool
	unavailable error
}

func orderedCandidates(recorded map[Subject]Fingerprint) []Candidate {
	var candidates []Candidate
	for _, subject := range orderedRecordedSubjects(recorded) {
		candidates = append(candidates, Candidate{subject, recorded[subject]})
	}
	return candidates
}

func validateCandidates(candidates []Candidate, kind Kind) error {
	shape := &RecordedBatchError{Tier: RecordShapeRefusal, ViewKind: kind}
	kinds := &RecordedBatchError{Tier: RecordKindRefusal, ViewKind: kind}
	for _, candidate := range candidates {
		if err := candidate.Recorded.Validate(); err != nil {
			shape.Failures = append(shape.Failures, RecordedFailure{Subject: candidate.Subject, Shape: err})
		} else if candidate.Recorded.ResultKind != kind {
			kinds.Failures = append(kinds.Failures, RecordedFailure{Subject: candidate.Subject, Kind: candidate.Recorded.ResultKind})
		}
	}
	if len(shape.Failures) != 0 {
		return shape
	}
	if len(kinds.Failures) != 0 {
		return kinds
	}
	return nil
}

func (v *Snapshot) prepareCandidates(candidates []Candidate) error {
	if err := validateCandidates(candidates, v.kind); err != nil {
		return err
	}
	subjects := make([]Subject, len(candidates))
	for i, candidate := range candidates {
		subjects[i] = candidate.Subject
	}
	return v.requireMembers(subjects)
}

// observeRecordInputs owns one endpoint cache, including normalized fail-closed
// evaluation errors. No cache survives this call or crosses a runtime binding.
func (v *Snapshot) observeRecordInputs(ctx context.Context, records []recordCheck, results []recordResult) ([]runtimeinput.State, error) {
	shared := map[string]runtimeinput.State{}
	if v.engine != nil && v.engine.progress != nil {
		for i, record := range records {
			if results[i].evaluated && record.Recorded.RuntimeInputs != "" {
				v.engine.progress(Progress{Phase: "runtime"})
				break
			}
		}
	}
	states := make([]runtimeinput.State, len(records))
	for i, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if results[i].evaluated {
			var err error
			states[i], err = v.currentRuntimeContext(ctx, record.Recorded, shared)
			if err != nil {
				return nil, err
			}
		}
	}
	return states, ctx.Err()
}

// runtimeMotion preserves demonstrated staleness even if an input returns to its
// recorded value. A newly deciding refusal starts with no accepted authority.
func (v *Snapshot) runtimeMotion(ctx context.Context, candidate Candidate, prior Verdict, before, after runtimeinput.State) Verdict {
	if candidate.Recorded.RuntimeInputs == "" || before == after || prior.Status == Stale {
		return prior
	}
	moved, failed := runtimeInputVerdict(candidate.Recorded, after)
	if !failed {
		moved = refusal(Stale, RuntimeInputsCause, Changed, "runtimeinputs")
	}
	return v.judgmentFor(candidate.Subject, v.withMovedInputs(ctx, moved, candidate.Recorded))
}

// checkRecords is the one ordered checking kernel. Callers prepare the whole
// batch before entering. Current proofs are subject-scoped; admission, runtime
// spans, selected obligations and answers are always indexed by record.
func (v *Snapshot) checkRecords(ctx context.Context, records []recordCheck, deferClose, retain bool) (results []recordResult, opErr error) {
	ctx, done := v.engine.beginOperation(ctx)
	defer done(&opErr)
	if ctx == nil {
		return nil, errors.New("gofresh: nil checking context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	results = make([]recordResult, len(records))
	positives := make([]ObservationAuthority, len(records))
	hasRuntime := false
	for i, record := range records {
		cl := v.facts.closure(record.Subject)
		verdict, refused := record.refusal, record.refusal.Status != ""
		if !refused {
			verdict, refused = recordedEvidenceVerdict(record.Recorded, cl)
		}
		if refused {
			results[i].verdict = v.judgmentFor(record.Subject, verdict)
			continue
		}
		results[i].evaluated = true
		hasRuntime = hasRuntime || record.Recorded.RuntimeInputs != ""
		if record.observed {
			positives[i] = admittedObservation(record.Recorded, record.Subject, cl)
		}
	}
	if viewTestHooks.runtimeWindow != nil {
		viewTestHooks.runtimeWindow()
	}
	before, err := v.observeRecordInputs(ctx, records, results)
	if err != nil {
		return nil, err
	}
	selected := make([]bool, len(records))
	seen := map[Subject]bool{}
	var proofs []Subject
	for i, record := range records {
		if !results[i].evaluated || !record.observed {
			continue
		}
		cl, rec := v.facts.closure(record.Subject), record.Recorded
		pure := v.purityMatches(rec, record.Subject)
		ordinary := decideAfterClosure(rec, cl, v.guards(), before[i], v.kind, pure)
		if ordinary.Status == Unverifiable && positives[i].accepted() && rec.InertTestVariantApplicability != (InertTestVariantApplicability{}) && decideAfterClosureObserved(rec, cl, v.guards(), before[i], v.kind, pure, positives[i]).Status == Valid {
			selected[i] = true
			if !seen[record.Subject] {
				seen[record.Subject] = true
				proofs = append(proofs, record.Subject)
			}
		}
	}
	if err := v.ensureObservable(ctx, proofs); err != nil {
		return nil, err
	}
	for i, record := range records {
		if !results[i].evaluated {
			continue
		}
		if selected[i] {
			if v.currentApplicabilityObservable(record.Subject, positives[i].OutcomeMethod) {
				positives[i].CurrentApplicability = true
			} else {
				positives[i] = ObservationAuthority{}
				v.mu.RLock()
				proof := v.observable[record.Subject]
				v.mu.RUnlock()
				if analysisUnavailable(proof.Reason) {
					results[i].unavailable = fmt.Errorf("%w: applicability for %s.%s: %s", ErrAnalysisUnavailable, record.Subject.Package, record.Subject.Symbol, proof.Reason)
				}
			}
		}
		cl, rec := v.facts.closure(record.Subject), record.Recorded
		pure := v.purityMatches(rec, record.Subject)
		verdict := decideAfterClosure(rec, cl, v.guards(), before[i], v.kind, pure)
		if record.observed {
			verdict = decideAfterClosureObserved(rec, cl, v.guards(), before[i], v.kind, pure, positives[i])
		}
		results[i].verdict = v.withMovedInputs(ctx, verdict, rec)
	}
	after, err := v.observeRecordInputs(ctx, records, results)
	if err != nil {
		return nil, err
	}
	if err := v.closeCheckWindow(ctx, hasRuntime, deferClose); err != nil {
		return nil, err
	}
	for i, record := range records {
		result := &results[i]
		result.before, result.after = before[i], after[i]
		result.verdict = v.judgmentFor(record.Subject, v.runtimeMotion(ctx, record.Candidate, result.verdict, before[i], after[i]))
		result.selected = selected[i] && positives[i].CurrentApplicability && result.verdict.Status == Valid
		if retain && result.selected {
			if err := v.retainApplicabilityCheck(ctx, record.Recorded, record.Subject, true); err != nil {
				return nil, err
			}
		}
		if trace.AnyEnabled() {
			target := record.Subject.Package + "." + record.Subject.Symbol
			if trace.Enabled(ctx, trace.DomainSession, target) {
				trace.Emit(ctx, trace.DomainSession, "check_verdict", target,
					trace.String("status", string(result.verdict.Status)),
					trace.Int("cause", int(result.verdict.Ground.Cause.Kind)),
					trace.Int("condition", int(result.verdict.Ground.Cause.Condition)),
					trace.String("reason", result.verdict.Reason),
				)
			}
		}
	}
	return results, ctx.Err()
}

func (v *Snapshot) checkMap(ctx context.Context, recorded map[Subject]Fingerprint, observed, deferClose bool) (map[Subject]Verdict, error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil checking context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	candidates := orderedCandidates(recorded)
	if err := v.prepareCandidates(candidates); err != nil {
		return nil, err
	}
	records := make([]recordCheck, len(candidates))
	for i, candidate := range candidates {
		records[i] = recordCheck{Candidate: candidate, observed: observed}
	}
	results, err := v.checkRecords(ctx, records, deferClose, true)
	if err != nil {
		return nil, err
	}
	verdicts := make(map[Subject]Verdict, len(results))
	for i, result := range results {
		subject := candidates[i].Subject
		verdicts[subject] = result.verdict
	}
	return verdicts, nil
}

// CheckingUnit owns ordered historical candidates and their independently closing
// intervals. Admission rounds serialize; input refusals append nothing and leave
// it open. An operational failure ends the unit. Closing during an active round
// cancels that round and refuses, rather than omitting its pending obligations.
type CheckingUnit struct {
	mu     sync.Mutex
	gate   chan struct{}
	phase  unitPhase
	view   *Snapshot
	slots  []checkingSlot
	busy   bool
	cancel context.CancelFunc
}

type checkingSlot struct {
	record    recordCheck
	result    recordResult
	extension bool
	ledger    TestVariantLedger
}

// BeginCheck selects the whole allowed subject set without observing a new tree.
// The transaction owns no producing contribution or producer validation seal.
func (b *RuntimeBinding) BeginCheck(subjects []Subject) (*CheckingUnit, error) {
	v, err := b.newView(subjects)
	if err != nil {
		return nil, err
	}
	return &CheckingUnit{view: v, gate: make(chan struct{}, 1)}, nil
}

// CheckBatch appends one ordinary slot per candidate, including duplicates. The
// returned indices remain stable through later rounds and explicit extensions.
func (u *CheckingUnit) CheckBatch(ctx context.Context, candidates []Candidate) ([]CheckedCandidate, error) {
	owned := append([]Candidate(nil), candidates...)
	return u.round(ctx, func() ([]checkingSlot, error) {
		if err := u.view.prepareCandidates(owned); err != nil {
			return nil, err
		}
		slots := make([]checkingSlot, len(owned))
		for i, candidate := range owned {
			slots[i].record = recordCheck{Candidate: candidate, observed: true}
		}
		return slots, nil
	})
}

// ExtendInertBatch appends separately licensed operations; it never replaces the
// referenced slot's historical judgment. All indices are admitted before work.
func (u *CheckingUnit) ExtendInertBatch(ctx context.Context, requests []InertRequest) ([]CheckedCandidate, error) {
	owned := make([]InertRequest, len(requests))
	for i, request := range requests {
		owned[i] = InertRequest{request.Index, request.PriorLedger.Clone()}
	}
	return u.round(ctx, func() ([]checkingSlot, error) {
		for _, request := range owned {
			if request.Index < 0 || request.Index >= len(u.slots) {
				return nil, fmt.Errorf("gofresh: checking candidate index %d is outside this unit", request.Index)
			}
		}
		slots := make([]checkingSlot, len(owned))
		for i, request := range owned {
			candidate := u.slots[request.Index].record.Candidate
			recorded, ledger, verdict, err := u.view.prepareInertExtension(candidate.Recorded, request.PriorLedger, candidate.Subject)
			if err != nil {
				return nil, err
			}
			if verdict.Status == "" {
				candidate.Recorded = recorded
			}
			slots[i] = checkingSlot{record: recordCheck{Candidate: candidate, observed: true, refusal: verdict}, extension: true, ledger: ledger.Clone()}
		}
		return slots, nil
	})
}

func (u *CheckingUnit) round(ctx context.Context, prepare func() ([]checkingSlot, error)) ([]CheckedCandidate, error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil checking context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if u == nil || u.view == nil {
		return nil, errors.New("gofresh: uninitialized checking unit")
	}
	select {
	case u.gate <- struct{}{}:
		defer func() { <-u.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	u.mu.Lock()
	if err := ctx.Err(); err != nil {
		u.mu.Unlock()
		return nil, err
	}
	if u.phase != unitOpen {
		u.mu.Unlock()
		return nil, errUnitClosed
	}
	slots, err := prepare()
	if cause := ctx.Err(); cause != nil {
		u.mu.Unlock()
		return nil, cause
	}
	if err != nil {
		u.mu.Unlock()
		return nil, err
	}
	work, cancel := context.WithCancel(ctx)
	u.busy, u.cancel = true, cancel
	u.mu.Unlock()
	defer cancel()
	records := make([]recordCheck, len(slots))
	for i := range slots {
		records[i] = slots[i].record
	}
	results, err := u.view.checkRecords(work, records, true, false)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.busy, u.cancel = false, nil
	if err = u.finishWork(ctx, err); err != nil {
		return nil, err
	}
	checked := make([]CheckedCandidate, len(slots))
	for i := range slots {
		slots[i].result = results[i]
		index := len(u.slots)
		u.slots = append(u.slots, slots[i])
		checked[i] = slots[i].checked(index)
	}
	return checked, nil
}

// finishWork is called under mu at a round's commit boundary. Caller
// cancellation outranks cancellation caused by abort or concurrent closing.
func (u *CheckingUnit) finishWork(ctx context.Context, err error) error {
	if cause := ctx.Err(); cause != nil {
		u.phase = unitFailed
		return cause
	}
	if u.phase == unitAborted {
		return errUnitAborted
	}
	if u.phase != unitOpen && u.phase != unitClosing {
		return errUnitClosed
	}
	if err != nil {
		u.phase = unitFailed
	}
	return err
}

func (s checkingSlot) checked(index int) CheckedCandidate {
	result := CheckedCandidate{Index: index, Subject: s.record.Subject, Verdict: s.result.verdict}
	if s.extension && result.Verdict.Status == Valid {
		result.Extension = &CheckedExtension{Fingerprint: s.record.Recorded, Ledger: s.ledger.Clone()}
	}
	return result
}

// Abort cancels owned work and prevents any subsequent final grant. It leaves an
// already closed unit, other transactions and immutable shared facts unchanged.
func (u *CheckingUnit) Abort() {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.phase == unitOpen || u.phase == unitClosing {
		u.phase = unitAborted
		if u.cancel != nil {
			u.cancel()
		}
	}
}

// Close freezes every slot and closes every consulted interval, including losing
// variants from earlier rounds. Only a successful terminal transition returns
// final answers. A retry requires a new unit; no shared binding is sealed.
func (u *CheckingUnit) Close(ctx context.Context) (checked []CheckedCandidate, opErr error) {
	if u == nil || u.view == nil {
		return nil, errors.New("gofresh: uninitialized checking unit")
	}
	u.mu.Lock()
	if u.phase != unitOpen {
		u.mu.Unlock()
		return nil, errUnitClosed
	}
	u.phase = unitClosing
	if ctx == nil || ctx.Err() != nil || u.busy {
		if u.cancel != nil {
			u.cancel()
		}
		u.phase = unitFailed
		u.mu.Unlock()
		if ctx == nil {
			return nil, errors.New("gofresh: nil checking close context")
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrUnitIncomplete
	}
	ctx, done := u.view.engine.beginOperation(ctx)
	defer done(&opErr)
	work, cancel := context.WithCancel(ctx)
	u.cancel = cancel
	u.mu.Unlock()
	defer cancel()
	results, err := u.close(work)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.cancel = nil
	if err := u.finishWork(ctx, err); err != nil {
		return nil, err
	}
	u.phase = unitClosed
	return results, nil
}

func (u *CheckingUnit) close(ctx context.Context) ([]CheckedCandidate, error) {
	current, err := u.view.newSeededValidationView(ctx)
	if err != nil {
		return nil, err
	}
	records := make([]recordCheck, len(u.slots))
	for i, slot := range u.slots {
		records[i] = slot.record
		if !slot.result.evaluated {
			records[i].refusal = slot.result.verdict
		}
	}
	results, err := current.checkRecords(ctx, records, true, false)
	if err != nil {
		return nil, err
	}
	var unavailable error
	checked := make([]CheckedCandidate, len(u.slots))
	for i, slot := range u.slots {
		result := results[i]
		if slot.result.verdict.Status == Stale {
			result.verdict = slot.result.verdict
		} else if slot.result.evaluated {
			result.verdict = current.runtimeMotion(ctx, slot.record.Candidate, result.verdict, slot.result.before, result.before)
			result.verdict = current.runtimeMotion(ctx, slot.record.Candidate, result.verdict, slot.result.after, result.after)
		}
		if (slot.extension && slot.result.verdict.Status == Valid || slot.result.selected) && result.verdict.Status != Valid {
			if result.verdict.Status == Unverifiable && result.unavailable != nil {
				if unavailable == nil {
					unavailable = result.unavailable
				}
			} else {
				return nil, fmt.Errorf("%w: applicability for candidate %d (%s.%s): %s", ErrViewChanged, i, slot.record.Subject.Package, slot.record.Subject.Symbol, result.verdict.Reason)
			}
		}
		slot.result = result
		checked[i] = slot.checked(i)
	}
	if err := u.view.closeValidationReobservation(ctx, current, unavailable); err != nil {
		return nil, err
	}
	return checked, nil
}

// CheckBatchWithLedgers checks a batch of candidates and, for any candidate
// that fails with ReasonTestVariants and has a prior ledger in ledgers,
// explicitly attempts an inert test-variant extension within the same checking
// unit before closing. The returned slice has one entry per candidate in
// request order, with Extension populated when an inert extension succeeded.
func (b *RuntimeBinding) CheckBatchWithLedgers(ctx context.Context, candidates []Candidate, ledgers map[int]TestVariantLedger) ([]CheckedCandidate, error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil checking context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if b == nil || b.snapshot == nil || b.snapshot.facts == nil {
		return nil, errors.New("gofresh: uninitialized runtime binding")
	}
	if err := b.snapshot.prepareCandidates(candidates); err != nil {
		return nil, err
	}
	var subjects []Subject
	seen := make(map[Subject]bool, len(candidates))
	for _, c := range candidates {
		if !seen[c.Subject] {
			seen[c.Subject] = true
			subjects = append(subjects, c.Subject)
		}
	}
	if len(subjects) == 0 {
		subjects = slices.Clone(b.snapshot.subjects)
	}
	u, err := b.BeginCheck(subjects)
	if err != nil {
		return nil, err
	}
	defer u.Abort()
	provisional, err := u.CheckBatch(ctx, candidates)
	if err != nil {
		return nil, err
	}
	var requests []InertRequest
	var requestCandidate []int
	for i, p := range provisional {
		if p.Verdict.Status == Stale && p.Verdict.Reason == ReasonTestVariants {
			if prior, ok := ledgers[i]; ok {
				requests = append(requests, InertRequest{Index: i, PriorLedger: prior})
				requestCandidate = append(requestCandidate, i)
			}
		}
	}
	if len(requests) > 0 {
		if _, err := u.ExtendInertBatch(ctx, requests); err != nil {
			return nil, err
		}
	}
	closed, err := u.Close(ctx)
	if err != nil {
		return nil, err
	}
	results := append([]CheckedCandidate(nil), closed[:len(candidates)]...)
	for k, candIdx := range requestCandidate {
		ext := closed[len(candidates)+k]
		if ext.Verdict.Status == Valid && ext.Extension != nil {
			results[candIdx] = CheckedCandidate{
				Index:     candIdx,
				Subject:   candidates[candIdx].Subject,
				Verdict:   ext.Verdict,
				Extension: ext.Extension,
			}
		}
	}
	return results, nil
}

// checkInertTestVariantExtension explicitly licenses an inert delta from prior
// to this view's ledger, then checks every remaining guard under ordinary or
// observed policy. The caller vouches that prior is the complete ledger paired
// with recorded's effective compartment, core, listing/build configuration,
// toolchain and derivation. Historical provenance is caller-trusted, not
// hash-authenticated. Only Valid returns an updated fingerprint and
// independently owned ledger. Producing constituents are never refreshed.
// withDeferredCheckClose makes the returned judgment and pair provisional
// until this view successfully validates.
func (v *Snapshot) checkInertTestVariantExtension(ctx context.Context, recorded Fingerprint, prior TestVariantLedger, subject Subject, observed bool) (Fingerprint, TestVariantLedger, Verdict, error) {
	if v == nil || v.facts == nil || v.engine == nil {
		return Fingerprint{}, TestVariantLedger{}, Verdict{}, errors.New("gofresh: uninitialized snapshot")
	}
	refuse := func(verdict Verdict, err error) (Fingerprint, TestVariantLedger, Verdict, error) {
		if err == nil {
			verdict = v.judgmentFor(subject, verdict)
		}
		return Fingerprint{}, TestVariantLedger{}, verdict, err
	}
	if ctx == nil {
		return refuse(Verdict{}, errors.New("gofresh: nil analysis context"))
	}
	if err := ctx.Err(); err != nil {
		return refuse(Verdict{}, err)
	}
	if err := v.prepareCandidates([]Candidate{{subject, recorded}}); err != nil {
		return refuse(Verdict{}, err)
	}
	candidate, ledger, rejected, err := v.prepareInertExtension(recorded, prior, subject)
	if err != nil || rejected.Status != "" {
		return refuse(rejected, err)
	}
	var verdict Verdict
	if observed {
		verdict, err = v.CheckObserved(ctx, candidate, subject)
	} else {
		verdict, err = v.Check(ctx, candidate, subject)
	}
	if err != nil || verdict.Status != Valid {
		return refuse(verdict, err)
	}
	if err := v.retainApplicabilityCheck(ctx, candidate, subject, observed); err != nil {
		return refuse(Verdict{}, err)
	}
	return candidate, ledger, verdict, nil
}

// prepareInertExtension licenses only the compartment substitution. It observes
// no runtime inputs or proof and preserves every original producing constituent.
// The caller has admitted shape, kind and membership for the entire batch first.
// An empty verdict means the resulting endpoint still needs the checking kernel.
func (v *Snapshot) prepareInertExtension(recorded Fingerprint, prior TestVariantLedger, subject Subject) (Fingerprint, TestVariantLedger, Verdict, error) {
	refuse := func(verdict Verdict, err error) (Fingerprint, TestVariantLedger, Verdict, error) {
		return Fingerprint{}, TestVariantLedger{}, verdict, err
	}
	cl := v.facts.closure(subject)
	if !recorded.recognizedApplicability() || recorded.EffectiveTestVariantClosure() == "" {
		condition := Missing
		if !recorded.recognizedApplicability() {
			condition = Unsupported
		}
		return refuse(refusal(Stale, TestVariantsCause, condition, ReasonTestVariants), nil)
	}
	if recorded.ClosureStrategy != ClosureStrategy {
		return refuse(closureStrategyVerdict(recorded), nil)
	}
	// The only waived comparison is the effective compartment. Core and
	// derivations still use the shared ladder, before any ledger judgment.
	candidate := recorded
	candidate.InertTestVariantApplicability = InertTestVariantApplicability{InertTestVariantExtension, cl.TestVariants}
	if verdict, failed := recordedEvidenceVerdict(candidate, cl); failed {
		return refuse(verdict, nil)
	}
	if mismatch := guard.CompareFacts(recorded.Guards, v.guards(), v.kind); mismatch.Axis != guard.NoAxis {
		return refuse(guardVerdict(mismatch), nil)
	}
	ledger, err := v.TestVariantLedger(subject)
	if err != nil {
		return refuse(Verdict{}, err)
	}
	if !inertTestVariantLedgersForSubject(prior, ledger, subject.Symbol) {
		return refuse(refusal(Stale, TestVariantsCause, Refused, ReasonTestVariants), nil)
	}
	return candidate, ledger, Verdict{}, nil
}

// Applicability obligations are checks of historical evidence, never producer
// attachments. Keeping them separate prevents validation from treating a reuse
// check as a newly completed execution or requiring a new process receipt.
type applicabilityCheck struct {
	recorded Fingerprint
	subject  Subject
	observed bool
}

func (v *Snapshot) retainApplicabilityCheck(ctx context.Context, rec Fingerprint, subject Subject, observed bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sealed {
		return errViewSealed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	check := applicabilityCheck{rec, subject, observed}
	if !slices.Contains(v.applicabilityChecks, check) {
		v.applicabilityChecks = append(v.applicabilityChecks, check)
	}
	return nil
}

func (v *Snapshot) currentApplicabilityObservable(subject Subject, outcomeMethod string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	p := v.observable[subject]
	if outcomeMethod == outcome.StaticMethod {
		return p.Observable && p.EffectFree
	}
	return p.Observable && p.OutcomeMethod == outcome.Method
}

func (v *Snapshot) validateApplicabilityChecks(ctx context.Context) error {
	// Validate has sealed registration before reading these obligations.
	v.mu.RLock()
	checks := append([]applicabilityCheck(nil), v.applicabilityChecks...)
	v.mu.RUnlock()
	if len(checks) == 0 {
		return nil
	}
	current, err := v.newSeededValidationView(ctx)
	if err != nil {
		return err
	}
	return v.validateApplicabilityBatches(ctx, current, checks)
}

// applicabilityRecords preserves every historical variant and its policy in one
// ordered batch, sharing endpoint observations across subjects and policies.
func applicabilityRecords(checks []applicabilityCheck) []recordCheck {
	records := make([]recordCheck, len(checks))
	for i, check := range checks {
		records[i] = recordCheck{Candidate: Candidate{check.subject, check.recorded}, observed: check.observed}
	}
	return records
}

func (v *Snapshot) validateApplicabilityBatches(ctx context.Context, current *Snapshot, checks []applicabilityCheck) error {
	var unavailable error
	records := applicabilityRecords(checks)
	results, err := current.checkRecords(ctx, records, true, false)
	if err := deferValidationUnavailability(err, &unavailable); err != nil {
		return err
	}
	for i, result := range results {
		if result.verdict.Status == Valid {
			continue
		}
		if result.verdict.Status == Unverifiable && result.unavailable != nil {
			if unavailable == nil {
				unavailable = result.unavailable
			}
			continue
		}
		subject := checks[i].subject
		return fmt.Errorf("%w: applicability for %s.%s: %s", ErrViewChanged, subject.Package, subject.Symbol, result.verdict.Reason)
	}
	return v.closeValidationReobservation(ctx, current, unavailable)
}
