package gofresh

import (
	"context"
	"errors"
	"fmt"
	"sync"

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
// In a ProvisionalCheck it is provisional too; only successful Close grants use.
type CheckedExtension struct {
	Fingerprint Fingerprint
	Ledger      TestVariantLedger
}

// ProvisionalCheck is an advisory answer before closing. Neither its verdict nor
// its optional extension grants permission to reuse or publish evidence.
type ProvisionalCheck struct {
	Index     int
	Subject   Subject
	Verdict   Verdict
	Extension *CheckedExtension
}

// CheckedCandidate is a final judgment after the entire checking unit closes.
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

func (v *View) prepareCandidates(candidates []Candidate) error {
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
func (v *View) observeRecordInputs(ctx context.Context, records []recordCheck, results []recordResult) ([]runtimeinput.State, error) {
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
func (v *View) runtimeMotion(ctx context.Context, candidate Candidate, prior Verdict, before, after runtimeinput.State) Verdict {
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
func (v *View) checkRecords(ctx context.Context, records []recordCheck, deferClose, retain bool) (results []recordResult, opErr error) {
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
		cl := v.facts.maximal[record.Subject]
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
		cl, rec := v.facts.maximal[record.Subject], record.Recorded
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
			if v.currentApplicabilityObservable(record.Subject) {
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
		cl, rec := v.facts.maximal[record.Subject], record.Recorded
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
	}
	return results, ctx.Err()
}

func (v *View) checkMap(ctx context.Context, recorded map[Subject]Fingerprint, observed, deferClose bool) (map[Subject]Verdict, error) {
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
	view   *View
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
func (u *CheckingUnit) CheckBatch(ctx context.Context, candidates []Candidate) ([]ProvisionalCheck, error) {
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
func (u *CheckingUnit) ExtendInertBatch(ctx context.Context, requests []InertRequest) ([]ProvisionalCheck, error) {
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

func (u *CheckingUnit) round(ctx context.Context, prepare func() ([]checkingSlot, error)) ([]ProvisionalCheck, error) {
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
		return nil, ErrUnitClosed
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
	provisional := make([]ProvisionalCheck, len(slots))
	for i := range slots {
		slots[i].result = results[i]
		index := len(u.slots)
		u.slots = append(u.slots, slots[i])
		checked := slots[i].checked(index)
		provisional[i] = ProvisionalCheck{checked.Index, checked.Subject, checked.Verdict, checked.Extension}
	}
	return provisional, nil
}

// finishWork is called under mu at a round's commit boundary. Caller
// cancellation outranks cancellation caused by abort or concurrent closing.
func (u *CheckingUnit) finishWork(ctx context.Context, err error) error {
	if cause := ctx.Err(); cause != nil {
		u.phase = unitFailed
		return cause
	}
	if u.phase == unitAborted {
		return ErrUnitAborted
	}
	if u.phase != unitOpen && u.phase != unitClosing {
		return ErrUnitClosed
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
		return nil, ErrUnitClosed
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
	if err := deferValidationUnavailability(current.reobserveBase(ctx), &unavailable); err != nil {
		return nil, err
	}
	for _, view := range []*View{u.view, current} {
		if err := deferValidationUnavailability(view.cutUnavailable, &unavailable); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if unavailable != nil {
		return nil, unavailable
	}
	return checked, nil
}
