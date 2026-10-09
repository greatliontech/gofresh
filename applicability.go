package gofresh

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/internal/outcome"
)

// InertTestVariantExtension identifies the recognized applicability transform.
const InertTestVariantExtension = "gofresh/inert-test-variant-extension@1"

// InertTestVariantApplicability is a consumer-licensed effective compartment,
// distinct from the immutable producing fingerprint. Its zero value means no
// transform. Unknown strategies are readable persisted data but confer no reuse.
type InertTestVariantApplicability struct {
	Strategy           string
	TestVariantClosure string
}

// EffectiveTestVariantClosure returns the applicability endpoint when present,
// otherwise the producing compartment. It does not recognize or validate a
// strategy; Check fails closed on an unknown one.
func (f Fingerprint) EffectiveTestVariantClosure() string {
	if f.InertTestVariantApplicability != (InertTestVariantApplicability{}) {
		return f.InertTestVariantApplicability.TestVariantClosure
	}
	return f.TestVariantClosure
}

func (f Fingerprint) recognizedApplicability() bool {
	a := f.InertTestVariantApplicability
	return a == (InertTestVariantApplicability{}) || (a.Strategy == InertTestVariantExtension && a.TestVariantClosure != "" && f.TestVariantClosure != "")
}

// CheckInertTestVariantExtension explicitly licenses an inert delta from prior
// to this view's ledger, then checks every remaining guard under ordinary policy.
// The caller vouches that prior is the complete ledger paired with recorded's
// effective compartment, core, listing/build configuration, toolchain and
// derivation. Historical provenance is caller-trusted, not hash-authenticated.
// Only Valid returns an updated fingerprint and independently owned ledger.
// Producing constituents are never refreshed. WithDeferredCheckClose makes the
// returned judgment and pair provisional until this view successfully validates.
func (v *View) CheckInertTestVariantExtension(ctx context.Context, recorded Fingerprint, prior TestVariantLedger, subject Subject) (Fingerprint, TestVariantLedger, Verdict, error) {
	return v.checkInertTestVariantExtension(ctx, recorded, prior, subject, false)
}

// CheckObservedInertTestVariantExtension selects the same explicit extension
// under observed policy. Original producer support must qualify independently;
// current analysis establishes applicability, never new historical support.
// The return and deferred-close obligations are CheckInertTestVariantExtension's.
func (v *View) CheckObservedInertTestVariantExtension(ctx context.Context, recorded Fingerprint, prior TestVariantLedger, subject Subject) (Fingerprint, TestVariantLedger, Verdict, error) {
	return v.checkInertTestVariantExtension(ctx, recorded, prior, subject, true)
}

func (v *View) checkInertTestVariantExtension(ctx context.Context, recorded Fingerprint, prior TestVariantLedger, subject Subject, observed bool) (Fingerprint, TestVariantLedger, Verdict, error) {
	refuse := func(verdict Verdict, err error) (Fingerprint, TestVariantLedger, Verdict, error) {
		return Fingerprint{}, TestVariantLedger{}, verdict, err
	}
	if ctx == nil {
		return refuse(Verdict{}, errors.New("gofresh: nil analysis context"))
	}
	if err := ctx.Err(); err != nil {
		return refuse(Verdict{}, err)
	}
	closures, err := v.prepareRecorded(map[Subject]Fingerprint{subject: recorded})
	if err != nil {
		return refuse(Verdict{}, err)
	}
	cl := closures[subject]
	if !recorded.recognizedApplicability() || recorded.EffectiveTestVariantClosure() == "" {
		return refuse(Verdict{Stale, ReasonTestVariants}, nil)
	}
	if recorded.ClosureStrategy != ClosureStrategy {
		return refuse(Verdict{Stale, "closure strategy"}, nil)
	}
	// The only waived comparison is the effective compartment. Core and
	// derivations still use the shared ladder, before any ledger judgment.
	candidate := recorded
	candidate.InertTestVariantApplicability = InertTestVariantApplicability{InertTestVariantExtension, cl.TestVariants}
	if verdict, failed := recordedEvidenceVerdict(candidate, cl); failed {
		return refuse(verdict, nil)
	}
	if mismatch := guard.Compare(recorded.Guards, v.facts.guards, v.kind); mismatch != "" {
		return refuse(Verdict{Stale, mismatch}, nil)
	}
	ledger, err := v.TestVariantLedger(subject)
	if err != nil {
		return refuse(Verdict{}, err)
	}
	if !DiffTestVariantLedgers(prior, ledger).Inert() {
		return refuse(Verdict{Stale, ReasonTestVariants}, nil)
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

// Applicability obligations are checks of historical evidence, never producer
// attachments. Keeping them separate prevents validation from treating a reuse
// check as a newly completed execution or requiring a new process receipt.
type applicabilityCheck struct {
	recorded Fingerprint
	subject  Subject
	observed bool
}

func (v *View) retainApplicabilityCheck(ctx context.Context, rec Fingerprint, subject Subject, observed bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sealed {
		return ErrViewSealed
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

func (v *View) currentApplicabilityObservable(subject Subject) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	p := v.observable[subject]
	return p.Observable && p.OutcomeMethod == outcome.Method
}

func (v *View) validateApplicabilityChecks(ctx context.Context) error {
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

// Each batch has one policy and at most one historical record per subject.
// Distinct records of the same subject occupy separate batches: a map overwrite
// would silently discard an obligation. Proof derivation remains view-shared;
// runtime evidence is shared only by identical manifests within a batch phase.
type applicabilityBatch struct {
	recorded map[Subject]Fingerprint
	observed bool
}

func batchApplicabilityChecks(checks []applicabilityCheck) []applicabilityBatch {
	var batches []applicabilityBatch
	for _, check := range checks {
		index := -1
		for i, batch := range batches {
			if _, exists := batch.recorded[check.subject]; batch.observed == check.observed && !exists {
				index = i
				break
			}
		}
		if index < 0 {
			index = len(batches)
			batches = append(batches, applicabilityBatch{make(map[Subject]Fingerprint), check.observed})
		}
		batches[index].recorded[check.subject] = check.recorded
	}
	return batches
}

func (v *View) validateApplicabilityBatches(ctx context.Context, current *View, checks []applicabilityCheck) error {
	var unavailable error
	for _, batch := range batchApplicabilityChecks(checks) {
		var verdicts map[Subject]Verdict
		var err error
		proofUnavailable := make(map[Subject]error)
		// Runtime comparisons close within every batch. The base observation
		// closes all batches together, after every historical obligation, so a
		// cut base comparison cannot hide a later batch's concrete failure.
		if batch.observed {
			verdicts, err = current.checkObservedBatch(ctx, batch.recorded, true, proofUnavailable)
		} else {
			verdicts, err = current.checkBatch(ctx, batch.recorded, true)
		}
		if err := deferValidationUnavailability(err, &unavailable); err != nil {
			return err
		}
		for subject, verdict := range verdicts {
			if verdict.Status == Valid {
				continue
			}
			if verdict.Status == Unverifiable && proofUnavailable[subject] != nil {
				if unavailable == nil {
					unavailable = proofUnavailable[subject]
				}
				continue
			}
			return fmt.Errorf("%w: applicability for %s.%s: %s", ErrViewChanged, subject.Package, subject.Symbol, verdict.Reason)
		}
	}
	if err := deferValidationUnavailability(current.reobserveBase(ctx), &unavailable); err != nil {
		return err
	}
	for _, view := range []*View{v, current} {
		view.mu.RLock()
		cut := view.cutUnavailable
		view.mu.RUnlock()
		if err := deferValidationUnavailability(cut, &unavailable); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return unavailable
}

// Unavailability is a verdict only after all other validation obligations have
// closed. A concrete fault or cancellation always outranks a held cut.
func deferValidationUnavailability(err error, unavailable *error) error {
	if errors.Is(err, ErrAnalysisUnavailable) {
		if *unavailable == nil {
			*unavailable = err
		}
		return nil
	}
	return err
}
