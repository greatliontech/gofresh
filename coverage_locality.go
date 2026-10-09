package gofresh

import (
	"context"
	"errors"
)

// CoverageLocalityStrategy identifies the empty-external-effect locality rule.
// It is independent of outcome support. Its inventory currently shares the
// ObservationRTA memo key: changes to this projection must invalidate that key
// too, even though this public strategy is separately named.
const CoverageLocalityStrategy = "gofresh/coverage-locality@1"

// CoverageLocalityStatus is a static admission, not a mutant outcome.
type CoverageLocalityStatus uint8

const (
	// CoverageLocalityRefused is also the missing-evidence zero value.
	CoverageLocalityRefused CoverageLocalityStatus = iota
	// CoverageLocalityAdmitted establishes only the process-locality component.
	CoverageLocalityAdmitted
)

// CoverageLocality binds a static disposition to one selected subject and its
// immutable view's code identities. Reason is diagnostic prose. These values
// carry no profile, completion, purity or outcome assertion.
type CoverageLocality struct {
	Status               CoverageLocalityStatus
	Reason               string
	Subject              Subject
	Strategy             string
	MaximalClosure       string
	TestVariantClosure   string
	Toolchain            string
	BuildConfig          string
	ClosureStrategy      string
	DynamicStateStrategy string
	ObservationStrategy  string
}

// CaptureCoverageLocality returns a disposition for every subject in this view
// and selects their proof re-establishment on Validate of this same view. Use a
// Sibling for a subset. No runtime-input attachment is required. The caller must
// include the actual batch's every contributing root and independently establish
// normally completed coverage under this audited build/toolchain selection.
// Initialization, TestMain and callbacks are included by the static inventory.
// Admission is only a conjunction component: it does not establish compilation
// equivalence, verdict-preserving coverage narrowing, or any mutant outcome.
// In particular compile-time constant/goto influence needs a consumer rule.
func (v *View) CaptureCoverageLocality(ctx context.Context) (result map[Subject]CoverageLocality, opErr error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil analysis context")
	}
	if len(v.subjects) == 0 {
		return nil, errors.New("gofresh: coverage locality needs contributing subjects")
	}
	ctx, done := v.engine.beginOperation(ctx)
	defer done(&opErr)
	if err := v.ensureObservable(ctx, v.subjects); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sealed {
		return nil, ErrViewSealed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v.coverageSelected = true
	result = make(map[Subject]CoverageLocality, len(v.subjects))
	for _, subject := range v.subjects {
		proof := v.observable[subject]
		cl := v.facts.maximal[subject]
		evidence := CoverageLocality{
			Subject: subject, Strategy: CoverageLocalityStrategy,
			MaximalClosure: cl.Hash, TestVariantClosure: cl.TestVariants,
			Toolchain: v.facts.guards.Toolchain, BuildConfig: v.facts.guards.BuildConfig,
			ClosureStrategy: ClosureStrategy, DynamicStateStrategy: DynamicStateStrategy,
			ObservationStrategy: ObservationRTA,
			Reason:              proof.Reason,
		}
		switch {
		case v.facts.vouchDischarges[subject] != "" || v.facts.attestationDischarges[subject] != "" || v.facts.packageProcessDischarges[subject] != "":
			evidence.Reason = "coverage locality cannot rely on caller-discharge assertions"
		case proof.Observable && proof.CoverageLocal:
			evidence.Status = CoverageLocalityAdmitted
		default:
			if evidence.Reason == "" {
				evidence.Reason = "coverage locality requires an audited empty external-effect inventory"
			}
		}
		result[subject] = evidence
	}
	return result, nil
}
