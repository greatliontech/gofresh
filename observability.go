package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"

	"github.com/greatliontech/gofresh/internal/closure"
)

func (v *Snapshot) packageMates() []closure.Subject {
	if v.parent != nil {
		return v.parent.requests
	}
	return v.requests
}

// ensureObservable runs the drift-forced observability proof for subjects
// not yet computed, inside one single-observation drift bracket pair and
// over one shared closure Hasher
// (REQ-fresh-coherent-view attribution; equivalence per
// REQ-closure-observability-batch-equivalence).
func (v *Snapshot) ensureObservable(ctx context.Context, subjects []Subject) (err error) {
	if ctx == nil {
		return errors.New("gofresh: nil precise-analysis context")
	}
	var hasher *closure.Hasher
	defer func() { accountPass(ctx, hasher) }()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gofresh: precise analysis cancelled: %w", err)
	}
	v.mu.RLock()
	observableRequests := make([]closure.Subject, 0, len(subjects))
	for _, subject := range subjects {
		request := closure.Subject{Package: subject.Package, Symbol: subject.Symbol}
		if _, ok := v.observable[subject]; !ok {
			observableRequests = append(observableRequests, request)
		}
	}
	v.mu.RUnlock()
	if len(observableRequests) == 0 {
		return nil
	}
	if v.beforePreciseAnalysis != nil {
		v.beforePreciseAnalysis()
	}
	// The bracket opens on the view's own agreed facts: any change since
	// construction that persists to the closing observation refuses there,
	// so a separate opening observation bought only earlier refusal on a
	// dirty tree at the price of one pass on every clean one
	// (REQ-fresh-coherent-view: the pair is load-bearing where facts
	// become the record; the bracket only compares).
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gofresh: precise analysis cancelled: %w", err)
	}
	emitSnapshotViewHook(v.facts.snapshot)
	hasher, err = closure.NewBracketAt(ctx, v.facts.reader, v.session.buildFlags...)
	emitBeforeAnalysisViewHook()
	if err != nil {
		return err
	}
	liveSnapshot, err := hasher.PassReader().Snapshot(ctx)
	if err != nil {
		return err
	}
	if liveSnapshot.Identity() != v.facts.snapshot.Identity() {
		return fmt.Errorf("%w: analysis environment", ErrViewChanged)
	}
	// The bracket's analysis scope is the view's: the same identity
	// outside the source closure the observation pass set, so its
	// memos and the pass's are one store. The observability memo's key
	// completes with the package test-binary closure hash inside the
	// Hasher (REQ-closure-observability-memo). Since the per-subject
	// isolation landed, SHAPE REFUSALS memoize too - a change to the
	// analyzer's shape capability (a new admitted shape, a widened
	// guard) must bump ObservationRTA, or cached refusals serve under
	// semantics that no longer refuse them.
	hasher.SetAnalysisScope(v.session.analysisScope(v.facts.guards))
	hasher.SetPackageMates(v.packageMates())
	if v.session.progress != nil {
		v.session.wireProgress(hasher)
	}
	// The caller's analysis budget bounds only the precise analysis itself: the
	// Hasher's analysis context carries the budget deadline, so exhaustion
	// surfaces as analysis failure — degrading to unavailable evidence, never
	// validity — while the operation, its brackets, and Hasher construction
	// stay governed by the caller's context alone.
	var analysisCtx context.Context
	budget := v.session.analysisBudget
	if budget > 0 {
		bound, cancelBudget := analysisBound(ctx, budget)
		defer cancelBudget()
		analysisCtx = bound
		if err := hasher.BoundAnalysis(analysisCtx); err != nil {
			return err
		}
	}
	observableComputed, err := hasher.ComputeObservabilityBatch(observableRequests)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("gofresh: observation proof cancelled: %w", ctx.Err())
		}
		// Isolation retries per subject so a fact reached only by one
		// subject can never deny a sibling's proof. While the analysis
		// context lives, the Hasher memoizes load failures, so a failing
		// package's load runs once per analysis however many subjects
		// retry; once the analysis budget expires, retries fail at the
		// subprocess boundary without real work.
		observableComputed = make(map[closure.Subject]closure.Observability, len(observableRequests))
		cut := 0
		for _, request := range observableRequests {
			isolated, isolatedErr := hasher.ComputeObservabilityBatch([]closure.Subject{request})
			if isolatedErr != nil {
				if ctx.Err() != nil {
					return fmt.Errorf("gofresh: observation proof cancelled: %w", ctx.Err())
				}
				// The isolated refusal composes here, outside the batch's
				// attributed return, so it attributes the selection itself
				// exactly as its in-batch twin does
				// (REQ-closure-refusal-channels). A refusal under an
				// expired analysis budget names the budget: the reason
				// is the record's, read long after the pass, and "context
				// deadline exceeded" alone would not say whose deadline
				// (REQ-fresh-context).
				reason := unavailableReason(isolatedErr.Error())
				if analysisCtx != nil && analysisCtx.Err() != nil {
					cut++
					reason = unavailableReason(budgetExhausted(budget) + ": " + isolatedErr.Error())
				}
				observableComputed[request] = closure.Observability{Reason: closure.AttributeSelection(reason, hasher.SelectionAttribution())}
				continue
			}
			maps.Copy(observableComputed, isolated)
		}
		// One diagnostic per pass the budget cut, never one per
		// subject: the count is the fact, the per-subject reasons
		// ride the records (REQ-fresh-progress).
		reportBudgetCut(v.session.progress, budget, cut, "unproven")
	}
	after, err := v.observe(ctx)
	if err != nil {
		return err
	}
	if err := v.holdCutUnavailable(v.compareObservationContext(ctx, after)); err != nil {
		return err
	}
	v.mu.Lock()
	if v.sealed {
		v.mu.Unlock()
		return errViewSealed
	}
	if err := ctx.Err(); err != nil {
		v.mu.Unlock()
		return fmt.Errorf("gofresh: precise analysis cancelled: %w", err)
	}
	for _, request := range observableRequests {
		subject := Subject{Package: request.Package, Symbol: request.Symbol}
		v.observable[subject] = observableComputed[request]
	}
	v.mu.Unlock()
	return ctx.Err()
}

func compatibleObservationProof(recorded Fingerprint, subject Subject) bool {
	compatible, _ := compatibleObservationProofMode(recorded, subject)
	return compatible
}

func compatibleObservationProofMode(recorded Fingerprint, subject Subject) (compatible, effectFree bool) {
	proof := recorded.ObservationProof
	if recorded.ObservationAssertion != "caller assertion" || proof.Strategy != ObservationRTA || proof.Subject != subject || recorded.ToolchainContent == "" || recorded.AdmissionPolicy == "" {
		return false, false
	}
	if proof.Observable == (proof.Reason != "") {
		return false, false
	}
	if proof.Evidence == observationProofEvidence(recorded) {
		return true, false
	}
	if proof.Observable && proof.Evidence == observationProofEvidenceMode(recorded, true) {
		return true, true
	}
	return false, false
}

func observationProofEvidence(recorded Fingerprint) string {
	return observationProofEvidenceMode(recorded, false)
}

func observationProofEvidenceMode(recorded Fingerprint, effectFree bool) string {
	proof := recorded.ObservationProof
	maximalClosure, assertion := recorded.MaximalClosure, recorded.ObservationAssertion
	if !effectFree {
		sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s%d:%s%d:%s%t%d:%s%d:%s%d:%s", len(maximalClosure), maximalClosure, len(assertion), assertion, len(proof.Strategy), proof.Strategy, len(proof.Subject.Package), proof.Subject.Package, len(proof.Subject.Symbol), proof.Subject.Symbol, proof.Observable, len(proof.Reason), proof.Reason, len(recorded.ToolchainContent), recorded.ToolchainContent, len(recorded.AdmissionPolicy), recorded.AdmissionPolicy))
		return hex.EncodeToString(sum[:])[:32]
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s%d:%s%d:%s%t%t%d:%s%d:%s%d:%s", len(maximalClosure), maximalClosure, len(assertion), assertion, len(proof.Strategy), proof.Strategy, len(proof.Subject.Package), proof.Subject.Package, len(proof.Subject.Symbol), proof.Subject.Symbol, proof.Observable, effectFree, len(proof.Reason), proof.Reason, len(recorded.ToolchainContent), recorded.ToolchainContent, len(recorded.AdmissionPolicy), recorded.AdmissionPolicy))
	return hex.EncodeToString(sum[:])[:32]
}
