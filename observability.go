package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"

	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/observability"
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
	if len(subjects) == 0 {
		return nil
	}
	if v.kind == SourceResult {
		return errors.New("gofresh: source-result snapshot has no runtime observation proof")
	}
	v.mu.RLock()
	observableRequests := make([]closure.Subject, 0, len(subjects))
	for _, subject := range subjects {
		if v.facts.maximal[subject].staticDecl {
			v.mu.RUnlock()
			return fmt.Errorf("gofresh: non-callable declaration %s.%s has no runtime execution", subject.Package, subject.Symbol)
		}
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
	prover, err := observability.NewBracketAt(ctx, v.facts.reader, v.session.buildFlags...)
	hasher = prover.BaseHasher()
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
	execModel := v.effectiveExecutionModel()
	scope := v.session.analysisScope(v.facts.guards)
	scope.SingleSubject, scope.PackageProcess = execModel.singleSubject(), execModel.packageProcess()
	hasher.SetAnalysisScope(scope)
	prover.SetPackageMates(v.packageMates())
	if v.session.progress != nil {
		v.session.wireProgress(hasher)
	}
	var analysisCtx context.Context
	budget := v.session.analysisBudget
	if budget > 0 {
		bound, cancelBudget := analysisBound(ctx, budget)
		defer cancelBudget()
		analysisCtx = bound
		if err := prover.BoundAnalysis(analysisCtx); err != nil {
			return err
		}
	}
	observableComputed, err := prover.ComputeObservabilityBatch(observableRequests)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("gofresh: observation proof cancelled: %w", ctx.Err())
		}
		observableComputed = make(map[closure.Subject]observability.Observability, len(observableRequests))
		cut := 0
		for _, request := range observableRequests {
			isolated, isolatedErr := prover.ComputeObservabilityBatch([]closure.Subject{request})
			if isolatedErr != nil {
				if ctx.Err() != nil {
					return fmt.Errorf("gofresh: observation proof cancelled: %w", ctx.Err())
				}
				reason := unavailableReason(isolatedErr.Error())
				if analysisCtx != nil && analysisCtx.Err() != nil {
					cut++
					reason = unavailableReason(budgetExhausted(budget) + ": " + isolatedErr.Error())
				}
				observableComputed[request] = observability.Observability{Reason: closure.AttributeSelection(reason, hasher.SelectionAttribution())}
				continue
			}
			maps.Copy(observableComputed, isolated)
		}
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
	compatible, _, _ := compatibleObservationProofFull(recorded, subject)
	return compatible
}

func compatibleObservationProofMode(recorded Fingerprint, subject Subject) (compatible, effectFree bool) {
	compatible, effectFree, _ = compatibleObservationProofFull(recorded, subject)
	return compatible, effectFree
}

func compatibleObservationProofFull(recorded Fingerprint, subject Subject) (compatible, effectFree, reqSingleSubject bool) {
	proof := recorded.ObservationProof
	if recorded.ObservationAssertion != "caller assertion" || proof.Strategy != ObservationRTA || proof.Subject != subject || recorded.ToolchainContent == "" || recorded.AdmissionPolicy == "" {
		return false, false, false
	}
	if proof.Observable == (proof.Reason != "") {
		return false, false, false
	}
	if proof.Evidence == observationProofEvidenceFull(recorded, false, false) {
		return true, false, false
	}
	if proof.Observable && proof.Evidence == observationProofEvidenceFull(recorded, true, false) {
		return true, true, false
	}
	if proof.Observable && proof.Evidence == observationProofEvidenceFull(recorded, false, true) {
		return true, false, true
	}
	if proof.Observable && proof.Evidence == observationProofEvidenceFull(recorded, true, true) {
		return true, true, true
	}
	return false, false, false
}

func observationProofEvidence(recorded Fingerprint) string {
	return observationProofEvidenceFull(recorded, false, false)
}

func observationProofEvidenceMode(recorded Fingerprint, effectFree bool) string {
	return observationProofEvidenceFull(recorded, effectFree, false)
}

func observationProofEvidenceFull(recorded Fingerprint, effectFree, reqSingleSubject bool) string {
	proof := recorded.ObservationProof
	maximalClosure, assertion := recorded.MaximalClosure, recorded.ObservationAssertion
	if !effectFree && !reqSingleSubject {
		sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s%d:%s%d:%s%t%d:%s%d:%s%d:%s", len(maximalClosure), maximalClosure, len(assertion), assertion, len(proof.Strategy), proof.Strategy, len(proof.Subject.Package), proof.Subject.Package, len(proof.Subject.Symbol), proof.Subject.Symbol, proof.Observable, len(proof.Reason), proof.Reason, len(recorded.ToolchainContent), recorded.ToolchainContent, len(recorded.AdmissionPolicy), recorded.AdmissionPolicy))
		return hex.EncodeToString(sum[:16])
	}
	if !reqSingleSubject {
		sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s%d:%s%d:%s%t%t%d:%s%d:%s%d:%s", len(maximalClosure), maximalClosure, len(assertion), assertion, len(proof.Strategy), proof.Strategy, len(proof.Subject.Package), proof.Subject.Package, len(proof.Subject.Symbol), proof.Subject.Symbol, proof.Observable, effectFree, len(proof.Reason), proof.Reason, len(recorded.ToolchainContent), recorded.ToolchainContent, len(recorded.AdmissionPolicy), recorded.AdmissionPolicy))
		return hex.EncodeToString(sum[:16])
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s%d:%s%d:%s%t%t:ss:%t%d:%s%d:%s%d:%s", len(maximalClosure), maximalClosure, len(assertion), assertion, len(proof.Strategy), proof.Strategy, len(proof.Subject.Package), proof.Subject.Package, len(proof.Subject.Symbol), proof.Subject.Symbol, proof.Observable, effectFree, reqSingleSubject, len(proof.Reason), proof.Reason, len(recorded.ToolchainContent), recorded.ToolchainContent, len(recorded.AdmissionPolicy), recorded.AdmissionPolicy))
	return hex.EncodeToString(sum[:16])
}
