package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/outcome"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// PrepareOutcomeSupport derives support for exactly this view's contributing
// subject set, before execution. Use a sibling view for a narrower process set.
// The caller runs that exact set under the engine's complete producer environment
// and excludes environment mutation. Unsupported inventories return a capability
// carrying their refusal; they never turn process health into outcome evidence.
// Preparation selects each subject's observation proof for producer validation.
func (v *View) PrepareOutcomeSupport(ctx context.Context, frame runtimeinput.ProducerFrame, process string) (runtimeinput.OutcomeSupport, error) {
	if len(v.subjects) == 0 {
		return runtimeinput.OutcomeSupport{}, fmt.Errorf("gofresh: outcome support needs contributing subjects")
	}
	env, err := gotool.EnvForCommand(v.engine.evidenceEnv(), frame.PkgDir)
	if err != nil {
		return runtimeinput.OutcomeSupport{}, err
	}
	binding, err := frame.OutcomeBinding(process, env)
	if err != nil {
		return runtimeinput.OutcomeSupport{}, err
	}
	fingerprints, err := v.CaptureObservedBatch(ctx)
	if err != nil {
		return runtimeinput.OutcomeSupport{}, err
	}
	if v.beforeOutcomeIssue != nil {
		v.beforeOutcomeIssue()
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sealed {
		return runtimeinput.OutcomeSupport{}, ErrViewSealed
	}
	if err := ctx.Err(); err != nil {
		return runtimeinput.OutcomeSupport{}, err
	}
	var subjects []string
	reason := ""
	for _, subject := range v.subjects {
		proof := v.observable[subject]
		if proof.OutcomeMethod != outcome.Method && reason == "" {
			reason = fmt.Sprintf("operation-outcome support unavailable for %q", subject.Package+"."+subject.Symbol)
		}
		subjects = append(subjects, outcomeSubject(fingerprints[subject], subject))
	}
	return outcome.Prepare(binding, subjects, reason), nil
}

func outcomeSubject(fingerprint Fingerprint, subject Subject) string {
	// A string-array encoding is total; it frames every field and uses the
	// manifest's canonical escaping without another serialization grammar.
	data, _ := json.Marshal([]string{outcome.Method, subject.Package, subject.Symbol, fingerprint.MaximalClosure, fingerprint.TestVariantClosure, fingerprint.Guards.Toolchain, fingerprint.Guards.BuildConfig, fingerprint.ObservationProof.Strategy})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
