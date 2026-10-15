package gofresh

import (
	"context"

	"github.com/greatliontech/gofresh/runtimeinput"
)

// These test adapters expose individual kernel endpoints to drift/authority
// tests without requiring their synthetic records to satisfy source admission.
func (v *View) observeRuntimeInputs(ctx context.Context, recorded map[Subject]Fingerprint) (map[Subject]runtimeinput.State, error) {
	candidates := orderedCandidates(recorded)
	records := make([]recordCheck, len(candidates))
	results := make([]recordResult, len(candidates))
	for i, candidate := range candidates {
		records[i].Candidate = candidate
		results[i].evaluated = true
	}
	states, err := v.observeRecordInputs(ctx, records, results)
	if err != nil {
		return nil, err
	}
	observed := make(map[Subject]runtimeinput.State, len(candidates))
	for i, candidate := range candidates {
		observed[candidate.Subject] = states[i]
	}
	return observed, nil
}

func (v *View) finishRuntimeObservation(ctx context.Context, recorded map[Subject]Fingerprint, before map[Subject]runtimeinput.State, verdicts map[Subject]Verdict) (map[Subject]Verdict, error) {
	after, err := v.observeRuntimeInputs(ctx, recorded)
	if err != nil {
		return nil, err
	}
	for subject, fingerprint := range recorded {
		verdicts[subject] = v.runtimeMotion(ctx, Candidate{subject, fingerprint}, verdicts[subject], before[subject], after[subject])
	}
	for subject, verdict := range verdicts {
		verdicts[subject] = v.judgmentFor(subject, verdict)
	}
	return verdicts, nil
}
