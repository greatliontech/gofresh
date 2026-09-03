package gofresh

import (
	"testing"

	"github.com/greatliontech/gofresh/guard"
)

// The pass's analysis scope wires the real strategy constants to the
// axes their memos read, and its proof, fact, and scan renderings are
// byte for byte the identities persisted entries were written under —
// a swapped constant would key the observability memo by the fact
// strategy and stop a proof-strategy bump from retiring stale proofs
// (REQ-closure-observability-memo, REQ-closure-dynamic-state-memo,
// REQ-closure-scan-memo).
func TestAnalysisScopeWiresTheStrategyConstants(t *testing.T) {
	guards := guard.Guards{Toolchain: "tc", BuildConfig: "bc"}
	plain := (&Engine{}).analysisScope(guards)
	if got, want := plain.Proofs(), ObservationRTA+"|tc|bc"; got != want {
		t.Errorf("Proofs = %q, want %q", got, want)
	}
	if got, want := plain.Facts(), DynamicStateStrategy+"|tc|bc"; got != want {
		t.Errorf("Facts = %q, want %q", got, want)
	}
	if got, want := plain.Scan(), DynamicStateStrategy+"|tc|bc|vouches:"; got != want {
		t.Errorf("Scan = %q, want %q", got, want)
	}
	attested := (&Engine{singleSubjectExecution: true, packageProcessExecution: true, dynamicStateVouches: map[string]bool{"example.com/dep:Hooks": true, "a.example/x:Y": true}}).analysisScope(guards)
	if got, want := attested.Facts(), DynamicStateStrategy+"|tc|bc|single-subject-execution|package-process-execution"; got != want {
		t.Errorf("attested Facts = %q, want %q", got, want)
	}
	if got, want := attested.Scan(), attested.Facts()+"|vouches:a.example/x:Y,example.com/dep:Hooks"; got != want {
		t.Errorf("attested Scan = %q, want %q", got, want)
	}
	if attested.Proofs() != plain.Proofs() {
		t.Error("an attestation or vouch moved the proof scope")
	}
}
