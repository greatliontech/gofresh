package gofresh

import (
	"slices"
	"testing"

	"github.com/greatliontech/gofresh/guard"
)

// The engine supplies the strategy, guard and assertion axes; the constructed
// hasher supplies the source and admission dependencies before a memo is armed.
// A swapped constant must not key proofs by the fact derivation
// (REQ-closure-observability-memo, REQ-closure-dynamic-state-memo,
// REQ-closure-scan-memo).
func TestAnalysisScopeWiresTheStrategyConstants(t *testing.T) {
	guards := guard.Guards{Toolchain: "tc", BuildConfig: "bc"}
	plain := (&Engine{}).analysisScope(guards)
	if plain.ProofStrategy != ObservationRTA || plain.FactStrategy != DynamicStateStrategy || plain.Toolchain != "tc" || plain.BuildConfig != "bc" {
		t.Fatalf("wrong caller-owned scope axes: %+v", plain)
	}
	if plain.Proofs() != "" || plain.Facts() != "" || plain.Scan() != "" || plain.TestingScan() != "" {
		t.Fatal("reported guards without source dependencies armed a memo")
	}
	attested := (&Engine{singleSubjectExecution: true, packageProcessExecution: true, dynamicStateVouches: map[string]bool{"example.com/dep:Hooks": true, "a.example/x:Y": true}}).analysisScope(guards)
	slices.Sort(attested.Vouches)
	if !attested.SingleSubject || !attested.PackageProcess || plain.SingleSubject || plain.PackageProcess || !slices.Equal(attested.Vouches, []string{"a.example/x:Y", "example.com/dep:Hooks"}) || len(plain.Vouches) != 0 {
		t.Fatalf("assertion axes not preserved: plain=%+v attested=%+v", plain, attested)
	}
	if attested.ProofStrategy != plain.ProofStrategy || attested.FactStrategy != plain.FactStrategy || attested.Toolchain != plain.Toolchain || attested.BuildConfig != plain.BuildConfig {
		t.Fatal("assertions moved an unrelated scope axis")
	}
}
