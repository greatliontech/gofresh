package closure

import "testing"

// Each memo's scope renders exactly the axes its derivation reads: the
// proofs and the facts keep the identities their hand-joined strings
// carried (persisted entries keep serving), the typed testing scan reads
// the guards and its own strategy alone, the view scan joins the sorted
// vouch set, and the zero value arms nothing.
func TestAnalysisScopeRendersEachMemosAxes(t *testing.T) {
	scope := AnalysisScope{ProofStrategy: "rta@1", FactStrategy: "facts@2", Toolchain: "tc", BuildConfig: "bc", Vouches: []string{"b:y", "a:x"}}
	if got, want := scope.Proofs(), "rta@1|tc|bc"; got != want {
		t.Errorf("Proofs = %q, want %q", got, want)
	}
	if got, want := scope.TestingScan(), testingScanStrategy+"|tc|bc"; got != want {
		t.Errorf("TestingScan = %q, want %q", got, want)
	}
	if got, want := scope.Facts(), "facts@2|tc|bc"; got != want {
		t.Errorf("Facts = %q, want %q", got, want)
	}
	if got, want := scope.Scan(), "facts@2|tc|bc|vouches:a:x,b:y"; got != want {
		t.Errorf("Scan = %q, want %q", got, want)
	}
	attested := scope
	attested.SingleSubject, attested.PackageProcess = true, true
	if got, want := attested.Facts(), "facts@2|tc|bc|single-subject-execution|package-process-execution"; got != want {
		t.Errorf("attested Facts = %q, want %q", got, want)
	}
	if attested.Proofs() != scope.Proofs() || attested.TestingScan() != scope.TestingScan() {
		t.Error("an attestation moved a scope that does not read it")
	}
	var zero AnalysisScope
	if zero.Proofs() != "" || zero.TestingScan() != "" || zero.Facts() != "" || zero.Scan() != "" {
		t.Errorf("the zero scope arms a memo: %q %q %q %q", zero.Proofs(), zero.TestingScan(), zero.Facts(), zero.Scan())
	}
	// A rendering is inert exactly when the axis that versions it is
	// absent, never armed under a partial identity.
	guardsOnly := AnalysisScope{Toolchain: "tc", BuildConfig: "bc", SingleSubject: true, Vouches: []string{"a:x"}}
	if guardsOnly.Proofs() != "" || guardsOnly.Facts() != "" || guardsOnly.Scan() != "" {
		t.Errorf("guards without a strategy armed a memo: %q %q %q", guardsOnly.Proofs(), guardsOnly.Facts(), guardsOnly.Scan())
	}
	if guardsOnly.TestingScan() != testingScanStrategy+"|tc|bc" {
		t.Errorf("the testing scan, which reads the guards alone, is inert under them: %q", guardsOnly.TestingScan())
	}
	strategiesOnly := AnalysisScope{ProofStrategy: "rta@1", FactStrategy: "facts@2"}
	if strategiesOnly.TestingScan() != "" {
		t.Errorf("the testing scan armed without guards: %q", strategiesOnly.TestingScan())
	}
}
