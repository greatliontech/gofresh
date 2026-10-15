package gofresh

import (
	"testing"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/internal/outcome"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// This property starts at the admitted-facts decision layer. It does not issue
// producing support or assert that arbitrary text is a canonical stored record.
// Diagnostic changes must preserve the decision and every accepted authority.
func FuzzJudgmentDiagnosticIndependence(f *testing.F) {
	for _, text := range []string{"", "a different cause", sharedDynamicStatePrefix + "not semantic authority", "runtimeinputs", "test variants"} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		guards := guard.Guards{Toolchain: "toolchain", BuildConfig: "build"}
		recorded := Fingerprint{MaximalClosure: "core", TestVariantClosure: "tests", ToolchainContent: "stdlib", AdmissionPolicy: "policy", Guards: guards, RuntimeInputs: "already-validated manifest", RuntimeDigest: "digest", ResultKind: CodeResult}
		for _, origin := range []closure.RefusalKind{closure.DependenceRefusal, closure.OpenWorldRefusal, closure.SharedDynamicStateRefusal, closure.AmbiguousSubjectRefusal} {
			for mask := 0; mask < 8; mask++ {
				cl := closure.Closure{Hash: "core", TestVariants: "tests", ToolchainContent: "stdlib", AdmissionPolicy: "policy", Unverifiable: true, Refusal: origin, Reason: "original diagnostic"}
				state := runtimeinput.State{OK: true, Digest: "digest", Unverifiable: mask&1 != 0, Reason: "original runtime diagnostic"}
				var observation ObservationAuthority
				if mask&2 != 0 {
					observation = ObservationAuthority{Assertion: "caller assertion", ProofStrategy: ObservationRTA, OutcomeMethod: outcome.Method}
				}
				purity := testPurityAuthority(mask&4 != 0)
				before := decideAfterClosureObserved(recorded, cl, guards, state, CodeResult, purity, observation)
				cl.Reason, state.Reason = text, text
				after := decideAfterClosureObserved(recorded, cl, guards, state, CodeResult, purity, observation)
				before.Reason, after.Reason = "", ""
				if before != after {
					t.Fatalf("diagnostic changed semantic judgment: origin=%d inputs=%d text=%q before=%+v after=%+v", origin, mask, text, before, after)
				}
			}
		}
	})
}
