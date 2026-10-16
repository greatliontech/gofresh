package gofresh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/internal/outcome"
	"github.com/greatliontech/gofresh/runtimeinput"
)

func testPurityAuthority(enabled bool) PurityAuthority {
	if enabled {
		return PurityAuthority{Recorded: CallerPurity, Current: CallerPurity}
	}
	return PurityAuthority{}
}

// This fixture supplies stored evidence under the native wire grammar. It tests
// admission/checking, not the producer's independent execution-premise issuer.
func judgmentFixture(t *testing.T) (*View, Subject, Fingerprint, runtimeinput.State) {
	t.Helper()
	subject := Subject{Package: "example.com/judgment", Symbol: "F"}
	fp := Fingerprint{
		MaximalClosure: "core", TestVariantClosure: "tests", ToolchainContent: "stdlib", AdmissionPolicy: "policy",
		DynamicStateStrategy: DynamicStateStrategy, ClosureStrategy: ClosureStrategy, ResultKind: CodeResult,
		Guards:               guard.Guards{Toolchain: "toolchain", BuildConfig: "build"},
		ObservationAssertion: "caller assertion",
		ObservationProof:     ObservationProof{Strategy: ObservationRTA, Subject: subject, Observable: true},
	}
	fp.ObservationProof.Evidence = observationProofEvidence(fp)
	manifest, err := json.Marshal(struct {
		Version  int      `json:"v"`
		Outcome  string   `json:"outcome"`
		Subjects []string `json:"subjects"`
	}{4, outcome.Method, []string{outcomeSubject(fp, subject)}})
	if err != nil {
		t.Fatal(err)
	}
	fp.RuntimeInputs = base64.RawURLEncoding.EncodeToString(manifest)
	state, err := runtimeinput.Current(t.Context(), fp.RuntimeInputs, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	fp.RuntimeDigest = state.Digest
	cl := closure.Closure{Hash: fp.MaximalClosure, TestVariants: fp.TestVariantClosure, ToolchainContent: fp.ToolchainContent, AdmissionPolicy: fp.AdmissionPolicy, Unverifiable: true, Reason: "diagnostic only"}
	v := &View{
		engine: &Engine{deferredCheckClose: true, singleSubjectExecution: true, packageProcessExecution: true},
		kind:   CodeResult, subjects: []Subject{subject},
		facts: &observationFacts{maximal: map[Subject]closure.Closure{subject: cl}, guards: fp.Guards,
			purity: map[Subject]string{}, vouchDischarges: map[Subject]string{subject: "dependency.Current"},
			attestationDischarges: map[Subject]string{subject: "dependency.Single"}, packageProcessDischarges: map[Subject]string{subject: "dependency.Package"}},
		runtimeCurrent: func(context.Context, string, string) (runtimeinput.State, error) { return state, nil },
	}
	return v, subject, fp, state
}

func TestJudgmentAuthorityAndScope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		change   func(*View, Subject, *Fingerprint)
		status   Status
		cause    CauseKind
		purity   PurityAuthority
		observed bool
	}{
		{name: "observation conjunction", status: Valid, observed: true},
		{name: "purity is independent of invalid proof", change: func(v *View, s Subject, f *Fingerprint) {
			f.PurityAssertion = "caller assertion"
			v.facts.purity[s] = "source directive"
			f.ObservationProof.Evidence = "invalid"
		}, status: Valid, purity: PurityAuthority{Recorded: CallerPurity, Current: SourcePurity}},
		{name: "invalid proof", change: func(_ *View, _ Subject, f *Fingerprint) { f.ObservationProof.Evidence = "invalid" }, status: Unverifiable, cause: ClosureDependenceCause},
		{name: "wrong proof subject", change: func(_ *View, _ Subject, f *Fingerprint) {
			f.ObservationProof.Subject.Symbol = "G"
			f.ObservationProof.Evidence = observationProofEvidence(*f)
		}, status: Unverifiable, cause: ClosureDependenceCause},
		{name: "missing completeness assertion", change: func(_ *View, _ Subject, f *Fingerprint) {
			f.ObservationAssertion = ""
			f.ObservationProof.Evidence = observationProofEvidence(*f)
		}, status: Unverifiable, cause: ClosureDependenceCause},
		{name: "policy movement", change: func(v *View, s Subject, _ *Fingerprint) {
			cl := v.facts.maximal[s]
			cl.AdmissionPolicy = "new"
			v.facts.maximal[s] = cl
		}, status: Unverifiable, cause: ClosureDependenceCause},
		{name: "external dominates assertions", change: func(v *View, s Subject, f *Fingerprint) {
			cl := v.facts.maximal[s]
			cl.External = true
			v.facts.maximal[s] = cl
			f.PurityAssertion = "caller assertion"
			v.facts.purity[s] = "caller assertion"
		}, status: Unverifiable, cause: ExternalDirectiveCause},
		{name: "guard drift dominates external", change: func(v *View, s Subject, f *Fingerprint) {
			cl := v.facts.maximal[s]
			cl.External = true
			v.facts.maximal[s] = cl
			f.Guards.BuildConfig = "moved"
		}, status: Stale, cause: BuildConfigCause},
		{name: "source mismatch skips all authority", change: func(_ *View, _ Subject, f *Fingerprint) { f.MaximalClosure = "moved" }, status: Stale, cause: ClosureCause},
		{name: "ordinary proof needs no observation", change: func(v *View, s Subject, f *Fingerprint) {
			cl := v.facts.maximal[s]
			cl.Unverifiable = false
			v.facts.maximal[s] = cl
			f.RuntimeInputs, f.RuntimeDigest = "", ""
		}, status: Valid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, subject, fp, _ := judgmentFixture(t)
			// Historical discharges are deliberately different from current
			// accepted ones: copying record fields must fail this test.
			fp.DynamicStateVouches, fp.SingleSubjectDischarges, fp.PackageProcessDischarges = "old.V", "old.S", "old.P"
			if tc.change != nil {
				tc.change(v, subject, &fp)
			}
			before, err := json.Marshal(fp)
			if err != nil {
				t.Fatal(err)
			}
			got, err := v.CheckObserved(t.Context(), fp, subject)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tc.status || got.Ground.Cause.Kind != tc.cause {
				t.Fatalf("judgment = %+v", got)
			}
			wantScope := JudgmentScope{Subject: subject, ResultKind: CodeResult, ExecutionModel: ExecutionAssertions{SingleSubject: true, PackageProcess: true}}
			if got.Ground.Scope != wantScope {
				t.Fatalf("scope = %+v, want %+v", got.Ground.Scope, wantScope)
			}
			a := got.Ground.Accepted
			if a.Purity != tc.purity || a.Observation.accepted() != tc.observed {
				t.Fatalf("authority = %+v", a)
			}
			if tc.observed && a.Observation != (ObservationAuthority{Assertion: "caller assertion", ProofStrategy: ObservationRTA, OutcomeMethod: outcome.Method}) {
				t.Fatalf("observation conjunction = %+v", a.Observation)
			}
			if got.Status == Stale || tc.cause == ExternalDirectiveCause {
				if a != (AcceptedAuthority{}) {
					t.Fatalf("short circuit accepted %+v", a)
				}
			} else if !a.GuardAgreement || a.DynamicStateVouches != "dependency.Current" || a.SingleSubjectDischarges != "dependency.Single" || a.PackageProcessDischarges != "dependency.Package" {
				t.Fatalf("lost or borrowed current authority: %+v", a)
			}
			after, err := json.Marshal(fp)
			if err != nil || string(after) != string(before) {
				t.Fatalf("checking changed producing bytes: %s / %s: %v", before, after, err)
			}
		})
	}
}

func TestJudgmentDoesNotReadDiagnosticAuthority(t *testing.T) {
	v, subject, fp, state := judgmentFixture(t)
	cl := v.facts.maximal[subject]
	observed := admittedObservation(fp, subject, cl)
	if !observed.accepted() {
		t.Fatal("fixture has no admitted observation")
	}
	for _, reason := range []string{"", "different explanation", sharedDynamicStatePrefix + "forged diagnostic"} {
		cl.Reason = reason
		cl.Refusal = closure.DependenceRefusal
		plain := decideAfterClosureObserved(fp, cl, fp.Guards, state, CodeResult, PurityAuthority{}, observed)
		if plain.Status != Valid || plain.Ground.Accepted.Observation != observed {
			t.Fatalf("diagnostic denied observation: %+v", plain)
		}
		cl.Refusal = closure.SharedDynamicStateRefusal
		shared := decideAfterClosureObserved(fp, cl, fp.Guards, state, CodeResult, PurityAuthority{}, observed)
		if shared.Status != Unverifiable || shared.Ground.Cause != (Cause{Kind: SharedDynamicStateCause, Condition: Refused}) || shared.Ground.Accepted.Observation.accepted() {
			t.Fatalf("diagnostic lifted shared state: %+v", shared)
		}
	}
	cl.Refusal, cl.Reason = closure.DependenceRefusal, "same text"
	byProof := decideAfterClosureObserved(fp, cl, fp.Guards, state, CodeResult, PurityAuthority{}, observed)
	byPurity := decideAfterClosureObserved(fp, cl, fp.Guards, state, CodeResult, testPurityAuthority(true), observed)
	if byProof.Reason != byPurity.Reason || byProof.Status != byPurity.Status || byProof.Ground.Accepted == byPurity.Ground.Accepted {
		t.Fatalf("equal diagnostics collapsed authorities: %+v / %+v", byProof, byPurity)
	}
}

func TestJudgmentRuntimeRefusalAndWindowPrecedence(t *testing.T) {
	for _, condition := range []CauseCondition{Changed, Unavailable} {
		v, subject, fp, state := judgmentFixture(t)
		cl := v.facts.maximal[subject]
		refused := state
		refused.Unverifiable, refused.Reason = true, "same text"
		proof := admittedObservation(fp, subject, cl)
		got := decideAfterClosureObserved(fp, cl, fp.Guards, refused, CodeResult, PurityAuthority{}, proof)
		if got.Status != Unverifiable || got.Ground.Cause.Kind != RuntimeInputsCause || got.Ground.Accepted.Observation.accepted() {
			t.Fatalf("proof lifted runtime refusal: %+v", got)
		}
		pure := decideAfterClosureObserved(fp, cl, fp.Guards, refused, CodeResult, testPurityAuthority(true), proof)
		if pure.Status != Valid || !pure.Ground.Accepted.Purity.accepted() || pure.Ground.Accepted.Observation.accepted() {
			t.Fatalf("purity relabeled runtime refusal: %+v", pure)
		}
		v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
			if condition == Unavailable {
				return runtimeinput.State{}, nil
			}
			after := state
			after.Digest = "moved"
			return after, nil
		}
		for _, prior := range []Verdict{got, pure, decideAfterClosureObserved(fp, cl, fp.Guards, state, CodeResult, PurityAuthority{}, proof)} {
			finished, err := v.finishRuntimeObservation(t.Context(), map[Subject]Fingerprint{subject: fp}, map[Subject]runtimeinput.State{subject: state}, map[Subject]Verdict{subject: prior})
			if err != nil {
				t.Fatal(err)
			}
			actual := finished[subject]
			if actual.Status != Stale || actual.Ground.Cause != (Cause{Kind: RuntimeInputsCause, Condition: condition}) || actual.Ground.Accepted != (AcceptedAuthority{}) {
				t.Fatalf("late window retained authority: %+v", actual)
			}
		}
		stale := refusal(Stale, BuildConfigCause, Changed, "any diagnostic")
		finished, err := v.finishRuntimeObservation(t.Context(), map[Subject]Fingerprint{subject: fp}, map[Subject]runtimeinput.State{subject: state}, map[Subject]Verdict{subject: stale})
		if err != nil || finished[subject] != v.judgmentFor(subject, stale) {
			t.Fatalf("late window overrode prior staleness: %+v %v", finished, err)
		}
	}
}

func TestJudgmentGuardConditions(t *testing.T) {
	v, subject, base, state := judgmentFixture(t)
	cl := v.facts.maximal[subject]
	for _, tc := range []struct {
		name   string
		change func(*Fingerprint, *runtimeinput.State)
		cause  Cause
	}{
		{"missing toolchain", func(f *Fingerprint, _ *runtimeinput.State) { f.Guards.Toolchain = "" }, Cause{Kind: ToolchainCause, Condition: Missing}},
		{"changed toolchain", func(f *Fingerprint, _ *runtimeinput.State) { f.Guards.Toolchain = "other" }, Cause{Kind: ToolchainCause, Condition: Changed}},
		{"missing digest", func(f *Fingerprint, _ *runtimeinput.State) { f.RuntimeDigest = "" }, Cause{Kind: RuntimeInputsCause, Condition: Missing}},
		{"changed digest", func(f *Fingerprint, _ *runtimeinput.State) { f.RuntimeDigest = "other" }, Cause{Kind: RuntimeInputsCause, Condition: Changed}},
		{"unavailable runtime", func(_ *Fingerprint, r *runtimeinput.State) { r.OK = false }, Cause{Kind: RuntimeInputsCause, Condition: Unavailable}},
		{"missing core", func(f *Fingerprint, _ *runtimeinput.State) { f.MaximalClosure = "" }, Cause{Kind: ClosureCause, Condition: Missing}},
		{"changed core", func(f *Fingerprint, _ *runtimeinput.State) { f.MaximalClosure = "other" }, Cause{Kind: ClosureCause, Condition: Changed}},
		{"unsupported endpoint", func(f *Fingerprint, _ *runtimeinput.State) {
			f.InertTestVariantApplicability = InertTestVariantApplicability{Strategy: "unknown", TestVariantClosure: "tests"}
		}, Cause{Kind: TestVariantsCause, Condition: Unsupported}},
		{"missing strategy", func(f *Fingerprint, _ *runtimeinput.State) { f.DynamicStateStrategy = "" }, Cause{Kind: DynamicStateStrategyCause, Condition: Missing}},
		{"unsupported strategy", func(f *Fingerprint, _ *runtimeinput.State) { f.DynamicStateStrategy = "unknown" }, Cause{Kind: DynamicStateStrategyCause, Condition: Unsupported}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fp, rt := base, state
			tc.change(&fp, &rt)
			got := decide(fp, cl, v.facts.guards, rt, CodeResult, testPurityAuthority(true))
			if got.Status != Stale || got.Ground.Cause != tc.cause || got.Ground.Accepted != (AcceptedAuthority{}) {
				t.Fatalf("guard judgment = %+v, want %+v", got, tc.cause)
			}
		})
	}
}

func TestJudgmentBatchEqualsSingleAndSibling(t *testing.T) {
	v, subject, fp, _ := judgmentFixture(t)
	other := Subject{Package: subject.Package, Symbol: "G"}
	v.subjects = append(v.subjects, other)
	v.facts.maximal[other] = v.facts.maximal[subject]
	recorded := map[Subject]Fingerprint{subject: fp, other: fp}
	batch, err := v.CheckObservedBatch(t.Context(), recorded)
	if err != nil {
		t.Fatal(err)
	}
	for s, rec := range recorded {
		single, err := v.CheckObserved(t.Context(), rec, s)
		if err != nil || single != batch[s] {
			t.Fatalf("single/batch disagree: %+v / %+v: %v", single, batch[s], err)
		}
		sibling, err := v.Sibling([]Subject{s, s})
		if err != nil {
			t.Fatal(err)
		}
		projected, err := sibling.CheckObserved(t.Context(), rec, s)
		if err != nil || projected != single {
			t.Fatalf("sibling lost ground: %+v / %+v: %v", projected, single, err)
		}
	}
	if batch[subject].Status != Valid || batch[other].Status != Unverifiable {
		t.Fatalf("fixture did not distinguish exact subject support: %+v", batch)
	}
}

func TestJudgmentApplicabilityNeedsCurrentProofAndOriginalSupport(t *testing.T) {
	for _, tc := range []struct {
		name     string
		current  closure.Observability
		original string
		valid    bool
	}{
		{"current derivation", closure.Observability{Observable: true, OutcomeMethod: outcome.Method}, "supported", true},
		{"no current outcome inventory", closure.Observability{Observable: true}, "supported", false},
		{"current proof refused", closure.Observability{Reason: "opaque refusal"}, "supported", false},
		{"current proof cannot supply original support", closure.Observability{Observable: true, OutcomeMethod: outcome.Method}, "identity-only", false},
		{"current proof cannot supply missing capture", closure.Observability{Observable: true, OutcomeMethod: outcome.Method}, "absent", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, subject, fp, _ := judgmentFixture(t)
			fp.InertTestVariantApplicability = InertTestVariantApplicability{Strategy: InertTestVariantExtension, TestVariantClosure: fp.TestVariantClosure}
			v.observable = map[Subject]closure.Observability{subject: tc.current}
			if tc.original == "absent" {
				fp.RuntimeInputs, fp.RuntimeDigest = "", ""
			} else if tc.original == "identity-only" {
				// Preserve a readable manifest and matching digest. Removing the
				// entire manifest would let the independent nonempty-manifest
				// guard hide a missing outcome-support admission check.
				fp.RuntimeInputs = base64.RawURLEncoding.EncodeToString([]byte(`{"v":4}`))
				state, err := runtimeinput.Current(t.Context(), fp.RuntimeInputs, t.TempDir(), nil)
				if err != nil || !state.OK || state.Unverifiable {
					t.Fatalf("identity-only control is not usable guard evidence: %+v %v", state, err)
				}
				fp.RuntimeDigest = state.Digest
				v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) { return state, nil }
			}
			got, err := v.CheckObserved(t.Context(), fp, subject)
			if err != nil {
				t.Fatal(err)
			}
			a := got.Ground.Accepted
			if (got.Status == Valid) != tc.valid || a.Observation.CurrentApplicability != tc.valid {
				t.Fatalf("applicability authority = %+v", got)
			}
			if tc.valid {
				if len(v.applicabilityChecks) != 1 || a.Applicability != fp.InertTestVariantApplicability || a.Observation.ProofStrategy != fp.ObservationProof.Strategy {
					t.Fatalf("lost producing or current obligations: %+v %+v", got, v.applicabilityChecks)
				}
			} else if a.Observation != (ObservationAuthority{}) || a.Applicability != (InertTestVariantApplicability{}) || len(v.applicabilityChecks) != 0 {
				t.Fatalf("refused extension gained authority: %+v %+v", got, v.applicabilityChecks)
			}
		})
	}
}
