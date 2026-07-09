package gofresh

import (
	"os/exec"
	"testing"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// TestDecide exhaustively pins the pure verdict function (REQ-fresh-verdict,
// REQ-fresh-sound): the base state is valid, and each perturbation drives exactly
// one verdict. It isolates the guard-set policy (a measurement-guard drift is stale
// for a Measurement, valid for a CodeResult) and the purity override.
func TestDecide(t *testing.T) {
	base := func() (Fingerprint, closure.Closure, guard.Guards, runtimeinput.State) {
		return Fingerprint{
				Closure:       "C",
				Guards:        guard.Guards{Toolchain: "tc", BuildConfig: "bc", Machine: "m", RuntimeConfig: "rc"},
				RuntimeInputs: "MANIFEST",
				RuntimeDigest: "D",
			},
			closure.Closure{Hash: "C"},
			guard.Guards{Toolchain: "tc", BuildConfig: "bc", Machine: "m", RuntimeConfig: "rc"},
			runtimeinput.State{Digest: "D", OK: true}
	}

	tests := []struct {
		name     string
		mutate   func(*Fingerprint, *closure.Closure, *guard.Guards, *runtimeinput.State)
		kind     Kind
		pure     bool
		want     Status
		wantReas string
	}{
		{"all clean", nil, Measurement, false, Valid, ""},
		{"closure mismatch", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) { c.Hash = "C2" }, Measurement, false, Stale, "closure"},
		{"closure missing", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) { f.Closure = "" }, Measurement, false, Stale, "closure"},
		{"closure both empty", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.Closure = ""
			c.Hash = "" // an unevaluable closure is not proof, so never valid (REQ-fresh-sound)
		}, Measurement, false, Stale, "closure"},
		{"runtime digest mismatch", func(_ *Fingerprint, _ *closure.Closure, _ *guard.Guards, r *runtimeinput.State) { r.Digest = "D2" }, Measurement, false, Stale, "runtimeinputs"},
		{"runtime not OK", func(_ *Fingerprint, _ *closure.Closure, _ *guard.Guards, r *runtimeinput.State) { r.OK = false }, Measurement, false, Stale, "runtimeinputs"},
		{"runtime digest missing", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) { f.RuntimeDigest = "" }, Measurement, false, Stale, "runtimeinputs"},
		{"toolchain drift", func(_ *Fingerprint, _ *closure.Closure, g *guard.Guards, _ *runtimeinput.State) { g.Toolchain = "tc2" }, Measurement, false, Stale, "toolchain"},
		{"machine drift under Measurement", func(_ *Fingerprint, _ *closure.Closure, g *guard.Guards, _ *runtimeinput.State) { g.Machine = "m2" }, Measurement, false, Stale, "machine"},
		{"machine drift under CodeResult ignored", func(_ *Fingerprint, _ *closure.Closure, g *guard.Guards, _ *runtimeinput.State) { g.Machine = "m2" }, CodeResult, false, Valid, ""},
		{"closure unverifiable, not pure", func(_ *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.Unverifiable = true
			c.Reason = "reaches os.Open"
		}, Measurement, false, Unverifiable, "reaches os.Open"},
		{"closure unverifiable, pure overrides", func(_ *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) { c.Unverifiable = true }, Measurement, true, Valid, ""},
		{"runtime unverifiable, not pure", func(_ *Fingerprint, _ *closure.Closure, _ *guard.Guards, r *runtimeinput.State) {
			r.Unverifiable = true
			r.Reason = "unbounded input"
		}, Measurement, false, Unverifiable, "unbounded input"},
		{"runtime unverifiable, pure overrides", func(_ *Fingerprint, _ *closure.Closure, _ *guard.Guards, r *runtimeinput.State) { r.Unverifiable = true }, Measurement, true, Valid, ""},
		// An absent manifest is the caller's assertion that the run observed no
		// runtime inputs (REQ-inputs-absent-asserted) — the guard holds vacuously.
		{"no manifest, clean", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.RuntimeInputs = ""
			f.RuntimeDigest = ""
		}, Measurement, false, Valid, ""},
		// A digest without its manifest is corruption, not absence: the digest
		// proves the guard applied, so the recording is unevaluable — stale
		// (REQ-guard-completeness), never the vacuous hold above.
		{"digest without manifest", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.RuntimeInputs = ""
		}, Measurement, false, Stale, "runtimeinputs"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, cl, cur, rt := base()
			if tc.mutate != nil {
				tc.mutate(&rec, &cl, &cur, &rt)
			}
			got := decide(rec, cl, cur, rt, tc.kind, tc.pure)
			if got.Status != tc.want || got.Reason != tc.wantReas {
				t.Errorf("decide = {%s %q}, want {%s %q}", got.Status, got.Reason, tc.want, tc.wantReas)
			}
		})
	}
}

// FuzzDecideSound is a property witness for REQ-fresh-sound and
// REQ-inputs-evidence-not-proof: with the code guards holding and the closure hash
// matching, decide never returns Valid when the closure or the runtime inputs reach
// an unverifiable dependence and no purity override applies. Guards are fixed equal
// and non-empty so the property exercises the unverifiability branch, not a guard
// mismatch.
func FuzzDecideSound(f *testing.F) {
	f.Add("C", "C", true, false, "", false)
	f.Add("C", "C", false, false, "M", true)
	f.Fuzz(func(t *testing.T, recCl, curCl string, clUnver, pure bool, manifest string, rtUnver bool) {
		g := guard.Guards{Toolchain: "t", BuildConfig: "b"}
		rec := Fingerprint{Closure: recCl, Guards: g, RuntimeInputs: manifest, RuntimeDigest: "D"}
		cl := closure.Closure{Hash: curCl, Unverifiable: clUnver}
		rt := runtimeinput.State{Digest: "D", Unverifiable: rtUnver, OK: true}
		v := decide(rec, cl, g, rt, CodeResult, pure)
		if v.Status == Valid && !pure {
			if cl.Unverifiable || (rec.RuntimeInputs != "" && rt.Unverifiable) {
				t.Fatalf("sound violated: valid with an unverifiable dependence and no purity override (rec=%+v cl=%+v rt=%+v)", rec, cl, rt)
			}
		}
	})
}

// TestEngineNeverInfersPurity pins REQ-purity-responsibility: a default engine treats
// no subject as pure — purity is only ever an explicit input, never inferred.
func TestEngineNeverInfersPurity(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, s := range []Subject{{Package: "p", Symbol: "F"}, {Package: "p", Symbol: "T.M"}, {}} {
		if e.assumePure(s) {
			t.Errorf("default engine inferred purity for %+v", s)
		}
	}
}

const methodPkg = "github.com/greatliontech/gofresh/closure/fixtures/methodsubject"

// TestCaptureCheckRoundTrip pins the happy path end to end: a fingerprint captured
// for a pure subject is Valid when checked against the same tree, and the same
// fingerprint checked against a different subject's closure is stale. The subject is
// pure (reaches no external dependence) so the clean verdict is Valid, not
// Unverifiable.
func TestCaptureCheckRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	e, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	subj := Subject{Package: methodPkg, Symbol: "Adder.Value"}
	fp, err := e.Capture(subj, ".")
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	v, err := e.Check(fp, subj, ".", CodeResult)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v.Status != Valid {
		t.Errorf("round-trip: got %s (%s), want valid", v.Status, v.Reason)
	}
	// The same recorded fingerprint checked against a different subject (Adder.Ptr
	// has a different closure) is stale on the closure guard.
	other := Subject{Package: methodPkg, Symbol: "Adder.Ptr"}
	v2, err := e.Check(fp, other, ".", CodeResult)
	if err != nil {
		t.Fatalf("Check other: %v", err)
	}
	if v2.Status != Stale || v2.Reason != "closure" {
		t.Errorf("cross-subject: got {%s %q}, want {stale closure}", v2.Status, v2.Reason)
	}
	// A recorded manifest that cannot be re-evaluated is an unevaluable applicable
	// guard — Stale, never an error and never valid (REQ-guard-completeness).
	bad := fp
	bad.RuntimeInputs = "not a manifest"
	bad.RuntimeDigest = "D"
	v3, err := e.Check(bad, subj, ".", CodeResult)
	if err != nil {
		t.Fatalf("Check malformed manifest: %v", err)
	}
	if v3.Status != Stale || v3.Reason != "runtimeinputs" {
		t.Errorf("malformed manifest: got {%s %q}, want {stale runtimeinputs}", v3.Status, v3.Reason)
	}
}

// TestBuildInputsAffectVerdict pins that WithBuildInputs threads into the buildconfig
// guard end to end: a fingerprint captured with no build inputs is stale on
// buildconfig when checked by an engine that used a build flag, so a build-invocation
// change is caught.
func TestBuildInputsAffectVerdict(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	subj := Subject{Package: methodPkg, Symbol: "Adder.Value"}
	plain, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fp, err := plain.Capture(subj, ".") // captured with no build inputs
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	tagged, err := New(WithBuildInputs("-tags=integration"))
	if err != nil {
		t.Fatalf("New tagged: %v", err)
	}
	v, err := tagged.Check(fp, subj, ".", CodeResult)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v.Status != Stale || v.Reason != "buildconfig" {
		t.Errorf("build-input change: got {%s %q}, want {stale buildconfig}", v.Status, v.Reason)
	}
}

// TestAssumePureOverride pins REQ-purity-override end to end: a subject whose closure
// reaches an unverifiable dependence is Unverifiable by default, and Valid when the
// engine is given a purity predicate that asserts it.
func TestAssumePureOverride(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	subj := Subject{Package: "github.com/greatliontech/gofresh/closure/fixtures/harnessroot", Symbol: "BenchmarkProd"}

	e, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fp, err := e.Capture(subj, ".")
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if v, err := e.Check(fp, subj, ".", Measurement); err != nil {
		t.Fatalf("Check: %v", err)
	} else if v.Status != Unverifiable {
		t.Errorf("default: got %s, want unverifiable (closure reaches file I/O)", v.Status)
	}

	pure, err := New(WithAssumePure(func(s Subject) bool { return s == subj }))
	if err != nil {
		t.Fatalf("New pure: %v", err)
	}
	if v, err := pure.Check(fp, subj, ".", Measurement); err != nil {
		t.Fatalf("Check pure: %v", err)
	} else if v.Status != Valid {
		t.Errorf("assume-pure: got %s (%s), want valid", v.Status, v.Reason)
	}
}
