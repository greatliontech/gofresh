package gofresh

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
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
				MaximalClosure: "C",
				Guards:         guard.Guards{Toolchain: "tc", BuildConfig: "bc", Machine: "m", RuntimeConfig: "rc"},
				RuntimeInputs:  "MANIFEST",
				RuntimeDigest:  "D",
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
		{"closure missing", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.MaximalClosure = ""
		}, Measurement, false, Stale, "closure"},
		{"closure both empty", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.MaximalClosure = ""
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
		{"closure unverifiable, pure overrides", func(_ *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.Unverifiable = true
		}, Measurement, true, Valid, ""},
		{"runtime unverifiable, not pure", func(_ *Fingerprint, _ *closure.Closure, _ *guard.Guards, r *runtimeinput.State) {
			r.Unverifiable = true
			r.Reason = "unbounded input"
		}, Measurement, false, Unverifiable, "unbounded input"},
		{"runtime unverifiable, pure overrides", func(_ *Fingerprint, _ *closure.Closure, _ *guard.Guards, r *runtimeinput.State) {
			r.Unverifiable = true
		}, Measurement, true, Valid, ""},
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
		rec := Fingerprint{MaximalClosure: recCl, Guards: g, RuntimeInputs: manifest, RuntimeDigest: "D"}
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

func TestFingerprintDataShape(t *testing.T) {
	typeOf := reflect.TypeFor[Fingerprint]()
	want := []string{"MaximalClosure", "Refinement", "ObservationAssertion", "ObservationProof", "Guards", "PurityAssertion", "RuntimeInputs", "RuntimeDigest", "ResultKind"}
	if typeOf.Kind() != reflect.Struct || typeOf.NumField() != len(want) {
		t.Fatalf("Fingerprint shape = %s with %d fields, want data struct with %d fields", typeOf.Kind(), typeOf.NumField(), len(want))
	}
	for i, name := range want {
		field := typeOf.Field(i)
		if field.Name != name || !field.IsExported() {
			t.Fatalf("Fingerprint field %d = %s exported=%v, want exported %s", i, field.Name, field.IsExported(), name)
		}
	}
	if typeOf.NumMethod() != 0 || reflect.PointerTo(typeOf).NumMethod() != 0 {
		t.Fatal("Fingerprint carries behavior rather than data only")
	}
}

func TestObservationRTAVersion(t *testing.T) {
	if ObservationRTA != "gofresh/observation-rta@3" {
		t.Fatalf("ObservationRTA = %q, want fresh-mutation proof semantics", ObservationRTA)
	}
}

func TestPropCommitIdentityAbsent(t *testing.T) {
	typeOf := reflect.TypeFor[Fingerprint]()
	for i := 0; i < typeOf.NumField(); i++ {
		if strings.Contains(strings.ToLower(typeOf.Field(i).Name), "commit") {
			t.Fatalf("fingerprint validity surface contains commit identity field %s", typeOf.Field(i).Name)
		}
	}
}

func TestAssumePureInputShape(t *testing.T) {
	typeOf := reflect.TypeOf(WithAssumePure)
	wantPredicate := reflect.TypeFor[func(Subject) bool]()
	if typeOf.NumIn() != 1 || typeOf.In(0) != wantPredicate || typeOf.NumOut() != 1 || typeOf.Out(0) != reflect.TypeFor[Option]() {
		t.Fatalf("WithAssumePure type = %s, want func(func(Subject) bool) Option", typeOf)
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
	fp, err := e.Capture(context.Background(), subj, ".")
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	v, err := e.Check(context.Background(), fp, subj, ".")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v.Status != Valid {
		t.Errorf("round-trip: got %s (%s), want valid", v.Status, v.Reason)
	}
	// The same recorded fingerprint checked against a different subject (Adder.Ptr
	// has a different closure) is stale on the closure guard.
	other := Subject{Package: methodPkg, Symbol: "Adder.Ptr"}
	v2, err := e.Check(context.Background(), fp, other, ".")
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
	v3, err := e.Check(context.Background(), bad, subj, ".")
	if err != nil {
		t.Fatalf("Check malformed manifest: %v", err)
	}
	if v3.Status != Stale || v3.Reason != "runtimeinputs" {
		t.Errorf("malformed manifest: got {%s %q}, want {stale runtimeinputs}", v3.Status, v3.Reason)
	}
}

// TestBuildFlagsAffectVerdict pins that WithBuildFlags threads into the buildconfig
// guard end to end: a fingerprint captured with no build flags is stale on
// buildconfig when checked by an engine that used one, so a build-invocation change
// is caught.
func TestBuildFlagsAffectVerdict(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	subj := Subject{Package: methodPkg, Symbol: "Adder.Value"}
	plain, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fp, err := plain.Capture(context.Background(), subj, ".") // captured with no build inputs
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	tagged, err := New(WithBuildFlags("-tags=integration"))
	if err != nil {
		t.Fatalf("New tagged: %v", err)
	}
	v, err := tagged.Check(context.Background(), fp, subj, ".")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v.Status != Stale || v.Reason != "buildconfig" {
		t.Errorf("build-input change: got {%s %q}, want {stale buildconfig}", v.Status, v.Reason)
	}
}

func TestBuildInputsRejectFlags(t *testing.T) {
	if _, err := New(WithBuildInputs("-race")); err == nil || !strings.Contains(err.Error(), "WithBuildFlags") {
		t.Fatalf("flag-shaped opaque input accepted: %v", err)
	}
}

func TestBuildFlagsRejectOverlay(t *testing.T) {
	flags := []string{"-overlay=overlay.json"}
	if _, err := New(WithBuildFlags(flags...)); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("engine accepted overlay: %v", err)
	}
	if _, err := ScanPureDirectivesInWithBuildFlags(t.TempDir(), flags, "example.com/p"); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("purity scanner accepted overlay: %v", err)
	}
}

// TestBuildFlagsSelectSourceAndPurity pins build-selection coherence across the
// closure and purity surfaces. The same tag that produced the result selects every
// analyzed declaration; an unselected file cannot contribute code or confer purity.
func TestBuildFlagsSelectSourceAndPurity(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	tmp := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/tagged\n\ngo 1.26\n")
	write("selected_default.go", "//go:build !special\n\npackage tagged\n\n//gofresh:pure\nfunc Selected() int { return 1 }\n")
	write("selected_special.go", "//go:build special\n\npackage tagged\n\nfunc Selected() int { return 2 }\n")

	const pkg = "example.com/tagged"
	flags := []string{"-tags=special"}
	defaultPure, err := ScanPureDirectivesIn(tmp, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !defaultPure(Subject{Package: pkg, Symbol: "Selected"}) {
		t.Fatal("default build did not find its purity directive")
	}
	specialPure, err := ScanPureDirectivesInWithBuildFlags(tmp, flags, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if specialPure(Subject{Package: pkg, Symbol: "Selected"}) {
		t.Fatal("unselected default file conferred purity on the special build")
	}

	recorded, err := New(WithDir(tmp), WithBuildFlags(flags...))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: pkg, Symbol: "Selected"}
	fp, err := recorded.Capture(context.Background(), subject, tmp)
	if err != nil {
		t.Fatal(err)
	}
	write("selected_special.go", "//go:build special\n\npackage tagged\n\nfunc Selected() int { return 3 }\n")
	current, err := New(WithDir(tmp), WithBuildFlags(flags...))
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := current.Check(context.Background(), fp, subject, tmp)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" {
		t.Fatalf("selected source edit = {%s %q}, want {stale closure}", verdict.Status, verdict.Reason)
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
	fp, err := e.CaptureFor(context.Background(), subj, ".", Measurement)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if v, err := e.Check(context.Background(), fp, subj, "."); err != nil {
		t.Fatalf("Check: %v", err)
	} else if v.Status != Unverifiable {
		t.Errorf("default: got %s, want unverifiable (closure reaches file I/O)", v.Status)
	}

	pure, err := New(WithAssumePure(func(s Subject) bool { return s == subj }))
	if err != nil {
		t.Fatalf("New pure: %v", err)
	}
	pureFP, err := pure.CaptureFor(context.Background(), subj, ".", Measurement)
	if err != nil {
		t.Fatalf("Capture pure: %v", err)
	}
	if pureFP.PurityAssertion != "caller assertion" {
		t.Fatalf("purity assertion = %q, want attributable caller assertion", pureFP.PurityAssertion)
	}
	if v, err := pure.Check(context.Background(), fp, subj, "."); err != nil {
		t.Fatalf("Check unrecorded pure: %v", err)
	} else if v.Status != Unverifiable {
		t.Errorf("unrecorded assume-pure: got %s, want unverifiable", v.Status)
	}
	if v, err := pure.Check(context.Background(), pureFP, subj, "."); err != nil {
		t.Fatalf("Check pure: %v", err)
	} else if v.Status != Valid {
		t.Errorf("assume-pure: got %s (%s), want valid", v.Status, v.Reason)
	}
}

// TestWithDirOutOfTree pins the explicit tree root: an engine rooted at a
// directory the process does not run inside fingerprints that tree's
// subjects — the analyzed tree is an input, never a cwd coupling.
func TestWithDirOutOfTree(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	tmp := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/tiny\n\ngo 1.26\n")
	write("tiny.go", "package tiny\n\n//gofresh:pure\nfunc Add(a, b int) int { return a + b }\n")
	write("tiny_test.go", "package tiny\n\nimport \"testing\"\n\n//gofresh:pure\nfunc TestAdd(t *testing.T) {\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal(\"sum\")\n\t}\n}\n")

	e, err := New(WithDir(tmp))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	subj := Subject{Package: "example.com/tiny", Symbol: "TestAdd"}
	fp, err := e.Capture(context.Background(), subj, tmp)
	if err != nil {
		t.Fatalf("Capture out of tree: %v", err)
	}
	v, err := e.Check(context.Background(), fp, subj, tmp)
	if err != nil || v.Status != Valid {
		t.Fatalf("round trip = %+v, %v", v, err)
	}
	// The directive scanner honors the same root.
	pred, err := ScanPureDirectivesIn(tmp, "example.com/tiny")
	if err != nil {
		t.Fatalf("ScanPureDirectivesIn: %v", err)
	}
	if !pred(Subject{Package: "example.com/tiny", Symbol: "Add"}) {
		t.Fatal("out-of-tree directive not honored")
	}
}

func TestDefaultDirIsFrozenAtEngineConstruction(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New()
	if err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.Chdir(other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	if engine.dir != original {
		t.Fatalf("default engine dir after chdir = %q, want frozen %q", engine.dir, original)
	}
}

// TestWithDirCoherence pins the one-tree rule: an engine rooted somewhere
// refuses guard capture in a different tree — an incoherent fingerprint
// (closure from one tree, environment from another) is never produced.
func TestWithDirCoherence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := New(WithDir(dir))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := e.Capture(context.Background(), Subject{Package: "example.com/x", Symbol: "F"}, t.TempDir()); err == nil || !strings.Contains(err.Error(), "one tree per fingerprint") {
		t.Fatalf("incoherent dirs accepted: %v", err)
	}
}

func TestDefaultDirCoherence(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.coherentDir(t.TempDir()); err == nil || !strings.Contains(err.Error(), "one tree per fingerprint") {
		t.Fatalf("default engine accepted guards from another tree: %v", err)
	}
}

func TestWithDirCoherenceResolvesSymlinks(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base")
	other := filepath.Join(root, "other")
	child := filepath.Join(other, "child")
	for _, dir := range []string{base, child} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join("..", "other", "child"), filepath.Join(base, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	engineDir := filepath.Join(base, "link") + string(os.PathSeparator) + ".."
	e, err := New(WithDir(engineDir))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.coherentDir(base); err == nil || !strings.Contains(err.Error(), "one tree per fingerprint") {
		t.Fatalf("symlink-divergent trees accepted: %v", err)
	}
}
