package gofresh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/closure/testvariant"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/internal/outcome"
	"github.com/greatliontech/gofresh/runtimeinput"
	"github.com/greatliontech/stipulator/stipulate/structural"
)

// TestDecide exhaustively pins the pure verdict function (REQ-fresh-verdict,
// REQ-fresh-sound): the base state is valid, and each perturbation drives exactly
// one verdict. It isolates the guard-set policy (a measurement-guard drift is stale
// for a Measurement, valid for a CodeResult) and the purity override.
func TestDecide(t *testing.T) {
	base := func() (Fingerprint, closure.Closure, guard.Guards, runtimeinput.State) {
		return Fingerprint{
				MaximalClosure:       "C",
				ToolchainContent:     "stdlib",
				TestVariantClosure:   "T",
				Guards:               guard.Guards{Toolchain: "tc", BuildConfig: "bc", Machine: "m", RuntimeConfig: "rc"},
				DynamicStateStrategy: DynamicStateStrategy,
				RuntimeInputs:        "MANIFEST",
				RuntimeDigest:        "D",
			},
			closure.Closure{Hash: "C", TestVariants: "T", ToolchainContent: "stdlib"},
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
		{"policy movement preserves independent purity", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.AdmissionPolicy = "old"
			c.AdmissionPolicy = "new"
			c.Unverifiable = true
		}, CodeResult, true, Valid, ""},
		{"toolchain content drift", func(_ *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.ToolchainContent = "other"
		}, CodeResult, false, Stale, "toolchain content"},
		{"toolchain content drift under purity", func(_ *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.ToolchainContent = "other"
		}, CodeResult, true, Stale, "toolchain content"},
		{"historical content absent", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.ToolchainContent = ""
		}, CodeResult, true, Unverifiable, "toolchain content evidence unavailable"},
		{"current content unavailable", func(_ *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.ToolchainContent = ""
		}, CodeResult, false, Unverifiable, "toolchain content evidence unavailable"},
		{"runtime drift before missing content", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, r *runtimeinput.State) {
			f.ToolchainContent = ""
			r.Digest = "moved"
		}, CodeResult, true, Stale, "runtimeinputs"},
		{"closure mismatch", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) { c.Hash = "C2" }, Measurement, false, Stale, "closure"},
		{"closure missing", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.MaximalClosure = ""
		}, Measurement, false, Stale, "closure"},
		{"closure both empty", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.MaximalClosure = ""
			c.Hash = "" // an unevaluable closure is not proof, so never valid (REQ-fresh-sound)
		}, Measurement, false, Stale, "closure"},
		{"test variant mismatch", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.TestVariants = "T2"
		}, Measurement, false, Stale, "test variants"},
		// A recorded compartment that predates the partition is absence of
		// proof, never valid — even when the current compartment is also
		// unevaluable (REQ-closure-test-variant-identity fail-closed arm).
		{"test variant missing on pre-partition record", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.TestVariantClosure = ""
			c.TestVariants = ""
		}, Measurement, false, Stale, "test variants"},
		// Core drift wins over compartment drift: the compartment discriminates
		// only inside an unchanged core (REQ-closure-test-variant-identity).
		{"core and compartment both drifted", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.Hash = "C2"
			c.TestVariants = "T2"
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
		// An absent manifest supplies no observation or caller assertion. Here
		// independent source evidence needs no runtime-input guard.
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
			got := decide(rec, cl, cur, rt, tc.kind, testPurityAuthority(tc.pure))
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
	f.Add("C", "C", "T", "T", "stdlib", "stdlib", true, false, "", false)
	f.Add("C", "C", "T", "T2", "stdlib", "stdlib", false, false, "M", true)
	f.Add("C", "C", "", "T", "stdlib", "changed", false, false, "M", false)
	f.Add("C", "C", "T", "T", "", "stdlib", false, true, "M", false)
	f.Fuzz(func(t *testing.T, recCl, curCl, recTv, curTv, recStd, curStd string, clUnver, pure bool, manifest string, rtUnver bool) {
		g := guard.Guards{Toolchain: "t", BuildConfig: "b"}
		rec := Fingerprint{MaximalClosure: recCl, TestVariantClosure: recTv, ToolchainContent: recStd, DynamicStateStrategy: DynamicStateStrategy, Guards: g, RuntimeInputs: manifest, RuntimeDigest: "D"}
		cl := closure.Closure{Hash: curCl, TestVariants: curTv, ToolchainContent: curStd, Unverifiable: clUnver}
		rt := runtimeinput.State{Digest: "D", Unverifiable: rtUnver, OK: true}
		v := decide(rec, cl, g, rt, CodeResult, testPurityAuthority(pure))
		if v.Status == Valid && (recStd == "" || recStd != curStd) {
			t.Fatal("valid with missing or changed toolchain content")
		}
		if v.Status == Valid && !pure {
			if cl.Unverifiable || (rec.RuntimeInputs != "" && rt.Unverifiable) {
				t.Fatalf("sound violated: valid with an unverifiable dependence and no purity override (rec=%+v cl=%+v rt=%+v)", rec, cl, rt)
			}
		}
		// The compartment is evidence like the core: valid requires a
		// non-empty recorded compartment equal to the current one
		// (REQ-closure-test-variant-identity).
		if v.Status == Valid && (rec.TestVariantClosure == "" || rec.TestVariantClosure != cl.TestVariants) {
			t.Fatalf("sound violated: valid across test-variant compartment drift (rec=%+v cl=%+v)", rec, cl)
		}
	})
}

// TestEngineNeverInfersPurity pins REQ-purity-responsibility: a default engine treats
// no subject as pure — purity is only ever an explicit input, never inferred.
func TestEngineNeverInfersPurity(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	e, err := newEngine()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, s := range []Subject{{Package: "p", Symbol: "F"}, {Package: "p", Symbol: "T.M"}, {}} {
		if e.assumePure(s) {
			t.Errorf("default engine inferred purity for %+v", s)
		}
	}
}

// TestFingerprintDataShape pins the fingerprint as exported data — every
// constituent an exported field of the stated type, in order — whose
// behaviour is its record form and explicit effective-compartment accessor:
// the encoder and validity ladder on the value, the decoder on the pointer
// (REQ-fresh-fingerprint-data, REQ-fresh-fingerprint-record,
// REQ-fresh-observation-data).
func TestFingerprintDataShape(t *testing.T) {
	typeOf := reflect.TypeFor[Fingerprint]()
	want := []struct {
		name string
		typ  reflect.Type
	}{
		{"MaximalClosure", reflect.TypeFor[string]()}, {"ToolchainContent", reflect.TypeFor[string]()}, {"AdmissionPolicy", reflect.TypeFor[string]()}, {"TestVariantClosure", reflect.TypeFor[string]()},
		{"InertTestVariantApplicability", reflect.TypeFor[InertTestVariantApplicability]()},
		{"ObservationAssertion", reflect.TypeFor[string]()}, {"ObservationProof", reflect.TypeFor[ObservationProof]()},
		{"Guards", reflect.TypeFor[guard.Guards]()}, {"PurityAssertion", reflect.TypeFor[string]()},
		{"DynamicStateVouches", reflect.TypeFor[string]()}, {"SingleSubjectDischarges", reflect.TypeFor[string]()},
		{"PackageProcessDischarges", reflect.TypeFor[string]()}, {"DynamicStateStrategy", reflect.TypeFor[string]()},
		{"ClosureStrategy", reflect.TypeFor[string]()}, {"RuntimeInputs", reflect.TypeFor[string]()},
		{"RuntimeDigest", reflect.TypeFor[string]()}, {"ResultKind", reflect.TypeFor[Kind]()},
	}
	if typeOf.Kind() != reflect.Struct || typeOf.NumField() != len(want) {
		t.Fatalf("Fingerprint shape = %s with %d fields, want data struct with %d fields", typeOf.Kind(), typeOf.NumField(), len(want))
	}
	for i, w := range want {
		field := typeOf.Field(i)
		if field.Name != w.name || !field.IsExported() || field.Type != w.typ || field.Tag != "" {
			t.Fatalf("Fingerprint field %d = %s %s exported=%v tag=%q, want exported %s %s untagged", i, field.Name, field.Type, field.IsExported(), field.Tag, w.name, w.typ)
		}
	}
	methods := func(typ reflect.Type) []string {
		var names []string
		for i := 0; i < typ.NumMethod(); i++ {
			names = append(names, typ.Method(i).Name)
		}
		return names
	}
	if got := methods(typeOf); !reflect.DeepEqual(got, []string{"EffectiveTestVariantClosure", "MarshalJSON", "Validate"}) {
		t.Fatalf("Fingerprint value methods = %v, want record form and effective compartment", got)
	}
	if got := methods(reflect.PointerTo(typeOf)); !reflect.DeepEqual(got, []string{"EffectiveTestVariantClosure", "MarshalJSON", "UnmarshalJSON", "Validate"}) {
		t.Fatalf("Fingerprint pointer methods = %v, want record form and effective compartment", got)
	}
	structural.ExportedData[Subject](t,
		structural.FieldOf[string]("Package"),
		structural.FieldOf[string]("Symbol"),
	)
	structural.ExportedData[InertTestVariantApplicability](t,
		structural.FieldOf[string]("Strategy"),
		structural.FieldOf[string]("TestVariantClosure"),
	)
	structural.ExportedData[ObservationProof](t,
		structural.FieldOf[string]("Strategy"),
		structural.FieldOf[Subject]("Subject"),
		structural.FieldOf[bool]("Observable"),
		structural.FieldOf[string]("Reason"),
		structural.FieldOf[string]("Evidence"),
	)
	structural.ExportedData[guard.Guards](t,
		structural.FieldOf[string]("Toolchain"),
		structural.FieldOf[string]("BuildConfig"),
		structural.FieldOf[string]("Machine"),
		structural.FieldOf[string]("RuntimeConfig"),
	)
	structural.FunctionSignature[func(Fingerprint) string](t, Fingerprint.EffectiveTestVariantClosure)
	structural.FunctionSignature[func(Fingerprint) ([]byte, error)](t, Fingerprint.MarshalJSON)
	structural.FunctionSignature[func(Fingerprint) error](t, Fingerprint.Validate)
	structural.FunctionSignature[func(*Fingerprint, []byte) error](t, (*Fingerprint).UnmarshalJSON)
}

func TestObservationRTAVersion(t *testing.T) {
	if ObservationRTA != "gofresh/observation-rta@53" {
		t.Fatalf("ObservationRTA = %q, want content- and policy-bound proof evidence", ObservationRTA)
	}
}

func TestDynamicStateStrategyVersion(t *testing.T) {
	if DynamicStateStrategy != "gofresh/dynamic-state@44" {
		t.Fatalf("DynamicStateStrategy = %q, want the corrected SSA reachability derivation", DynamicStateStrategy)
	}
}

func TestClosureStrategyVersion(t *testing.T) {
	if ClosureStrategy != "gofresh/closure@1 gofresh/canonical-member@2 gofresh/variant-parse@2" {
		t.Fatalf("ClosureStrategy = %q, want the composition of the fold, canonical-member, and compartment derivations", ClosureStrategy)
	}
}

// Every capture path stamps the closure identity's derivation beside
// the hash, so a consumer keying a judgment to the identity can compare
// two records within one derivation (REQ-closure-identity-strategy).
func TestEveryCaptureStampsTheClosureStrategy(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := scanMemoModule(t)
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), scanMemoSubjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := view.Capture(context.Background(), scanMemoSubjects[0])
	if err != nil {
		t.Fatal(err)
	}
	if plain.ClosureStrategy != ClosureStrategy {
		t.Fatalf("Capture stamped closure strategy %q, want %q", plain.ClosureStrategy, ClosureStrategy)
	}
	batch, err := view.CaptureBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	observed, err := view.CaptureObservedBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for name, fps := range map[string]map[Subject]Fingerprint{"CaptureBatch": batch, "CaptureObservedBatch": observed} {
		if len(fps) != len(scanMemoSubjects) {
			t.Fatalf("%s returned %d fingerprints for %d subjects", name, len(fps), len(scanMemoSubjects))
		}
		for subject, fp := range fps {
			if fp.ClosureStrategy != ClosureStrategy {
				t.Fatalf("%s: %s stamped closure strategy %q, want %q", subject.Symbol, name, fp.ClosureStrategy, ClosureStrategy)
			}
		}
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
	typeOf := reflect.TypeOf(withAssumePure)
	wantPredicate := reflect.TypeFor[func(Subject) bool]()
	if typeOf.NumIn() != 1 || typeOf.In(0) != wantPredicate || typeOf.NumOut() != 1 || typeOf.Out(0) != reflect.TypeFor[option]() {
		t.Fatalf("withAssumePure type = %s, want func(func(Subject) bool) option", typeOf)
	}
}

const methodPkg = "github.com/greatliontech/gofresh/closure/fixtures/methodsubject"

// TestCaptureCheckRoundTrip pins the happy path end to end: a fingerprint captured
// for a pure subject is Valid when checked against the same tree, and the same
// fingerprint checked against a different subject's closure is stale. The subject is
// pure (reaches no external dependence) so the clean verdict is Valid, not
// Unverifiable.
func TestCaptureCheckRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	e, err := newEngine()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	subj := Subject{Package: methodPkg, Symbol: "Adder.Value"}
	fp, err := e.capture(context.Background(), subj, ".")
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	v, err := e.check(context.Background(), fp, subj, ".")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v.Status != Valid {
		t.Errorf("round-trip: got %s (%s), want valid", v.Status, v.Reason)
	}
	// The same recorded fingerprint checked against a different subject (Adder.Ptr
	// has a different closure) is stale on the closure guard.
	other := Subject{Package: methodPkg, Symbol: "Adder.Ptr"}
	v2, err := e.check(context.Background(), fp, other, ".")
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
	v3, err := e.check(context.Background(), bad, subj, ".")
	if err != nil {
		t.Fatalf("Check malformed manifest: %v", err)
	}
	if v3.Status != Stale || v3.Reason != "runtimeinputs" {
		t.Errorf("malformed manifest: got {%s %q}, want {stale runtimeinputs}", v3.Status, v3.Reason)
	}
}

// TestBuildFlagsAffectVerdict pins that withBuildFlags threads into the buildconfig
// guard end to end: a fingerprint captured with no build flags is stale on
// buildconfig when checked by an engine that used one, so a build-invocation change
// is caught.
func TestBuildFlagsAffectVerdict(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	subj := Subject{Package: methodPkg, Symbol: "Adder.Value"}
	plain, err := newEngine()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fp, err := plain.capture(context.Background(), subj, ".") // captured with no build inputs
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	tagged, err := newEngine(withBuildFlags("-tags=integration"))
	if err != nil {
		t.Fatalf("New tagged: %v", err)
	}
	v, err := tagged.check(context.Background(), fp, subj, ".")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v.Status != Stale || v.Reason != "buildconfig" {
		t.Errorf("build-input change: got {%s %q}, want {stale buildconfig}", v.Status, v.Reason)
	}
}

func TestBuildInputsRejectFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := newEngine(withBuildInputs("-race")); err == nil || !strings.Contains(err.Error(), "BuildFlags") {
		t.Fatalf("flag-shaped opaque input accepted: %v", err)
	}
}

func TestBuildFlagsRejectOverlay(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	flags := []string{"-overlay=overlay.json"}
	if _, err := newEngine(withBuildFlags(flags...)); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("engine accepted overlay: %v", err)
	}
	if _, err := ScanPureDirectives(t.TempDir(), os.Environ(), flags, "example.com/p"); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("purity scanner accepted overlay: %v", err)
	}
}

// TestBuildFlagsSelectSourceAndPurity pins build-selection coherence across the
// closure and purity surfaces. The same tag that produced the result selects every
// analyzed declaration; an unselected file cannot contribute code or confer purity.
func TestBuildFlagsSelectSourceAndPurity(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	defaultPure, err := scanPureDirectivesIn(tmp, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !defaultPure(Subject{Package: pkg, Symbol: "Selected"}) {
		t.Fatal("default build did not find its purity directive")
	}
	specialPure, err := ScanPureDirectives(tmp, os.Environ(), flags, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if specialPure(Subject{Package: pkg, Symbol: "Selected"}) {
		t.Fatal("unselected default file conferred purity on the special build")
	}

	recorded, err := newEngine(withDir(tmp), withBuildFlags(flags...))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: pkg, Symbol: "Selected"}
	fp, err := recorded.capture(context.Background(), subject, tmp)
	if err != nil {
		t.Fatal(err)
	}
	write("selected_special.go", "//go:build special\n\npackage tagged\n\nfunc Selected() int { return 3 }\n")
	current, err := newEngine(withDir(tmp), withBuildFlags(flags...))
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := current.check(context.Background(), fp, subject, tmp)
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
	if testing.Short() {
		t.Skip("runs the engine over the fixture corpus")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	subj := Subject{Package: "github.com/greatliontech/gofresh/closure/fixtures/harnessroot", Symbol: "BenchmarkProd"}

	e, err := newEngine()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fp, err := e.captureFor(context.Background(), subj, ".", Measurement)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if v, err := e.check(context.Background(), fp, subj, "."); err != nil {
		t.Fatalf("Check: %v", err)
	} else if v.Status != Unverifiable {
		t.Errorf("default: got %s, want unverifiable (closure reaches file I/O)", v.Status)
	}

	pure, err := newEngine(withAssumePure(func(s Subject) bool { return s == subj }))
	if err != nil {
		t.Fatalf("New pure: %v", err)
	}
	pureFP, err := pure.captureFor(context.Background(), subj, ".", Measurement)
	if err != nil {
		t.Fatalf("Capture pure: %v", err)
	}
	if pureFP.PurityAssertion != "caller assertion" {
		t.Fatalf("purity assertion = %q, want attributable caller assertion", pureFP.PurityAssertion)
	}
	if v, err := pure.check(context.Background(), fp, subj, "."); err != nil {
		t.Fatalf("Check unrecorded pure: %v", err)
	} else if v.Status != Unverifiable {
		t.Errorf("unrecorded assume-pure: got %s, want unverifiable", v.Status)
	}
	if v, err := pure.check(context.Background(), pureFP, subj, "."); err != nil {
		t.Fatalf("Check pure: %v", err)
	} else if v.Status != Valid {
		t.Errorf("assume-pure: got %s (%s), want valid", v.Status, v.Reason)
	}
}

// TestWithDirOutOfTree pins the explicit tree root: an engine rooted at a
// directory the process does not run inside fingerprints that tree's
// subjects — the analyzed tree is an input, never a cwd coupling.
func TestWithDirOutOfTree(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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

	e, err := newEngine(withDir(tmp))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	subj := Subject{Package: "example.com/tiny", Symbol: "TestAdd"}
	fp, err := e.capture(context.Background(), subj, tmp)
	if err != nil {
		t.Fatalf("Capture out of tree: %v", err)
	}
	v, err := e.check(context.Background(), fp, subj, tmp)
	if err != nil || v.Status != Valid {
		t.Fatalf("round trip = %+v, %v", v, err)
	}
	// The directive scanner honors the same root.
	pred, err := scanPureDirectivesIn(tmp, "example.com/tiny")
	if err != nil {
		t.Fatalf("ScanPureDirectives: %v", err)
	}
	if !pred(Subject{Package: "example.com/tiny", Symbol: "Add"}) {
		t.Fatal("out-of-tree directive not honored")
	}
}

func TestDefaultDirIsFrozenAtEngineConstruction(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine()
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
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := e.capture(context.Background(), Subject{Package: "example.com/x", Symbol: "F"}, t.TempDir()); err == nil || !strings.Contains(err.Error(), "one tree per fingerprint") {
		t.Fatalf("incoherent dirs accepted: %v", err)
	}
}

func TestDefaultDirCoherence(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	e, err := newEngine()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.coherentDir(t.TempDir()); err == nil || !strings.Contains(err.Error(), "one tree per fingerprint") {
		t.Fatalf("default engine accepted guards from another tree: %v", err)
	}
}

func TestWithDirCoherenceResolvesSymlinks(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	e, err := newEngine(withDir(engineDir))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.coherentDir(base); err == nil || !strings.Contains(err.Error(), "one tree per fingerprint") {
		t.Fatalf("symlink-divergent trees accepted: %v", err)
	}
}

// TestExternalDirectiveWithholdsReuse pins REQ-external-directive and
// REQ-external-precedence end to end: a subject carrying //gofresh:external is
// unverifiable "external directive" whenever its guards hold, a caller purity
// assertion confers nothing (and records no attribution), and a real source
// change still reports stale — externality never masks guard information.
func TestExternalDirectiveWithholdsReuse(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	write("go.mod", "module example.com/ext\n\ngo 1.26\n")
	write("ext.go", "package ext\n\n//gofresh:external\nfunc Reads() int { return 1 }\n")

	const pkg = "example.com/ext"
	subj := Subject{Package: pkg, Symbol: "Reads"}
	e, err := newEngine(withDir(tmp), withAssumePure(func(Subject) bool { return true }))
	if err != nil {
		t.Fatal(err)
	}
	fp, err := e.capture(context.Background(), subj, tmp)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if fp.PurityAssertion != "" {
		t.Fatalf("purity assertion on an external subject = %q, want none (REQ-external-precedence)", fp.PurityAssertion)
	}
	if v, err := e.check(context.Background(), fp, subj, tmp); err != nil {
		t.Fatalf("Check: %v", err)
	} else if v.Status != Unverifiable || v.Reason != "external directive" {
		t.Fatalf("verdict = {%s %q}, want {unverifiable external directive}", v.Status, v.Reason)
	}

	// A source change stales — externality withholds reuse, never guard info.
	write("ext.go", "package ext\n\n//gofresh:external\nfunc Reads() int { return 2 }\n")
	changed, err := newEngine(withDir(tmp))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := changed.check(context.Background(), fp, subj, tmp); err != nil {
		t.Fatalf("Check changed: %v", err)
	} else if v.Status != Stale || v.Reason != "closure" {
		t.Fatalf("changed-source verdict = {%s %q}, want {stale closure}", v.Status, v.Reason)
	}
}

// TestExternalDirectiveConflictRefused pins the contradiction refusal
// (REQ-external-precedence): one declaration carrying both //gofresh:pure and
// //gofresh:external fails observation rather than picking a winner.
func TestExternalDirectiveConflictRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module example.com/conflict\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "c.go"), []byte("package conflict\n\n//gofresh:pure\n//gofresh:external\nfunc Torn() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := newEngine(withDir(tmp))
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.capture(context.Background(), Subject{Package: "example.com/conflict", Symbol: "Torn"}, tmp)
	if err == nil || !strings.Contains(err.Error(), "gofresh:pure and //gofresh:external") {
		t.Fatalf("Capture = %v, want the contradiction refusal", err)
	}
}

// TestExternalDirectiveImmuneToObservationEvidence pins the observation half of
// REQ-external-precedence at the verdict function: completed observation
// evidence upgrades inferred closure unverifiability, never a declared
// external subject.
func TestExternalDirectiveImmuneToObservationEvidence(t *testing.T) {
	rec := Fingerprint{
		MaximalClosure:   "h",
		ToolchainContent: "stdlib",
		Guards:           guard.Guards{Toolchain: "tc", BuildConfig: "bc"},
		RuntimeInputs:    "manifest",
		RuntimeDigest:    "d",
	}
	rt := runtimeinput.State{Manifest: "manifest", Digest: "d", OK: true}
	inferred := closure.Closure{Hash: "h", ToolchainContent: "stdlib", Unverifiable: true, Reason: "reaches os.Open"}
	observed := ObservationAuthority{Assertion: "caller assertion", ProofStrategy: ObservationRTA, OutcomeMethod: "gofresh/immutable-environment@1"}
	if v := decideAfterClosureObserved(rec, inferred, rec.Guards, rt, CodeResult, PurityAuthority{}, observed); v.Status != Valid {
		t.Fatalf("observed inferred unverifiability = {%s %q}, want valid (the upgrade this test contrasts)", v.Status, v.Reason)
	}
	declared := closure.Closure{Hash: "h", ToolchainContent: "stdlib", Unverifiable: true, External: true, Reason: "external directive"}
	if v := decideAfterClosureObserved(rec, declared, rec.Guards, rt, CodeResult, PurityAuthority{}, observed); v.Status != Unverifiable || v.Reason != "external directive" {
		t.Fatalf("observed external subject = {%s %q}, want {unverifiable external directive}", v.Status, v.Reason)
	}
	if v := decideAfterClosureObserved(rec, declared, rec.Guards, rt, CodeResult, testPurityAuthority(true), observed); v.Status != Unverifiable || v.Reason != "external directive" {
		t.Fatalf("pure external subject = {%s %q}, want {unverifiable external directive}", v.Status, v.Reason)
	}
}

// TestExternalDirectiveFixtureScan pins the scanner surface over the committed
// fixture package: exact-form directives on functions and methods mark their
// subjects, near-miss forms do not.
func TestExternalDirectiveFixtureScan(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/externaldirective"
	e, err := newEngine()
	if err != nil {
		t.Fatal(err)
	}
	for symbol, wantExternal := range map[string]bool{
		"Declared":        true,
		"T.Declared":      true,
		"NotDeclared":     false,
		"SpacedDirective": false,
		"T.NotDeclared":   false,
	} {
		subj := Subject{Package: pkg, Symbol: symbol}
		fp, err := e.capture(context.Background(), subj, ".")
		if err != nil {
			t.Fatalf("Capture %s: %v", symbol, err)
		}
		v, err := e.check(context.Background(), fp, subj, ".")
		if err != nil {
			t.Fatalf("Check %s: %v", symbol, err)
		}
		if wantExternal && (v.Status != Unverifiable || v.Reason != "external directive") {
			t.Errorf("%s = {%s %q}, want {unverifiable external directive}", symbol, v.Status, v.Reason)
		}
		if !wantExternal && v.Reason == "external directive" {
			t.Errorf("%s marked external without the directive", symbol)
		}
	}
}

// TestExternalDirectiveConflictScopedToScanSubjects pins the refusal scope
// (REQ-external-precedence): a contradiction in a dependency that yields no
// subject of the scan does not brick its dependents; scanning the conflicted
// package itself refuses.
func TestExternalDirectiveConflictScopedToScanSubjects(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	tmp := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(tmp, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/scoped\n\ngo 1.26\n")
	write("dep/dep.go", "package dep\n\n//gofresh:pure\n//gofresh:external\nfunc Torn() int { return 1 }\n")
	write("top.go", "package scoped\n\nimport \"example.com/scoped/dep\"\n\nfunc Uses() int { return dep.Torn() }\n")

	e, err := newEngine(withDir(tmp))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.capture(context.Background(), Subject{Package: "example.com/scoped", Symbol: "Uses"}, tmp); err != nil {
		t.Fatalf("dependent capture refused by a dependency's conflict: %v", err)
	}
	_, err = e.capture(context.Background(), Subject{Package: "example.com/scoped/dep", Symbol: "Torn"}, tmp)
	if err == nil || !strings.Contains(err.Error(), "gofresh:pure and //gofresh:external") {
		t.Fatalf("conflicted package's own capture = %v, want the contradiction refusal", err)
	}

	// A conflicted METHOD promoting into a requested subject refuses too —
	// including one declared in another package and promoted through
	// embedding, which only the method-set path can sight.
	write("meth/meth.go", "package meth\n\ntype T struct{}\n\n//gofresh:pure\n//gofresh:external\nfunc (T) Torn() int { return 1 }\n")
	_, err = e.capture(context.Background(), Subject{Package: "example.com/scoped/meth", Symbol: "T.Torn"}, tmp)
	if err == nil || !strings.Contains(err.Error(), "gofresh:pure and //gofresh:external") {
		t.Fatalf("conflicted method capture = %v, want the contradiction refusal", err)
	}
	write("embed/embed.go", "package embed\n\nimport \"example.com/scoped/meth\"\n\ntype W struct{ meth.T }\n")
	_, err = e.capture(context.Background(), Subject{Package: "example.com/scoped/embed", Symbol: "W.Torn"}, tmp)
	if err == nil || !strings.Contains(err.Error(), "gofresh:pure and //gofresh:external") {
		t.Fatalf("promoted conflicted method capture = %v, want the contradiction refusal", err)
	}
}

// FuzzControlAndSessionAuthority is a property witness for REQ-control-authority,
// REQ-control-execution-description, REQ-control-project-isolation,
// REQ-control-request-project, REQ-control-trust-source, and REQ-vouch-input.
func FuzzControlAndSessionAuthority(f *testing.F) {
	f.Add("example.com/pkg", "Hook", "sub/dir", "-tags=fast", "out.test", "-v")
	f.Add("example.com/v2/sub", "State", "nested", "-race", "bin.test", "-count=1")
	f.Fuzz(func(t *testing.T, pkg, sym, relDir, flagVal, outPath, extraFlag string) {
		cleanIdent := func(s, def string) string {
			var b strings.Builder
			for _, r := range s {
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
					b.WriteRune(r)
				}
			}
			res := b.String()
			if res == "" || (res[0] >= '0' && res[0] <= '9') {
				return def
			}
			return res
		}
		vName := cleanIdent(sym, "Hook")
		pName := "example.com/" + strings.ToLower(cleanIdent(pkg, "pkg"))
		colonForm := pName + ":" + vName
		dotForm := pName + "." + vName
		gotCanon, err := ParseVouchEntry(colonForm)
		if err != nil || gotCanon != dotForm {
			t.Fatalf("ParseVouchEntry(%q) = (%q, %v), want %q", colonForm, gotCanon, err, dotForm)
		}
		gotSessionVouches, err := canonicalSessionVouches([]string{dotForm, dotForm})
		if err != nil || !slices.Equal(gotSessionVouches, []string{dotForm}) {
			t.Fatalf("canonicalSessionVouches = (%v, %v), want [%q]", gotSessionVouches, err, dotForm)
		}
		if _, err := canonicalSessionVouches([]string{colonForm}); err == nil {
			t.Fatalf("canonicalSessionVouches accepted non-canonical colon form %q", colonForm)
		}
		if _, err := canonicalSessionVouches([]string{pName}); err == nil {
			t.Fatalf("canonicalSessionVouches accepted bare package %q", pName)
		}
		bd := BuildDescription{
			Directory:   "/workspace/mod",
			Package:     pName,
			Environment: []string{"GOENV=off"},
			Flags:       []string{flagVal},
			Inputs:      []string{"input=1"},
		}
		compileArgs := bd.TestCompileArgs(outPath, extraFlag)
		wantArgs := []string{"test", "-c", "-o", outPath, flagVal, extraFlag, pName}
		if !slices.Equal(compileArgs, wantArgs) {
			t.Fatalf("TestCompileArgs = %v, want %v", compileArgs, wantArgs)
		}
		// NewSession refuses invalid build/policy authority before any work.
		ctx := context.Background()
		validBuild := BuildDescription{Directory: "/tmp", Environment: []string{"GOENV=off"}, Inputs: []string{}}
		for _, invalidBuild := range []BuildDescription{
			{Directory: "", Environment: []string{}, Inputs: []string{}},
			{Directory: "/tmp", Package: pName, Environment: []string{}, Inputs: []string{}},
			{Directory: "/tmp", Environment: nil, Inputs: []string{}},
			{Directory: "/tmp", Environment: []string{}, Inputs: nil},
		} {
			if _, err := NewSession(ctx, invalidBuild, SessionPolicy{}); err == nil {
				t.Fatalf("NewSession accepted invalid BuildDescription: %+v", invalidBuild)
			}
		}
		if _, err := NewSession(ctx, validBuild, SessionPolicy{Execution: ExecutionModel(99)}); err == nil {
			t.Fatal("NewSession accepted unknown ExecutionModel")
		}
		if _, err := NewSession(ctx, validBuild, SessionPolicy{AnalysisBudget: -1}); err == nil {
			t.Fatal("NewSession accepted negative AnalysisBudget")
		}
		if _, err := NewSession(ctx, validBuild, SessionPolicy{PureSubjects: []Subject{{Package: pName, Symbol: ""}}}); err == nil {
			t.Fatal("NewSession accepted empty PureSubjects symbol")
		}
		if _, err := NewSession(ctx, validBuild, SessionPolicy{Vouches: []string{"invalid"}}); err == nil {
			t.Fatal("NewSession accepted invalid vouch identity")
		}
		// Process path rebasing and project isolation.
		sub := cleanIdent(relDir, "sub")
		rebased, err := rebaseProcessPath("/workspace/mod", sub)
		if err != nil || rebased != "/workspace/mod"+string(filepath.Separator)+sub {
			t.Fatalf("rebaseProcessPath = (%q, %v)", rebased, err)
		}
		eng := &engine{dir: "/workspace/mod", evidenceRoot: "/workspace"}
		if got := eng.evidenceRootFor("/workspace/mod"); got != "/workspace" {
			t.Fatalf("evidenceRootFor with explicit root = %q, want /workspace", got)
		}
		engNoRoot := &engine{dir: "/workspace/mod"}
		if got := engNoRoot.evidenceRootFor("/workspace/mod"); got != "/workspace/mod" {
			t.Fatalf("evidenceRootFor without explicit root = %q, want /workspace/mod", got)
		}
	})
}

// FuzzGuardRelevanceAndViewLifetime is a property witness for
// REQ-guard-runtime-relevance and REQ-guard-view-lifetime.
func FuzzGuardRelevanceAndViewLifetime(f *testing.F) {
	f.Add("tc1", "bc1", "m1", "rc1", "m2", "rc2", true, false)
	f.Add("tcA", "bcA", "", "", "mB", "rcB", false, true)
	f.Fuzz(func(t *testing.T, tc, bc, m1, rc1, m2, rc2 string, clUnver, rtUnver bool) {
		if tc == "" {
			tc = "tc"
		}
		if bc == "" {
			bc = "bc"
		}
		codeGuards := guard.Guards{Toolchain: tc, BuildConfig: bc}
		recCode := Fingerprint{
			MaximalClosure:       "C",
			ToolchainContent:     "stdlib",
			TestVariantClosure:   "T",
			DynamicStateStrategy: DynamicStateStrategy,
			ClosureStrategy:      ClosureStrategy,
			Guards:               codeGuards,
			RuntimeInputs:        "M",
			RuntimeDigest:        "D",
			ResultKind:           CodeResult,
		}
		if err := validateRecordedKind(recCode); err != nil {
			t.Fatalf("valid CodeResult rejected: %v", err)
		}
		if m1 != "" || rc1 != "" {
			badCode := recCode
			badCode.Guards.Machine = m1
			badCode.Guards.RuntimeConfig = rc1
			if err := validateRecordedKind(badCode); err == nil {
				t.Fatalf("CodeResult carrying measurement guards (%q, %q) was not refused", m1, rc1)
			}
		}
		// Omitting measurement guards from CodeResult means machine/runtimeConfig
		// changes do not stale CodeResult, but unverifiable runtime/closure
		// effects still withhold validity (REQ-guard-runtime-relevance).
		curGuards := guard.Guards{Toolchain: tc, BuildConfig: bc, Machine: m2, RuntimeConfig: rc2}
		cl := closure.Closure{Hash: "C", ToolchainContent: "stdlib", TestVariants: "T", Unverifiable: clUnver, Reason: "effect"}
		rt := runtimeinput.State{Manifest: "M", Digest: "D", OK: true, Unverifiable: rtUnver, Reason: "rt-effect"}
		v := decide(recCode, cl, curGuards, rt, CodeResult, PurityAuthority{})
		if (clUnver || rtUnver) && v.Status != Unverifiable {
			t.Fatalf("CodeResult ignored unverifiable runtime/closure effect: %+v", v)
		}
		if !clUnver && !rtUnver && v.Status != Valid {
			t.Fatalf("CodeResult staled on measurement-only guard movement: %+v", v)
		}
		// View lifetime: a Snapshot and its derived Sibling share the construction
		// code-guard capture, while independent RuntimeBindings supply their own
		// measurement guards without mutating the shared Snapshot facts.
		s1 := Subject{Package: "example.com/p", Symbol: "F"}
		s2 := Subject{Package: "example.com/p", Symbol: "G"}
		parent := &Snapshot{
			subjects: []Subject{s1, s2},
			packages: []string{"example.com/p"},
			kind:     Measurement,
			facts: &observationFacts{
				guards:  codeGuards,
				maximal: map[Subject]subjectFacts{s1: {}, s2: {}},
			},
		}
		sib, err := parent.Sibling([]Subject{s1})
		if err != nil {
			t.Fatalf("Sibling: %v", err)
		}
		if sib.guards() != codeGuards || parent.guards() != codeGuards {
			t.Fatalf("Sibling altered base snapshot guards: sib=%+v parent=%+v", sib.guards(), parent.guards())
		}
		b1 := &RuntimeBinding{snapshot: parent, runtime: boundRuntime{guards: guard.RuntimeGuards{Machine: m1, RuntimeConfig: rc1}}}
		b2 := &RuntimeBinding{snapshot: parent, runtime: boundRuntime{guards: guard.RuntimeGuards{Machine: m2, RuntimeConfig: rc2}}}
		v1, err := b1.newView([]Subject{s1})
		if err != nil {
			t.Fatalf("b1.newView: %v", err)
		}
		v2, err := b2.newView([]Subject{s1})
		if err != nil {
			t.Fatalf("b2.newView: %v", err)
		}
		if v1.guards().Toolchain != tc || v1.guards().Machine != m1 || v2.guards().Machine != m2 || parent.guards().Machine != "" {
			t.Fatalf("RuntimeBinding guard lifetime violated: v1=%+v v2=%+v parent=%+v", v1.guards(), v2.guards(), parent.guards())
		}
	})
}

// FuzzFreshnessVerdictAndObservationInvariants is a property witness for
// REQ-fresh-applicability-transform, REQ-fresh-commit-independent,
// REQ-fresh-dependency-identities, REQ-fresh-historical-implementation,
// REQ-fresh-observation-compatibility, REQ-fresh-observation-conjunction,
// REQ-fresh-observation-data, REQ-fresh-observation-lifecycle,
// REQ-fresh-producing-evidence, REQ-fresh-static-certificate,
// REQ-fresh-toolchain-dependencies, and REQ-purity-observation-separation.
func FuzzFreshnessVerdictAndObservationInvariants(f *testing.F) {
	f.Add("C1", "TV1", "TV2", "stdlib1", "policy1", "D1", true, false, false)
	f.Add("C2", "TVA", "TVB", "stdlib2", "policy2", "D2", false, true, true)
	f.Fuzz(func(t *testing.T, clHash, tv1, tv2, stdContent, admPolicy, rtDigest string, observable, rtUnver, sharedDyn bool) {
		if clHash == "" {
			clHash = "C"
		}
		if tv1 == "" {
			tv1 = "TV1"
		}
		if tv2 == "" || tv2 == tv1 {
			tv2 = tv1 + "_next"
		}
		if stdContent == "" {
			stdContent = "stdlib"
		}
		if admPolicy == "" {
			admPolicy = "policy"
		}
		if rtDigest == "" {
			rtDigest = "D"
		}
		subj := Subject{Package: "example.com/pkg", Symbol: "Bench"}
		guards := guard.Guards{Toolchain: "tc", BuildConfig: "bc"}
		reason := ""
		if !observable {
			reason = "reaches net.Dial"
		}
		rec := Fingerprint{
			MaximalClosure:       clHash,
			ToolchainContent:     stdContent,
			AdmissionPolicy:      admPolicy,
			TestVariantClosure:   tv1,
			ObservationAssertion: "caller assertion",
			ObservationProof: ObservationProof{
				Strategy:   ObservationRTA,
				Subject:    subj,
				Observable: observable,
				Reason:     reason,
			},
			Guards:               guards,
			DynamicStateStrategy: DynamicStateStrategy,
			ClosureStrategy:      ClosureStrategy,
			RuntimeInputs:        "manifest",
			RuntimeDigest:        rtDigest,
			ResultKind:           CodeResult,
		}
		rec.ObservationProof.Evidence = observationProofEvidence(rec)

		// 1. Observation proof compatibility & integrity (REQ-fresh-observation-compatibility, REQ-fresh-observation-data).
		if !compatibleObservationProof(rec, subj) {
			t.Fatalf("canonical proof rejected: %+v", rec)
		}
		if compatibleObservationProof(rec, Subject{Package: subj.Package, Symbol: subj.Symbol + "_other"}) {
			t.Fatal("proof accepted for wrong subject")
		}
		for _, mutate := range []func(*Fingerprint){
			func(fp *Fingerprint) { fp.MaximalClosure += "_drift" },
			func(fp *Fingerprint) { fp.ToolchainContent = "" },
			func(fp *Fingerprint) { fp.ToolchainContent += "_drift" },
			func(fp *Fingerprint) { fp.AdmissionPolicy = "" },
			func(fp *Fingerprint) { fp.AdmissionPolicy += "_drift" },
			func(fp *Fingerprint) { fp.ObservationAssertion = "" },
			func(fp *Fingerprint) { fp.ObservationProof.Strategy = "other" },
			func(fp *Fingerprint) { fp.ObservationProof.Observable = !fp.ObservationProof.Observable },
		} {
			copyRec := rec
			mutate(&copyRec)
			if compatibleObservationProof(copyRec, subj) {
				t.Fatalf("mutated proof remained compatible: %+v", copyRec)
			}
		}

		// 2. JSON representation round-trip & dependency identity preservation (REQ-fresh-dependency-identities).
		encoded, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var roundTripped Fingerprint
		if err := json.Unmarshal(encoded, &roundTripped); err != nil || roundTripped != rec {
			t.Fatalf("JSON round-trip mismatch: got %+v, err %v", roundTripped, err)
		}

		// 3. Guard precedence & toolchain dependency authority (REQ-fresh-dependency-identities, REQ-fresh-toolchain-dependencies).
		cl := closure.Closure{
			Hash:             clHash,
			ToolchainContent: stdContent,
			AdmissionPolicy:  admPolicy,
			TestVariants:     tv1,
			Unverifiable:     true,
			Reason:           "reaches os.Open",
		}
		if sharedDyn {
			cl.Refusal = closure.SharedDynamicStateRefusal
			cl.Culprit = closure.Subject{Package: "example.com/pkg", Symbol: "Global"}
		}
		rt := runtimeinput.State{Manifest: "manifest", Digest: rtDigest, OK: true, Unverifiable: rtUnver, Reason: "unbounded"}
		missingStd := rec
		missingStd.ToolchainContent = ""
		if v := decide(missingStd, cl, guards, rt, CodeResult, PurityAuthority{}); v.Status != Unverifiable || v.Ground.Cause != (Cause{Kind: ToolchainContentCause, Condition: Missing}) {
			t.Fatalf("missing historical ToolchainContent = %+v, want Unverifiable/Missing", v)
		}
		unavailStdCl := cl
		unavailStdCl.ToolchainContent = ""
		if v := decide(rec, unavailStdCl, guards, rt, CodeResult, PurityAuthority{}); v.Status != Unverifiable || v.Ground.Cause != (Cause{Kind: ToolchainContentCause, Condition: Unavailable}) {
			t.Fatalf("unavailable current ToolchainContent = %+v, want Unverifiable/Unavailable", v)
		}
		driftedStdCl := cl
		driftedStdCl.ToolchainContent = stdContent + "_drift"
		if v := decide(rec, driftedStdCl, guards, rt, CodeResult, PurityAuthority{}); v.Status != Stale || v.Ground.Cause != (Cause{Kind: ToolchainContentCause, Condition: Changed}) {
			t.Fatalf("drifted ToolchainContent = %+v, want Stale/Changed", v)
		}
		driftedRt := rt
		driftedRt.Digest = rtDigest + "_moved"
		if v := decide(missingStd, cl, guards, driftedRt, CodeResult, PurityAuthority{}); v.Status != Stale || v.Ground.Cause.Kind != RuntimeInputsCause {
			t.Fatalf("guard-precedence violated: runtime drift with missing ToolchainContent = %+v, want Stale/RuntimeInputsCause", v)
		}

		// Historical authority & AdmissionPolicy binding on observation support (REQ-fresh-toolchain-dependencies).
		manifestBytes, err := json.Marshal(struct {
			Version  int      `json:"v"`
			Outcome  string   `json:"outcome"`
			Subjects []string `json:"subjects"`
		}{4, outcome.Method, []string{outcomeSubject(rec, subj)}})
		if err != nil {
			t.Fatalf("Marshal manifest: %v", err)
		}
		recSupported := rec
		recSupported.RuntimeInputs = base64.RawURLEncoding.EncodeToString(manifestBytes)
		gotAuth := admittedObservation(recSupported, subj, cl)
		if observable != gotAuth.accepted() {
			t.Fatalf("admittedObservation(observable=%v) = %+v", observable, gotAuth)
		}
		missingPolicyRec := recSupported
		missingPolicyRec.AdmissionPolicy = ""
		if auth := admittedObservation(missingPolicyRec, subj, cl); auth.accepted() {
			t.Fatalf("missing historical AdmissionPolicy accepted observation authority: %+v", auth)
		}
		if v := decideAfterClosureObserved(missingPolicyRec, cl, guards, rt, CodeResult, PurityAuthority{}, admittedObservation(missingPolicyRec, subj, cl)); v.Status != Unverifiable {
			t.Fatalf("missing historical AdmissionPolicy lifted closure refusal: %+v", v)
		}
		driftedPolicyCl := cl
		driftedPolicyCl.AdmissionPolicy = admPolicy + "_drift"
		if auth := admittedObservation(recSupported, subj, driftedPolicyCl); auth.accepted() {
			t.Fatalf("drifted AdmissionPolicy accepted observation authority: %+v", auth)
		}
		if v := decideAfterClosureObserved(recSupported, driftedPolicyCl, guards, rt, CodeResult, PurityAuthority{}, admittedObservation(recSupported, subj, driftedPolicyCl)); v.Status != Unverifiable {
			t.Fatalf("drifted AdmissionPolicy lifted closure refusal: %+v", v)
		}
		for _, depMutate := range []func(*Fingerprint){
			func(fp *Fingerprint) { fp.ToolchainContent += "_drift" },
			func(fp *Fingerprint) { fp.AdmissionPolicy += "_drift" },
		} {
			mutFP := recSupported
			depMutate(&mutFP)
			if runtimeinput.HasOutcomeSupport(recSupported.RuntimeInputs, outcomeSubject(mutFP, subj)) {
				t.Fatalf("outcomeSubject failed to bind toolchain dependency in %+v", mutFP)
			}
		}

		// 4. Observation conjunction & separation from purity and shared dynamic state
		// (REQ-fresh-observation-conjunction, REQ-purity-observation-separation).
		obsAuth := ObservationAuthority{}
		if observable {
			obsAuth = ObservationAuthority{Assertion: rec.ObservationAssertion, ProofStrategy: ObservationRTA, OutcomeMethod: outcome.Method}
		}
		vObs := decideAfterClosureObserved(rec, cl, guards, rt, CodeResult, PurityAuthority{}, obsAuth)
		wantLift := observable && !rtUnver && !sharedDyn
		if wantLift {
			if vObs.Status != Valid || vObs.Ground.Accepted.Observation != obsAuth || vObs.Ground.Accepted.Purity != (PurityAuthority{}) {
				t.Fatalf("observation conjunction failed to lift or conflated purity: %+v", vObs)
			}
		} else if vObs.Status == Valid {
			t.Fatalf("unsound observation lift (observable=%v rtUnver=%v sharedDyn=%v): %+v", observable, rtUnver, sharedDyn, vObs)
		}

		// 5. Applicability transform, dependency propagation & historical implementation preservation
		// (REQ-fresh-applicability-transform, REQ-fresh-historical-implementation, REQ-fresh-static-certificate, REQ-fresh-producing-evidence, REQ-fresh-observation-lifecycle, REQ-fresh-toolchain-dependencies).
		if rec.EffectiveTestVariantClosure() != tv1 {
			t.Fatalf("EffectiveTestVariantClosure without transform = %q, want %q", rec.EffectiveTestVariantClosure(), tv1)
		}
		curCl := cl
		curCl.TestVariants = tv2
		curMaxFacts := closure.MaximalFacts{
			Identity: closure.MaximalIdentity{
				Hash:             curCl.Hash,
				ToolchainContent: curCl.ToolchainContent,
				AdmissionPolicy:  curCl.AdmissionPolicy,
				TestVariants:     curCl.TestVariants,
			},
		}
		ledger := testvariant.TestVariantLedger{BindingStrategy: testvariant.BindingStrategy}
		gitDir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(gitDir, ".git", "refs", "heads"), 0o755); err != nil {
			t.Fatalf("MkdirAll .git: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitDir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
			t.Fatalf("WriteFile HEAD: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitDir, ".git", "refs", "heads", "main"), []byte("1111111111111111111111111111111111111111\n"), 0o644); err != nil {
			t.Fatalf("WriteFile main ref: %v", err)
		}
		view := &Snapshot{
			subjects:  []Subject{subj},
			packages:  []string{subj.Package},
			moduleDir: gitDir,
			kind:      CodeResult,
			facts: &observationFacts{
				guards:             guards,
				maximal:            map[Subject]subjectFacts{subj: {source: curMaxFacts}},
				testVariantLedgers: map[string]testvariant.TestVariantLedger{subj.Package: ledger},
			},
			observable:           map[Subject]closure.Observability{subj: {Observable: observable, Reason: reason}},
			capturedObserved:     map[Subject]bool{},
			attachedObservations: map[Subject]runtimeinput.State{},
		}
		staticFP := view.fingerprintLocked(subj, curCl)
		if staticFP.ToolchainContent != curCl.ToolchainContent || staticFP.AdmissionPolicy != curCl.AdmissionPolicy {
			t.Fatalf("fingerprintLocked did not propagate toolchain dependencies: got (%q, %q), want (%q, %q)", staticFP.ToolchainContent, staticFP.AdmissionPolicy, curCl.ToolchainContent, curCl.AdmissionPolicy)
		}
		obsFP := view.observedFingerprintLocked(subj)
		if obsFP.ToolchainContent != curCl.ToolchainContent || obsFP.AdmissionPolicy != curCl.AdmissionPolicy || obsFP.ObservationProof.Evidence != observationProofEvidence(obsFP) {
			t.Fatalf("observedFingerprintLocked did not propagate and bind toolchain dependencies: %+v", obsFP)
		}
		if staticFP.RuntimeInputs != "" || staticFP.RuntimeDigest != "" || staticFP.ObservationAssertion != "" {
			t.Fatalf("static certificate carried producing runtime evidence: %+v", staticFP)
		}

		// 6. Commit-independence: no commit field on Fingerprint, and VCS commit / dirty-tree mutations
		// leave fingerprint projection and verdict decisions invariant (REQ-fresh-commit-independent).
		fpType := reflect.TypeFor[Fingerprint]()
		for i := 0; i < fpType.NumField(); i++ {
			if strings.Contains(strings.ToLower(fpType.Field(i).Name), "commit") {
				t.Fatalf("Fingerprint contains commit identity field %s", fpType.Field(i).Name)
			}
		}
		verdictBeforeVCS := decide(rec, cl, guards, rt, CodeResult, testPurityAuthority(true))
		if err := os.WriteFile(filepath.Join(gitDir, ".git", "HEAD"), []byte("2222222222222222222222222222222222222222\n"), 0o644); err != nil {
			t.Fatalf("WriteFile detached HEAD: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitDir, ".git", "refs", "heads", "main"), []byte("3333333333333333333333333333333333333333\n"), 0o644); err != nil {
			t.Fatalf("WriteFile mutated main ref: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitDir, "dirty.tmp"), []byte(clHash), 0o644); err != nil {
			t.Fatalf("WriteFile dirty.tmp: %v", err)
		}
		if gotFP := view.fingerprintLocked(subj, curCl); gotFP != staticFP {
			t.Fatalf("VCS commit/dirty mutation altered fingerprintLocked: before=%+v after=%+v", staticFP, gotFP)
		}
		if gotVerdict := decide(rec, cl, guards, rt, CodeResult, testPurityAuthority(true)); gotVerdict != verdictBeforeVCS {
			t.Fatalf("VCS commit/dirty mutation altered decide: before=%+v after=%+v", verdictBeforeVCS, gotVerdict)
		}

		if _, err := view.attachRuntimeState(subj, rec, &rt, true); err == nil {
			t.Fatal("attachRuntimeState accepted uncaptured observation proof")
		}
		extended, _, rejVerdict, err := view.prepareInertExtension(rec, ledger, subj)
		if err != nil || rejVerdict.Status != "" {
			t.Fatalf("prepareInertExtension failed on identical empty ledgers: verdict=%+v err=%v", rejVerdict, err)
		}
		if extended.TestVariantClosure != tv1 || extended.EffectiveTestVariantClosure() != tv2 || extended.MaximalClosure != rec.MaximalClosure || extended.ObservationProof != rec.ObservationProof || extended.RuntimeInputs != rec.RuntimeInputs || extended.RuntimeDigest != rec.RuntimeDigest {
			t.Fatalf("prepareInertExtension mutated producing fields: before=%+v after=%+v", rec, extended)
		}
		unknownApp := extended
		unknownApp.InertTestVariantApplicability.Strategy = "unknown/strategy@1"
		if v, failed := recordedEvidenceVerdict(unknownApp, curCl); !failed || v.Status != Stale || v.Ground.Cause.Condition != Unsupported {
			t.Fatalf("unknown applicability strategy not refused as Stale/Unsupported: %+v", v)
		}
	})
}

// FuzzPreparationAndUnitCoherence is a property witness for
// REQ-fresh-preparation, REQ-fresh-coherent-view, REQ-fresh-unit-bindings,
// and REQ-fresh-unit-exclusion.
func FuzzPreparationAndUnitCoherence(f *testing.F) {
	f.Add("example.com/p", "F", "Unknown1", "Unknown2", "D1", "D2", true)
	f.Add("example.com/q", "G", "MissingA", "MissingB", "DA", "DB", false)
	f.Fuzz(func(t *testing.T, pkg, knownSym, unk1, unk2, d1, d2 string, hasShapeErr bool) {
		if pkg == "" {
			pkg = "example.com/p"
		}
		if knownSym == "" {
			knownSym = "F"
		}
		if unk1 == "" || unk1 == knownSym {
			unk1 = knownSym + "_unk1"
		}
		if unk2 == "" || unk2 == knownSym || unk2 == unk1 {
			unk2 = knownSym + "_unk2"
		}
		sKnown := Subject{Package: pkg, Symbol: knownSym}
		sUnk1 := Subject{Package: pkg, Symbol: unk1}
		sUnk2 := Subject{Package: pkg, Symbol: unk2}

		view := &Snapshot{
			subjects: []Subject{sKnown},
			packages: []string{pkg},
			kind:     Measurement,
			facts: &observationFacts{
				guards:               guard.Guards{Toolchain: "tc", BuildConfig: "bc"},
				maximal:              map[Subject]subjectFacts{sKnown: {}},
				sourceFiles:          []string{"a.go"},
				sourceFilesBySubject: map[Subject][]string{sKnown: {"a.go"}},
				fileDigests:          map[string]string{"a.go": "h1"},
			},
		}
		goodFP := Fingerprint{
			MaximalClosure:       "C",
			ToolchainContent:     "stdlib",
			TestVariantClosure:   "T",
			DynamicStateStrategy: DynamicStateStrategy,
			ClosureStrategy:      ClosureStrategy,
			Guards:               guard.Guards{Toolchain: "tc", BuildConfig: "bc", Machine: "m", RuntimeConfig: "rc"},
			RuntimeInputs:        "M",
			RuntimeDigest:        d1,
			ResultKind:           Measurement,
		}
		wrongKindFP := goodFP
		wrongKindFP.ResultKind = CodeResult
		wrongKindFP.Guards.Machine = ""
		wrongKindFP.Guards.RuntimeConfig = ""

		badShapeFP := goodFP
		badShapeFP.ResultKind = Kind(99)

		// Tier 1 (Shape) precedes Tier 2 (Kind) and Tier 3 (Membership) (REQ-fresh-preparation).
		candidates := []Candidate{
			{Subject: sUnk1, Recorded: goodFP},
			{Subject: sKnown, Recorded: wrongKindFP},
		}
		if hasShapeErr {
			candidates = append(candidates, Candidate{Subject: sUnk2, Recorded: badShapeFP})
		}
		prepErr := view.prepareCandidates(candidates)
		var batchErr *RecordedBatchError
		if !errors.As(prepErr, &batchErr) {
			t.Fatalf("prepareCandidates err = %v, want *RecordedBatchError", prepErr)
		}
		if hasShapeErr && batchErr.Tier != RecordShapeRefusal {
			t.Fatalf("shape error did not win tier precedence: %+v", batchErr)
		}
		if !hasShapeErr && batchErr.Tier != RecordKindRefusal {
			t.Fatalf("kind error did not win over unknown subject: %+v", batchErr)
		}

		// Tier 3 deduplicates unknown subjects in request order.
		unkCandidates := []Candidate{
			{Subject: sUnk2, Recorded: goodFP},
			{Subject: sKnown, Recorded: goodFP},
			{Subject: sUnk1, Recorded: goodFP},
			{Subject: sUnk2, Recorded: goodFP},
		}
		unkErr := view.prepareCandidates(unkCandidates)
		var unknown *UnknownSubjectsError
		if !errors.As(unkErr, &unknown) || !slices.Equal(unknown.Subjects, []Subject{sUnk2, sUnk1}) {
			t.Fatalf("unknown subjects = %+v (%v), want [%+v %+v]", unknown, unkErr, sUnk2, sUnk1)
		}

		// Unit bindings & foreign handle refusal (REQ-fresh-unit-bindings).
		u1 := &producingUnit{snapshot: view, view: view}
		u2 := &producingUnit{snapshot: view, view: view}
		if _, err := u1.register(context.Background(), BuildBinding{snapshot: &Snapshot{}, pkg: pkg, identity: "id"}, ProcessDescription{Identity: "p"}); err == nil {
			t.Fatal("register accepted BuildBinding from foreign snapshot")
		}
		if _, err := u1.register(context.Background(), BuildBinding{snapshot: view, pkg: pkg + "_other", identity: "id"}, ProcessDescription{Identity: "p"}); err == nil {
			t.Fatal("register accepted BuildBinding from foreign package")
		}
		exec := &unitExecution{ready: true}
		u1.execution = exec
		foreignContrib := Contribution{unit: u2, execution: exec}
		if err := u1.submit(foreignContrib, Terminal{Kind: NormalCompletion}); err == nil {
			t.Fatal("submit accepted foreign unit's contribution")
		}
		ownContrib := Contribution{unit: u1, execution: exec}
		if err := u1.submit(ownContrib, Terminal{Kind: NormalCompletion, Reason: "unexpected"}); err == nil {
			t.Fatal("submit accepted NormalCompletion with non-empty reason")
		}
		if err := u1.submit(ownContrib, Terminal{Kind: AbnormalCompletion, Reason: ""}); err == nil {
			t.Fatal("submit accepted AbnormalCompletion with empty reason")
		}

		// Runtime motion & hold-still exclusion (REQ-fresh-coherent-view, REQ-fresh-unit-exclusion).
		sBefore := runtimeinput.State{Manifest: "M", Digest: d1, OK: true}
		sAfter := runtimeinput.State{Manifest: "M", Digest: d2, OK: true}
		cand := Candidate{Subject: sKnown, Recorded: goodFP}
		movedVerdict := view.runtimeMotion(context.Background(), cand, Verdict{Status: Valid}, sBefore, sAfter)
		if d1 != d2 && (movedVerdict.Status != Stale || movedVerdict.Ground.Cause.Kind != RuntimeInputsCause) {
			t.Fatalf("runtimeMotion did not stale on moved digest (%q != %q): %+v", d1, d2, movedVerdict)
		}
		if d1 == d2 && movedVerdict.Status != Valid {
			t.Fatalf("runtimeMotion staled on unchanged state: %+v", movedVerdict)
		}
		var held error
		unavailErr := unavailableReason("cut")
		if err := deferValidationUnavailability(errors.Join(ErrAnalysisUnavailable, errors.New(unavailErr)), &held); err != nil || held == nil {
			t.Fatalf("deferValidationUnavailability did not hold ErrAnalysisUnavailable: err=%v held=%v", err, held)
		}
		if err := deferValidationUnavailability(ErrViewChanged, &held); !errors.Is(err, ErrViewChanged) {
			t.Fatalf("concrete ErrViewChanged did not outrank held unavailability: %v", err)
		}
	})
}

