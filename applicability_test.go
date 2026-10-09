package gofresh

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/closure/testvariant"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/runtimeinput"
)

func TestInertApplicabilityRecordGrammar(t *testing.T) {
	f := fullFingerprint()
	f.InertTestVariantApplicability = InertTestVariantApplicability{InertTestVariantExtension, "endpoint"}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	nested := `"inertTestVariantApplicability":{"strategy":"` + InertTestVariantExtension + `","testVariantClosure":"endpoint"}`
	if !strings.Contains(string(data), nested+`,"resultKind":1`) {
		t.Fatalf("native form: %s", data)
	}
	for _, malformed := range []string{
		`null`, `{}`, `{"strategy":"s"}`, `{"testVariantClosure":"v"}`,
		`{"strategy":"","testVariantClosure":"v"}`, `{"strategy":"s","testVariantClosure":""}`,
		`{"strategy":null,"testVariantClosure":"v"}`, `{"strategy":"s","testVariantClosure":null}`,
		`{"strategy":"s","strategy":"s","testVariantClosure":"v"}`,
		`{"strategy":"s","testVariantClosure":"v","testVariantClosure":"v"}`,
		`{"strategy":"s","testVariantClosure":"v","other":1}`,
		`{"testVariantClosure":"v","strategy":"s"}`, `{"strategy":1,"testVariantClosure":"v"}`,
		`{"strategy":"s","testVariantClosure":true}`,
	} {
		bad := strings.Replace(string(data), nested, `"inertTestVariantApplicability":`+malformed, 1)
		var back Fingerprint
		if err := json.Unmarshal([]byte(bad), &back); err == nil || back != (Fingerprint{}) {
			t.Fatalf("accepted %s: %+v %v", bad, back, err)
		}
	}
	for _, partial := range []InertTestVariantApplicability{{Strategy: "s"}, {TestVariantClosure: "v"}} {
		f.InertTestVariantApplicability = partial
		if _, err := json.Marshal(f); err == nil {
			t.Fatal("encoded partial applicability")
		}
	}
	f.InertTestVariantApplicability = InertTestVariantApplicability{"future", f.TestVariantClosure}
	data, err = json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back Fingerprint
	if err := json.Unmarshal(data, &back); err != nil || back != f {
		t.Fatalf("unknown strategy unreadable: %v", err)
	}
	if verdict, failed := recordedEvidenceVerdict(back, closure.Closure{Hash: f.MaximalClosure, TestVariants: f.TestVariantClosure}); !failed || verdict.Status != Stale {
		t.Fatal("unknown strategy served under original hash")
	}
}

func applicabilityFixture(t *testing.T) (*View, Fingerprint, Subject, TestVariantLedger) {
	t.Helper()
	s := Subject{"example.com/p", "BenchmarkEnv"}
	f := Fingerprint{MaximalClosure: "core", TestVariantClosure: "A", ClosureStrategy: ClosureStrategy, DynamicStateStrategy: DynamicStateStrategy, ResultKind: Measurement, Guards: guard.Guards{Toolchain: "go", BuildConfig: "build", Machine: "machine", RuntimeConfig: "runtime"}}
	l := TestVariantLedger{BindingStrategy: testvariant.BindingStrategy}
	v := &View{engine: &Engine{}, subjects: []Subject{s}, kind: Measurement, facts: &observationFacts{maximal: map[Subject]closure.Closure{s: {Hash: "core", TestVariants: "B"}}, guards: f.Guards, testVariantLedgers: map[string]TestVariantLedger{s.Package: l}}, observable: map[Subject]closure.Observability{}}
	return v, f, s, l
}

func TestInertExtensionRequiresEveryGuardAndRecognizedEvidence(t *testing.T) {
	for name, change := range map[string]func(*View, *Fingerprint, *TestVariantLedger){
		"core":                     func(v *View, f *Fingerprint, l *TestVariantLedger) { f.MaximalClosure = "moved" },
		"missing core":             func(v *View, f *Fingerprint, l *TestVariantLedger) { f.MaximalClosure = "" },
		"missing compartment":      func(v *View, f *Fingerprint, l *TestVariantLedger) { f.TestVariantClosure = "" },
		"closure derivation":       func(v *View, f *Fingerprint, l *TestVariantLedger) { f.ClosureStrategy = "old" },
		"dynamic derivation":       func(v *View, f *Fingerprint, l *TestVariantLedger) { f.DynamicStateStrategy = "old" },
		"toolchain":                func(v *View, f *Fingerprint, l *TestVariantLedger) { f.Guards.Toolchain = "old" },
		"build":                    func(v *View, f *Fingerprint, l *TestVariantLedger) { f.Guards.BuildConfig = "old" },
		"machine":                  func(v *View, f *Fingerprint, l *TestVariantLedger) { f.Guards.Machine = "old" },
		"runtime":                  func(v *View, f *Fingerprint, l *TestVariantLedger) { f.Guards.RuntimeConfig = "old" },
		"missing runtime manifest": func(v *View, f *Fingerprint, l *TestVariantLedger) { f.RuntimeDigest = "orphan" },
		"unknown endpoint": func(v *View, f *Fingerprint, l *TestVariantLedger) {
			f.InertTestVariantApplicability = InertTestVariantApplicability{"future", "A"}
		},
		"missing binding evidence": func(v *View, f *Fingerprint, l *TestVariantLedger) { l.BindingStrategy = "" },
		"unknown binding evidence": func(v *View, f *Fingerprint, l *TestVariantLedger) { l.BindingStrategy = "future" },
		"removed declaration": func(v *View, f *Fingerprint, l *TestVariantLedger) {
			l.Declarations = []TestVariantDeclaration{{File: "p_test.go", Kind: "func", Name: "Removed", Hash: "h"}}
		},
		"external": func(v *View, f *Fingerprint, l *TestVariantLedger) {
			for s, c := range v.facts.maximal {
				c.External = true
				v.facts.maximal[s] = c
			}
		},
		"unverifiable": func(v *View, f *Fingerprint, l *TestVariantLedger) {
			for s, c := range v.facts.maximal {
				c.Unverifiable = true
				c.Reason = "file dependence"
				v.facts.maximal[s] = c
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, observed := range []bool{false, true} {
				v, f, s, l := applicabilityFixture(t)
				change(v, &f, &l)
				updated, ledger, verdict, err := v.checkInertTestVariantExtension(context.Background(), f, l, s, observed)
				if err != nil || verdict.Status == Valid || updated != (Fingerprint{}) || !reflect.DeepEqual(ledger, TestVariantLedger{}) {
					t.Fatalf("refusal leaked pair: %+v %+v %+v %v", updated, ledger, verdict, err)
				}
			}
		})
	}
	for _, pure := range []bool{false, true} {
		v, f, s, l := applicabilityFixture(t)
		if pure {
			c := v.facts.maximal[s]
			c.Unverifiable = true
			v.facts.maximal[s] = c
			v.facts.purity = map[Subject]string{s: "caller assertion"}
			f.PurityAssertion = "caller assertion"
		}
		updated, _, verdict, err := v.CheckInertTestVariantExtension(context.Background(), f, l, s)
		if err != nil || verdict.Status != Valid {
			t.Fatalf("independently valid ordinary case needs no outcome support: %+v %v", verdict, err)
		}
		if updated.TestVariantClosure != "A" || updated.EffectiveTestVariantClosure() != "B" {
			t.Fatal("producing coordinate was rewritten")
		}
		updated.InertTestVariantApplicability = InertTestVariantApplicability{}
		if updated != f {
			t.Fatal("producing constituents changed")
		}
	}
}

func TestInertExtensionPreservesSupportedExecutionAcrossRestarts(t *testing.T) {
	if testing.Short() {
		t.Skip("executes an observed benchmark and analyzes repeated test growth")
	}
	ctx := context.Background()
	dir := t.TempDir()
	source := `package growth
import ("os"; "testing")
func BenchmarkEnv(b *testing.B) { for i:=0; i<b.N; i++ { _ = os.Getenv("OUTCOME_VALUE") } }
func TestReadsFile(t *testing.T) { _, _ = os.ReadFile("fixture") }
`
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/growth\n\ngo 1.26\n")
	write("growth_test.go", source)
	write("fixture", "unexecuted sibling input")
	env, err := gotool.EnvForCommand(os.Environ(), dir)
	if err != nil {
		t.Fatal(err)
	}
	env = gotool.SetEnv(env, "OUTCOME_VALUE", "guarded")
	s := Subject{"example.com/growth", "BenchmarkEnv"}
	newView := func(extra ...Option) *View {
		t.Helper()
		opts := append([]Option{WithDir(dir), WithEnv(env...)}, extra...)
		e, err := New(opts...)
		if err != nil {
			t.Fatal(err)
		}
		v, err := e.NewViewFor(ctx, []Subject{s}, dir, Measurement)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	producer := newView()
	if !producer.facts.maximal[s].Unverifiable {
		t.Fatal("sibling did not establish maximal ClassB dependence")
	}
	frame := runtimeinput.CaptureProducerFrame(ctx, dir, dir, runtimeinput.FrameOptions{})
	support, err := producer.PrepareOutcomeSupport(ctx, frame, "benchmark")
	if err != nil {
		t.Fatal(err)
	}
	fp, err := producer.CaptureObserved(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := producer.TestVariantLedger(s)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "growth.test")
	build := exec.CommandContext(ctx, "go", "test", "-c", "-o", bin, ".")
	build.Dir = dir
	build.Env = env
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %s %v", out, err)
	}
	log := filepath.Join(t.TempDir(), "inputs.log")
	run := exec.CommandContext(ctx, bin, "-test.run=^$", "-test.bench=^BenchmarkEnv$", "-test.benchtime=1x", "-test.testlogfile="+log)
	run.Dir = dir
	run.Env = env
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("benchmark: %s %v", out, err)
	}
	logged, err := os.ReadFile(log)
	if err != nil || !strings.Contains(string(logged), "getenv OUTCOME_VALUE\n") {
		t.Fatalf("benchmark did not observe its environment: %s %v", logged, err)
	}
	receipt, err := frame.Completion("benchmark", env, "")
	if err != nil {
		t.Fatal(err)
	}
	obs, reason, err := frame.Observe(ctx, log, runtimeinput.ProducerIngest{Identity: "benchmark", Env: env, Completion: receipt, Outcome: support})
	if err != nil || reason != "" {
		t.Fatalf("actual producer support: %s %v", reason, err)
	}
	fp, err = producer.AttachObservation(s, fp, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := producer.Validate(ctx); err != nil {
		t.Fatal(err)
	}
	original := fp
	if !runtimeinput.HasOutcomeSupport(fp.RuntimeInputs, outcomeSubject(fp, s)) {
		t.Fatal("actual producer missing support")
	}
	baseline := newView()
	if verdict, err := baseline.Check(ctx, fp, s); err != nil || verdict.Status != Unverifiable {
		t.Fatalf("ordinary original recording: %+v %v", verdict, err)
	}
	if verdict, err := baseline.CheckObserved(ctx, fp, s); err != nil || verdict.Status != Valid {
		t.Fatalf("supported original recording: %+v %v", verdict, err)
	}
	for _, name := range []string{"TestArithmetic", "TestMoreArithmetic"} {
		source += "\nfunc " + name + "(t *testing.T) { if 2+2 != 4 { t.Fatal(\"arithmetic\") } }\n"
		write("growth_test.go", source)
		current := newView()
		if verdict, err := current.CheckObserved(ctx, fp, s); err != nil || verdict.Status != Stale || verdict.Reason != ReasonTestVariants {
			t.Fatalf("implicit extension: %+v %v", verdict, err)
		}
		if u, l, verdict, err := current.CheckInertTestVariantExtension(ctx, fp, ledger, s); err != nil || verdict.Status != Unverifiable || u != (Fingerprint{}) || !reflect.DeepEqual(l, TestVariantLedger{}) {
			t.Fatalf("ordinary unexpectedly lifted: %+v %v", verdict, err)
		}
		updated, next, verdict, err := current.CheckObservedInertTestVariantExtension(ctx, fp, ledger, s)
		if err != nil || verdict.Status != Valid {
			t.Fatalf("supported inert extension: %+v %v", verdict, err)
		}
		unchanged := updated
		unchanged.InertTestVariantApplicability = InertTestVariantApplicability{}
		if unchanged != original || updated.EffectiveTestVariantClosure() == fp.EffectiveTestVariantClosure() {
			t.Fatal("extension changed producer facts or failed to move endpoint")
		}
		if !runtimeinput.HasOutcomeSupport(updated.RuntimeInputs, outcomeSubject(original, s)) {
			t.Fatal("lost original support")
		}
		if err := current.Validate(ctx); err != nil {
			t.Fatal(err)
		}
		// A separate checker process consumes the native recording and ledger;
		// the parent reloads the same pair for the next extension.
		pair := applicabilityStoredPair{updated, next, s}
		data, err := json.Marshal(pair)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "record.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		checker := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestApplicabilityCheckerReload$", "-test.count=1", "-test.v")
		checker.Dir = dir
		checker.Env = gotool.SetEnv(gotool.SetEnv(env, "GOFRESH_CHECKER_RECORD", path), "GOFRESH_CHECKER_DIR", dir)
		if output, err := checker.CombinedOutput(); err != nil || !strings.Contains(string(output), "persisted applicability checked") {
			t.Fatalf("checker process: %v\n%s", err, output)
		}
		data, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		pair.Fingerprint = Fingerprint{}
		pair.Ledger = TestVariantLedger{}
		if err := json.Unmarshal(data, &pair); err != nil {
			t.Fatal(err)
		}
		fp, ledger = pair.Fingerprint, pair.Ledger
		restarted := newView()
		if verdict, err := restarted.CheckObserved(ctx, fp, s); err != nil || verdict.Status != Valid {
			t.Fatalf("persisted endpoint: %+v %v", verdict, err)
		}
		if verdict, err := restarted.Check(ctx, fp, s); err != nil || verdict.Status != Unverifiable {
			t.Fatalf("ordinary endpoint inferred observation policy: %+v %v", verdict, err)
		}
	}
	// Missing original support is never backfilled by a successful current proof.
	bracket, err := runtimeinput.CaptureBracket(ctx, dir, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := runtimeinput.FromTestLog([]byte("getenv OUTCOME_VALUE\n"), dir, dir, env, runtimeinput.WithCompletedProcess("identity-only"), runtimeinput.WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	missing := fp
	missing.RuntimeInputs, missing.RuntimeDigest = plain.Manifest, plain.Digest
	if verdict, err := newView().CheckObserved(ctx, missing, s); err != nil || verdict.Status != Unverifiable {
		t.Fatalf("backfilled support: %+v %v", verdict, err)
	}
	pureRecord := missing
	pureRecord.PurityAssertion = "caller assertion"
	pureView := newView(WithAssumePure(func(subject Subject) bool { return subject == s }))
	if updated, _, verdict, err := pureView.CheckObservedInertTestVariantExtension(ctx, pureRecord, ledger, s); err != nil || verdict.Status != Valid || updated.RuntimeInputs != plain.Manifest {
		t.Fatalf("explicit purity demanded outcome support: %+v %v", verdict, err)
	}
	if len(pureView.observable) != 0 {
		t.Fatal("independently valid purity paid for an observation proof")
	}
	if err := pureView.Validate(ctx); err != nil {
		t.Fatalf("purity applicability validation demanded producing support: %v", err)
	}
	for name, damage := range map[string]func(*Fingerprint){
		"assertion":                func(f *Fingerprint) { f.ObservationAssertion = "" },
		"proof strategy":           func(f *Fingerprint) { f.ObservationProof.Strategy = "future" },
		"proof integrity":          func(f *Fingerprint) { f.ObservationProof.Evidence = "broken" },
		"proof subject":            func(f *Fingerprint) { f.ObservationProof.Subject.Symbol = "TestReadsFile" },
		"proof disposition":        func(f *Fingerprint) { f.ObservationProof.Observable = false },
		"manual producing refresh": func(f *Fingerprint) { f.TestVariantClosure = f.EffectiveTestVariantClosure() },
		"manifest absent":          func(f *Fingerprint) { f.RuntimeInputs, f.RuntimeDigest = "", "" },
		"support absent":           func(f *Fingerprint) { f.RuntimeInputs, f.RuntimeDigest = plain.Manifest, plain.Digest },
	} {
		bad := fp
		damage(&bad)
		current := newView()
		if updated, _, verdict, err := current.CheckObservedInertTestVariantExtension(ctx, bad, ledger, s); err != nil || verdict.Status != Unverifiable || updated != (Fingerprint{}) {
			t.Fatalf("%s supplied historical evidence: %+v %v", name, verdict, err)
		}
	}
	env = gotool.SetEnv(env, "OUTCOME_VALUE", "moved")
	if updated, _, verdict, err := newView().CheckObservedInertTestVariantExtension(ctx, fp, ledger, s); err != nil || verdict.Status != Stale || updated != (Fingerprint{}) {
		t.Fatalf("environment drift: %+v %v", verdict, err)
	}
	env = gotool.SetEnv(env, "OUTCOME_VALUE", "guarded")
	// A current analysis cut or unsupported inventory cannot reuse the old proof.
	for _, proof := range []closure.Observability{{Reason: unavailableReason("test cut")}, {Observable: true}} {
		v := newView()
		v.observable[s] = proof
		if verdict, err := v.CheckObserved(ctx, fp, s); err != nil || verdict.Status != Unverifiable {
			t.Fatalf("current proof/inventory ignored: %+v %v", verdict, err)
		}
	}
	if verdict, err := newView(WithAnalysisBudget(time.Nanosecond)).CheckObserved(ctx, fp, s); err != nil || verdict.Status != Unverifiable {
		t.Fatalf("budget-cut current applicability reused historical proof: %+v %v", verdict, err)
	}
	deferred := newView(WithDeferredCheckClose())
	if _, _, verdict, err := deferred.CheckObservedInertTestVariantExtension(ctx, fp, ledger, s); err != nil || verdict.Status != Valid {
		t.Fatalf("deferred extension: %+v %v", verdict, err)
	}
	if len(deferred.capturedObserved) != 0 || len(deferred.applicabilityChecks) == 0 {
		t.Fatal("applicability either became producer evidence or lost its validation obligation")
	}
	deferred.engine.analysisBudget = time.Nanosecond
	if err := deferred.Validate(ctx); !errors.Is(err, ErrAnalysisUnavailable) {
		t.Fatalf("validation ignored current proof unavailability: %v", err)
	}
	// Sibling producer transactions retain their selected applicability duties.
	parent := newView(WithDeferredCheckClose())
	if _, _, verdict, err := parent.CheckObservedInertTestVariantExtension(ctx, fp, ledger, s); err != nil || verdict.Status != Valid {
		t.Fatalf("parent extension: %+v %v", verdict, err)
	}
	sibling, err := parent.Sibling([]Subject{s})
	if err != nil {
		t.Fatal(err)
	}
	if len(sibling.applicabilityChecks) == 0 {
		t.Fatal("sibling dropped applicability obligations")
	}
	parent.engine.analysisBudget = time.Nanosecond
	if err := sibling.Validate(ctx); !errors.Is(err, ErrAnalysisUnavailable) {
		t.Fatalf("sibling skipped proof validation: %v", err)
	}
	// A concurrent validation seals even when it is cancelled. In-flight
	// applicability analysis cannot publish either its proof or a replacement.
	concurrent := newView()
	entered, release := make(chan struct{}), make(chan struct{})
	concurrent.beforePreciseAnalysis = func() { close(entered); <-release }
	done := make(chan error, 1)
	go func() {
		updated, ledger, _, err := concurrent.CheckObservedInertTestVariantExtension(ctx, fp, ledger, s)
		if updated != (Fingerprint{}) || !reflect.DeepEqual(ledger, TestVariantLedger{}) {
			done <- errors.New("published during concurrent validation")
			return
		}
		done <- err
	}()
	<-entered
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := concurrent.Validate(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled validation: %v", err)
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrViewSealed) {
		t.Fatalf("analysis publication crossed seal: %v", err)
	}
	write("growth_test.go", strings.Replace(source, "_ = os.Getenv(\"OUTCOME_VALUE\")", "_, _ = os.LookupEnv(\"OUTCOME_VALUE\")", 1))
	if updated, _, verdict, err := newView().CheckObservedInertTestVariantExtension(ctx, fp, ledger, s); err != nil || verdict.Status != Stale || updated != (Fingerprint{}) {
		t.Fatalf("changed subject extended: %+v %v", verdict, err)
	}
	write("growth_test.go", source)
	deferred = newView(WithDeferredCheckClose())
	if _, _, verdict, err := deferred.CheckObservedInertTestVariantExtension(ctx, fp, ledger, s); err != nil || verdict.Status != Valid {
		t.Fatalf("deferred extension: %+v %v", verdict, err)
	}
	// New initialization is not inert even though the producing benchmark remains.
	write("growth_test.go", source+"\nfunc init() { os.Setenv(\"OUTCOME_VALUE\",\"changed\") }\n")
	if err := deferred.Validate(ctx); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("deferred close missed source drift: %v", err)
	}
	if updated, _, verdict, err := newView().CheckObservedInertTestVariantExtension(ctx, fp, ledger, s); err != nil || verdict.Status != Stale || updated != (Fingerprint{}) {
		t.Fatalf("blocker accepted: %+v %v", verdict, err)
	}
}

type applicabilityStoredPair struct {
	Fingerprint Fingerprint
	Ledger      TestVariantLedger
	Subject     Subject
}

func TestApplicabilityCheckerReload(t *testing.T) {
	if testing.Short() {
		t.Skip("checks a persisted applicability record in a child process")
	}
	path := os.Getenv("GOFRESH_CHECKER_RECORD")
	if path == "" {
		return
	}
	dir := os.Getenv("GOFRESH_CHECKER_DIR")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var pair applicabilityStoredPair
	if err := json.Unmarshal(data, &pair); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	view, err := engine.NewViewFor(ctx, []Subject{pair.Subject}, dir, pair.Fingerprint.ResultKind)
	if err != nil {
		t.Fatal(err)
	}
	if verdict, err := view.Check(ctx, pair.Fingerprint, pair.Subject); err != nil || verdict.Status != Unverifiable {
		t.Fatalf("ordinary reloaded record: %+v %v", verdict, err)
	}
	if verdict, err := view.CheckObserved(ctx, pair.Fingerprint, pair.Subject); err != nil || verdict.Status != Valid {
		t.Fatalf("observed reloaded record: %+v %v", verdict, err)
	}
	ledger, err := view.TestVariantLedger(pair.Subject)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pair.Ledger, ledger) {
		t.Fatal("reloaded companion ledger differs from the endpoint")
	}
	if err := view.Validate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("persisted applicability checked")
}

func TestInertExtensionHonorsSealAndCancellation(t *testing.T) {
	v, f, s, l := applicabilityFixture(t)
	v.sealed = true
	if fp, _, _, err := v.CheckInertTestVariantExtension(context.Background(), f, l, s); !errors.Is(err, ErrViewSealed) || fp != (Fingerprint{}) {
		t.Fatalf("sealed publication: %v", err)
	}
	v.sealed = false
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if fp, _, _, err := v.CheckInertTestVariantExtension(ctx, f, l, s); !errors.Is(err, context.Canceled) || fp != (Fingerprint{}) {
		t.Fatalf("cancelled publication: %v", err)
	}
}

func TestInertExtensionCannotPublishAcrossConcurrentValidation(t *testing.T) {
	for _, observed := range []bool{false, true} {
		v, f, s, l := applicabilityFixture(t)
		v.engine.deferredCheckClose = true
		f.RuntimeInputs, f.RuntimeDigest = "recorded input", "digest"
		entered, release := make(chan struct{}), make(chan struct{})
		first := true
		v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
			if first {
				first = false
				close(entered)
				<-release
			}
			return runtimeinput.State{OK: true, Digest: "digest"}, nil
		}
		done := make(chan error, 1)
		go func() {
			updated, ledger, _, err := v.checkInertTestVariantExtension(context.Background(), f, l, s, observed)
			if updated != (Fingerprint{}) || !reflect.DeepEqual(ledger, TestVariantLedger{}) {
				done <- errors.New("published a pair after seal")
				return
			}
			done <- err
		}()
		<-entered
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := v.Validate(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("validation did not seal: %v", err)
		}
		close(release)
		if err := <-done; !errors.Is(err, ErrViewSealed) {
			t.Fatalf("extension crossed validation: %v", err)
		}
	}
}

func TestInertExtensionRechecksRuntimeAndProofEvidence(t *testing.T) {
	for _, state := range []runtimeinput.State{{}, {OK: true, Digest: "moved"}, {OK: true, Digest: "digest", Unverifiable: true, Reason: "incomplete"}} {
		v, f, s, l := applicabilityFixture(t)
		v.engine.deferredCheckClose = true
		f.RuntimeInputs, f.RuntimeDigest = "recorded input", "digest"
		v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) { return state, nil }
		if updated, _, verdict, err := v.CheckObservedInertTestVariantExtension(context.Background(), f, l, s); err != nil || verdict.Status == Valid || updated != (Fingerprint{}) {
			t.Fatalf("runtime refusal: %+v %v", verdict, err)
		}
	}
	// A manifest changes between the two observations even under deferred close.
	v, f, s, l := applicabilityFixture(t)
	v.engine.deferredCheckClose = true
	f.RuntimeInputs, f.RuntimeDigest = "recorded input", "digest"
	calls := 0
	v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
		calls++
		if calls == 1 {
			return runtimeinput.State{OK: true, Digest: "digest"}, nil
		}
		return runtimeinput.State{OK: true, Digest: "moved"}, nil
	}
	if updated, _, verdict, err := v.CheckInertTestVariantExtension(context.Background(), f, l, s); err != nil || verdict.Status != Stale || updated != (Fingerprint{}) {
		t.Fatalf("moving input served: %+v %v", verdict, err)
	}
}
