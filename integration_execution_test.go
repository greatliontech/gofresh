package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func applicabilityFixture(t *testing.T) (*Snapshot, Fingerprint, Subject, TestVariantLedger) {
	t.Helper()
	s := Subject{"example.com/p", "BenchmarkEnv"}
	f := Fingerprint{MaximalClosure: "core", ToolchainContent: "stdlib", AdmissionPolicy: "audit", TestVariantClosure: "A", ClosureStrategy: ClosureStrategy, DynamicStateStrategy: DynamicStateStrategy, ResultKind: Measurement, Guards: guard.Guards{Toolchain: "go", BuildConfig: "build", Machine: "machine", RuntimeConfig: "runtime"}}
	l := TestVariantLedger{BindingStrategy: testvariant.BindingStrategy}
	v := &Snapshot{session: &engine{}, subjects: []Subject{s}, kind: Measurement, facts: &observationFacts{maximal: map[Subject]subjectFacts{s: testSubjectFacts(closure.Closure{Hash: "core", ToolchainContent: "stdlib", AdmissionPolicy: "audit", TestVariants: "B"})}, guards: f.Guards, testVariantLedgers: map[string]TestVariantLedger{s.Package: l}}, observable: map[Subject]closure.Observability{}}
	return v, f, s, l
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
	newViewIn := func(t *testing.T, selectedEnv []string, extra ...option) *Snapshot {
		t.Helper()
		opts := append([]option{withDir(dir), withEnv(selectedEnv...)}, extra...)
		e, err := newEngine(opts...)
		if err != nil {
			t.Fatal(err)
		}
		v, err := e.newViewFor(ctx, []Subject{s}, dir, Measurement)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	newView := func(extra ...option) *Snapshot {
		t.Helper()
		return newViewIn(t, env, extra...)
	}
	producer := newView()
	if !producer.facts.closure(s).Unverifiable {
		t.Fatal("sibling did not establish maximal ClassB dependence")
	}
	frame := runtimeinput.CaptureProducerFrame(ctx, dir, dir, runtimeinput.FrameOptions{})
	support, _, err := producer.prepareOutcomeSupport(ctx, frame, "benchmark")
	if err != nil {
		t.Fatal(err)
	}
	fp, err := producer.captureObserved(ctx, s)
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
		if u, l, verdict, err := current.checkInertTestVariantExtension(ctx, fp, ledger, s, false); err != nil || verdict.Status != Unverifiable || u != (Fingerprint{}) || !reflect.DeepEqual(l, TestVariantLedger{}) {
			t.Fatalf("ordinary unexpectedly lifted: %+v %v", verdict, err)
		}
		updated, next, verdict, err := current.checkInertTestVariantExtension(ctx, fp, ledger, s, true)
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
	// These checks read one completed extension and immutable source. Join all
	// independent transactions before the subsequent source-drift edits. Engines
	// whose budgets change remain private; the damage cases share configuration
	// only, retaining a fresh two-observation View for each case.
	guardedEnv := append([]string(nil), env...)
	damageEngine, err := newEngine(withDir(dir), withEnv(guardedEnv...))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("stable checking", func(t *testing.T) {
		t.Run("missing support", func(t *testing.T) {
			t.Parallel()
			missing := fp
			missing.RuntimeInputs, missing.RuntimeDigest = plain.Manifest, plain.Digest
			if verdict, err := newViewIn(t, guardedEnv).CheckObserved(ctx, missing, s); err != nil || verdict.Status != Unverifiable {
				t.Fatalf("backfilled support: %+v %v", verdict, err)
			}
		})
		t.Run("independent purity", func(t *testing.T) {
			t.Parallel()
			pureRecord := fp
			pureRecord.RuntimeInputs, pureRecord.RuntimeDigest = plain.Manifest, plain.Digest
			pureRecord.PurityAssertion = "caller assertion"
			pureView := newViewIn(t, guardedEnv, withAssumePure(func(subject Subject) bool { return subject == s }))
			if updated, _, verdict, err := pureView.checkInertTestVariantExtension(ctx, pureRecord, ledger, s, true); err != nil || verdict.Status != Valid || updated.RuntimeInputs != plain.Manifest {
				t.Fatalf("explicit purity demanded outcome support: %+v %v", verdict, err)
			}
			if len(pureView.observable) != 0 {
				t.Fatal("independently valid purity paid for an observation proof")
			}
			if err := pureView.Validate(ctx); err != nil {
				t.Fatalf("purity applicability validation demanded producing support: %v", err)
			}
		})
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
			t.Run("damaged "+name, func(t *testing.T) {
				t.Parallel()
				bad := fp
				damage(&bad)
				current, err := damageEngine.newViewFor(ctx, []Subject{s}, dir, Measurement)
				if err != nil {
					t.Fatal(err)
				}
				if updated, _, verdict, err := current.checkInertTestVariantExtension(ctx, bad, ledger, s, true); err != nil || verdict.Status != Unverifiable || updated != (Fingerprint{}) {
					t.Fatalf("%s supplied historical evidence: %+v %v", name, verdict, err)
				}
			})
		}
		t.Run("environment drift", func(t *testing.T) {
			t.Parallel()
			movedEnv := gotool.SetEnv(guardedEnv, "OUTCOME_VALUE", "moved")
			if updated, _, verdict, err := newViewIn(t, movedEnv).checkInertTestVariantExtension(ctx, fp, ledger, s, true); err != nil || verdict.Status != Stale || updated != (Fingerprint{}) {
				t.Fatalf("environment drift: %+v %v", verdict, err)
			}
		})
		// A current analysis cut or unsupported inventory cannot reuse the old proof.
		for name, proof := range map[string]closure.Observability{"cut": {Reason: unavailableReason("test cut")}, "unsupported": {Observable: true}} {
			t.Run("current "+name, func(t *testing.T) {
				t.Parallel()
				v := newViewIn(t, guardedEnv)
				v.observable[s] = proof
				if verdict, err := v.CheckObserved(ctx, fp, s); err != nil || verdict.Status != Unverifiable {
					t.Fatalf("current proof/inventory ignored: %+v %v", verdict, err)
				}
			})
		}
		t.Run("current budget cut", func(t *testing.T) {
			t.Parallel()
			if verdict, err := newViewIn(t, guardedEnv, withAnalysisBudget(time.Nanosecond)).CheckObserved(ctx, fp, s); err != nil || verdict.Status != Unverifiable {
				t.Fatalf("budget-cut current applicability reused historical proof: %+v %v", verdict, err)
			}
		})
		t.Run("deferred validation", func(t *testing.T) {
			t.Parallel()
			deferred := newViewIn(t, guardedEnv, withDeferredCheckClose())
			if _, _, verdict, err := deferred.checkInertTestVariantExtension(ctx, fp, ledger, s, true); err != nil || verdict.Status != Valid {
				t.Fatalf("deferred extension: %+v %v", verdict, err)
			}
			if len(deferred.capturedObserved) != 0 || len(deferred.applicabilityChecks) == 0 {
				t.Fatal("applicability either became producer evidence or lost its validation obligation")
			}
			deferred.session.analysisBudget = time.Nanosecond
			if err := deferred.Validate(ctx); !errors.Is(err, ErrAnalysisUnavailable) {
				t.Fatalf("validation ignored current proof unavailability: %v", err)
			}
		})
		// Sibling producer transactions retain their selected applicability duties.
		t.Run("sibling validation", func(t *testing.T) {
			t.Parallel()
			parent := newViewIn(t, guardedEnv, withDeferredCheckClose())
			if _, _, verdict, err := parent.checkInertTestVariantExtension(ctx, fp, ledger, s, true); err != nil || verdict.Status != Valid {
				t.Fatalf("parent extension: %+v %v", verdict, err)
			}
			sibling, err := parent.Sibling([]Subject{s})
			if err != nil {
				t.Fatal(err)
			}
			if len(sibling.applicabilityChecks) == 0 {
				t.Fatal("sibling dropped applicability obligations")
			}
			parent.session.analysisBudget = time.Nanosecond
			if err := sibling.Validate(ctx); !errors.Is(err, ErrAnalysisUnavailable) {
				t.Fatalf("sibling skipped proof validation: %v", err)
			}
		})
		// A concurrent validation seals even when it is cancelled. In-flight
		// applicability analysis cannot publish either its proof or a replacement.
		t.Run("publication seal", func(t *testing.T) {
			t.Parallel()
			concurrent := newViewIn(t, guardedEnv)
			entered, release := make(chan struct{}), make(chan struct{})
			concurrent.beforePreciseAnalysis = func() { close(entered); <-release }
			workerCtx, stopWorker := context.WithCancel(ctx)
			done := make(chan struct{})
			var resultErr error
			releaseAnalysis := sync.OnceFunc(func() { close(release) })
			defer func() {
				releaseAnalysis()
				stopWorker()
				select {
				case <-done:
				case <-time.After(30 * time.Second):
					t.Error("applicability worker did not finish")
				}
			}()
			go func() {
				defer close(done)
				updated, ledger, _, err := concurrent.checkInertTestVariantExtension(workerCtx, fp, ledger, s, true)
				if updated != (Fingerprint{}) || !reflect.DeepEqual(ledger, TestVariantLedger{}) {
					resultErr = errors.New("published during concurrent validation")
					return
				}
				resultErr = err
			}()
			select {
			case <-entered:
			case <-done:
				t.Fatalf("applicability ended before the analysis boundary: %v", resultErr)
			case <-time.After(30 * time.Second):
				t.Fatal("applicability did not reach the analysis boundary")
			}
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			if err := concurrent.Validate(cancelled); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled validation: %v", err)
			}
			releaseAnalysis()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("applicability did not finish after release")
			}
			if !errors.Is(resultErr, errViewSealed) {
				t.Fatalf("analysis publication crossed seal: %v", resultErr)
			}
		})
	})
	write("growth_test.go", strings.Replace(source, "_ = os.Getenv(\"OUTCOME_VALUE\")", "_, _ = os.LookupEnv(\"OUTCOME_VALUE\")", 1))
	if updated, _, verdict, err := newView().checkInertTestVariantExtension(ctx, fp, ledger, s, true); err != nil || verdict.Status != Stale || updated != (Fingerprint{}) {
		t.Fatalf("changed subject extended: %+v %v", verdict, err)
	}
	write("growth_test.go", source)
	deferred := newView(withDeferredCheckClose())
	if _, _, verdict, err := deferred.checkInertTestVariantExtension(ctx, fp, ledger, s, true); err != nil || verdict.Status != Valid {
		t.Fatalf("deferred extension: %+v %v", verdict, err)
	}
	// New initialization is not inert even though the producing benchmark remains.
	write("growth_test.go", source+"\nfunc init() { os.Setenv(\"OUTCOME_VALUE\",\"changed\") }\n")
	if err := deferred.Validate(ctx); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("deferred close missed source drift: %v", err)
	}
	if updated, _, verdict, err := newView().checkInertTestVariantExtension(ctx, fp, ledger, s, true); err != nil || verdict.Status != Stale || updated != (Fingerprint{}) {
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
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	view, err := engine.newViewFor(ctx, []Subject{pair.Subject}, dir, pair.Fingerprint.ResultKind)
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

type checkingFixture struct {
	binding      *RuntimeBinding
	dir          string
	subjects     []Subject
	old, current map[Subject]Fingerprint
	ledger       TestVariantLedger
}

func newCheckingFixture(t *testing.T) checkingFixture {
	t.Helper()
	dir := writeSupportedViewModule(t)
	const source = `package observed
import ("os"; "testing")
func TestRead(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }
func TestOther(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }
func PureA() {}
func PureB() {}
`
	if err := os.WriteFile(filepath.Join(dir, "observed_test.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{{"example.com/observed", "TestRead"}, {"example.com/observed", "TestOther"}, {"example.com/observed", "PureA"}, {"example.com/observed", "PureB"}}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{Execution: PackageExecution, PureSubjects: subjects[2:]})
	if err != nil {
		t.Fatal(err)
	}
	f := checkingFixture{dir: dir, subjects: subjects}
	produce := func() map[Subject]Fingerprint {
		snapshot, err := session.Snapshot(t.Context(), subjects, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		f.binding = bindTestRuntime(t, snapshot, RuntimeDescription{})
		producer, err := f.binding.newView(subjects)
		if err != nil {
			t.Fatal(err)
		}
		observation := supportedObservation(t, producer, dir, dir, "historical execution", "getenv OUTCOME_VALUE\n")
		captured, err := producer.CaptureObservedBatch(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, subject := range subjects {
			captured[subject], err = producer.AttachObservation(subject, captured[subject], observation)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := producer.Validate(t.Context()); err != nil {
			t.Fatal(err)
		}
		return captured
	}
	f.old = produce()
	f.ledger, err = f.binding.Snapshot().TestVariantLedger(subjects[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "observed_test.go"), []byte(source+"\nfunc TestArithmetic(t *testing.T) {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f.current = produce()
	return f
}

func (f checkingFixture) unit(t *testing.T) *CheckingUnit {
	t.Helper()
	u, err := f.binding.BeginCheck(f.subjects)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(u.Abort)
	return u
}

func TestCheckingUnitCandidatesAndLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("checks historical variants and independently executes a native package unit")
	}
	if runtime.GOOS != "linux" {
		t.Skip("supported outcome method requires Linux")
	}
	f := newCheckingFixture(t)
	a, b, pure := f.subjects[0], f.subjects[1], f.subjects[2]
	t.Run("consumer rounds and independent production", func(t *testing.T) {
		u := f.unit(t)
		candidates := []Candidate{{a, f.old[a]}, {b, f.current[b]}}
		first, err := u.CheckBatch(t.Context(), candidates)
		if err != nil || len(first) != 2 || first[0].Index != 0 || first[1].Index != 1 || first[0].Verdict.Status != Stale || first[1].Verdict.Status != Valid {
			t.Fatalf("initial variants: %+v %v", first, err)
		}
		candidates[0].Recorded = Fingerprint{}
		prior := f.ledger.Clone()
		extended, err := u.ExtendInertBatch(t.Context(), []InertRequest{{Index: 0, PriorLedger: prior}})
		if err != nil || len(extended) != 1 || extended[0].Index != 2 || extended[0].Verdict.Status != Valid || extended[0].Extension == nil {
			t.Fatalf("explicit extension: %+v %v", extended, err)
		}
		expected := extended[0].Extension.Ledger.Clone()
		// Caller input and every nested returned ledger reference are independent.
		prior.FileHeaders[0].Bindings.Package = "changed input"
		extended[0].Extension.Ledger.FileHeaders[0].Bindings.Package = "changed output"
		extended[0].Extension.Ledger.FileHeaders[0].Bindings.References[0] = "changed reference"
		extended[0].Extension.Ledger.Declarations[0].Name = "changed declaration"
		extended[0].Extension.Fingerprint.RuntimeInputs = "borrowed"
		// Another native producing transaction completes while this checking unit
		// holds provisional answers. Neither lifecycle may seal the other.
		snapshot := f.binding.Snapshot()
		build, err := snapshot.BuildDescription(a.Package)
		if err != nil {
			t.Fatal(err)
		}
		binary := filepath.Join(t.TempDir(), "package.test")
		runner := gotool.Runner{}
		if output, err := runner.Run(t.Context(), build.Directory, build.Environment, "test", "-c", "-o", binary, build.Package); err != nil {
			t.Fatalf("build: %v\n%s", err, output)
		}
		artifact, err := snapshot.BindBuilt(a.Package, "retained-package")
		if err != nil {
			t.Fatal(err)
		}
		producer, err := f.binding.BeginPackage([]Subject{a})
		if err != nil {
			t.Fatal(err)
		}
		defer producer.Abort()
		process, err := producer.Register(t.Context(), artifact, ProcessDescription{Identity: "independent execution", Capture: filepath.Join(t.TempDir(), "capture")})
		if err != nil {
			t.Fatal(err)
		}
		cmd, err := testProgramCmd(t.Context(), process.Directory(), process.Environment(), binary, "-test.run=^TestRead$", "-test.testlogfile="+process.Capture())
		if err != nil {
			t.Fatal(err)
		}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("execution: %v\n%s", err, output)
		}
		if err := producer.Submit(process, Terminal{Kind: NormalCompletion}); err != nil {
			t.Fatal(err)
		}
		produced, err := producer.Close(t.Context())
		if err != nil || produced.Subjects[0].Verdict.Status != Valid {
			t.Fatalf("independent producer: %+v %v", produced, err)
		}
		older, err := u.CheckBatch(t.Context(), []Candidate{{a, f.current[a]}})
		if err != nil || len(older) != 1 || older[0].Index != 3 || older[0].Verdict.Status != Valid {
			t.Fatalf("older candidate: %+v %v", older, err)
		}
		if len(u.view.capturedObserved) != 0 || len(u.view.attachedObservations) != 0 {
			t.Fatal("historical checking acquired producing obligations")
		}
		final, err := u.Close(t.Context())
		if err != nil || len(final) != 4 {
			t.Fatalf("close all candidates: %+v %v", final, err)
		}
		for i, result := range final {
			want := Valid
			if i == 0 {
				want = Stale
			}
			if result.Index != i || result.Verdict.Status != want {
				t.Fatalf("slot %d: %+v", i, result)
			}
		}
		if final[0].Extension != nil || final[2].Extension == nil || !reflect.DeepEqual(final[2].Extension.Ledger, expected) || final[2].Extension.Fingerprint.RuntimeInputs != f.old[a].RuntimeInputs {
			t.Fatal("extension replaced old evidence or borrowed a mutable ledger")
		}
		if final[3].Subject != a || final[1].Subject != b {
			t.Fatal("consumer winner indices changed")
		}
		u.Abort()
		if _, err := u.CheckBatch(t.Context(), []Candidate{{a, f.current[a]}}); !errors.Is(err, errUnitClosed) {
			t.Fatalf("closed unit reopened: %v", err)
		}
		if _, err := u.Close(t.Context()); !errors.Is(err, errUnitClosed) {
			t.Fatalf("closed unit reclosed: %v", err)
		}
	})
	t.Run("historical admission stays candidate local", func(t *testing.T) {
		u := f.unit(t)
		good := f.current[a]
		good.InertTestVariantApplicability = InertTestVariantApplicability{InertTestVariantExtension, good.TestVariantClosure}
		bad := good
		bad.ObservationProof.Evidence = "incompatible"
		requests := []Candidate{{a, bad}, {a, good}, {a, good}, {a, bad}}
		read := u.view.runtimeCheck()
		reads := 0
		u.view.runtimeCurrent = func(ctx context.Context, manifest, root string) (runtimeinput.State, error) {
			reads++
			return read(ctx, manifest, root)
		}
		got, err := u.CheckBatch(t.Context(), requests)
		if err != nil || len(got) != 4 || reads != 2 {
			t.Fatalf("variant batch: %+v reads=%d %v", got, reads, err)
		}
		if len(u.view.observable) != 1 || len(u.view.capturedObserved) != 0 {
			t.Fatal("current proof was not shared independently of historical producer obligations")
		}
		final, err := u.Close(t.Context())
		if err != nil || reads != 4 || len(final) != 4 {
			t.Fatalf("variant closing: %+v reads=%d %v", final, reads, err)
		}
		for i, result := range final {
			want := Valid
			if i == 0 || i == 3 {
				want = Unverifiable
			}
			if result.Verdict.Status != want {
				t.Fatalf("slot %d borrowed authority: %+v", i, result)
			}
			if want == Unverifiable && result.Verdict.Ground.Accepted.Observation.accepted() {
				t.Fatal("rejected proof gained observation authority")
			}
		}
	})
	t.Run("endpoint caches include failures and never cross rounds", func(t *testing.T) {
		u := f.unit(t)
		reads := map[string]int{}
		u.view.runtimeCurrent = func(_ context.Context, manifest, _ string) (runtimeinput.State, error) {
			reads[manifest]++
			if manifest == "bad" {
				return runtimeinput.State{}, errors.New("unreadable")
			}
			return runtimeinput.State{OK: true, Manifest: manifest, Digest: "same"}, nil
		}
		var candidates []Candidate
		for _, manifest := range []string{"good", "bad", "bad", "good"} {
			fp := f.current[pure]
			fp.RuntimeInputs, fp.RuntimeDigest = manifest, "same"
			candidates = append(candidates, Candidate{pure, fp})
		}
		for round := 1; round <= 2; round++ {
			got, err := u.CheckBatch(t.Context(), candidates)
			if err != nil || len(got) != 4 || reads["good"] != round*2 || reads["bad"] != round*2 {
				t.Fatalf("round %d: reads=%v result=%+v err=%v", round, reads, got, err)
			}
			for i, result := range got {
				if result.Index != (round-1)*4+i || (result.Verdict.Status == Valid) != (i == 0 || i == 3) {
					t.Fatalf("round candidate: %+v", result)
				}
			}
		}
		if final, err := u.Close(t.Context()); err != nil || len(final) != 8 || reads["good"] != 6 || reads["bad"] != 6 {
			t.Fatalf("close endpoints: reads=%v final=%+v err=%v", reads, final, err)
		}
	})
	t.Run("loser intervals close and stale cannot recover", func(t *testing.T) {
		u := f.unit(t)
		values := map[string]string{"restored": "unavailable", "loser": "recorded", "winner": "recorded"}
		reads := map[string]int{}
		u.view.runtimeCurrent = func(_ context.Context, manifest, _ string) (runtimeinput.State, error) {
			reads[manifest]++
			if values[manifest] == "unavailable" {
				return runtimeinput.State{}, errors.New("input temporarily unreadable")
			}
			return runtimeinput.State{OK: true, Manifest: manifest, Digest: values[manifest]}, nil
		}
		var candidates []Candidate
		for _, manifest := range []string{"restored", "loser", "winner"} {
			fp := f.current[pure]
			fp.RuntimeInputs, fp.RuntimeDigest = manifest, "recorded"
			candidates = append(candidates, Candidate{pure, fp})
		}
		first, err := u.CheckBatch(t.Context(), candidates)
		if err != nil || first[0].Verdict.Status != Stale || first[1].Verdict.Status != Valid || first[2].Verdict.Status != Valid {
			t.Fatalf("opening: %+v %v", first, err)
		}
		values["restored"], values["loser"] = "recorded", "changed"
		final, err := u.Close(t.Context())
		if err != nil || len(final) != 3 || final[0].Verdict.Status != Stale || final[1].Verdict.Status != Stale || final[2].Verdict.Status != Valid {
			t.Fatalf("losing variants escaped closing: %+v %v", final, err)
		}
		if first[0].Verdict.Ground.Cause.Condition != Unavailable || final[0].Verdict != first[0].Verdict {
			t.Fatal("restoring an unreadable input replaced its already decisive stale answer")
		}
		if final[1].Verdict.Ground.Accepted.GuardAgreement || final[1].Verdict.Ground.Accepted.Observation.accepted() {
			t.Fatal("runtime motion retained positive authority")
		}
		for manifest, count := range reads {
			if count != 4 {
				t.Fatalf("manifest %q observed %d times, want independent endpoints", manifest, count)
			}
		}
	})
	t.Run("whole batch preparation is atomic", func(t *testing.T) {
		u := f.unit(t)
		if _, err := u.CheckBatch(t.Context(), []Candidate{{a, f.current[a]}}); err != nil {
			t.Fatal(err)
		}
		priorHook := viewTestHooks.runtimeWindow
		viewTestHooks.runtimeWindow = func() { t.Fatal("invalid input opened a runtime window") }
		defer func() { viewTestHooks.runtimeWindow = priorHook }()
		wrongKind := f.current[a]
		wrongKind.ResultKind = Measurement
		unknown := Subject{a.Package, "Unknown"}
		requests := []Candidate{{a, f.current[a]}, {a, Fingerprint{}}, {unknown, wrongKind}, {b, Fingerprint{}}}
		if got, err := u.CheckBatch(t.Context(), requests); got != nil {
			t.Fatal("partial shape answer escaped")
		} else {
			var batch *RecordedBatchError
			if !errors.As(err, &batch) || batch.Tier != RecordShapeRefusal || len(batch.Failures) != 2 {
				t.Fatalf("whole shape tier: %v", err)
			}
		}
		if _, err := u.CheckBatch(t.Context(), []Candidate{{unknown, wrongKind}, {b, wrongKind}}); err == nil {
			t.Fatal("kind mismatch accepted")
		} else {
			var batch *RecordedBatchError
			if !errors.As(err, &batch) || batch.Tier != RecordKindRefusal || len(batch.Failures) != 2 {
				t.Fatalf("whole kind tier: %v", err)
			}
		}
		other := Subject{a.Package, "OtherUnknown"}
		if _, err := u.CheckBatch(t.Context(), []Candidate{{unknown, f.current[a]}, {other, f.current[a]}, {unknown, f.current[a]}}); err == nil {
			t.Fatal("unknown subjects accepted")
		} else {
			var missing *UnknownSubjectsError
			if !errors.As(err, &missing) || !slices.Equal(missing.Subjects, []Subject{unknown, other}) {
				t.Fatalf("whole membership tier: %v", err)
			}
		}
		if _, err := u.ExtendInertBatch(t.Context(), []InertRequest{{0, f.ledger}, {9, f.ledger}}); err == nil {
			t.Fatal("foreign index accepted")
		}
		if len(u.slots) != 1 || u.phase != unitOpen {
			t.Fatal("input refusal appended slots or ended the unit")
		}
		viewTestHooks.runtimeWindow = priorHook
		if got, err := u.CheckBatch(t.Context(), []Candidate{{b, f.current[b]}}); err != nil || got[0].Index != 1 {
			t.Fatalf("input refusal prevented later admission: %+v %v", got, err)
		}
		if _, err := u.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("whole runtime span cannot upgrade later", func(t *testing.T) {
		u := f.unit(t)
		read := u.view.runtimeCheck()
		refused := true
		u.view.runtimeCurrent = func(ctx context.Context, manifest, root string) (runtimeinput.State, error) {
			state, err := read(ctx, manifest, root)
			if refused {
				state.Unverifiable, state.Reason = true, "earlier endpoint could not establish the input"
			}
			return state, err
		}
		if got, err := u.CheckBatch(t.Context(), []Candidate{{a, f.current[a]}}); err != nil || got[0].Verdict.Status != Unverifiable {
			t.Fatalf("opening refusal: %+v %v", got, err)
		}
		refused = false
		if got, err := u.Close(t.Context()); err != nil || got[0].Verdict.Status != Stale || got[0].Verdict.Ground.Accepted.GuardAgreement {
			t.Fatalf("closing forgot a consulted earlier endpoint: %+v %v", got, err)
		}
	})
	t.Run("evidence only refusal observes no runtime", func(t *testing.T) {
		u := f.unit(t)
		u.view.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
			t.Fatal("evidence-only refusal read runtime")
			return runtimeinput.State{}, nil
		}
		if got, err := u.CheckBatch(t.Context(), []Candidate{{a, f.old[a]}}); err != nil || got[0].Verdict.Status != Stale {
			t.Fatalf("evidence refusal: %+v %v", got, err)
		}
		if got, err := u.Close(t.Context()); err != nil || got[0].Verdict.Status != Stale {
			t.Fatalf("evidence close: %+v %v", got, err)
		}
	})
	t.Run("legacy map and singleton adapters agree", func(t *testing.T) {
		legacy, err := f.binding.newView(f.subjects)
		if err != nil {
			t.Fatal(err)
		}
		batch := map[Subject]Fingerprint{a: f.current[a], b: f.current[b]}
		want, err := legacy.CheckObservedBatch(t.Context(), batch)
		if err != nil {
			t.Fatal(err)
		}
		u := f.unit(t)
		if _, err := u.CheckBatch(t.Context(), []Candidate{{b, batch[b]}, {a, batch[a]}}); err != nil {
			t.Fatal(err)
		}
		got, err := u.Close(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range got {
			single, err := f.binding.Check(t.Context(), row.Subject, batch[row.Subject])
			if err != nil || single != row.Verdict || row.Verdict != want[row.Subject] {
				t.Fatalf("adapter changed judgment: %+v %v", row, err)
			}
		}
	})
	t.Run("source drift grants no prefix", func(t *testing.T) {
		u := f.unit(t)
		if _, err := u.CheckBatch(t.Context(), []Candidate{{a, f.current[a]}, {b, f.current[b]}}); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(f.dir, "observed_test.go")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Error(err)
			}
		}()
		if err := os.WriteFile(path, append(data, []byte("\nfunc TestLate(t *testing.T) {}\n")...), 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := u.Close(t.Context()); !errors.Is(err, ErrViewChanged) || got != nil {
			t.Fatalf("source drift exposed final answers: %+v %v", got, err)
		}
	})
	t.Run("selected loser proof must be reestablished", func(t *testing.T) {
		u := f.unit(t)
		if _, err := u.CheckBatch(t.Context(), []Candidate{{a, f.old[a]}, {b, f.current[b]}}); err != nil {
			t.Fatal(err)
		}
		if got, err := u.ExtendInertBatch(t.Context(), []InertRequest{{0, f.ledger}}); err != nil || got[0].Verdict.Status != Valid {
			t.Fatalf("extension control: %+v %v", got, err)
		}
		if _, err := u.CheckBatch(t.Context(), []Candidate{{a, f.current[a]}}); err != nil {
			t.Fatal(err)
		}
		engine := f.binding.snapshot.session
		prior := engine.analysisBudget
		engine.analysisBudget = time.Nanosecond
		defer func() { engine.analysisBudget = prior }()
		analyses := 0
		priorAnalysis := viewTestHooks.beforeAnalysis
		viewTestHooks.beforeAnalysis = func() { analyses++ }
		defer func() { viewTestHooks.beforeAnalysis = priorAnalysis }()
		if got, err := u.Close(t.Context()); !errors.Is(err, ErrAnalysisUnavailable) || got != nil || analyses != 1 {
			t.Fatalf("losing extension reused opening proof: %+v %v", got, err)
		}
	})
	t.Run("CheckBatchWithLedgers extends ReasonTestVariants in one unit", func(t *testing.T) {
		candidates := []Candidate{{a, f.old[a]}, {b, f.current[b]}}
		checked, err := f.binding.CheckBatchWithLedgers(t.Context(), candidates, map[int]TestVariantLedger{0: f.ledger})
		if err != nil || len(checked) != 2 {
			t.Fatalf("CheckBatchWithLedgers: %+v %v", checked, err)
		}
		if checked[0].Index != 0 || checked[0].Subject != a || checked[0].Verdict.Status != Valid || checked[0].Extension == nil {
			t.Fatalf("candidate 0 not extended: %+v", checked[0])
		}
		if checked[1].Index != 1 || checked[1].Subject != b || checked[1].Verdict.Status != Valid || checked[1].Extension != nil {
			t.Fatalf("candidate 1 unexpected extension: %+v", checked[1])
		}
		// Mixed batch where candidate 0 is inertly extended and candidate 1's prior ledger is non-inert (removed declaration).
		nonInertLedger := f.ledger.Clone()
		nonInertLedger.Declarations = append(nonInertLedger.Declarations, TestVariantDeclaration{
			File: "observed_test.go", Package: "observed", Kind: "func", Name: "TestOther", Hash: "edited-hash", References: []string{"TestOther"},
		})
		mixed, err := f.binding.CheckBatchWithLedgers(t.Context(), []Candidate{{a, f.old[a]}, {b, f.old[b]}}, map[int]TestVariantLedger{
			0: f.ledger,
			1: nonInertLedger,
		})
		if err != nil || len(mixed) != 2 {
			t.Fatalf("mixed CheckBatchWithLedgers: %+v %v", mixed, err)
		}
		if mixed[0].Verdict.Status != Valid || mixed[0].Extension == nil {
			t.Fatalf("mixed candidate 0 should extend to Valid: %+v", mixed[0])
		}
		if mixed[1].Verdict.Status != Stale || mixed[1].Verdict.Reason != ReasonTestVariants || mixed[1].Verdict.Ground.Cause != (Cause{Kind: TestVariantsCause, Condition: Changed}) || mixed[1].Extension != nil {
			t.Fatalf("mixed candidate 1 should remain Stale/ReasonTestVariants (Condition: Changed): %+v", mixed[1])
		}
		// When the compartment delta is inert for candidate 1, but a downstream tier (e.g. runtime digest)
		// fails after compartment substitution, the unextended candidate retains its TestVariants (Changed) verdict.
		driftedRuntime := f.old[b]
		driftedRuntime.RuntimeDigest = "0000000000000000000000000000000000000000000000000000000000000000"
		downstreamFailed, err := f.binding.CheckBatchWithLedgers(t.Context(), []Candidate{{a, f.old[a]}, {b, driftedRuntime}}, map[int]TestVariantLedger{
			0: f.ledger,
			1: f.ledger,
		})
		if err != nil || len(downstreamFailed) != 2 {
			t.Fatalf("downstreamFailed CheckBatchWithLedgers: %+v %v", downstreamFailed, err)
		}
		if downstreamFailed[0].Verdict.Status != Valid || downstreamFailed[0].Extension == nil {
			t.Fatalf("downstreamFailed candidate 0 should extend to Valid: %+v", downstreamFailed[0])
		}
		if downstreamFailed[1].Verdict.Status != Stale || downstreamFailed[1].Verdict.Reason != ReasonTestVariants || downstreamFailed[1].Verdict.Ground.Cause != (Cause{Kind: TestVariantsCause, Condition: Changed}) || downstreamFailed[1].Extension != nil {
			t.Fatalf("downstreamFailed candidate 1 should remain unextended Stale/ReasonTestVariants (Condition: Changed): %+v", downstreamFailed[1])
		}
		// Atomic preparation precedence and nil-context refusal on CheckBatchWithLedgers.
		if _, err := f.binding.CheckBatchWithLedgers(nil, candidates, nil); err == nil {
			t.Fatal("nil context accepted by CheckBatchWithLedgers")
		}
		unknown := Subject{a.Package, "TestMissing"}
		var batch *RecordedBatchError
		if _, err := f.binding.CheckBatchWithLedgers(t.Context(), []Candidate{{unknown, Fingerprint{}}}, nil); !errors.As(err, &batch) || batch.Tier != RecordShapeRefusal {
			t.Fatalf("CheckBatchWithLedgers shape-before-membership precedence = %v, want RecordShapeRefusal", err)
		}
		var unknownErr *UnknownSubjectsError
		if _, err := f.binding.CheckBatchWithLedgers(t.Context(), []Candidate{{unknown, f.current[a]}}, nil); !errors.As(err, &unknownErr) || unknownErr.Scope != SelectedView {
			t.Fatalf("CheckBatchWithLedgers unknown subject error = %v, want UnknownSubjectsError{Scope: SelectedView}", err)
		}
	})
}

func TestCheckingUnitCancellationAndAbort(t *testing.T) {
	if testing.Short() {
		t.Skip("closes independent checking intervals under cancellation")
	}
	dir := writeViewModule(t, "package view\nfunc F() {}\n")
	subject := Subject{"example.com/view", "F"}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	binding := bindTestRuntime(t, snapshot, RuntimeDescription{})
	fp, err := binding.CurrentFacts(t.Context(), subject)
	if err != nil {
		t.Fatal(err)
	}
	fp.RuntimeInputs, fp.RuntimeDigest = "held", "same"
	for _, closePhase := range []bool{false, true} {
		for _, callerCancel := range []bool{false, true} {
			u, err := binding.BeginCheck([]Subject{subject})
			if err != nil {
				t.Fatal(err)
			}
			ready, release := make(chan struct{}), make(chan struct{})
			once := sync.Once{}
			u.view.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
				return runtimeinput.State{OK: true, Manifest: "held", Digest: "same"}, nil
			}
			if closePhase {
				if _, err := u.CheckBatch(t.Context(), []Candidate{{subject, fp}}); err != nil {
					t.Fatal(err)
				}
			}
			u.view.runtimeCurrent = func(ctx context.Context, _, _ string) (runtimeinput.State, error) {
				once.Do(func() { close(ready) })
				<-release
				return runtimeinput.State{}, ctx.Err()
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				if closePhase {
					got, err := u.Close(ctx)
					if got != nil {
						done <- errors.New("aborted close returned evidence")
						return
					}
					done <- err
				} else {
					got, err := u.CheckBatch(ctx, []Candidate{{subject, fp}})
					if got != nil {
						done <- errors.New("aborted round returned evidence")
						return
					}
					done <- err
				}
			}()
			select {
			case <-ready:
			case err := <-done:
				t.Fatalf("work did not reach observation: %v", err)
			case <-time.After(20 * time.Second):
				t.Fatal("observation did not start")
			}
			if callerCancel {
				cancel()
			}
			u.Abort()
			close(release)
			want := errUnitAborted
			if callerCancel {
				want = context.Canceled
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("closing=%v callerCancelled=%v: %v, want %v", closePhase, callerCancel, err, want)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("cancelled work did not finish")
			}
			cancel()
			if got, err := u.Close(t.Context()); !errors.Is(err, errUnitClosed) || got != nil {
				t.Fatalf("ended unit reopened: %+v %v", got, err)
			}
		}
	}
	// A fresh transaction remains usable after every independent abort above.
	t.Run("serialized rounds", func(t *testing.T) {
		u, err := binding.BeginCheck([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		defer u.Abort()
		ready, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		resume := sync.OnceFunc(func() { close(release) })
		defer resume()
		u.view.runtimeCurrent = func(ctx context.Context, _, _ string) (runtimeinput.State, error) {
			once.Do(func() { close(ready); <-release })
			return runtimeinput.State{OK: true, Manifest: "held", Digest: "same"}, ctx.Err()
		}
		type answer struct {
			rows []CheckedCandidate
			err  error
		}
		first, second := make(chan answer, 1), make(chan answer, 1)
		go func() { rows, err := u.CheckBatch(t.Context(), []Candidate{{subject, fp}}); first <- answer{rows, err} }()
		select {
		case <-ready:
		case <-time.After(20 * time.Second):
			t.Fatal("first round did not start")
		}
		go func() {
			rows, err := u.CheckBatch(t.Context(), []Candidate{{subject, fp}})
			second <- answer{rows, err}
		}()
		// Cancellation while waiting for admission never cancels the active round.
		cancelled, cancel := context.WithCancel(t.Context())
		defer cancel()
		waiting := &checkingAdmissionContext{Context: cancelled, observed: make(chan struct{})}
		waiter := make(chan answer, 1)
		go func() {
			rows, err := u.CheckBatch(waiting, []Candidate{{subject, fp}})
			waiter <- answer{rows, err}
		}()
		select {
		case <-waiting.observed:
		case <-time.After(20 * time.Second):
			t.Fatal("waiter did not reach admission while the first round was active")
		}
		cancel()
		select {
		case got := <-waiter:
			if !errors.Is(got.err, context.Canceled) || got.rows != nil {
				t.Fatalf("cancelled waiter: %+v %v", got.rows, got.err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("cancelled waiter did not return before the active round was released")
		}
		resume()
		for i, ch := range []chan answer{first, second} {
			select {
			case got := <-ch:
				if got.err != nil || len(got.rows) != 1 || got.rows[0].Index != i {
					t.Fatalf("serialized round %d: %+v %v", i, got.rows, got.err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("serialized round did not finish")
			}
		}
		if rows, err := u.Close(t.Context()); err != nil || len(rows) != 2 {
			t.Fatalf("serialized close: %+v %v", rows, err)
		}
	})
	t.Run("closing refuses active admission", func(t *testing.T) {
		u, err := binding.BeginCheck([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		ready, release := make(chan struct{}), make(chan struct{})
		resume := sync.OnceFunc(func() { close(release) })
		defer resume()
		u.view.runtimeCurrent = func(ctx context.Context, _, _ string) (runtimeinput.State, error) {
			close(ready)
			<-release
			return runtimeinput.State{}, ctx.Err()
		}
		done := make(chan error, 1)
		go func() {
			rows, err := u.CheckBatch(t.Context(), []Candidate{{subject, fp}})
			if rows != nil {
				done <- errors.New("closed admission appended a candidate")
				return
			}
			done <- err
		}()
		select {
		case <-ready:
		case <-time.After(20 * time.Second):
			t.Fatal("round did not start")
		}
		if rows, err := u.Close(t.Context()); !errors.Is(err, ErrUnitIncomplete) || rows != nil {
			t.Fatalf("active round was silently excluded: %+v %v", rows, err)
		}
		resume()
		select {
		case err := <-done:
			if !errors.Is(err, errUnitClosed) {
				t.Fatalf("late append: %v", err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("closed admission did not return")
		}
		if len(u.slots) != 0 {
			t.Fatal("round appended after closing froze the unit")
		}
	})
	t.Run("runtime cancellation is not an ordinary failure", func(t *testing.T) {
		u, err := binding.BeginCheck([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		u.view.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
			calls++
			return runtimeinput.State{}, context.Canceled
		}
		if rows, err := u.CheckBatch(t.Context(), []Candidate{{subject, fp}, {subject, fp}}); !errors.Is(err, context.Canceled) || rows != nil || calls != 1 {
			t.Fatalf("runtime cancellation became an answer: %+v calls=%d err=%v", rows, calls, err)
		}
		if rows, err := u.Close(t.Context()); !errors.Is(err, errUnitClosed) || rows != nil {
			t.Fatalf("operational failure left the unit open: %+v %v", rows, err)
		}
	})
	t.Run("cancelled close ends unit", func(t *testing.T) {
		u, err := binding.BeginCheck([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if rows, err := u.Close(ctx); !errors.Is(err, context.Canceled) || rows != nil {
			t.Fatalf("cancelled close: %+v %v", rows, err)
		}
		if _, err := u.CheckBatch(t.Context(), nil); !errors.Is(err, errUnitClosed) {
			t.Fatalf("cancelled close reopened: %v", err)
		}
	})
	ordinary := fp
	ordinary.RuntimeInputs, ordinary.RuntimeDigest = "", ""
	if got, err := binding.Check(t.Context(), subject, ordinary); err != nil || got.Status != Valid {
		t.Fatalf("aborted sibling sealed binding: %+v %v", got, err)
	}
}

// checkingAdmissionContext reports consultation of the cancellation channel.
// With the gate held by another round, this marks admission waiting after the
// entry's initial Err check without adding a production scheduling hook.
type checkingAdmissionContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *checkingAdmissionContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func writeSupportedViewModule(t *testing.T) string {
	t.Helper()
	dir := writeObservedViewModule(t)
	source := "package observed\n\nimport (\"os\"; \"testing\")\n\nfunc TestRead(*testing.T) { _ = os.Getenv(\"OUTCOME_VALUE\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "observed_test.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// supportedObservation is a checker fixture with actual engine-issued support.
// The execution test below separately checks receipts from a real test binary.
func supportedObservation(t *testing.T, view *Snapshot, root, dir, process, log string) runtimeinput.Observation {
	t.Helper()
	frame := runtimeinput.CaptureProducerFrame(context.Background(), root, dir, runtimeinput.FrameOptions{})
	support, _, err := view.prepareOutcomeSupport(context.Background(), frame, process)
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.EnvForCommand(view.session.evidenceEnv(), dir)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := frame.Completion(process, env, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "capture.log")
	if err := os.WriteFile(path, []byte("# test log\n"+log), 0o644); err != nil {
		t.Fatal(err)
	}
	observation, reason, err := frame.Observe(context.Background(), path, runtimeinput.ProducerIngest{Identity: process, Env: env, Completion: receipt, Outcome: support})
	if err != nil || reason != "" {
		t.Fatalf("supported fixture = %q %v", reason, err)
	}
	return observation
}

func TestOutcomeSupportCannotCrossTestVariantChange(t *testing.T) {
	if testing.Short() {
		t.Skip("builds source views across a test-body change")
	}
	ctx := context.Background()
	dir := writeSupportedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	before, err := engine.newView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	old, err := before.captureObserved(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	observation := supportedObservation(t, before, dir, dir, "old execution", "getenv OUTCOME_VALUE\n")
	newBody := "package observed\nimport (\"os\"; \"testing\")\nfunc TestRead(*testing.T) { _, _ = os.ReadFile(\"fixture\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "observed_test.go"), []byte(newBody), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := engine.newView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := after.captureObserved(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.MaximalClosure != old.MaximalClosure || fresh.TestVariantClosure == old.TestVariantClosure || !fresh.ObservationProof.Observable {
		t.Fatal("fixture did not isolate an observable test-body change")
	}
	fresh.RuntimeInputs, fresh.RuntimeDigest = observation.Manifest, observation.Digest
	verdict, err := after.CheckObserved(ctx, fresh, subject)
	if err != nil || verdict.Status != Unverifiable {
		t.Fatalf("new test body borrowed old outcomes: %+v %v", verdict, err)
	}
}

func TestOutcomePreparationRejectsInvalidAndEndedTransactions(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs source views and exercises preparation lifecycle")
	}
	ctx := context.Background()
	dir := writeSupportedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	frame := runtimeinput.CaptureProducerFrame(ctx, dir, dir, runtimeinput.FrameOptions{})
	view, err := engine.newView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := (&Snapshot{session: engine, facts: view.facts}).prepareOutcomeSupport(ctx, frame, "worker"); err == nil || !strings.Contains(err.Error(), "contributing subjects") {
		t.Fatalf("empty preparation: %v", err)
	}
	bad := frame
	bad.PkgDir = "bad\x00directory"
	if _, _, err := view.prepareOutcomeSupport(ctx, bad, "worker"); err == nil {
		t.Fatal("invalid environment coordinate accepted")
	}
	if _, _, err := view.prepareOutcomeSupport(ctx, frame, ""); err == nil {
		t.Fatal("invalid process identity accepted")
	}
	for _, cancelInstead := range []bool{false, true} {
		view, err := engine.newView(ctx, []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		callCtx, cancel := context.WithCancel(ctx)
		view.beforeOutcomeIssue = func() {
			if cancelInstead {
				cancel()
				return
			}
			if err := view.Validate(ctx); err == nil {
				t.Error("validation accepted missing attachment")
			}
		}
		support, _, err := view.prepareOutcomeSupport(callCtx, frame, "worker")
		cancel()
		want := errViewSealed
		if cancelInstead {
			want = context.Canceled
		}
		if !errors.Is(err, want) || len(support.Subjects()) != 0 {
			t.Fatalf("ended preparation: %v, want %v", err, want)
		}
	}
}

func TestOutcomeSupportBindsActualExecutionAndRecordedSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes an observed test binary")
	}
	ctx := context.Background()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module example.com/outcomes\n\ngo 1.26\n",
		"fixture": "guarded bytes",
		"subject_test.go": `package outcomes
import ("os"; "testing")
func TestEnv(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }
func TestOther(t *testing.T) { _ = os.Getenv("OUTCOME_OTHER") }
func TestFile(t *testing.T) { _, _ = os.ReadFile("fixture") }
func TestFail(t *testing.T) { _, _ = os.LookupEnv("OUTCOME_VALUE"); t.Error("ordinary failure") }
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env, err := gotool.EnvForCommand(os.Environ(), dir)
	if err != nil {
		t.Fatal(err)
	}
	env = gotool.SetEnv(env, "OUTCOME_VALUE", "value")
	bin := filepath.Join(t.TempDir(), "subject.test")
	build := exec.Command("go", "test", "-c", "-o", bin, ".")
	build.Dir = dir
	build.Env = env
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	engine, err := newEngine(withDir(dir), withEnv(env...))
	if err != nil {
		t.Fatal(err)
	}
	// Join the independently owned execution transactions before inspecting
	// mixed-process support. The fixture and executable stay parent-owned.
	t.Run("transactions", func(t *testing.T) {
		for _, tc := range []struct {
			symbol    string
			supported bool
			exit      int
		}{
			{"TestEnv", true, 0}, {"TestFail", true, 1}, {"TestFile", false, 0},
		} {
			t.Run(tc.symbol, func(t *testing.T) {
				t.Parallel()
				subject := Subject{Package: "example.com/outcomes", Symbol: tc.symbol}
				view, err := engine.newView(ctx, []Subject{subject}, dir)
				if err != nil {
					t.Fatal(err)
				}
				frame := runtimeinput.CaptureProducerFrame(ctx, dir, dir, runtimeinput.FrameOptions{})
				support, _, err := view.prepareOutcomeSupport(ctx, frame, "execution")
				if err != nil {
					t.Fatal(err)
				}
				fp, err := view.captureObserved(ctx, subject)
				if err != nil {
					t.Fatal(err)
				}
				log := filepath.Join(t.TempDir(), "input.log")
				command := exec.Command(bin, "-test.v", "-test.run=^"+tc.symbol+"$", "-test.testlogfile="+log)
				command.Dir = dir
				command.Env = env
				output, runErr := command.CombinedOutput()
				if command.ProcessState == nil || !command.ProcessState.Exited() || command.ProcessState.ExitCode() != tc.exit {
					t.Fatalf("execution: %v\n%s", runErr, output)
				}
				if tc.exit == 1 && !strings.Contains(string(output), "ordinary failure") {
					t.Fatalf("not the expected completed failure: %s", output)
				}
				receipt, err := frame.Completion("execution", env, "")
				if err != nil {
					t.Fatal(err)
				}
				obs, reason, err := frame.Observe(ctx, log, runtimeinput.ProducerIngest{Identity: "execution", Env: env, Completion: receipt, Outcome: support})
				if err != nil {
					t.Fatal(err)
				}
				if tc.supported != (reason == "") {
					t.Fatalf("outcome reason=%q, want supported=%t", reason, tc.supported)
				}
				fp, err = view.AttachObservation(subject, fp, obs)
				if err != nil {
					t.Fatal(err)
				}
				if err := view.Validate(ctx); err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(fp)
				if err != nil {
					t.Fatal(err)
				}
				var stored Fingerprint
				if err := json.Unmarshal(data, &stored); err != nil || stored != fp {
					t.Fatalf("record roundtrip=%v", err)
				}
				current, err := engine.newView(ctx, []Subject{subject}, dir)
				if err != nil {
					t.Fatal(err)
				}
				verdict, err := current.CheckObserved(ctx, stored, subject)
				if err != nil {
					t.Fatal(err)
				}
				want := Unverifiable
				if tc.supported {
					want = Valid
				}
				if verdict.Status != want {
					t.Fatalf("verdict=%+v want %v", verdict, want)
				}
				if tc.symbol != "TestEnv" {
					return
				}
				// Isolate support identity from the stale-guard ladder: each changed
				// fingerprint names its own fresh code facts, but retains the old
				// runtime support. No ordinary verdict comparison can mask an omitted
				// constituent of the support identity in this check.
				for name, change := range map[string]func(*Fingerprint){
					"closure":      func(f *Fingerprint) { f.MaximalClosure = "another closure" },
					"test variant": func(f *Fingerprint) { f.TestVariantClosure = "another test variant" },
					"toolchain":    func(f *Fingerprint) { f.Guards.Toolchain = "another toolchain" },
					"build":        func(f *Fingerprint) { f.Guards.BuildConfig = "another build" },
				} {
					fresh := fp
					change(&fresh)
					fresh.ObservationProof.Evidence = observationProofEvidence(fresh)
					if !compatibleObservationProof(fresh, subject) {
						t.Fatal("test did not construct a compatible fresh proof")
					}
					if runtimeinput.HasOutcomeSupport(obs.Manifest, outcomeSubject(fresh, subject)) {
						t.Fatalf("%s borrowed old outcome support", name)
					}
				}
				changedStrategy := fp
				changedStrategy.ObservationProof.Strategy = "another proof strategy"
				if runtimeinput.HasOutcomeSupport(obs.Manifest, outcomeSubject(changedStrategy, subject)) {
					t.Fatal("another proof strategy borrowed old outcome support")
				}
				// Same package and environment are insufficient: the runtime evidence
				// must include the exact subject's preparation identity.
				other := Subject{Package: subject.Package, Symbol: "TestOther"}
				otherView, err := engine.newView(ctx, []Subject{other}, dir)
				if err != nil {
					t.Fatal(err)
				}
				otherFP, err := otherView.captureObserved(ctx, other)
				if err != nil {
					t.Fatal(err)
				}
				otherFP.RuntimeInputs, otherFP.RuntimeDigest = fp.RuntimeInputs, fp.RuntimeDigest
				wrong, err := otherView.CheckObserved(ctx, otherFP, other)
				if err != nil || wrong.Status != Unverifiable {
					t.Fatalf("borrowed subject support=%+v %v", wrong, err)
				}
				// An identity-only observation is still useful for input movement,
				// but neither attachment nor checking manufactures outcome support.
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
				refused, err := current.CheckObserved(ctx, missing, subject)
				if err != nil || refused.Status != Unverifiable {
					t.Fatalf("identity-only support=%+v %v", refused, err)
				}
				movedEnv := gotool.SetEnv(env, "OUTCOME_VALUE", "changed")
				movedEngine, err := newEngine(withDir(dir), withEnv(movedEnv...))
				if err != nil {
					t.Fatal(err)
				}
				moved, err := movedEngine.newView(ctx, []Subject{subject}, dir)
				if err != nil {
					t.Fatal(err)
				}
				stale, err := moved.CheckObserved(ctx, stored, subject)
				if err != nil || stale.Status != Stale {
					t.Fatalf("moved environment=%+v %v", stale, err)
				}
			})
		}
	})
	// A process set containing an unsupported member cannot borrow support
	// from an independently eligible member.
	set := []Subject{{Package: "example.com/outcomes", Symbol: "TestEnv"}, {Package: "example.com/outcomes", Symbol: "TestFile"}}
	view, err := engine.newView(ctx, set, dir)
	if err != nil {
		t.Fatal(err)
	}
	frame := runtimeinput.CaptureProducerFrame(ctx, dir, dir, runtimeinput.FrameOptions{})
	support, _, err := view.prepareOutcomeSupport(ctx, frame, "mixed")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := frame.OutcomeBinding("mixed", env)
	if err != nil {
		t.Fatal(err)
	}
	if reason := support.Reason(binding); !strings.Contains(reason, "example.com/outcomes.TestFile") {
		t.Fatalf("mixed support reason=%q", reason)
	}
	// No explicit CaptureObserved follows preparation here: preparation itself
	// must retain the proof/attachment obligation used by producer validation.
	if err := view.Validate(ctx); err == nil || !strings.Contains(err.Error(), "no attached completed observation") {
		t.Fatalf("preparation lost its validation obligation: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := view.prepareOutcomeSupport(cancelled, frame, "cancelled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled support=%v", err)
	}
}

func TestStaticReachabilityAdmitsEffectFreeSubjectWithIdentityOnlyObservation(t *testing.T) {
	if testing.Short() {
		t.Skip("builds source views and checks static-reachability outcome support")
	}
	ctx := context.Background()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module example.com/staticreach\n\ngo 1.26\n",
		"fixture": "guarded bytes",
		"subject.go": `package staticreach

func PureAdd(a, b int) int {
	return a + b
}
`,
		"subject_test.go": `package staticreach

import (
	"os"
	"testing"
)

func TestPure(t *testing.T) {
	if PureAdd(1, 2) != 3 {
		t.Fatal("wrong sum")
	}
}

func TestEnv(t *testing.T) {
	_ = os.Getenv("STATIC_REACH_ENV")
}

func TestFile(t *testing.T) {
	_, _ = os.ReadFile("fixture")
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env, err := gotool.EnvForCommand(os.Environ(), dir)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withDir(dir), withEnv(env...))
	if err != nil {
		t.Fatal(err)
	}
	pureAdd := Subject{Package: "example.com/staticreach", Symbol: "PureAdd"}
	testPure := Subject{Package: "example.com/staticreach", Symbol: "TestPure"}
	testEnv := Subject{Package: "example.com/staticreach", Symbol: "TestEnv"}
	testFile := Subject{Package: "example.com/staticreach", Symbol: "TestFile"}
	subjects := []Subject{pureAdd, testPure, testEnv, testFile}

	view, err := engine.newView(ctx, subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	bracket, err := runtimeinput.CaptureBracket(ctx, dir, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	identityObs, err := runtimeinput.FromTestLog([]byte("# test log\n"), dir, dir, env, runtimeinput.WithCompletedProcess("identity-only"), runtimeinput.WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	stored := make(map[Subject]Fingerprint, len(subjects))
	for _, s := range subjects {
		fp, err := view.captureObserved(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		fp, err = view.AttachObservation(s, fp, identityObs)
		if err != nil {
			t.Fatal(err)
		}
		stored[s] = fp
	}
	if err := view.Validate(ctx); err != nil {
		t.Fatal(err)
	}

	checkView, err := engine.newView(ctx, subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []Subject{pureAdd, testPure} {
		verdict, err := checkView.CheckObserved(ctx, stored[s], s)
		if err != nil {
			t.Fatal(err)
		}
		if verdict.Status != Valid {
			t.Fatalf("%v status = %v (reason=%q), want Valid", s, verdict.Status, verdict.Reason)
		}
		if verdict.Ground.Accepted.Observation.OutcomeMethod != "gofresh/static-reachability@1" {
			t.Fatalf("%v accepted observation = %+v, want OutcomeMethod=gofresh/static-reachability@1", s, verdict.Ground.Accepted.Observation)
		}
		// Downgrading the proof seal to the non-effect-free mode removes static-reachability authority.
		downgraded := stored[s]
		downgraded.ObservationProof.Evidence = observationProofEvidenceMode(downgraded, false)
		refused, err := checkView.CheckObserved(ctx, downgraded, s)
		if err != nil || refused.Status != Unverifiable {
			t.Fatalf("%v with non-effect-free seal = %+v %v, want Unverifiable", s, refused, err)
		}
	}
	for _, s := range []Subject{testEnv, testFile} {
		verdict, err := checkView.CheckObserved(ctx, stored[s], s)
		if err != nil {
			t.Fatal(err)
		}
		if verdict.Status != Unverifiable {
			t.Fatalf("%v status = %v, want Unverifiable under identity-only observation", s, verdict.Status)
		}
	}
}

// This witness executes the admitted subject set, including the unsupported
// member. A fixture that ran only the publishable subset would not test the
// process-wide support obligation.
func TestPackageUnitOwnsTheWholeExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes package processes and independent retries")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the admitted immutable-environment outcome method is Linux-specific")
	}
	dir := t.TempDir()
	const source = `package packageunit
import ("os"; "testing")
func TestA(t *testing.T) { if os.Getenv("PACKAGE_A") != "a" { t.Fatal("wrong A") } }
func TestB(t *testing.T) { if os.Getenv("PACKAGE_B") != "b" { t.Fatal("wrong B") } }
func TestFile(t *testing.T) { _, _ = os.ReadFile("input") }
func TestPureFile(t *testing.T) { _, _ = os.ReadFile("input") }
func TestFail(t *testing.T) { _ = os.Getenv("PACKAGE_FAIL"); t.Error("ordinary failure") }
func TestCrash(t *testing.T) { _ = os.Getenv("PACKAGE_CRASH"); panic("abnormal termination") }
`
	for name, text := range map[string]string{
		"go.mod":    "module example.com/packageunit\n\ngo 1.27.0\n",
		"p_test.go": source,
		"input":     "guarded input",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	pkg := "example.com/packageunit"
	a, b := Subject{Package: pkg, Symbol: "TestA"}, Subject{Package: pkg, Symbol: "TestB"}
	file, pureFile := Subject{Package: pkg, Symbol: "TestFile"}, Subject{Package: pkg, Symbol: "TestPureFile"}
	fail, crash := Subject{Package: pkg, Symbol: "TestFail"}, Subject{Package: pkg, Symbol: "TestCrash"}
	env := gotool.SetEnv(gotool.SetEnv(os.Environ(), "PACKAGE_A", "a"), "PACKAGE_B", "b")
	runner := gotool.Runner{}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: env, Inputs: []string{}}, SessionPolicy{Execution: PackageExecution, PureSubjects: []Subject{pureFile}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(t.Context(), []Subject{a, b, file, pureFile, fail, crash}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	execution := bindTestRuntime(t, snapshot, RuntimeDescription{})
	build, err := snapshot.BuildDescription(pkg)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "package.test")
	args := append([]string{"test", "-c", "-o", binary}, build.Flags...)
	args = append(args, build.Package)
	if output, err := runner.Run(t.Context(), build.Directory, build.Environment, args...); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	bound, err := snapshot.BindBuilt(pkg, "retained-package-artifact")
	if err != nil {
		t.Fatal(err)
	}
	start := func(t *testing.T, selected []Subject, exit int, terminal Terminal) (*Unit, Contribution) {
		t.Helper()
		requested := append([]Subject(nil), selected...)
		requested = append(requested, selected[0])
		u, err := execution.BeginPackage(requested)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(u.Abort)
		requested[0] = Subject{Package: "wrong", Symbol: "borrowed"}
		process, err := u.Register(t.Context(), bound, ProcessDescription{Identity: t.Name(), Capture: filepath.Join(t.TempDir(), "capture"), BracketPaths: []string{"input"}})
		if err != nil {
			t.Fatal(err)
		}
		actual := process.Subjects()
		if !slices.Equal(actual, selected) {
			t.Fatalf("execution scope = %v, want %v", actual, selected)
		}
		actual[0] = requested[0]
		if !slices.Equal(process.Subjects(), selected) {
			t.Fatal("contribution aliases its subject scope")
		}
		if _, err := u.Register(t.Context(), bound, ProcessDescription{Identity: "second process"}); err == nil {
			t.Fatal("one execution silently admitted a second process")
		}
		var symbols []string
		for _, subject := range selected {
			symbols = append(symbols, subject.Symbol)
		}
		cmd, err := testProgramCmd(t.Context(), process.Directory(), process.Environment(), binary,
			"-test.v", "-test.run=^("+strings.Join(symbols, "|")+")$", "-test.testlogfile="+process.Capture())
		if err != nil {
			t.Fatal(err)
		}
		output, runErr := cmd.CombinedOutput()
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() || cmd.ProcessState.ExitCode() != exit {
			t.Fatalf("process exit want %d: %v\n%s", exit, runErr, output)
		}
		for _, symbol := range symbols {
			if !strings.Contains(string(output), "=== RUN   "+symbol) {
				t.Fatalf("declared subject %s did not execute: %s", symbol, output)
			}
		}
		if err := u.Submit(process, terminal); err != nil {
			t.Fatal(err)
		}
		return u, process
	}
	var completed Finalized
	for _, missing := range []string{"contributor", "terminal", "never started"} {
		t.Run(missing, func(t *testing.T) {
			u, err := execution.BeginPackage([]Subject{a, b})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(u.Abort)
			if missing != "contributor" {
				process, err := u.Register(t.Context(), bound, ProcessDescription{Identity: t.Name()})
				if err != nil {
					t.Fatal(err)
				}
				if missing == "never started" {
					if err := u.Submit(process, Terminal{Kind: NeverStarted, Reason: "cancelled before spawn"}); err != nil {
						t.Fatal(err)
					}
				}
			}
			result, err := u.Close(t.Context())
			if err == nil || !reflect.DeepEqual(result, Finalized{}) {
				t.Fatalf("missing producing premise supplied executed evidence: %+v %v", result, err)
			}
			if missing != "never started" && !errors.Is(err, ErrUnitIncomplete) {
				t.Fatalf("missing premise lost its cause: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		name        string
		subjects    []Subject
		exit        int
		terminal    Terminal
		observation ObservationDisposition
		statuses    []Status
	}{
		{"two observing subjects", []Subject{b, a}, 0, Terminal{Kind: NormalCompletion}, SupportedObservation, []Status{Valid, Valid}},
		{"unsupported contributor", []Subject{a, file}, 0, Terminal{Kind: NormalCompletion}, IdentityObservation, []Status{Unverifiable, Unverifiable}},
		{"purity does not promote sibling", []Subject{a, pureFile}, 0, Terminal{Kind: NormalCompletion}, IdentityObservation, []Status{Unverifiable, Valid}},
		{"ordinary failing test", []Subject{a, fail}, 1, Terminal{Kind: NormalCompletion}, SupportedObservation, []Status{Valid, Valid}},
		{"abnormal original attempt", []Subject{a, crash}, 2, Terminal{Kind: AbnormalCompletion, Reason: "harness terminated by panic"}, IncompleteObservation, []Status{Unverifiable, Unverifiable}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, _ := start(t, tc.subjects, tc.exit, tc.terminal)
			result, err := u.Close(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if result.Process != t.Name() || result.Artifact != "retained-package-artifact" || result.Terminal != tc.terminal || result.Observation != tc.observation || len(result.Subjects) != len(tc.subjects) {
				t.Fatalf("closed process account = %+v", result)
			}
			if (result.ObservationReason != "") != (tc.observation == IncompleteObservation) {
				t.Fatalf("capture completeness account = %q", result.ObservationReason)
			}
			if tc.observation == IdentityObservation && result.OutcomeReason == "" {
				t.Fatal("unsupported inventory lost its outcome account")
			}
			for i, row := range result.Subjects {
				if row.Subject != tc.subjects[i] || row.Verdict.Status != tc.statuses[i] {
					t.Fatalf("subject %d = %v: %+v, want %v", i, row.Subject, row.Verdict, tc.statuses[i])
				}
				if got := runtimeinput.HasOutcomeSupport(row.Fingerprint.RuntimeInputs, outcomeSubject(row.Fingerprint, row.Subject)); got != (tc.observation == SupportedObservation) {
					t.Fatalf("subject %v borrowed outcome authority: %t", row.Subject, got)
				}
				if row.Fingerprint.RuntimeInputs != result.Subjects[0].Fingerprint.RuntimeInputs || row.Fingerprint.RuntimeDigest != result.Subjects[0].Fingerprint.RuntimeDigest {
					t.Fatal("one process was partitioned into fabricated per-subject observations")
				}
			}
			if tc.name == "two observing subjects" {
				inputs, err := runtimeinput.Describe(result.Subjects[0].Fingerprint.RuntimeInputs, dir)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Contains(inputs.EnvNames, "PACKAGE_A") || !slices.Contains(inputs.EnvNames, "PACKAGE_B") {
					t.Fatalf("sibling reads missing from process observation: %+v", inputs)
				}
				completed = result
			}
			if _, err := u.Close(t.Context()); !errors.Is(err, errUnitClosed) {
				t.Fatalf("closed execution reopened: %v", err)
			}
		})
	}
	t.Run("independent retry", func(t *testing.T) {
		u, _ := start(t, []Subject{a}, 0, Terminal{Kind: NormalCompletion})
		result, err := u.Close(t.Context())
		if err != nil || result.Observation != SupportedObservation || len(result.Subjects) != 1 || result.Subjects[0].Verdict.Status != Valid {
			t.Fatalf("retry inherited another attempt's failure: %+v %v", result, err)
		}
		inputs, err := runtimeinput.Describe(result.Subjects[0].Fingerprint.RuntimeInputs, dir)
		if err != nil || slices.Contains(inputs.EnvNames, "PACKAGE_CRASH") || slices.Contains(inputs.EnvNames, "PACKAGE_B") {
			t.Fatalf("retry inherited another attempt's inputs: %+v %v", inputs, err)
		}
	})
	t.Run("cancellation keeps closed sibling", func(t *testing.T) {
		u, _ := start(t, []Subject{a, b}, 0, Terminal{Kind: NormalCompletion})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		result, err := u.Close(ctx)
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, Finalized{}) {
			t.Fatalf("cancelled closing exposed evidence: %+v %v", result, err)
		}
		if len(completed.Subjects) != 2 || completed.Subjects[0].Verdict.Status != Valid {
			t.Fatal("cancellation discarded independently closed evidence")
		}
	})
	t.Run("closing drift exposes no prefix", func(t *testing.T) {
		u, _ := start(t, []Subject{a, b}, 0, Terminal{Kind: NormalCompletion})
		path := filepath.Join(dir, "p_test.go")
		changed := strings.Replace(source, `"wrong B"`, `"changed B"`, 1)
		if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.WriteFile(path, []byte(source), 0600); err != nil {
				t.Error(err)
			}
		})
		result, err := u.Close(t.Context())
		if !errors.Is(err, ErrViewChanged) || !reflect.DeepEqual(result, Finalized{}) {
			t.Fatalf("drift exposed a subject prefix: %+v %v", result, err)
		}
	})
}

func TestProcessAccountPreservesFinalizedFacts(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes retained artifacts across closing dispositions")
	}
	if runtime.GOOS != "linux" {
		t.Skip("admitted immutable-environment outcome support requires Linux")
	}
	dir := writeSupportedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	env := gotool.SetEnv(os.Environ(), "OUTCOME_VALUE", "accounted")
	runner := gotool.Runner{}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: env, Inputs: []string{}}, SessionPolicy{Execution: PackageExecution})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	binding := bindTestRuntime(t, snapshot, RuntimeDescription{})
	build, err := snapshot.BuildDescription(subject.Package)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "account.test")
	args := append([]string{"test", "-c", "-o", binary}, build.Flags...)
	args = append(args, build.Package)
	if output, err := runner.Run(t.Context(), build.Directory, build.Environment, args...); err != nil {
		t.Fatalf("build retained artifact: %v\n%s", err, output)
	}
	bound, err := snapshot.BindBuilt(subject.Package, "retained-account-artifact")
	if err != nil {
		t.Fatal(err)
	}
	register := func(t *testing.T) (*Unit, Contribution) {
		t.Helper()
		u, err := binding.BeginPackage([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(u.Abort)
		if got, ok := u.Account(); ok || got != (ProcessAccount{}) {
			t.Fatalf("unregistered unit invented an execution: %+v %t", got, ok)
		}
		c, err := u.Register(t.Context(), bound, ProcessDescription{Identity: t.Name(), Capture: filepath.Join(t.TempDir(), "capture")})
		if err != nil {
			t.Fatal(err)
		}
		got, ok := u.Account()
		want := ProcessAccount{Process: t.Name(), Artifact: "retained-account-artifact", Prepared: true}
		if !ok || got != want {
			t.Fatalf("registered account = %+v, want %+v", got, want)
		}
		return u, c
	}
	run := func(t *testing.T, c Contribution) {
		t.Helper()
		cmd, err := testProgramCmd(t.Context(), c.Directory(), c.Environment(), binary, "-test.v", "-test.run=^TestRead$", "-test.testlogfile="+c.Capture())
		if err != nil {
			t.Fatal(err)
		}
		if output, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(output), "=== RUN   TestRead") {
			t.Fatalf("retained artifact execution: %v\n%s", err, output)
		}
	}
	// The expected reporting bytes come from the native finalizer's public
	// CompletedState boundary, before any deliberate closing refusal.
	completed := func(t *testing.T, c Contribution) (runtimeinput.State, string, string) {
		t.Helper()
		x := c.execution
		receipt, err := x.frame.Completion(x.process.Identity, c.Environment(), x.terminal.Reason)
		if err != nil {
			t.Fatal(err)
		}
		in := runtimeinput.ProducerIngest{Identity: x.process.Identity, Env: c.Environment(), Completion: receipt, Outcome: x.support, Runner: runner}
		observe := x.frame.Observe
		if x.outcomeReason != "" {
			observe = x.frame.ObserveInputs
		}
		observation, reason, err := observe(t.Context(), c.Capture(), in)
		if err != nil {
			t.Fatal(err)
		}
		state, err := runtimeinput.CompletedState(observation)
		if err != nil {
			t.Fatal(err)
		}
		return state, reason, observation.Attribution
	}
	var closed *Unit
	var closedAccount ProcessAccount
	t.Run("successful account owns canonical data", func(t *testing.T) {
		u, c := register(t)
		run(t, c)
		if err := u.Submit(c, Terminal{Kind: NormalCompletion}); err != nil {
			t.Fatal(err)
		}
		want, reason, attribution := completed(t, c)
		result, err := u.Close(t.Context())
		if err != nil || len(result.Subjects) != 1 || result.Subjects[0].Verdict.Status != Valid {
			t.Fatalf("close: %+v %v", result, err)
		}
		account, ok := u.Account()
		if !ok || account.Observation != SupportedObservation || account.Inputs != want || account.ObservationReason != reason || account.Attribution != attribution || !account.Inputs.OK {
			t.Fatalf("finalized account: %+v, want native state %+v", account, want)
		}
		fp := result.Subjects[0].Fingerprint
		if account.Inputs.Manifest != fp.RuntimeInputs || account.Inputs.Digest != fp.RuntimeDigest || account.Observation != result.Observation || account.Terminal != result.Terminal || account.OutcomeReason != result.OutcomeReason {
			t.Fatal("successful close and process account disagree")
		}
		inputs, err := runtimeinput.Describe(account.Inputs.Manifest, dir)
		if err != nil || !slices.Contains(inputs.EnvNames, "OUTCOME_VALUE") {
			t.Fatalf("actual process read missing from account: %+v %v", inputs, err)
		}
		closed, closedAccount = u, account
		account.Inputs = runtimeinput.State{Manifest: "caller replacement", Reason: "changed"}
		account.Terminal = Terminal{Kind: NeverStarted, Reason: "changed"}
		account.Process = "changed"
		if err := os.Remove(c.Capture()); err != nil {
			t.Fatal(err)
		}
		u.Abort()
		if got, _ := u.Account(); got != closedAccount {
			t.Fatalf("returned data, removed capture or abort changed closed account: %+v", got)
		}
	})
	for _, ending := range []string{"missing terminal", "never started", "cancelled", "aborted"} {
		t.Run(ending+" stays unknown", func(t *testing.T) {
			u, c := register(t)
			terminal := Terminal{}
			if ending == "never started" {
				terminal = Terminal{Kind: NeverStarted, Reason: "no execution slot"}
			} else if ending == "cancelled" || ending == "aborted" {
				run(t, c)
				terminal = Terminal{Kind: NormalCompletion}
			}
			if terminal.Kind != 0 {
				if err := u.Submit(c, terminal); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := u.Account()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if ending == "cancelled" {
				cancel()
			} else if ending == "aborted" {
				u.Abort()
			}
			result, err := u.Close(ctx)
			if err == nil || !reflect.DeepEqual(result, Finalized{}) {
				t.Fatalf("unfinalized execution returned evidence: %+v %v", result, err)
			}
			if ending == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("caller cancellation lost: %v", err)
			}
			if err := os.Remove(c.Capture()); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			got, ok := u.Account()
			if !ok || got != before || got.Terminal != terminal || got.Observation != UnknownObservation || got.Inputs != (runtimeinput.State{}) {
				t.Fatalf("unfinalized account invented observations: %+v", got)
			}
		})
	}
	for _, missing := range []bool{false, true} {
		name := "abnormal completion"
		if missing {
			name = "missing capture"
		}
		t.Run(name, func(t *testing.T) {
			u, c := register(t)
			terminal := Terminal{Kind: NormalCompletion}
			if !missing {
				// A complete-looking flushed capture cannot override the
				// executor's abnormal terminal assertion.
				run(t, c)
				terminal = Terminal{Kind: AbnormalCompletion, Reason: "harness killed after output"}
			}
			if err := u.Submit(c, terminal); err != nil {
				t.Fatal(err)
			}
			want, reason, attribution := completed(t, c)
			result, err := u.Close(t.Context())
			if err != nil || result.Observation != IncompleteObservation {
				t.Fatalf("incomplete closing: %+v %v", result, err)
			}
			got, ok := u.Account()
			if !ok || got.Terminal != terminal || got.Observation != IncompleteObservation || got.ObservationReason == "" || got.ObservationReason != reason || got.Inputs != want || got.Attribution != attribution || !got.Inputs.Unverifiable || got.Inputs.Manifest == "" {
				t.Fatalf("incomplete native state lost: %+v, want %+v", got, want)
			}
		})
	}
	t.Run("identity-only singleton", func(t *testing.T) {
		u, err := binding.BeginIdentity(subject)
		if err != nil {
			t.Fatal(err)
		}
		defer u.Abort()
		c, err := u.Register(t.Context(), bound, ProcessDescription{Identity: t.Name(), Capture: filepath.Join(t.TempDir(), "capture")})
		if err != nil {
			t.Fatal(err)
		}
		run(t, c)
		if err := u.Submit(c, Terminal{Kind: NormalCompletion}); err != nil {
			t.Fatal(err)
		}
		want, reason, attribution := completed(t, c)
		result, err := u.Close(t.Context())
		if err != nil || result.Observation != IdentityObservation {
			t.Fatalf("identity-only closing: %+v %v", result, err)
		}
		got, ok := u.Account()
		if !ok || got.Observation != IdentityObservation || got.Inputs != want || got.ObservationReason != reason || got.Attribution != attribution || got.OutcomeReason == "" {
			t.Fatalf("identity-only account promoted or lost native data: %+v", got)
		}
	})
	for _, cancelled := range []bool{false, true} {
		name := "abort after observation"
		if cancelled {
			name = "caller cancellation outranks abort after observation"
		}
		t.Run(name, func(t *testing.T) {
			u, c := register(t)
			run(t, c)
			if err := u.Submit(c, Terminal{Kind: NormalCompletion}); err != nil {
				t.Fatal(err)
			}
			want, _, _ := completed(t, c)
			entered, resume := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			defer release()
			prior := viewTestHooks.observe
			defer func() { viewTestHooks.observe = prior }()
			pause := sync.OnceFunc(func() { close(entered); <-resume })
			viewTestHooks.observe = pause
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type closing struct {
				result Finalized
				err    error
			}
			done := make(chan closing, 1)
			go func() { result, err := u.Close(ctx); done <- closing{result, err} }()
			select {
			case <-entered:
			case got := <-done:
				t.Fatalf("close missed post-observation barrier: %v", got.err)
			case <-time.After(30 * time.Second):
				t.Fatal("close did not reach post-observation barrier")
			}
			before, ok := u.Account()
			if !ok || before.Inputs != want || before.Observation != SupportedObservation {
				t.Errorf("facts unavailable during closing: %+v", before)
			}
			u.Abort()
			wantErr := errUnitAborted
			if cancelled {
				cancel()
				wantErr = context.Canceled
			}
			release()
			got := <-done
			if !errors.Is(got.err, wantErr) || !reflect.DeepEqual(got.result, Finalized{}) {
				t.Fatalf("aborted close published evidence or lost cause: %+v %v", got.result, got.err)
			}
			if err := os.Remove(c.Capture()); err != nil {
				t.Fatal(err)
			}
			if account, _ := u.Account(); account != before {
				t.Fatalf("abort or report read changed finalized facts: %+v", account)
			}
		})
	}
	for _, singleton := range []bool{false, true} {
		name := "package source drift"
		if singleton {
			name = "singleton source drift"
		}
		t.Run(name, func(t *testing.T) {
			// Both public Close forms must suppress every reusable result,
			// while retaining the exact observation established before refusal.
			var c Contribution
			var account func() (ProcessAccount, bool)
			var abort func()
			var submit func(Contribution, Terminal) error
			var closeUnit func() (bool, error)
			if singleton {
				u, err := binding.Begin(subject)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(u.Abort)
				c, err = u.Register(t.Context(), bound, ProcessDescription{Identity: t.Name(), Capture: filepath.Join(t.TempDir(), "capture")})
				if err != nil {
					t.Fatal(err)
				}
				account, abort, submit = u.Account, u.Abort, u.Submit
				closeUnit = func() (bool, error) {
					result, err := u.Close(t.Context())
					return reflect.DeepEqual(result, Finalized{}), err
				}
			} else {
				u, contribution := register(t)
				c = contribution
				account, abort, submit = u.Account, u.Abort, u.Submit
				closeUnit = func() (bool, error) {
					result, err := u.Close(t.Context())
					return reflect.DeepEqual(result, Finalized{}), err
				}
			}
			run(t, c)
			if err := submit(c, Terminal{Kind: NormalCompletion}); err != nil {
				t.Fatal(err)
			}
			sourcePath := filepath.Join(dir, "observed_test.go")
			source, err := os.ReadFile(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.WriteFile(sourcePath, source, 0600); err != nil {
					t.Error(err)
				}
			}()
			changed := strings.Replace(string(source), "OUTCOME_VALUE", "CHANGED_SOURCE", 1)
			if err := os.WriteFile(sourcePath, []byte(changed), 0600); err != nil {
				t.Fatal(err)
			}
			// Source motion also moves the producing bracket. Compare the
			// canonical native state of that actual span, including its refusal.
			want, reason, attribution := completed(t, c)
			if zero, err := closeUnit(); !errors.Is(err, ErrViewChanged) || !zero {
				t.Fatalf("source drift exposed evidence: zero=%t %v", zero, err)
			}
			got, ok := account()
			if !ok || got.Process != t.Name() || got.Artifact != "retained-account-artifact" || !got.Prepared || got.Terminal != (Terminal{Kind: NormalCompletion}) || got.Observation != SupportedObservation || got.Inputs != want || got.ObservationReason != reason || got.Attribution != attribution {
				t.Fatalf("refused closing lost process facts: %+v, want native state %+v", got, want)
			}
			if err := os.Remove(c.Capture()); err != nil {
				t.Fatal(err)
			}
			abort()
			if later, _ := account(); later != got {
				t.Fatal("failed unit account changed on abort or capture deletion")
			}
		})
	}
	if closed == nil {
		t.Fatal("independently closed fixture did not complete")
	}
	if got, _ := closed.Account(); got != closedAccount {
		t.Fatal("later independent units changed the closed process account")
	}
}

func TestProcessAccountDuringRegistration(t *testing.T) {
	if testing.Short() {
		t.Skip("prepares a real process at a deterministic registration boundary")
	}
	if runtime.GOOS != "linux" {
		t.Skip("fixture expects admitted immutable-environment outcome support")
	}
	dir := writeSupportedViewModule(t)
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{Execution: PackageExecution})
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	binding := bindTestRuntime(t, snapshot, RuntimeDescription{})
	bound, err := snapshot.BindBuilt(subject.Package, "declared-artifact")
	if err != nil {
		t.Fatal(err)
	}
	for _, cancelled := range []bool{false, true} {
		name := "prepared"
		if cancelled {
			name = "failed reservation"
		}
		t.Run(name, func(t *testing.T) {
			u, err := binding.Begin(subject)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Abort()
			entered, resume := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			defer release()
			u.view.beforeOutcomeIssue = func() { close(entered); <-resume }
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type registered struct {
				c   Contribution
				err error
			}
			done := make(chan registered, 1)
			go func() {
				c, err := u.Register(ctx, bound, ProcessDescription{Identity: "reserved-process"})
				done <- registered{c, err}
			}()
			select {
			case <-entered:
			case got := <-done:
				t.Fatalf("preparation missed barrier: %v", got.err)
			case <-time.After(30 * time.Second):
				t.Fatal("preparation did not reach barrier")
			}
			want := ProcessAccount{Process: "reserved-process", Artifact: "declared-artifact"}
			if got, ok := u.Account(); !ok || got != want {
				t.Errorf("pending reservation account: %+v %t", got, ok)
			}
			if cancelled {
				cancel()
			}
			release()
			result := <-done
			if cancelled {
				if !errors.Is(result.err, context.Canceled) || result.c != (Contribution{}) {
					t.Fatalf("cancelled reservation returned a handle: %+v", result)
				}
			} else {
				if result.err != nil {
					t.Fatal(result.err)
				}
				want.Prepared = true
				// Concurrent reads observe either side of the terminal
				// submission, never a partially populated terminal fact.
				var readers sync.WaitGroup
				readers.Go(func() {
					for range 100 {
						got, ok := u.Account()
						if !ok || (got.Terminal != (Terminal{}) && got.Terminal != (Terminal{Kind: NeverStarted, Reason: "no execution"})) {
							t.Errorf("torn concurrent submission account: %+v", got)
						}
					}
				})
				if err := u.Submit(result.c, Terminal{Kind: NeverStarted, Reason: "no execution"}); err != nil {
					t.Error(err)
				}
				readers.Wait()
				want.Terminal = Terminal{Kind: NeverStarted, Reason: "no execution"}
			}
			u.Abort()
			if got, ok := u.Account(); !ok || got != want {
				t.Fatalf("settled reservation account: %+v, want %+v", got, want)
			}
		})
	}
}

func TestUnitsSelectProducingEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes independently closing producing units")
	}
	t.Run("source", func(t *testing.T) { testUnitsSelectProducingEvidence(t, true, false) })
	if runtime.GOOS != "linux" {
		t.Skip("the admitted immutable-environment outcome method is Linux-specific")
	}
	t.Run("mixed", func(t *testing.T) { testUnitsSelectProducingEvidence(t, false, false) })
	t.Run("mutating", func(t *testing.T) { testUnitsSelectProducingEvidence(t, false, true) })
}

func testUnitsSelectProducingEvidence(t *testing.T, sourceOnly, mutating bool) {
	dir := t.TempDir()
	const pkg = "example.com/selection"
	for name, text := range map[string]string{
		"go.mod": "module " + pkg + "\n\ngo 1.27.0\n",
		"p_test.go": `package selection
import ("os"; "testing")
func TestScalar(t *testing.T) { if 2 + 2 != 4 { t.Fail() } }
func TestEnv(t *testing.T) { if os.Getenv("SELECTION_INPUT") != "original" { t.Fail() } }
//gofresh:pure
func TestPure(t *testing.T) { _ = os.Getenv("SELECTION_INPUT") }
//gofresh:pure
func TestMutator(t *testing.T) { _ = os.Setenv("SELECTION_INPUT", "changed") }
//gofresh:external
func TestExternal(t *testing.T) {}
`,
	} {
		if !mutating {
			text = strings.Replace(text, `_ = os.Setenv("SELECTION_INPUT", "changed")`, ``, 1)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if sourceOnly {
		// Maximal closure facts include all package siblings. Keep this package
		// source-only rather than refining away the mixed fixture's I/O effects.
		if err := os.WriteFile(filepath.Join(dir, "p_test.go"), []byte(`package selection
import ("testing"; "unicode/utf16")
func TestScalar(t *testing.T) { if !utf16.IsSurrogate(0xd800) { t.Fail() } }
`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scalar := Subject{Package: pkg, Symbol: "TestScalar"}
	env := Subject{Package: pkg, Symbol: "TestEnv"}
	pure := Subject{Package: pkg, Symbol: "TestPure"}
	mutator := Subject{Package: pkg, Symbol: "TestMutator"}
	external := Subject{Package: pkg, Symbol: "TestExternal"}
	runner := gotool.Runner{}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: gotool.SetEnv(os.Environ(), "SELECTION_INPUT", "original"), Inputs: []string{}}, SessionPolicy{Execution: PackageExecution, PureSubjects: []Subject{external}})
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{env, pure, mutator, external}
	if sourceOnly {
		subjects = []Subject{scalar}
	}
	snapshot, err := session.Snapshot(t.Context(), subjects, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	runtime := bindTestRuntime(t, snapshot, RuntimeDescription{})
	build, err := snapshot.BuildDescription(pkg)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "package.test")
	args := append([]string{"test", "-c", "-o", binary}, build.Flags...)
	args = append(args, build.Package)
	if output, err := runner.Run(t.Context(), build.Directory, build.Environment, args...); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	bound, err := snapshot.BindBuilt(pkg, "retained")
	if err != nil {
		t.Fatal(err)
	}
	start := func(t *testing.T, subjects []Subject, capture, singleton bool) *Unit {
		t.Helper()
		var u *Unit
		if singleton {
			unit, err := runtime.Begin(subjects[0])
			if err != nil {
				t.Fatal(err)
			}
			u = unit
		} else {
			unit, err := runtime.BeginPackage(subjects)
			if err != nil {
				t.Fatal(err)
			}
			u = unit
		}
		t.Cleanup(u.Abort)
		process := ProcessDescription{Identity: t.Name()}
		if capture {
			process.Capture = filepath.Join(t.TempDir(), "capture")
		}
		c, err := u.Register(t.Context(), bound, process)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(c.Subjects(), subjects) {
			t.Fatalf("runnable roster = %v, want %v", c.Subjects(), subjects)
		}
		var names []string
		for _, subject := range subjects {
			names = append(names, subject.Symbol)
		}
		args := []string{"-test.v", "-test.run=^(" + strings.Join(names, "|") + ")$"}
		if capture {
			args = append(args, "-test.testlogfile="+c.Capture())
		}
		cmd, err := testProgramCmd(t.Context(), c.Directory(), c.Environment(), binary, args...)
		if err != nil {
			t.Fatal(err)
		}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("execution: %v\n%s", err, output)
		}
		if err := u.Submit(c, Terminal{Kind: NormalCompletion}); err != nil {
			t.Fatal(err)
		}
		return u
	}
	for _, tc := range []struct {
		name        string
		subjects    []Subject
		capture     bool
		singleton   bool
		observation ObservationDisposition
		observed    []Subject
		statuses    []Status
	}{
		{"singleton without capture", []Subject{scalar}, false, true, UnknownObservation, nil, []Status{Valid}},
		{"package without capture", []Subject{scalar}, false, false, UnknownObservation, nil, []Status{Valid}},
		{"optional identity capture", []Subject{scalar}, true, false, IdentityObservation, nil, []Status{Valid}},
		{"purity without capture", []Subject{pure}, false, true, UnknownObservation, nil, []Status{Valid}},
		{"purity identity capture", []Subject{pure}, true, true, IdentityObservation, nil, []Status{Valid}},
		{"mixed supported roster", []Subject{pure, env}, true, false, SupportedObservation, []Subject{env}, []Status{Valid, Valid}},
		{"purity is not preservation", []Subject{env, mutator}, true, false, IdentityObservation, []Subject{env}, []Status{Unverifiable, Valid}},
		{"external defeats caller purity", []Subject{external}, true, true, SupportedObservation, []Subject{external}, []Status{Unverifiable}},
		{"observing missing capture", []Subject{env}, false, true, IncompleteObservation, []Subject{env}, []Status{Unverifiable}},
	} {
		if slices.Contains(tc.subjects, scalar) != sourceOnly {
			continue
		}
		if slices.Contains(tc.subjects, mutator) != mutating {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			u := start(t, tc.subjects, tc.capture, tc.singleton)
			if len(tc.observed) != 0 && len(u.view.capturedObserved) != len(tc.subjects) {
				t.Fatal("process-wide preparation omitted a runnable contributor")
			}
			result, err := u.Close(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if result.Observation != tc.observation || result.Terminal.Kind != NormalCompletion {
				t.Fatalf("process account: %+v", result)
			}
			for i, row := range result.Subjects {
				fp := row.Fingerprint
				accepted := row.Verdict.Ground.Accepted
				accepted.GuardAgreement, accepted.RuntimeInputs = false, false
				if sourceOnly && (fp.PurityAssertion != "" || accepted != (AcceptedAuthority{})) {
					t.Fatalf("source-only result acquired assertion authority: %+v", row)
				}
				if row.Subject == external && (fp.PurityAssertion != "" || row.Verdict.Ground.Cause != (Cause{Kind: ExternalDirectiveCause, Condition: Refused})) {
					t.Fatalf("externality lost its precedence: %+v", row)
				}
				selected := slices.Contains(tc.observed, row.Subject)
				if row.Verdict.Status != tc.statuses[i] || (fp.ObservationAssertion != "") != selected || (fp.ObservationProof != (ObservationProof{})) != selected {
					t.Fatalf("subject %v: %+v", row.Subject, row)
				}
				if !tc.capture && len(tc.observed) == 0 && (fp.RuntimeInputs != "" || fp.RuntimeDigest != "" || row.Verdict.Ground.Accepted.Observation != (ObservationAuthority{})) {
					t.Fatalf("absent capture acquired observation evidence: %+v", row)
				}
				if len(tc.observed) == 0 && runtimeinput.HasOutcomeSupport(fp.RuntimeInputs, outcomeSubject(fp, row.Subject)) {
					t.Fatal("optional capture acquired outcome authority")
				}
				if tc.observation == SupportedObservation {
					// Process-wide outcome preparation uses every contributor's
					// inventory, even when that subject's result selects source or
					// assertion evidence and retains no observation proof of its own.
					u.view.mu.RLock()
					prepared := u.view.observedFingerprintLocked(row.Subject)
					u.view.mu.RUnlock()
					if !runtimeinput.HasOutcomeSupport(fp.RuntimeInputs, outcomeSubject(prepared, row.Subject)) {
						t.Fatalf("process outcome evidence omitted contributor %v", row.Subject)
					}
				}
				verdict, err := runtime.Check(t.Context(), row.Subject, fp)
				if err != nil || verdict.Status != row.Verdict.Status {
					t.Fatalf("independent check: %+v %v", verdict, err)
				}
			}
			if _, err := u.Close(t.Context()); !errors.Is(err, errUnitClosed) {
				t.Fatalf("closed unit reopened: %v", err)
			}
		})
	}
	if mutating {
		return
	}
	t.Run("independent closing and corruption refusal", func(t *testing.T) {
		plain := pure
		mixed := []Subject{pure, env}
		if sourceOnly {
			plain, mixed = scalar, []Subject{scalar}
		}
		first := start(t, []Subject{plain}, false, true)
		second := start(t, mixed, true, false)
		if _, err := second.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(first.view.capturedObserved) != 0 || len(first.execution.observed) != 0 {
			t.Fatal("sibling selected observation obligations on a shared snapshot")
		}
		fp := first.execution.fingerprints[plain]
		fp.PurityAssertion = "caller assertion"
		first.execution.fingerprints[plain] = fp
		result, err := first.Close(t.Context())
		if err == nil || !reflect.DeepEqual(result, Finalized{}) {
			t.Fatalf("capture-free corruption escaped: %+v %v", result, err)
		}
		retry := start(t, []Subject{plain}, false, true)
		result, err = retry.Close(t.Context())
		if err != nil || result.Subjects[0].Verdict.Status != Valid || result.Subjects[0].Fingerprint.ObservationAssertion != "" {
			t.Fatalf("retry borrowed failed obligations: %+v %v", result, err)
		}
	})
}

func TestRuntimeBindingsShareGenerationAcrossPackages(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes two retained package artifacts")
	}
	if runtime.GOOS != "linux" {
		t.Skip("supported immutable-environment observations require Linux")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/bindings\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var subjects []Subject
	for _, name := range []string{"a", "b"} {
		pkgDir := filepath.Join(dir, name)
		if err := os.Mkdir(pkgDir, 0700); err != nil {
			t.Fatal(err)
		}
		const source = `package bound
import ("os"; "testing")
func TestRuntime(t *testing.T) {
 if os.Getenv("BOUND_VALUE") != "delivered" { t.Fatal("wrong process environment") }
 t.Log("actual-pwd=" + os.Getenv("PWD"))
}
`
		if err := os.WriteFile(filepath.Join(pkgDir, "p_test.go"), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, Subject{Package: "example.com/bindings/" + name, Symbol: "TestRuntime"})
	}
	buildEnv := gotool.SetEnv(gotool.SetEnv(os.Environ(), "GOENV", "off"), "BOUND_VALUE", "compiler-only")
	runEnv := gotool.SetEnv(buildEnv, "BOUND_VALUE", "delivered")
	runner := gotool.Runner{}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: buildEnv, Inputs: []string{}}, SessionPolicy{Execution: PackageExecution})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(t.Context(), subjects, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	facts := snapshot.facts
	priorObserve, priorGuardDir := viewTestHooks.observe, viewTestHooks.guardDir
	defer func() { viewTestHooks.observe, viewTestHooks.guardDir = priorObserve, priorGuardDir }()
	passes := 0
	viewTestHooks.observe = func() { passes++ }
	viewTestHooks.guardDir = func(got string) {
		if got != dir {
			t.Errorf("source/build observation moved to runtime directory %q", got)
		}
	}
	a := bindTestRuntime(t, snapshot, RuntimeDescription{Directory: "a", Environment: runEnv})
	b := bindTestRuntime(t, snapshot, RuntimeDescription{Directory: "b", Environment: runEnv})
	if passes != 0 || a.Snapshot() != snapshot || b.Snapshot() != snapshot {
		t.Fatal("runtime binding observed or replaced the source/build generation")
	}
	bindings := []*RuntimeBinding{a, b}
	failed, err := a.BeginPackage([]Subject{subjects[0]})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := failed.Close(t.Context()); !errors.Is(err, ErrUnitIncomplete) || len(result.Subjects) != 0 {
		t.Fatalf("incomplete sibling exposed evidence: %+v %v", result, err)
	}
	cancelled, err := b.BeginPackage([]Subject{subjects[1]})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := cancelled.Close(ctx); !errors.Is(err, context.Canceled) || len(result.Subjects) != 0 {
		t.Fatalf("cancelled sibling exposed evidence: %+v %v", result, err)
	}
	artifacts := make([]BuildBinding, len(subjects))
	binaries := make([]string, len(subjects))
	for i, subject := range subjects {
		build, err := snapshot.BuildDescription(subject.Package)
		if err != nil {
			t.Fatal(err)
		}
		binaries[i] = filepath.Join(t.TempDir(), "package.test")
		if out, err := runner.Run(t.Context(), build.Directory, build.Environment, "test", "-c", "-o", binaries[i], build.Package); err != nil {
			t.Fatalf("build: %v\n%s", err, out)
		}
		artifacts[i], err = snapshot.BindBuilt(subject.Package, subject.Package+"-retained")
		if err != nil {
			t.Fatal(err)
		}
	}
	run := func(binding *RuntimeBinding, i int) Fingerprint {
		t.Helper()
		u, err := binding.BeginPackage([]Subject{subjects[i]})
		if err != nil {
			t.Fatal(err)
		}
		defer u.Abort()
		c, err := u.Register(t.Context(), artifacts[i], ProcessDescription{Identity: "actual-process", Capture: filepath.Join(t.TempDir(), "capture")})
		if err != nil {
			t.Fatal(err)
		}
		if pwd, _ := gotool.LookupEnv(c.Environment(), "PWD"); pwd != c.Directory() {
			t.Fatalf("process PWD=%q, directory=%q", pwd, c.Directory())
		}
		cmd, err := testProgramCmd(t.Context(), c.Directory(), c.Environment(), binaries[i], "-test.v", "-test.run=^TestRuntime$", "-test.testlogfile="+c.Capture())
		if err != nil {
			t.Fatal(err)
		}
		if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "actual-pwd="+c.Directory()) {
			t.Fatalf("actual process: %v\n%s", err, out)
		}
		if err := u.Submit(c, Terminal{Kind: NormalCompletion}); err != nil {
			t.Fatal(err)
		}
		result, err := u.Close(t.Context())
		if err != nil || result.Observation != SupportedObservation || len(result.Subjects) != 1 || result.Subjects[0].Verdict.Status != Valid {
			t.Fatalf("bound closing: %+v %v", result, err)
		}
		fp := result.Subjects[0].Fingerprint
		inputs, err := runtimeinput.Describe(fp.RuntimeInputs, dir)
		if err != nil || !slices.Contains(inputs.EnvNames, "PWD") || !slices.Contains(inputs.EnvNames, "BOUND_VALUE") {
			t.Fatalf("honest runtime inventory: %+v %v", inputs, err)
		}
		if fp.Guards.Machine != "" || fp.Guards.RuntimeConfig != "" {
			t.Fatal("code record acquired measurement guards")
		}
		return fp
	}
	records := []Fingerprint{run(a, 0), run(b, 1)}
	for i, binding := range bindings {
		if verdict, err := binding.Check(t.Context(), subjects[i], records[i]); err != nil || verdict.Status != Valid {
			t.Fatalf("same binding check: %+v %v", verdict, err)
		}
		if verdict, err := bindings[1-i].Check(t.Context(), subjects[i], records[i]); err != nil || verdict.Status != Stale || !strings.Contains(verdict.Reason, "PWD") {
			t.Fatalf("cross-PWD check: %+v %v", verdict, err)
		}
	}
	// A new binding can execute the very same retained artifact. It cannot
	// overwrite either an old binding or the record already produced under it.
	before := passes
	rebound := bindTestRuntime(t, snapshot, RuntimeDescription{Directory: "b", Environment: gotool.SetEnv(runEnv, "UNREAD_RUNTIME_VALUE", "other")})
	if passes != before {
		t.Fatal("rebinding loaded source")
	}
	recordB := run(rebound, 0)
	if recordB.Guards != records[0].Guards || recordB.RuntimeDigest == records[0].RuntimeDigest {
		t.Fatal("runtime rebinding changed build guards or hid observed PWD motion")
	}
	if verdict, err := a.Check(t.Context(), subjects[0], records[0]); err != nil || verdict.Status != Valid {
		t.Fatalf("new binding mutated old binding: %+v %v", verdict, err)
	}
	later, err := session.Snapshot(t.Context(), subjects, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := later.BindBuilt(subjects[0].Package, artifacts[0].identity)
	if err != nil {
		t.Fatal(err)
	}
	u, err := a.BeginIdentity(subjects[0])
	if err != nil {
		t.Fatal(err)
	}
	defer u.Abort()
	if _, err := u.Register(t.Context(), foreign, ProcessDescription{Identity: "borrowed"}); err == nil {
		t.Fatal("equal artifact identity crossed snapshot generations")
	}
	if snapshot.facts != facts || facts.guards != records[0].Guards {
		t.Fatal("a binding or later generation mutated shared compilation state")
	}
	if got, err := a.CurrentFacts(t.Context(), subjects[0]); err != nil || got.Guards != records[0].Guards || got.RuntimeInputs != "" {
		t.Fatalf("later generation changed an old binding's immutable facts: %+v %v", got.Guards, err)
	}
}

func TestRuntimeBindingGuardAgreementAndClosing(t *testing.T) {
	if testing.Short() {
		t.Skip("observes source and runtime guard generations")
	}
	if runtime.GOOS != "linux" {
		t.Skip("measurement support requires Linux")
	}
	dir := writeViewModule(t, "package view\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	prior := viewTestHooks.runtimeGuards
	defer func() { viewTestHooks.runtimeGuards = prior }()
	samples, machine := 0, "machine-a"
	viewTestHooks.runtimeGuards = func(g *guard.RuntimeGuards) { samples++; g.Machine = machine }
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	if samples != 0 || snapshot.facts.guards.Machine != "" || snapshot.facts.guards.RuntimeConfig != "" {
		t.Fatal("source/build generation captured runtime guards")
	}
	a := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: []string{"GOGC=100"}})
	if samples != 2 {
		t.Fatalf("recording-time runtime samples=%d, want agreement pair", samples)
	}
	fp, err := a.CurrentFacts(t.Context(), subject)
	if err != nil {
		t.Fatal(err)
	}
	b := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: []string{"GOGC=200"}})
	other, err := b.CurrentFacts(t.Context(), subject)
	if err != nil || other.Guards.BuildConfig != fp.Guards.BuildConfig || other.Guards.RuntimeConfig == fp.Guards.RuntimeConfig {
		t.Fatalf("runtime configuration did not separate from compilation: %+v %v", other.Guards, err)
	}
	if got, err := b.Check(t.Context(), subject, fp); err != nil || got.Status != Stale || got.Reason != "runtimeconfig" {
		t.Fatalf("runtime-only drift: %+v %v", got, err)
	}
	v, err := a.newView([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := v.Sibling([]Subject{subject})
	if err != nil || sibling.runtime != v.runtime || sibling.guards() != fp.Guards {
		t.Fatalf("sibling lost its immutable runtime binding: %v", err)
	}
	seed, err := v.newSeededValidationView(t.Context())
	if err != nil || seed.runtime != v.runtime || seed.guards() != fp.Guards {
		t.Fatalf("seeded validation lost its runtime binding: %v", err)
	}
	if _, err := v.captureObserved(t.Context(), subject); err != nil {
		t.Fatalf("observability refinement used different guards: %v", err)
	}
	machine = "machine-b"
	c := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: []string{"GOGC=100"}})
	if c.runtime.guards.Machine != machine || a.runtime.guards.Machine != "machine-a" {
		t.Fatal("new binding did not capture its own immutable machine observation")
	}
	if got, err := c.Check(t.Context(), subject, fp); err != nil || got.Status != Stale || got.Reason != "machine" {
		t.Fatalf("fresh binding ignored machine change: %+v %v", got, err)
	}
	if got, err := a.Check(t.Context(), subject, fp); !errors.Is(err, ErrViewChanged) || got != (Verdict{}) {
		t.Fatalf("old binding published before closing runtime drift: %+v %v", got, err)
	}
	if _, err := seed.newSeededValidationView(t.Context()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("seeded validation forgot old machine: %v", err)
	}
	if err := sibling.reobserveBase(t.Context()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("sibling comparison forgot old machine: %v", err)
	}
	if _, err := sibling.captureObserved(t.Context(), subject); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("refinement failed to close its runtime guards: %v", err)
	}
	// Binding refusal leaves all previously admitted bindings intact.
	viewTestHooks.runtimeGuards = func(g *guard.RuntimeGuards) { samples++; g.Machine = string(rune('a' + samples)) }
	if got, err := snapshot.BindRuntime(t.Context(), RuntimeDescription{}); !errors.Is(err, ErrViewChanged) || got != nil {
		t.Fatalf("torn machine binding admitted: nonnil=%t error=%v", got != nil, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	viewTestHooks.runtimeGuards = func(*guard.RuntimeGuards) { cancel() }
	if got, err := snapshot.BindRuntime(ctx, RuntimeDescription{}); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("cancelled runtime binding admitted: nonnil=%t error=%v", got != nil, err)
	}
	viewTestHooks.runtimeGuards = func(g *guard.RuntimeGuards) { g.Machine = "machine-a" }
	if got, err := a.Check(t.Context(), subject, fp); err != nil || got.Status != Valid {
		t.Fatalf("refused bindings damaged old binding: %+v %v", got, err)
	}
}

func TestSnapshotAndCodeBindingNeedNoMachineSupport(t *testing.T) {
	if testing.Short() {
		t.Skip("observes code and measurement snapshots with unavailable machine support")
	}
	prior := guard.MachineFactSources
	guard.MachineFactSources = nil
	defer func() { guard.MachineFactSources = prior }()
	dir := writeViewModule(t, "package view\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []Kind{CodeResult, Measurement} {
		snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, kind)
		if err != nil {
			t.Fatalf("snapshot required measurement support: %v", err)
		}
		binding, err := snapshot.BindRuntime(t.Context(), RuntimeDescription{})
		if kind == Measurement {
			if err == nil || binding != nil {
				t.Fatal("measurement binding ignored unavailable machine support")
			}
			continue
		}
		if err != nil {
			t.Fatalf("code binding probed machine support: %v", err)
		}
		fp, err := binding.CurrentFacts(t.Context(), subject)
		if err != nil || fp.Guards.Machine != "" || fp.Guards.RuntimeConfig != "" {
			t.Fatalf("code binding captured measurement guards: %+v %v", fp.Guards, err)
		}
		if got, err := binding.Check(t.Context(), subject, fp); err != nil || got.Status != Valid {
			t.Fatalf("code closing required machine support: %+v %v", got, err)
		}
	}
}

// The retained binary consumes the before value and flushes its real testlog.
// Movement occurs only afterward, reproducing the producing-span failure rather
// than testing a fabricated verdict or a later diagnostic execution.
type runtimeMotionFixture struct {
	dir, binary                              string
	reader, unknown, supported, direntReader Subject
	binding                                  *RuntimeBinding
	artifact                                 BuildBinding
	runner                                   gotool.Runner
}

func newRuntimeMotionFixture(t *testing.T) runtimeMotionFixture {
	t.Helper()
	dir := t.TempDir()
	const pkg = "example.com/runtimemotion"
	const source = `package runtimemotion
import ("os"; "testing")
func TestReader(t *testing.T) {
 b, err := os.ReadFile("input")
 if err != nil || string(b) != "before" { t.Fatalf("read %q: %v", b, err) }
 t.Logf("actually consumed %q", b)
}
func TestDirentReader(t *testing.T) {
 b, err := os.ReadFile("data/input")
 if err != nil || string(b) != "before" { t.Fatalf("read %q: %v", b, err) }
 t.Logf("actually consumed %q", b)
}
func TestUnknown(t *testing.T) {
 b, err := os.ReadFile("uncovered")
 if err != nil || string(b) != "stable" { t.Fatalf("read %q: %v", b, err) }
}
func TestSupported(t *testing.T) {
 if os.Getenv("MOTION_CONTROL") != "stable" { t.Fatal("wrong environment") }
}
`
	for name, content := range map[string]string{"go.mod": "module " + pkg + "\n\ngo 1.27.0\n", "p_test.go": source, "input": "before"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	external := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(external, []byte("stable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(dir, "uncovered")); err != nil {
		t.Fatal(err)
	}
	reader := Subject{Package: pkg, Symbol: "TestReader"}
	unknown := Subject{Package: pkg, Symbol: "TestUnknown"}
	supported := Subject{Package: pkg, Symbol: "TestSupported"}
	direntReader := Subject{Package: pkg, Symbol: "TestDirentReader"}
	env := gotool.SetEnv(os.Environ(), "MOTION_CONTROL", "stable")
	runner := gotool.Runner{}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: env, Inputs: []string{}}, SessionPolicy{Execution: PackageExecution, PureSubjects: []Subject{reader, unknown, direntReader}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(t.Context(), []Subject{reader, unknown, supported, direntReader}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	binding := bindTestRuntime(t, snapshot, RuntimeDescription{})
	build, err := snapshot.BuildDescription(pkg)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "package.test")
	args := append([]string{"test", "-c", "-o", binary}, build.Flags...)
	args = append(args, build.Package)
	if output, err := runner.Run(t.Context(), build.Directory, build.Environment, args...); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	artifact, err := snapshot.BindBuilt(pkg, binary)
	if err != nil {
		t.Fatal(err)
	}
	return runtimeMotionFixture{dir, binary, reader, unknown, supported, direntReader, binding, artifact, runner}
}

func TestRuntimeMovementRefusesPureProductionAndHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes a retained test binary")
	}
	f := newRuntimeMotionFixture(t)
	dir, binary, reader, unknown, supported, binding, artifact, _ := f.dir, f.binary, f.reader, f.unknown, f.supported, f.binding, f.artifact, f.runner
	var stable Fingerprint
	for _, tc := range []struct {
		name    string
		subject Subject
		move    bool
	}{
		{"stable_reader", reader, false},
		{"known_motion", reader, true},
		{"independent_unknown_pure", unknown, false},
		{"independent_supported", supported, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := binding.BeginPackage([]Subject{tc.subject})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(u.Abort)
			contribution, err := u.Register(t.Context(), artifact, ProcessDescription{Identity: t.Name(), Capture: filepath.Join(t.TempDir(), "capture"), BracketPaths: []string{"input"}})
			if err != nil {
				t.Fatal(err)
			}
			cmd, err := testProgramCmd(t.Context(), contribution.Directory(), contribution.Environment(), binary, "-test.v", "-test.run=^"+tc.subject.Symbol+"$", "-test.testlogfile="+contribution.Capture())
			if err != nil {
				t.Fatal(err)
			}
			output, runErr := cmd.CombinedOutput()
			if runErr != nil || cmd.ProcessState == nil || !cmd.ProcessState.Exited() || cmd.ProcessState.ExitCode() != 0 {
				t.Fatalf("execution: %v\n%s", runErr, output)
			}
			if tc.subject == reader && !strings.Contains(string(output), `actually consumed "before"`) {
				t.Fatal("execution did not establish consumed value")
			}
			if err := u.Submit(contribution, Terminal{Kind: NormalCompletion}); err != nil {
				t.Fatal(err)
			}
			if tc.move {
				if err := os.WriteFile(filepath.Join(dir, "input"), []byte("after"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			final, closeErr := u.Close(t.Context())
			account, ok := u.Account()
			if !ok || account.Terminal.Kind != NormalCompletion || account.Inputs.Manifest == "" {
				t.Fatal("finalization lost established process facts")
			}
			if !tc.move {
				if closeErr != nil || len(final.Subjects) != 1 || final.Subjects[0].Verdict.Status != Valid {
					t.Fatalf("positive control refused: %+v %v", final, closeErr)
				}
				if account.Inputs.BracketMoved {
					t.Fatal("stable control acquired movement")
				}
				if tc.subject == reader {
					stable = final.Subjects[0].Fingerprint
				}
				if tc.subject == unknown && !account.Inputs.Unverifiable {
					t.Fatal("unknown control lacked a blind spot")
				}
				if tc.subject == supported && final.Observation != SupportedObservation {
					t.Fatal("supported control lost support")
				}
				return
			}
			var span *RuntimeInputSpanError
			if !errors.As(closeErr, &span) || span.Cause() != (Cause{Kind: RuntimeInputsCause, Condition: Changed}) || len(final.Subjects) != 0 || !account.Inputs.BracketMoved {
				t.Fatalf("motion was not a structured closing refusal: %+v %+v %v", final, account, closeErr)
			}
			if _, err := u.Close(t.Context()); !errors.Is(err, errUnitClosed) {
				t.Fatalf("failed close reopened: %v", err)
			}
			// A stored v4 failure stays stale both before and after restoration.
			failed := stable
			failed.RuntimeInputs, failed.RuntimeDigest = account.Inputs.Manifest, account.Inputs.Digest
			for _, restore := range []bool{false, true} {
				if restore {
					if err := os.WriteFile(filepath.Join(dir, "input"), []byte("before"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				verdict, err := binding.Check(t.Context(), reader, failed)
				if err != nil || verdict.Status != Stale || verdict.Ground.Cause != span.Cause() || verdict.Ground.Accepted != (AcceptedAuthority{}) {
					t.Fatalf("restored=%t history authorized drift: %+v %v", restore, verdict, err)
				}
			}
			// Older native records remain byte-stable history. Their ambiguous
			// manifest cannot gain authority, even under independent purity.
			raw, err := base64.RawURLEncoding.DecodeString(failed.RuntimeInputs)
			if err != nil {
				t.Fatal(err)
			}
			for version := 1; version <= 3; version++ {
				legacy := failed
				old := strings.Replace(string(raw), `"v":4`, fmt.Sprintf(`"v":%d`, version), 1)
				old = strings.Replace(old, `,"bracketMoved":true`, "", 1)
				legacy.RuntimeInputs = base64.RawURLEncoding.EncodeToString([]byte(old))
				encoded, err := json.Marshal(legacy)
				if err != nil {
					t.Fatal(err)
				}
				var historical Fingerprint
				if err := json.Unmarshal(encoded, &historical); err != nil {
					t.Fatalf("v%d history unreadable: %v", version, err)
				}
				verdict, err := binding.Check(t.Context(), reader, historical)
				if err != nil || verdict.Status != Stale || verdict.Ground.Cause != (Cause{Kind: RuntimeInputsCause, Condition: Unavailable}) || verdict.Ground.Accepted != (AcceptedAuthority{}) {
					t.Fatalf("v%d gained reuse: %+v %v", version, verdict, err)
				}
				again, err := json.Marshal(historical)
				if err != nil || string(again) != string(encoded) {
					t.Fatal("history bytes changed")
				}
				if runtimeinput.HasOutcomeSupport(historical.RuntimeInputs, outcomeSubject(historical, reader)) {
					t.Fatal("old history gained support")
				}
			}
		})
	}
}


// A retained executable is built under the analyzed feature selection, even
// when its runtime environment names a different compiler feature level. Its
// observation and later judgment use the actual runtime values.
func TestSessionSeparatesCompilationFromExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs and executes a fixture binary")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("the supported-outcome feature-selection anchor uses linux/amd64")
	}
	ctx := t.Context()
	dir := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/session\n\ngo 1.27.0\n")
	write("base.go", "//go:build !amd64.v2\n\npackage session\nfunc Value() int { return 1 }\n")
	write("feature.go", "//go:build amd64.v2\n\npackage session\nfunc Value() int { return 2 }\n")
	write("value_test.go", `package session
import ("os"; "testing")
var sink int
func BenchmarkValue(b *testing.B) { for b.Loop() { sink = Value() + len(os.Getenv("FRESH_SESSION_VALUE")) } }
func BenchmarkFile(b *testing.B) { for b.Loop() { data, _ := os.ReadFile("input"); sink = len(data) } }
func TestValue(t *testing.T) { t.Logf("selected=%d", Value()) }
`)
	// The same relative spelling in the library's cwd is another process's
	// empty log. It must never stand in for the actual child's getenv capture.
	shadow := t.TempDir()
	for _, root := range []string{dir, shadow} {
		child := filepath.Join(root, "capture-relative", "real", "child")
		if err := os.MkdirAll(child, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(child, filepath.Join(root, "capture-relative", "via")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(shadow, "capture-relative", "real", "testlog"), []byte("# test log\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "capture-relative", "testlog"), []byte("# test log\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(shadow)
	buildEnv := gotool.SetEnv(gotool.SetEnv(os.Environ(), "GOAMD64", "v1"), "GOENV", "off")
	runtimeEnv := gotool.SetEnv(gotool.SetEnv(buildEnv, "GOAMD64", "v2"), "FRESH_SESSION_VALUE", "produced")
	type queryGate struct {
		started, release chan struct{}
		entered          atomic.Bool
		spawnMarker      string
	}
	var closingGate atomic.Pointer[queryGate]
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		gate := closingGate.Load()
		if gate != nil && strings.Join(cmd.Args[1:], " ") == "env -json" && gate.entered.CompareAndSwap(false, true) {
			if gate.spawnMarker != "" {
				original, arguments := cmd.Path, append([]string(nil), cmd.Args[1:]...)
				cmd.Path = "/bin/sh"
				cmd.Args = append([]string{"sh", "-c", `printf started > "$1"; shift; exec "$@"`, "query-marker", gate.spawnMarker, original}, arguments...)
			}
			close(gate.started)
			<-gate.release
		}
	}}
	configuration := BuildDescription{Directory: dir, Environment: buildEnv, Inputs: []string{}}
	policy := SessionPolicy{Execution: SingleSubjectExecution, PrepareCommand: runner.Prepare}
	session, err := NewSession(ctx, configuration, policy)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/session", Symbol: "BenchmarkValue"}
	fileSubject := Subject{Package: subject.Package, Symbol: "BenchmarkFile"}
	snapshot, err := session.Snapshot(ctx, []Subject{subject, fileSubject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	execution := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: runtimeEnv})
	ledger, err := snapshot.TestVariantLedger(subject)
	if err != nil || ledger.BindingStrategy == "" || len(ledger.Declarations) == 0 {
		t.Fatalf("snapshot ledger: %+v %v", ledger, err)
	}
	files := snapshot.SourceFiles()
	if len(files) == 0 {
		t.Fatal("snapshot has no source inventory")
	}
	originalFile := files[0]
	files[0] = "borrowed"
	if snapshot.SourceFiles()[0] != originalFile {
		t.Fatal("source projection aliases snapshot")
	}
	currentFacts, err := execution.CurrentFacts(ctx, subject)
	if err != nil || currentFacts.RuntimeInputs != "" || currentFacts.ObservationAssertion != "" || currentFacts.ObservationProof.Strategy != "" {
		t.Fatalf("analysis facts gained producing evidence: %v", err)
	}
	build, err := snapshot.BuildDescription(subject.Package)
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := gotool.LookupEnv(build.Environment, "GOAMD64"); value != "v1" {
		t.Fatalf("build selected %q", value)
	}
	binary := filepath.Join(t.TempDir(), "bench.test")
	args := append([]string{"test", "-c", "-o", binary}, build.Flags...)
	args = append(args, build.Package)
	if out, err := runner.Run(ctx, build.Directory, build.Environment, args...); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	bound, err := snapshot.BindBuilt(subject.Package, "fixture-test-artifact")
	if err != nil {
		t.Fatal(err)
	}
	missing, err := execution.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missing.Close(ctx); !errors.Is(err, ErrUnitIncomplete) {
		t.Fatalf("empty unit closed: %v", err)
	}
	if _, err := missing.Register(ctx, bound, ProcessDescription{Identity: "late"}); !errors.Is(err, errUnitClosed) {
		t.Fatalf("failed unit reopened: %v", err)
	}
	control, err := testProgramCmd(ctx, dir, runtimeEnv, binary, "-test.run=^TestValue$", "-test.v")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := control.CombinedOutput(); err != nil || !strings.Contains(string(out), "selected=1") {
		t.Fatalf("actual artifact: %v\n%s", err, out)
	}
	unit, err := execution.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	defer unit.Abort()
	capture := filepath.Join("capture-relative", "via") + string(filepath.Separator) + ".." + string(filepath.Separator) + "testlog"
	contribution, err := unit.Register(ctx, bound, ProcessDescription{Identity: "benchmark-process", Capture: capture, ExcludedPaths: []string{"capture-relative"}})
	if err != nil {
		t.Fatal(err)
	}
	if contribution.Capture() != dir+string(filepath.Separator)+capture {
		t.Fatalf("capture was not resolved against execution: %q", contribution.Capture())
	}
	if _, err := unit.Register(ctx, bound, ProcessDescription{Identity: "unaccounted-process"}); err == nil {
		t.Fatal("second contributor admitted by a single-process unit")
	}
	sibling, err := execution.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Abort()
	if err := sibling.Submit(contribution, Terminal{Kind: NormalCompletion}); err == nil {
		t.Fatal("borrowed a sibling's contribution")
	}
	if err := unit.Submit(contribution, Terminal{}); err == nil {
		t.Fatal("missing terminal event accepted")
	}
	if value, _ := gotool.LookupEnv(contribution.Environment(), "GOAMD64"); value != "v2" {
		t.Fatalf("runtime selected %q", value)
	}
	cmd, err := testProgramCmd(ctx, contribution.Directory(), contribution.Environment(), binary,
		"-test.run=^$", "-test.bench=^BenchmarkValue$", "-test.benchtime=1x", "-test.count=1", "-test.testlogfile="+contribution.Capture())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "BenchmarkValue") {
		t.Fatalf("measurement: %v\n%s", err, out)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "capture-relative", "real", "testlog")); err != nil || !strings.Contains(string(data), "getenv FRESH_SESSION_VALUE") {
		t.Fatalf("the requested capture destination was not used: %v\n%s", err, data)
	}
	if err := unit.Submit(contribution, Terminal{Kind: NormalCompletion}); err != nil {
		t.Fatal(err)
	}
	if err := unit.Submit(contribution, Terminal{Kind: AbnormalCompletion, Reason: "conflicting terminal"}); err == nil {
		t.Fatal("terminal disposition replaced")
	}
	gate := &queryGate{started: make(chan struct{}), release: make(chan struct{})}
	releaseClosing := sync.OnceFunc(func() { close(gate.release) })
	defer releaseClosing()
	closingGate.Store(gate)
	type closeResult struct {
		value Finalized
		err   error
	}
	closed := make(chan closeResult, 1)
	go func() { value, err := unit.Close(ctx); closed <- closeResult{value, err} }()
	select {
	case <-gate.started:
	case result := <-closed:
		t.Fatalf("close did not reach finalization: %v", result.err)
	case <-time.After(10 * time.Second):
		t.Fatal("close did not reach the roots query")
	}
	secondClose := make(chan error, 1)
	go func() { _, err := unit.Close(ctx); secondClose <- err }()
	secondPending := false
	select {
	case err := <-secondClose:
		if !errors.Is(err, errUnitClosed) {
			t.Fatalf("concurrent close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("another close entered finalization instead of refusing the sealed unit")
		secondPending = true
	}
	releaseClosing()
	closingGate.Store(nil)
	if secondPending {
		select {
		case <-secondClose:
		case <-time.After(10 * time.Second):
			t.Fatal("second closing did not return after release")
		}
	}
	var completed closeResult
	select {
	case completed = <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("released closing did not finish")
	}
	final, err := completed.value, completed.err
	if err != nil {
		t.Fatal(err)
	}
	if final.Verdict.Status != Valid || final.Observation != SupportedObservation || final.Terminal.Kind != NormalCompletion || final.ObservationReason != "" || final.OutcomeReason != "" {
		t.Fatalf("closed evidence: verdict=%+v observation=%q outcome=%q", final.Verdict, final.ObservationReason, final.OutcomeReason)
	}
	if _, err := unit.Close(ctx); !errors.Is(err, errUnitClosed) {
		t.Fatalf("closed unit reopened: %v", err)
	}
	record := sessionCheckRecord{Build: configuration, Runtime: RuntimeDescription{Environment: runtimeEnv}, Subject: subject, Fingerprint: final.Fingerprint}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(recordPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	checkerEnv := gotool.SetEnv(os.Environ(), "FRESH_SESSION_CHECK", recordPath)
	checkerEnv = gotool.SetEnv(checkerEnv, "XDG_CACHE_HOME", t.TempDir())
	checker, err := testProgramCmd(ctx, dir, checkerEnv, executable, "-test.run=^TestSessionCheckerProcess$", "-test.v")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := checker.CombinedOutput(); err != nil || !strings.Contains(string(out), "record valid in fresh process") {
		t.Fatalf("restart check: %v\n%s", err, out)
	}
	if err := unit.Submit(contribution, Terminal{Kind: NormalCompletion}); !errors.Is(err, errUnitClosed) {
		t.Fatalf("late submission: %v", err)
	}
	second, err := sibling.Register(ctx, bound, ProcessDescription{Identity: "independent-process", Capture: filepath.Join(t.TempDir(), "testlog")})
	if err != nil {
		t.Fatalf("sibling preparation after closing: %v", err)
	}
	secondCmd, err := testProgramCmd(ctx, second.Directory(), second.Environment(), binary, "-test.run=^$", "-test.bench=^BenchmarkValue$", "-test.benchtime=1x", "-test.count=1", "-test.testlogfile="+second.Capture())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := secondCmd.CombinedOutput(); err != nil {
		t.Fatalf("sibling execution: %v\n%s", err, out)
	}
	if err := sibling.Submit(second, Terminal{Kind: NormalCompletion}); err != nil {
		t.Fatal(err)
	}
	if result, err := sibling.Close(ctx); err != nil || result.Verdict.Status != Valid {
		t.Fatalf("sibling closing: %+v %v", result.Verdict, err)
	}
	aborted, err := execution.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	abortProcess, err := aborted.Register(ctx, bound, ProcessDescription{Identity: "aborted-close", Capture: filepath.Join(t.TempDir(), "testlog")})
	if err != nil {
		t.Fatal(err)
	}
	abortCommand, err := testProgramCmd(ctx, abortProcess.Directory(), abortProcess.Environment(), binary, "-test.run=^$", "-test.bench=^BenchmarkValue$", "-test.benchtime=1x", "-test.count=1", "-test.testlogfile="+abortProcess.Capture())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := abortCommand.CombinedOutput(); err != nil {
		t.Fatalf("aborted-close execution: %v\n%s", err, out)
	}
	if err := aborted.Submit(abortProcess, Terminal{Kind: NormalCompletion}); err != nil {
		t.Fatal(err)
	}
	abortGate := &queryGate{started: make(chan struct{}), release: make(chan struct{}), spawnMarker: filepath.Join(t.TempDir(), "spawned")}
	releaseAbort := sync.OnceFunc(func() { close(abortGate.release) })
	defer releaseAbort()
	closingGate.Store(abortGate)
	abortResult := make(chan closeResult, 1)
	go func() { value, err := aborted.Close(ctx); abortResult <- closeResult{value, err} }()
	select {
	case <-abortGate.started:
	case result := <-abortResult:
		t.Fatalf("closing did not reach its abort boundary: %v", result.err)
	case <-time.After(10 * time.Second):
		t.Fatal("closing did not reach its abort boundary")
	}
	aborted.Abort()
	releaseAbort()
	closingGate.Store(nil)
	select {
	case result := <-abortResult:
		if !errors.Is(result.err, errUnitAborted) || result.value.Fingerprint.MaximalClosure != "" {
			t.Fatalf("aborted close returned final evidence: %+v %v", result.value.Verdict, result.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("aborted closing did not stop")
	}
	if _, err := os.Stat(abortGate.spawnMarker); !os.IsNotExist(err) {
		t.Fatalf("aborted closing started another query: %v", err)
	}
	diagnostic, err := execution.BeginIdentity(subject)
	if err != nil {
		t.Fatal(err)
	}
	diagnosticProcess, err := diagnostic.Register(ctx, bound, ProcessDescription{Identity: "profile-process", Capture: filepath.Join(t.TempDir(), "testlog")})
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "cpu.pprof")
	profileCommand, err := testProgramCmd(ctx, diagnosticProcess.Directory(), diagnosticProcess.Environment(), binary, "-test.run=^$", "-test.bench=^BenchmarkValue$", "-test.benchtime=1x", "-test.count=1", "-test.cpuprofile="+profile, "-test.testlogfile="+diagnosticProcess.Capture())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := profileCommand.CombinedOutput(); err != nil {
		t.Fatalf("diagnostic execution: %v\n%s", err, out)
	}
	if err := diagnostic.Submit(diagnosticProcess, Terminal{Kind: NormalCompletion}); err != nil {
		t.Fatal(err)
	}
	if result, err := diagnostic.Close(ctx); err != nil || result.Observation != IdentityObservation || result.Fingerprint.ObservationProof.Strategy != "" {
		t.Fatalf("diagnostic gained observation authority: disposition=%d error=%v", result.Observation, err)
	}
	write("input", "before")
	fileUnit, err := execution.BeginIdentity(fileSubject)
	if err != nil {
		t.Fatal(err)
	}
	fileProcess, err := fileUnit.Register(ctx, bound, ProcessDescription{Identity: "identity-file", Capture: filepath.Join(t.TempDir(), "testlog")})
	if err != nil {
		t.Fatal(err)
	}
	fileCommand, err := testProgramCmd(ctx, fileProcess.Directory(), fileProcess.Environment(), binary, "-test.run=^$", "-test.bench=^BenchmarkFile$", "-test.benchtime=1x", "-test.count=1", "-test.testlogfile="+fileProcess.Capture())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := fileCommand.CombinedOutput(); err != nil {
		t.Fatalf("identity-file execution: %v\n%s", err, out)
	}
	if err := fileUnit.Submit(fileProcess, Terminal{Kind: NormalCompletion}); err != nil {
		t.Fatal(err)
	}
	priorObserve := viewTestHooks.observe
	viewTestHooks.observe = func() { write("input", "after") }
	t.Cleanup(func() { viewTestHooks.observe = priorObserve })
	fileResult, fileErr := fileUnit.Close(ctx)
	viewTestHooks.observe = priorObserve
	if !errors.Is(fileErr, ErrViewChanged) || fileResult.Fingerprint.MaximalClosure != "" {
		t.Fatalf("identity-only closing missed runtime motion during source validation: %+v %v", fileResult.Verdict, fileErr)
	}
	unstarted, err := execution.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	unstartedProcess, err := unstarted.Register(ctx, bound, ProcessDescription{Identity: "never-started"})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstarted.Submit(unstartedProcess, Terminal{Kind: NeverStarted, Reason: "executor cancelled before spawn"}); err != nil {
		t.Fatal(err)
	}
	if result, err := unstarted.Close(ctx); err == nil || result.Fingerprint.MaximalClosure != "" {
		t.Fatalf("unstarted process became evidence: %+v %v", result.Verdict, err)
	}
	abnormal, err := execution.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	abnormalProcess, err := abnormal.Register(ctx, bound, ProcessDescription{Identity: "abnormal"})
	if err != nil {
		t.Fatal(err)
	}
	if err := abnormal.Submit(abnormalProcess, Terminal{Kind: AbnormalCompletion, Reason: "executor observed termination"}); err != nil {
		t.Fatal(err)
	}
	if result, err := abnormal.Close(ctx); err != nil || result.Observation != IncompleteObservation || result.Terminal.Kind != AbnormalCompletion || result.Verdict.Status != Unverifiable {
		t.Fatalf("abnormal disposition lost: terminal=%+v observation=%d verdict=%+v error=%v", result.Terminal, result.Observation, result.Verdict, err)
	}
	current, err := NewSession(ctx, configuration, policy)
	if err != nil {
		t.Fatal(err)
	}
	checking, err := current.Snapshot(ctx, []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := bindTestRuntime(t, checking, RuntimeDescription{Environment: runtimeEnv}).Check(ctx, subject, final.Fingerprint)
	if err != nil || verdict.Status != Valid {
		t.Fatalf("later check: %+v %v", verdict, err)
	}
	compilerChange := configuration
	compilerChange.Environment = gotool.SetEnv(buildEnv, "CGO_CFLAGS_ALLOW", "-fplugin=changed")
	compilerSession, err := NewSession(ctx, compilerChange, policy)
	if err != nil {
		t.Fatal(err)
	}
	compilerSnapshot, err := compilerSession.Snapshot(ctx, []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err = bindTestRuntime(t, compilerSnapshot, RuntimeDescription{Environment: runtimeEnv}).Check(ctx, subject, final.Fingerprint)
	if err != nil || verdict.Status != Stale || verdict.Reason != "buildconfig" {
		t.Fatalf("compiler environment change ignored: %+v %v", verdict, err)
	}
	ambientChange := configuration
	ambientChange.Environment = gotool.SetEnv(gotool.SetEnv(buildEnv, "ANTIGRAVITY_SOURCE_METADATA", "step=99"), "TERM", "dumb")
	ambientSession, err := NewSession(ctx, ambientChange, policy)
	if err != nil {
		t.Fatal(err)
	}
	ambientSnapshot, err := ambientSession.Snapshot(ctx, []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err = bindTestRuntime(t, ambientSnapshot, RuntimeDescription{Environment: runtimeEnv}).Check(ctx, subject, final.Fingerprint)
	if err != nil || verdict.Status != Valid {
		t.Fatalf("ambient shell variable falsified build guard: %+v %v", verdict, err)
	}
	changedRuntime := gotool.SetEnv(runtimeEnv, "FRESH_SESSION_VALUE", "changed")
	verdict, err = bindTestRuntime(t, snapshot, RuntimeDescription{Environment: changedRuntime}).Check(ctx, subject, final.Fingerprint)
	if err != nil || verdict.Status != Stale {
		t.Fatalf("changed runtime served: %+v %v", verdict, err)
	}
	configuration.Environment = gotool.SetEnv(buildEnv, "GOAMD64", "v2")
	write("feature.go", "//go:build amd64.v2\n\npackage session\nfunc Value() int { return 3 }\n")
	changedBuild, err := NewSession(ctx, configuration, policy)
	if err != nil {
		t.Fatal(err)
	}
	changedBuildSnapshot, err := changedBuild.Snapshot(ctx, []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	buildV2, err := changedBuildSnapshot.BuildDescription(subject.Package)
	if err != nil {
		t.Fatal(err)
	}
	binaryV2 := filepath.Join(t.TempDir(), "bench.test")
	args = append([]string{"test", "-c", "-o", binaryV2}, buildV2.Flags...)
	args = append(args, buildV2.Package)
	if out, err := runner.Run(ctx, buildV2.Directory, buildV2.Environment, args...); err != nil {
		t.Fatalf("changed build: %v\n%s", err, out)
	}
	changedControl, err := testProgramCmd(ctx, dir, runtimeEnv, binaryV2, "-test.run=^TestValue$", "-test.v")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := changedControl.CombinedOutput(); err != nil || !strings.Contains(string(out), "selected=3") {
		t.Fatalf("changed actual artifact: %v\n%s", err, out)
	}
	wrongBuild, err := execution.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	foreignBinding, err := changedBuildSnapshot.BindBuilt(subject.Package, "different-build")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongBuild.Register(ctx, foreignBinding, ProcessDescription{Identity: "wrong-build"}); err == nil {
		t.Fatal("borrowed an artifact from another snapshot")
	}
	wrongBuild.Abort()
	verdict, err = bindTestRuntime(t, changedBuildSnapshot, RuntimeDescription{Environment: runtimeEnv}).Check(ctx, subject, final.Fingerprint)
	if err != nil || verdict.Status != Stale {
		t.Fatalf("changed producing build served: %+v %v", verdict, err)
	}
	pending, err := execution.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	prepared, resume := make(chan struct{}), make(chan struct{})
	resumePreparation := sync.OnceFunc(func() { close(resume) })
	defer resumePreparation()
	defer pending.Abort()
	pending.view.beforeOutcomeIssue = func() { close(prepared); <-resume }
	registered := make(chan error, 1)
	go func() {
		_, err := pending.Register(ctx, bound, ProcessDescription{Identity: "unfinished-preparation"})
		registered <- err
	}()
	select {
	case <-prepared:
	case err := <-registered:
		t.Fatalf("preparation ended before its owned boundary: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("preparation did not reach its boundary")
	}
	if result, err := pending.Close(ctx); !errors.Is(err, ErrUnitIncomplete) || result.Fingerprint.MaximalClosure != "" {
		t.Fatalf("unfinished preparation closed: %+v %v", result.Verdict, err)
	}
	resumePreparation()
	select {
	case err := <-registered:
		if !errors.Is(err, errUnitClosed) {
			t.Fatalf("late preparation admitted: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("closed preparation did not return")
	}
	drifting, err := execution.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	driftProcess, err := drifting.Register(ctx, bound, ProcessDescription{Identity: "source-drift", Capture: filepath.Join(t.TempDir(), "testlog")})
	if err != nil {
		t.Fatal(err)
	}
	write("base.go", "//go:build !amd64.v2\n\npackage session\nfunc Value() int { return 9 }\n")
	driftCommand, err := testProgramCmd(ctx, driftProcess.Directory(), driftProcess.Environment(), binary, "-test.run=^$", "-test.bench=^BenchmarkValue$", "-test.benchtime=1x", "-test.count=1", "-test.testlogfile="+driftProcess.Capture())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := driftCommand.CombinedOutput(); err != nil {
		t.Fatalf("drift-arm execution: %v\n%s", err, out)
	}
	if err := drifting.Submit(driftProcess, Terminal{Kind: NormalCompletion}); err != nil {
		t.Fatal(err)
	}
	if result, err := drifting.Close(ctx); !errors.Is(err, ErrViewChanged) || result.Fingerprint.MaximalClosure != "" {
		t.Fatalf("source drift returned final evidence: %+v %v", result.Verdict, err)
	}
	write("base.go", "//go:build !amd64.v2\n\npackage session\nfunc Value() int { return 1 }\n")
	write("unused_test.go", "package session\nimport \"testing\"\nfunc TestUnused(t *testing.T) {}\n")
	extensionSession, err := NewSession(ctx, build, policy)
	if err == nil {
		t.Fatal("package-filled execution description accepted as a session configuration")
	}
	configuration.Environment = buildEnv
	extensionSession, err = NewSession(ctx, configuration, policy)
	if err != nil {
		t.Fatal(err)
	}
	extensionSnapshot, err := extensionSession.Snapshot(ctx, []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	extension := bindTestRuntime(t, extensionSnapshot, RuntimeDescription{Environment: runtimeEnv})
	if verdict, err := extension.Check(ctx, subject, final.Fingerprint); err != nil || verdict.Status != Stale {
		t.Fatalf("ordinary checking silently extended applicability: %+v %v", verdict, err)
	}
	checked, err := extension.CheckBatchWithLedgers(ctx, []Candidate{{subject, final.Fingerprint}}, map[int]TestVariantLedger{0: ledger})
	if err != nil || len(checked) != 1 || checked[0].Verdict.Status != Valid || checked[0].Extension == nil {
		t.Fatalf("licensed extension: %+v %v", checked, err)
	}
	extended, paired := checked[0].Extension.Fingerprint, checked[0].Extension.Ledger
	if extended.TestVariantClosure != final.Fingerprint.TestVariantClosure || extended.ObservationProof != final.Fingerprint.ObservationProof || extended.RuntimeInputs != final.Fingerprint.RuntimeInputs || len(paired.Declarations) <= len(ledger.Declarations) {
		t.Fatal("extension lost producing evidence or returned the wrong companion ledger")
	}
	// Price only the native provisional operation, independently of the public
	// wrapper's closing call. The next observation belongs to that closing call.
	preview, err := extension.newView([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	preview.session.deferredCheckClose = true
	previewPasses := 0
	viewTestHooks.observe = func() { previewPasses++ }
	_, _, previewVerdict, previewErr := preview.checkInertTestVariantExtension(ctx, final.Fingerprint, ledger, subject, true)
	preview.session.deferredCheckClose = false
	viewTestHooks.observe = priorObserve
	if previewErr != nil || previewVerdict.Status != Valid {
		t.Fatalf("provisional control: %+v %v", previewVerdict, previewErr)
	}
	passes := 0
	viewTestHooks.observe = func() {
		passes++
		if passes == previewPasses+1 {
			write("base.go", "//go:build !amd64.v2\n\npackage session\nfunc Value() int { return 77 }\n")
		}
	}
	rejected, closingErr := extension.CheckBatchWithLedgers(ctx, []Candidate{{subject, final.Fingerprint}}, map[int]TestVariantLedger{0: ledger})
	viewTestHooks.observe = priorObserve
	if !errors.Is(closingErr, ErrViewChanged) || len(rejected) != 0 {
		t.Fatalf("extension returned provisional evidence without closing: passes=%d preview=%d error=%v", passes, previewPasses, closingErr)
	}
}

type sessionCheckRecord struct {
	Build       BuildDescription
	Runtime     RuntimeDescription
	Subject     Subject
	Fingerprint Fingerprint
	Want        Status
}

// The parent starts this in a new process with an empty memo home. The stored
// native fingerprint is decoded as data; no producing receipt is recreated.
func TestSessionCheckerProcess(t *testing.T) {
	path := os.Getenv("FRESH_SESSION_CHECK")
	if path == "" {
		t.Skip("subprocess entry")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record sessionCheckRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	session, err := NewSession(ctx, record.Build, SessionPolicy{Execution: SingleSubjectExecution})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(ctx, []Subject{record.Subject}, record.Fingerprint.ResultKind)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := bindTestRuntime(t, snapshot, record.Runtime).Check(ctx, record.Subject, record.Fingerprint)
	want := record.Want
	if want == "" {
		want = Valid
	}
	if err != nil || verdict.Status != want {
		t.Fatalf("record check: %+v %v", verdict, err)
	}
	t.Logf("record %s in fresh process", want)
}

func bindTestRuntime(t *testing.T, snapshot *Snapshot, description RuntimeDescription) *RuntimeBinding {
	t.Helper()
	binding, err := snapshot.BindRuntime(t.Context(), description)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestSnapshotCaptureAndCaptureBatch(t *testing.T) {
	ctx := t.Context()
	for _, s := range []*Snapshot{nil, {}} {
		for name, call := range map[string]func() error{
			"Capture":         func() error { _, err := s.Capture(ctx, Subject{}); return err },
			"CaptureBatch":    func() error { _, err := s.CaptureBatch(ctx); return err },
			"captureObserved": func() error { _, err := s.captureObserved(ctx, Subject{}); return err },
			"CaptureObservedBatch": func() error {
				_, err := s.CaptureObservedBatch(ctx)
				return err
			},
			"AttachObservation": func() error {
				_, err := s.AttachObservation(Subject{}, Fingerprint{}, runtimeinput.Observation{})
				return err
			},
			"Check":              func() error { _, err := s.Check(ctx, Fingerprint{}, Subject{}); return err },
			"CheckBatch":         func() error { _, err := s.CheckBatch(ctx, nil); return err },
			"CheckObserved":      func() error { _, err := s.CheckObserved(ctx, Fingerprint{}, Subject{}); return err },
			"CheckObservedBatch": func() error { _, err := s.CheckObservedBatch(ctx, nil); return err },
			"Validate":           func() error { return s.Validate(ctx) },
			"checkInertTestVariantExtension": func() error {
				_, _, _, err := s.checkInertTestVariantExtension(ctx, Fingerprint{}, TestVariantLedger{}, Subject{}, false)
				return err
			},
			"prepareOutcomeSupport": func() error {
				_, _, err := s.prepareOutcomeSupport(ctx, runtimeinput.ProducerFrame{}, "worker")
				return err
			},
			"SourceFilesFor":    func() error { _, err := s.SourceFilesFor(Subject{}); return err },
			"TestVariantLedger": func() error { _, err := s.TestVariantLedger(Subject{}); return err },
			"Sibling":           func() error { _, err := s.Sibling(nil); return err },
			"ExplainDynamicState": func() error {
				_, err := s.ExplainDynamicState(ctx, "pkg", "Var")
				return err
			},
		} {
			if err := call(); err == nil || err.Error() != "gofresh: uninitialized snapshot" {
				t.Fatalf("%s on %#v = %v, want uninitialized snapshot error", name, s, err)
			}
		}
		if files := s.SourceFiles(); files != nil {
			t.Fatalf("SourceFiles on %#v = %v, want nil", s, files)
		}
	}
	if testing.Short() {
		t.Skip("spawns go subprocesses to build a session snapshot")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/cap\n\ngo 1.26\n",
		"cap.go": "package cap\nfunc A() int { return 1 }\nfunc B() int { return 2 }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	session, err := NewSession(ctx, BuildDescription{
		Directory:   dir,
		Environment: gotool.SetEnv(os.Environ(), "GOWORK", "off"),
		Inputs:      []string{},
	}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	subA := Subject{Package: "example.com/cap", Symbol: "A"}
	subB := Subject{Package: "example.com/cap", Symbol: "B"}
	snapshot, err := session.Snapshot(ctx, []Subject{subA, subB}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	fpA, err := snapshot.Capture(ctx, subA)
	if err != nil || fpA.MaximalClosure == "" {
		t.Fatalf("Capture(A): %+v, %v", fpA, err)
	}
	batch, err := snapshot.CaptureBatch(ctx)
	if err != nil {
		t.Fatalf("CaptureBatch: %v", err)
	}
	if len(batch) != 2 || batch[subA].MaximalClosure != fpA.MaximalClosure || batch[subB].MaximalClosure == "" {
		t.Fatalf("CaptureBatch mismatch: %+v vs %+v", batch, fpA)
	}
}

func TestSessionPolicyAssumePureAndSnapshotFor(t *testing.T) {
	ctx := t.Context()
	var nilSession *Session
	if _, err := nilSession.SnapshotFor(ctx, nil, "", CodeResult); err == nil {
		t.Fatal("nil session SnapshotFor succeeded")
	}
	if testing.Short() {
		t.Skip("spawns go subprocesses to build a session snapshot")
	}
	dir := t.TempDir()
	modDir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(modDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"go.mod": "module example.com/sub\n\ngo 1.26\n",
		"sub.go": "package sub\nimport \"os\"\nfunc Impure() string { return os.Getenv(\"X\") }\nfunc Other() int { return 1 }\n",
	} {
		if err := os.WriteFile(filepath.Join(modDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	impure := Subject{Package: "example.com/sub", Symbol: "Impure"}
	other := Subject{Package: "example.com/sub", Symbol: "Other"}
	session, err := NewSession(ctx, BuildDescription{
		Directory:   modDir,
		Environment: gotool.SetEnv(os.Environ(), "GOWORK", "off"),
		Inputs:      []string{},
	}, SessionPolicy{
		AssumePure: func(s Subject) bool {
			return s == impure
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.SnapshotFor(ctx, []Subject{impure}, dir, CodeResult); err == nil {
		t.Fatal("mismatched moduleDir accepted by SnapshotFor")
	}
	snapshot, err := session.SnapshotFor(ctx, []Subject{impure, other}, modDir, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := snapshot.Sibling([]Subject{impure})
	if err != nil {
		t.Fatal(err)
	}
	fp, err := sibling.Capture(ctx, impure)
	if err != nil {
		t.Fatalf("Capture(impure): %v", err)
	}
	verdict, err := sibling.Check(ctx, fp, impure)
	if err != nil || verdict.Status != Valid {
		t.Fatalf("Check(impure) with AssumePure: %+v, %v", verdict, err)
	}
	if err := sibling.Validate(ctx); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// One build can execute in distinct runtime directories. A truthful PWD read
// is a runtime dependency even though each execution's frame is well bound.
func TestSessionPWDIsARecordedRuntimeDependency(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes a retained fixture")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the admitted immutable-environment outcome method is Linux-only")
	}
	ctx := t.Context()
	dir := t.TempDir()
	for name, text := range map[string]string{
		"go.mod": "module example.com/pwd\n\ngo 1.27.0\n",
		"p.go":   "package p\n",
		"p_test.go": `package p
import ("os"; "testing")
var sink string
func BenchmarkPWD(b *testing.B) { for b.Loop() { sink = os.Getenv("PWD") } }
func TestPWD(t *testing.T) { t.Log("actual-pwd=" + os.Getenv("PWD")) }
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, b := filepath.Join(dir, "runtime-a"), filepath.Join(dir, "runtime-b-longer")
	for _, child := range []string{a, b} {
		if err := os.Mkdir(child, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	env := gotool.SetEnv(os.Environ(), "GOENV", "off")
	build := BuildDescription{Directory: dir, Environment: env, Inputs: []string{}}
	runner := gotool.Runner{}
	policy := SessionPolicy{Execution: SingleSubjectExecution}
	subject := Subject{Package: "example.com/pwd", Symbol: "BenchmarkPWD"}
	session, err := NewSession(ctx, build, policy)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(ctx, []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	execution := bindTestRuntime(t, snapshot, RuntimeDescription{Directory: a, Environment: env})
	description, err := snapshot.BuildDescription(subject.Package)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "bench.test")
	args := append([]string{"test", "-c", "-o", bin}, description.Flags...)
	args = append(args, description.Package)
	if out, err := runner.Run(ctx, description.Directory, description.Environment, args...); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, cwd := range []string{a, b} {
		cmd, err := testProgramCmd(ctx, cwd, env, bin, "-test.run=^TestPWD$", "-test.v")
		if err != nil {
			t.Fatal(err)
		}
		if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "actual-pwd="+cwd) {
			t.Fatalf("runtime control %s: %v\n%s", cwd, err, out)
		}
	}
	bound, err := snapshot.BindBuilt(subject.Package, "retained-pwd-binary")
	if err != nil {
		t.Fatal(err)
	}
	u, err := execution.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Abort()
	capture := filepath.Join(t.TempDir(), "testlog")
	c, err := u.Register(ctx, bound, ProcessDescription{Identity: "pwd-process", Capture: capture})
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := testProgramCmd(ctx, c.Directory(), c.Environment(), bin, "-test.run=^$", "-test.bench=^BenchmarkPWD$", "-test.benchtime=1x", "-test.testlogfile="+c.Capture())
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "\nPASS\n") {
		t.Fatalf("measurement: %v\n%s", err, out)
	}
	log, err := os.ReadFile(capture)
	if err != nil || !strings.Contains(string(log), "getenv PWD\n") {
		t.Fatalf("no PWD capture: %v\n%s", err, log)
	}
	if err := u.Submit(c, Terminal{Kind: NormalCompletion}); err != nil {
		t.Fatal(err)
	}
	final, err := u.Close(ctx)
	if err != nil || final.Verdict.Status != Valid || final.Observation != SupportedObservation {
		t.Fatalf("closing: %+v, %v", final, err)
	}
	data, err := json.Marshal(final.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	var recorded Fingerprint
	if err := json.Unmarshal(data, &recorded); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, cwd string
		unrelated bool
		want      Status
	}{
		{"same", a, false, Valid}, {"unrelated value", a, true, Valid}, {"other directory", b, false, Stale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtimeEnv := env
			if tc.unrelated {
				runtimeEnv = gotool.SetEnv(env, "UNREAD_RUNTIME_VALUE", "changed")
			}
			view := bindTestRuntime(t, snapshot, RuntimeDescription{Directory: tc.cwd, Environment: runtimeEnv})
			facts, err := view.CurrentFacts(ctx, subject)
			if err != nil || facts.Guards.BuildConfig != recorded.Guards.BuildConfig {
				t.Fatalf("runtime-only change moved build guard: %v", err)
			}
			got, err := view.Check(ctx, subject, recorded)
			if err != nil || got.Status != tc.want {
				t.Fatalf("check=%+v err=%v, want %v", got, err, tc.want)
			}
			if !tc.unrelated {
				record := sessionCheckRecord{Build: build, Runtime: RuntimeDescription{Directory: tc.cwd, Environment: runtimeEnv}, Subject: subject, Fingerprint: recorded, Want: tc.want}
				encoded, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "record.json")
				if err := os.WriteFile(path, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
				checkerEnv := gotool.SetEnv(os.Environ(), "FRESH_SESSION_CHECK", path)
				checkerEnv = gotool.SetEnv(checkerEnv, "XDG_CACHE_HOME", t.TempDir())
				checker, err := testProgramCmd(ctx, dir, checkerEnv, executable, "-test.run=^TestSessionCheckerProcess$", "-test.v")
				if err != nil {
					t.Fatal(err)
				}
				if out, err := checker.CombinedOutput(); err != nil || !strings.Contains(string(out), "record "+string(tc.want)+" in fresh process") {
					t.Fatalf("restart: %v\n%s", err, out)
				}
			}
		})
	}
	d, err := runtimeinput.Describe(recorded.RuntimeInputs, dir)
	if err != nil || len(d.EnvNames) != 1 || d.EnvNames[0] != "PWD" {
		t.Fatalf("recorded inputs=%+v, %v", d, err)
	}
	// Reconstruct the actual older encoding: it retained support but omitted
	// the truthful PWD read. Native record I/O preserves that history, whereas
	// current checking must not license it even in the original directory.
	var oldManifest struct {
		Version  int      `json:"v"`
		Outcome  string   `json:"outcome,omitempty"`
		Subjects []string `json:"subjects,omitempty"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(recorded.RuntimeInputs)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &oldManifest); err != nil {
		t.Fatal(err)
	}
	oldManifest.Version = 2
	raw, err = json.Marshal(oldManifest)
	if err != nil {
		t.Fatal(err)
	}
	legacy := recorded
	legacy.RuntimeInputs = base64.RawURLEncoding.EncodeToString(raw)
	fold := "version 2\noutcome " + oldManifest.Outcome + "\n"
	for _, subject := range oldManifest.Subjects {
		fold += "subject " + subject + "\n"
	}
	digest := sha256.Sum256([]byte(fold))
	legacy.RuntimeDigest = hex.EncodeToString(digest[:])[:32]
	before, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var restored Fingerprint
	if err := json.Unmarshal(before, &restored); err != nil {
		t.Fatalf("historical native record lost readability: %v", err)
	}
	for _, observed := range []bool{false, true} {
		view, err := execution.newView([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		var verdict Verdict
		if observed {
			verdict, err = view.CheckObserved(ctx, restored, subject)
		} else {
			verdict, err = view.Check(ctx, restored, subject)
		}
		if err != nil || verdict.Status == Valid {
			t.Fatalf("legacy check observed=%t: %+v, %v", observed, verdict, err)
		}
	}
	got, err := execution.Check(ctx, subject, restored)
	if err != nil || got.Status == Valid {
		t.Fatalf("legacy snapshot check: %+v, %v", got, err)
	}
	after, err := json.Marshal(restored)
	if err != nil || string(before) != string(after) {
		t.Fatalf("checking rewrote historical evidence: %v", err)
	}
}

func TestObservedApplicabilityBatchSharesCurrentProofAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("analyzes a multi-subject observed applicability batch")
	}
	ctx := context.Background()
	dir := writeSupportedViewModule(t)
	source := `package observed
import ("os"; "testing")
func TestRead(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }
func TestOther(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }
func TestReadsFile(t *testing.T) { _, _ = os.ReadFile("fixture") }
`
	write := func(text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "observed_test.go"), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(source)
	subjects := []Subject{{"example.com/observed", "TestRead"}, {"example.com/observed", "TestOther"}}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	newView := func() *Snapshot {
		t.Helper()
		v, err := engine.newView(ctx, subjects, dir)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	producer := newView()
	proofs, err := producer.CaptureObservedBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := producer.TestVariantLedger(subjects[0])
	if err != nil {
		t.Fatal(err)
	}
	observation := supportedObservation(t, producer, dir, dir, "both tests", "getenv OUTCOME_VALUE\n")
	for _, subject := range subjects {
		proofs[subject], err = producer.AttachObservation(subject, proofs[subject], observation)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := producer.Validate(ctx); err != nil {
		t.Fatal(err)
	}
	write(source + "\nfunc TestArithmetic(t *testing.T) { if 2+2 != 4 { t.Fatal(\"arithmetic\") } }\n")
	extending := newView()
	for _, subject := range subjects {
		updated, _, verdict, err := extending.checkInertTestVariantExtension(ctx, proofs[subject], ledger, subject, true)
		if err != nil || verdict.Status != Valid {
			t.Fatalf("extension: %+v %v", verdict, err)
		}
		proofs[subject] = updated
	}
	checking := newView()
	analyses := 0
	checking.beforePreciseAnalysis = func() { analyses++ }
	verdicts, err := checking.CheckObservedBatch(ctx, proofs)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		if verdicts[subject].Status != Valid {
			t.Fatalf("batch subject %v: %+v", subject, verdicts[subject])
		}
	}
	if analyses != 1 {
		t.Fatalf("batch paid %d precise analyses, want one", analyses)
	}
}

func TestApplicabilityValidationDefersUnavailableUntilAllObligationsClose(t *testing.T) {
	if testing.Short() {
		t.Skip("validates retained historical records across a proof cut and runtime drift")
	}
	f := newApplicabilityValidationFixture(t)
	ctx := context.Background()
	for _, observedFile := range []bool{false, true} {
		t.Run(map[bool]string{false: "separate policies", true: "same observed batch"}[observedFile], func(t *testing.T) {
			f.engine.analysisBudget = 0
			if err := os.WriteFile(f.input, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			v := f.view(t)
			f.extend(t, v, f.subjects[0], f.recorded[f.subjects[0]], true)
			f.extend(t, v, f.subjects[2], f.fileRecord, observedFile)
			f.engine.analysisBudget = time.Nanosecond
			if err := v.Validate(ctx); !errors.Is(err, ErrAnalysisUnavailable) {
				t.Fatalf("unchanged cut: %v", err)
			}
			analyses := 0
			viewTestHooks.beforeAnalysis = func() {
				analyses++
				if err := os.WriteFile(f.input, []byte("moved"), 0600); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(func() { viewTestHooks.beforeAnalysis = nil })
			err := v.Validate(ctx)
			if analyses != 1 || !errors.Is(err, ErrViewChanged) || errors.Is(err, ErrAnalysisUnavailable) || !strings.Contains(err.Error(), "PureA") {
				t.Fatalf("later runtime drift masked by A's cut (%d analyses): %v", analyses, err)
			}
		})
	}
}

func TestProducerUnavailabilityDoesNotSkipRetainedApplicability(t *testing.T) {
	if testing.Short() {
		t.Skip("validates mixed producer and historical applicability evidence")
	}
	f := newApplicabilityValidationFixture(t)
	ctx := context.Background()
	v := f.view(t)
	f.extend(t, v, f.subjects[2], f.fileRecord, false)
	observation := supportedObservation(t, v, f.dir, f.dir, "current producer", "getenv OUTCOME_VALUE\n")
	current, err := v.CaptureObservedBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range f.subjects {
		if _, err := v.AttachObservation(subject, current[subject], observation); err != nil {
			t.Fatal(err)
		}
	}
	f.engine.analysisBudget = time.Nanosecond
	if err := v.Validate(ctx); !errors.Is(err, ErrAnalysisUnavailable) {
		t.Fatalf("unchanged mixed cut: %v", err)
	}
	viewTestHooks.beforeAnalysis = func() {
		if err := os.WriteFile(f.input, []byte("moved"), 0600); err != nil {
			t.Error(err)
		}
	}
	defer func() { viewTestHooks.beforeAnalysis = nil }()
	err = v.Validate(ctx)
	if !errors.Is(err, ErrViewChanged) || errors.Is(err, ErrAnalysisUnavailable) || !strings.Contains(err.Error(), "PureA") {
		t.Fatalf("producer cut hid historical runtime drift: %v", err)
	}
}

func TestApplicabilityValidationClosesSourceAfterUnavailableProof(t *testing.T) {
	if testing.Short() {
		t.Skip("moves source at the last runtime comparison after a proof cut")
	}
	f := newApplicabilityValidationFixture(t)
	v := f.view(t)
	f.extend(t, v, f.subjects[0], f.recorded[f.subjects[0]], true)
	f.extend(t, v, f.subjects[2], f.recorded[f.subjects[2]], false)
	f.engine.analysisBudget = time.Nanosecond
	phases := 0
	f.engine.progress = func(p Progress) {
		if p.Phase != "runtime" {
			return
		}
		phases++
		if phases != 2 {
			return
		}
		path := filepath.Join(f.dir, "observed_test.go")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
			return
		}
		if err := os.WriteFile(path, append(data, []byte("\nfunc TestLateAddition(t *testing.T) {}\n")...), 0600); err != nil {
			t.Error(err)
		}
	}
	err := v.Validate(context.Background())
	if phases != 2 || !errors.Is(err, ErrViewChanged) || errors.Is(err, ErrAnalysisUnavailable) {
		t.Fatalf("final source close lost to proof cut (%d runtime phases): %v", phases, err)
	}
}

func TestApplicabilityValidationSharesCompatibleBatches(t *testing.T) {
	if testing.Short() {
		t.Skip("counts validation analysis and runtime windows over retained batches")
	}
	f := newApplicabilityValidationFixture(t)
	v := f.view(t)
	for i, subject := range f.subjects {
		f.extend(t, v, subject, f.recorded[subject], i < 2)
	}
	analyses, windows, runtimePhases := 0, 0, 0
	viewTestHooks.beforeAnalysis = func() { analyses++ }
	viewTestHooks.runtimeWindow = func() { windows++ }
	f.engine.progress = func(p Progress) {
		if p.Phase == "runtime" {
			runtimePhases++
		}
	}
	defer func() { viewTestHooks.beforeAnalysis = nil; viewTestHooks.runtimeWindow = nil }()
	if err := v.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if analyses != 1 || windows != 1 || runtimePhases != 2 {
		t.Fatalf("validation sharing: analyses=%d windows=%d runtime phases=%d; want 1,1,2", analyses, windows, runtimePhases)
	}
	// Count evaluations themselves, not just phase announcements. Each pair
	// carries the identical manifest, which is read once per endpoint across policies.
	current := f.view(t)
	read := current.runtimeCheck()
	reads := 0
	current.runtimeCurrent = func(ctx context.Context, manifest, root string) (runtimeinput.State, error) {
		reads++
		return read(ctx, manifest, root)
	}
	if err := v.validateApplicabilityBatches(context.Background(), current, v.applicabilityChecks); err != nil {
		t.Fatal(err)
	}
	if reads != 2 {
		t.Fatalf("four historical records caused %d runtime reads; want one per endpoint (2)", reads)
	}
}

func TestApplicabilityValidationPreservesDistinctRecordsOfOneSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("validates distinct historical manifests of the same subject")
	}
	f := newApplicabilityValidationFixture(t)
	for _, fileFirst := range []bool{false, true} {
		if err := os.WriteFile(f.input, []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
		v := f.view(t)
		subject := f.subjects[2]
		records := []Fingerprint{f.recorded[subject], f.fileRecord}
		if fileFirst {
			records[0], records[1] = records[1], records[0]
		}
		for _, record := range records {
			f.extend(t, v, subject, record, false)
		}
		if len(v.applicabilityChecks) != 2 {
			t.Fatalf("lost historical record: %d", len(v.applicabilityChecks))
		}
		if err := v.Validate(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.input, []byte("moved"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := v.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
			t.Fatalf("fileFirst=%v lost distinct manifest: %v", fileFirst, err)
		}
	}
}

// The construction pass reports its units — each package's listing and
// closure fold with its position, the shared typed load with its pattern
// count — and a warm precise analysis reports the memo hit that stood in
// for its program load, while an operation returning its caller's
// cancellation reports what the pass persisted.
func TestProgressReportsUnitsServedAndKept(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":      "module example.com/units\n\ngo 1.26\n",
		"a/a.go":      "package a\n\nfunc A() int { return 1 }\n",
		"a/a_test.go": "package a\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {\n\tif A() != 1 {\n\t\tt.Fatal()\n\t}\n}\n",
		"b/b.go":      "package b\n\nfunc B() int { return 2 }\n",
		"b/b_test.go": "package b\n\nimport \"testing\"\n\nfunc TestB(t *testing.T) {\n\tif B() != 2 {\n\t\tt.Fatal()\n\t}\n}\n",
	}
	for path, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a, b := Subject{Package: "example.com/units/a", Symbol: "TestA"}, Subject{Package: "example.com/units/b", Symbol: "TestB"}
	var events []Progress
	engine, err := newEngine(withDir(dir), withProgress(func(p Progress) { events = append(events, p) }))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{a, b}, dir)
	if err != nil {
		t.Fatal(err)
	}
	hashes, lists, loads := map[string]Progress{}, map[string]bool{}, 0
	for _, e := range events {
		switch e.Phase {
		case "hash":
			hashes[e.Package] = e
		case "list":
			lists[e.Package] = true
		case "typecheck":
			// The shared view load carries no package and counts its
			// patterns; a package's own testing-scan load (a cold memo
			// under a served scan) names its package with one pattern.
			if e.Package != "" {
				continue
			}
			loads++
			if e.Total < 2 {
				t.Fatalf("typed load reports %d patterns, want the two view packages at least", e.Total)
			}
		}
	}
	for _, pkg := range []string{a.Package, b.Package} {
		if !lists[pkg] {
			t.Fatalf("no list event for %s: %+v", pkg, events)
		}
		h, ok := hashes[pkg]
		if !ok || h.Total != 2 || h.Index < 1 || h.Index > 2 {
			t.Fatalf("hash event for %s = %+v, want index in 1..2 of 2", pkg, h)
		}
	}
	if loads == 0 {
		t.Fatal("no typed-load event on the construction pass")
	}

	// A cold precise analysis loads and proves; the same view's second
	// engine over the same tree serves the proof from the memo and says
	// so instead of loading.
	if _, err := view.captureObserved(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	events = nil
	warm, err := newEngine(withDir(dir), withProgress(func(p Progress) { events = append(events, p) }))
	if err != nil {
		t.Fatal(err)
	}
	warmView, err := warm.newView(context.Background(), []Subject{a}, dir)
	if err != nil {
		t.Fatal(err)
	}
	events = nil
	if _, err := warmView.captureObserved(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	served, proved, detailed := 0, false, 0
	for _, e := range events {
		if e.Phase == "served" && e.Served == "observability proof" {
			served++
			if e.Index != 1 || e.Detail != "" {
				t.Fatalf("served summary = %+v, want one package counted and no Detail (a consumer printing details must stay silent)", e)
			}
		}
		if e.Phase == "prove" {
			proved = true
		}
		if e.Detail != "" {
			detailed++
		}
	}
	if served != 1 || proved {
		t.Fatalf("warm capture served summaries=%d proved=%t, want exactly one summary and no proof: %+v", served, proved, events)
	}
	if detailed != 0 {
		t.Fatalf("%d Detail-bearing events on a clean warm capture; served must not ride the diagnostic channel", detailed)
	}

	// An operation cancelled mid-analysis reports what the pass
	// persisted before the cancellation.
	cancelled, cancel := context.WithCancel(context.Background())
	viewTestHooks.beforeAnalysis = cancel
	defer func() { viewTestHooks.beforeAnalysis = nil }()
	events = nil
	coldView, err := warm.newView(context.Background(), []Subject{b}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coldView.captureObserved(cancelled, b); err == nil {
		t.Fatal("cancelled capture succeeded")
	}
	var reported []string
	for _, e := range events {
		if e.Phase == "cancelled" {
			reported = append(reported, e.Detail)
		}
	}
	// Cancelled before its analysis, the pass persisted nothing: the
	// report says so in the one rendering, counts and nouns in order.
	if len(reported) != 1 || reported[0] != "0 observability proof slices and 0 scans persisted this operation; a rerun serves them" {
		t.Fatalf("kept-on-cancel reports = %q, want exactly one per operation with its counts: %+v", reported, events)
	}

	// A non-context failure reports no cancellation.
	viewTestHooks.beforeAnalysis = nil
	events = nil
	if _, err := warm.newView(context.Background(), []Subject{{Package: a.Package, Symbol: "NoSuch"}}, dir); err == nil {
		t.Fatal("unknown subject built a view")
	}
	for _, e := range events {
		if e.Phase == "cancelled" {
			t.Fatalf("a refusal that is not a cancellation reported one: %+v", e)
		}
	}
}

// The operation boundary reports once however many public operations
// nest: an inner beginOperation on an already-accounted context is a
// no-op finisher, and the outer one emits the served summaries and the
// cancel report over everything its passes accounted.
func TestOperationBoundaryReportsOncePerOperation(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, preparationSource)
	var events []Progress
	engine, err := newEngine(withDir(dir), withProgress(func(p Progress) { events = append(events, p) }))
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := closureNewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	hasher.Served("effect scan", "example.com/view")
	outerCtx, outerDone := engine.beginOperation(context.Background())
	innerCtx, innerDone := engine.beginOperation(outerCtx)
	accountPass(innerCtx, hasher)
	cancelled := context.Canceled
	innerDone(&cancelled)
	if len(events) != 0 {
		t.Fatalf("the nested operation reported: %+v", events)
	}
	outerDone(&cancelled)
	served, reports := 0, 0
	for _, e := range events {
		switch e.Phase {
		case "served":
			served++
			if e.Served != "effect scan" || e.Index != 1 || e.Detail != "" {
				t.Fatalf("served summary = %+v", e)
			}
		case "cancelled":
			reports++
		}
	}
	if served != 1 || reports != 1 {
		t.Fatalf("outer operation emitted served=%d cancelled=%d, want one each: %+v", served, reports, events)
	}
}

// An installed runner reaches every go command the engine spawns
// itself: an observation over a module pays its snapshots and its
// listings through the runner's hook — no separate toolchain probe,
// since the toolchain guard reads the snapshot (REQ-guard-toolchain) —
// and none outside it, which the source walk below pins for the sites.
func TestEngineSpawnsThroughTheInstalledRunner(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns go env and go list subprocesses over a module fixture")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m.go"), []byte("package m\n\nfunc F() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m_test.go"), []byte("package m\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) { if F() != 1 { t.Fatal() } }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var args [][]string
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		mu.Lock()
		defer mu.Unlock()
		args = append(args, append([]string(nil), cmd.Args...))
	}}
	e, err := newEngine(withDir(dir), withGoRunner(runner))
	if err != nil {
		t.Fatal(err)
	}
	// Construction validates the flags through the runner too; the pass
	// is judged on its own spawns.
	mu.Lock()
	args = nil
	mu.Unlock()
	if _, err := e.capture(context.Background(), Subject{Package: "example.com/m", Symbol: "TestF"}, dir); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	seen := map[string]bool{}
	snapshots := 0
	for _, a := range args {
		seen[strings.Join(a[1:], " ")] = true
		if len(a) > 1 && a[1] == "list" {
			seen["list"] = true
		}
		if strings.Join(a[1:], " ") == "env -json" {
			snapshots++
		}
	}
	for _, want := range []string{"env -json", "list"} {
		if !seen[want] {
			t.Errorf("the runner never saw `go %s` on the pass; spawns seen: %v", want, args)
		}
	}
	if seen["version"] {
		t.Errorf("the pass paid a `go version` probe beside its snapshot: %v", args)
	}
	// One snapshot serves each pass: the closure's construction, the
	// guard's digest, and the flag validation read the construction
	// pass's, and the bracket's closing pass takes exactly one fresh
	// snapshot of its own whose guard comparison refuses drift
	// (REQ-guard-buildconfig) — two per capture, never a third.
	if snapshots != 2 {
		t.Fatalf("%d `go env -json` spawns on one capture, want 2 (the construction pass and the closing pass): %v", snapshots, args)
	}
}

func TestUnitRegistrationCancellationRetainsCallerCause(t *testing.T) {
	if testing.Short() {
		t.Skip("prepares a real observation proof at a deterministic closing boundary")
	}
	dir := writeSupportedViewModule(t)
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{Execution: PackageExecution})
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	execution := bindTestRuntime(t, snapshot, RuntimeDescription{})
	bound, err := snapshot.BindBuilt(subject.Package, "declared-artifact")
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{"singleton", "package"} {
		for _, ending := range []string{"close", "abort"} {
			for _, cancellation := range []string{"live caller", "cancelled caller"} {
				t.Run(form+"/"+ending+"/"+cancellation, func(t *testing.T) {
					var transaction *Unit
					var register func(context.Context, BuildBinding, ProcessDescription) (Contribution, error)
					var end func()
					if form == "singleton" {
						u, err := execution.Begin(subject)
						if err != nil {
							t.Fatal(err)
						}
						transaction, register = u, u.Register
						t.Cleanup(u.Abort)
						end = u.Abort
						if ending == "close" {
							end = func() {
								result, err := u.Close(t.Context())
								if !errors.Is(err, ErrUnitIncomplete) || len(result.Subjects) != 0 || result.Process != "" {
									t.Fatalf("pending singleton closed: %+v %v", result, err)
								}
							}
						}
					} else {
						u, err := execution.BeginPackage([]Subject{subject})
						if err != nil {
							t.Fatal(err)
						}
						transaction, register = u, u.Register
						t.Cleanup(u.Abort)
						end = u.Abort
						if ending == "close" {
							end = func() {
								result, err := u.Close(t.Context())
								if !errors.Is(err, ErrUnitIncomplete) || len(result.Subjects) != 0 || result.Process != "" {
									t.Fatalf("pending package closed: %+v %v", result, err)
								}
							}
						}
					}
					prepared, resume := make(chan struct{}), make(chan struct{})
					release := sync.OnceFunc(func() { close(resume) })
					defer release()
					transaction.view.beforeOutcomeIssue = func() { close(prepared); <-resume }
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					type result struct {
						contribution Contribution
						err          error
					}
					done := make(chan result, 1)
					go func() {
						c, err := register(ctx, bound, ProcessDescription{Identity: "paused-process"})
						done <- result{c, err}
					}()
					select {
					case <-prepared:
					case got := <-done:
						t.Fatalf("preparation did not reach pause: %v", got.err)
					case <-time.After(30 * time.Second):
						t.Fatal("preparation did not reach pause")
					}
					want := errUnitClosed
					if cancellation == "cancelled caller" {
						cancel()
						want = context.Canceled
					}
					end()
					release()
					select {
					case got := <-done:
						if !errors.Is(got.err, want) || got.contribution != (Contribution{}) {
							t.Fatalf("terminal registration = %+v, want no contribution and %v", got, want)
						}
					case <-time.After(30 * time.Second):
						t.Fatal("terminal registration did not finish")
					}
				})
			}
		}
	}
}

func TestUnitRefusesScratchDeclarationsBeforePreparation(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs a subject snapshot")
	}
	dir := t.TempDir()
	for name, text := range map[string]string{
		"go.mod": "module example.com/prepare\n\ngo 1.27.0\n",
		"p.go":   "package p\nfunc F() int { return 1 }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/prepare", Symbol: "F"}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	execution := bindTestRuntime(t, snapshot, RuntimeDescription{})
	bound, err := snapshot.BindBuilt(subject.Package, "executor-declared-artifact")
	if err != nil {
		t.Fatal(err)
	}
	for _, ns := range []runtimeinput.ScratchNamespace{{Dir: ".", Pattern: "bad/name"}, {Dir: "..", Pattern: "scratch-*"}, {Dir: "", Pattern: "scratch-*"}, {Dir: ".", Pattern: ""}} {
		t.Run(ns.Dir+":"+ns.Pattern, func(t *testing.T) {
			u, err := execution.Begin(subject)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Abort()
			_, err = u.Register(t.Context(), bound, ProcessDescription{Identity: "worker", ScratchNamespaces: []runtimeinput.ScratchNamespace{{Dir: ".", Pattern: "valid-*"}, ns}})
			if err == nil || !strings.Contains(err.Error(), "scratch namespace") {
				t.Fatalf("declaration admitted: %v", err)
			}
			if u.execution != nil || u.phase != unitOpen {
				t.Fatal("invalid declaration reached producing preparation")
			}
			if _, err := u.Register(t.Context(), bound, ProcessDescription{Identity: "worker", ScratchNamespaces: []runtimeinput.ScratchNamespace{{Dir: ".", Pattern: "valid-*"}}}); err != nil {
				t.Fatalf("valid declaration after input refusal: %v", err)
			}
		})
	}
}
