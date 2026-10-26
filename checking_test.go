package gofresh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/runtimeinput"
)

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
		runner := gotool.Runner{Containment: &gotool.Containment{}}
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
		cmd, err := runner.Program(t.Context(), process.Directory(), process.Environment(), binary, "-test.run=^TestRead$", "-test.testlogfile="+process.Capture())
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
		if _, err := u.CheckBatch(t.Context(), []Candidate{{a, f.current[a]}}); !errors.Is(err, ErrUnitClosed) {
			t.Fatalf("closed unit reopened: %v", err)
		}
		if _, err := u.Close(t.Context()); !errors.Is(err, ErrUnitClosed) {
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
		engine := f.binding.snapshot.session.engine
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
	t.Run("CheckBatchWithLedgers and CheckWithLedger extend ReasonTestVariants in one unit", func(t *testing.T) {
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
		single, err := f.binding.CheckWithLedger(t.Context(), a, f.old[a], &f.ledger)
		if err != nil || single.Verdict.Status != Valid || single.Extension == nil {
			t.Fatalf("CheckWithLedger with prior ledger: %+v %v", single, err)
		}
		withoutLedger, err := f.binding.CheckWithLedger(t.Context(), a, f.old[a], nil)
		if err != nil || withoutLedger.Verdict.Status != Stale || withoutLedger.Verdict.Reason != ReasonTestVariants || withoutLedger.Extension != nil {
			t.Fatalf("CheckWithLedger without prior ledger: %+v %v", withoutLedger, err)
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
		if mixed[1].Verdict.Status != Stale || mixed[1].Verdict.Reason != ReasonTestVariants || mixed[1].Extension != nil {
			t.Fatalf("mixed candidate 1 should remain Stale/ReasonTestVariants: %+v", mixed[1])
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
			want := ErrUnitAborted
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
			if got, err := u.Close(t.Context()); !errors.Is(err, ErrUnitClosed) || got != nil {
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
			rows []ProvisionalCheck
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
			if !errors.Is(err, ErrUnitClosed) {
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
		if rows, err := u.Close(t.Context()); !errors.Is(err, ErrUnitClosed) || rows != nil {
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
		if _, err := u.CheckBatch(t.Context(), nil); !errors.Is(err, ErrUnitClosed) {
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
