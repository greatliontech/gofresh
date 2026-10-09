package gofresh

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/runtimeinput"
)

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
func supportedObservation(t *testing.T, view *View, root, dir, process, log string) runtimeinput.Observation {
	t.Helper()
	frame := runtimeinput.CaptureProducerFrame(context.Background(), root, dir, runtimeinput.FrameOptions{})
	support, err := view.PrepareOutcomeSupport(context.Background(), frame, process)
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.EnvForCommand(view.engine.evidenceEnv(), dir)
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
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	before, err := engine.NewView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	old, err := before.CaptureObserved(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	observation := supportedObservation(t, before, dir, dir, "old execution", "getenv OUTCOME_VALUE\n")
	newBody := "package observed\nimport (\"os\"; \"testing\")\nfunc TestRead(*testing.T) { _, _ = os.ReadFile(\"fixture\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "observed_test.go"), []byte(newBody), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := engine.NewView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := after.CaptureObserved(ctx, subject)
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
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	frame := runtimeinput.CaptureProducerFrame(ctx, dir, dir, runtimeinput.FrameOptions{})
	view, err := engine.NewView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&View{}).PrepareOutcomeSupport(ctx, frame, "worker"); err == nil || !strings.Contains(err.Error(), "contributing subjects") {
		t.Fatalf("empty preparation: %v", err)
	}
	bad := frame
	bad.PkgDir = "bad\x00directory"
	if _, err := view.PrepareOutcomeSupport(ctx, bad, "worker"); err == nil {
		t.Fatal("invalid environment coordinate accepted")
	}
	if _, err := view.PrepareOutcomeSupport(ctx, frame, ""); err == nil {
		t.Fatal("invalid process identity accepted")
	}
	for _, cancelInstead := range []bool{false, true} {
		view, err := engine.NewView(ctx, []Subject{subject}, dir)
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
		support, err := view.PrepareOutcomeSupport(callCtx, frame, "worker")
		cancel()
		want := ErrViewSealed
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
	engine, err := New(WithDir(dir), WithEnv(env...))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		symbol    string
		supported bool
		exit      int
	}{
		{"TestEnv", true, 0}, {"TestFail", true, 1}, {"TestFile", false, 0},
	} {
		t.Run(tc.symbol, func(t *testing.T) {
			subject := Subject{Package: "example.com/outcomes", Symbol: tc.symbol}
			view, err := engine.NewView(ctx, []Subject{subject}, dir)
			if err != nil {
				t.Fatal(err)
			}
			frame := runtimeinput.CaptureProducerFrame(ctx, dir, dir, runtimeinput.FrameOptions{})
			support, err := view.PrepareOutcomeSupport(ctx, frame, "execution")
			if err != nil {
				t.Fatal(err)
			}
			fp, err := view.CaptureObserved(ctx, subject)
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
			supportCheck := ValidateRecordedObservationSupport(stored, subject)
			if (supportCheck.Status == RecordedSupportNative) != tc.supported {
				t.Fatalf("native producer record support = %+v; supported=%t", supportCheck, tc.supported)
			}
			current, err := engine.NewView(ctx, []Subject{subject}, dir)
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
				fresh.ObservationProof.Evidence = observationProofEvidence(fresh.MaximalClosure, fresh.ObservationAssertion, fresh.ObservationProof)
				if !compatibleObservationProof(fresh.ObservationProof, fresh.ObservationAssertion, subject, fresh.MaximalClosure) {
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
			otherView, err := engine.NewView(ctx, []Subject{other}, dir)
			if err != nil {
				t.Fatal(err)
			}
			otherFP, err := otherView.CaptureObserved(ctx, other)
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
			movedEngine, err := New(WithDir(dir), WithEnv(movedEnv...))
			if err != nil {
				t.Fatal(err)
			}
			moved, err := movedEngine.NewView(ctx, []Subject{subject}, dir)
			if err != nil {
				t.Fatal(err)
			}
			stale, err := moved.CheckObserved(ctx, stored, subject)
			if err != nil || stale.Status != Stale {
				t.Fatalf("moved environment=%+v %v", stale, err)
			}
		})
	}
	// A process set containing an unsupported member cannot borrow support
	// from an independently eligible member.
	set := []Subject{{Package: "example.com/outcomes", Symbol: "TestEnv"}, {Package: "example.com/outcomes", Symbol: "TestFile"}}
	view, err := engine.NewView(ctx, set, dir)
	if err != nil {
		t.Fatal(err)
	}
	frame := runtimeinput.CaptureProducerFrame(ctx, dir, dir, runtimeinput.FrameOptions{})
	support, err := view.PrepareOutcomeSupport(ctx, frame, "mixed")
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
	if _, err := view.PrepareOutcomeSupport(cancelled, frame, "cancelled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled support=%v", err)
	}
}
