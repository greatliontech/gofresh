package gofresh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/runtimeinput"
)

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
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: env, Inputs: []string{}}, SessionPolicy{Execution: PackageExecution, PureSubjects: []Subject{pureFile}, Runner: runner})
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
	start := func(t *testing.T, selected []Subject, exit int, terminal Terminal) (*PackageUnit, Contribution) {
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
		cmd, err := runner.Program(t.Context(), process.Directory(), process.Environment(), binary,
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
	var completed FinalizedProcess
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
			if err == nil || !reflect.DeepEqual(result, FinalizedProcess{}) {
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
			if _, err := u.Close(t.Context()); !errors.Is(err, ErrUnitClosed) {
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
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, FinalizedProcess{}) {
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
		if !errors.Is(err, ErrViewChanged) || !reflect.DeepEqual(result, FinalizedProcess{}) {
			t.Fatalf("drift exposed a subject prefix: %+v %v", result, err)
		}
	})
}

func TestPackageUnitRefusesIncompatibleScope(t *testing.T) {
	// Membership and package checks are decidable before analysis. These facts
	// deliberately supply no analyzer: an accidental preparation would panic.
	a := Subject{Package: "example.com/a", Symbol: "TestA"}
	b := Subject{Package: a.Package, Symbol: "TestB"}
	c := Subject{Package: "example.com/c", Symbol: "TestC"}
	engine := &Engine{executionModel: ExecutionAssertions{SingleSubject: true}}
	view := &View{engine: engine, subjects: []Subject{a, b, c}, packages: []string{a.Package, c.Package}, facts: &observationFacts{}}
	snapshot := &Snapshot{session: &Session{engine: engine}, view: view}
	execution := &RuntimeBinding{snapshot: snapshot}
	for _, selected := range [][]Subject{nil, {a, b}, {a, c}, {a, {Package: a.Package, Symbol: "unknown"}}} {
		if u, err := execution.BeginPackage(selected); err == nil || u != nil {
			t.Fatalf("invalid executed scope admitted: %v", selected)
		}
	}
	u, err := execution.BeginPackage([]Subject{a, a})
	if err != nil || !slices.Equal(u.producing.view.subjects, []Subject{a}) {
		t.Fatalf("singleton package scope refused: %v", err)
	}
	engine.executionModel.SingleSubject = false
	u, err = execution.BeginPackage([]Subject{b, a, b})
	if err != nil || !slices.Equal(u.producing.view.subjects, []Subject{b, a}) {
		t.Fatalf("package scope or order lost: %v", err)
	}
	if _, err := execution.BeginPackage([]Subject{a, c}); err == nil {
		t.Fatal("cross-package process admitted without the singleton assertion")
	}
	u.Abort()
}
