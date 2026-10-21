package gofresh

import (
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
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: gotool.SetEnv(os.Environ(), "SELECTION_INPUT", "original"), Inputs: []string{}}, SessionPolicy{Execution: PackageExecution, PureSubjects: []Subject{external}, Runner: runner})
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
	bound, err := snapshot.BindArtifact(t.Context(), pkg, ArtifactDescription{Identity: "retained", Path: binary})
	if err != nil {
		t.Fatal(err)
	}
	start := func(t *testing.T, subjects []Subject, capture, singleton bool) *producingUnit {
		t.Helper()
		var u *producingUnit
		if singleton {
			unit, err := runtime.Begin(subjects[0])
			if err != nil {
				t.Fatal(err)
			}
			u = unit.producing
		} else {
			unit, err := runtime.BeginPackage(subjects)
			if err != nil {
				t.Fatal(err)
			}
			u = unit.producing
		}
		t.Cleanup(u.abort)
		process := ProcessDescription{Identity: t.Name()}
		if capture {
			process.Capture = filepath.Join(t.TempDir(), "capture")
		}
		c, err := u.register(t.Context(), bound, process)
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
		cmd, err := runner.Program(t.Context(), c.Directory(), c.Environment(), binary, args...)
		if err != nil {
			t.Fatal(err)
		}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("execution: %v\n%s", err, output)
		}
		if err := u.submit(c, Terminal{Kind: NormalCompletion}); err != nil {
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
			result, err := u.close(t.Context())
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
			if _, err := u.close(t.Context()); !errors.Is(err, ErrUnitClosed) {
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
		if _, err := second.close(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(first.view.capturedObserved) != 0 || len(first.execution.observed) != 0 {
			t.Fatal("sibling selected observation obligations on a shared snapshot")
		}
		fp := first.execution.fingerprints[plain]
		fp.PurityAssertion = "caller assertion"
		first.execution.fingerprints[plain] = fp
		result, err := first.close(t.Context())
		if err == nil || !reflect.DeepEqual(result, FinalizedProcess{}) {
			t.Fatalf("capture-free corruption escaped: %+v %v", result, err)
		}
		retry := start(t, []Subject{plain}, false, true)
		result, err = retry.close(t.Context())
		if err != nil || result.Subjects[0].Verdict.Status != Valid || result.Subjects[0].Fingerprint.ObservationAssertion != "" {
			t.Fatalf("retry borrowed failed obligations: %+v %v", result, err)
		}
	})
}
