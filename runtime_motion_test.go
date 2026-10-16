package gofresh

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/runtimeinput"
)

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
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: env, Inputs: []string{}}, SessionPolicy{Execution: PackageExecution, PureSubjects: []Subject{reader, unknown, direntReader}, Runner: runner})
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
	dir, binary, reader, unknown, supported, binding, artifact, runner := f.dir, f.binary, f.reader, f.unknown, f.supported, f.binding, f.artifact, f.runner
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
			cmd, err := runner.Program(t.Context(), contribution.Directory(), contribution.Environment(), binary, "-test.v", "-test.run=^"+tc.subject.Symbol+"$", "-test.testlogfile="+contribution.Capture())
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
			if _, err := u.Close(t.Context()); !errors.Is(err, ErrUnitClosed) {
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
