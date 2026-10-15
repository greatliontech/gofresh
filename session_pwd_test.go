package gofresh

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/runtimeinput"
)

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
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	policy := SessionPolicy{Runner: runner, Execution: SingleSubjectExecution}
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
		cmd, err := runner.Program(ctx, cwd, env, bin, "-test.run=^TestPWD$", "-test.v")
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
	cmd, err := runner.Program(ctx, c.Directory(), c.Environment(), bin, "-test.run=^$", "-test.bench=^BenchmarkPWD$", "-test.benchtime=1x", "-test.testlogfile="+c.Capture())
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
				checker, err := runner.Program(ctx, dir, checkerEnv, executable, "-test.run=^TestSessionCheckerProcess$", "-test.v")
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
