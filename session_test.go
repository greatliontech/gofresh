package gofresh

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/gotool"
)

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
	runner := gotool.Runner{Containment: &gotool.Containment{}, Prepare: func(cmd *exec.Cmd) {
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
	policy := SessionPolicy{Execution: SingleSubjectExecution, Runner: runner}
	session, err := NewSession(ctx, configuration, RuntimeDescription{Environment: runtimeEnv}, policy)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/session", Symbol: "BenchmarkValue"}
	fileSubject := Subject{Package: subject.Package, Symbol: "BenchmarkFile"}
	snapshot, err := session.Snapshot(ctx, []Subject{subject, fileSubject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
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
	currentFacts, err := snapshot.CurrentFacts(ctx, subject)
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
	missing, err := snapshot.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missing.Close(ctx); !errors.Is(err, ErrUnitIncomplete) {
		t.Fatalf("empty unit closed: %v", err)
	}
	if _, err := missing.Register(ctx, bound, ProcessDescription{Identity: "late"}); !errors.Is(err, ErrUnitClosed) {
		t.Fatalf("failed unit reopened: %v", err)
	}
	control, err := runner.Program(ctx, dir, runtimeEnv, binary, "-test.run=^TestValue$", "-test.v")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := control.CombinedOutput(); err != nil || !strings.Contains(string(out), "selected=1") {
		t.Fatalf("actual artifact: %v\n%s", err, out)
	}
	unit, err := snapshot.Begin(subject)
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
	sibling, err := snapshot.Begin(subject)
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
	cmd, err := runner.Program(ctx, contribution.Directory(), contribution.Environment(), binary,
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
		if !errors.Is(err, ErrUnitClosed) {
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
	if _, err := unit.Close(ctx); !errors.Is(err, ErrUnitClosed) {
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
	checker, err := runner.Program(ctx, dir, checkerEnv, executable, "-test.run=^TestSessionCheckerProcess$", "-test.v")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := checker.CombinedOutput(); err != nil || !strings.Contains(string(out), "record valid in fresh process") {
		t.Fatalf("restart check: %v\n%s", err, out)
	}
	if err := unit.Submit(contribution, Terminal{Kind: NormalCompletion}); !errors.Is(err, ErrUnitClosed) {
		t.Fatalf("late submission: %v", err)
	}
	second, err := sibling.Register(ctx, bound, ProcessDescription{Identity: "independent-process", Capture: filepath.Join(t.TempDir(), "testlog")})
	if err != nil {
		t.Fatalf("sibling preparation after closing: %v", err)
	}
	secondCmd, err := runner.Program(ctx, second.Directory(), second.Environment(), binary, "-test.run=^$", "-test.bench=^BenchmarkValue$", "-test.benchtime=1x", "-test.count=1", "-test.testlogfile="+second.Capture())
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
	aborted, err := snapshot.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	abortProcess, err := aborted.Register(ctx, bound, ProcessDescription{Identity: "aborted-close", Capture: filepath.Join(t.TempDir(), "testlog")})
	if err != nil {
		t.Fatal(err)
	}
	abortCommand, err := runner.Program(ctx, abortProcess.Directory(), abortProcess.Environment(), binary, "-test.run=^$", "-test.bench=^BenchmarkValue$", "-test.benchtime=1x", "-test.count=1", "-test.testlogfile="+abortProcess.Capture())
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
		if !errors.Is(result.err, ErrUnitAborted) || result.value.Fingerprint.MaximalClosure != "" {
			t.Fatalf("aborted close returned final evidence: %+v %v", result.value.Verdict, result.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("aborted closing did not stop")
	}
	if _, err := os.Stat(abortGate.spawnMarker); !os.IsNotExist(err) {
		t.Fatalf("aborted closing started another query: %v", err)
	}
	diagnostic, err := snapshot.BeginIdentity(subject)
	if err != nil {
		t.Fatal(err)
	}
	diagnosticProcess, err := diagnostic.Register(ctx, bound, ProcessDescription{Identity: "profile-process", Capture: filepath.Join(t.TempDir(), "testlog")})
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "cpu.pprof")
	profileCommand, err := runner.Program(ctx, diagnosticProcess.Directory(), diagnosticProcess.Environment(), binary, "-test.run=^$", "-test.bench=^BenchmarkValue$", "-test.benchtime=1x", "-test.count=1", "-test.cpuprofile="+profile, "-test.testlogfile="+diagnosticProcess.Capture())
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
	fileUnit, err := snapshot.BeginIdentity(fileSubject)
	if err != nil {
		t.Fatal(err)
	}
	fileProcess, err := fileUnit.Register(ctx, bound, ProcessDescription{Identity: "identity-file", Capture: filepath.Join(t.TempDir(), "testlog")})
	if err != nil {
		t.Fatal(err)
	}
	fileCommand, err := runner.Program(ctx, fileProcess.Directory(), fileProcess.Environment(), binary, "-test.run=^$", "-test.bench=^BenchmarkFile$", "-test.benchtime=1x", "-test.count=1", "-test.testlogfile="+fileProcess.Capture())
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
	unstarted, err := snapshot.Begin(subject)
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
	abnormal, err := snapshot.Begin(subject)
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
	current, err := NewSession(ctx, configuration, RuntimeDescription{Environment: runtimeEnv}, policy)
	if err != nil {
		t.Fatal(err)
	}
	checking, err := current.Snapshot(ctx, []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := checking.Check(ctx, subject, final.Fingerprint)
	if err != nil || verdict.Status != Valid {
		t.Fatalf("later check: %+v %v", verdict, err)
	}
	compilerChange := configuration
	compilerChange.Environment = gotool.SetEnv(buildEnv, "FRESH_COMPILER_SETTING", "changed")
	compilerSession, err := NewSession(ctx, compilerChange, RuntimeDescription{Environment: runtimeEnv}, policy)
	if err != nil {
		t.Fatal(err)
	}
	compilerSnapshot, err := compilerSession.Snapshot(ctx, []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err = compilerSnapshot.Check(ctx, subject, final.Fingerprint)
	if err != nil || verdict.Status != Stale || verdict.Reason != "buildconfig" {
		t.Fatalf("unprojected compiler environment ignored: %+v %v", verdict, err)
	}
	changedRuntime := gotool.SetEnv(runtimeEnv, "FRESH_SESSION_VALUE", "changed")
	changed, err := NewSession(ctx, configuration, RuntimeDescription{Environment: changedRuntime}, policy)
	if err != nil {
		t.Fatal(err)
	}
	changedSnapshot, err := changed.Snapshot(ctx, []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err = changedSnapshot.Check(ctx, subject, final.Fingerprint)
	if err != nil || verdict.Status != Stale {
		t.Fatalf("changed runtime served: %+v %v", verdict, err)
	}
	configuration.Environment = gotool.SetEnv(buildEnv, "GOAMD64", "v2")
	write("feature.go", "//go:build amd64.v2\n\npackage session\nfunc Value() int { return 3 }\n")
	changedBuild, err := NewSession(ctx, configuration, RuntimeDescription{Environment: runtimeEnv}, policy)
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
	changedControl, err := runner.Program(ctx, dir, runtimeEnv, binaryV2, "-test.run=^TestValue$", "-test.v")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := changedControl.CombinedOutput(); err != nil || !strings.Contains(string(out), "selected=3") {
		t.Fatalf("changed actual artifact: %v\n%s", err, out)
	}
	wrongBuild, err := snapshot.Begin(subject)
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
	verdict, err = changedBuildSnapshot.Check(ctx, subject, final.Fingerprint)
	if err != nil || verdict.Status != Stale {
		t.Fatalf("changed producing build served: %+v %v", verdict, err)
	}
	pending, err := snapshot.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	prepared, resume := make(chan struct{}), make(chan struct{})
	resumePreparation := sync.OnceFunc(func() { close(resume) })
	defer resumePreparation()
	defer pending.Abort()
	pending.producing.view.beforeOutcomeIssue = func() { close(prepared); <-resume }
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
		if !errors.Is(err, ErrUnitClosed) {
			t.Fatalf("late preparation admitted: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("closed preparation did not return")
	}
	drifting, err := snapshot.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	driftProcess, err := drifting.Register(ctx, bound, ProcessDescription{Identity: "source-drift", Capture: filepath.Join(t.TempDir(), "testlog")})
	if err != nil {
		t.Fatal(err)
	}
	write("base.go", "//go:build !amd64.v2\n\npackage session\nfunc Value() int { return 9 }\n")
	driftCommand, err := runner.Program(ctx, driftProcess.Directory(), driftProcess.Environment(), binary, "-test.run=^$", "-test.bench=^BenchmarkValue$", "-test.benchtime=1x", "-test.count=1", "-test.testlogfile="+driftProcess.Capture())
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
	extensionSession, err := NewSession(ctx, build, RuntimeDescription{Environment: runtimeEnv}, policy)
	if err == nil {
		t.Fatal("package-filled execution description accepted as a session configuration")
	}
	configuration.Environment = buildEnv
	extensionSession, err = NewSession(ctx, configuration, RuntimeDescription{Environment: runtimeEnv}, policy)
	if err != nil {
		t.Fatal(err)
	}
	extensionSnapshot, err := extensionSession.Snapshot(ctx, []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	if verdict, err := extensionSnapshot.Check(ctx, subject, final.Fingerprint); err != nil || verdict.Status != Stale {
		t.Fatalf("ordinary checking silently extended applicability: %+v %v", verdict, err)
	}
	extended, paired, verdict, err := extensionSnapshot.CheckInertExtension(ctx, subject, final.Fingerprint, ledger)
	if err != nil || verdict.Status != Valid {
		t.Fatalf("licensed extension: %+v %v", verdict, err)
	}
	if extended.TestVariantClosure != final.Fingerprint.TestVariantClosure || extended.ObservationProof != final.Fingerprint.ObservationProof || extended.RuntimeInputs != final.Fingerprint.RuntimeInputs || len(paired.Declarations) <= len(ledger.Declarations) {
		t.Fatal("extension lost producing evidence or returned the wrong companion ledger")
	}
	// Price only the native provisional operation, independently of the public
	// wrapper's closing call. The next observation belongs to that closing call.
	preview, err := extensionSnapshot.view.Sibling([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	previewPasses := 0
	viewTestHooks.observe = func() { previewPasses++ }
	_, _, previewVerdict, previewErr := preview.CheckObservedInertTestVariantExtension(ctx, final.Fingerprint, ledger, subject)
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
	rejected, rejectedLedger, _, closingErr := extensionSnapshot.CheckInertExtension(ctx, subject, final.Fingerprint, ledger)
	viewTestHooks.observe = priorObserve
	if !errors.Is(closingErr, ErrViewChanged) || rejected.MaximalClosure != "" || len(rejectedLedger.Declarations) != 0 {
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
	session, err := NewSession(ctx, record.Build, record.Runtime, SessionPolicy{Execution: SingleSubjectExecution})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(ctx, []Subject{record.Subject}, record.Fingerprint.ResultKind)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := snapshot.Check(ctx, record.Subject, record.Fingerprint)
	want := record.Want
	if want == "" {
		want = Valid
	}
	if err != nil || verdict.Status != want {
		t.Fatalf("record check: %+v %v", verdict, err)
	}
	t.Logf("record %s in fresh process", want)
}
