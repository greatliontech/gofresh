//go:build unix

package gotool

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// shimGo installs a `go` script first on PATH for the test's process
// (exec resolves the binary through the process PATH, not the child's
// environment) and returns the environment the child runs under.
func shimGo(t *testing.T, script string) []string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go"), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return os.Environ()
}

func groupAlive(pid int) bool {
	err := syscall.Kill(-pid, 0)
	return !errors.Is(err, syscall.ESRCH)
}

// Contain: the child leads its own group and a cancellation sweeps it —
// the grandchild sleeping under the leader dies with it, and the
// command reports the cancellation rather than hanging on the pipe the
// grandchild held; an already-reaped leader answers process-done.
func TestContainSweepsTheGroupOnCancellation(t *testing.T) {
	env := shimGo(t, "sleep 30 &\necho started\nwait\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd, err := Runner{Containment: &Containment{WaitDelay: 500 * time.Millisecond}}.Command(ctx, "", env, "version")
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := stdout.Read(buf); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if !groupAlive(pid) {
		t.Fatal("the child does not lead a live group")
	}
	cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled command returned nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled command hung: the grandchild's pipe was never swept")
	}
	deadline := time.Now().Add(2 * time.Second)
	for groupAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if groupAlive(pid) {
		t.Fatal("the group outlived the cancellation")
	}
	// A leader already gone: the cancel answers process-done.
	if err := cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("cancel over an empty group = %v, want process-done", err)
	}
}

// Quit: with the cause admitted, the group is asked to quit first and
// the leader that handles it exits on its own before the grace.
func TestContainQuitsBeforeKillingOnTheNamedCause(t *testing.T) {
	// The leader's quit handler takes its own child with it, so the
	// group empties and the cancel returns on that, inside the grace.
	env := shimGo(t, "sleep 30 &\nchild=$!\ntrap 'kill $child; exit 3' QUIT\necho started\nwait\n")
	cause := errors.New("envelope expired")
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	c := Containment{WaitDelay: time.Second, Grace: 3 * time.Second, Quit: func(err error) bool { return errors.Is(err, cause) }}
	cmd, err := Runner{Containment: &c}.Command(ctx, "", env, "version")
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if _, err := stdout.Read(buf); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	cancel(cause)
	err = cmd.Wait()
	if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 3 {
		t.Fatalf("the leader did not exit on the quit: err=%v state=%v", err, cmd.ProcessState)
	}
	// The leader's own exit ends the wait well inside the grace: the
	// cancel returns on the empty group, never after the full grace.
	if took := time.Since(started); took > c.Grace/2 {
		t.Fatalf("the cancel waited %v for a leader that exited at once (grace %v)", took, c.Grace)
	}
}

// A leader that ignores the quit is killed with its group after the
// grace — the load-bearing half of the rule: the group never leaks
// behind a cancel that returned.
func TestContainKillsTheGroupAfterTheGrace(t *testing.T) {
	env := shimGo(t, "trap '' QUIT\necho started\nsleep 30 & wait\n")
	cause := errors.New("envelope expired")
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	c := Containment{WaitDelay: time.Second, Grace: 300 * time.Millisecond, Quit: func(err error) bool { return errors.Is(err, cause) }}
	cmd, err := Runner{Containment: &c}.Command(ctx, "", env, "version")
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if _, err := stdout.Read(buf); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cancel(cause)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled command hung past the grace and the wait delay")
	}
	if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != -1 {
		t.Fatalf("the leader was not killed after the grace: %v", cmd.ProcessState)
	}
	deadline := time.Now().Add(2 * time.Second)
	for groupAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if groupAlive(pid) {
		t.Fatal("the group outlived the grace kill")
	}
}

// A containment naming no delay bounds the reap by the default, never
// leaving it unbounded; and a failed command's refusal carries a
// bounded stderr.
func TestContainmentDefaultsTheDelayAndRunBoundsTheRefusal(t *testing.T) {
	env := shimGo(t, "echo started\nsleep 30 &\nexit 0\n")
	ctx := context.Background()
	cmd, err := Runner{Containment: &Containment{}}.Command(ctx, "", env, "version")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.WaitDelay != time.Second || DefaultWaitDelay != time.Second {
		t.Fatalf("WaitDelay = %v, want the one-second default", cmd.WaitDelay)
	}
	// A quit with no grace named is the default grace, never a kill on
	// the quit's heels.
	if got := (Containment{Quit: func(error) bool { return true }}).grace(); got != 10*time.Second || DefaultGrace != 10*time.Second {
		t.Fatalf("grace = %v, want the ten-second default", got)
	}
	if got := (Containment{Grace: 300 * time.Millisecond}).grace(); got != 300*time.Millisecond {
		t.Fatalf("a named grace = %v", got)
	}
	started := time.Now()
	if _, err := (Runner{Containment: &Containment{}}).Run(ctx, "", env, "version"); !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("run over a held pipe = %v, want ErrWaitDelay after the default delay", err)
	}
	if took := time.Since(started); took > 5*time.Second {
		t.Fatalf("the reap waited %v: the delay was not bounded", took)
	}
	env = shimGo(t, "head -c 200000 /dev/zero | tr '\\0' 'e' >&2\nexit 1\n")
	_, err = Runner{}.Run(ctx, "", env, "list")
	if err == nil || len(err.Error()) > stderrBound+256 || !strings.Contains(err.Error(), "bytes elided") {
		t.Fatalf("refusal is unbounded or unmarked: len %d", len(err.Error()))
	}
}

// Run keeps the answer a wait-delay expiry leaves: the process exited
// cleanly with its answer written while a descendant held stdout past
// the delay — the output returns beside exec.ErrWaitDelay, and the
// sampler takes the first line as the version.
func TestRunSalvagesTheAnswerAWaitDelayLeaves(t *testing.T) {
	env := shimGo(t, "echo go1.99.0\nsleep 5 &\nexit 0\n")
	ctx := context.Background()
	r := Runner{Containment: &Containment{WaitDelay: 200 * time.Millisecond}}
	out, err := r.Run(ctx, "", env, "env", "GOVERSION")
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("err = %v, want ErrWaitDelay beside the answer", err)
	}
	if strings.TrimSpace(string(out)) != "go1.99.0" {
		t.Fatalf("output beside the error = %q", out)
	}
	version, err := r.SampleGoVersion(ctx, "", env)
	if err != nil || version != "go1.99.0" {
		t.Fatalf("sample = %q, %v; want the salvaged answer", version, err)
	}
	// A process that exited non-zero salvages nothing.
	env = shimGo(t, "echo go1.99.0\nsleep 5 &\nexit 2\n")
	if out, err := r.Run(ctx, "", env, "env", "GOVERSION"); err == nil || len(out) != 0 {
		t.Fatalf("a failed process salvaged output: %q, %v", out, err)
	}
}

// Sampler memoizes by the directory's coordinate and the environment —
// two spellings of one directory pay one sample — and never memoizes
// a cancelled sample.
func TestSamplerMemoizesByCoordinateAndNeverACancellation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Three spellings of one coordinate: the directory, an uncleaned
	// `x/..` spelling (never through filepath.Join, which cleans), and a
	// symlink to it — one sample.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	spellings := []string{dir, dir + "/x/..", link, dir}
	counter := filepath.Join(t.TempDir(), "count")
	env := shimGo(t, "echo x >> "+counter+"\necho go1.99.0\n")
	s := &Sampler{}
	ctx := context.Background()
	for _, d := range spellings {
		v, err := s.Sample(ctx, d, env)
		if err != nil || v != "go1.99.0" {
			t.Fatalf("sample %s = %q, %v", d, v, err)
		}
	}
	// Two orderings of one environment are one key.
	reversed := append([]string(nil), env...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	if _, err := s.Sample(ctx, dir, reversed); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(counter)
	if n := strings.Count(string(data), "x"); n != 1 {
		t.Fatalf("%d samples for one coordinate, want 1", n)
	}
	// A sample cancelled MID-FLIGHT is no sample: the memo holds
	// nothing for that key, and the next live sample runs the shim.
	slow := shimGo(t, "echo x >> "+counter+"\nsleep 2\necho go1.99.0\n")
	timed, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if _, err := s.Sample(timed, filepath.Join(dir, "x"), slow); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled sample = %v", err)
	}
	if _, err := s.Sample(ctx, filepath.Join(dir, "x"), slow); err != nil {
		t.Fatalf("after a cancellation the live sample is taken: %v", err)
	}
	data, _ = os.ReadFile(counter)
	if n := strings.Count(string(data), "x"); n != 3 {
		t.Fatalf("%d shim runs, want 3 (one memoized coordinate, the cancelled sample, the live one after it)", n)
	}
}

// EnvReader takes the pass's one snapshot on its first key and serves
// every later key from it.
func TestEnvReaderTakesOneSnapshot(t *testing.T) {
	spawns := 0
	r := &EnvReader{Runner: Runner{Prepare: func(*exec.Cmd) { spawns++ }}, Dir: "", Env: os.Environ()}
	ctx := context.Background()
	for _, key := range []string{"GOMODCACHE", "GOFLAGS", "GOEXPERIMENT", "GOROOT"} {
		if _, err := r.Value(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	if spawns != 1 {
		t.Fatalf("%d spawns for four keys, want 1", spawns)
	}
	root, _ := r.Value(ctx, "GOROOT")
	if root == "" {
		t.Fatal("GOROOT empty from the snapshot")
	}
	_ = strconv.Itoa
}
