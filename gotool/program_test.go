//go:build unix

package gotool

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Program prepares a consumer's own program under the go-command
// policy: the directory set, PWD derived from it, the duplicate-key and
// nil refusals in the program's name, the boundary applied before
// Prepare sees the command, the program resolved as os/exec resolves it
// (a bare name through the parent's PATH, a path against Dir), and the
// containment's group sweep — a shell that spawns a sleeper dies with
// its group on cancellation and the reap is bounded by the wait delay,
// exactly as Command does for go (REQ-fresh-go-command-policy).
func TestProgramPreparesAConsumerCommandUnderThePolicy(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "prog.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\npwd\necho \"$MARK\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var prepared *exec.Cmd
	boundaryBeforePrepare := false
	r := Runner{Containment: &Containment{WaitDelay: 500 * time.Millisecond}, Prepare: func(c *exec.Cmd) {
		prepared = c
		boundaryBeforePrepare = c.SysProcAttr != nil && c.SysProcAttr.Setpgid && c.WaitDelay == 500*time.Millisecond
	}}
	env := append(os.Environ(), "MARK=marked")
	cmd, err := r.Program(context.Background(), dir, env, script)
	if err != nil {
		t.Fatal(err)
	}
	if prepared != cmd {
		t.Fatal("Prepare did not see the prepared command")
	}
	if !boundaryBeforePrepare {
		t.Fatal("Prepare ran before the boundary was applied")
	}
	var pwd string
	for _, e := range cmd.Env {
		if v, ok := strings.CutPrefix(e, "PWD="); ok {
			pwd = v
		}
	}
	// t.TempDir is absolute and clean, so the derived PWD is the
	// directory itself.
	if pwd != dir || cmd.Dir != dir {
		t.Fatalf("PWD %q dir %q, want both %q", pwd, cmd.Dir, dir)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(string(out)), "\n"); len(lines) != 2 || lines[1] != "marked" {
		t.Fatalf("output = %q", out)
	}

	// The refusals are the policy's, spelled for the program, the name
	// judged first so an empty one is never spelled as the subject.
	var nilCtx context.Context
	for _, c := range []struct {
		name string
		call func() (*exec.Cmd, error)
		want string
	}{
		{"empty name", func() (*exec.Cmd, error) { return r.Program(context.Background(), dir, env, "") }, "gotool: empty program name"},
		{"empty name before the nil env", func() (*exec.Cmd, error) { return r.Program(context.Background(), dir, nil, "") }, "gotool: empty program name"},
		{"nil env", func() (*exec.Cmd, error) { return r.Program(context.Background(), dir, nil, script) }, script + ": nil environment"},
		{"nil ctx", func() (*exec.Cmd, error) { return r.Program(nilCtx, dir, env, script) }, script + ": nil context"},
		{"duplicate keys, spelled with the args", func() (*exec.Cmd, error) {
			return r.Program(context.Background(), dir, []string{"A=1", "A=2"}, script, "x")
		}, script + " x: environment: "},
	} {
		cmd, err := c.call()
		if err == nil || cmd != nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: err = %v, cmd = %v; want an error containing %q", c.name, err, cmd, c.want)
		}
	}

	// Resolution is os/exec's: a name carrying a path separator resolves
	// against Dir; a bare name through the parent's PATH — the derived
	// environment's PATH, which alone names the directory, governs the
	// child and never the lookup.
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "inner.sh"), []byte("#!/bin/sh\npwd\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd, err = r.Program(context.Background(), sub, env, "./inner.sh")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := cmd.Output(); err != nil || strings.TrimSpace(string(out)) != sub {
		t.Fatalf("a path resolved against Dir: out %q err %v, want %q", out, err, sub)
	}
	cmd, err = r.Program(context.Background(), sub, []string{"PATH=" + sub}, "inner.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cmd.Output(); err == nil || !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("a bare name resolved outside the parent's PATH: err = %v, want %v", err, exec.ErrNotFound)
	}

	// The sweep: the program's sleeper dies with the group on
	// cancellation, and the reap does not wait on its pipe.
	sleeper := filepath.Join(dir, "sleeper.sh")
	if err := os.WriteFile(sleeper, []byte("#!/bin/sh\nsleep 30 &\necho started\nwait\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd, err = r.Program(ctx, dir, env, sleeper)
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
	if _, err := stdout.Read(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if !groupAlive(pid) {
		t.Fatal("the group is not alive after start")
	}
	cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled program reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reap waited on the sleeper's pipe past the delay")
	}
	deadline := time.Now().Add(2 * time.Second)
	for groupAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if groupAlive(pid) {
		t.Fatal("the sleeper outlived the cancellation")
	}
}

// The quit arm reaches a consumer's program through Program exactly as
// it reaches go through Command: a cancellation on the named cause asks
// the group to quit first, and a leader that exits on the quit ends the
// wait well inside the grace.
func TestProgramQuitsTheConsumersGroupOnTheNamedCause(t *testing.T) {
	dir := t.TempDir()
	leader := filepath.Join(dir, "leader.sh")
	if err := os.WriteFile(leader, []byte("#!/bin/sh\nsleep 30 &\nchild=$!\ntrap 'kill $child; exit 3' QUIT\necho started\nwait\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("envelope expired")
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	c := Containment{WaitDelay: time.Second, Grace: 3 * time.Second, Quit: func(err error) bool { return errors.Is(err, cause) }}
	cmd, err := Runner{Containment: &c}.Program(ctx, dir, os.Environ(), leader)
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
	if _, err := stdout.Read(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	cancel(cause)
	err = cmd.Wait()
	if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 3 {
		t.Fatalf("the leader did not exit on the quit: err=%v state=%v", err, cmd.ProcessState)
	}
	if took := time.Since(started); took > c.Grace/2 {
		t.Fatalf("the cancel waited %v for a leader that exited at once (grace %v)", took, c.Grace)
	}
}
