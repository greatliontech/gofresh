//go:build unix

package gotool

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
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

// testEnv is the ambient environment with the named keys replaced —
// the policy refuses a duplicate, so a test never appends blindly.
func testEnv(t *testing.T, pins ...string) []string {
	t.Helper()
	env := make([]string, 0, len(os.Environ())+len(pins))
	for _, entry := range os.Environ() {
		keep := true
		key, _, _ := split(entry)
		for _, pin := range pins {
			if pinKey, _, _ := split(pin); EqualEnvKey(key, pinKey) {
				keep = false
			}
		}
		if keep {
			env = append(env, entry)
		}
	}
	return append(env, pins...)
}

func TestRunOK(t *testing.T) {
	out, err := (Runner{}).Run(context.Background(), "", os.Environ(), "env", "GOMODCACHE")
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		t.Error("empty GOMODCACHE")
	}
}

func TestRunError(t *testing.T) {
	if _, err := (Runner{}).Run(context.Background(), "", os.Environ(), "this-is-not-a-go-subcommand"); err == nil {
		t.Fatal("expected error")
	} else if !strings.Contains(err.Error(), "go this-is-not-a-go-subcommand") {
		t.Errorf("error not wrapped with command: %v", err)
	}
}

// A nil environment is refused: the child would inherit the ambient one,
// which no entry of the public packages may read.
//
//gofresh:pure
func TestRunRefusesANilEnvironment(t *testing.T) {
	if _, err := (Runner{}).Run(context.Background(), "", nil, "version"); err == nil {
		t.Fatal("a nil environment ran go under the ambient one")
	}
	if _, err := (Runner{}).TakeEnvSnapshot(context.Background(), "", nil); err == nil {
		t.Fatal("a nil environment snapshotted the ambient one")
	}
	if _, err := LoadPackages(context.Background(), packages.NeedName, "", nil, nil, "."); err == nil {
		t.Fatal("a nil environment loaded packages under the ambient one")
	}
	if _, err := LoadPackages(nil, packages.NeedName, "", []string{}, nil, "."); err == nil {
		t.Fatal("a nil context loaded packages")
	}
	if _, err := LoadPackages(context.Background(), packages.NeedName, "", []string{"GOPACKAGESDRIVER=custom"}, nil, "."); err == nil {
		t.Fatal("an external package driver was accepted")
	}
}

// The toolchain sample runs in the target module's directory under the
// caller's environment: the version it answers is the one the go
// command selects THERE (REQ-fresh-toolchain-skew).
func TestSampleGoVersionRunsInTheModuleDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/sample\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := testEnv(t, "GOTOOLCHAIN=local", "GOFLAGS=")
	var seen string
	r := Runner{Prepare: func(cmd *exec.Cmd) { seen = cmd.Dir }}
	got, err := r.SampleGoVersion(context.Background(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if seen != dir {
		t.Fatalf("the sample ran in %q, want the module directory %q", seen, dir)
	}
	if !strings.HasPrefix(got, "go") || strings.ContainsAny(got, " \n") {
		t.Fatalf("sample = %q, want one go version token", got)
	}
	// The reference is an independent spawn in the same directory under
	// the policy's environment for it: the sample is that answer, trimmed.
	ref := exec.Command("go", "env", "GOVERSION")
	refEnv, err := EnvForCommand(env, dir)
	if err != nil {
		t.Fatal(err)
	}
	ref.Dir, ref.Env = dir, refEnv
	want, err := ref.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.TrimSpace(string(want)) {
		t.Fatalf("sample = %q, want the directory's own answer %q", got, strings.TrimSpace(string(want)))
	}
}

// The runner's spawn policy sees the command before it starts, with
// its directory and the policy's environment already set: a hook that
// edits cmd.Env edits the environment the child runs under.
func TestRunnerPrepareSeesTheCommandBeforeItStarts(t *testing.T) {
	dir := t.TempDir()
	var prepared *exec.Cmd
	var preparedDir string
	var preparedEnv []string
	r := Runner{Prepare: func(cmd *exec.Cmd) {
		if cmd.Process != nil {
			t.Fatal("the hook saw a started command")
		}
		prepared, preparedDir, preparedEnv = cmd, cmd.Dir, slices.Clone(cmd.Env)
	}}
	if _, err := r.Run(context.Background(), dir, testEnv(t, "GOFLAGS="), "env", "GOOS"); err != nil {
		t.Fatal(err)
	}
	if prepared == nil || len(prepared.Args) < 2 || prepared.Args[1] != "env" {
		t.Fatalf("the hook did not see the go command: %v", prepared)
	}
	if preparedDir != dir {
		t.Fatalf("the hook saw Dir %q, want %q already set", preparedDir, dir)
	}
	if pwd, ok := LookupEnv(preparedEnv, "PWD"); !ok || pwd != dir {
		t.Fatalf("the hook saw PWD %q (present %v) in %d entries, want the policy's %q already set", pwd, ok, len(preparedEnv), dir)
	}
}

// The canonical directory follows symlinks and applies `..` after the
// link it followed: the raw spelling is never cleaned first, which
// would fold `via/..` onto the link's own parent.
func TestCanonicalDirWalksThroughALinkBeforeDotDot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	got, err := CanonicalDir(link)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("CanonicalDir(link) = %q, want the real directory %q", got, want)
	}
	// `link/..` walks THROUGH the link to the target's parent; a lexical
	// clean would fold it onto the link's own parent. The raw string is
	// built by concatenation — filepath.Join would clean it first.
	nested := filepath.Join(root, "elsewhere", "target")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	through := filepath.Join(root, "via")
	if err := os.Symlink(nested, through); err != nil {
		t.Fatal(err)
	}
	got, err = CanonicalDir(through + string(os.PathSeparator) + "..")
	if err != nil {
		t.Fatal(err)
	}
	wantParent, err := filepath.EvalSymlinks(filepath.Join(root, "elsewhere"))
	if err != nil {
		t.Fatal(err)
	}
	if got != wantParent {
		t.Fatalf("CanonicalDir(via/..) = %q, want the target's parent %q (a lexical clean answers %q)", got, wantParent, filepath.Clean(through+"/.."))
	}
	// The relative form walks the same way from the working directory.
	t.Chdir(root)
	if got, err := CanonicalDir("via" + string(os.PathSeparator) + ".."); err != nil || got != wantParent {
		t.Fatalf("relative CanonicalDir(via/..) = %q, %v; want %q", got, err, wantParent)
	}
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
	_, err = (Runner{}).Run(ctx, "", env, "list")
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

// The environment snapshot serves the answer a cleanly exited process
// wrote beside a descendant's pipe hold when it is a whole document; a
// torn document refuses with the hold named
// (REQ-fresh-go-command-policy).
func TestTakeEnvSnapshotServesTheSalvagedAnswer(t *testing.T) {
	env := shimGo(t, `echo '{"GOOS":"plan9","GOARCH":"amd64"}'`+"\nsleep 5 &\nexit 0\n")
	ctx := context.Background()
	r := Runner{Containment: &Containment{WaitDelay: 200 * time.Millisecond}}
	snapshot, err := r.TakeEnvSnapshot(ctx, "", env)
	if err != nil || snapshot.Value("GOOS") != "plan9" {
		t.Fatalf("snapshot = %v, %v; want the salvaged document", snapshot, err)
	}
	for _, torn := range []string{`printf '{"GOOS":'`, "echo null", "echo '{}'"} {
		env = shimGo(t, torn+"\nsleep 5 &\nexit 0\n")
		if _, err := r.TakeEnvSnapshot(ctx, "", env); !errors.Is(err, exec.ErrWaitDelay) {
			t.Fatalf("%s = %v, want the hold named", torn, err)
		}
	}
	// Without a hold the same non-documents refuse on their own terms.
	env = shimGo(t, "echo null\nexit 0\n")
	if _, err := r.TakeEnvSnapshot(ctx, "", env); err == nil || !strings.Contains(err.Error(), "no values") {
		t.Fatalf("null = %v, want no values", err)
	}
}

// Salvaged is the one guard the structured readers apply: the wait-delay
// form of a cleanly exited process under a live context; a context
// cancelled while the descendant held the pipe salvages nothing — a
// caller's cancellation is never answered, and never memoized
// (REQ-fresh-go-command-policy).
func TestSalvagedRefusesUnderACancelledContext(t *testing.T) {
	// The shim writes its own pid beside its answer; the context is
	// cancelled once the leader exited (held waitable on Linux, reaped
	// elsewhere), so the runner is inside its descendant's pipe hold —
	// never on the answer alone, which the shell writes before it
	// forks the holder and exits: a cancellation landing in that gap
	// sweeps a live leader and answers nothing, a different case from
	// the one this test pins, and one a loaded machine reaches.
	answered := filepath.Join(t.TempDir(), "answered")
	t.Setenv("GOFRESH_TEST_ANSWERED", answered)
	env := shimGo(t, "echo go1.99.0\necho $$ > \"$GOFRESH_TEST_ANSWERED\"\nsleep 5 &\nexit 0\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Both waits end with the test or at a deadline, never spinning
	// past it: a pid reused between the reap and a poll would answer
	// forever, and the run's own bound then names the miss.
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		deadline := time.After(20 * time.Second)
		wait := func(ready func() bool) bool {
			for !ready() {
				select {
				case <-done:
					return false
				case <-deadline:
					return false
				default:
					time.Sleep(5 * time.Millisecond)
				}
			}
			return true
		}
		pid := 0
		if !wait(func() bool {
			if b, err := os.ReadFile(answered); err == nil {
				pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			}
			return pid != 0
		}) {
			return
		}
		if !wait(func() bool {
			if runtime.GOOS == "linux" {
				data, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
				_, state, _ := strings.Cut(string(data), ") ")
				return strings.HasPrefix(state, "Z ")
			}
			return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
		}) {
			return
		}
		cancel()
	}()
	r := Runner{Containment: &Containment{WaitDelay: 3 * time.Second}}
	out, err := r.Run(ctx, "", env, "env", "GOVERSION")
	if ctx.Err() == nil {
		t.Fatal("the leader was never seen exited, so the cancellation never landed during the hold")
	}
	if runtime.GOOS == "linux" {
		if !errors.Is(err, context.Canceled) || len(out) != 0 {
			t.Fatalf("contained cancellation = %q, %v; want no answer", out, err)
		}
	} else if !errors.Is(err, exec.ErrWaitDelay) || strings.TrimSpace(string(out)) != "go1.99.0" {
		t.Fatalf("run = %q, %v; want the answer beside the wait-delay form", out, err)
	}
	if Salvaged(ctx, err) {
		t.Fatal("a cancelled context salvaged the answer")
	}
	if Salvaged(context.Background(), exec.ErrWaitDelay) != true {
		t.Fatal("a live context did not salvage the wait-delay form")
	}
	if _, err := r.SampleGoVersion(ctx, "", env); err == nil {
		t.Fatal("the sample served under a cancelled context")
	}
}

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
