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
	"testing"
	"time"
)

func shimGo(t *testing.T, body string) []string {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return os.Environ()
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

// A reader never memoizes a cancellation: a snapshot refused by the
// caller's context is retried on the next live call, while any other
// failure is the reader's answer for its lifetime.
func TestEnvReaderNeverMemoizesACancellation(t *testing.T) {
	r := NewEnvReader(Runner{}, "", os.Environ())
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Snapshot(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled snapshot = %v", err)
	}
	if r.once.taken {
		t.Fatal("a cancelled snapshot was held")
	}
	snapshot, err := r.Snapshot(context.Background())
	if err != nil || snapshot == nil || snapshot.Value("GOROOT") == "" {
		t.Fatalf("the live snapshot after a cancellation: %v, %v", snapshot, err)
	}
	if again, err := r.Snapshot(context.Background()); err != nil || again != snapshot {
		t.Fatal("the live snapshot is not held")
	}
	failing := NewEnvReader(Runner{}, "", []string{"BAD"})
	if _, err := failing.Snapshot(context.Background()); err == nil {
		t.Fatal("a malformed environment took a snapshot")
	}
	if _, err := failing.Snapshot(context.Background()); err == nil {
		t.Fatal("a failed snapshot is not the reader's sticky answer")
	}
}

// A primed reader hands the construction snapshot on — no probe — and
// a nil snapshot primes nothing: the reader takes its own on first use
// rather than answering empty values for a snapshot never taken.
func TestPrimedEnvReaderPrimesOnlyARealSnapshot(t *testing.T) {
	ctx := context.Background()
	taken, err := (Runner{}).TakeEnvSnapshot(ctx, "", os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	spawns := 0
	counting := Runner{Prepare: func(*exec.Cmd) { spawns++ }}
	primed := PrimedEnvReader(counting, "", os.Environ(), taken)
	if got, err := primed.Value(ctx, "GOROOT"); err != nil || got != taken.Value("GOROOT") || spawns != 0 {
		t.Fatalf("primed reader probed (%d spawns) or answered %q, %v", spawns, got, err)
	}
	unprimed := PrimedEnvReader(counting, "", os.Environ(), nil)
	if got, err := unprimed.Value(ctx, "GOROOT"); err != nil || got == "" || spawns != 1 {
		t.Fatalf("nil-primed reader: %q, %v after %d spawns; want its own snapshot taken once", got, err, spawns)
	}
	if (*EnvSnapshot)(nil).Values() != nil {
		t.Fatal("nil EnvSnapshot.Values() returned non-nil map")
	}
	if _, err := EnvSnapshotFromValues(nil); err == nil {
		t.Fatal("nil map accepted by EnvSnapshotFromValues")
	}
	if _, err := EnvSnapshotFromValues(map[string]string{}); err == nil {
		t.Fatal("empty map accepted by EnvSnapshotFromValues")
	}
	inputMap := map[string]string{"GOVERSION": "go1.27.0"}
	fromMap, err := EnvSnapshotFromValues(inputMap)
	if err != nil {
		t.Fatal(err)
	}
	inputMap["GOVERSION"] = "mutated-caller"
	returnedMap := fromMap.Values()
	returnedMap["GOVERSION"] = "mutated-return"
	if got := fromMap.Value("GOVERSION"); got != "go1.27.0" {
		t.Fatalf("EnvSnapshot aliased caller or returned map: got %q, want go1.27.0", got)
	}
}

// The judged-run memo's key is the directory's coordinate and the
// normalized environment less PWD: two package directories never share
// an entry, one directory spelled uncleaned or through a symlink and one
// environment in two orders share theirs, any other setting moves it,
// PWD alone does not, and a malformed environment is refused.
func TestMemoKeyCoversTheCoordinateAndEnvironment(t *testing.T) {
	key := func(dir string, env []string) string {
		t.Helper()
		k, err := memoKey(dir, env)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	base := []string{"PATH=/bin", "HOME=/h", "PWD=" + dir}
	if key(dir, base) == key(filepath.Join(dir, "x"), base) {
		t.Fatal("two package directories share a key")
	}
	for _, spelling := range []string{dir + "/x/..", link} {
		if key(spelling, base) != key(dir, base) {
			t.Fatalf("%s spelled a second key for one directory", spelling)
		}
	}
	if key(dir, []string{"PWD=" + dir, "HOME=/h", "PATH=/bin"}) != key(dir, base) {
		t.Fatal("the environment's order moved the key")
	}
	if key(dir, base) != key(dir, []string{"PATH=/bin", "HOME=/h", "PWD=/other"}) {
		t.Fatal("PWD alone moved the key")
	}
	// With no directory named the command runs in the process's own,
	// which the go command reads through PWD: two spellings keep their
	// own keys.
	if key("", base) == key("", []string{"PATH=/bin", "HOME=/h", "PWD=/other"}) {
		t.Fatal("PWD was dropped from the key of the process's own directory")
	}
	for _, extra := range []string{"GOWORK=/w/go.work", "XDG_CONFIG_HOME=/c", "GOTOOLCHAIN=local", "ZZZ=1"} {
		if key(dir, base) == key(dir, append(append([]string(nil), base...), extra)) {
			t.Fatalf("%s did not move the key", extra)
		}
	}
	if _, err := memoKey(dir, []string{"A=1", "A=2"}); err == nil {
		t.Fatal("a duplicated key was admitted")
	}
}

// The memo files one holder per key for its lifetime, whatever the
// instance: two spellings of one directory and two orderings of one
// environment share a holder, another directory or setting gets its
// own, and a malformed environment is refused.
func TestRunMemoHoldsOneHolderPerKey(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	made := 0
	make := func() *int { made++; v := made; return &v }
	m := &RunMemo[*int]{}
	base := []string{"PATH=/bin", "HOME=/h", "PWD=" + dir}
	first, err := m.Get(dir, base, make)
	if err != nil {
		t.Fatal(err)
	}
	for _, ask := range []struct {
		dir string
		env []string
	}{{dir + "/x/..", base}, {link, base}, {dir, []string{"PWD=/other", "HOME=/h", "PATH=/bin"}}} {
		got, err := m.Get(ask.dir, ask.env, make)
		if err != nil || got != first {
			t.Fatalf("Get(%s, %v) = %v, %v; want the first holder", ask.dir, ask.env, got, err)
		}
	}
	if made != 1 {
		t.Fatalf("%d holders made for one key, want 1", made)
	}
	other, err := m.Get(dir, append(append([]string(nil), base...), "GOTOOLCHAIN=local"), make)
	if err != nil || other == first {
		t.Fatalf("another setting shared the holder (%v, %v)", other, err)
	}
	if _, err := m.Get(dir, []string{"A=1", "A=2"}, make); err == nil {
		t.Fatal("a malformed environment was keyed")
	}
}

func TestEnvReaderOwnsSuppliedEnvironment(t *testing.T) {
	env := append(shimGo(t, "printf '{\"GOVERSION\":\"%s\"}\\n' \"$SAMPLE_VERSION\"\n"), "SAMPLE_VERSION=go1.99.1")
	r := NewEnvReader(Runner{}, t.TempDir(), env)
	env[len(env)-1] = "SAMPLE_VERSION=go1.99.2"
	got, err := r.Value(context.Background(), "GOVERSION")
	if err != nil || got != "go1.99.1" {
		t.Fatalf("reader adopted caller mutation: %q, %v", got, err)
	}
}

func TestEnvReaderConcurrentWaitersAndPanicRecovery(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "count")
	env := shimGo(t, "echo x >> "+counter+"\nsleep 0.2\nprintf '{\"GOVERSION\":\"go1.99.0\"}\\n'\n")
	r := NewEnvReader(Runner{}, t.TempDir(), env)
	first := make(chan error, 1)
	go func() {
		_, err := r.Snapshot(context.Background())
		first <- err
	}()
	time.Sleep(50 * time.Millisecond)
	timed, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := r.Snapshot(timed); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter = %v, want DeadlineExceeded", err)
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if got, err := r.Value(context.Background(), "GOVERSION"); err != nil || got != "go1.99.0" {
		t.Fatalf("after waiter timeout = %q, %v", got, err)
	}

	firstPanic := true
	pr := NewEnvReader(Runner{Prepare: func(*exec.Cmd) {
		if firstPanic {
			firstPanic = false
			panic("hook fault")
		}
	}}, t.TempDir(), shimGo(t, "printf '{\"GOVERSION\":\"go1.99.0\"}\\n'\n"))
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic")
			}
		}()
		_, _ = pr.Snapshot(context.Background())
	}()
	if got, err := pr.Value(context.Background(), "GOVERSION"); err != nil || got != "go1.99.0" {
		t.Fatalf("after panic = %q, %v", got, err)
	}
}

// List spells `go list` ahead of its arguments and serves a clean
// listing; the wait-delay form (a holder on the pipe here) is refused
// with ErrListingRefused where Run would have served it: a listing has no
// wholeness test (REQ-fresh-go-command-policy).
func TestListRefusesTheSalvagedAnswer(t *testing.T) {
	env := shimGo(t, "echo \"$@\"\nexit 0\n")
	r := Runner{Prepare: func(c *exec.Cmd) { c.WaitDelay = 200 * time.Millisecond }}
	out, err := r.List(context.Background(), "", env, "-deps", "example.com/p")
	if err != nil || strings.TrimSpace(string(out)) != "list -deps example.com/p" {
		t.Fatalf("clean listing: out %q err %v", out, err)
	}

	env = shimGo(t, "echo example.com/p\nsleep 2 &\nexit 0\n")
	out, err = r.List(context.Background(), "", env, "-deps", "example.com/p")
	if !errors.Is(err, ErrListingRefused) || out != nil {
		t.Fatalf("held listing: out %q err %v, want no output and ErrListingRefused", out, err)
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("a refused listing reads as a served salvage: %v", err)
	}
	if !strings.Contains(err.Error(), "go list -deps example.com/p") || !strings.Contains(err.Error(), exec.ErrWaitDelay.Error()) {
		t.Fatalf("the refusal names neither the listing nor exec's error: %v", err)
	}
	// Run itself serves the same shape — the refusal is List's alone.
	if out, err := r.Run(context.Background(), "", env, "list", "-deps", "example.com/p"); !errors.Is(err, exec.ErrWaitDelay) || strings.TrimSpace(string(out)) != "example.com/p" {
		t.Fatalf("Run stopped serving the salvage: out %q err %v", out, err)
	}
}
