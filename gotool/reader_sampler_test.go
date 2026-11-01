//go:build unix

package gotool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

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
// own, and a malformed environment is refused — the holder's
// discipline (an answer taken once, a failure sticky, a cancellation
// never stored, concurrent asks waiting) being each holder's own, which
// the Sampler and the pass reader pin (REQ-fresh-toolchain-skew).
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

// A failed sample is memoized like an answered one: two asks of one
// refused (coordinate, environment) spawn once and answer the same
// refusal — the toolchain does not change between two asks in one
// lifetime (REQ-fresh-toolchain-skew).
func TestSamplerMemoizesAFailedSample(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "count")
	env := shimGo(t, "echo x >> "+counter+"\necho 'go: cannot find main module' >&2\nexit 1\n")
	s := &Sampler{}
	ctx := context.Background()
	dir := t.TempDir()
	_, first := s.Sample(ctx, dir, env)
	_, second := s.Sample(ctx, dir, env)
	if first == nil || second == nil || first.Error() != second.Error() {
		t.Fatalf("a refused sample was not memoized: %v then %v", first, second)
	}
	if !strings.Contains(first.Error(), "cannot find main module") {
		t.Fatalf("the refusal lost go's own words: %v", first)
	}
	data, _ := os.ReadFile(counter)
	if n := strings.Count(string(data), "x"); n != 1 {
		t.Fatalf("%d spawns for one refused coordinate, want 1", n)
	}
}

// Concurrent asks on one key wait on the first's spawn: eight asks of
// one coordinate under one environment run the shim once, every ask
// answered with that one sample (REQ-fresh-toolchain-skew).
func TestSamplerSerializesConcurrentAsksOnOneKey(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "count")
	env := shimGo(t, "echo x >> "+counter+"\nsleep 0.3\necho go1.99.0\n")
	s := &Sampler{}
	dir := t.TempDir()
	const asks = 8
	answers := make(chan string, asks)
	var wg sync.WaitGroup
	for i := 0; i < asks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := s.Sample(context.Background(), dir, env)
			if err != nil {
				t.Errorf("concurrent sample: %v", err)
			}
			answers <- v
		}()
	}
	wg.Wait()
	close(answers)
	for v := range answers {
		if v != "go1.99.0" {
			t.Fatalf("an ask answered %q", v)
		}
	}
	data, _ := os.ReadFile(counter)
	if n := strings.Count(string(data), "x"); n != 1 {
		t.Fatalf("%d spawns for %d concurrent asks on one key, want 1", n, asks)
	}
}

// A waiter on a key another ask is sampling leaves with its own
// cancellation when its context ends first — the first ask's spawn
// runs on and its answer is stored, so a later ask is served without
// a spawn (REQ-fresh-toolchain-skew).
func TestSamplerWaiterLeavesWithItsOwnCancellation(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "count")
	env := shimGo(t, "echo x >> "+counter+"\nsleep 2\necho go1.99.0\n")
	s := &Sampler{}
	dir := t.TempDir()
	first := make(chan error, 1)
	go func() {
		v, err := s.Sample(context.Background(), dir, env)
		if err == nil && v != "go1.99.0" {
			err = fmt.Errorf("first ask answered %q", v)
		}
		first <- err
	}()
	time.Sleep(200 * time.Millisecond)
	timed, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := s.Sample(timed, dir, env)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the waiter answered %v, want its own deadline", err)
	}
	if waited := time.Since(started); waited > time.Second {
		t.Fatalf("the waiter left after %s, want at its own deadline", waited)
	}
	if err := <-first; err != nil {
		t.Fatalf("the first ask: %v", err)
	}
	if v, err := s.Sample(context.Background(), dir, env); err != nil || v != "go1.99.0" {
		t.Fatalf("the later ask = %q, %v", v, err)
	}
	data, _ := os.ReadFile(counter)
	if n := strings.Count(string(data), "x"); n != 1 {
		t.Fatalf("%d spawns, want 1 (the first ask's; the waiter spawned nothing, the later ask was served)", n)
	}
}

// A take that panics — a consumer's hook, recovered by its caller —
// stores nothing and releases the holder: the next ask on the key
// takes again instead of waiting on a take that never ends
// (REQ-fresh-toolchain-skew).
func TestSamplerReleasesTheHolderAfterAPanickingTake(t *testing.T) {
	env := shimGo(t, "echo go1.99.0\n")
	first := true
	s := &Sampler{Runner: Runner{Prepare: func(*exec.Cmd) {
		if first {
			first = false
			panic("the hook's own fault")
		}
	}}}
	dir := t.TempDir()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the hook's panic did not reach the caller")
			}
		}()
		_, _ = s.Sample(context.Background(), dir, env)
	}()
	timed, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if v, err := s.Sample(timed, dir, env); err != nil || v != "go1.99.0" {
		t.Fatalf("the ask after a panicking take = %q, %v; want the sample taken afresh", v, err)
	}
}

// A cancelled ask leaves an unfilled holder, but its environment still belongs
// to its original key. Reusing the caller's slice for another request cannot
// change what a later live ask under that first key actually samples.
func TestSamplerOwnsEnvironmentAfterCancelledTake(t *testing.T) {
	env := append(shimGo(t, "printf '%s\\n' \"$SAMPLE_VERSION\"\n"), "SAMPLE_VERSION=go1.99.1")
	original := append([]string(nil), env...)
	s := &Sampler{}
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Sample(ctx, dir, env); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ask: %v", err)
	}
	env[len(env)-1] = "SAMPLE_VERSION=go1.99.2"
	if got, err := s.Sample(context.Background(), dir, original); err != nil || got != "go1.99.1" {
		t.Fatalf("original key sampled another environment: %q, %v", got, err)
	}
	if got, err := s.Sample(context.Background(), dir, env); err != nil || got != "go1.99.2" {
		t.Fatalf("distinct key did not sample its own environment: %q, %v", got, err)
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

// A snapshot sampler answers the toolchain from its reader's one
// snapshot — the GOVERSION `go env` reported, the same string the
// spawning sampler returns — and spawns nothing of its own; an ask for
// another directory or environment than the reader's pass is refused,
// and a reader whose snapshot failed answers that failure
// (REQ-fresh-toolchain-skew).
func TestSnapshotSamplerAnswersItsReadersPassWithoutASpawn(t *testing.T) {
	ctx := context.Background()
	spawns := 0
	runner := Runner{Prepare: func(*exec.Cmd) { spawns++ }}
	env := os.Environ()
	reader := NewEnvReader(runner, "", env)
	want, err := (&Sampler{Runner: Runner{}}).Sample(ctx, "", env)
	if err != nil {
		t.Fatal(err)
	}
	s := SnapshotSampler{Reader: reader}
	got, err := s.Sample(ctx, "", env)
	if err != nil || got != want {
		t.Fatalf("SnapshotSampler.Sample = %q, %v; want the spawning sampler's %q", got, err, want)
	}
	if spawns != 1 {
		t.Fatalf("%d spawns, want the reader's one snapshot", spawns)
	}
	if got, err := s.Sample(ctx, "", env); err != nil || got != want || spawns != 1 {
		t.Fatalf("a second ask answered %q, %v after %d spawns", got, err, spawns)
	}
	if _, err := s.Sample(ctx, t.TempDir(), env); !errors.Is(err, errSnapshotPass) {
		t.Fatalf("another directory answered: %v", err)
	}
	if _, err := s.Sample(ctx, "", SetEnv(env, "GOFRESH_SNAPSHOT_PROBE", "1")); !errors.Is(err, errSnapshotPass) {
		t.Fatalf("another environment answered: %v", err)
	}
	if _, err := (SnapshotSampler{}).Sample(ctx, "", env); err == nil {
		t.Fatal("no reader sampled")
	}
	// A reader whose snapshot failed answers that failure — the
	// environment well-formed, the go command refusing — never a
	// version; a snapshot naming no GOVERSION is no sample.
	refusing := shimGo(t, "echo 'go: boom' >&2\nexit 1\n")
	if got, err := (SnapshotSampler{Reader: NewEnvReader(Runner{}, "", refusing)}).Sample(ctx, "", refusing); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("a failed snapshot sampled %q, %v; want the snapshot's own refusal", got, err)
	}
	versionless := shimGo(t, "echo '{\"GOROOT\":\"/x\"}'\n")
	if got, err := (SnapshotSampler{Reader: NewEnvReader(Runner{}, "", versionless)}).Sample(ctx, "", versionless); err == nil || !strings.Contains(err.Error(), "no GOVERSION") {
		t.Fatalf("a snapshot without GOVERSION sampled %q, %v", got, err)
	}
}

// List spells `go list` ahead of its arguments and serves a clean
// listing; the wait-delay form (a holder on the pipe here) is refused
// with ErrListingRefused — never the served salvage's form, so Salvaged
// is false for it — where Run would have served it: a listing has no
// wholeness test (REQ-fresh-go-command-policy).
func TestListRefusesTheSalvagedAnswer(t *testing.T) {
	env := shimGo(t, "echo \"$@\"\nexit 0\n")
	r := Runner{Containment: &Containment{WaitDelay: 200 * time.Millisecond}}
	out, err := r.List(context.Background(), "", env, "-deps", "example.com/p")
	if err != nil || strings.TrimSpace(string(out)) != "list -deps example.com/p" {
		t.Fatalf("clean listing: out %q err %v", out, err)
	}

	env = shimGo(t, "echo example.com/p\nsleep 2 &\nexit 0\n")
	out, err = r.List(context.Background(), "", env, "-deps", "example.com/p")
	if !errors.Is(err, ErrListingRefused) || out != nil {
		t.Fatalf("held listing: out %q err %v, want no output and ErrListingRefused", out, err)
	}
	// The refusal is its own form — never the served salvage's: the
	// guard every structured reader applies is false for it.
	if errors.Is(err, exec.ErrWaitDelay) || Salvaged(context.Background(), err) {
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
