// Package gotool is the fleet's go-command policy: it runs the go
// command line tool under one complete normalized environment (env.go),
// surfacing stderr on failure; prepares a command a consumer streams
// itself (Command; Program over the consumer's own program) under one
// process-boundary rule (Containment); samples the toolchain in the
// target module's directory, memoized (Sampler);
// reads go's environment once per pass (EnvReader); and resolves a
// directory to its one canonical coordinate (CanonicalDir, Coordinate).
// A Runner's containment and hook reach the go commands a consumer
// spawns through it and, installed on an engine (gofresh.WithGoRunner),
// every go command that engine spawns itself; the package loader's
// `go list` children carry the same environment (x/tools appends its
// own PWD, the same derivation) and spawn through x/tools, outside any
// hook.
package gotool

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Run executes `go <args>` in dir ("" = current directory) with env as
// its complete process environment and returns stdout. On failure the
// error includes the command and go's stderr. The directory matters: a
// go.mod `toolchain` directive / GOTOOLCHAIN is resolved relative to it,
// so provenance capture and `go test` must run in the same dir to
// describe the same toolchain.
func Run(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	return Runner{}.Run(ctx, dir, env, args...)
}

// Runner runs the go command line tool — and prepares a consumer's own
// program the same way (Program) — under a caller-owned spawn policy.
// Containment, when set, is the one process-boundary rule applied to
// every command the runner prepares, under that command's own context;
// Prepare, when set, sees the command after that, its Dir, Env, and
// boundary already set (a resource policy of the consumer's own). The
// zero Runner is the plain spawn. A runner reaches the go commands a
// consumer spawns through it and, installed on an engine, the engine's
// own.
type Runner struct {
	Containment *Containment
	Prepare     func(*exec.Cmd)
}

// Command prepares `go <args>` under the policy without starting it:
// Dir set, Env the complete derived environment, Prepare applied. A
// consumer that streams the child's output to its own sinks, or applies
// a resource policy of its own once the process exists, runs the
// returned command itself; Run is the collected form. It is Program
// over the go command.
func (r Runner) Command(ctx context.Context, dir string, env []string, args ...string) (*exec.Cmd, error) {
	return r.Program(ctx, dir, env, "go", args...)
}

// Program prepares the program name with args under the policy without
// starting it — the same policy Command applies to go: Dir set, Env the
// complete derived environment (PWD derived from Dir when one is
// given), the runner's containment when it carries one, Prepare last. It is the
// consumer-command form of the go-command policy
// (REQ-fresh-go-command-policy): a consumer's test binary, resolver
// child, or pinned measurement runs under the one boundary rule
// instead of a hand copy of it. The program resolves as os/exec
// resolves it — a bare name through the parent process's own PATH
// lookup, a name carrying a path separator against Dir; the derived
// environment governs the child, never the lookup. A consumer that
// sets SysProcAttr fields after construction merges into the one
// Program set: the boundary's process group lives there. There is no
// form of the boundary over a command prepared elsewhere — the sweep's
// context and the command's must be one, which only construction makes
// so: a separately passed context reads the wrong cause for Quit, a
// command built without a context refuses to start, and a started
// command is past containing.
func (r Runner) Program(ctx context.Context, dir string, env []string, name string, args ...string) (*exec.Cmd, error) {
	if name == "" {
		return nil, errors.New("gotool: empty program name")
	}
	if env == nil {
		// A nil environment would let the child inherit the ambient one;
		// the caller names the environment it runs under (an empty
		// non-nil slice is a deliberate empty environment).
		return nil, fmt.Errorf("%s: nil environment", name)
	}
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil context", name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	commandEnv, err := EnvForCommand(env, dir)
	if err != nil {
		return nil, fmt.Errorf("%s: environment: %w", strings.Join(append([]string{name}, args...), " "), err)
	}
	cmd.Env = commandEnv
	if r.Containment != nil {
		contain(ctx, cmd, *r.Containment)
	}
	if r.Prepare != nil {
		r.Prepare(cmd)
	}
	return cmd, nil
}

// Run is the collected form under the runner's spawn policy: it owns
// the command's streams (a Prepare hook's own are replaced). When the
// process itself exited cleanly but a descendant held its output pipe
// past the command's WaitDelay, the output read so far is returned
// BESIDE exec.ErrWaitDelay — the consumer decides whether that answer
// serves (a toolchain sample does: a wrapper's housekeeping child is not
// a failed sample) — never discarded behind the error. A failed
// command's refusal carries go's stderr bounded to its head and tail,
// so a refusal text a consumer keys a record on never grows with a
// tree's diagnostics.
func (r Runner) Run(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	cmd, err := r.Command(ctx, dir, env, args...)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if err != nil {
		if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
			return stdout.Bytes(), fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
		}
		if _, ok := errors.AsType[*exec.ExitError](err); ok {
			return nil, fmt.Errorf("go %s: %w: %s",
				strings.Join(args, " "), err, boundedText(stderr.Bytes()))
		}
		return nil, fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return stdout.Bytes(), nil
}

// ErrListingRefused is List's refusal of the wait-delay form: the
// listing's output was not drained within the wait delay, and a listing
// has no wholeness test. It is its own sentinel, never exec.ErrWaitDelay,
// so Salvaged is false for a refused listing and no reader serves it.
var ErrListingRefused = errors.New("the listing was not drained within the wait delay (a descendant's hold or a stalled copier); a listing has no wholeness test and is refused")

// List runs `go list <args>` under the policy and returns its stdout,
// refusing the wait-delay form Run would serve. At the delay's expiry
// exec closes the parent's read end and drops whatever the copier had
// not yet read — unobserved in practice, since the copier drains a
// pipe as fast as the process fills it, but nothing forbids a stalled
// copier leaving a cleanly exited process's tail behind, and a
// descendant sharing the pipe could write into it — and a listing has
// no wholeness test to tell either apart from a clean answer (a cut at
// a line or object boundary reads as a shorter, well-formed set; a
// consumer's "names at least the package itself" is fail-open on a
// missing dependency). So where Run serves the form and the structured
// readers judge it by their own test, List refuses it defensively with
// ErrListingRefused, the exec error's text carried
// (REQ-fresh-go-command-policy). Every other failure is Run's.
func (r Runner) List(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	out, err := r.Run(ctx, dir, env, append([]string{"list"}, args...)...)
	if errors.Is(err, exec.ErrWaitDelay) {
		return nil, fmt.Errorf("go list %s: %w: %v", strings.Join(args, " "), ErrListingRefused, err)
	}
	return out, err
}

// stderrBound is the most of a failed command's stderr a refusal
// carries: half from its head, half from its tail, the elision counted.
const stderrBound = 32 << 10

// boundedText trims text to stderrBound bytes, keeping the head and the
// tail and naming the bytes elided between them.
func boundedText(text []byte) string {
	text = bytes.TrimSpace(text)
	if len(text) <= stderrBound {
		return string(text)
	}
	half := stderrBound / 2
	return fmt.Sprintf("%s\n... %d bytes elided ...\n%s", text[:half], len(text)-2*half, text[len(text)-half:])
}

// Containment is the one process-boundary rule a Runner applies to
// every command it prepares: the child runs in its own process group,
// a cancellation sweeps the whole group (an already-empty group is the
// process-done case, never an injected error over a finished command),
// and WaitDelay bounds how long the reap waits on a descendant holding
// the pipes — zero meaning DefaultWaitDelay, never an unbounded wait.
// Quit, when set and true for the cancellation's cause (the command's
// own context's), asks the group to quit first — a goroutine dump on an
// expired envelope — and kills it after Grace (zero meaning
// DefaultGrace, never a kill on the quit's heels); the reap is then
// bounded by Grace plus WaitDelay, since exec's wait delay starts when
// the cancellation returns. The platform arms live in contain_*.go.
type Containment struct {
	WaitDelay time.Duration
	Quit      func(cause error) bool
	Grace     time.Duration
}

// DefaultWaitDelay bounds the reap when a Containment names no delay;
// DefaultGrace is the quit grace when a Containment names none — long
// enough for a test binary to write its goroutine dump.
const (
	DefaultWaitDelay = time.Second
	DefaultGrace     = 10 * time.Second
)

func (c Containment) waitDelay() time.Duration {
	if c.WaitDelay <= 0 {
		return DefaultWaitDelay
	}
	return c.WaitDelay
}

func (c Containment) grace() time.Duration {
	if c.Grace <= 0 {
		return DefaultGrace
	}
	return c.Grace
}

// Sampler is the memoized toolchain sampler every consumer's provenance
// check reads: one sample per (coordinate, normalized environment) for
// the sampler's lifetime, which is one judged run — the consumer's one
// verb invocation, a long-lived server's per-request operation; never
// a process, or a toolchain replaced under the memo is judged by its
// predecessor's sample — a failed sample memoized like an answered
// one (the toolchain does not change within one run), a
// cancelled sample never memoized, and the salvage the wait-delay form
// allows: the first line a cleanly exited process wrote is the sample
// when it is a go version.
type Sampler struct {
	Runner Runner
	mu     sync.Mutex
	memo   map[string]sampled
}

type sampled struct {
	version string
	err     error
}

// Sample is SampleGoVersion memoized by Coordinate(dir) and env.
func (s *Sampler) Sample(ctx context.Context, dir string, env []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key := Coordinate(dir) + "\x00" + strings.Join(memoEnv(env), "\x00")
	s.mu.Lock()
	got, ok := s.memo[key]
	s.mu.Unlock()
	if ok {
		return got.version, got.err
	}
	got.version, got.err = s.Runner.SampleGoVersion(ctx, dir, env)
	if ctx.Err() != nil {
		// A cancelled sample is no sample: never memoized, the
		// cancellation answered whatever the memo holds.
		return "", ctx.Err()
	}
	s.mu.Lock()
	if s.memo == nil {
		s.memo = map[string]sampled{}
	}
	s.memo[key] = got
	s.mu.Unlock()
	return got.version, got.err
}

// EnvReader reads go's environment for one pass: the first key takes
// the pass's one `go env -json` snapshot under the runner, every later
// key reads it — no per-key probe, no snapshot-or-probe ladder. A
// reader is pass-scoped exactly as the snapshot is — except a consumer
// that holds one reader across the observations of one judged run
// under its own hold-still obligation over the settings the reader's
// keys read (a runtime-input ingest's roots memo), which is that
// obligation's span, not a pass's — and a snapshot that failed is the
// reader's answer for its whole lifetime: the pass fails closed rather
// than re-probing an environment that refused.
type EnvReader struct {
	Runner   Runner
	Dir      string
	Env      []string
	mu       sync.Mutex
	taken    bool
	snapshot *EnvSnapshot
	err      error
}

// NewEnvReader is a pass's reader over the runner, directory, and
// complete environment every spawn of that pass shares — the one value
// an analysis entry takes in place of a directory, an environment, and
// a snapshot.
func NewEnvReader(r Runner, dir string, env []string) *EnvReader {
	return &EnvReader{Runner: r, Dir: dir, Env: env}
}

// PrimedEnvReader is a reader whose snapshot is already taken — a
// later step of the pass that holds the construction snapshot hands it
// on, so no step of one pass probes twice. A nil snapshot primes
// nothing: the reader takes its own on first use, never answering
// empty values for a snapshot that was never taken.
func PrimedEnvReader(r Runner, dir string, env []string, snapshot *EnvSnapshot) *EnvReader {
	reader := NewEnvReader(r, dir, env)
	if snapshot != nil {
		reader.snapshot, reader.taken = snapshot, true
	}
	return reader
}

// Snapshot returns the pass's snapshot, taking it on the first call. A
// snapshot that failed is the reader's answer for its lifetime — the
// pass fails closed rather than re-probing an environment that refused
// — except a cancellation, which is the caller's and never memoized.
func (r *EnvReader) Snapshot(ctx context.Context) (*EnvSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.taken {
		return r.snapshot, r.err
	}
	snapshot, err := r.Runner.TakeEnvSnapshot(ctx, r.Dir, r.Env)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	r.snapshot, r.err, r.taken = snapshot, err, true
	return r.snapshot, r.err
}

// Taken returns the snapshot the reader holds, nil until its first
// successful read — a caller building a sibling reader over the same
// pass primes it with this, so the pass probes once.
func (r *EnvReader) Taken() *EnvSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil
	}
	return r.snapshot
}

// Value returns one go-env setting from the pass's snapshot.
func (r *EnvReader) Value(ctx context.Context, key string) (string, error) {
	snapshot, err := r.Snapshot(ctx)
	if err != nil {
		return "", err
	}
	return snapshot.Value(key), nil
}

// EnvSnapshot is one observation pass's single `go env -json` read: every
// same-pass consumer of a go-env value - the build-config digest, GOFLAGS
// validation, GOMODCACHE resolution - derives from it instead of probing
// again, so one pass pays one env exec. The snapshot is pass-scoped for
// record-producing passes: sharing it across such passes would let a
// mid-run environment change escape a later pass's observation —
// unless the sharer holds those settings still for the whole span by
// its own stated obligation (a runtime-input ingest's roots memo over
// one judged run). A
// precise-analysis bracket may reuse its view's construction snapshot for
// GOMODCACHE resolution only, revalidating GOFLAGS live, because the
// bracket's closing pass takes a fresh snapshot whose guard comparison
// refuses any covered drift.
type EnvSnapshot struct {
	// JSON is the raw `go env -json` output, byte-identical to a direct
	// probe so digests derived from it cannot drift.
	JSON []byte
	// values are the parsed settings for single-key reads.
	values map[string]string
}

// Identity renders the snapshot's settings as one canonical string —
// sorted key=value lines — leaving out GOGCCFLAGS, which embeds a
// per-invocation temporary path and selects no source (the compiler
// and CGO settings it is probed from are settings of their own); two
// snapshots of one environment render identically.
func (s *EnvSnapshot) Identity() string {
	if s == nil {
		return ""
	}
	keys := make([]string, 0, len(s.values))
	for k := range s.values {
		if k != "GOGCCFLAGS" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(s.values[k])
		b.WriteByte('\n')
	}
	return b.String()
}

// Lookup reports key's value and whether the document carries the key
// at all — an unset setting answers "" and true, a key the document
// never names answers false.
func (s *EnvSnapshot) Lookup(key string) (string, bool) {
	if s == nil {
		return "", false
	}
	value, ok := s.values[key]
	return value, ok
}

// Value returns one parsed go-env setting ("" when absent).
func (s *EnvSnapshot) Value(key string) string {
	if s == nil {
		return ""
	}
	return s.values[key]
}

// TakeEnvSnapshot performs the pass's one `go env -json` read under the
// runner's spawn policy and the caller's complete environment — the
// boundary-hook form a consumer whose spec owns every go child takes.
func (r Runner) TakeEnvSnapshot(ctx context.Context, dir string, env []string) (*EnvSnapshot, error) {
	out, err := r.Run(ctx, dir, env, "env", "-json")
	if err != nil && !Salvaged(ctx, err) {
		return nil, err
	}
	values, parseErr := ParseEnvDocument(out)
	if parseErr != nil {
		// The answer a cleanly exited process wrote beside a descendant's
		// pipe hold serves when it is a whole document; a torn one refuses
		// with the hold named.
		if err != nil {
			return nil, err
		}
		return nil, parseErr
	}
	return &EnvSnapshot{JSON: out, values: values}, nil
}

// ParseEnvDocument parses a `go env -json` answer: a document with at
// least one key — `null` and an empty object are no environment, and a
// torn document does not parse.
func ParseEnvDocument(out []byte) (map[string]string, error) {
	var values map[string]string
	if err := json.Unmarshal(out, &values); err != nil {
		return nil, fmt.Errorf("gotool: parse go env -json: %w", err)
	}
	if len(values) == 0 {
		return nil, errors.New("gotool: parse go env -json: no values")
	}
	return values, nil
}

// Salvaged reports whether err is the wait-delay form Run answers
// beside a cleanly exited process's output — what the copier had
// drained when the delay expired, whole only by the reader's own test;
// a descendant's hold or a stalled copier kept the pipe from EOF —
// under a context that is still live: the one guard every structured
// reader (the toolchain sample, the environment snapshot — from whose
// keys a consumer's runtime-input ingest reads its roots) applies
// before its own wholeness test of the answer.
// List's refusal is not this form: it carries ErrListingRefused.
func Salvaged(ctx context.Context, err error) bool {
	return errors.Is(err, exec.ErrWaitDelay) && ctx.Err() == nil
}

// SampleGoVersion is the toolchain sample REQ-fresh-toolchain-skew
// specifies: `go env GOVERSION` run IN THE TARGET MODULE'S DIRECTORY,
// never the tool's own — under GOTOOLCHAIN=auto the go command re-execs
// a per-module selected toolchain, so a version sampled elsewhere can
// agree while the module's toolchain skews. The sample is the string a
// consumer hands to ToolchainSkew.
func (r Runner) SampleGoVersion(ctx context.Context, dir string, env []string) (string, error) {
	out, err := r.Run(ctx, dir, env, "env", "GOVERSION")
	if Salvaged(ctx, err) {
		// The process answered and exited; a descendant held the pipe
		// past the wait delay. The first line is the sample when it is
		// a go version — a wrapper's housekeeping is not a failed
		// sample.
		answer, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
		if strings.HasPrefix(answer, "go") {
			return answer, nil
		}
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// SampleGoVersion is Runner{}.SampleGoVersion.
func SampleGoVersion(ctx context.Context, dir string, env []string) (string, error) {
	return Runner{}.SampleGoVersion(ctx, dir, env)
}

// TakeEnvSnapshot is Runner{}.TakeEnvSnapshot.
func TakeEnvSnapshot(ctx context.Context, dir string, env []string) (*EnvSnapshot, error) {
	return Runner{}.TakeEnvSnapshot(ctx, dir, env)
}

// memoEnv is the environment half of a memo key: normalized when the
// entries allow it, so two orderings of one environment key alike, the
// raw entries otherwise (the spawn refuses those on its own).
func memoEnv(env []string) []string {
	if normalized, err := NormalizeEnv(env); err == nil {
		return normalized
	}
	return env
}

// Coordinate is the degrading form of CanonicalDir every consumer
// keys a store or a memo on: the canonical coordinate, else the
// absolute spelling, else the spelling given — never an error, so a
// key exists for every directory a caller names, and two spellings of
// one directory key alike wherever the filesystem answers.
func Coordinate(dir string) string {
	if canonical, err := CanonicalDir(dir); err == nil {
		return canonical
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// CanonicalDir resolves dir to one coordinate: absolute, then every
// element evaluated in turn, symlinks followed, `..` applied to the
// resolved prefix — never a lexical clean of the spelling first. The
// relative form is made absolute by concatenation, not filepath.Abs,
// whose cleaning would fold `link/..` onto the link's parent where the
// element-wise walk reaches the target's parent (the Unix kernel's own
// walk; Windows normalizes `..` lexically before the filesystem sees
// it, so there the two can name different directories). An engine's
// root, its evidence root, and every consumer's module directory
// resolve through it, so two spellings of one directory are one
// coordinate.
func CanonicalDir(dir string) (string, error) {
	raw := dir
	if !filepath.IsAbs(raw) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		raw = cwd + string(os.PathSeparator) + raw
	}
	return filepath.EvalSymlinks(raw)
}
