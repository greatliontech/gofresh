// Package gotool runs the go command line tool under one complete
// normalized environment (env.go), surfacing stderr on failure;
// reads go's environment once per pass (EnvReader); resolves a
// directory to its one canonical coordinate (CanonicalDir, Coordinate);
// and reads a toolchain version's language series, pair, and release
// tags through the canonical grammar (LanguageSeries, ParseGoVersion,
// ReleaseTags).
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
	"slices"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
)

// Runner runs the go command line tool under a caller-supplied command
// preparation hook. Prepare, when set, sees the command after Dir and
// Env are configured.
type Runner struct {
	Prepare func(*exec.Cmd)
}

// Command prepares `go <args>` under the policy without starting it:
// Dir set, Env the complete derived environment, Prepare applied.
func (r Runner) Command(ctx context.Context, dir string, env []string, args ...string) (*exec.Cmd, error) {
	if env == nil {
		// A nil environment would let the child inherit the ambient one;
		// the caller names the environment it runs under (an empty
		// non-nil slice is a deliberate empty environment).
		return nil, errors.New("go: nil environment")
	}
	if ctx == nil {
		return nil, errors.New("go: nil context")
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	commandEnv, err := EnvForCommand(env, dir)
	if err != nil {
		return nil, fmt.Errorf("%s: environment: %w", strings.Join(append([]string{"go"}, args...), " "), err)
	}
	cmd.Env = commandEnv
	if r.Prepare != nil {
		r.Prepare(cmd)
	}
	return cmd, nil
}

// Run is the collected form under the runner's spawn policy: it owns
// the command's streams (a Prepare hook's own are replaced). When the
// process itself exited cleanly but a descendant held its output pipe
// past the command's WaitDelay, the output read so far is returned
// BESIDE exec.ErrWaitDelay — never discarded behind the error. A failed
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
// has no wholeness test.
var ErrListingRefused = errors.New("the listing was not drained within the wait delay (a descendant's hold or a stalled copier); a listing has no wholeness test and is refused")

// List runs `go list <args>` under the policy and returns its stdout,
// refusing the wait-delay form Run would serve (REQ-fresh-go-command-policy).
// Every other failure is Run's.
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
	Runner Runner
	Dir    string
	Env    []string
	once   once[*EnvSnapshot]
}

// NewEnvReader is a pass's reader over the runner, directory, and
// complete environment every spawn of that pass shares — the one value
// an analysis entry takes in place of a directory, an environment, and
// a snapshot. The reader owns a copy of the supplied environment.
func NewEnvReader(r Runner, dir string, env []string) *EnvReader {
	return &EnvReader{Runner: r, Dir: dir, Env: slices.Clone(env)}
}

// PrimedEnvReader is a reader whose snapshot is already taken — a
// later step of the pass that holds the construction snapshot hands it
// on, so no step of one pass probes twice. A nil snapshot primes
// nothing: the reader takes its own on first use, never answering
// empty values for a snapshot that was never taken.
func PrimedEnvReader(r Runner, dir string, env []string, snapshot *EnvSnapshot) *EnvReader {
	reader := NewEnvReader(r, dir, env)
	if snapshot != nil {
		reader.once.prime(snapshot)
	}
	return reader
}

// Snapshot returns the pass's snapshot, taking it on the first call. A
// snapshot that failed is the reader's answer for its lifetime — the
// pass fails closed rather than re-probing an environment that refused
// — except a cancellation, which is the caller's and never memoized.
func (r *EnvReader) Snapshot(ctx context.Context) (*EnvSnapshot, error) {
	return r.once.take(ctx, func(ctx context.Context) (*EnvSnapshot, error) {
		return r.Runner.TakeEnvSnapshot(ctx, r.Dir, r.Env)
	})
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
// runner's spawn policy and the caller's complete environment.
func (r Runner) TakeEnvSnapshot(ctx context.Context, dir string, env []string) (*EnvSnapshot, error) {
	out, err := r.Run(ctx, dir, env, "env", "-json")
	if err != nil && !(errors.Is(err, exec.ErrWaitDelay) && ctx.Err() == nil) {
		return nil, err
	}
	values, parseErr := parseEnvDocument(out)
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

// parseEnvDocument parses a `go env -json` answer: a document with at
// least one key — `null` and an empty object are no environment, and a
// torn document does not parse.
func parseEnvDocument(out []byte) (map[string]string, error) {
	var values map[string]string
	if err := json.Unmarshal(out, &values); err != nil {
		return nil, fmt.Errorf("gotool: parse go env -json: %w", err)
	}
	if len(values) == 0 {
		return nil, errors.New("gotool: parse go env -json: no values")
	}
	return values, nil
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

// LoadPackages loads patterns through x/tools/go/packages under the
// policy's package-loader environment (EnvForPackages, with GOPACKAGESDRIVER
// pinned off and a non-nil Config.Env guaranteed so x/tools never falls
// back to os.Environ()), explicit working directory, and caller context.
// Input containers are copied before consulting ctx. Because
// x/tools/go/packages.Config carries no spawn hook, the loader's `go list`
// children spawn outside any Runner's Containment or Prepare hook
// (REQ-fresh-go-command-policy, REQ-fresh-coherent-view).
func LoadPackages(ctx context.Context, mode packages.LoadMode, dir string, env, buildFlags []string, patterns ...string) ([]*packages.Package, error) {
	if ctx == nil {
		return nil, errors.New("gotool: nil context")
	}
	if env == nil {
		return nil, errors.New("gotool: nil environment")
	}
	packageEnv, err := EnvForPackages(env)
	if err != nil {
		return nil, err
	}
	if packageEnv == nil {
		packageEnv = []string{}
	}
	cfg := &packages.Config{
		Context:    ctx,
		Mode:       mode,
		Tests:      true,
		Dir:        dir,
		Env:        packageEnv,
		BuildFlags: slices.Clone(buildFlags),
	}
	patterns = slices.Clone(patterns)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if cancelled := ctx.Err(); cancelled != nil {
		return nil, cancelled
	}
	return pkgs, err
}
