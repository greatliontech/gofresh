// Package gotool is the fleet's go-command policy: it runs the go
// command line tool under one complete normalized environment (env.go),
// surfacing stderr on failure; samples the toolchain in the target
// module's directory; and resolves a directory to its one canonical
// coordinate. The policy covers the go commands gofresh spawns itself;
// the package loader's `go list` children carry the same environment
// (x/tools appends its own PWD, the same derivation) and spawn through
// x/tools, outside the runner's hook.
package gotool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
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

// Runner runs the go command line tool under a caller-owned spawn
// policy: Prepare, when set, sees the command before it starts, its
// Dir and Env already set — a consumer that owns its children's
// process boundary sets the group there and, since CommandContext's
// default Cancel kills the leader alone, replaces Cancel and WaitDelay
// so a cancellation sweeps the group (Run without a hook is the plain
// spawn). The hook reaches the go commands gofresh spawns itself; the
// package loader's children spawn through x/tools, outside it.
type Runner struct {
	Prepare func(*exec.Cmd)
}

// Run is Run under the runner's spawn policy.
func (r Runner) Run(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
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
		return nil, fmt.Errorf("go %s: environment: %w", strings.Join(args, " "), err)
	}
	cmd.Env = commandEnv
	if r.Prepare != nil {
		r.Prepare(cmd)
	}
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			return nil, fmt.Errorf("go %s: %w: %s",
				strings.Join(args, " "), err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// EnvSnapshot is one observation pass's single `go env -json` read: every
// same-pass consumer of a go-env value - the build-config digest, GOFLAGS
// validation, GOMODCACHE resolution - derives from it instead of probing
// again, so one pass pays one env exec. The snapshot is pass-scoped for
// record-producing passes: sharing it across such passes would let a
// mid-run environment change escape a later pass's observation. A
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

// Value returns one parsed go-env setting ("" when absent).
func (s *EnvSnapshot) Value(key string) string {
	if s == nil {
		return ""
	}
	return s.values[key]
}

// TakeEnvSnapshot performs the pass's one `go env -json` read under the
// caller's complete environment.
func TakeEnvSnapshot(ctx context.Context, dir string, env []string) (*EnvSnapshot, error) {
	out, err := Run(ctx, dir, env, "env", "-json")
	if err != nil {
		return nil, err
	}
	var values map[string]string
	if err := json.Unmarshal(out, &values); err != nil {
		return nil, fmt.Errorf("gotool: parse go env -json: %w", err)
	}
	return &EnvSnapshot{JSON: out, values: values}, nil
}

// SampleGoVersion is the toolchain sample REQ-fresh-toolchain-skew
// specifies: `go env GOVERSION` run IN THE TARGET MODULE'S DIRECTORY,
// never the tool's own — under GOTOOLCHAIN=auto the go command re-execs
// a per-module selected toolchain, so a version sampled elsewhere can
// agree while the module's toolchain skews. The sample is the string a
// consumer hands to ToolchainSkew.
func (r Runner) SampleGoVersion(ctx context.Context, dir string, env []string) (string, error) {
	out, err := r.Run(ctx, dir, env, "env", "GOVERSION")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// SampleGoVersion is Runner{}.SampleGoVersion.
func SampleGoVersion(ctx context.Context, dir string, env []string) (string, error) {
	return Runner{}.SampleGoVersion(ctx, dir, env)
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
