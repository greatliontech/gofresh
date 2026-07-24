// Package gotool runs the go command line tool, surfacing stderr on failure.
package gotool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/greatliontech/gofresh/internal/processenv"
)

// Run executes `go <args>` in the current directory. See RunIn.
func Run(args ...string) ([]byte, error) { return RunIn("", args...) }

// RunIn executes `go <args>` in dir ("" = current directory) and returns stdout.
// On failure the error includes the command and go's stderr. The directory
// matters: a go.mod `toolchain` directive / GOTOOLCHAIN is resolved relative to
// it, so provenance capture and `go test` must run in the same dir to describe
// the same toolchain.
func RunIn(dir string, args ...string) ([]byte, error) {
	return RunInContext(context.Background(), dir, args...)
}

// RunInContext is RunIn with caller-owned cancellation.
func RunInContext(ctx context.Context, dir string, args ...string) ([]byte, error) {
	return runInContext(ctx, dir, nil, args...)
}

// RunInContextEnv executes go with env as its complete process environment.
func RunInContextEnv(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	return runInContext(ctx, dir, env, args...)
}

func runInContext(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("go: nil context")
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	if env != nil {
		commandEnv, err := processenv.ForCommand(env, dir)
		if err != nil {
			return nil, fmt.Errorf("go %s: environment: %w", strings.Join(args, " "), err)
		}
		cmd.Env = commandEnv
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
// again, so one pass pays one env exec. The snapshot is pass-scoped by
// construction: sharing it across passes would let a mid-run environment
// change escape a later pass's observation.
type EnvSnapshot struct {
	// JSON is the raw `go env -json` output, byte-identical to a direct
	// probe so digests derived from it cannot drift.
	JSON []byte
	// values are the parsed settings for single-key reads.
	values map[string]string
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
	out, err := RunInContextEnv(ctx, dir, env, "env", "-json")
	if err != nil {
		return nil, err
	}
	var values map[string]string
	if err := json.Unmarshal(out, &values); err != nil {
		return nil, fmt.Errorf("gotool: parse go env -json: %w", err)
	}
	return &EnvSnapshot{JSON: out, values: values}, nil
}
