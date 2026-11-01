package guard

import (
	"context"
	"os"

	"github.com/greatliontech/gofresh/gotool"
)

// The tests' ambient forms: the process environment and a background
// context, spelled once here — the public entry names both.
func ambientCapture(moduleDir string, kind Kind, buildInputs ...string) (Guards, error) {
	return captureUnderSnapshot(context.Background(), moduleDir, os.Environ(), kind, nil, buildInputs...)
}

func captureUnder(ctx context.Context, moduleDir string, env []string, kind Kind, buildInputs ...string) (Guards, error) {
	return captureUnderSnapshot(ctx, moduleDir, env, kind, nil, buildInputs...)
}

// captureUnderSnapshot is the one reader-building form the two above
// reduce to: a plain runner's reader over dir and env, primed with the
// snapshot when one is given.
func captureUnderSnapshot(ctx context.Context, moduleDir string, env []string, kind Kind, snapshot *gotool.EnvSnapshot, buildInputs ...string) (Guards, error) {
	return Capture(ctx, gotool.PrimedEnvReader(gotool.Runner{}, moduleDir, env, snapshot), env, kind, buildInputs...)
}
