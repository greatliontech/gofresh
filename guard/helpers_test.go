package guard

import (
	"context"
	"os"

	"github.com/greatliontech/gofresh/gotool"
)

// The tests' ambient forms: the process environment and a background
// context, spelled once here — the public entry names both.
func ambientCapture(moduleDir string, kind Kind, buildInputs ...string) (Guards, error) {
	return Capture(context.Background(), moduleDir, os.Environ(), os.Environ(), kind, nil, buildInputs...)
}

func captureUnder(ctx context.Context, moduleDir string, env []string, kind Kind, buildInputs ...string) (Guards, error) {
	return Capture(ctx, moduleDir, env, env, kind, nil, buildInputs...)
}

func captureUnderSnapshot(ctx context.Context, moduleDir string, env []string, kind Kind, snapshot *gotool.EnvSnapshot, buildInputs ...string) (Guards, error) {
	return Capture(ctx, moduleDir, env, env, kind, snapshot, buildInputs...)
}
