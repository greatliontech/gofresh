package closure

import (
	"context"
	"os"
)

// The tests' ambient forms: the process environment and a background
// context, spelled once here — the public entries name both.
func newAt(dir string, buildFlags ...string) (*Hasher, error) {
	return NewAt(context.Background(), dir, os.Environ(), nil, buildFlags...)
}

func newAtEnv(ctx context.Context, dir string, env []string, buildFlags ...string) (*Hasher, error) {
	return NewAt(ctx, dir, env, nil, buildFlags...)
}

func loadViewPackagesEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*ViewLoad, error) {
	return LoadViewPackages(ctx, dir, env, buildFlags, nil, pkgPaths...)
}
