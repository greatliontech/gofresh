package closure

import (
	"context"
	"github.com/greatliontech/gofresh/gotool"
	"os"
)

// The tests' ambient forms: the process environment and a background
// context, spelled once here — the public entries name both.
func newAt(dir string, buildFlags ...string) (*Hasher, error) {
	return NewAt(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()), buildFlags...)
}

func newAtEnv(ctx context.Context, dir string, env []string, buildFlags ...string) (*Hasher, error) {
	return NewAt(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, env), buildFlags...)
}

func loadViewPackagesEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*ViewLoad, error) {
	return LoadViewPackages(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, env), buildFlags, pkgPaths...)
}
