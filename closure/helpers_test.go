package closure

import (
	"context"
	"github.com/greatliontech/gofresh/gotool"
	"os"
	"testing"
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

// cgoEnabled reports the go command's resolved CGO_ENABLED — the
// setting every listing obeys: without cgo the go command refuses a
// race listing, and the closest chain to a netgo listing is the cgo0
// row's rather than the base's.
func cgoEnabled(t *testing.T) bool {
	t.Helper()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), t.TempDir(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.Value("CGO_ENABLED") == "1"
}

// closestChainSuffix is the label suffix of the chain closest to a
// netgo listing on this host: the toolchain's base row under cgo, its
// cgo0 row without.
func closestChainSuffix(t *testing.T) string {
	t.Helper()
	if cgoEnabled(t) {
		return ""
	}
	return " cgo0"
}
