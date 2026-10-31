package closure

import (
	"context"
	"os"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/testenv"
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
// race listing.
func cgoEnabled(t *testing.T) bool {
	t.Helper()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), t.TempDir(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.Value("CGO_ENABLED") == "1"
}

func isolateProofCache(t *testing.T) {
	t.Helper()
	cache, err := testenv.GoBuildCache(context.Background(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOCACHE", cache)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
}

// unauditedTagGOROOT constructs an isolated GOROOT copy of the host toolchain
// with a tag-gated file in package strings (`//go:build badstd`) that declares
// an unapproved single-argument push linkname.
func unauditedTagGOROOT(t *testing.T) string {
	t.Helper()
	return testenv.UnauditedTagGOROOT(t, os.Environ())
}
