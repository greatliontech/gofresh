package gofresh

import (
	"context"
	"os"
	"testing"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// The tests' ambient forms of the public entries: the process
// environment and a background context, spelled once here.
func closureNewAt(dir string, buildFlags ...string) (*closure.Hasher, error) {
	return closure.NewAt(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()), buildFlags...)
}

func riFromTestLog(log []byte, moduleDir, packageDir string, opts ...runtimeinput.TestLogOption) (runtimeinput.Observation, error) {
	return runtimeinput.FromTestLog(log, moduleDir, packageDir, os.Environ(), opts...)
}

func riCaptureBracket(moduleDir string, roots []string, opts ...runtimeinput.BracketOption) (runtimeinput.Bracket, error) {
	return runtimeinput.CaptureBracket(context.Background(), moduleDir, roots, opts...)
}

func closureNewAtEnv(ctx context.Context, dir string, env []string, buildFlags ...string) (*closure.Hasher, error) {
	return closure.NewAt(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, env), buildFlags...)
}

func scanPureDirectives(pkgPaths ...string) (func(Subject) bool, error) {
	return ScanPureDirectives("", os.Environ(), nil, pkgPaths...)
}

func scanPureDirectivesIn(dir string, pkgPaths ...string) (func(Subject) bool, error) {
	return ScanPureDirectives(dir, os.Environ(), nil, pkgPaths...)
}

func closureLoadViewPackagesEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*closure.ViewLoad, error) {
	return closure.LoadViewPackages(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, env), buildFlags, pkgPaths...)
}

func riCurrentCtx(ctx context.Context, encoded, moduleDir string) (runtimeinput.State, error) {
	return runtimeinput.Current(ctx, encoded, moduleDir, os.Environ())
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
