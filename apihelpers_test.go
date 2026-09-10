package gofresh

import (
	"context"
	"os"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// The tests' ambient forms of the public entries: the process
// environment and a background context, spelled once here.
func closureNewAt(dir string, buildFlags ...string) (*closure.Hasher, error) {
	return closure.NewAt(context.Background(), dir, os.Environ(), nil, buildFlags...)
}

func riFromTestLog(log []byte, moduleDir, packageDir string, opts ...runtimeinput.TestLogOption) (runtimeinput.Observation, error) {
	return runtimeinput.FromTestLog(log, moduleDir, packageDir, os.Environ(), opts...)
}

func riCaptureBracket(moduleDir string, roots []string, opts ...runtimeinput.BracketOption) (runtimeinput.Bracket, error) {
	return runtimeinput.CaptureBracket(context.Background(), moduleDir, roots, opts...)
}

func closureNewAtEnv(ctx context.Context, dir string, env []string, buildFlags ...string) (*closure.Hasher, error) {
	return closure.NewAt(ctx, dir, env, nil, buildFlags...)
}

func scanPureDirectives(pkgPaths ...string) (func(Subject) bool, error) {
	return ScanPureDirectives("", os.Environ(), nil, pkgPaths...)
}

func scanPureDirectivesIn(dir string, pkgPaths ...string) (func(Subject) bool, error) {
	return ScanPureDirectives(dir, os.Environ(), nil, pkgPaths...)
}

func closureLoadViewPackagesEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*closure.ViewLoad, error) {
	return closure.LoadViewPackages(ctx, dir, env, buildFlags, nil, pkgPaths...)
}

func riCurrentCtx(ctx context.Context, encoded, moduleDir string) (runtimeinput.State, error) {
	return runtimeinput.Current(ctx, encoded, moduleDir, os.Environ())
}
