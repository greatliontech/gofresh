package gofresh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/testenv"
)

func parseAndTypecheckDAG(t testing.TB, virtualDir string, filesByPkg map[string]map[string]string) []*packages.Package {
	t.Helper()
	return testenv.ParseAndTypecheckDAG(t, virtualDir, filesByPkg)
}

var (
	sharedTestBinariesMu sync.Mutex
	sharedTestBinaries   = map[string]string{}
	sharedTestBinaryDirs []string
)

// compileSharedTestBinaryOnce compiles a `go test -c` binary for pkgDir and
// buildFlags at most once per test-binary execution, returning the compiled
// binary path. All shared binaries are removed at TestMain exit.
func compileSharedTestBinaryOnce(t testing.TB, pkgDir string, buildFlags ...string) string {
	t.Helper()
	absDir, err := filepath.Abs(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	key := absDir + "\x00" + strings.Join(buildFlags, "\x00")
	sharedTestBinariesMu.Lock()
	defer sharedTestBinariesMu.Unlock()
	if bin, ok := sharedTestBinaries[key]; ok {
		if _, err := os.Stat(bin); err == nil {
			return bin
		}
	}
	tmpDir, err := os.MkdirTemp("", "gofresh-shared-testbin-*")
	if err != nil {
		t.Fatal(err)
	}
	sharedTestBinaryDirs = append(sharedTestBinaryDirs, tmpDir)
	binPath := filepath.Join(tmpDir, "pkg.test")
	env, err := gotool.PreserveBuildCache(context.Background(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"test", "-c", "-o", binPath}
	args = append(args, buildFlags...)
	args = append(args, ".")
	if _, err := (gotool.Runner{}).Run(context.Background(), absDir, env, args...); err != nil {
		t.Fatalf("compileSharedTestBinaryOnce(%s): %v", absDir, err)
	}
	sharedTestBinaries[key] = binPath
	return binPath
}

func cleanupSharedTestBinaries() {
	sharedTestBinariesMu.Lock()
	dirs := sharedTestBinaryDirs
	sharedTestBinaryDirs = nil
	clear(sharedTestBinaries)
	sharedTestBinariesMu.Unlock()
	for _, dir := range dirs {
		_ = os.RemoveAll(dir)
	}
}
