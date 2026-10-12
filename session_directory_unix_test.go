//go:build unix

package gofresh

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// The directory is resolved by the filesystem after rebasing: via/.. names
// the link target's parent, not the build directory. The expected directory is
// independently constructed, never obtained from the resolver under test.
func TestSessionRuntimeDirectoryPreservesSymlinkParents(t *testing.T) {
	build, destination := t.TempDir(), t.TempDir()
	destination, err := filepath.EvalSymlinks(destination)
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(destination, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(child, filepath.Join(build, "via")); err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(t.Context(), BuildDescription{Directory: build, Environment: os.Environ(), Inputs: []string{}}, RuntimeDescription{Directory: "via/.."}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if session.runtimeDir != destination {
		t.Fatalf("runtime directory = %q, want filesystem parent %q", session.runtimeDir, destination)
	}
	if pwd, _ := gotool.LookupEnv(session.engine.evidenceEnv(), "PWD"); pwd != destination {
		t.Fatalf("runtime PWD = %q, want %q", pwd, destination)
	}
}
