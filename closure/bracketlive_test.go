package closure

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// A bracket's live snapshot is its own pass: taken fresh over the
// construction reader's runner, directory, and environment, so the
// memo scopes by the environment the bracket's loads run in, while the
// classification keeps the construction snapshot's module cache. A
// module cache moved between construction and the bracket shows in the
// live snapshot and not in the classification.
func TestBracketLiveSnapshotIsItsOwnPass(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	construction, err := gotool.TakeEnvSnapshot(ctx, dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	moved := gotool.SetEnv(os.Environ(), "GOMODCACHE", filepath.Join(t.TempDir(), "modcache"))
	h, err := NewBracketAt(ctx, gotool.PrimedEnvReader(gotool.Runner{}, dir, moved, construction))
	if err != nil {
		t.Fatal(err)
	}
	live := h.snapshot.Value("GOMODCACHE")
	if live == construction.Value("GOMODCACHE") {
		t.Fatalf("the bracket's snapshot is the construction's (%q): no fresh pass was taken", live)
	}
	if want, _ := gotool.LookupEnv(moved, "GOMODCACHE"); live != want {
		t.Fatalf("live GOMODCACHE = %q, want the moved %q", live, want)
	}
	if h.modCache != filepath.Clean(construction.Value("GOMODCACHE")) {
		t.Fatalf("classification module cache = %q, want the construction snapshot's %q", h.modCache, construction.Value("GOMODCACHE"))
	}
}
