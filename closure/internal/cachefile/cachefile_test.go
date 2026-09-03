package cachefile

import (
	"os"
	"path/filepath"
	"testing"
)

// An unwritable store is a cost, never a fault: a store fails silently
// and leaves nothing behind, a load misses, and no call panics — the
// mechanism a hermetic environment that forbids user-cache writes
// relies on.
func TestUnwritableStoreIsSilent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	root := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(root, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(root, 0o700) })
	SetRoot(root)
	t.Cleanup(func() { SetRoot("") })
	Store("class", "scope", "key", map[string]int{"n": 1})
	var got map[string]int
	if Load("class", "scope", "key", &got) {
		t.Fatalf("an unwritable store served an entry: %v", got)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("the unwritable root gained entries: %v %v", entries, err)
	}
}

// A redirected root receives the store and serves it back under the
// exact scope and key; a mismatched scope misses.
func TestRedirectedStoreRoundTrips(t *testing.T) {
	root := t.TempDir()
	SetRoot(root)
	t.Cleanup(func() { SetRoot("") })
	Store("class", "scope", "key", map[string]int{"n": 1})
	var got map[string]int
	if !Load("class", "scope", "key", &got) || got["n"] != 1 {
		t.Fatalf("stored entry not served: %v", got)
	}
	if Load("class", "other", "key", &got) {
		t.Fatal("a mismatched scope served")
	}
	if entries, _ := filepath.Glob(filepath.Join(root, "gofresh", "class", "*.json")); len(entries) != 1 {
		t.Fatalf("store wrote %d entries under the redirect, want 1", len(entries))
	}
}
