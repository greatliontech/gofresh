package closure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
	"github.com/greatliontech/gofresh/gotool"
)

// TestDigestTraversalEndsAtTheNextFileBoundary pins the digest
// traversal's check point (REQ-closure-observability-toolchain-key: the
// digests are read on every construction and the traversal checks its
// context before every file read): a context cancelled while the
// audited surface is being digested ends the traversal at the next file
// boundary — the file the cancellation lands on is the last one read
// and the construction answers the cancellation — and the listing
// record the memo stored before the digests were read, the completed
// listing's own, stands under the live seeds' scope.
func TestDigestTraversalEndsAtTheNextFileBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const stopAt = 3
	reads := 0
	prior := digestReadForTest
	digestReadForTest = func(name string) {
		reads++
		if reads == stopAt {
			cancel()
		}
	}
	t.Cleanup(func() { digestReadForTest = prior })
	_, err := newAtEnv(ctx, ".", environmentWith())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a construction cancelled mid-digest answered %v, want the cancellation", err)
	}
	if reads != stopAt {
		t.Fatalf("the traversal read %d files with the cancellation at read %d, want exactly that many: the next boundary ends it", reads, stopAt)
	}
	snapshot, err := gotool.NewEnvReader(gotool.Runner{}, ".", os.Environ()).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, surfaceSeeds()), "listing")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("the completed listing's record does not stand after the cancelled digest traversal: %v", err)
	}
}

// TestPackageFileWalkEndsAtTheNextEntry pins the package-file walk's
// check point (REQ-closure-observability-toolchain-key: the walk checks
// the package's cancellation check at every entry): over a planted tree
// a context cancelled at the walk's second entry ends it at the third —
// the entries seen are exactly the two before the cancellation's check
// fired — answering the cancellation with nothing listed; a context
// cancelled before the walk ends it at the root entry; the live walk
// lists the three files.
func TestPackageFileWalkEndsAtTheNextEntry(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go", "c.go"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("package p\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &Hasher{ctx: ctx}
	const stopAt = 2
	seen := 0
	prior := walkEntryForTest
	walkEntryForTest = func(path string) {
		seen++
		if seen == stopAt {
			cancel()
		}
	}
	t.Cleanup(func() { walkEntryForTest = prior })
	files, err := allPackageFiles(h.contextErr, dir)
	if !errors.Is(err, context.Canceled) || len(files) != 0 {
		t.Fatalf("a walk cancelled at entry %d answered %v with %d files, want the cancellation and nothing listed", stopAt, err, len(files))
	}
	if seen != stopAt {
		t.Fatalf("the walk visited %d entries with the cancellation at entry %d, want exactly that many: the next entry's check ends it", seen, stopAt)
	}
	walkEntryForTest = prior
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if files, err := allPackageFiles((&Hasher{ctx: cancelled}).contextErr, dir); !errors.Is(err, context.Canceled) || len(files) != 0 {
		t.Fatalf("a pre-cancelled walk answered %v with %d files, want the cancellation at the root entry", err, len(files))
	}
	live, err := allPackageFiles((&Hasher{ctx: context.Background()}).contextErr, dir)
	if err != nil || len(live) != 3 {
		t.Fatalf("the live walk answered %v with %d files, want the three", err, len(live))
	}
}
