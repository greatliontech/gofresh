package cachefile

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
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

func TestRetentionBoundUnderChurn(t *testing.T) {
	root := t.TempDir()
	SetRoot(root)
	SetMaxBytes(1024)
	t.Cleanup(func() {
		SetMaxBytes(0)
		SetRoot("")
	})

	for i := range 40 {
		key := fmt.Sprintf("key-%02d", i)
		Store("scanfacts", "scope-v1", key, map[string]int{"seq": i, "pad": 123456789})
	}

	report, err := Prune(1024)
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}
	if report.UsedBytes > 1024 || report.RemainingBytes > 1024 {
		t.Fatalf("store exceeded 1024-byte cap under churn: report=%+v", report)
	}
	if report.RemainingBytes <= 0 {
		t.Fatalf("expected newest entries to remain within cap: report=%+v", report)
	}
	var got map[string]int
	if !Load("scanfacts", "scope-v1", "key-39", &got) || got["seq"] != 39 {
		t.Fatalf("newest entry was evicted under churn: %v", got)
	}
	if Load("scanfacts", "scope-v1", "key-00", &got) {
		t.Fatalf("oldest entry survived 40-key churn under 1024-byte cap: %v", got)
	}
}

func TestPrunePreservesTempWritesAndReclaimsObsoleteClasses(t *testing.T) {
	root := t.TempDir()
	SetRoot(root)
	SetMaxBytes(-1)
	t.Cleanup(func() {
		SetMaxBytes(0)
		SetRoot("")
	})

	Store("active-class", "scope-a", "k1", map[string]string{"v": "1"})
	Store("obsolete-class-v0", "old-scope", "abandoned", map[string]string{"v": "old"})

	activeDir := filepath.Join(root, "gofresh", "active-class")
	tmpFile := filepath.Join(activeDir, ".cache-inflight")
	if err := os.WriteFile(tmpFile, []byte("inflight"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := Prune(0)
	if err != nil {
		t.Fatalf("Prune(0) failed: %v", err)
	}
	if report.RemovedEntries != 2 || report.RemainingBytes != 0 || report.ReclaimedBytes != report.UsedBytes {
		t.Fatalf("unexpected prune report: %+v", report)
	}
	if _, err := os.Stat(tmpFile); err != nil {
		t.Fatalf("in-flight temp file was removed by Prune: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "gofresh", "obsolete-class-v0")); !os.IsNotExist(err) {
		t.Fatalf("empty obsolete class directory was not removed: %v", err)
	}
}

func TestPreviewPruneMatchesPruneWithoutMutatingStore(t *testing.T) {
	root := t.TempDir()
	SetRoot(root)
	SetMaxBytes(-1)
	t.Cleanup(func() {
		SetMaxBytes(0)
		SetRoot("")
	})

	Store("active-class", "scope-a", "k1", map[string]string{"v": "1"})
	Store("active-class", "scope-a", "k2", map[string]string{"v": "2"})

	preview, err := PreviewPrune(0)
	if err != nil {
		t.Fatalf("PreviewPrune(0) failed: %v", err)
	}
	if preview.RemovedEntries != 2 || preview.RemainingBytes != 0 || preview.ReclaimedBytes != preview.UsedBytes {
		t.Fatalf("unexpected preview report: %+v", preview)
	}
	var got map[string]string
	if !Load("active-class", "scope-a", "k1", &got) || !Load("active-class", "scope-a", "k2", &got) {
		t.Fatal("PreviewPrune evicted entries")
	}
	actual, err := Prune(0)
	if err != nil {
		t.Fatalf("Prune(0) failed: %v", err)
	}
	if actual != preview {
		t.Fatalf("Prune(0) = %+v, want preview %+v", actual, preview)
	}
}

func TestPruneCountsSkippedEntriesAndContinues(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads and removes anywhere")
	}
	root := t.TempDir()
	SetRoot(root)
	SetMaxBytes(-1)
	t.Cleanup(func() {
		SetMaxBytes(0)
		SetRoot("")
	})

	Store("writable", "scope", "k1", map[string]int{"n": 1})
	Store("locked", "scope", "k2", map[string]int{"n": 2})

	lockedDir := filepath.Join(root, "gofresh", "locked")
	if err := os.Chmod(lockedDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(lockedDir, 0o700) })

	report, err := Prune(0)
	if err != nil {
		t.Fatalf("Prune(0) failed: %v", err)
	}
	if report.RemovedEntries != 1 || report.SkippedEntries != 1 {
		t.Fatalf("expected 1 removed and 1 skipped entry, got %+v", report)
	}
	var got map[string]int
	if Load("writable", "scope", "k1", &got) {
		t.Fatalf("writable entry was not evicted: %v", got)
	}
}

func TestConcurrentStoreLoadAndPrune(t *testing.T) {
	root := t.TempDir()
	SetRoot(root)
	SetMaxBytes(2048)
	t.Cleanup(func() {
		SetMaxBytes(0)
		SetRoot("")
	})

	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := range 25 {
				key := fmt.Sprintf("w%d-k%d", worker, i%8)
				Merge("dynamicstate", "scope", key, map[string]int{fmt.Sprintf("f%d", i): i})
				var out map[string]int
				_ = Load("dynamicstate", "scope", key, &out)
				if i%5 == 0 {
					_, _ = Prune(1024)
				}
			}
		}(w)
	}
	wg.Wait()

	report, err := Prune(2048)
	if err != nil {
		t.Fatalf("final Prune failed: %v", err)
	}
	if report.RemainingBytes > 2048 {
		t.Fatalf("remaining bytes exceeded bound after concurrent run: %+v", report)
	}
}
