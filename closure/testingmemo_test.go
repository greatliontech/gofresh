package closure

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func testingScanModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/tscan\n\ngo 1.26\n")
	writeFile(t, dir, "scan.go", "package tscan\n\nfunc Pure(x int) int { return x + 1 }\n")
	writeFile(t, dir, "scan_test.go", `package tscan

import "testing"

func TestPure(t *testing.T) {
	_ = t.TempDir()
	if Pure(1) != 2 {
		t.Fatal("pure")
	}
}
`)
	return dir
}

// countTestingScanLoads observes the typed scan's own program load; a
// memo hit must never reach it.
func countTestingScanLoads(t *testing.T) *int {
	t.Helper()
	loads := 0
	prev := analysisTestHooks.testingTypeOwnLoad
	analysisTestHooks.testingTypeOwnLoad = func(string) { loads++ }
	t.Cleanup(func() { analysisTestHooks.testingTypeOwnLoad = prev })
	return &loads
}

// TestTestingScanMemoServesWithoutTypeLoad pins the memo's core property
// (REQ-closure-testing-scan-memo): a scan derived once serves from the
// persistent memo with no type-environment load and byte-equivalent
// results — an effect-free scan included — and without a caller scope the
// memo stays disabled.
func TestTestingScanMemoServesWithoutTypeLoad(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := testingScanModule(t)
	if err := os.MkdirAll(filepath.Join(dir, "plain"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "plain/plain.go", "package plain\n\nfunc P() int { return 0 }\n")
	loads := countTestingScanLoads(t)

	first, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	first.SetMemoScope("strategy@1|toolchain|build")
	derived, err := first.maximalTestingTypeEffects("example.com/tscan")
	if err != nil {
		t.Fatal(err)
	}
	if *loads != 1 {
		t.Fatalf("derivation loads = %d, want 1", *loads)
	}
	if len(derived.effects) == 0 || derived.preferred == "" {
		t.Fatalf("derived scan carries no testing facts: %+v", derived)
	}

	second, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	second.SetMemoScope("strategy@1|toolchain|build")
	served, err := second.maximalTestingTypeEffects("example.com/tscan")
	if err != nil {
		t.Fatal(err)
	}
	if *loads != 1 {
		t.Fatalf("memo hit loaded the type environment: loads = %d", *loads)
	}
	if !reflect.DeepEqual(served, derived) {
		t.Fatalf("served scan diverged:\n got %+v\nwant %+v", served, derived)
	}

	// Without a caller-supplied scope the memo is disabled: the scan
	// loads even though a matching entry exists under some scope.
	bare, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	bareScan, err := bare.maximalTestingTypeEffects("example.com/tscan")
	if err != nil {
		t.Fatal(err)
	}
	if *loads != 2 {
		t.Fatalf("scope-less scan loads = %d, want 2", *loads)
	}
	if !reflect.DeepEqual(bareScan, derived) {
		t.Fatalf("scope-less scan diverged:\n got %+v\nwant %+v", bareScan, derived)
	}

	// An effect-free scan round-trips as a hit: the recorded absence of
	// testing effects serves without a load.
	third, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	third.SetMemoScope("strategy@1|toolchain|build")
	emptyDerived, err := third.maximalTestingTypeEffects("example.com/tscan/plain")
	if err != nil {
		t.Fatal(err)
	}
	if *loads != 3 {
		t.Fatalf("effect-free derivation loads = %d, want 3", *loads)
	}
	if len(emptyDerived.effects) != 0 || emptyDerived.preferred != "" {
		t.Fatalf("plain package scan carries facts: %+v", emptyDerived)
	}
	fourth, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	fourth.SetMemoScope("strategy@1|toolchain|build")
	emptyServed, err := fourth.maximalTestingTypeEffects("example.com/tscan/plain")
	if err != nil {
		t.Fatal(err)
	}
	if *loads != 3 {
		t.Fatalf("effect-free memo hit loaded the type environment: loads = %d", *loads)
	}
	if !reflect.DeepEqual(emptyServed, emptyDerived) {
		t.Fatalf("effect-free served scan diverged:\n got %+v\nwant %+v", emptyServed, emptyDerived)
	}

	// A key-derivation failure disables the memo for the package —
	// fail-open to recomputation: the scan still derives, serves nothing
	// from the memo, and persists nothing. The poisoned session list
	// cache fails the closure hash while the scan's own load stays
	// healthy — a single-sided failure.
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	memoDir := filepath.Join(cache, "gofresh", testingScanDirName)
	before, err := os.ReadDir(memoDir)
	if err != nil {
		t.Fatal(err)
	}
	broken, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	broken.SetMemoScope("strategy@1|toolchain|build")
	broken.lists["example.com/tscan"] = []listPkg{{
		ImportPath: "example.com/tscan",
		Dir:        filepath.Join(dir, "missing"),
		GoFiles:    []string{"gone.go"},
		Module:     &listMod{Path: "example.com/tscan", Main: true, Dir: dir},
	}}
	brokenScan, err := broken.maximalTestingTypeEffects("example.com/tscan")
	if err != nil {
		t.Fatalf("fail-open derivation errored: %v", err)
	}
	if *loads != 4 {
		t.Fatalf("fail-open scan loads = %d, want 4 (a failed key must not serve)", *loads)
	}
	if !reflect.DeepEqual(brokenScan, derived) {
		t.Fatalf("fail-open scan diverged:\n got %+v\nwant %+v", brokenScan, derived)
	}
	after, err := os.ReadDir(memoDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("a failed key derivation persisted an entry: %d -> %d files", len(before), len(after))
	}
}

// TestTestingScanMemoMissesOnScopeAndSourceChange pins the key's
// completeness (REQ-closure-testing-scan-memo): a scope change and a
// test-only source change each miss — the scan reads test-variant
// source, so the compartment axis participates — and a corrupt entry
// recomputes silently.
func TestTestingScanMemoMissesOnScopeAndSourceChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := testingScanModule(t)
	loads := countTestingScanLoads(t)

	first, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	first.SetMemoScope("scope-a")
	before, err := first.maximalTestingTypeEffects("example.com/tscan")
	if err != nil {
		t.Fatal(err)
	}
	if *loads != 1 {
		t.Fatalf("derivation loads = %d, want 1", *loads)
	}

	otherScope, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	otherScope.SetMemoScope("scope-b")
	if _, err := otherScope.maximalTestingTypeEffects("example.com/tscan"); err != nil {
		t.Fatal(err)
	}
	if *loads != 2 {
		t.Fatal("a different scope served from the memo")
	}

	// A test-only edit moves the key and the scan alike.
	testSrc, err := os.ReadFile(filepath.Join(dir, "scan_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scan_test.go"), append(testSrc, []byte("\nfunc TestExtra(t *testing.T) { t.Setenv(\"K\", \"V\") }\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	moved, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	moved.SetMemoScope("scope-a")
	after, err := moved.maximalTestingTypeEffects("example.com/tscan")
	if err != nil {
		t.Fatal(err)
	}
	if *loads != 3 {
		t.Fatal("a test-only source change served from the memo")
	}
	if !hasEffectReason(after.effects, "reaches testing.Setenv (process or path mutation)") {
		t.Fatalf("post-edit scan misses the new testing effect: %+v", after)
	}
	if reflect.DeepEqual(after, before) {
		t.Fatal("post-edit scan equals the pre-edit scan")
	}

	// Corrupt entries recompute silently.
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(cache, "gofresh", testingScanDirName))
	if err != nil || len(entries) == 0 {
		t.Fatalf("memo entries = %v, err %v", entries, err)
	}
	for _, entry := range entries {
		if err := os.WriteFile(filepath.Join(cache, "gofresh", testingScanDirName, entry.Name()), []byte("corrupt"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	recomputed, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	recomputed.SetMemoScope("scope-a")
	if _, err := recomputed.maximalTestingTypeEffects("example.com/tscan"); err != nil {
		t.Fatal(err)
	}
	if *loads != 4 {
		t.Fatal("a corrupt entry served")
	}
}
