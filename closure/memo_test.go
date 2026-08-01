package closure

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func memoModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/memo\n\ngo 1.26\n")
	writeFile(t, dir, "memo.go", "package memo\n\nfunc Pure(x int) int { return x + 1 }\n")
	writeFile(t, dir, "memo_test.go", `package memo

import "testing"

func TestPure(t *testing.T) {
	if Pure(1) != 2 {
		t.Fatal("pure")
	}
}
`)
	return dir
}

// A memoized proof serves byte-equivalent results without loading the
// program (REQ-closure-observability-memo): the second hasher under the
// same scope and unchanged source emits no load or prove events and
// returns identical dispositions.
func TestObservabilityMemoServesEquivalentProofsWithoutLoading(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := memoModule(t)
	subjects := []Subject{
		{Package: "example.com/memo", Symbol: "Pure"},
		{Package: "example.com/memo", Symbol: "TestPure"},
		{Package: "example.com/memo", Symbol: "Missing"},
	}

	first, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	first.SetMemoScope("strategy@1|toolchain|build")
	cold, err := first.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}

	second, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	second.SetMemoScope("strategy@1|toolchain|build")
	loads := 0
	second.OnProgress(func(phase, _ string) {
		if phase == "load" || phase == "prove" {
			loads++
		}
	})
	warm, err := second.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if loads != 0 {
		t.Fatalf("warm batch emitted %d load/prove events, want the memo to skip the program", loads)
	}
	if len(warm) != len(cold) {
		t.Fatalf("warm results = %d, cold %d", len(warm), len(cold))
	}
	for subject, proof := range cold {
		if warm[subject] != proof {
			t.Fatalf("memoized proof for %s differs: cold %+v, warm %+v", subject.Symbol, proof, warm[subject])
		}
	}
}

// The memo misses on a different scope and on changed source: the key is
// the complete input identity (REQ-closure-observability-memo).
func TestObservabilityMemoMissesOnScopeAndSourceChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := memoModule(t)
	subjects := []Subject{{Package: "example.com/memo", Symbol: "Pure"}}

	first, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	first.SetMemoScope("scope-a")
	if _, err := first.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}

	otherScope, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	otherScope.SetMemoScope("scope-b")
	loads := 0
	otherScope.OnProgress(func(phase, _ string) {
		if phase == "load" {
			loads++
		}
	})
	if _, err := otherScope.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}
	if loads == 0 {
		t.Fatal("a different scope served from the memo")
	}

	src, err := os.ReadFile(filepath.Join(dir, "memo.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memo.go"), append(src, []byte("\nfunc Extra() int { return 9 }\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	moved, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	moved.SetMemoScope("scope-a")
	loads = 0
	moved.OnProgress(func(phase, _ string) {
		if phase == "load" {
			loads++
		}
	})
	if _, err := moved.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}
	if loads == 0 {
		t.Fatal("changed source served from the memo")
	}

	// Test-only source is part of the analyzed test binary: an edit that
	// moves only the test-variant compartment must miss exactly as a core
	// edit does — the analyzed program's bytes moved.
	testSrc, err := os.ReadFile(filepath.Join(dir, "memo_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memo_test.go"), append(testSrc, []byte("\nfunc TestExtra(t *testing.T) { t.Setenv(\"K\", \"V\") }\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	testMoved, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	testMoved.SetMemoScope("scope-a")
	loads = 0
	testMoved.OnProgress(func(phase, _ string) {
		if phase == "load" {
			loads++
		}
	})
	if _, err := testMoved.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}
	if loads == 0 {
		t.Fatal("a test-only source change served from the memo")
	}
}

// cancelWhenDirNonEmpty cancels every context consult once dir holds an
// entry — deterministic mid-group cancellation landing right after the
// first attribution slice's memo write.
type cancelWhenDirNonEmpty struct{ dir string }

func (c cancelWhenDirNonEmpty) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c cancelWhenDirNonEmpty) Done() <-chan struct{}       { return nil }
func (c cancelWhenDirNonEmpty) Value(any) any               { return nil }
func (c cancelWhenDirNonEmpty) Err() error {
	entries, err := os.ReadDir(c.dir)
	if err == nil && len(entries) > 0 {
		return context.Canceled
	}
	return nil
}

// TestObservabilityMemoKeepsCompletedSlicesOnDeadline pins the write
// granularity (REQ-closure-observability-memo): a deadline expiring
// mid-group forfeits only the interrupted slice's proofs — every
// completed slice persists and a later pass serves it from the memo.
func TestObservabilityMemoKeepsCompletedSlicesOnDeadline(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheRoot)
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/slices\n\ngo 1.26\n")
	count := maxAttributedSubjects + 2
	var source strings.Builder
	source.WriteString("package slices\n\n")
	subjects := make([]Subject, count)
	for i := range subjects {
		symbol := fmt.Sprintf("F%d", i)
		fmt.Fprintf(&source, "func %s() int { return %d }\n", symbol, i)
		subjects[i] = Subject{Package: "example.com/slices", Symbol: symbol}
	}
	writeFile(t, dir, "slices.go", source.String())

	first, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	first.SetMemoScope("scope-a")
	memoFiles := filepath.Join(cacheRoot, "gofresh", "observability")
	first.ctx = cancelWhenDirNonEmpty{dir: memoFiles}
	if _, err := first.ComputeObservabilityBatch(subjects); err == nil {
		t.Fatal("mid-group cancellation did not surface")
	}

	entries, err := os.ReadDir(memoFiles)
	if err != nil || len(entries) != 1 {
		t.Fatalf("memo entries = %v, err %v; want exactly one", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(memoFiles, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var entry memoEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if len(entry.Proofs) != maxAttributedSubjects {
		t.Fatalf("persisted proofs = %d, want the completed slice's %d", len(entry.Proofs), maxAttributedSubjects)
	}
	for i := range maxAttributedSubjects {
		if _, ok := entry.Proofs[fmt.Sprintf("F%d", i)]; !ok {
			t.Fatalf("completed slice's proof F%d missing from the memo", i)
		}
	}
	for i := maxAttributedSubjects; i < count; i++ {
		if _, ok := entry.Proofs[fmt.Sprintf("F%d", i)]; ok {
			t.Fatalf("interrupted slice's proof F%d persisted", i)
		}
	}

	second, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	second.SetMemoScope("scope-a")
	results, err := second.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != count {
		t.Fatalf("resumed batch results = %d, want %d", len(results), count)
	}
}
