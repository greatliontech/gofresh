package closure

import (
	"os"
	"path/filepath"
	"testing"
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
}
