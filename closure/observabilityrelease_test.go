package closure

import "testing"

// TestObservabilityBatchReleasesPrograms pins the bounded-peak discipline:
// programs are per-package test binaries no later group can reuse, so the
// batch releases each group's whole-program SSA with the group — peak
// memory follows the largest single binary, never the batch's package
// count.
func TestObservabilityBatchReleasesPrograms(t *testing.T) {
	const base = "github.com/greatliontech/gofresh/closure/fixtures/"
	subjects := []Subject{
		{Package: base + "observable", Symbol: "TestReadFile"},
		{Package: base + "observablestat", Symbol: "TestStat"},
	}
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	results, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(subjects) {
		t.Fatalf("results = %d, want %d", len(results), len(subjects))
	}
	if len(h.progs) != 0 {
		retained := make([]string, 0, len(h.progs))
		for pkg := range h.progs {
			retained = append(retained, pkg)
		}
		t.Fatalf("batch retained %d whole-program SSAs: %v", len(retained), retained)
	}
}

// TestObservabilityBatchReleasesProgramOnUnrootedGroup pins the release on
// the all-unrooted exit: the group loaded a program to discover its
// subjects cannot root, and that program is released like any other.
func TestObservabilityBatchReleasesProgramOnUnrootedGroup(t *testing.T) {
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/observable"
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	results, err := h.ComputeObservabilityBatch([]Subject{{Package: pkg, Symbol: "NoSuchSubject"}})
	if err != nil {
		t.Fatal(err)
	}
	if proof := results[Subject{Package: pkg, Symbol: "NoSuchSubject"}]; proof.Observable {
		t.Fatalf("unrooted subject granted a proof: %+v", proof)
	}
	if len(h.progs) != 0 {
		t.Fatalf("all-unrooted group retained %d programs", len(h.progs))
	}
}
