package closure

import "testing"

// BenchmarkComputeObservabilityBatch measures the proof analyzer end to end
// over a mixed fixture set — the per-target cost a consumer's capture batch
// pays. Allocations are the tracked axis; the memo is disabled (no scope)
// so the analysis itself is measured.
func BenchmarkComputeObservabilityBatch(b *testing.B) {
	const base = "github.com/greatliontech/gofresh/closure/fixtures/"
	subjects := []Subject{
		{Package: base + "observable", Symbol: "TestReadFile"},
		{Package: base + "observable", Symbol: "TestGetenv"},
		{Package: base + "observablebad", Symbol: "TestOpenStat"},
		{Package: base + "observablefresh", Symbol: "TestFreshFileNameEscape"},
		{Package: base + "observablemutation", Symbol: "TestRemove"},
	}
	b.ReportAllocs()
	for b.Loop() {
		h, err := New()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := h.ComputeObservabilityBatch(subjects); err != nil {
			b.Fatal(err)
		}
	}
}
