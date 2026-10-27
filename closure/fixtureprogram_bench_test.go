package closure

import (
	"testing"

	progpkg "github.com/greatliontech/gofresh/closure/internal/program"
)

// BenchmarkFixturePreparation compares identical source-loading/SSA workloads.
// Each iteration owns a new generation, each target a fresh SSA program. Neither
// arm computes or serves proof memos. Typed-graph retention lasts one iteration;
// allocation totals are not a measurement of its live or peak resident memory.
//
//gofresh:pure
func BenchmarkFixturePreparation(b *testing.B) {
	const base = "github.com/greatliontech/gofresh/closure/fixtures/"
	paths := []string{base + "observable", base + "external", base + "initfile", base + "rootcollision/bench"}
	h, err := newAt("")
	if err != nil {
		b.Fatal(err)
	}
	b.Run("independent", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, path := range paths {
				if _, err := progpkg.Load(b.Context(), h.dir, h.packageEnv, h.buildFlags, path); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("prepared", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			prepared, err := progpkg.Prepare(b.Context(), h.dir, h.packageEnv, h.buildFlags, paths...)
			if err != nil {
				b.Fatal(err)
			}
			for _, path := range paths {
				if _, err := prepared.Build(b.Context(), path); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}
