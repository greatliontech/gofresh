package nativeproof

import (
	"errors"
	"math"
	"testing"
)

// The benchmark fixture is built normally once per benchmark setup, outside the
// timed region. All profiles use the same seven positives and two actual wrapper
// refusals as TestDefaultOptimizedCompilerArtifact; no budget or grammar changes
// distinguish the populations. Run exclusively under the repository's benchmark
// lock policy. These benchmarks contain no wall-clock assertions.
func BenchmarkNativeImageParse(b *testing.B) {
	raw, _, _ := buildCompilerFixture(b)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		im, err := NewImage(b.Context(), raw)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkImage = im
	}
}

var benchmarkImage *Image
var benchmarkCertificate Certificate

// Cold includes a fresh immutable image copy/hash/parse for each root query.
func BenchmarkNativeProofCold(b *testing.B) { benchmarkNativeRoots(b, true) }

// RepeatedRoots reuses one immutable image across roots and iterations. There is
// intentionally no checked-result memo: proposal and independent checking both
// run again, exposing their actual allocation/time cost to profiling.
func BenchmarkNativeProofRepeatedRoots(b *testing.B) { benchmarkNativeRoots(b, false) }

func benchmarkNativeRoots(b *testing.B, cold bool) {
	raw, _, entries := buildCompilerFixture(b)
	im, err := NewImage(b.Context(), raw)
	if err != nil {
		b.Fatal(err)
	}
	type root struct {
		name     string
		entry    uint64
		face     Interface
		accepted bool
	}
	var roots []root
	for _, k := range kernels {
		entry, ok := entries[kernelSymbol(k.name)]
		if !ok {
			b.Fatalf("fixture did not retain %s", k.name)
		}
		roots = append(roots, root{k.name, entry, face(k.inputs, k.results), true})
	}
	for _, name := range []string{"Count", "NormalizeVia"} {
		entry, ok := entries[kernelSymbol(name)]
		if !ok {
			b.Fatalf("fixture did not retain %s", name)
		}
		roots = append(roots, root{name, entry, face(Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}, Masks{RAX: math.MaxUint64}), false})
	}
	for _, r := range roots {
		b.Run(r.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				selected := im
				if cold {
					selected, err = NewImage(b.Context(), raw)
					if err != nil {
						b.Fatal(err)
					}
				}
				p, err := Propose(b.Context(), selected, r.entry, r.face)
				var c Certificate
				if err == nil {
					c, err = Check(b.Context(), selected, r.entry, r.face, p)
				}
				if r.accepted {
					if err != nil || c.checked == nil {
						b.Fatalf("accepted population changed: %v", err)
					}
				} else {
					var refusal *Refusal
					if !errors.As(err, &refusal) || refusal.Premise != "data-memory" || refusal.PC != r.entry || c.checked != nil {
						b.Fatalf("refused population changed: %v", err)
					}
				}
				benchmarkCertificate = c
			}
		})
	}
}
