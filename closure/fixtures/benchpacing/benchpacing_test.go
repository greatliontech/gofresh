package benchpacing

import (
	"os"
	"testing"
)

func BenchmarkLoopOnly(b *testing.B) {
	n := 0
	for b.Loop() {
		n++
	}
	_ = n
}

func BenchmarkLoopReadsFile(b *testing.B) {
	for b.Loop() {
		if _, err := os.ReadFile("baseline.txt"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResultField(b *testing.B) {
	r := testing.BenchmarkResult{N: 3}
	for b.Loop() {
		_ = r.N
	}
}

func BenchmarkReporting(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(8)
	b.ReportMetric(1, "widgets/op")
}
