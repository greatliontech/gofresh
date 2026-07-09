package dep

import "testing"

const DepOnly = 1

func Use() {}

func BenchmarkSame(b *testing.B) {
	for b.Loop() {
		_ = DepOnly
	}
}
