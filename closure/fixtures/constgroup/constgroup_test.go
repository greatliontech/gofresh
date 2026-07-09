package constgroup

import "testing"

const (
	Seed = iota
	Used
)

func BenchmarkConstGroup(b *testing.B) {
	for b.Loop() {
		_ = Used
	}
}
