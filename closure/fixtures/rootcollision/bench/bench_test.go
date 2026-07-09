package bench

import (
	"testing"

	"github.com/greatliontech/gofresh/closure/fixtures/rootcollision/dep"
)

const RealOnly = 2

func BenchmarkSame(b *testing.B) {
	dep.Use()
	for b.Loop() {
		_ = RealOnly
	}
}
