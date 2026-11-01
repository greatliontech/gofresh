package initstdcallback

import (
	"os"
	"sort"
	"testing"
)

var initData []byte

func init() {
	xs := []int{2, 1}
	sort.Slice(xs, func(i, j int) bool {
		initData, _ = os.ReadFile("pre.txt")
		return xs[i] < xs[j]
	})
}

func BenchmarkInitStdCallback(b *testing.B) {
	for b.Loop() {
		_ = len(initData)
	}
}
