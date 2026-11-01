package sharedparam

import (
	"os"
	"testing"
)

var preBytes []byte

func load(name string) []byte {
	b, _ := os.ReadFile(name)
	return b
}

func init() {
	preBytes = load("pre.txt")
}

func BenchmarkSharedParam(b *testing.B) {
	for b.Loop() {
		_ = len(preBytes) + len(load("post.txt"))
	}
}
