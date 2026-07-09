package sharedglobal

import (
	"os"
	"testing"
)

var (
	path = "pre.txt"
	data []byte
)

func load() {
	data, _ = os.ReadFile(path)
}

func init() {
	load()
}

func BenchmarkSharedGlobal(b *testing.B) {
	path = "post.txt"
	for b.Loop() {
		load()
		_ = len(data)
	}
}
