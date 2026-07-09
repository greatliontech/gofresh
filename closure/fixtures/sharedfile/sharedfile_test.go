package sharedfile

import (
	"os"
	"testing"
)

var initBytes []byte

func load() []byte {
	b, _ := os.ReadFile("fixture.txt")
	return b
}

func init() {
	initBytes = load()
}

func BenchmarkSharedFile(b *testing.B) {
	for b.Loop() {
		_ = len(initBytes) + len(load())
	}
}
