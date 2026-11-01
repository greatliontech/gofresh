package sharedchdir

import (
	"os"
	"syscall"
	"testing"
)

var initBytes []byte

func load() []byte {
	b, _ := os.ReadFile("fixture.txt")
	return b
}

func init() {
	_ = syscall.Chdir("pre")
	initBytes = load()
}

func BenchmarkSharedChdir(b *testing.B) {
	_ = syscall.Chdir("../post")
	for b.Loop() {
		_ = len(initBytes) + len(load())
	}
}
