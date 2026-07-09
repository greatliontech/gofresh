package syscallbinding

import (
	"os"
	"syscall"
	"testing"
)

var initBytes []byte

func load() []byte {
	b, _ := os.ReadFile("link")
	return b
}

func init() {
	_ = syscall.Unlink("link")
	_ = syscall.Symlink("pre.txt", "link")
	initBytes = load()
}

func BenchmarkSyscallBinding(b *testing.B) {
	_ = syscall.Unlink("link")
	_ = syscall.Symlink("post.txt", "link")
	for b.Loop() {
		_ = len(initBytes) + len(load())
	}
}
