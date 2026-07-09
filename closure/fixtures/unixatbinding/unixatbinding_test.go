package unixatbinding

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

var initBytes []byte

func load() []byte {
	b, _ := os.ReadFile("link")
	return b
}

func init() {
	_ = unix.Unlinkat(unix.AT_FDCWD, "link", 0)
	_ = unix.Symlinkat("pre.txt", unix.AT_FDCWD, "link")
	initBytes = load()
}

func BenchmarkUnixAtBinding(b *testing.B) {
	_ = unix.Unlinkat(unix.AT_FDCWD, "link", 0)
	_ = unix.Symlinkat("post.txt", unix.AT_FDCWD, "link")
	for b.Loop() {
		_ = len(initBytes) + len(load())
	}
}
