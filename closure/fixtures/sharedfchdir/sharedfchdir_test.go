//go:build !plan9

// Plan 9 has a different syscall.Open signature; this fixture exercises the
// descriptor-based POSIX-compatible call surface.
package sharedfchdir

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

func chdir(name string) {
	fd, err := syscall.Open(name, syscall.O_RDONLY, 0)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	_ = syscall.Fchdir(fd)
}

func init() {
	chdir("pre")
	initBytes = load()
}

func BenchmarkSharedFchdir(b *testing.B) {
	chdir("../post")
	for b.Loop() {
		_ = len(initBytes) + len(load())
	}
}
