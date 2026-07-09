package unixfchdir

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

var initBytes []byte

func load() []byte {
	b, _ := os.ReadFile("fixture.txt")
	return b
}

func chdir(name string) {
	fd, err := unix.Open(name, unix.O_RDONLY, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	_ = unix.Fchdir(fd)
}

func init() {
	chdir("pre")
	initBytes = load()
}

func BenchmarkUnixFchdir(b *testing.B) {
	chdir("../post")
	for b.Loop() {
		_ = len(initBytes) + len(load())
	}
}
