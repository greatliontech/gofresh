package unixcwd

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func init() {
	_ = unix.Chdir("data")
}

func BenchmarkUnixCWD(b *testing.B) {
	for b.Loop() {
		_, _ = os.ReadFile("fixture.txt")
	}
}
