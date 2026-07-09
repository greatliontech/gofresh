package initcwd

import (
	"os"
	"syscall"
	"testing"
)

func init() {
	_ = syscall.Chdir("data")
}

func BenchmarkInitCWD(b *testing.B) {
	for b.Loop() {
		_, _ = os.ReadFile("fixture.txt")
	}
}
