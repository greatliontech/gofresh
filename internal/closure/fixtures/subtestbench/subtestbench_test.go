package subtestbench

import (
	"os"
	"testing"
)

func BenchmarkSubRead(b *testing.B) {
	b.Run("child", func(*testing.B) {
		_, _ = os.ReadFile("fixture.txt")
	})
}

func BenchmarkSubPure(b *testing.B) {
	b.Run("child", func(*testing.B) {
		_ = len("x")
	})
}
