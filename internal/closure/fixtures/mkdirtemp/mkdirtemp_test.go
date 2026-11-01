package mkdirtemp

import (
	"os"
	"testing"
)

func BenchmarkMkdirTemp(b *testing.B) {
	for b.Loop() {
		_, _ = os.MkdirTemp("", "pew-*")
	}
}
