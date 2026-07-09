package mkdir

import (
	"os"
	"testing"
)

func BenchmarkMkdir(b *testing.B) {
	for b.Loop() {
		_ = os.Mkdir("scratch", 0o700)
	}
}
