package tempdir

import "testing"

func BenchmarkTempDir(b *testing.B) {
	for b.Loop() {
		_ = b.TempDir()
	}
}
