package copyfs

import (
	"os"
	"testing"
	"testing/fstest"
)

func BenchmarkCopyFS(b *testing.B) {
	for b.Loop() {
		_ = os.CopyFS("out", fstest.MapFS{"x": {Data: []byte("x")}})
	}
}
