package openrootread

import (
	"os"
	"testing"
)

func BenchmarkRootOpenFileRead(b *testing.B) {
	root, _ := os.OpenRoot(".")
	if root != nil {
		defer root.Close()
	}
	for b.Loop() {
		f, _ := root.OpenFile("fixture.txt", os.O_RDONLY, 0)
		if f != nil {
			_ = f.Close()
		}
	}
}
