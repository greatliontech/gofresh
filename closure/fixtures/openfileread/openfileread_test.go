package openfileread

import (
	"os"
	"testing"
)

func BenchmarkOpenFileRead(b *testing.B) {
	for b.Loop() {
		f, _ := os.OpenFile("fixture.txt", os.O_RDONLY, 0)
		if f != nil {
			_ = f.Close()
		}
	}
}
