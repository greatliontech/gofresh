package createtemp

import (
	"os"
	"testing"
)

func BenchmarkCreateTemp(b *testing.B) {
	for b.Loop() {
		f, _ := os.CreateTemp("", "pew-*")
		if f != nil {
			_ = f.Close()
		}
	}
}
