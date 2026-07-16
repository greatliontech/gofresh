package external

import (
	"os"
	"testing"
)

func BenchmarkReadFile(b *testing.B) {
	for b.Loop() {
		_, _ = os.ReadFile("fixture.txt")
	}
}

func TestReadFile(*testing.T) {
	_, _ = os.ReadFile("fixture.txt")
}
