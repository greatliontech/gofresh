package initfile

import (
	"os"
	"testing"
)

var initData []byte

func init() {
	initData, _ = os.ReadFile("fixture.txt")
}

func BenchmarkInitFile(b *testing.B) {
	for b.Loop() {
		_ = len(initData)
	}
}
