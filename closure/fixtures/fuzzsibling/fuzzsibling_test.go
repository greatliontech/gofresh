package fuzzsibling

import (
	"os"
	"testing"
)

func FuzzDecode(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = len(data)
	})
}

func TestSiblingRead(t *testing.T) {
	_, _ = os.ReadFile("fixture.txt")
}
