package initstdhelper

import (
	"path/filepath"
	"testing"
)

var matches []string

func init() {
	matches, _ = filepath.Glob("fixtures/*")
}

func BenchmarkInitStdHelper(b *testing.B) {
	for b.Loop() {
		_ = len(matches)
	}
}
