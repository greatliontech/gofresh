package pathbinding

import (
	"os"
	"testing"
)

var initBytes []byte

func load() []byte {
	b, _ := os.ReadFile("link")
	return b
}

func init() {
	_ = os.Remove("link")
	_ = os.Symlink("pre.txt", "link")
	initBytes = load()
}

func BenchmarkPathBinding(b *testing.B) {
	_ = os.Remove("link")
	_ = os.Symlink("post.txt", "link")
	for b.Loop() {
		_ = len(initBytes) + len(load())
	}
}
