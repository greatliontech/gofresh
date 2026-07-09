package testmainroot

import (
	"os"
	"testing"
)

var scale int
var sink int

func TestMain(m *testing.M) {
	scale = setup()
	os.Exit(m.Run())
}

func setup() int { return 1 }

func BenchmarkTestMainRoot(b *testing.B) {
	for b.Loop() {
		sink += scale
	}
}
