package testmainruntimefile

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func BenchmarkTestMainRuntimeFile(b *testing.B) {
	for b.Loop() {
		_, _ = os.ReadFile("fixture.txt")
	}
}
