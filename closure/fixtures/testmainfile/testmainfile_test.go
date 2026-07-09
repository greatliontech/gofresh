package testmainfile

import (
	"os"
	"testing"
)

var mainData []byte

func TestMain(m *testing.M) {
	mainData, _ = os.ReadFile("fixture.txt")
	os.Exit(m.Run())
}

func BenchmarkTestMainFile(b *testing.B) {
	for b.Loop() {
		_ = len(mainData)
	}
}
