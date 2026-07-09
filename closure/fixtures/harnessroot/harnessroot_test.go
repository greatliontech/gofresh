package harnessroot

import (
	"os"
	"testing"
)

// setup runs inside TestMain, before any benchmark, and reaches file I/O — an
// unverifiable (Class-B) dependence reachable only through the test harness.
func setup() {
	if f, err := os.Open("fixture.dat"); err == nil {
		f.Close()
	}
}

func TestMain(m *testing.M) {
	setup()
	os.Exit(m.Run())
}

// BenchmarkProd runs through the harness, so TestMain's setup (and its file I/O) is
// part of its closure.
func BenchmarkProd(b *testing.B) {
	for b.Loop() {
		_ = Prod()
	}
}
