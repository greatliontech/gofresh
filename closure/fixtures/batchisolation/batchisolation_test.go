package batchisolation

import (
	"os"
	"testing"
)

func testMainHelper() { _ = os.Getenv("GOFRESH_BATCH_TEST") }

func TestStandardDynamic(t *testing.T) {
	var value interface{ TempDir() string } = t
	_ = value.TempDir()
}

func TestMain(m *testing.M) {
	testMainHelper()
	os.Exit(m.Run())
}

func BenchmarkHarness(b *testing.B) {
	for b.Loop() {
		_ = startupValue
	}
}

func BenchmarkSibling(b *testing.B) {
	for b.Loop() {
		benchmarkSiblingHelper()
	}
}

func benchmarkSiblingHelper() {}
