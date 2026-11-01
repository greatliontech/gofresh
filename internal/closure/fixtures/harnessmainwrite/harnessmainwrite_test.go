package harnessmainwrite

import (
	"os"
	"testing"
)

// TestMain performs an unobserved filesystem mutation: a write is not
// a bracketed observation input, so the test-main walk's per-effect
// classification blocks the proof with the write's own reason.
func TestMain(m *testing.M) {
	_ = os.WriteFile("out.txt", []byte("x"), 0o644)
	_ = os.Remove("out.txt")
	os.Exit(m.Run())
}

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
