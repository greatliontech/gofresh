package harnessmainfmt

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

// The writer-sink admission holds in test-main flow exactly as in the
// other tiers: a format into a locally constructed in-memory sink is
// value computation, not an effect.
func TestMain(m *testing.M) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "setup %d", Prod())
	_ = b.Len()
	os.Exit(m.Run())
}

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
