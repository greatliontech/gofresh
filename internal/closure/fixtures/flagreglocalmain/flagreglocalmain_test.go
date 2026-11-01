package flagreglocalmain

import (
	"flag"
	"os"
	"testing"
)

// A registration result held in a local and read later is a sink the
// registration-facts judgment cannot trace: the package poisons, so
// the harness's post-run read of parsed state cannot slip through as
// an unobserved input channel.
func TestMain(m *testing.M) {
	v := flag.Bool("flagreglocalmain.v", false, "fixture flag")
	code := m.Run()
	if *v {
		code = 0
	}
	os.Exit(code)
}

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
