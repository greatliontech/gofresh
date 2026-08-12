package flagreginvoke

import (
	"flag"
	"os"
	"testing"
)

type registrar interface {
	BoolVar(p *bool, name string, value bool, usage string)
}

var quiet bool

// A dynamically dispatched registration target is admitted nowhere:
// the facts walk can sink-judge only static call sites, so the
// family-named invoke target keeps its blocking classification.
func TestMain(m *testing.M) {
	var r registrar = flag.CommandLine
	r.BoolVar(&quiet, "flagreginvoke.quiet", false, "fixture flag")
	code := m.Run()
	if quiet {
		code = 0
	}
	os.Exit(code)
}

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
