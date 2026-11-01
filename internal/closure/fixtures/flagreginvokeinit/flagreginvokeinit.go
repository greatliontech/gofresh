package flagreginvokeinit

import "flag"

type registrar interface {
	BoolVar(p *bool, name string, value bool, usage string)
}

var quiet bool

// A dynamically dispatched registration target in startup flow keeps
// its blocking classification: the facts walk can sink-judge only
// static call sites, so admitting the invoke would leave the
// registered storage unguarded.
func init() {
	var r registrar = flag.CommandLine
	r.BoolVar(&quiet, "flagreginvokeinit.quiet", false, "fixture flag")
}

func Prod() int { return 7 }
