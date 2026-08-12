package flagregmethod

import "flag"

// Method-form registration and the method-expression form judge the
// pointer argument past the receiver. The package still blocks at the
// scan tier - flag.CommandLine is an unaudited symbol - so these
// shapes pin the registration-facts judgment itself (the white-box
// facts assertions), not a subject verdict.
var (
	verbose bool
	quiet   bool
)

func init() {
	flag.CommandLine.BoolVar(&verbose, "flagregmethod.v", false, "fixture flag")
	reg := (*flag.FlagSet).BoolVar
	reg(flag.CommandLine, &quiet, "flagregmethod.q", false, "fixture flag")
}

func Prod() int { return 7 }
