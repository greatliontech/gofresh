package flagregmethod

import "flag"

// Method-form registration and the method-expression form judge the
// pointer argument past the receiver: flag.CommandLine is an audited
// selector, the storage is marked, and a subject reading none of it
// proves observable. The white-box facts assertions pin the receiver
// judgment itself.
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
