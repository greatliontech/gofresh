package flagregmainread

import "flag"

// Registered storage read in user test-main flow: the implicit
// flag.Parse inside m.Run can have written it before the read, so the
// reference is the covert channel's read side - here it masks the
// harness exit code on command-line state the test log cannot audit.
var verbose = flag.Bool("flagregmainread.verbose", false, "fixture flag")

func Prod() int { return 7 }
