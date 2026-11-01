package flagreginit

import "flag"

// Registration from a package initializer is a process-local registry
// mutation - admitted. The subject never references the registered
// variable; a reference would be the covert channel's read side and
// refuses (the flag-backed reference refusal).
var verbose = flag.Bool("flagreginit.verbose", false, "fixture flag")

func Prod() int { return 7 }
