package flagregsubject

import "flag"

// Registration reached from subject flow keeps the exclusion whatever
// its sink: the admission is tier-scoped to startup and test-main
// flow, so the subject-tier walk classifies flag.Bool itself - the
// traceable store keeps the package unpoisoned, pinning that the
// refusal comes from the walk's own classification.
var late *bool

func Prod() int {
	late = flag.Bool("flagregsubject.late", false, "fixture flag")
	return 7
}
