package flagregalias

import "flag"

// An init that escapes the registered storage's address into another
// package variable creates an alias the mark cannot follow: the
// startup-flow reference refusal blocks it at the escape site, so the
// subject's laundered read (*q) can never prove observable.
var (
	quiet bool
	q     *bool
)

func init() {
	flag.BoolVar(&quiet, "flagregalias.quiet", false, "fixture flag")
	q = &quiet
}

func Prod() bool { return *q }
