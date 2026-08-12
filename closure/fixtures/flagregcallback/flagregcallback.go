package flagregcallback

import "flag"

// Callback-family registration (Var, TextVar, Func, BoolFunc) runs
// arbitrary code at flag.Parse: no sink judgment can bound what it
// writes, so the family keeps the audited-pure exclusion outright.
func init() {
	flag.BoolFunc("flagregcallback.trace", "fixture flag", func(string) error { return nil })
}

func Prod() int { return 7 }
