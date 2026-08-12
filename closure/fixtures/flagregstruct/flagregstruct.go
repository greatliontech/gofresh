package flagregstruct

import "flag"

// Registration into a field of a package-level struct roots at the
// struct variable through the field selection: the whole variable
// carries flag-registered state, so a subject-flow reference to it
// refuses while subjects that never touch it stay observable.
var cfg struct {
	Checks int
}

// An array-element target roots at the array variable through the
// index selection exactly as a field does.
var arr [2]int

// A value-family result stored through a field selection is the same
// sanctioned write: the selection computing the store's address passes
// with it.
var holder struct{ V *bool }

func init() {
	flag.IntVar(&cfg.Checks, "flagregstruct.checks", 100, "fixture flag")
	flag.IntVar(&arr[0], "flagregstruct.n", 1, "fixture flag")
	holder.V = flag.Bool("flagregstruct.v", false, "fixture flag")
}

func Prod() int { return 7 }

func ProdRead() int { return cfg.Checks }

// Passing the registered field's address to an ordinary call escapes
// it - only the registration write's own argument computation passes.
func deref(p *int) int { return *p }

func ProdEscape() int { return deref(&cfg.Checks) }
