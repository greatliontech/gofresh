package flagregescape

import "flag"

// The registration target reaches the call through a helper parameter:
// a sink the registration-facts judgment cannot trace to a
// package-level variable. The package poisons - every subject blocks -
// because an admitted registration with unguarded storage would be an
// unobserved input channel.
var quiet bool

func register(p *bool) { flag.BoolVar(p, "flagregescape.quiet", false, "fixture flag") }

func init() { register(&quiet) }

func Prod() int { return 7 }
