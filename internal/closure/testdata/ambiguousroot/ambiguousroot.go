// Package ambiguousroot declares a harness root name in BOTH test
// variants: the binary runs one of the two colliders, and a rooted-flow
// inventory over the binary cannot say which — the tombstoned root
// leaves the package's inventory incomplete.
package ambiguousroot

// Size reports a constant.
func Size() int { return 1 }
