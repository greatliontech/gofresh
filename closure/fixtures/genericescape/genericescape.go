// Package genericescape pins that a generic method reached only by interface
// escape (never called, so not RTA-reachable) still has its body hashed. The
// benchmark boxes Box[int] into an interface; addInterfaceMethodSet enqueues the
// instantiated method, whose own object carries no source decl node — its generic
// origin must be resolved and hashed, or a body change is a false-valid.
package genericescape

type Box[T any] struct{ v T }

func (b Box[T]) Secret() int { return 4096 }

var sink any

func leak(x any) { sink = x }
