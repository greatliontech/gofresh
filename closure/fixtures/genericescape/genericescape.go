// Package genericescape pins that a generic method reached only by interface
// escape (never called, so not RTA-reachable) is still analyzed. The
// benchmark boxes Box[int] into an interface; addInterfaceMethodSet enqueues
// the instantiated method, whose own object carries no source decl node —
// its generic origin must be resolved and scanned, or the method's effect
// stays invisible and a proof over it is a false-valid.
package genericescape

import "os"

type Box[T any] struct{ v T }

func (b Box[T]) Secret() int { return 4096 + len(os.Getenv("ESCAPE")) }

var sink any

func leak(x any) { sink = x }
