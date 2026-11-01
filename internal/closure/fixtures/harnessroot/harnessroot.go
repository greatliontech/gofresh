package harnessroot

// Prod is a pure production function: it reaches no test setup and no I/O, so its
// closure is verifiable — unless the test main is wrongly rooted into it.
func Prod() int { return 7 }
