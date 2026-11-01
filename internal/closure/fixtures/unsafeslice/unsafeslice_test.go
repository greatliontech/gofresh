package unsafeslice

import (
	"testing"
	"unsafe"
)

// TestSliceHeader's unsafe.Slice site carries no unsafe.Pointer-typed
// value - operands are a *byte and a length, the result a []byte - so
// the subject walk's type-graph arm cannot price it and the package
// scan must keep blocking: an out-of-bounds read through the fabricated
// slice is a testlog-invisible input.
func TestSliceHeader(*testing.T) {
	var b byte
	s := unsafe.Slice(&b, 1)
	_ = s[0]
}
