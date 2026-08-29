package scalarglobalwrite

import "testing"

// TestDirectWrite mutates the scalar global directly: no external
// effect, no carrier, no unsafe — the observability proof grants.
func TestDirectWrite(*testing.T) {
	_ = BumpDirect()
}

// TestUnsafeWrite mutates the same global through an
// unsafe.Pointer-typed value and must refuse at the subject tier
// (the widen path), never the package scan.
func TestUnsafeWrite(*testing.T) {
	_ = BumpUnsafe()
}
