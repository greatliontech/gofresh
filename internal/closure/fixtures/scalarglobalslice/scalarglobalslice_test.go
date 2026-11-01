package scalarglobalslice

import "testing"

// TestSliceWrite mutates the scalar global through unsafe.Slice and
// must refuse at the package scan, the channel's only arm.
func TestSliceWrite(*testing.T) {
	_ = BumpSlice()
}
