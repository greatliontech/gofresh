// Package scalarglobalslice is the scalar-global boundary's
// unsafe.Slice channel, deliberately its own package: the call site
// carries no unsafe.Pointer-typed value the subject walk can price,
// so the refusal is the package scan's — and that block is
// package-wide (only the unsafe.Pointer class is narrowed to subject
// attribution), which is why this channel cannot share
// scalarglobalwrite's package without pre-blocking its clean
// direct-write subject.
package scalarglobalslice

import "unsafe"

// Count is the non-carrier scalar global.
var Count int

// BumpSlice mutates the global with NO unsafe.Pointer-typed value
// anywhere in the body (operands *int and a length, result []int).
func BumpSlice() int {
	s := unsafe.Slice(&Count, 1)
	s[0]++
	return Count
}
