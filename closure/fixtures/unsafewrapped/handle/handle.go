// Package handle wraps an opaque pointer whose unsafe payload is visible
// only through the named type's underlying structure: no exported path
// produces an unsafe.Pointer-typed value, so an analysis that stops at the
// named type without walking its underlying misses the fact entirely.
package handle

import "unsafe"

// Handle carries an opaque pointer.
type Handle struct {
	p unsafe.Pointer
}

// New returns an empty handle without touching the pointer field.
func New() Handle { return Handle{} }

// Size reports a fixed size without touching the pointer field.
func (h Handle) Size() int { return 1 }
