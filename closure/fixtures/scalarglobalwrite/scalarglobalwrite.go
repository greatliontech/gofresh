// Package scalarglobalwrite is the named anchor for the scalar-global
// mutation boundary: a plain package-level variable sits outside the
// shared-dynamic-state carrier net by clause, its direct mutation is
// admitted (per-process-deterministic content the whole-graph hash
// covers; the admission's enforcement is the view-tier plain-data
// builder test), and an unsafe-mediated mutation refuses on the
// channel it uses — an unsafe.Pointer-typed value refuses at the
// subject walk, while unsafe.Slice and kin, whose call sites carry no
// such value, keep the package-scan block. The laundered-address
// entry shape (a plain uintptr crossing the signature) is pinned by
// the closure-verdict test for a uintptr address input — the
// re-materializing conversion is the same walk tripwire, and go vet's
// unsafeptr check keeps that variant out of tree.
package scalarglobalwrite

import "unsafe"

// Count is the non-carrier scalar global: no function, interface,
// channel, or unsafe pointer anywhere in its type.
var Count int

// BumpDirect is the admitted twin: a direct write to the scalar.
func BumpDirect() int {
	Count++
	return Count
}

// BumpUnsafe mutates the global through an unsafe.Pointer-typed
// value — the subject walk's channel.
func BumpUnsafe() int {
	p := (*int)(unsafe.Pointer(&Count))
	*p++
	return Count
}
