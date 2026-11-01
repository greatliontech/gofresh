package unsafesibling

import "unsafe"

// Grammar and Carry model an operator-grammar fixture file: unsafe
// references a clean sibling subject never reaches.
type Grammar unsafe.Pointer

func Carry(p unsafe.Pointer) unsafe.Pointer { return p }
