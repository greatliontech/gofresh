//go:build !linux

package resident

// hostMemory answers nothing: the reading has a Linux /proc form only,
// and an absent datum is the honest answer elsewhere.
func hostMemory() (Memory, bool) { return Memory{}, false }
