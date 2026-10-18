//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package assemblycapture

import (
	"os"
	"syscall"
)

// A namespace replacement can put a FIFO at any selected path. NONBLOCK applies
// to the actual open, before the descriptor's regular-file check; a preceding
// Stat would leave a replacement window. No no-follow or lexical cleaning is
// applied: the tool's symlink and component-resolution semantics are retained.
func openObservationFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
