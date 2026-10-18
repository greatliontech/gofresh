//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)

package assemblycapture

import "os"

// Current-action acquisition is unavailable on these platforms. This reader
// serves the source-selection observation, whose opened descriptor is checked
// by readObservation before any content is consumed.
func openObservationFile(path string) (*os.File, error) { return os.Open(path) }
