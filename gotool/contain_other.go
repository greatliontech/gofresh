//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris || windows)

package gotool

import (
	"context"
	"os/exec"
)

// contain on a platform with no process-group primitive keeps the
// plain spawn under the wait delay: the leader alone is the boundary.
func contain(_ context.Context, cmd *exec.Cmd, c Containment) {
	cmd.WaitDelay = c.waitDelay()
}
