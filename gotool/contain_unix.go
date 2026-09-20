//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package gotool

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// contain is the Unix arm of Containment: the child leads its own
// process group (Setpgid), so a cancellation kills the group — every
// descendant that would otherwise outlive the leader and hold its
// pipes — and an already-empty group (ESRCH: Wait reaped the leader
// before the cancellation was noticed) is the process-done case. With
// Quit true for the cancellation's cause the group is asked to quit
// first and killed after Grace.
func contain(ctx context.Context, cmd *exec.Cmd, c Containment) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = c.waitDelay()
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		group := -cmd.Process.Pid
		if c.Quit != nil && c.Quit(context.Cause(ctx)) {
			if err := syscall.Kill(group, syscall.SIGQUIT); err != nil {
				return processDone(err)
			}
			deadline := time.After(c.grace())
			tick := time.NewTicker(50 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-deadline:
					return processDone(syscall.Kill(group, syscall.SIGKILL))
				case <-tick.C:
					if err := processDone(syscall.Kill(group, 0)); errors.Is(err, os.ErrProcessDone) {
						return err
					}
				}
			}
		}
		return processDone(syscall.Kill(group, syscall.SIGKILL))
	}
}

func processDone(err error) error {
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
