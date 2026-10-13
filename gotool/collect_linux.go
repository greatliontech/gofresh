//go:build !android

package gotool

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

func runCollected(cmd *exec.Cmd, contained bool) error {
	if !contained {
		return cmd.Run()
	}
	return runContained(cmd, waitExited, killGroup)
}

func waitExited(pid int) error {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func killGroup(pid int) error {
	err := unix.Kill(-pid, unix.SIGKILL)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

// runContained retains the exited leader as a waitable child until the pipe
// drain and the last group signal finish. Reaping earlier would release its
// numeric process-group identity and make a later signal unsafe. Raw pipe files
// keep os/exec from owning an inaccessible copier/drain behind that reap.
func runContained(cmd *exec.Cmd, exited, sweep func(int) error) error {
	out, outWriter, err := os.Pipe()
	if err != nil {
		return err
	}
	defer out.Close()
	defer outWriter.Close()
	errout, errWriter, err := os.Pipe()
	if err != nil {
		return err
	}
	defer errout.Close()
	defer errWriter.Close()
	stdout, stderr := cmd.Stdout, cmd.Stderr
	cmd.Stdout, cmd.Stderr = outWriter, errWriter
	var signals sync.Mutex
	finished := false
	cancel := cmd.Cancel
	if cancel != nil {
		cmd.Cancel = func() error {
			signals.Lock()
			defer signals.Unlock()
			if finished {
				return os.ErrProcessDone
			}
			return cancel()
		}
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = outWriter.Close()
	_ = errWriter.Close()
	copied := make(chan error, 2)
	go func() { _, err := io.Copy(stdout, out); copied <- err }()
	go func() { _, err := io.Copy(stderr, errout); copied <- err }()
	ownershipErr := exited(cmd.Process.Pid)
	if ownershipErr != nil {
		signals.Lock()
		finished = true
		signals.Unlock()
		// No group signal without the unreaped-child premise. The process
		// handle can still end its own leader without a numeric identity guess.
		_ = cmd.Process.Kill()
	}
	copyErr, timedOut := drainCollected(copied, cmd.WaitDelay, func() { _ = out.Close(); _ = errout.Close() })
	// A Cancel already in flight finishes before the last sweep. Later calls
	// are inert before Wait is allowed to release the leader's identity.
	signals.Lock()
	finished = true
	var sweepErr error
	if ownershipErr == nil {
		sweepErr = sweep(cmd.Process.Pid)
	}
	signals.Unlock()
	waitErr := cmd.Wait()
	if err := errors.Join(ownershipErr, sweepErr); err != nil {
		// Do not wrap a drain sentinel into a cleanup refusal: structured
		// readers would otherwise mistake it for an admissible salvage.
		return fmt.Errorf("containment: %w (command result: %v)", err, waitErr)
	}
	if waitErr != nil {
		return waitErr
	}
	if timedOut {
		return exec.ErrWaitDelay
	}
	return copyErr
}

func drainCollected(copied <-chan error, wait time.Duration, closePipes func()) (copyErr error, timedOut bool) {
	var timer *time.Timer
	var expired <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for remaining := 2; remaining > 0; {
		// An already completed drain is success even for a tiny WaitDelay.
		select {
		case err := <-copied:
			remaining--
			if copyErr == nil {
				copyErr = err
			}
			continue
		default:
		}
		if timer == nil {
			timer = time.NewTimer(wait)
			expired = timer.C
		}
		select {
		case err := <-copied:
			remaining--
			if copyErr == nil {
				copyErr = err
			}
		case <-expired:
			timedOut = true
			expired = nil
			closePipes()
		}
	}
	return copyErr, timedOut
}
