//go:build windows

package gotool

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// contain is the Windows arm of Containment: the child starts its own
// process group, and a cancellation ends the process tree under it
// (taskkill /T), falling back to the leader alone; Quit has no
// signal on Windows and the tree kill stands for it. WaitDelay bounds
// the reap as on every platform.
func contain(_ context.Context, cmd *exec.Cmd, c Containment) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	cmd.WaitDelay = c.waitDelay()
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		// The command's own environment names the system root — the
		// policy reads no ambient variable; the platform default stands
		// when the environment carries none.
		root, _ := LookupEnv(cmd.Env, "SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		kill := exec.CommandContext(ctx, filepath.Join(root, "System32", "taskkill.exe"), "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
		kill.Env = cmd.Env
		if err := kill.Run(); err == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
}
