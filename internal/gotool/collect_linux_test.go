//go:build linux && !android

package gotool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunnerContainsPreparedProcessGroupDescendants(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "exited"} {
		t.Run(mode, func(t *testing.T) {
			bin := t.TempDir()
			pidFile := filepath.Join(bin, "pid")
			script := "#!/bin/sh\n[ \"$1 $2\" = 'env -json' ] || exit 2\nsleep 60 &\nchild=$!\nprintf '%s\\n' \"$child\" > \"$GOFRESH_QUERY_PID\"\nwait\n"
			if mode == "exited" {
				script = strings.Replace(script, "wait\n", "printf '%s\\n' '{\"GOVERSION\":\"go1.99.0\"}'\nexit 0\n", 1)
			}
			if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("GOFRESH_QUERY_PID", pidFile)
			ctx, cancel := context.WithCancel(t.Context())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 500*time.Millisecond)
			}
			defer cancel()
			done := make(chan error, 1)
			env, err := NormalizeEnv(os.Environ())
			if err != nil {
				t.Fatal(err)
			}
			runner := Runner{
				Prepare: func(cmd *exec.Cmd) {
					cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
					cmd.WaitDelay = 300 * time.Millisecond
					cmd.Cancel = func() error {
						if cmd.Process == nil {
							return os.ErrProcessDone
						}
						if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
							return os.ErrProcessDone
						} else {
							return err
						}
					}
				},
			}
			reader := NewEnvReader(runner, t.TempDir(), env)
			go func() {
				snapshot, err := reader.Snapshot(ctx)
				if mode == "exited" && err == nil && snapshot.Value("GOVERSION") != "go1.99.0" {
					err = fmt.Errorf("lost the complete environment answer")
				}
				done <- err
			}()
			var pid int
			limit := time.Now().Add(2 * time.Second)
			for time.Now().Before(limit) {
				data, err := os.ReadFile(pidFile)
				if err == nil {
					pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
					if pid > 0 {
						break
					}
				}
				time.Sleep(5 * time.Millisecond)
			}
			if pid <= 0 {
				t.Fatal("query never started its descendant")
			}
			child, err := os.FindProcess(pid)
			if err != nil {
				t.Fatal(err)
			}
			defer child.Release()
			defer child.Kill()
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				if mode == "exited" {
					if err != nil {
						t.Fatalf("complete answer was not salvaged: %v", err)
					}
				} else if err == nil || ctx.Err() == nil {
					t.Fatalf("query returned without its cancellation: %v, %v", err, ctx.Err())
				}
			case <-time.After(6 * time.Second):
				_ = child.Kill()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("query did not return after cleanup")
				}
				t.Fatal("query ignored cancellation while a descendant held its pipe")
			}
			limit = time.Now().Add(time.Second)
			for {
				data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
				if os.IsNotExist(err) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				_, suffix, ok := strings.Cut(string(data), ") ")
				if ok && strings.HasPrefix(suffix, "Z ") {
					break
				}
				if time.Now().After(limit) {
					t.Fatalf("query left a live descendant: %s", data)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestDrainCollectedZeroWaitDelayDoesNotArmImmediateTimer(t *testing.T) {
	copied := make(chan error, 2)
	closed := false
	go func() {
		time.Sleep(15 * time.Millisecond)
		copied <- nil
		copied <- nil
	}()
	copyErr, timedOut := drainCollected(copied, 0, func() { closed = true })
	if copyErr != nil || timedOut || closed {
		t.Fatalf("drainCollected(wait=0) = (%v, timedOut=%v, closed=%v), want (nil, false, false)", copyErr, timedOut, closed)
	}
}
