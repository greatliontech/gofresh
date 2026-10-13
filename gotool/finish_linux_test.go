//go:build linux && !android

package gotool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCollectedRunSweepsAfterTheLeaderExits(t *testing.T) {
	for _, mode := range []string{"success", "failure", "closed-pipes"} {
		t.Run(mode, func(t *testing.T) {
			pids := filepath.Join(t.TempDir(), "pids")
			t.Setenv("QUERY_PIDS", pids)
			exit := 0
			if mode == "failure" {
				exit = 7
			}
			sleep := "sleep 60 &"
			if mode == "closed-pipes" {
				sleep = "sleep 60 </dev/null >/dev/null 2>&1 &"
			}
			env := shimGo(t, fmt.Sprintf("%s\nprintf '%%s %%s' $$ $! > \"$QUERY_PIDS\"\necho go1.99.0\nexit %d\n", sleep, exit))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type result struct {
				data []byte
				err  error
			}
			done := make(chan result, 1)
			go func() {
				data, err := (Runner{Containment: &Containment{WaitDelay: time.Second}}).Run(ctx, "", env, "env", "GOVERSION")
				done <- result{data, err}
			}()
			var leader, child int
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				data, _ := os.ReadFile(pids)
				fields := strings.Fields(string(data))
				if len(fields) == 2 {
					leader, _ = strconv.Atoi(fields[0])
					child, _ = strconv.Atoi(fields[1])
					if leader > 0 && child > 0 {
						break
					}
				}
				time.Sleep(time.Millisecond)
			}
			if child <= 0 {
				t.Fatal("query did not start its child")
			}
			process, err := os.FindProcess(child)
			if err != nil {
				t.Fatal(err)
			}
			defer process.Release()
			defer process.Kill()
			select {
			case got := <-done:
				if mode == "failure" {
					var failure *exec.ExitError
					if !errors.As(got.err, &failure) || failure.ExitCode() != 7 || len(got.data) != 0 {
						t.Fatalf("failure = %q %v", got.data, got.err)
					}
				} else if mode == "closed-pipes" {
					if got.err != nil || strings.TrimSpace(string(got.data)) != "go1.99.0" {
						t.Fatalf("normal output = %q %v", got.data, got.err)
					}
				} else if !errors.Is(got.err, exec.ErrWaitDelay) || strings.TrimSpace(string(got.data)) != "go1.99.0" {
					t.Fatalf("salvage = %q %v", got.data, got.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("query did not finish its pipe drain")
			}
			deadline = time.Now().Add(time.Second)
			for {
				data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child))
				if os.IsNotExist(err) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				_, state, _ := strings.Cut(string(data), ") ")
				if strings.HasPrefix(state, "Z ") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("pipe holder survived: %s", data)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestCollectedRunHoldsIdentityThroughCancellationAndSweep(t *testing.T) {
	for _, failSweep := range []bool{false, true} {
		t.Run(fmt.Sprint(failSweep), func(t *testing.T) {
			env := shimGo(t, "echo go1.99.0\nexit 0\n")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cancelled := make(chan struct{})
			var notified sync.Once
			var signals atomic.Int32
			r := Runner{Containment: &Containment{}, Prepare: func(cmd *exec.Cmd) {
				original := cmd.Cancel
				cmd.Cancel = func() error {
					signals.Add(1)
					defer notified.Do(func() { close(cancelled) })
					return original()
				}
			}}
			cmd, err := r.Command(ctx, "", env, "env", "GOVERSION")
			if err != nil {
				t.Fatal(err)
			}
			var out, errout bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errout
			held := func(pid int) error {
				data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				if err != nil {
					return err
				}
				_, state, _ := strings.Cut(string(data), ") ")
				if !strings.HasPrefix(state, "Z ") {
					return fmt.Errorf("leader identity not held: %s", data)
				}
				return nil
			}
			sweeps := 0
			err = runContained(cmd, func(pid int) error {
				if err := waitExited(pid); err != nil {
					return err
				}
				if err := held(pid); err != nil {
					return err
				}
				cancel()
				select {
				case <-cancelled:
				case <-time.After(3 * time.Second):
					return fmt.Errorf("cancellation did not run before cleanup")
				}
				return nil
			}, func(pid int) error {
				sweeps++
				if err := held(pid); err != nil {
					return err
				}
				if failSweep {
					return unix.EPERM
				}
				return killGroup(pid)
			})
			if sweeps != 1 || cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
				t.Fatalf("sweeps=%d state=%v err=%v", sweeps, cmd.ProcessState, err)
			}
			if failSweep {
				if !errors.Is(err, unix.EPERM) || Salvaged(context.Background(), err) {
					t.Fatalf("cleanup refusal = %v", err)
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel = %v", err)
			}
			if err := cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) || signals.Load() != 1 {
				t.Fatalf("late signal attempted: %v, calls=%d", err, signals.Load())
			}
		})
	}
	t.Run("never-started", func(t *testing.T) {
		cmd, err := (Runner{Containment: &Containment{}}).Program(t.Context(), "", os.Environ(), filepath.Join(t.TempDir(), "absent"))
		if err != nil {
			t.Fatal(err)
		}
		unexpected := func(int) error { t.Error("attempted process action without a started child"); return nil }
		if err := runContained(cmd, unexpected, unexpected); err == nil {
			t.Fatal("absent program started")
		}
	})
}

func TestCollectedCleanupRefusalCannotAuthorizeSalvage(t *testing.T) {
	env := shimGo(t, "echo go1.99.0\nsleep 60 &\nexit 0\n")
	cmd, err := (Runner{Containment: &Containment{WaitDelay: 50 * time.Millisecond}}).Command(t.Context(), "", env, "env", "GOVERSION")
	if err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errout
	err = runContained(cmd, waitExited, func(pid int) error {
		// Clean up the actual fixture, but expose a refused cleanup result.
		if err := killGroup(pid); err != nil {
			t.Fatal(err)
		}
		return unix.EPERM
	})
	if !errors.Is(err, unix.EPERM) || errors.Is(err, exec.ErrWaitDelay) || Salvaged(t.Context(), err) || cmd.ProcessState == nil || !cmd.ProcessState.Success() {
		t.Fatalf("cleanup refusal became the wait-delay form: %v", err)
	}
}

func TestCollectedDrainAndOwnershipFailure(t *testing.T) {
	t.Run("already-drained", func(t *testing.T) {
		for _, failure := range []error{nil, io.ErrUnexpectedEOF} {
			copied := make(chan error, 2)
			copied <- failure
			copied <- nil
			err, expired := drainCollected(copied, time.Nanosecond, func() { t.Error("closed an already-drained pipe") })
			if expired || !errors.Is(err, failure) {
				t.Fatalf("completed drain = %v, expired=%t", err, expired)
			}
		}
	})
	t.Run("ownership-failure", func(t *testing.T) {
		env := shimGo(t, "echo go1.99.0\nsleep 60\n")
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var signals atomic.Int32
		cmd, err := (Runner{Containment: &Containment{}, Prepare: func(cmd *exec.Cmd) {
			cmd.Cancel = func() error { signals.Add(1); return nil }
		}}).Command(ctx, "", env, "env", "GOVERSION")
		if err != nil {
			t.Fatal(err)
		}
		writing, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		defer once.Do(func() { close(release) })
		cmd.Stdout = collectedWriter(func(p []byte) (int, error) {
			close(writing)
			<-release
			return len(p), nil
		})
		cmd.Stderr = io.Discard
		done := make(chan error, 1)
		go func() {
			done <- runContained(cmd, func(int) error {
				select {
				case <-writing:
					return unix.ECHILD
				case <-time.After(3 * time.Second):
					return fmt.Errorf("no output")
				}
			}, func(int) error { t.Error("swept without ownership"); return nil })
		}()
		select {
		case <-writing:
		case <-time.After(3 * time.Second):
			t.Fatal("no output")
		}
		// Handle-only failure cleanup kills the leader after closing the signal
		// gate. The blocked copier keeps us before the final sweep and Wait.
		deadline := time.Now().Add(3 * time.Second)
		for {
			data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", cmd.Process.Pid))
			_, state, _ := strings.Cut(string(data), ") ")
			if strings.HasPrefix(state, "Z ") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("failure cleanup did not kill the leader")
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
		if err := cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) || signals.Load() != 0 {
			t.Errorf("ownership failure left signalling enabled during drain: %v, %d", err, signals.Load())
		}
		// Injected ECHILD did not reap the actual leader. Its zombie still
		// owns the group, which the fixture can safely clean before releasing it.
		if err := killGroup(cmd.Process.Pid); err != nil {
			t.Error(err)
		}
		once.Do(func() { close(release) })
		select {
		case err = <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("failure did not return")
		}
		if !errors.Is(err, unix.ECHILD) {
			t.Fatalf("ownership refusal = %v", err)
		}
		if err := cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) || signals.Load() != 0 {
			t.Fatalf("ownership failure left signalling enabled: %v, %d", err, signals.Load())
		}
	})
}

type collectedWriter func([]byte) (int, error)

func (w collectedWriter) Write(p []byte) (int, error) { return w(p) }
