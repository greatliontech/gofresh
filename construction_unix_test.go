//go:build unix

package gofresh

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/gotool"
)

// A vouch input must not be opened once configuration has cancelled the entry.
// A FIFO makes an otherwise silent post-cancellation read observable without
// claiming cancellation can interrupt a filesystem call that already started.
func TestConstructionCancellationPrecedesVouchObservation(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, RepositoryVouchFile)
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := NewContext(ctx, WithDir(dir), func(*Engine) { cancel() })
		done <- err
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("construction: %v", err)
			}
			return
		case <-tick.C:
			// A nonblocking writer succeeds only if construction opened the
			// read end. Closing it releases that erroneous read as EOF.
			fd, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0600)
			if err == nil {
				_ = syscall.Close(fd)
				t.Error("construction opened the vouch input after cancellation")
			} else if !errors.Is(err, syscall.ENXIO) {
				t.Fatal(err)
			}
		case <-deadline.C:
			t.Fatal("cancelled construction did not end")
		}
	}
}

// Preparation cancellation reaches the actual query, including a cancellation
// after command preparation but before spawn and one while the child runs.
func TestConstructionContextOwnsTheEnvironmentQuery(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"before-spawn", "running", "completed-answer"} {
		t.Run(mode, func(t *testing.T) {
			during := mode != "before-spawn"
			dir := t.TempDir()
			started := filepath.Join(dir, "started")
			release := filepath.Join(dir, "release")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runner := gotool.Runner{Containment: &gotool.Containment{}, Prepare: func(cmd *exec.Cmd) {
				if strings.Join(cmd.Args[1:], " ") != "env -json" {
					t.Errorf("unexpected preparation query: %v", cmd.Args)
				}
				cmd.Path = shell
				cmd.Args = []string{shell, "-c", `printf started > "$1"; while ! test -f "$2"; do sleep 0.01; done; printf '{"GOFLAGS":""}'`, "constructor-query", started, release}
				if mode == "completed-answer" {
					// A policy may retain a successfully exiting child's answer.
					// That answer does not keep its cancelled owner alive.
					cmd.Cancel = func() error {
						if err := os.WriteFile(release, nil, 0600); err != nil {
							return err
						}
						return os.ErrProcessDone
					}
				}
				if !during {
					cancel()
				}
			}}
			if !during {
				if err := os.WriteFile(release, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			type result struct {
				engine *Engine
				err    error
			}
			done := make(chan result, 1)
			go func() {
				e, err := NewContext(ctx, WithDir(dir), WithGoRunner(runner))
				done <- result{e, err}
			}()
			// Releasing the shim also cleans up a background-context mutant:
			// the deciding failure is the assertion, never an oracle timeout.
			defer func() { _ = os.WriteFile(release, nil, 0600) }()
			if during {
				deadline := time.NewTimer(5 * time.Second)
				defer deadline.Stop()
				tick := time.NewTicker(5 * time.Millisecond)
				defer tick.Stop()
			waitForStart:
				for {
					if _, err := os.Stat(started); err == nil {
						break
					}
					select {
					case <-tick.C:
					case r := <-done:
						t.Fatalf("constructor returned before query started: %v", r.err)
					case <-deadline.C:
						t.Error("query did not start")
						break waitForStart
					}
				}
				cancel()
			}
			var r result
			select {
			case r = <-done:
			case <-time.After(2 * time.Second):
				t.Error("cancelled construction kept its query running")
				if err := os.WriteFile(release, nil, 0600); err != nil {
					t.Fatal(err)
				}
				select {
				case r = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("released query did not end")
				}
			}
			if r.engine != nil || !errors.Is(r.err, context.Canceled) {
				t.Fatalf("cancelled construction: engine returned=%t error=%v", r.engine != nil, r.err)
			}
			if !during {
				if _, err := os.Stat(started); !os.IsNotExist(err) {
					t.Fatalf("query spawned after cancellation: %v", err)
				}
			}
		})
	}
}
