//go:build linux && !android

package assemblycapture

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/gotool"
	"golang.org/x/sys/unix"
)

// boundaryFixture is a protocol peer, not a Packet constructor. It exercises
// the compiled private shim against actual processes and actual wait statuses.
func boundaryFixture(t *testing.T, dir string, observe bool) (string, <-chan boundaryStart, <-chan boundaryFinish) {
	t.Helper()
	socket := filepath.Join(dir, "boundary.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	starts := make(chan boundaryStart, 1)
	finishes := make(chan boundaryFinish, 1)
	done := make(chan struct{})
	t.Cleanup(func() { _ = listener.Close(); <-done })
	go func() {
		defer close(done)
		conn, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		var one [1]byte
		oob := make([]byte, unix.CmsgSpace(4))
		_, n, _, _, err := conn.ReadMsgUnix(one[:], oob)
		if err != nil {
			return
		}
		messages, err := unix.ParseSocketControlMessage(oob[:n])
		if err != nil {
			return
		}
		for _, message := range messages {
			fds, err := unix.ParseUnixRights(&message)
			if err != nil {
				return
			}
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
		}
		dec, enc := json.NewDecoder(conn), json.NewEncoder(conn)
		var start boundaryStart
		if dec.Decode(&start) != nil {
			return
		}
		starts <- start
		if enc.Encode(boundaryReply{Observe: observe}) != nil || !observe {
			return
		}
		var finish boundaryFinish
		if dec.Decode(&finish) != nil {
			return
		}
		finishes <- finish
		_ = enc.Encode(boundaryReply{})
	}()
	return socket, starts, finishes
}

func TestPrivateBoundaryForwardsDispositionAndStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("compiled private execution boundary")
	}
	dir := t.TempDir()
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	s := &Selection{request: Request{Env: env}, runner: contained(gotool.Runner{})}
	shim, err := buildShim(t.Context(), s, dir)
	if err != nil {
		t.Fatal(err)
	}
	// A shell intrinsically ignores SIGQUIT. Start a small Go process and exec
	// the system kill utility at its own PID: exec restores caught handlers to
	// kernel defaults, giving the signal-disposition test a real terminating
	// oracle without repeating the boundary's sigaction implementation.
	signalSource := filepath.Join(dir, "signal.go")
	put(t, signalSource, `package main
import("os";"strconv";"syscall")
func main(){if len(os.Args)!=2{os.Exit(126)};if syscall.Exec("/bin/kill",[]string{"kill","-"+os.Args[1],strconv.Itoa(os.Getpid())},os.Environ())!=nil{os.Exit(127)}}
`)
	signalTool := filepath.Join(dir, "signal-tool")
	signalEnv := gotool.SetEnv(env, "GOFLAGS", "")
	if _, err := s.runner.Run(t.Context(), dir, signalEnv, "build", "-o", signalTool, signalSource); err != nil {
		t.Fatal(err)
	}
	for _, observe := range []bool{false, true} {
		name := "exec"
		if observe {
			name = "observed"
		}
		t.Run(name, func(t *testing.T) {
			socket, starts, finishes := boundaryFixture(t, t.TempDir(), observe)
			command := exec.Command(shim, socket, "token", "/bin/sh", "-c", `read word; printf 'out:%s:%s:%s' "$1" "$BOUNDARY_TEST" "$word"; printf 'err:exact' >&2; exit 7`, "real-tool", "space value")
			command.Dir = dir
			command.Env = gotool.SetEnv(env, "BOUNDARY_TEST", "owned value")
			command.Stdin = strings.NewReader("stdin-value\n")
			var stdout, stderr strings.Builder
			command.Stdout = &stdout
			command.Stderr = &stderr
			err := command.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 7 {
				t.Fatalf("exit disposition=%v", err)
			}
			if stdout.String() != "out:space value:owned value:stdin-value" || stderr.String() != "err:exact" {
				t.Fatalf("streams: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			start := <-starts
			if start.CWD != dir || start.Tool != "/bin/sh" || start.Args[len(start.Args)-1] != "space value" {
				t.Fatalf("raw boundary: %+v", start)
			}
			if observe {
				finish := <-finishes
				if finish.Exit != 7 || finish.Signal != 0 {
					t.Fatalf("child disposition: %+v", finish)
				}
			}
		})
	}
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGABRT, syscall.SIGSEGV, syscall.SIGKILL} {
		t.Run("signal-"+strconv.Itoa(int(sig)), func(t *testing.T) {
			socket, _, finishes := boundaryFixture(t, t.TempDir(), true)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `ulimit -c 0; exec "$@"`, "bounded-core", shim, socket, "token", signalTool, strconv.Itoa(int(sig)))
			cmd.Dir = t.TempDir()
			var stderr strings.Builder
			cmd.Stderr = &stderr
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("signal error=%v", err)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != sig {
				t.Fatalf("signal disposition=%v", exit.Sys())
			}
			if finish := <-finishes; finish.Signal != int(sig) {
				t.Fatalf("child signal=%+v", finish)
			}
			if stderr.Len() != 0 {
				t.Fatalf("boundary added signal diagnostics: %q", stderr.String())
			}
		})
	}
	t.Run("version", func(t *testing.T) {
		socket, starts, _ := boundaryFixture(t, t.TempDir(), false)
		out, err := exec.Command(shim, socket, "token", "/bin/echo", "-V=full").Output()
		if err != nil || string(out) != "-V=full\n" {
			t.Fatalf("version forwarding=%q/%v", out, err)
		}
		if start := <-starts; len(start.Args) != 1 || start.Args[0] != "-V=full" {
			t.Fatalf("version argv=%+v", start)
		}
	})
	t.Run("contained-cancellation", func(t *testing.T) {
		socket, starts, _ := boundaryFixture(t, t.TempDir(), true)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		runner := gotool.Runner{Containment: &gotool.Containment{}, Prepare: func(cmd *exec.Cmd) {
			cmd.Path = shim
			cmd.Args = []string{shim, socket, "token", "/bin/sh", "-c", "sleep 60"}
		}}
		done := make(chan error, 1)
		go func() { _, err := runner.Run(ctx, dir, env, "version"); done <- err }()
		select {
		case <-starts:
		case <-time.After(10 * time.Second):
			t.Fatal("boundary did not start")
		}
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("cancelled action succeeded")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("contained cancellation did not reap boundary and tool")
		}
	})
}
