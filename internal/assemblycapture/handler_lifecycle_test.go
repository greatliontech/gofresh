//go:build linux && !android

package assemblycapture

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type actionCheckpoint struct {
	Phase   string
	PID     int
	Success bool
	conn    *net.UnixConn
}

func (g actionCheckpoint) release() error {
	defer g.conn.Close()
	return json.NewEncoder(g.conn).Encode(true)
}

func actionCheckpoints(t *testing.T) (string, <-chan actionCheckpoint) {
	t.Helper()
	path := filepath.Join(shortCaptureDir(t), "gate.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan actionCheckpoint, 8)
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		for {
			select {
			case e := <-events:
				_ = e.conn.Close()
			default:
				return
			}
		}
	})
	go func() {
		defer close(done)
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			var event actionCheckpoint
			if err = json.NewDecoder(conn).Decode(&event); err != nil {
				_ = conn.Close()
				return
			}
			event.conn = conn
			events <- event
		}
	}()
	return path, events
}

func nextCheckpoint(t *testing.T, events <-chan actionCheckpoint, phase string) actionCheckpoint {
	t.Helper()
	select {
	case event := <-events:
		if event.Phase != phase {
			_ = event.conn.Close()
			t.Fatalf("checkpoint=%q want=%q", event.Phase, phase)
		}
		return event
	case <-time.After(20 * time.Second):
		t.Fatalf("real child never reached %s checkpoint", phase)
	}
	return actionCheckpoint{}
}

// The test schedules the actual assembler, without adding a production hook.
// Parent ptrace stops its own child at exec; it never edits instructions or
// machine state. The unchanged production handler still receives authenticated
// shim messages and actual tool completion, over its ordinary socket.
func checkpointShim(t *testing.T, f actionFixture, control, mode string) string {
	t.Helper()
	selection := *f.selection
	prior := selection.runner.Prepare
	var writeErr error
	selection.runner.Prepare = func(cmd *exec.Cmd) {
		if prior != nil {
			prior(cmd)
		}
		if len(cmd.Args) == 0 || cmd.Args[len(cmd.Args)-1] != filepath.Join(cmd.Dir, "main.go") {
			return
		}
		source := string(shimSource)
		replace := func(old, new string) {
			if strings.Count(source, old) != 1 {
				writeErr = fmt.Errorf("checkpoint fixture seam absent: %s", old)
				return
			}
			source = strings.Replace(source, old, new, 1)
		}
		if mode == "fifo" {
			replace("enc, dec := json.NewEncoder(conn), json.NewDecoder(conn)", "enc, dec := json.NewEncoder(conn), json.NewDecoder(conn)\nif fixtureTarget(tool,os.Args[4:]) { fixtureCheckpoint(\"before\",0,true) }")
		} else {
			replace("if err = cmd.Start(); err != nil {", "fixtureStopped := fixtureTarget(tool,os.Args[4:])\nif fixtureStopped { runtime.LockOSThread(); cmd.SysProcAttr=&syscall.SysProcAttr{Ptrace:true} }\nif err = cmd.Start(); err != nil {")
			replace("done := make(chan struct{})", `if fixtureStopped {
var stopped syscall.WaitStatus
for { _,err=syscall.Wait4(cmd.Process.Pid,&stopped,0,nil); if err!=syscall.EINTR { break } }
if err!=nil || !stopped.Stopped() { fatal(fmt.Errorf("exec stop unavailable: %v, %v",stopped,err)) }
fixtureCheckpoint("running",cmd.Process.Pid,true)
if err=syscall.PtraceDetach(cmd.Process.Pid);err!=nil {fatal(err)}
runtime.UnlockOSThread()
}
done := make(chan struct{})`)
			replace("err = cmd.Wait()", "err = cmd.Wait()\nif fixtureStopped { fixtureCheckpoint(\"completed\",cmd.Process.Pid,cmd.ProcessState.Success()) }")
		}
		source += "\nfunc fixtureTarget(tool string,args []string)bool{if tool!=" + strconv.Quote(filepath.Join(f.selection.goenv["GOTOOLDIR"], "asm")) + "||len(args)==0||args[len(args)-1]!=" + strconv.Quote(f.source) + "{return false};for _,arg:=range args{if arg==\"-gensymabis\"{return false}};return true}\n"
		source += `func fixtureCheckpoint(phase string,pid int,success bool){
conn,err:=net.DialUnix("unix",nil,&net.UnixAddr{Name:` + strconv.Quote(control) + `,Net:"unix"});if err!=nil{fatal(err)};defer conn.Close()
if err=json.NewEncoder(conn).Encode(struct{Phase string;PID int;Success bool}{phase,pid,success});err!=nil{fatal(err)}
var release bool;if err=json.NewDecoder(conn).Decode(&release);err!=nil{fatal(err)};if !release{fatal(fmt.Errorf("checkpoint refused"))}
}
`
		if writeErr == nil {
			writeErr = os.WriteFile(cmd.Args[len(cmd.Args)-1], []byte(source), 0600)
		}
	}
	shim, err := buildShim(t.Context(), &selection, t.TempDir())
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	return shim
}

type actionRun struct {
	server *captureServer
	err    error
}

func TestHandlerClosingValidationAndCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("real running/completed child interval barriers")
	}
	f := newActionFixture(t, false)
	control, events := actionCheckpoints(t)
	shim := checkpointShim(t, f, control, "interval")
	for _, mode := range []string{"unchanged", "include-mutate-restore", "cancel-after-completion"} {
		t.Run(mode, func(t *testing.T) {
			beforeWatch, beforeFiles := ownedDescriptorCounts(t, f.header, f.source)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan actionRun, 1)
			temp := shortCaptureDir(t)
			go func() { c, err := runActionBuild(ctx, cancel, f, shim, temp, true); done <- actionRun{c, err} }()
			running := nextCheckpoint(t, events, "running")
			defer running.conn.Close()
			if running.PID <= 0 {
				t.Fatal("no actual child at exec barrier")
			}
			if mode == "include-mutate-restore" {
				info, err := os.Stat(f.header)
				if err != nil {
					t.Fatal(err)
				}
				original, err := os.ReadFile(f.header)
				if err != nil {
					t.Fatal(err)
				}
				put(t, f.header, "#define CHOICE NOP\n")
				if err = os.WriteFile(f.header, original, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.Chtimes(f.header, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
				// A final byte/stat comparison alone now agrees. Only this live
				// action's watch owns the external include's transient mutation.
				if err = f.selection.Validate(t.Context()); err != nil {
					t.Fatalf("outer selection unexpectedly owns mutation: %v", err)
				}
			}
			if err := running.release(); err != nil {
				t.Fatal(err)
			}
			completed := nextCheckpoint(t, events, "completed")
			defer completed.conn.Close()
			if !completed.Success || completed.PID != running.PID {
				t.Fatal("assembler did not genuinely complete before postbarrier", completed)
			}
			if mode == "cancel-after-completion" {
				cancel()
			}
			if err := completed.release(); err != nil && mode != "cancel-after-completion" {
				t.Fatal(err)
			}
			var result actionRun
			select {
			case result = <-done:
			case <-time.After(20 * time.Second):
				cancel()
				t.Fatal("handler/build cleanup did not complete")
			}
			if result.server == nil {
				t.Fatal(result.err)
			}
			packet, finishErr := result.server.finish()
			switch mode {
			case "unchanged":
				if result.err != nil || finishErr != nil || packet == nil {
					t.Fatalf("unchanged interval refused: %v/%v", result.err, finishErr)
				}
			case "include-mutate-restore":
				if result.err == nil || !strings.Contains(result.err.Error(), "protected input namespace mutated") || packet != nil || finishErr == nil {
					t.Fatalf("closing action guard absent: packet=%v run=%v finish=%v", packet, result.err, finishErr)
				}
				for _, token := range []string{"after-tool", strconv.Quote(f.provider.ID), strconv.Quote(filepath.Join(f.selection.goenv["GOTOOLDIR"], "asm")), strconv.Quote(f.header), "wd "} {
					if !strings.Contains(result.err.Error(), token) {
						t.Errorf("closing action attribution lacks %q: %v", token, result.err)
					}
				}
			case "cancel-after-completion":
				if ctx.Err() != context.Canceled || result.err == nil || packet != nil || finishErr == nil {
					t.Fatalf("post-completion cancellation accepted: packet=%v run=%v finish=%v", packet, result.err, finishErr)
				}
			}
			afterWatch, afterFiles := ownedDescriptorCounts(t, f.header, f.source)
			if beforeWatch != afterWatch || beforeFiles != afterFiles {
				t.Fatalf("handler descriptors leaked: watches %d->%d files %d->%d", beforeWatch, afterWatch, beforeFiles, afterFiles)
			}
		})
	}
}

func TestHandlerFIFOReplacementCannotStrandCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("actual shim and handler FIFO replacement")
	}
	f := newActionFixture(t, false)
	control, events := actionCheckpoints(t)
	shim := checkpointShim(t, f, control, "fifo")
	beforeWatch, beforeFiles := ownedDescriptorCounts(t, f.source)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan actionRun, 1)
	temp := shortCaptureDir(t)
	go func() { c, err := runActionBuild(ctx, cancel, f, shim, temp, true); done <- actionRun{c, err} }()
	before := nextCheckpoint(t, events, "before")
	defer before.conn.Close()
	if err := os.Remove(f.source); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(f.source, 0600); err != nil {
		t.Fatal(err)
	}
	if err := before.release(); err != nil {
		t.Fatal(err)
	}
	var result actionRun
	select {
	case result = <-done:
		cancel()
	case <-time.After(3 * time.Second):
		// A broken blocking open must not hang the oracle's teardown. First
		// request cancellation; if it cannot reap the handler, connect a
		// nonblocking writer/reader to release the actual blocked FIFO open.
		cancel()
		select {
		case result = <-done:
		case <-time.After(3 * time.Second):
			fd, err := unix.Open(f.source, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			_ = unix.Close(fd)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("FIFO rescue failed to release handler")
			}
			t.Fatal("FIFO open stranded handler and cancellation; rescue released it")
		}
		t.Fatalf("FIFO replacement did not refuse promptly before cancellation: %v", result.err)
	}
	if result.server == nil || result.err == nil || !strings.Contains(result.err.Error(), "nonregular input") {
		t.Fatalf("wrong FIFO refusal: %v", result.err)
	}
	if packet, err := result.server.finish(); packet != nil || err == nil {
		t.Fatal("FIFO action supplied a packet")
	}
	afterWatch, afterFiles := ownedDescriptorCounts(t, f.source)
	if afterWatch != beforeWatch || afterFiles != beforeFiles {
		t.Fatalf("FIFO handler leaked descriptors: %d/%d -> %d/%d", beforeWatch, beforeFiles, afterWatch, afterFiles)
	}
}
