//go:build linux && !android

package assemblycapture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/buildflags"
)

type actionFixture struct {
	selection      *Selection
	provider       Package
	header, source string
}

func newActionFixture(t *testing.T, profile bool) actionFixture {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skip("real assembly fixture uses amd64")
	}
	dir := t.TempDir()
	headerDir := t.TempDir()
	put(t, filepath.Join(dir, "go.mod"), "module example.com/actioncapture\n\ngo 1.27.0\n")
	put(t, filepath.Join(dir, "p.go"), "package p\nfunc One()\nfunc Two()\n")
	for i, name := range []string{"One", "Two"} {
		put(t, filepath.Join(dir, fmt.Sprintf("%d_amd64.s", i)), "#include \"capture_choice.h\"\nTEXT ·"+name+"(SB),4,$0-0\nCHOICE\n")
	}
	header := filepath.Join(headerDir, "capture_choice.h")
	put(t, header, "#define CHOICE RET\n")
	asmFlags, err := buildflags.Join([]string{"-I", headerDir})
	if err != nil {
		t.Fatal(err)
	}
	flags := []string{"-asmflags=example.com/actioncapture=" + asmFlags}
	if profile {
		snapshot, err := contained(gotool.Runner{}).TakeEnvSnapshot(t.Context(), dir, os.Environ())
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(snapshot.Value("GOROOT"), "src", "cmd", "compile", "default.pgo"))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "selected.pgo")
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		flags = append(flags, "-pgo="+path)
	}
	s, err := BeginSelection(t.Context(), gotool.Runner{}, Request{Dir: dir, Env: os.Environ(), Flags: flags, Roots: []string{"."}})
	if err != nil {
		t.Fatal(err)
	}
	sealFixture(t, s)
	if _, ok := s.files[header]; ok {
		t.Fatal("external include is incorrectly owned by whole-selection guard")
	}
	if _, ok := s.directories[headerDir]; ok {
		t.Fatal("external include directory is under whole-selection guard")
	}
	return actionFixture{selection: s, provider: s.packages["example.com/actioncapture"], header: header, source: filepath.Join(dir, "0_amd64.s")}
}

func shortCaptureDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ac-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

// runActionBuild exercises the real boundary handler and real Go actions. It
// deliberately has no outer whole-selection watcher: action-interval failures
// must be caught by the handler itself. The selection was genuinely observed
// and sealed before this run, and finish receives only its actual receipts.
func runActionBuild(ctx context.Context, cancel context.CancelFunc, f actionFixture, shim, temp string, cold bool) (*captureServer, error) {
	limits, _ := (Limits{}).normalized()
	m := &meter{ctx: ctx, limits: limits}
	c, err := startServer(ctx, cancel, f.selection, f.provider, m, temp)
	if err != nil {
		return nil, err
	}
	defer c.close()
	boundary, err := buildflags.Join([]string{shim, c.listener.Addr().String(), c.token})
	if err != nil {
		return c, err
	}
	args := append([]string{"build"}, f.selection.request.Flags...)
	if cold {
		args = append(args, "-a")
	}
	args = append(args, "-o", filepath.Join(temp, "output.a"), "-toolexec="+boundary)
	args = append(args, f.selection.request.Roots...)
	_, err = f.selection.runner.Run(ctx, f.selection.request.Dir, f.selection.request.Env, args...)
	c.close()
	if c.err != nil {
		return c, c.err
	}
	return c, err
}

func receiptView(c *captureServer, actions []*capturedAction) *captureServer {
	return &captureServer{ctx: c.ctx, selection: c.selection, provider: c.provider, m: c.m, actions: slices.Clone(actions)}
}

func ownedDescriptorCounts(t *testing.T, paths ...string) (int, int) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var watches, files int
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil {
			continue
		}
		if target == "anon_inode:inotify" {
			watches++
		}
		for _, path := range paths {
			if target == path {
				files++
			}
		}
	}
	return watches, files
}
