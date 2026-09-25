package runtimeinput

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/gotool"
)

// The roots probe serves the answer a cleanly exited process wrote
// beside a descendant's pipe hold when its four values are present; a
// torn answer refuses with the hold named
// (REQ-fresh-go-command-policy).
func TestRootsProbeServesTheSalvagedAnswer(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shim := t.TempDir()
	script := "#!/bin/sh\n\"" + goBinary + "\" \"$@\"\nstatus=$?\nsleep 5 &\nexit $status\n"
	if err := os.WriteFile(filepath.Join(shim, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	runner := gotool.Runner{Containment: &gotool.Containment{WaitDelay: 200 * time.Millisecond}}
	pkgDir := t.TempDir()
	roots, err := resolveRoots(context.Background(), runner, pkgDir, pkgDir, env)
	if err != nil || roots.toolchain == "" {
		t.Fatalf("roots = %+v, %v; want the salvaged answer", roots, err)
	}
	// A torn document, a banner glued before the document, and a
	// document missing a key all refuse — the first two naming the hold.
	for _, wrapper := range []string{
		"#!/bin/sh\nprintf '{\"GOROOT\":'\nsleep 5 &\nexit 0\n",
		"#!/bin/sh\nprintf banner\n\"" + goBinary + "\" \"$@\"\nsleep 5 &\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(shim, "go"), []byte(wrapper), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveRoots(context.Background(), runner, pkgDir, t.TempDir(), env); !errors.Is(err, exec.ErrWaitDelay) {
			t.Fatalf("wrapper %q = %v, want the hold named", wrapper, err)
		}
	}
	partial := "#!/bin/sh\necho '{\"GOROOT\":\"/r\",\"GOMODCACHE\":\"/m\"}'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(shim, "go"), []byte(partial), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveRoots(context.Background(), runner, pkgDir, t.TempDir(), env); err == nil || !strings.Contains(err.Error(), "no GOCACHE") {
		t.Fatalf("a document missing a key = %v, want the key named", err)
	}
}
