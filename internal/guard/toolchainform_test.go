package guard

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// The toolchain guard read from the pass's snapshot is byte-identical
// to the `go version` line minus its prefix — the former live probe's
// value — on the running toolchain, under a target platform in the
// environment too (the host keys, never GOOS/GOARCH), so no recorded
// guard moves and the pass pays one spawn for both code guards
// (REQ-guard-toolchain).
func TestToolchainGuardIsGoVersionsOwnForm(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	ctx := context.Background()
	dir := t.TempDir()
	env := os.Environ()
	out, err := gotool.Runner{}.Run(ctx, dir, env, "version")
	if err != nil {
		t.Fatal(err)
	}
	live := strings.TrimPrefix(strings.TrimSpace(string(out)), "go version ")
	reader := gotool.NewEnvReader(gotool.Runner{}, dir, env)
	snapshot, err := reader.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := toolchainOf(snapshot); err != nil || got != live {
		t.Fatalf("toolchain guard %q (%v), `go version` says %q", got, err, live)
	}
	// A target platform in the environment is the build-configuration
	// guard's business: `go version` still prints the host platform,
	// and so must the derived guard — the host keys, never GOOS/GOARCH.
	cross := gotool.SetEnv(gotool.SetEnv(env, "GOOS", "windows"), "GOARCH", "arm64")
	out, err = gotool.Runner{}.Run(ctx, dir, cross, "version")
	if err != nil {
		t.Fatal(err)
	}
	if crossLive := strings.TrimPrefix(strings.TrimSpace(string(out)), "go version "); crossLive != live {
		t.Fatalf("`go version` moved under a target platform: %q vs %q", crossLive, live)
	}
	crossSnapshot, err := gotool.NewEnvReader(gotool.Runner{}, dir, cross).Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := toolchainOf(crossSnapshot); err != nil || got != live {
		t.Fatalf("toolchain guard %q (%v) under GOOS=windows GOARCH=arm64, want the host's %q", got, err, live)
	}
	// The capture reads the same value, and pays the reader's one
	// snapshot for it: no `go version` spawn beside the `go env -json`.
	spawns := 0
	counted := gotool.NewEnvReader(gotool.Runner{Prepare: func(c *exec.Cmd) { spawns++ }}, dir, env)
	g, err := Capture(ctx, counted, env, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	if g.Toolchain != live {
		t.Fatalf("captured toolchain guard %q, want %q", g.Toolchain, live)
	}
	if spawns != 1 {
		t.Fatalf("the capture paid %d go spawns for its code guards, want the one snapshot", spawns)
	}
	// A document that answers no version, or no host platform (a shim,
	// a toolchain before GOVERSION existed), is no identity: the capture
	// refuses naming the missing key, never a non-empty guard over an
	// empty part. The program resolves through the parent's PATH
	// (Program's rule), so the shim goes there; these arms are the
	// test's last.
	shim := t.TempDir()
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, missing := range []string{"GOVERSION", "GOHOSTOS", "GOHOSTARCH"} {
		document := map[string]string{"GOFLAGS": "", "GOVERSION": "go1.99.0", "GOHOSTOS": "linux", "GOHOSTARCH": "amd64"}
		delete(document, missing)
		body, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(shim, "go"), []byte("#!/bin/sh\necho '"+string(body)+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		shimmed := gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ())
		if g, err := Capture(ctx, shimmed, os.Environ(), CodeResult); err == nil || !strings.Contains(err.Error(), "no "+missing) {
			t.Fatalf("a document without %s captured %+v, %v; want a refusal naming it", missing, g, err)
		}
	}
}
