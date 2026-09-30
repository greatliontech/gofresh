//go:build unix

package runtimeinput

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// The roots memo is one judged run's: through one Roots, three spellings
// of one package directory and two orderings of one environment pay one
// `go env -json`; PWD alone moves nothing; any other setting is a new
// entry; a nil memo pays every call. The counting shim execs the real
// go by its absolute path, so one probe is one count (a go wrapper that
// re-invoked `go` through PATH would count twice).
func TestRootsMemoizeForTheJudgedRun(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shim := t.TempDir()
	counter := filepath.Join(t.TempDir(), "count")
	script := "#!/bin/sh\necho x >> " + counter + "\nexec \"" + goBinary + "\" \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shim, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	spawns := func() int {
		data, _ := os.ReadFile(counter)
		return strings.Count(string(data), "x")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	reversed := append([]string(nil), env...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	memo := &Roots{}
	ctx := context.Background()
	for _, ask := range []struct {
		dir string
		env []string
	}{{dir, env}, {dir + "/x/..", env}, {link, env}, {dir, reversed}, {dir, gotool.SetEnv(env, "PWD", "/elsewhere")}} {
		roots, err := resolveRoots(ctx, memo, gotool.Runner{}, dir, ask.dir, ask.env)
		if err != nil || roots.toolchain == "" {
			t.Fatalf("resolve %s: %+v, %v", ask.dir, roots, err)
		}
	}
	if n := spawns(); n != 1 {
		t.Fatalf("%d probes for one coordinate and environment, want 1", n)
	}
	if _, err := resolveRoots(ctx, memo, gotool.Runner{}, dir, dir, gotool.SetEnv(env, "ZZZ_ROOTS_MEMO", "1")); err != nil {
		t.Fatal(err)
	}
	if n := spawns(); n != 2 {
		t.Fatalf("%d probes after a changed setting, want 2", n)
	}
	// Two package directories never share an entry.
	if _, err := resolveRoots(ctx, memo, gotool.Runner{}, dir, filepath.Join(dir, "x"), env); err != nil {
		t.Fatal(err)
	}
	if n := spawns(); n != 3 {
		t.Fatalf("%d probes after a second directory, want 3", n)
	}
	// A nil memo pays every call.
	for range 2 {
		if _, err := resolveRoots(ctx, nil, gotool.Runner{}, dir, dir, env); err != nil {
			t.Fatal(err)
		}
	}
	if n := spawns(); n != 5 {
		t.Fatalf("%d probes with a nil memo, want 5 (two unmemoized calls)", n)
	}
}

// The producer ingest reads the memo it carries: two observations
// through one Roots pay one probe; observations carrying none pay one
// each (REQ-inputs-producer-facade).
func TestProducerIngestReadsItsRootsMemo(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shim := t.TempDir()
	counter := filepath.Join(t.TempDir(), "count")
	script := "#!/bin/sh\necho x >> " + counter + "\nexec \"" + goBinary + "\" \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shim, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	root, pkgDir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	env := producerEnv(pkgDir)
	spawns := func() int {
		data, _ := os.ReadFile(counter)
		return strings.Count(string(data), "x")
	}
	observe := func(memo *Roots) {
		t.Helper()
		_, reason, err := frame.Observe(context.Background(), writeTestlog(t, ""), ProducerIngest{Identity: "worker", Env: env, Roots: memo})
		if err != nil || reason != "" {
			t.Fatalf("observe = reason %q, err %v", reason, err)
		}
	}
	before := spawns()
	memo := &Roots{}
	observe(memo)
	observe(memo)
	if n := spawns() - before; n != 1 {
		t.Fatalf("two observations through one memo paid %d probes, want 1", n)
	}
	observe(nil)
	observe(nil)
	if n := spawns() - before; n != 3 {
		t.Fatalf("two memo-less observations paid %d more probes, want 2 (total 3)", n-1)
	}
}
