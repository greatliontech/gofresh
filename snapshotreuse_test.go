package gofresh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/greatliontech/gofresh/internal/gotool"
)

// TestObservedCaptureReusesConstructionSnapshot pins that the
// precise-analysis bracket derives its env-derived configuration from the
// view's construction snapshot: the process environment is immutable
// analysis configuration, so re-reading go env would cost two process
// executions per capture batch and could only agree.
func TestObservedCaptureReusesConstructionSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	var seen *gotool.EnvSnapshot
	viewTestHooks.snapshot = func(s *gotool.EnvSnapshot) { seen = s }
	t.Cleanup(func() { viewTestHooks.snapshot = nil })
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if view.facts.snapshot == nil {
		t.Fatal("view retained no construction snapshot")
	}
	if _, err := view.CaptureObserved(context.Background(), subject); err != nil {
		t.Fatal(err)
	}
	if seen != view.facts.snapshot {
		t.Fatalf("bracket snapshot = %p, want the construction snapshot %p", seen, view.facts.snapshot)
	}
}

// TestObservedCaptureRefusesMidWindowOverlayBeforeAnyLoad pins the
// bracket's live build-flag revalidation: an overlay written to the go env
// file after view construction refuses before any load whose derivations
// could persist to the observability memo — no load or prove phase runs.
// GOENV redirects the go command's env file to a sandbox path, so the
// user's real configuration is never touched.
func TestObservedCaptureRefusesMidWindowOverlayBeforeAnyLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	goenv := filepath.Join(t.TempDir(), "goenv")
	if err := os.WriteFile(goenv, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var phases []string
	var mu sync.Mutex
	// Replace, never append: the ambient environment may itself carry
	// GOENV (a stipulator witness run does), and the engine rejects
	// duplicate keys by design.
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GOENV=") {
			env = append(env, kv)
		}
	}
	env = append(env, "GOENV="+goenv)
	engine, err := New(
		WithDir(dir),
		WithEnv(env...),
		WithProgress(func(p Progress) {
			mu.Lock()
			phases = append(phases, p.Phase)
			mu.Unlock()
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	phases = nil
	mu.Unlock()
	if err := os.WriteFile(goenv, []byte("GOFLAGS=-overlay=/absent.json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = view.CaptureObserved(context.Background(), subject)
	if err == nil || !strings.Contains(err.Error(), "overlay") {
		t.Fatalf("mid-window overlay capture = %v, want the build-flag overlay refusal", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, phase := range phases {
		if phase == "load" || phase == "prove" {
			t.Fatalf("phase %q ran after the overlay was written; refusal must precede any load (phases: %v)", phase, phases)
		}
	}
}
