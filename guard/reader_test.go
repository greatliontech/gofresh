package guard

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// Capture refuses a nil reader and a malformed environment before any
// probe, and digests under the normalized environment.
func TestCaptureRefusesANilReaderAndAMalformedEnvironment(t *testing.T) {
	ctx := context.Background()
	if _, err := Capture(ctx, nil, os.Environ(), CodeResult); err == nil || !strings.Contains(err.Error(), "nil environment reader") {
		t.Fatalf("Capture(nil) = %v", err)
	}
	// An out-of-range kind refuses before any spawn.
	spawned := false
	silent := gotool.NewEnvReader(gotool.Runner{Prepare: func(*exec.Cmd) { spawned = true }}, t.TempDir(), os.Environ())
	if _, err := Capture(ctx, silent, os.Environ(), Kind(7)); err == nil || !strings.Contains(err.Error(), "invalid result kind") || spawned {
		t.Fatalf("an invalid kind: err = %v, spawned = %v; want the refusal with no spawn", err, spawned)
	}
	dup := append(append([]string(nil), os.Environ()...), "GOFLAGS=a", "GOFLAGS=b")
	if _, err := Capture(ctx, gotool.NewEnvReader(gotool.Runner{}, t.TempDir(), dup), os.Environ(), CodeResult); err == nil || !strings.Contains(err.Error(), "guard:") {
		t.Fatalf("a duplicated key captured: %v", err)
	}
}

// A capture through an unprimed reader takes the pass's one snapshot
// through THAT reader, so the caller's later keys read it: one `go env
// -json` for the pass, whichever side asks first.
func TestCapturePrimesTheCallersReader(t *testing.T) {
	ctx := context.Background()
	snapshots := 0
	r := gotool.NewEnvReader(gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 2 && cmd.Args[1] == "env" && cmd.Args[2] == "-json" {
			snapshots++
		}
	}}, t.TempDir(), os.Environ())
	if _, err := Capture(ctx, r, os.Environ(), CodeResult); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Value(ctx, "GOFLAGS"); err != nil {
		t.Fatal(err)
	}
	if snapshots != 1 {
		t.Fatalf("%d snapshots for one pass, want 1 (the capture primed the caller's reader)", snapshots)
	}
}
