package gotool

import (
	"context"
	"os"
	"os/exec"
	"testing"
)

// A primed reader hands the construction snapshot on — no probe — and
// a nil snapshot primes nothing: the reader takes its own on first use
// rather than answering empty values for a snapshot never taken.
func TestPrimedEnvReaderPrimesOnlyARealSnapshot(t *testing.T) {
	ctx := context.Background()
	taken, err := TakeEnvSnapshot(ctx, "", os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	spawns := 0
	counting := Runner{Prepare: func(*exec.Cmd) { spawns++ }}
	primed := PrimedEnvReader(counting, "", os.Environ(), taken)
	if got, err := primed.Value(ctx, "GOROOT"); err != nil || got != taken.Value("GOROOT") || spawns != 0 {
		t.Fatalf("primed reader probed (%d spawns) or answered %q, %v", spawns, got, err)
	}
	unprimed := PrimedEnvReader(counting, "", os.Environ(), nil)
	if got, err := unprimed.Value(ctx, "GOROOT"); err != nil || got == "" || spawns != 1 {
		t.Fatalf("nil-primed reader: %q, %v after %d spawns; want its own snapshot taken once", got, err, spawns)
	}
}
