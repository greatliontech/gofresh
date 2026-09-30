//go:build unix

package gotool

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// List spells `go list` ahead of its arguments and serves a clean
// listing; the wait-delay form (a holder on the pipe here) is refused
// with ErrListingRefused — never the served salvage's form, so Salvaged
// is false for it — where Run would have served it: a listing has no
// wholeness test (REQ-fresh-go-command-policy).
func TestListRefusesTheSalvagedAnswer(t *testing.T) {
	env := shimGo(t, "echo \"$@\"\nexit 0\n")
	r := Runner{Containment: &Containment{WaitDelay: 200 * time.Millisecond}}
	out, err := r.List(context.Background(), "", env, "-deps", "example.com/p")
	if err != nil || strings.TrimSpace(string(out)) != "list -deps example.com/p" {
		t.Fatalf("clean listing: out %q err %v", out, err)
	}

	env = shimGo(t, "echo example.com/p\nsleep 2 &\nexit 0\n")
	out, err = r.List(context.Background(), "", env, "-deps", "example.com/p")
	if !errors.Is(err, ErrListingRefused) || out != nil {
		t.Fatalf("held listing: out %q err %v, want no output and ErrListingRefused", out, err)
	}
	// The refusal is its own form — never the served salvage's: the
	// guard every structured reader applies is false for it.
	if errors.Is(err, exec.ErrWaitDelay) || Salvaged(context.Background(), err) {
		t.Fatalf("a refused listing reads as a served salvage: %v", err)
	}
	if !strings.Contains(err.Error(), "go list -deps example.com/p") || !strings.Contains(err.Error(), exec.ErrWaitDelay.Error()) {
		t.Fatalf("the refusal names neither the listing nor exec's error: %v", err)
	}
	// Run itself serves the same shape — the refusal is List's alone.
	if out, err := r.Run(context.Background(), "", env, "list", "-deps", "example.com/p"); !errors.Is(err, exec.ErrWaitDelay) || strings.TrimSpace(string(out)) != "example.com/p" {
		t.Fatalf("Run stopped serving the salvage: out %q err %v", out, err)
	}
}
