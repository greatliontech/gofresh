//go:build unix

package gotool

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// A snapshot sampler answers the toolchain from its reader's one
// snapshot — the GOVERSION `go env` reported, the same string the
// spawning sampler returns — and spawns nothing of its own; an ask for
// another directory or environment than the reader's pass is refused,
// and a reader whose snapshot failed answers that failure
// (REQ-fresh-toolchain-skew).
func TestSnapshotSamplerAnswersItsReadersPassWithoutASpawn(t *testing.T) {
	ctx := context.Background()
	spawns := 0
	runner := Runner{Prepare: func(*exec.Cmd) { spawns++ }}
	env := os.Environ()
	reader := NewEnvReader(runner, "", env)
	want, err := (&Sampler{Runner: Runner{}}).Sample(ctx, "", env)
	if err != nil {
		t.Fatal(err)
	}
	s := SnapshotSampler{Reader: reader}
	got, err := s.Sample(ctx, "", env)
	if err != nil || got != want {
		t.Fatalf("SnapshotSampler.Sample = %q, %v; want the spawning sampler's %q", got, err, want)
	}
	if spawns != 1 {
		t.Fatalf("%d spawns, want the reader's one snapshot", spawns)
	}
	if got, err := s.Sample(ctx, "", env); err != nil || got != want || spawns != 1 {
		t.Fatalf("a second ask answered %q, %v after %d spawns", got, err, spawns)
	}
	if _, err := s.Sample(ctx, t.TempDir(), env); !errors.Is(err, errSnapshotPass) {
		t.Fatalf("another directory answered: %v", err)
	}
	if _, err := s.Sample(ctx, "", SetEnv(env, "GOFRESH_SNAPSHOT_PROBE", "1")); !errors.Is(err, errSnapshotPass) {
		t.Fatalf("another environment answered: %v", err)
	}
	if _, err := (SnapshotSampler{}).Sample(ctx, "", env); err == nil {
		t.Fatal("no reader sampled")
	}
	// A reader whose snapshot failed answers that failure — the
	// environment well-formed, the go command refusing — never a
	// version; a snapshot naming no GOVERSION is no sample.
	refusing := shimGo(t, "echo 'go: boom' >&2\nexit 1\n")
	if got, err := (SnapshotSampler{Reader: NewEnvReader(Runner{}, "", refusing)}).Sample(ctx, "", refusing); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("a failed snapshot sampled %q, %v; want the snapshot's own refusal", got, err)
	}
	versionless := shimGo(t, "echo '{\"GOROOT\":\"/x\"}'\n")
	if got, err := (SnapshotSampler{Reader: NewEnvReader(Runner{}, "", versionless)}).Sample(ctx, "", versionless); err == nil || !strings.Contains(err.Error(), "no GOVERSION") {
		t.Fatalf("a snapshot without GOVERSION sampled %q, %v", got, err)
	}
}
