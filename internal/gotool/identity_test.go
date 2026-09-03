package gotool

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Two snapshots of one environment render the same identity even though
// the raw go env output differs per invocation (GOGCCFLAGS embeds a
// temporary path), and the identity carries the settings that select
// source.
func TestEnvSnapshotIdentityIsStableAcrossTakes(t *testing.T) {
	base := os.Environ()[:0:0]
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "GOENV" && key != "GOFLAGS" {
			base = append(base, entry)
		}
	}
	env := append(append([]string(nil), base...), "GOENV=off", "GOFLAGS=")
	dir := t.TempDir()
	first, err := TakeEnvSnapshot(context.Background(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	second, err := TakeEnvSnapshot(context.Background(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity() != second.Identity() {
		t.Fatalf("identity moved between two takes:\n%s\n---\n%s", first.Identity(), second.Identity())
	}
	for _, key := range []string{"GOVERSION=", "GOROOT=", "GOOS=", "GOARCH=", "GOFLAGS=", "GOWORK="} {
		if !strings.Contains(first.Identity(), "\n"+key) && !strings.HasPrefix(first.Identity(), key) {
			t.Fatalf("identity lacks %s:\n%s", key, first.Identity())
		}
	}
	if strings.Contains(first.Identity(), "GOGCCFLAGS=") {
		t.Fatal("identity carries GOGCCFLAGS")
	}
	if (*EnvSnapshot)(nil).Identity() != "" {
		t.Fatal("nil snapshot has an identity")
	}
	tagged, err := TakeEnvSnapshot(context.Background(), dir, append(append([]string(nil), base...), "GOENV=off", "GOFLAGS=-tags=x"))
	if err != nil {
		t.Fatal(err)
	}
	if tagged.Identity() == first.Identity() {
		t.Fatal("a changed GOFLAGS rendered the same identity")
	}
}
