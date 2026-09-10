package gotool

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestRunOK(t *testing.T) {
	out, err := Run(context.Background(), "", os.Environ(), "env", "GOMODCACHE")
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		t.Error("empty GOMODCACHE")
	}
}

func TestRunError(t *testing.T) {
	if _, err := Run(context.Background(), "", os.Environ(), "this-is-not-a-go-subcommand"); err == nil {
		t.Fatal("expected error")
	} else if !strings.Contains(err.Error(), "go this-is-not-a-go-subcommand") {
		t.Errorf("error not wrapped with command: %v", err)
	}
}

// A nil environment is refused: the child would inherit the ambient one,
// which no entry of the public packages may read.
//
//gofresh:pure
func TestRunRefusesANilEnvironment(t *testing.T) {
	if _, err := Run(context.Background(), "", nil, "version"); err == nil {
		t.Fatal("a nil environment ran go under the ambient one")
	}
	if _, err := TakeEnvSnapshot(context.Background(), "", nil); err == nil {
		t.Fatal("a nil environment snapshotted the ambient one")
	}
}
