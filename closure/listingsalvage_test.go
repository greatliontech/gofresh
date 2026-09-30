//go:build unix

package closure

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/gotool"
)

// The package listing reads the runner's List: a go whose listing
// exits cleanly while a descendant holds the pipe past the wait delay
// is refused as a LISTING (gotool.ErrListingRefused, never the served
// salvage's form) — the bare Run route would have refused too, by
// discarding the salvaged output on any error, but with exec's
// wait-delay error, which the salvage guard reads as served — while
// the same shim's environment document, whole by its own test, still
// serves the reader (REQ-fresh-go-command-policy).
func TestListingRefusesTheSalvagedAnswer(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shim := t.TempDir()
	// Every go command answers through the real go and then forks a
	// holder of the pipe: the structured readers salvage their whole
	// documents, the listing refuses.
	script := "#!/bin/sh\n\"" + goBinary + "\" \"$@\"\nstatus=$?\nsleep 2 &\nexit $status\n"
	if err := os.WriteFile(filepath.Join(shim, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir := listingMemoModule(t)
	runner := gotool.Runner{Containment: &gotool.Containment{WaitDelay: 300 * time.Millisecond}}
	h, err := NewAt(context.Background(), gotool.NewEnvReader(runner, dir, os.Environ()))
	if err != nil {
		t.Fatalf("the reader's whole document did not serve: %v", err)
	}
	_, err = h.list(listingMemoPkg)
	if !errors.Is(err, gotool.ErrListingRefused) {
		t.Fatalf("the held listing was not refused as a listing: %v", err)
	}
	if errors.Is(err, exec.ErrWaitDelay) || gotool.Salvaged(context.Background(), err) {
		t.Fatalf("the refused listing reads as a served salvage: %v", err)
	}
}
