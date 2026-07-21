package observablefreshinit

import (
	"os"
	"path/filepath"
	"testing"
)

// The startup stage calls the same helper with a non-fresh argument:
// caller-site enumeration is per-subject reachability, so the init call
// is invisible to the boundary analysis — soundness rests on the
// startup walk blocking every startup-reachable effect first, and this
// package pins exactly that mask.
func init() {
	sharedHelper("/tmp/fixture-startup")
}

func sharedHelper(dir string) {
	target := filepath.Join(dir, "s.txt")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		return
	}
	_ = os.Remove(target)
}

func TestFreshHelperShadowedByStartupCaller(t *testing.T) {
	sharedHelper(t.TempDir())
}
