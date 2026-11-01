package harnessarg

import (
	"os"
	"testing"
)

// loud's String reads a non-constant path, so the subject tier must
// refuse the proof — and the only path that keeps String reachable is
// the argument method set of the t.Log call, pinning that the audited
// harness channel leaves argument methods visible to reachability.
type loud struct{ path string }

func (l loud) String() string {
	data, _ := os.ReadFile(l.path)
	return string(data)
}

func TestLogEffectfulArgument(t *testing.T) {
	t.Log(loud{path: "baseline.txt"})
}
