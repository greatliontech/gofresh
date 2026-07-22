package gofresh

import (
	"os"
	"testing"
)

// Tests must never read or write the real user cache: the observability
// memo (REQ-closure-observability-memo) keys under it, and shared state
// would let one run's proofs leak into another's assertions.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "gofresh-cache-*")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_CACHE_HOME", tmp)
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}
