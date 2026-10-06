package gofresh

import (
	"context"
	"os"
	"testing"

	"github.com/greatliontech/gofresh/internal/testenv"
)

// Tests must never read or write the real user proof cache: the observability
// memo (REQ-closure-observability-memo) keys under it, and shared state
// would let one run's proofs leak into another's assertions.
func TestMain(m *testing.M) {
	cache, err := testenv.GoBuildCache(context.Background(), os.Environ())
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("GOCACHE", cache); err != nil {
		panic(err)
	}
	tmp, err := os.MkdirTemp("", "gofresh-cache-*")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_CACHE_HOME", tmp)
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}
