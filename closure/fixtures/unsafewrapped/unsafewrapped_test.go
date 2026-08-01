package unsafewrapped

import (
	"testing"

	"github.com/greatliontech/gofresh/closure/fixtures/unsafewrapped/handle"
)

// TestWrappedUnsafeHandle reaches a value whose named type wraps
// unsafe.Pointer without any reachable code producing an unsafe-typed
// value directly: the analysis discovers the fact only through the named
// type's underlying structure, and the proof must refuse.
func TestWrappedUnsafeHandle(t *testing.T) {
	if handle.New().Size() != 1 {
		t.Fatal("handle")
	}
}
