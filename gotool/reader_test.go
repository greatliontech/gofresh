package gotool

import (
	"context"
	"errors"
	"os"
	"testing"
)

// A reader never memoizes a cancellation: a snapshot refused by the
// caller's context is retried on the next live call, while any other
// failure is the reader's answer for its lifetime.
func TestEnvReaderNeverMemoizesACancellation(t *testing.T) {
	r := NewEnvReader(Runner{}, "", os.Environ())
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Snapshot(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled snapshot = %v", err)
	}
	if r.Taken() != nil {
		t.Fatal("a cancelled snapshot was held")
	}
	if snapshot, err := r.Snapshot(context.Background()); err != nil || snapshot == nil || snapshot.Value("GOROOT") == "" {
		t.Fatalf("the live snapshot after a cancellation: %v, %v", snapshot, err)
	}
	if r.Taken() == nil {
		t.Fatal("the live snapshot is not held")
	}
	failing := NewEnvReader(Runner{}, "", []string{"BAD"})
	if _, err := failing.Snapshot(context.Background()); err == nil {
		t.Fatal("a malformed environment took a snapshot")
	}
	if _, err := failing.Snapshot(context.Background()); err == nil || failing.Taken() != nil {
		t.Fatal("a failed snapshot is not the reader's sticky answer")
	}
}
