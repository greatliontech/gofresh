package gofresh

import (
	"context"
	"testing"
	"time"
)

// The default deadline constructor preserves both the requested analysis bound
// and the operation's earlier bound/cancellation (REQ-fresh-context). Tests of
// cut provenance may replace the clock; these tests use the real constructor.
func TestAnalysisBoundPreservesDeadlineContract(t *testing.T) {
	prior := viewTestHooks.analysisBound
	viewTestHooks.analysisBound = nil
	t.Cleanup(func() { viewTestHooks.analysisBound = prior })
	parent := context.Background()
	t.Run("requested duration", func(t *testing.T) {
		const budget = time.Minute
		before := time.Now()
		ctx, cancel := analysisBound(parent, budget)
		defer cancel()
		after := time.Now()
		deadline, ok := ctx.Deadline()
		if !ok || deadline.Before(before.Add(budget)) || deadline.After(after.Add(budget)) || ctx.Err() != nil {
			t.Fatalf("deadline = %v/%t, context=%v; want the requested minute", deadline, ok, ctx.Err())
		}
		cancel()
		if ctx.Err() != context.Canceled || parent.Err() != nil {
			t.Fatalf("analysis cancellation: child=%v parent=%v", ctx.Err(), parent.Err())
		}
	})
	t.Run("actual expiry", func(t *testing.T) {
		ctx, cancel := analysisBound(parent, time.Nanosecond)
		defer cancel()
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
			t.Fatal("analysis deadline did not expire")
		}
		if ctx.Err() != context.DeadlineExceeded || parent.Err() != nil {
			t.Fatalf("expiry: child=%v parent=%v", ctx.Err(), parent.Err())
		}
	})
	t.Run("unbounded preserves parent", func(t *testing.T) {
		p, stop := context.WithCancel(parent)
		defer stop()
		ctx, cancel := analysisBound(p, 0)
		cancel()
		if ctx != p || p.Err() != nil {
			t.Fatal("unbounded analysis introduced or cancelled an operation context")
		}
	})
	t.Run("parent cancellation", func(t *testing.T) {
		p, stop := context.WithCancel(parent)
		defer stop()
		ctx, cancel := analysisBound(p, time.Minute)
		defer cancel()
		stop()
		if ctx.Err() != context.Canceled {
			t.Fatalf("operation cancellation = %v", ctx.Err())
		}
	})
	t.Run("earlier parent deadline", func(t *testing.T) {
		deadline := time.Now().Add(time.Minute)
		p, stop := context.WithDeadline(parent, deadline)
		defer stop()
		ctx, cancel := analysisBound(p, 2*time.Minute)
		defer cancel()
		got, ok := ctx.Deadline()
		if !ok || !got.Equal(deadline) {
			t.Fatalf("parent deadline = %v/%t, want %v", got, ok, deadline)
		}
	})
}
