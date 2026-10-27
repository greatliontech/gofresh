package gofresh

import (
	"context"
	"errors"
	"testing"
)

// A cancelled or missing preparation context admits no configuration work.
func TestConstructionContextRefusesBeforeOptions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []context.Context{nil, ctx} {
		called := false
		e, err := newEngineContext(input, func(*engine) { called = true })
		if e != nil || err == nil || called {
			t.Fatalf("context %v: engine returned=%t error=%v option called=%v", input, e != nil, err, called)
		}
		if input != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation returned %v", err)
		}
	}
}

// A cancellation during configuration cannot be reported as an unrelated flag
// refusal, even where the invalid flag prevents an environment query entirely.
func TestConstructionContextKeepsCancellationAttribution(t *testing.T) {
	for _, option := range []option{withBuildFlags("-overlay=unused"), withBuildInputs("-overlay=unused"), withEnv("malformed")} {
		ctx, cancel := context.WithCancel(context.Background())
		e, err := newEngineContext(ctx, withDir(t.TempDir()), option, func(*engine) { cancel() })
		cancel()
		if e != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled preparation: engine returned=%t error=%v", e != nil, err)
		}
	}
}
