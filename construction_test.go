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
		e, err := NewContext(input, func(*Engine) { called = true })
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
	for _, option := range []Option{WithBuildFlags("-overlay=unused"), WithBuildInputs("-overlay=unused"), WithEnv("malformed")} {
		ctx, cancel := context.WithCancel(context.Background())
		e, err := NewContext(ctx, WithDir(t.TempDir()), option, func(*Engine) { cancel() })
		cancel()
		if e != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled preparation: engine returned=%t error=%v", e != nil, err)
		}
	}
}
