package closure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure/internal/listing"
)

func TestSelectedSourceCaptureCumulativeBudget(t *testing.T) {
	startup, main, use := startupFixture(t, map[string][]string{"main": {`package main;var X=2;func consume(int){};func main(){consume(X)}`}})
	// Selected listing data is still captured when the source interpreter does
	// not consume it. Make capture dominate the later binding cost, so replacing
	// the remainder with a fresh allowance would wrongly admit either consumer.
	startup.source.metas[0].Deps = make([]string, 2048)
	for i := range startup.source.metas[0].Deps {
		startup.source.metas[0].Deps[i] = strings.Repeat("d", 64)
	}
	limits := defaultRegistrationLimits()
	raw, err := newSelectedSourceBinder(t.Context(), startup.source, main, limits.source)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := captureSelectedSource(startup.source, limits.source)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := captured.binder(t.Context(), main)
	if err != nil {
		t.Fatal(err)
	}
	if bound.work != captured.work+raw.work || bound.bytes != captured.bytes+raw.bytes || bound.limits != limits.source {
		t.Fatal("capture and binding did not retain exactly one cumulative account")
	}
	activation := regionActivationInput{owner: main.Prog, selection: startup.source.prog, root: main, unwind: regionNoActiveUnwind, premises: []string{"conditional ordinary source activation with unknown incoming globals"}}
	proposal, err := proposeRegionActivation(t.Context(), activation, limits.region)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareSourceEntry(t.Context(), startup, main, use, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := checkSourceActivation(t.Context(), startup.source, activation, proposal, limits.source, limits.region); err != nil {
		t.Fatal(err)
	}
	for _, consumer := range []string{"startup", "activation"} {
		for _, dimension := range []string{"work", "bytes"} {
			t.Run(consumer+"/"+dimension, func(t *testing.T) {
				capture, err := captureSelectedSource(startup.source, limits.source)
				if err != nil {
					t.Fatal(err)
				}
				if consumer == "startup" {
					if _, err := capture.strings(startup.linkerFlags); err != nil {
						t.Fatal(err)
					}
				}
				bounded := limits
				if dimension == "work" {
					bounded.source.work = capture.work + raw.work - 1
				} else {
					bounded.source.bytes = capture.bytes + raw.bytes - 1
				}
				// Both components fit on their own. Their composition does not.
				if _, err := captureSelectedSource(startup.source, bounded.source); err != nil {
					t.Fatal("capture alone failed", err)
				}
				if _, err := newSelectedSourceBinder(t.Context(), startup.source, main, bounded.source); err != nil {
					t.Fatal("binding alone failed", err)
				}
				if consumer == "startup" {
					got, err := prepareSourceEntry(t.Context(), startup, main, use, bounded)
					var failure *sourceStartupFailure
					if got != nil || !errors.As(err, &failure) || failure.phase != sourceStartupSelection || failure.operation != "owner" {
						t.Fatalf("startup renewed capture allowance or lost attribution: %v", err)
					}
				} else {
					if got, err := checkSourceActivation(t.Context(), startup.source, activation, proposal, bounded.source, bounded.region); got != nil || err == nil {
						t.Fatal("activation renewed capture allowance")
					}
				}
			})
		}
	}
}

func TestSelectedSourceCaptureOwnedSelection(t *testing.T) {
	startup, main, _ := startupFixture(t, map[string][]string{"main": {`package main;func consume(int){};func main(){consume(1)}`}})
	startup.source.metas[0].Module = &listing.Module{Path: "original", Replace: &listing.Module{Path: "replacement"}}
	flags := []string{"-X=main.value=original"}
	capture, err := captureSelectedSource(startup.source, defaultRegistrationLimits().source)
	if err != nil {
		t.Fatal(err)
	}
	ownedFlags, err := capture.strings(flags)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() {
		startup.source.metas[0].GoFiles[0] = "forged.go"
		startup.source.metas[0].Module.Replace.Path = "forged replacement"
		flags[0] = "changed"
	}}
	b, err := capture.binder(ctx, main)
	if err != nil {
		t.Fatal(err)
	}
	if b.source.metas[0].GoFiles[0] != "0.go" || b.source.metas[0].Module.Replace.Path != "replacement" || ownedFlags[0] != "-X=main.value=original" {
		t.Fatal("callback changed captured selection buffers")
	}
	// Module identity is retained inventory, not an interpretation of module
	// behavior. Cyclic caller metadata must be bounded before any callback.
	startup.source.metas[0].Module.Replace = startup.source.metas[0].Module
	if got, err := captureSelectedSource(startup.source, selectedSourceLimits{work: 1000, bytes: 10000, depth: 2}); got != nil || err == nil {
		t.Fatal("cyclic module inventory escaped capture bound")
	}
}

func TestSourceStartupCaptureControl(t *testing.T) {
	startup, main, use := startupFixture(t, map[string][]string{"main": {`package main;func consume(int){};func main(){consume(1)}`}})
	startup.linkerFlags = []string{"-X=main.value=external"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err := prepareSourceEntry(ctx, startup, main, use, registrationLimits{})
	var failure *sourceStartupFailure
	if got != nil || !errors.Is(err, context.Canceled) || !errors.As(err, &failure) || failure.phase != sourceStartupSelection || failure.operation != "capture" {
		t.Fatalf("capture cancellation attribution changed: %v", err)
	}
	got, err = prepareSourceEntry(t.Context(), startup, nil, use, registrationLimits{})
	if got != nil || !errors.As(err, &failure) || failure.phase != sourceStartupSelection || failure.operation != "external-initialization" {
		t.Fatalf("linker flags bypassed initialization control: %v", err)
	}
	limits := defaultRegistrationLimits()
	startup.linkerFlags[0] = strings.Repeat("x", limits.source.bytes)
	counted := &regionCallCountingContext{Context: t.Context()}
	got, err = prepareSourceEntry(counted, startup, main, use, limits)
	if got != nil || !errors.As(err, &failure) || failure.operation != "capture" || counted.checks != 0 {
		t.Fatalf("unbounded capture reached caller callback: %v, callbacks=%d", err, counted.checks)
	}
}
