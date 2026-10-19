package nativeproof

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestTransitionDeferredXORPreservesDeadCycle(t *testing.T) {
	for _, region := range []bool{false, true} {
		for _, mode := range []string{"dead-self", "dead-other-form", "live", "unknown"} {
			code := hexBytes(t, "b80000000085c0740431c9ebfec3")
			if mode == "dead-other-form" {
				code[10] = 0xc1
			}
			if mode == "live" {
				code[1] = 1
			}
			branch, xor, cut := uint64(7), uint64(9), uint64(13)
			if mode == "unknown" {
				code = code[7:]
				branch, xor, cut = 0, 2, 6
			}
			entry := testEntry
			if region {
				code = append([]byte{0xc3}, code...)
				entry++
			}
			im := image(t, code)
			propose := func(stop uint64, choices ...TransitionExpansion) (TransitionProposal, error) {
				if region {
					return ProposeRegionTransition(t.Context(), im, entry, stop, TransitionLimits{}, TransitionOptions{Expansions: choices})
				}
				return ProposeTransition(t.Context(), im, stop, TransitionLimits{}, TransitionOptions{Expansions: choices})
			}
			check := func(p TransitionProposal) (TransitionCertificate, error) {
				if region {
					return CheckRegionTransition(t.Context(), im, entry, transitionFace(), p, TransitionLimits{})
				}
				return CheckTransition(t.Context(), im, transitionFace(), p, TransitionLimits{})
			}
			p, err := propose(entry + cut)
			if err != nil {
				t.Fatal(region, mode, err)
			}
			c, err := check(p)
			p0, err0 := propose(entry + branch)
			if err0 != nil {
				t.Fatal(err0)
			}
			prior, err0 := check(p0)
			if err0 != nil {
				t.Fatal(err0)
			}
			next, nextErr := CheckTransitionContinuation(t.Context(), prior, continuationProposal(t, prior, entry+cut))
			if mode == "live" || mode == "unknown" {
				transitionRefused(t, c, err)
				transitionRefused(t, next, nextErr)
			} else {
				if err != nil || nextErr != nil {
					t.Fatal("formerly accepted dead cycle refused", region, mode, err, nextErr)
				}
				b, _ := c.Bound()
				if len(b.ExcludedBoundaries) != 1 || b.ExcludedBoundaries[0].PC != entry+xor || b.ConditionalRegion != region {
					t.Fatal("dead XOR lost its actual boundary/root")
				}
				for _, ins := range b.Instructions {
					if ins.Start == entry+xor {
						t.Fatal("excluded XOR acquired execution authority")
					}
				}
				assertTransitionAlpha(t, c, next)
			}
			// Expansion is a fixed search choice, never error-driven fallback.
			// A selected unsupported form refuses; a selected self-XOR discovers
			// the cycle and refuses even when its incoming condition is false.
			if _, err := propose(entry+cut, TransitionExpansion{PC: entry + xor}); err == nil {
				t.Fatal("expanded cycle/form selected successful fallback")
			}
		}
	}
}

func TestTransitionXORExpansionEvidence(t *testing.T) {
	// Two distinct CALL activations execute the same XOR instruction. Choices
	// are occurrence-qualified, and continuation retains the first activation's
	// checked transfers and effects across its actual return.
	im := image(t, hexBytes(t, "e806000000e801000000c331c9c3"))
	end := testEntry + 10
	choices := []TransitionExpansion{{PC: testEntry}, {PC: testEntry + 5},
		{PC: testEntry + 11, Context: 1},
		{PC: testEntry + 11, Context: 4}}
	f := transitionFace()
	f.Regions = append(f.Regions, RelativeRegion{Bytes: RelativeSpan{Start: -8, End: 0}, Readable: true, Writable: true})
	p, err := ProposeTransition(t.Context(), im, end, TransitionLimits{}, TransitionOptions{Expansions: choices})
	if err != nil {
		t.Fatal(err)
	}
	flat, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	// The cut at the first call's continuation has only the first activation's
	// expansion choices. Extending it must preserve those exact occurrences.
	first, err := ProposeTransition(t.Context(), im, testEntry+5, TransitionLimits{}, TransitionOptions{Expansions: []TransitionExpansion{choices[0], choices[2]}})
	if err != nil {
		t.Fatal(err)
	}
	prior, err := CheckTransition(t.Context(), im, f, first, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	nextProposal := continuationProposal(t, prior, end, TransitionOptions{Expansions: []TransitionExpansion{choices[1], choices[3]}})
	continued, err := CheckTransitionContinuation(t.Context(), prior, nextProposal)
	if err != nil {
		t.Fatal(err)
	}
	assertCallTLSAlpha(t, flat, continued)
	before, _ := flat.Bound()
	for _, mode := range []string{"omitted", "duplicate", "unused", "wrong-context", "cancel", "budget"} {
		q := lifecycleProposal(p)
		ctx := t.Context()
		limits := TransitionLimits{}
		switch mode {
		case "omitted":
			q.Nodes[1].Expanded = false
		case "duplicate":
			q.Nodes = append(q.Nodes, q.Nodes[1])
		case "unused":
			q.Nodes[len(q.Nodes)-1].Expanded = true
		case "wrong-context":
			q.Nodes[0].Successors[0] = q.Nodes[4].ID
		case "cancel":
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		case "budget":
			limits.RelationLimits.Work = 1
		}
		c, err := CheckTransition(ctx, im, f, q, limits)
		transitionRefused(t, c, err)
		if mode == "cancel" && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	owned := lifecycleProposal(p)
	ctx := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
		if n == 1 {
			owned.Nodes[1].PC++
			owned.Nodes[1].Expanded = false
		}
	}}
	if _, err := CheckTransition(ctx, im, f, owned, TransitionLimits{}); err != nil {
		t.Fatal("choice container was not captured", err)
	}
	after, _ := flat.Bound()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed sibling changed positive evidence")
	}
	// Truncated boundary encoding is fatal before any exclusion can be proposed.
	invalid := image(t, hexBytes(t, "b80000000085c074020f"))
	if _, err := ProposeTransition(t.Context(), invalid, testEntry+9, TransitionLimits{}); err == nil {
		t.Fatal("invalid deferred boundary accepted")
	}
}
