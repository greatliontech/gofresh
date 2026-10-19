package nativeproof

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestTransitionNewFormsDeferredAcrossDeadCycles(t *testing.T) {
	// Each byte spelling was a structural-only boundary before its transfer
	// grammar existed. Admitting that transfer must not expose its dead cycle.
	for _, form := range []string{"84c9", "84e1", "4084e4", "f6c1ff", "a8ff",
		"393424", "48393424", "3b3424", "483b3424", "833c2400", "48833c2400", "813c2400000000", "48813c2400000000", "90", "6690", "488711", "f0480fc111", "4801f2", "0f1f440000"} {
		for _, region := range []bool{false, true} {
			for _, guard := range []string{"dead", "live", "unknown"} {
				t.Run(form+"/"+guard+map[bool]string{false: "/elf", true: "/region"}[region], func(t *testing.T) {
					prefix := hexBytes(t, "b80000000085c0")
					if guard == "live" {
						prefix[1] = 1
					}
					if guard == "unknown" {
						prefix = nil
					}
					boundary := hexBytes(t, form)
					code := append(prefix, 0x74, byte(len(boundary)+2))
					point := testEntry + uint64(len(code))
					branch := point - 2
					code = append(code, boundary...)
					code = append(code, 0xeb, 0xfe, 0xc3)
					entry := testEntry
					if region {
						code = append([]byte{0xc3}, code...)
						entry++
						point++
						branch++
					}
					im := image(t, code)
					cut := testEntry + uint64(len(code)-1)
					propose := func(ctx context.Context, stop uint64, l TransitionLimits, expansions ...TransitionExpansion) (TransitionProposal, error) {
						if region {
							return ProposeRegionTransition(ctx, im, entry, stop, l, expansions...)
						}
						return ProposeTransition(ctx, im, stop, l, expansions...)
					}
					check := func(ctx context.Context, p TransitionProposal, l TransitionLimits) (TransitionCertificate, error) {
						if region {
							return CheckRegionTransition(ctx, im, entry, stateFace(16, 0), p, l)
						}
						return CheckTransition(ctx, im, stateFace(16, 0), p, l)
					}
					p, err := propose(t.Context(), cut, TransitionLimits{})
					if err != nil {
						t.Fatal(err)
					}
					flat, flatErr := check(t.Context(), p, TransitionLimits{})
					before, err := propose(t.Context(), branch, TransitionLimits{})
					if err != nil {
						t.Fatal(err)
					}
					root, err := check(t.Context(), before, TransitionLimits{})
					if err != nil {
						t.Fatal(err)
					}
					next, nextErr := CheckTransitionContinuation(t.Context(), root, p)
					if guard != "dead" {
						transitionRefused(t, flat, flatErr)
						transitionRefused(t, next, nextErr)
					} else {
						if flatErr != nil || nextErr != nil {
							t.Fatal("lost dead-form positive", flatErr, nextErr)
						}
						b := next.checked.bound
						if len(b.ExcludedBoundaries) != 1 || b.ExcludedBoundaries[0].PC != point || b.ConditionalRegion != region || len(b.Accesses) != 0 {
							t.Fatal("dead form acquired transfer")
						}
						assertTransitionAlpha(t, flat, next)
					}
					// Expansion is a prior search choice: even a proved-dead arm's
					// exposed cycle refuses; there is no error-driven fallback.
					_, err = propose(t.Context(), cut, TransitionLimits{}, TransitionExpansion{PC: point})
					var refusal *Refusal
					if !errors.As(err, &refusal) || refusal.Premise != "acyclic-control" {
						t.Fatal("expanded cycle did not refuse", err)
					}
					ctx, cancel := context.WithCancel(t.Context())
					cancel()
					if _, err := propose(ctx, cut, TransitionLimits{}); !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
					c, err := check(ctx, p, TransitionLimits{})
					transitionRefused(t, c, err)
					if !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
					c, err = CheckTransitionContinuation(ctx, root, p)
					transitionRefused(t, c, err)
					if !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
					c, err = check(t.Context(), p, TransitionLimits{RelationLimits: RelationLimits{Work: 1}})
					transitionRefused(t, c, err)
					if _, err = propose(t.Context(), cut, TransitionLimits{RelationLimits: RelationLimits{Instructions: 1}}); err == nil {
						t.Fatal("budget selected fallback")
					}
				})
			}
		}
	}
}

func TestTransitionOptionalNewFormsStillValidate(t *testing.T) {
	for _, form := range []string{"84c9", "f6c1ff", "a8ff", "48393424", "483b3424", "48833c2400", "48813c2400000000", "90", "6690"} {
		boundary := hexBytes(t, form)
		// A malformed LOCK prefix faults independently of the false guard.
		code := append(hexBytes(t, "b80000000085c074"), byte(len(boundary)+3))
		code = append(code, 0xf0)
		code = append(code, boundary...)
		code = append(code, 0xeb, 0xfe, 0xc3)
		im := image(t, code)
		if _, err := ProposeTransition(t.Context(), im, testEntry+uint64(len(code)-1), TransitionLimits{}); err == nil {
			t.Fatal("invalid prefix became dead evidence", form)
		}
		// Cut precedes the malformed terminal physically, but the false branch
		// still requires structural decoding and cannot borrow unavailable bytes.
		truncated := boundary[:len(boundary)-1]
		if form == "90" {
			truncated = []byte{0x66}
		}
		code = append(hexBytes(t, "b80000000085c0eb01c374fd"), truncated...)
		im = image(t, code)
		if _, err := ProposeTransition(t.Context(), im, testEntry+9, TransitionLimits{}); err == nil {
			t.Fatal("truncation became dead evidence", form)
		}
		// Explicit expansion of a live form still checks its actual state and
		// memory applicability rather than accepting a boundary declaration.
		code = append(append([]byte(nil), boundary...), 0xc3)
		im = image(t, code)
		p, err := ProposeTransition(t.Context(), im, testEntry+uint64(len(boundary)), TransitionLimits{}, TransitionExpansion{PC: testEntry})
		if err != nil {
			t.Fatal(err)
		}
		f := stateFace(16, 0)
		i, _, err := decodeBytes(im, testEntry)
		if err != nil {
			t.Fatal(err)
		}
		if i.Op == x86asm.CMP {
			f.Regions = nil
			f.Words = nil
		} else {
			f.Conditions.InstructionMapping = false
		}
		c, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
		transitionRefused(t, c, err)
	}
	for _, form := range []string{"39c8", "4839c8", "83f800", "4883f800", "85c9", "4885c9", "f7c101000000", "48f7c101000000", "a901000000", "48a901000000"} {
		code := hexBytes(t, form)
		im := image(t, append(code, 0xc3))
		i, _, err := decodeBytes(im, testEntry)
		if err != nil {
			t.Fatal(err)
		}
		if TransitionExpansionRequired(i) {
			t.Fatal("legacy register form became optional", form)
		}
		p, err := ProposeTransition(t.Context(), im, testEntry+uint64(len(code)), TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckTransition(t.Context(), im, stateFace(16, 0), p, TransitionLimits{}); err != nil {
			t.Fatal("legacy live form refused", form, err)
		}
	}
}
