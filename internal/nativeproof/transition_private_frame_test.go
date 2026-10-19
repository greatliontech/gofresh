package nativeproof

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestTransitionPrivateFrameRetainedPremise(t *testing.T) {
	// PUSH/POP preserves an incoming pointer even if its numeric value points
	// into the saved slot. Generic return must retain that slot's changed bytes;
	// an ownership antecedent, rather than pointer inequality, licenses a later
	// consumer to consider a private projection.
	im, face := returnFixture(t, "554889e55dc3")
	face.PrivateFrame = &TransitionPrivateFrame{Bytes: RelativeSpan{-24, 0}}
	p := entryRelationProposal(t, im, testEntry+4)
	first := entryRelationCheck(t, im, face, p)
	q := entryRelationProposal(t, im, testEntry+5)
	next, err := CheckTransitionContinuation(t.Context(), first, q)
	if err != nil {
		t.Fatal(err)
	}
	returned := checkedReturn(t, next)
	b, _ := returned.Bound()
	if !reflect.DeepEqual(b.Prefix.Interface.PrivateFrame, face.PrivateFrame) {
		t.Fatal("private lifetime premise disappeared in continuation/return")
	}
	const origin = uint64(1 << 40)
	values := entryRelationValues(b.Prefix, origin, 0)
	values[b.Prefix.InitialRegisters[RBP]] = origin - 8
	if stateEval(t, b.State.Registers[RBP].Value, values) != origin-8 {
		t.Fatal("ownership fabricated pointer inequality or lost restoration")
	}
	writes := 0
	for _, access := range b.Accesses {
		if access.Kind == FrameWrite {
			writes++
			if access.Bytes != (RelativeSpan{-8, 0}) || stateEval(t, access.Value, values) != origin-8 {
				t.Fatal("private write was erased or changed")
			}
		}
	}
	if writes != 1 {
		t.Fatal("return lost the private write occurrence")
	}
	for _, cell := range b.State.Memory {
		if !cell.Image && cell.Offset >= -8 && cell.Offset < 0 {
			want := (origin - 8) >> (8 * uint(cell.Offset+8)) & 255
			if stateEval(t, cell.Value, values) != want {
				t.Fatal("release rolled back residual bytes")
			}
		}
	}
	// Both caller input and returned projection are mutable, but not the owned
	// premise. An independently checked root without it remains without it.
	face.PrivateFrame.Bytes.Start = -8
	b.Prefix.Interface.PrivateFrame.Bytes.Start = -16
	retained, _ := returned.Bound()
	if retained.Prefix.Interface.PrivateFrame.Bytes != (RelativeSpan{-24, 0}) {
		t.Fatal("mutable ownership declaration changed an existing theorem")
	}
	face.PrivateFrame = nil
	plain := checkedReturn(t, entryRelationCheck(t, im, face, q))
	plainBound, _ := plain.Bound()
	if plainBound.Prefix.Interface.PrivateFrame != nil || len(plainBound.Accesses) != len(b.Accesses) {
		t.Fatal("generic return invented ownership or omitted frame effects")
	}
}

func TestTransitionPrivateFrameValidation(t *testing.T) {
	im, face := returnFixture(t, "c3")
	face.PrivateFrame = &TransitionPrivateFrame{Bytes: RelativeSpan{-24, 0}}
	p := entryRelationProposal(t, im, testEntry)
	entryRelationCheck(t, im, face, p)
	for _, tc := range []struct {
		name string
		edit func(*TransitionInterface)
	}{
		{"empty", func(f *TransitionInterface) { f.PrivateFrame.Bytes.Start = 0 }},
		{"reverse", func(f *TransitionInterface) { f.PrivateFrame.Bytes.End = -32 }},
		{"control-overlap", func(f *TransitionInterface) { f.PrivateFrame.Bytes.End = 1 }},
		{"outside-envelope", func(f *TransitionInterface) { f.PrivateFrame.Bytes.Start = -32 }},
		{"wrapping", func(f *TransitionInterface) { f.PrivateFrame.Bytes.Start = math.MinInt64 }},
		{"no-memory", func(f *TransitionInterface) { f.Regions = f.Regions[1:] }},
		{"no-write", func(f *TransitionInterface) { f.Regions[0].Writable = false }},
		{"no-read", func(f *TransitionInterface) { f.Regions[0].Readable = false }},
		{"no-lifetime", func(f *TransitionInterface) { f.ReturnContext = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := cloneTransitionInterface(face)
			tc.edit(&f)
			c, err := CheckRegionTransition(t.Context(), im, testEntry, f, p, TransitionLimits{})
			transitionRefused(t, c, err)
		})
	}
	c, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
	transitionRefused(t, c, err)
	count := &imageCallbackContext{Context: t.Context()}
	if _, err := CheckRegionTransition(count, im, testEntry, face, p, TransitionLimits{}); err != nil {
		t.Fatal(err)
	}
	for at := 1; at <= count.calls; at++ {
		f := cloneTransitionInterface(face)
		ctx := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n == at {
				f.PrivateFrame.Bytes = RelativeSpan{}
			}
		}}
		c, err := CheckRegionTransition(ctx, im, testEntry, f, p, TransitionLimits{})
		if err != nil || c.checked.bound.Interface.PrivateFrame.Bytes != face.PrivateFrame.Bytes {
			t.Fatal("context callback crossed the premise snapshot", at, err)
		}
		cancelCtx, cancel := context.WithCancel(t.Context())
		stop := &imageCallbackContext{Context: cancelCtx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		c, err = CheckRegionTransition(stop, im, testEntry, face, p, TransitionLimits{})
		cancel()
		if !errors.Is(err, context.Canceled) || c.checked != nil {
			t.Fatal("cancelled premise check published", at, err)
		}
	}
}
