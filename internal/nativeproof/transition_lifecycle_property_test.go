package nativeproof

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
)

func lifecycleProposal(p TransitionProposal) TransitionProposal {
	p.Nodes = append([]TransitionNode(nil), p.Nodes...)
	for i := range p.Nodes {
		p.Nodes[i].Successors = append([]TransitionOccurrenceID(nil), p.Nodes[i].Successors...)
	}
	return p
}

func lifecycleFace(extra uint8) TransitionInterface {
	f := transitionFace()
	if extra&64 != 0 {
		f.Conditions.CPUID = CPUIDModel
	}
	if extra&128 != 0 {
		f.ImageRegions = []Span{{testEntry, testEntry + 1}}
	}
	for j := int64(0); j < int64(extra%17); j++ {
		off := 16 + 8*j
		f.Regions = append(f.Regions, RelativeRegion{RelativeSpan{off, off + 8}, true, false})
		f.Words = append(f.Words, off)
		f.Envelope.End = off + 8
	}
	f.Origin.Max = 1<<47 - uint64(f.Envelope.End) - 16
	return f
}

// Expected snapshots must not rely on Bound's copying behavior: that behavior
// is under test. Expression handles remain immutable; every mutable container is
// independently copied here before a different projection is deliberately changed.
// Geometry is an immutable handle, retained by exact identity rather than cloned.
func lifecycleSnapshot(b TransitionBound) TransitionBound {
	b.Interface.Regions = slices.Clone(b.Interface.Regions)
	b.Interface.ImageRegions = slices.Clone(b.Interface.ImageRegions)
	b.Interface.Words = slices.Clone(b.Interface.Words)
	b.ExcludedOrigins = slices.Clone(b.ExcludedOrigins)
	b.InitialMemory = slices.Clone(b.InitialMemory)
	b.Words = slices.Clone(b.Words)
	b.Memory = slices.Clone(b.Memory)
	b.Instructions = slices.Clone(b.Instructions)
	b.Accesses = slices.Clone(b.Accesses)
	b.PrimitiveEffects = slices.Clone(b.PrimitiveEffects)
	b.Frames = slices.Clone(b.Frames)
	b.Abstractions = slices.Clone(b.Abstractions)
	b.Expansions = slices.Clone(b.Expansions)
	b.Boundary.Bytes = slices.Clone(b.Boundary.Bytes)
	b.ExcludedBoundaries = slices.Clone(b.ExcludedBoundaries)
	for j := range b.ExcludedBoundaries {
		b.ExcludedBoundaries[j].Bytes = slices.Clone(b.ExcludedBoundaries[j].Bytes)
	}
	return b
}

// Property inputs choose the state shape and an actual callback checkpoint.
// Mutations touch caller-owned containers only, never private immutable arenas.
// This is lifecycle evidence alongside the separate interface/transfer domains.
func FuzzTransitionLifecycle(f *testing.F) {
	for _, extra := range []uint8{0, 1, 16, 64, 65, 80, 128, 129, 144, 192} {
		for _, checkpoint := range []uint32{0, 1, 0xffffffff} {
			f.Add(extra, checkpoint)
		}
	}
	f.Fuzz(func(t *testing.T, extra uint8, checkpoint uint32) {
		prefix := hexBytes(t, entryPrefix)
		suffix := hexBytes(t, "bd00000000")
		if extra&64 != 0 {
			prefix = append(prefix, 0x0f, 0xa2)
			suffix = append(suffix, 0x0f, 0xa2)
		}
		im := image(t, append(append(slices.Clone(prefix), suffix...), 0xc3))
		bound := func(c TransitionCertificate) TransitionBound {
			t.Helper()
			b, ok := c.Bound()
			if !ok || b.ImageDigest != im.digest {
				t.Fatal("positive construction lost its certificate or image identity")
			}
			return b
		}
		cut := testEntry + uint64(len(prefix))
		p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		count := &imageCallbackContext{Context: t.Context()}
		root, err := CheckTransition(count, im, lifecycleFace(extra), p, TransitionLimits{})
		if err != nil || count.calls == 0 {
			t.Fatal("missing positive root or callbacks", err)
		}
		before := lifecycleSnapshot(bound(root))
		inherited := func(b TransitionBound) {
			t.Helper()
			if b.Geometry != before.Geometry || b.Origin != before.Origin || b.InitialRegisters != before.InitialRegisters ||
				!reflect.DeepEqual(b.InitialMemory, before.InitialMemory) || !reflect.DeepEqual(b.Words, before.Words) ||
				!reflect.DeepEqual(b.Interface, before.Interface) {
				t.Fatal("continuation replaced inherited inputs or premises")
			}
		}
		at := int(uint64(checkpoint)%uint64(count.calls)) + 1
		face, supplied, proposal := lifecycleFace(extra), *im, lifecycleProposal(p)
		mutated := false
		callback := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n != at {
				return
			}
			mutated = true
			supplied = Image{}
			for i := range face.Regions {
				face.Regions[i] = RelativeRegion{}
			}
			for i := range face.ImageRegions {
				face.ImageRegions[i] = Span{}
			}
			for i := range face.Words {
				face.Words[i]++
			}
			for i := range proposal.Nodes {
				for j := range proposal.Nodes[i].Successors {
					proposal.Nodes[i].Successors[j]++
				}
				proposal.Nodes[i].PC++
			}
		}}
		owned, err := CheckTransition(callback, &supplied, face, proposal, TransitionLimits{})
		if err != nil || !mutated {
			t.Fatal("root capture did not isolate callback mutations", err)
		}
		ownedBound := bound(owned)
		ownedRoot, ownedRootBefore := owned, lifecycleSnapshot(ownedBound)
		assertCutStateAlpha(t, before, ownedBound)
		cancelled, cancel := context.WithCancel(t.Context())
		ctx := &imageCallbackContext{Context: cancelled, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		c, err := CheckTransition(ctx, im, lifecycleFace(extra), p, TransitionLimits{})
		cancel()
		if c.checked != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled root published evidence", err)
		}

		next, err := ProposeTransitionContinuation(t.Context(), root, cut+uint64(len(suffix)))
		if err != nil {
			t.Fatal(err)
		}
		count = &imageCallbackContext{Context: t.Context()}
		continued, err := CheckTransitionContinuation(count, root, next)
		if err != nil || count.calls == 0 {
			t.Fatal("missing positive continuation or callbacks", err)
		}
		want := lifecycleSnapshot(bound(continued))
		inherited(want)
		at = int(uint64(checkpoint)%uint64(count.calls)) + 1
		projection := bound(root)
		proposal = lifecycleProposal(next)
		mutated = false
		callback = &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n != at {
				return
			}
			mutated = true
			for i := range projection.Boundary.Bytes {
				projection.Boundary.Bytes[i] = 0
			}
			for i := range projection.Interface.Regions {
				projection.Interface.Regions[i] = RelativeRegion{}
			}
			for i := range projection.Interface.ImageRegions {
				projection.Interface.ImageRegions[i] = Span{}
			}
			for i := range projection.Memory {
				projection.Memory[i] = TransitionByte{}
			}
			for i := range projection.InitialMemory {
				projection.InitialMemory[i] = TransitionByte{}
			}
			for i := range projection.PrimitiveEffects {
				projection.PrimitiveEffects[i] = CPUIDEffect{}
			}
			for i := range proposal.Nodes {
				proposal.Nodes[i].Size++
				for j := range proposal.Nodes[i].Successors {
					proposal.Nodes[i].Successors[j]++
				}
			}
		}}
		owned, err = CheckTransitionContinuation(callback, root, proposal)
		if err != nil || !mutated {
			t.Fatal("continuation capture did not isolate callback mutations", err)
		}
		ownedBound = bound(owned)
		inherited(ownedBound)
		assertCutStateAlpha(t, want, ownedBound)
		ownedBefore := lifecycleSnapshot(ownedBound)
		cancelled, cancel = context.WithCancel(t.Context())
		ctx = &imageCallbackContext{Context: cancelled, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		c, err = CheckTransitionContinuation(ctx, root, next)
		cancel()
		if c.checked != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled continuation published evidence", err)
		}
		for _, retained := range []struct {
			certificate TransitionCertificate
			snapshot    TransitionBound
		}{{root, before}, {ownedRoot, ownedRootBefore}, {continued, want}, {owned, ownedBefore}} {
			if !reflect.DeepEqual(retained.snapshot, bound(retained.certificate)) {
				t.Fatal("retained predecessor or sibling changed across construction")
			}
		}
	})
}
