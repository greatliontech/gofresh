package nativeproof

import (
	"context"
	"errors"
	"math"
	"strconv"
	"testing"
)

func geometryCertificate(t testing.TB) (*Image, TransitionCertificate) {
	t.Helper()
	im := image(t, []byte{0x90, 0xc3})
	f := transitionFace()
	f.Words = nil
	f.Regions = []RelativeRegion{
		{Bytes: RelativeSpan{4, 8}, Readable: true, Writable: true},
		{Bytes: RelativeSpan{0, 4}, Readable: true, Writable: true},
		{Bytes: RelativeSpan{2, 6}, Readable: true, Writable: true},
	}
	f.ImageRegions = []Span{{testEntry, testEntry + 1}, {testEntry + 1, testEntry + 2}}
	f.EntryImagePointers = []TransitionEntryImagePointer{{Register: RAX, Address: testEntry}}
	p, err := ProposeRegionTransition(t.Context(), im, testEntry, testEntry, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckRegionTransition(t.Context(), im, testEntry, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return im, c
}

func TestTransitionGeometryOwnedCoverageAndAccess(t *testing.T) {
	im, c := geometryCertificate(t)
	b, _ := c.BoundFor(im)
	g := b.Geometry
	stack, err := g.ResolveStorage(t.Context(), StackOffset(0), 8)
	if err != nil {
		t.Fatal(err)
	}
	image, err := g.ResolveStorage(t.Context(), ImageAddress(testEntry), 2)
	if err != nil {
		t.Fatal(err)
	}
	if stack.Width() != 8 || image.Width() != 2 || stack.Start() == image.Start() {
		t.Fatal("canonical extent differs")
	}
	for _, test := range []struct {
		pointer TransitionPointer
		extent  TransitionExtent
	}{{b.Registers[RSP].Pointer, stack}, {b.Registers[RAX].Pointer, image}} {
		resolved, err := g.ResolvePointer(t.Context(), test.pointer, 0, test.extent.Width())
		if err != nil || resolved != test.extent {
			t.Fatal("pointer and selector did not normalize", err)
		}
	}
	m, err := newTransitionChecker(t.Context(), im, transitionRoot{entry: testEntry, region: true}, c.checked.limits, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.inherit(*c.checked); err != nil {
		t.Fatal(err)
	}
	// Aggregate coordinate coverage is not the permission of one native operand.
	for _, test := range []struct {
		pointer TransitionPointer
		width   int
	}{{b.Registers[RSP].Pointer, 8}, {b.Registers[RAX].Pointer, 2}} {
		if _, err := m.accessPointer(test.pointer, FrameRead, test.width); err == nil {
			t.Fatal("union coverage manufactured a native access grant")
		}
	}
	if _, err := m.accessPointer(b.Registers[RSP].Pointer, FrameRead, 4); err != nil {
		t.Fatal("existing full-region access refused", err)
	}
	for j := int64(0); j < stack.Width(); j++ {
		key, err := stack.Byte(j)
		if err != nil {
			t.Fatal(err)
		}
		cell, exists := m.memory[key]
		if !exists || cell.TransitionLocation != key {
			t.Fatal("shared canonical byte absent")
		}
	}
	sub, err := stack.Subextent(2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if contained, err := g.Contains(stack, sub); err != nil || !contained {
		t.Fatal("lost containment", err)
	}
	if overlap, err := g.Overlaps(stack, sub); err != nil || !overlap {
		t.Fatal("lost overlap", err)
	}
	if overlap, err := g.Overlaps(stack, image); err != nil || overlap {
		t.Fatal("lost checked stack/image separation", err)
	}
	if n, err := g.Compare(stack.Start(), image.Start()); err != nil || n >= 0 {
		t.Fatal("nondeterministic role ordering", err)
	}
	if aligned, err := g.CheckAlignment(stack, 8); err != nil || !aligned {
		t.Fatal("lost universal alignment", err)
	}
	if aligned, err := g.CheckAlignment(sub, 8); err != nil || aligned {
		t.Fatal("misaligned subextent", err)
	}
	for _, bad := range []int64{-1, 8, math.MaxInt64} {
		if _, err := stack.Byte(bad); err == nil {
			t.Fatal("out-of-bounds byte")
		}
	}
	for _, bad := range [][2]int64{{-1, 1}, {0, 0}, {7, 2}, {1, math.MaxInt64}} {
		if _, err := stack.Subextent(bad[0], bad[1]); err == nil {
			t.Fatal("out-of-bounds subextent")
		}
	}
	for _, bad := range []StorageSelector{nil, ImageAddress(-1), StackOffset(8), StackOffset(math.MaxInt64), ImageAddress(testEntry + 2)} {
		if _, err := g.ResolveStorage(t.Context(), bad, 1); err == nil {
			t.Fatal("invalid selector admitted", bad)
		}
	}
	for _, width := range []int64{-1, 0, 9, math.MaxInt64} {
		if _, err := g.ResolveStorage(t.Context(), StackOffset(0), width); err == nil {
			t.Fatal("invalid or partially covered full extent admitted", width)
		}
	}
	end, err := m.advance(b.Registers[RAX].Pointer, 2)
	if err != nil {
		t.Fatal("lost image one-past pointer", err)
	}
	if _, err := g.ResolvePointer(t.Context(), end, 0, 1); err == nil {
		t.Fatal("one-past pointer granted a byte")
	}
	if _, err := g.ResolvePointer(t.Context(), end, -1, 1); err != nil {
		t.Fatal("one-past could not move back", err)
	}
}

func TestTransitionGeometryLogicalLoadBoundary(t *testing.T) {
	const boundary = imageStateAddress + 4096
	loads := []interfaceMapping{
		{start: imageStateAddress, end: boundary, file: 0x10000, filesz: 4096, read: true, write: true},
		{start: boundary, end: boundary + 4096, file: 0x11000, filesz: 4096, read: true, write: true},
	}
	im, err := NewImage(t.Context(), transitionImageELF(t, []byte{0xc3}, loads))
	if err != nil {
		t.Fatal(err)
	}
	f := transitionFace()
	f.ImageRegions = []Span{{boundary - 1, boundary}, {boundary, boundary + 1}}
	f.EntryImagePointers = []TransitionEntryImagePointer{{Register: RAX, Address: boundary - 1}, {Register: RBX, Address: boundary}}
	p, err := ProposeRegionTransition(t.Context(), im, testEntry, testEntry, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckRegionTransition(t.Context(), im, testEntry, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b := c.checked.bound
	m, err := newTransitionChecker(t.Context(), im, transitionRoot{entry: testEntry, region: true}, c.checked.limits, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.inherit(*c.checked); err != nil {
		t.Fatal(err)
	}
	onePast, err := m.advance(b.Registers[RAX].Pointer, 1)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := b.Geometry.ResolveStorage(t.Context(), ImageAddress(boundary-1), 2)
	if err != nil || aggregate.Width() != 2 {
		t.Fatal("aggregate lost adjacent declared bytes", err)
	}
	if _, err := b.Geometry.ResolvePointer(t.Context(), onePast, 0, 1); err == nil {
		t.Fatal("one-past acquired adjacent logical load authority")
	}
	if _, err := m.accessPointer(onePast, FrameRead, 1); err == nil {
		t.Fatal("native access escaped original logical load")
	}
	next, err := b.Geometry.ResolvePointer(t.Context(), b.Registers[RBX].Pointer, 0, 1)
	if err != nil {
		t.Fatal("actual adjacent-load pointer refused", err)
	}
	byteKey, err := aggregate.Byte(1)
	if err != nil || next.Start() != byteKey {
		t.Fatal("adjacent coordinates failed canonical normalization", err)
	}
	if _, err := m.accessPointer(b.Registers[RBX].Pointer, FrameRead, 1); err != nil {
		t.Fatal("actual adjacent-load read refused", err)
	}
}

func TestTransitionGeometryApplicationAssociation(t *testing.T) {
	f := newApplicationFixture(t, "", "c3")
	parent, child := f.certificates(t)
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.BoundFor(f.im)
	input := child.checked.prefix.checked.bound.Geometry
	if b.Geometry.Input() != input || b.Geometry.Current() != b.ChildEntry.Geometry || b.Geometry.Current() != b.Successor.Geometry || input == b.Geometry.Current() {
		t.Fatal("application lost independent input or actual caller owner")
	}
	for _, pair := range b.Memory {
		selector, err := input.Describe(pair.Input.TransitionLocation)
		if err != nil {
			t.Fatal(err)
		}
		e, err := input.ResolveStorage(t.Context(), selector, 1)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := b.Geometry.ResolveExtent(t.Context(), e)
		if err != nil || actual.Start() != pair.Current.TransitionLocation {
			t.Fatal("application byte association disagrees with current storage", err)
		}
		if _, err := b.Geometry.ResolveExtent(t.Context(), actual); err == nil {
			t.Fatal("caller coordinates were laundered as callee inputs")
		}
	}
}

func TestTransitionGeometryForeignAndProjectionIsolation(t *testing.T) {
	im, c := geometryCertificate(t)
	b, _ := c.BoundFor(im)
	p, err := ProposeRegionTransition(t.Context(), im, testEntry, testEntry, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := CheckRegionTransition(t.Context(), im, testEntry, b.Interface, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	foreign := other.checked.bound.Geometry
	g := b.Geometry
	if g == foreign || g.Origin() == foreign.Origin() {
		t.Fatal("fresh root reused owned coordinates or inputs")
	}
	local, _ := g.ResolveStorage(t.Context(), StackOffset(0), 8)
	remote, _ := foreign.ResolveStorage(t.Context(), StackOffset(0), 8)
	if local == remote || local.Start() == remote.Start() {
		t.Fatal("independent roots share storage identity")
	}
	for _, query := range []func() error{
		func() error { _, e := g.Overlaps(local, remote); return e },
		func() error { _, e := g.Contains(local, remote); return e },
		func() error { _, e := g.CheckAlignment(remote, 8); return e },
		func() error { _, e := g.Compare(local.Start(), remote.Start()); return e },
		func() error { _, e := g.Describe(remote.Start()); return e },
		func() error {
			_, e := g.ResolvePointer(t.Context(), other.checked.bound.Registers[RSP].Pointer, 0, 1)
			return e
		},
		func() error {
			_, e := g.ResolvePointer(t.Context(), other.checked.bound.Registers[RAX].Pointer, 0, 1)
			return e
		},
		func() error {
			_, e := (ActualTransitionGeometry{}).ResolveStorage(t.Context(), StackOffset(0), 1)
			return e
		},
		func() error { _, e := g.ResolvePointer(t.Context(), AddressPointer{}, 0, 1); return e },
	} {
		if err := query(); err == nil {
			t.Fatal("foreign or zero geometry supplied authority")
		}
	}
	b.Interface.Regions[0].Bytes = RelativeSpan{100, 200}
	b.Interface.ImageRegions[0] = Span{}
	b.Origin = other.checked.bound.Origin
	if retained, err := g.ResolveStorage(t.Context(), StackOffset(0), 8); err != nil || retained != local {
		t.Fatal("mutable projection changed geometry", err)
	}
	proposal, err := ProposeTransitionContinuation(t.Context(), c, testEntry+1, TransitionOptions{Expansions: []TransitionExpansion{{PC: testEntry}}})
	if err != nil {
		t.Fatal(err)
	}
	next, err := CheckTransitionContinuation(t.Context(), c, proposal)
	if err != nil {
		t.Fatal(err)
	}
	if next.checked.bound.Geometry != g || next.checked.bound.Origin != g.Origin() {
		t.Fatal("continuation replaced geometry identity")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := g.ResolveStorage(ctx, StackOffset(0), 8); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation", err)
	}
	if _, err := g.ResolvePointer(ctx, c.checked.bound.Registers[RSP].Pointer, 0, 8); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored pointer cancellation", err)
	}
}

func TestTransitionGeometrySharedStackRange(t *testing.T) {
	im, c := geometryCertificate(t)
	b := c.checked.bound
	m, err := newTransitionChecker(t.Context(), im, transitionRoot{entry: testEntry, region: true}, c.checked.limits, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.inherit(*c.checked); err != nil {
		t.Fatal(err)
	}
	sp := b.Registers[RSP].Pointer
	// Pointer arithmetic uses the entire checked envelope, not the represented
	// byte inventory. Its closed endpoints are both admissible pointer values.
	for _, offset := range []int64{-48, -1, 0, 1, 7, 8} {
		pointer, err := m.advance(sp, offset)
		if err != nil {
			t.Fatal("enclosed pointer refused", offset, err)
		}
		if got, original := b.Geometry.OriginalStack(pointer); !original || got != offset {
			t.Fatal("pointer changed original arithmetic view", offset)
		}
		if offset >= 0 && offset < 8 {
			resolved, err := b.Geometry.ResolvePointer(t.Context(), sp, offset, 1)
			if err != nil {
				t.Fatal("represented byte refused", offset, err)
			}
			access, err := m.accessPointer(pointer, FrameRead, 1)
			if err != nil || access != resolved.Start() {
				t.Fatal("native and coordinate ranges disagree", offset, err)
			}
		} else {
			if _, err := b.Geometry.ResolvePointer(t.Context(), sp, offset, 1); err == nil {
				t.Fatal("arithmetic envelope supplied storage", offset)
			}
			_, err := m.accessPointer(pointer, FrameRead, 1)
			premise := "transition-permission"
			if offset == 8 {
				premise = "transition-envelope"
			}
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Premise != premise {
				t.Fatal("lost full-range versus permission distinction", offset, err)
			}
		}
	}
	for _, offset := range []int64{-49, 9, math.MinInt64, math.MaxInt64} {
		_, err := m.advance(sp, offset)
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.Premise != "transition-envelope" {
			t.Fatal("out-of-envelope arithmetic accepted or misclassified", offset, err)
		}
		if _, err := b.Geometry.ResolvePointer(t.Context(), sp, offset, 1); err == nil {
			t.Fatal("out-of-envelope resolution accepted", offset)
		}
	}
	for _, offset := range []int64{-1, 1} {
		pointer, err := m.advance(sp, offset)
		if err != nil {
			t.Fatal(err)
		}
		delta := int64(math.MaxInt64)
		if offset < 0 {
			delta = math.MinInt64
		}
		_, err = m.advance(pointer, delta)
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.Premise != "transition-origin" {
			t.Fatal("signed displacement overflow accepted or misclassified", err)
		}
		if _, err := b.Geometry.ResolvePointer(t.Context(), pointer, delta, 1); err == nil {
			t.Fatal("signed displacement overflow resolved")
		}
		if offset > 0 {
			if strconv.IntSize == 64 {
				width := int64(math.MaxInt64)
				_, err := m.accessPointer(pointer, FrameRead, int(width))
				if !errors.As(err, &refusal) || refusal.Premise != "transition-origin" {
					t.Fatal("full-extent overflow accepted or misclassified", err)
				}
			}
			if _, err := b.Geometry.ResolvePointer(t.Context(), pointer, 0, math.MaxInt64); err == nil {
				t.Fatal("full-extent overflow resolved")
			}
		}
	}
	for _, width := range []int64{-1, 0, 9, math.MaxInt64} {
		if _, err := b.Geometry.ResolvePointer(t.Context(), sp, 0, width); err == nil {
			t.Fatal("invalid or escaped extent resolved", width)
		}
		if _, err := m.accessPointer(sp, FrameRead, int(width)); err == nil {
			t.Fatal("invalid or escaped extent accessed", width)
		}
	}
	if len(m.bound.Accesses) != len(b.Accesses) {
		t.Fatal("coordinate or permission judgment recorded an execution")
	}
}

func TestTransitionGeometryCanonicalImageEnd(t *testing.T) {
	const end = uint64(1 << 47)
	loads := []interfaceMapping{{start: end - 4096, end: end, file: 0x10000, filesz: 4096, read: true, write: true}}
	im, err := NewImage(t.Context(), transitionImageELF(t, []byte{0xc3}, loads))
	if err != nil {
		t.Fatal(err)
	}
	f := transitionFace()
	f.ImageRegions = []Span{{end - 1, end}}
	f.EntryImagePointers = []TransitionEntryImagePointer{{Register: RAX, Address: end - 1}}
	p, err := ProposeRegionTransition(t.Context(), im, testEntry, testEntry, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckRegionTransition(t.Context(), im, testEntry, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b := c.checked.bound
	m, err := newTransitionChecker(t.Context(), im, transitionRoot{entry: testEntry, region: true}, c.checked.limits, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.inherit(*c.checked); err != nil {
		t.Fatal(err)
	}
	pointer := b.Registers[RAX].Pointer
	extent, err := b.Geometry.ResolvePointer(t.Context(), pointer, 0, 1)
	if err != nil {
		t.Fatal("last canonical image byte refused", err)
	}
	last, err := m.accessPointer(pointer, FrameRead, 1)
	if err != nil || last != extent.Start() {
		t.Fatal("native last-byte access refused", err)
	}
	coordinate, err := b.Geometry.Describe(extent.End())
	if err != nil || coordinate != ImageAddress(end) {
		t.Fatal("exclusive image endpoint changed", err)
	}
	// The exclusive extent endpoint is permitted; materializing that same
	// noncanonical number as a pointer or using it as an access start is not.
	_, err = m.advance(pointer, 1)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Premise != "transition-image" {
		t.Fatal("noncanonical one-past pointer accepted or misclassified", err)
	}
	if _, err := b.Geometry.ResolvePointer(t.Context(), pointer, 1, 1); err == nil {
		t.Fatal("noncanonical first byte resolved")
	}
	if _, err := m.accessPointer(pointer, FrameRead, 2); err == nil {
		t.Fatal("full image extent escaped canonical mapping")
	}
}
