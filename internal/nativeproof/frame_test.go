package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"testing"
)

const frameData = uint64(0x60000000)
const frameStack = uint64(0x70000000)

func memoryFace() FrameInterface {
	return FrameInterface{
		Regions:  []ByteRegion{{Span{frameData, frameData + 32}, true, true, false}, {Span{frameStack, frameStack + 128}, true, true, false}},
		Pointers: []RegisterPointer{{RAX, RegionPointer{0, 0, 0}}},
		Stack:    RegionPointer{1, 64, 64}, Preserved: Masks{RBP: math.MaxUint64, R14: math.MaxUint64},
		Conditions: FrameConditions{Conditions: face(Masks{}, Masks{}).Conditions, MemoryMapping: true, NoHiddenAliases: true, UnalignedAccess: true},
	}
}

func proveFrame(t testing.TB, im *Image, entry uint64, f FrameInterface) (FrameCertificate, error) {
	t.Helper()
	p, err := ProposeFrame(t.Context(), im, entry, FrameLimits{})
	if err != nil {
		return FrameCertificate{}, err
	}
	return CheckFrame(t.Context(), im, entry, f, p, FrameLimits{})
}

func frameRefusal(t testing.TB, c FrameCertificate, err error, premise string) {
	t.Helper()
	if _, ok := c.Bound(); ok {
		t.Fatal("refusal returned a frame certificate")
	}
	requireRefusal(t, Certificate{}, err, premise)
}

func TestFrameScalarFieldsAndAliases(t *testing.T) {
	for _, tc := range []struct {
		name, code    string
		kind          AccessKind
		width, offset int
	}{
		{"Get64", "488b4008c3", FrameRead, 8, 8},
		{"Put64", "48895808c3", FrameWrite, 8, 8},
		{"Get32", "8b4010c3", FrameRead, 4, 16},
		{"Put32", "895810c3", FrameWrite, 4, 16},
		{"Get8", "0fb64014c3", FrameRead, 1, 20},
		{"Put8", "885814c3", FrameWrite, 1, 20},
		{"Get16", "0fb74016c3", FrameRead, 2, 22},
		{"Put16", "66895816c3", FrameWrite, 2, 22},
	} {
		t.Run(tc.name, func(t *testing.T) {
			im := image(t, hexBytes(t, tc.code))
			f := memoryFace()
			c, err := proveFrame(t, im, testEntry, f)
			if err != nil {
				t.Fatal(err)
			}
			b, ok := c.Bound()
			if !ok || b.Rules != FrameRules || b.ReturnedRSP != frameStack+72 || len(b.Accesses) != 2 || b.Accesses[0] != (FrameAccess{testEntry, tc.kind, Span{frameData + uint64(tc.offset), frameData + uint64(tc.offset+tc.width)}, tc.width}) || b.Accesses[1].Kind != FrameReturnRead {
				t.Fatalf("wrong derived footprint: %+v", b)
			}
			checkFrameOracle(t, im, b, 30)
		})
	}
	// Distinct argument views overlap in actual addresses; memory identity is
	// those bytes, not the index of the region through which they were reached.
	f := memoryFace()
	f.Regions = append(f.Regions, ByteRegion{Span{frameData + 4, frameData + 32}, true, true, false})
	f.Pointers = append(f.Pointers, RegisterPointer{RBX, RegionPointer{2, 0, 0}})
	im := image(t, hexBytes(t, "488b0b48894808c3"))
	c, err := proveFrame(t, im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	checkFrameOracle(t, im, b, 50)
	// A range produces a conservative full-width footprint, never just its base.
	f = memoryFace()
	f.Pointers[0].Pointer.Max = 7
	im = image(t, hexBytes(t, "488918c3"))
	c, err = proveFrame(t, im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = c.Bound()
	if b.Accesses[0].Bytes != (Span{frameData, frameData + 15}) {
		t.Fatal(b.Accesses)
	}
	checkFrameOracle(t, im, b, 80)
}

const frameSpill = "4883ec1048890424488b0c244889194883c410c3"

func TestFrameStackSpillReloadAndOverlap(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		change     func(*FrameInterface)
	}{
		{"spill-reload", frameSpill, nil},
		{"entry-stack-pointer", "488b4c2408488919c3", func(f *FrameInterface) { f.MemoryPointers = []MemoryPointer{{frameStack + 72, RegionPointer{0, 0, 0}}} }},
		{"pointer-copy", "4889c14883c108488919c3", nil},
		{"pointer-LEA", "488d4808488919c3", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := memoryFace()
			if tc.change != nil {
				tc.change(&f)
			}
			im := image(t, hexBytes(t, tc.code))
			c, err := proveFrame(t, im, testEntry, f)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c.Bound()
			checkFrameOracle(t, im, b, 50)
		})
	}
	// RDX and RSP name the same spill bytes through different region views.
	f := memoryFace()
	f.Regions = append(f.Regions, ByteRegion{Span{frameStack + 32, frameStack + 64}, true, true, false})
	f.Pointers = append(f.Pointers, RegisterPointer{RDX, RegionPointer{2, 16, 16}})
	im := image(t, hexBytes(t, "4883ec1048890424488b0a4889194883c410c3"))
	c, err := proveFrame(t, im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	checkFrameOracle(t, im, b, 50)
	// A one-byte write through the alias changes 0x60000000 to 0x600000ff,
	// outside the data region: retaining its spill provenance would be unsound.
	im = image(t, hexBytes(t, "4883ec1048890424c602ff488b0c244889194883c410c3"))
	c, err = proveFrame(t, im, testEntry, f)
	frameRefusal(t, c, err, "frame-address")
	for _, mutation := range []string{
		"c6442403ff", // scalar byte in the middle of the spill
		"895c2404",   // scalar upper-word store
		"48895c2404", // overlapping unaligned whole-word store
		"4889442401", // same pointer with shifted byte lanes
	} {
		im := image(t, hexBytes(t, "4883ec1048890424"+mutation+"488b0c244889194883c410c3"))
		c, err := proveFrame(t, im, testEntry, memoryFace())
		frameRefusal(t, c, err, "frame-address")
	}
}

func TestFrameRefusesUnjustifiedAccesses(t *testing.T) {
	for _, tc := range []struct {
		name, code, premise string
		change              func(*FrameInterface)
	}{
		{"end-overrun", "48895819c3", "frame-bounds", nil},
		{"negative-offset", "488958ffc3", "frame-bounds", nil},
		{"unknown-base", "488919c3", "frame-address", nil},
		{"unknown-loaded-pointer", "488b08488919c3", "frame-address", nil},
		{"unknown-loaded-call", "488b08ffd1c3", "instruction-semantics", nil},
		{"scalar-not-origin", "48b90000006000000000488919c3", "frame-address", nil},
		{"partial-register", "4889c1b100488919c3", "frame-address", nil},
		{"high-byte-register", "4889c1b500488919c3", "frame-address", nil},
		{"32-bit-register", "4889c189c9488919c3", "frame-address", nil},
		{"pointer-add-underflow", "4883c0ff488918c3", "frame-bounds", nil},
		{"protected-return", "48891c24c3", "frame-return", nil},
		{"lost-stack", "4883ec08c3", "frame-return", nil},
		{"partial-stack", "83c408c3", "frame-stack", nil},
		{"context-clobber", "4889c5c3", "preserved-register", nil},
		{"undefined-flags", "7401c3c3", "flag-input-bound", nil},
		{"syscall", "0f05c3", "instruction-semantics", nil},
		{"direct-call", "e800000000c3", "instruction-semantics", nil},
		{"cycle", "ebfe", "acyclic-control", nil},
		{"truncation", "488b", "instruction-decode", nil},
		{"missing-return", "488b00", "instruction-mapping", nil},
		{"readonly-store", "488918c3", "frame-permission", func(f *FrameInterface) { f.Regions[0].Writable = false }},
		{"unreadable-load", "488b00c3", "frame-permission", func(f *FrameInterface) { f.Regions[0].Readable = false }},
		{"protected-data", "48895808c3", "frame-protected", func(f *FrameInterface) { f.Protected = []Span{{frameData + 10, frameData + 11}} }},
		{"range-overrun", "488918c3", "frame-bounds", func(f *FrameInterface) { f.Pointers[0].Pointer.Max = 25 }},
		{"pointer-overflow", "c3", "frame-pointer", func(f *FrameInterface) { f.Pointers[0].Pointer.Max = math.MaxUint64 }},
		{"region-overflow", "c3", "frame-region", func(f *FrameInterface) { f.Regions[0].Bytes = Span{math.MaxUint64 - 8, math.MaxUint64} }},
		{"permission-alias", "c3", "frame-alias", func(f *FrameInterface) {
			f.Regions = append(f.Regions, ByteRegion{Span{frameData, frameData + 8}, true, false, false})
		}},
		{"unmapped-image", "c3", "frame-mapping", func(f *FrameInterface) { f.Regions[0].Image = true }},
		{"external-code-alias", "c3", "frame-mapping", func(f *FrameInterface) { f.Regions[0].Bytes = Span{testEntry, testEntry + 1} }},
		{"writable-code", "c3", "frame-mapping", func(f *FrameInterface) {
			f.Regions[0].Bytes = Span{testEntry, testEntry + 1}
			f.Regions[0].Image = true
		}},
		{"return-pointer-premise", "c3", "frame-pointer", func(f *FrameInterface) { f.MemoryPointers = []MemoryPointer{{frameStack + 64, RegionPointer{0, 0, 0}}} }},
		{"contradictory-pointers", "c3", "frame-pointer", func(f *FrameInterface) {
			f.MemoryPointers = []MemoryPointer{{frameStack + 8, RegionPointer{0, 0, 0}}, {frameStack + 12, RegionPointer{0, 8, 8}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := memoryFace()
			if tc.change != nil {
				tc.change(&f)
			}
			c, err := proveFrame(t, image(t, hexBytes(t, tc.code)), testEntry, f)
			frameRefusal(t, c, err, tc.premise)
		})
	}
}

func TestFrameJoinsAllSuccessors(t *testing.T) {
	// AX and DX can name different offsets in one region. Both branches assign
	// CX, whose joined pointer range must cover both possible stores.
	f := memoryFace()
	f.Pointers = append(f.Pointers, RegisterPointer{RDX, RegionPointer{0, 8, 8}})
	im := image(t, hexBytes(t, "4883fb0074054889c1eb034889d1488919c3"))
	c, err := proveFrame(t, im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	found := false
	for _, a := range b.Accesses {
		if a.Kind == FrameWrite {
			found = true
			if a.Bytes != (Span{frameData, frameData + 16}) {
				t.Fatal(a)
			}
		}
	}
	if !found {
		t.Fatal("missing joined write")
	}
	checkFrameOracle(t, im, b, 50)
	p, err := ProposeFrame(t.Context(), im, testEntry, FrameLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for j := range p.Nodes {
		if len(p.Nodes[j].Successors) == 2 {
			p.Nodes[j].Successors = p.Nodes[j].Successors[:1]
			break
		}
	}
	bad, err := CheckFrame(t.Context(), im, testEntry, f, p, FrameLimits{})
	frameRefusal(t, bad, err, "frame-proposal")
	// One predecessor overwrites CX with an arbitrary scalar: its pointer is
	// unknown after joining, even when a sampled branch would not take that edge.
	im = image(t, hexBytes(t, "4883fb0074054889c1eb034889d9488919c3"))
	c, err = proveFrame(t, im, testEntry, f)
	frameRefusal(t, c, err, "frame-address")
	// A branch corrupts one byte of a spilled pointer. The sibling does not
	// license retaining that pointer fact at the shared reload.
	im = image(t, hexBytes(t, "4883ec10488904244883fb007405c6442400ff488b0c244889194883c410c3"))
	c, err = proveFrame(t, im, testEntry, f)
	frameRefusal(t, c, err, "frame-address")
}

func TestFrameImageDataAndActualPermissions(t *testing.T) {
	raw := callbackELF(t, "488b0dc5ffffffc3", "c3") // replaced with exact RIP-relative data displacement below
	binary.LittleEndian.PutUint32(raw[0x1003:], uint32(descriptorAddress-(testEntry+7)))
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	f := memoryFace()
	f.Regions = append(f.Regions, ByteRegion{Span{descriptorAddress, descriptorAddress + 8}, true, false, true})
	c, err := proveFrame(t, im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if b.Accesses[0].Bytes != (Span{descriptorAddress, descriptorAddress + 8}) {
		t.Fatal(b.Accesses)
	}
	if len(b.ReturnedPointers) != 1 || b.ReturnedPointers[0].Register != RAX {
		t.Fatal("image scalar load acquired pointer authority", b.ReturnedPointers)
	}
	f.Regions[len(f.Regions)-1].Writable = true
	c, err = proveFrame(t, im, testEntry, f)
	frameRefusal(t, c, err, "frame-mapping")
	// A real writable PT_LOAD is a possible mutable region, not initial-value
	// evidence. Its BSS tail can be mapped under the same explicit memory model.
	raw = callbackELF(t, "48891d00000000c3", "c3")
	binary.LittleEndian.PutUint32(raw[0x1003:], uint32(descriptorAddress+0x1000-(testEntry+7)))
	im, err = NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	f = memoryFace()
	f.Regions = append(f.Regions, ByteRegion{Span{descriptorAddress + 0x1000, descriptorAddress + 0x1008}, true, true, true})
	if _, err = proveFrame(t, im, testEntry, f); err != nil {
		t.Fatal(err)
	}
	bss := append([]byte(nil), raw...)
	binary.LittleEndian.PutUint64(bss[208:], 0)
	bssImage, err := NewImage(t.Context(), bss)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = proveFrame(t, bssImage, testEntry, f); err != nil {
		t.Fatal(err)
	}
	// An actual second mapping of its backing page is not hidden by interface
	// NoHiddenAliases: structural contradictions still refuse.
	binary.LittleEndian.PutUint64(raw[184:], 0x2000)
	im, err = NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	c, err = proveFrame(t, im, testEntry, f)
	frameRefusal(t, c, err, "frame-alias")
}

func TestFrameProposalOwnershipBudgetsAndCancellation(t *testing.T) {
	im := image(t, hexBytes(t, frameSpill))
	f := memoryFace()
	f.MemoryPointers = []MemoryPointer{{frameStack + 8, RegionPointer{0, 0, 0}}}
	f.Protected = []Span{{frameData + 24, frameData + 32}}
	p, err := ProposeFrame(t.Context(), im, testEntry, FrameLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckFrame(t.Context(), im, testEntry, f, p, FrameLimits{})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := c.Bound()
	projection, _ := c.Bound()
	projection.Interface.Regions[0].Writable = false
	projection.Interface.Pointers[0].Pointer.Max = 31
	projection.Interface.MemoryPointers[0].Address = 0
	projection.Interface.Protected[0].End = 0
	projection.Accesses[0].Bytes.End = 0
	projection.Instructions[0].End = 0
	now, _ := c.Bound()
	if !reflect.DeepEqual(want, now) {
		t.Fatal("mutable certificate projection")
	}
	for _, change := range []func(*FrameProposal){
		func(p *FrameProposal) { p.ImageDigest[0] ^= 1 }, func(p *FrameProposal) { p.Entry++ },
		func(p *FrameProposal) { p.Nodes = p.Nodes[:len(p.Nodes)-1] },
		func(p *FrameProposal) { p.Nodes[0].Successors[0]++ },
		func(p *FrameProposal) { p.Nodes[0].Size++ },
		func(p *FrameProposal) { p.Nodes[0] = p.Nodes[1] },
	} {
		q, _ := ProposeFrame(t.Context(), im, testEntry, FrameLimits{})
		change(&q)
		bad, err := CheckFrame(t.Context(), im, testEntry, f, q, FrameLimits{})
		frameRefusal(t, bad, err, "frame-proposal")
	}
	// Even repairing a proposal's public digest cannot authorize changed bytes.
	// These instructions have identical graph shapes but a different load base.
	goodImage := image(t, hexBytes(t, "488b00c3"))
	badImage := image(t, hexBytes(t, "488b01c3"))
	wrong, err := ProposeFrame(t.Context(), goodImage, testEntry, FrameLimits{})
	if err != nil {
		t.Fatal(err)
	}
	bad, err := CheckFrame(t.Context(), badImage, testEntry, f, wrong, FrameLimits{})
	frameRefusal(t, bad, err, "frame-proposal")
	wrong.ImageDigest = badImage.digest
	bad, err = CheckFrame(t.Context(), badImage, testEntry, f, wrong, FrameLimits{})
	frameRefusal(t, bad, err, "frame-address")
	for _, limit := range []FrameLimits{{Instructions: 1}, {States: 1}, {Regions: 1}, {RegionBytes: 1}, {StateBytes: 1}, {Work: 1}} {
		bad, err := CheckFrame(t.Context(), im, testEntry, f, p, limit)
		frameRefusal(t, bad, err, "frame-budget")
	}
	for _, change := range []func(*FrameConditions){
		func(c *FrameConditions) { c.MemoryMapping = false }, func(c *FrameConditions) { c.NoHiddenAliases = false }, func(c *FrameConditions) { c.UnalignedAccess = false },
	} {
		g := cloneFrameInterface(f)
		change(&g.Conditions)
		bad, err := CheckFrame(t.Context(), im, testEntry, g, p, FrameLimits{})
		frameRefusal(t, bad, err, "frame-premises")
	}
	count := &imageCallbackContext{Context: t.Context()}
	if _, err := CheckFrame(count, im, testEntry, f, p, FrameLimits{}); err != nil {
		t.Fatal(err)
	}
	for at := 1; at <= count.calls; at++ {
		supplied := *im
		g := cloneFrameInterface(f)
		q, _ := ProposeFrame(t.Context(), im, testEntry, FrameLimits{})
		ctx := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n == at {
				supplied = Image{}
				g.Regions[0].Bytes.End = 0
				g.Pointers[0].Pointer.Max = math.MaxUint64
				g.MemoryPointers[0].Address = 0
				g.Protected[0].End = 0
				q.Nodes[0].Successors[0] = 0
			}
		}}
		got, err := CheckFrame(ctx, &supplied, testEntry, g, q, FrameLimits{})
		if err != nil {
			t.Fatal(err)
		}
		bound, _ := got.Bound()
		if !reflect.DeepEqual(bound, want) {
			t.Fatal("callback changed owned frame inputs")
		}
		cancelCtx, cancel := context.WithCancel(t.Context())
		ctx = &imageCallbackContext{Context: cancelCtx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		got, err = CheckFrame(ctx, im, testEntry, f, p, FrameLimits{})
		cancel()
		if _, ok := got.Bound(); ok || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled evidence: %v", err)
		}
	}
	if _, ok := (FrameCertificate{}).Bound(); ok {
		t.Fatal("zero frame certificate")
	}
}

func FuzzFrameSpillByteInvalidation(f *testing.F) {
	for _, offset := range []uint8{0, 3, 7, 8, 15} {
		f.Add(offset)
	}
	for _, offset := range []uint8{0, 1, 3, 7, 8} {
		f.Add(offset | 0x80)
	}
	f.Fuzz(func(t *testing.T, offset uint8) {
		pointerWrite := offset&0x80 != 0
		offset &= 0x7f
		var code []byte
		invalid := false
		if pointerWrite {
			// Keep the full store within the allocated sixteen-byte frame.
			// A same-pointer overwrite at offset zero is complete; shifted
			// overlapping lanes must not acquire full-word provenance.
			offset %= 9
			code = hexBytes(t, "4883ec10488904244889442400488b0c244889194883c410c3")
			code[12] = offset
			invalid = offset > 0 && offset < 8
		} else {
			offset %= 16
			code = hexBytes(t, "4883ec1048890424c6442400ff488b0c244889194883c410c3")
			code[11] = offset
			invalid = offset < 8
		}
		im := image(t, code)
		c, err := proveFrame(t, im, testEntry, memoryFace())
		if invalid {
			frameRefusal(t, c, err, "frame-address")
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := c.Bound()
		checkFrameOracle(t, im, b, 3)
	})
}

func TestFrameProposalOwnsImageAndCancels(t *testing.T) {
	im := image(t, hexBytes(t, frameSpill))
	count := &imageCallbackContext{Context: t.Context()}
	want, err := ProposeFrame(count, im, testEntry, FrameLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for at := 1; at <= count.calls; at++ {
		supplied := *im
		ctx := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n == at {
				supplied = Image{}
			}
		}}
		got, err := ProposeFrame(ctx, &supplied, testEntry, FrameLimits{})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("mixed proposal: %v", err)
		}
		cancelCtx, cancel := context.WithCancel(t.Context())
		ctx = &imageCallbackContext{Context: cancelCtx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		got, err = ProposeFrame(ctx, im, testEntry, FrameLimits{})
		cancel()
		if !errors.Is(err, context.Canceled) || got.Entry != 0 || len(got.Nodes) != 0 {
			t.Fatalf("partial cancelled proposal: %v", err)
		}
	}
}

func FuzzFrameFullWidthBounds(f *testing.F) {
	for _, seed := range []struct {
		offset          int8
		maximum, width  uint8
		write, writable bool
	}{
		{0, 0, 3, true, true}, {24, 0, 3, true, true}, {25, 0, 3, true, true}, {-1, 0, 0, false, true},
		{16, 7, 3, false, true}, {16, 8, 3, true, false}, {16, 9, 3, true, true},
	} {
		f.Add(seed.offset, seed.maximum, seed.width, seed.write, seed.writable)
	}
	f.Fuzz(func(t *testing.T, offset int8, maximum, widthCode uint8, write, writable bool) {
		maximum %= 33
		width := 1 << (widthCode % 4)
		var code []byte
		if width == 8 {
			code = append(code, 0x48)
		}
		if width == 2 {
			code = append(code, 0x66)
		}
		op, modrm := byte(0x8b), byte(0x48)
		if write {
			op, modrm = 0x89, 0x58
		}
		if width == 1 {
			op--
		}
		code = append(code, op, modrm, byte(offset), 0xc3)
		face := memoryFace()
		face.Pointers[0].Pointer.Max = uint64(maximum)
		face.Regions[0].Writable = writable
		im := image(t, code)
		c, err := proveFrame(t, im, testEntry, face)
		bounded := offset >= 0 && int(maximum)+int(offset)+width <= 32
		if !bounded {
			frameRefusal(t, c, err, "frame-bounds")
			return
		}
		if write && !writable {
			frameRefusal(t, c, err, "frame-permission")
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := c.Bound()
		checkFrameOracle(t, im, b, 3)
	})
}
