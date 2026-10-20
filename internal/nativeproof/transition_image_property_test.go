package nativeproof

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/big"
	"math/rand"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
	"golang.org/x/arch/x86/x86asm"
)

// The synthetic mapping intent is input to both the ELF writer and independent
// integer oracle. File bytes deliberately look initialized and pointer-like;
// neither they nor the zero-fill suffix supply transition input values.
func transitionImageELF(t testing.TB, code []byte, loads []interfaceMapping) []byte {
	t.Helper()
	raw := elfBytes(code)
	if 64+56*(len(loads)+1) > 4096 {
		t.Fatal("fixture header overflow")
	}
	binary.LittleEndian.PutUint16(raw[56:], uint16(len(loads)+1))
	for j, m := range loads {
		end := m.file + m.filesz
		if end > uint64(len(raw)) {
			old := len(raw)
			raw = append(raw, make([]byte, int(end)-old)...)
			for k := old; k < len(raw); k++ {
				raw[k] = byte(k*37 + 19)
			}
		}
		h := raw[64+56*(j+1):]
		binary.LittleEndian.PutUint32(h, 1)
		flags := uint32(0)
		if m.execute {
			flags |= 1
		}
		if m.write {
			flags |= 2
		}
		if m.read {
			flags |= 4
		}
		binary.LittleEndian.PutUint32(h[4:], flags)
		binary.LittleEndian.PutUint64(h[8:], m.file)
		binary.LittleEndian.PutUint64(h[16:], m.start)
		binary.LittleEndian.PutUint64(h[32:], m.filesz)
		binary.LittleEndian.PutUint64(h[40:], m.end-m.start)
		binary.LittleEndian.PutUint64(h[48:], 1)
	}
	return raw
}

const imageStateAddress = uint64(0x700000)

func imageStateLoads() []interfaceMapping {
	return []interfaceMapping{
		{start: imageStateAddress, end: imageStateAddress + 128, file: 0x10000, filesz: 32, read: true, write: true},
		{start: imageStateAddress + 0x2000, end: imageStateAddress + 0x2040, file: 0x11000, filesz: 16, read: true},
	}
}

// Large sequence layouts must not acquire accidental file-page aliases merely
// because their code allocation grew past a fixed fixture data offset. These
// independently planned offsets keep both data loads beyond the complete code
// mapping; deliberate alias cases use imageStateLoads directly instead.
func imageSequenceLoads(native int) []interfaceMapping {
	loads := imageStateLoads()
	start := uint64(sequenceMappingSize(native)) + 0x2000
	for j := range loads {
		loads[j].file = start + uint64(j)*4096
	}
	return loads
}

func imageStateFace() TransitionInterface {
	f := stateFace(16, 0)
	f.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 128}, {imageStateAddress + 16, imageStateAddress + 48}, {imageStateAddress + 0x2000, imageStateAddress + 0x2040}}
	return f
}

func imageInterfaceFixture(t testing.TB, loads []interfaceMapping) interfaceImage {
	t.Helper()
	raw := transitionImageELF(t, []byte{0xc3}, loads)
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	x := interfaceImage{im: im, entry: testEntry, digest: sha256.Sum256(raw), loads: [][2]uint64{{testEntry, testEntry + 1}}, dataLoads: []interfaceMapping{{start: testEntry, end: testEntry + 1, file: 0x1000, filesz: 1, read: true, execute: true}}}
	for _, m := range loads {
		x.loads = append(x.loads, [2]uint64{m.start, m.end})
		x.dataLoads = append(x.dataLoads, m)
	}
	x.proposal = TransitionProposal{ImageDigest: x.digest, Entry: testEntry, Cut: testEntry, Root: 1, Nodes: []TransitionNode{{ID: 1, PC: testEntry, Size: 1}}}
	return x
}

func TestTransitionImageInterfaceProperty(t *testing.T) {
	if err := quick.Check(func(start, width uint64, mode uint8, budget uint16) bool {
		loads := imageStateLoads()
		// Permission is a PT_LOAD fact, never a caller-supplied grant.
		loads[0].read, loads[0].write = mode&1 != 0, mode&2 != 0
		if mode&4 != 0 {
			loads[1].file = loads[0].file
		} // readonly/writable aliases both refuse
		x := imageInterfaceFixture(t, loads)
		f := imageStateFace()
		if mode&8 != 0 {
			start = imageStateAddress + start%129
			width %= 130
		}
		f.ImageRegions = append(f.ImageRegions, Span{start, start + width})
		l := interfacePropertyLimits()
		l.Bytes = 1 + int(budget)
		interfaceCheckLimits(t, x, f, l)
		return true
	}, &quick.Config{MaxCount: 128, Rand: rand.New(rand.NewSource(814))}); err != nil {
		t.Fatal(err)
	}
	for _, span := range []Span{{0, 8}, {imageStateAddress - 1, imageStateAddress + 1}, {imageStateAddress + 127, imageStateAddress + 129}, {1<<47 - 1, 1 << 47}, {math.MaxUint64 - 3, 4}} {
		f := imageStateFace()
		f.ImageRegions = []Span{span}
		interfaceCheck(t, imageInterfaceFixture(t, imageStateLoads()), f)
	}
	for _, n := range []int{255, 256, 257} {
		f := imageStateFace()
		f.Regions = nil
		f.Words = nil
		f.ImageRegions = nil
		for range n {
			f.ImageRegions = append(f.ImageRegions, Span{imageStateAddress, imageStateAddress + 1})
		}
		interfaceCheck(t, imageInterfaceFixture(t, imageStateLoads()), f)
	}
	// A zero-file-size partial page is still a backing alias, including BSS.
	loads := imageStateLoads()
	loads[0].start++
	loads[0].file++
	loads[0].filesz = 0
	loads[1].file = 0x10000
	f := imageStateFace()
	f.ImageRegions = []Span{{imageStateAddress + 1, imageStateAddress + 32}}
	interfaceCheck(t, imageInterfaceFixture(t, loads), f)
}

// The seed is a real instruction sequence. Arbitrary fuzz records need not
// retain it, and no later instruction repairs a lost pointer automatically.
func imageSequenceRecords(distance int32, choice byte, constant uint64) []byte {
	ops := []to.Intent{
		{Operation: to.LEARIP, Dst: 12, SignedDisp: int64(imageStateAddress) - int64(testEntry+7)},
		{Operation: to.MoveRegister, Dst: 13, Src: 4},
		{Operation: to.Load, Dst: 0, Base: 12, SignedDisp: 64}, // arbitrary BSS-looking input
		{Operation: to.Store, Base: 13, Src: 0},
		{Operation: to.Store, Base: 12, Src: 13, SignedDisp: 16}, // stack pointer in image
		{Operation: to.Load, Dst: 14, Base: 12, SignedDisp: 16},
		{Operation: to.Store, Base: 14, Src: 12, SignedDisp: 8}, // image pointer in stack
		{Operation: to.Load, Dst: 15, Base: 13, SignedDisp: 8},
		{Operation: to.MoveImmediate, Dst: 0, Immediate: constant},
		{Operation: to.Store, Base: 15, Src: 0, SignedDisp: 16 + int64(distance)},
		{Operation: to.Load, Dst: 1, Base: 12, SignedDisp: 16},
		{Operation: to.Store, Base: 13, Src: 1, SignedDisp: 24},
		{Operation: to.Load, Dst: 2, Base: 13, SignedDisp: 24},
		{Operation: to.Subtract, Dst: 15, Immediate: ^uint64(7)},
		{Operation: to.LEA, Dst: 3, Base: 15, SignedDisp: -8},
		{Operation: to.Store, Base: 3, Src: 2, SignedDisp: 80},
		{Operation: to.Load, Dst: 0, Base: 3, SignedDisp: 80},
	}
	var records []byte
	for _, i := range ops {
		records = append(records, sequenceRecord(i, choice)...)
	}
	return records
}

func TestTransitionImageStateProperty(t *testing.T) {
	if err := quick.Check(func(values [64]uint64, choice byte, constant, layout uint64) bool {
		var raw []byte
		for _, v := range values {
			raw = binary.LittleEndian.AppendUint64(raw, v)
		}
		// Every overlapping eight-byte distance, plus disjoint/touching controls.
		for distance := int32(-8); distance <= 8; distance++ {
			program := sequenceRecords(imageSequenceRecords(distance, choice, constant), nil, 4096)
			checkStateSequence(t, imageStateFace(), program, raw, []byte{255, 255, 255}, layout, 4096, imageStateLoads()...)
		}
		return true
	}, &quick.Config{MaxCount: 8, Rand: rand.New(rand.NewSource(815))}); err != nil {
		t.Fatal(err)
	}
}

func FuzzTransitionImageStateSequence(f *testing.F) {
	values := make([]byte, 512)
	for j := range values {
		values[j] = byte(j*37 + 19)
	}
	for _, d := range []int32{-8, -7, -1, 0, 1, 7, 8, 112, math.MinInt32, math.MaxInt32} {
		f.Add(imageSequenceRecords(d, 0, imageStateAddress), []byte{}, []byte{255, 255, 255}, values, uint64(4096), uint64(781))
	}
	long := append(imageSequenceRecords(8, 0, imageStateAddress), make([]byte, 32*4097)...)
	f.Add(long, []byte{}, []byte{0x55}, values, uint64(65536), uint64(917))
	f.Fuzz(func(t *testing.T, records, blocks, cuts, raw []byte, requested, layout uint64) {
		limit := sequencePositiveLimit(requested)
		program := sequenceRecords(records, blocks, limit)
		checkStateSequence(t, imageStateFace(), program, raw, cuts, layout, limit, imageSequenceLoads(len(program))...)
	})
}

func TestTransitionImagePointerOwnership(t *testing.T) {
	program := sequenceRecords(imageSequenceRecords(8, 0, 0), nil, 4096)
	x := sequenceLayout(t, program, 1, imageStateLoads()...)
	f := imageStateFace()
	c, err := CheckTransition(t.Context(), x.im, f, x.proposal(1), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	p := c.checked.bound.Registers[12].Pointer
	if pointer, ok := p.(AddressPointer); !ok || !pointer.isImage() {
		t.Fatal("RIP did not establish Image provenance")
	}
	// Equal bytes are not the same owner, while copies of the constructed Image
	// share the immutable data origin even across repeated snapshot wrappers.
	foreign, err := NewImage(t.Context(), x.im.data)
	if err != nil {
		t.Fatal(err)
	}
	copyImage := *x.im
	for _, im := range []*Image{x.im, x.im.snapshot(), &copyImage, foreign} {
		m := &transitionChecker{im: im, face: f, bound: c.checked.bound, valueBuilder: &valueBuilder{}}
		_, err := m.advance(p, 1)
		if (err == nil) != (im != foreign) {
			t.Fatal("owner relation differs", err)
		}
	}
	// A projection may contain a syntactically plausible provenance arm, but
	// cannot reconstruct a certificate or replace its private current cells.
	b, _ := c.Bound()
	b.Registers[12].Pointer = b.Geometry.stackPointer(0)
	b.Interface.ImageRegions[0] = Span{0, math.MaxUint64}
	next, err := CheckTransitionContinuation(t.Context(), c, x.proposal(3))
	if err != nil {
		t.Fatal(err)
	}
	if next.checked.bound.Registers[12].Pointer != p {
		t.Fatal("projection granted authority")
	}
	for _, cell := range next.checked.bound.InitialMemory {
		if cell.isImage() && (cell.Pointer != nil || cell.Value.View().Op != br.Variable) {
			t.Fatal("raw image cell acquired loader facts")
		}
	}
}

func FuzzTransitionImageInterface(f *testing.F) {
	encode := func(spans ...Span) []byte {
		var raw []byte
		for _, s := range spans {
			raw = binary.LittleEndian.AppendUint64(raw, s.Start)
			raw = binary.LittleEndian.AppendUint64(raw, s.End)
		}
		return raw
	}
	for _, size := range []uint64{1, 8, 513, 4097, 1<<20 + 1} {
		f.Add(encode(Span{imageStateAddress, imageStateAddress + size}), uint32(1<<20-1), uint64(1<<40), uint64(1<<44), uint8(3))
		f.Add(encode(Span{imageStateAddress, imageStateAddress + size}), uint32(1<<20-1), uint64(1<<40), uint64(1<<44), uint8(7))
	}
	f.Add(encode(Span{imageStateAddress, imageStateAddress + 8}, Span{imageStateAddress + 3, imageStateAddress + 11}), uint32(15), uint64(imageStateAddress), uint64(imageStateAddress+8192), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, bytes uint32, low, high uint64, permissions uint8) {
		loads := []interfaceMapping{{start: imageStateAddress, end: imageStateAddress + 1<<20 + 1, file: 0x10000, read: permissions&1 != 0, write: permissions&2 != 0}}
		x := imageInterfaceFixture(t, loads)
		face := stateFace(16, 0)
		face.Origin.Min, face.Origin.Max = low, high
		if permissions&4 != 0 {
			face.Regions = nil
			face.Words = nil
		}
		face.ImageRegions = nil
		for len(raw) > 0 && len(face.ImageRegions) <= 256 {
			var row [16]byte
			n := copy(row[:], raw)
			raw = raw[n:]
			face.ImageRegions = append(face.ImageRegions, Span{binary.LittleEndian.Uint64(row[:8]), binary.LittleEndian.Uint64(row[8:])})
		}
		limits := interfacePropertyLimits()
		limits.Bytes = 1 + int(bytes%uint32(1<<20+1))
		// Size work independently from the declared input, including sort levels
		// and root variables. This is a configuration allowance, not a pass rule.
		limits.Nodes = 2*(1<<20) + 4096
		limits.Work = 256*(1<<20) + 4096
		interfaceCheckLimits(t, x, face, limits)
	})
}

func TestTransitionImagePermissionsAndProvenance(t *testing.T) {
	for permissions := 0; permissions < 4; permissions++ {
		loads := imageStateLoads()
		loads[0].read, loads[0].write = permissions&1 != 0, permissions&2 != 0
		for _, operation := range []to.Operation{to.Load, to.Store} {
			for _, offset := range []int64{0, 1, 7, 8, 119, 120, 121, 127} {
				i := to.Intent{Operation: operation, Base: 12, SignedDisp: offset}
				if operation == to.Load {
					i.Dst = 0
				} else {
					i.Src = 4
				}
				ops := []stateInstruction{stateOp(to.Intent{Operation: to.LEARIP, Dst: 12, SignedDisp: int64(imageStateAddress) - int64(testEntry+7)}, 0), stateOp(i, 0)}
				checkStateSequence(t, imageStateFace(), ops, make([]byte, 512), []byte{255}, 1, 4096, loads...)
			}
		}
	}
	for _, tc := range []struct {
		name    string
		target  uint64
		tail    []to.Intent
		premise string
	}{
		{"readonly-read", imageStateAddress + 0x2000, []to.Intent{{Operation: to.Load, Dst: 0, Base: 12}}, ""},
		{"readonly-write", imageStateAddress + 0x2000, []to.Intent{{Operation: to.Store, Src: 4, Base: 12}}, "transition-permission"},
		{"bss-read", imageStateAddress + 64, []to.Intent{{Operation: to.Load, Dst: 0, Base: 12}}, ""},
		{"one-past", imageStateAddress + 120, []to.Intent{{Operation: to.LEA, Dst: 12, Base: 12, SignedDisp: 8}, {Operation: to.Load, Dst: 0, Base: 12}}, "transition-image"},
		{"escaping-add", imageStateAddress + 120, []to.Intent{{Operation: to.LEA, Dst: 12, Base: 12, SignedDisp: 9}}, "transition-image"},
		{"escaping-sub", imageStateAddress, []to.Intent{{Operation: to.Subtract, Dst: 12, Immediate: 1}}, "transition-image"},
		{"image-and", imageStateAddress, []to.Intent{{Operation: to.And, Dst: 12, Immediate: ^uint64(15)}}, "transition-alignment"},
		{"numeric-address", imageStateAddress, []to.Intent{{Operation: to.MoveImmediate, Dst: 12, Immediate: imageStateAddress}, {Operation: to.Load, Dst: 0, Base: 12}}, "transition-provenance"},
		{"raw-word", imageStateAddress, []to.Intent{{Operation: to.Load, Dst: 12, Base: 12}, {Operation: to.Load, Dst: 0, Base: 12}}, "transition-provenance"},
		{"unmapped-lea", imageStateAddress + 4096, nil, "transition-image"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := []stateInstruction{stateOp(to.Intent{Operation: to.LEARIP, Dst: 12, SignedDisp: int64(tc.target) - int64(testEntry+7)}, 0)}
			for _, i := range tc.tail {
				ops = append(ops, stateOp(i, 0))
			}
			x := sequenceLayout(t, ops, 1, imageStateLoads()...)
			face := imageStateFace()
			raw := make([]byte, 512)
			// Every image input is independently raw, even when it looks exactly
			// like a mapped address; such bytes must not gain pointer provenance.
			for j := 137; j+8 <= len(raw); j += 8 {
				binary.LittleEndian.PutUint64(raw[j:], imageStateAddress)
			}
			checkStateSequence(t, face, ops, raw, []byte{255}, 1, 4096, imageStateLoads()...)
			c, err := CheckTransition(t.Context(), x.im, face, x.proposal(len(ops)), TransitionLimits{})
			if tc.premise == "" {
				if err != nil {
					t.Fatal("positive full scope refused", err)
				}
			} else {
				sequenceRefused(t, c, err, tc.premise, x.pcs[len(ops)-1])
			}
		})
	}
	// The same admitted pointer cannot access undeclared bytes of its mapping.
	ops := []stateInstruction{stateOp(to.Intent{Operation: to.LEARIP, Dst: 12, SignedDisp: int64(imageStateAddress) - int64(testEntry+7)}, 0), stateOp(to.Intent{Operation: to.Load, Dst: 0, Base: 12}, 0)}
	x := sequenceLayout(t, ops, 1, imageStateLoads()...)
	face := imageStateFace()
	face.ImageRegions = nil
	c, err := CheckTransition(t.Context(), x.im, face, x.proposal(2), TransitionLimits{})
	sequenceRefused(t, c, err, "transition-permission", x.pcs[1])
}

func TestTransitionImageContinuationResources(t *testing.T) {
	face := imageStateFace()
	ops := sequenceRecords(imageSequenceRecords(8, 0, 0), nil, 4096)
	// Dependencies live in both byte namespaces throughout; no reset masks the
	// imported constructor depth. The shared resource oracle locates the exact
	// first depth overflow and requires refusal there, direct and segmented.
	for range 80 {
		for _, i := range []to.Intent{{Operation: to.Load, Dst: 0, Base: 12, SignedDisp: 16}, {Operation: to.Store, Base: 13, Src: 0, SignedDisp: -8}, {Operation: to.Load, Dst: 1, Base: 13, SignedDisp: -8}, {Operation: to.Store, Base: 12, Src: 1, SignedDisp: 16}} {
			ops = append(ops, stateOp(i, 0))
		}
	}
	checkStateSequence(t, face, ops, make([]byte, 512), []byte{255, 255, 255, 255}, 3, 4096, imageStateLoads()...)
	short := sequenceRecords(imageSequenceRecords(0, 0, 0), nil, 4096)
	x := sequenceLayout(t, short, 1, imageStateLoads()...)
	root, err := CheckTransition(t.Context(), x.im, face, x.proposal(10), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	assertTransitionRetainedExpressionUnion(t, root, x.proposal(11))
	second, err := CheckTransitionContinuation(t.Context(), root, x.proposal(11))
	if err != nil {
		t.Fatal(err)
	}
	limit := second.checked.work
	bounded, err := CheckTransition(t.Context(), x.im, face, x.proposal(10), TransitionLimits{RelationLimits: RelationLimits{Work: limit}})
	if err != nil {
		t.Fatal(err)
	}
	bounded, err = CheckTransitionContinuation(t.Context(), bounded, x.proposal(11))
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransitionContinuation(t.Context(), bounded, x.proposal(12))
	transitionRefused(t, c, err)
	if bounded.checked.work != limit {
		t.Fatal("cumulative work changed with limit")
	}
	// Untouched image bytes still cost copies, term imports and final projection.
	// This is an independent lower bound, not just a measured-limit replay.
	largeLoads := imageStateLoads()
	largeLoads[0].end = imageStateAddress + 2048
	largeFace := imageStateFace()
	largeFace.Regions = nil
	largeFace.Words = nil
	largeFace.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 2048}}
	large := sequenceLayout(t, short[:3], 1, largeLoads...)
	first, err := CheckTransition(t.Context(), large.im, largeFace, large.proposal(1), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	second, err = CheckTransitionContinuation(t.Context(), first, large.proposal(2))
	if err != nil {
		t.Fatal(err)
	}
	if second.checked.work-first.checked.work < 8*2048 {
		t.Fatal("image state escaped cumulative work accounting")
	}
	first, err = CheckTransition(t.Context(), large.im, largeFace, large.proposal(1), TransitionLimits{RelationLimits: RelationLimits{Work: first.checked.work + 2048}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = CheckTransitionContinuation(t.Context(), first, large.proposal(2))
	transitionRefused(t, c, err)
}

func TestTransitionImageAndStackTagsDoNotProveInequality(t *testing.T) {
	face := imageStateFace()
	face.Origin = OriginDomain{Min: imageStateAddress + 65536, Max: imageStateAddress + 65536, Modulus: 16}
	face.Envelope = RelativeSpan{-65536, 64}
	face.Regions = []RelativeRegion{{Bytes: RelativeSpan{0, 8}, Readable: true, Writable: true}}
	face.Words = nil
	ops := []stateInstruction{
		stateOp(to.Intent{Operation: to.LEARIP, Dst: 12, SignedDisp: int64(imageStateAddress) - int64(testEntry+7)}, 0),
		stateOp(to.Intent{Operation: to.LEA, Dst: 3, Base: 4, SignedDisp: -65536}, 0),
		stateOp(to.Intent{Operation: to.Store, Base: 12, Src: 3}, 0),
		stateOp(to.Intent{Operation: to.Load, Dst: 2, Base: 12}, 0),
		stateOp(to.Intent{Operation: to.Load, Dst: 0, Base: 2}, 0),
	}
	checkStateSequence(t, face, ops, make([]byte, 512), []byte{255}, 1, 4096, imageStateLoads()...)
	x := sequenceLayout(t, ops, 1, imageStateLoads()...)
	c, err := CheckTransition(t.Context(), x.im, face, x.proposal(4), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b := c.checked.bound
	values := map[br.Term]uint64{b.Origin: face.Origin.Min}
	if stateEval(t, b.Registers[12].Value, values) != stateEval(t, b.Registers[2].Value, values) {
		t.Fatal("control lost numerical alias")
	}
	if p, ok := b.Registers[12].Pointer.(AddressPointer); !ok || !p.isImage() {
		t.Fatal("image arm missing")
	}
	if requireStackPointer(t, b.Registers[2].Pointer).offset != -65536 {
		t.Fatal("stack arm missing")
	}
	refused, err := CheckTransitionContinuation(t.Context(), c, x.proposal(5))
	sequenceRefused(t, refused, err, "transition-permission", x.pcs[4])
}

// This synthetic consumer is downstream of the generic mixed-state properties.
// It grants only 32 image bytes and the original tiny stack footprints. The
// large stack-relative value is representable, not a 64 KiB mapped stack claim.
func TestTransitionImageFourWordPrefix(t *testing.T) {
	code := hexBytes(t, entryPrefix+"bd00000000")
	leaPC := testEntry + uint64(len(code))
	code = append(code, 0x48, 0x8d, 0x3d)
	code = binary.LittleEndian.AppendUint32(code, uint32(int64(imageStateAddress)-int64(leaPC+7)))
	code = append(code, hexBytes(t, "488d9c240000ffff48895f1048895f1848891f48896708b800000000")...)
	cut := testEntry + uint64(len(code))
	code = append(code, 0x0f, 0xa2, 0x85, 0xc0, 0xc3)
	raw := transitionImageELF(t, code, imageStateLoads())
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	face := transitionFace()
	face.Envelope.Start = -65584
	face.Origin.Min = 65584
	face.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 32}}
	root := continuationRoot(t, im, leaPC, face, TransitionLimits{})
	p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransitionContinuation(t.Context(), root, p)
	if err != nil {
		t.Fatal(err)
	}
	b := c.checked.bound
	if b.Registers[RDI].Pointer != b.Geometry.imagePointer(1, imageStateAddress) {
		t.Fatal("wrong image base")
	}
	for _, reg := range []Register{RBP, RAX} {
		if b.Registers[reg].Pointer != nil || stateEval(t, b.Registers[reg].Value, nil) != 0 {
			t.Fatal("zero write did not clear full register/provenance")
		}
	}
	for _, cell := range b.Memory {
		if !cell.isImage() {
			continue
		}
		off := cell.offset - int64(imageStateAddress)
		want := int64(-65584)
		if off >= 8 && off < 16 {
			want = -48
		}
		if cell.Pointer != b.Geometry.stackPointer(want) || cell.PointerLane != uint8(off%8) {
			t.Fatal("incorrect image pointer word/lane", cell)
		}
		for _, s := range []uint64{1 << 32, 1 << 40, 1 << 46} {
			if got := stateEval(t, cell.Value, map[br.Term]uint64{b.Origin: s}); got != uint64(byte((s+uint64(want))>>(8*(off%8)))) {
				t.Fatal("incorrect image word bits")
			}
		}
	}
	if len(b.Accesses) != 7 {
		t.Fatal("incomplete access inventory")
	}
	for j, off := range []int64{16, 24, 0, 8} {
		a := b.Accesses[j+3]
		if !a.Bytes.start.isImage() || a.Kind != FrameWrite || extentCoordinates(a.Bytes) != (RelativeSpan{int64(imageStateAddress) + off, int64(imageStateAddress) + off + 8}) {
			t.Fatal("wrong store order")
		}
	}
	if b.Boundary.PC != cut || string(b.Boundary.Bytes) != string([]byte{0x0f, 0xa2}) {
		t.Fatal("CPUID was not retained unexecuted")
	}
	direct, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	assertTransitionAlpha(t, direct, c)
	assertCPUQueryExecutionRefused(t, im, face, p, c)
	assertImagePrefixMissingPremises(t, im, face, p, leaPC)
	assertCPUQueryConditionalStep(t, im, face, p, x86asm.TEST)
}

// Full signed disp32 values participate in positive address constructions as
// well as refusals. The fixture moves the data LOAD, not the intended operand;
// unbounded integer arithmetic decides canonicality and logical mapping first.
func FuzzTransitionImageRIPArithmetic(f *testing.F) {
	for _, pc := range []uint64{0, 1 << 31, 1 << 40, 1<<47 - 4096} {
		for _, disp := range []int32{math.MinInt32, -4097, -8, -7, -1, 0, 1, 2, 4096, math.MaxInt32} {
			f.Add(pc, disp, uint8(15), uint8(3))
		}
	}
	f.Fuzz(func(t *testing.T, requested uint64, displacement int32, dst, ignored uint8) {
		pc := (requested % uint64(1<<47)) / 4096 * 4096
		dst %= 16
		intent := to.Intent{Operation: to.LEARIP, Dst: dst, SignedDisp: int64(displacement)}
		encoded, err := to.Encode(intent, to.Encoding{Form: to.LEA8D, REX: 0x48 | dst/8<<2 | ignored&3, DispBytes: 4})
		if err != nil {
			t.Fatal(err)
		}
		target := new(big.Int).Add(interfaceU(pc+7), big.NewInt(int64(displacement)))
		ceiling := new(big.Int).Lsh(big.NewInt(1), 47)
		valid := target.Sign() >= 0 && target.Cmp(ceiling) < 0
		loadIndex := 0
		var loads []interfaceMapping
		if valid {
			a := target.Uint64()
			if a >= pc && a < pc+9 {
				// A readonly instruction mapping can supply address provenance;
				// it still supplies no implicit data access or initial scalar.
			} else if a <= 1<<47-16 && (a+16 <= pc || a >= pc+4096) {
				loads = []interfaceMapping{{start: a, end: a + 16, file: 0x2000 + a%4096, read: true, write: true}}
				loadIndex = 1
			} else {
				valid = false
			}
		}
		raw := transitionImageELF(t, append(encoded, 0x0f, 0x0b), loads)
		binary.LittleEndian.PutUint64(raw[24:], pc)
		binary.LittleEndian.PutUint64(raw[80:], pc)
		im, err := NewImage(t.Context(), raw)
		if err != nil {
			t.Fatal(err)
		}
		p := TransitionProposal{ImageDigest: sha256.Sum256(raw), Entry: pc, Cut: pc + 7, Root: 1, Nodes: []TransitionNode{{ID: 1, PC: pc, Size: 7, Successors: []TransitionOccurrenceID{2}}, {ID: 2, PC: pc + 7, Size: 2}}}
		face := stateFace(16, 0)
		c, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
		if !valid {
			sequenceRefused(t, c, err, "transition-image", pc)
			return
		}
		if err != nil {
			t.Fatal("valid independent RIP construction refused", err)
		}
		b := c.checked.bound
		if len(b.Accesses) != 0 || b.Registers[dst].Pointer != b.Geometry.imagePointer(loadIndex, target.Uint64()) || stateEval(t, b.Registers[dst].Value, nil) != target.Uint64() {
			t.Fatal("RIP address relation differs")
		}
	})
}
