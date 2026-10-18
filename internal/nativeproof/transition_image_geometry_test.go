package nativeproof

import (
	"encoding/binary"
	"math/rand"
	"slices"
	"testing"
	"testing/quick"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

type imageGeometry struct {
	entry         uint64
	face          TransitionInterface
	loads         []interfaceMapping
	program       []stateInstruction
	first, second Span
}

// A 72-byte descriptor supplies independent uint32 lengths/backing lengths,
// full uint64 access offsets, overlap coordinates, order, encoding and signed
// overlap displacement. The two declared spans share the full 1 MiB allowance
// with 32 stack bytes. No small-size clamp is imposed on the property grammar.
// Physical loads include independently sized undeclared leading/trailing bytes;
// their page-separated positions and file offsets are planned before encoding.
func imageGeometryPlan(t testing.TB, descriptor []byte, translated, constant uint64) imageGeometry {
	t.Helper()
	var d [72]byte
	copy(d[:], descriptor)
	u32 := func(at int) uint64 { return uint64(binary.LittleEndian.Uint32(d[at:])) }
	u64 := func(at int) uint64 { return binary.LittleEndian.Uint64(d[at:]) }
	const budget = uint64(1 << 20)
	a := uint64(24) + u32(0)%(budget-32-8-24+1)
	b := uint64(8) + u32(4)%(budget-32-a-8+1)
	remaining := budget - 32 - a - b
	duplicate := u32(56) % (min(a, remaining) + 1)
	prefixA, suffixA := u32(8)%4096, 8+u32(12)%4096
	prefixB, suffixB := u32(16)%4096, 8+u32(20)%4096
	page := func(x uint64) uint64 { return (x + 4095) / 4096 * 4096 }
	// Translation is independent of geometry/payload. A 32 MiB reserve keeps
	// both relative layouts canonical; high-boundary arithmetic is also covered
	// by the separate full-disp32 RIP and arbitrary-interface populations.
	anchor := (translated % uint64(1<<47-32<<20)) / 4096 * 4096
	// This arm deliberately gives an image byte and a stack-relative byte the
	// SAME coordinate number, while their actual addresses remain disjoint.
	// A signed disp32 LEA must still be able to construct the stack coordinate.
	if d[64]&8 != 0 {
		anchor %= 1 << 30
	}
	g := imageGeometry{entry: anchor}
	start := anchor + (1 << 20) + u32(28)%(1<<20)
	if d[64]&2 != 0 {
		g.entry = anchor + 16<<20
		start = anchor + 4096 + u32(28)%(1<<20)
	}
	start = page(start) + u32(24)%4096
	g.first = Span{start + prefixA, start + prefixA + a}
	first := interfaceMapping{start: start, end: g.first.End + suffixA, read: true, write: true}
	start = page(first.end) + 4096 + u32(28)%(1<<20)
	start = page(start) + u32(24)/4096%4096
	g.second = Span{start + prefixB, start + prefixB + b}
	second := interfaceMapping{start: start, end: g.second.End + suffixB, read: true, write: true}
	first.filesz = u32(32) % (first.end - first.start + 1)
	second.filesz = u32(36) % (second.end - second.start + 1)
	g.face = stateFace(16, 0)
	g.face.Regions = []RelativeRegion{{Bytes: RelativeSpan{0, 32}, Readable: true, Writable: true}}
	g.face.Words = nil
	g.face.ImageRegions = []Span{g.first, g.second}
	if duplicate != 0 {
		at := g.first.Start + u32(60)%(a-duplicate+1)
		g.face.ImageRegions = append(g.face.ImageRegions, Span{at, at + duplicate})
	}
	if d[64]&1 != 0 {
		slices.Reverse(g.face.ImageRegions)
	}
	targetA := g.first.Start + 8 + u64(40)%(a-23)
	targetB := g.second.Start + u64(48)%(b-7)
	if d[64]&8 != 0 {
		g.face.Regions[0].Bytes = RelativeSpan{int64(targetA), int64(targetA) + 32}
	}
	pc := g.entry
	emit := func(i to.Intent) {
		encoded, err := to.Encode(i, stateEncoding(i, d[65]))
		if err != nil {
			t.Fatal(err)
		}
		g.program = append(g.program, stateOp(i, d[65]))
		pc += uint64(len(encoded))
	}
	rip := func(dst uint8, address uint64) {
		emit(to.Intent{Operation: to.LEARIP, Dst: dst, SignedDisp: int64(address) - int64(pc+7)})
	}
	rip(12, targetA)
	if d[64]&8 != 0 {
		emit(to.Intent{Operation: to.LEA, Dst: 13, Base: 4, SignedDisp: int64(targetA)})
	} else {
		emit(to.Intent{Operation: to.MoveRegister, Dst: 13, Src: 4})
	}
	rip(11, targetB)
	for _, i := range []to.Intent{
		{Operation: to.Load, Dst: 0, Base: 12},
		{Operation: to.Store, Base: 13, Src: 0},
		{Operation: to.Store, Base: 12, Src: 13},
		{Operation: to.Load, Dst: 14, Base: 12},
		{Operation: to.Store, Base: 14, Src: 11, SignedDisp: 8},
		{Operation: to.Load, Dst: 15, Base: 13, SignedDisp: 8},
		{Operation: to.Store, Base: 15, Src: 12},
		{Operation: to.Load, Dst: 2, Base: 15},
		{Operation: to.Load, Dst: 3, Base: 2},
		{Operation: to.Store, Base: 3, Src: 0, SignedDisp: 16},
		{Operation: to.MoveImmediate, Dst: 0, Immediate: constant},
	} {
		emit(i)
	}
	distance := int64(int32(binary.LittleEndian.Uint32(d[68:]))) % 17
	if distance < -8 {
		distance += 17
	}
	if distance > 8 {
		distance -= 17
	}
	for _, i := range []to.Intent{
		{Operation: to.Store, Base: 12, Src: 0, SignedDisp: distance},
		{Operation: to.Load, Dst: 1, Base: 12},
		{Operation: to.Store, Base: 13, Src: 1, SignedDisp: 24},
		{Operation: to.Load, Dst: 9, Base: 13, SignedDisp: 24},
		{Operation: to.Store, Base: 15, Src: 9},
		{Operation: to.Load, Dst: 10, Base: 15},
		{Operation: to.LEA, Dst: 6, Base: 12, SignedDisp: int64(first.end - targetA)},
		{Operation: to.Subtract, Dst: 6, Immediate: first.end - targetA},
		{Operation: to.Load, Dst: 7, Base: 6},
	} {
		emit(i)
	}
	file := uint64(sequenceMappingSize(statePopulationInstructions+len(g.program))) + 0x2000
	first.file = file + first.start%4096
	second.file = page(first.file+first.filesz) + 4096 + second.start%4096
	g.loads = []interfaceMapping{first, second}
	if d[64]&4 != 0 {
		slices.Reverse(g.loads)
	}
	return g
}

func imageGeometryIndex(g imageGeometry, span Span) int {
	for j, m := range g.loads {
		if span.Start >= m.start && span.End <= m.end {
			return j
		}
	}
	panic("fixture lost its intended data load")
}

// This driver reuses the existing independent interface, state, constructor-
// depth and cut oracles. There is no second memory interpreter. Every accepted
// boundary checks ALL input/current bytes and tags, not just the accessed word.
func checkImageStatefulGeometry(t testing.TB, descriptor, footprints, records, valuation, cutBits []byte, translation, constant uint64, permissions uint8) {
	t.Helper()
	g := imageGeometryPlan(t, descriptor, translation, constant)
	cuts := append([]byte(nil), cutBits...)
	for len(cuts) < 3 {
		cuts = append(cuts, 0)
	}
	for _, cut := range []int{4, 6, 7, 10, 12, 15, 21, 22} {
		cuts[(cut-1)/8] |= 1 << ((cut - 1) % 8)
	}
	check := func(face TransitionInterface, ops []stateInstruction, loads []interfaceMapping) sequenceOutcome {
		return checkStateSequenceAt(t, face, ops, valuation, cuts, translation, g.entry, statePopulationInstructions, loads...)
	}
	baseline := check(g.face, g.program, g.loads)
	// As in the original stateful-geometry population, an independently sized
	// allowance outside host int is an explicitly checked configuration refusal,
	// not a state theorem. This matters for large unions/many cuts on 386.
	if baseline.configuration {
		return
	}
	if baseline != (sequenceOutcome{cut: len(g.program)}) {
		t.Fatalf("geometry lost its complete positive: %+v", baseline)
	}
	a, b := imageGeometryIndex(g, g.first), imageGeometryIndex(g, g.second)
	// Independently selected permissions affect real PT_LOAD flags. The optional
	// first scalar write also reaches a write-only prefix before a later read.
	permissionLoads := slices.Clone(g.loads)
	permissionLoads[a].read, permissionLoads[a].write = permissions&1 != 0, permissions&2 != 0
	permissionLoads[b].read, permissionLoads[b].write = permissions&4 != 0, permissions&8 != 0
	permissionProgram := slices.Clone(g.program)
	if permissions&16 != 0 {
		permissionProgram[3] = stateOp(to.Intent{Operation: to.MoveImmediate, Dst: 0, Immediate: constant}, 0)
	}
	check(g.face, permissionProgram, permissionLoads)
	// Named single-premise counterparts must reach the expected frontier, not
	// merely return some error somewhere in a different input population.
	readDenied := slices.Clone(g.loads)
	readDenied[a].read = false
	if got := check(g.face, g.program, readDenied); got != (sequenceOutcome{cut: 3, premise: "transition-permission"}) {
		t.Fatal("read-permission frontier", got)
	}
	writeDenied := slices.Clone(g.loads)
	writeDenied[b].write = false
	if got := check(g.face, g.program, writeDenied); got != (sequenceOutcome{cut: 9, premise: "transition-permission"}) {
		t.Fatal("write-permission frontier", got)
	}
	// Remove every declaration covering A, then give its first read only seven
	// bytes. The actual mapping/permissions still admit the complete eight bytes.
	targetA := g.entry + 7 + uint64(g.program[0].intent.SignedDisp)
	edge := cloneTransitionInterface(g.face)
	edge.ImageRegions = []Span{g.second, {targetA, targetA + 7}}
	if got := check(edge, g.program, g.loads); got != (sequenceOutcome{cut: 3, premise: "transition-permission"}) {
		t.Fatal("declared full-width frontier", got)
	}
	// The accepted one-past pointer crosses an actual continuation cut. A new
	// eight-byte access seven bytes before the logical end must fail there.
	endProgram := append(slices.Clone(g.program), stateOp(to.Intent{Operation: to.LEA, Dst: 6, Base: 12, SignedDisp: int64(g.loads[a].end-targetA) - 7}, 0), stateOp(to.Intent{Operation: to.Load, Dst: 0, Base: 6}, 0))
	if got := check(g.face, endProgram, g.loads); got != (sequenceOutcome{cut: len(endProgram) - 1, premise: "transition-image"}) {
		t.Fatal("logical mapping full-width frontier", got)
	}
	alias := slices.Clone(g.loads)
	alias[a].filesz, alias[b].filesz = 1, 1
	alias[b].file = alias[a].file/4096*4096 + alias[b].start%4096
	if got := check(g.face, g.program, alias); got.premise != "frame-alias" || got.cut != 0 {
		t.Fatal("backing alias frontier", got)
	}
	// Raw absolute endpoint pairs can express any declared footprint, including
	// holes, reordered overlaps, untouched regions, overflow and budget excess.
	// The first counted region overflow is retained; no unmaterialized tail is
	// claimed. Nonempty inputs replace the planned footprints, never root values.
	if len(footprints) != 0 {
		face := cloneTransitionInterface(g.face)
		face.ImageRegions = nil
		for len(footprints) != 0 && len(face.ImageRegions) <= 256 {
			var row [16]byte
			n := copy(row[:], footprints)
			footprints = footprints[n:]
			face.ImageRegions = append(face.ImageRegions, Span{binary.LittleEndian.Uint64(row[:8]), binary.LittleEndian.Uint64(row[8:])})
		}
		check(face, g.program, g.loads)
	}
	// Arbitrary literal operations continue from the live mixed state. No anchor
	// repair, reinitialization, new root inputs or periodic dependency reset.
	if len(records) != 0 {
		tail := sequenceRecords(records, nil, statePopulationInstructions)
		check(g.face, append(slices.Clone(g.program), tail...), g.loads)
	}
}

func FuzzTransitionImageStatefulGeometry(f *testing.F) {
	for _, size := range []uint32{0, 1, 17, 489, 4097} {
		for _, order := range []byte{0, 7, 8, 15} {
			d := make([]byte, 72)
			for at, value := range map[int]uint32{0: size, 4: size / 2, 8: 19, 12: 7, 16: 31, 20: 8, 24: 4097, 28: 8193, 32: 23, 36: 0, 56: 13, 60: 3, 68: 7} {
				binary.LittleEndian.PutUint32(d[at:], value)
			}
			d[64], d[65] = order, 0xff
			g := imageGeometryPlan(f, d, 1<<44, 0xfedcba9876543210)
			// Value every byte of the larger seeded unions, including untouched
			// BSS-looking tails. This raw field remains independent and unbounded
			// in the fuzz grammar; it is never generated from artifact contents.
			values := make([]byte, 137+sequenceCardinality(g.face))
			if _, err := rand.New(rand.NewSource(881)).Read(values); err != nil {
				f.Fatal(err)
			}
			var spans []byte
			for _, s := range []Span{g.second, g.first, {g.first.Start + 1, g.first.End - 1}} {
				spans = binary.LittleEndian.AppendUint64(spans, s.Start)
				spans = binary.LittleEndian.AppendUint64(spans, s.End)
			}
			record := sequenceRecord(to.Intent{Operation: to.Store, Base: 12, Src: 13}, 0)
			f.Add(d, spans, record, values, []byte{0xff}, uint64(1<<44), uint64(0xfedcba9876543210), uint8(15))
		}
	}
	f.Fuzz(func(t *testing.T, descriptor, footprints, records, values, cuts []byte, translation, constant uint64, permissions uint8) {
		checkImageStatefulGeometry(t, descriptor, footprints, records, values, cuts, translation, constant, permissions)
	})
}

func TestTransitionImageStatefulGeometryProperty(t *testing.T) {
	// Quick trials sample manageable larger unions; the fuzz grammar above keeps
	// the entire byte-budget domain and raw uncorrelated payload fields.
	if err := quick.Check(func(shape [9]uint64, values [128]uint64, translation, constant uint64, permissions uint8) bool {
		var descriptor, raw []byte
		for _, v := range shape {
			descriptor = binary.LittleEndian.AppendUint64(descriptor, v)
		}
		for _, v := range values {
			raw = binary.LittleEndian.AppendUint64(raw, v)
		}
		binary.LittleEndian.PutUint32(descriptor, uint32(shape[0]%8192))
		binary.LittleEndian.PutUint32(descriptor[4:], uint32(shape[1]%4096))
		checkImageStatefulGeometry(t, descriptor, nil, nil, raw, nil, translation, constant, permissions)
		return true
	}, &quick.Config{MaxCount: 12, Rand: rand.New(rand.NewSource(0x494d4747454f))}); err != nil {
		t.Fatal(err)
	}
}
