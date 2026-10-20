package nativeproof

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func concreteAccessValue(v uint64, width int) br.Term {
	t, err := br.NewBuilder(1).Const(br.Bits(width), v)
	if err != nil {
		panic(err)
	}
	return t
}

func assertConcreteAccesses(t testing.TB, got, want []TransitionAccess, values map[br.Term]uint64, instructions []GuardedInstruction) {
	t.Helper()
	owners := map[uint64]TransitionOccurrenceID{}
	ids := map[TransitionOccurrenceID]bool{}
	for _, ins := range instructions {
		if ins.ID == 0 || ids[ins.ID] || owners[ins.Start] != 0 {
			t.Fatal("nonunique straight-line fixture occurrence")
		}
		ids[ins.ID] = true
		owners[ins.Start] = ins.ID
	}
	if len(got) != len(want) {
		t.Fatal("access count differs")
	}
	for j, g := range got {
		w := want[j]
		w.ID = owners[w.PC]
		if w.ID == 0 {
			t.Fatal("reference access has no instruction occurrence")
		}
		gv, wv := g.Value, w.Value
		g.Value, w.Value = br.Term{}, br.Term{}
		if g != w || gv.Sort() != wv.Sort() || stateEval(t, gv, values) != stateEval(t, wv, nil) {
			t.Fatal("independent access/value sequence differs", j, g, w)
		}
	}
}

// Synthetic intent exists before encoding. The reference machine below consumes
// this intent, not a production decoder, address helper, transfer, or disassembly.
// Encoding alternatives deliberately cover the admitted immediate and ModRM/SIB
// forms. This is a bounded synthetic population, not actual-startup evidence.
type transitionIntent struct {
	op             string
	dst, src, base int
	imm            uint64
	disp           int32
	form           int
}

func encodeTransitionIntent(i transitionIntent) (code []byte, size int) {
	put32 := func(v uint32) { code = binary.LittleEndian.AppendUint32(code, v) }
	rex := func(r, b int) { code = append(code, 0x48|byte(r>>3)<<2|byte(b>>3)) }
	mem := func(op byte, r int) {
		rex(r, i.base)
		code = append(code, op)
		mod := byte(0)
		if i.form%3 == 1 || i.disp != 0 || i.base%8 == 5 {
			mod = 0x40
		}
		if i.form%3 == 2 || i.disp < -128 || i.disp > 127 {
			mod = 0x80
		}
		code = append(code, mod|byte(r%8)<<3|byte(i.base%8))
		if i.base%8 == 4 {
			code = append(code, 0x24)
		}
		if mod == 0x40 {
			code = append(code, byte(i.disp))
		}
		if mod == 0x80 {
			put32(uint32(i.disp))
		}
	}
	switch i.op {
	case "copy":
		if i.form%2 == 0 {
			rex(i.src, i.dst)
			code = append(code, 0x89, 0xc0|byte(i.src%8)<<3|byte(i.dst%8))
		} else {
			rex(i.dst, i.src)
			code = append(code, 0x8b, 0xc0|byte(i.dst%8)<<3|byte(i.src%8))
		}
	case "imm":
		rex(0, i.dst)
		if i.form%2 == 0 {
			code = append(code, 0xb8+byte(i.dst%8))
			code = binary.LittleEndian.AppendUint64(code, i.imm)
		} else {
			code = append(code, 0xc7, 0xc0|byte(i.dst%8))
			put32(uint32(i.imm))
		}
	case "imm32":
		if i.dst >= 8 {
			code = append(code, 0x41)
		}
		code = append(code, 0xb8+byte(i.dst%8))
		put32(uint32(i.imm))
	case "load":
		mem(0x8b, i.dst)
	case "store":
		mem(0x89, i.src)
	case "store-imm":
		mem(0xc7, 0)
		put32(uint32(i.imm))
	case "lea":
		mem(0x8d, i.dst)
	case "sub", "and":
		group, acc := byte(5), byte(0x2d)
		if i.op == "and" {
			group, acc = 4, 0x25
		}
		rex(0, i.dst)
		if i.form == 2 && i.dst == 0 {
			code = append(code, acc)
			put32(uint32(i.imm))
		} else if i.form == 0 {
			code = append(code, 0x83, 0xc0|group<<3|byte(i.dst%8), byte(i.imm))
		} else {
			code = append(code, 0x81, 0xc0|group<<3|byte(i.dst%8))
			put32(uint32(i.imm))
		}
	case "jump":
		if i.form%2 == 0 {
			code = append(code, 0xeb, 2)
		} else {
			code = append(code, 0xe9, 2, 0, 0, 0)
		}
		size = len(code)
		return append(code, 0x0f, 0x0b), size // unreachable UD2, never a proof premise
	default:
		panic("unknown synthetic intent")
	}
	return code, len(code)
}

type transitionReference struct {
	regs [16]uint64
	// The reference's tags identify a concrete origin-relative word, separately
	// from uint64 ISA values; no production provenance helper participates.
	pointers [16]*int64
	memory   map[uint64]byte
	lanes    map[uint64]struct {
		offset int64
		lane   int
	}
	// CF, ZF, OF, SF, AF, PF. AF's value is ignored after logical operations;
	// its undefined status is checked separately from these concrete oracle bits.
	flags      [6]bool
	accesses   []TransitionAccess
	written    [16]bool
	flagWriter string
	origin     uint64
}

func (r *transitionReference) step(i transitionIntent, pc uint64) {
	ptr := func(off int64) *int64 { return &off }
	parity := func(value uint64) bool {
		odd := false
		for bit := uint(0); bit < 8; bit++ {
			odd = odd != (value>>bit&1 != 0)
		}
		return !odd
	}
	address := r.regs[i.base] + uint64(int64(i.disp))
	access := func(kind AccessKind) {
		off := int64(address - r.origin)
		r.accesses = append(r.accesses, TransitionAccess{PC: pc, Kind: kind, Bytes: RelativeSpan{off, off + 8}})
	}
	store := func(v uint64, p *int64) {
		access(FrameWrite)
		r.accesses[len(r.accesses)-1].Value = concreteAccessValue(v, 64)
		for j := 0; j < 8; j++ {
			r.memory[address+uint64(j)] = byte(v >> (8 * j))
			delete(r.lanes, address+uint64(j))
			if p != nil {
				r.lanes[address+uint64(j)] = struct {
					offset int64
					lane   int
				}{*p, j}
			}
		}
	}
	switch i.op {
	case "jump":
		return
	case "store":
		store(r.regs[i.src], r.pointers[i.src])
		return
	case "store-imm":
		store(i.imm, nil)
		return
	}
	r.written[i.dst] = true
	switch i.op {
	case "copy":
		r.regs[i.dst] = r.regs[i.src]
		r.pointers[i.dst] = r.pointers[i.src]
	case "imm", "imm32":
		r.regs[i.dst] = i.imm
		if i.op == "imm32" {
			r.regs[i.dst] = uint64(uint32(i.imm))
		}
		r.pointers[i.dst] = nil
	case "lea":
		r.regs[i.dst] = address
		p := r.pointers[i.base]
		r.pointers[i.dst] = nil
		if p != nil {
			r.pointers[i.dst] = ptr(*p + int64(i.disp))
		}
	case "load":
		access(FrameRead)
		var v uint64
		for j := 0; j < 8; j++ {
			v |= uint64(r.memory[address+uint64(j)]) << uint(8*j)
		}
		r.accesses[len(r.accesses)-1].Value = concreteAccessValue(v, 64)
		r.regs[i.dst] = v
		r.pointers[i.dst] = nil
		first, ok := r.lanes[address]
		for j := 0; j < 8; j++ {
			lane, found := r.lanes[address+uint64(j)]
			ok = ok && found && lane.offset == first.offset && lane.lane == j
		}
		if ok {
			r.pointers[i.dst] = ptr(first.offset)
		}
	case "sub":
		left := r.regs[i.dst]
		r.regs[i.dst] = left - i.imm
		result := r.regs[i.dst]
		r.flags = [6]bool{left < i.imm, result == 0, (left^i.imm)&(left^result)&(1<<63) != 0, result>>63 != 0, (left^i.imm^result)&16 != 0, parity(result)}
		if p := r.pointers[i.dst]; p != nil {
			r.pointers[i.dst] = ptr(*p - int64(i.imm))
		}
		r.flagWriter = "sub"
	case "and":
		r.regs[i.dst] &= i.imm
		result := r.regs[i.dst]
		r.flags = [6]bool{false, result == 0, false, result>>63 != 0, false, parity(result)}
		if r.pointers[i.dst] != nil {
			r.pointers[i.dst] = ptr(int64(r.regs[i.dst] - r.origin))
		}
		r.flagWriter = "and"
	}
}

func assertIntentReference(t testing.TB, c TransitionCertificate, program []transitionIntent, pcs []uint64, sample uint64) {
	t.Helper()
	b, _ := c.Bound()
	rng := rand.New(rand.NewPCG(sample, 0x71e))
	origin := (uint64(0x100000000)+(sample&0xffff)*256)&^(b.Interface.Origin.Modulus-1) | b.Interface.Origin.Residue
	r := transitionReference{origin: origin, memory: make(map[uint64]byte), lanes: make(map[uint64]struct {
		offset int64
		lane   int
	})}
	values := make(map[br.Term]uint64)
	for j := range r.flags {
		r.flags[j] = rng.Uint64()&1 != 0
	}
	initialPredicates := [3]bool{r.flags[0], r.flags[1], r.flags[3] != r.flags[2]}
	for j, predicate := range []br.Term{b.InitialPredicates.CF, b.InitialPredicates.ZF, b.InitialPredicates.SFXorOF} {
		if predicate.View().Op == br.Variable {
			var value uint64
			if initialPredicates[j] {
				value = 1
			}
			values[predicate] = value
		}
	}
	for j, v := range b.InitialRegisters {
		r.regs[j] = rng.Uint64()
		values[v] = r.regs[j]
	}
	r.regs[RSP] = origin
	values[b.Origin] = origin
	zero := int64(0)
	r.pointers[RSP] = &zero
	for _, w := range b.Words {
		values[w.Value] = rng.Uint64()
	}
	for _, v := range b.InitialMemory {
		if v.Value.View().Op == br.Variable {
			values[v.Value] = uint64(byte(rng.Uint32()))
		}
		r.memory[origin+uint64(v.Offset)] = byte(evalRelationTerm(t, v.Value, values, 0))
	}
	for j, i := range program {
		r.step(i, pcs[j])
	}
	assertConcreteAccesses(t, b.Accesses, r.accesses, values, b.Instructions)
	for j, v := range b.Registers {
		if got := evalRelationTerm(t, v.Value, values, 0); got != r.regs[j] {
			t.Fatalf("register%d got%x want%x", j, got, r.regs[j])
		}
		var expected TransitionPointer
		if r.pointers[j] != nil {
			expected = OriginPointer{b.Origin, *r.pointers[j]}
		}
		if v.Pointer != expected {
			t.Fatal("register provenance differs", j)
		}
		if (b.Preserved[j] == 0) != r.written[j] {
			t.Fatal("root preservation reset", j)
		}
	}
	for _, v := range b.Memory {
		address := origin + uint64(v.Offset)
		if got := byte(evalRelationTerm(t, v.Value, values, 0)); got != r.memory[address] {
			t.Fatal("memory value differs", v.Offset)
		}
		lane, found := r.lanes[address]
		var expected TransitionPointer
		if found {
			expected = OriginPointer{b.Origin, lane.offset}
		}
		if v.Image || v.Pointer != expected || found && int(v.PointerLane) != lane.lane {
			t.Fatal("byte provenance differs", v.Offset)
		}
	}
	private := [3]bool{r.flags[0], r.flags[1], r.flags[3] != r.flags[2]}
	for j, v := range c.checked.flags {
		if got := evalRelationTerm(t, v, values, 0) != 0; got != private[j] {
			t.Fatal("private predicate differs", j, r.flagWriter)
		}
	}
	for j, f := range []TransitionFlag{b.Flags.CF, b.Flags.ZF, b.Flags.OF, b.Flags.SF, b.Flags.AF, b.Flags.PF} {
		if f.Preserved != (r.flagWriter == "") || f.Defined != (r.flagWriter != "and" || j != 4) {
			t.Fatal("flag status differs", j)
		}
		if f.Value.Valid() && (!f.Defined || (evalRelationTerm(t, f.Value, values, 0) != 0) != r.flags[j]) {
			t.Fatal("projected public flag differs from independent ISA oracle", j)
		}
	}
}

// Alpha-renaming is solely a test oracle between independent root checks. The
// continuation implementation must instead preserve the original term handles.
func assertTransitionAlpha(t testing.TB, direct, segmented TransitionCertificate) {
	t.Helper()
	a, b := direct.checked.bound, segmented.checked.bound
	scopes := map[br.Scope]br.Scope{a.Origin.View().Scope: b.Origin.View().Scope}
	if len(a.PrimitiveEffects) != len(b.PrimitiveEffects) {
		t.Fatal("primitive occurrence count differs")
	}
	for j, effect := range a.PrimitiveEffects {
		if p, ok := effect.(LockedExchange64Effect); ok {
			q, valid := b.PrimitiveEffects[j].(LockedExchange64Effect)
			if !valid || p.PC != q.PC || p.Context != q.Context || p.ReadAccess != q.ReadAccess || p.WriteAccess != q.WriteAccess {
				t.Fatal("exchange occurrence differs")
			}
			continue
		}
		if p, ok := effect.(LockedExchangeAdd64Effect); ok {
			q, valid := b.PrimitiveEffects[j].(LockedExchangeAdd64Effect)
			if !valid || p.PC != q.PC || p.Context != q.Context || p.ReadAccess != q.ReadAccess || p.WriteAccess != q.WriteAccess {
				t.Fatal("exchange-add occurrence differs")
			}
			continue
		}
		if p, ok := effect.(LockedCompareExchangeEffect); ok {
			q, valid := b.PrimitiveEffects[j].(LockedCompareExchangeEffect)
			if !valid || p.Width != q.Width || p.PC != q.PC || p.Context != q.Context || p.ReadAccess != q.ReadAccess || p.WriteAccess != q.WriteAccess {
				t.Fatal("locked occurrence differs")
			}
			continue
		}
		if p, ok := effect.(LockedLogicalEffect); ok {
			q, valid := b.PrimitiveEffects[j].(LockedLogicalEffect)
			if !valid || p.Width != q.Width || p.Kind != q.Kind || p.PC != q.PC || p.Context != q.Context || p.ReadAccess != q.ReadAccess || p.WriteAccess != q.WriteAccess {
				t.Fatal("locked logical occurrence differs")
			}
			continue
		}
		p, ok := effect.(CPUIDEffect)
		q, valid := b.PrimitiveEffects[j].(CPUIDEffect)
		if !ok || !valid || p.PC != q.PC {
			t.Fatal("primitive occurrence kind/PC differs")
		}
		ps, qs := p.ResultsEAX.View().Scope, q.ResultsEAX.View().Scope
		if ps == qs {
			t.Fatal("independent roots reused a query scope")
		}
		if _, exists := scopes[ps]; exists {
			t.Fatal("query reused an origin scope")
		}
		for _, mapped := range scopes {
			if mapped == qs {
				t.Fatal("non-bijective query scope map")
			}
		}
		scopes[ps] = qs
	}
	seen := map[[2]br.Term]bool{}
	var equal func(br.Term, br.Term)
	equal = func(x, y br.Term) {
		t.Helper()
		if !x.Valid() || !y.Valid() {
			if x.Valid() != y.Valid() {
				t.Fatal("missing expression")
			}
			return
		}
		pair := [2]br.Term{x, y}
		if seen[pair] {
			return
		}
		seen[pair] = true
		p, q := x.View(), y.View()
		if p.Op != q.Op || p.Sort != q.Sort || p.Immediate != q.Immediate || p.Scratch != q.Scratch || len(p.Args) != len(q.Args) {
			t.Fatal("direct/segmented expression shape differs", p, q)
		}
		if p.Op == br.Variable && (scopes[p.Scope] != q.Scope || q.Scope == (br.Scope{})) {
			t.Fatal("foreign symbolic namespace")
		}
		for j := range p.Args {
			equal(p.Args[j], q.Args[j])
		}
	}
	if a.Origin == b.Origin {
		t.Fatal("independent roots unexpectedly share namespace")
	}
	for j, effect := range a.PrimitiveEffects {
		if p, ok := effect.(LockedExchange64Effect); ok {
			q := b.PrimitiveEffects[j].(LockedExchange64Effect)
			for k, root := range []br.Term{p.Before, p.Replacement, p.After, p.Register} {
				equal(root, []br.Term{q.Before, q.Replacement, q.After, q.Register}[k])
			}
			continue
		}
		if p, ok := effect.(LockedExchangeAdd64Effect); ok {
			q := b.PrimitiveEffects[j].(LockedExchangeAdd64Effect)
			for k, root := range []br.Term{p.Before, p.Delta, p.After, p.Register} {
				equal(root, []br.Term{q.Before, q.Delta, q.After, q.Register}[k])
			}
			continue
		}
		if p, ok := effect.(LockedCompareExchangeEffect); ok {
			q := b.PrimitiveEffects[j].(LockedCompareExchangeEffect)
			for k, root := range []br.Term{p.Before, p.Compare, p.Replacement, p.After, p.Accumulator, p.Success} {
				equal(root, []br.Term{q.Before, q.Compare, q.Replacement, q.After, q.Accumulator, q.Success}[k])
			}
			continue
		}
		if p, ok := effect.(LockedLogicalEffect); ok {
			q := b.PrimitiveEffects[j].(LockedLogicalEffect)
			for k, root := range []br.Term{p.Before, p.Operand, p.After} {
				equal(root, []br.Term{q.Before, q.Operand, q.After}[k])
			}
			continue
		}
		p, q := effect.(CPUIDEffect), b.PrimitiveEffects[j].(CPUIDEffect)
		for k, root := range []br.Term{p.Leaf, p.Subleaf, p.ResultsEAX, p.ResultsEBX, p.ResultsECX, p.ResultsEDX} {
			equal(root, []br.Term{q.Leaf, q.Subleaf, q.ResultsEAX, q.ResultsEBX, q.ResultsECX, q.ResultsEDX}[k])
		}
	}
	if a.Preserved != b.Preserved || len(a.Instructions) != len(b.Instructions) || len(a.Accesses) != len(b.Accesses) || !reflect.DeepEqual(a.Interface, b.Interface) || !reflect.DeepEqual(a.ExcludedOrigins, b.ExcludedOrigins) || !reflect.DeepEqual(a.Boundary, b.Boundary) {
		t.Fatal("direct/segmented scope differs")
	}
	for j, access := range a.Accesses {
		other := b.Accesses[j]
		equal(access.Value, other.Value)
		access.Value, other.Value = br.Term{}, br.Term{}
		if access != other {
			t.Fatal("direct/segmented access differs")
		}
	}
	for j, occurrence := range a.Instructions {
		if occurrence.Span != b.Instructions[j].Span {
			t.Fatal("occurrence extent differs")
		}
		equal(occurrence.Guard, b.Instructions[j].Guard)
	}
	equal(a.CutGuard, b.CutGuard)
	equal(a.EntryPredicate, b.EntryPredicate)
	equal(a.InitialDirection, b.InitialDirection)
	equal(a.Direction, b.Direction)
	if len(a.ExcludedBoundaries) != len(b.ExcludedBoundaries) {
		t.Fatal("excluded coverage differs")
	}
	excluded := map[uint64]ExcludedBoundary{}
	for _, e := range b.ExcludedBoundaries {
		excluded[e.PC] = e
	}
	for _, e := range a.ExcludedBoundaries {
		other, ok := excluded[e.PC]
		if !ok || !reflect.DeepEqual(e.CutBoundary, other.CutBoundary) {
			t.Fatal("excluded bytes differ")
		}
		equal(e.Guard, other.Guard)
	}
	for j, p := range []br.Term{a.InitialPredicates.CF, a.InitialPredicates.ZF, a.InitialPredicates.SFXorOF} {
		equal(p, []br.Term{b.InitialPredicates.CF, b.InitialPredicates.ZF, b.InitialPredicates.SFXorOF}[j])
	}
	pointer := func(x, y TransitionPointer) {
		t.Helper()
		switch p := x.(type) {
		case nil:
			if y != nil {
				t.Fatal("pointer kind differs")
			}
		case OriginPointer:
			q, ok := y.(OriginPointer)
			if !ok || p.Offset != q.Offset {
				t.Fatal("stack pointer differs")
			}
			equal(p.Origin, q.Origin)
		case ImagePointer:
			if p != y {
				t.Fatal("image pointer owner/mapping/address differs")
			}
		case entryValueLineage:
			q, ok := y.(entryValueLineage)
			if !ok {
				t.Fatal("entry value lineage kind differs")
			}
			equal(p.value, q.value)
		default:
			t.Fatal("unknown pointer arm")
		}
	}
	for j := range a.Registers {
		equal(a.Registers[j].Value, b.Registers[j].Value)
		pointer(a.Registers[j].Pointer, b.Registers[j].Pointer)
	}
	if len(a.Memory) != len(b.Memory) {
		t.Fatal("memory extent differs")
	}
	for j, v := range a.Memory {
		w := b.Memory[j]
		equal(v.Value, w.Value)
		pointer(v.Pointer, w.Pointer)
		if v.TransitionLocation != w.TransitionLocation || v.PointerLane != w.PointerLane {
			t.Fatal("memory relation differs")
		}
	}
	for j := range direct.checked.flags {
		equal(direct.checked.flags[j], segmented.checked.flags[j])
	}
}

func checkSyntheticContinuations(t testing.TB, program []transitionIntent, variant uint64) {
	t.Helper()
	var code []byte
	var pcs []uint64
	for _, i := range program {
		pcs = append(pcs, testEntry+uint64(len(code)))
		encoded, _ := encodeTransitionIntent(i)
		code = append(code, encoded...)
	}
	cut := testEntry + uint64(len(code))
	// The unexecuted endpoint is deliberately outside the transition grammar.
	im := image(t, append(code, 0x0f, 0x0b))
	face := transitionFace()
	face.Origin = OriginDomain{0x10000, 1 << 46, 16 << uint(variant%2), variant % 16}
	face.Envelope = RelativeSpan{-128, 128}
	face.Regions = []RelativeRegion{{RelativeSpan{-64, 64}, true, true}}
	face.Words = nil
	if variant%3 != 0 {
		face.Words = []int64{0, 8}
	}
	if variant%3 == 2 {
		face.Regions = append(face.Regions, RelativeRegion{RelativeSpan{-32, 32}, true, true})
	}
	direct, err := CheckTransition(t.Context(), im, face, rootTransitionProposal(t, im, cut), TransitionLimits{})
	if err != nil {
		t.Fatalf("synthetic program %x\n%+v\n%v", code, program, err)
	}
	segmented := continuationRoot(t, im, testEntry, face, TransitionLimits{})
	initial := segmented.checked.bound
	for j := range program {
		next := cut
		if j+1 < len(pcs) {
			next = pcs[j+1]
		}
		var err error
		segmented, err = CheckTransitionContinuation(t.Context(), segmented, continuationProposal(t, segmented, next))
		if err != nil {
			t.Fatalf("segment%d intent%+v: %v", j, program[j], err)
		}
		b := segmented.checked.bound
		if b.Origin != initial.Origin || b.InitialRegisters != initial.InitialRegisters || !reflect.DeepEqual(b.InitialMemory, initial.InitialMemory) || !reflect.DeepEqual(b.Words, initial.Words) {
			t.Fatal("inherited terms were reconstructed")
		}
	}
	assertTransitionAlpha(t, direct, segmented)
	for sample := uint64(0); sample < 4; sample++ {
		assertIntentReference(t, segmented, program, pcs, variant*4+sample)
	}
	// A different split has the same theorem despite a different work history.
	if len(program) > 1 {
		middle := continuationRoot(t, im, pcs[len(program)/2], face, TransitionLimits{})
		other, err := CheckTransitionContinuation(t.Context(), middle, continuationProposal(t, middle, cut))
		if err != nil {
			t.Fatal(err)
		}
		assertTransitionAlpha(t, other, segmented)
	}
}

func generatedTransitionIntents(data []byte) []transitionIntent {
	program := []transitionIntent{{op: "copy", dst: 12, src: 4}, {op: "lea", dst: 3, base: 4, disp: 8}, {op: "store", src: 3, base: 12, disp: 16}}
	for j, v := range data {
		if j == 20 {
			break
		}
		i := transitionIntent{dst: int(v >> 4), src: int(v>>4) ^ 3, base: 12, form: int(v % 3), disp: int32(int(v%5)*8 - 16), imm: uint64(v) * 0x01010101}
		if i.dst == 4 || i.dst == 12 {
			i.dst = 0
		}
		switch v % 11 {
		case 0:
			i.op = "copy"
		case 1:
			i.op = "imm"
			if i.form%2 != 0 {
				i.imm = uint64(int64(int32(uint32(i.imm))))
			}
		case 2:
			i.op = "imm32"
		case 3:
			i.op = "load"
		case 4:
			i.op = "store"
		case 5:
			i.op = "store-imm"
			i.imm = uint64(int64(int32(uint32(i.imm))))
		case 6:
			i.op = "lea"
		case 7:
			i.op = "sub"
			i.imm = uint64(int64(int(v%7) - 3))
		case 8:
			i.op = "and"
			i.dst = 4
			i.imm = ^uint64(15)
		case 9:
			i.op = "jump"
		case 10:
			i.op = "load"
			i.disp = 16
		}
		program = append(program, i)
	}
	return program
}

func TestTransitionGeneratedSyntheticContinuations(t *testing.T) {
	for seed := uint64(0); seed < 24; seed++ {
		rng := rand.New(rand.NewPCG(seed, 0x1e37))
		data := make([]byte, 20)
		for j := range data {
			data[j] = byte(rng.Uint32())
		}
		t.Run(fmt.Sprint(seed), func(t *testing.T) { checkSyntheticContinuations(t, generatedTransitionIntents(data), seed) })
	}
	// All base registers, all canonical displacement sizes and both register
	// MOV directions; SIB/no-displacement and RBP/R13 special cases are included.
	for base := 0; base < 16; base++ {
		for form := 0; form < 3; form++ {
			p := []transitionIntent{{op: "copy", dst: base, src: 4, form: form}, {op: "store", base: base, src: base, form: form}, {op: "load", base: base, dst: (base + 1) % 16, form: form}}
			checkSyntheticContinuations(t, p, uint64(base*3+form))
		}
	}
	// Accumulator-specific imm32 arithmetic and both full-register immediate
	// encodings, including negative sign extension and unsigned high bits.
	for form := 0; form < 3; form++ {
		p := []transitionIntent{{op: "copy", dst: 0, src: 4}, {op: "sub", dst: 0, imm: 8, form: form}, {op: "and", dst: 0, imm: ^uint64(15), form: form}, {op: "imm", dst: 9, imm: ^uint64(0), form: form % 2}, {op: "imm32", dst: 5, imm: 0xffffffff}}
		checkSyntheticContinuations(t, p, uint64(form))
	}
}

func FuzzTransitionSyntheticContinuation(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, uint64(0))
	f.Add([]byte{255, 128, 17, 37, 81, 64, 10}, uint64(15))
	f.Fuzz(func(t *testing.T, data []byte, variant uint64) {
		checkSyntheticContinuations(t, generatedTransitionIntents(data), variant)
	})
}

func TestTransitionContinuationBackwardAcyclic(t *testing.T) {
	im, _ := transitionFixture(t, "eb064889e04889c34889e0ebf5")
	root := continuationRoot(t, im, testEntry+11, transitionFace(), TransitionLimits{})
	c, err := CheckTransitionContinuation(t.Context(), root, continuationProposal(t, root, testEntry+5))
	if err != nil {
		t.Fatal(err)
	}
	want := []Span{{testEntry, testEntry + 2}, {testEntry + 8, testEntry + 11}, {testEntry + 11, testEntry + 13}, {testEntry + 2, testEntry + 5}}
	if !reflect.DeepEqual(straightFetches(t, c.checked.bound), want) {
		t.Fatal("numeric ordering substituted for execution ordering")
	}
}
