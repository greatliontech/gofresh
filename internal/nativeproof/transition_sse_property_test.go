package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"math/rand"
	"slices"
	"strings"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// This bounded evolving grammar complements the integer-only sequence grammar.
// It has 1..4 stages, eight initialized scalar vector registers (XMM0..3 binary32
// and XMM8..11 binary64), eight arbitrary untouched vectors, and 96 owned bytes.
// Each stage forks on a different entry-DL bit, changes current memory/vectors,
// joins, compares current vectors, optionally overwrites flags with byte TEST,
// and branches on actual parity. Optional ordinary CALL/RET transfers a current
// memory value to another vector. Later stages consume the preceding state.
// Operands range over normals, infinities, zeros and quiet NaNs, with randomized
// payload/sign bits. Separate negative cases introduce exceptional operands.
// These tests sample this grammar, not all SSE programs or symbolic domains.
// The concrete interpreter below consumes generated intent, never decoded
// instructions, production transfer helpers, or projected checker values.
type sseSeqKind uint8

const (
	sseSeqImmediate sseSeqKind = iota
	sseSeqStore
	sseSeqLoad
	sseSeqCompare
	sseSeqTest
	sseSeqBranch
	sseSeqJump
	sseSeqCall
	sseSeqReturn
)

type sseSeqOp struct {
	kind                             sseSeqKind
	reg, other, width, target, owner int
	offset                           int8
	value                            uint64
	condition                        byte // 0: ZF; 1: PF; 2: !PF
	near                             bool
}

type sseSeqProgram struct {
	ops    []sseSeqOp
	cuts   []int
	pcs    []uint64
	code   []byte
	stages int
}

func sseSeqBits(width int, choice byte, payload uint64) uint64 {
	if width == 32 {
		sign := uint64(uint32(payload) & 0x80000000)
		switch choice % 6 {
		case 0:
			return sign
		case 1:
			return sign | 0x7f800000
		case 2:
			return sign | 0x7fc00000 | payload&0x3fffff
		case 3:
			return uint64(math.Float32bits(-1))
		case 4:
			return uint64(math.Float32bits(1))
		default:
			return sign | uint64(1+(payload>>23)%254)<<23 | payload&0x7fffff
		}
	}
	sign := payload & (uint64(1) << 63)
	switch choice % 6 {
	case 0:
		return sign
	case 1:
		return sign | 0x7ff0000000000000
	case 2:
		return sign | 0x7ff8000000000000 | payload&0x7ffffffffffff
	case 3:
		return math.Float64bits(-1)
	case 4:
		return math.Float64bits(1)
	default:
		return sign | (1+(payload>>52)%2046)<<52 | payload&0xfffffffffffff
	}
}

func sseSeqGenerate(data []byte) sseSeqProgram {
	var p sseSeqProgram
	at := 0
	next := func() byte {
		if len(data) == 0 {
			return 0
		}
		v := data[at%len(data)]
		at++
		return v
	}
	payload := func() uint64 {
		var v uint64
		for j := 0; j < 8; j++ {
			v |= uint64(next()) << uint(8*j)
		}
		return v
	}
	emit := func(op sseSeqOp) int { op.owner = -1; p.ops = append(p.ops, op); return len(p.ops) - 1 }
	store := func(value uint64, off int8) {
		emit(sseSeqOp{kind: sseSeqImmediate, reg: int(RAX), width: 64, value: value})
		emit(sseSeqOp{kind: sseSeqStore, reg: int(RAX), offset: off})
	}
	p.stages = 1 + int(next()%4)
	for _, width := range []int{32, 64} {
		bank := 0
		if width == 64 {
			bank = 8
		}
		for r := 0; r < 4; r++ {
			store(sseSeqBits(width, next(), payload()), 8)
			emit(sseSeqOp{kind: sseSeqLoad, reg: bank + r, width: width, offset: 8})
		}
	}
	p.cuts = append(p.cuts, len(p.ops))
	for stage := 0; stage < p.stages; stage++ {
		width, bank := 32, 0
		if next()&1 != 0 {
			width, bank = 64, 8
		}
		dst, src := bank+int(next()%4), bank+int(next()%4)
		off := int8(8 + 8*(next()%6))
		emit(sseSeqOp{kind: sseSeqTest, reg: int(RDX), value: 1 << uint(stage)})
		fork := emit(sseSeqOp{kind: sseSeqBranch, near: next()&1 != 0})
		for arm := 0; arm < 2; arm++ {
			if arm == 1 {
				p.ops[fork].target = len(p.ops)
			}
			store(sseSeqBits(width, next(), payload()), off)
			emit(sseSeqOp{kind: sseSeqLoad, reg: dst, width: width, offset: off})
			if next()&1 != 0 {
				// Reuse memory written by this arm, without resetting the vector
				// bank or inventing values for the other path.
				emit(sseSeqOp{kind: sseSeqLoad, reg: src, width: width, offset: off})
			}
			if arm == 0 {
				emit(sseSeqOp{kind: sseSeqJump, target: -1})
			}
		}
		for j := fork + 1; j < p.ops[fork].target; j++ {
			if p.ops[j].kind == sseSeqJump {
				p.ops[j].target = len(p.ops)
			}
		}
		p.cuts = append(p.cuts, len(p.ops))
		emit(sseSeqOp{kind: sseSeqCompare, reg: dst, other: src, width: width})
		if next()&1 != 0 {
			emit(sseSeqOp{kind: sseSeqImmediate, reg: int(RAX), width: 8, value: uint64(next())})
			emit(sseSeqOp{kind: sseSeqTest, reg: int(RAX), value: uint64(next())})
		}
		parity := emit(sseSeqOp{kind: sseSeqBranch, condition: 1 + next()%2, near: next()&1 != 0})
		emit(sseSeqOp{kind: sseSeqImmediate, reg: int(RBX), width: 32, value: 100 + uint64(stage)})
		skip := emit(sseSeqOp{kind: sseSeqJump})
		p.ops[parity].target = len(p.ops)
		emit(sseSeqOp{kind: sseSeqImmediate, reg: int(RBX), width: 32, value: 200 + uint64(stage)})
		p.ops[skip].target = len(p.ops)
		emit(sseSeqOp{kind: sseSeqStore, reg: int(RBX), offset: 56})
		if next()&1 != 0 {
			call := emit(sseSeqOp{kind: sseSeqCall})
			skip := emit(sseSeqOp{kind: sseSeqJump})
			p.ops[call].target = len(p.ops)
			p.cuts = append(p.cuts, len(p.ops)) // common cut inside the active callee
			body := emit(sseSeqOp{kind: sseSeqLoad, reg: bank + int(next()%4), width: width, offset: off + 8})
			p.ops[body].owner = call
			ret := emit(sseSeqOp{kind: sseSeqReturn, target: call + 1})
			p.ops[ret].owner = call
			p.ops[skip].target = len(p.ops)
		}
		p.cuts = append(p.cuts, len(p.ops))
	}
	return p
}

func (p *sseSeqProgram) encode() {
	p.pcs = make([]uint64, len(p.ops)+1)
	encode := func(o sseSeqOp) []byte {
		switch o.kind {
		case sseSeqImmediate:
			if o.width == 64 {
				return binary.LittleEndian.AppendUint64([]byte{0x48, 0xb8}, o.value)
			}
			if o.width == 8 {
				return []byte{0xb0, byte(o.value)}
			}
			return binary.LittleEndian.AppendUint32([]byte{0xbb}, uint32(o.value))
		case sseSeqStore:
			return []byte{0x48, 0x89, 0x44 | byte(o.reg)<<3, 0x24, byte(o.offset)}
		case sseSeqLoad:
			return sseIntegrationLoad(o.width, o.reg, o.offset)
		case sseSeqCompare:
			return sseIntegrationCompare(o.width, o.reg, o.other)
		case sseSeqTest:
			return []byte{0xf6, 0xc0 | byte(o.reg), byte(o.value)}
		case sseSeqBranch:
			form := to.JccShort
			if o.near {
				form = to.JccNear
			}
			encoded, err := to.Encode(to.Intent{Operation: to.Branch, Condition: []uint8{4, 10, 11}[o.condition]}, to.Encoding{Form: form})
			if err != nil {
				panic(err)
			}
			return encoded
		case sseSeqJump:
			return []byte{0xe9, 0, 0, 0, 0}
		case sseSeqCall:
			return []byte{0xe8, 0, 0, 0, 0}
		case sseSeqReturn:
			return []byte{0xc3}
		}
		panic("unsupported SSE sequence intent")
	}
	for j, o := range p.ops {
		p.pcs[j] = testEntry + uint64(len(p.code))
		p.code = append(p.code, encode(o)...)
	}
	p.pcs[len(p.ops)] = testEntry + uint64(len(p.code))
	for j, o := range p.ops {
		if o.kind != sseSeqBranch && o.kind != sseSeqJump && o.kind != sseSeqCall {
			continue
		}
		delta := int64(p.pcs[o.target]) - int64(p.pcs[j+1])
		end := int(p.pcs[j+1] - testEntry)
		if o.kind == sseSeqBranch && !o.near {
			if delta < -128 || delta > 127 {
				panic("fixture short branch overflow")
			}
			p.code[end-1] = byte(int8(delta))
		} else {
			binary.LittleEndian.PutUint32(p.code[end-4:end], uint32(int32(delta)))
		}
	}
}

func (p sseSeqProgram) activation(j int) TransitionActivationID {
	if p.ops[j].owner < 0 {
		return 0
	}
	return TransitionActivationID(p.ops[j].owner + 1)
}

func (p sseSeqProgram) inventory(cut int) (map[int]bool, []TransitionExpansion) {
	seen := map[int]bool{}
	work := []int{0}
	var expansions []TransitionExpansion
	for len(work) > 0 {
		j := work[len(work)-1]
		work = work[:len(work)-1]
		if j == cut || seen[j] {
			continue
		}
		seen[j] = true
		o := p.ops[j]
		if o.kind == sseSeqLoad || o.kind == sseSeqCompare || o.kind == sseSeqTest || o.kind == sseSeqCall {
			expansions = append(expansions, TransitionExpansion{PC: p.pcs[j], AllActivations: true})
		}
		switch o.kind {
		case sseSeqBranch:
			work = append(work, j+1, o.target)
		case sseSeqJump, sseSeqCall, sseSeqReturn:
			work = append(work, o.target)
		default:
			work = append(work, j+1)
		}
	}
	return seen, expansions
}

type sseSeqAccess struct {
	pc         uint64
	activation TransitionActivationID
	kind       AccessKind
	offset     int64
	width      int
	value      uint64
}

func (p sseSeqProgram) proposal(digest [32]byte, cut int) TransitionProposal {
	seen, choices := p.inventory(cut)
	seen[cut] = true
	expanded := map[uint64]bool{}
	for _, e := range choices {
		expanded[e.PC] = true
	}
	q := TransitionProposal{ImageDigest: digest, Entry: p.pcs[0], Cut: p.pcs[cut], Root: 1}
	for j := 0; j <= len(p.ops); j++ {
		if !seen[j] {
			continue
		}
		n := TransitionNode{ID: TransitionOccurrenceID(j + 1), PC: p.pcs[j], Size: 5}
		if j < len(p.ops) {
			n.Size = uint8(p.pcs[j+1] - p.pcs[j])
		}
		if j != cut {
			n.Expanded = expanded[n.PC]
			o := p.ops[j]
			switch o.kind {
			case sseSeqBranch:
				n.Successors = []TransitionOccurrenceID{TransitionOccurrenceID(j + 2), TransitionOccurrenceID(o.target + 1)}
			case sseSeqJump, sseSeqCall, sseSeqReturn:
				n.Successors = []TransitionOccurrenceID{TransitionOccurrenceID(o.target + 1)}
			default:
				n.Successors = []TransitionOccurrenceID{TransitionOccurrenceID(j + 2)}
			}
		}
		q.Nodes = append(q.Nodes, n)
	}
	return q
}

type sseSeqState struct {
	regs     [16]uint64
	vectors  [16][2]uint64
	memory   map[int64]byte
	flags    [6]bool // CF, OF, SF, ZF, AF, PF
	defined  [6]bool
	trace    []int
	accesses []sseSeqAccess
	base     uint64
}
type sseSeqCoverage struct {
	compareWidth    [2]bool
	width           [2]bool
	result          [4]bool // unordered, less, equal, greater
	fork, parity    [2]bool
	condition       [3]bool
	encoding        [2]bool
	call, overwrite bool
	partitions      [3]bool // single suffix, multiple suffixes, active-callee cut
}

func sseSeqInitial(b TransitionBound, branches uint64) (sseSeqState, map[br.Term]uint64) {
	r := sseSeqState{memory: map[int64]byte{}, base: 0x100000000}
	v := map[br.Term]uint64{}
	for j, term := range b.InitialRegisters {
		r.regs[j] = 0xfeed000000000000 + uint64(j)*257 + branches
		v[term] = r.regs[j]
	}
	r.regs[RSP], r.regs[RDX] = r.base, branches
	v[b.Origin], v[b.InitialRegisters[RDX]] = r.base, branches
	for j, x := range b.InitialVectors {
		r.vectors[j] = [2]uint64{0x1234000000000001 + uint64(j)*71 + branches, 0xfedc000000000003 + uint64(j)*97 + branches}
		v[x.Lo], v[x.Hi] = r.vectors[j][0], r.vectors[j][1]
	}
	for _, cell := range b.InitialMemory {
		r.memory[cell.Offset] = byte(uint64(cell.Offset)*37 + branches)
		v[cell.Value] = uint64(r.memory[cell.Offset])
	}
	for _, term := range []br.Term{b.InitialPredicates.CF, b.InitialPredicates.ZF, b.InitialPredicates.SFXorOF} {
		v[term] = 0
	}
	for j := range r.defined {
		r.defined[j] = true
	}
	return r, v
}

func (p sseSeqProgram) execute(t testing.TB, r sseSeqState, cut int, coverage *sseSeqCoverage) sseSeqState {
	t.Helper()
	access := func(j int, kind AccessKind, off int64, width int, value uint64) uint64 {
		if kind == FrameWrite {
			for k := 0; k < width; k++ {
				r.memory[off+int64(k)] = byte(value >> uint(8*k))
			}
		} else {
			value = 0
			for k := 0; k < width; k++ {
				value |= uint64(r.memory[off+int64(k)]) << uint(8*k)
			}
		}
		r.accesses = append(r.accesses, sseSeqAccess{p.pcs[j], p.activation(j), kind, off, width, value})
		return value
	}
	for j, steps := 0, 0; j != cut; steps++ {
		if steps > len(p.ops) {
			t.Fatal("generated intent did not reach common cut")
		}
		o := p.ops[j]
		r.trace = append(r.trace, j)
		next := j + 1
		switch o.kind {
		case sseSeqImmediate:
			if o.width == 8 {
				r.regs[o.reg] = r.regs[o.reg]&^255 | o.value
			} else {
				r.regs[o.reg] = o.value
			}
		case sseSeqStore:
			access(j, FrameWrite, int64(r.regs[RSP]-r.base)+int64(o.offset), 8, r.regs[o.reg])
		case sseSeqLoad:
			v := access(j, FrameRead, int64(r.regs[RSP]-r.base)+int64(o.offset), o.width/8, 0)
			r.vectors[o.reg] = [2]uint64{v, 0}
			coverage.width[o.width/32-1] = true
		case sseSeqCompare:
			coverage.compareWidth[o.width/32-1] = true
			decode := func(v uint64) float64 {
				if o.width == 32 {
					return float64(math.Float32frombits(uint32(v)))
				}
				return math.Float64frombits(v)
			}
			a, b := decode(r.vectors[o.reg][0]), decode(r.vectors[o.other][0])
			unordered := math.IsNaN(a) || math.IsNaN(b)
			r.flags = [6]bool{unordered || a < b, false, false, unordered || a == b, false, unordered}
			for k := range r.defined {
				r.defined[k] = true
			}
			outcome := 3
			if unordered {
				outcome = 0
			} else if a < b {
				outcome = 1
			} else if a == b {
				outcome = 2
			}
			coverage.result[outcome] = true
		case sseSeqTest:
			v := byte(r.regs[o.reg]) & byte(o.value)
			r.flags = [6]bool{false, false, v&128 != 0, v == 0, false, bits.OnesCount8(v)%2 == 0}
			r.defined = [6]bool{true, true, true, true, false, true}
			if o.reg == int(RAX) {
				coverage.overwrite = true
			}
		case sseSeqBranch:
			taken := r.flags[3]
			if o.condition == 1 {
				taken = r.flags[5]
			} else if o.condition == 2 {
				taken = !r.flags[5]
			}
			index := 0
			if taken {
				index = 1
				next = o.target
			}
			if o.condition == 0 {
				coverage.fork[index] = true
			} else {
				coverage.parity[index] = true
			}
			coverage.condition[o.condition] = true
			encoding := 0
			if o.near {
				encoding = 1
			}
			coverage.encoding[encoding] = true
		case sseSeqJump:
			next = o.target
		case sseSeqCall:
			coverage.call = true
			r.regs[RSP] -= 8
			access(j, FrameWrite, int64(r.regs[RSP]-r.base), 8, p.pcs[j+1])
			next = o.target
		case sseSeqReturn:
			v := access(j, FrameReturnRead, int64(r.regs[RSP]-r.base), 8, 0)
			if v != p.pcs[o.target] {
				t.Fatal("intent return word corrupted")
			}
			r.regs[RSP] += 8
			next = o.target
		}
		j = next
	}
	return r
}

func sseSeqAssert(t testing.TB, p sseSeqProgram, b TransitionBound, cut int, branches uint64, coverage *sseSeqCoverage) {
	t.Helper()
	_ = sseIntegrationValues(t, b) // check all original lane identities and sorts
	r, values := sseSeqInitial(b, branches)
	r = p.execute(t, r, cut, coverage)
	eval := func(term br.Term) uint64 { return evalRelationTerm(t, term, values, 0) }
	if b.Interface.Conditions.SSE != SSEModel || !b.SSE.MXCSRPreserved || !b.SSE.UpperVectorsPreserved || eval(b.CutGuard) != 1 {
		t.Fatal("lost complete-cut or SSE context")
	}
	for j, v := range b.Vectors {
		if v.Lo.Sort() != br.Bits(64) || v.Hi.Sort() != br.Bits(64) || eval(v.Lo) != r.vectors[j][0] || eval(v.Hi) != r.vectors[j][1] {
			t.Fatalf("cut%d branch%d XMM%d differs", cut, branches, j)
		}
	}
	for j, v := range b.Registers {
		if eval(v.Value) != r.regs[j] {
			t.Fatalf("cut%d branch%d GPR%d differs", cut, branches, j)
		}
	}
	for _, cell := range b.Memory {
		if eval(cell.Value) != uint64(r.memory[cell.Offset]) || cell.Pointer != nil {
			t.Fatal("current byte memory differs")
		}
	}
	if len(b.Memory) != len(r.memory) {
		t.Fatal("memory inventory differs")
	}
	flags := []TransitionFlag{b.Flags.CF, b.Flags.OF, b.Flags.SF, b.Flags.ZF, b.Flags.AF, b.Flags.PF}
	// The initialization cut precedes the first flag writer. All later cuts
	// follow an actual byte TEST or UCOMI and must expose precisely those flags.
	if cut > p.cuts[0] {
		for j, f := range flags {
			if f.Defined != r.defined[j] || f.Preserved {
				t.Fatal("flag definedness/preservation differs")
			}
			if f.Defined && (f.Value.Sort() != br.Bool() || (eval(f.Value) == 1) != r.flags[j]) {
				t.Fatal("current flag value differs")
			}
		}
	}
	expected, _ := p.inventory(cut)
	written := map[int]bool{}
	wantAccesses := map[transitionTestPoint]sseSeqAccess{}
	for j := range expected {
		o := p.ops[j]
		if o.kind == sseSeqImmediate {
			written[o.reg] = true
		}
		if o.kind == sseSeqCall || o.kind == sseSeqReturn {
			written[int(RSP)] = true
		}
		a := sseSeqAccess{pc: p.pcs[j], activation: p.activation(j), offset: int64(o.offset), width: 8}
		switch o.kind {
		case sseSeqStore:
			a.kind = FrameWrite
		case sseSeqLoad:
			a.kind, a.width = FrameRead, o.width/8
			if o.owner >= 0 {
				a.offset -= 8
			}
		case sseSeqCall:
			a.kind, a.offset = FrameWrite, -8
		case sseSeqReturn:
			a.kind, a.offset = FrameReturnRead, -8
		default:
			continue
		}
		wantAccesses[transitionTestPoint{a.pc, a.activation}] = a
	}
	for j, reg := range b.Registers {
		preserved := ^uint64(0)
		if written[j] {
			preserved = 0
		}
		if b.Preserved[j] != preserved {
			t.Fatal("GPR preservation mask differs")
		}
		if j == int(RSP) {
			if reg.Pointer != (OriginPointer{Origin: b.Origin, Offset: int64(r.regs[j] - r.base)}) {
				t.Fatal("stack scalar/provenance differs")
			}
		} else if reg.Pointer != nil {
			t.Fatal("scalar register acquired pointer provenance")
		}
	}
	if len(b.Instructions) != len(expected) {
		t.Fatal("extra or omitted instruction occurrences")
	}
	active := map[transitionTestPoint]bool{}
	var trace []int
	for _, ins := range b.Instructions {
		j, ok := slices.BinarySearch(p.pcs, ins.Start)
		if !ok || !expected[j] || ins.End != p.pcs[j+1] || ins.Context != p.activation(j) {
			t.Fatal("instruction occurrence differs from intent")
		}
		delete(expected, j)
		if eval(ins.Guard) == 1 {
			trace = append(trace, j)
			active[transitionTestPoint{ins.Start, ins.Context}] = true
		}
	}
	if !slices.Equal(trace, r.trace) {
		t.Fatal("filtered instruction order differs")
	}
	var accesses []sseSeqAccess
	if len(b.Accesses) != len(wantAccesses) {
		t.Fatal("extra or omitted access occurrences")
	}
	for _, a := range b.Accesses {
		key := transitionTestPoint{a.PC, a.Context}
		want, ok := wantAccesses[key]
		if !ok || a.Image || a.Kind != want.kind || a.Bytes.Start != want.offset || a.Bytes.End != want.offset+int64(want.width) || a.Value.Sort() != br.Bits(want.width*8) {
			t.Fatal("access occurrence differs from intent")
		}
		delete(wantAccesses, key)
		if active[transitionTestPoint{a.PC, a.Context}] {
			accesses = append(accesses, sseSeqAccess{a.PC, a.Context, a.Kind, a.Bytes.Start, int(a.Bytes.End - a.Bytes.Start), eval(a.Value)})
		}
	}
	if !slices.Equal(accesses, r.accesses) || len(b.PrimitiveEffects) != 0 {
		t.Fatal("ordered memory/primitive effects differ")
	}
	wantFrames := 0
	if cut < len(p.ops) && p.ops[cut].owner >= 0 {
		wantFrames = 1
	}
	if len(b.Frames) != wantFrames {
		t.Fatal("active call context differs")
	}
}

func sseSeqCheck(t testing.TB, data []byte, coverage *sseSeqCoverage) {
	t.Helper()
	p := sseSeqGenerate(data)
	p.encode()
	face := sseIntegrationFace()
	face.Conditions.SSE = SSEModel
	im := image(t, append(append([]byte{}, p.code...), 0xbb, 0, 0, 0, 0))
	limits := TransitionLimits{RelationLimits: RelationLimits{Nodes: 131072, Work: 8_000_000, Depth: 512}}
	proposal := func(cut int) TransitionProposal {
		_, choices := p.inventory(cut)
		q, err := ProposeTransition(t.Context(), im, p.pcs[cut], limits, TransitionOptions{Expansions: choices})
		if err != nil {
			t.Fatal(err)
		}
		independent := p.proposal(im.digest, cut)
		stateSameContextInventory(t, q, independent)
		return independent
	}
	final := len(p.ops)
	direct, err := CheckTransition(t.Context(), im, face, proposal(final), limits)
	if err != nil {
		t.Fatal(err)
	}
	bound, _ := direct.Bound()
	for branch := uint64(0); branch < 1<<uint(p.stages); branch++ {
		sseSeqAssert(t, p, bound, final, branch, coverage)
	}
	// Distinct partition shapes depend on input, and every selected cut is a
	// common boundary, including optional cuts inside an active callee.
	selector := byte(0)
	if len(data) > 1 {
		selector = data[1]
	}
	cuts := []int{p.cuts[0]}
	for j, cut := range p.cuts[1:] {
		if cut != final && selector&(1<<uint(j%8)) != 0 {
			cuts = append(cuts, cut)
		}
	}
	cuts = append(cuts, final)
	coverage.partitions[0] = coverage.partitions[0] || len(cuts) == 2
	coverage.partitions[1] = coverage.partitions[1] || len(cuts) > 2
	var current TransitionCertificate
	var initial TransitionBound
	for j, cut := range cuts {
		if j == 0 {
			current, err = CheckTransition(t.Context(), im, face, proposal(cut), limits)
		} else {
			current, err = CheckTransitionContinuation(t.Context(), current, proposal(cut))
		}
		if err != nil {
			t.Fatalf("partition %v cut%d: %v", cuts, cut, err)
		}
		b, _ := current.Bound()
		if j == 0 {
			initial = b
		} else if b.InitialVectors != initial.InitialVectors || b.InitialRegisters != initial.InitialRegisters || b.InitialPredicates != initial.InitialPredicates || b.SSE != initial.SSE {
			t.Fatal("partition restarted entry identities/context")
		}
		if cut < final && p.ops[cut].owner >= 0 {
			coverage.partitions[2] = true
		}
		for branch := uint64(0); branch < 1<<uint(p.stages); branch++ {
			sseSeqAssert(t, p, b, cut, branch, coverage)
		}
	}
}

func TestTransitionSSEEvolvingSequences(t *testing.T) {
	var coverage sseSeqCoverage
	for seed := int64(0); seed < 16; seed++ {
		data := make([]byte, 160)
		_, _ = rand.New(rand.NewSource(seed)).Read(data)
		data[0] = byte(seed % 4)
		if seed%2 == 0 {
			data[1] = 0
		} else {
			data[1] = 255
		}
		t.Run(fmt.Sprint(seed), func(t *testing.T) { sseSeqCheck(t, data, &coverage) })
	}
	for _, group := range [][]bool{coverage.width[:], coverage.compareWidth[:], coverage.result[:], coverage.fork[:], coverage.parity[:], coverage.condition[:], coverage.encoding[:], coverage.partitions[:], {coverage.call, coverage.overwrite}} {
		for _, hit := range group {
			if !hit {
				t.Fatalf("generated population missed required dimension: %+v", coverage)
			}
		}
	}
}

func FuzzTransitionSSEEvolvingSequences(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{255})
	for seed := int64(0); seed < 4; seed++ {
		data := make([]byte, 160)
		_, _ = rand.New(rand.NewSource(seed)).Read(data)
		data[0], data[1] = byte(seed), 255
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 512 {
			data = data[:512]
		}
		sseSeqCheck(t, data, &sseSeqCoverage{})
	})
}

func TestTransitionSSEEvolvingRefusals(t *testing.T) {
	p := sseSeqGenerate([]byte{1, 255, 2, 3, 4, 5, 6, 7})
	p.encode()
	face := sseIntegrationFace()
	face.Conditions.SSE = SSEModel
	im := image(t, append(append([]byte{}, p.code...), 0xbb, 0, 0, 0, 0))
	_, choices := p.inventory(len(p.ops))
	q, err := ProposeTransition(t.Context(), im, p.pcs[len(p.ops)], TransitionLimits{}, TransitionOptions{Expansions: choices})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckTransition(t.Context(), im, face, q, TransitionLimits{}); err != nil {
		t.Fatal("refusal controls need an accepted baseline", err)
	}
	// Inventory controls cannot ignore an extra occurrence or a missing transfer.
	for _, extra := range []bool{false, true} {
		bad := q
		bad.Nodes = slices.Clone(q.Nodes)
		if extra {
			bad.Nodes = append(bad.Nodes, bad.Nodes[0])
		} else {
			bad.Nodes = bad.Nodes[1:]
		}
		c, err := CheckTransition(t.Context(), im, face, bad, TransitionLimits{})
		transitionRefused(t, c, err)
	}
	for _, l := range []TransitionLimits{{RelationLimits: RelationLimits{Work: 1}}, {RelationLimits: RelationLimits{Nodes: 1}}, {LiveStateBytes: 1}} {
		c, err := CheckTransition(t.Context(), im, face, q, l)
		transitionRefused(t, c, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c, err := CheckTransition(ctx, im, face, q, TransitionLimits{})
	transitionRefused(t, c, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("root cancellation was replaced by another refusal", err)
	}
	_, prefixChoices := p.inventory(p.cuts[0])
	pre, err := ProposeTransition(t.Context(), im, p.pcs[p.cuts[0]], TransitionLimits{}, TransitionOptions{Expansions: prefixChoices})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := CheckTransition(t.Context(), im, face, pre, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err = CheckTransitionContinuation(ctx, parent, q)
	transitionRefused(t, c, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("continuation cancellation was replaced by another refusal", err)
	}
	// Reconstruct the same prefix with only sixteen cumulative work ticks left;
	// continuation must not restart that budget while importing vector state.
	limited, err := CheckTransition(t.Context(), im, face, pre, TransitionLimits{RelationLimits: RelationLimits{Work: parent.checked.work + 16}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = CheckTransitionContinuation(t.Context(), limited, q)
	transitionRefused(t, c, err)
	var budget *Refusal
	if !errors.As(err, &budget) || !strings.Contains(budget.Premise, "budget") {
		t.Fatal("cumulative budget failed for unrelated reason", err)
	}
	// The same load/compare vocabulary must refuse signaling NaNs/subnormals.
	// No normal-path assumption may rescue even a self-comparison.
	for _, width := range []int{32, 64} {
		for _, bad := range []uint64{1, 0x7ff000007f800001} {
			code := sseIntegrationStore(bad, 8)
			code = append(code, sseIntegrationLoad(width, 3, 8)...)
			code = append(code, sseIntegrationCompare(width, 3, 3)...)
			c, err := sseIntegrationCheck(t, code, face)
			transitionRefused(t, c, err)
			var excluded *Refusal
			if !errors.As(err, &excluded) || excluded.Premise != "transition-sse-operands" {
				t.Fatal("exceptional operand failed for unrelated reason", err)
			}
		}
	}
}

func TestTransitionParityOracleConditions(t *testing.T) {
	// The preexisting scalar oracle orders flags CF,ZF,OF,SF,AF,PF. Exercise
	// every combination so JP/JNP cannot accidentally consume SF, AF or ZF.
	for raw := 0; raw < 64; raw++ {
		var flags [6]bool
		for j := range flags {
			flags[j] = raw&(1<<uint(j)) != 0
		}
		if dagCondition(t, 10, flags) != (raw&32 != 0) || dagCondition(t, 11, flags) != (raw&32 == 0) {
			t.Fatal("independent parity condition uses wrong flag index")
		}
	}
	for _, cc := range []uint8{10, 11} {
		for _, displacement := range []int64{-128, -1, 0, 127} {
			for _, form := range []to.Form{to.JccShort, to.JccNear} {
				i := to.Intent{Operation: to.Branch, Condition: cc, SignedDisp: displacement}
				encoded, err := to.Encode(i, to.Encoding{Form: form})
				if err != nil {
					t.Fatal(err)
				}
				d, err := to.Parse(encoded, 1<<40)
				if err != nil || d.Intent != i || d.Target != uint64(int64(1<<40)+int64(len(encoded))+displacement) {
					t.Fatal("independent JP/JNP branch encoding/target differs", err)
				}
				compareExecutedEncoding(t, encoded)
			}
		}
		// Decoder admission does not bind an arbitrary entry PF. The existing
		// three scalar entry predicates remain exactly CF,ZF,SF!=OF.
		c, err := sseIntegrationCheck(t, sseIntegrationParityDiamond(0x70+cc, false), sseIntegrationFace())
		transitionRefused(t, c, err)
	}
}
