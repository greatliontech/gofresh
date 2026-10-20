package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// This grammar's bound is three iterations, established by its actual selector
// branches and MOVs before INC/CMP/Jcc. The execution fuel below is only an oracle
// abort condition. It supplies neither a checker premise nor a termination proof.
// Semantic answers use the existing concrete ISA interpreter, never a native
// decoder, proposal, certificate, or symbolic transfer helper.
const occurrenceOracleMaximum = 3

type occurrenceOraclePlacement uint8

const (
	occurrenceOracleLocal occurrenceOraclePlacement = iota
	occurrenceOracleChildLoop
	occurrenceOracleParentLoop
	occurrenceOracleNested
)

type occurrenceOraclePayload uint8

const (
	occurrenceOracleCAS occurrenceOraclePayload = iota
	occurrenceOracleByte
	occurrenceOracleQuery
	occurrenceOracleMixed
)

// Supplemental query shapes are separate from the core placement/payload/layout
// population. They do not enlarge its declared 18 shapes or 144 valuations.
type occurrenceOracleVariant uint8

const (
	occurrenceOracleCore occurrenceOracleVariant = iota
	occurrenceOracleEarlyQuery
	occurrenceOracleResetQuery
)

const occurrenceOracleFixedLeaf, occurrenceOracleFixedSubleaf = 0x12, 0x34

type occurrenceOracleOp struct {
	intent      to.Intent
	next, taken int
	name        string
}

type occurrenceOracleProgram struct {
	ops       []occurrenceOracleOp
	pcs       []uint64
	encoded   [][]byte
	code      []byte
	face      TransitionInterface
	placement occurrenceOraclePlacement
	payload   occurrenceOraclePayload
	variant   occurrenceOracleVariant
	maximum   int
	entry     int
	boundary  int
	// Logical instruction indices, not decoded address/context coordinates.
	outerHeader, childHeader, body, call, rootReturn, earlyExit int
}

type occurrenceOracleBuilder struct {
	ops     []occurrenceOracleOp
	variant occurrenceOracleVariant
}

func (b *occurrenceOracleBuilder) emit(name string, i to.Intent) int {
	j := len(b.ops)
	b.ops = append(b.ops, occurrenceOracleOp{i, j + 1, -1, name})
	return j
}

func (b *occurrenceOracleBuilder) move(name string, reg uint8, value uint64) int {
	return b.emit(name, to.Intent{Operation: to.MoveImmediate32, Dst: reg, Immediate: value})
}

func (b *occurrenceOracleBuilder) jump(name string, target int) int {
	j := b.emit(name, to.Intent{Operation: to.Jump})
	b.ops[j].next = target
	return j
}

// Values 0,1,2 select zero, one, two iterations; every other full-width input
// selects the maximum. This is executable domain restriction, not input repair.
func (b *occurrenceOracleBuilder) selectStart(counter uint8, maximum int) {
	var jumps []int
	for n := 0; n < maximum; n++ {
		b.emit("selector-compare", to.Intent{Operation: to.CompareImmediate, Dst: uint8(RSI), Immediate: uint64(n)})
		branch := b.emit("selector-branch", to.Intent{Operation: to.Branch, Condition: 5})
		b.move("selected-start", counter, uint64(maximum-n))
		jumps = append(jumps, b.jump("selector-join", -1))
		b.ops[branch].taken = len(b.ops)
	}
	b.move("default-start", counter, 0)
	for _, j := range jumps {
		b.ops[j].next = len(b.ops)
	}
}

func (b *occurrenceOracleBuilder) prologue(root bool) {
	if root {
		b.emit("anchor", to.Intent{Operation: to.MoveRegister, Dst: uint8(R14), Src: uint8(RSP)})
	} else {
		// The caller's 24-byte frame and actual CALL place the child origin
		// 32 bytes below the root. Derive the data anchor in the child too,
		// so a standalone child theorem needs no invented incoming pointer.
		b.emit("child-anchor", to.Intent{Operation: to.LEA, Dst: uint8(R14), Base: uint8(RSP), SignedDisp: 32})
	}
	b.emit("save-bp", to.Intent{Operation: to.Push, Dst: uint8(RBP)})
	b.emit("allocate", to.Intent{Operation: to.Subtract, Dst: uint8(RSP), Immediate: 16})
}

func (b *occurrenceOracleBuilder) epilogue() int {
	b.emit("deallocate", to.Intent{Operation: to.Add, Dst: uint8(RSP), Immediate: 16})
	b.emit("restore-bp", to.Intent{Operation: to.Pop, Dst: uint8(RBP)})
	return b.emit("return", to.Intent{Operation: to.Return})
}

func (b *occurrenceOracleBuilder) payload(kind occurrenceOraclePayload) int {
	first := len(b.ops)
	// Read the previous iteration/invocation's scratch before replacing it.
	b.emit("old-scratch", to.Intent{Operation: to.Load, Dst: uint8(R10), Base: uint8(RSP)})
	if kind == occurrenceOracleQuery || kind == occurrenceOracleMixed {
		if b.variant == occurrenceOracleResetQuery {
			b.move("reset-leaf", uint8(RAX), occurrenceOracleFixedLeaf)
			b.move("reset-subleaf", uint8(RCX), occurrenceOracleFixedSubleaf)
		}
		b.emit("query", to.Intent{Operation: to.CPUID})
	}
	if kind == occurrenceOracleCAS || kind == occurrenceOracleMixed {
		b.emit("cas32", to.Intent{Operation: to.LockedCompareExchange, Width: 32, Base: uint8(R14), Src: uint8(RDX), SignedDisp: 16})
	}
	if kind == occurrenceOracleByte {
		b.emit("byte-or", to.Intent{Operation: to.LockedOr, Width: 8, Base: uint8(R14), Src: uint8(RDX), SignedDisp: 17})
		b.emit("byte-and", to.Intent{Operation: to.LockedAndImmediate, Width: 8, Base: uint8(R14), Immediate: 0x7f, SignedDisp: 17})
		b.emit("unchanged-or", to.Intent{Operation: to.LockedOrImmediate, Width: 8, Base: uint8(R14), SignedDisp: 17})
		b.emit("unchanged-and", to.Intent{Operation: to.LockedAndImmediate, Width: 8, Base: uint8(R14), Immediate: 255, SignedDisp: 17})
	}
	b.emit("new-scratch", to.Intent{Operation: to.Store, Base: uint8(RSP), Src: uint8(RAX)})
	return first
}

func (b *occurrenceOracleBuilder) diamond(counter uint8) {
	b.emit("diamond-compare", to.Intent{Operation: to.CompareImmediate, Dst: counter, Immediate: 2})
	fork := b.emit("diamond-branch", to.Intent{Operation: to.Branch, Condition: 3})
	b.move("short-arm", uint8(R8), 0x17)
	join := b.jump("diamond-join", -1)
	b.ops[fork].taken = len(b.ops)
	b.move("long-arm", uint8(R8), 0x29)
	b.move("long-arm-extra", uint8(R11), 0x31)
	b.ops[join].next = len(b.ops)
}

func occurrenceOracleBuild(t testing.TB, placement occurrenceOraclePlacement, payload occurrenceOraclePayload, layout, maximum int) occurrenceOracleProgram {
	t.Helper()
	return occurrenceOracleBuildVariant(t, placement, payload, layout, maximum, occurrenceOracleCore)
}

func occurrenceOracleBuildVariant(t testing.TB, placement occurrenceOraclePlacement, payload occurrenceOraclePayload, layout, maximum int, variant occurrenceOracleVariant) occurrenceOracleProgram {
	t.Helper()
	if maximum < 0 || maximum > occurrenceOracleMaximum {
		t.Fatal("oracle grammar maximum outside declared domain")
	}
	if placement == occurrenceOracleNested && maximum < 2 {
		t.Fatal("two-by-two nested grammar needs at least two iterations")
	}
	if variant > occurrenceOracleResetQuery || variant != occurrenceOracleCore && (placement != occurrenceOracleLocal || payload != occurrenceOracleQuery) {
		t.Fatal("supplemental variant requires the local query grammar")
	}
	p := occurrenceOracleProgram{placement: placement, payload: payload, variant: variant, maximum: maximum, outerHeader: -1, childHeader: -1, body: -1, call: -1, earlyExit: -1}
	b := &occurrenceOracleBuilder{variant: variant}
	b.prologue(true)
	loop := func(counter uint8, child bool, body func()) {
		if placement == occurrenceOracleNested {
			b.move("fixed-two-start", counter, uint64(maximum-2))
		} else {
			b.selectStart(counter, maximum)
		}
		header := b.emit("header", to.Intent{Operation: to.CompareImmediate, Dst: counter, Immediate: uint64(maximum)})
		if child {
			p.childHeader = header
		} else {
			p.outerHeader = header
		}
		exit := b.emit("loop-exit", to.Intent{Operation: to.Branch, Condition: 3})
		body()
		if variant == occurrenceOracleEarlyQuery {
			b.emit("outcome-compare", to.Intent{Operation: to.CompareImmediate, Width: 32, Dst: uint8(RAX)})
			p.earlyExit = b.emit("outcome-exit", to.Intent{Operation: to.Branch, Condition: 4})
		}
		b.diamond(counter)
		b.emit("increment", to.Intent{Operation: to.Increment64, Dst: counter})
		b.jump("backedge", header)
		b.ops[exit].taken = len(b.ops)
		if variant == occurrenceOracleEarlyQuery {
			b.ops[p.earlyExit].taken = len(b.ops)
		}
	}
	call := func() {
		p.call = b.emit("call-child", to.Intent{Operation: to.Call})
		// Child SP = current SP-8; its saved BP and 16-byte frame put scratch
		// at current SP-32. Returning must not erase these concrete bytes.
		b.emit("released-scratch", to.Intent{Operation: to.Load, Dst: uint8(R9), Base: uint8(RSP), SignedDisp: -32})
	}
	switch placement {
	case occurrenceOracleLocal:
		loop(uint8(R12), false, func() { p.body = b.payload(payload) })
	case occurrenceOracleChildLoop:
		call()
	case occurrenceOracleParentLoop, occurrenceOracleNested:
		loop(uint8(R12), false, call)
	default:
		t.Fatal("unknown oracle placement")
	}
	// Primitive history remains observable even after all result GPRs die.
	if payload == occurrenceOracleQuery || payload == occurrenceOracleMixed {
		for _, reg := range []Register{RAX, RBX, RCX, RDX} {
			b.move("erase-result", uint8(reg), 0)
		}
	}
	p.rootReturn = b.epilogue()
	if placement != occurrenceOracleLocal {
		b.ops[p.call].taken = len(b.ops)
		b.prologue(false)
		if placement == occurrenceOracleParentLoop {
			p.body = b.payload(payload)
		} else {
			loop(uint8(R13), true, func() { p.body = b.payload(payload) })
		}
		b.epilogue()
	}
	p.boundary = b.emit("unexecuted-continuation", to.Intent{Operation: to.NoOp})
	p.ops = b.ops
	p.encode(t, layout)
	p.face = TransitionInterface{
		Origin:   OriginDomain{Min: 1 << 40, Max: (1 << 40) + 64, Modulus: 16},
		Envelope: RelativeSpan{-128, 64},
		Regions: []RelativeRegion{
			{Bytes: RelativeSpan{-128, 0}, Readable: true, Writable: true},
			{Bytes: RelativeSpan{0, 8}, Readable: true},
			{Bytes: RelativeSpan{8, 64}, Readable: true, Writable: true},
		},
		Conditions:    interfaceConditions(),
		ReturnContext: &TransitionReturnContext{Target: p.pcs[p.boundary], Preserved: []Register{RBP}},
	}
	p.face.Conditions.CPUID = CPUIDModel
	p.face.Conditions.LockedMemory = LockedMemoryModel
	p.face.Conditions.SSE = SSEModel
	return p
}

func occurrenceOracleEncoding(i to.Intent) to.Encoding {
	switch i.Operation {
	case to.Call:
		return to.Encoding{Form: to.CALLE8}
	case to.Return:
		return to.Encoding{Form: to.RETC3}
	case to.Push:
		return to.Encoding{Form: to.PUSH50}
	case to.Pop:
		return to.Encoding{Form: to.POP58}
	case to.NoOp:
		return to.Encoding{Form: to.NOP90}
	case to.CPUID:
		return to.Encoding{Form: to.CPUID0FA2}
	case to.Add:
		return to.Encoding{Form: to.ADD83, REX: 0x48}
	case to.Branch:
		return to.Encoding{Form: to.JccNear}
	case to.Jump:
		return to.Encoding{Form: to.JMPE9}
	case to.LockedCompareExchange:
		return to.Encoding{Form: to.LOCKCMPXCHG0FB1, REX: 0x41, DispBytes: 1}
	case to.LockedOr:
		return to.Encoding{Form: to.LOCKOR08, REX: 0x41, DispBytes: 1}
	case to.LockedOrImmediate:
		return to.Encoding{Form: to.LOCKOR80, REX: 0x41, DispBytes: 1}
	case to.LockedAndImmediate:
		return to.Encoding{Form: to.LOCKAND80, REX: 0x41, DispBytes: 1}
	default:
		return stateEncoding(i, 0)
	}
}

// Each original instruction gets an explicit delivery JMP. This permits two
// physical layouts without conflating byte position, execution step, and loop
// progress. Encoding uses intent; no parser supplies an operand or successor.
func (p *occurrenceOracleProgram) encode(t testing.TB, layout int) {
	t.Helper()
	original := p.ops
	n := len(original)
	p.ops = make([]occurrenceOracleOp, 2*n)
	p.pcs = make([]uint64, 2*n)
	p.encoded = make([][]byte, 2*n)
	p.code = make([]byte, 32*n)
	for j := range p.code {
		p.code[j] = 0xcc
	}
	for j, op := range original {
		slot := j
		if layout&1 != 0 {
			slot = n - 1 - j
		}
		p.pcs[2*j] = testEntry + uint64(slot*32)
		p.ops[2*j] = op
		p.ops[2*j].next = 2*j + 1
		p.ops[2*j].taken = 2 * op.taken
		p.ops[2*j+1] = occurrenceOracleOp{intent: to.Intent{Operation: to.Jump}, next: 2 * op.next, taken: -1, name: "delivery"}
		if op.intent.Operation == to.Jump {
			p.ops[2*j].next = 2 * op.next
		}
	}
	for j := range original {
		at := 2 * j
		i := p.ops[at].intent
		e := occurrenceOracleEncoding(i)
		bytes, err := to.Encode(i, e)
		if err != nil {
			t.Fatalf("encode %s: %v", p.ops[at].name, err)
		}
		p.pcs[at+1] = p.pcs[at] + uint64(len(bytes))
		if i.Operation == to.Call || i.Operation == to.Branch || i.Operation == to.Jump {
			target := p.ops[at].taken
			if i.Operation == to.Jump {
				target = p.ops[at].next
			}
			i.SignedDisp = int64(p.pcs[target]) - int64(p.pcs[at+1])
			bytes, err = to.Encode(i, e)
			if err != nil {
				t.Fatal(err)
			}
		}
		p.ops[at].intent, p.encoded[at] = i, bytes
		off := int(p.pcs[at] - testEntry)
		copy(p.code[off:], bytes)
		if p.ops[at+1].next < len(p.ops) {
			jump := to.Intent{Operation: to.Jump, SignedDisp: int64(p.pcs[p.ops[at+1].next]) - int64(p.pcs[at+1]+5)}
			p.ops[at+1].intent = jump
			p.encoded[at+1], err = to.Encode(jump, to.Encoding{Form: to.JMPE9})
			if err != nil {
				t.Fatal(err)
			}
			copy(p.code[off+len(bytes):], p.encoded[at+1])
		}
	}
	for _, index := range []*int{&p.entry, &p.boundary, &p.outerHeader, &p.childHeader, &p.body, &p.call, &p.rootReturn, &p.earlyExit} {
		if *index >= 0 {
			*index *= 2
		}
	}
}

type occurrenceOracleInput struct {
	state   stateReference
	vectors [16][2]uint64
}

func occurrenceOracleInitial(p occurrenceOracleProgram, selector uint64, variant int) occurrenceOracleInput {
	// Independent bytes span every GPR, declared memory byte, and vector lane.
	// Formula-generated population values are supplemented by callers replacing
	// these arrays directly; none are recovered from symbolic projections.
	raw := make([]byte, 8+128+1+192)
	for j := range raw {
		raw[j] = byte(j*73 + variant*41 + 19)
	}
	s := stateRawInitial(p.face, raw)
	s.regs[RSI] = selector
	s.regs[RAX] = 0xdeadbeef00000007 + uint64(variant&1)
	s.regs[RDX] = 11
	s.outcomes = make([][4]uint32, 8)
	for j := range s.outcomes {
		for lane := range s.outcomes[j] {
			s.outcomes[j][lane] = uint32(0x80000001) + uint32(j*257+lane*37+variant*19)
		}
	}
	put := func(off int64, width int, value uint64) {
		for lane := 0; lane < width; lane++ {
			s.memory[stateLocation{off: off + int64(lane)}] = stateByte{value: byte(value >> (8 * lane))}
		}
	}
	put(0, 8, p.pcs[p.boundary])
	put(16, 4, 7)
	if p.payload == occurrenceOracleByte {
		put(17, 1, 0x91)
	}
	input := occurrenceOracleInput{state: s}
	for r := range input.vectors {
		input.vectors[r] = [2]uint64{uint64(r+1)*0x123456789abcdef ^ uint64(variant), uint64(r+1)*0xfedcba987654321 ^ uint64(variant+17)}
	}
	return input
}

// These IDs are reference execution coordinates, not proposed evidence IDs.
// The adapter must establish an injective mapping to exact projected IDs before
// using guards. PC/context lookup cannot recover this information in a loop.
type occurrenceOracleFrame struct {
	activation, parent uint64
	call, after        int
	slot               uint64
}

type occurrenceOracleVisit struct {
	id, activation uint64
	instruction    int
	branchSlot     int // -1 for nonbranches; 0 fallthrough, 1 taken
	before, after  [16]uint64
	flags          [6]bool
	defined        [6]bool
	preserved      [6]bool
}

type occurrenceOracleEvent struct {
	occurrence uint64
	kind       string
	index      int // original access/primitive/visit index, never filtered
}

type occurrenceOracleResult struct {
	state        stateReference
	vectors      [16][2]uint64
	visits       []occurrenceOracleVisit
	events       []occurrenceOracleEvent
	activations  []occurrenceOracleFrame
	frames       []occurrenceOracleFrame
	returned     bool
	boundary     occurrenceOracleVisit
	lineage      [16]occurrenceOracleLineage
	lineageBytes map[stateLocation]occurrenceOracleLineage
}

// Caller-value lineage is not address provenance. The concrete ISA helper owns
// all numeric/address semantics; this small companion carries only the declared
// preserved-register token through full-word copies and ordered saved bytes.
type occurrenceOracleLineage struct {
	valid    bool
	register Register
	lane     uint8
}

func (r *occurrenceOracleResult) transferLineage(t testing.TB, i to.Intent, firstAccess int) {
	t.Helper()
	before := r.lineage
	read := occurrenceOracleLineage{}
	for _, access := range r.state.accesses[firstAccess:] {
		if access.write || access.width != 8 {
			continue
		}
		candidate := r.lineageBytes[access.off]
		for lane := uint8(0); lane < 8; lane++ {
			cell := r.lineageBytes[access.off.add(int64(lane))]
			if !cell.valid || cell.register != candidate.register || cell.lane != lane {
				candidate = occurrenceOracleLineage{}
				break
			}
		}
		read = candidate
	}
	for _, access := range r.state.accesses[firstAccess:] {
		if !access.write {
			continue
		}
		source := occurrenceOracleLineage{}
		if access.width == 8 {
			if i.Operation == to.Push {
				source = before[i.Dst]
			} else if i.Operation == to.Store {
				source = before[i.Src]
			}
		}
		for lane := 0; lane < access.width; lane++ {
			key := access.off.add(int64(lane))
			delete(r.lineageBytes, key)
			if source.valid {
				source.lane = uint8(lane)
				r.lineageBytes[key] = source
			}
		}
	}
	switch i.Operation {
	case to.MoveRegister:
		r.lineage[i.Dst] = occurrenceOracleLineage{}
		if i.Width == 0 || i.Width == 64 {
			r.lineage[i.Dst] = before[i.Src]
		}
	case to.Load, to.Pop:
		r.lineage[i.Dst] = occurrenceOracleLineage{}
		if i.Width == 0 || i.Width == 64 {
			r.lineage[i.Dst] = read
		}
	case to.MoveImmediate, to.MoveImmediate32, to.LEA, to.Increment64, to.Add, to.Subtract:
		r.lineage[i.Dst] = occurrenceOracleLineage{}
	case to.CPUID:
		for _, reg := range []Register{RAX, RBX, RCX, RDX} {
			r.lineage[reg] = occurrenceOracleLineage{}
		}
	case to.LockedCompareExchange:
		r.lineage[RAX] = occurrenceOracleLineage{}
	case to.Branch, to.Jump, to.NoOp, to.CompareImmediate, to.Compare,
		to.Store, to.StoreImmediate, to.Push, to.Call, to.Return,
		to.LockedOr, to.LockedAnd, to.LockedOrImmediate, to.LockedAndImmediate:
		// Memory copies/invalidation were handled above; no caller-value token
		// is introduced by these operations. RSP never carries such a token.
	default:
		t.Fatalf("missing reference caller-lineage rule for intent %v", i.Operation)
	}
}

// A reference cut is the encounter of an intent instruction, not a production
// occurrence locator. encounter=1 expresses numeric first-hit semantics; later
// encounters let the adapter distinguish them rather than silently equating PCs.
type occurrenceOracleCut struct{ instruction, encounter int }

var (
	occurrenceOracleFuelError    = errors.New("occurrence reference fuel exhausted")
	occurrenceOracleOutcomeError = errors.New("occurrence reference outcome missing")
	occurrenceOracleReturnError  = errors.New("occurrence reference control word differs")
	occurrenceOracleCutError     = errors.New("occurrence reference cut not encountered")
)

// Fuel is supplied explicitly so malformed reference inputs cannot hang a test.
// Cancellation, exhausted fuel/outcomes and malformed returns return no partial
// positive result. The root RET consumes actual bytes just like a child RET.
func occurrenceOracleRun(t testing.TB, ctx context.Context, p occurrenceOracleProgram, initial occurrenceOracleInput, fuel int) (occurrenceOracleResult, error) {
	t.Helper()
	return occurrenceOracleRunTo(t, ctx, p, initial, fuel, nil)
}

func occurrenceOracleRunTo(t testing.TB, ctx context.Context, p occurrenceOracleProgram, initial occurrenceOracleInput, fuel int, cut *occurrenceOracleCut) (occurrenceOracleResult, error) {
	t.Helper()
	r := occurrenceOracleResult{state: initial.state.clone(), vectors: initial.vectors, lineageBytes: map[stateLocation]occurrenceOracleLineage{}}
	for _, reg := range p.face.ReturnContext.Preserved {
		r.lineage[reg] = occurrenceOracleLineage{valid: true, register: reg}
	}
	queries, encounters := 0, 0
	for pc := p.entry; ; {
		if err := ctx.Err(); err != nil {
			return occurrenceOracleResult{}, err
		}
		if fuel <= 0 {
			return occurrenceOracleResult{}, occurrenceOracleFuelError
		}
		fuel--
		if pc < 0 || pc >= len(p.ops) || pc == p.boundary {
			return occurrenceOracleResult{}, fmt.Errorf("reference reached unexpected instruction %d", pc)
		}
		op := p.ops[pc]
		id, activation := uint64(len(r.visits)+1), uint64(0)
		if len(r.frames) != 0 {
			activation = r.frames[len(r.frames)-1].activation
		}
		r.state.context = TransitionActivationID(activation)
		v := occurrenceOracleVisit{id: id, activation: activation, instruction: pc, branchSlot: -1, before: r.state.regs}
		if cut != nil && pc == cut.instruction {
			encounters++
			if encounters == cut.encounter {
				r.boundary = v
				return r, nil
			}
		}
		if op.intent.Operation == to.CPUID {
			if queries >= len(r.state.outcomes) {
				return occurrenceOracleResult{}, occurrenceOracleOutcomeError
			}
			queries++
		}
		if op.intent.Operation == to.Return {
			expected := p.pcs[p.boundary]
			if len(r.frames) != 0 {
				expected = p.pcs[r.frames[len(r.frames)-1].after]
			}
			off := int64(r.state.regs[RSP] - r.state.origin)
			var actual uint64
			for lane := 0; lane < 8; lane++ {
				cell, ok := r.state.memory[stateLocation{off: off + int64(lane)}]
				if !ok {
					return occurrenceOracleResult{}, occurrenceOracleReturnError
				}
				actual |= uint64(cell.value) << (8 * lane)
			}
			if actual != expected {
				return occurrenceOracleResult{}, occurrenceOracleReturnError
			}
		}
		a, q := len(r.state.accesses), len(r.state.primitives)
		r.events = append(r.events, occurrenceOracleEvent{id, "fetch", len(r.visits)})
		r.state.referenceExec(t, op.intent, pc, p.pcs[pc]+uint64(len(p.encoded[pc])))
		r.transferLineage(t, op.intent, a)
		for j := a; j < len(r.state.accesses); j++ {
			kind := "read"
			if r.state.accesses[j].write {
				kind = "write"
			} else if r.state.accesses[j].returnRead {
				kind = "return-read"
			}
			r.events = append(r.events, occurrenceOracleEvent{id, kind, j})
		}
		for j := q; j < len(r.state.primitives); j++ {
			r.events = append(r.events, occurrenceOracleEvent{id, "primitive", j})
		}
		next := op.next
		switch op.intent.Operation {
		case to.Branch:
			v.branchSlot = 0
			if dagCondition(t, op.intent.Condition, r.state.flags) {
				v.branchSlot, next = 1, op.taken
			}
		case to.Call:
			frame := occurrenceOracleFrame{activation: id, parent: activation, call: pc, after: op.next, slot: r.state.regs[RSP]}
			r.frames = append(r.frames, frame)
			r.activations = append(r.activations, frame)
			next = op.taken
		case to.Return:
			if len(r.frames) == 0 {
				r.returned = true
			} else {
				frame := r.frames[len(r.frames)-1]
				next = frame.after
				r.frames = r.frames[:len(r.frames)-1]
			}
		}
		v.after, v.flags = r.state.regs, r.state.flags
		v.defined, v.preserved = r.state.flagStatus()
		r.visits = append(r.visits, v)
		if r.returned {
			if cut != nil {
				return occurrenceOracleResult{}, occurrenceOracleCutError
			}
			return r, nil
		}
		pc = next
	}
}

func occurrenceOracleCount(p occurrenceOracleProgram, r occurrenceOracleResult, index int) int {
	n := 0
	for _, visit := range r.visits {
		if visit.instruction == index {
			n++
		}
	}
	return n
}

func occurrenceOracleAssertReference(t testing.TB, p occurrenceOracleProgram, input occurrenceOracleInput, r occurrenceOracleResult, count int) {
	t.Helper()
	if !r.returned || len(r.frames) != 0 || r.state.returnTarget != p.pcs[p.boundary] || r.state.regs[RSP] != input.state.origin+8 || r.state.regs[RBP] != input.state.regs[RBP] || r.vectors != input.vectors {
		t.Fatal("reference failed complete return/frame/vector preservation")
	}
	for reg, lineage := range r.lineage {
		expected := occurrenceOracleLineage{}
		if reg == int(RBP) {
			expected = occurrenceOracleLineage{valid: true, register: RBP}
		}
		if lineage != expected {
			t.Fatal("reference retained/invented a caller-value token", reg, lineage)
		}
	}
	for key := range r.state.memory {
		expected := occurrenceOracleLineage{}
		if !key.image && key.off >= -8 && key.off < 0 {
			expected = occurrenceOracleLineage{valid: true, register: RBP, lane: uint8(key.off + 8)}
		} else if !key.image && len(r.activations) != 0 && key.off >= -40 && key.off < -32 {
			expected = occurrenceOracleLineage{valid: true, register: RBP, lane: uint8(key.off + 40)}
		}
		if r.lineageBytes[key] != expected {
			t.Fatal("reference saved-word lineage/lane differs", key)
		}
	}
	for reg := range input.state.regs {
		if !r.state.written[reg] && (r.state.regs[reg] != input.state.regs[reg] || r.state.ptrs[reg] != input.state.ptrs[reg]) {
			t.Fatal("reference changed an unwritten register", reg)
		}
	}
	if r.state.regs[R14] != input.state.origin || r.state.ptrs[R14] != (statePointer{valid: true}) {
		t.Fatal("reference lost derived root stack anchor")
	}
	terminal := p.maximum
	if p.variant == occurrenceOracleEarlyQuery && count > 0 && input.state.outcomes[count-1][0] == 0 {
		// Supplemental early-exit inputs enter with start zero. The successful
		// outcome branch precedes this iteration's increment.
		terminal = count - 1
	}
	if p.outerHeader >= 0 && r.state.regs[R12] != uint64(terminal) || p.childHeader >= 0 && r.state.regs[R13] != uint64(p.maximum) {
		t.Fatal("reference exit did not retain actual terminal counter")
	}
	if p.payload == occurrenceOracleQuery || p.payload == occurrenceOracleMixed {
		for _, reg := range []Register{RAX, RBX, RCX, RDX} {
			if r.state.regs[reg] != 0 {
				t.Fatal("history-only primitive result was not erased", reg)
			}
		}
	}
	if got := occurrenceOracleCount(p, r, p.body); got != count {
		t.Fatalf("body count %d, expected %d", got, count)
	}
	if len(r.state.memory) != len(input.state.memory) {
		t.Fatal("reference changed represented byte domain")
	}
	for location, before := range input.state.memory {
		after, exists := r.state.memory[location]
		if !exists || !r.state.frame[location] && after != before {
			t.Fatal("reference changed an untouched byte", location)
		}
		if location.off >= 0 && location.off < 8 && after != before {
			t.Fatal("root control storage changed")
		}
	}
	for _, off := range []int64{15, 20, 21, 22, 23, 63} {
		if r.state.memory[stateLocation{off: off}] != input.state.memory[stateLocation{off: off}] {
			t.Fatal("narrow operation changed neighboring sentinel", off)
		}
	}
	accesses, primitives, fetches := 0, 0, 0
	for _, e := range r.events {
		if e.occurrence == 0 || e.occurrence > uint64(len(r.visits)) {
			t.Fatal("event has no exact occurrence")
		}
		visit := r.visits[e.occurrence-1]
		switch e.kind {
		case "fetch":
			if e.index != fetches || visit.id != uint64(fetches+1) {
				t.Fatal("fetch sequence identity differs")
			}
			fetches++
		case "primitive":
			if e.index != primitives {
				t.Fatal("primitive order differs")
			}
			primitives++
		case "read", "write", "return-read":
			if e.index != accesses || r.state.accesses[e.index].instruction != visit.instruction || r.state.accesses[e.index].context != TransitionActivationID(visit.activation) {
				t.Fatal("access occurrence/order differs")
			}
			accesses++
		default:
			t.Fatal("unknown reference event")
		}
	}
	if accesses != len(r.state.accesses) || primitives != len(r.state.primitives) || fetches != len(r.visits) {
		t.Fatal("reference event inventory incomplete")
	}
	seen := map[uint64]bool{}
	for _, frame := range r.activations {
		if seen[frame.activation] || frame.activation == 0 || r.visits[frame.activation-1].instruction != frame.call || r.visits[frame.activation-1].activation != frame.parent {
			t.Fatal("CALL activation not owned by its invoking occurrence")
		}
		seen[frame.activation] = true
	}
}

func TestOccurrenceOracleFinitePopulation(t *testing.T) {
	var counts, kinds uint8
	var success, failure, unchanged, short, long bool
	for placement := occurrenceOracleLocal; placement <= occurrenceOracleParentLoop; placement++ {
		for payload := occurrenceOracleCAS; payload <= occurrenceOracleQuery; payload++ {
			for layout := 0; layout < 2; layout++ {
				p := occurrenceOracleBuild(t, placement, payload, layout, occurrenceOracleMaximum)
				for count := 0; count <= occurrenceOracleMaximum; count++ {
					for variant := 0; variant < 2; variant++ {
						t.Run(fmt.Sprintf("placement%d/payload%d/layout%d/count%d/value%d", placement, payload, layout, count, variant), func(t *testing.T) {
							input := occurrenceOracleInitial(p, uint64(count), variant)
							before := input.state.clone()
							r, err := occurrenceOracleRun(t, t.Context(), p, input, 2048)
							if err != nil {
								t.Fatal(err)
							}
							occurrenceOracleAssertReference(t, p, input, r, count)
							if !reflect.DeepEqual(before, input.state) {
								t.Fatal("reference execution mutated its original inputs")
							}
							counts |= 1 << count
							kinds |= 1 << payload
							for _, v := range r.visits {
								short = short || p.ops[v.instruction].name == "short-arm"
								long = long || p.ops[v.instruction].name == "long-arm-extra"
							}
							for _, primitive := range r.state.primitives {
								if rmw, ok := primitive.(stateRMW); ok {
									unchanged = unchanged || rmw.before == rmw.after
									if rmw.kind == to.LockedCompareExchange {
										success, failure = success || rmw.success, failure || !rmw.success
									}
								}
							}
							occurrenceOracleCheckPayload(t, p, input, r, count)
						})
					}
				}
			}
		}
	}
	if counts != 15 || kinds != 7 || !success || !failure || !unchanged || !short || !long {
		t.Fatal("finite reference population missed a promised dimension", counts, kinds, success, failure, unchanged, short, long)
	}
}

// Closed-form checks anchor the reused concrete semantics to this grammar's
// independently chosen inputs, including effects that final-state checks miss.
func occurrenceOracleCheckPayload(t testing.TB, p occurrenceOracleProgram, input occurrenceOracleInput, r occurrenceOracleResult, count int) {
	t.Helper()
	perIteration := 1
	if p.payload == occurrenceOracleByte {
		perIteration = 4
	} else if p.payload == occurrenceOracleMixed {
		perIteration = 2
	}
	if len(r.state.primitives) != count*perIteration {
		t.Fatal("primitive count lost an iteration")
	}
	query := 0
	previous := uint64(7)
	previousByte, byteStep := uint64(input.state.memory[stateLocation{off: 17}].value), 0
	compare, replacement := input.state.regs[RAX], input.state.regs[RDX]
	subleaf := uint32(input.state.regs[RCX])
	primitiveVisits := make(map[int]occurrenceOracleVisit)
	for _, event := range r.events {
		if event.kind == "primitive" {
			primitiveVisits[event.index] = r.visits[event.occurrence-1]
		}
	}
	for step, primitive := range r.state.primitives {
		visit, present := primitiveVisits[step]
		if !present {
			t.Fatal("primitive has no concrete visit")
		}
		switch e := primitive.(type) {
		case stateQuery:
			if p.payload == occurrenceOracleMixed && step%2 != 0 {
				t.Fatal("mixed primitive order lost query-before-CAS")
			}
			leaf := uint32(compare)
			if p.variant == occurrenceOracleResetQuery {
				leaf, subleaf = occurrenceOracleFixedLeaf, occurrenceOracleFixedSubleaf
			}
			tuple := input.state.outcomes[query]
			if e.leaf != leaf || e.subleaf != subleaf || e.results != tuple || visit.instruction != e.instruction || uint32(visit.before[RAX]) != leaf || uint32(visit.before[RCX]) != subleaf {
				t.Fatal("query did not consume prior selectors and distinct input tuple")
			}
			compare, replacement, subleaf = uint64(tuple[0]), uint64(tuple[3]), tuple[2]
			query++
		case stateRMW:
			if p.payload == occurrenceOracleMixed && step%2 != 1 {
				t.Fatal("mixed primitive order lost CAS-after-query")
			}
			if e.readAccess < 0 || e.readAccess+1 >= len(r.state.accesses) {
				t.Fatal("RMW lost original access pair")
			}
			read, write := r.state.accesses[e.readAccess], r.state.accesses[e.readAccess+1]
			if read.write || !write.write || read.instruction != e.instruction || write.instruction != e.instruction || read.off != write.off || read.value != e.before || write.value != e.after {
				t.Fatal("RMW read/write pair differs")
			}
			if e.kind == to.LockedCompareExchange {
				ok := uint64(uint32(compare)) == previous
				after, accumulator := previous, previous
				if ok {
					after, accumulator = uint64(uint32(replacement)), compare
				}
				if e.width != 4 || e.before != previous || e.compare != uint64(uint32(compare)) || e.replacement != uint64(uint32(replacement)) || e.success != ok || e.after != after || e.accumulator != accumulator || visit.instruction != e.instruction || visit.before[RAX] != compare || visit.after[RAX] != accumulator {
					t.Fatal("CAS32 current-memory/high-accumulator relation differs")
				}
				previous, compare = after, accumulator
			} else {
				kinds := []to.Operation{to.LockedOr, to.LockedAndImmediate, to.LockedOrImmediate, to.LockedAndImmediate}
				operands := []uint64{input.state.regs[RDX] & 255, 0x7f, 0, 255}
				slot := byteStep % 4
				after := previousByte & operands[slot]
				if slot%2 == 0 {
					after = previousByte | operands[slot]
				}
				if e.width != 1 || e.kind != kinds[slot] || e.before != previousByte || e.replacement != operands[slot] || e.after != after {
					t.Fatal("byte RMW kind/operand/current state differs")
				}
				previousByte, byteStep = after, byteStep+1
			}
		default:
			t.Fatal("unknown primitive in concrete grammar")
		}
	}
	if count != 0 && p.payload == occurrenceOracleByte && r.state.memory[stateLocation{off: 17}].value != 0x1b {
		t.Fatal("byte OR/AND did not retain evolving one-byte result")
	}
}

func TestOccurrenceOracleNestedAndResidualState(t *testing.T) {
	for _, payload := range []occurrenceOraclePayload{occurrenceOracleCAS, occurrenceOracleQuery, occurrenceOracleMixed} {
		p := occurrenceOracleBuild(t, occurrenceOracleNested, payload, 1, 3)
		input := occurrenceOracleInitial(p, ^uint64(0), 1)
		r, err := occurrenceOracleRun(t, t.Context(), p, input, 2048)
		if err != nil {
			t.Fatal(err)
		}
		occurrenceOracleAssertReference(t, p, input, r, 4)
		occurrenceOracleCheckPayload(t, p, input, r, 4)
		if len(r.activations) != 2 || r.activations[0].call != r.activations[1].call || r.activations[0].activation == r.activations[1].activation || r.activations[0].slot != r.activations[1].slot {
			t.Fatal("same CALL/slot failed to create distinct activations")
		}
		var oldScratch, newScratch, released []uint64
		for _, a := range r.state.accesses {
			switch p.ops[a.instruction].name {
			case "old-scratch":
				oldScratch = append(oldScratch, a.value)
			case "new-scratch":
				newScratch = append(newScratch, a.value)
			case "released-scratch":
				released = append(released, a.value)
			}
		}
		if len(oldScratch) != 4 || len(newScratch) != 4 || len(released) != 2 || !slices.Equal(oldScratch[1:], newScratch[:3]) || released[0] != newScratch[1] || released[1] != newScratch[3] {
			t.Fatal("iteration/call return reset released scratch")
		}
	}
}

func TestOccurrenceOracleFirstHitAndActiveFrame(t *testing.T) {
	p := occurrenceOracleBuild(t, occurrenceOracleChildLoop, occurrenceOracleQuery, 1, 3)
	input := occurrenceOracleInitial(p, ^uint64(0), 0)
	var prefixes []occurrenceOracleResult
	for encounter := 1; encounter <= 4; encounter++ {
		cut := occurrenceOracleCut{instruction: p.childHeader, encounter: encounter}
		r, err := occurrenceOracleRunTo(t, t.Context(), p, input, 2048, &cut)
		if err != nil {
			t.Fatal(err)
		}
		if r.returned || len(r.frames) != 1 || r.boundary.instruction != p.childHeader || r.boundary.activation != r.frames[0].activation || r.boundary.id != uint64(len(r.visits)+1) || r.state.regs[R13] != uint64(encounter-1) || len(r.state.primitives) != encounter-1 {
			t.Fatal("same-PC encounter lost exact state/frame/primitive prefix")
		}
		if r.state.regs[RSP] != input.state.origin-56 || r.frames[0].slot != input.state.origin-32 {
			t.Fatal("active child frame/control slot was not derived from CALL")
		}
		if len(prefixes) != 0 {
			prior := prefixes[len(prefixes)-1]
			if r.boundary.id <= prior.boundary.id || !reflect.DeepEqual(prior.visits, r.visits[:len(prior.visits)]) || !slices.Equal(prior.events, r.events[:len(prior.events)]) {
				t.Fatal("later reference encounter replaced executed prefix")
			}
		}
		prefixes = append(prefixes, r)
	}
	// First hit is before the first CMP executes: the prior selector/prologue's
	// flags still stand. A later identical PC cannot substitute for this cut.
	first := prefixes[0]
	if len(first.state.primitives) != 0 || occurrenceOracleCount(p, first, p.childHeader) != 0 || occurrenceOracleCount(p, prefixes[3], p.childHeader) != 3 {
		t.Fatal("first-hit cut accidentally executed its boundary or a later visit")
	}
	missing := occurrenceOracleCut{instruction: p.childHeader, encounter: 5}
	if got, err := occurrenceOracleRunTo(t, t.Context(), p, input, 2048, &missing); !errors.Is(err, occurrenceOracleCutError) || !reflect.DeepEqual(got, occurrenceOracleResult{}) {
		t.Fatal("unreached occurrence accepted as complete cut", err)
	}
}

func TestOccurrenceOracleDomainAndAbortControls(t *testing.T) {
	for maximum := 0; maximum <= 1; maximum++ {
		p := occurrenceOracleBuild(t, occurrenceOracleLocal, occurrenceOracleCAS, 0, maximum)
		for _, selector := range []uint64{0, 1, 2, ^uint64(0)} {
			input := occurrenceOracleInitial(p, selector, 0)
			r, err := occurrenceOracleRun(t, t.Context(), p, input, 2048)
			if err != nil {
				t.Fatal(err)
			}
			count := maximum
			if selector < uint64(maximum) {
				count = int(selector)
			}
			occurrenceOracleAssertReference(t, p, input, r, count)
		}
	}
	p := occurrenceOracleBuild(t, occurrenceOracleLocal, occurrenceOracleQuery, 0, 3)
	input := occurrenceOracleInitial(p, ^uint64(0), 0)
	good, err := occurrenceOracleRun(t, t.Context(), p, input, 2048)
	if err != nil || occurrenceOracleCount(p, good, p.body) != 3 {
		t.Fatal("abort controls lack complete maximum-domain baseline", err)
	}
	for _, mode := range []string{"fuel", "cancel", "outcomes", "return"} {
		t.Run(mode, func(t *testing.T) {
			in := input
			in.state = input.state.clone()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fuel, expected := 2048, occurrenceOracleFuelError
			switch mode {
			case "fuel":
				fuel = len(good.visits) - 1
			case "cancel":
				cancel()
				expected = context.Canceled
			case "outcomes":
				in.state.outcomes = in.state.outcomes[:2]
				expected = occurrenceOracleOutcomeError
			case "return":
				in.state.memory[stateLocation{}] = stateByte{}
				// Force a changed control word even if its low byte was zero.
				in.state.memory[stateLocation{off: 1}] = stateByte{value: input.state.memory[stateLocation{off: 1}].value ^ 1}
				expected = occurrenceOracleReturnError
			}
			got, err := occurrenceOracleRun(t, ctx, p, in, fuel)
			if !errors.Is(err, expected) || !reflect.DeepEqual(got, occurrenceOracleResult{}) {
				t.Fatal("reference abort returned partial positive state", mode, err)
			}
		})
	}
	// A missing increment is a genuinely nonterminating intent path for this
	// selector. The reference ceiling aborts; it must not invent an endpoint.
	broken := p
	broken.ops = slices.Clone(p.ops)
	for j, op := range broken.ops {
		if op.intent.Operation == to.Increment64 {
			broken.ops[j].intent = to.Intent{Operation: to.NoOp}
		}
	}
	// Supply enough independent outcomes to ensure fuel, not tuple exhaustion,
	// is the isolated failure. No encoding/checker consumes this intent mutant.
	looping := input
	looping.state = input.state.clone()
	looping.state.outcomes = make([][4]uint32, len(good.visits)+1)
	if got, err := occurrenceOracleRun(t, t.Context(), broken, looping, len(good.visits)); !errors.Is(err, occurrenceOracleFuelError) || !reflect.DeepEqual(got, occurrenceOracleResult{}) {
		t.Fatal("looping intent borrowed termination from oracle fuel", err)
	}
}

func TestOccurrenceOracleEncodingTargets(t *testing.T) {
	// Literal rel32 arithmetic checks the independently encoded target without
	// importing either decoder. It also checks real CALL return-byte locations.
	for layout := 0; layout < 2; layout++ {
		p := occurrenceOracleBuild(t, occurrenceOracleParentLoop, occurrenceOracleQuery, layout, 3)
		backward := false
		for j, op := range p.ops {
			if len(p.encoded[j]) == 0 {
				continue
			}
			switch op.intent.Operation {
			case to.Call, to.Jump, to.Branch:
				bytes := p.encoded[j]
				delta := int64(int32(binary.LittleEndian.Uint32(bytes[len(bytes)-4:])))
				target := op.next
				if op.intent.Operation != to.Jump {
					target = op.taken
				}
				if uint64(int64(p.pcs[j])+int64(len(bytes))+delta) != p.pcs[target] {
					t.Fatal("encoded transfer differs from original intent")
				}
				backward = backward || delta < 0
				if op.intent.Operation == to.Call && p.pcs[op.next] != p.pcs[j]+uint64(len(bytes)) {
					t.Fatal("CALL continuation is not its actual byte end")
				}
			}
		}
		if !backward {
			t.Fatal("layout omitted backward physical edge")
		}
	}
}
