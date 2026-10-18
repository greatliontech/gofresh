package nativeproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"math/bits"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// These are bounded synthetic state/segmentation controls, not source-startup
// evidence. Intent and independently valued entry memory precede both encoding
// and checking. The reference consumes neither decoded instructions nor symbolic
// transfer/address/provenance helpers. Encoder structure has its own population
// in transition_encoding_property_test.go; here payloads and machine states vary
// independently of opcode/register/form selectors.
type statePointer struct {
	valid bool
	off   int64
	image bool
	load  int
}

type stateLocation struct {
	image bool
	off   int64
}

func (p stateLocation) add(n int64) stateLocation      { p.off += n; return p }
func stateByteLocation(b TransitionByte) stateLocation { return stateLocation{b.Image, b.Offset} }

type stateByte struct {
	value byte
	ptr   statePointer
	lane  uint8
}

type stateAccess struct {
	instruction int
	write       bool
	off         stateLocation
}

type stateQuery struct {
	instruction   int
	leaf, subleaf uint32
	results       [4]uint32 // EAX, EBX, ECX, EDX, chosen before checking
}

type stateReference struct {
	origin  uint64
	regs    [16]uint64
	ptrs    [16]statePointer
	memory  map[stateLocation]stateByte
	words   map[int64]uint64
	written [16]bool
	// CF, ZF, OF, SF, AF, PF. Undefined AF has no compared value.
	flags    [6]bool
	writer   to.Operation
	accesses []stateAccess
	frame    map[stateLocation]bool
	loads    []interfaceMapping
	outcomes [][4]uint32
	queries  []stateQuery
}

func stateFace(modulus, residue uint64) TransitionInterface {
	return TransitionInterface{
		Origin:   OriginDomain{Min: 1 << 40, Max: 1 << 44, Modulus: modulus, Residue: residue},
		Envelope: RelativeSpan{-1 << 32, 1 << 32},
		Regions: []RelativeRegion{
			{RelativeSpan{-32, 40}, true, true},
			{RelativeSpan{-8, 16}, true, true}, // union, not a second set of inputs
			{RelativeSpan{56, 64}, false, true},
		},
		Words: []int64{-16, 0, 24},
		Conditions: TransitionConditions{Machine: MachineModel, InstructionMapping: true, EntryState: true,
			IsolatedExecution: true, MemoryMapping: true, NoHiddenAliases: true, UnalignedAccess: true},
	}
}

func stateInitial(face TransitionInterface, seed uint64) stateReference {
	rng := rand.New(rand.NewPCG(seed, 0x5154415445))
	r := stateReference{memory: map[stateLocation]stateByte{}, words: map[int64]uint64{}, frame: map[stateLocation]bool{}}
	// This range is deliberately far from every synthetic image. It is selected
	// from the interface, not from the checker's origin exclusions or outputs.
	first := face.Origin.Min + (face.Origin.Residue+face.Origin.Modulus-face.Origin.Min%face.Origin.Modulus)%face.Origin.Modulus
	r.origin = first + rng.Uint64()%((face.Origin.Max-first)/face.Origin.Modulus+1)*face.Origin.Modulus
	for j := range r.regs {
		r.regs[j] = rng.Uint64()
	}
	r.regs[4], r.ptrs[4] = r.origin, statePointer{valid: true}
	for j := range r.flags {
		r.flags[j] = rng.Uint64()&1 != 0
	}
	for _, region := range face.Regions {
		for off := region.Bytes.Start; off < region.Bytes.End; off++ {
			key := stateLocation{off: off}
			if _, exists := r.memory[key]; !exists {
				r.memory[key] = stateByte{value: byte(rng.Uint64())}
			}
		}
	}
	for _, region := range face.ImageRegions {
		for addr := region.Start; addr < region.End; addr++ {
			key := stateLocation{image: true, off: int64(addr)}
			if _, exists := r.memory[key]; !exists {
				r.memory[key] = stateByte{value: byte(rng.Uint64())}
			}
		}
	}
	for _, off := range face.Words {
		v := rng.Uint64()
		r.words[off] = v
		for lane := 0; lane < 8; lane++ {
			r.memory[stateLocation{off: off + int64(lane)}] = stateByte{value: byte(v >> (8 * lane))}
		}
	}
	return r
}

// Raw valuations are a product, not a PRNG's 64-bit subset of that product.
// Layout: origin index (8 bytes), sixteen GPR words (128 bytes), six flag bits
// (one byte), then every declared byte in increasing offset order. Missing data
// is zero padded. RSP is necessarily the chosen origin, not an independent GPR;
// its eight input bytes are consumed but cannot weaken that interface premise.
// Words alias the same eight byte values rather than introducing inconsistent
// duplicate assignments. Sufficiently long arrays express every joint valuation
// of this interface. Subsequent 16-byte records supply independent per-query
// BV32 tuples; they constrain only test evaluation, never the checking interface.
func stateRawInitial(face TransitionInterface, data []byte) stateReference {
	read := func(n int) []byte {
		out := make([]byte, n)
		used := copy(out, data)
		data = data[used:]
		return out
	}
	r := stateReference{memory: map[stateLocation]stateByte{}, words: map[int64]uint64{}, frame: map[stateLocation]bool{}}
	index := binary.LittleEndian.Uint64(read(8))
	first := face.Origin.Min + (face.Origin.Residue+face.Origin.Modulus-face.Origin.Min%face.Origin.Modulus)%face.Origin.Modulus
	r.origin = first + index%((face.Origin.Max-first)/face.Origin.Modulus+1)*face.Origin.Modulus
	for j := range r.regs {
		r.regs[j] = binary.LittleEndian.Uint64(read(8))
	}
	r.regs[4], r.ptrs[4] = r.origin, statePointer{valid: true}
	flags := read(1)[0]
	for j := range r.flags {
		r.flags[j] = flags&(1<<j) != 0
	}
	for _, region := range face.Regions {
		for off := region.Bytes.Start; off < region.Bytes.End; off++ {
			r.memory[stateLocation{off: off}] = stateByte{}
		}
	}
	for _, region := range face.ImageRegions {
		for addr := region.Start; addr < region.End; addr++ {
			r.memory[stateLocation{true, int64(addr)}] = stateByte{}
		}
	}
	var offsets []stateLocation
	for off := range r.memory {
		offsets = append(offsets, off)
	}
	slices.SortFunc(offsets, func(a, b stateLocation) int {
		if a.image != b.image {
			if a.image {
				return 1
			}
			return -1
		}
		if a.off < b.off {
			return -1
		}
		if a.off > b.off {
			return 1
		}
		return 0
	})
	for _, off := range offsets {
		var value byte
		if len(data) != 0 {
			value, data = data[0], data[1:]
		}
		r.memory[off] = stateByte{value: value}
	}
	for _, off := range face.Words {
		var word uint64
		for lane := 0; lane < 8; lane++ {
			word |= uint64(r.memory[stateLocation{off: off + int64(lane)}].value) << (8 * lane)
		}
		r.words[off] = word
	}
	// Each remaining 16-byte record independently supplies the full product of
	// four uint32 outcomes. An absent tail selects zero, never checker output.
	for len(data) != 0 {
		var tuple [4]uint32
		for j := range tuple {
			tuple[j] = binary.LittleEndian.Uint32(read(4))
		}
		r.outcomes = append(r.outcomes, tuple)
	}
	return r
}

func (r stateReference) clone() stateReference {
	memory, frame := r.memory, r.frame
	r.memory, r.frame = map[stateLocation]stateByte{}, map[stateLocation]bool{}
	for off, v := range memory {
		r.memory[off] = v
	}
	for off, v := range frame {
		r.frame[off] = v
	}
	r.accesses = slices.Clone(r.accesses)
	r.queries = slices.Clone(r.queries)
	r.outcomes = slices.Clone(r.outcomes)
	return r
}

func (r *stateReference) referenceExec(t testing.TB, i to.Intent, index int, nextPC ...uint64) {
	t.Helper()
	if i.Operation == to.Jump {
		return
	}
	if i.Operation == to.CPUID {
		q := stateQuery{instruction: index, leaf: uint32(r.regs[0]), subleaf: uint32(r.regs[1])}
		if len(r.queries) < len(r.outcomes) {
			q.results = r.outcomes[len(r.queries)]
		}
		r.queries = append(r.queries, q)
		for slot, reg := range []int{0, 3, 1, 2} {
			r.regs[reg], r.ptrs[reg], r.written[reg] = uint64(q.results[slot]), statePointer{}, true
		}
		return
	}
	address := r.regs[i.Base] + uint64(i.SignedDisp)
	access := func(write bool) stateLocation {
		t.Helper()
		p := r.ptrs[i.Base]
		base := r.origin
		if p.image {
			base = 0
		}
		if !p.valid || address != base+uint64(p.off+i.SignedDisp) {
			t.Fatal("invalid reference address construction")
		}
		off := stateLocation{p.image, int64(address - base)}
		for j := int64(0); j < 8; j++ {
			if _, ok := r.memory[off.add(j)]; !ok {
				t.Fatal("reference access outside declared bytes", off)
			}
		}
		r.accesses = append(r.accesses, stateAccess{index, write, off})
		return off
	}
	if i.Operation == to.Store || i.Operation == to.StoreImmediate {
		off := access(true)
		value, ptr := i.Immediate, statePointer{}
		if i.Operation == to.Store {
			value, ptr = r.regs[i.Src], r.ptrs[i.Src]
		}
		for lane := uint8(0); lane < 8; lane++ {
			b := stateByte{value: byte(value >> (8 * lane)), ptr: ptr}
			if ptr.valid {
				b.lane = lane
			}
			r.memory[off.add(int64(lane))] = b
			r.frame[off.add(int64(lane))] = true
		}
		return
	}
	r.written[i.Dst] = true
	switch i.Operation {
	case to.MoveRegister:
		r.regs[i.Dst], r.ptrs[i.Dst] = r.regs[i.Src], r.ptrs[i.Src]
	case to.MoveImmediate, to.MoveImmediate32:
		r.regs[i.Dst], r.ptrs[i.Dst] = i.Immediate, statePointer{}
	case to.LEA:
		p := r.ptrs[i.Base]
		if p.valid {
			p.off += i.SignedDisp
		}
		r.regs[i.Dst], r.ptrs[i.Dst] = address, p
	case to.LEARIP:
		if len(nextPC) != 1 {
			t.Fatal("RIP intent requires independently located next PC")
		}
		v := nextPC[0] + uint64(i.SignedDisp)
		found := -1
		for j, load := range r.loads {
			if v >= load.start && v < load.end {
				found = j
			}
		}
		if found < 0 {
			t.Fatal("reference RIP address has no mapping")
		}
		r.regs[i.Dst], r.ptrs[i.Dst] = v, statePointer{valid: true, image: true, off: int64(v), load: found}
	case to.Load:
		off := access(false)
		var value uint64
		p := r.memory[off].ptr
		for lane := uint8(0); lane < 8; lane++ {
			b := r.memory[off.add(int64(lane))]
			value |= uint64(b.value) << (8 * lane)
			if b.ptr != r.memory[off].ptr || b.lane != lane {
				p = statePointer{}
			}
		}
		r.regs[i.Dst], r.ptrs[i.Dst] = value, p
	case to.Subtract:
		x, y := r.regs[i.Dst], i.Immediate
		z := x - y
		r.regs[i.Dst] = z
		r.flags = [6]bool{x < y, z == 0, (x^y)&(x^z)&(1<<63) != 0, z>>63 != 0, (x^y^z)&16 != 0, bits.OnesCount8(byte(z))%2 == 0}
		if r.ptrs[i.Dst].valid {
			r.ptrs[i.Dst].off -= int64(y)
		}
		r.writer = to.Subtract
	case to.And:
		r.regs[i.Dst] &= i.Immediate
		z := r.regs[i.Dst]
		r.flags = [6]bool{false, z == 0, false, z>>63 != 0, false, bits.OnesCount8(byte(z))%2 == 0}
		if !r.ptrs[i.Dst].valid || r.ptrs[i.Dst].image {
			t.Fatal("valid AND construction lost its pointer")
		}
		r.ptrs[i.Dst].off = int64(z - r.origin)
		r.writer = to.And
	default:
		t.Fatal("unknown reference intent", i)
	}
}

// No fallback scratch assignment: a reset/extra variable in a continuation is
// an error, even if evaluating it as zero would accidentally give the right bits.
func stateEval(t testing.TB, term br.Term, values map[br.Term]uint64) uint64 {
	t.Helper()
	seen := map[br.Term]bool{}
	stack := []br.Term{term}
	var assignments []br.Assignment
	edges := 0
	maximum := int(^uint(0) >> 1)
	for len(stack) != 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !x.Valid() {
			t.Fatal("missing state term")
		}
		if seen[x] {
			continue
		}
		seen[x] = true
		v := x.View()
		if v.Op == br.Variable {
			value, ok := values[x]
			if !ok {
				t.Fatal("unbound or reconstructed entry variable", v)
			}
			assignments = append(assignments, br.Assignment{Variable: x, Value: value})
		}
		if len(v.Args) > maximum-edges {
			t.Fatal("evaluator edge inventory is not representable by host int")
		}
		edges += len(v.Args)
		stack = append(stack, v.Args...)
	}
	limits, representable := stateEvaluationLimits(len(seen), edges, len(assignments))
	if !representable {
		t.Fatal("evaluator allowance is not representable by host int")
	}
	value, err := br.Eval(t.Context(), term, assignments, limits)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// These counts size only diagnostic evaluation of an already accepted term;
// they never choose a reference answer or excuse a production-checker refusal.
// Eval's graph validation remembers the greatest arrival depth at each node.
// Under its 512-level ceiling, a node can expand at most 512 times, so the
// graph walk pops at most 1+512*edges entries. Its memoized value evaluation
// calls at most 1+edges nodes (including cache hits). Meter creation and the
// final check add two ticks. Assignment validation is currently unmetered;
// reserving one per assignment also accounts for that separate input inventory.
// Nodes must accommodate both unique graph nodes and the assignment snapshot.
func stateEvaluationLimits(nodes, edges, assignments int) (br.Limits, bool) {
	if nodes < 1 || edges < 0 || assignments < 0 {
		return br.Limits{}, false
	}
	work := new(big.Int).Mul(big.NewInt(int64(edges)), big.NewInt(513))
	work.Add(work, big.NewInt(4))
	work.Add(work, big.NewInt(int64(assignments)))
	maximum := new(big.Int).SetUint64(uint64(^uint(0) >> 1))
	if work.Cmp(maximum) > 0 {
		return br.Limits{}, false
	}
	return br.Limits{Nodes: max(nodes, assignments), Work: int(work.Int64())}, true
}

// Handles are used only after the entire independently prescribed input shape
// has been checked: distinct variables, exact byte union and exact word slices.
// In particular a reported constant or omitted byte cannot seed the reference.
func stateBindings(t testing.TB, c TransitionCertificate, face TransitionInterface, initial stateReference, preservedFlags bool) map[br.Term]uint64 {
	t.Helper()
	b := c.checked.bound
	if !reflect.DeepEqual(b.Interface, face) || b.Origin != b.InitialRegisters[4] {
		t.Fatal("entry interface/origin changed")
	}
	scope := b.Origin.View().Scope
	seen := map[uint64]bool{}
	values := map[br.Term]uint64{}
	variable := func(x br.Term, sort br.Sort, value uint64) {
		t.Helper()
		v := x.View()
		if v.Op != br.Variable || v.Sort != sort || !v.Scratch || v.Scope != scope || scope == (br.Scope{}) || len(v.Args) != 0 || seen[v.Immediate] {
			t.Fatal("entry inputs are not independent fresh variables", v)
		}
		seen[v.Immediate] = true
		values[x] = value
	}
	for j, x := range b.InitialRegisters {
		variable(x, br.Bits(64), initial.regs[j])
	}
	if len(b.Words) != len(face.Words) {
		t.Fatal("input word keyset differs")
	}
	words := map[int64]br.Term{}
	for _, w := range b.Words {
		v, ok := initial.words[w.Offset]
		if !ok || words[w.Offset].Valid() {
			t.Fatal("extra/duplicate input word", w.Offset)
		}
		variable(w.Value, br.Bits(64), v)
		words[w.Offset] = w.Value
	}
	if len(b.InitialMemory) != len(initial.memory) {
		t.Fatalf("initial byte keyset size %d, expected %d", len(b.InitialMemory), len(initial.memory))
	}
	byteSeen := map[stateLocation]bool{}
	type wordLane struct {
		word br.Term
		bit  uint64
	}
	wordBytes := map[int64]wordLane{}
	for _, off := range face.Words {
		for lane := int64(0); lane < 8; lane++ {
			wordBytes[off+lane] = wordLane{words[off], uint64(lane * 8)}
		}
	}
	for _, b := range b.InitialMemory {
		key := stateByteLocation(b)
		want, ok := initial.memory[key]
		if !ok || byteSeen[key] || b.Pointer != nil || b.PointerLane != 0 {
			t.Fatal("initial byte keyset/provenance differs", b.Offset)
		}
		byteSeen[key] = true
		if lane, grouped := wordBytes[b.Offset]; grouped && !b.Image {
			v := b.Value.View()
			if v.Op != br.Extract || v.Sort != br.Bits(8) || v.Immediate != lane.bit || len(v.Args) != 1 || v.Args[0] != lane.word {
				t.Fatal("initial word byte has wrong independent slice", b.Offset)
			}
		} else {
			variable(b.Value, br.Bits(8), uint64(want.value))
		}
	}
	if preservedFlags {
		for j, value := range []bool{initial.flags[0], initial.flags[1], initial.flags[3] != initial.flags[2]} {
			v := uint64(0)
			if value {
				v = 1
			}
			variable(c.checked.flags[j], br.Bool(), v)
		}
	}
	for _, b := range b.InitialMemory {
		if stateEval(t, b.Value, values) != uint64(initial.memory[stateByteLocation(b)].value) {
			t.Fatal("initial byte value differs", b.Offset)
		}
	}
	return values
}

type stateInstruction struct {
	intent to.Intent
	choice uint8
}

// This is an actual supplied checker limit, including the unexecuted cut, not
// an accepted-program truncation rule. Oversized inputs instantiate their first
// counted overflow prefix; no claim is made about their uninstantiated suffix.
const statePopulationInstructions = 4096

func stateInventoryOverflow(t testing.TB, c TransitionCertificate, err error, nodes, limit int) {
	t.Helper()
	var refusal *Refusal
	if nodes <= limit || !errors.As(err, &refusal) || refusal.Premise != "transition-budget" || c.checked != nil {
		t.Fatal("counted inventory overflow did not refuse at its actual supplied limit", err)
	}
}

func stateExpressionDepthRefused(t testing.TB, c TransitionCertificate, err error, pc uint64) {
	t.Helper()
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Premise != "relation-budget" || refusal.Detail != "constructed expression depth" || refusal.PC != pc || c.checked != nil {
		t.Fatal("expected the independently counted constructor-depth fault", err)
	}
}

// This is a resource oracle, separate from the ISA/provenance oracle. It counts
// the current constructor vocabulary's expression levels, including SUB/AND's
// zero comparison and MOV/32's unused old-destination extraction. It does not
// assert that these are minimal mathematical expressions. Accepted projections
// are checked against the count before it licenses any depth-refusal control.
// Thus arbitrary load/store dependencies need no periodic heap/register reset.
type stateDepthProfile struct {
	regs   [16]int
	flags  [3]int
	memory map[stateLocation]int
}

func stateInitialDepth(face TransitionInterface) stateDepthProfile {
	d := stateDepthProfile{memory: map[stateLocation]int{}, flags: [3]int{1, 1, 1}}
	for j := range d.regs {
		d.regs[j] = 1
	}
	for _, r := range face.Regions {
		for off := r.Bytes.Start; off < r.Bytes.End; off++ {
			d.memory[stateLocation{off: off}] = 1
		}
	}
	for _, r := range face.ImageRegions {
		for addr := r.Start; addr < r.End; addr++ {
			d.memory[stateLocation{true, int64(addr)}] = 1
		}
	}
	for _, off := range face.Words {
		for j := int64(0); j < 8; j++ {
			d.memory[stateLocation{off: off + j}] = 2
		}
	}
	return d
}

func (d *stateDepthProfile) step(i to.Intent, before stateReference) int {
	base := before.origin
	if before.ptrs[i.Base].image {
		base = 0
	}
	address := stateLocation{before.ptrs[i.Base].image, int64(before.regs[i.Base] + uint64(i.SignedDisp) - base)}
	switch i.Operation {
	case to.Jump:
		return 1
	case to.CPUID:
		needed := max(d.regs[0]+1, d.regs[1]+1, 2)
		for _, reg := range []int{0, 3, 1, 2} {
			d.regs[reg] = 2
		}
		return needed
	case to.MoveRegister:
		d.regs[i.Dst] = d.regs[i.Src]
	case to.MoveImmediate:
		d.regs[i.Dst] = 1
	case to.LEARIP:
		d.regs[i.Dst] = 1
	case to.MoveImmediate32:
		needed := max(d.regs[i.Dst]+1, 2)
		d.regs[i.Dst] = 2
		return needed
	case to.LEA:
		d.regs[i.Dst] = d.regs[i.Base] + 1
	case to.Load:
		h := d.memory[address]
		for j := int64(1); j < 8; j++ {
			h = 1 + max(h, d.memory[address.add(j)])
		}
		d.regs[i.Dst] = h
	case to.Store, to.StoreImmediate:
		h := 2
		if i.Operation == to.Store {
			h = d.regs[i.Src] + 1
		}
		for j := int64(0); j < 8; j++ {
			d.memory[address.add(j)] = h
		}
		return h
	case to.Subtract:
		d.regs[i.Dst]++
		h := d.regs[i.Dst]
		d.flags = [3]int{h, h + 1, h}
		return h + 1
	case to.And:
		d.regs[i.Dst]++
		h := d.regs[i.Dst]
		d.flags = [3]int{1, h + 1, h + 1}
		return h + 1
	}
	return d.regs[i.Dst]
}

func stateTermHeight(term br.Term, memo map[br.Term]int) int {
	if memo == nil {
		memo = map[br.Term]int{}
	}
	if h := memo[term]; h != 0 {
		return h
	}
	h := 1
	for _, arg := range term.View().Args {
		h = max(h, 1+stateTermHeight(arg, memo))
	}
	memo[term] = h
	return h
}

func (d stateDepthProfile) assertProjection(t testing.TB, c TransitionCertificate) {
	t.Helper()
	memo := map[br.Term]int{}
	for j, r := range c.checked.bound.Registers {
		if stateTermHeight(r.Value, memo) != d.regs[j] {
			t.Fatal("register constructor-depth premise changed", j, stateTermHeight(r.Value, memo), d.regs[j])
		}
	}
	for _, b := range c.checked.bound.Memory {
		if stateTermHeight(b.Value, memo) != d.memory[stateByteLocation(b)] {
			t.Fatal("byte constructor-depth premise changed", b.Offset)
		}
	}
	for j, flag := range c.checked.flags {
		if stateTermHeight(flag, memo) != d.flags[j] {
			t.Fatal("predicate constructor-depth premise changed", j)
		}
	}
}

// Encoding choices are constrained only by their representable payload. No
// semantic operand is reconstructed by parsing the resulting bytes.
func stateEncoding(i to.Intent, choice uint8) to.Encoding {
	if i.Operation == to.CPUID {
		return to.Encoding{Form: to.CPUID0FA2}
	}
	e := to.Encoding{REX: 0x48}
	r, b := uint8(0), i.Dst
	mem := false
	switch i.Operation {
	case to.MoveRegister:
		e.Form, r = to.MOV89, i.Src
		if choice&1 != 0 {
			e.Form, r, b = to.MOV8B, i.Dst, i.Src
		}
	case to.MoveImmediate:
		e.Form = to.MOVB8Imm64
		if choice&1 != 0 && uint64(int64(int32(i.Immediate))) == i.Immediate {
			e.Form = to.MOVC7
		}
	case to.MoveImmediate32:
		e.Form, e.REX = to.MOVB8Imm32, 0
		if i.Dst >= 8 {
			e.REX = 0x41
		}
		return e
	case to.Load, to.LEA:
		mem, e.Form, r, b = true, to.MOV8B, i.Dst, i.Base
		if i.Operation == to.LEA {
			e.Form = to.LEA8D
		}
	case to.LEARIP:
		e.Form, e.REX, e.DispBytes = to.LEA8D, 0x48|i.Dst/8<<2|choice&3, 4
		return e
	case to.Store:
		mem, e.Form, r, b = true, to.MOV89, i.Src, i.Base
	case to.StoreImmediate:
		mem, e.Form, b = true, to.MOVC7, i.Base
	case to.Subtract, to.And:
		e.Form = to.SUB81
		if i.Dst == 0 && choice%3 == 2 {
			e.Form = to.SUB2D
		} else if choice%3 == 0 && uint64(int64(int8(i.Immediate))) == i.Immediate {
			e.Form = to.SUB83
		}
		if i.Operation == to.And {
			e.Form += to.AND83 - to.SUB83
		}
	case to.Jump:
		e.REX, e.Form = 0, to.JMPE9
		if choice&1 == 0 && int64(int8(i.SignedDisp)) == i.SignedDisp {
			e.Form = to.JMPEB
		}
		return e
	}
	e.REX |= r/8<<2 | b/8
	if mem {
		e.SIB = b%8 == 4 || choice&4 != 0
		if e.SIB {
			e.Scale = choice >> 3 & 3
		}
		e.DispBytes = 4
		if i.SignedDisp == 0 && b%8 != 5 && choice%3 == 0 {
			e.DispBytes = 0
		} else if int64(int8(i.SignedDisp)) == i.SignedDisp && choice%3 == 1 {
			e.DispBytes = 1
		}
	}
	return e
}

type stateLayout struct {
	im       *Image
	digest   [32]byte
	pcs      []uint64 // logical order; includes the unexecuted endpoint
	encoded  [][]byte
	intents  []to.Intent // original intent, retained independently of emitted bytes
	mappings []interfaceMapping
}

func (x stateLayout) proposal(cut int) TransitionProposal {
	p := TransitionProposal{ImageDigest: x.digest, Entry: x.pcs[0], Cut: x.pcs[cut]}
	for j := 0; j <= cut; j++ {
		n := Node{PC: x.pcs[j], Size: uint8(len(x.encoded[j]))}
		if j < cut {
			n.Successors = []uint64{x.pcs[j+1]}
		}
		p.Nodes = append(p.Nodes, n)
	}
	return p
}

// Each logical operation is followed by an independently laid-out JMP. Blocks
// may go forward or backward physically; arbitrary gap bytes are never executed.
// The final UD2 is intentionally outside the executed grammar.
func stateArrange(t testing.TB, program []stateInstruction, seed uint64) stateLayout {
	t.Helper()
	n := len(program) / 2
	rng := rand.New(rand.NewPCG(seed, 0x4c41594f5554))
	permutation := rng.Perm(n + 1)
	// Put logical entry at the first mapped byte, but permute all other blocks.
	for j, p := range permutation {
		if p == 0 {
			permutation[0], permutation[j] = 0, permutation[0]
			break
		}
	}
	positions := make([]int, n+1)
	for physical, logical := range permutation {
		positions[logical] = physical * 32
	}
	code := make([]byte, 32*(n+1))
	for j := range code {
		code[j] = byte(rng.Uint64())
	}
	x := stateLayout{pcs: make([]uint64, len(program)+1), encoded: make([][]byte, len(program)+1)}
	for _, op := range program {
		x.intents = append(x.intents, op.intent)
	}
	for j := 0; j < n; j++ {
		ins := program[2*j]
		b, err := to.Encode(ins.intent, stateEncoding(ins.intent, ins.choice))
		if err != nil {
			t.Fatal(err)
		}
		off := positions[j]
		x.pcs[2*j], x.encoded[2*j] = testEntry+uint64(off), b
		copy(code[off:], b)
		jumpPC := testEntry + uint64(off+len(b))
		target := testEntry + uint64(positions[j+1])
		disp := int64(target) - int64(jumpPC+5)
		choice := uint8(1)
		if program[2*j+1].choice&1 == 0 && int64(int8(int64(target)-int64(jumpPC+2))) == int64(target)-int64(jumpPC+2) {
			disp, choice = int64(target)-int64(jumpPC+2), 0
		}
		jump := to.Intent{Operation: to.Jump, SignedDisp: disp}
		b, err = to.Encode(jump, stateEncoding(jump, choice))
		if err != nil {
			t.Fatal(err)
		}
		x.pcs[2*j+1], x.encoded[2*j+1] = jumpPC, b
		copy(code[off+len(x.encoded[2*j]):], b)
	}
	x.pcs[len(program)] = testEntry + uint64(positions[n])
	x.encoded[len(program)] = []byte{0x0f, 0x0b}
	copy(code[positions[n]:], x.encoded[len(program)])
	// Retain no convenient bytes beyond the final physical instruction. This
	// also exercises a decoded cut/fetch ending exactly at a mapping edge.
	end := 0
	for j, pc := range x.pcs {
		end = max(end, int(pc-testEntry)+len(x.encoded[j]))
	}
	raw := elfBytes(code[:end])
	x.digest = sha256.Sum256(raw)
	var err error
	x.im, err = NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func stateAssert(t testing.TB, c TransitionCertificate, x stateLayout, cut int, initial, want stateReference, values map[br.Term]uint64) {
	t.Helper()
	b := c.checked.bound
	stateQueryBindings(t, b, x, want, values)
	if b.ImageDigest != x.digest || b.Entry != x.pcs[0] || b.Rules != TransitionRules {
		t.Fatal("state lost image/entry/rule binding")
	}
	if len(b.Instructions) != cut {
		t.Fatal("executed fetch count", len(b.Instructions), cut)
	}
	for j, span := range b.Instructions {
		if span != (Span{x.pcs[j], x.pcs[j] + uint64(len(x.encoded[j]))}) {
			t.Fatal("fetch ordering/extent", j, span)
		}
	}
	if b.Boundary.PC != x.pcs[cut] || b.Boundary.Instruction.Len != len(x.encoded[cut]) || !bytes.Equal(b.Boundary.Bytes, x.encoded[cut]) {
		t.Fatal("unexecuted boundary not retained separately")
	}
	if len(b.Accesses) != len(want.accesses) {
		t.Fatal("access count", len(b.Accesses), len(want.accesses))
	}
	frame := map[stateLocation]bool{}
	for j, a := range want.accesses {
		kind := FrameRead
		if a.write {
			kind = FrameWrite
			for k := int64(0); k < 8; k++ {
				frame[a.off.add(k)] = true
			}
		}
		if b.Accesses[j] != (TransitionAccess{PC: x.pcs[a.instruction], Kind: kind, Bytes: RelativeSpan{a.off.off, a.off.off + 8}, Image: a.off.image}) {
			t.Fatal("ordered access differs", j, b.Accesses[j], a)
		}
	}
	if !reflect.DeepEqual(frame, want.frame) {
		t.Fatal("write frame differs")
	}
	pointer := func(got TransitionPointer, p statePointer) {
		t.Helper()
		var expected TransitionPointer
		if p.valid && p.image {
			actual, ok := got.(ImagePointer)
			if !ok || actual.Address != uint64(p.off) || actual.owner != &x.im.data[0] {
				t.Fatal("image provenance differs", got, p)
			}
			// The reference's fixture mapping, not the returned pointer, fixes
			// ownership and logical extent. Address-to-load checks are separate.
			if actual.load != p.load || p.load < 0 || p.load >= len(x.mappings) || actual.Address < x.mappings[p.load].start || actual.Address > x.mappings[p.load].end {
				t.Fatal("image mapping provenance differs")
			}
			return
		}
		if p.valid {
			expected = OriginPointer{Origin: b.Origin, Offset: p.off}
		}
		if got != expected {
			t.Fatal("origin provenance differs", got, expected)
		}
	}
	for j, v := range b.Registers {
		if v.Value.Sort() != br.Bits(64) {
			t.Fatal("register relation width differs", j)
		}
		if got := stateEval(t, v.Value, values); got != want.regs[j] {
			t.Fatalf("register %d: got %#x want %#x at logical cut %d", j, got, want.regs[j], cut)
		}
		pointer(v.Pointer, want.ptrs[j])
		preserved := ^uint64(0)
		if want.written[j] {
			preserved = 0
		}
		if b.Preserved[j] != preserved {
			t.Fatal("exact preservation mask differs", j, b.Preserved[j], preserved)
		}
	}
	if len(b.Memory) != len(want.memory) {
		t.Fatal("final byte keyset size", len(b.Memory), len(want.memory))
	}
	seen := map[stateLocation]bool{}
	for _, v := range b.Memory {
		key := stateByteLocation(v)
		w, ok := want.memory[key]
		if !ok || seen[key] {
			t.Fatal("extra/duplicate final byte", v.Offset)
		}
		seen[key] = true
		if v.Value.Sort() != br.Bits(8) || stateEval(t, v.Value, values) != uint64(w.value) {
			t.Fatal("final byte differs", v.Offset)
		}
		pointer(v.Pointer, w.ptr)
		if v.PointerLane != w.lane {
			t.Fatal("pointer lane differs", v.Offset)
		}
		if !frame[key] && w != initial.memory[key] {
			t.Fatal("reference changed byte outside write frame")
		}
	}
	for j, f := range []TransitionFlag{b.Flags.CF, b.Flags.ZF, b.Flags.OF, b.Flags.SF, b.Flags.AF, b.Flags.PF} {
		defined := want.writer != to.And || j != 4
		if f.Preserved != (want.writer == 0) || f.Defined != defined || !defined && f.Value.Valid() {
			t.Fatal("arithmetic flag defined/preserved/value status differs", j, f)
		}
		if f.Value.Valid() && (f.Value.Sort() != br.Bool() || (stateEval(t, f.Value, values) != 0) != want.flags[j]) {
			t.Fatal("projected arithmetic flag value differs", j)
		}
	}
	for j, want := range []bool{want.flags[0], want.flags[1], want.flags[3] != want.flags[2]} {
		if c.checked.flags[j].Sort() != br.Bool() || (stateEval(t, c.checked.flags[j], values) != 0) != want {
			t.Fatal("private CF/ZF/SF!=OF differs", j)
		}
	}
}

func stateExpanded(ops []stateInstruction) []stateInstruction {
	var program []stateInstruction
	for _, op := range ops {
		program = append(program, op, stateInstruction{intent: to.Intent{Operation: to.Jump}, choice: op.choice >> 5})
	}
	return program
}

func stateInheritedInputs(t testing.TB, original, current TransitionBound) {
	t.Helper()
	if len(current.PrimitiveEffects) < len(original.PrimitiveEffects) || !slices.Equal(current.PrimitiveEffects[:len(original.PrimitiveEffects)], original.PrimitiveEffects) {
		t.Fatal("continuation replaced prior primitive outcomes or selectors")
	}
	if current.Origin != original.Origin || current.InitialRegisters != original.InitialRegisters ||
		!slices.Equal(current.InitialMemory, original.InitialMemory) || !slices.Equal(current.Words, original.Words) ||
		!slices.Equal(current.ExcludedOrigins, original.ExcludedOrigins) || !reflect.DeepEqual(current.Interface, original.Interface) {
		t.Fatal("continuation replaced original terms, memory, or origin/interface premises")
	}
}

func stateCheckProgram(t testing.TB, ops []stateInstruction, face TransitionInterface, initial stateReference, layoutSeed, cuts uint64, everyCut bool, partitions ...[]int) {
	t.Helper()
	program := stateExpanded(ops)
	wants := []stateReference{initial.clone()}
	r := initial.clone()
	// Execute intent BEFORE bytes exist. Branch displacement is a layout fact;
	// reference memory effects use logical instruction indices until comparison.
	for j, op := range program {
		r.referenceExec(t, op.intent, j)
		wants = append(wants, r.clone())
	}
	x := stateArrange(t, program, layoutSeed)
	stateCheckLocated(t, x, face, initial, wants, cuts, everyCut, partitions...)
}

func stateCheckLocated(t testing.TB, x stateLayout, face TransitionInterface, initial stateReference, wants []stateReference, cuts uint64, everyCut bool, partitions ...[]int) {
	t.Helper()
	length := len(wants) - 1
	overflow := length+1 > statePopulationInstructions
	// Node allowance scales with all instructions; work includes dense
	// partitioning's quadratic graph inventories and repeated imports. Depth is
	// counted independently below, so long live heap/register dependencies are
	// retained rather than refreshed or excluded by an artificial command cap.
	continuations := 3
	if everyCut {
		continuations = length
	} else if len(partitions) != 0 {
		continuations = len(partitions[0]) + 1
	}
	limits, representable := sequenceLimits(face, length, len(initial.memory), continuations, statePopulationInstructions)
	if !representable {
		c, err := CheckTransition(t.Context(), x.im, face, x.proposal(0), limits)
		sequenceRefused(t, c, err, "transition-budget", 0)
		return
	}
	if overflow {
		c, err := CheckTransition(t.Context(), x.im, face, x.proposal(length), limits)
		stateInventoryOverflow(t, c, err, len(x.proposal(length).Nodes), limits.Instructions)
		// Still require exact-state acceptance up to the actual resource frontier.
		// A prefix theorem is never a theorem about the uninstantiated input tail.
		length = limits.Instructions - 1
	}
	if len(x.intents) != len(wants)-1 {
		t.Fatal("layout lost its original intent inventory")
	}
	depth := stateInitialDepth(face)
	depthFault := -1
	for j := 0; j < length; j++ {
		if depth.step(x.intents[j], wants[j]) > limits.Depth {
			depthFault, length = j, j
			depth = stateInitialDepth(face)
			for k := 0; k < j; k++ {
				depth.step(x.intents[k], wants[k])
			}
			break
		}
	}
	if depthFault >= 0 && !overflow {
		c, err := CheckTransition(t.Context(), x.im, face, x.proposal(len(wants)-1), limits)
		stateExpressionDepthRefused(t, c, err, x.pcs[depthFault])
	}
	r := wants[length]
	direct, err := CheckTransition(t.Context(), x.im, face, x.proposal(length), limits)
	if err != nil {
		t.Fatalf("independently valid full construction refused: %v", err)
	}
	directValues := stateBindings(t, direct, face, initial, r.writer == 0)
	stateAssert(t, direct, x, length, initial, r, directValues)
	depth.assertProjection(t, direct)
	root, err := CheckTransition(t.Context(), x.im, face, x.proposal(0), limits)
	if err != nil {
		t.Fatal(err)
	}
	values := stateBindings(t, root, face, initial, true)
	stateAssert(t, root, x, 0, initial, wants[0], values)
	original, _ := root.Bound()
	if original.Origin.View().Scope == direct.checked.bound.Origin.View().Scope {
		t.Fatal("independent roots reused a variable scope")
	}
	var boundaries []int
	if length == 0 {
		// Entry itself is the unexecuted boundary; there is no advancing suffix.
	} else if len(partitions) != 0 {
		for _, cut := range partitions[0] {
			if cut > 0 && cut <= length {
				boundaries = append(boundaries, cut)
			}
		}
		boundaries = append(boundaries, length)
		slices.Sort(boundaries)
		boundaries = slices.Compact(boundaries)
	} else if everyCut {
		for j := 1; j <= length; j++ {
			boundaries = append(boundaries, j)
		}
	} else {
		boundaries = []int{1, 1 + int(cuts%uint64(length)), length}
		slices.Sort(boundaries)
		boundaries = slices.Compact(boundaries)
	}
	for _, cut := range boundaries {
		prior := root.checked.bound
		root, err = CheckTransitionContinuation(t.Context(), root, x.proposal(cut))
		if err != nil {
			t.Fatalf("valid continuation to logical boundary %d refused: %v", cut, err)
		}
		stateInheritedInputs(t, original, root.checked.bound)
		stateInheritedInputs(t, prior, root.checked.bound)
		stateAssert(t, root, x, cut, initial, wants[cut], values)
	}
	// Secondary only: both roots and every selected prefix have already been
	// checked against independent states using their own validated input handles.
	assertTransitionAlpha(t, direct, root)
	depth.assertProjection(t, root)
	if depthFault >= 0 {
		c, err := CheckTransitionContinuation(t.Context(), root, x.proposal(depthFault+1))
		stateExpressionDepthRefused(t, c, err, x.pcs[depthFault])
	}
	if overflow {
		c, err := CheckTransitionContinuation(t.Context(), root, x.proposal(len(wants)-1))
		stateInventoryOverflow(t, c, err, len(x.proposal(len(wants)-1).Nodes), limits.Instructions)
	}
}
