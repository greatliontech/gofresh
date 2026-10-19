package nativeproof

import (
	"crypto/sha256"
	"encoding/binary"
	quickrand "math/rand"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"testing/quick"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

func stateSameInventory(t testing.TB, got, want TransitionProposal) {
	t.Helper()
	transitionInventoryMap(t, got, want)
}

func FuzzTransitionStateInventory(f *testing.F) {
	for fault := uint8(0); fault < 11; fault++ {
		f.Add(uint64(fault*17), uint8(fault*3), fault, uint8(fault+1))
	}
	f.Fuzz(func(t *testing.T, layout uint64, selector, fault, permutation uint8) {
		face := stateFace(16, layout%16)
		face.Conditions.CPUID = CPUIDModel
		ops := []stateInstruction{
			stateOp(to.Intent{Operation: to.MoveRegister, Dst: 12, Src: 4}, permutation),
			stateOp(to.Intent{Operation: to.Store, Base: 12, Src: 12, SignedDisp: -8}, permutation),
			stateOp(to.Intent{Operation: to.Load, Base: 12, Dst: 2, SignedDisp: -8}, permutation),
			stateOp(to.Intent{Operation: to.Subtract, Dst: 2, Immediate: 7}, permutation),
			stateOp(to.Intent{Operation: to.CPUID}, 0),
		}
		program := stateExpanded(ops)
		initial := stateInitial(face, layout)
		wants := []stateReference{initial.clone()}
		r := initial.clone()
		for j, op := range program {
			r.referenceExec(t, op.intent, j)
			wants = append(wants, r.clone())
		}
		x := stateArrange(t, program, layout)
		cut := 1 + int(selector)%len(program)
		p := x.proposal(cut)
		c, err := CheckTransition(t.Context(), x.im, face, p, TransitionLimits{})
		if err != nil || c.checked == nil {
			t.Fatal("independently valid inventory refused", err)
		}
		stateAssert(t, c, x, cut, initial, wants[cut], stateBindings(t, c, face, initial))
		proposed, err := ProposeTransition(t.Context(), x.im, p.Cut, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		stateSameInventory(t, proposed, p)
		// A node list is an inventory, not an execution-order assertion.
		rng := rand.New(rand.NewPCG(uint64(permutation), layout))
		rng.Shuffle(len(p.Nodes), func(i, j int) { p.Nodes[i], p.Nodes[j] = p.Nodes[j], p.Nodes[i] })
		c, err = CheckTransition(t.Context(), x.im, face, p, TransitionLimits{})
		if err != nil || c.checked == nil {
			t.Fatal("permuted valid inventory refused", err)
		}
		stateAssert(t, c, x, cut, initial, wants[cut], stateBindings(t, c, face, initial))
		root, err := CheckTransition(t.Context(), x.im, face, x.proposal(0), TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		values := stateBindings(t, root, face, initial)
		stateAssert(t, root, x, 0, initial, initial, values)
		prior, _ := root.Bound()
		continued, err := CheckTransitionContinuation(t.Context(), root, p)
		if err != nil || continued.checked == nil {
			t.Fatal("permuted valid continuation inventory refused", err)
		}
		stateInheritedInputs(t, prior, continued.checked.bound)
		stateAssert(t, continued, x, cut, initial, wants[cut], values)
		bad := x.proposal(cut)
		node := int(permutation) % len(bad.Nodes)
		switch fault % 11 {
		case 0:
			bad.Nodes = append(bad.Nodes[:node], bad.Nodes[node+1:]...)
		case 1:
			bad.Nodes = append(bad.Nodes, TransitionNode{ID: TransitionOccurrenceID(x.pcs[0] + 31), PC: x.pcs[0] + 31, Size: 1})
		case 2:
			bad.Nodes = append(bad.Nodes, bad.Nodes[node])
		case 3:
			bad.Nodes[node].Size++
		case 4:
			bad.Nodes[0].Successors = []TransitionOccurrenceID{bad.Root}
		case 5:
			bad.Entry++
		case 6:
			bad.ImageDigest[permutation%32] ^= 1
		case 7:
			bad.Cut++
		case 8:
			bad.Nodes[node].PC++
		case 9:
			bad.Nodes[cut].Successors = []TransitionOccurrenceID{bad.Root}
		case 10:
			bad.Nodes[0].Successors = append(bad.Nodes[0].Successors, bad.Nodes[0].Successors[0])
		}
		c, err = CheckTransition(t.Context(), x.im, face, bad, TransitionLimits{})
		transitionRefused(t, c, err)
		c, err = CheckTransitionContinuation(t.Context(), root, bad)
		transitionRefused(t, c, err)
	})
}

// Two actual PT_LOADs carry distant blocks. File allocation stays below 16 KiB;
// a 2 GiB rel32 does not turn into a multi-gigabyte backing slice. Both loads use
// distinct file pages with the loader's actual 4 KiB congruence.
func stateSparseELF(entry uint64, first []byte, target uint64, second []byte) []byte {
	secondOff := uint64(0x2000) + target%4096
	raw := elfBytes(first)
	raw = append(raw, make([]byte, int(secondOff)+len(second)-len(raw))...)
	binary.LittleEndian.PutUint64(raw[24:], entry)
	binary.LittleEndian.PutUint64(raw[80:], entry)
	binary.LittleEndian.PutUint16(raw[56:], 2)
	const ph = 120
	binary.LittleEndian.PutUint32(raw[ph:], 1)
	binary.LittleEndian.PutUint32(raw[ph+4:], 5)
	binary.LittleEndian.PutUint64(raw[ph+8:], secondOff)
	binary.LittleEndian.PutUint64(raw[ph+16:], target)
	binary.LittleEndian.PutUint64(raw[ph+32:], uint64(len(second)))
	binary.LittleEndian.PutUint64(raw[ph+40:], uint64(len(second)))
	binary.LittleEndian.PutUint64(raw[ph+48:], 4096)
	copy(raw[secondOff:], second)
	return raw
}

func FuzzTransitionStateSparseRel32(f *testing.F) {
	for _, disp := range []int32{-2147483648, 2147483647, -0x12345678, 0x76543210, -8193, 8193, -8192, 8192, -6, -5, -4, -3, -2, -1, 0, 1, 127, 128} {
		f.Add(disp, uint64(0xfedcba9876543210), uint8(15), uint8(0), uint64(731))
	}
	f.Fuzz(func(t *testing.T, displacement int32, immediate uint64, dst, src uint8, valuation uint64) {
		stateRelativeJump(t, int64(displacement), false, valuation)
		if displacement >= -8192 && displacement <= 8192 {
			return // fully checked by the compact mapping, not an excluded input
		}
		dst, src = dst%16, src%16
		face := stateFace(16, valuation%16)
		initial := stateInitial(face, valuation)
		intents := []to.Intent{
			{Operation: to.MoveImmediate, Dst: dst, Immediate: immediate},
			{Operation: to.Jump, SignedDisp: int64(displacement)},
			{Operation: to.MoveRegister, Dst: src, Src: dst},
		}
		wants := []stateReference{initial.clone()}
		r := initial.clone()
		for j, i := range intents {
			r.referenceExec(t, i, j)
			wants = append(wants, r.clone())
		}
		x := stateLayout{pcs: make([]uint64, 4), encoded: make([][]byte, 4), intents: slices.Clone(intents)}
		for j, i := range intents {
			var err error
			x.encoded[j], err = to.Encode(i, stateEncoding(i, 1))
			if err != nil {
				t.Fatal(err)
			}
		}
		x.encoded[3] = []byte{0x0f, 0x0b}
		x.pcs[0] = 1 << 33
		x.pcs[1] = x.pcs[0] + uint64(len(x.encoded[0]))
		x.pcs[2] = uint64(int64(x.pcs[1])+5) + uint64(int64(displacement))
		x.pcs[3] = x.pcs[2] + uint64(len(x.encoded[2]))
		first := append(slices.Clone(x.encoded[0]), x.encoded[1]...)
		second := append(slices.Clone(x.encoded[2]), x.encoded[3]...)
		raw := stateSparseELF(x.pcs[0], first, x.pcs[2], second)
		x.digest = sha256.Sum256(raw)
		var err error
		x.im, err = NewImage(t.Context(), raw)
		if err != nil {
			t.Fatal(err)
		}
		stateCheckLocated(t, x, face, initial, wants, valuation, true)
		proposed, err := ProposeTransition(t.Context(), x.im, x.pcs[3], TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		stateSameInventory(t, proposed, x.proposal(3))
		// The cut's last byte is present in the file but outside both logical
		// mappings. It must not be borrowed to close the declared boundary.
		truncated := slices.Clone(raw)
		binary.LittleEndian.PutUint64(truncated[152:], uint64(len(second)-1))
		binary.LittleEndian.PutUint64(truncated[160:], uint64(len(second)-1))
		im, err := NewImage(t.Context(), truncated)
		if err != nil {
			t.Fatal(err)
		}
		p := x.proposal(3)
		p.ImageDigest = sha256.Sum256(truncated)
		c, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
		transitionRefused(t, c, err)
		// Relocate the second LOAD without changing the JMP bytes. The actual
		// branch now enters an unmapped gap, even though candidate nodes persist.
		gap := stateSparseELF(x.pcs[0], first, x.pcs[2]+4096, second)
		im, err = NewImage(t.Context(), gap)
		if err != nil {
			t.Fatal(err)
		}
		p.ImageDigest = sha256.Sum256(gap)
		c, err = CheckTransition(t.Context(), im, face, p, TransitionLimits{})
		transitionRefused(t, c, err)
	})
}

// A jump to an unexecuted one-byte NOP admits every relative displacement that
// does not land inside the jump itself. Nearby targets share one actual LOAD;
// distant targets use separate LOADs. A self-target or interior target cannot
// describe this grammar's acyclic non-overlapping executed prefix, regardless of
// how surrounding bytes are arranged, so those cases require refusal instead.
func stateRelativeJump(t testing.TB, displacement int64, short bool, valuation uint64) {
	t.Helper()
	face := stateFace(16, valuation%16)
	initial := stateInitial(face, valuation)
	i := to.Intent{Operation: to.Jump, SignedDisp: displacement}
	want := initial.clone()
	want.referenceExec(t, i, 0)
	form := to.JMPE9
	if short {
		form = to.JMPEB
	}
	encoded, err := to.Encode(i, to.Encoding{Form: form})
	if err != nil {
		t.Fatal(err)
	}
	entry := uint64(1 << 33)
	target := uint64(int64(entry) + int64(len(encoded)) + displacement)
	valid := target < entry || target >= entry+uint64(len(encoded))
	cut := target
	if !valid {
		cut = entry + uint64(len(encoded)) + 1
	}
	var raw []byte
	if displacement < -8192 || displacement > 8192 {
		raw = stateSparseELF(entry, encoded, target, []byte{0x90})
	} else {
		start := min(entry, cut) / 4096 * 4096
		end := max(entry+uint64(len(encoded)), cut+1)
		code := make([]byte, end-start)
		rng := rand.New(rand.NewPCG(valuation, 0x4a554d50))
		for j := range code {
			code[j] = byte(rng.Uint64())
		}
		copy(code[entry-start:], encoded)
		code[cut-start] = 0x90
		raw = elfBytes(code)
		binary.LittleEndian.PutUint64(raw[24:], entry)
		binary.LittleEndian.PutUint64(raw[80:], start)
	}
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	x := stateLayout{im: im, digest: sha256.Sum256(raw), pcs: []uint64{entry, cut}, encoded: [][]byte{encoded, {0x90}}, intents: []to.Intent{i}}
	if valid {
		stateCheckLocated(t, x, face, initial, []stateReference{initial, want}, 0, true)
		proposed, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		stateSameInventory(t, proposed, x.proposal(1))
		return
	}
	p := x.proposal(1)
	p.Nodes[0].Successors[0] = TransitionOccurrenceID(target) // actual encoded edge, not the desired cut
	c, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
	transitionRefused(t, c, err)
	// Even a rejected-distance invocation contains a constructed positive case.
	stateRelativeJump(t, 0, short, valuation)
}

func FuzzTransitionStateRel8(f *testing.F) {
	for displacement := -128; displacement <= 127; displacement++ {
		f.Add(int8(displacement), uint64(displacement)*0x123456789abcdef)
	}
	f.Fuzz(func(t *testing.T, displacement int8, valuation uint64) {
		stateRelativeJump(t, int64(displacement), true, valuation)
	})
}

func FuzzTransitionStateLongFrontier(f *testing.F) {
	for _, n := range []uint16{0, 1, 21, 32, 65, 128, 257, 1024, 2047, 2048} {
		f.Add(n, uint64(n)*0x123456789abcdef, uint8(n), uint16(n/2))
	}
	f.Fuzz(func(t *testing.T, length uint16, valuation uint64, form uint8, split uint16) {
		face := stateFace(16, valuation%16)
		// A first overflowing inventory suffices to exercise the actual supplied
		// bound. Never turn its accepted prefix into a claim about a longer tail.
		ops := make([]stateInstruction, min(int(length), statePopulationInstructions/2+1))
		for j := range ops {
			// Avoid an artificial expression-depth failure: this property moves
			// the graph frontier, not the existing expression-depth frontier.
			ops[j] = stateOp(to.Intent{Operation: to.MoveImmediate, Dst: uint8(j % 16), Immediate: valuation + uint64(j)*0xfedcba987654321}, form)
		}
		initial := stateInitial(face, valuation)
		stateCheckProgram(t, ops, face, initial, valuation, uint64(split), false)
		if length == 0 || 2*int(length)+1 > statePopulationInstructions {
			return // empty entry, or the counted overflow already checked above
		}
		program := stateExpanded(ops)
		wants := []stateReference{initial.clone()}
		r := initial.clone()
		for j, op := range program {
			r.referenceExec(t, op.intent, j)
			wants = append(wants, r.clone())
		}
		x := stateArrange(t, program, valuation)
		p := x.proposal(len(program))
		limits := TransitionLimits{RelationLimits: RelationLimits{Instructions: len(program) + 1}}
		c, err := CheckTransition(t.Context(), x.im, face, p, limits)
		if err != nil || c.checked == nil || len(c.checked.bound.Instructions) != len(program) {
			t.Fatal("exact graph frontier did not accept entire chain", err)
		}
		stateAssert(t, c, x, len(program), initial, wants[len(program)], stateBindings(t, c, face, initial))
		root, err := CheckTransition(t.Context(), x.im, face, x.proposal(0), limits)
		if err != nil {
			t.Fatal(err)
		}
		values := stateBindings(t, root, face, initial)
		stateAssert(t, root, x, 0, initial, initial, values)
		original, _ := root.Bound()
		cut := 1 + int(split)%len(program)
		root, err = CheckTransitionContinuation(t.Context(), root, x.proposal(cut))
		if err != nil {
			t.Fatal("local segment at exact graph frontier refused", err)
		}
		stateInheritedInputs(t, original, root.checked.bound)
		stateAssert(t, root, x, cut, initial, wants[cut], values)
		if cut < len(program) {
			root, err = CheckTransitionContinuation(t.Context(), root, p)
			if err != nil {
				t.Fatal("inherited exact graph frontier refused", err)
			}
			stateInheritedInputs(t, original, root.checked.bound)
			stateAssert(t, root, x, len(program), initial, wants[len(program)], values)
		}
		if !reflect.DeepEqual(c.checked.bound.Instructions, root.checked.bound.Instructions) {
			t.Fatal("long continuation silently truncated coverage")
		}
		limits.Instructions--
		c, err = CheckTransition(t.Context(), x.im, face, p, limits)
		stateInventoryOverflow(t, c, err, len(p.Nodes), limits.Instructions)
		root, err = CheckTransition(t.Context(), x.im, face, x.proposal(0), limits)
		if err != nil {
			t.Fatal(err)
		}
		stateAssert(t, root, x, 0, initial, initial, stateBindings(t, root, face, initial))
		c, err = CheckTransitionContinuation(t.Context(), root, p)
		stateInventoryOverflow(t, c, err, len(p.Nodes), limits.Instructions)
	})
}

func FuzzTransitionStatePartitions(f *testing.F) {
	for _, n := range []int{4, 9, 16, 65, 129} {
		data := make([]byte, n*32)
		for j := 0; j < n; j++ {
			r := data[j*32 : (j+1)*32]
			r[0], r[1], r[2], r[3], r[4], r[5] = byte(j%12), byte(j), byte(15-j), byte(j%16), byte(j), byte(31-j)
			binary.LittleEndian.PutUint64(r[8:], 0x80000000+uint64(j)*0x123456789abcdef)
			binary.LittleEndian.PutUint64(r[16:], 0xfedcba9876543210+uint64(j))
			binary.LittleEndian.PutUint32(r[24:], 0x7fffffff-uint32(j)*7919)
		}
		f.Add(data, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, uint64(n)*0x123456789abcdef, uint64(n))
	}
	f.Add([]byte{8}, []byte{0}, uint64(0x8123456789abcdef), uint64(987))
	f.Fuzz(func(t *testing.T, data, cutBits []byte, valuation, layout uint64) {
		ops := stateGenerated(data)
		var cuts []int
		for j := 1; j < 2*len(ops); j++ {
			if (j-1)/8 < len(cutBits) && cutBits[(j-1)/8]&(1<<((j-1)%8)) != 0 {
				cuts = append(cuts, j)
			}
		}
		face := stateFace(1<<31, valuation%(1<<31))
		// Every subset of logical boundaries within the actual instruction limit is
		// representable, independently of command bytes, layout and entry values.
		// Each intermediate inherited state is checked, not just the last cut.
		stateCheckProgram(t, ops, face, stateInitial(face, valuation), layout, 0, false, cuts)
	})
}

// These direct quick.Check bodies complement the byte-slice fuzzers: Go's fuzz
// minimizer may spend a short campaign shrinking one long interesting program.
// Fixed bounded random populations ensure full programs and dense partitions are
// actually exercised even in a seed-only run, without a long fuzzing requirement.
func TestTransitionStateWholeProgramProperty(t *testing.T) {
	t.Parallel()
	if err := quick.Check(func(programSeed, valuation, layout, cuts uint64, length uint8) bool {
		rng := rand.New(rand.NewPCG(programSeed, 0x50524f4752414d))
		data := make([]byte, 32*(1+int(length)))
		for j := 0; j < len(data); j += 8 {
			binary.LittleEndian.PutUint64(data[j:], rng.Uint64())
		}
		face := stateFace(1<<31, valuation%(1<<31))
		stateCheckProgram(t, stateGenerated(data), face, stateInitial(face, valuation), layout, cuts, false)
		return true
	}, &quick.Config{MaxCount: 64, Rand: quickrand.New(quickrand.NewSource(0x5154415445))}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionStatePartitionProperty(t *testing.T) {
	t.Parallel()
	if err := quick.Check(func(programSeed, valuation, layout, cutLow, cutHigh uint64, length uint8) bool {
		rng := rand.New(rand.NewPCG(programSeed, 0x4355545354415445))
		data := make([]byte, 32*(1+int(length)))
		for j := 0; j < len(data); j += 8 {
			binary.LittleEndian.PutUint64(data[j:], rng.Uint64())
		}
		ops := stateGenerated(data)
		var cuts []int
		for j := 1; j < 2*len(ops); j++ {
			bitset, bit := cutLow, j-1
			if bit >= 64 {
				bitset, bit = cutHigh, bit-64
			}
			if bitset&(uint64(1)<<bit) != 0 {
				cuts = append(cuts, j)
			}
		}
		face := stateFace(1<<31, valuation%(1<<31))
		stateCheckProgram(t, ops, face, stateInitial(face, valuation), layout, 0, false, cuts)
		return true
	}, &quick.Config{MaxCount: 32, Rand: quickrand.New(quickrand.NewSource(0x504152544954494f))}); err != nil {
		t.Fatal(err)
	}
}

// This resource oracle concerns the native expression constructor's depth
// policy, not the minimum mathematical depth of an equivalent expression. A
// dependent binary LEA/SUB adds one level; SUB additionally constructs its ZF
// comparison. The accepted predecessor's projected expression height is checked
// independently before any depth refusal is credited. No other budget refusal
// is allowed, and every accepted root/intermediate state has the full oracle.
func FuzzTransitionStateDependentDepth(f *testing.F) {
	for _, n := range []int{0, 1, 31, 65, 257, 510, 511, 512, 1024} {
		chain := make([]byte, 5*n)
		for j := 0; j < n; j++ {
			chain[j*5] = byte(j % 2)
			binary.LittleEndian.PutUint32(chain[j*5+1:], 0x80000000+uint32(j)*7919)
		}
		values := make([]byte, 8+128+1+80)
		for j := range values {
			values[j] = byte(j*37 + n)
		}
		binary.LittleEndian.PutUint64(values[8:], 1<<63+uint64(n))
		f.Add(chain, uint16(510+511*(n%16)), values, uint64(n), n%2 != 0)
	}
	f.Fuzz(func(t *testing.T, chain []byte, requestedDepth uint16, valuation []byte, layout uint64, pointer bool) {
		depth := 2 + int(requestedDepth%511) // all usable supplied depths, through 512
		// The packed field represents every (depth, register) pair: 511*16
		// combinations fit independently in uint16, unlike a correlated selector.
		register := uint8(requestedDepth/511) % 16
		face := stateFace(16, layout%16)
		face.Origin.Min, face.Origin.Max = 1<<43, 1<<44
		face.Envelope = RelativeSpan{-1 << 41, 1 << 41}
		initial := stateRawInitial(face, valuation)
		var ops []stateInstruction
		copyCount := 0
		if pointer {
			ops = append(ops, stateOp(to.Intent{Operation: to.MoveRegister, Dst: register, Src: 4}, 0))
			copyCount = 1
		}
		height, fault := 1, false
		for len(chain) != 0 {
			var record [5]byte
			n := copy(record[:], chain)
			chain = chain[n:]
			payload := int64(int32(binary.LittleEndian.Uint32(record[1:])))
			i := to.Intent{Operation: to.LEA, Dst: register, Base: register, SignedDisp: payload}
			needed := height + 1
			if record[0]&1 != 0 {
				i = to.Intent{Operation: to.Subtract, Dst: register, Immediate: uint64(payload)}
				needed++
			}
			ops = append(ops, stateOp(i, record[0]>>1))
			height++
			if needed > depth {
				fault = true
				break // actual depth frontier; no claim about the remaining chain
			}
		}
		program := stateExpanded(ops)
		wants := []stateReference{initial.clone()}
		r := initial.clone()
		for j, op := range program {
			r.referenceExec(t, op.intent, j)
			wants = append(wants, r.clone())
		}
		x := stateArrange(t, program, layout)
		limits := TransitionLimits{RelationLimits: RelationLimits{Instructions: len(program) + 1, Nodes: 128*len(program) + 4096, Work: 20_000_000, Depth: depth}}
		cut := len(program)
		if fault {
			cut -= 2 // boundary is the first instruction whose constructor exceeds depth
		}
		direct, err := CheckTransition(t.Context(), x.im, face, x.proposal(cut), limits)
		if err != nil {
			t.Fatal("dependent prefix below the counted depth frontier refused", err)
		}
		values := stateBindings(t, direct, face, initial)
		stateAssert(t, direct, x, cut, initial, wants[cut], values)
		if got, want := stateTermHeight(direct.checked.bound.Registers[register].Value, nil), 1+cut/2-copyCount; got != want {
			t.Fatalf("constructor-depth premise changed: got %d want %d", got, want)
		}
		root, err := CheckTransition(t.Context(), x.im, face, x.proposal(0), limits)
		if err != nil {
			t.Fatal(err)
		}
		original, _ := root.Bound()
		values = stateBindings(t, root, face, initial)
		stateAssert(t, root, x, 0, initial, initial, values)
		if cut > 0 {
			for _, next := range slices.Compact([]int{max(1, cut/2), cut}) {
				root, err = CheckTransitionContinuation(t.Context(), root, x.proposal(next))
				if err != nil {
					t.Fatal("inherited dependent prefix below depth frontier refused", err)
				}
				stateInheritedInputs(t, original, root.checked.bound)
				stateAssert(t, root, x, next, initial, wants[next], values)
			}
		}
		assertTransitionAlpha(t, direct, root)
		if fault {
			c, err := CheckTransition(t.Context(), x.im, face, x.proposal(len(program)), limits)
			stateExpressionDepthRefused(t, c, err, x.pcs[cut])
			c, err = CheckTransitionContinuation(t.Context(), root, x.proposal(len(program)))
			stateExpressionDepthRefused(t, c, err, x.pcs[cut])
		}
	})
}
