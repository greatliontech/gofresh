package nativeproof

import (
	"encoding/binary"
	"math"
	"math/rand/v2"
	"reflect"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// generatedDAG specifies a graph before encoding it. Logical blocks form a
// forward DAG, but their physical layout is shuffled, so neither increasing PCs
// nor discovery order is a valid substitute for a topological traversal. Each
// block can reach its logical successor and another later block, exercising
// shared destinations, joins and repeated growth of the discovered inventory.
func generatedDAG(seed uint64, count int) ([]byte, []int, map[uint64]Node) {
	r := rand.New(rand.NewPCG(seed, seed^0xbb67ae8584caa73b))
	code := make([]byte, 16*(count+1))
	for j := range code {
		code[j] = 0xcc // Unreachable gaps must not become proof boundaries or paths.
	}
	positions := r.Perm(count)
	for j := range positions {
		positions[j] = 16 * (positions[j] + 1)
	}
	want := make(map[uint64]Node)
	emit := func(offset int, bytes []byte, targets ...int) {
		copy(code[offset:], bytes)
		n := Node{PC: testEntry + uint64(offset), Size: uint8(len(bytes))}
		for _, target := range targets {
			n.Successors = append(n.Successors, testEntry+uint64(target))
		}
		want[n.PC] = n
	}
	jump := func(op []byte, offset, target int) []byte {
		encoded := append([]byte(nil), op...)
		encoded = append(encoded, make([]byte, 4)...)
		binary.LittleEndian.PutUint32(encoded[len(op):], uint32(int32(target-offset-len(encoded))))
		return encoded
	}
	emit(0, []byte{0x31, 0xc0}, 2) // Defined RAX and flags; no inputs required.
	emit(2, jump([]byte{0xe9}, 2, positions[0]), positions[0])
	for logical, base := range positions {
		if logical == count-1 {
			emit(base, []byte{0xc3})
			continue
		}
		mov := []byte{0xb9, 0, 0, 0, 0} // MOV ECX, imm32 leaves RAX and flags intact.
		binary.LittleEndian.PutUint32(mov[1:], r.Uint32())
		emit(base, mov, base+5)
		other := positions[logical+1+r.IntN(count-logical-1)]
		emit(base+5, jump([]byte{0x0f, 0x84}, base+5, other), base+11, other)
		emit(base+11, jump([]byte{0xe9}, base+11, positions[logical+1]), positions[logical+1])
	}
	return code, positions, want
}

func assertGraphPath(t testing.TB, r *Refusal, nodes map[uint64]Node) {
	t.Helper()
	if r.Path[0] != testEntry || r.Path[len(r.Path)-1] != r.PC {
		t.Fatalf("invalid refusal endpoints: %+v", r)
	}
	for j := 1; j < len(r.Path); j++ {
		from, to := r.Path[j-1], r.Path[j]
		found := false
		for _, next := range nodes[from].Successors {
			found = found || next == to
		}
		if !found {
			t.Fatalf("refusal path invents edge %#x -> %#x: %+v", from, to, r)
		}
	}
}

func checkGeneratedDAG(t testing.TB, seed uint64, count int) {
	t.Helper()
	code, positions, want := generatedDAG(seed, count)
	im := image(t, code)
	f := face(Masks{}, Masks{RAX: math.MaxUint64})
	p, err := Propose(t.Context(), im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != len(want) {
		t.Fatalf("reachable inventory size: got %d want %d", len(p.Nodes), len(want))
	}
	seen := make(map[uint64]bool)
	for _, n := range p.Nodes {
		if seen[n.PC] || !reflect.DeepEqual(n, want[n.PC]) {
			t.Fatalf("wrong reachable instruction/edges: got %+v want %+v", n, want[n.PC])
		}
		seen[n.PC] = true
	}
	r := rand.New(rand.NewPCG(seed, 0x3c6ef372fe94f82b))
	r.Shuffle(len(p.Nodes), func(a, b int) { p.Nodes[a], p.Nodes[b] = p.Nodes[b], p.Nodes[a] })
	c, err := Check(t.Context(), im, testEntry, f, p)
	if err != nil {
		t.Fatal(err)
	}
	bound, ok := c.Bound()
	if !ok || len(bound.Instructions) != len(want) {
		t.Fatal("missing checked coverage")
	}
	for _, span := range bound.Instructions {
		n, exists := want[span.Start]
		if !exists || span.End != span.Start+uint64(n.Size) || !seen[span.Start] {
			t.Fatalf("wrong checked extent: %+v", span)
		}
		delete(seen, span.Start)
	}
	for j, n := range p.Nodes {
		if len(n.Successors) == 2 {
			p.Nodes[j].Successors = p.Nodes[j].Successors[:1]
			bad, err := Check(t.Context(), im, testEntry, f, p)
			refusal := requireRefusal(t, bad, err, "proposal-inventory")
			assertGraphPath(t, refusal, want)
			break
		}
	}
	if count > 1 {
		// A tainted logical block remains arbitrary along the sequential path to
		// the return. Independent diamonds below exercise disagreement between
		// separately completing branches in both predecessor arrival orders.
		tainted := append([]byte(nil), code...)
		base := positions[r.IntN(count-1)]
		copy(tainted[base:], []byte{0x89, 0xd8, 0x90, 0x90, 0x90})
		badImage := image(t, tainted)
		q, err := Propose(t.Context(), badImage, testEntry, f)
		if err != nil {
			t.Fatal(err)
		}
		bad, err := Check(t.Context(), badImage, testEntry, f, q)
		refusal := requireRefusal(t, bad, err, "result-input-bound")
		if refusal.PC != testEntry+uint64(positions[count-1]) {
			t.Fatalf("wrong return refusal: %+v", refusal)
		}
		taintedGraph := make(map[uint64]Node)
		for _, n := range q.Nodes {
			taintedGraph[n.PC] = n
		}
		assertGraphPath(t, refusal, taintedGraph)

		// A branch into a decoded MOV's interior is an overlapping instruction
		// entrance, regardless of the layout or the proposal's node order.
		overlap := append([]byte(nil), code...)
		base = positions[0]
		binary.LittleEndian.PutUint32(overlap[base+7:], uint32(int32((base+1)-(base+11))))
		bad, err = prove(t, image(t, overlap), testEntry, f)
		refusal = requireRefusal(t, bad, err, "instruction-overlap")
		original := want[testEntry+uint64(base+5)]
		changed := original
		changed.Successors = []uint64{testEntry + uint64(base+11), testEntry + uint64(base+1)}
		want[changed.PC] = changed
		assertGraphPath(t, refusal, want)
		want[original.PC] = original
	}
	// Replacing the terminal return with a back edge makes the reachable graph
	// cyclic. No traversal-order or partial topological result can authorize it.
	cyclic := append([]byte(nil), code...)
	last := positions[count-1]
	cyclic[last] = 0xe9
	binary.LittleEndian.PutUint32(cyclic[last+1:], uint32(int32(positions[0]-last-5)))
	bad, err := prove(t, image(t, cyclic), testEntry, f)
	refusal := requireRefusal(t, bad, err, "acyclic-control")
	pc := testEntry + uint64(last)
	want[pc] = Node{PC: pc, Size: 5, Successors: []uint64{testEntry + uint64(positions[0])}}
	assertGraphPath(t, refusal, want)
}

func TestGeneratedControlFlow(t *testing.T) {
	for _, count := range []int{1, 2, 3, 7, 31, 73} {
		for seed := uint64(0); seed < 8; seed++ {
			checkGeneratedDAG(t, seed, count)
		}
	}
	for seed := uint64(0); seed < 32; seed++ {
		checkGeneratedDiamonds(t, seed)
	}
}

// runDiamond is a concrete test oracle for this fixture grammar, not an abstract
// definedness interpreter. It follows the actual mapped/decoded branch and
// returns RBX at RET; it asserts no machine effects or execution provenance.
func runDiamond(t testing.TB, im *Image, rax, rcx uint64) (uint64, []uint64) {
	t.Helper()
	var trace []uint64
	seen := make(map[uint64]bool)
	rbx := uint64(0xfeedface) // Both arms must overwrite arbitrary entry RBX.
	zero, compared := false, false
	for pc := testEntry; ; {
		if seen[pc] {
			t.Fatal("diamond fixture contains a concrete cycle")
		}
		seen[pc] = true
		trace = append(trace, pc)
		encoded, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		i, err := x86asm.Decode(encoded, 64)
		if err != nil || i.Len <= 0 {
			t.Fatalf("diamond decode at %#x: %v", pc, err)
		}
		next := pc + uint64(i.Len)
		switch i.Op {
		case x86asm.CMP:
			if i.Args[0] != x86asm.RAX || i.Args[1] != x86asm.Imm(0) {
				t.Fatalf("unexpected fixture comparison: %v", i)
			}
			zero, compared = rax == 0, true
		case x86asm.JE, x86asm.JMP:
			rel, ok := i.Args[0].(x86asm.Rel)
			if !ok || i.Op == x86asm.JE && !compared {
				t.Fatalf("unexpected fixture branch: %v", i)
			}
			if i.Op == x86asm.JMP || zero {
				// Fixture addresses and displacements fit signed 64-bit arithmetic.
				target := int64(next) + int64(rel)
				if target < 0 {
					t.Fatal("negative fixture branch target")
				}
				next = uint64(target)
			}
		case x86asm.MOV:
			if i.Args[0] != x86asm.RBX || i.Args[1] != x86asm.RCX {
				t.Fatalf("unexpected fixture move: %v", i)
			}
			rbx = rcx
		case x86asm.XOR:
			if i.Args[0] != x86asm.RBX || i.Args[1] != x86asm.RBX {
				t.Fatalf("unexpected fixture XOR: %v", i)
			}
			rbx, zero = 0, true
		case x86asm.NOP:
		case x86asm.RET:
			return rbx, trace
		default:
			t.Fatalf("unexpected diamond instruction: %v", i)
		}
		pc = next
	}
}

func checkDiamondJoin(t testing.TB, code []byte, unknownRAX uint64, unknownEarlier bool) {
	t.Helper()
	im := image(t, code)
	f := face(Masks{RAX: math.MaxUint64}, Masks{RBX: math.MaxUint64})
	p, err := Propose(t.Context(), im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	// These entry states agree on every declared input bit but have different
	// return values. The same branch must execute for both, using actual decoded
	// lengths and targets rather than assuming the handwritten byte offsets.
	a, unknownPath := runDiamond(t, im, unknownRAX, 0)
	b, otherUnknownPath := runDiamond(t, im, unknownRAX, math.MaxUint64)
	if a != 0 || b != math.MaxUint64 || !reflect.DeepEqual(unknownPath, otherUnknownPath) {
		t.Fatal("fixture did not expose an undeclared-RCX result dependence")
	}
	knownA, knownPath := runDiamond(t, im, 1-unknownRAX, 0)
	knownB, otherKnownPath := runDiamond(t, im, 1-unknownRAX, math.MaxUint64)
	if knownA != 0 || knownB != 0 || !reflect.DeepEqual(knownPath, otherKnownPath) {
		t.Fatal("fixture's independent known branch depends on RCX")
	}
	ret := unknownPath[len(unknownPath)-1]
	if ret != knownPath[len(knownPath)-1] {
		t.Fatal("fixture branches do not share a return")
	}
	order := make(map[uint64]int)
	nodes := make(map[uint64]Node)
	for j, n := range p.Nodes {
		order[n.PC] = j
		nodes[n.PC] = n
	}
	unknownPredecessor := unknownPath[len(unknownPath)-2]
	knownPredecessor := knownPath[len(knownPath)-2]
	if unknownPredecessor == knownPredecessor || (order[unknownPredecessor] < order[knownPredecessor]) != unknownEarlier {
		t.Fatal("fixture does not exercise its claimed independent predecessor arrival order")
	}
	c, err := Check(t.Context(), im, testEntry, f, p)
	refusal := requireRefusal(t, c, err, "result-input-bound")
	if refusal.PC != ret {
		t.Fatalf("result dependence refused at %#x, want decoded return %#x", refusal.PC, ret)
	}
	assertGraphPath(t, refusal, nodes)

	// Positive control: declaring RCX defines both branch results, though they
	// remain different functions of the admitted inputs.
	f.Inputs[RCX] = math.MaxUint64
	p.Interface = f
	if _, err := Check(t.Context(), im, testEntry, f, p); err != nil {
		t.Fatalf("both branches input-defined: %v", err)
	}
	// Positive control: replacing the single MOV with XOR defines both branches
	// without declaring RCX. The full mapped-byte proof is rebuilt for that image.
	defined := append([]byte(nil), code...)
	replaced := false
	for _, pc := range unknownPath {
		encoded, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		i, err := x86asm.Decode(encoded, 64)
		if err != nil {
			t.Fatal(err)
		}
		if i.Op == x86asm.MOV {
			if replaced || i.Len != 3 {
				t.Fatal("fixture must contain one three-byte MOV on the unknown path")
			}
			copy(defined[pc-testEntry:], []byte{0x48, 0x31, 0xdb})
			replaced = true
		}
	}
	if !replaced {
		t.Fatal("fixture has no unknown source to replace")
	}
	f.Inputs[RCX] = 0
	if _, err := prove(t, image(t, defined), testEntry, f); err != nil {
		t.Fatalf("both branches constant-defined: %v", err)
	}
}

func TestDiamondJoinDependsOnBothPredecessors(t *testing.T) {
	t.Run("unknown-earlier", func(t *testing.T) {
		checkDiamondJoin(t, hexBytes(t, "4883f80074054889cbeb064831db909090c3"), 1, true)
	})
	t.Run("unknown-later", func(t *testing.T) {
		checkDiamondJoin(t, hexBytes(t, "4883f80074054831dbeb064889cb909090c3"), 0, false)
	})
}

// Independent arms never visit each other. Padding controls their completion
// order; swapping branch direction and physical layout varies that order without
// making either arm a sequential tail of the other.
func checkGeneratedDiamonds(t testing.TB, seed uint64) {
	t.Helper()
	r := rand.New(rand.NewPCG(seed, seed^0xa54ff53a5f1d36f1))
	for _, unknownEarlier := range []bool{true, false} {
		code := make([]byte, 97)
		for j := range code {
			code[j] = 0xcc
		}
		unknown, known := 32, 64
		if r.IntN(2) == 0 {
			unknown, known = known, unknown
		}
		unknownRAX := uint64(r.IntN(2))
		taken, fallthroughTarget := unknown, known
		if unknownRAX == 1 {
			taken, fallthroughTarget = known, unknown
		}
		copy(code, []byte{0x48, 0x83, 0xf8, 0, 0x0f, 0x84})
		binary.LittleEndian.PutUint32(code[6:], uint32(int32(taken-10)))
		code[10] = 0xe9
		binary.LittleEndian.PutUint32(code[11:], uint32(int32(fallthroughTarget-15)))
		short := r.IntN(3)
		long := short + 4 + r.IntN(4)
		unknownPadding, knownPadding := short, long
		if !unknownEarlier {
			unknownPadding, knownPadding = long, short
		}
		for _, arm := range []struct {
			base, padding int
			op            []byte
		}{
			{unknown, unknownPadding, []byte{0x48, 0x89, 0xcb}},
			{known, knownPadding, []byte{0x48, 0x31, 0xdb}},
		} {
			copy(code[arm.base:], arm.op)
			at := arm.base + len(arm.op)
			for j := 0; j < arm.padding; j++ {
				code[at] = 0x90
				at++
			}
			code[at] = 0xe9
			binary.LittleEndian.PutUint32(code[at+1:], uint32(int32(96-at-5)))
		}
		code[96] = 0xc3
		checkDiamondJoin(t, code, unknownRAX, unknownEarlier)
	}
}

func TestConditionalEdgesShareDestination(t *testing.T) {
	im := image(t, hexBytes(t, "31c00f8400000000c3"))
	f := face(Masks{}, Masks{RAX: math.MaxUint64})
	p, err := Propose(t.Context(), im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(t.Context(), im, testEntry, f, p); err != nil {
		t.Fatal(err)
	}
	for j := range p.Nodes {
		if p.Nodes[j].PC == testEntry+2 {
			if !reflect.DeepEqual(p.Nodes[j].Successors, []uint64{testEntry + 8, testEntry + 8}) {
				t.Fatal("conditional edge multiplicity lost")
			}
			p.Nodes[j].Successors = p.Nodes[j].Successors[:1]
			bad, err := Check(t.Context(), im, testEntry, f, p)
			requireRefusal(t, bad, err, "proposal-inventory")
			return
		}
	}
	t.Fatal("missing conditional instruction")
}

func TestProposalSuccessorAppendDoesNotMutateOtherNodes(t *testing.T) {
	im := image(t, hexBytes(t, kernels[2].code))
	f := face(kernels[2].inputs, kernels[2].results)
	p, err := Propose(t.Context(), im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range p.Nodes {
		if len(n.Successors) != 0 {
			// Appending to a borrowed successor slice may allocate a new slice,
			// but cannot overwrite another instruction's independently owned edges.
			grown := append(n.Successors, math.MaxUint64)
			grown[len(grown)-1] = testEntry
		}
	}
	if _, err := Check(t.Context(), im, testEntry, f, p); err != nil {
		t.Fatalf("appending to one successor slice changed another node: %v", err)
	}
}

func FuzzGeneratedControlFlow(f *testing.F) {
	f.Add(uint64(0), uint8(0))
	f.Add(uint64(1), uint8(1))
	f.Add(uint64(2), uint8(7))
	f.Add(uint64(math.MaxUint64), uint8(63))
	f.Fuzz(func(t *testing.T, seed uint64, size uint8) {
		checkGeneratedDAG(t, seed, 1+int(size)%64)
		checkGeneratedDiamonds(t, seed)
	})
}
