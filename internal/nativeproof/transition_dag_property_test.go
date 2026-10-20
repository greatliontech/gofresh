package nativeproof

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// Node intent, logical successors and data targets precede byte generation. Each
// block has an explicit fallthrough JMP, allowing backward physical DAG edges.
type dagOp struct {
	i           to.Intent
	e           to.Encoding
	next, taken int
	address     uint64
	// Structural-only terminal intent. No reference execution rule exists for it.
	boundary []byte
}
type dagLayout struct {
	stateLayout
	edges       [][]int
	callReturns map[int]int
}

func dagArrange(t testing.TB, ops []dagOp, seed uint64) dagLayout {
	t.Helper()
	n := len(ops)
	permutation := rand.New(rand.NewPCG(seed, 0x444147)).Perm(n + 1)
	for j, p := range permutation {
		if p == 0 {
			permutation[0], permutation[j] = 0, permutation[0]
			break
		}
	}
	return dagArrangePermutation(t, ops, permutation)
}

// A caller-supplied permutation ranges over the full placement product. Even
// the entry may occupy a nonfirst physical slot; the ELF header binds its PC.
func dagArrangePermutation(t testing.TB, ops []dagOp, permutation []int) dagLayout {
	t.Helper()
	n := len(ops)
	if len(permutation) != n+1 {
		t.Fatal("layout permutation size")
	}
	seenPositions := make([]bool, n+1)
	for _, j := range permutation {
		if j < 0 || j > n || seenPositions[j] {
			t.Fatal("invalid layout permutation")
		}
		seenPositions[j] = true
	}
	position := make([]int, n+1)
	for j, logical := range permutation {
		position[logical] = j * 32
	}
	x := dagLayout{stateLayout: stateLayout{pcs: make([]uint64, 2*n+1), encoded: make([][]byte, 2*n+1), intents: make([]to.Intent, 2*n)}, edges: make([][]int, 2*n+1)}
	code := make([]byte, 32*(n+1))
	for j := range code {
		code[j] = 0xcc
	}
	for j, op := range ops {
		pc := testEntry + uint64(position[j])
		if op.boundary != nil {
			x.pcs[2*j], x.encoded[2*j] = pc, slices.Clone(op.boundary)
			copy(code[position[j]:], op.boundary)
			continue
		}
		i := op.i
		b, err := to.Encode(i, op.e)
		if err != nil {
			t.Fatal(err)
		}
		if i.Operation == to.Branch || i.Operation == to.Call {
			i.SignedDisp = int64(testEntry) + int64(position[op.taken]) - int64(pc) - int64(len(b))
		}
		if op.address != 0 {
			i.SignedDisp = int64(op.address) - int64(pc) - int64(len(b))
		}
		b, err = to.Encode(i, op.e)
		if err != nil {
			t.Fatal(err)
		}
		x.pcs[2*j], x.encoded[2*j], x.intents[2*j] = pc, b, i
		x.edges[2*j] = []int{2*j + 1}
		if i.Operation == to.Call {
			x.edges[2*j] = []int{2 * op.taken}
		}
		if i.Operation == to.Return {
			x.edges[2*j] = nil
		}
		if i.Operation == to.Branch {
			x.edges[2*j] = append(x.edges[2*j], 2*op.taken)
		}
		pc += uint64(len(b))
		jump := to.Intent{Operation: to.Jump, SignedDisp: int64(testEntry) + int64(position[op.next]) - int64(pc+5)}
		jb, err := to.Encode(jump, to.Encoding{Form: to.JMPE9})
		if err != nil {
			t.Fatal(err)
		}
		x.pcs[2*j+1], x.encoded[2*j+1], x.intents[2*j+1], x.edges[2*j+1] = pc, jb, jump, []int{2 * op.next}
		copy(code[position[j]:], append(slices.Clone(b), jb...))
	}
	x.pcs[2*n], x.encoded[2*n] = testEntry+uint64(position[n]), []byte{0x0f, 0x0b}
	copy(code[position[n]:], x.encoded[2*n])
	loads := imageStateLoads()
	for j := range loads {
		loads[j].file = uint64((len(code)+4095)/4096*4096 + 0x2000 + j*4096)
	}
	raw := transitionImageELF(t, code, loads)
	binary.LittleEndian.PutUint64(raw[24:], x.pcs[0])
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	x.im, x.digest = im, sha256.Sum256(raw)
	x.mappings = append([]interfaceMapping{{start: testEntry, end: testEntry + uint64(len(code)), read: true, execute: true}}, loads...)
	return x
}

func (x dagLayout) proposal(cut int) TransitionProposal {
	p := TransitionProposal{ImageDigest: x.digest, Entry: x.pcs[0], Cut: x.pcs[cut], Root: 1}
	seen := map[int]bool{}
	queue := []int{0}
	for len(queue) > 0 {
		j := queue[0]
		queue = queue[1:]
		if seen[j] {
			continue
		}
		seen[j] = true
		n := TransitionNode{ID: TransitionOccurrenceID(j + 1), PC: x.pcs[j], Size: uint8(len(x.encoded[j]))}
		if j != cut {
			if j < len(x.intents) && to.RequiresExpansion(x.intents[j]) {
				n.Expanded = true
			}
			for _, next := range x.edges[j] {
				n.Successors = append(n.Successors, TransitionOccurrenceID(next+1))
				queue = append(queue, next)
			}
		}
		p.Nodes = append(p.Nodes, n)
	}
	return p
}

func dagCondition(t testing.TB, cc uint8, flags [6]bool) bool {
	t.Helper()
	c, z, l := flags[0], flags[1], flags[3] != flags[2]
	switch cc {
	case 2:
		return c
	case 3:
		return !c
	case 4:
		return z
	case 5:
		return !z
	case 6:
		return c || z
	case 7:
		return !c && !z
	case 10:
		return flags[5]
	case 11:
		return !flags[5]
	case 12:
		return l
	case 13:
		return !l
	case 14:
		return z || l
	case 15:
		return !z && !l
	}
	t.Fatal("invalid reference condition", cc)
	return false
}

type dagEvent struct {
	pc    uint64
	kind  string
	start int64
	width int
	image bool
}

func dagAssert(t testing.TB, c TransitionCertificate, x dagLayout, cut int, face TransitionInterface, initial stateReference, inactive []byte) {
	t.Helper()
	// Semantic occurrences, not reported effects, index independent 128-bit
	// totalizations. Zero padding is an explicit test input, never a fallback for
	// an unrecognized symbolic variable. Every byte can vary independently.
	totalizations := map[uint64][4]uint32{}
	for j, i := range x.intents {
		if i.Operation != to.CPUID {
			continue
		}
		var raw [16]byte
		n := copy(raw[:], inactive)
		inactive = inactive[n:]
		var tuple [4]uint32
		for k := range tuple {
			tuple[k] = binary.LittleEndian.Uint32(raw[k*4:])
		}
		totalizations[x.pcs[j]] = tuple
	}
	r := initial.clone()
	r.loads = x.mappings
	var want []dagEvent
	for j, steps := 0, 0; j != cut; steps++ {
		if steps >= len(x.pcs) {
			t.Fatal("reference path does not reach requested cut")
		}
		i := x.intents[j]
		want = append(want, dagEvent{pc: x.pcs[j], kind: "fetch", start: int64(x.pcs[j]), width: len(x.encoded[j])})
		a, q := len(r.accesses), len(r.primitives)
		r.referenceExec(t, i, j, x.pcs[j]+uint64(len(x.encoded[j])))
		if len(r.accesses) > a {
			v := r.accesses[a]
			kind := "read"
			if v.write {
				kind = "write"
			}
			want = append(want, dagEvent{x.pcs[j], kind, v.off.off, v.width, v.off.image})
		}
		if len(r.primitives) > q {
			want = append(want, dagEvent{pc: x.pcs[j], kind: "query"})
		}
		edge := 0
		if i.Operation == to.Branch && dagCondition(t, i.Condition, r.flags) {
			edge = 1
		}
		j = x.edges[j][edge]
	}
	b := c.checked.bound
	if b.ImageDigest != x.digest || b.Entry != x.pcs[0] || b.Rules != TransitionRules {
		t.Fatal("DAG scope binding differs")
	}
	values := stateBindings(t, c, face, initial)
	if b.Direction.Sort() != br.Bool() || (stateEval(t, b.Direction, values) != 0) != r.direction {
		t.Fatal("DAG current direction differs from executed intent")
	}
	inventory := x.proposal(cut)
	if len(inventory.Nodes) != len(b.Instructions)+len(b.ExcludedBoundaries)+1 {
		t.Fatal("structural coverage differs")
	}
	structural := map[uint64]TransitionNode{}
	for _, n := range inventory.Nodes {
		structural[n.PC] = n
	}
	guards := map[uint64]br.Term{}
	for _, v := range b.Instructions {
		if guards[v.Start].Valid() || v.Guard.Sort() != br.Bool() || structural[v.Start].Size != uint8(v.End-v.Start) {
			t.Fatal("duplicate occurrence")
		}
		guards[v.Start] = v.Guard
	}
	queries := map[uint64]stateQuery{}
	for q := range statePrimitivesOf[stateQuery](r) {
		queries[x.pcs[q.instruction]] = q
	}
	scopes := map[br.Scope]bool{b.Origin.View().Scope: true}
	queryPCs := map[uint64]bool{}
	var orderedQueries []dagEvent
	for _, effect := range b.PrimitiveEffects {
		e, ok := effect.(CPUIDEffect)
		if !ok || queryPCs[e.PC] || !guards[e.PC].Valid() || e.Leaf.Sort() != br.Bits(32) || e.Subleaf.Sort() != br.Bits(32) {
			t.Fatal("unaccounted query occurrence")
		}
		queryPCs[e.PC] = true
		// Guards and selectors are checked before the occurrence's outcomes are
		// assigned, even on inactive arms. No unknown-variable fallback is allowed.
		active := stateEval(t, guards[e.PC], values) != 0
		leaf, subleaf := stateEval(t, e.Leaf, values), stateEval(t, e.Subleaf, values)
		q, executed := queries[e.PC]
		if active != executed || active && (leaf != uint64(q.leaf) || subleaf != uint64(q.subleaf)) {
			t.Fatal("query guard/old selectors differ")
		}
		if active {
			orderedQueries = append(orderedQueries, dagEvent{pc: e.PC, kind: "query"})
		}
		totalization, accounted := totalizations[e.PC]
		if !accounted {
			t.Fatal("query has no input-owned totalization")
		}
		scope := e.ResultsEAX.View().Scope
		if scopes[scope] || scope == (br.Scope{}) {
			t.Fatal("nonfresh optional query scope")
		}
		scopes[scope] = true
		for slot, v := range []br.Term{e.ResultsEAX, e.ResultsEBX, e.ResultsECX, e.ResultsEDX} {
			view := v.View()
			if view.Op != br.Variable || view.Sort != br.Bits(32) || view.Scope != scope || view.Scratch || view.Immediate != uint64(slot) || len(view.Args) != 0 {
				t.Fatal("unbound optional outcome")
			}
			value := totalization[slot]
			if active {
				value = q.results[slot]
			}
			values[v] = uint64(value)
		}
	}
	accesses := map[uint64]TransitionAccess{}
	var orderedAccesses []dagEvent
	for _, a := range b.Accesses {
		if a.Kind != FrameRead && a.Kind != FrameWrite {
			t.Fatal("invalid guarded access kind", a.Kind)
		}
		if _, ok := accesses[a.PC]; ok || !guards[a.PC].Valid() {
			t.Fatal("unaccounted access")
		}
		accesses[a.PC] = a
		if stateEval(t, guards[a.PC], values) != 0 {
			kind := "read"
			if a.Kind == FrameWrite {
				kind = "write"
			}
			orderedAccesses = append(orderedAccesses, dagEvent{a.PC, kind, a.Bytes.Start, int(a.Bytes.End - a.Bytes.Start), a.Image})
		}
	}
	var wantQueries, wantAccesses []dagEvent
	for _, e := range want {
		if e.kind == "query" {
			wantQueries = append(wantQueries, e)
		}
		if e.kind == "read" || e.kind == "write" {
			wantAccesses = append(wantAccesses, e)
		}
	}
	if !slices.Equal(orderedQueries, wantQueries) {
		t.Fatal("filtered primitive slice order differs", orderedQueries, wantQueries)
	}
	if !slices.Equal(orderedAccesses, wantAccesses) {
		t.Fatal("filtered access slice order differs", orderedAccesses, wantAccesses)
	}
	var got []dagEvent
	for _, i := range b.Instructions {
		if stateEval(t, i.Guard, values) == 0 {
			continue
		}
		got = append(got, dagEvent{pc: i.Start, kind: "fetch", start: int64(i.Start), width: int(i.End - i.Start)})
		if a, ok := accesses[i.Start]; ok {
			kind := "read"
			if a.Kind == FrameWrite {
				kind = "write"
			}
			got = append(got, dagEvent{i.Start, kind, a.Bytes.Start, int(a.Bytes.End - a.Bytes.Start), a.Image})
		}
		if queryPCs[i.Start] {
			got = append(got, dagEvent{pc: i.Start, kind: "query"})
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("filtered ordered trace differs\ngot %v\nwant %v", got, want)
	}
	for j, e := range b.ExcludedBoundaries {
		if guards[e.PC].Valid() || structural[e.PC].Size != uint8(len(e.Bytes)) || len(structural[e.PC].Successors) != 0 || stateEval(t, e.Guard, values) != 0 {
			t.Fatal("excluded terminal is executed or structurally unbound")
		}
		left, right := c.checked.exclusions[j].Roots()
		if left != e.Guard || right.Sort() != br.Bool() || !literalBool(right, 0) {
			t.Fatal("excluded terminal proof differs")
		}
	}
	if b.CutGuard.Sort() != br.Bool() || stateEval(t, b.CutGuard, values) != 1 || b.Boundary.PC != x.pcs[cut] || !slices.Equal(b.Boundary.Bytes, x.encoded[cut]) {
		t.Fatal("cut relation differs")
	}
	pointer := func(got TransitionPointer, want statePointer) {
		t.Helper()
		if got == nil {
			return
		}
		if !want.valid {
			t.Fatal("invented pointer", got)
		}
		switch p := got.(type) {
		case OriginPointer:
			if want.image || p.Origin != b.Origin || p.Offset != want.off {
				t.Fatal("wrong stack provenance")
			}
		case ImagePointer:
			if !want.image || p.Address != uint64(want.off) || p.load != want.load || p.owner != &x.im.data[0] {
				t.Fatal("wrong image provenance")
			}
		}
	}
	for reg, v := range b.Registers {
		if v.Value.Sort() != br.Bits(64) || stateEval(t, v.Value, values) != r.regs[reg] {
			t.Fatalf("register %d differs: got %#x want %#x", reg, stateEval(t, v.Value, values), r.regs[reg])
		}
		pointer(v.Pointer, r.ptrs[reg])
		if (initial.regs[reg]^r.regs[reg])&b.Preserved[reg] != 0 {
			t.Fatal("false register preservation")
		}
	}
	if len(b.Memory) != len(r.memory) {
		t.Fatal("byte domain differs")
	}
	seenBytes := map[stateLocation]bool{}
	for _, v := range b.Memory {
		key := stateByteLocation(v)
		w, ok := r.memory[key]
		if !ok || seenBytes[key] || v.Value.Sort() != br.Bits(8) || stateEval(t, v.Value, values) != uint64(w.value) {
			t.Fatal("merged byte differs", v.TransitionLocation)
		}
		seenBytes[key] = true
		pointer(v.Pointer, w.ptr)
		if v.Pointer != nil && v.PointerLane != w.lane {
			t.Fatal("wrong pointer lane")
		}
	}
	for j, v := range c.checked.flags {
		if !v.Valid() && r.writer == to.ShiftLeft32CL && j == 2 {
			continue
		}
		w := []bool{r.flags[0], r.flags[1], r.flags[3] != r.flags[2]}[j]
		if v.Sort() != br.Bool() || (stateEval(t, v, values) != 0) != w {
			t.Fatal("merged predicate differs", j)
		}
	}
	for j, f := range []TransitionFlag{b.Flags.CF, b.Flags.ZF, b.Flags.OF, b.Flags.SF, b.Flags.AF, b.Flags.PF} {
		if r.writer >= to.Increment64 {
			stateAssertScalarFlag(t, j, f, r, values)
			continue
		}
		if f.Preserved && r.writer != 0 {
			t.Fatal("false flag preservation")
		}
		undefinedAF := (r.writer == to.And || r.writer == to.Test || r.writer == to.TestImmediate || r.writer == to.Clear32 || stateLogical(r.writer)) && j == 4
		if f.Defined && undefinedAF || !f.Defined && f.Value.Valid() {
			t.Fatal("false flag definedness")
		}
		if f.Value.Valid() && (f.Value.Sort() != br.Bool() || (stateEval(t, f.Value, values) != 0) != r.flags[j]) {
			t.Fatal("wrong public flag value", j)
		}
	}
}

func dagCheck(t testing.TB, ops []dagOp, face TransitionInterface, initial stateReference, seed uint64, cuts ...int) {
	t.Helper()
	x := dagArrange(t, ops, seed)
	end := len(ops) * 2
	for j := range x.intents {
		compareExecutedEncoding(t, x.encoded[j])
	}
	direct, err := CheckTransition(t.Context(), x.im, face, x.proposal(end), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, inactive := range [][]byte{nil, {0x78, 0x56, 0x34, 0x12, 0xff, 0, 0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9}} {
		dagAssert(t, direct, x, end, face, initial, inactive)
	}
	root, err := CheckTransition(t.Context(), x.im, face, x.proposal(0), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	original := root.checked.bound
	for _, cut := range append(slices.Clone(cuts), len(ops)) {
		prior := root.checked.bound
		root, err = CheckTransitionContinuation(t.Context(), root, x.proposal(cut*2))
		if err != nil {
			t.Fatal(err)
		}
		stateInheritedInputs(t, original, root.checked.bound)
		stateInheritedInputs(t, prior, root.checked.bound)
		dagAssert(t, root, x, cut*2, face, initial, []byte{1, 0xef, 0xcd, 0xab})
	}
	assertTransitionAlpha(t, direct, root)
}

func dagBranch(cc uint8, next, taken int) dagOp {
	return dagOp{i: to.Intent{Operation: to.Branch, Condition: cc}, e: to.Encoding{Form: to.JccNear}, next: next, taken: taken}
}
func dagScalar(i to.Intent, e to.Encoding, next int) dagOp { return dagOp{i: i, e: e, next: next} }

func TestTransitionGuardedInitialPredicates(t *testing.T) {
	face := cpuidFace()
	for _, cc := range []uint8{2, 3, 4, 5, 6, 7, 12, 13, 14, 15} {
		for flags := 0; flags < 8; flags++ {
			initial := stateInitial(face, uint64(flags))
			initial.flags = [6]bool{flags&1 != 0, flags&2 != 0, false, flags&4 != 0, false, false}
			initial.outcomes = [][4]uint32{{17, 23, 31, 47}, {53, 61, 73, 89}}
			ops := []dagOp{
				dagBranch(cc, 1, 2),
				dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 3),
				dagScalar(to.Intent{Operation: to.StoreImmediate, Base: 4, Width: 8, Immediate: 1}, to.Encoding{Form: to.MOVC6, SIB: true}, 3),
				dagScalar(to.Intent{Operation: to.CompareImmediate, Dst: 0, Width: 32, Immediate: 0}, to.Encoding{Form: to.CMP83}, 4),
				dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 5),
			}
			dagCheck(t, ops, face, initial, uint64(cc)*31+uint64(flags), 3, 4)
		}
	}
}

func TestTransitionGuardOnlyHistory(t *testing.T) {
	face := cpuidFace()
	initial := stateInitial(face, 9)
	ops := []dagOp{dagBranch(4, 1, 2), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 3), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 3)}
	for _, reg := range []uint8{0, 3, 1, 2} {
		ops = append(ops, dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: reg}, to.Encoding{Form: to.MOVB8Imm32}, len(ops)+1))
	}
	ops = append(ops, dagScalar(to.Intent{Operation: to.CompareImmediate, Dst: 0, Width: 32}, to.Encoding{Form: to.CMP83}, len(ops)+1))
	for flags := 0; flags < 8; flags++ {
		initial.flags = [6]bool{flags&1 != 0, flags&2 != 0, false, flags&4 != 0, false, false}
		dagCheck(t, ops, face, initial, uint64(flags), 3, 7)
	}
}

func TestTransitionGuardedOwnershipAndBudgets(t *testing.T) {
	face := cpuidFace()
	ops := []dagOp{dagBranch(4, 1, 2), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 3), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 3)}
	x := dagArrange(t, ops, 1)
	p := x.proposal(6)
	for _, limits := range []TransitionLimits{{LiveStateBytes: 1}, {LiveStateBytes: 4000}, {RelationLimits: RelationLimits{Work: 100}}, {RelationLimits: RelationLimits{Nodes: 16}}} {
		c, err := CheckTransition(t.Context(), x.im, face, p, limits)
		transitionRefused(t, c, err)
	}
	root := continuationRoot(t, x.im, x.pcs[0], face, TransitionLimits{})
	before, _ := root.Bound()
	c, err := CheckTransitionContinuation(t.Context(), root, p)
	if err != nil {
		t.Fatal(err)
	}
	projection, ok := c.Bound()
	if !ok || len(projection.Instructions) == 0 {
		t.Fatal("missing positive guarded certificate")
	}
	checkedBefore := lifecycleSnapshot(projection)
	projection.Instructions[0].Guard = br.Term{}
	projection.InitialPredicates = TransitionPredicates{}
	projection.CutGuard = br.Term{}
	after, _ := root.Bound()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("parent mutated")
	}
	checkedAfter, ok := c.Bound()
	if !ok || !reflect.DeepEqual(checkedBefore, checkedAfter) {
		t.Fatal("guard projection mutated its checked certificate")
	}
	sibling, err := CheckTransitionContinuation(t.Context(), root, p)
	if err != nil {
		t.Fatal(err)
	}
	stateInheritedInputs(t, before, sibling.checked.bound)
	checkedAfter, ok = c.Bound()
	if !ok || !reflect.DeepEqual(checkedBefore, checkedAfter) {
		t.Fatal("sibling construction mutated retained guarded evidence")
	}
	if c.checked.bound.PrimitiveEffects[0].(CPUIDEffect).ResultsEAX == sibling.checked.bound.PrimitiveEffects[0].(CPUIDEffect).ResultsEAX {
		t.Fatal("siblings reused suffix outcomes")
	}
}
