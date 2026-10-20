package nativeproof

import (
	"testing"
	"unsafe"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

// Count the actual immutable term DAG, including proof proposal intermediates.
// This oracle uses neither valueBuilder.depth nor a reported spent-work total.
func exclusionTermInventory(roots ...br.Term) (int, int) {
	depth := map[br.Term]int{}
	var visit func(br.Term) int
	visit = func(x br.Term) int {
		if !x.Valid() {
			return 0
		}
		if d := depth[x]; d != 0 {
			return d
		}
		d := 1
		for _, a := range x.View().Args {
			d = max(d, visit(a)+1)
		}
		depth[x] = d
		return d
	}
	maximum := 0
	for _, r := range roots {
		maximum = max(maximum, visit(r))
	}
	return len(depth), maximum
}

func exclusionPrefixRoots(t testing.TB, c TransitionCertificate) []br.Term {
	t.Helper()
	b := c.checked.bound
	if len(b.Words) != 0 || len(b.PrimitiveEffects) != 0 || len(b.ExcludedBoundaries) != 0 || len(b.Accesses) != 0 {
		t.Fatal("budget fixture acquired uncounted dependency kinds")
	}
	r := []br.Term{b.Origin, b.EntryPredicate, b.CutGuard, b.InitialDirection, b.Direction, b.InitialPredicates.CF, b.InitialPredicates.ZF, b.InitialPredicates.SFXorOF}
	r = append(r, b.InitialRegisters[:]...)
	r = append(r, c.checked.flags[:]...)
	for _, v := range b.Registers {
		r = append(r, v.Value)
	}
	for _, mem := range [][]TransitionByte{b.Memory, b.InitialMemory} {
		for _, v := range mem {
			r = append(r, v.Value)
		}
	}
	for _, v := range b.Instructions {
		r = append(r, v.Guard)
	}
	for _, v := range []TransitionFlag{b.Flags.CF, b.Flags.ZF, b.Flags.OF, b.Flags.SF, b.Flags.AF, b.Flags.PF} {
		r = append(r, v.Value)
	}
	return r
}

func exclusionBudgetFixture(t testing.TB, l TransitionLimits) (*Image, TransitionCertificate, TransitionProposal) {
	t.Helper()
	// CMP RAX,RAX; JE cut; unsupported CALL RAX; cut UD2.
	im := image(t, []byte{0x48, 0x39, 0xc0, 0x74, 2, 0xff, 0xd0, 0x0f, 0x0b})
	face := stateFace(16, 0)
	face.Regions = []RelativeRegion{{RelativeSpan{0, 64}, true, true}}
	face.Words = nil
	prefix := TransitionProposal{ImageDigest: im.digest, Entry: testEntry, Cut: testEntry + 3, Root: 1, Nodes: []TransitionNode{{ID: 1, PC: testEntry, Size: 3, Successors: []TransitionOccurrenceID{2}}, {ID: 2, PC: testEntry + 3, Size: 2}}}
	root, err := CheckTransition(t.Context(), im, face, prefix, l)
	if err != nil {
		t.Fatal("same-allowance prefix refused", err)
	}
	stateBindings(t, root, face, stateRawInitial(face, nil))
	full := TransitionProposal{ImageDigest: im.digest, Entry: testEntry, Cut: testEntry + 7, Root: 1, Nodes: []TransitionNode{{ID: 1, PC: testEntry, Size: 3, Successors: []TransitionOccurrenceID{2}}, {ID: 2, PC: testEntry + 3, Size: 2, Successors: []TransitionOccurrenceID{3, 4}}, {ID: 3, PC: testEntry + 5, Size: 2}, {ID: 4, PC: testEntry + 7, Size: 2}}}
	return im, root, full
}

func TestTransitionExclusionProofNodeAndStorageBudgets(t *testing.T) {
	_, template, p := exclusionBudgetFixture(t, TransitionLimits{})
	// Derive JE's false incoming guard from the instruction intent, binding its
	// comparison to the authentic original input (not a reported exclusion guard).
	z := template.checked.flags[flagZero]
	v := z.View()
	if v.Op != br.Equal || len(v.Args) != 2 || v.Args[0] != template.checked.bound.InitialRegisters[RAX] || v.Args[1] != v.Args[0] {
		t.Fatal("CMP intent binding differs")
	}
	b := br.NewBuilder(8)
	guard, err := b.Make(br.Not, br.Bool(), 0, z)
	if err != nil {
		t.Fatal(err)
	}
	truth, err := b.Const(br.Bool(), 1)
	if err != nil {
		t.Fatal(err)
	}
	falsity, err := b.Const(br.Bool(), 0)
	if err != nil {
		t.Fatal(err)
	}
	roots := append(exclusionPrefixRoots(t, template), truth, falsity, guard)
	baseNodes, _ := exclusionTermInventory(roots...)
	count := &imageCallbackContext{Context: t.Context()}
	proposal, err := br.Propose(count, guard, falsity, br.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := br.Check(count, guard, falsity, proposal, br.Limits{}); err != nil {
		t.Fatal(err)
	}
	var proofRoots []br.Term
	for _, s := range proposal.Steps {
		proofRoots = append(proofRoots, s.Left, s.Right)
	}
	fullNodes, _ := exclusionTermInventory(append(roots, proofRoots...)...)
	if fullNodes <= baseNodes || len(proposal.Steps) > baseNodes {
		t.Fatal("fixture does not isolate cumulative candidate import")
	}
	_, low, full := exclusionBudgetFixture(t, TransitionLimits{RelationLimits: RelationLimits{Nodes: baseNodes}})
	c, err := CheckTransitionContinuation(t.Context(), low, full)
	exclusionRefusal(t, c, err, testEntry+5, "relation-budget", "input expression nodes/depth")
	_, enough, full := exclusionBudgetFixture(t, TransitionLimits{RelationLimits: RelationLimits{Nodes: fullNodes}})
	c, err = CheckTransitionContinuation(t.Context(), enough, full)
	if err != nil || c.checked == nil {
		t.Fatal("kernel-derived node allowance refused", err)
	}
	// At CALL, both fork states and the full graph's pointer slots are live.
	// This is the declared storage accounting for 64 input cells, computed from
	// their types/count, not sampled from a failing checker or its spent counter.
	stateBytes := int(unsafe.Sizeof(transitionNodeState{})) + 1024 + 64*(2*int(unsafe.Sizeof(TransitionLocation{})+unsafe.Sizeof(TransitionByte{}))+64)
	inputNodes, _ := exclusionTermInventory(guard, falsity)
	// One owned full occurrence witness replaces prefix reconstruction. Graph
	// nodes reserve 4096 bytes; inherited projection elements reserve 256 each.
	retained := template.checked.bound
	inherited := 256 * (len(retained.InitialMemory) + len(retained.Memory) + len(retained.Instructions) + len(retained.ExcludedOrigins) + len(retained.Interface.Regions))
	occupied := 2*stateBytes + 8*len(p.Nodes) + 4096*len(p.Nodes) + inherited + 64*(len(template.checked.witness.Nodes)-1)
	storage := occupied + 4096*(inputNodes-1)
	_, low, full = exclusionBudgetFixture(t, TransitionLimits{LiveStateBytes: storage})
	c, err = CheckTransitionContinuation(t.Context(), low, full)
	exclusionRefusal(t, c, err, testEntry+5, "transition-budget", "bitrelation budget: graph node budget")
	proofNodes, _ := exclusionTermInventory(proofRoots...)
	capacity := max(proofNodes, len(proposal.Steps), (count.calls+7)/8)
	_, enough, full = exclusionBudgetFixture(t, TransitionLimits{LiveStateBytes: occupied + 4096*capacity})
	c, err = CheckTransitionContinuation(t.Context(), enough, full)
	if err != nil || c.checked == nil {
		t.Fatal("kernel-derived storage allowance refused", err)
	}
}

func TestTransitionExclusionProofImportDepth(t *testing.T) {
	// !p OR (p AND q) rewrites to !(p AND !q). Conjoining (p AND !q)
	// makes the whole guard false, but a checked congruence intermediate is one
	// level deeper than the input. A shallow root must refuse that imported term.
	build := func(c TransitionCertificate) (br.Term, br.Term) {
		b := br.NewBuilder(32)
		p, q := c.checked.bound.InitialPredicates.CF, c.checked.bound.InitialPredicates.ZF
		makeTerm := func(op br.Op, args ...br.Term) br.Term {
			x, err := b.Make(op, br.Bool(), 0, args...)
			if err != nil {
				t.Fatal(err)
			}
			return x
		}
		np, nq := makeTerm(br.Not, p), makeTerm(br.Not, q)
		g := makeTerm(br.And, makeTerm(br.Or, np, makeTerm(br.And, p, q)), makeTerm(br.And, p, nq))
		zero, err := b.Const(br.Bool(), 0)
		if err != nil {
			t.Fatal(err)
		}
		return g, zero
	}
	_, template, _ := exclusionBudgetFixture(t, TransitionLimits{})
	guard, zero := build(template)
	_, inputDepth := exclusionTermInventory(guard, zero)
	p, err := br.Propose(t.Context(), guard, zero, br.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := br.Check(t.Context(), guard, zero, p, br.Limits{}); err != nil {
		t.Fatal(err)
	}
	var proofRoots []br.Term
	for _, s := range p.Steps {
		proofRoots = append(proofRoots, s.Left, s.Right)
	}
	proofNodes, proofDepth := exclusionTermInventory(proofRoots...)
	if proofDepth <= inputDepth {
		t.Fatal("fixture lacks a deeper proof intermediate")
	}
	for _, depth := range []int{inputDepth, proofDepth} {
		im, root, full := exclusionBudgetFixture(t, TransitionLimits{RelationLimits: RelationLimits{Depth: depth}})
		prefixNodes, _ := exclusionTermInventory(exclusionPrefixRoots(t, root)...)
		if prefixNodes+proofNodes+32 >= root.checked.limits.Nodes {
			t.Fatal("depth control could instead exhaust nodes")
		}
		// Actual opaque continuation at these same allowances remains a positive
		// integration control. The deeper proof-import frontier is isolated below.
		if c, err := CheckTransitionContinuation(t.Context(), root, full); err != nil || c.checked == nil {
			t.Fatal("same-depth native continuation refused", err)
		}
		m, err := newTransitionChecker(t.Context(), im, transitionRoot{entry: im.entry}, root.checked.limits, root.checked.work)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.inherit(*root.checked); err != nil {
			t.Fatal(err)
		}
		guard, zero := build(root)
		m.pc = testEntry + 5
		m.falsity = zero
		if err := m.importTerm(guard); err != nil {
			t.Fatal("input guard should fit", err)
		}
		w, err := m.proveFalseGuard(guard)
		if depth == inputDepth {
			if w.Valid() {
				t.Fatal("over-depth proof escaped")
			}
			exclusionRefusal(t, TransitionCertificate{}, err, testEntry+5, "relation-budget", "input expression nodes/depth")
		} else if err != nil || !w.Valid() {
			t.Fatal("independently sufficient proof depth refused", err)
		}
	}
}
