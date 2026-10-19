package nativeproof

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

const occurrenceEntry uint64 = 0x401000

func occurrenceImage(t *testing.T, encoded string) *Image {
	t.Helper()
	code, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4096+len(code))
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	u16 := func(at int, v uint16) { binary.LittleEndian.PutUint16(b[at:], v) }
	u64 := func(at int, v uint64) { binary.LittleEndian.PutUint64(b[at:], v) }
	u16(16, 2)
	u16(18, 62)
	binary.LittleEndian.PutUint32(b[20:], 1)
	u64(24, occurrenceEntry)
	u64(32, 64)
	u16(52, 64)
	u16(54, 56)
	u16(56, 1)
	binary.LittleEndian.PutUint32(b[64:], 1)
	binary.LittleEndian.PutUint32(b[68:], 5)
	u64(72, 4096)
	u64(80, occurrenceEntry)
	u64(96, uint64(len(code)))
	u64(104, uint64(len(code)))
	u64(112, 4096)
	copy(b[4096:], code)
	im, err := NewImage(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	return im
}

func occurrenceFace() TransitionInterface {
	return TransitionInterface{Origin: OriginDomain{Min: 1 << 40, Max: 1 << 44, Modulus: 16}, Envelope: RelativeSpan{-64, 64}, Regions: []RelativeRegion{{Bytes: RelativeSpan{-64, 64}, Readable: true, Writable: true}}, Conditions: TransitionConditions{Machine: MachineModel, InstructionMapping: true, EntryState: true, IsolatedExecution: true, MemoryMapping: true, NoHiddenAliases: true, UnalignedAccess: true}}
}

func occurrenceProof(t *testing.T, im *Image, cut uint64, options TransitionOptions) (TransitionCertificate, TransitionProposal) {
	t.Helper()
	p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{}, options)
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransition(t.Context(), im, occurrenceFace(), p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

func TestTransitionOccurrenceFiniteLoop(t *testing.T) {
	im := occurrenceImage(t, "b8000000004883c0014883f80375f690")
	c, p := occurrenceProof(t, im, occurrenceEntry+15, TransitionOptions{MaxOccurrences: 10})
	b, _ := c.Bound()
	if len(b.ExcludedBoundaries) != 1 || !b.ExcludedBoundaries[0].Frontier {
		t.Fatal("missing false supported frontier")
	}
	seen := map[TransitionOccurrenceID]bool{}
	repeats := 0
	for _, ins := range b.Instructions {
		if ins.ID == 0 || seen[ins.ID] || ins.Context != 0 {
			t.Fatal("loop reused identity or fabricated activation")
		}
		seen[ins.ID] = true
		if ins.Start == occurrenceEntry+5 {
			repeats++
		}
		if _, err := c.InstructionAt(t.Context(), ins.ID); err != nil {
			t.Fatal(err)
		}
	}
	if repeats != 3 {
		t.Fatalf("iterations: %d", repeats)
	}
	if _, err := c.InstructionAt(t.Context(), b.Boundary.ID); err == nil {
		t.Fatal("unexecuted cut inspected as executed")
	}
	small, err := ProposeTransition(t.Context(), im, p.Cut, TransitionLimits{}, TransitionOptions{MaxOccurrences: 7})
	if err != nil {
		t.Fatal(err)
	}
	if rejected, err := CheckTransition(t.Context(), im, occurrenceFace(), small, TransitionLimits{}); err == nil || rejected.checked != nil {
		t.Fatal("feasible frontier accepted")
	}
	if _, err := ProposeTransition(t.Context(), im, p.Cut, TransitionLimits{}); err == nil {
		t.Fatal("cyclic acyclic-discovery accepted")
	}
}

func TestTransitionOccurrenceGraphAdversaries(t *testing.T) {
	im := occurrenceImage(t, "b8000000004883c0014883f80375f690")
	_, p := occurrenceProof(t, im, occurrenceEntry+15, TransitionOptions{MaxOccurrences: 10})
	mutations := map[string]func(*TransitionProposal){
		"duplicate": func(q *TransitionProposal) { q.Nodes[1].ID = q.Nodes[0].ID },
		"zero":      func(q *TransitionProposal) { q.Nodes[0].ID = 0 },
		"missing":   func(q *TransitionProposal) { q.Nodes[0].Successors = nil },
		"redirect":  func(q *TransitionProposal) { q.Nodes[0].Successors[0] = q.Nodes[2].ID },
		"swap": func(q *TransitionProposal) {
			for j := range q.Nodes {
				if len(q.Nodes[j].Successors) == 2 {
					slices.Reverse(q.Nodes[j].Successors)
					return
				}
			}
		},
		"disconnected": func(q *TransitionProposal) { q.Nodes = append(q.Nodes, TransitionNode{ID: 999, PC: p.Cut, Size: 1}) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			work := 0
			l, _ := transitionLimits(TransitionLimits{})
			q, err := captureTransitionProposal(p, l, &work)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&q)
			if c, err := CheckTransition(t.Context(), im, occurrenceFace(), q, TransitionLimits{}); err == nil || c.checked != nil {
				t.Fatal("mutant accepted")
			}
		})
	}
	// Sparse IDs are identifiers, not array indices or a claimed rank.
	work := 0
	l, _ := transitionLimits(TransitionLimits{})
	q, _ := captureTransitionProposal(p, l, &work)
	remap := func(id TransitionOccurrenceID) TransitionOccurrenceID { return ^TransitionOccurrenceID(0) - id*97 }
	q.Root = remap(q.Root)
	for j := range q.Nodes {
		q.Nodes[j].ID = remap(q.Nodes[j].ID)
		for k, id := range q.Nodes[j].Successors {
			q.Nodes[j].Successors[k] = remap(id)
		}
	}
	if _, err := CheckTransition(t.Context(), im, occurrenceFace(), q, TransitionLimits{}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionOccurrenceCoincidentConditionalSlots(t *testing.T) {
	im := occurrenceImage(t, "740090")
	_, p := occurrenceProof(t, im, occurrenceEntry+2, TransitionOptions{})
	if len(p.Nodes[0].Successors) != 2 || p.Nodes[0].Successors[0] != p.Nodes[0].Successors[1] {
		t.Fatal("coincident slots collapsed")
	}
	p.Nodes[0].Successors = p.Nodes[0].Successors[:1]
	if _, err := CheckTransition(t.Context(), im, occurrenceFace(), p, TransitionLimits{}); err == nil {
		t.Fatal("missing coincident slot accepted")
	}
}

func TestTransitionOccurrenceUnequalDepthJoin(t *testing.T) {
	im := occurrenceImage(t, "7405b801000000b90200000090")
	c, p := occurrenceProof(t, im, occurrenceEntry+12, TransitionOptions{})
	if len(p.Nodes) != 4 {
		t.Fatal("acyclic join was unnecessarily unfolded")
	}
	joined := p.Nodes[2].ID
	incoming := 0
	for _, n := range p.Nodes {
		for _, id := range n.Successors {
			if id == joined {
				incoming++
			}
		}
	}
	if incoming != 2 {
		t.Fatal("missing unequal-depth join")
	}
	want, err := br.NewBuilder(1).Const(br.Bits(64), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := br.Prove(t.Context(), c.checked.bound.Registers[RCX].Value, want, br.Limits{}); err != nil {
		t.Fatal("join successor state lost", err)
	}
}

func TestTransitionOccurrenceRepeatedPrimitive(t *testing.T) {
	im := occurrenceImage(t, "41b8000000000fa24983c0014983f80375f490")
	p, err := ProposeTransition(t.Context(), im, occurrenceEntry+18, TransitionLimits{}, TransitionOptions{MaxOccurrences: 13})
	if err != nil {
		t.Fatal(err)
	}
	f := occurrenceFace()
	f.Conditions.CPUID = CPUIDModel
	c, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if len(b.PrimitiveEffects) != 3 {
		t.Fatalf("effects: %d", len(b.PrimitiveEffects))
	}
	ids := map[TransitionOccurrenceID]bool{}
	scopes := map[br.Scope]bool{}
	for _, effect := range b.PrimitiveEffects {
		e := effect.(CPUIDEffect)
		if ids[e.ID] || scopes[e.ResultsEAX.View().Scope] || e.Context != 0 {
			t.Fatal("reused primitive origin")
		}
		ids[e.ID], scopes[e.ResultsEAX.View().Scope] = true, true
		matched := false
		for _, ins := range b.Instructions {
			if ins.ID == e.ID {
				matched = ins.Start == e.PC && ins.Context == e.Context
			}
		}
		if !matched {
			t.Fatal("unowned effect")
		}
	}
}

func TestTransitionOccurrenceContinuationOwnership(t *testing.T) {
	im := occurrenceImage(t, "b8000000004883c0014883f80375f6b90700000090")
	first, _ := occurrenceProof(t, im, occurrenceEntry+15, TransitionOptions{MaxOccurrences: 10})
	before, _ := first.Bound()
	p, err := ProposeTransitionContinuation(t.Context(), first, occurrenceEntry+20)
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransitionContinuation(t.Context(), first, p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if b.Origin != before.Origin || b.InitialRegisters != before.InitialRegisters || !reflect.DeepEqual(b.Instructions[:len(before.Instructions)], before.Instructions) || !reflect.DeepEqual(b.ExcludedBoundaries, before.ExcludedBoundaries) {
		t.Fatal("prefix identity or original state changed")
	}
	valid := lifecycleProposal(p)
	p.Nodes[0].Successors[0] = 0
	b.Instructions[0].ID = 0
	b.Boundary.Bytes[0] ^= 0xff
	after, _ := c.Bound()
	if after.Instructions[0].ID == 0 || after.Boundary.Bytes[0] != 0x90 {
		t.Fatal("borrowed projection/proposal")
	}
	if _, err := ProposeTransitionContinuation(t.Context(), first, occurrenceEntry+5); err == nil {
		t.Fatal("numeric cut reinterpreted as later occurrence")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if rejected, err := CheckTransitionContinuation(ctx, first, valid); !errors.Is(err, context.Canceled) || rejected.checked != nil {
		t.Fatal("cancelled continuation accepted")
	}
}

func TestTransitionOccurrenceDecodedCycleOverlapAndPaths(t *testing.T) {
	// Every edge is the actual decoded edge, and the cut is reachable separately.
	im := occurrenceImage(t, "b8000000004883c0014883f80375f690")
	occurrenceProof(t, im, occurrenceEntry+15, TransitionOptions{MaxOccurrences: 10})
	p := TransitionProposal{ImageDigest: im.digest, Entry: occurrenceEntry, Cut: occurrenceEntry + 15, Root: 1, Nodes: []TransitionNode{{ID: 1, PC: occurrenceEntry, Size: 5, Successors: []TransitionOccurrenceID{2}}, {ID: 2, PC: occurrenceEntry + 5, Size: 4, Successors: []TransitionOccurrenceID{3}}, {ID: 3, PC: occurrenceEntry + 9, Size: 4, Successors: []TransitionOccurrenceID{4}}, {ID: 4, PC: occurrenceEntry + 13, Size: 2, Successors: []TransitionOccurrenceID{5, 2}}, {ID: 5, PC: occurrenceEntry + 15, Size: 1}}}
	c, err := CheckTransition(t.Context(), im, occurrenceFace(), p, TransitionLimits{})
	var refusal *Refusal
	if c.checked != nil || !errors.As(err, &refusal) || refusal.Premise != "acyclic-control" {
		t.Fatal("decoded cycle did not decide refusal", err)
	}
	// JE's taken edge enters the immediate of MOV. Even the ordinary native
	// discoverer must report occupancy before trying to interpret interior bytes.
	aligned := occurrenceImage(t, "7400b800000000c3")
	if _, err := Propose(t.Context(), aligned, occurrenceEntry, Interface{}); err != nil {
		t.Fatal("aligned-edge baseline refused", err)
	}
	im = occurrenceImage(t, "7401b800000000c3")
	_, err = Propose(t.Context(), im, occurrenceEntry, Interface{})
	if !errors.As(err, &refusal) || refusal.Premise != "instruction-overlap" || !slices.Equal(refusal.Path, []uint64{occurrenceEntry, occurrenceEntry + 3}) {
		t.Fatal("ordinary occupancy/path changed", err)
	}
	p = TransitionProposal{ImageDigest: im.digest, Entry: occurrenceEntry, Cut: occurrenceEntry + 7, Root: 1, Nodes: []TransitionNode{{ID: 1, PC: occurrenceEntry, Size: 2, Successors: []TransitionOccurrenceID{2, 3}}, {ID: 2, PC: occurrenceEntry + 2, Size: 5, Successors: []TransitionOccurrenceID{4}}, {ID: 3, PC: occurrenceEntry + 3, Size: 2}, {ID: 4, PC: occurrenceEntry + 7, Size: 1}}}
	c, err = CheckTransition(t.Context(), im, occurrenceFace(), p, TransitionLimits{})
	if c.checked != nil || !errors.As(err, &refusal) || refusal.Premise != "instruction-overlap" || !slices.Equal(refusal.Path, []uint64{occurrenceEntry, occurrenceEntry + 3}) {
		t.Fatal("occurrence occupancy/path changed", err)
	}
}

func TestTransitionOccurrenceRepeatedTheoremApplicationAndParentReturn(t *testing.T) {
	im := occurrenceImage(t, "e81b000000e816000000c390"+strings.Repeat("90", 20)+"0fa2c3")
	f := occurrenceFace()
	f.Conditions.CPUID = CPUIDModel
	f.ReturnContext = &TransitionReturnContext{Target: occurrenceEntry + 11}
	p, err := ProposeRegionTransition(t.Context(), im, occurrenceEntry, occurrenceEntry, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	current, err := CheckRegionTransition(t.Context(), im, occurrenceEntry, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	root := current.checked.bound
	var activations []TransitionActivationID
	for _, after := range []uint64{occurrenceEntry + 5, occurrenceEntry + 10} {
		childFace := occurrenceFace()
		childFace.Conditions.CPUID = CPUIDModel
		childFace.Origin = OriginDomain{Min: 1 << 39, Max: 1 << 45, Modulus: 8}
		childFace.Envelope = RelativeSpan{-32, 32}
		childFace.Regions = []RelativeRegion{{Bytes: RelativeSpan{-32, 32}, Readable: true, Writable: true}}
		childFace.ReturnContext = &TransitionReturnContext{Target: after}
		q, err := ProposeRegionTransition(t.Context(), im, occurrenceEntry+32, occurrenceEntry+34, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		child, err := CheckRegionTransition(t.Context(), im, occurrenceEntry+32, childFace, q, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		returned, err := CheckTransitionReturn(t.Context(), child)
		if err != nil {
			t.Fatal(err)
		}
		callID := current.checked.bound.Boundary.ID
		applied, err := CheckTransitionCallReturn(t.Context(), current, returned)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := applied.Bound()
		if a.ID != callID || a.Activation != TransitionActivationID(callID) || !applied.AppliesTo(returned) {
			t.Fatal("application lost invoking occurrence")
		}
		activations = append(activations, a.Activation)
		current, _ = applied.Successor()
	}
	if activations[0] == activations[1] {
		t.Fatal("repeated theorem shared activation")
	}
	b := current.checked.bound
	if b.Origin != root.Origin || b.InitialRegisters != root.InitialRegisters || len(b.PrimitiveEffects) != 2 || len(b.Accesses) != 4 {
		t.Fatal("application lost original state/effects")
	}
	a, z := b.PrimitiveEffects[0].(CPUIDEffect), b.PrimitiveEffects[1].(CPUIDEffect)
	if a.ID == z.ID || a.ResultsEAX.View().Scope == z.ResultsEAX.View().Scope || a.Context != activations[0] || z.Context != activations[1] {
		t.Fatal("repeated outcomes collapsed")
	}
	returned, err := CheckTransitionReturn(t.Context(), current)
	if err != nil {
		t.Fatal(err)
	}
	end, _ := returned.Bound()
	if !end.State.CalleeTerminated || end.State.PC != occurrenceEntry+11 || len(end.Accesses) != 5 || end.Accesses[4].ID != b.Boundary.ID {
		t.Fatal("parent return incomplete")
	}
}

func TestTransitionOccurrencePrefixRedirectAndCallbackOwnership(t *testing.T) {
	im := occurrenceImage(t, "b8000000004883c0014883f80375f690")
	prior, _ := occurrenceProof(t, im, occurrenceEntry+9, TransitionOptions{})
	p, err := ProposeTransitionContinuation(t.Context(), prior, occurrenceEntry+15, TransitionOptions{MaxOccurrences: 8})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := CheckTransitionContinuation(t.Context(), prior, p)
	if err != nil {
		t.Fatal(err)
	}
	oldADD := prior.checked.bound.Instructions[1].ID
	bad := lifecycleProposal(p)
	var frontier TransitionOccurrenceID
	for _, n := range bad.Nodes {
		if n.Frontier {
			frontier = n.ID
			if n.PC != occurrenceEntry+5 {
				t.Fatal("wrong frontier fixture")
			}
		}
	}
	if frontier == 0 {
		t.Fatal("missing frontier")
	}
	for j := range bad.Nodes {
		for k, id := range bad.Nodes[j].Successors {
			if id == frontier {
				bad.Nodes[j].Successors[k] = oldADD
			}
		}
	}
	bad.Nodes = slices.DeleteFunc(bad.Nodes, func(n TransitionNode) bool { return n.ID == frontier })
	rejected, err := CheckTransitionContinuation(t.Context(), prior, bad)
	var refusal *Refusal
	if rejected.checked != nil || !errors.As(err, &refusal) || refusal.Premise != "acyclic-control" {
		t.Fatal("actual suffix edge into executed occurrence was not rejected", err)
	}
	count := &imageCallbackContext{Context: t.Context()}
	if _, err := CheckTransitionContinuation(count, prior, p); err != nil {
		t.Fatal(err)
	}
	before, _ := prior.Bound()
	for _, at := range []int{1, count.calls / 2, count.calls} {
		owned := lifecycleProposal(p)
		callback := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n == at {
				for j := range owned.Nodes {
					owned.Nodes[j].ID = 0
					owned.Nodes[j].Expanded = !owned.Nodes[j].Expanded
					for k := range owned.Nodes[j].Successors {
						owned.Nodes[j].Successors[k] = 0
					}
				}
			}
		}}
		got, err := CheckTransitionContinuation(callback, prior, owned)
		if err != nil {
			t.Fatal("proposal containers borrowed across callback", err)
		}
		assertCutStateAlpha(t, baseline.checked.bound, got.checked.bound)
	}
	after, _ := prior.Bound()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("predecessor changed")
	}
	limited := *prior.checked
	limited.limits.Work = limited.work + len(p.Nodes)
	rejected, err = CheckTransitionContinuation(t.Context(), TransitionCertificate{&limited}, p)
	if rejected.checked != nil || !errors.As(err, &refusal) || !strings.Contains(refusal.Premise, "budget") {
		t.Fatal("cumulative account reset", err)
	}
}

func TestTransitionOccurrenceNestedCalleeFrontierAndParentReturn(t *testing.T) {
	im := occurrenceImage(t, "e81b000000c390"+strings.Repeat("90", 25)+"41b800000000e8150000004983c0014983f80375f1c3"+strings.Repeat("90", 10)+"0fa2c3")
	f := occurrenceFace()
	f.Conditions.CPUID = CPUIDModel
	f.ReturnContext = &TransitionReturnContext{Target: occurrenceEntry + 6}
	p, err := ProposeRegionTransition(t.Context(), im, occurrenceEntry, occurrenceEntry, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := CheckRegionTransition(t.Context(), im, occurrenceEntry, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	childFace := occurrenceFace()
	childFace.Conditions.CPUID = CPUIDModel
	childFace.Origin = OriginDomain{Min: 1 << 39, Max: 1 << 45, Modulus: 8}
	childFace.Envelope = RelativeSpan{-32, 32}
	childFace.Regions = []RelativeRegion{{Bytes: RelativeSpan{-32, 32}, Readable: true, Writable: true}}
	childFace.ReturnContext = &TransitionReturnContext{Target: occurrenceEntry + 5}
	q, err := ProposeRegionTransition(t.Context(), im, occurrenceEntry+32, occurrenceEntry+53, TransitionLimits{}, TransitionOptions{MaxOccurrences: 19, Expansions: []TransitionExpansion{{PC: occurrenceEntry + 38, AllActivations: true}}})
	if err != nil {
		t.Fatal(err)
	}
	child, err := CheckRegionTransition(t.Context(), im, occurrenceEntry+32, childFace, q, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	complete, err := CheckTransitionReturn(t.Context(), child)
	if err != nil {
		t.Fatal(err)
	}
	call, err := CheckTransitionCallReturn(t.Context(), parent, complete)
	if err != nil {
		t.Fatal(err)
	}
	successor, _ := call.Successor()
	b := successor.checked.bound
	if len(b.PrimitiveEffects) != 3 || len(b.Frames) != 0 || len(b.ExcludedBoundaries) != 1 || !b.ExcludedBoundaries[0].Frontier || b.ExcludedBoundaries[0].Context != TransitionActivationID(parent.checked.bound.Boundary.ID) {
		t.Fatal("nested effects/frontier/parent context lost")
	}
	contexts := map[TransitionActivationID]bool{}
	for _, effect := range b.PrimitiveEffects {
		e := effect.(CPUIDEffect)
		if contexts[e.Context] || e.Context == 0 || e.Context == TransitionActivationID(parent.checked.bound.Boundary.ID) {
			t.Fatal("nested CALL activation collapsed")
		}
		contexts[e.Context] = true
		found := false
		for _, ins := range b.Instructions {
			if ins.ID == TransitionOccurrenceID(e.Context) {
				found = ins.Start == occurrenceEntry+38 && ins.Context == TransitionActivationID(parent.checked.bound.Boundary.ID)
			}
		}
		if !found {
			t.Fatal("nested context not derived from actual CALL occurrence")
		}
	}
	returned, err := CheckTransitionReturn(t.Context(), successor)
	if err != nil {
		t.Fatal(err)
	}
	end, _ := returned.Bound()
	if !end.State.CalleeTerminated || end.State.PC != occurrenceEntry+6 || end.Accesses[len(end.Accesses)-1].ID != b.Boundary.ID {
		t.Fatal("nested composition did not complete exact parent return")
	}
}

func TestTransitionOccurrenceExcludedAddressBecomesReturnCut(t *testing.T) {
	im := occurrenceImage(t, "b80000000085c07505b801000000c390")
	f := occurrenceFace()
	f.ReturnContext = &TransitionReturnContext{Target: occurrenceEntry + 15}
	p, err := ProposeRegionTransition(t.Context(), im, occurrenceEntry, occurrenceEntry+9, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	prior, err := CheckRegionTransition(t.Context(), im, occurrenceEntry, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	old := prior.checked.bound.ExcludedBoundaries
	if len(old) != 1 || old[0].PC != occurrenceEntry+14 {
		t.Fatal("fixture lacks independently false return occurrence")
	}
	q := continuationProposal(t, prior, occurrenceEntry+14)
	next, err := CheckTransitionContinuation(t.Context(), prior, q)
	if err != nil {
		t.Fatal(err)
	}
	b := next.checked.bound
	if b.Boundary.ID == old[0].ID || b.Boundary.PC != old[0].PC || !reflect.DeepEqual(old, b.ExcludedBoundaries) {
		t.Fatal("continuation replaced old exclusion or reused occurrence")
	}
	completed, err := CheckTransitionReturn(t.Context(), next)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := completed.Bound()
	if r.Instructions[len(r.Instructions)-1].ID != b.Boundary.ID || r.Accesses[len(r.Accesses)-1].ID != b.Boundary.ID {
		t.Fatal("return borrowed excluded occurrence")
	}
}

func TestTransitionOccurrenceAnchoredSameAddress(t *testing.T) {
	im := occurrenceImage(t, "b8000000004883c0014883f80375f690")
	prior, _ := occurrenceProof(t, im, occurrenceEntry+5, TransitionOptions{})
	old := prior.checked.bound
	q, err := ProposeNextTransitionContinuation(t.Context(), prior, old.Boundary.PC)
	if err != nil {
		t.Fatal(err)
	}
	next, err := CheckTransitionContinuation(t.Context(), prior, q)
	if err != nil {
		t.Fatal(err)
	}
	b := next.checked.bound
	if q.After != old.Boundary.ID || b.Endpoint != (TransitionEndpoint{Mode: TransitionFirstAfter, Anchor: old.Boundary.ID, Cut: b.Boundary.ID}) || b.Boundary.ID == old.Boundary.ID || b.Boundary.PC != old.Boundary.PC || b.Origin != old.Origin {
		t.Fatal("anchored locator lost exact later occurrence or original state")
	}
	if _, err := ProposeTransitionContinuation(t.Context(), prior, old.Boundary.PC); err == nil {
		t.Fatal("numeric locator became a later occurrence")
	}
	// The third visit is a valid first-future cut from the second visit. Moving
	// its anchor back to the first visit leaves a complete, reachable later cut,
	// but illegally executes the second visit instead of stopping there.
	third, err := ProposeNextTransitionContinuation(t.Context(), next, old.Boundary.PC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckTransitionContinuation(t.Context(), next, third); err != nil {
		t.Fatal("later-cut control lacks its valid immediate predecessor", err)
	}
	third.After = old.Boundary.ID
	skipped, err := CheckTransitionContinuation(t.Context(), prior, third)
	var skippedRefusal *Refusal
	if skipped.checked != nil || !errors.As(err, &skippedRefusal) || skippedRefusal.Premise != "transition-proposal" || skippedRefusal.PC != old.Boundary.PC {
		t.Fatal("checker skipped a feasible first-future encounter for a later valid cut", err)
	}
	for _, mode := range []string{"wrong-anchor", "numeric", "root", "foreign-id-alone", "anchor-frontier", "anchor-cut", "cancel", "budget"} {
		t.Run(mode, func(t *testing.T) {
			p := lifecycleProposal(q)
			c := prior
			ctx := t.Context()
			var got TransitionCertificate
			var err error
			want := "transition-anchor"
			switch mode {
			case "wrong-anchor":
				p.After = prior.checked.witness.Root
			case "numeric":
				p.After = 0
				want = "transition-continuation"
			case "anchor-frontier", "anchor-cut":
				for j := range p.Nodes {
					if p.Nodes[j].ID == p.After {
						p.Nodes[j].Successors = nil
						p.Nodes[j].Frontier = mode == "anchor-frontier"
					}
				}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "budget":
				limited := *c.checked
				limited.limits.Work = limited.work + 1
				c = TransitionCertificate{&limited}
			}
			if mode == "root" {
				got, err = CheckTransition(ctx, im, occurrenceFace(), p, TransitionLimits{})
			} else if mode == "foreign-id-alone" {
				got, err = CheckTransitionContinuation(ctx, TransitionCertificate{}, p)
				want = "transition-predecessor"
			} else {
				got, err = CheckTransitionContinuation(ctx, c, p)
			}
			if got.checked != nil {
				t.Fatal("invalid anchored extension published evidence")
			}
			if mode == "cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation replaced", err)
				}
				return
			}
			var r *Refusal
			if !errors.As(err, &r) {
				t.Fatal(err)
			}
			if mode == "budget" {
				if !strings.Contains(r.Premise, "budget") {
					t.Fatal(err)
				}
			} else if r.Premise != want {
				t.Fatal("wrong deciding refusal", mode, err)
			}
		})
	}
}

func TestTransitionOccurrenceSameSiteTheoremApplication(t *testing.T) {
	im := occurrenceImage(t, "41b800000000e8150000004983c0014983f80275f1c390"+strings.Repeat("90", 9)+"4c8b4c24f80fa248894424f8c3")
	f := occurrenceFace()
	f.Conditions.CPUID = CPUIDModel
	f.ReturnContext = &TransitionReturnContext{Target: occurrenceEntry + 22}
	p, err := ProposeRegionTransition(t.Context(), im, occurrenceEntry, occurrenceEntry+6, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	caller, err := CheckRegionTransition(t.Context(), im, occurrenceEntry, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	childFace := occurrenceFace()
	childFace.Conditions.CPUID = CPUIDModel
	childFace.Origin = OriginDomain{Min: 1 << 39, Max: 1 << 45, Modulus: 8}
	childFace.Envelope = RelativeSpan{-32, 32}
	childFace.Regions = []RelativeRegion{{Bytes: RelativeSpan{-32, 32}, Readable: true, Writable: true}}
	childFace.ReturnContext = &TransitionReturnContext{Target: occurrenceEntry + 11}
	childProposal, err := ProposeRegionTransition(t.Context(), im, occurrenceEntry+32, occurrenceEntry+44, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	child, err := CheckRegionTransition(t.Context(), im, occurrenceEntry+32, childFace, childProposal, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	theorem, err := CheckTransitionReturn(t.Context(), child)
	if err != nil {
		t.Fatal(err)
	}
	first, err := CheckTransitionCallReturn(t.Context(), caller, theorem)
	if err != nil {
		t.Fatal(err)
	}
	firstEnd, _ := first.Successor()
	firstBound := firstEnd.checked.bound
	q, err := ProposeNextTransitionContinuation(t.Context(), firstEnd, occurrenceEntry+6)
	if err != nil {
		t.Fatal(err)
	}
	secondCaller, err := CheckTransitionContinuation(t.Context(), firstEnd, q)
	if err != nil {
		t.Fatal(err)
	}
	if secondCaller.checked.bound.Boundary.ID == caller.checked.bound.Boundary.ID || secondCaller.checked.bound.Boundary.PC != caller.checked.bound.Boundary.PC {
		t.Fatal("same-site cut did not get a later occurrence")
	}
	second, err := CheckTransitionCallReturn(t.Context(), secondCaller, theorem)
	if err != nil {
		t.Fatal(err)
	}
	secondEnd, _ := second.Successor()
	b := secondEnd.checked.bound
	if !first.AppliesTo(theorem) || !second.AppliesTo(theorem) || b.Origin != caller.checked.bound.Origin || b.InitialRegisters != caller.checked.bound.InitialRegisters || len(b.PrimitiveEffects) != 2 || len(b.Accesses) != 8 {
		t.Fatal("same-site application lost scope or ordered effects")
	}
	a, z := b.PrimitiveEffects[0].(CPUIDEffect), b.PrimitiveEffects[1].(CPUIDEffect)
	if a.ID == z.ID || a.Context == z.Context || a.ResultsEAX.View().Scope == z.ResultsEAX.View().Scope || !reflect.DeepEqual(firstBound.PrimitiveEffects, b.PrimitiveEffects[:1]) || !reflect.DeepEqual(firstBound.Accesses, b.Accesses[:len(firstBound.Accesses)]) {
		t.Fatal("same-site invocation reused or replaced history")
	}
	// Every bit of the second child's old-scratch read comes from the first
	// query's stored zero-extended result, rather than fresh callee inputs.
	builder := br.NewBuilder(32)
	expected, err := builder.Make(br.ZExt, br.Bits(64), 0, a.ResultsEAX)
	if err != nil {
		t.Fatal(err)
	}
	for bit := 0; bit < 64; bit += 8 {
		left := occurrenceRange(t, builder, b.Registers[R9].Value, bit, 8)
		right := occurrenceRange(t, builder, expected, bit, 8)
		if _, err := br.Prove(t.Context(), left, right, br.Limits{}); err != nil {
			t.Fatal("released child scratch was reset", bit, err)
		}
	}
	endProposal := continuationProposal(t, secondEnd, occurrenceEntry+21)
	beforeReturn, err := CheckTransitionContinuation(t.Context(), secondEnd, endProposal)
	if err != nil {
		t.Fatal(err)
	}
	returned, err := CheckTransitionReturn(t.Context(), beforeReturn)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := returned.Bound()
	if !r.State.CalleeTerminated || len(r.Accesses) != 9 || r.State.PC != occurrenceEntry+22 {
		t.Fatal("same-site composition failed parent return")
	}
	// A separately checked full suffix reaches RET. Reinterpreting it as a
	// later CALL cut must reject its executed FIRST future CALL, independently
	// of discovery and of the remaining finite-progress proof.
	full, err := ProposeNextTransitionContinuation(t.Context(), firstEnd, occurrenceEntry+21, TransitionOptions{MaxOccurrences: 24, Expansions: []TransitionExpansion{{PC: occurrenceEntry + 6, AllActivations: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckTransitionContinuation(t.Context(), firstEnd, full); err != nil {
		t.Fatal("skip-first control has no positive baseline", err)
	}
	full.Cut = occurrenceEntry + 6
	bad, err := CheckTransitionContinuation(t.Context(), firstEnd, full)
	var refusal *Refusal
	if bad.checked != nil || !errors.As(err, &refusal) || refusal.Premise != "transition-cut" || refusal.PC != occurrenceEntry+6 {
		t.Fatal("checker permitted skipping the first future target", err)
	}
}

// Decompose every requested bit range through the expression language's exact
// byte assembly/projection operators. This avoids requiring an unrelated whole-
// word Concat/Extract normalizer while comparing all 64 restored bits.
func occurrenceRange(t *testing.T, b *br.Builder, x br.Term, lo, width int) br.Term {
	t.Helper()
	v := x.View()
	constant := func(value uint64) br.Term {
		r, err := b.Const(br.Bits(width), value)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	switch v.Op {
	case br.Constant:
		return constant(v.Immediate >> uint(lo) & mask(width))
	case br.Extract:
		return occurrenceRange(t, b, v.Args[0], lo+int(v.Immediate), width)
	case br.Trunc:
		return occurrenceRange(t, b, v.Args[0], lo, width)
	case br.ZExt:
		if lo >= v.Args[0].Sort().Width() {
			return constant(0)
		}
		if lo+width <= v.Args[0].Sort().Width() {
			return occurrenceRange(t, b, v.Args[0], lo, width)
		}
	case br.Concat:
		low := v.Args[0].Sort().Width()
		if lo+width <= low {
			return occurrenceRange(t, b, v.Args[0], lo, width)
		}
		if lo >= low {
			return occurrenceRange(t, b, v.Args[1], lo-low, width)
		}
	}
	if lo == 0 && width == x.Sort().Width() {
		return x
	}
	r, err := b.Make(br.Extract, br.Bits(width), uint64(lo), x)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTransitionOccurrenceRepeatedCallActivation(t *testing.T) {
	im := occurrenceImage(t, "41b800000000e80d0000004983c0014983f80375f1909090c3")
	c, _ := occurrenceProof(t, im, occurrenceEntry+21, TransitionOptions{MaxOccurrences: 16, Expansions: []TransitionExpansion{{PC: occurrenceEntry + 6}}})
	b, _ := c.Bound()
	parents := map[TransitionActivationID]TransitionOccurrenceID{}
	for _, ins := range b.Instructions {
		if ins.Start == occurrenceEntry+6 {
			parents[TransitionActivationID(ins.ID)] = ins.ID
		}
	}
	if len(parents) != 3 || len(b.Frames) != 0 {
		t.Fatal("repeated CALL collapsed or left active frame")
	}
	returns := 0
	for _, access := range b.Accesses {
		if access.Kind == FrameReturnRead {
			returns++
			if parents[access.Context] == 0 || access.PC != occurrenceEntry+24 {
				t.Fatal("return not bound to its actual CALL")
			}
		}
	}
	if returns != 3 {
		t.Fatal("return effect lost")
	}
}

func TestTransitionOccurrenceCalleeLoopApplication(t *testing.T) {
	im := occurrenceImage(t, "e80b0000009090909090909090909090b8000000004883c0014883f80375f6c3")
	childFace := occurrenceFace()
	childFace.Origin = OriginDomain{Min: 1 << 39, Max: 1 << 45, Modulus: 8}
	childFace.Envelope = RelativeSpan{-32, 32}
	childFace.Regions = []RelativeRegion{{Bytes: RelativeSpan{-32, 32}, Readable: true, Writable: true}}
	childFace.ReturnContext = &TransitionReturnContext{Target: occurrenceEntry + 5}
	p, err := ProposeRegionTransition(t.Context(), im, occurrenceEntry+16, occurrenceEntry+31, TransitionLimits{}, TransitionOptions{MaxOccurrences: 10})
	if err != nil {
		t.Fatal(err)
	}
	child, err := CheckRegionTransition(t.Context(), im, occurrenceEntry+16, childFace, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := CheckTransitionReturn(t.Context(), child)
	if err != nil {
		t.Fatal(err)
	}
	parent, _ := occurrenceProof(t, im, occurrenceEntry, TransitionOptions{})
	application, err := CheckTransitionCallReturn(t.Context(), parent, completed)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := application.Bound()
	if !application.AppliesTo(completed) || a.Successor.Origin != parent.checked.bound.Origin || len(a.Successor.Frames) != 0 || a.Successor.Boundary.Context != 0 || a.Successor.Boundary.PC != occurrenceEntry+5 {
		t.Fatal("application reset caller or failed return")
	}
	if len(a.Successor.ExcludedBoundaries) != 1 || !a.Successor.ExcludedBoundaries[0].Frontier || a.Successor.ExcludedBoundaries[0].Context != a.Activation {
		t.Fatal("callee frontier mapping lost")
	}
	ids := map[TransitionOccurrenceID]bool{}
	for _, ins := range a.Successor.Instructions {
		if ids[ins.ID] {
			t.Fatal("noninjective embedding")
		}
		ids[ins.ID] = true
	}
	childFace.Conditions.CPUID = CPUIDModel
	strong, err := CheckRegionTransition(t.Context(), im, occurrenceEntry+16, childFace, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	strongReturn, err := CheckTransitionReturn(t.Context(), strong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckTransitionCallReturn(t.Context(), parent, strongReturn); err == nil {
		t.Fatal("unestablished callee premise accepted")
	}
}

func TestTransitionOccurrenceReturnCorruptionAndBudgets(t *testing.T) {
	im := occurrenceImage(t, "e8010000009048c7042400000000c3")
	p, err := ProposeTransition(t.Context(), im, occurrenceEntry+5, TransitionLimits{}, TransitionOptions{Expansions: []TransitionExpansion{{PC: occurrenceEntry}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckTransition(t.Context(), im, occurrenceFace(), p, TransitionLimits{}); err == nil {
		t.Fatal("corrupt actual return word accepted")
	}
	im = occurrenceImage(t, "b8000000004883c0014883f80375f690")
	_, p = occurrenceProof(t, im, occurrenceEntry+15, TransitionOptions{MaxOccurrences: 10})
	for _, limits := range []TransitionLimits{{RelationLimits: RelationLimits{Instructions: len(p.Nodes) - 1}}, {RelationLimits: RelationLimits{Work: 3}}, {LiveStateBytes: 4096}} {
		if c, err := CheckTransition(t.Context(), im, occurrenceFace(), p, limits); err == nil || c.checked != nil {
			t.Fatal("resource exhaustion became successful frontier")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if c, err := CheckTransition(ctx, im, occurrenceFace(), p, TransitionLimits{}); err == nil || c.checked != nil {
		t.Fatal("cancelled check published proof")
	}
}
