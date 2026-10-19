package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// Only a checked occurrence shape supplies assignment meaning. Numerical answers
// come from the test-owned reference tuples, never from a checker expression.
// Selectors are evaluated before this occurrence's outputs become bound.
func stateQueryBindings(t testing.TB, b TransitionBound, x stateLayout, want stateReference, values map[br.Term]uint64) {
	t.Helper()
	if err := statePrimitiveBindings(t, b, x, want, values); err != nil {
		t.Fatal(err)
	}
}

// Compare the single concrete execution stream position by position, binding
// each query's outcomes only after its earlier dependencies have been checked.
// Returning shape/order failures lets adversarial evidence controls exercise
// the same oracle without invoking a second, weaker order-only predicate.
func statePrimitiveBindings(t testing.TB, b TransitionBound, x stateLayout, want stateReference, values map[br.Term]uint64) error {
	t.Helper()
	if len(b.PrimitiveEffects) != len(want.primitives) {
		return fmt.Errorf("ordered primitive inventory differs")
	}
	entry := b.Origin.View().Scope
	known := map[br.Term]uint64{}
	for term, value := range values {
		if v := term.View(); v.Scratch && v.Scope == entry {
			known[term] = value
		}
	}
	scopes := map[br.Scope]bool{entry: true}
	for j, reference := range want.primitives {
		switch q := reference.(type) {
		case stateQuery:
			e, ok := b.PrimitiveEffects[j].(CPUIDEffect)
			if !ok || b.Interface.Conditions.CPUID != CPUIDModel || e.PC != x.pcs[q.instruction] || e.Context != q.context || e.Leaf.Sort() != br.Bits(32) || e.Subleaf.Sort() != br.Bits(32) {
				return fmt.Errorf("primitive %d kind/PC/context/model/selector width differs", j)
			}
			if stateEval(t, e.Leaf, known) != uint64(q.leaf) || stateEval(t, e.Subleaf, known) != uint64(q.subleaf) {
				return fmt.Errorf("query did not capture both old selectors")
			}
			scope := e.ResultsEAX.View().Scope
			if scope == (br.Scope{}) || scopes[scope] {
				return fmt.Errorf("query scope not fresh per occurrence")
			}
			scopes[scope] = true
			for slot, term := range []br.Term{e.ResultsEAX, e.ResultsEBX, e.ResultsECX, e.ResultsEDX} {
				v := term.View()
				if v.Op != br.Variable || v.Sort != br.Bits(32) || v.Scratch || v.Scope != scope || v.Immediate != uint64(slot) || len(v.Args) != 0 {
					return fmt.Errorf("query outcomes not independent BV32 inputs")
				}
				known[term], values[term] = uint64(q.results[slot]), uint64(q.results[slot])
			}
		case stateRMW:
			e, ok := b.PrimitiveEffects[j].(LockedCompareExchange64Effect)
			var terms []br.Term
			var expected []uint64
			switch q.kind {
			case to.LockedExchange:
				x, valid := b.PrimitiveEffects[j].(LockedExchange64Effect)
				ok = valid
				e.PC, e.Context, e.ReadAccess, e.WriteAccess, e.Before, e.After = x.PC, x.Context, x.ReadAccess, x.WriteAccess, x.Before, x.After
				terms, expected = []br.Term{x.Before, x.Replacement, x.After, x.Register}, []uint64{q.before, q.replacement, q.after, q.accumulator}
			case to.LockedExchangeAdd:
				x, valid := b.PrimitiveEffects[j].(LockedExchangeAdd64Effect)
				ok = valid
				e.PC, e.Context, e.ReadAccess, e.WriteAccess, e.Before, e.After = x.PC, x.Context, x.ReadAccess, x.WriteAccess, x.Before, x.After
				terms, expected = []br.Term{x.Before, x.Delta, x.After, x.Register}, []uint64{q.before, q.replacement, q.after, q.accumulator}
			default:
				success := uint64(0)
				if q.success {
					success = 1
				}
				terms, expected = []br.Term{e.Before, e.Compare, e.Replacement, e.After, e.Accumulator, e.Success}, []uint64{q.before, q.compare, q.replacement, q.after, q.accumulator, success}
			}
			if !ok || e.PC != x.pcs[q.instruction] || e.Context != q.context || e.ReadAccess != q.readAccess || e.WriteAccess != q.readAccess+1 || e.ReadAccess < 0 || e.WriteAccess >= len(b.Accesses) || b.Interface.Conditions.Locked64 != Locked64Model {
				return fmt.Errorf("primitive %d locked occurrence/group differs", j)
			}
			for k, term := range terms {
				width := br.Bits(64)
				if k == 5 {
					width = br.Bool()
				}
				if term.Sort() != width || stateEval(t, term, known) != expected[k] {
					return fmt.Errorf("locked scalar relation %d differs", k)
				}
			}
			read, write := b.Accesses[e.ReadAccess], b.Accesses[e.WriteAccess]
			if read.Kind != FrameRead || write.Kind != FrameWrite || read.PC != e.PC || write.PC != e.PC || read.Context != e.Context || write.Context != e.Context || read.Bytes != write.Bytes || read.Image != write.Image || read.Value != e.Before || write.Value != e.After {
				return fmt.Errorf("locked read/write lost grouping")
			}
		default:
			return fmt.Errorf("unsupported reference primitive %T", reference)
		}
	}
	return nil
}

func cpuidFace() TransitionInterface {
	f := sequenceFace(7)
	f.Conditions.CPUID = CPUIDModel
	return f
}

func cpuidProgram() []stateInstruction {
	var program []stateInstruction
	emit := func(i to.Intent) { program = append(program, stateOp(i, 0)) }
	// Undefined AF and its private predicates must survive each query unchanged.
	emit(to.Intent{Operation: to.And, Dst: 4, Immediate: ^uint64(15)})
	for _, reg := range []uint8{0, 3, 1, 2} {
		emit(to.Intent{Operation: to.MoveRegister, Dst: reg, Src: 4})
	}
	emit(to.Intent{Operation: to.CPUID})
	// All four lanes flow through ordinary memory, including non-selector EBX/EDX.
	for slot, reg := range []uint8{0, 3, 1, 2} {
		emit(to.Intent{Operation: to.Store, Base: 4, Src: reg, SignedDisp: int64(8 * slot)})
	}
	// The second query selects with the first query's results.
	emit(to.Intent{Operation: to.CPUID})
	for _, reg := range []uint8{0, 3, 1, 2} {
		emit(to.Intent{Operation: to.MoveImmediate, Dst: reg, Immediate: 0})
	}
	// Two identical selector pairs may produce different independent tuples.
	emit(to.Intent{Operation: to.CPUID})
	for _, reg := range []uint8{0, 3, 1, 2} {
		emit(to.Intent{Operation: to.MoveImmediate, Dst: reg, Immediate: 0})
	}
	emit(to.Intent{Operation: to.CPUID})
	for _, reg := range []uint8{0, 3, 1, 2} {
		emit(to.Intent{Operation: to.MoveImmediate, Dst: reg, Immediate: 0})
	}
	emit(to.Intent{Operation: to.MoveRegister, Dst: 15, Src: 4})
	return program
}

func TestTransitionCPUIDProduct(t *testing.T) {
	if err := quick.Check(func(tuples [4][4]uint32, initial [512]byte, layout uint64) bool {
		face := cpuidFace()
		r := stateRawInitial(face, initial[:])
		r.outcomes = tuples[:]
		stateCheckProgram(t, []stateInstruction{stateOp(to.Intent{Operation: to.CPUID}, 0)}, face, r, layout, 0, true)
		stateCheckProgram(t, cpuidProgram(), face, r, layout, 0, true)
		return true
	}, &quick.Config{MaxCount: 24}); err != nil {
		t.Fatal(err)
	}
}

func FuzzTransitionCPUIDSequence(f *testing.F) {
	var records []byte
	for _, i := range cpuidProgram() {
		records = append(records, sequenceRecord(i.intent, i.choice)...)
	}
	valuation := make([]byte, 512)
	for j := range valuation {
		valuation[j] = byte(j*37 + 17)
	}
	f.Add(records, []byte{0x24}, []byte{0xff, 0xff, 0xff, 0xff}, valuation, uint64(73))
	f.Add(sequenceRecord(to.Intent{Operation: to.CPUID}, 0), []byte{}, []byte{255}, valuation, uint64(0))
	f.Fuzz(func(t *testing.T, records, blocks, cuts, raw []byte, layout uint64) {
		checkStateSequence(t, cpuidFace(), sequenceRecords(records, blocks, 4096), raw, cuts, layout, 4096)
	})
}

// This compact factor preserves the full 128-bit response product and independent
// 64-bit selectors while avoiding long-sequence mutation cost. The evolving
// sequence family separately exercises arbitrary interleaving and segmentation.
func FuzzTransitionCPUIDProduct(f *testing.F) {
	for _, v := range []uint32{0, 1, 0x80000000, 0xffffffff} {
		f.Add(v, ^v, v^0x12345678, v^0x87654321, uint64(0xfedcba9876543210), uint64(0x8765432112345678), []byte{17, 31, 63, 127, 255})
	}
	f.Fuzz(func(t *testing.T, eax, ebx, ecx, edx uint32, rax, rcx uint64, raw []byte) {
		face := cpuidFace()
		initial := stateRawInitial(face, raw)
		initial.regs[0], initial.regs[1] = rax, rcx
		initial.outcomes = [][4]uint32{{eax, ebx, ecx, edx}}
		stateCheckProgram(t, []stateInstruction{stateOp(to.Intent{Operation: to.CPUID}, 0)}, face, initial, 0, 0, true)
	})
}

func TestTransitionCPUIDEncoding(t *testing.T) {
	compareExecutedEncoding(t, []byte{0x0f, 0xa2})
	compareExecutedEncoding(t, []byte{0x0f})
	for prefix := 0; prefix < 256; prefix++ {
		compareExecutedEncoding(t, []byte{byte(prefix), 0x0f, 0xa2})
	}
	for second := 0; second < 256; second++ {
		compareExecutedEncoding(t, []byte{0x0f, byte(second)})
	}
}

func TestTransitionCPUIDPremisesAndIdentity(t *testing.T) {
	im, cut := transitionFixture(t, "0fa2")
	p := continuationProposal(t, im, cut)
	face := cpuidFace()
	for _, model := range []string{"", "unknown", CPUIDModel + ";extra"} {
		bad := cloneTransitionInterface(face)
		bad.Conditions.CPUID = model
		c, err := CheckTransition(t.Context(), im, bad, p, TransitionLimits{})
		premise := "transition-primitive-model"
		if model == "" {
			premise = "transition-primitive-premise"
		}
		sequenceRefused(t, c, err, premise, testEntry)
		if model == "" {
			root := continuationRoot(t, im, testEntry, bad, TransitionLimits{})
			projection, _ := root.Bound()
			projection.Interface.Conditions.CPUID = CPUIDModel
			c, err = CheckTransitionContinuation(t.Context(), root, p)
			sequenceRefused(t, c, err, premise, testEntry)
		}
	}
	root := continuationRoot(t, im, testEntry, face, TransitionLimits{})
	for _, rules := range []string{"gofresh/native-transition@3;" + ValueRules + ";" + FrameRules, "gofresh/native-transition@4;" + ValueRules + ";" + FrameRules, TransitionRules + ";unknown"} {
		old := *root.checked
		old.bound.Rules = rules
		c, err := CheckTransitionContinuation(t.Context(), TransitionCertificate{&old}, p)
		sequenceRefused(t, c, err, "transition-predecessor", 0)
	}
	for _, mutate := range []func(*TransitionConditions){
		func(c *TransitionConditions) { c.Machine = "unknown" },
		func(c *TransitionConditions) { c.InstructionMapping = false },
		func(c *TransitionConditions) { c.EntryState = false },
		func(c *TransitionConditions) { c.IsolatedExecution = false },
		func(c *TransitionConditions) { c.MemoryMapping = false },
		func(c *TransitionConditions) { c.NoHiddenAliases = false },
		func(c *TransitionConditions) { c.UnalignedAccess = false },
	} {
		bad := cloneTransitionInterface(face)
		mutate(&bad.Conditions)
		c, err := CheckTransition(t.Context(), im, bad, p, TransitionLimits{})
		sequenceRefused(t, c, err, "transition-premises", testEntry)
	}
}

func TestTransitionCPUIDInheritedEffectsAndSiblings(t *testing.T) {
	im, cut := transitionFixture(t, "0fa2b800000000bb00000000b900000000ba000000004889e70fa2")
	face := cpuidFace()
	root := continuationRoot(t, im, testEntry+2, face, TransitionLimits{})
	before := lifecycleSnapshot(root.checked.bound)
	// The next boundary follows complete result overwrite; another continuation
	// must retain selectors and outputs that have no remaining state users.
	middle := continuationProposal(t, im, cut-2)
	parent, err := CheckTransitionContinuation(t.Context(), root, middle)
	if err != nil {
		t.Fatal(err)
	}
	stateInheritedInputs(t, before, parent.checked.bound)
	old := lifecycleSnapshot(parent.checked.bound)
	proposal := continuationProposal(t, im, cut)
	assertTransitionRetainedExpressionUnion(t, parent, proposal)
	left, err := CheckTransitionContinuation(t.Context(), parent, proposal)
	if err != nil {
		t.Fatal(err)
	}
	right, err := CheckTransitionContinuation(t.Context(), parent, proposal)
	if err != nil {
		t.Fatal(err)
	}
	stateInheritedInputs(t, old, left.checked.bound)
	stateInheritedInputs(t, old, right.checked.bound)
	a := left.checked.bound.PrimitiveEffects[1].(CPUIDEffect)
	b := right.checked.bound.PrimitiveEffects[1].(CPUIDEffect)
	if a.ResultsEAX.View().Scope == b.ResultsEAX.View().Scope {
		t.Fatal("siblings reused outcome origin")
	}
	projection, _ := parent.Bound()
	projection.PrimitiveEffects[0] = CPUIDEffect{}
	if !reflect.DeepEqual(old, parent.checked.bound) || !reflect.DeepEqual(before, root.checked.bound) {
		t.Fatal("projection/continuation mutated ancestor")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c, err := CheckTransitionContinuation(ctx, parent, proposal)
	if c.checked != nil || err == nil {
		t.Fatal("cancelled query published evidence")
	}
	if !slices.Equal(parent.checked.bound.PrimitiveEffects, old.PrimitiveEffects) {
		t.Fatal("cancelled query changed effects")
	}
}

func TestTransitionCPUIDCoincidentPointerDestruction(t *testing.T) {
	for _, imagePointers := range []bool{false, true} {
		face := imageStateFace()
		face.Conditions.CPUID = CPUIDModel
		face.Origin = OriginDomain{Min: 1 << 28, Max: 1 << 29, Modulus: 16}
		face.Envelope = RelativeSpan{-65536, 65536}
		var program []stateInstruction
		for slot, reg := range []uint8{0, 3, 1, 2} {
			i := to.Intent{Operation: to.MoveRegister, Dst: reg, Src: 4}
			if imagePointers {
				i = to.Intent{Operation: to.LEARIP, Dst: reg, SignedDisp: int64(imageStateAddress) - int64(testEntry+uint64(7*(slot+1)))}
			}
			program = append(program, stateOp(i, 0))
		}
		program = append(program, stateOp(to.Intent{Operation: to.CPUID}, 0))
		raw := make([]byte, 8+128+1+sequenceCardinality(face)+16)
		for j := 8; j < len(raw)-16; j++ {
			raw[j] = byte(j*73 + 19)
		}
		value := uint32(face.Origin.Min)
		if imagePointers {
			value = uint32(imageStateAddress)
		}
		for j := 0; j < 4; j++ {
			binary.LittleEndian.PutUint32(raw[len(raw)-16+j*4:], value)
		}
		checkStateSequence(t, face, program, raw, []byte{255}, 0, 4096, imageStateLoads()...)
	}
}

func TestTransitionCPUIDRetainedBudgets(t *testing.T) {
	face := cpuidFace()
	face.Regions, face.ImageRegions, face.Words = nil, nil, nil
	// Initial 16 registers, 3 predicates and 2 constants; the query adds two
	// selectors, four variables and four extensions. One shared constant replaces
	// every result. The root needs 32 nodes, while inherited event-only roots plus
	// the new query exceed that same combined allowance.
	code := "0fa248b8000000000000000048bb000000000000000048b9000000000000000048ba00000000000000000fa2"
	im, cut := transitionFixture(t, code)
	p := continuationProposal(t, im, cut)
	root := continuationRoot(t, im, cut-2, face, TransitionLimits{RelationLimits: RelationLimits{Nodes: 32}})
	c, err := CheckTransitionContinuation(t.Context(), root, p)
	sequenceRefused(t, c, err, "relation-budget", cut-2)
	root = continuationRoot(t, im, cut-2, face, TransitionLimits{})
	assertTransitionRetainedExpressionUnion(t, root, p)
	next, err := CheckTransitionContinuation(t.Context(), root, p)
	if err != nil {
		t.Fatal(err)
	}
	bounded := continuationRoot(t, im, cut-2, face, TransitionLimits{RelationLimits: RelationLimits{Work: next.checked.work - 1}})
	c, err = CheckTransitionContinuation(t.Context(), bounded, p)
	sequenceRefused(t, c, err, "relation-budget", cut)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Detail != "construction work budget" {
		t.Fatal("continuation did not exhaust its cumulative work allowance", err)
	}
	if bounded.checked.work >= next.checked.work-1 {
		t.Fatal("root exhausted continuation allowance")
	}
	// A deep old selector retained only by the event remains an import root.
	im, cut = transitionFixture(t, strings.Repeat("488d4001", 20)+code)
	root = continuationRoot(t, im, cut-2, face, TransitionLimits{})
	assertTransitionRetainedExpressionUnion(t, root, continuationProposal(t, im, cut))
	m, err := newTransitionChecker(t.Context(), im, transitionRoot{entry: im.entry}, root.checked.limits, 0)
	if err != nil {
		t.Fatal(err)
	}
	m.limits.Depth, m.valueBuilder.limits.Depth = 21, 21
	if err := m.inherit(*root.checked); !errors.As(err, &refusal) || refusal.Premise != "relation-budget" || refusal.Detail != "input expression depth" || refusal.PC != im.entry {
		t.Fatal("event-only selector did not trigger the import-depth refusal", err)
	}
	// An executed query's selector extraction itself must respect depth, even
	// though its new register values have shallow depth two.
	root = continuationRoot(t, im, testEntry+80, face, TransitionLimits{RelationLimits: RelationLimits{Depth: 21}})
	c, err = CheckTransitionContinuation(t.Context(), root, continuationProposal(t, im, testEntry+82))
	stateExpressionDepthRefused(t, c, err, testEntry+80)
}

func TestTransitionCPUIDIndependentRawTuples(t *testing.T) {
	// Explicitly exercise all four 32-bit lanes' high bits independently.
	for lane := 0; lane < 4; lane++ {
		for bit := 0; bit < 32; bit++ {
			face := cpuidFace()
			r := stateRawInitial(face, nil)
			r.outcomes = make([][4]uint32, 1)
			r.outcomes[0][lane] = uint32(1) << bit
			stateCheckProgram(t, []stateInstruction{stateOp(to.Intent{Operation: to.CPUID}, 0)}, face, r, uint64(bit), 0, true)
		}
	}
	// Full raw product tail is independent of entry registers and memory.
	face := cpuidFace()
	raw := make([]byte, 8+128+1+sequenceCardinality(face)+16)
	for j, v := range []uint32{0x80000000, 0xffffffff, 0x12345678, 0x87654321} {
		binary.LittleEndian.PutUint32(raw[len(raw)-16+j*4:], v)
	}
	r := stateRawInitial(face, raw)
	stateCheckProgram(t, []stateInstruction{stateOp(to.Intent{Operation: to.CPUID}, 0)}, face, r, 73, 0, true)
}
