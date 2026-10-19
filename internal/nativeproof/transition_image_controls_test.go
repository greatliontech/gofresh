package nativeproof

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
	"golang.org/x/arch/x86/x86asm"
)

// Missing-primitive-premise control. A structural proposal can cross CPUID,
// but neither direct nor continuation checking can invent its applicability.
func assertCPUQueryExecutionRefused(t testing.TB, im *Image, face TransitionInterface, prefix TransitionProposal, prior TransitionCertificate) {
	t.Helper()
	boundary := prior.checked.bound.Boundary
	if boundary.PC != prefix.Cut || !bytes.Equal(boundary.Bytes, []byte{0x0f, 0xa2}) {
		t.Fatal("control is not the checked, unexecuted CPUID")
	}
	next := boundary.PC + 2
	raw, err := im.instructionBytes(next)
	if err != nil {
		t.Fatal("following boundary must be mapped", err)
	}
	instruction, valid := cutReference(raw)
	if !valid || instruction.Len <= 0 {
		t.Fatal("following boundary must independently decode")
	}
	attempt := lifecycleProposal(prefix)
	attempt.Cut = next
	found := false
	for j := range attempt.Nodes {
		if attempt.Nodes[j].PC == boundary.PC {
			if attempt.Nodes[j].Size != 2 || len(attempt.Nodes[j].Successors) != 0 {
				t.Fatal("old cut inventory differs")
			}
			attempt.Nodes[j].Successors = []TransitionOccurrenceID{TransitionOccurrenceID(next)}
			found = true
		}
	}
	if !found {
		t.Fatal("missing old cut")
	}
	attempt.Nodes = append(attempt.Nodes, TransitionNode{ID: TransitionOccurrenceID(next), PC: next, Size: uint8(instruction.Len)})
	proposed, err := ProposeTransition(t.Context(), im, next, TransitionLimits{})
	if err != nil {
		t.Fatal("structurally valid CPUID proposal refused", err)
	}
	stateSameInventory(t, proposed, attempt)
	direct, err := CheckTransition(t.Context(), im, face, attempt, TransitionLimits{})
	sequenceRefused(t, direct, err, "transition-primitive-premise", boundary.PC)
	continued, err := CheckTransitionContinuation(t.Context(), prior, attempt)
	sequenceRefused(t, continued, err, "transition-primitive-premise", boundary.PC)
}

// Recheck the original root with the additional configuration predicate, then
// consume that opaque root for exactly one architectural query. The decoded
// following instruction remains unexecuted. No hardware response is sampled.
func assertCPUQueryConditionalStep(t testing.TB, im *Image, face TransitionInterface, prefix TransitionProposal, following x86asm.Op) {
	t.Helper()
	tuples := [][4]uint32{{0, 0, 0, 0}, {0x80000000, 0xffffffff, 0x12345678, 0x87654321}}
	nextPC := prefix.Cut + 2
	raw, err := im.instructionBytes(nextPC)
	if err != nil {
		t.Fatal(err)
	}
	next, valid := cutReference(raw)
	if !valid || next.Op != following {
		t.Fatalf("CPU query's following boundary differs: bytes=%x decoded=%v valid=%v want=%v", raw, next, valid, following)
	}
	face = cloneTransitionInterface(face)
	face.Conditions.CPUID = CPUIDModel
	root, err := CheckTransition(t.Context(), im, face, prefix, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	before := lifecycleSnapshot(root.checked.bound)
	if !bytes.Equal(before.Boundary.Bytes, []byte{0x0f, 0xa2}) || before.Registers[RCX].Value != before.InitialRegisters[RCX] || stateEval(t, before.Registers[RAX].Value, nil) != 0 {
		t.Fatal("query control requires proved EAX zero and arbitrary original ECX")
	}
	p, err := ProposeTransition(t.Context(), im, nextPC, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransitionContinuation(t.Context(), root, p)
	if err != nil {
		t.Fatal(err)
	}
	b := c.checked.bound
	stateInheritedInputs(t, before, b)
	fetches := straightFetches(t, b)
	if len(b.PrimitiveEffects) != 1 || b.Boundary.PC != nextPC || b.Boundary.Instruction != next || !bytes.Equal(b.Boundary.Bytes, raw[:next.Len]) || len(b.Instructions) != len(before.Instructions)+1 || fetches[len(before.Instructions)] != (Span{prefix.Cut, nextPC}) || !slices.Equal(b.Instructions[:len(before.Instructions)], before.Instructions) {
		t.Fatal("query occurrence or following unexecuted boundary differs")
	}
	e := b.PrimitiveEffects[0].(CPUIDEffect)
	for reg := RAX; reg <= R15; reg++ {
		var output br.Term
		switch reg {
		case RAX:
			output = e.ResultsEAX
		case RBX:
			output = e.ResultsEBX
		case RCX:
			output = e.ResultsECX
		case RDX:
			output = e.ResultsEDX
		default:
			if b.Registers[reg] != before.Registers[reg] || b.Preserved[reg] != before.Preserved[reg] {
				t.Fatal("query changed another register")
			}
			continue
		}
		v := b.Registers[reg].Value.View()
		if v.Op != br.ZExt || v.Sort != br.Bits(64) || len(v.Args) != 1 || v.Args[0] != output || b.Registers[reg].Pointer != nil || b.Preserved[reg] != 0 {
			t.Fatal("query output register transfer differs")
		}
	}
	if !slices.Equal(b.Memory, before.Memory) || !slices.Equal(b.Accesses, before.Accesses) || b.Flags != before.Flags || c.checked.flags != root.checked.flags {
		t.Fatal("query changed ordinary memory, access inventory or flags")
	}
	for _, tuple := range tuples {
		for _, selector := range []uint64{0, 0x1234567887654321, ^uint64(0)} {
			values := map[br.Term]uint64{b.InitialRegisters[RCX]: selector}
			want := stateReference{primitives: []statePrimitive{stateQuery{instruction: 0, leaf: 0, subleaf: uint32(selector), results: tuple}}}
			stateQueryBindings(t, b, stateLayout{pcs: []uint64{prefix.Cut}}, want, values)
			for slot, reg := range []Register{RAX, RBX, RCX, RDX} {
				if stateEval(t, b.Registers[reg].Value, values) != uint64(tuple[slot]) {
					t.Fatal("query output mapping/zero extension differs")
				}
			}
		}
	}
	direct, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	assertTransitionAlpha(t, direct, c)
	if !reflect.DeepEqual(before, root.checked.bound) {
		t.Fatal("query mutated its predecessor")
	}
	t.Logf("conditional architectural CPUID at %#x reaches unexecuted %v %#x; four unconstrained outcomes, no actual CPU applicability claim", prefix.Cut, next.Op, nextPC)
}

// Each negative removes exactly one premise from a successful full interface.
// In particular, the narrow envelope retains the adequate S bound and image
// footprint; absence of permission is tested with the broad envelope intact.
func assertImagePrefixMissingPremises(t testing.TB, im *Image, face TransitionInterface, proposal TransitionProposal, ripPC uint64) {
	t.Helper()
	raw, err := im.instructionBytes(ripPC)
	if err != nil {
		t.Fatal(err)
	}
	rip, err := to.Parse(raw, ripPC)
	if err != nil || rip.Intent.Operation != to.LEARIP {
		t.Fatal("RIP control", err)
	}
	raw, err = im.instructionBytes(rip.Next)
	if err != nil {
		t.Fatal(err)
	}
	stack, err := to.Parse(raw, rip.Next)
	if err != nil || stack.Intent.Operation != to.LEA || stack.Intent.Base != 4 || stack.Intent.SignedDisp != -65536 {
		t.Fatal("stack LEA control", err)
	}
	for _, kind := range []string{"envelope", "permission"} {
		bad := cloneTransitionInterface(face)
		pc, premise := rip.Next, "transition-envelope"
		if kind == "envelope" {
			bad.Envelope.Start = -48
		} else {
			bad.ImageRegions = nil
			pc, premise = stack.Next, "transition-permission"
		}
		root := continuationRoot(t, im, ripPC, bad, TransitionLimits{})
		direct, err := CheckTransition(t.Context(), im, bad, proposal, TransitionLimits{})
		sequenceRefused(t, direct, err, premise, pc)
		continued, err := CheckTransitionContinuation(t.Context(), root, proposal)
		sequenceRefused(t, continued, err, premise, pc)
	}
}
