package nativeproof

import (
	"context"
	"errors"
	"math"
	"reflect"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

const returnFrameCode = "493b66107613554889e54883ec10b82a0000004883c4105dc30f0b"
const returnContinuation = testEntry + 64

func returnFixture(t testing.TB, text string) (*Image, TransitionInterface) {
	t.Helper()
	code := hexBytes(t, text)
	if len(code) > 64 {
		t.Fatal("fixture continuation overlaps code")
	}
	for len(code) < 64 {
		code = append(code, 0x90)
	}
	code = append(code, 0xbb, 1, 0, 0, 0)
	im, err := NewImage(t.Context(), transitionImageELF(t, code, imageStateLoads()))
	if err != nil {
		t.Fatal(err)
	}
	face := TransitionInterface{
		Origin: OriginDomain{Min: 4096, Max: 1<<47 - 4096, Modulus: 16}, Envelope: RelativeSpan{-24, 8},
		Regions:       []RelativeRegion{{Bytes: RelativeSpan{-24, 0}, Readable: true, Writable: true}, {Bytes: RelativeSpan{0, 8}, Readable: true}},
		Conditions:    interfaceConditions(),
		ReturnContext: &TransitionReturnContext{Target: returnContinuation, Preserved: []Register{RBP}},
	}
	return im, face
}

func returnPrefix(t testing.TB, im *Image, face TransitionInterface, cut uint64, expansions ...TransitionExpansion) TransitionCertificate {
	t.Helper()
	return entryRelationCheck(t, im, face, entryRelationProposal(t, im, cut, expansions...))
}

func checkedReturn(t testing.TB, prefix TransitionCertificate) TransitionReturnCertificate {
	t.Helper()
	c, err := CheckTransitionReturn(t.Context(), prefix)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func returnRefused(t testing.TB, c TransitionReturnCertificate, err error) {
	t.Helper()
	if err == nil || c.checked != nil {
		t.Fatal("invalid terminal relation acquired authority", err)
	}
	var r *Refusal
	if !errors.As(err, &r) && !errors.Is(err, context.Canceled) {
		t.Fatal("unstructured return refusal", err)
	}
}

func TestTransitionReturnActualGuardedFrame(t *testing.T) {
	im, face := returnFixture(t, returnFrameCode)
	face.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 24}}
	face.EntryImagePointers = []TransitionEntryImagePointer{{Register: R14, Address: imageStateAddress}}
	face.EntryWordUpperBounds = []TransitionEntryWordUpperBound{{Address: imageStateAddress + 16}}
	face.ReturnContext.Preserved = []Register{RBP, R14}
	ret := testEntry + 24
	direct := returnPrefix(t, im, face, ret, TransitionExpansion{PC: testEntry})
	complete := checkedReturn(t, direct)
	b, ok := complete.BoundFor(im)
	if !ok || !b.State.CalleeTerminated || b.State.PC != returnContinuation || b.Continuation.PC != returnContinuation || len(b.State.Restored) != 2 || len(b.Prefix.Frames) != 0 {
		t.Fatal("missing terminal context or checked continuation")
	}
	if len(b.Prefix.Instructions) != 8 || len(b.Instructions) != 9 || len(b.Prefix.Accesses) != 3 || len(b.Accesses) != 4 || len(b.Prefix.ExcludedBoundaries) != 1 || b.Prefix.ExcludedBoundaries[0].PC != testEntry+25 {
		t.Fatal("incomplete actual prologue/body/epilogue/return coverage")
	}
	if b.Instructions[8] != (GuardedInstruction{ID: b.Prefix.Boundary.ID, Span: Span{ret, ret + 1}, Guard: b.Prefix.CutGuard}) || b.Accesses[3].ID != b.Prefix.Boundary.ID || b.Accesses[3].Kind != FrameReturnRead || b.Accesses[3].Bytes != (RelativeSpan{0, 8}) || b.Accesses[3].PC != ret || b.Accesses[3].Context != 0 {
		t.Fatal("RET did not execute once in the root context")
	}
	if b.Accesses[1].Bytes != (RelativeSpan{-8, 0}) || b.Accesses[1].Kind != FrameWrite || b.Accesses[2].Bytes != (RelativeSpan{-8, 0}) || b.Accesses[2].Kind != FrameRead {
		t.Fatal("saved caller word lost ordered write/read effects")
	}
	if b.State.Preserved[RBP] != 0 || b.State.Preserved[RSP] != 0 || b.State.Preserved[R14] != math.MaxUint64 || b.State.Registers[RSP].Pointer != (OriginPointer{Origin: b.Prefix.Origin, Offset: 8}) || !slices.Equal(b.State.Memory, b.Prefix.Memory) {
		t.Fatal("restored frame was mistaken for an unwritten frame or writes rolled back")
	}
	reg, ok := direct.EntryValueRegister(b.State.Registers[RBP].Pointer)
	if !ok || reg != RBP || b.State.Registers[R14].Pointer != b.Prefix.Registers[R14].Pointer {
		t.Fatal("caller value lineage or concrete entry pointer was not restored")
	}
	if i, err := complete.InstructionAt(t.Context(), b.Prefix.Boundary.ID); err != nil || i.Op != x86asm.RET {
		t.Fatal("terminal inspection omitted actual RET", err)
	}
	if _, err := complete.InstructionAt(t.Context(), ^TransitionOccurrenceID(0)); err == nil {
		t.Fatal("unexecuted caller continuation gained an executed occurrence")
	}
	if value, err := complete.RegisterValue(t.Context(), x86asm.RSP); err != nil || value != b.State.Registers[RSP].Value {
		t.Fatal("register query returned before-RET stack state", err)
	}
	if value, err := complete.RegisterValue(t.Context(), x86asm.EAX); err != nil || stateEval(t, value, nil) != 42 {
		t.Fatal("returned alias query differs", err)
	}
	for _, base := range []uint64{4096, 1 << 40, 1<<47 - 4096} {
		for _, originalBP := range []uint64{0, 1, base, imageStateAddress, 1 << 63, math.MaxUint64} {
			values := entryRelationValues(b.Prefix, base, base-1)
			values[b.Prefix.InitialRegisters[RBP]] = originalBP
			if stateEval(t, b.State.Registers[RBP].Value, values) != originalBP || stateEval(t, b.State.Registers[RSP].Value, values) != base+8 || stateEval(t, b.State.Registers[R14].Value, values) != imageStateAddress || stateEval(t, b.State.Registers[RAX].Value, values) != 42 || stateEval(t, b.Accesses[3].Value, values) != returnContinuation {
				t.Fatal("actual final state disagrees with caller frame semantics")
			}
			for _, v := range b.State.Memory {
				if !v.Image && v.Offset >= -8 && v.Offset < 0 {
					if stateEval(t, v.Value, values) != originalBP>>(8*uint(v.Offset+8))&255 || v.Pointer != b.State.Registers[RBP].Pointer || v.PointerLane != uint8(v.Offset+8) {
						t.Fatal("saved bytes or full-word lineage did not survive return")
					}
				}
			}
		}
	}
	// Every prefix extends under its original predicate, control word, owner and
	// value lineage. No continuation supplies or reapplies those entry facts.
	segmented := returnPrefix(t, im, face, testEntry+6, TransitionExpansion{PC: testEntry})
	initial, _ := segmented.Bound()
	for _, cut := range []uint64{testEntry + 7, testEntry + 14, testEntry + 23, ret} {
		var err error
		segmented, err = CheckTransitionContinuation(t.Context(), segmented, continuationProposal(t, segmented, cut))
		if err != nil {
			t.Fatal(err)
		}
		stateInheritedInputs(t, initial, segmented.checked.bound)
	}
	assertTransitionAlpha(t, direct, segmented)
	other, _ := checkedReturn(t, segmented).Bound()
	for _, r := range []Register{RBP, RSP, R14} {
		left, right := entryRelationValues(b.Prefix, 8192, 17), entryRelationValues(other.Prefix, 8192, 17)
		if stateEval(t, b.State.Registers[r].Value, left) != stateEval(t, other.State.Registers[r].Value, right) {
			t.Fatal("segmented return changed a restored register")
		}
	}
}

func TestTransitionReturnRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		cut        uint64
	}{
		{"wrong-stack", "55c3", 1},
		{"wrong-pop-register", "554889e55bc3", 5},
		{"partial-saved-word", "55c60424005dc3", 6},
		{"scalar-cannot-recreate-lineage", "4889e84883c0004889c5c3", 10},
		{"constant-cannot-recreate-lineage", "bd00000000c3", 5},
		{"non-return", "b801000000c3", 0},
		{"return-immediate", "c20800", 0},
		{"prefixed-return", "f3c3", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			im, face := returnFixture(t, tc.code)
			prefix := returnPrefix(t, im, face, testEntry+tc.cut)
			c, err := CheckTransitionReturn(t.Context(), prefix)
			returnRefused(t, c, err)
		})
	}
	for _, tc := range []struct {
		name, code string
		cut        uint64
		expand     bool
	}{
		{"write-control", "48890424c3", 4, false},
		{"write-then-restore-control", "4889042448c7042440104000c3", 12, false},
		{"failed-locked-writeback", "f0480fb10c24c3", 6, true},
		{"lineage-dereference", "488b4500c3", 4, false},
		{"lineage-address-arithmetic", "488d4508488b00c3", 7, false},
		{"lineage-stack-address", "4889ecc3", 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			im, face := returnFixture(t, tc.code)
			face.Conditions.LockedMemory = LockedMemoryModel
			// Underlying writable storage still cannot authorize writing the
			// protected control word, even with its original numeric contents.
			face.Regions = []RelativeRegion{{Bytes: RelativeSpan{-24, 8}, Readable: true, Writable: true}}
			var expansions []TransitionExpansion
			if tc.expand {
				expansions = append(expansions, TransitionExpansion{PC: testEntry})
			}
			p := entryRelationProposal(t, im, testEntry+tc.cut, expansions...)
			prefix, err := CheckRegionTransition(t.Context(), im, testEntry, face, p, TransitionLimits{})
			if err == nil {
				c, err := CheckTransitionReturn(t.Context(), prefix)
				returnRefused(t, c, err)
			} else {
				transitionRefused(t, prefix, err)
			}
		})
	}
	// Arbitrary entry bits equal to an image pointer never regain its provenance.
	im, face := returnFixture(t, "49be0000700000000000c3")
	face.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 8}}
	face.EntryImagePointers = []TransitionEntryImagePointer{{R14, imageStateAddress}}
	face.ReturnContext.Preserved = []Register{R14}
	prefix := returnPrefix(t, im, face, testEntry+10)
	c, err := CheckTransitionReturn(t.Context(), prefix)
	returnRefused(t, c, err)
	// An active checked child RET is not the root's incoming continuation.
	im, face = returnFixture(t, "e80b000000c39090909090909090909090c3")
	prefix = returnPrefix(t, im, face, testEntry+16, TransitionExpansion{PC: testEntry})
	c, err = CheckTransitionReturn(t.Context(), prefix)
	returnRefused(t, c, err)
}

func TestTransitionReturnEntryContext(t *testing.T) {
	im, face := returnFixture(t, "c3")
	p := entryRelationProposal(t, im, testEntry)
	for _, tc := range []struct {
		name string
		edit func(*TransitionInterface)
	}{
		{"missing-slot", func(f *TransitionInterface) { f.Regions = nil }},
		{"short-slot", func(f *TransitionInterface) { f.Regions[1].Bytes.End = 7 }},
		{"unreadable-slot", func(f *TransitionInterface) { f.Regions[1].Readable = false }},
		{"short-envelope", func(f *TransitionInterface) { f.Envelope.End = 7 }},
		{"control-conflict", func(f *TransitionInterface) { f.Words = []int64{0} }},
		{"unmapped-target", func(f *TransitionInterface) { f.ReturnContext.Target = 1 }},
		{"foreign-continuation", func(f *TransitionInterface) { f.ReturnContext.Target = 0x900000 }},
		{"noncanonical-target", func(f *TransitionInterface) { f.ReturnContext.Target = 1 << 47 }},
		{"duplicate-preserved", func(f *TransitionInterface) { f.ReturnContext.Preserved = []Register{RBP, RBP} }},
		{"invalid-preserved", func(f *TransitionInterface) { f.ReturnContext.Preserved = []Register{Register(255)} }},
		{"stack-preserved", func(f *TransitionInterface) { f.ReturnContext.Preserved = []Register{RSP} }},
		{"too-many-preserved", func(f *TransitionInterface) { f.ReturnContext.Preserved = make([]Register, 16) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := cloneTransitionInterface(face)
			tc.edit(&f)
			c, err := CheckRegionTransition(t.Context(), im, testEntry, f, p, TransitionLimits{})
			transitionRefused(t, c, err)
		})
	}
	elf, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
	transitionRefused(t, elf, err)
	// No incoming context leaves the existing prefix API intact, but cannot
	// later append an incoming control word or turn an unexecuted RET into proof.
	without := cloneTransitionInterface(face)
	without.ReturnContext = nil
	plain := returnPrefix(t, im, without, testEntry)
	c, err := CheckTransitionReturn(t.Context(), plain)
	returnRefused(t, c, err)
	// A target inside an independently decoded MOV is not a boundary even if
	// decoding from that interior byte alone happens to yield an instruction.
	im, face = returnFixture(t, "b801000000c3")
	face.ReturnContext.Target = testEntry + 1
	p = entryRelationProposal(t, im, testEntry+5)
	bad, err := CheckRegionTransition(t.Context(), im, testEntry, face, p, TransitionLimits{})
	transitionRefused(t, bad, err)
}

func TestTransitionReturnOwnershipCancellationBudgets(t *testing.T) {
	im, face := returnFixture(t, "554889e55dc3")
	p := entryRelationProposal(t, im, testEntry+5)
	prefix := entryRelationCheck(t, im, face, p)
	before, _ := prefix.Bound()
	complete := checkedReturn(t, prefix)
	bound, _ := complete.Bound()
	foreign, err := NewImage(t.Context(), im.data)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := complete.BoundFor(foreign); ok {
		t.Fatal("foreign image borrowed terminal theorem")
	}
	other := returnPrefix(t, foreign, face, testEntry+5)
	if _, ok := other.EntryValueRegister(bound.State.Registers[RBP].Pointer); ok {
		t.Fatal("foreign caller-value lineage borrowed entry ownership")
	}
	bound.Prefix.Interface.ReturnContext.Target = 1
	bound.Prefix.Interface.ReturnContext.Preserved[0] = RAX
	bound.State.Registers[RSP] = TransitionValue{}
	bound.State.Restored[0] = RAX
	bound.State.Memory[0] = TransitionByte{}
	bound.Instructions[0] = GuardedInstruction{}
	bound.Accesses[0] = TransitionAccess{}
	bound.Continuation.Bytes[0] = 0
	retained, _ := complete.Bound()
	if !reflect.DeepEqual(retained.Prefix, before) || retained.State.PC != returnContinuation || retained.State.Restored[0] != RBP || retained.Continuation.Bytes[0] != 0xbb {
		t.Fatal("mutable return projections changed opaque evidence")
	}
	count := &imageCallbackContext{Context: t.Context()}
	if _, err := CheckTransitionReturn(count, prefix); err != nil {
		t.Fatal(err)
	}
	for at := 1; at <= count.calls; at++ {
		ctx, cancel := context.WithCancel(t.Context())
		stopped := &imageCallbackContext{Context: ctx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		c, err := CheckTransitionReturn(stopped, prefix)
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatal("return cancellation lost", at, err)
		}
		returnRefused(t, c, err)
	}
	// Root configuration is captured before the first user context callback.
	supplied := *im
	f := cloneTransitionInterface(face)
	ctx := &imageCallbackContext{Context: t.Context(), onErr: func(int) {
		f.ReturnContext.Target = 1
		f.ReturnContext.Preserved[0] = RAX
		supplied = Image{}
	}}
	owned, err := CheckRegionTransition(ctx, &supplied, testEntry, f, p, TransitionLimits{})
	if err != nil || !reflect.DeepEqual(owned.checked.bound.Interface, face) {
		t.Fatal("return configuration was not copied before callbacks", err)
	}
	checkedReturn(t, owned)
	limits := TransitionLimits{RelationLimits: RelationLimits{Work: prefix.checked.work + 1}}
	limited, err := CheckRegionTransition(t.Context(), im, testEntry, face, p, limits)
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransitionReturn(t.Context(), limited)
	returnRefused(t, c, err)
	c, err = CheckTransitionReturn(nil, prefix)
	returnRefused(t, c, err)
	c, err = CheckTransitionReturn(t.Context(), TransitionCertificate{})
	returnRefused(t, c, err)
	var zero TransitionReturnCertificate
	if _, ok := zero.Bound(); ok {
		t.Fatal("zero return certificate acquired authority")
	}
	if _, ok := zero.Prefix(); ok {
		t.Fatal("zero terminal certificate fabricated a prefix")
	}
	if _, err := zero.RegisterValue(t.Context(), x86asm.RSP); err == nil {
		t.Fatal("zero terminal certificate fabricated a register")
	}
	if _, err := zero.InstructionAt(t.Context(), 1); err == nil {
		t.Fatal("zero terminal certificate fabricated an instruction")
	}
	if reflect.TypeFor[TransitionCertificate]() == reflect.TypeFor[TransitionReturnCertificate]() {
		t.Fatal("terminal state can masquerade as an inside-callee cut")
	}
	// Exercise the actual current-word equality obligation independently of
	// constructor privacy, rather than merely trusting the declared target.
	corrupt := *prefix.checked
	corrupt.bound = cloneTransitionBound(corrupt.bound)
	constant, _ := br.NewBuilder(1).Const(br.Bits(8), 0)
	for j := range corrupt.bound.Memory {
		v := &corrupt.bound.Memory[j]
		if !v.Image && v.Offset == 0 {
			v.Value = constant
		}
	}
	c, err = CheckTransitionReturn(t.Context(), TransitionCertificate{&corrupt})
	returnRefused(t, c, err)
	unchanged, _ := prefix.Bound()
	if !reflect.DeepEqual(unchanged, before) {
		t.Fatal("return attempt changed predecessor")
	}
}
