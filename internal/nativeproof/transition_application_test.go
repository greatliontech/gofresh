package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

const applicationChild = testEntry + 64

type applicationFixture struct {
	im                  *Image
	parent, child       TransitionInterface
	call, ret           uint64
	parentExp, childExp []TransitionExpansion
}

func newApplicationFixture(t testing.TB, prefix, body string) applicationFixture {
	t.Helper()
	code := hexBytes(t, prefix)
	call := testEntry + uint64(len(code))
	code = append(code, 0xe8, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(code[len(code)-4:], uint32(applicationChild-call-5))
	// Reading the released saved-BP word after return must observe residual data.
	code = append(code, 0x48, 0x8b, 0x44, 0x24, 0xf0, 0xc3)
	for len(code) < 64 {
		code = append(code, 0x90)
	}
	bodyBytes := hexBytes(t, body)
	code = append(code, bodyBytes...)
	for len(code) < 128 {
		code = append(code, 0x90)
	}
	code = append(code, 0xbb, 1, 0, 0, 0)
	im, err := NewImage(t.Context(), transitionImageELF(t, code, imageStateLoads()))
	if err != nil {
		t.Fatal(err)
	}
	parent := TransitionInterface{
		Origin: OriginDomain{Min: 65536, Max: 131072, Modulus: 16}, Envelope: RelativeSpan{-64, 32},
		Regions:    []RelativeRegion{{Bytes: RelativeSpan{-64, 0}, Readable: true, Writable: true}, {Bytes: RelativeSpan{0, 32}, Readable: true}},
		Conditions: interfaceConditions(), ReturnContext: &TransitionReturnContext{Target: testEntry + 128},
		PrivateFrame: &TransitionPrivateFrame{Bytes: RelativeSpan{-64, 0}},
	}
	child := TransitionInterface{
		Origin: OriginDomain{Min: 65528, Max: 131064, Modulus: 16, Residue: 8}, Envelope: RelativeSpan{-24, 8},
		Regions:    []RelativeRegion{{Bytes: RelativeSpan{-24, 0}, Readable: true, Writable: true}, {Bytes: RelativeSpan{0, 8}, Readable: true}},
		Conditions: interfaceConditions(), ReturnContext: &TransitionReturnContext{Target: call + 5, Preserved: []Register{RBP}},
		PrivateFrame: &TransitionPrivateFrame{Bytes: RelativeSpan{-24, 0}},
	}
	return applicationFixture{im: im, parent: parent, child: child, call: call, ret: applicationChild + uint64(len(bodyBytes)-1)}
}

func (f applicationFixture) certificates(t testing.TB) (TransitionCertificate, TransitionReturnCertificate) {
	t.Helper()
	parent := applicationRoot(t, f.im, testEntry, f.call, f.parent, f.parentExp)
	child := applicationRoot(t, f.im, applicationChild, f.ret, f.child, f.childExp)
	return parent, checkedReturn(t, child)
}

func applicationRoot(t testing.TB, im *Image, entry, cut uint64, face TransitionInterface, expansions []TransitionExpansion) TransitionCertificate {
	t.Helper()
	p, err := ProposeRegionTransition(t.Context(), im, entry, cut, TransitionLimits{}, expansions...)
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckRegionTransition(t.Context(), im, entry, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func applicationRefused(t testing.TB, c TransitionCallCertificate, err error) {
	t.Helper()
	if err == nil || c.checked != nil {
		t.Fatal("invalid application acquired authority", err)
	}
	var r *Refusal
	if !errors.As(err, &r) && !errors.Is(err, context.Canceled) {
		t.Fatal("unstructured application refusal", err)
	}
}

func TestTransitionApplicationActualCallAndResidualState(t *testing.T) {
	f := newApplicationFixture(t, "488d6c2418", "554889e5b82a0000005dc3")
	f.child.Words = []int64{-24}
	parent, child := f.certificates(t)
	before, _ := parent.Bound()
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := c.BoundFor(f.im)
	if !ok || !c.AppliesTo(child) || c.AppliesTo(TransitionReturnCertificate{}) {
		t.Fatal("missing exact callee identity")
	}
	other := checkedReturn(t, child.checked.prefix)
	if c.AppliesTo(other) {
		t.Fatal("independently completed theorem borrowed exact identity")
	}
	if actual, ok := c.Callee(); !ok || actual.checked != child.checked {
		t.Fatal("lost subordinate certificate")
	}
	if b.StackShift != -8 || b.Activation != callContext("", f.call) || b.ChildEntry.Boundary.PC != applicationChild || b.Successor.Boundary.PC != f.call+5 || len(b.Successor.Frames) != 0 || b.Successor.Boundary.Context != "" {
		t.Fatal("incorrect activation/return relationship")
	}
	stateInheritedInputs(t, before, b.Successor)
	if b.Registers[RBP].Pointer != before.Registers[RBP].Pointer || b.Successor.Registers[RBP].Pointer != before.Registers[RBP].Pointer || len(b.Words) != 1 || b.Inputs != child.checked.prefix.checked.bound.InitialRegisters {
		t.Fatal("lost actual caller provenance or entry grouping")
	}
	if len(b.Successor.Accesses) != 4 || b.Successor.Accesses[0].Kind != FrameWrite || b.Successor.Accesses[0].Bytes != (RelativeSpan{-8, 0}) || b.Successor.Accesses[3].Kind != FrameReturnRead || b.Successor.Accesses[3].Context != b.Activation {
		t.Fatal("CALL/save/restore/RET trace incomplete")
	}
	for _, base := range []uint64{65536, 100000, 131072} {
		values := map[br.Term]uint64{before.Origin: base}
		if stateEval(t, b.Successor.Registers[RAX].Value, values) != 42 || stateEval(t, b.Successor.Registers[RBP].Value, values) != base+24 || stateEval(t, b.Successor.Registers[RSP].Value, values) != base {
			t.Fatal("replayed caller state differs")
		}
	}
	successor, _ := c.Successor()
	p, err := ProposeRegionTransition(t.Context(), f.im, testEntry, f.call+10, TransitionLimits{}, b.Successor.Expansions...)
	if err != nil {
		t.Fatal(err)
	}
	later, err := CheckTransitionContinuation(t.Context(), successor, p)
	if err != nil {
		t.Fatal(err)
	}
	if later.checked.bound.Registers[RAX].Pointer != before.Registers[RBP].Pointer || stateEval(t, later.checked.bound.Registers[RAX].Value, map[br.Term]uint64{before.Origin: 65536}) != 65560 {
		t.Fatal("released scratch read lost residual pointer/value")
	}
	if successor.checked.work <= parent.checked.work+child.checked.work || later.checked.work <= successor.checked.work || successor.checked.limits.LiveStateBytes >= parent.checked.limits.LiveStateBytes {
		t.Fatal("application cost disappeared from successor")
	}
	after, _ := parent.Bound()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("caller input mutated")
	}
	b.Memory[0].Current.PointerLane = 99
	b.Words[0].Input.Offset = 99
	b.ChildEntry.Memory = nil
	b.Successor.Interface.Regions[0].Bytes.Start = 99
	b.Successor.Boundary.Bytes[0] ^= 1
	fresh, _ := c.Bound()
	if fresh.Memory[0].Current.PointerLane == 99 || fresh.Words[0].Input.Offset == 99 || len(fresh.ChildEntry.Memory) == 0 || fresh.Successor.Interface.Regions[0].Bytes.Start == 99 || slices.Equal(fresh.Successor.Boundary.Bytes, b.Successor.Boundary.Bytes) {
		t.Fatal("mutable application projection aliases authority")
	}
}

func guardedApplicationFixture(t testing.TB, prefix string, parentOffset int64) applicationFixture {
	f := newApplicationFixture(t, prefix, returnFrameCode)
	f.ret = applicationChild + 24
	f.childExp = []TransitionExpansion{{PC: applicationChild}}
	for _, face := range []*TransitionInterface{&f.parent, &f.child} {
		face.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 24}}
		face.EntryImagePointers = []TransitionEntryImagePointer{{Register: R14, Address: imageStateAddress}}
		face.EntryWordUpperBounds = []TransitionEntryWordUpperBound{{Address: imageStateAddress + 16}}
	}
	f.parent.EntryWordUpperBounds[0].OriginOffset = parentOffset
	return f
}

func TestTransitionApplicationCurrentGuardAndRootShift(t *testing.T) {
	f := guardedApplicationFixture(t, "488d6424f0", -24)
	f.child.Origin.Min -= 16
	f.child.Origin.Max -= 16
	parent, child := f.certificates(t)
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if b.StackShift != -24 || len(b.Successor.ExcludedBoundaries) != 1 || b.Successor.ExcludedBoundaries[0].Context != b.Activation || b.Successor.Registers[RSP].Pointer != parent.checked.bound.Registers[RSP].Pointer {
		t.Fatal("guarded return did not retain parent-root offset or exclusion")
	}
	for _, tc := range []struct {
		name, prefix string
		offset       int64
	}{
		{"weak-root-guard", "", 0},
		{"moved-current-word", "49896610", -8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := guardedApplicationFixture(t, tc.prefix, tc.offset)
			parent, child := f.certificates(t)
			c, err := CheckTransitionCallReturn(t.Context(), parent, child)
			applicationRefused(t, c, err)
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Premise != "transition-application-premise" {
				t.Fatal("replay refusal hid a missing current-state premise check", err)
			}
		})
	}
}

func TestTransitionApplicationUnusedEntryPremise(t *testing.T) {
	// This callee does not read the bounded word. Its conditional theorem still
	// cannot be applied outside the stated domain, even when unchecked replay of
	// the body would complete successfully. This isolates premise discharge from
	// a subsequent failure in the child's own stack guard.
	for _, offset := range []int64{-8, 0} {
		f := newApplicationFixture(t, "", "b82a000000c3")
		f.parent.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 8}}
		f.child.ImageRegions = slices.Clone(f.parent.ImageRegions)
		f.parent.EntryWordUpperBounds = []TransitionEntryWordUpperBound{{Address: imageStateAddress, OriginOffset: offset}}
		f.child.EntryWordUpperBounds = []TransitionEntryWordUpperBound{{Address: imageStateAddress}}
		parent, child := f.certificates(t)
		c, err := CheckTransitionCallReturn(t.Context(), parent, child)
		if offset == -8 {
			if err != nil || !c.AppliesTo(child) {
				t.Fatal("entailed unused premise refused", err)
			}
			continue
		}
		applicationRefused(t, c, err)
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.Premise != "transition-application-premise" {
			t.Fatal("unused premise was not independently established", err)
		}
	}
}

func TestTransitionApplicationSubtractedStackGuard(t *testing.T) {
	// CALL follows SUB RSP,56: the actual child origin is (S-56)-8.
	// The entry premise is word<S-64, not the weaker word<S.
	f := guardedApplicationFixture(t, "4883ec38", -64)
	f.parent.Envelope.Start = -128
	f.parent.Regions[0].Bytes.Start = -128
	f.parent.PrivateFrame.Bytes.Start = -128
	f.child.Origin.Min -= 56
	f.child.Origin.Max -= 56
	f.child.Origin.Residue = 0
	parent, child := f.certificates(t)
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if b.StackShift != -64 || b.Successor.Registers[RSP].Pointer != (OriginPointer{Origin: parent.checked.bound.Origin, Offset: -56}) {
		t.Fatal("subtracted SP chain did not preserve its parent-root relation")
	}
}

func TestTransitionApplicationPremiseControls(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*applicationFixture)
	}{
		{"no-parent-private-frame", func(f *applicationFixture) { f.parent.PrivateFrame = nil }},
		{"short-parent-private-frame", func(f *applicationFixture) { f.parent.PrivateFrame.Bytes.Start = -24 }},
		{"domain", func(f *applicationFixture) { f.child.Origin.Min += 16 }},
		{"congruence", func(f *applicationFixture) { f.child.Origin.Modulus = 32 }},
		{"envelope", func(f *applicationFixture) { f.child.Envelope.Start = -80 }},
		{"permissions", func(f *applicationFixture) {
			f.parent.PrivateFrame = nil
			f.child.PrivateFrame = nil
			f.parent.Regions = []RelativeRegion{{Bytes: RelativeSpan{-64, -8}, Readable: true}, {Bytes: RelativeSpan{-8, 0}, Readable: true, Writable: true}, {Bytes: RelativeSpan{0, 32}, Readable: true}}
		}},
		{"continuation", func(f *applicationFixture) { f.child.ReturnContext.Target = testEntry + 128 }},
		{"primitive", func(f *applicationFixture) { f.child.Conditions.CPUID = CPUIDModel }},
		{"image-grant", func(f *applicationFixture) { f.child.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 8}} }},
		{"pointer-bits-without-provenance", func(f *applicationFixture) {
			*f = newApplicationFixture(t, "49be0000700000000000", "b82a000000c3")
			f.child.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 8}}
			f.parent.ImageRegions = slices.Clone(f.child.ImageRegions)
			f.child.EntryImagePointers = []TransitionEntryImagePointer{{Register: R14, Address: imageStateAddress}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplicationFixture(t, "", "b82a000000c3")
			tc.edit(&f)
			parent, child := f.certificates(t)
			before, _ := parent.Bound()
			c, err := CheckTransitionCallReturn(t.Context(), parent, child)
			applicationRefused(t, c, err)
			after, _ := parent.Bound()
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed sibling mutated caller")
			}
		})
	}
	for _, prefix := range []string{"85c0", "31c0", "4883e4f0"} {
		t.Run("undefined-flags/"+prefix, func(t *testing.T) {
			f := newApplicationFixture(t, prefix, "b82a000000c3")
			if prefix == "31c0" {
				f.parentExp = []TransitionExpansion{{PC: testEntry}}
			}
			parent, child := f.certificates(t)
			c, err := CheckTransitionCallReturn(t.Context(), parent, child)
			applicationRefused(t, c, err)
		})
	}
	f := newApplicationFixture(t, "", "b82a000000c3")
	parent, _ := f.certificates(t)
	copy := newApplicationFixture(t, "", "b82a000000c3")
	_, otherOwner := copy.certificates(t)
	c, err := CheckTransitionCallReturn(t.Context(), parent, otherOwner)
	applicationRefused(t, c, err)
	wrongEntry := applicationRoot(t, f.im, f.ret, f.ret, f.child, nil)
	c, err = CheckTransitionCallReturn(t.Context(), parent, checkedReturn(t, wrongEntry))
	applicationRefused(t, c, err)
}

func TestTransitionApplicationBoundedValues(t *testing.T) {
	for n := 0; n < 12; n++ {
		value := uint32(0x13579bdf) * uint32(n)
		imm := []byte{0xb8, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(imm[1:], value)
		f := newApplicationFixture(t, "", fmt.Sprintf("55%x5dc3", imm))
		f.parent.Origin.Min += uint64(n * 16)
		f.child.Origin.Min += uint64(n * 16)
		f.parent.Origin.Max -= uint64(n * 16)
		f.child.Origin.Max -= uint64(n * 16)
		parent, child := f.certificates(t)
		c, err := CheckTransitionCallReturn(t.Context(), parent, child)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := c.Bound()
		if stateEval(t, b.Successor.Registers[RAX].Value, nil) != uint64(value) || b.Successor.Registers[RBP].Pointer != parent.checked.bound.Registers[RBP].Pointer {
			t.Fatal("bounded generated call/return disagrees")
		}
	}
}

func TestTransitionApplicationCumulativeLimitsAndCancellation(t *testing.T) {
	f := newApplicationFixture(t, "", "554889e5b82a0000005dc3")
	parent, child := f.certificates(t)
	before, _ := parent.Bound()
	const generous = 10000000
	count := &checkpointContext{Context: t.Context(), remaining: generous}
	c, err := CheckTransitionCallReturn(count, parent, child)
	if err != nil {
		t.Fatal(err)
	}
	calls := generous - count.remaining
	for _, at := range []int{1, 100, calls / 2, calls - 1, calls} {
		ctx := &checkpointContext{Context: t.Context(), remaining: at}
		c, err := CheckTransitionCallReturn(ctx, parent, child)
		applicationRefused(t, c, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation was hidden", at, err)
		}
	}
	work := c.checked.successor.checked.work
	for _, limit := range []int{parent.checked.work, parent.checked.work + child.checked.work, work - 1} {
		copy := *parent.checked
		copy.limits.Work = limit
		c, err := CheckTransitionCallReturn(t.Context(), TransitionCertificate{&copy}, child)
		applicationRefused(t, c, err)
	}
	copy := *parent.checked
	copy.limits.Work = work
	if _, err := CheckTransitionCallReturn(t.Context(), TransitionCertificate{&copy}, child); err != nil {
		t.Fatal("exact cumulative work allowance refused", err)
	}
	copy = *parent.checked
	copy.limits.LiveStateBytes = 8192
	limited, err := CheckTransitionCallReturn(t.Context(), TransitionCertificate{&copy}, child)
	applicationRefused(t, limited, err)
	after, _ := parent.Bound()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("resource failure changed immutable caller")
	}
	if _, err := CheckTransitionCallReturn(t.Context(), parent, child); err != nil {
		t.Fatal("failed sibling damaged later application", err)
	}
}

func TestTransitionApplicationNestedActivation(t *testing.T) {
	// The root calls 64; that activation calls 96. Apply the independently
	// completed theorem at 96 while the root's first call is still active.
	f := newApplicationFixture(t, "", "e81b000000c3")
	code := make([]byte, 134)
	for j := range code {
		code[j] = 0x90
	}
	copy(code, hexBytes(t, "e83b000000c3"))
	copy(code[64:], hexBytes(t, "e81b000000c3"))
	copy(code[96:], hexBytes(t, "55b82a0000005dc3"))
	var err error
	f.im, err = NewImage(t.Context(), transitionImageELF(t, code, imageStateLoads()))
	if err != nil {
		t.Fatal(err)
	}
	parent := applicationRoot(t, f.im, testEntry, testEntry+64, f.parent, []TransitionExpansion{{PC: testEntry}})
	f.child.Origin.Min -= 8
	f.child.Origin.Max -= 8
	f.child.Origin.Residue = 0
	f.child.ReturnContext.Target = testEntry + 69
	child := checkedReturn(t, applicationRoot(t, f.im, testEntry+96, testEntry+103, f.child, nil))
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if b.StackShift != -16 || len(b.ChildEntry.Frames) != 2 || !slices.Equal(b.Successor.Frames, parent.checked.bound.Frames) || b.Successor.Boundary.Context != callContext("", testEntry) {
		t.Fatal("same numeric continuation lost parent activation")
	}
}

func TestTransitionApplicationRebasesCalleeExpansions(t *testing.T) {
	f := newApplicationFixture(t, "", "e80c000000c39090909090909090909090c3")
	f.ret = applicationChild + 5
	f.childExp = []TransitionExpansion{{PC: applicationChild}}
	parent, child := f.certificates(t)
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	nested := callContext(b.Activation, applicationChild)
	if len(b.Successor.Accesses) != 4 || b.Successor.Accesses[1].Context != b.Activation || b.Successor.Accesses[2].Context != nested || b.Successor.Accesses[3].Context != b.Activation || len(b.Successor.Frames) != 0 {
		t.Fatal("callee expansion lost nested activation or return ordering")
	}
}

func TestTransitionApplicationProtectedControlScan(t *testing.T) {
	f := newApplicationFixture(t, "", "c3")
	parent, child := f.certificates(t)
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	for _, context := range []string{b.Activation, callContext(b.Activation, applicationChild)} {
		m, err := newTransitionChecker(t.Context(), f.im, transitionRoot{entry: testEntry, region: true}, parent.checked.limits, 0)
		if err != nil {
			t.Fatal(err)
		}
		m.bound.Accesses = slices.Clone(b.ChildEntry.Accesses)
		// The supplied value is exactly the initiating CALL value. A final-value
		// comparison would wrongly accept this write; the footprint must refuse.
		m.bound.Accesses = append(m.bound.Accesses, TransitionAccess{PC: applicationChild, Context: context, Kind: FrameWrite, Bytes: RelativeSpan{-8, 0}, Value: b.ChildEntry.Accesses[len(b.ChildEntry.Accesses)-1].Value})
		if err := m.applicationProtectedSlot(b.ChildEntry, b.Activation, -8); err == nil {
			t.Fatal("same-value descendant write acquired control-slot authority")
		}
	}
}

func TestTransitionApplicationMachineAndOrderedEffects(t *testing.T) {
	f := newApplicationFixture(t, "", "0fa2b82a000000c3")
	f.parent.Conditions.CPUID = CPUIDModel
	f.child.Conditions.CPUID = CPUIDModel
	parent, child := f.certificates(t)
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if len(b.Successor.PrimitiveEffects) != 1 {
		t.Fatal("overwritten primitive outcome erased ordered effect")
	}
	effect, ok := b.Successor.PrimitiveEffects[0].(CPUIDEffect)
	if !ok || effect.Context != b.Activation || effect.PC != applicationChild || stateEval(t, b.Successor.Registers[RAX].Value, nil) != 42 {
		t.Fatal("primitive occurrence was not rebased under actual CALL")
	}
	f = newApplicationFixture(t, "", "c3")
	f.parent.Conditions.CPUID = CPUIDModel // compatible additional parent premise
	parent, child = f.certificates(t)
	if _, err := CheckTransitionCallReturn(t.Context(), parent, child); err != nil {
		t.Fatal("harmless stronger parent machine context refused", err)
	}
	f = newApplicationFixture(t, "b89e000000bf021000004889e60f05", "c3")
	f.parent.Conditions.Syscall = LinuxAMD64SyscallModel
	f.parent.Conditions.UserAddressBits = 48
	f.parentExp = []TransitionExpansion{{PC: testEntry + 13}}
	parent, child = f.certificates(t)
	c, err = CheckTransitionCallReturn(t.Context(), parent, child)
	applicationRefused(t, c, err)
}

func TestTransitionApplicationCurrentWordAndImageProvenance(t *testing.T) {
	// The parent's store precedes CALL. Child Words[-24] therefore specializes
	// that current eight-byte pointer, not a replacement arbitrary entry word.
	f := newApplicationFixture(t, "48896c24e0", "488b4424e8c3")
	f.parent.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 8}}
	f.parent.EntryImagePointers = []TransitionEntryImagePointer{{Register: RBP, Address: imageStateAddress}}
	f.child.Words = []int64{-24}
	parent, child := f.certificates(t)
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	want := parent.checked.bound.Registers[RBP]
	if len(b.Words) != 1 || b.Words[0].Current.Pointer != want.Pointer || b.Successor.Registers[RAX].Pointer != want.Pointer || b.Successor.Registers[RBP].Pointer != want.Pointer {
		t.Fatal("current word grouping lost caller image provenance")
	}
	values := map[br.Term]uint64{parent.checked.bound.InitialRegisters[RBP]: imageStateAddress}
	if stateEval(t, b.Words[0].Current.Value, values) != imageStateAddress || stateEval(t, b.Successor.Registers[RAX].Value, values) != imageStateAddress {
		t.Fatal("current word used original scratch values")
	}
	lanes := 0
	for _, binding := range b.Memory {
		if !binding.Input.Image && binding.Input.Offset >= -24 && binding.Input.Offset < -16 {
			lane := uint8(binding.Input.Offset + 24)
			if binding.Current.Offset != binding.Input.Offset-8 || binding.Current.Pointer != want.Pointer || binding.Current.PointerLane != lane {
				t.Fatal("byte and word substitutions disagree")
			}
			lanes++
		}
	}
	if lanes != 8 {
		t.Fatal("missing coherent pointer lanes")
	}
}

func TestTransitionApplicationExecutableCallerKeepsRootAuthority(t *testing.T) {
	f := newApplicationFixture(t, "", "c3")
	f.parent.PrivateFrame, f.parent.ReturnContext, f.child.PrivateFrame = nil, nil, nil
	p, err := ProposeTransition(t.Context(), f.im, f.call, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := CheckTransition(t.Context(), f.im, f.parent, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	child := checkedReturn(t, applicationRoot(t, f.im, applicationChild, f.ret, f.child, nil))
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if b.Successor.ConditionalRegion || b.Successor.Entry != f.im.entry || !reflect.DeepEqual(b.Successor.Interface, parent.checked.bound.Interface) {
		t.Fatal("application changed caller authority or premises")
	}
}

func TestTransitionApplicationSSEInputsAndReplayPreservation(t *testing.T) {
	for _, childSSE := range []bool{false, true} {
		// Load current XMM0 from an arbitrary parent stack word before CALL.
		f := newApplicationFixture(t, "f30f10442418", "c3")
		f.parentExp = []TransitionExpansion{{PC: testEntry}}
		f.parent.Conditions.SSE = SSEModel
		if childSSE {
			f.child.Conditions.SSE = SSEModel
		}
		parent, child := f.certificates(t)
		c, err := CheckTransitionCallReturn(t.Context(), parent, child)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := c.Bound()
		if b.Vectors[0] == parent.checked.bound.InitialVectors[0] {
			t.Fatal("fixture did not change the incoming vector")
		}
		if b.InputVectors != child.checked.prefix.checked.bound.InitialVectors || b.Vectors != parent.checked.bound.Vectors || b.Successor.Vectors != parent.checked.bound.Vectors || b.Successor.InitialVectors != parent.checked.bound.InitialVectors || !b.Successor.SSE.MXCSRPreserved || !b.Successor.SSE.UpperVectorsPreserved {
			t.Fatal("callee SSE interface fabricated or erased current caller vectors")
		}
	}
	f := newApplicationFixture(t, "", "c3")
	f.child.Conditions.SSE = SSEModel
	parent, child := f.certificates(t)
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	applicationRefused(t, c, err)
}

func TestTransitionApplicationMissingAuthority(t *testing.T) {
	f := newApplicationFixture(t, "", "c3")
	parent, child := f.certificates(t)
	for _, inputs := range []struct {
		ctx    context.Context
		parent TransitionCertificate
		child  TransitionReturnCertificate
	}{{nil, parent, child}, {t.Context(), TransitionCertificate{}, child}, {t.Context(), parent, TransitionReturnCertificate{}}} {
		c, err := CheckTransitionCallReturn(inputs.ctx, inputs.parent, inputs.child)
		applicationRefused(t, c, err)
	}
	var zero TransitionCallCertificate
	if _, ok := zero.Bound(); ok {
		t.Fatal("zero application projection acquired authority")
	}
	if _, ok := zero.BoundFor(f.im); ok {
		t.Fatal("zero application image binding acquired authority")
	}
	if _, ok := zero.Callee(); ok {
		t.Fatal("zero application acquired a callee")
	}
	if _, ok := zero.Successor(); ok || zero.AppliesTo(child) {
		t.Fatal("zero application acquired a successor or exact identity")
	}
	beforeRET := applicationRoot(t, f.im, applicationChild, f.ret, f.child, nil)
	c, err := CheckTransitionCallReturn(t.Context(), beforeRET, child)
	applicationRefused(t, c, err)
}
