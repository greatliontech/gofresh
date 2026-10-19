package nativeproof

import (
	"slices"
	"testing"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// Every structural descriptor also reaches the independent machine-state
// oracle. Memory premises make the complete selected operand accessible; a GPR
// base is delivered by an actual MOV, never assumed from its numeric value.
func descriptorState(t testing.TB, d to.Descriptor, immediate uint64, disp int32, raw []byte) {
	t.Helper()
	i := descriptorPayload(d, immediate, disp)
	if i.Operation >= to.LockedCompareExchange || i.Width == 8 && (i.Operation == to.Test || i.Operation == to.TestImmediate) {
		atomicDescriptorState(t, d, i, raw)
		return
	}
	if i.FS || i.Operation == to.Call || i.Operation == to.Return || i.Operation == to.Push || i.Operation == to.Pop || i.Operation == to.Syscall {
		callTLSDescriptorState(t, d, i, raw)
		return
	}
	face := stateFace(16, 0)
	face.Regions = nil
	face.Words = nil
	face.Conditions.CPUID = CPUIDModel
	var ops []dagOp
	deliver := func(reg uint8) {
		if reg == 4 {
			return
		}
		p := to.Intent{Operation: to.MoveRegister, Dst: reg, Src: 4}
		ops = append(ops, dagScalar(p, stateEncoding(p, 0), len(ops)+1))
	}
	mem := i.Operation == to.Load || i.Operation == to.Store || i.Operation == to.StoreImmediate
	width := 8
	if i.Width != 0 {
		width = int(i.Width) / 8
	}
	if mem && !i.RIP {
		deliver(i.Base)
		face.Regions = []RelativeRegion{{RelativeSpan{i.SignedDisp, i.SignedDisp + int64(width)}, true, true}}
	}
	if i.Operation == to.LEA {
		deliver(i.Base)
	}
	if i.Operation == to.And || i.Operation == to.Subtract || i.Operation == to.Add {
		deliver(i.Dst)
		// Alignment predicates constrain this operation's admissible semantic
		// payload, independently of the encoding population's arbitrary bits.
		if i.Operation == to.And {
			i.Immediate = ^uint64(15)
		}
	}
	if i.Operation == to.Branch && (i.Condition == 10 || i.Condition == 11) {
		// Entry PF has no projection. An actual byte TEST defines parity from
		// the arbitrary incoming AL; no fourth private entry predicate is added.
		producer := to.Intent{Operation: to.TestImmediate, Dst: 0, Width: 8, Immediate: 255}
		ops = append(ops, dagScalar(producer, to.Encoding{Form: to.TESTF6}, len(ops)+1))
	}
	op := dagScalar(i, d.Encoding, len(ops)+1)
	if i.RIP || i.Operation == to.LEARIP {
		op.address = imageStateAddress + 32
		face.ImageRegions = []Span{{imageStateAddress + 32, imageStateAddress + 40}}
	}
	if i.Operation == to.Jump || i.Operation == to.Branch {
		// Branch payloads are layout facts. Both edges end at the cut here;
		// independent multiarm populations check their condition semantics.
		i.SignedDisp = 0
		op.i = i
		op.taken = op.next
		if i.Operation == to.Jump {
			// A JMP semantic record's target must be its explicit trampoline.
			op.i.SignedDisp = 0
		}
	}
	ops = append(ops, op)
	x := dagArrange(t, ops, 0)
	initial := stateRawInitial(face, raw)
	c, err := CheckTransition(t.Context(), x.im, face, x.proposal(2*len(ops)), TransitionLimits{})
	if err != nil {
		t.Fatalf("descriptor state %+v: %v", d, err)
	}
	dagAssert(t, c, x, 2*len(ops), face, initial, nil)
}

func TestTransitionCompleteDescriptorStatePopulation(t *testing.T) {
	t.Parallel()
	raw := make([]byte, 512)
	for j := range raw {
		raw[j] = byte(j*31 + 17)
	}
	count := 0
	for d := range to.Descriptors {
		descriptorState(t, d, 0xfedcba9876543280, -0x12345, raw)
		count++
	}
	if count != 157118 {
		t.Fatal("incomplete semantic descriptor population", count)
	}
	for value := uint64(0); value < 256; value++ {
		for _, form := range []to.Form{to.MOVC6, to.MOVB0} {
			for _, d := range []to.Descriptor{{Intent: to.Intent{Operation: to.MoveImmediate, Dst: 0, HighDst: true, Width: 8}, Encoding: to.Encoding{Form: form}}, {Intent: to.Intent{Operation: to.MoveImmediate, Dst: 15, Width: 8}, Encoding: to.Encoding{Form: form, REX: 0x4f}}} {
				descriptorState(t, d, value, 0, raw)
			}
		}
	}
}

func FuzzTransitionDescriptorState(f *testing.F) {
	descriptors := slices.Collect(to.Descriptors)
	type formWidth struct {
		form  to.Form
		width uint8
	}
	newForms := map[formWidth]bool{}
	for index, d := range descriptors {
		if d.Intent.Operation == to.Clear32 {
			f.Add(uint32(index), ^uint64(0), int32(0), []byte{255, 128, 1, 0})
		}
		key := formWidth{d.Encoding.Form, d.Intent.Width}
		if (d.Intent.Operation >= to.LockedCompareExchange || d.Intent.Width == 8 && (d.Intent.Operation == to.Test || d.Intent.Operation == to.TestImmediate)) && !newForms[key] {
			newForms[key] = true
			f.Add(uint32(index), uint64(0x80000000ffffffff), int32(-16), []byte{255, 128, 1, 0})
		}
	}
	for _, index := range []uint32{0, 17, 31, 255, 8192, 32768, 53418} {
		f.Add(index, uint64(0x80000000ffffffff), int32(-128), []byte{1, 255, 128, 0})
	}
	f.Fuzz(func(t *testing.T, index uint32, immediate uint64, disp int32, raw []byte) {
		descriptorState(t, descriptors[int(index)%len(descriptors)], immediate, disp, raw)
	})
}
