package nativeproof

import (
	"encoding/binary"
	"testing"
	"testing/quick"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

func tupleBytes(tuples [][4]uint32) []byte {
	var raw []byte
	for _, tuple := range tuples {
		for _, word := range tuple {
			raw = binary.LittleEndian.AppendUint32(raw, word)
		}
	}
	return raw
}

// Independent queries with equal selectors have no value dependency that could
// accidentally reveal a reordered event list. Likewise, these stores have their
// own destinations: the trace assertions, not just final values, must notice a
// reordered access list.
func TestTransitionGuardedIndependentTraceOrder(t *testing.T) {
	var ops []dagOp
	for range 2 {
		ops = append(ops, dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 0, Immediate: 1}, to.Encoding{Form: to.MOVB8Imm32}, len(ops)+1))
		ops = append(ops, dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 1, Immediate: 7}, to.Encoding{Form: to.MOVB8Imm32}, len(ops)+1))
		ops = append(ops, dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, len(ops)+1))
	}
	for offset := int64(0); offset < 2; offset++ {
		ops = append(ops, dagScalar(to.Intent{Operation: to.StoreImmediate, Base: 4, Width: 8, SignedDisp: offset, Immediate: uint64(offset + 1)}, to.Encoding{Form: to.MOVC6, SIB: true, DispBytes: 1}, len(ops)+1))
	}
	ops = append(ops, dagScalar(to.Intent{Operation: to.Load, Dst: 15, Base: 4}, to.Encoding{Form: to.MOV8B, REX: 0x4c, SIB: true}, len(ops)+1))
	if err := quick.Check(func(entry [512]byte, outcomes [2][4]uint32, layout uint64) bool {
		face := cpuidFace()
		initial := stateRawInitial(face, entry[:])
		initial.outcomes = outcomes[:]
		dagCheck(t, ops, face, initial, layout, 3, 6)
		return true
	}, &quick.Config{MaxCount: 8}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionIndependentInactiveProducts(t *testing.T) {
	face := cpuidFace()
	ops := []dagOp{dagBranch(4, 1, 2)}
	for _, next := range []int{5, 3, 4, 5} {
		ops = append(ops, dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, next))
	}
	ops = append(ops, dagScalar(to.Intent{Operation: to.CompareImmediate, Width: 32, Dst: 0}, to.Encoding{Form: to.CMP83}, 6))
	for _, reg := range []uint8{0, 3, 1, 2} {
		ops = append(ops, dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: reg}, to.Encoding{Form: to.MOVB8Imm32}, len(ops)+1))
	}
	x := dagArrange(t, ops, 37)
	// Input arrays in each trial are selected independently of all certificates.
	if err := quick.Check(func(entry [512]byte, active, inactive, changed [4][4]uint32) bool {
		initial := stateRawInitial(face, entry[:])
		initial.outcomes = active[:]
		variants := [][]byte{tupleBytes(inactive[:])}
		for j := range inactive {
			one := inactive
			one[j] = changed[j]
			variants = append(variants, tupleBytes(one[:]))
		}
		direct, err := CheckTransition(t.Context(), x.im, face, x.proposal(20), TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		prefix, err := CheckTransition(t.Context(), x.im, face, x.proposal(10), TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		split, err := CheckTransitionContinuation(t.Context(), prefix, x.proposal(20))
		if err != nil {
			t.Fatal(err)
		}
		for _, zf := range []bool{false, true} {
			initial.flags[1] = zf
			for _, raw := range variants {
				dagAssert(t, direct, x, 20, face, initial, raw)
				dagAssert(t, prefix, x, 10, face, initial, raw)
				dagAssert(t, split, x, 20, face, initial, raw)
			}
		}
		return true
	}, &quick.Config{MaxCount: 32}); err != nil {
		t.Fatal(err)
	}
}
