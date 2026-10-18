package nativeproof

import (
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

func TestTransitionMixedPrimitiveOrderSurvivesOverwrites(t *testing.T) {
	query := to.Descriptor{Intent: to.Intent{Operation: to.CPUID}, Encoding: to.Encoding{Form: to.CPUID0FA2}}
	rmw := to.Descriptor{Intent: to.Intent{Operation: to.LockedCompareExchange, Base: 4, Src: 2}, Encoding: to.Encoding{Form: to.LOCKCMPXCHG0FB1, REX: 0x48, SIB: true}}
	program := []to.Descriptor{query, rmw, query, rmw}
	for _, reg := range []uint8{0, 1, 2, 3} {
		program = append(program, to.Descriptor{Intent: to.Intent{Operation: to.MoveImmediate32, Dst: reg}, Encoding: to.Encoding{Form: to.MOVB8Imm32}})
	}
	program = append(program, to.Descriptor{Intent: to.Intent{Operation: to.StoreImmediate, Base: 4}, Encoding: to.Encoding{Form: to.MOVC7, REX: 0x48, SIB: true}}, query, rmw)
	x, f := atomicLayout(t, program)
	f.Conditions.CPUID = CPUIDModel
	initial := stateInitial(f, 731)
	initial.loads = x.mappings
	initial.outcomes = [][4]uint32{{1, 2, 3, 4}, {5, 6, 7, 8}, {9, 10, 11, 12}}
	atomicStateCuts(t, x, f, initial)
	want := initial.clone()
	for j, i := range x.intents {
		want.referenceExec(t, i, j, x.pcs[j]+uint64(len(x.encoded[j])))
	}
	c, err := CheckTransition(t.Context(), x.im, f, x.proposal(len(x.intents)), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b := c.checked.bound
	if len(want.primitives) != 6 {
		t.Fatal("fixture lost mixed stream")
	}
	// Independent permutations alter only the projected event order: the final
	// register/heap relations remain byte-for-byte identical. The same oracle
	// used for positive generated checks must nevertheless reject every swap.
	for i := 0; i < len(b.PrimitiveEffects); i++ {
		for j := i + 1; j < len(b.PrimitiveEffects); j++ {
			permuted := cloneTransitionBound(b)
			permuted.PrimitiveEffects[i], permuted.PrimitiveEffects[j] = permuted.PrimitiveEffects[j], permuted.PrimitiveEffects[i]
			if !reflect.DeepEqual(permuted.Registers, b.Registers) || !reflect.DeepEqual(permuted.Memory, b.Memory) {
				t.Fatal("permutation changed final state")
			}
			values := stateBindings(t, c, f, initial)
			if err := statePrimitiveBindings(t, permuted, x, want, values); err == nil {
				t.Fatal("primitive permutation accepted", i, j)
			}
		}
	}
	// Unpermuted order remains a positive independent control after all refusals.
	values := stateBindings(t, c, f, initial)
	if err := statePrimitiveBindings(t, b, x, want, values); err != nil {
		t.Fatal(err)
	}
	for _, event := range b.PrimitiveEffects {
		if e, ok := event.(CPUIDEffect); ok {
			for _, v := range []br.Term{e.ResultsEAX, e.ResultsEBX, e.ResultsECX, e.ResultsEDX} {
				if _, present := values[v]; !present {
					t.Fatal("unbound primitive origin")
				}
			}
		}
	}
}
