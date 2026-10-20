package nativeproof

import (
	"context"
	"errors"
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
	"golang.org/x/arch/x86/x86asm"
)

func TestTransitionDirectionRootAndCLD(t *testing.T) {
	im, cut := transitionFixture(t, "fcbb2a000000")
	face := stateFace(16, 0)
	root := continuationRoot(t, im, testEntry, face, TransitionLimits{})
	before := root.checked.bound
	if before.Direction != before.InitialDirection || before.InitialDirection.Sort() != br.Bool() || before.InitialDirection.View().Op != br.Variable || before.InitialFS.Valid() || before.SSE != (TransitionSSEContext{}) {
		t.Fatal("DF is not an unconditional arbitrary root input")
	}
	p := continuationProposal(t, root, testEntry+1, TransitionOptions{Expansions: []TransitionExpansion{{PC: testEntry}}})
	cleared, err := CheckTransitionContinuation(t.Context(), root, p)
	if err != nil {
		t.Fatal(err)
	}
	b := cleared.checked.bound
	if !literalBool(b.Direction, 0) || b.InitialDirection != before.InitialDirection || b.Flags != before.Flags || cleared.checked.flags != root.checked.flags || b.Registers != before.Registers || !reflect.DeepEqual(b.Memory, before.Memory) || b.Thread != before.Thread || b.Vectors != before.Vectors || b.SSE != before.SSE || b.Preserved != before.Preserved || len(b.Accesses) != 0 || len(b.PrimitiveEffects) != 0 {
		t.Fatal("CLD changed state other than current DF")
	}
	// The input-shape oracle demands a distinct Bool, independent of all three
	// arithmetic predicates, even after that Bool is absent from current state.
	for flags := 0; flags < 128; flags++ {
		raw := make([]byte, 137)
		raw[136] = byte(flags)
		initial := stateRawInitial(face, raw)
		values := stateBindings(t, cleared, face, initial)
		if stateEval(t, before.Direction, values) != uint64(flags>>6) || stateEval(t, b.Direction, values) != 0 {
			t.Fatal("CLD assumed an initially clear DF or left it set", flags)
		}
	}
	full := continuationProposal(t, cleared, cut)
	assertTransitionRetainedExpressionUnion(t, cleared, full)
	later, err := CheckTransitionContinuation(t.Context(), cleared, full)
	if err != nil {
		t.Fatal(err)
	}
	stateInheritedInputs(t, before, later.checked.bound)
	if later.checked.bound.Direction != b.Direction || root.checked.bound.Direction != before.InitialDirection {
		t.Fatal("continuation refreshed DF or mutated the predecessor")
	}
	projection, _ := later.Bound()
	projection.Direction, projection.InitialDirection = br.Term{}, br.Term{}
	again, _ := later.Bound()
	if !again.Direction.Valid() || again.InitialDirection != before.InitialDirection {
		t.Fatal("direction projection aliases authority")
	}
}

func TestTransitionDirectionJoin(t *testing.T) {
	// ZF selects a preserving arm; its complement executes CLD. Joining must
	// select the current value under the incoming arm guard, before guard union.
	copy := to.Intent{Operation: to.MoveRegister, Dst: 9, Src: 9}
	ops := []dagOp{
		dagBranch(4, 1, 2),
		dagScalar(to.Intent{Operation: to.ClearDirection}, to.Encoding{Form: to.CLDFC}, 3),
		dagScalar(copy, stateEncoding(copy, 0), 3),
		dagScalar(copy, stateEncoding(copy, 1), 4),
	}
	face := stateFace(16, 0)
	for layout := uint64(0); layout < 8; layout++ {
		x := dagArrange(t, ops, layout)
		prefix, err := CheckTransition(t.Context(), x.im, face, x.proposal(6), TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		full := x.proposal(8)
		next, err := CheckTransitionContinuation(t.Context(), prefix, full)
		if err != nil {
			t.Fatal(err)
		}
		direct, err := CheckTransition(t.Context(), x.im, face, full, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		assertTransitionAlpha(t, direct, next)
		stateInheritedInputs(t, prefix.checked.bound, next.checked.bound)
		for flags := 0; flags < 128; flags++ {
			raw := make([]byte, 137)
			raw[136] = byte(flags)
			initial := stateRawInitial(face, raw)
			dagAssert(t, prefix, x, 6, face, initial, nil)
			dagAssert(t, next, x, 8, face, initial, nil)
		}
	}
}

func TestTransitionDirectionPreservesCurrentArithmeticFlags(t *testing.T) {
	// SBB projects all six values; TEST makes AF undefined. CLD preserves both
	// the actual current values and their guarantees, not fresh entry predicates.
	for _, producer := range []string{"19d8", "84c0"} {
		im, cut := transitionFixture(t, producer+"fc")
		at := cut - 1
		face := stateFace(16, 0)
		p, err := ProposeTransition(t.Context(), im, at, TransitionLimits{}, TransitionOptions{Expansions: []TransitionExpansion{{PC: testEntry}}})
		if err != nil {
			t.Fatal(err)
		}
		prior, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		next, err := CheckTransitionContinuation(t.Context(), prior, continuationProposal(t, prior, cut, TransitionOptions{Expansions: []TransitionExpansion{{PC: at}}}))
		if err != nil {
			t.Fatal(err)
		}
		if next.checked.bound.Flags != prior.checked.bound.Flags || next.checked.flags != prior.checked.flags || !literalBool(next.checked.bound.Direction, 0) || prior.checked.bound.Direction != prior.checked.bound.InitialDirection {
			t.Fatal("CLD replaced current arithmetic state or arithmetic changed DF")
		}
	}
}

func TestTransitionDirectionActualCallAndReturn(t *testing.T) {
	for _, callerCLD := range []bool{false, true} {
		for _, childCLD := range []bool{false, true} {
			prefix, body := "", "c3"
			if callerCLD {
				prefix = "fc"
			}
			if childCLD {
				body = "fcc3"
			}
			f := newApplicationFixture(t, prefix, body)
			if callerCLD {
				f.parentExp = []TransitionExpansion{{PC: testEntry}}
			}
			if childCLD {
				f.childExp = []TransitionExpansion{{PC: applicationChild}}
			}
			parent, child := f.certificates(t)
			c, err := CheckTransitionCallReturn(t.Context(), parent, child)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c.Bound()
			before, independent := parent.checked.bound, child.checked.prefix.checked.bound
			if b.InputDirection != independent.InitialDirection || b.InputDirection == before.InitialDirection || b.Direction != before.Direction || b.ChildEntry.Direction != before.Direction || b.ChildEntry.InitialDirection != before.InitialDirection || b.Successor.InitialDirection != before.InitialDirection {
				t.Fatal("callee DF was not associated with actual post-CALL current state")
			}
			for df := uint64(0); df < 2; df++ {
				values := map[br.Term]uint64{before.InitialDirection: df, independent.InitialDirection: 1 - df}
				want := df
				if callerCLD || childCLD {
					want = 0
				}
				if stateEval(t, b.Successor.Direction, values) != want {
					t.Fatal("CALL/RET restored DF or borrowed arbitrary child input")
				}
				childWant := 1 - df
				if childCLD {
					childWant = 0
				}
				if stateEval(t, child.checked.state.Direction, values) != childWant {
					t.Fatal("conditional terminal RET restored original DF")
				}
			}
			successor, _ := c.Successor()
			p := continuationProposal(t, successor, f.call+10)
			ret, err := CheckTransitionContinuation(t.Context(), successor, p)
			if err != nil {
				t.Fatal(err)
			}
			returned := checkedReturn(t, ret)
			if returned.checked.state.Direction != b.Successor.Direction || returned.checked.prefix.checked.bound.InitialDirection != before.InitialDirection {
				t.Fatal("outer return lost original/current DF")
			}
		}
	}
}

func TestTransitionDirectionSyscallPreservation(t *testing.T) {
	for _, bits := range []int{48, 57} {
		for _, placement := range []int{0, 1, 2} { // preserve, CLD before, CLD after
			var ops []dagOp
			add := func(i to.Intent) { ops = append(ops, dagScalar(i, stateEncoding(i, 0), len(ops)+1)) }
			add(to.Intent{Operation: to.MoveImmediate32, Dst: 0, Immediate: 158})
			add(to.Intent{Operation: to.MoveImmediate32, Dst: 7, Immediate: 0x1002})
			if placement == 1 {
				add(to.Intent{Operation: to.ClearDirection})
			}
			ops = append(ops, dagScalar(to.Intent{Operation: to.Syscall}, to.Encoding{Form: to.SYSCALL0F05}, len(ops)+1))
			if placement == 2 {
				add(to.Intent{Operation: to.ClearDirection})
			}
			x := dagArrange(t, ops, uint64(placement))
			face := callTLSFace()
			face.Conditions.UserAddressBits = bits
			cut := 2 * len(ops)
			c, err := CheckTransition(t.Context(), x.im, face, x.proposal(cut), TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			ceiling := uint64(1)<<(bits-1) - 4096
			for _, base := range []uint64{0, ceiling - 1, ceiling, ^uint64(0)} {
				for flags := 0; flags < 128; flags++ {
					raw := make([]byte, 137)
					raw[136] = byte(flags)
					initial := stateRawInitial(face, raw)
					initial.regs[6], initial.fs = base, 0x12345678
					callTLSAssert(t, c, x, cut, face, initial)
				}
			}
		}
	}
}

func TestTransitionDirectionFormsAndExclusion(t *testing.T) {
	compareExecutedEncoding(t, []byte{0xfc})
	for _, code := range [][]byte{{0xfd}, {0x66, 0xfc}, {0x67, 0xfc}, {0x40, 0xfc}, {0x48, 0xfc}, {0xf0, 0xfc}, {0xf2, 0xfc}, {0xf3, 0xfc}, {0x64, 0xfc}, {0x65, 0xfc}, {0x2e, 0xfc}} {
		compareExecutedEncoding(t, code)
	}
	inst, err := x86asm.Decode([]byte{0xfc}, 64)
	if err != nil || !TransitionExpansionRequired(inst) {
		t.Fatal("CLD is not an explicit expansion", err)
	}
	inst.Args[0] = x86asm.RAX
	if err := validateTransitionForm(testEntry, inst, []byte{0xfc}); err == nil {
		t.Fatal("CLD accepted an operand")
	}
	for _, raw := range []string{"fc", "fd", "66fc"} {
		im, cut := transitionFixture(t, raw)
		p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{})
		if err == nil {
			c, err := CheckTransition(t.Context(), im, stateFace(16, 0), p, TransitionLimits{})
			transitionRefused(t, c, err)
		}
	}
	// The unexpanded CLD arm is independently false. Admitting CLD must not
	// force execution or inspect a successor for this structural boundary.
	im, cut := transitionFixture(t, "4839c07401fc")
	p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransition(t.Context(), im, stateFace(16, 0), p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b := c.checked.bound
	if len(b.ExcludedBoundaries) != 1 || b.ExcludedBoundaries[0].Instruction.Op != x86asm.CLD || b.Direction != b.InitialDirection {
		t.Fatal("excluded CLD acquired execution semantics")
	}
}

func TestTransitionDirectionConstructionLimits(t *testing.T) {
	im, cut := transitionFixture(t, "fcbb2a000000")
	face := stateFace(16, 0)
	p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{}, TransitionOptions{Expansions: []TransitionExpansion{{PC: testEntry}}})
	if err != nil {
		t.Fatal(err)
	}
	full, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []TransitionLimits{
		{RelationLimits: RelationLimits{Work: full.checked.work - 1}},
		{RelationLimits: RelationLimits{Nodes: 20}},
		{LiveStateBytes: 1},
	} {
		c, err := CheckTransition(t.Context(), im, face, p, l)
		transitionRefused(t, c, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c, err := CheckTransition(ctx, im, face, p, TransitionLimits{})
	transitionRefused(t, c, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	partial, err := ProposeTransition(t.Context(), im, testEntry+1, TransitionLimits{}, TransitionOptions{Expansions: []TransitionExpansion{{PC: testEntry}}})
	if err != nil {
		t.Fatal(err)
	}
	root, err := CheckTransition(t.Context(), im, face, partial, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err = CheckTransitionContinuation(ctx, root, continuationProposal(t, root, cut))
	transitionRefused(t, c, err)
	if !errors.Is(err, context.Canceled) || !literalBool(root.checked.bound.Direction, 0) || root.checked.bound.InitialDirection.View().Op != br.Variable {
		t.Fatal("cancelled continuation changed retained direction state", err)
	}
}
