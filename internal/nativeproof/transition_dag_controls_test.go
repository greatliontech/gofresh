package nativeproof

import (
	"context"
	"errors"
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

func TestTransitionGuardedCoverageControls(t *testing.T) {
	face := cpuidFace()
	// Literal bytes supply coincident successors, a backward physical DAG,
	// overlapping instructions, dead-but-unsupported forms and cycles. The cut
	// itself may be unsupported, but no prior unsupported node is a stopping rule.
	for _, code := range []string{"7400", "74054889e0ebf84889c3", "b80000000083f80074020f054889c3", "74014889c3", "7402ebfc4889c3", "7402c3904889c3"} {
		im, cut := transitionFixture(t, code)
		c, err := proveTransition(t, im, cut, face)
		if code == "7400" {
			if err != nil {
				t.Fatal(err)
			}
			for flags := 0; flags < 8; flags++ {
				b := c.checked.bound
				values := map[br.Term]uint64{b.InitialPredicates.CF: uint64(flags & 1), b.InitialPredicates.ZF: uint64(flags >> 1 & 1), b.InitialPredicates.SFXorOF: uint64(flags >> 2 & 1)}
				if stateEval(t, b.CutGuard, values) != 1 {
					t.Fatal("coincident edge union lost")
				}
			}
		} else {
			transitionRefused(t, c, err)
		}
	}
	// A branch can bypass a proposed old cut. No theorem about that cut may be
	// manufactured by a proposed ordered list or by an endpoint-only comparison.
	ops := []dagOp{dagBranch(4, 1, 2), dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 0}, to.Encoding{Form: to.MOVB8Imm32}, 3), dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 3}, to.Encoding{Form: to.MOVB8Imm32}, 3)}
	x := dagArrange(t, ops, 9)
	for _, cut := range []int{2, 4} {
		c, err := CheckTransition(t.Context(), x.im, face, x.proposal(cut), TransitionLimits{})
		transitionRefused(t, c, err)
	}
	// Corrupting an otherwise opaque predecessor is an internal adversarial
	// control: continuation must reconstruct coverage instead of trusting a list.
	root := continuationRoot(t, x.im, x.pcs[0], face, TransitionLimits{})
	fake := *root.checked
	fake.bound = cloneTransitionBound(fake.bound)
	fake.bound.Boundary.PC = x.pcs[2]
	c, err := CheckTransitionContinuation(t.Context(), TransitionCertificate{&fake}, x.proposal(6))
	transitionRefused(t, c, err)
}

func TestTransitionGuardedFalseTransferPolicy(t *testing.T) {
	// TEST defines CF as literal false. JB's taken arm has a valid encoding but
	// no address provenance; its transfer may be skipped only under that literal
	// false guard. The full arm remains in the byte/edge inventory.
	face := cpuidFace()
	ops := []dagOp{dagScalar(to.Intent{Operation: to.Test, Width: 32, Dst: 0, Src: 0}, to.Encoding{Form: to.TEST85}, 1), dagBranch(2, 2, 3), dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 3, Immediate: 7}, to.Encoding{Form: to.MOVB8Imm32}, 4), dagScalar(to.Intent{Operation: to.Load, Base: 3, Dst: 0}, to.Encoding{Form: to.MOV8B, REX: 0x48}, 4)}
	face.Regions = nil
	face.Words = nil
	x := dagArrange(t, ops, 12)
	c, err := CheckTransition(t.Context(), x.im, face, x.proposal(8), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	dagAssert(t, c, x, 8, face, stateInitial(face, 7), nil)
	if len(c.checked.bound.Instructions) != 8 {
		t.Fatal("false arm disappeared from syntactic coverage")
	}
	// CMP EAX,EAX has an independently obvious false carry mathematically, but
	// this checker has not proved that simplification: it must retain/refuse the
	// unproved arm, not silently use operand equality as graph-pruning authority.
	ops[0] = dagScalar(to.Intent{Operation: to.Compare, Width: 32, Dst: 0, Src: 0}, to.Encoding{Form: to.CMP39}, 1)
	x = dagArrange(t, ops, 12)
	c, err = CheckTransition(t.Context(), x.im, face, x.proposal(8), TransitionLimits{})
	transitionRefused(t, c, err)
}

func TestTransitionGuardedCancellationAndRetainedRoots(t *testing.T) {
	face := cpuidFace()
	ops := []dagOp{dagBranch(4, 1, 2), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 3), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 3), dagScalar(to.Intent{Operation: to.CompareImmediate, Width: 32, Dst: 0}, to.Encoding{Form: to.CMP83}, 4)}
	x := dagArrange(t, ops, 31)
	root := continuationRoot(t, x.im, x.pcs[0], face, TransitionLimits{})
	before, _ := root.Bound()
	p := x.proposal(8)
	count := &imageCallbackContext{Context: t.Context()}
	c, err := CheckTransitionContinuation(count, root, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{1, count.calls / 4, count.calls / 2, count.calls * 3 / 4, count.calls} {
		ctx := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {}}
		ctx.onErr = func(n int) {
			if n == at {
				ctx.Context = contextCanceled()
			}
		}
		bad, err := CheckTransitionContinuation(ctx, root, p)
		if !errors.Is(err, context.Canceled) || bad.checked != nil {
			t.Fatal("cancellation published a partial DAG", err)
		}
	}
	after, _ := root.Bound()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("cancelled continuation mutated root")
	}
	// Dead entry predicates and optional outcomes remain imported even after
	// later instructions overwrite all corresponding current registers/flags.
	ops = append(ops, dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 0}, to.Encoding{Form: to.MOVB8Imm32}, 5))
	y := dagArrange(t, ops, 31)
	r := continuationRoot(t, y.im, y.pcs[8], face, TransitionLimits{})
	assertTransitionRetainedExpressionUnion(t, r, y.proposal(10))
	if c.checked.bound.InitialPredicates != before.InitialPredicates {
		t.Fatal("root predicate identities changed")
	}
}

func contextCanceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestTransitionGuardedNestedAndSequential(t *testing.T) {
	face := cpuidFace()
	ops := []dagOp{
		dagBranch(4, 1, 4), dagBranch(2, 2, 3),
		dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 5),
		dagScalar(to.Intent{Operation: to.StoreImmediate, Base: 4, Width: 8, Immediate: 127}, to.Encoding{Form: to.MOVC6, SIB: true}, 5),
		dagScalar(to.Intent{Operation: to.Store, Base: 4, Width: 32, Src: 3}, to.Encoding{Form: to.MOV89, SIB: true}, 5),
		dagScalar(to.Intent{Operation: to.Test, Width: 32, Dst: 0, Src: 0}, to.Encoding{Form: to.TEST85}, 6),
		dagBranch(4, 7, 8), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 9),
		dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 9),
		dagScalar(to.Intent{Operation: to.Load, Base: 4, Dst: 8}, to.Encoding{Form: to.MOV8B, REX: 0x4c, SIB: true}, 10),
	}
	for flags := 0; flags < 8; flags++ {
		for _, zero := range []bool{false, true} {
			initial := stateInitial(face, uint64(flags))
			initial.flags = [6]bool{flags&1 != 0, flags&2 != 0, false, flags&4 != 0, false, false}
			if zero {
				initial.regs[0] = 0
			}
			initial.outcomes = [][4]uint32{{0, 1, 2, 3}, {4, 5, 6, 7}}
			dagCheck(t, ops, face, initial, uint64(flags)*13, 5, 6, 9)
		}
	}
}

func TestTransitionGuardedLiveStateAccounting(t *testing.T) {
	face := cpuidFace()
	face.Regions = []RelativeRegion{{RelativeSpan{0, 8}, true, true}}
	face.Words = nil
	var ops []dagOp
	for j := 0; j < 64; j++ {
		ops = append(ops, dagBranch(4, j+1, j+1))
	}
	x := dagArrange(t, ops, 44)
	// Find the root's measured allocation threshold independently of the private
	// node representation. The larger graph's pointer inventory is explicit.
	low, high := 1, 1<<20
	for low < high {
		mid := (low + high) / 2
		c, err := CheckTransition(t.Context(), x.im, face, x.proposal(0), TransitionLimits{LiveStateBytes: mid})
		if err == nil && c.checked != nil {
			high = mid
		} else {
			low = mid + 1
		}
	}
	room := low + 8*(len(x.pcs)-1)
	p := x.proposal(len(ops) * 2)
	c, err := CheckTransition(t.Context(), x.im, face, p, TransitionLimits{LiveStateBytes: room})
	transitionRefused(t, c, err)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Detail != "aggregate live-state bytes" {
		t.Fatal("fork did not hit aggregate state allowance", err)
	}
	// Two live states suffice irrespective of how many earlier joins were
	// consumed. Holding every historical state would exhaust this allowance.
	c, err = CheckTransition(t.Context(), x.im, face, p, TransitionLimits{LiveStateBytes: room + low})
	if err != nil {
		t.Fatal("consumed node state was retained", err)
	}
	for _, zero := range []bool{false, true} {
		initial := stateInitial(face, 7)
		initial.flags[1] = zero
		dagAssert(t, c, x, len(ops)*2, face, initial, nil)
	}
}

func TestTransitionGuardedPointerJoins(t *testing.T) {
	face := imageStateFace()
	face.Conditions.CPUID = CPUIDModel
	for _, imagePointer := range []bool{false, true} {
		for _, partial := range []bool{false, true} {
			for _, same := range []bool{false, true} {
				first := dagScalar(to.Intent{Operation: to.MoveRegister, Dst: 15, Src: 4}, to.Encoding{Form: to.MOV89, REX: 0x49}, 1)
				if imagePointer {
					first = dagScalar(to.Intent{Operation: to.LEARIP, Dst: 15}, to.Encoding{Form: to.LEA8D, REX: 0x4c, DispBytes: 4}, 1)
					first.address = imageStateAddress
				}
				store := to.Intent{Operation: to.Store, Base: 4, Src: 15}
				if !same {
					store.Src = 4
				}
				if partial {
					store.Width = 8
					store.Src = 4
				}
				ops := []dagOp{first, dagScalar(to.Intent{Operation: to.Store, Base: 4, Src: 15}, to.Encoding{Form: to.MOV89, REX: 0x4c, SIB: true}, 2), dagBranch(4, 3, 4), dagScalar(store, stateEncoding(store, 0), 4), dagScalar(to.Intent{Operation: to.Load, Base: 4, Dst: 9}, to.Encoding{Form: to.MOV8B, REX: 0x4c, SIB: true}, 5)}
				x := dagArrange(t, ops, 17)
				c, err := CheckTransition(t.Context(), x.im, face, x.proposal(10), TransitionLimits{})
				if err != nil {
					t.Fatal(err)
				}
				pointer := c.checked.bound.Registers[9].Pointer
				wantPointer := !partial && (!imagePointer || same)
				if (pointer != nil) != wantPointer {
					t.Fatal("join kept unequal provenance or lost identical fact", imagePointer, partial, same, pointer)
				}
				for _, zero := range []bool{false, true} {
					initial := stateInitial(face, 2)
					initial.flags[1] = zero
					dagAssert(t, c, x, 10, face, initial, nil)
				}
			}
		}
	}
}

func TestTransitionGuardedShortConditions(t *testing.T) {
	face := cpuidFace()
	for _, cc := range []uint8{2, 3, 4, 5, 6, 7, 12, 13, 14, 15} {
		for flags := 0; flags < 8; flags++ {
			ops := []dagOp{dagBranch(cc, 1, 2), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 3), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 3)}
			ops[0].e.Form = to.JccShort
			initial := stateInitial(face, uint64(flags))
			initial.flags = [6]bool{flags&1 != 0, flags&2 != 0, false, flags&4 != 0, false, false}
			initial.outcomes = [][4]uint32{{1, 2, 3, 4}}
			dagCheck(t, ops, face, initial, uint64(flags))
		}
	}
}

func TestTransitionGuardedCumulativeWorkAndCapture(t *testing.T) {
	face := cpuidFace()
	ops := []dagOp{dagBranch(4, 1, 2), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 3), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 3)}
	x := dagArrange(t, ops, 11)
	p := x.proposal(6)
	root := continuationRoot(t, x.im, x.pcs[0], face, TransitionLimits{})
	whole, err := CheckTransitionContinuation(t.Context(), root, p)
	if err != nil {
		t.Fatal(err)
	}
	limited, err := CheckTransition(t.Context(), x.im, face, x.proposal(0), TransitionLimits{RelationLimits: RelationLimits{Work: whole.checked.work - 1}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransitionContinuation(t.Context(), limited, p)
	transitionRefused(t, c, err)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Premise != "relation-budget" {
		t.Fatal("cumulative work was reset", err)
	}
	projection, _ := root.Bound()
	ctx := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
		if n == 1 {
			p.Nodes[0].Successors[1] = 0
			p.Cut = 0
			projection.InitialPredicates = TransitionPredicates{}
			projection.CutGuard = br.Term{}
		}
	}}
	c, err = CheckTransitionContinuation(ctx, root, p)
	if err != nil {
		t.Fatal("branch proposal was not captured before callback", err)
	}
	for _, zero := range []bool{false, true} {
		initial := stateInitial(face, 3)
		initial.flags[1] = zero
		dagAssert(t, c, x, 6, face, initial, nil)
	}
}
