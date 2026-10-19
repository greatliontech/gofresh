package closure

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

func selectedCheckCompleteReturn(t testing.TB, raw []byte, image *nativeproof.Image, application nativeproof.TransitionCallCertificate, header nativeproof.TransitionCertificate) {
	t.Helper()
	prior, ok := application.Successor()
	if !ok {
		t.Fatal("missing actual-call successor")
	}
	incoming, _ := prior.BoundFor(image)
	firstHeader, _ := header.BoundFor(image)
	decode := globalCandidateDecoder(t, raw)
	var ret uint64
	var expansions []nativeproof.TransitionExpansion
	for pc, count := incoming.Boundary.PC, 0; count < 64; count++ {
		i := decode(pc)
		if i.Op == x86asm.RET {
			ret = pc
			break
		}
		if nativeproof.TransitionExpansionRequired(i) {
			expansions = append(expansions, nativeproof.TransitionExpansion{PC: pc})
		}
		pc += uint64(i.Len)
	}
	if ret == 0 {
		t.Fatal("candidate native epilogue has no actual RET")
	}
	for _, start := range []nativeproof.TransitionCertificate{prior, header} {
		b, _ := start.Bound()
		choices := expansions
		if b.Boundary.ID == firstHeader.Boundary.ID {
			// INC lies before the first header cut in address order but has not
			// executed. Other optional forms already in the prefix repeat later.
			choices = nil
			for _, e := range expansions {
				if decode(e.PC).Op != x86asm.XOR {
					choices = append(choices, e)
				}
			}
		}
		options := nativeproof.TransitionOptions{MaxOccurrences: 128, Expansions: choices}
		proposal, err := nativeproof.ProposeTransitionContinuation(t.Context(), start, ret, options)
		if err != nil {
			t.Fatal(err)
		}
		prefix, err := nativeproof.CheckTransitionContinuation(t.Context(), start, proposal)
		if err != nil {
			t.Fatal(err)
		}
		completed, err := nativeproof.CheckTransitionReturn(t.Context(), prefix)
		if err != nil {
			t.Fatal(err)
		}
		assertSelectedCheckReturn(t, image, incoming, completed)
		result, _ := completed.Bound()
		t.Logf("actual complete native caller RET=%#x from cut=%#x: %d retained instruction occurrences, %d accesses, %d primitives", ret, b.Boundary.PC, len(result.Instructions), len(result.Accesses), len(result.Prefix.PrimitiveEffects))
	}
	var loopChoices []nativeproof.TransitionExpansion
	for _, e := range expansions {
		if decode(e.PC).Op != x86asm.XOR {
			loopChoices = append(loopChoices, e)
		}
	}
	short, err := nativeproof.ProposeTransitionContinuation(t.Context(), header, ret, nativeproof.TransitionOptions{MaxOccurrences: 8, Expansions: loopChoices})
	if err != nil {
		t.Fatal(err)
	}
	bad, err := nativeproof.CheckTransitionContinuation(t.Context(), header, short)
	var refusal *nativeproof.Refusal
	if _, accepted := bad.Bound(); accepted || !errors.As(err, &refusal) || refusal.Premise != "transition-frontier" {
		t.Fatalf("incomplete native loop did not refuse at its feasible frontier: %v", err)
	}
}

// The tail's source correspondence is a separate obligation. These assertions
// check the native return against its incoming conditional caller state, including
// residual scratch and the two actual epilogue reads; no ELF-root fact is assumed.
func assertSelectedCheckReturn(t testing.TB, image *nativeproof.Image, incoming nativeproof.TransitionBound, completed nativeproof.TransitionReturnCertificate) {
	t.Helper()
	b, ok := completed.BoundFor(image)
	if !ok {
		t.Fatal("complete caller return does not belong to the selected image")
	}
	if !b.Prefix.ConditionalRegion || b.Prefix.Entry != incoming.Entry || b.Prefix.Origin != incoming.Origin || b.Prefix.EntryPredicate != incoming.EntryPredicate || b.Prefix.InitialRegisters != incoming.InitialRegisters || b.Prefix.InitialVectors != incoming.InitialVectors || !reflect.DeepEqual(b.Prefix.Interface, incoming.Interface) {
		t.Fatal("native loop completion changed the original caller scope or premises")
	}
	if !b.State.CalleeTerminated || incoming.Interface.ReturnContext == nil || b.State.PC != incoming.Interface.ReturnContext.Target || b.Continuation.PC != b.State.PC || len(b.Prefix.Frames) != 0 {
		t.Fatal("native caller did not complete its actual incoming return")
	}
	if !reflect.DeepEqual(b.State.Memory, incoming.Memory) || b.State.Vectors != incoming.Vectors || b.State.SSE != incoming.SSE || b.State.Thread != incoming.Thread || !reflect.DeepEqual(b.Prefix.PrimitiveEffects, incoming.PrimitiveEffects) || !reflect.DeepEqual(b.Prefix.Abstractions, incoming.Abstractions) {
		t.Fatal("integer loop or return lost residual bytes, vector/thread context or prior effects")
	}
	if len(b.Instructions) <= len(incoming.Instructions) || !reflect.DeepEqual(b.Instructions[:len(incoming.Instructions)], incoming.Instructions) || len(b.Accesses) < len(incoming.Accesses) || !reflect.DeepEqual(b.Accesses[:len(incoming.Accesses)], incoming.Accesses) {
		t.Fatal("completed caller lost its executed prefix")
	}
	constants := br.NewBuilder(16)
	falseTerm, err := constants.Make(br.Constant, br.Bool(), 0)
	if err != nil {
		t.Fatal(err)
	}
	guards := make(map[nativeproof.TransitionOccurrenceID]br.Term, len(b.Instructions))
	for _, instruction := range b.Instructions {
		if _, duplicate := guards[instruction.ID]; duplicate || instruction.ID == 0 {
			t.Fatal("instruction occurrence identity was collapsed")
		}
		guards[instruction.ID] = instruction.Guard
	}
	var active []nativeproof.TransitionAccess
	for _, access := range b.Accesses[len(incoming.Accesses):] {
		guard, found := guards[access.ID]
		if !found {
			t.Fatal("epilogue access lacks its exact occurrence guard")
		}
		if _, err := br.Prove(t.Context(), guard, falseTerm, br.Limits{}); err == nil {
			continue
		}
		// Complete-return coverage establishes this retained reach condition
		// for every admitted input; no independently unknown arm counts as live.
		if _, err := br.Prove(t.Context(), guard, b.Prefix.CutGuard, br.Limits{}); err != nil {
			t.Fatalf("epilogue access is neither excluded nor total: %v", err)
		}
		active = append(active, access)
	}
	if len(active) != 2 {
		t.Fatalf("completed caller has %d active epilogue accesses, want two", len(active))
	}
	readBP, readReturn := active[0], active[1]
	if readBP.Image || readBP.Kind != nativeproof.FrameRead || readBP.Bytes != (nativeproof.RelativeSpan{Start: -8, End: 0}) || readReturn.Image || readReturn.Kind != nativeproof.FrameReturnRead || readReturn.Bytes != (nativeproof.RelativeSpan{Start: 0, End: 8}) {
		t.Fatal("epilogue did not read the saved frame pointer and original control word in order")
	}
	for register, want := range map[nativeproof.Register]uint64{nativeproof.RAX: 11, nativeproof.RCX: 11, nativeproof.RDX: 2048, nativeproof.RSI: 0xffffffff} {
		budget := 128
		expected, err := constants.Const(br.Bits(64), want)
		if err != nil {
			t.Fatal(err)
		}
		if err := selectedCheckEqual(t.Context(), b.Prefix.CutGuard, b.State.Registers[register].Value, expected, &budget); err != nil {
			t.Fatalf("completed native loop register %d differs from %#x: %v", register, want, err)
		}
	}
	for register := range b.State.Registers {
		switch nativeproof.Register(register) {
		case nativeproof.RAX, nativeproof.RCX, nativeproof.RDX, nativeproof.RSI, nativeproof.RSP, nativeproof.RBP:
			continue
		}
		if b.State.Registers[register] != incoming.Registers[register] {
			t.Fatalf("loop or epilogue changed unrelated register %d", register)
		}
	}
	budget := 128
	if err := selectedCheckEqual(t.Context(), b.Prefix.EntryPredicate, b.State.Registers[nativeproof.RBP].Value, incoming.InitialRegisters[nativeproof.RBP], &budget); err != nil {
		t.Fatalf("original frame pointer was not restored: %v", err)
	}
	if b.State.Registers[nativeproof.RSP].Pointer != (nativeproof.OriginPointer{Origin: incoming.Origin, Offset: 8}) {
		t.Fatal("return did not consume the original control slot")
	}
}

// Each ITE partitions the admitted scope; prove both arm implications rather
// than demanding a single rewrite flatten the entire finite exit-state union.
// Concatenations partition every result bit exactly once. Only checked false
// guards discharge an arm without checking its value.
func selectedCheckEqual(ctx context.Context, guard, value, expected br.Term, budget *int) error {
	if value.Sort() != br.Bits(64) || expected.Sort() != value.Sort() {
		return fmt.Errorf("selected return assertion requires two complete words")
	}
	return selectedCheckRange(ctx, guard, value, expected, 0, budget)
}

func selectedCheckRange(ctx context.Context, guard, value, root br.Term, offset int, budget *int) error {
	if *budget <= 0 {
		return fmt.Errorf("selected return assertion exhausted its branch bound")
	}
	*budget--
	width := value.Sort().Width()
	if width <= 0 || offset < 0 || offset > root.Sort().Width()-width {
		return fmt.Errorf("selected return assertion has an invalid bit range")
	}
	builder := br.NewBuilder(4)
	expected := root
	if offset != 0 || width != root.Sort().Width() {
		var err error
		expected, err = builder.Make(br.Extract, br.Bits(width), uint64(offset), root)
		if err != nil {
			return err
		}
	}
	relation := globalFunctionCorrespondence{antecedent: guard}
	err := relation.equal(ctx, value, expected)
	if err == nil || !globalFunctionUnproved(err) {
		return err
	}
	view := value.View()
	if view.Op == br.Concat && len(view.Args) == 2 {
		low, high := view.Args[0], view.Args[1]
		if low.Sort().Width()+high.Sort().Width() != width {
			return fmt.Errorf("selected return concatenation does not cover its word")
		}
		if err := selectedCheckRange(ctx, guard, low, root, offset, budget); err != nil {
			return err
		}
		return selectedCheckRange(ctx, guard, high, root, offset+low.Sort().Width(), budget)
	}
	if view.Op != br.ITE || len(view.Args) != 3 {
		return fmt.Errorf("value root %+v expected %+v: %w", view, expected.View(), err)
	}
	negative, err := builder.Make(br.Not, br.Bool(), 0, view.Args[0])
	if err != nil {
		return err
	}
	for index, condition := range []br.Term{view.Args[0], negative} {
		path, err := builder.Make(br.And, br.Bool(), 0, guard, condition)
		if err != nil {
			return err
		}
		if err := selectedCheckRange(ctx, path, view.Args[index+1], root, offset, budget); err != nil {
			return err
		}
	}
	return nil
}

func TestSelectedReturnRangeAssertion(t *testing.T) {
	b := br.NewBuilder(4096)
	x, err := b.Input(br.Bits(64), br.NewScope(), 0)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := b.Input(br.Bool(), br.NewScope(), 0)
	if err != nil {
		t.Fatal(err)
	}
	makeTerm := func(op br.Op, sort br.Sort, immediate uint64, args ...br.Term) br.Term {
		v, err := b.Make(op, sort, immediate, args...)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	negative := makeTerm(br.Not, br.Bool(), 0, guard)
	truth := makeTerm(br.Constant, br.Bool(), 1)
	// Corrupt either arm, under both a selecting antecedent and an antecedent
	// admitting both arms. Every bit is checked; an arbitrary excluded arm must
	// not defeat the positive controls.
	for flipped := -1; flipped < 64; flipped++ {
		var word br.Term
		for lane := 0; lane < 8; lane++ {
			v := makeTerm(br.Extract, br.Bits(8), uint64(lane*8), x)
			if flipped >= 0 && flipped/8 == lane {
				mask := makeTerm(br.Constant, br.Bits(8), uint64(1)<<uint(flipped%8))
				v = makeTerm(br.BitXor, br.Bits(8), 0, v, mask)
			}
			if lane == 0 {
				word = v
			} else {
				word = makeTerm(br.Concat, br.Bits((lane+1)*8), 0, word, v)
			}
		}
		for arm, selected := range []br.Term{guard, negative} {
			for _, both := range []bool{false, true} {
				outside := makeTerm(br.Constant, br.Bits(64), 0)
				admitted := selected
				if both {
					outside, admitted = x, truth
				}
				arms := [2]br.Term{outside, outside}
				arms[arm] = word
				joined := makeTerm(br.ITE, br.Bits(64), 0, guard, arms[0], arms[1])
				budget := 128
				err := selectedCheckEqual(t.Context(), admitted, joined, x, &budget)
				if flipped < 0 && err != nil || flipped >= 0 && !globalFunctionUnproved(err) {
					t.Fatalf("bit corruption %d, arm %d, both feasible %t: %v", flipped, arm, both, err)
				}
			}
		}
	}
}
