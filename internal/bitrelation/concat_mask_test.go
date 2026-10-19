package bitrelation_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func concatMaskTerms(f factory, low, high br.Term, bits uint64) (br.Term, br.Term) {
	w := low.Sort().Width() + high.Sort().Width()
	left := f.make(br.BitAnd, br.Bits(w), 0, f.make(br.Concat, br.Bits(w), 0, low, high), f.con(br.Bits(w), bits))
	right := f.make(br.Concat, br.Bits(w), 0,
		f.make(br.BitAnd, low.Sort(), 0, low, f.con(low.Sort(), bits&widthMask(low.Sort().Width()))),
		f.make(br.BitAnd, high.Sort(), 0, high, f.con(high.Sort(), bits>>low.Sort().Width())))
	return left, right
}

func TestConcatMaskEverySmallValuation(t *testing.T) {
	// Every mask, split and joint low/high valuation at total widths 2..5.
	// The independent big-integer interpreter does not reuse mask/split helpers
	// from production. Both fields may be arbitrary, even when one is erased.
	for width := 2; width <= 5; width++ {
		for split := 1; split < width; split++ {
			f := newFactory(t)
			low := f.variable(br.Bits(split), br.NewScope(), 0, false)
			high := f.variable(br.Bits(width-split), br.NewScope(), 0, true)
			for bits := uint64(0); bits <= widthMask(width); bits++ {
				left, right := concatMaskTerms(f, low, high, bits)
				direct(t, br.ConcatMask, left, right)
				prove(t, left, right)
				for lo := uint64(0); lo <= widthMask(split); lo++ {
					for hi := uint64(0); hi <= widthMask(width-split); hi++ {
						assertValues(t, left, right, map[br.Term]uint64{low: lo, high: hi})
					}
				}
			}
		}
	}
}

func TestConcatMaskEveryWidthAndSplit(t *testing.T) {
	rng := rand.New(rand.NewPCG(0xc04ca7, 0x32ff64))
	for width := 2; width <= 64; width++ {
		for split := 1; split < width; split++ {
			f := newFactory(t)
			low := f.variable(br.Bits(split), br.NewScope(), 0, false)
			high := f.variable(br.Bits(width-split), br.NewScope(), 0, true)
			for _, bits := range []uint64{widthMask(split), widthMask(width) ^ widthMask(split), rng.Uint64() & widthMask(width)} {
				left, right := concatMaskTerms(f, low, high, bits)
				direct(t, br.ConcatMask, left, right)
				prove(t, left, right)
				// Wide valuations are boundary cases plus deterministic samples,
				// not an exhaustive population or assumptions of the proof.
				for _, pair := range [][2]uint64{{0, 0}, {widthMask(split), widthMask(width - split)}, {rng.Uint64() & widthMask(split), rng.Uint64() & widthMask(width-split)}} {
					assertValues(t, left, right, map[br.Term]uint64{low: pair[0], high: pair[1]})
				}
			}
		}
	}
}

func TestConcatMaskPartialRegisterComposition(t *testing.T) {
	f := newFactory(t)
	scratch := f.variable(br.Bits(64), br.NewScope(), 0, true)
	low := f.con(br.Bits(8), 0xa7)
	inserted := f.make(br.Concat, br.Bits(64), 0, low, f.make(br.Extract, br.Bits(56), 8, scratch))
	read32 := f.make(br.Extract, br.Bits(32), 0, inserted)
	for _, args := range [][2]br.Term{{read32, f.con(br.Bits(32), 255)}, {f.con(br.Bits(32), 255), read32}} {
		masked := f.make(br.BitAnd, br.Bits(32), 0, args[:]...)
		written := f.make(br.ZExt, br.Bits(64), 0, masked)
		proof := prove(t, written, f.con(br.Bits(64), 0xa7))
		used := false
		for _, step := range proof.Steps {
			used = used || step.Rule == br.ConcatMask
		}
		if !used {
			t.Fatal("partial-register regression did not exercise checked mask distribution")
		}
	}
}

func TestConcatMaskRejectsForgedSplitOrOperand(t *testing.T) {
	f := newFactory(t)
	scope := br.NewScope()
	low := f.variable(br.Bits(4), scope, 0, false)
	high := f.variable(br.Bits(4), scope, 0, true)
	foreign := f.variable(br.Bits(4), br.NewScope(), 0, false)
	left, right := concatMaskTerms(f, low, high, 0xa5)
	direct(t, br.ConcatMask, left, right)
	and := func(x br.Term, bits uint64) br.Term { return f.make(br.BitAnd, x.Sort(), 0, x, f.con(x.Sort(), bits)) }
	join := func(lo, hi br.Term) br.Term { return f.make(br.Concat, br.Bits(8), 0, lo, hi) }
	for _, bad := range []br.Term{
		join(and(low, 4), and(high, 10)), join(and(low, 5), and(high, 11)),
		join(and(high, 5), and(low, 10)), join(and(foreign, 5), and(high, 10)),
		join(and(low, 5), and(low, 10)),
		join(and(f.make(br.Trunc, br.Bits(3), 0, low), 5), and(f.make(br.ZExt, br.Bits(5), 0, high), 10)),
		join(f.make(br.BitOr, br.Bits(4), 0, low, f.con(br.Bits(4), 5)), and(high, 10)),
		join(and(low, 5), f.make(br.BitXor, br.Bits(4), 0, high, f.con(br.Bits(4), 10))),
	} {
		refusal(t, left, bad, br.Proof{Steps: []br.Step{{Rule: br.ConcatMask, Left: left, Right: bad}}}, br.InvalidRule)
	}
	parts := left.View().Args
	for _, bad := range []br.Term{
		f.make(br.BitOr, br.Bits(8), 0, parts...),
		f.make(br.BitAnd, br.Bits(8), 0, parts[1], parts[0]),
		f.make(br.BitAnd, br.Bits(8), 0, parts[0], f.variable(br.Bits(8), scope, 1, false)),
	} {
		refusal(t, bad, right, br.Proof{Steps: []br.Step{{Rule: br.ConcatMask, Left: bad, Right: right}}}, br.InvalidRule)
	}
	refusal(t, right, left, br.Proof{Steps: []br.Step{{Rule: br.ConcatMask, Left: right, Right: left}}}, br.InvalidRule)
	refusal(t, left, right, br.Proof{Steps: []br.Step{{Rule: br.Reflexivity, Left: left, Right: left}, {Rule: br.ConcatMask, Left: left, Right: right, Premises: []int{0}}}}, br.InvalidRule)
}

func TestConcatMaskOwnershipAndBounds(t *testing.T) {
	f := newFactory(t)
	low, high := f.variable(br.Bits(8), br.NewScope(), 0, false), f.variable(br.Bits(24), br.NewScope(), 0, true)
	left, right := concatMaskTerms(f, low, high, 255)
	prove(t, left, right)
	proposal := br.Proof{Steps: []br.Step{{Rule: br.ConcatMask, Left: left, Right: right}}}
	ctx := &conditionalCheckpoint{Context: t.Context(), action: func(n int) {
		if n == 1 {
			proposal.Steps[0].Right = f.con(br.Bits(32), 0)
		}
	}}
	witness, err := br.Check(ctx, left, right, proposal, br.Limits{})
	if err != nil || !witness.Valid() {
		t.Fatalf("caller callback changed the owned rule: %v", err)
	}
	for _, limits := range []br.Limits{{Nodes: 1}, {Work: 1}, {Steps: 1}} {
		_, err := br.Propose(t.Context(), left, right, limits)
		var refusal *br.Refusal
		if !errors.As(err, &refusal) || refusal.Code != br.Budget {
			t.Fatalf("mask expansion lacks its specific budget refusal: %+v: %v", limits, err)
		}
	}
	for _, limits := range []br.Limits{{Nodes: 1}, {Work: 1}} {
		w, err := br.Check(t.Context(), left, right, br.Proof{Steps: []br.Step{{Rule: br.ConcatMask, Left: left, Right: right}}}, limits)
		var refusal *br.Refusal
		if w.Valid() || !errors.As(err, &refusal) || refusal.Code != br.Budget {
			t.Fatalf("mask checking lacks its specific budget refusal: %+v: %v", limits, err)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := br.Propose(cancelled, left, right, br.Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("proposal ignored cancellation: %v", err)
	}
	if w, err := br.Check(cancelled, left, right, br.Proof{Steps: []br.Step{{Rule: br.ConcatMask, Left: left, Right: right}}}, br.Limits{}); w.Valid() || !errors.Is(err, context.Canceled) {
		t.Fatalf("checker ignored cancellation: %v", err)
	}
}
