package bitrelation_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func conditionalConcatTerms(f factory, p, a, b, c, d br.Term, mode int) (br.Term, br.Term) {
	out := br.Bits(a.Sort().Width() + c.Sort().Width())
	low, high := a, c
	if mode != 1 {
		low = f.make(br.ITE, a.Sort(), 0, p, a, b)
	} else {
		b = a
	}
	if mode != 0 {
		high = f.make(br.ITE, c.Sort(), 0, p, c, d)
	} else {
		d = c
	}
	left := f.make(br.Concat, out, 0, low, high)
	right := f.make(br.ITE, out, 0, p, f.make(br.Concat, out, 0, a, c), f.make(br.Concat, out, 0, b, d))
	return left, right
}

func TestConditionalConcatSmallValuations(t *testing.T) {
	for low := 1; low <= 3; low++ {
		for high := 1; high <= 3; high++ {
			for mode := range 3 {
				f := newFactory(t)
				p := f.variable(br.Bool(), br.NewScope(), 0, false)
				a, b := f.variable(br.Bits(low), br.NewScope(), 0, false), f.variable(br.Bits(low), br.NewScope(), 0, false)
				c, d := f.variable(br.Bits(high), br.NewScope(), 0, false), f.variable(br.Bits(high), br.NewScope(), 0, true)
				left, right := conditionalConcatTerms(f, p, a, b, c, d, mode)
				direct(t, br.ConditionalOperation, left, right)
				prove(t, left, right)
				for av := uint64(0); av <= widthMask(low); av++ {
					for bv := uint64(0); bv <= widthMask(low); bv++ {
						for cv := uint64(0); cv <= widthMask(high); cv++ {
							for dv := uint64(0); dv <= widthMask(high); dv++ {
								for pv := uint64(0); pv < 2; pv++ {
									assertValues(t, left, right, map[br.Term]uint64{p: pv, a: av, b: bv, c: cv, d: dv})
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestConditionalConcatWideFields(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x494645, 0x434f4e434154))
	for _, widths := range [][2]int{{1, 63}, {63, 1}, {8, 56}, {24, 8}, {32, 32}} {
		for mode := range 3 {
			f := newFactory(t)
			p := f.variable(br.Bool(), br.NewScope(), 0, false)
			a, b := f.variable(br.Bits(widths[0]), br.NewScope(), 0, false), f.variable(br.Bits(widths[0]), br.NewScope(), 0, false)
			c, d := f.variable(br.Bits(widths[1]), br.NewScope(), 0, false), f.variable(br.Bits(widths[1]), br.NewScope(), 0, true)
			left, right := conditionalConcatTerms(f, p, a, b, c, d, mode)
			direct(t, br.ConditionalOperation, left, right)
			prove(t, left, right)
			for sample := range 132 {
				values := map[br.Term]uint64{p: uint64(sample & 1)}
				for i, input := range []br.Term{a, b, c, d} {
					mask := widthMask(input.Sort().Width())
					value := rng.Uint64() & mask
					if sample < 4 {
						value = []uint64{0, 1, mask, uint64(1) << (input.Sort().Width() - 1)}[(sample+i)%4]
					}
					values[input] = value
				}
				assertValues(t, left, right, values)
			}
		}
	}
}

func TestConditionalConcatRejectsWrongCorrelation(t *testing.T) {
	f := newFactory(t)
	p, q := f.variable(br.Bool(), br.NewScope(), 0, false), f.variable(br.Bool(), br.NewScope(), 0, false)
	a, b := f.variable(br.Bits(3), br.NewScope(), 0, false), f.variable(br.Bits(3), br.NewScope(), 0, false)
	c, d := f.variable(br.Bits(5), br.NewScope(), 0, false), f.variable(br.Bits(5), br.NewScope(), 0, true)
	left, right := conditionalConcatTerms(f, p, a, b, c, d, 2)
	direct(t, br.ConditionalOperation, left, right)
	out := right.Sort()
	cat := func(a, b br.Term) br.Term { return f.make(br.Concat, out, 0, a, b) }
	yes, no := right.View().Args[1], right.View().Args[2]
	for i, wrong := range []br.Term{
		f.make(br.ITE, out, 0, q, yes, no),
		f.make(br.ITE, out, 0, p, no, yes),
		f.make(br.ITE, out, 0, p, cat(a, d), no),
		f.make(br.ITE, out, 0, p, yes, cat(b, c)),
		f.make(br.ITE, out, 0, p, cat(c, a), cat(d, b)),
		f.make(br.ITE, out, 0, p, cat(a, c), cat(a, d)),
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			refusal(t, left, wrong, br.Proof{Steps: []br.Step{{Rule: br.ConditionalOperation, Left: left, Right: wrong}}}, br.InvalidRule)
		})
	}
	independent := cat(f.make(br.ITE, a.Sort(), 0, p, a, b), f.make(br.ITE, c.Sort(), 0, q, c, d))
	refusal(t, independent, right, br.Proof{Steps: []br.Step{{Rule: br.ConditionalOperation, Left: independent, Right: right}}}, br.InvalidRule)
	// The original one-operand inference remains valid even if the other field
	// is conditional. Local checking need not demand the proposer's cofactoring.
	one := f.make(br.ITE, out, 0, p, cat(a, left.View().Args[1]), cat(b, left.View().Args[1]))
	direct(t, br.ConditionalOperation, left, one)
}

func TestConditionalConcatJoinedBytes(t *testing.T) {
	for _, width := range []int{32, 64} {
		f := newFactory(t)
		p := f.variable(br.Bool(), br.NewScope(), 0, false)
		a, b := uint64(0xffe0e555), uint64(0x80000000)
		if width == 64 {
			a, b = 0xfff8000000000555, 0x8000000000000000
		}
		var word br.Term
		for lane := 0; lane < width/8; lane++ {
			part := f.make(br.ITE, br.Bits(8), 0, p, f.con(br.Bits(8), a>>uint(8*lane)&255), f.con(br.Bits(8), b>>uint(8*lane)&255))
			if lane == 0 {
				word = part
			} else {
				word = f.make(br.Concat, br.Bits((lane+1)*8), 0, word, part)
			}
		}
		whole := f.make(br.ITE, br.Bits(width), 0, p, f.con(br.Bits(width), a), f.con(br.Bits(width), b))
		prove(t, word, whole)
		for pv := uint64(0); pv < 2; pv++ {
			assertValues(t, word, whole, map[br.Term]uint64{p: pv})
		}
	}
}

func TestConditionalConcatRetainsMaskComposition(t *testing.T) {
	f := newFactory(t)
	p := f.variable(br.Bool(), br.NewScope(), 0, false)
	a, b := f.variable(br.Bits(3), br.NewScope(), 0, false), f.variable(br.Bits(3), br.NewScope(), 0, false)
	c := f.variable(br.Bits(5), br.NewScope(), 0, true)
	low := f.make(br.ITE, br.Bits(3), 0, p, a, b)
	left, right := concatMaskTerms(f, low, c, 0x55)
	direct(t, br.ConcatMask, left, right)
	prove(t, left, right)
}

func TestConditionalConcatRetainsMaskBooleanEncoding(t *testing.T) {
	f := newFactory(t)
	p := f.variable(br.Bool(), br.NewScope(), 0, false)
	low := f.make(br.ITE, br.Bits(2), 0, p, f.con(br.Bits(2), 2), f.con(br.Bits(2), 3))
	left, right := concatMaskTerms(f, low, f.con(br.Bits(2), 0), 1)
	direct(t, br.ConcatMask, left, right)
	prove(t, left, right)
	computed := f.make(br.Add, br.Bits(4), 0, f.con(br.Bits(4), 0), f.con(br.Bits(4), 1))
	for _, args := range [][2]br.Term{{left.View().Args[0], computed}, {computed, left.View().Args[0]}} {
		prove(t, f.make(br.BitAnd, br.Bits(4), 0, args[:]...), right)
	}
}

func TestConditionalConcatRetainsConvertedMask(t *testing.T) {
	f := newFactory(t)
	p := f.variable(br.Bool(), br.NewScope(), 0, false)
	a, b := f.variable(br.Bits(2), br.NewScope(), 0, false), f.variable(br.Bits(2), br.NewScope(), 0, false)
	c := f.variable(br.Bits(4), br.NewScope(), 0, true)
	low := f.make(br.ITE, br.Bits(2), 0, p, a, b)
	x := f.make(br.Trunc, br.Bits(4), 0, f.make(br.Concat, br.Bits(6), 0, low, c))
	left := f.make(br.BitAnd, br.Bits(4), 0, x, f.con(br.Bits(4), 5))
	_, right := concatMaskTerms(f, low, f.make(br.Trunc, br.Bits(2), 0, c), 5)
	prove(t, left, right)
}

func TestConditionalConcatCumulativeSearch(t *testing.T) {
	f := newFactory(t)
	p := f.variable(br.Bool(), br.NewScope(), 0, false)
	a, b := f.variable(br.Bits(3), br.NewScope(), 0, false), f.variable(br.Bits(3), br.NewScope(), 0, false)
	c, d := f.variable(br.Bits(5), br.NewScope(), 0, false), f.variable(br.Bits(5), br.NewScope(), 0, true)
	left, right := conditionalConcatTerms(f, p, a, b, c, d, 2)
	count := &conditionalCheckpoint{Context: t.Context()}
	proof, err := br.Propose(count, left, right, br.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	check(t, left, right, proof)
	for _, limits := range []br.Limits{{Work: count.calls - 1}, {Steps: len(proof.Steps) - 1}} {
		_, err := br.Propose(t.Context(), left, right, limits)
		var refusal *br.Refusal
		if !errors.As(err, &refusal) || refusal.Code != br.Budget {
			t.Fatalf("alternative normalization restarted its allowance: %v", err)
		}
	}
	for at := 1; at <= count.calls; at++ {
		ctx, cancel := context.WithCancel(t.Context())
		callback := &conditionalCheckpoint{Context: ctx, action: func(n int) {
			if n == at {
				cancel()
			}
		}}
		_, err := br.Propose(callback, left, right, br.Limits{})
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("alternative normalization masked cancellation at %d: %v", at, err)
		}
	}
}

func TestConditionalConcatMaskValuations(t *testing.T) {
	for width := 1; width <= 4; width++ {
		f := newFactory(t)
		s := br.Bits(width)
		p := f.variable(br.Bool(), br.NewScope(), 0, false)
		a, b := f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, true)
		high := f.variable(br.Bits(1), br.NewScope(), 0, false)
		conditional := f.make(br.ITE, s, 0, p, a, b)
		for mask := uint64(0); mask <= widthMask(width+1); mask++ {
			for position := range 2 {
				left, right := concatMaskTerms(f, conditional, high, mask)
				direct(t, br.ConcatMask, left, right)
				if position == 1 {
					view := left.View()
					left = f.make(br.BitAnd, left.Sort(), 0, view.Args[1], view.Args[0])
				}
				prove(t, left, right)
				for av := uint64(0); av <= widthMask(width); av++ {
					for bv := uint64(0); bv <= widthMask(width); bv++ {
						for pv := uint64(0); pv < 2; pv++ {
							for hv := uint64(0); hv < 2; hv++ {
								assertValues(t, left, right, map[br.Term]uint64{p: pv, a: av, b: bv, high: hv})
							}
						}
					}
				}
			}
		}
	}
}

func TestConditionalConcatCancellationAndBudget(t *testing.T) {
	f := newFactory(t)
	p := f.variable(br.Bool(), br.NewScope(), 0, false)
	a, b := f.variable(br.Bits(3), br.NewScope(), 0, false), f.variable(br.Bits(3), br.NewScope(), 0, false)
	c, d := f.variable(br.Bits(5), br.NewScope(), 0, false), f.variable(br.Bits(5), br.NewScope(), 0, true)
	left, right := conditionalConcatTerms(f, p, a, b, c, d, 2)
	proof := br.Proof{Steps: []br.Step{{Rule: br.ConditionalOperation, Left: left, Right: right}}}
	count := &conditionalCheckpoint{Context: t.Context()}
	if witness, err := br.Check(count, left, right, proof, br.Limits{}); err != nil || !witness.Valid() {
		t.Fatal(err)
	}
	for at := 1; at <= count.calls; at++ {
		ctx, cancel := context.WithCancel(t.Context())
		callback := &conditionalCheckpoint{Context: ctx, action: func(n int) {
			if n == at {
				cancel()
			}
		}}
		witness, err := br.Check(callback, left, right, proof, br.Limits{})
		cancel()
		if witness.Valid() || !errors.Is(err, context.Canceled) {
			t.Fatalf("conditional concatenation masked cancellation at %d: %v", at, err)
		}
	}
	for _, limits := range []br.Limits{{Nodes: 7}, {Work: count.calls - 1}} {
		witness, err := br.Check(t.Context(), left, right, proof, limits)
		var refusal *br.Refusal
		if witness.Valid() || !errors.As(err, &refusal) || refusal.Code != br.Budget {
			t.Fatalf("conditional concatenation exceeded its finite account: %v", err)
		}
	}
}
