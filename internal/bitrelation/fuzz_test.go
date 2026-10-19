package bitrelation_test

import (
	"context"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

// The fuzz grammar exercises exact constant evaluation and independent checking
// for every primitive, plus symbolic interval and truncation rules. Widths are
// uniform over 1..64, the operator selector covers arithmetic/comparison/shift
// families, and shift counts include width, above-width and uint64 extrema.
// Conditional arithmetic/order adds both operand positions, an independent
// third word and a condition selected from a width-independent input bit.
func FuzzExactScalarSemantics(f *testing.F) {
	for _, w := range []uint8{0, 1, 7, 31, 63} {
		for op := uint8(0); op < 23; op++ {
			f.Add(w, op, ^uint64(0), uint64(1), uint64(64))
			f.Add(w|64, op, uint64(1), ^uint64(0), uint64(0))
		}
	}
	f.Fuzz(func(t *testing.T, wByte, selector uint8, a, b, shift uint64) {
		w := int(wByte%64) + 1
		s := br.Bits(w)
		a &= widthMask(w)
		b &= widthMask(w)
		g := newFactory(t)
		x, y := g.con(s, a), g.con(s, b)
		var root br.Term
		binary := []br.Op{br.Add, br.Sub, br.BitAnd, br.BitOr, br.BitXor, br.Equal, br.ULT, br.ULE, br.SLT, br.SLE}
		if int(selector%23) < len(binary) {
			op := binary[selector%23]
			out := s
			if op == br.Equal || op == br.ULT || op == br.ULE || op == br.SLT || op == br.SLE {
				out = br.Bool()
			}
			root = g.make(op, out, 0, x, y)
		} else {
			switch selector % 23 {
			case 10:
				root = g.make(br.BitNot, s, 0, x)
			case 11:
				root = g.make(br.Shl, s, shift, x)
			case 12:
				root = g.make(br.LShr, s, shift, x)
			case 13:
				root = g.make(br.AShr, s, shift, x)
			case 14:
				root = g.make(br.ITE, s, 0, g.con(br.Bool(), b&1), x, y)
			case 15:
				root = g.make(br.Nonzero, br.Bool(), 0, x)
			case 16:
				root = g.make(br.BoolToBits, s, 0, g.con(br.Bool(), a&1))
			case 17, 18:
				if w < 64 {
					op := br.ZExt
					if selector%23 == 18 {
						op = br.SExt
					}
					root = g.make(op, br.Bits(64), 0, x)
				} else {
					root = g.make(br.Trunc, br.Bits(32), 0, x)
				}
			case 19:
				width := int(shift%uint64(w)) + 1
				offset := b % uint64(w-width+1)
				root = g.make(br.Extract, br.Bits(width), offset, x)
			case 20:
				if w <= 32 {
					root = g.make(br.Concat, br.Bits(2*w), 0, x, y)
				} else {
					root = g.make(br.Trunc, br.Bits(32), 0, x)
				}
			case 21:
				root = g.make(br.Not, br.Bool(), 0, g.make(br.And, br.Bool(), 0, g.con(br.Bool(), a&1), g.con(br.Bool(), b&1)))
			case 22:
				root = g.make(br.Or, br.Bool(), 0, g.con(br.Bool(), a&1), g.con(br.Bool(), b&1))
			}
		}
		want := reference(t, root, nil)
		got, err := br.Eval(context.Background(), root, nil, br.Limits{})
		if err != nil || got != want {
			t.Fatalf("width=%d op=%d got=%x want=%x err=%v", w, selector%23, got, want, err)
		}
		target := g.con(root.Sort(), want)
		prove(t, root, target)
		// A one-bit mutation of the claimed answer must never pass a direct
		// constant-fold certificate, even though both terms remain well typed.
		bad := g.con(root.Sort(), want^1)
		refusal(t, root, bad, br.Proof{Steps: []br.Step{{Rule: br.ConstantFold, Left: root, Right: bad}}}, br.InvalidRule)
		// Exercise symbolic order, carry and path partition at every sampled
		// width, including 64. Every positive has a local certificate and an
		// independently evaluated input assignment; samples are never premises.
		controlScope := br.NewScope()
		vx, vy := g.variable(s, controlScope, 0, false), g.variable(s, controlScope, 1, false)
		bp, bq := g.variable(br.Bool(), controlScope, 2, false), g.variable(br.Bool(), controlScope, 3, false)
		not := func(v br.Term) br.Term { return g.make(br.Not, br.Bool(), 0, v) }
		sum := g.make(br.Add, s, 0, vx, vy)
		carry := g.make(br.ULT, br.Bool(), 0, sum, vx)
		carryFlags := not(g.make(br.Or, br.Bool(), 0, g.make(br.ULT, br.Bool(), 0, vx, sum), g.make(br.Equal, br.Bool(), 0, vx, sum)))
		signedInclusive := g.make(br.SLE, br.Bool(), 0, vx, vy)
		signedFlags := g.make(br.Or, br.Bool(), 0, g.make(br.SLT, br.Bool(), 0, vx, vy), g.make(br.Equal, br.Bool(), 0, vy, vx))
		direct(t, br.TotalOrder, signedFlags, signedInclusive)
		partition := g.make(br.Or, br.Bool(), 0, not(bp), g.make(br.And, br.Bool(), 0, bp, bq))
		partitioned := not(g.make(br.And, br.Bool(), 0, bp, not(bq)))
		conjunction := g.make(br.And, br.Bool(), 0, g.make(br.And, br.Bool(), 0, bp, bq), not(bq))
		falsity := g.con(br.Bool(), 0)
		direct(t, br.ConjunctionContradiction, conjunction, falsity)
		for _, pair := range [][2]br.Term{{carry, carryFlags}, {signedFlags, signedInclusive}, {partition, partitioned}, {conjunction, falsity}, {g.make(br.ITE, s, 0, not(bp), vx, vy), g.make(br.ITE, s, 0, bp, vy, vx)}} {
			prove(t, pair[0], pair[1])
			assertValues(t, pair[0], pair[1], map[br.Term]uint64{vx: a, vy: b, bp: shift & 1, bq: (shift >> 1) & 1})
		}
		vz := g.variable(s, br.NewScope(), 0, false)
		operation := conditionalOperations[int(selector)%len(conditionalOperations)]
		position := int(selector) / len(conditionalOperations) % 2
		conditional, distributed := conditionalOperationTerms(g, operation, position, bp, vx, vy, vz)
		direct(t, br.ConditionalOperation, conditional, distributed)
		prove(t, conditional, distributed)
		assertValues(t, conditional, distributed, map[br.Term]uint64{vx: a, vy: b, vz: shift & widthMask(w), bp: uint64(wByte >> 6 & 1)})
		// A symbolic low field plus arbitrary upper scratch bits must project
		// exactly, regardless of extension sign or discarded native register bits.
		// Trunc requires a strictly narrower result, so width 64 has no such case.
		if w < 64 {
			scope := br.NewScope()
			v := g.variable(s, scope, 0, false)
			high := g.variable(br.Bits(64-w), scope, 0, true)
			full := g.make(br.Concat, br.Bits(64), 0, v, high)
			ext := br.ZExt
			if selector&1 != 0 {
				ext = br.SExt
			}
			extended := g.make(ext, br.Bits(64), 0, v)
			for _, wide := range []br.Term{full, extended} {
				low := g.make(br.Trunc, s, 0, wide)
				prove(t, low, v)
				for _, value := range []uint64{a, b, shift & widthMask(w), 0, widthMask(w)} {
					assertValues(t, low, v, map[br.Term]uint64{v: value, high: shift & widthMask(64-w)})
				}
			}
			// Project through a native-width path merge, preserving both
			// distinct branch values and its exact independently chosen condition.
			other := g.make(br.ZExt, br.Bits(64), 0, g.make(br.Add, s, 0, v, g.con(s, 1)))
			projected := g.make(br.Trunc, s, 0, g.make(br.ITE, br.Bits(64), 0, bp, full, other))
			selected := g.make(br.ITE, s, 0, bp, v, g.make(br.Add, s, 0, v, g.con(s, 1)))
			prove(t, projected, selected)
			assertValues(t, projected, selected, map[br.Term]uint64{v: a, high: shift & widthMask(64-w), bp: shift & 1})
		}
		if a != b {
			// Order in the mathematical signed domain without host signed overflow.
			sign := uint64(1) << (w - 1)
			low, high := a, b
			if low^sign > high^sign {
				low, high = high, low
			}
			v, l, r := interval(g, w, low, high, true)
			prove(t, l, r)
			for _, value := range []uint64{a, b, shift & widthMask(w), 0, widthMask(w), sign, sign - 1} {
				assertValues(t, l, r, map[br.Term]uint64{v: value})
			}
		}
	})
}

func BenchmarkIntervalProposal(b *testing.B) {
	f := newFactory(b)
	_, l, r := interval(f, 32, 0xd800, 0xe000, true)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := br.Propose(context.Background(), l, r, br.Limits{}); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkIntervalCheck(b *testing.B) {
	f := newFactory(b)
	_, l, r := interval(f, 32, 0xd800, 0xe000, true)
	p := prove(b, l, r)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := br.Check(context.Background(), l, r, p, br.Limits{}); err != nil {
			b.Fatal(err)
		}
	}
}
