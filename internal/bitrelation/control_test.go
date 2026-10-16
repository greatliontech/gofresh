package bitrelation_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func TestConditionalBitsBoundaryWidthsDistinctBranches(t *testing.T) {
	for _, w := range []int{1, 64} {
		f := newFactory(t)
		s := br.Bits(w)
		scope := br.NewScope()
		p, a, b := f.variable(br.Bool(), scope, 0, false), f.variable(br.Bool(), scope, 1, false), f.variable(br.Bool(), scope, 2, false)
		enc := func(v br.Term) br.Term { return f.make(br.BoolToBits, s, 0, v) }
		l := f.make(br.ITE, s, 0, p, enc(a), enc(b))
		r := enc(f.make(br.ITE, br.Bool(), 0, p, a, b))
		direct(t, br.ConditionalBits, l, r)
		prove(t, l, r)
		for pv := uint64(0); pv < 2; pv++ {
			for av := uint64(0); av < 2; av++ {
				for bv := uint64(0); bv < 2; bv++ {
					assertValues(t, l, r, map[br.Term]uint64{p: pv, a: av, b: bv})
				}
			}
		}
		wrong := enc(f.make(br.ITE, br.Bool(), 0, p, b, a))
		refusal(t, l, wrong, br.Proof{Steps: []br.Step{{Rule: br.ConditionalBits, Left: l, Right: wrong}}}, br.InvalidRule)
	}
}

func TestTotalOrderSignedWideExtremaAndRandomPairs(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x19e3779b9, 0x7f4a7c15))
	for _, w := range []int{32, 64} {
		f := newFactory(t)
		s := br.Bits(w)
		scope := br.NewScope()
		x, y := f.variable(s, scope, 0, false), f.variable(s, scope, 1, false)
		lt := f.make(br.SLT, br.Bool(), 0, x, y)
		le := f.make(br.SLE, br.Bool(), 0, x, y)
		pairs := [][2]br.Term{
			{le, f.make(br.Not, br.Bool(), 0, f.make(br.SLT, br.Bool(), 0, y, x))},
			{f.make(br.Not, br.Bool(), 0, lt), f.make(br.SLE, br.Bool(), 0, y, x)},
		}
		for _, eq := range []br.Term{f.make(br.Equal, br.Bool(), 0, x, y), f.make(br.Equal, br.Bool(), 0, y, x)} {
			pairs = append(pairs, [2]br.Term{f.make(br.Or, br.Bool(), 0, lt, eq), le}, [2]br.Term{f.make(br.Or, br.Bool(), 0, eq, lt), le})
		}
		for _, pair := range pairs {
			direct(t, br.TotalOrder, pair[0], pair[1])
			prove(t, pair[0], pair[1])
		}
		checkPair := func(xv, yv uint64) {
			for _, pair := range pairs {
				assertValues(t, pair[0], pair[1], map[br.Term]uint64{x: xv, y: yv})
			}
		}
		half := uint64(1) << (w - 1)
		extrema := []uint64{0, 1, half - 2, half - 1, half, half + 1, widthMask(w) - 1, widthMask(w)}
		for _, xv := range extrema {
			for _, yv := range extrema {
				checkPair(xv, yv)
			}
		}
		// Fixed draws make this regression reproducible. The fuzz grammar adds
		// independently generated wide signed pairs beyond this finite sample.
		for i := 0; i < 512; i++ {
			checkPair(rng.Uint64()&widthMask(w), rng.Uint64()&widthMask(w))
		}
	}
}

func TestControlRulesRejectValidEarlierPremises(t *testing.T) {
	f := newFactory(t)
	scope := br.NewScope()
	s := br.Bits(8)
	x, y := f.variable(s, scope, 0, false), f.variable(s, scope, 1, false)
	p, q, r := f.variable(br.Bool(), scope, 2, false), f.variable(br.Bool(), scope, 3, false), f.variable(br.Bool(), scope, 4, false)
	not := func(v br.Term) br.Term { return f.make(br.Not, br.Bool(), 0, v) }
	enc := func(v br.Term) br.Term { return f.make(br.BoolToBits, s, 0, v) }
	narrow := func(v br.Term) br.Term { return f.make(br.Extract, br.Bits(4), 2, v) }
	cases := []struct {
		name string
		rule br.Rule
		l, r br.Term
	}{
		{"total-order", br.TotalOrder, f.make(br.SLE, br.Bool(), 0, x, y), not(f.make(br.SLT, br.Bool(), 0, y, x))},
		{"conditional-projection", br.ConditionalProjection, narrow(f.make(br.ITE, s, 0, p, x, y)), f.make(br.ITE, br.Bits(4), 0, p, narrow(x), narrow(y))},
		{"conditional-bits", br.ConditionalBits, f.make(br.ITE, s, 0, p, enc(q), enc(r)), enc(f.make(br.ITE, br.Bool(), 0, p, q, r))},
		{"conditional-swap", br.ConditionalSwap, f.make(br.ITE, s, 0, not(p), x, y), f.make(br.ITE, s, 0, p, y, x)},
		{"boolean-partition", br.BooleanPartition, f.make(br.Or, br.Bool(), 0, not(p), f.make(br.And, br.Bool(), 0, p, q)), not(f.make(br.And, br.Bool(), 0, p, not(q)))},
		{"sign-boundary", br.SignBoundary, f.make(br.ULT, br.Bool(), 0, x, f.con(s, 128)), not(f.make(br.SLT, br.Bool(), 0, x, f.con(s, 0)))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			direct(t, tc.rule, tc.l, tc.r)
			proposal := br.Proof{Steps: []br.Step{
				{Rule: br.Reflexivity, Left: tc.l, Right: tc.l},
				{Rule: tc.rule, Left: tc.l, Right: tc.r, Premises: []int{0}},
			}}
			w, err := br.Check(context.Background(), tc.l, tc.r, proposal, br.Limits{})
			var rejection *br.Refusal
			if w.Valid() || !errors.As(err, &rejection) || rejection.Code != br.InvalidRule || rejection.Step != 1 || rejection.Rule != tc.rule {
				t.Fatalf("extra valid premise did not refuse its local rule: witness=%v err=%v", w.Valid(), err)
			}
		})
	}
}

func TestTotalOrderEverySmallPair(t *testing.T) {
	for w := 1; w <= 8; w++ {
		f := newFactory(t)
		s := br.Bits(w)
		scope := br.NewScope()
		x, y := f.variable(s, scope, 0, false), f.variable(s, scope, 1, false)
		for _, strict := range []br.Op{br.ULT, br.SLT} {
			inclusive := br.ULE
			if strict == br.SLT {
				inclusive = br.SLE
			}
			lt := f.make(strict, br.Bool(), 0, x, y)
			le := f.make(inclusive, br.Bool(), 0, x, y)
			neg := f.make(br.Not, br.Bool(), 0, f.make(strict, br.Bool(), 0, y, x))
			pairs := [][2]br.Term{{le, neg}, {f.make(br.Not, br.Bool(), 0, lt), f.make(inclusive, br.Bool(), 0, y, x)}}
			for _, eq := range []br.Term{f.make(br.Equal, br.Bool(), 0, x, y), f.make(br.Equal, br.Bool(), 0, y, x)} {
				pairs = append(pairs, [2]br.Term{f.make(br.Or, br.Bool(), 0, lt, eq), le}, [2]br.Term{f.make(br.Or, br.Bool(), 0, eq, lt), le})
			}
			for _, pair := range pairs {
				direct(t, br.TotalOrder, pair[0], pair[1])
				prove(t, pair[0], pair[1])
			}
			for xv := uint64(0); xv <= widthMask(w); xv++ {
				for yv := uint64(0); yv <= widthMask(w); yv++ {
					for _, pair := range pairs {
						assertValues(t, pair[0], pair[1], map[br.Term]uint64{x: xv, y: yv})
					}
				}
			}
		}
	}
}

func TestConditionalRulesEverySmallValue(t *testing.T) {
	for w := 2; w <= 8; w++ {
		f := newFactory(t)
		scope := br.NewScope()
		s := br.Bits(w)
		p, q := f.variable(br.Bool(), scope, 0, false), f.variable(br.Bool(), scope, 1, false)
		x, y := f.variable(s, scope, 2, false), f.variable(s, scope, 3, true)
		not := func(a br.Term) br.Term { return f.make(br.Not, br.Bool(), 0, a) }
		type law struct {
			rule br.Rule
			l, r br.Term
		}
		var laws []law
		add := func(rule br.Rule, l, r br.Term) {
			direct(t, rule, l, r)
			prove(t, l, r)
			laws = append(laws, law{rule, l, r})
		}
		for i := 0; i < 2; i++ {
			for j := 0; j < 2; j++ {
				args := []br.Term{p, q}
				if j == 1 {
					args[0], args[1] = args[1], args[0]
				}
				parts := []br.Term{not(p), f.make(br.And, br.Bool(), 0, args...)}
				if i == 1 {
					parts[0], parts[1] = parts[1], parts[0]
				}
				add(br.BooleanPartition, f.make(br.Or, br.Bool(), 0, parts...), not(f.make(br.And, br.Bool(), 0, p, not(q))))
				args = []br.Term{not(p), q}
				if j == 1 {
					args[0], args[1] = args[1], args[0]
				}
				parts = []br.Term{p, f.make(br.And, br.Bool(), 0, args...)}
				if i == 1 {
					parts[0], parts[1] = parts[1], parts[0]
				}
				add(br.BooleanPartition, f.make(br.Or, br.Bool(), 0, parts...), not(f.make(br.And, br.Bool(), 0, not(p), not(q))))
			}
		}
		add(br.ConditionalSwap, f.make(br.ITE, s, 0, not(p), x, y), f.make(br.ITE, s, 0, p, y, x))
		for _, op := range []br.Op{br.Trunc, br.Extract} {
			for off := uint64(0); off <= 1; off++ {
				if op == br.Trunc && off != 0 {
					continue
				}
				narrow := br.Bits(w - 1)
				wide := f.make(br.ITE, s, 0, p, x, y)
				add(br.ConditionalProjection, f.make(op, narrow, off, wide), f.make(br.ITE, narrow, 0, p, f.make(op, narrow, off, x), f.make(op, narrow, off, y)))
			}
		}
		enc := func(b br.Term) br.Term { return f.make(br.BoolToBits, s, 0, b) }
		for _, other := range []br.Term{enc(q), f.con(s, 0), f.con(s, 1)} {
			boolean := q
			if other.View().Op == br.Constant {
				boolean = f.con(br.Bool(), other.View().Immediate)
			}
			add(br.ConditionalBits, f.make(br.ITE, s, 0, p, enc(q), other), enc(f.make(br.ITE, br.Bool(), 0, p, q, boolean)))
			add(br.ConditionalBits, f.make(br.ITE, s, 0, p, other, enc(q)), enc(f.make(br.ITE, br.Bool(), 0, p, boolean, q)))
		}
		for pv := uint64(0); pv < 2; pv++ {
			for qv := uint64(0); qv < 2; qv++ {
				for value := uint64(0); value <= widthMask(w); value++ {
					for _, other := range []uint64{0, widthMask(w), value} {
						for _, law := range laws {
							assertValues(t, law.l, law.r, map[br.Term]uint64{p: pv, q: qv, x: value, y: other})
						}
					}
				}
			}
		}
	}
}

func TestControlRulesRejectChangedConditionsAndBits(t *testing.T) {
	f := newFactory(t)
	s := br.Bits(8)
	scope := br.NewScope()
	x, y, z := f.variable(s, scope, 0, false), f.variable(s, scope, 1, false), f.variable(s, scope, 2, false)
	p, q := f.variable(br.Bool(), scope, 3, false), f.variable(br.Bool(), scope, 4, false)
	not := func(a br.Term) br.Term { return f.make(br.Not, br.Bool(), 0, a) }
	reject := func(rule br.Rule, l, r br.Term) {
		t.Helper()
		refusal(t, l, r, br.Proof{Steps: []br.Step{{Rule: rule, Left: l, Right: r}}}, br.InvalidRule)
	}
	le := f.make(br.ULE, br.Bool(), 0, x, y)
	reject(br.TotalOrder, le, not(f.make(br.SLT, br.Bool(), 0, y, x)))
	reject(br.TotalOrder, le, not(f.make(br.ULT, br.Bool(), 0, x, y)))
	for _, eq := range []br.Term{f.make(br.Equal, br.Bool(), 0, x, z), f.make(br.Equal, br.Bool(), 0, z, y)} {
		reject(br.TotalOrder, f.make(br.Or, br.Bool(), 0, f.make(br.ULT, br.Bool(), 0, x, y), eq), le)
	}
	l := f.make(br.Extract, br.Bits(4), 2, f.make(br.ITE, s, 0, p, x, y))
	r := f.make(br.ITE, br.Bits(4), 0, p, f.make(br.Extract, br.Bits(4), 2, x), f.make(br.Extract, br.Bits(4), 3, y))
	reject(br.ConditionalProjection, l, r)
	r = f.make(br.ITE, br.Bits(4), 0, q, f.make(br.Extract, br.Bits(4), 2, x), f.make(br.Extract, br.Bits(4), 2, y))
	reject(br.ConditionalProjection, l, r)
	r = f.make(br.ITE, br.Bits(4), 0, p, f.make(br.Extract, br.Bits(4), 2, y), f.make(br.Extract, br.Bits(4), 2, x))
	reject(br.ConditionalProjection, l, r)
	enc := func(a br.Term) br.Term { return f.make(br.BoolToBits, s, 0, a) }
	reject(br.ConditionalBits, f.make(br.ITE, s, 0, p, enc(q), f.con(s, 2)), enc(f.make(br.ITE, br.Bool(), 0, p, q, f.con(br.Bool(), 1))))
	reject(br.ConditionalBits, f.make(br.ITE, s, 0, p, enc(q), x), enc(f.make(br.ITE, br.Bool(), 0, p, q, f.make(br.Nonzero, br.Bool(), 0, x))))
	reject(br.ConditionalBits, f.make(br.ITE, s, 0, p, enc(q), f.con(s, 0)), enc(f.make(br.ITE, br.Bool(), 0, q, q, f.con(br.Bool(), 0))))
	reject(br.ConditionalSwap, f.make(br.ITE, s, 0, not(p), x, y), f.make(br.ITE, s, 0, p, x, y))
	reject(br.BooleanPartition, f.make(br.Or, br.Bool(), 0, not(p), f.make(br.And, br.Bool(), 0, q, q)), not(f.make(br.And, br.Bool(), 0, p, not(q))))
	reject(br.BooleanPartition, f.make(br.Or, br.Bool(), 0, not(q), f.make(br.And, br.Bool(), 0, p, q)), not(f.make(br.And, br.Bool(), 0, p, not(q))))
	// Non-identical conditions have a concrete counterexample, not an implied
	// relation from their shared Boolean sort or variable-slot spelling.
	if reference(t, l, map[br.Term]uint64{p: 1, q: 0, x: 4, y: 8}) == reference(t, r, map[br.Term]uint64{p: 1, q: 0, x: 4, y: 8}) {
		t.Fatal("projection swap lacks counterexample")
	}
}

// These expression shapes reproduce scalar endpoints discovered by the actual
// optimized artifact integration. They contain no symbol names or source facts:
// each proof is independently universal over its typed scalar variables.
func TestOptimizedControlEndpointShapes(t *testing.T) {
	for _, w := range []int{4, 5, 6, 7, 8, 32, 64} {
		f := newFactory(t)
		s := br.Bits(w)
		scope := br.NewScope()
		x, y := f.variable(s, scope, 0, false), f.variable(s, scope, 1, false)
		b := br.Bool()
		falseTerm, trueTerm := f.con(b, 0), f.con(b, 1)
		not := func(a br.Term) br.Term { return f.make(br.Not, b, 0, a) }
		and := func(a, c br.Term) br.Term { return f.make(br.And, b, 0, a, c) }
		or := func(a, c br.Term) br.Term { return f.make(br.Or, b, 0, a, c) }
		path := func(a br.Term) br.Term { return or(falseTerm, and(trueTerm, a)) }
		lt := func(op br.Op, a, c br.Term) br.Term { return f.make(op, b, 0, a, c) }
		inclusive := func(a, c br.Term) br.Term { return or(lt(br.ULT, a, c), lt(br.Equal, a, c)) }
		add, xor := f.make(br.Add, s, 0, x, y), f.make(br.BitXor, s, 0, x, y)
		pairs := [][2]br.Term{{f.make(br.ITE, s, 0, path(not(lt(br.ULT, x, y))), xor, add), f.make(br.ITE, s, 0, inclusive(y, x), xor, add)}}
		enc := func(a br.Term) br.Term { return f.make(br.BoolToBits, br.Bits(8), 0, a) }
		carry := enc(lt(br.ULT, add, x))
		nativeCarry := enc(not(inclusive(x, f.make(br.Add, s, 0, f.make(br.Add, s, 0, f.con(s, 0), x), f.make(br.Shl, s, 0, y)))))
		pairs = append(pairs, [2]br.Term{carry, nativeCarry})
		if w < 64 {
			max, lo, hi, replacement := uint64(7), uint64(2), uint64(4), uint64(6)
			if w == 32 {
				max, lo, hi, replacement = 1114111, 55296, 57344, 65533
			}
			c := func(v uint64) br.Term { return f.con(s, v) }
			upperScratch := f.variable(br.Bits(64-w), scope, 0, true)
			reg := f.make(br.Concat, br.Bits(64), 0, x, upperScratch)
			low := f.make(br.Extract, s, 0, reg)
			sourceInterval := f.make(br.ITE, b, 0, path(lt(br.SLE, c(lo), x)), lt(br.SLT, x, c(hi)), falseTerm)
			byteBits := enc(lt(br.SLT, low, c(hi)))
			partial := f.make(br.Concat, br.Bits(64), 0, byteBits, f.make(br.Extract, br.Bits(56), 8, reg))
			zero := f.make(br.ZExt, br.Bits(64), 0, f.make(br.BitXor, s, 0, low, low))
			nativeInterval := f.make(br.Extract, br.Bits(8), 0, f.make(br.ITE, br.Bits(64), 0, not(lt(br.SLT, low, c(lo))), partial, zero))
			pairs = append(pairs, [2]br.Term{enc(sourceInterval), nativeInterval})
			valid := and(path(not(lt(br.SLT, x, c(0)))), not(lt(br.SLT, c(max), x)))
			source := f.make(br.ITE, s, 0, path(and(path(valid), not(sourceInterval))), x, c(replacement))
			unsignedBound := inclusive(low, c(max))
			offset := f.make(br.Extract, s, 0, f.make(br.ZExt, br.Bits(64), 0, f.make(br.Add, s, 0, c((-lo)&widthMask(w)), low)))
			inRange := lt(br.ULT, offset, c(hi-lo))
			condition := or(not(unsignedBound), and(not(not(unsignedBound)), not(not(inRange))))
			native := f.make(br.Extract, s, 0, f.make(br.ITE, br.Bits(64), 0, condition, f.make(br.ZExt, br.Bits(64), 0, c(replacement)), reg))
			pairs = append(pairs, [2]br.Term{source, native})
			for index, pair := range pairs[2:] {
				t.Logf("projected endpoint width=%d shape=%d", w, index)
				prove(t, pair[0], pair[1])
				values := []uint64{0, 1, lo - 1, lo, hi - 1, hi, max, max + 1, 1 << uint(w-1), widthMask(w)}
				if w <= 8 {
					values = nil
					for value := uint64(0); value <= widthMask(w); value++ {
						values = append(values, value)
					}
				}
				for _, value := range values {
					assertValues(t, pair[0], pair[1], map[br.Term]uint64{x: value, y: 0, upperScratch: widthMask(64 - w)})
				}
			}
		}
		for _, pair := range pairs[:2] {
			prove(t, pair[0], pair[1])
			values := []uint64{0, 1, 1 << uint(w-1), widthMask(w)}
			if w <= 8 {
				values = nil
				for value := uint64(0); value <= widthMask(w); value++ {
					values = append(values, value)
				}
			}
			for _, xv := range values {
				for _, yv := range values {
					assertValues(t, pair[0], pair[1], map[br.Term]uint64{x: xv, y: yv})
				}
			}
		}
	}
}

func TestProjectionExpansionBudgetAndCancellation(t *testing.T) {
	f := newFactory(t)
	scope := br.NewScope()
	p := f.variable(br.Bool(), scope, 0, false)
	x := f.variable(br.Bits(64), scope, 1, false)
	y := f.variable(br.Bits(64), scope, 2, true)
	l := f.make(br.Extract, br.Bits(32), 4, f.make(br.ITE, br.Bits(64), 0, p, x, y))
	r := f.make(br.ITE, br.Bits(32), 0, p, f.make(br.Extract, br.Bits(32), 4, x), f.make(br.Extract, br.Bits(32), 4, y))
	prove(t, l, r)
	for _, limits := range []br.Limits{{Nodes: 1}, {Steps: 3}, {Work: 10}} {
		if w, err := br.Prove(context.Background(), l, r, limits); err == nil || w.Valid() {
			t.Fatal("projection escaped proof budget")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if w, err := br.Prove(ctx, l, r, br.Limits{}); err == nil || w.Valid() {
		t.Fatal("projection escaped cancellation")
	}
}

func TestSignBoundaryEverySmallValueAndExtrema(t *testing.T) {
	for _, w := range []int{1, 2, 3, 4, 5, 6, 7, 8, 32, 64} {
		f := newFactory(t)
		s := br.Bits(w)
		x := f.variable(s, br.NewScope(), 0, false)
		half := uint64(1) << (w - 1)
		l := f.make(br.ULT, br.Bool(), 0, x, f.con(s, half))
		r := f.make(br.Not, br.Bool(), 0, f.make(br.SLT, br.Bool(), 0, x, f.con(s, 0)))
		direct(t, br.SignBoundary, l, r)
		prove(t, l, r)
		values := []uint64{0, half - 1, half, widthMask(w)}
		if w <= 8 {
			values = nil
			for value := uint64(0); value <= widthMask(w); value++ {
				values = append(values, value)
			}
		}
		for _, v := range values {
			assertValues(t, l, r, map[br.Term]uint64{x: v})
		}
		bad := f.make(br.ULT, br.Bool(), 0, x, f.con(s, half-1))
		refusal(t, bad, r, br.Proof{Steps: []br.Step{{Rule: br.SignBoundary, Left: bad, Right: r}}}, br.InvalidRule)
		bad = f.make(br.Not, br.Bool(), 0, f.make(br.SLT, br.Bool(), 0, x, f.con(s, 1)))
		refusal(t, l, bad, br.Proof{Steps: []br.Step{{Rule: br.SignBoundary, Left: l, Right: bad}}}, br.InvalidRule)
	}
}
