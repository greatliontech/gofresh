package bitrelation_test

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

type factory struct {
	t testing.TB
	b *br.Builder
}

func newFactory(t testing.TB) factory { return factory{t, br.NewBuilder(0)} }
func (f factory) make(op br.Op, s br.Sort, imm uint64, args ...br.Term) br.Term {
	f.t.Helper()
	v, err := f.b.Make(op, s, imm, args...)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}
func (f factory) con(s br.Sort, v uint64) br.Term { f.t.Helper(); return f.make(br.Constant, s, v) }
func (f factory) variable(s br.Sort, scope br.Scope, slot uint64, scratch bool) br.Term {
	f.t.Helper()
	var v br.Term
	var err error
	if scratch {
		v, err = f.b.Scratch(s, scope, slot)
	} else {
		v, err = f.b.Input(s, scope, slot)
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}
func widthMask(w int) uint64 { return ^uint64(0) >> (64 - w) }
func check(t testing.TB, l, r br.Term, p br.Proof) br.Witness {
	t.Helper()
	w, err := br.Check(context.Background(), l, r, p, br.Limits{})
	if err != nil || !w.Valid() {
		t.Fatalf("check: witness=%v err=%v", w.Valid(), err)
	}
	return w
}
func direct(t testing.TB, rule br.Rule, l, r br.Term) br.Witness {
	t.Helper()
	return check(t, l, r, br.Proof{Steps: []br.Step{{Rule: rule, Left: l, Right: r}}})
}
func prove(t testing.TB, l, r br.Term) br.Proof {
	t.Helper()
	p, err := br.Propose(context.Background(), l, r, br.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	check(t, l, r, p)
	return p
}
func refusal(t testing.TB, l, r br.Term, p br.Proof, code br.Code) {
	t.Helper()
	w, err := br.Check(context.Background(), l, r, p, br.Limits{})
	var re *br.Refusal
	if w.Valid() || !errors.As(err, &re) || re.Code != code {
		t.Fatalf("want %s refusal, got witness=%v err=%v", code, w.Valid(), err)
	}
}

// reference uses unbounded integers, explicit mathematical signed interpretation,
// and a final Euclidean reduction. It does not call the production evaluator or
// its primitive arithmetic helpers. Projection is syntax only, not authority.
func reference(t testing.TB, root br.Term, env map[br.Term]uint64) uint64 {
	t.Helper()
	var eval func(br.Term) *big.Int
	modulus := func(w int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(w)) }
	asSigned := func(x *big.Int, w int) *big.Int {
		y := new(big.Int).Set(x)
		if x.Bit(w-1) != 0 {
			y.Sub(y, modulus(w))
		}
		return y
	}
	eval = func(term br.Term) *big.Int {
		v := term.View()
		r := new(big.Int)
		if v.Op == br.Variable {
			n, ok := env[term]
			if !ok {
				t.Fatal("reference missing variable")
			}
			return r.SetUint64(n)
		}
		a := make([]*big.Int, len(v.Args))
		for i, arg := range v.Args {
			a[i] = eval(arg)
		}
		truth := func(b bool) {
			if b {
				r.SetInt64(1)
			}
		}
		switch v.Op {
		case br.Constant:
			r.SetUint64(v.Immediate)
		case br.Not:
			truth(a[0].Sign() == 0)
		case br.And:
			truth(a[0].Sign() != 0 && a[1].Sign() != 0)
		case br.Or:
			truth(a[0].Sign() != 0 || a[1].Sign() != 0)
		case br.ITE:
			if a[0].Sign() != 0 {
				r.Set(a[1])
			} else {
				r.Set(a[2])
			}
		case br.Equal:
			truth(a[0].Cmp(a[1]) == 0)
		case br.ULT:
			truth(a[0].Cmp(a[1]) < 0)
		case br.ULE:
			truth(a[0].Cmp(a[1]) <= 0)
		case br.SLT:
			truth(asSigned(a[0], v.Args[0].Sort().Width()).Cmp(asSigned(a[1], v.Args[1].Sort().Width())) < 0)
		case br.SLE:
			truth(asSigned(a[0], v.Args[0].Sort().Width()).Cmp(asSigned(a[1], v.Args[1].Sort().Width())) <= 0)
		case br.Add:
			r.Add(a[0], a[1])
		case br.Sub:
			r.Sub(a[0], a[1])
		case br.BitAnd:
			r.And(a[0], a[1])
		case br.BitOr:
			r.Or(a[0], a[1])
		case br.BitXor:
			r.Xor(a[0], a[1])
		case br.BitNot:
			r.Not(a[0])
		case br.Shl:
			if v.Immediate < uint64(v.Sort.Width()) {
				r.Lsh(a[0], uint(v.Immediate))
			}
		case br.LShr:
			if v.Immediate < uint64(v.Sort.Width()) {
				r.Rsh(a[0], uint(v.Immediate))
			}
		case br.AShr:
			x := asSigned(a[0], v.Sort.Width())
			if v.Immediate >= uint64(v.Sort.Width()) {
				if x.Sign() < 0 {
					r.SetInt64(-1)
				}
			} else {
				r.Rsh(x, uint(v.Immediate))
			}
		case br.Trunc, br.ZExt, br.BoolToBits:
			r.Set(a[0])
		case br.SExt:
			r.Set(asSigned(a[0], v.Args[0].Sort().Width()))
		case br.Concat:
			r.Lsh(a[1], uint(v.Args[0].Sort().Width()))
			r.Add(r, a[0])
		case br.Extract:
			r.Rsh(a[0], uint(v.Immediate))
		case br.Nonzero:
			truth(a[0].Sign() != 0)
		default:
			t.Fatalf("reference unknown operator %v", v.Op)
		}
		if !v.Sort.IsBool() {
			r.Mod(r, modulus(v.Sort.Width()))
		}
		return r
	}
	return eval(root).Uint64()
}

func assertValues(t testing.TB, l, r br.Term, env map[br.Term]uint64) {
	t.Helper()
	want := reference(t, l, env)
	other := reference(t, r, env)
	if want != other {
		t.Fatalf("accepted false theorem: left=%x right=%x env=%v", want, other, env)
	}
	assign := make([]br.Assignment, 0, len(env))
	for v, n := range env {
		assign = append(assign, br.Assignment{Variable: v, Value: n})
	}
	for _, term := range []br.Term{l, r} {
		got, err := br.Eval(context.Background(), term, assign, br.Limits{})
		if err != nil || got != want {
			t.Fatalf("eval=%x err=%v want=%x", got, err, want)
		}
	}
}

func interval(f factory, w int, l, u uint64, ite bool) (br.Term, br.Term, br.Term) {
	s := br.Bits(w)
	x := f.variable(s, br.NewScope(), 0, false)
	lo, hi := f.con(s, l), f.con(s, u)
	less := f.make(br.SLT, br.Bool(), 0, x, lo)
	upper := f.make(br.SLT, br.Bool(), 0, x, hi)
	left := f.make(br.And, br.Bool(), 0, f.make(br.Not, br.Bool(), 0, less), upper)
	if ite {
		left = f.make(br.ITE, br.Bool(), 0, less, f.con(br.Bool(), 0), upper)
	}
	right := f.make(br.ULT, br.Bool(), 0, f.make(br.Sub, s, 0, x, lo), f.con(s, (u-l)&widthMask(w)))
	return x, left, right
}

func TestSignedIntervalAllSmallValuesAndEndpointGuards(t *testing.T) {
	for w := 2; w <= 8; w++ {
		t.Run(fmt.Sprint(w), func(t *testing.T) {
			min, max := -(1 << (w - 1)), (1<<(w-1))-1
			bounds := [][2]int{{min, max}, {min, 0}, {-1, 0}, {0, max}, {min, min + 1}, {max - 1, max}, {-1, 1}}
			// Every endpoint pair is checked at widths 2..4, plus intervals
			// spanning/sign-touching both extrema at all widths through eight.
			if w <= 4 {
				bounds = nil
				for l := min; l < max; l++ {
					for u := l + 1; u <= max; u++ {
						bounds = append(bounds, [2]int{l, u})
					}
				}
			}
			for _, bound := range bounds {
				f := newFactory(t)
				x, l, r := interval(f, w, uint64(bound[0])&widthMask(w), uint64(bound[1])&widthMask(w), false)
				direct(t, br.SignedInterval, l, r)
				prove(t, l, r)
				for value := 0; value < 1<<w; value++ {
					assertValues(t, l, r, map[br.Term]uint64{x: uint64(value)})
				}
			}
		})
	}
	for _, w := range []int{1, 32, 64} {
		m := widthMask(w)
		min := uint64(1) << (w - 1)
		max := min - 1
		for _, ends := range [][2]uint64{{min, max}, {min, 0}, {m, 0}} {
			f := newFactory(t)
			x, l, r := interval(f, w, ends[0], ends[1], true)
			prove(t, l, r)
			for _, v := range []uint64{0, 1 & m, min, max, m, ends[0], ends[1], (ends[0] - 1) & m, (ends[1] - 1) & m} {
				assertValues(t, l, r, map[br.Term]uint64{x: v})
			}
		}
		for _, ends := range [][2]uint64{{0, 0}, {max, min}, {0, min}, {max, max}} {
			f := newFactory(t)
			_, l, r := interval(f, w, ends[0], ends[1], false)
			refusal(t, l, r, br.Proof{Steps: []br.Step{{Rule: br.SignedInterval, Left: l, Right: r}}}, br.InvalidRule)
		}
	}
}

func TestRewriteUniversality(t *testing.T) {
	for w := 2; w <= 8; w++ {
		f := newFactory(t)
		s := br.Bits(w)
		x := f.variable(s, br.NewScope(), 0, false)
		zero, ones := f.con(s, 0), f.con(s, widthMask(w))
		type law struct {
			rule br.Rule
			l, r br.Term
		}
		laws := []law{}
		add := func(rule br.Rule, l, r br.Term) { laws = append(laws, law{rule, l, r}) }
		for _, op := range []br.Op{br.Add, br.Sub, br.BitOr, br.BitXor} {
			add(br.Algebra, f.make(op, s, 0, x, zero), x)
		}
		add(br.Algebra, f.make(br.BitAnd, s, 0, x, ones), x)
		add(br.Algebra, f.make(br.BitAnd, s, 0, x, zero), zero)
		for _, op := range []br.Op{br.Sub, br.BitXor} {
			add(br.Algebra, f.make(op, s, 0, x, x), zero)
		}
		for _, op := range []br.Op{br.BitAnd, br.BitOr} {
			add(br.Algebra, f.make(op, s, 0, x, x), x)
		}
		add(br.Algebra, f.make(br.BitNot, s, 0, f.make(br.BitNot, s, 0, x)), x)
		for _, op := range []br.Op{br.Shl, br.LShr, br.AShr} {
			add(br.Algebra, f.make(op, s, 0, x), x)
		}
		for _, op := range []br.Op{br.Equal, br.ULT, br.ULE, br.SLT, br.SLE} {
			v := uint64(0)
			if op == br.Equal || op == br.ULE || op == br.SLE {
				v = 1
			}
			add(br.Algebra, f.make(op, br.Bool(), 0, x, x), f.con(br.Bool(), v))
		}
		for _, op := range []br.Op{br.Add, br.BitAnd, br.BitOr, br.BitXor, br.Equal} {
			out := s
			if op == br.Equal {
				out = br.Bool()
			}
			add(br.Commute, f.make(op, out, 0, x, ones), f.make(op, out, 0, ones, x))
		}
		add(br.SubtractConstant, f.make(br.Sub, s, 0, x, ones), f.make(br.Add, s, 0, x, f.con(s, 1)))
		for _, ext := range []br.Op{br.ZExt, br.SExt} {
			y := f.make(ext, br.Bits(w+2), 0, x)
			add(br.Conversion, f.make(br.Trunc, s, 0, y), x)
			add(br.Conversion, f.make(br.Trunc, br.Bits(w-1), 0, y), f.make(br.Trunc, br.Bits(w-1), 0, x))
			add(br.Conversion, f.make(br.Trunc, br.Bits(w+1), 0, y), f.make(ext, br.Bits(w+1), 0, x))
			add(br.Conversion, f.make(ext, br.Bits(w+3), 0, y), f.make(ext, br.Bits(w+3), 0, x))
		}
		add(br.Conversion, f.make(br.SExt, br.Bits(w+2), 0, f.make(br.ZExt, br.Bits(w+1), 0, x)), f.make(br.ZExt, br.Bits(w+2), 0, x))
		add(br.Conversion, f.make(br.Extract, s, 0, x), x)
		for _, law := range laws {
			direct(t, law.rule, law.l, law.r)
			prove(t, law.l, law.r)
			for value := 0; value < 1<<w; value++ {
				assertValues(t, law.l, law.r, map[br.Term]uint64{x: uint64(value)})
			}
		}
	}
}

func TestBooleanLawsEveryValuation(t *testing.T) {
	f := newFactory(t)
	s := br.Bool()
	scope := br.NewScope()
	a, b := f.variable(s, scope, 0, false), f.variable(s, scope, 1, false)
	zero, one := f.con(s, 0), f.con(s, 1)
	not := func(x br.Term) br.Term { return f.make(br.Not, s, 0, x) }
	type law struct{ l, r br.Term }
	laws := []law{{not(not(a)), a}}
	for _, x := range []br.Term{a, zero, one} {
		for _, y := range []br.Term{b, zero, one} {
			if x == a && y == b {
				continue
			}
			for _, op := range []br.Op{br.And, br.Or} {
				l := f.make(op, s, 0, x, y)
				r := x
				if op == br.And {
					if x == zero || y == zero {
						r = zero
					} else if x == one {
						r = y
					}
				} else {
					if x == one || y == one {
						r = one
					} else if x == zero {
						r = y
					}
				}
				laws = append(laws, law{l, r})
			}
		}
	}
	laws = append(laws, law{f.make(br.And, s, 0, a, a), a}, law{f.make(br.Or, s, 0, a, a), a})
	for _, parts := range [][2]br.Term{{zero, b}, {one, b}, {b, zero}, {b, one}, {one, zero}, {zero, one}, {b, b}} {
		l := f.make(br.ITE, s, 0, a, parts[0], parts[1])
		var r br.Term
		switch {
		case parts[0] == parts[1]:
			r = parts[0]
		case parts[0] == one && parts[1] == zero:
			r = a
		case parts[0] == zero && parts[1] == one:
			r = not(a)
		case parts[0] == zero:
			r = f.make(br.And, s, 0, not(a), b)
		case parts[0] == one:
			r = f.make(br.Or, s, 0, a, b)
		case parts[1] == zero:
			r = f.make(br.And, s, 0, a, b)
		case parts[1] == one:
			r = f.make(br.Or, s, 0, not(a), b)
		}
		laws = append(laws, law{l, r})
	}
	for _, l := range laws {
		direct(t, br.BooleanLaw, l.l, l.r)
		prove(t, l.l, l.r)
		for av := uint64(0); av < 2; av++ {
			for bv := uint64(0); bv < 2; bv++ {
				assertValues(t, l.l, l.r, map[br.Term]uint64{a: av, b: bv})
			}
		}
	}
}

func TestPartialRegisterAndExplicitBooleanMapping(t *testing.T) {
	for w := 2; w <= 8; w++ {
		f := newFactory(t)
		scope := br.NewScope()
		lo := f.variable(br.Bits(w), scope, 0, false)
		hi := f.variable(br.Bits(w), scope, 0, true)
		full := f.make(br.Concat, br.Bits(2*w), 0, lo, hi)
		low := f.make(br.Trunc, br.Bits(w), 0, full)
		high := f.make(br.Extract, br.Bits(w), uint64(w), full)
		prove(t, lo, low)
		prove(t, hi, high)
		for v := 0; v < 1<<w; v++ {
			for _, scratch := range []uint64{0, widthMask(w), uint64(v)} {
				env := map[br.Term]uint64{lo: uint64(v), hi: scratch}
				assertValues(t, lo, low, env)
				assertValues(t, hi, high, env)
			}
		}
	}
	f := newFactory(t)
	scope := br.NewScope()
	lo := f.variable(br.Bits(32), scope, 0, false)
	hi := f.variable(br.Bits(32), scope, 0, true)
	reg := f.make(br.Concat, br.Bits(64), 0, lo, hi)
	prove(t, lo, f.make(br.Trunc, br.Bits(32), 0, reg))
	if _, err := br.Prove(context.Background(), reg, f.make(br.ZExt, br.Bits(64), 0, lo), br.Limits{}); err == nil {
		t.Fatal("arbitrary upper register bits became zero")
	}
	b := f.variable(br.Bool(), scope, 2, false)
	canonical := f.make(br.BoolToBits, br.Bits(8), 0, b)
	prove(t, b, f.make(br.Nonzero, br.Bool(), 0, canonical))
	byteVar := f.variable(br.Bits(8), scope, 3, false)
	round := f.make(br.BoolToBits, br.Bits(8), 0, f.make(br.Nonzero, br.Bool(), 0, byteVar))
	if _, err := br.Prove(context.Background(), byteVar, round, br.Limits{}); err == nil {
		t.Fatal("arbitrary byte became a canonical Boolean")
	}
	if reference(t, byteVar, map[br.Term]uint64{byteVar: 2}) == reference(t, round, map[br.Term]uint64{byteVar: 2}) {
		t.Fatal("control has no counterexample")
	}
	// Sign extension of a one-bit true is all ones, never canonical 1.
	onebit := f.make(br.BoolToBits, br.Bits(1), 0, b)
	sext := f.make(br.SExt, br.Bits(8), 0, onebit)
	refusal(t, sext, canonical, br.Proof{Steps: []br.Step{{Rule: br.Conversion, Left: sext, Right: canonical}}}, br.InvalidRule)
}

func TestAdditionalConversionRulesAllSmallValues(t *testing.T) {
	for w := 2; w <= 8; w++ {
		f := newFactory(t)
		scope := br.NewScope()
		x := f.variable(br.Bits(w), scope, 0, false)
		h := f.variable(br.Bits(w), scope, 1, true)
		full := f.make(br.Concat, br.Bits(2*w), 0, x, h)
		pairs := [][2]br.Term{
			{f.make(br.Trunc, br.Bits(w-1), 0, full), f.make(br.Trunc, br.Bits(w-1), 0, x)},
			{f.make(br.Trunc, br.Bits(w+1), 0, full), f.make(br.Concat, br.Bits(w+1), 0, x, f.make(br.Trunc, br.Bits(1), 0, h))},
			{f.make(br.Trunc, br.Bits(w-1), 0, f.make(br.Trunc, br.Bits(w), 0, full)), f.make(br.Trunc, br.Bits(w-1), 0, full)},
			{f.make(br.Extract, br.Bits(w-1), uint64(w+1), full), f.make(br.Extract, br.Bits(w-1), 1, h)},
		}
		for _, pair := range pairs {
			direct(t, br.Conversion, pair[0], pair[1])
			prove(t, pair[0], pair[1])
			for v := 0; v < 1<<w; v++ {
				for _, hv := range []uint64{0, widthMask(w), uint64(v)} {
					assertValues(t, pair[0], pair[1], map[br.Term]uint64{x: uint64(v), h: hv})
				}
			}
		}
	}
	f := newFactory(t)
	scope := br.NewScope()
	b := f.variable(br.Bool(), scope, 0, false)
	bit := f.variable(br.Bits(1), scope, 1, false)
	for _, w := range []int{1, 2, 8, 32, 64} {
		v := f.make(br.BoolToBits, br.Bits(w), 0, b)
		pairs := [][2]br.Term{{f.make(br.Nonzero, br.Bool(), 0, v), b}}
		if w > 1 {
			pairs = append(pairs, [2]br.Term{f.make(br.Trunc, br.Bits(1), 0, v), f.make(br.BoolToBits, br.Bits(1), 0, b)})
		}
		if w < 64 {
			pairs = append(pairs, [2]br.Term{f.make(br.ZExt, br.Bits(64), 0, v), f.make(br.BoolToBits, br.Bits(64), 0, b)})
			if w > 1 {
				pairs = append(pairs, [2]br.Term{f.make(br.SExt, br.Bits(64), 0, v), f.make(br.BoolToBits, br.Bits(64), 0, b)})
			}
		}
		round := f.make(br.BoolToBits, br.Bits(w), 0, f.make(br.Nonzero, br.Bool(), 0, bit))
		want := bit
		if w > 1 {
			want = f.make(br.ZExt, br.Bits(w), 0, bit)
		}
		pairs = append(pairs, [2]br.Term{round, want})
		for _, pair := range pairs {
			direct(t, br.Conversion, pair[0], pair[1])
			prove(t, pair[0], pair[1])
			for bv := uint64(0); bv < 2; bv++ {
				for v := uint64(0); v < 2; v++ {
					assertValues(t, pair[0], pair[1], map[br.Term]uint64{b: bv, bit: v})
				}
			}
		}
	}
}

func TestInclusiveLowerIntervalAndExactVariableInput(t *testing.T) {
	for w := 2; w <= 8; w++ {
		f := newFactory(t)
		x, left, right := interval(f, w, widthMask(w), 1, false)
		lv := left.View()
		lower := lv.Args[0].View().Args[0].View().Args[1]
		inclusive := f.make(br.And, br.Bool(), 0, f.make(br.SLE, br.Bool(), 0, lower, x), lv.Args[1])
		direct(t, br.SignedInterval, inclusive, right)
		prove(t, inclusive, right)
		for v := 0; v < 1<<w; v++ {
			assertValues(t, inclusive, right, map[br.Term]uint64{x: uint64(v)})
		}
	}
}

func TestComparisonBoundEverySmallValue(t *testing.T) {
	for w := 1; w <= 8; w++ {
		f := newFactory(t)
		s := br.Bits(w)
		x := f.variable(s, br.NewScope(), 0, false)
		for end := uint64(0); end <= widthMask(w); end++ {
			for _, op := range []br.Op{br.ULE, br.SLE} {
				l := f.make(op, br.Bool(), 0, x, f.con(s, end))
				maximum := widthMask(w)
				strict := br.ULT
				if op == br.SLE {
					maximum = (uint64(1) << (w - 1)) - 1
					strict = br.SLT
				}
				var r br.Term
				if end == maximum {
					r = f.con(br.Bool(), 1)
				} else {
					r = f.make(strict, br.Bool(), 0, x, f.con(s, (end+1)&widthMask(w)))
				}
				direct(t, br.ComparisonBound, l, r)
				prove(t, l, r)
				for v := uint64(0); v <= widthMask(w); v++ {
					assertValues(t, l, r, map[br.Term]uint64{x: v})
				}
			}
		}
		for _, op := range []br.Op{br.ULT, br.SLT} {
			minimum := uint64(0)
			if op == br.SLT {
				minimum = uint64(1) << (w - 1)
			}
			l := f.make(op, br.Bool(), 0, x, f.con(s, minimum))
			r := f.con(br.Bool(), 0)
			direct(t, br.ComparisonBound, l, r)
			for v := uint64(0); v <= widthMask(w); v++ {
				assertValues(t, l, r, map[br.Term]uint64{x: v})
			}
		}
	}
	for _, w := range []int{1, 32, 64} {
		f := newFactory(t)
		s := br.Bits(w)
		x := f.variable(s, br.NewScope(), 0, false)
		for _, op := range []br.Op{br.ULE, br.SLE} {
			maximum := widthMask(w)
			strict := br.ULT
			if op == br.SLE {
				maximum = (uint64(1) << (w - 1)) - 1
				strict = br.SLT
			}
			l := f.make(op, br.Bool(), 0, x, f.con(s, maximum))
			bad := f.make(strict, br.Bool(), 0, x, f.con(s, (maximum+1)&widthMask(w)))
			refusal(t, l, bad, br.Proof{Steps: []br.Step{{Rule: br.ComparisonBound, Left: l, Right: bad}}}, br.InvalidRule)
			prove(t, l, f.con(br.Bool(), 1))
		}
	}
	// Default-optimized native ranges commonly use an inclusive unsigned bound.
	f := newFactory(t)
	_, l, r := interval(f, 32, 0xd800, 0xe000, true)
	rv := r.View()
	native := f.make(br.ULE, br.Bool(), 0, rv.Args[0], f.con(br.Bits(32), 2047))
	prove(t, l, native)
}
