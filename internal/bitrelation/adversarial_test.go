package bitrelation_test

import (
	"context"
	"errors"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func TestTypingRefusesMalformedTerms(t *testing.T) {
	f := newFactory(t)
	s := br.Bits(8)
	x := f.variable(s, br.NewScope(), 0, false)
	b := f.con(br.Bool(), 1)
	for _, tc := range []struct {
		op   br.Op
		s    br.Sort
		imm  uint64
		args []br.Term
	}{
		{br.Constant, br.Bits(0), 0, nil}, {br.Constant, br.Bits(65), 0, nil}, {br.Constant, br.Bool(), 2, nil}, {br.Constant, s, 256, nil},
		{br.Variable, s, 0, nil}, {br.Op(255), s, 0, nil}, {br.Add, s, 1, []br.Term{x, x}}, {br.Add, s, 0, []br.Term{x, b}},
		{br.Not, s, 0, []br.Term{x}}, {br.ULT, s, 0, []br.Term{x, x}}, {br.SLT, br.Bool(), 0, []br.Term{b, b}},
		{br.Trunc, s, 0, []br.Term{x}}, {br.ZExt, s, 0, []br.Term{x}}, {br.SExt, br.Bool(), 0, []br.Term{x}},
		{br.ITE, s, 0, []br.Term{x, x, x}}, {br.Concat, br.Bits(8), 0, []br.Term{x, x}},
		{br.Extract, br.Bits(4), 5, []br.Term{x}}, {br.Extract, br.Bits(4), ^uint64(0), []br.Term{x}},
		{br.BoolToBits, s, 0, []br.Term{x}}, {br.Nonzero, br.Bool(), 0, []br.Term{b}}, {br.Add, s, 0, []br.Term{x, {}}},
	} {
		v, err := f.b.Make(tc.op, tc.s, tc.imm, tc.args...)
		if err == nil || v.Valid() {
			t.Fatalf("accepted malformed op=%v sort=%v", tc.op, tc.s)
		}
	}
	if v, err := f.b.Input(s, br.Scope{}, 0); err == nil || v.Valid() {
		t.Fatal("zero namespace")
	}
	var zero br.Builder
	if v, err := zero.Const(s, 0); err == nil || v.Valid() {
		t.Fatal("zero builder")
	}
}

func TestCertificateEndpointsScopesAndInferenceTampering(t *testing.T) {
	f := newFactory(t)
	x, l, r := interval(f, 32, 0xd800, 0xe000, true)
	p := prove(t, l, r)
	y := f.variable(x.Sort(), br.NewScope(), 0, false)
	scratch := f.variable(x.Sort(), x.View().Scope, x.View().Immediate, true)
	for _, other := range []br.Term{y, scratch} {
		refusal(t, x, other, br.Proof{Steps: []br.Step{{Rule: br.Reflexivity, Left: x, Right: other}}}, br.InvalidRule)
	}
	refusal(t, r, l, p, br.Endpoint)
	refusal(t, l, f.con(br.Bool(), 1), p, br.Endpoint)
	refusal(t, l, r, br.Proof{Steps: []br.Step{{Rule: br.Reflexivity, Left: l, Right: l}}}, br.Endpoint)
	clone := func() br.Proof {
		q := br.Proof{Steps: append([]br.Step(nil), p.Steps...)}
		for i := range q.Steps {
			q.Steps[i].Premises = append([]int(nil), q.Steps[i].Premises...)
		}
		return q
	}
	for i := range p.Steps {
		q := clone()
		q.Steps[i].Rule = br.Rule(255)
		refusal(t, l, r, q, br.InvalidRule)
		q = clone()
		q.Steps[i].Premises = []int{i}
		refusal(t, l, r, q, br.InvalidRule)
		q = clone()
		q.Steps[i].Right = f.con(q.Steps[i].Right.Sort(), 1)
		w, err := br.Check(context.Background(), l, r, q, br.Limits{})
		if err == nil || w.Valid() {
			t.Fatalf("forged intermediate %d accepted", i)
		}
	}
	// The checker must not accept equality just because the producer can reduce
	// some different endpoints or because a chain contains a valid final pair.
	q := clone()
	q.Steps[0].Left = y
	q.Steps[0].Right = y
	if w, err := br.Check(context.Background(), l, r, q, br.Limits{}); err == nil || w.Valid() {
		t.Fatal("substituted variable premise accepted")
	}
	last := p.Steps[len(p.Steps)-1]
	last.Premises = []int{-1, 0}
	refusal(t, l, r, br.Proof{Steps: []br.Step{last}}, br.InvalidRule)
	refusal(t, l, r, br.Proof{}, br.Malformed)
}

type callbackContext struct {
	context.Context
	callback func()
	calls    int
	cancelAt int
}

func TestEvalRejectsAssignmentBudgetBeforeSnapshotAndCallbacks(t *testing.T) {
	f := newFactory(t)
	x := f.variable(br.Bits(8), br.NewScope(), 0, false)
	assignments := make([]br.Assignment, 64)
	ctx := &callbackContext{Context: context.Background(), callback: func() { t.Fatal("oversized input invoked context before refusal") }}
	_, err := br.Eval(ctx, x, assignments, br.Limits{Nodes: 1})
	var r *br.Refusal
	if !errors.As(err, &r) || r.Code != br.Budget || r.Detail != "assignment budget" || ctx.calls != 0 {
		t.Fatalf("budget refusal: %v, callbacks=%d", err, ctx.calls)
	}
	// The refusal itself allocates once. Copying even this small rejected slice
	// adds another allocation; no size-dependent snapshot may precede rejection.
	allocs := testing.AllocsPerRun(20, func() {
		_, err = br.Eval(context.Background(), x, assignments, br.Limits{Nodes: 1})
	})
	if allocs > 1 {
		t.Fatalf("oversized assignments allocated a snapshot: %g allocations", allocs)
	}
	for _, limits := range []br.Limits{{Nodes: -1}, {Steps: -1}, {Work: -1}} {
		_, err = br.Eval(ctx, x, assignments, limits)
		if !errors.As(err, &r) || r.Code != br.Malformed || ctx.calls != 0 {
			t.Fatalf("invalid limits: %v", err)
		}
	}
}

func (c *callbackContext) Err() error {
	c.calls++
	if c.callback != nil {
		f := c.callback
		c.callback = nil
		f()
	}
	if c.cancelAt > 0 && c.calls >= c.cancelAt {
		return context.Canceled
	}
	return nil
}

func TestImmutableOwnershipSurvivesContextCallbacks(t *testing.T) {
	f := newFactory(t)
	x, l, r := interval(f, 32, 0xd800, 0xe000, true)
	p := prove(t, l, r)
	before := l.Digest()
	projection := l.View()
	projection.Args[0] = f.con(br.Bool(), 1)
	projection.Immediate = 99
	projection.Op = br.Constant
	ctx := &callbackContext{Context: context.Background(), callback: func() {
		*f.b = *br.NewBuilder(1)
		for i := range p.Steps {
			for j := range p.Steps[i].Premises {
				p.Steps[i].Premises[j] = -1
			}
			p.Steps[i].Rule = br.Rule(255)
			p.Steps[i].Left = br.Term{}
		}
		p.Steps = nil
	}}
	w, err := br.Check(ctx, l, r, p, br.Limits{})
	if err != nil || !w.Valid() {
		t.Fatalf("owned snapshot was changed by callback: %v", err)
	}
	if l.Digest() != before {
		t.Fatal("term changed")
	}
	wl, wr := w.Roots()
	if wl != l || wr != r || w.Dependencies() == [32]byte{} {
		t.Fatal("lost independently bound roots")
	}
	assign := []br.Assignment{{Variable: x, Value: 0xd800}}
	ctx = &callbackContext{Context: context.Background(), callback: func() { assign[0].Value = 0 }}
	got, err := br.Eval(ctx, l, assign, br.Limits{})
	if err != nil || got != 1 {
		t.Fatalf("evaluation borrowed assignments: %d %v", got, err)
	}
	// Replacing a public builder while proposing cannot redirect old nodes.
	ctx = &callbackContext{Context: context.Background(), callback: func() { *f.b = *br.NewBuilder(1) }}
	w, err = br.Prove(ctx, l, r, br.Limits{})
	if err != nil || !w.Valid() {
		t.Fatal(err)
	}
}

func TestDependencyIdentityAndExplicitMapping(t *testing.T) {
	f, g := newFactory(t), newFactory(t)
	scope := br.NewScope()
	x := f.variable(br.Bits(32), scope, 4, false)
	same := g.variable(br.Bits(32), scope, 4, false)
	w := direct(t, br.Reflexivity, x, same)
	if x.Digest() != same.Digest() {
		t.Fatal("same explicit variable mapping has different identity")
	}
	y := f.variable(br.Bits(32), br.NewScope(), 4, false)
	v := direct(t, br.Reflexivity, y, y)
	if w.Dependencies() == v.Dependencies() {
		t.Fatal("variable scope omitted from dependency identity")
	}
	for _, other := range []br.Term{f.variable(br.Bits(32), scope, 5, false), f.variable(br.Bits(32), scope, 4, true), f.variable(br.Bits(64), scope, 4, false)} {
		if x.Digest() == other.Digest() {
			t.Fatal("typed variable identity collapsed")
		}
	}
	a := f.make(br.Add, x.Sort(), 0, x, f.con(x.Sort(), 0))
	b := f.make(br.BitXor, x.Sort(), 0, x, f.con(x.Sort(), 0))
	w1 := direct(t, br.Algebra, a, x)
	w2 := direct(t, br.Algebra, b, x)
	if w1.Dependencies() == w2.Dependencies() {
		t.Fatal("actual root graph omitted from dependency identity")
	}
	if (br.Witness{}).Valid() || (br.Witness{}).Dependencies() != [32]byte{} {
		t.Fatal("zero witness")
	}
}

func TestCancellationAndBudgetsNeverReturnPartialEvidence(t *testing.T) {
	f := newFactory(t)
	_, l, r := interval(f, 64, 1<<63, (1<<63)-1, true)
	p := prove(t, l, r)
	for _, at := range []int{1, 2, 10, 40} {
		ctx := &callbackContext{Context: context.Background(), cancelAt: at}
		w, err := br.Check(ctx, l, r, p, br.Limits{})
		if w.Valid() || !errors.Is(err, context.Canceled) {
			t.Fatalf("check cancel at %d: %v", at, err)
		}
		ctx = &callbackContext{Context: context.Background(), cancelAt: at}
		q, err := br.Propose(ctx, l, r, br.Limits{})
		if len(q.Steps) != 0 || !errors.Is(err, context.Canceled) {
			t.Fatalf("propose cancel at %d: %v", at, err)
		}
	}
	for _, limits := range []br.Limits{{Nodes: 1}, {Steps: 1}, {Work: 1}, {Nodes: -1}, {Steps: -1}, {Work: -1}} {
		w, err := br.Check(context.Background(), l, r, p, limits)
		if w.Valid() || err == nil {
			t.Fatalf("check ignored %+v", limits)
		}
		q, err := br.Propose(context.Background(), l, r, limits)
		if len(q.Steps) != 0 || err == nil {
			t.Fatalf("proposal ignored %+v", limits)
		}
	}
	b := br.NewBuilder(1)
	if _, err := b.Const(br.Bits(8), 0); err != nil {
		t.Fatal(err)
	}
	if v, err := b.Const(br.Bits(8), 1); err == nil || v.Valid() {
		t.Fatal("unbounded arena")
	}
	x := f.variable(br.Bool(), br.NewScope(), 0, false)
	for i := 0; i < 513; i++ {
		x = f.make(br.Not, br.Bool(), 0, x)
	}
	w, err := br.Check(context.Background(), x, x, br.Proof{Steps: []br.Step{{Rule: br.Reflexivity, Left: x, Right: x}}}, br.Limits{Nodes: 2000})
	if err == nil || w.Valid() {
		t.Fatal("unbounded expression depth")
	}
}

func TestIntervalWrongSideConditionsRefuse(t *testing.T) {
	f := newFactory(t)
	x, l, r := interval(f, 8, 0x80, 0x7f, false)
	rv := r.View()
	badDelta := f.make(br.ULT, br.Bool(), 0, rv.Args[0], f.con(br.Bits(8), 254))
	badOffset := f.make(br.ULT, br.Bool(), 0, f.make(br.Sub, br.Bits(8), 0, x, f.con(br.Bits(8), 0x81)), rv.Args[1])
	badSign := f.make(br.SLT, br.Bool(), 0, rv.Args[0], rv.Args[1])
	for _, bad := range []br.Term{badDelta, badOffset, badSign} {
		refusal(t, l, bad, br.Proof{Steps: []br.Step{{Rule: br.SignedInterval, Left: l, Right: bad}}}, br.InvalidRule)
	}
	lv := l.View()
	upper := lv.Args[1].View()
	unsigned := f.make(br.ULT, br.Bool(), 0, upper.Args...)
	badLeft := f.make(br.And, br.Bool(), 0, lv.Args[0], unsigned)
	refusal(t, badLeft, r, br.Proof{Steps: []br.Step{{Rule: br.SignedInterval, Left: badLeft, Right: r}}}, br.InvalidRule)
	// A syntactically similar empty/wrapping signed interval is not this rule.
	_, empty, wrap := interval(f, 8, 127, 128, false)
	refusal(t, empty, wrap, br.Proof{Steps: []br.Step{{Rule: br.SignedInterval, Left: empty, Right: wrap}}}, br.InvalidRule)
}

func TestLocalRuleAdversarialCrossProduct(t *testing.T) {
	f := newFactory(t)
	s := br.Bits(2)
	scope := br.NewScope()
	x, y := f.variable(s, scope, 0, false), f.variable(s, scope, 1, false)
	terms := []br.Term{x, y, f.con(s, 0), f.con(s, 1), f.con(s, 3)}
	for _, op := range []br.Op{br.Add, br.Sub, br.BitAnd, br.BitOr, br.BitXor, br.Equal, br.SLT, br.ULT} {
		terms = append(terms, f.make(op, func() br.Sort {
			if op == br.Equal || op == br.SLT || op == br.ULT {
				return br.Bool()
			}
			return s
		}(), 0, x, y))
	}
	terms = append(terms, f.con(br.Bool(), 0), f.con(br.Bool(), 1), f.make(br.Not, br.Bool(), 0, f.make(br.SLT, br.Bool(), 0, x, y)))
	for _, a := range terms {
		for _, b := range terms {
			if a.Sort() != b.Sort() {
				continue
			}
			for rule := br.ConstantFold; rule <= br.SignBoundary; rule++ {
				w, err := br.Check(context.Background(), a, b, br.Proof{Steps: []br.Step{{Rule: rule, Left: a, Right: b}}}, br.Limits{})
				if err != nil {
					if w.Valid() {
						t.Fatal("partial witness")
					}
					continue
				}
				for xv := uint64(0); xv < 4; xv++ {
					for yv := uint64(0); yv < 4; yv++ {
						assertValues(t, a, b, map[br.Term]uint64{x: xv, y: yv})
					}
				}
			}
		}
	}
}
