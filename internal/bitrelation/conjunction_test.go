package bitrelation_test

import (
	"context"
	"errors"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func TestConjunctionContradictionEveryValuation(t *testing.T) {
	f, other := newFactory(t), newFactory(t)
	scope := br.NewScope()
	a, b, c := f.variable(br.Bool(), scope, 0, false), f.variable(br.Bool(), scope, 1, false), f.variable(br.Bool(), scope, 2, true)
	bCopy := other.variable(br.Bool(), scope, 1, false)
	not := func(x br.Term) br.Term { return f.make(br.Not, br.Bool(), 0, x) }
	and := func(x, y br.Term) br.Term { return f.make(br.And, br.Bool(), 0, x, y) }
	falsehood := f.con(br.Bool(), 0)
	for _, root := range []br.Term{and(and(a, b), and(c, not(bCopy))), and(and(not(bCopy), c), and(b, a)), and(b, and(a, and(not(bCopy), c)))} {
		direct(t, br.ConjunctionContradiction, root, falsehood)
		prove(t, root, falsehood)
		for v := uint64(0); v < 8; v++ {
			if reference(t, root, map[br.Term]uint64{a: v & 1, b: (v >> 1) & 1, bCopy: (v >> 1) & 1, c: (v >> 2) & 1}) != 0 {
				t.Fatal("nested conjunction disagrees with Boolean semantics")
			}
			// The two arenas carry one logical b variable, so Eval receives only
			// one assignment for its shared scope/slot identity.
			got, err := br.Eval(t.Context(), root, []br.Assignment{{Variable: a, Value: v & 1}, {Variable: b, Value: (v >> 1) & 1}, {Variable: c, Value: (v >> 2) & 1}}, br.Limits{})
			if err != nil || got != 0 {
				t.Fatalf("nested conjunction eval=%d: %v", got, err)
			}
		}
	}
	// Guarded unsigned order is the entry-condition use case. A bit boundary
	// or a signed comparison must not silently replace the original ordering.
	x, y := f.variable(br.Bits(64), scope, 3, false), f.variable(br.Bits(64), scope, 4, false)
	root := and(and(a, f.make(br.ULT, br.Bool(), 0, x, y)), f.make(br.ULE, br.Bool(), 0, y, x))
	prove(t, root, falsehood)
	for _, values := range [][2]uint64{{0, 0}, {0, 1}, {1, 0}, {1 << 63, 0}, {0, ^uint64(0)}, {^uint64(0), 1 << 63}} {
		for av := uint64(0); av < 2; av++ {
			assertValues(t, root, falsehood, map[br.Term]uint64{a: av, x: values[0], y: values[1]})
		}
	}
}

func TestConjunctionContradictionRetainsScopeAndBooleanStructure(t *testing.T) {
	f := newFactory(t)
	scope := br.NewScope()
	a, b, c := f.variable(br.Bool(), scope, 0, false), f.variable(br.Bool(), scope, 1, false), f.variable(br.Bool(), scope, 2, false)
	not := func(x br.Term) br.Term { return f.make(br.Not, br.Bool(), 0, x) }
	and := func(x, y br.Term) br.Term { return f.make(br.And, br.Bool(), 0, x, y) }
	falsity := f.con(br.Bool(), 0)
	for _, other := range []br.Term{c, f.variable(br.Bool(), br.NewScope(), 1, false), f.variable(br.Bool(), scope, 1, true)} {
		root := and(and(a, b), not(other))
		refusal(t, root, falsity, br.Proof{Steps: []br.Step{{Rule: br.ConjunctionContradiction, Left: root, Right: falsity}}}, br.InvalidRule)
		if reference(t, root, map[br.Term]uint64{a: 1, b: 1, other: 0}) != 1 {
			t.Fatal("scope control has no counterexample")
		}
		if w, err := br.Prove(t.Context(), root, falsity, br.Limits{}); err == nil || w.Valid() {
			t.Fatal("proved an unconstrained conjunct false")
		}
	}
	for _, root := range []br.Term{
		and(f.make(br.Or, br.Bool(), 0, a, b), not(a)),
		and(not(and(a, b)), a),
		and(f.make(br.ITE, br.Bool(), 0, c, a, b), not(a)),
	} {
		refusal(t, root, falsity, br.Proof{Steps: []br.Step{{Rule: br.ConjunctionContradiction, Left: root, Right: falsity}}}, br.InvalidRule)
		counterexample := false
		for v := uint64(0); v < 8; v++ {
			counterexample = counterexample || reference(t, root, map[br.Term]uint64{a: v & 1, b: (v >> 1) & 1, c: (v >> 2) & 1}) != 0
		}
		if !counterexample {
			t.Fatal("Boolean structure control has no counterexample")
		}
	}
	root := and(and(a, b), not(b))
	refusal(t, root, f.con(br.Bool(), 1), br.Proof{Steps: []br.Step{{Rule: br.ConjunctionContradiction, Left: root, Right: f.con(br.Bool(), 1)}}}, br.InvalidRule)
	refusal(t, root, falsity, br.Proof{Steps: []br.Step{{Rule: br.Reflexivity, Left: a, Right: a}, {Rule: br.ConjunctionContradiction, Left: root, Right: falsity, Premises: []int{0}}}}, br.InvalidRule)
}

func TestConjunctionContradictionBoundsAndCancellation(t *testing.T) {
	f := newFactory(t)
	scope := br.NewScope()
	a := f.variable(br.Bool(), scope, 0, false)
	root := a
	for i := uint64(1); i < 32; i++ {
		root = f.make(br.And, br.Bool(), 0, root, f.variable(br.Bool(), scope, i, false))
	}
	root = f.make(br.And, br.Bool(), 0, root, f.make(br.Not, br.Bool(), 0, a))
	falsity := f.con(br.Bool(), 0)
	b := f.variable(br.Bool(), scope, 33, false)
	_, stepErr := br.Propose(t.Context(), f.make(br.And, br.Bool(), 0, a, b), a, br.Limits{Steps: 2})
	var stepRefusal *br.Refusal
	if !errors.As(stepErr, &stepRefusal) || stepRefusal.Code != br.Budget {
		t.Fatalf("exhausted Congruence budget changed category: %v", stepErr)
	}
	proposal := br.Proof{Steps: []br.Step{{Rule: br.ConjunctionContradiction, Left: root, Right: falsity}}}
	direct(t, br.ConjunctionContradiction, root, falsity)
	prove(t, root, falsity)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{cancelled, t.Context()} {
		limits := br.Limits{}
		if ctx != cancelled {
			limits.Work = 1
		}
		w, err := br.Check(ctx, root, falsity, proposal, limits)
		if err == nil || w.Valid() {
			t.Fatal("unchecked conjunction proof escaped cancellation/budget")
		}
		if ctx == cancelled && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if p, err := br.Propose(ctx, root, falsity, limits); err == nil || len(p.Steps) != 0 {
			t.Fatal("partial conjunction proposal escaped refusal")
		}
	}
}
