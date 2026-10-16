package bitrelation_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func TestBooleanComplementEveryValuation(t *testing.T) {
	f, copy := newFactory(t), newFactory(t)
	scope := br.NewScope()
	a := f.variable(br.Bool(), scope, 0, false)
	b := f.variable(br.Bool(), scope, 1, false)
	scratch := f.variable(br.Bool(), scope, 0, true)
	not := func(x br.Term) br.Term { return f.make(br.Not, br.Bool(), 0, x) }
	// Equal syntax in a different arena exercises structural comparison rather
	// than pointer identity, including a compound predicate and scratch state.
	aCopy := copy.variable(br.Bool(), scope, 0, false)
	bCopy := copy.variable(br.Bool(), scope, 1, false)
	scratchCopy := copy.variable(br.Bool(), scope, 0, true)
	for _, pair := range [][2]br.Term{
		{a, aCopy}, {scratch, scratchCopy},
		{f.make(br.And, br.Bool(), 0, a, b), copy.make(br.And, br.Bool(), 0, aCopy, bCopy)},
	} {
		for _, op := range []br.Op{br.And, br.Or} {
			value := uint64(0)
			if op == br.Or {
				value = 1
			}
			right := f.con(br.Bool(), value)
			for _, args := range [][2]br.Term{{pair[0], not(pair[1])}, {not(pair[1]), pair[0]}} {
				left := f.make(op, br.Bool(), 0, args[:]...)
				direct(t, br.BooleanLaw, left, right)
				prove(t, left, right)
				for av := uint64(0); av < 2; av++ {
					for bv := uint64(0); bv < 2; bv++ {
						for sv := uint64(0); sv < 2; sv++ {
							env := map[br.Term]uint64{a: av, aCopy: av, b: bv, bCopy: bv, scratch: sv, scratchCopy: sv}
							if reference(t, left, env) != value || reference(t, right, env) != value {
								t.Fatal("complement law disagrees with Boolean semantics")
							}
							got, err := br.Eval(t.Context(), left, []br.Assignment{{Variable: a, Value: av}, {Variable: b, Value: bv}, {Variable: scratch, Value: sv}}, br.Limits{})
							if err != nil || got != value {
								t.Fatalf("eval=%d err=%v want=%d", got, err, value)
							}
						}
					}
				}
			}
		}
	}
}

func TestBooleanComplementRejectsUnequalOperands(t *testing.T) {
	f := newFactory(t)
	scope := br.NewScope()
	a := f.variable(br.Bool(), scope, 0, false)
	for name, other := range map[string]br.Term{
		"slot":    f.variable(br.Bool(), scope, 1, false),
		"scope":   f.variable(br.Bool(), br.NewScope(), 0, false),
		"scratch": f.variable(br.Bool(), scope, 0, true),
	} {
		t.Run(name, func(t *testing.T) {
			for _, op := range []br.Op{br.And, br.Or} {
				value := uint64(0)
				if op == br.Or {
					value = 1
				}
				right := f.con(br.Bool(), value)
				neg := f.make(br.Not, br.Bool(), 0, other)
				for _, args := range [][2]br.Term{{a, neg}, {neg, a}} {
					left := f.make(op, br.Bool(), 0, args[:]...)
					refusal(t, left, right, br.Proof{Steps: []br.Step{{Rule: br.BooleanLaw, Left: left, Right: right}}}, br.InvalidRule)
					if w, err := br.Prove(t.Context(), left, right, br.Limits{}); err == nil || w.Valid() {
						t.Fatal("proved unequal operands complementary")
					}
					// Enumerate all assignments and retain a concrete counterexample.
					counterexample := false
					for av := uint64(0); av < 2; av++ {
						for ov := uint64(0); ov < 2; ov++ {
							if reference(t, left, map[br.Term]uint64{a: av, other: ov}) != value {
								counterexample = true
							}
						}
					}
					if !counterexample {
						t.Fatal("negative fixture lacks counterexample")
					}
				}
			}
		})
	}
}

func TestBooleanComplementRejectsMalformedClaims(t *testing.T) {
	f := newFactory(t)
	a := f.variable(br.Bool(), br.NewScope(), 0, false)
	neg := f.make(br.Not, br.Bool(), 0, a)
	for _, op := range []br.Op{br.And, br.Or} {
		value := uint64(0)
		if op == br.Or {
			value = 1
		}
		left, right := f.make(op, br.Bool(), 0, a, neg), f.con(br.Bool(), value)
		for _, wrong := range []br.Term{f.con(br.Bool(), 1-value), a, f.con(br.Bits(1), value)} {
			refusal(t, left, wrong, br.Proof{Steps: []br.Step{{Rule: br.BooleanLaw, Left: left, Right: wrong}}}, br.InvalidRule)
		}
		refusal(t, left, right, br.Proof{Steps: []br.Step{
			{Rule: br.Reflexivity, Left: a, Right: a},
			{Rule: br.BooleanLaw, Left: left, Right: right, Premises: []int{0}},
		}}, br.InvalidRule)
	}
	for _, op := range []br.Op{br.BitAnd, br.BitOr, br.BitXor} {
		x := f.variable(br.Bits(1), br.NewScope(), 0, false)
		left := f.make(op, br.Bits(1), 0, x, f.make(br.BitNot, br.Bits(1), 0, x))
		for v := uint64(0); v < 2; v++ {
			right := f.con(br.Bits(1), v)
			refusal(t, left, right, br.Proof{Steps: []br.Step{{Rule: br.BooleanLaw, Left: left, Right: right}}}, br.InvalidRule)
		}
	}
	left, right := f.make(br.Equal, br.Bool(), 0, a, neg), f.con(br.Bool(), 1)
	refusal(t, left, right, br.Proof{Steps: []br.Step{{Rule: br.BooleanLaw, Left: left, Right: right}}}, br.InvalidRule)
}

func TestBooleanComplementSourcePathAndLimits(t *testing.T) {
	f := newFactory(t)
	b := f.variable(br.Bool(), br.NewScope(), 0, false)
	truth, falsity := f.con(br.Bool(), 1), f.con(br.Bool(), 0)
	// Source branch transfer conjoins the incoming path with each condition:
	// entering b then !b produces And(And(true,b),Not(b)).
	path := f.make(br.And, br.Bool(), 0, f.make(br.And, br.Bool(), 0, truth, b), f.make(br.Not, br.Bool(), 0, b))
	proof := prove(t, path, falsity)
	w := check(t, path, falsity, proof)
	left, right := w.Roots()
	if left != path || right != falsity {
		t.Fatal("witness did not retain owned endpoints")
	}
	for v := uint64(0); v < 2; v++ {
		assertValues(t, path, falsity, map[br.Term]uint64{b: v})
	}
	refusal(t, path, truth, proof, br.Endpoint)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		ctx    context.Context
		limits br.Limits
		code   br.Code
	}{
		{cancelled, br.Limits{}, br.Cancelled},
		{t.Context(), br.Limits{Nodes: 1}, br.Budget},
		{t.Context(), br.Limits{Steps: 1}, br.Budget},
		{t.Context(), br.Limits{Work: 1}, br.Budget},
	} {
		t.Run(fmt.Sprint(tc.code, tc.limits), func(t *testing.T) {
			for _, run := range []func() (br.Witness, error){
				func() (br.Witness, error) { return br.Check(tc.ctx, path, falsity, proof, tc.limits) },
				func() (br.Witness, error) { return br.Prove(tc.ctx, path, falsity, tc.limits) },
			} {
				w, err := run()
				var re *br.Refusal
				if w.Valid() || !errors.As(err, &re) || re.Code != tc.code {
					t.Fatalf("want %s without witness; witness=%v err=%v", tc.code, w.Valid(), err)
				}
			}
		})
	}
}
