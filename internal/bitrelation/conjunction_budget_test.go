package bitrelation

import (
	"context"
	"errors"
	"testing"
)

// These controls enter the rule/search directly with builder-validated terms.
// Public API graph validation must not consume the budget before the new walk.
func conjunctionBudgetTerms(t *testing.T, count int, repeated, negatives bool) (Term, Term) {
	t.Helper()
	b := NewBuilder(4*count + 16)
	scope := NewScope()
	a, err := b.Input(Bool(), scope, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := a
	for i := 1; i < count; i++ {
		next := a
		if !repeated {
			next, err = b.Input(Bool(), scope, uint64(i))
			if err != nil {
				t.Fatal(err)
			}
		}
		if negatives && i >= count/2 {
			next, err = b.Make(Not, Bool(), 0, next)
			if err != nil {
				t.Fatal(err)
			}
		}
		root, err = b.Make(And, Bool(), 0, root, next)
		if err != nil {
			t.Fatal(err)
		}
	}
	zero, err := b.Make(Constant, Bool(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return root, zero
}

func requireConjunctionBudget(t *testing.T, err error) {
	t.Helper()
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Code != Budget {
		t.Fatalf("new conjunction machinery did not retain a budget refusal: %v", err)
	}
}

func TestConjunctionRuleTraversalAndComparisonBudgets(t *testing.T) {
	const count = 32
	for _, repeated := range []bool{true, false} {
		root, zero := conjunctionBudgetTerms(t, count, repeated, false)
		work := count / 2
		if !repeated {
			work = 4 * count
		}
		m, err := newMeter(t.Context(), Limits{Work: work})
		if err != nil {
			t.Fatal(err)
		}
		c := checker{e: equality{m: m, seen: map[pair]bool{}}}
		if c.conjunctionContradiction(root.n, zero.n) {
			t.Fatal("satisfiable conjunction accepted as false")
		}
		requireConjunctionBudget(t, c.err)
	}
}

type conjunctionCancellation struct {
	context.Context
	remaining int
}

func (c *conjunctionCancellation) Err() error {
	c.remaining--
	if c.remaining < 0 {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestConjunctionSearchTraversalComparisonAndCancellation(t *testing.T) {
	const count = 32
	for _, comparisons := range []bool{false, true} {
		root, _ := conjunctionBudgetTerms(t, count, !comparisons, comparisons)
		work := count / 2
		if comparisons {
			work = 4 * count
		}
		for _, cancel := range []bool{false, true} {
			ctx := context.Context(t.Context())
			limits := Limits{Work: work}
			if cancel {
				ctx = &conjunctionCancellation{Context: ctx, remaining: work}
				limits = Limits{}
			}
			m, err := newMeter(ctx, limits)
			if err != nil {
				t.Fatal(err)
			}
			p := proposer{m: m, b: NewBuilder(1000), e: equality{m: m, seen: map[pair]bool{}}}
			if _, _, ok := p.controlRewrite(root); ok {
				t.Fatal("satisfiable conjunction received a contradiction proposal")
			}
			if cancel {
				if !errors.Is(p.err, context.Canceled) {
					t.Fatalf("new search ignored cancellation: %v", p.err)
				}
			} else {
				requireConjunctionBudget(t, p.err)
			}
		}
	}
}
