package bitrelation_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

// A common native cut joins selector-chosen starts, then increments the same
// counter on each traversal. The selectors are arbitrary independent Booleans;
// no sampled selector, normal completion or restricted input is a premise.
func TestConditionalOperationJoinedCounterFrontier(t *testing.T) {
	frontier, zero := conditionalJoinedCounter(t)
	prove(t, frontier, zero)
}

func conditionalJoinedCounter(t testing.TB) (br.Term, br.Term) {
	f := newFactory(t)
	s := br.Bits(64)
	scope := br.NewScope()
	counter := f.con(s, 3)
	for value := 2; value >= 0; value-- {
		condition := f.variable(br.Bool(), scope, uint64(value), false)
		counter = f.make(br.ITE, s, 0, condition, f.con(s, uint64(value)), counter)
	}
	for range 3 {
		counter = f.make(br.Add, s, 0, counter, f.con(s, 1))
	}
	frontier := f.make(br.ULT, br.Bool(), 0, counter, f.con(s, 3))
	return frontier, f.con(br.Bool(), 0)
}

var conditionalOperations = []br.Op{br.Add, br.Sub, br.Equal, br.ULT, br.ULE, br.SLT, br.SLE}

func TestConditionalOperationRetainsOneOperandNormalForm(t *testing.T) {
	for _, op := range conditionalOperations {
		f := newFactory(t)
		s := br.Bits(32)
		p := f.variable(br.Bool(), br.NewScope(), 0, false)
		a, b, c, d := f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, false)
		fixed := f.make(br.ITE, s, 0, p, c, d)
		left, right := conditionalOperationTerms(f, op, 0, p, a, b, fixed)
		// The existing arithmetic/order search joins this one-operand lifting
		// form even when the fixed operand has a correlated conditional.
		prove(t, left, right)
	}
}

func conditionalOperationTerms(f factory, op br.Op, position int, p, a, b, fixed br.Term) (br.Term, br.Term) {
	s := a.Sort()
	out := s
	if op != br.Add && op != br.Sub {
		out = br.Bool()
	}
	args := [2]br.Term{fixed, fixed}
	args[position] = f.make(br.ITE, s, 0, p, a, b)
	left := f.make(op, out, 0, args[:]...)
	args[position] = a
	yes := f.make(op, out, 0, args[:]...)
	args[position] = b
	no := f.make(op, out, 0, args[:]...)
	return left, f.make(br.ITE, out, 0, p, yes, no)
}

func TestConditionalOperationEverySmallValuation(t *testing.T) {
	// Exhaustive joint valuations at widths 1..3, both condition values and
	// operand positions. In particular subtraction/order are not commutative.
	for width := 1; width <= 3; width++ {
		for _, op := range conditionalOperations {
			for position := 0; position < 2; position++ {
				f := newFactory(t)
				s := br.Bits(width)
				p := f.variable(br.Bool(), br.NewScope(), 0, false)
				a, b, c := f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, false)
				left, right := conditionalOperationTerms(f, op, position, p, a, b, c)
				direct(t, br.ConditionalOperation, left, right)
				if _, err := br.Prove(t.Context(), left, right, br.Limits{}); err != nil {
					t.Fatalf("width %d op %d position %d: %v", width, op, position, err)
				}
				for pv := uint64(0); pv < 2; pv++ {
					for av := uint64(0); av <= widthMask(width); av++ {
						for bv := uint64(0); bv <= widthMask(width); bv++ {
							for cv := uint64(0); cv <= widthMask(width); cv++ {
								assertValues(t, left, right, map[br.Term]uint64{p: pv, a: av, b: bv, c: cv})
							}
						}
					}
				}
			}
		}
	}
}

func TestConditionalOperationWideBoundaries(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x3349c0, 0x41fe72))
	for _, width := range []int{32, 64} {
		for _, op := range conditionalOperations {
			for position := 0; position < 2; position++ {
				f := newFactory(t)
				s := br.Bits(width)
				p := f.variable(br.Bool(), br.NewScope(), 0, false)
				a, b, c := f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, true)
				left, right := conditionalOperationTerms(f, op, position, p, a, b, c)
				direct(t, br.ConditionalOperation, left, right)
				if _, err := br.Prove(t.Context(), left, right, br.Limits{}); err != nil {
					t.Fatalf("width %d op %d position %d: %v", width, op, position, err)
				}
				half := uint64(1) << (width - 1)
				edges := []uint64{0, 1, 2, half - 1, half, half + 1, widthMask(width) - 1, widthMask(width)}
				check := func(av, bv, cv uint64) {
					for pv := uint64(0); pv < 2; pv++ {
						assertValues(t, left, right, map[br.Term]uint64{p: pv, a: av, b: bv, c: cv})
					}
				}
				for _, av := range edges {
					for _, bv := range edges {
						for _, cv := range edges {
							check(av, bv, cv)
						}
					}
				}
				// Finite reproducible wide sampling supplements the exhaustive small
				// product; these draws are not premises or an exhaustive wide claim.
				for range 128 {
					check(rng.Uint64()&widthMask(width), rng.Uint64()&widthMask(width), rng.Uint64()&widthMask(width))
				}
			}
		}
	}
}

func TestConditionalOperationRejectsMalformedInference(t *testing.T) {
	f := newFactory(t)
	s := br.Bits(32)
	p := f.variable(br.Bool(), br.NewScope(), 0, false)
	otherP := f.variable(br.Bool(), br.NewScope(), 0, false)
	a, b, c, stale := f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, false)
	for _, op := range conditionalOperations {
		for position := 0; position < 2; position++ {
			left, right := conditionalOperationTerms(f, op, position, p, a, b, c)
			direct(t, br.ConditionalOperation, left, right)
			out := right.Sort()
			v := right.View()
			_, wrongCondition := conditionalOperationTerms(f, op, position, otherP, a, b, c)
			_, staleOperand := conditionalOperationTerms(f, op, position, p, a, b, stale)
			_, wrongPosition := conditionalOperationTerms(f, op, 1-position, p, a, b, c)
			wrongOp := br.Sub
			if op == br.Sub {
				wrongOp = br.Add
			}
			if op != br.Add && op != br.Sub {
				wrongOp = br.ULT
				if op == br.ULT {
					wrongOp = br.SLT
				}
			}
			_, wrongOperator := conditionalOperationTerms(f, wrongOp, position, p, a, b, c)
			bad := []br.Term{f.make(br.ITE, out, 0, p, v.Args[2], v.Args[1]), wrongCondition, staleOperand, wrongPosition, wrongOperator, f.make(br.ITE, out, 0, p, f.con(out, 0), v.Args[2]), f.make(br.ITE, out, 0, p, v.Args[1], staleOperand.View().Args[2]), f.make(br.ITE, out, 0, p, v.Args[1], wrongOperator.View().Args[2]), f.make(br.ITE, out, 0, p, v.Args[1], f.con(out, 0))}
			// Keep the condition, first arm, operator and fixed operand valid;
			// only the second arm's selected input is replaced by the first's.
			bad = append(bad, f.make(br.ITE, out, 0, p, v.Args[1], v.Args[1]))
			if out.IsBool() {
				narrow := func(x br.Term) br.Term { return f.make(br.Trunc, br.Bits(31), 0, x) }
				_, wrongWidth := conditionalOperationTerms(f, op, position, p, narrow(a), narrow(b), narrow(c))
				bad = append(bad, wrongWidth, f.make(br.ITE, out, 0, p, v.Args[1], wrongWidth.View().Args[2]))
			} else {
				// A valid shift carries an immediate, but cannot replace an arm's
				// exact arithmetic head or smuggle in immediate-based semantics.
				bad = append(bad, f.make(br.ITE, out, 0, p, f.make(br.LShr, out, 1, a), v.Args[2]))
			}
			for j, wrong := range bad {
				t.Run(fmt.Sprintf("op%d/position%d/control%d", op, position, j), func(t *testing.T) {
					refusal(t, left, wrong, br.Proof{Steps: []br.Step{{Rule: br.ConditionalOperation, Left: left, Right: wrong}}}, br.InvalidRule)
				})
			}
			refusal(t, right, left, br.Proof{Steps: []br.Step{{Rule: br.ConditionalOperation, Left: right, Right: left}}}, br.InvalidRule)
			refusal(t, left, right, br.Proof{Steps: []br.Step{{Rule: br.Reflexivity, Left: left, Right: left}, {Rule: br.ConditionalOperation, Left: left, Right: right, Premises: []int{0}}}}, br.InvalidRule)
		}
	}
	// True distribution identities outside the closed bit-vector vocabulary
	// still cannot be justified by this rule alone.
	x := f.make(br.ITE, s, 0, p, a, b)
	l := f.make(br.BitAnd, s, 0, x, c)
	r := f.make(br.ITE, s, 0, p, f.make(br.BitAnd, s, 0, a, c), f.make(br.BitAnd, s, 0, b, c))
	refusal(t, l, r, br.Proof{Steps: []br.Step{{Rule: br.ConditionalOperation, Left: l, Right: r}}}, br.InvalidRule)
	left, right := conditionalOperationTerms(f, br.Equal, 0, p, p, otherP, otherP)
	refusal(t, left, right, br.Proof{Steps: []br.Step{{Rule: br.ConditionalOperation, Left: left, Right: right}}}, br.InvalidRule)
	if _, err := f.b.Make(br.Add, s, 1, x, c); err == nil {
		t.Fatal("nonzero arithmetic immediate constructed")
	}
}

type conditionalCheckpoint struct {
	context.Context
	calls  int
	action func(int)
}

func (c *conditionalCheckpoint) Err() error {
	c.calls++
	if c.action != nil {
		c.action(c.calls)
	}
	return c.Context.Err()
}

func TestConditionalOperationCancellationOwnershipAndBudgets(t *testing.T) {
	f := newFactory(t)
	s := br.Bits(64)
	p := f.variable(br.Bool(), br.NewScope(), 0, false)
	a, b, c := f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, false), f.variable(s, br.NewScope(), 0, false)
	left, right := conditionalOperationTerms(f, br.Sub, 1, p, a, b, c)
	proof := br.Proof{Steps: []br.Step{{Rule: br.ConditionalOperation, Left: left, Right: right}}}
	count := &conditionalCheckpoint{Context: t.Context()}
	if w, err := br.Check(count, left, right, proof, br.Limits{}); err != nil || !w.Valid() {
		t.Fatal(err)
	}
	for at := 1; at <= count.calls; at++ {
		ctx, cancel := context.WithCancel(t.Context())
		callback := &conditionalCheckpoint{Context: ctx, action: func(n int) {
			if n == at {
				cancel()
			}
		}}
		w, err := br.Check(callback, left, right, proof, br.Limits{})
		cancel()
		if w.Valid() || !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled local inference acquired authority", at, err)
		}
	}
	owned := br.Proof{Steps: append([]br.Step(nil), proof.Steps...)}
	callback := &conditionalCheckpoint{Context: t.Context(), action: func(int) { owned.Steps[0].Right = left; owned.Steps[0].Premises = []int{0} }}
	if w, err := br.Check(callback, left, right, owned, br.Limits{}); err != nil || !w.Valid() {
		t.Fatal("local proof borrowed mutable proposal", err)
	}
	for _, limit := range []br.Limits{{Nodes: 8}, {Work: count.calls - 1}} {
		w, err := br.Check(t.Context(), left, right, proof, limit)
		var r *br.Refusal
		if w.Valid() || !errors.As(err, &r) || r.Code != br.Budget {
			t.Fatal("unmetered conditional proof", limit, err)
		}
	}
	if w, err := br.Check(t.Context(), left, right, proof, br.Limits{Nodes: 9}); err != nil || !w.Valid() {
		t.Fatal("exact local graph population refused", err)
	}
	count = &conditionalCheckpoint{Context: t.Context()}
	proposal, err := br.Propose(count, left, right, br.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	check(t, left, right, proposal)
	for _, at := range []int{1, count.calls / 2, count.calls} {
		ctx, cancel := context.WithCancel(t.Context())
		callback := &conditionalCheckpoint{Context: ctx, action: func(n int) {
			if n == at {
				cancel()
			}
		}}
		q, err := br.Propose(callback, left, right, br.Limits{})
		cancel()
		if len(q.Steps) != 0 || !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled expansion published steps", at, err)
		}
	}
	for _, limit := range []br.Limits{{Steps: 1}, {Work: count.calls - 1}} {
		q, err := br.Propose(t.Context(), left, right, limit)
		var r *br.Refusal
		if len(q.Steps) != 0 || !errors.As(err, &r) || r.Code != br.Budget {
			t.Fatal("conditional search reset its account", limit, err)
		}
	}
}

func TestConditionalOperationGeneratedDepth(t *testing.T) {
	f := newFactory(t)
	s := br.Bits(64)
	scope := br.NewScope()
	p := f.variable(br.Bool(), scope, 0, false)
	a, b := f.variable(s, scope, 1, false), f.variable(s, scope, 2, false)
	deep := f.variable(s, scope, 3, false)
	for j := 0; j < 510; j++ {
		deep = f.make(br.BitOr, s, 0, deep, f.variable(s, scope, uint64(j+4), false))
	}
	left, right := conditionalOperationTerms(f, br.Add, 0, p, a, b, deep)
	direct(t, br.Reflexivity, left, left) // input depth is exactly the admitted 512
	q, err := br.Propose(t.Context(), left, left, br.Limits{})
	var r *br.Refusal
	if len(q.Steps) != 0 || !errors.As(err, &r) || r.Code != br.Budget || r.Detail != "expression depth budget" {
		t.Fatal("new branch depth was not checked before normalization", err)
	}
	w, err := br.Check(t.Context(), left, right, br.Proof{Steps: []br.Step{{Rule: br.ConditionalOperation, Left: left, Right: right}}}, br.Limits{})
	if w.Valid() || !errors.As(err, &r) || r.Code != br.Budget || r.Detail != "expression depth budget" {
		t.Fatal("deep conditional certificate accepted", err)
	}
}

func TestConditionalOperationGeneratedNodesShareBound(t *testing.T) {
	left, right := conditionalJoinedCounter(t)
	seen := map[br.Term]bool{}
	pending := []br.Term{left, right}
	for len(pending) > 0 {
		x := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[x] {
			continue
		}
		seen[x] = true
		pending = append(pending, x.View().Args...)
	}
	// The original roots fit exactly; generated conditional arms must consume
	// the same finite node allowance rather than obtaining one per branch.
	if w, err := br.Check(t.Context(), left, left, br.Proof{Steps: []br.Step{{Rule: br.Reflexivity, Left: left, Right: left}}}, br.Limits{Nodes: len(seen)}); err != nil || !w.Valid() {
		t.Fatal("original graph does not fit control", err)
	}
	q, err := br.Propose(t.Context(), left, right, br.Limits{Nodes: len(seen)})
	var r *br.Refusal
	if len(q.Steps) != 0 || !errors.As(err, &r) || r.Code != br.Budget {
		t.Fatal("branch construction escaped finite nodes", len(seen), err)
	}
	prove(t, left, right)
}

func TestConditionalOperationDoesNotReverseBooleanEncoding(t *testing.T) {
	f := newFactory(t)
	scope := br.NewScope()
	s := br.Bits(32)
	p, q, r := f.variable(br.Bool(), scope, 0, false), f.variable(br.Bool(), scope, 1, false), f.variable(br.Bool(), scope, 2, false)
	x := f.variable(s, scope, 3, false)
	bits := f.make(br.ITE, s, 0, p, f.make(br.BoolToBits, s, 0, q), f.make(br.BoolToBits, s, 0, r))
	root := f.make(br.Add, s, 0, bits, x)
	proposal, err := br.Propose(t.Context(), root, root, br.Limits{Nodes: 64, Steps: 128, Work: 1024})
	if err != nil {
		t.Fatal("conditional encoding rewrite cycled", err)
	}
	check(t, root, root, proposal)
}
