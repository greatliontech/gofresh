package bitrelation

import (
	"context"
	"crypto/sha256"
)

// Rule identifies one equality inference. Rules are checked independently of
// proposal search. Their exact side conditions live in the checker below.
type Rule uint8

const (
	Reflexivity Rule = iota + 1
	Symmetry
	Transitivity
	Congruence
	ConstantFold
	BooleanLaw
	Conversion
	Algebra
	SubtractConstant
	Commute
	SignedInterval
	ComparisonBound
	TotalOrder
	ConditionalProjection
	ConditionalBits
	ConditionalSwap
	BooleanPartition
	SignBoundary
	ConjunctionContradiction
	ConditionalOperation
)

// Step proposes an equality between Left and Right. Premises index earlier
// steps; no forward references, assumed facts or caller-positive flags exist.
type Step struct {
	Rule        Rule
	Left, Right Term
	Premises    []int
}

// Proof is an untrusted equality derivation. The last step must prove precisely
// the independently supplied roots. Check snapshots all fields before callbacks.
type Proof struct{ Steps []Step }

// Witness is an opaque checked scalar equality. Its zero value is invalid.
// There is no constructor from projections, digests, Booleans or serialized data.
type Witness struct{ checked *checked }
type checked struct {
	left, right Term
	digest      [32]byte
}

// Valid reports whether checking produced this witness.
func (w Witness) Valid() bool { return w.checked != nil }

// Dependencies returns the root-graph/rule-model commitment, not public authority.
func (w Witness) Dependencies() [32]byte {
	if !w.Valid() {
		return [32]byte{}
	}
	return w.checked.digest
}

// Roots returns immutable handles to the actual checked endpoints.
func (w Witness) Roots() (Term, Term) {
	if !w.Valid() {
		return Term{}, Term{}
	}
	return w.checked.left, w.checked.right
}

func copyProof(p Proof) Proof {
	r := Proof{Steps: append([]Step(nil), p.Steps...)}
	for i := range r.Steps {
		r.Steps[i].Premises = append([]int(nil), r.Steps[i].Premises...)
	}
	return r
}

// Check validates every inference and both independent endpoints. Rejection is
// absence of a proof, not evidence of inequivalence. All returned witnesses are
// conditional solely on this total scalar language and explicit variable mapping.
func Check(ctx context.Context, left, right Term, proposal Proof, limits Limits) (Witness, error) {
	// Bound copying before invoking even a user-defined Context.Err callback.
	l := limits
	if l.Steps == 0 {
		l.Steps = DefaultLimits().Steps
	}
	if l.Steps < 0 || len(proposal.Steps) > l.Steps {
		return Witness{}, refuse(Budget, "certificate step budget")
	}
	for _, s := range proposal.Steps {
		if len(s.Premises) > 3 {
			return Witness{}, refuse(Malformed, "too many premises")
		}
	}
	p := copyProof(proposal)
	m, err := newMeter(ctx, limits)
	if err != nil {
		return Witness{}, err
	}
	if len(p.Steps) == 0 {
		return Witness{}, refuse(Malformed, "empty derivation")
	}
	roots := []Term{left, right}
	for _, s := range p.Steps {
		roots = append(roots, s.Left, s.Right)
	}
	if err = graph(m, roots); err != nil {
		return Witness{}, err
	}
	c := checker{e: equality{m: m, seen: make(map[pair]bool)}}
	for i, s := range p.Steps {
		if err = m.tick(); err != nil {
			return Witness{}, err
		}
		for _, j := range s.Premises {
			if j < 0 || j >= i {
				return Witness{}, &Refusal{Code: InvalidRule, Detail: "premise is not an earlier checked step", Step: i, Rule: s.Rule}
			}
		}
		if s.Left.Sort() != s.Right.Sort() || !c.step(s, p.Steps) {
			if c.err != nil {
				return Witness{}, c.err
			}
			return Witness{}, &Refusal{Code: InvalidRule, Detail: "equality rule or side condition failed", Step: i, Rule: s.Rule}
		}
		if c.err != nil {
			return Witness{}, c.err
		}
	}
	last := p.Steps[len(p.Steps)-1]
	if !c.eq(left.n, last.Left.n) || !c.eq(right.n, last.Right.n) {
		if c.err != nil {
			return Witness{}, c.err
		}
		return Witness{}, refuse(Endpoint, "derivation does not bind the requested roots")
	}
	if c.err != nil {
		return Witness{}, c.err
	}
	if err = m.tick(); err != nil {
		return Witness{}, err
	}
	h := sha256.New()
	h.Write([]byte(RuleModel))
	ld, rd := left.Digest(), right.Digest()
	h.Write(ld[:])
	h.Write(rd[:])
	w := &checked{left: left, right: right}
	h.Sum(w.digest[:0])
	return Witness{w}, nil
}

type checker struct {
	e   equality
	err error
}

func (c *checker) eq(a, b *node) bool {
	if c.err != nil {
		return false
	}
	var ok bool
	ok, c.err = c.e.same(a, b)
	return ok
}
func constant(n *node, v uint64) bool { return n != nil && n.op == Constant && n.imm == v }
func (c *checker) step(s Step, steps []Step) bool {
	a, b := s.Left.n, s.Right.n
	if a.sort != b.sort {
		return false
	}
	ps := s.Premises
	switch s.Rule {
	case Reflexivity:
		return len(ps) == 0 && c.eq(a, b)
	case Symmetry:
		return len(ps) == 1 && c.eq(a, steps[ps[0]].Right.n) && c.eq(b, steps[ps[0]].Left.n)
	case Transitivity:
		return len(ps) == 2 && c.eq(a, steps[ps[0]].Left.n) && c.eq(steps[ps[0]].Right.n, steps[ps[1]].Left.n) && c.eq(b, steps[ps[1]].Right.n)
	case Congruence:
		if !sameHead(a, b) || len(ps) != int(a.arity) {
			return false
		}
		for i, p := range ps {
			if !c.eq(a.args[i], steps[p].Left.n) || !c.eq(b.args[i], steps[p].Right.n) {
				return false
			}
		}
		return true
	}
	if len(ps) != 0 {
		return false
	}
	switch s.Rule {
	case ConstantFold:
		if a.op == Variable || b.op != Constant {
			return false
		}
		var values [3]uint64
		for i := 0; i < int(a.arity); i++ {
			if a.args[i].op != Constant {
				return false
			}
			values[i] = a.args[i].imm
		}
		return primitive(a, values) == b.imm
	case BooleanLaw:
		return c.boolean(a, b)
	case Conversion:
		return c.conversion(a, b)
	case Algebra:
		return c.algebra(a, b)
	case SubtractConstant:
		return a.op == Sub && a.args[1].op == Constant && b.op == Add && c.eq(a.args[0], b.args[0]) && constant(b.args[1], (-a.args[1].imm)&mask(a.sort.width))
	case Commute:
		switch a.op {
		case Add, BitAnd, BitOr, BitXor, And, Or, Equal:
			return b.op == a.op && c.eq(a.args[0], b.args[1]) && c.eq(a.args[1], b.args[0])
		}
		return false
	case SignedInterval:
		return c.interval(a, b)
	case ComparisonBound:
		return c.comparisonBound(a, b)
	case TotalOrder:
		return c.totalOrder(a, b)
	case ConditionalProjection:
		return c.conditionalProjection(a, b)
	case ConditionalBits:
		return c.conditionalBits(a, b)
	case ConditionalSwap:
		return a.op == ITE && a.args[0].op == Not && b.op == ITE && c.eq(a.args[0].args[0], b.args[0]) && c.eq(a.args[1], b.args[2]) && c.eq(a.args[2], b.args[1])
	case BooleanPartition:
		return c.booleanPartition(a, b)
	case SignBoundary:
		return c.signBoundary(a, b)
	case ConjunctionContradiction:
		return c.conjunctionContradiction(a, b)
	case ConditionalOperation:
		return c.conditionalOperation(a, b)
	}
	return false
}

// comparisonBound converts an inclusive constant upper bound only when its
// successor exists in the selected signed/unsigned order. Extremal predicates
// are checked directly, rather than wrapping a maximum endpoint to a minimum.
func (c *checker) comparisonBound(a, b *node) bool {
	if a.op != ULE && a.op != SLE && a.op != ULT && a.op != SLT {
		return false
	}
	x, end := a.args[0], a.args[1]
	if end.op != Constant {
		return false
	}
	w := x.sort.width
	maximum, minimum := mask(w), uint64(0)
	strict := ULT
	if a.op == SLE || a.op == SLT {
		maximum = (uint64(1) << (w - 1)) - 1
		minimum = uint64(1) << (w - 1)
		strict = SLT
	}
	if a.op == ULT || a.op == SLT {
		return end.imm == minimum && constant(b, 0)
	}
	if end.imm == maximum {
		return constant(b, 1)
	}
	return b.op == strict && c.eq(x, b.args[0]) && constant(b.args[1], (end.imm+1)&mask(w))
}

func (c *checker) boolean(a, b *node) bool {
	x, y := a.args[0], a.args[1]
	// And/Or and Not have exactly Boolean operands by construction. The
	// complement must match structurally, including variable scope and scratch.
	if a.op == And && constant(b, 0) || a.op == Or && constant(b, 1) {
		for i := 0; i < 2; i++ {
			neg, other := a.args[i], a.args[1-i]
			if neg.op == Not && c.eq(neg.args[0], other) {
				return true
			}
		}
	}
	switch a.op {
	case Not:
		return x.op == Not && c.eq(x.args[0], b)
	case And:
		return constant(x, 0) && constant(b, 0) || constant(y, 0) && constant(b, 0) || constant(x, 1) && c.eq(y, b) || constant(y, 1) && c.eq(x, b) || c.eq(x, y) && c.eq(x, b)
	case Or:
		return constant(x, 1) && constant(b, 1) || constant(y, 1) && constant(b, 1) || constant(x, 0) && c.eq(y, b) || constant(y, 0) && c.eq(x, b) || c.eq(x, y) && c.eq(x, b)
	case ITE:
		z := a.args[2]
		if constant(x, 1) && c.eq(y, b) || constant(x, 0) && c.eq(z, b) || c.eq(y, z) && c.eq(y, b) {
			return true
		}
		if !a.sort.IsBool() {
			return false
		}
		if constant(y, 1) && constant(z, 0) && c.eq(x, b) {
			return true
		}
		if constant(y, 0) && constant(z, 1) && b.op == Not && c.eq(x, b.args[0]) {
			return true
		}
		if constant(y, 0) {
			return b.op == And && b.args[0].op == Not && c.eq(x, b.args[0].args[0]) && c.eq(z, b.args[1])
		}
		if constant(z, 0) {
			return b.op == And && c.eq(x, b.args[0]) && c.eq(y, b.args[1])
		}
		if constant(y, 1) {
			return b.op == Or && c.eq(x, b.args[0]) && c.eq(z, b.args[1])
		}
		if constant(z, 1) {
			return b.op == Or && b.args[0].op == Not && c.eq(x, b.args[0].args[0]) && c.eq(y, b.args[1])
		}
	}
	return false
}

func (c *checker) conversion(a, b *node) bool {
	x := a.args[0]
	switch a.op {
	case Trunc:
		switch x.op {
		case Concat:
			low, high := x.args[0], x.args[1]
			if a.sort == low.sort {
				return c.eq(low, b)
			}
			if a.sort.width < low.sort.width {
				return b.op == Trunc && c.eq(low, b.args[0])
			}
			return b.op == Concat && c.eq(low, b.args[0]) && b.args[1].op == Trunc && c.eq(high, b.args[1].args[0])
		case BoolToBits:
			return b.op == BoolToBits && c.eq(x.args[0], b.args[0])
		case Trunc:
			return b.op == Trunc && c.eq(x.args[0], b.args[0])
		case ZExt, SExt:
			y := x.args[0]
			if a.sort == y.sort {
				return c.eq(y, b)
			}
			if a.sort.width < y.sort.width {
				return b.op == Trunc && c.eq(y, b.args[0])
			}
			return b.op == x.op && c.eq(y, b.args[0])
		}
	case ZExt, SExt:
		if x.op == a.op {
			return b.op == a.op && c.eq(x.args[0], b.args[0])
		}
		if a.op == SExt && x.op == ZExt {
			return b.op == ZExt && c.eq(x.args[0], b.args[0])
		}
		if x.op == BoolToBits && (a.op == ZExt || x.sort.width > 1) {
			return b.op == BoolToBits && c.eq(x.args[0], b.args[0])
		}
	case Extract:
		if a.imm == 0 {
			return a.sort == x.sort && c.eq(x, b) || b.op == Trunc && c.eq(x, b.args[0])
		}
		if x.op == Concat && a.imm >= uint64(x.args[0].sort.width) {
			high := x.args[1]
			offset := a.imm - uint64(x.args[0].sort.width)
			return offset == 0 && a.sort == high.sort && c.eq(high, b) || b.op == Extract && b.imm == offset && c.eq(high, b.args[0])
		}
	case Nonzero:
		return x.op == BoolToBits && c.eq(x.args[0], b)
	case BoolToBits:
		if x.op == Nonzero && x.args[0].sort.width == 1 {
			return a.sort.width == 1 && c.eq(x.args[0], b) || b.op == ZExt && c.eq(x.args[0], b.args[0])
		}
	}
	return false
}

func (c *checker) algebra(a, b *node) bool {
	x, y := a.args[0], a.args[1]
	switch a.op {
	case Equal, ULT, ULE, SLT, SLE:
		v := uint64(0)
		if a.op == Equal || a.op == ULE || a.op == SLE {
			v = 1
		}
		return c.eq(x, y) && constant(b, v)
	case Add, Sub, BitOr, BitXor:
		if constant(y, 0) && c.eq(x, b) {
			return true
		}
	case BitAnd:
		if constant(y, mask(a.sort.width)) && c.eq(x, b) || constant(y, 0) && constant(b, 0) {
			return true
		}
	case BitNot:
		return x.op == BitNot && c.eq(x.args[0], b)
	case Shl, LShr, AShr:
		return a.imm == 0 && c.eq(x, b)
	}
	if a.op == Sub || a.op == BitXor {
		return c.eq(x, y) && constant(b, 0)
	}
	if a.op == BitAnd || a.op == BitOr {
		return c.eq(x, y) && c.eq(x, b)
	}
	return false
}

// interval checks the theorem, including the nonempty representable SIGNED
// endpoints. The positive mathematical difference can exceed MaxInt64; uint64
// subtraction gives its exact width-bit representation without signed overflow.
func (c *checker) interval(a, b *node) bool {
	if a.op != And || b.op != ULT {
		return false
	}
	lower, upper := a.args[0], a.args[1]
	if upper.op != SLT || upper.args[1].op != Constant {
		return false
	}
	x, u := upper.args[0], upper.args[1]
	var l *node
	if lower.op == Not && lower.args[0].op == SLT {
		p := lower.args[0]
		if !c.eq(p.args[0], x) {
			return false
		}
		l = p.args[1]
	} else if lower.op == SLE {
		if !c.eq(lower.args[1], x) {
			return false
		}
		l = lower.args[0]
	} else {
		return false
	}
	if l.op != Constant || l.sort != x.sort || u.sort != x.sort {
		return false
	}
	w := x.sort.width
	if signed(l.imm, w) >= signed(u.imm, w) {
		return false
	}
	delta := (u.imm - l.imm) & mask(w)
	if delta == 0 || b.args[0].sort != x.sort || !constant(b.args[1], delta) {
		return false
	}
	offset := b.args[0]
	if offset.op == Sub {
		return c.eq(offset.args[0], x) && c.eq(offset.args[1], l)
	}
	return offset.op == Add && c.eq(offset.args[0], x) && constant(offset.args[1], (-l.imm)&mask(w))
}
