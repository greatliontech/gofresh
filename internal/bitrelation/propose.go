package bitrelation

import "context"

// Propose searches a bounded, deliberately incomplete rewrite normal form. It
// returns only untrusted steps. Check must independently validate the result
// against the controller's own roots; proposal success is never authority.
func Propose(ctx context.Context, left, right Term, limits Limits) (Proof, error) {
	m, err := newMeter(ctx, limits)
	if err != nil {
		return Proof{}, err
	}
	if err = graph(m, []Term{left, right}); err != nil {
		return Proof{}, err
	}
	if left.Sort() != right.Sort() {
		return Proof{}, refuse(Unsupported, "different result sorts")
	}
	p := proposer{m: m, b: NewBuilder(m.limits.Nodes), memo: make(map[*node]normal), e: equality{m: m, seen: make(map[pair]bool)}}
	l := p.normalize(left)
	r := p.normalize(right)
	if p.err != nil {
		return Proof{}, p.err
	}
	ok, err := p.e.same(l.term.n, r.term.n)
	if err != nil {
		return Proof{}, err
	}
	if !ok {
		return Proof{}, refuse(Unsupported, "bounded rewrites did not join")
	}
	bridge := p.emit(Reflexivity, l.term, r.term)
	back := p.emit(Symmetry, r.term, right, r.step)
	mid := p.emit(Transitivity, left, r.term, l.step, bridge)
	p.emit(Transitivity, left, right, mid, back)
	if p.err != nil {
		return Proof{}, p.err
	}
	if err = m.tick(); err != nil {
		return Proof{}, err
	}
	return p.proof, nil
}

// Prove proposes, then independently checks under separate finite budgets. It
// cannot bind a program on behalf of a frontend: its only inputs are these roots.
func Prove(ctx context.Context, left, right Term, limits Limits) (Witness, error) {
	p, err := Propose(ctx, left, right, limits)
	if err != nil {
		return Witness{}, err
	}
	return Check(ctx, left, right, p, limits)
}

type normal struct {
	term Term
	step int
}
type proposer struct {
	m     *meter
	b     *Builder
	proof Proof
	memo  map[*node]normal
	e     equality
	err   error
}

func (p *proposer) emit(rule Rule, a, b Term, premises ...int) int {
	if p.err != nil {
		return 0
	}
	if p.err = p.m.tick(); p.err != nil {
		return 0
	}
	if len(p.proof.Steps) >= p.m.limits.Steps {
		p.err = refuse(Budget, "proposal step budget")
		return 0
	}
	i := len(p.proof.Steps)
	p.proof.Steps = append(p.proof.Steps, Step{Rule: rule, Left: a, Right: b, Premises: append([]int(nil), premises...)})
	return i
}
func (p *proposer) make(op Op, s Sort, imm uint64, args ...Term) Term {
	if p.err != nil {
		return Term{}
	}
	var t Term
	t, p.err = p.b.Make(op, s, imm, args...)
	return t
}
func (p *proposer) con(s Sort, v uint64) Term { return p.make(Constant, s, v) }
func (p *proposer) eq(a, b *node) bool {
	if p.err != nil {
		return false
	}
	var ok bool
	ok, p.err = p.e.same(a, b)
	return ok
}
func (p *proposer) normalize(t Term) normal {
	if p.err != nil {
		return normal{}
	}
	if p.err = p.m.tick(); p.err != nil {
		return normal{}
	}
	if v, ok := p.memo[t.n]; ok {
		return v
	}
	n := t.n
	if n.arity == 0 {
		v := normal{t, p.emit(Reflexivity, t, t)}
		p.memo[n] = v
		return v
	}
	args := make([]Term, n.arity)
	premises := make([]int, n.arity)
	for i := range args {
		v := p.normalize(Term{n.args[i]})
		args[i], premises[i] = v.term, v.step
	}
	cur := p.make(n.op, n.sort, n.imm, args...)
	if p.err != nil {
		return normal{}
	}
	step := p.emit(Congruence, t, cur, premises...)
	if p.err != nil {
		return normal{}
	}
	// Every proposed local rewrite has its own certificate step. Recursively
	// reducing the newly formed expression lets an ITE expose an interval rule.
	if rule, next, ok := p.rewrite(cur); ok && p.err == nil {
		local := p.emit(rule, cur, next)
		norm := p.normalize(next)
		joined := p.emit(Transitivity, cur, norm.term, local, norm.step)
		step = p.emit(Transitivity, t, norm.term, step, joined)
		cur = norm.term
	}
	v := normal{cur, step}
	p.memo[n] = v
	return v
}

// rewrite is heuristic pattern selection, intentionally separate from the
// checker's side-condition recognizers. No positive flag from here is reused.
func (p *proposer) rewrite(t Term) (Rule, Term, bool) {
	n := t.n
	x, y := n.args[0], n.args[1]
	s := n.sort
	tm := func(n *node) Term { return Term{n} }
	result := func(r Rule, t Term) (Rule, Term, bool) { return r, t, true }
	all := true
	var values [3]uint64
	for i := 0; i < int(n.arity); i++ {
		if n.args[i].op != Constant {
			all = false
			break
		}
		values[i] = n.args[i].imm
	}
	if n.arity > 0 && all {
		return result(ConstantFold, p.con(s, primitive(n, values)))
	}
	switch n.op {
	case Not:
		if x.op == Not {
			return result(BooleanLaw, tm(x.args[0]))
		}
	case And, Or:
		if p.eq(x, y) {
			return result(BooleanLaw, tm(x))
		}
		for i := 0; i < 2; i++ {
			a, b := n.args[i], n.args[1-i]
			if a.op == Not && p.eq(a.args[0], b) {
				value := uint64(0)
				if n.op == Or {
					value = 1
				}
				return result(BooleanLaw, p.con(Bool(), value))
			}
			if a.op != Constant {
				continue
			}
			if n.op == And && a.imm == 0 || n.op == Or && a.imm == 1 {
				return result(BooleanLaw, tm(a))
			}
			return result(BooleanLaw, tm(b))
		}
	case ITE:
		z := n.args[2]
		if x.op == Constant {
			if x.imm == 0 {
				return result(BooleanLaw, tm(z))
			}
			return result(BooleanLaw, tm(y))
		}
		if p.eq(y, z) {
			return result(BooleanLaw, tm(y))
		}
		if s.IsBool() {
			if constant(y, 1) && constant(z, 0) {
				return result(BooleanLaw, tm(x))
			}
			if constant(y, 0) && constant(z, 1) {
				return result(BooleanLaw, p.make(Not, Bool(), 0, tm(x)))
			}
			if constant(y, 0) {
				return result(BooleanLaw, p.make(And, Bool(), 0, p.make(Not, Bool(), 0, tm(x)), tm(z)))
			}
			if constant(z, 0) {
				return result(BooleanLaw, p.make(And, Bool(), 0, tm(x), tm(y)))
			}
			if constant(y, 1) {
				return result(BooleanLaw, p.make(Or, Bool(), 0, tm(x), tm(z)))
			}
			if constant(z, 1) {
				return result(BooleanLaw, p.make(Or, Bool(), 0, p.make(Not, Bool(), 0, tm(x)), tm(y)))
			}
		}
	case Trunc:
		switch x.op {
		case ZExt, SExt:
			base := x.args[0]
			if s == base.sort {
				return result(Conversion, tm(base))
			}
			if s.width < base.sort.width {
				return result(Conversion, p.make(Trunc, s, 0, tm(base)))
			}
			return result(Conversion, p.make(x.op, s, 0, tm(base)))
		case Trunc:
			return result(Conversion, p.make(Trunc, s, 0, tm(x.args[0])))
		case Concat:
			low, high := x.args[0], x.args[1]
			if s == low.sort {
				return result(Conversion, tm(low))
			}
			if s.width < low.sort.width {
				return result(Conversion, p.make(Trunc, s, 0, tm(low)))
			}
			return result(Conversion, p.make(Concat, s, 0, tm(low), p.make(Trunc, Bits(int(s.width-low.sort.width)), 0, tm(high))))
		case BoolToBits:
			return result(Conversion, p.make(BoolToBits, s, 0, tm(x.args[0])))
		}
	case ZExt, SExt:
		if x.op == n.op || n.op == SExt && x.op == ZExt {
			return result(Conversion, p.make(x.op, s, 0, tm(x.args[0])))
		}
		if x.op == BoolToBits && (n.op == ZExt || x.sort.width > 1) {
			return result(Conversion, p.make(BoolToBits, s, 0, tm(x.args[0])))
		}
	case Extract:
		if n.imm == 0 {
			if s == x.sort {
				return result(Conversion, tm(x))
			}
			return result(Conversion, p.make(Trunc, s, 0, tm(x)))
		}
		if x.op == Concat && n.imm >= uint64(x.args[0].sort.width) {
			high := x.args[1]
			off := n.imm - uint64(x.args[0].sort.width)
			if off == 0 && s == high.sort {
				return result(Conversion, tm(high))
			}
			return result(Conversion, p.make(Extract, s, off, tm(high)))
		}
	case Nonzero:
		if x.op == BoolToBits {
			return result(Conversion, tm(x.args[0]))
		}
	case BoolToBits:
		if x.op == Nonzero && x.args[0].sort.width == 1 {
			if s.width == 1 {
				return result(Conversion, tm(x.args[0]))
			}
			return result(Conversion, p.make(ZExt, s, 0, tm(x.args[0])))
		}
	case Equal, ULT, ULE, SLT, SLE:
		if p.eq(x, y) {
			v := uint64(0)
			if n.op == Equal || n.op == ULE || n.op == SLE {
				v = 1
			}
			return result(Algebra, p.con(s, v))
		}
		if y.op == Constant && n.op != Equal {
			maximum := mask(x.sort.width)
			strict := ULT
			if n.op == SLE || n.op == SLT {
				maximum = (uint64(1) << (x.sort.width - 1)) - 1
				strict = SLT
			}
			if n.op == ULE || n.op == SLE {
				if y.imm == maximum {
					return result(ComparisonBound, p.con(Bool(), 1))
				}
				return result(ComparisonBound, p.make(strict, Bool(), 0, tm(x), p.con(x.sort, (y.imm+1)&mask(x.sort.width))))
			}
		}
	case Add, Sub, BitOr, BitXor:
		if constant(y, 0) {
			return result(Algebra, tm(x))
		}
		if (n.op == Sub || n.op == BitXor) && p.eq(x, y) {
			return result(Algebra, p.con(s, 0))
		}
		if n.op == Sub && y.op == Constant {
			return result(SubtractConstant, p.make(Add, s, 0, tm(x), p.con(s, (-y.imm)&mask(s.width))))
		}
		if n.op == BitOr && p.eq(x, y) {
			return result(Algebra, tm(x))
		}
	case BitAnd:
		if constant(y, 0) {
			return result(Algebra, p.con(s, 0))
		}
		if constant(y, mask(s.width)) || p.eq(x, y) {
			return result(Algebra, tm(x))
		}
		if x.op == Concat && y.op == Constant {
			low, high := x.args[0], x.args[1]
			lo := p.make(BitAnd, low.sort, 0, tm(low), p.con(low.sort, y.imm&mask(low.sort.width)))
			hi := p.make(BitAnd, high.sort, 0, tm(high), p.con(high.sort, y.imm>>low.sort.width))
			return result(ConcatMask, p.make(Concat, s, 0, lo, hi))
		}
	case BitNot:
		if x.op == BitNot {
			return result(Algebra, tm(x.args[0]))
		}
	case Shl, LShr, AShr:
		if n.imm == 0 {
			return result(Algebra, tm(x))
		}
	}
	// Keep cheap identities first, then lift conditionals before an order rule
	// can hide them beneath NOT (for example ULE -> !ULT with swapped operands).
	if rule, next, ok := p.conditionalOperationRewrite(t); ok || p.err != nil {
		return rule, next, ok
	}
	if rule, next, ok := p.controlRewrite(t); ok || p.err != nil {
		return rule, next, ok
	}
	if n.op == And && y.op == SLT && y.args[1].op == Constant {
		var low *node
		v := y.args[0]
		hi := y.args[1]
		if x.op == Not && x.args[0].op == SLT && p.eq(x.args[0].args[0], v) {
			low = x.args[0].args[1]
		}
		if x.op == SLE && p.eq(x.args[1], v) {
			low = x.args[0]
		}
		if low != nil && low.op == Constant && signed(low.imm, v.sort.width) < signed(hi.imm, v.sort.width) {
			diff := (hi.imm - low.imm) & mask(v.sort.width)
			offset := p.make(Add, v.sort, 0, tm(v), p.con(v.sort, (-low.imm)&mask(v.sort.width)))
			return result(SignedInterval, p.make(ULT, Bool(), 0, offset, p.con(v.sort, diff)))
		}
	}
	// Orient constants to the right; never commute in both directions.
	switch n.op {
	case Add, BitAnd, BitOr, BitXor, Equal:
		if x.op == Constant && y.op != Constant {
			return result(Commute, p.make(n.op, s, 0, tm(y), tm(x)))
		}
	}
	return 0, Term{}, false
}
