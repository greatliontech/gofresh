package bitrelation

// Lift one conditional operand outward, preferring the left operand. The closed
// arithmetic/order vocabulary excludes BoolToBits, so this orientation cannot
// reverse ConditionalBits. Local checking shares none of this search's matching
// decisions. Construction, resulting depth and normalization use the same meter.
func (p *proposer) conditionalOperationRewrite(t Term) (Rule, Term, bool) {
	n := t.n
	switch n.op {
	case Add, Sub, Equal, ULT, ULE, SLT, SLE:
	default:
		return 0, Term{}, false
	}
	if n.args[0].sort.IsBool() {
		return 0, Term{}, false
	}
	for position := 0; position < 2; position++ {
		if p.err = p.m.tick(); p.err != nil {
			return 0, Term{}, false
		}
		x := n.args[position]
		if x.op != ITE {
			continue
		}
		var branches [2]Term
		for arm := 0; arm < 2; arm++ {
			if p.err = p.m.tick(); p.err != nil {
				return 0, Term{}, false
			}
			args := [2]Term{{n.args[0]}, {n.args[1]}}
			args[position] = Term{x.args[arm+1]}
			branches[arm] = p.make(n.op, n.sort, n.imm, args[:]...)
			if p.err != nil {
				return 0, Term{}, false
			}
		}
		if p.err = p.m.tick(); p.err != nil {
			return 0, Term{}, false
		}
		out := p.make(ITE, n.sort, 0, Term{x.args[0]}, branches[0], branches[1])
		if p.err != nil {
			return 0, Term{}, false
		}
		// Moving the unchanged operand beneath ITE can deepen a term. Admit the
		// generated graph before recursively searching it, under the existing
		// fixed depth ceiling and current cumulative work allowance.
		if p.err = graph(p.m, []Term{out}); p.err != nil {
			return 0, Term{}, false
		}
		return ConditionalOperation, out, true
	}
	return 0, Term{}, false
}

// controlRewrite proposes oriented order/path/projection rules. Checker rule
// recognition is separate: these patterns are search hints, never premises.
func (p *proposer) controlRewrite(t Term) (Rule, Term, bool) {
	if p.err != nil {
		return 0, Term{}, false
	}
	n := t.n
	tm := func(n *node) Term { return Term{n} }
	result := func(rule Rule, t Term) (Rule, Term, bool) { return rule, t, true }
	x, y := n.args[0], n.args[1]
	switch n.op {
	case And:
		// Search only conjunction leaves. The emitted rule independently checks
		// both occurrences and their scopes; this search result is not authority.
		queue := []*node{n}
		var positive, negative []*node
		visited := map[*node]bool{}
		for len(queue) != 0 {
			if p.err = p.m.tick(); p.err != nil {
				return 0, Term{}, false
			}
			at := queue[0]
			queue = queue[1:]
			if visited[at] {
				continue
			}
			visited[at] = true
			if at.op == And {
				queue = append(queue, at.args[0], at.args[1])
				continue
			}
			if at.op == Not {
				negative = append(negative, at.args[0])
			} else {
				positive = append(positive, at)
			}
		}
		for _, a := range positive {
			for _, b := range negative {
				if p.err = p.m.tick(); p.err != nil {
					return 0, Term{}, false
				}
				if p.eq(a, b) {
					return result(ConjunctionContradiction, p.con(Bool(), 0))
				}
				if p.err != nil {
					return 0, Term{}, false
				}
			}
		}
	case ULT:
		if constant(y, uint64(1)<<(x.sort.width-1)) {
			return result(SignBoundary, p.make(Not, Bool(), 0, p.make(SLT, Bool(), 0, tm(x), p.con(x.sort, 0))))
		}
	case Not:
		if (x.op == ULT || x.op == SLT) && x.args[0].op == Constant && x.args[1].op != Constant {
			op := ULE
			if x.op == SLT {
				op = SLE
			}
			return result(TotalOrder, p.make(op, Bool(), 0, tm(x.args[1]), tm(x.args[0])))
		}
	case ULE, SLE:
		// Constant right endpoints use ComparisonBound instead, avoiding a
		// cycle with the constant-left negated strict-comparison rule above.
		if y.op != Constant {
			op := ULT
			if n.op == SLE {
				op = SLT
			}
			return result(TotalOrder, p.make(Not, Bool(), 0, p.make(op, Bool(), 0, tm(y), tm(x))))
		}
	case Or:
		for i := 0; i < 2; i++ {
			less, eq := n.args[i], n.args[1-i]
			if (less.op == ULT || less.op == SLT) && eq.op == Equal && (p.eq(less.args[0], eq.args[0]) && p.eq(less.args[1], eq.args[1]) || p.eq(less.args[0], eq.args[1]) && p.eq(less.args[1], eq.args[0])) {
				op := ULE
				if less.op == SLT {
					op = SLE
				}
				return result(TotalOrder, p.make(op, Bool(), 0, tm(less.args[0]), tm(less.args[1])))
			}
			neg, conjunction := n.args[i], n.args[1-i]
			if conjunction.op == And {
				for j := 0; j < 2; j++ {
					condition := conjunction.args[j]
					if neg.op == Not && p.eq(neg.args[0], condition) || condition.op == Not && p.eq(condition.args[0], neg) {
						return result(BooleanPartition, p.make(Not, Bool(), 0, p.make(And, Bool(), 0, tm(condition), p.make(Not, Bool(), 0, tm(conjunction.args[1-j])))))
					}
				}
			}
		}
	case ITE:
		if x.op == Not {
			return result(ConditionalSwap, p.make(ITE, n.sort, 0, tm(x.args[0]), tm(n.args[2]), tm(y)))
		}
		if !n.sort.IsBool() {
			var branches [2]Term
			for i := 0; i < 2; i++ {
				branch := n.args[i+1]
				if branch.op == BoolToBits {
					branches[i] = tm(branch.args[0])
				} else if branch.op == Constant && branch.imm <= 1 {
					branches[i] = p.con(Bool(), branch.imm)
				} else {
					return 0, Term{}, false
				}
			}
			return result(ConditionalBits, p.make(BoolToBits, n.sort, 0, p.make(ITE, Bool(), 0, tm(x), branches[0], branches[1])))
		}
	case Trunc, Extract:
		if x.op == ITE {
			return result(ConditionalProjection, p.make(ITE, n.sort, 0, tm(x.args[0]), p.make(n.op, n.sort, n.imm, tm(x.args[1])), p.make(n.op, n.sort, n.imm, tm(x.args[2]))))
		}
	}
	return 0, Term{}, false
}
