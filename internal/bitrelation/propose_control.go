package bitrelation

// controlRewrite proposes oriented order/path/projection rules. Checker rule
// recognition is separate: these patterns are search hints, never premises.
func (p *proposer) controlRewrite(t Term) (Rule, Term, bool) {
	n := t.n
	tm := func(n *node) Term { return Term{n} }
	result := func(rule Rule, t Term) (Rule, Term, bool) { return rule, t, true }
	x, y := n.args[0], n.args[1]
	switch n.op {
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
