package bitrelation

// conditionalOperation distributes a closed set of total bit-vector operations
// through one conditional operand. Addition/subtraction remain modular; each
// comparison keeps its exact signedness and Boolean result sort. The condition,
// branch ordering, fixed operand and complete operator head are independently
// checked. No branch assumption or variable assignment is introduced.
func (c *checker) conditionalOperation(a, b *node) bool {
	switch a.op {
	case Add, Sub, Equal, ULT, ULE, SLT, SLE:
	default:
		return false
	}
	if a.arity != 2 || a.args[0].sort.IsBool() || b.op != ITE {
		return false
	}
	for position := 0; position < 2; position++ {
		if c.err = c.e.m.tick(); c.err != nil {
			return false
		}
		x := a.args[position]
		if x.op != ITE || !c.eq(x.args[0], b.args[0]) {
			continue
		}
		matches := true
		for arm := 1; arm <= 2; arm++ {
			branch := b.args[arm]
			if !sameHead(a, branch) || !c.eq(branch.args[position], x.args[arm]) || !c.eq(branch.args[1-position], a.args[1-position]) {
				matches = false
				break
			}
		}
		if matches {
			return c.err == nil
		}
	}
	return false
}

// conjunctionContradiction checks that one conjunct and its exact negation
// occur beneath Boolean ANDs. It never descends through OR, ITE or negation:
// a predicate in those positions need not hold when the whole formula holds.
func (c *checker) conjunctionContradiction(a, b *node) bool {
	if a.op != And || !a.sort.IsBool() || !b.sort.IsBool() || !constant(b, 0) {
		return false
	}
	pending := []*node{a}
	var leaves []*node
	seen := map[*node]bool{}
	for len(pending) != 0 {
		if c.err = c.e.m.tick(); c.err != nil {
			return false
		}
		n := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[n] {
			continue
		}
		seen[n] = true
		if n.op == And {
			pending = append(pending, n.args[0], n.args[1])
			continue
		}
		for _, other := range leaves {
			if c.err = c.e.m.tick(); c.err != nil {
				return false
			}
			if n.op == Not && c.eq(n.args[0], other) || other.op == Not && c.eq(other.args[0], n) {
				return c.err == nil
			}
			if c.err != nil {
				return false
			}
		}
		leaves = append(leaves, n)
	}
	return false
}

// signBoundary relates the unsigned lower half to nonnegative two's-complement
// values. The exact half-range bound and zero comparison are both necessary.
func (c *checker) signBoundary(a, b *node) bool {
	if a.op != ULT || b.op != Not || b.args[0].op != SLT {
		return false
	}
	x := a.args[0]
	signedLess := b.args[0]
	return constant(a.args[1], uint64(1)<<(x.sort.width-1)) && c.eq(x, signedLess.args[0]) && constant(signedLess.args[1], 0)
}

// totalOrder uses the total ordering of same-width vectors under one fixed
// interpretation. Strict predicates are never interchanged between signed and
// unsigned orders. Equality's operand order is immaterial, but both operands
// must be exactly those of the strict predicate.
func (c *checker) totalOrder(a, b *node) bool {
	switch a.op {
	case ULE, SLE:
		strict := ULT
		if a.op == SLE {
			strict = SLT
		}
		return b.op == Not && b.args[0].op == strict && c.eq(a.args[0], b.args[0].args[1]) && c.eq(a.args[1], b.args[0].args[0])
	case Not:
		x := a.args[0]
		inclusive := ULE
		if x.op == SLT {
			inclusive = SLE
		} else if x.op != ULT {
			return false
		}
		return b.op == inclusive && c.eq(x.args[0], b.args[1]) && c.eq(x.args[1], b.args[0])
	case Or:
		for i := 0; i < 2; i++ {
			less, equal := a.args[i], a.args[1-i]
			inclusive := ULE
			if less.op == SLT {
				inclusive = SLE
			} else if less.op != ULT {
				continue
			}
			if equal.op != Equal || b.op != inclusive {
				continue
			}
			if !c.eq(less.args[0], b.args[0]) || !c.eq(less.args[1], b.args[1]) {
				continue
			}
			if c.eq(less.args[0], equal.args[0]) && c.eq(less.args[1], equal.args[1]) || c.eq(less.args[0], equal.args[1]) && c.eq(less.args[1], equal.args[0]) {
				return true
			}
		}
	}
	return false
}

// conditionalProjection distributes only total, typed bit projections. Shape
// checking of all three projections fixes widths and Extract offsets; matching
// the exact operation/immediate prevents dropping or changing selected bits.
func (c *checker) conditionalProjection(a, b *node) bool {
	if a.op != Trunc && a.op != Extract {
		return false
	}
	x := a.args[0]
	if x.op != ITE || b.op != ITE || !c.eq(x.args[0], b.args[0]) {
		return false
	}
	for i := 1; i <= 2; i++ {
		branch := b.args[i]
		if branch.op != a.op || branch.imm != a.imm || branch.sort != a.sort || !c.eq(x.args[i], branch.args[0]) {
			return false
		}
	}
	return true
}

// conditionalBits factors a canonical Boolean encoding out of an ITE. An
// arbitrary bit vector is not an encoding: only BoolToBits and exact 0/1
// constants qualify. A one-bit signed extension is not such an encoding either.
func (c *checker) conditionalBits(a, b *node) bool {
	if a.op != ITE || a.sort.IsBool() || b.op != BoolToBits || b.args[0].op != ITE {
		return false
	}
	inner := b.args[0]
	if !c.eq(a.args[0], inner.args[0]) {
		return false
	}
	for i := 1; i <= 2; i++ {
		bits, boolean := a.args[i], inner.args[i]
		if bits.op == BoolToBits {
			if !c.eq(bits.args[0], boolean) {
				return false
			}
			continue
		}
		if bits.op != Constant || bits.imm > 1 || !constant(boolean, bits.imm) {
			return false
		}
	}
	return true
}

// booleanPartition checks !p OR (p AND q) = !(p AND !q). This is a
// two-valued identity, with exact matching of p on both paths. It neither
// assumes a path unreachable nor generalizes a Boolean to arbitrary bits.
func (c *checker) booleanPartition(a, b *node) bool {
	if a.op != Or || b.op != Not || b.args[0].op != And {
		return false
	}
	out := b.args[0]
	if out.args[1].op != Not {
		return false
	}
	for i := 0; i < 2; i++ {
		neg, conjunction := a.args[i], a.args[1-i]
		if conjunction.op != And {
			continue
		}
		for j := 0; j < 2; j++ {
			p := conjunction.args[j]
			complement := neg.op == Not && c.eq(neg.args[0], p) || p.op == Not && c.eq(p.args[0], neg)
			if complement && c.eq(p, out.args[0]) && c.eq(conjunction.args[1-j], out.args[1].args[0]) {
				return true
			}
		}
	}
	return false
}
