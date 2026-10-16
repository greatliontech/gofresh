package bitrelation

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
