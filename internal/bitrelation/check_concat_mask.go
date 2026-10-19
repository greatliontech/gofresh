package bitrelation

// concatMask checks AND(concat(low, high), mask) field by field. Concat's typed
// shape establishes nonempty fields whose widths sum to at most 64, so its low
// width is strictly below 64. No shifted mask bit can cross the checked split.
// This recognizer neither builds the proposer's replacement nor trusts its split.
func (c *checker) concatMask(a, b *node) bool {
	if a.op != BitAnd || a.args[0].op != Concat || a.args[1].op != Constant || b.op != Concat {
		return false
	}
	joined, bits := a.args[0], a.args[1].imm
	low, high := joined.args[0], joined.args[1]
	lo, hi := b.args[0], b.args[1]
	if lo.op != BitAnd || hi.op != BitAnd || lo.sort != low.sort || hi.sort != high.sort {
		return false
	}
	return c.eq(lo.args[0], low) && c.eq(hi.args[0], high) &&
		constant(lo.args[1], bits&mask(low.sort.width)) && constant(hi.args[1], bits>>low.sort.width)
}
