package nativeproof

import br "github.com/greatliontech/gofresh/internal/bitrelation"

// originOffsetCanonical checks a numeric S+offset over the entire original
// rounded domain, before image-page exclusions. It grants no address capability
// and deliberately does not require containment in the pointer envelope.
func (m *transitionChecker) originOffsetCanonical(offset int64) bool {
	lo, a := relative(m.lo, offset)
	hi, b := relative(m.hi, offset)
	return a && b && lo < 1<<47 && hi < 1<<47
}

// currentOriginOperand recognizes the closed pointer/value invariant, not a
// scalar equality or opaque entry-value lineage. Foreign origins are outside
// this rule and leave ordinary scalar reasoning available.
func (m *transitionChecker) currentOriginOperand(v TransitionValue) (OriginPointer, bool) {
	p, ok := v.Pointer.(OriginPointer)
	return p, ok && v.Value.Sort() == br.Bits(64) && m.bound.Origin.Valid() && p.Origin == m.bound.Origin
}

// refineOriginCompare refines an actual full-width CMP after its normal flag
// calculation and predicate installation. The checked pointer/value invariant
// makes offset order equivalent to both unsigned and signed value order on the
// original low-canonical domain. This is not an unconditional bitrelation fact.
// Other exact instruction flags and all definedness remain untouched.
func (m *transitionChecker) refineOriginCompare(left, right TransitionValue) (bool, error) {
	if !m.tick() {
		return false, m.err
	}
	a, aOK := m.currentOriginOperand(left)
	b, bOK := m.currentOriginOperand(right)
	if !aOK || !bOK {
		return false, nil
	}
	if err := m.offset(a.Offset); err != nil {
		return false, err
	}
	if err := m.offset(b.Offset); err != nil {
		return false, err
	}
	less, equal := m.falsity, m.falsity
	// Do not subtract signed offsets: their difference need not be representable.
	if a.Offset < b.Offset {
		less = m.truth
	}
	if a.Offset == b.Offset {
		equal = m.truth
	}
	m.bound.Flags.CF.Value, m.bound.Flags.ZF.Value = less, equal
	m.setPredicates(TransitionPredicates{CF: less, ZF: equal, SFXorOF: less})
	return true, m.err
}

// originWordUpperBound decides word < S+upperOffset from current full-word
// provenance. A known false result is distinct from an inapplicable rule; the
// latter leaves scalar premise discharge available. The numeric right operand
// may lie outside the address envelope and never becomes a pointer.
func (m *transitionChecker) originWordUpperBound(word TransitionValue, upperOffset int64) (holds, known bool, err error) {
	if !m.tick() {
		return false, false, m.err
	}
	p, ok := m.currentOriginOperand(word)
	if !ok {
		return false, false, nil
	}
	if err := m.offset(p.Offset); err != nil {
		return false, false, err
	}
	if !m.originOffsetCanonical(upperOffset) {
		return false, false, refuse(m.pc, "transition-origin", "numeric upper bound wraps or is noncanonical for an admitted origin")
	}
	return p.Offset < upperOffset, true, nil
}
