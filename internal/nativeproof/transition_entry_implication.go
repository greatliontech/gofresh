package nativeproof

import br "github.com/greatliontech/gofresh/internal/bitrelation"

// entryWordPredicate retains the declared strict upper bound and its implication
// at the original stack origin. validateEntryRelations checked nonwrapping,
// canonical S+offset for every admitted S. For a negative offset, unsigned
// S+offset < S therefore holds throughout that domain. This implication is a
// native origin-domain inference, not a second caller premise or a fact about a
// sampled satisfying valuation. In particular, it cannot be used in reverse to
// infer space for a child from the parent's weaker stack check.
func (m *transitionChecker) entryWordPredicate(word br.Term, offset int64) br.Term {
	upper := m.bound.Origin
	if offset != 0 {
		upper = m.binary(br.Add, upper, m.con(br.Bits(64), uint64(offset)))
	}
	predicate := m.compare(br.ULT, word, upper)
	if offset < 0 {
		predicate = m.and(predicate, m.compare(br.ULT, word, m.bound.Origin))
	}
	return predicate
}
