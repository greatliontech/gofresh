package nativeproof

import br "github.com/greatliontech/gofresh/internal/bitrelation"

// Entry relations have a closed positive-upper-bound grammar. Their storage,
// construction and validation belong to the same root/continuation allowances.
func (m *transitionChecker) reserveEntryRelations() error {
	n := len(m.face.EntryImagePointers) + len(m.face.EntryWordUpperBounds)
	const bytes = 64 // declarations and conservative backing-array slack
	if n > (m.limits.LiveStateBytes-m.liveStateBytes)/bytes {
		return refuse(m.pc, "transition-budget", "entry relation storage")
	}
	m.liveStateBytes += n * bytes
	return nil
}

func (m *transitionChecker) validateEntryRelations() error {
	if m.err != nil {
		return m.err
	}
	if len(m.face.EntryImagePointers) == 0 && len(m.face.EntryWordUpperBounds) == 0 {
		return nil
	}
	if !m.root.region {
		return refuse(m.pc, "transition-entry", "entry relations require a conditional-region root")
	}
	if err := m.reserveEntryRelations(); err != nil {
		return err
	}
	var seen [16]bool
	for _, p := range m.face.EntryImagePointers {
		if !m.tick() {
			return m.err
		}
		if p.Register > R15 || p.Register == RSP || seen[p.Register] {
			return refuse(m.pc, "transition-entry", "entry pointer requires a unique full GPR other than RSP")
		}
		seen[p.Register] = true
		if err := m.entryReadable(p.Address, 1); err != nil {
			return err
		}
	}
	if len(m.face.EntryWordUpperBounds) == 0 {
		return nil
	}
	origin, err := m.greatestEntryOrigin()
	if err != nil {
		return err
	}
	for _, w := range m.face.EntryWordUpperBounds {
		if !m.tick() {
			return m.err
		}
		if err := m.entryReadable(w.Address, 8); err != nil {
			return err
		}
		// This is a numeric upper bound, not a pointer or a memory grant. Its
		// offset need not lie in the pointer envelope, but must be representable
		// at both rounded extremes, before any image-page exclusions.
		if !m.originOffsetCanonical(w.OriginOffset) {
			return refuse(m.pc, "transition-entry", "entry upper bound wraps or is noncanonical for an origin")
		}
		var word uint64
		for lane := uint64(0); lane < 8; lane++ {
			v, err := m.entryWitnessByte(w.Address + lane)
			if err != nil {
				return err
			}
			word |= uint64(v) << (8 * lane)
		}
		upper, _ := relative(origin, w.OriginOffset)
		if word >= upper {
			return refuse(m.pc, "transition-entry", "entry relations have no coherent admissible byte valuation")
		}
	}
	return m.err
}

func (m *transitionChecker) entryReadable(address, width uint64) error {
	end, ok := plus(address, width)
	if !ok || end > 1<<47 || !m.imagePermission(Span{address, end}, FrameRead) {
		if m.err != nil {
			return m.err
		}
		return refuse(m.pc, "transition-entry", "entry location lacks its full declared readable image extent")
	}
	return nil
}

// Exclusions are sorted by start, but may overlap. Descending through them
// rounds below each forbidden component without sampling or iterating origins.
func (m *transitionChecker) greatestEntryOrigin() (uint64, error) {
	s := m.hi
	for j := len(m.bound.ExcludedOrigins) - 1; j >= 0; j-- {
		if !m.tick() {
			return 0, m.err
		}
		x := m.bound.ExcludedOrigins[j]
		if s < x.Start || s >= x.End {
			continue
		}
		if x.Start == 0 {
			return 0, refuse(m.pc, "transition-entry", "no admissible witness origin")
		}
		last := x.Start - 1
		delta := (last - m.face.Origin.Residue) & (m.face.Origin.Modulus - 1)
		if delta > last || last-delta < m.lo {
			return 0, refuse(m.pc, "transition-entry", "no admissible witness origin")
		}
		s = last - delta
	}
	return s, nil
}

// This defines ONE coherent candidate byte valuation, including overlapping
// words: immutable executable bytes have their actual code-integrity value;
// every otherwise free current byte is zero. Readonly non-executable bytes have
// no loading-value premise in a conditional region and remain free. Executable
// tails without file backing cannot supply a known integrity value and refuse.
// The incoming return control word has its explicit fixed value in the disjoint
// stack namespace. Page exclusions and NoHiddenAliases establish that separation
// from image antecedents; validation refuses overlapping arbitrary word inputs.
// Future fixed-byte entry forms must join this valuation, not pick independent
// per-word witnesses. Free witness bytes never initialize symbolic theorem memory.
//
// With only positive unsigned upper bounds, minimizing every free byte minimizes
// every overlapping word simultaneously; the greatest admissible origin maximizes
// every checked nonwrapping upper bound. Thus this candidate establishes joint
// nonvacuity. Universal transfer still ranges over ALL states satisfying the
// retained predicate; neither this candidate nor its origin escapes into evidence.
func (m *transitionChecker) entryWitnessByte(address uint64) (byte, error) {
	if !m.tick() {
		return 0, m.err
	}
	index, err := m.imageLoad(Span{address, address + 1}, false)
	if err != nil {
		return 0, err
	}
	load := m.im.loads[index]
	if !load.executable {
		return 0, nil
	}
	delta := address - load.va
	if delta >= load.filesz {
		return 0, refuse(m.pc, "transition-entry", "executable entry byte has unknown integrity contents")
	}
	return m.im.data[load.off+delta], nil
}

func (m *transitionChecker) initialEntryRelations() error {
	predicate := m.truth
	for _, p := range m.face.EntryImagePointers {
		load, err := m.imageLoad(Span{p.Address, p.Address + 1}, false)
		if err != nil {
			return err
		}
		m.pointers[p.Register] = m.bound.Geometry.imagePointer(load, p.Address)
		// Keep the original entry variable and preservation mask. Provenance
		// agrees with its bits under this explicit equality, not by replacing
		// the input with a fabricated register constant or a machine write.
		predicate = m.and(predicate, m.compare(br.Equal, m.bound.InitialRegisters[p.Register], m.con(br.Bits(64), p.Address)))
	}
	for _, w := range m.face.EntryWordUpperBounds {
		if !m.tick() {
			return m.err
		}
		word := m.memoryValue(m.bound.Geometry.imageLocation(int64(w.Address)), 8)
		predicate = m.and(predicate, m.entryWordPredicate(word.Value, w.OriginOffset))
	}
	m.bound.EntryPredicate = predicate
	m.state.path = predicate
	return m.err
}
