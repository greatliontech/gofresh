package nativeproof

import br "github.com/greatliontech/gofresh/internal/bitrelation"

// Input copies precede callbacks, but still consume the same cumulative work
// budget. Subtract before adding so even a hostile inventory cannot wrap it.
func transitionCopyWork(work *int, limit int, counts ...int) error {
	for _, n := range counts {
		if n < 0 || *work < 0 || *work > limit || n > limit-*work {
			return refuse(0, "relation-budget", "transition copy work budget")
		}
		*work += n
	}
	return nil
}

func captureTransitionProposal(p TransitionProposal, l TransitionLimits, work *int) (TransitionProposal, error) {
	if len(p.Nodes) > l.Instructions {
		return TransitionProposal{}, refuse(0, "transition-budget", "input inventory exceeds limits")
	}
	if err := transitionCopyWork(work, l.Work, len(p.Nodes)); err != nil {
		return TransitionProposal{}, err
	}
	for _, n := range p.Nodes {
		if len(n.Successors) > 1 {
			return TransitionProposal{}, refuse(n.PC, "transition-proposal", "unsupported successor count")
		}
		if err := transitionCopyWork(work, l.Work, len(n.Successors)); err != nil {
			return TransitionProposal{}, err
		}
	}
	p.Nodes = append([]Node(nil), p.Nodes...)
	for j := range p.Nodes {
		p.Nodes[j].Successors = append([]uint64(nil), p.Nodes[j].Successors...)
	}
	return p, nil
}

func (m *transitionChecker) inherit(prior checkedTransition) error {
	b := prior.bound
	// Charge every element copied into the successor's proof, including the
	// immutable root projections. Only expression nodes and image bytes share
	// immutable ownership; no predecessor container or construction arena survives.
	for _, n := range []int{len(b.Interface.Regions), len(b.Interface.ImageRegions), len(b.Interface.Words), len(b.ExcludedOrigins), len(b.InitialMemory), len(b.Words), len(b.Memory), len(b.Instructions), len(b.Accesses), len(b.Boundary.Bytes), 16} {
		for range n {
			if !m.tick() {
				return m.err
			}
		}
	}
	m.bound = cloneTransitionBound(b)
	m.face = m.bound.Interface
	m.lo, m.hi, _ = originRange(m.face.Origin)
	m.builder = br.NewBuilder(m.limits.Nodes)
	importRoot := func(t br.Term) error {
		if !t.Valid() {
			return nil // absent provenance or an intentionally unprojected flag
		}
		return m.importTerm(t)
	}
	for r, v := range b.Registers {
		m.state.regs[r], m.pointers[r] = v.Value, v.Pointer
		for _, root := range []br.Term{b.InitialRegisters[r], v.Value} {
			if err := importRoot(root); err != nil {
				return err
			}
		}
	}
	for _, w := range b.Words {
		if err := importRoot(w.Value); err != nil {
			return err
		}
	}
	for _, memory := range [][]TransitionByte{b.InitialMemory, b.Memory} {
		for _, v := range memory {
			if !m.tick() {
				return m.err
			}
			if err := importRoot(v.Value); err != nil {
				return err
			}
		}
	}
	// Every Stack arm retains this same root term by construction. Image arms
	// contain only owned mapping coordinates and introduce no expression roots.
	if err := importRoot(b.Origin); err != nil {
		return err
	}
	m.state.flags = prior.flags
	for _, root := range prior.flags {
		if err := importRoot(root); err != nil {
			return err
		}
	}
	for _, f := range []TransitionFlag{b.Flags.CF, b.Flags.OF, b.Flags.SF, b.Flags.ZF, b.Flags.AF, b.Flags.PF} {
		if err := importRoot(f.Value); err != nil {
			return err
		}
	}
	m.truth, m.falsity = m.con(br.Bool(), 1), m.con(br.Bool(), 0)
	if !m.tick() {
		return m.err
	}
	m.memory = make(map[TransitionLocation]TransitionByte, len(b.Memory))
	for _, v := range b.Memory {
		if !m.tick() {
			return m.err
		}
		m.memory[v.TransitionLocation] = v
	}
	return m.err
}
