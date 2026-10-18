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
	if len(p.Nodes) > l.Instructions || len(p.Expansions) > l.Instructions {
		return TransitionProposal{}, refuse(0, "transition-budget", "input inventory exceeds limits")
	}
	if err := transitionCopyWork(work, l.Work, len(p.Nodes), len(p.Expansions)); err != nil {
		return TransitionProposal{}, err
	}
	for _, n := range p.Nodes {
		if len(n.Successors) > 2 {
			return TransitionProposal{}, refuse(n.PC, "transition-proposal", "unsupported successor count")
		}
		if err := transitionCopyWork(work, l.Work, len(n.Successors), len(n.Context)); err != nil {
			return TransitionProposal{}, err
		}
	}
	for _, e := range p.Expansions {
		if err := transitionCopyWork(work, l.Work, len(e.Context)); err != nil {
			return TransitionProposal{}, err
		}
	}
	p.Expansions = append([]TransitionExpansion(nil), p.Expansions...)
	p.Nodes = append([]Node(nil), p.Nodes...)
	for j := range p.Nodes {
		p.Nodes[j].Successors = append([]uint64(nil), p.Nodes[j].Successors...)
	}
	return p, nil
}

func (m *transitionChecker) inherit(prior checkedTransition) error {
	b := prior.bound
	if len(prior.exclusions) != len(b.ExcludedBoundaries) {
		return refuse(m.pc, "transition-predecessor", "incomplete exclusions")
	}
	for _, e := range b.ExcludedBoundaries {
		if err := m.reserveExclusion(); err != nil {
			return err
		}
		if !m.tick() {
			return m.err
		}
		for range e.Bytes {
			if !m.tick() {
				return m.err
			}
		}
	}
	// Charge every element copied into the successor's proof, including the
	// immutable root projections. Only expression nodes and image bytes share
	// immutable ownership; no predecessor container or construction arena survives.
	for _, n := range []int{len(b.Interface.Regions), len(b.Interface.ImageRegions), len(b.Interface.Words), len(b.ExcludedOrigins), len(b.InitialMemory), len(b.Words), len(b.Memory), len(b.Instructions), len(b.Accesses), len(b.PrimitiveEffects), len(b.Boundary.Bytes), len(b.Frames), len(b.Expansions), len(b.Abstractions), len(prior.justifications), 16} {
		for range n {
			if !m.tick() {
				return m.err
			}
		}
	}
	for _, frame := range b.Frames {
		if err := transitionCopyWork(&m.work, m.limits.Work, len(frame.Context)); err != nil {
			return err
		}
	}
	for _, e := range b.Expansions {
		if err := transitionCopyWork(&m.work, m.limits.Work, len(e.Context)); err != nil {
			return err
		}
	}
	m.bound = cloneTransitionBound(b)
	m.frames, m.thread = m.bound.Frames, m.bound.Thread
	m.face = m.bound.Interface
	m.lo, m.hi, _ = originRange(m.face.Origin)
	m.builder = br.NewBuilder(m.limits.Nodes)
	importRoot := func(t br.Term) error {
		if !t.Valid() {
			return nil // absent provenance or an intentionally unprojected flag
		}
		return m.importTerm(t)
	}
	for _, e := range prior.justifications {
		if err := m.reserveExclusion(); err != nil {
			return err
		}
		left, right := e.Roots()
		if !e.Valid() || !literalBool(right, 0) {
			return refuse(m.pc, "transition-predecessor", "invalid retained side-condition proof")
		}
		for _, root := range []br.Term{left, right} {
			if err := importRoot(root); err != nil {
				return err
			}
		}
		m.justifications = append(m.justifications, e)
	}
	for _, root := range []br.Term{b.InitialFS, b.Thread.FS.Value} {
		if err := importRoot(root); err != nil {
			return err
		}
	}
	for _, frame := range b.Frames {
		if err := importRoot(frame.Slot.Origin); err != nil {
			return err
		}
	}
	for _, a := range b.Abstractions {
		if !m.tick() {
			return m.err
		}
		for _, root := range []br.Term{a.Value, a.Predicates.CF, a.Predicates.ZF, a.Predicates.SFXorOF} {
			if err := importRoot(root); err != nil {
				return err
			}
		}
	}
	for j, e := range prior.exclusions {
		if !m.tick() {
			return m.err
		}
		left, right := e.Roots()
		for _, root := range []br.Term{b.ExcludedBoundaries[j].Guard, left, right} {
			if err := importRoot(root); err != nil {
				return err
			}
		}
		m.exclusions = append(m.exclusions, e)
	}
	if !prior.coverageGuard.Valid() || prior.coverageGuard != b.CutGuard || b.CutGuard.Sort() != br.Bool() {
		return refuse(m.pc, "transition-predecessor", "missing exact cut reach proof")
	}
	if err := m.admitInitialization(); err != nil {
		return err
	}
	for _, root := range []br.Term{b.InitialPredicates.CF, b.InitialPredicates.ZF, b.InitialPredicates.SFXorOF, b.CutGuard} {
		if err := importRoot(root); err != nil {
			return err
		}
	}
	for _, occurrence := range b.Instructions {
		if err := importRoot(occurrence.Guard); err != nil {
			return err
		}
	}
	m.state.path, m.state.present = b.CutGuard, true
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
	for _, a := range b.Accesses {
		if err := importRoot(a.Value); err != nil {
			return err
		}
	}
	for _, effect := range b.PrimitiveEffects {
		// The opaque predecessor was constructed under this complete rule identity.
		// Import every dependency, including results absent from current state.
		var roots []br.Term
		switch e := effect.(type) {
		case CPUIDEffect:
			roots = []br.Term{e.Leaf, e.Subleaf, e.ResultsEAX, e.ResultsEBX, e.ResultsECX, e.ResultsEDX}
		case ArchSetFSEffect:
			roots = []br.Term{e.Number, e.Operation, e.Base, e.Valid, e.Result, e.BeforeFS, e.AfterFS}
		case LockedCompareExchange64Effect:
			roots = []br.Term{e.Before, e.Compare, e.Replacement, e.After, e.Accumulator, e.Success}
		default:
			return refuse(m.pc, "transition-predecessor", "unknown retained primitive")
		}
		for _, root := range roots {
			if err := importRoot(root); err != nil {
				return err
			}
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
	if err := m.reserveState(len(b.Memory)); err != nil {
		return err
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
