package nativeproof

import (
	"errors"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

// tryFalse distinguishes an incomplete proof search from exhausted/cancelled
// work. Only the former can leave precision unknown; no resource failure falls
// back to an accepted abstraction or boundary. Successful transfer side proofs
// remain owned dependencies alongside structural exclusions.
func (m *transitionChecker) tryFalse(t br.Term) (bool, error) {
	w, err := m.proveFalseGuard(t)
	if err == nil {
		if err := m.reserveExclusion(); err != nil {
			return false, err
		}
		m.justifications = append(m.justifications, w)
		return true, nil
	}
	var r *Refusal
	if errors.As(err, &r) && r.Premise == "transition-guard" && m.err == nil {
		return false, nil
	}
	return false, err
}

// proveFalseGuard submits the independently derived BOOL root, never a proposed guard.
// Both search and checking tick the root's cumulative meter. Their temporary
// graphs/certificates have conservative aggregate storage allowances; imported
// candidate terms also obey the root node/depth bounds before they can authorize.
func (m *transitionChecker) proveFalseGuard(guard br.Term) (witness br.Witness, failure error) {
	defer func() {
		if failure == nil {
			return
		}
		if m.err != nil {
			failure = m.err
			return
		}
		var r *br.Refusal
		if errors.As(failure, &r) {
			premise := "transition-guard"
			if r.Code == br.Budget {
				premise = "transition-budget"
			}
			failure = refuse(m.pc, premise, failure.Error())
		}
	}()
	if guard.Sort() != br.Bool() {
		return br.Witness{}, refuse(m.pc, "transition-guard", "guard is not BOOL")
	}
	right := m.falsity
	if !m.tick() {
		return br.Witness{}, m.err
	}
	room := m.limits.LiveStateBytes - m.liveStateBytes
	// Includes search maps, equality pairs, proof copies and graph traversal stacks.
	capacity := min(m.limits.Nodes, m.limits.Work-m.work, room/4096)
	if capacity <= 0 {
		return br.Witness{}, refuse(m.pc, "transition-budget", "guard proof storage/work")
	}
	l := br.Limits{Nodes: capacity, Steps: capacity, Work: min(m.limits.Work-m.work, capacity*8)}
	m.liveStateBytes += capacity * 4096
	defer func() { m.liveStateBytes -= capacity * 4096 }()
	ctx := &relationContext{Context: m.ctx, meter: m.valueBuilder}
	p, err := br.Propose(ctx, guard, right, l)
	if err != nil {
		return br.Witness{}, err
	}
	for _, step := range p.Steps {
		for _, root := range []br.Term{step.Left, step.Right} {
			if err := m.importTerm(root); err != nil {
				return br.Witness{}, err
			}
		}
	}
	w, err := br.Check(ctx, guard, right, p, l)
	if err != nil {
		return br.Witness{}, err
	}
	left, actualRight := w.Roots()
	if left != guard || actualRight != right || !w.Valid() {
		return br.Witness{}, refuse(m.pc, "transition-guard", "checked endpoints differ")
	}
	return w, nil
}

// Retained metadata includes the structural decode, up to fifteen owned bytes,
// an opaque witness and conservative slice growth slack. Expression nodes are
// separately bounded by the shared node budget and imported dependency union.
func (m *transitionChecker) reserveExclusion() error {
	const bytes = 1024
	if bytes > m.limits.LiveStateBytes-m.liveStateBytes {
		return refuse(m.pc, "transition-budget", "excluded-boundary storage")
	}
	m.liveStateBytes += bytes
	return nil
}
