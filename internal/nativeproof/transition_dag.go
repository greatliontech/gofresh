package nativeproof

import (
	"bytes"
	"slices"
	"unsafe"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

type transitionNodeState struct {
	scalar    symbolicState
	pointers  [16]TransitionPointer
	memory    map[TransitionLocation]TransitionByte
	preserved Masks
	flags     TransitionFlags
	frames    []TransitionFrame
	thread    TransitionThread
	vectors   TransitionVectors
	direction br.Term
}

// The allowance includes conservative map bucket/slack and per-entry storage,
// not just symbolic byte payload. Arithmetic is checked before allocation.
func (m *transitionChecker) reserveState(n int) error {
	base := int(unsafe.Sizeof(transitionNodeState{})) + 1024
	entry := 2*int(unsafe.Sizeof(TransitionLocation{})+unsafe.Sizeof(TransitionByte{})) + 64
	room := m.limits.LiveStateBytes - m.liveStateBytes
	if n < 0 || room < base || n > (room-base)/entry {
		return refuse(m.pc, "transition-budget", "aggregate live-state bytes")
	}
	m.stateBytes = base + n*entry
	m.liveStateBytes += m.stateBytes
	return nil
}

func (m *transitionChecker) takeState() *transitionNodeState {
	s := &transitionNodeState{m.state, m.pointers, m.memory, m.bound.Preserved, m.bound.Flags, m.frames, m.thread, m.vectors, m.direction}
	m.memory = nil
	return s
}

func (m *transitionChecker) installState(s *transitionNodeState) {
	m.state, m.pointers, m.memory = s.scalar, s.pointers, s.memory
	m.bound.Preserved, m.bound.Flags = s.preserved, s.flags
	m.frames, m.thread = s.frames, s.thread
	m.vectors = s.vectors
	m.direction = s.direction
}

func (m *transitionChecker) copyState(s *transitionNodeState) *transitionNodeState {
	if m.stateBytes > m.limits.LiveStateBytes-m.liveStateBytes {
		m.err = refuse(m.pc, "transition-budget", "aggregate live-state bytes")
		return nil
	}
	m.liveStateBytes += m.stateBytes
	r := *s
	r.memory = make(map[TransitionLocation]TransitionByte, len(s.memory))
	for k, v := range s.memory {
		if !m.tick() {
			return nil
		}
		r.memory[k] = v
	}
	return &r
}

func (m *transitionChecker) mergeState(slot **transitionNodeState, src *transitionNodeState) {
	if *slot == nil {
		*slot = src
		return
	}
	dst := *slot
	defer func() { m.liveStateBytes -= m.stateBytes }()
	if literalBool(src.scalar.path, 0) {
		return
	}
	if literalBool(dst.scalar.path, 0) {
		*slot = src
		return
	}
	if !slices.Equal(dst.frames, src.frames) {
		m.err = refuse(m.pc, "transition-context", "join has incompatible active call frames")
		return
	}
	if dst.thread.FS.Value.Valid() != src.thread.FS.Value.Valid() {
		m.err = refuse(m.pc, "transition-context", "join has incompatible thread state")
		return
	}
	if dst.thread.FS.Value.Valid() {
		dst.thread.FS.Value = m.ite(src.scalar.path, src.thread.FS.Value, dst.thread.FS.Value)
		if dst.thread.FS.Pointer != src.thread.FS.Pointer {
			dst.thread.FS.Pointer = nil
		}
		dst.thread.SelectorPreserved = dst.thread.SelectorPreserved && src.thread.SelectorPreserved
		dst.thread.ContextChanged = dst.thread.ContextChanged || src.thread.ContextChanged
	}
	for r := range dst.pointers {
		if !m.tick() {
			return
		}
		if dst.pointers[r] != src.pointers[r] {
			dst.pointers[r] = nil
		}
		dst.preserved[r] &= src.preserved[r]
	}
	// Iterate the immutable root inventory, not randomized map order, so term
	// construction and resource consumption are deterministic across partitions.
	for _, root := range m.bound.InitialMemory {
		if !m.tick() {
			return
		}
		k := root.TransitionLocation
		a, b := dst.memory[k], src.memory[k]
		a.Value = m.ite(src.scalar.path, b.Value, a.Value)
		if a.Pointer != b.Pointer || a.PointerLane != b.PointerLane {
			a.Pointer, a.PointerLane = nil, 0
		}
		dst.memory[k] = a
	}
	d := []*TransitionFlag{&dst.flags.CF, &dst.flags.OF, &dst.flags.SF, &dst.flags.ZF, &dst.flags.AF, &dst.flags.PF}
	s := []TransitionFlag{src.flags.CF, src.flags.OF, src.flags.SF, src.flags.ZF, src.flags.AF, src.flags.PF}
	for j, a := range d {
		if !m.tick() {
			return
		}
		b := s[j]
		a.Preserved = a.Preserved && b.Preserved
		a.Defined = a.Defined && b.Defined
		if a.Defined && a.Value.Valid() && b.Value.Valid() {
			a.Value = m.ite(src.scalar.path, b.Value, a.Value)
		} else {
			a.Value = br.Term{}
		}
	}
	if m.face.Conditions.SSE == SSEModel {
		m.mergeSSEVectors(&dst.vectors, src.vectors, src.scalar.path)
	}
	dst.direction = m.ite(src.scalar.path, src.direction, dst.direction)
	m.merge(&dst.scalar, src.scalar)
}

// Match the predecessor's owned witness exactly, including every excluded
// terminal. Only its common unexecuted cut may gain outgoing edges. New suffix
// edges cannot enter old executed/excluded occurrences, even at equal addresses.
func (m *transitionChecker) continuationStart(g *graph, prior checkedTransition) (int, error) {
	old := prior.bound.Boundary
	if len(prior.witness.Nodes) != len(prior.bound.Instructions)+len(prior.bound.ExcludedBoundaries)+1 || len(prior.exclusions) != len(prior.bound.ExcludedBoundaries) {
		return 0, refuse(old.PC, "transition-continuation", "predecessor coverage differs")
	}
	covered := map[TransitionOccurrenceID]bool{old.ID: true}
	for _, ins := range prior.bound.Instructions {
		if !m.tick() {
			return 0, m.err
		}
		idx, ok := g.byID[ins.ID]
		if !ok || covered[ins.ID] {
			return 0, refuse(ins.Start, "transition-continuation", "predecessor occurrence coverage differs")
		}
		n := g.nodes[idx]
		if n.pc != ins.Start || n.pc+uint64(n.size) != ins.End || n.activation != ins.Context || n.boundary != boundaryNone {
			return 0, refuse(ins.Start, "transition-continuation", "predecessor occurrence relation differs")
		}
		covered[ins.ID] = true
	}
	for j, b := range prior.bound.ExcludedBoundaries {
		if !m.tick() {
			return 0, m.err
		}
		left, right := prior.exclusions[j].Roots()
		if !prior.exclusions[j].Valid() || left != b.Guard || !literalBool(right, 0) || right.Sort() != br.Bool() {
			return 0, refuse(b.PC, "transition-continuation", "invalid retained exclusion")
		}
		idx, ok := g.byID[b.ID]
		if !ok || covered[b.ID] {
			return 0, refuse(b.PC, "transition-continuation", "excluded occurrence coverage differs")
		}
		n := g.nodes[idx]
		i, raw, err := decodeBytes(m.im, b.PC)
		if err != nil {
			return 0, err
		}
		kind := boundaryUnsupported
		if b.Frontier {
			kind = boundaryFrontier
		}
		if n.pc != b.PC || n.activation != b.Context || n.boundary != kind || i != b.Instruction || !bytes.Equal(raw, b.Bytes) {
			return 0, refuse(b.PC, "transition-continuation", "excluded boundary differs")
		}
		covered[b.ID] = true
	}
	i, raw, err := decodeBytes(m.im, old.PC)
	if err != nil {
		return 0, err
	}
	if i != old.Instruction || !bytes.Equal(raw, old.Bytes) {
		return 0, refuse(old.PC, "transition-continuation", "retained boundary bytes differ")
	}
	if m.witness.Root != prior.witness.Root {
		return 0, refuse(old.PC, "transition-continuation", "root occurrence changed")
	}
	before := make(map[TransitionOccurrenceID]bool, len(prior.witness.Nodes))
	for _, n := range prior.witness.Nodes {
		if !m.tick() {
			return 0, m.err
		}
		idx, exists := g.byID[n.ID]
		if !exists {
			return 0, refuse(n.PC, "transition-continuation", "predecessor occurrence absent")
		}
		full := m.witness.Nodes[idx]
		if n.PC != full.PC || n.Size != full.Size {
			return 0, refuse(n.PC, "transition-continuation", "predecessor extent changed")
		}
		if n.ID == old.ID {
			if g.nodes[idx].activation != old.Context {
				return 0, refuse(n.PC, "transition-continuation", "cut activation changed")
			}
			continue
		}
		if n.Expanded != full.Expanded || n.Frontier != full.Frontier || !slices.Equal(n.Successors, full.Successors) {
			return 0, refuse(n.PC, "transition-continuation", "predecessor choices or edges changed")
		}
		before[n.ID] = true
	}
	order := make([]int, 0, len(g.order))
	for _, idx := range g.order {
		if !m.tick() {
			return 0, m.err
		}
		n := g.nodes[idx]
		if before[n.id] {
			order = append(order, idx)
			continue
		}
		for _, next := range n.next[:n.count] {
			if before[g.nodes[next].id] {
				return 0, refuse(n.pc, "transition-continuation", "suffix re-enters old occurrence")
			}
		}
	}
	start := len(order)
	for _, idx := range g.order {
		if !m.tick() {
			return 0, m.err
		}
		if !before[g.nodes[idx].id] {
			order = append(order, idx)
		}
	}
	if start >= len(order) || g.nodes[order[start]].id != old.ID {
		return 0, refuse(old.PC, "transition-continuation", "cut does not separate prefix and suffix")
	}
	g.order = order
	return start, nil
}
