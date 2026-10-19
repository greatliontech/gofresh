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
	s := &transitionNodeState{m.state, m.pointers, m.memory, m.bound.Preserved, m.bound.Flags, m.frames, m.thread, m.vectors}
	m.memory = nil
	return s
}

func (m *transitionChecker) installState(s *transitionNodeState) {
	m.state, m.pointers, m.memory = s.scalar, s.pointers, s.memory
	m.bound.Preserved, m.bound.Flags = s.preserved, s.flags
	m.frames, m.thread = s.frames, s.thread
	m.vectors = s.vectors
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
	m.merge(&dst.scalar, src.scalar)
}

// Recover the prefix from the owned bytes, stopping at C, then check its exact
// membership and edges in root->D, including every proved-false terminal.
// Reaching D in the stopped walk is a bypass. Full-graph occupancy/cycle checks exclude overlaps
// and suffix re-entry. No second authoritative graph survives the call.
func (m *transitionChecker) continuationStart(g *graph, prior checkedTransition) (int, error) {
	old := prior.bound.Boundary
	prefix, err := m.graphPrefix(old.PC, true)
	if err != nil {
		return 0, err
	}
	if len(prior.exclusions) != len(prior.bound.ExcludedBoundaries) || len(prefix.nodes) != len(prior.bound.Instructions)+len(prior.exclusions)+1 {
		return 0, refuse(old.PC, "transition-continuation", "predecessor coverage differs")
	}
	coverage := make(map[programPoint]Span, len(prior.bound.Instructions))
	for _, occurrence := range prior.bound.Instructions {
		if !m.tick() {
			return 0, m.err
		}
		key := programPoint{occurrence.Start, occurrence.Context}
		if _, exists := coverage[key]; exists {
			return 0, refuse(old.PC, "transition-continuation", "duplicate predecessor occurrence")
		}
		coverage[key] = occurrence.Span
	}
	excluded := make(map[programPoint]ExcludedBoundary, len(prior.exclusions))
	for j, e := range prior.exclusions {
		if !m.tick() {
			return 0, m.err
		}
		b := prior.bound.ExcludedBoundaries[j]
		left, right := e.Roots()
		if !e.Valid() || left != b.Guard || !literalBool(right, 0) || right.Sort() != br.Bool() {
			return 0, refuse(b.PC, "transition-continuation", "invalid retained exclusion")
		}
		key := programPoint{b.PC, b.Context}
		if _, exists := coverage[key]; exists {
			return 0, refuse(b.PC, "transition-continuation", "duplicate excluded boundary")
		}
		coverage[key] = Span{b.PC, b.PC + uint64(len(b.Bytes))}
		excluded[key] = b
	}
	for _, n := range prefix.nodes {
		if !m.tick() {
			return 0, m.err
		}
		key := n.point()
		idx, exists := g.byPoint[key]
		if !exists {
			return 0, refuse(n.pc, "transition-continuation", "predecessor absent from full graph")
		}
		full := g.nodes[idx]
		if full.size != n.size {
			return 0, refuse(n.pc, "transition-continuation", "predecessor extent differs")
		}
		if key == (programPoint{old.PC, old.Context}) {
			continue
		}
		if n.boundary == boundaryCut {
			return 0, refuse(n.pc, "transition-continuation", "predecessor cut activation differs")
		}
		wantBoundary := boundaryNone
		if b, exists := excluded[key]; exists {
			wantBoundary = boundaryUnsupported
			i, raw, err := decodeBytes(m.im, n.pc)
			if err != nil {
				return 0, err
			}
			if i != b.Instruction || !bytes.Equal(raw, b.Bytes) {
				return 0, refuse(n.pc, "transition-continuation", "excluded bytes differ")
			}
		}
		if coverage[key] != (Span{n.pc, n.pc + uint64(n.size)}) || full.boundary != wantBoundary || n.boundary != wantBoundary || n.count != full.count {
			return 0, refuse(n.pc, "transition-continuation", "predecessor membership or terminal differs")
		}
		for edge, next := range n.next[:n.count] {
			if prefix.nodes[next].point() != g.nodes[full.next[edge]].point() {
				return 0, refuse(n.pc, "transition-continuation", "predecessor edge differs")
			}
		}
	}
	i, encoded, err := decodeBytes(m.im, old.PC)
	if err != nil {
		return 0, err
	}
	if i != old.Instruction || !bytes.Equal(encoded, old.Bytes) {
		return 0, refuse(old.PC, "transition-continuation", "predecessor boundary differs")
	}
	// Dead terminals may sort after C without executing there. Partition the
	// topological order by the reconstructed complete prefix, while refusing every
	// suffix edge back into it. This preserves all incoming control dependencies.
	order := make([]int, 0, len(g.order))
	for _, idx := range g.order {
		if !m.tick() {
			return 0, m.err
		}
		point := g.nodes[idx].point()
		if _, before := coverage[point]; before {
			order = append(order, idx)
			continue
		}
		for _, next := range g.nodes[idx].next[:g.nodes[idx].count] {
			if _, before := coverage[g.nodes[next].point()]; before {
				return 0, refuse(point.pc, "transition-continuation", "suffix re-enters prefix")
			}
		}
	}
	start := len(order)
	for _, idx := range g.order {
		if !m.tick() {
			return 0, m.err
		}
		if _, before := coverage[g.nodes[idx].point()]; !before {
			order = append(order, idx)
		}
	}
	if start >= len(order) || g.nodes[order[start]].point() != (programPoint{old.PC, old.Context}) {
		return 0, refuse(old.PC, "transition-continuation", "cut does not separate prefix and suffix")
	}
	g.order = order
	return start, nil
}
