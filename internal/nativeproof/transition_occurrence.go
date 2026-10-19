package nativeproof

import (
	"context"
	"slices"

	"golang.org/x/arch/x86/x86asm"
)

// reserveOccurrences covers sparse indices, edges, occupancy, topological work,
// activation ancestry and the retained owned witness before allocating them.
func (m *transitionChecker) reserveOccurrences(n int) error {
	if n < 0 || n > m.limits.Instructions || n > (m.limits.LiveStateBytes-m.liveStateBytes)/4096 {
		return refuse(m.pc, "transition-budget", "occurrence graph storage")
	}
	if err := transitionCopyWork(&m.work, m.limits.Work, n); err != nil {
		return err
	}
	m.liveStateBytes += n * 4096
	return nil
}

// decodeOccurrence derives activation transitions from actual decoded calls and
// returns. A frontier retains structural bytes but must first have an admitted
// transfer; an unsupported boundary cannot masquerade as an unfolding frontier.
func (m *transitionChecker) decodeOccurrence(n TransitionNode, activation TransitionActivationID, cut bool, activations map[TransitionActivationID]transitionActivation) (decodedInstruction, TransitionActivationID, error) {
	m.pc = n.PC
	if !m.tick() {
		return decodedInstruction{}, 0, m.err
	}
	i, _, err := decodeBytes(m.im, n.PC)
	if err != nil {
		return decodedInstruction{}, 0, err
	}
	if cut {
		if n.Expanded || n.Frontier {
			return decodedInstruction{}, 0, refuse(n.PC, "transition-cut", "cut has execution choice")
		}
		return decodedInstruction{boundary: boundaryCut, size: uint8(i.Len)}, activation, nil
	}
	optional := TransitionExpansionRequired(i)
	if n.Expanded && !optional {
		return decodedInstruction{}, 0, refuse(n.PC, "transition-expansion", "expansion is not an optional transfer")
	}
	if optional && !n.Expanded && !n.Frontier {
		return decodedInstruction{boundary: boundaryUnsupported, size: uint8(i.Len)}, activation, nil
	}
	// Endpoint selection is resolved above, independently of instruction form.
	// This sentinel lies outside the image's admitted low-canonical mappings.
	d, err := decodeTransitionBoundary(m.im, n.PC, ^uint64(0))
	if err != nil {
		return decodedInstruction{}, 0, err
	}
	if (n.Expanded || n.Frontier) && d.boundary != boundaryNone {
		return decodedInstruction{}, 0, refuse(n.PC, "transition-expansion", "selected encoding has no admitted transfer")
	}
	if d.boundary != boundaryNone {
		return d, activation, nil
	}
	nextActivation := activation
	switch i.Op {
	case x86asm.CALL:
		nextActivation = TransitionActivationID(n.ID)
		activations[nextActivation] = transitionActivation{activation, d.targets[0], n.PC + uint64(d.size)}
	case x86asm.RET:
		if activation == 0 {
			if n.Frontier {
				return decodedInstruction{}, 0, refuse(n.PC, "transition-frontier", "root return has no active transfer")
			}
			return decodedInstruction{boundary: boundaryUnsupported, size: d.size}, activation, nil
		}
		a, ok := activations[activation]
		if !ok {
			return decodedInstruction{}, 0, refuse(n.PC, "transition-context", "missing call activation")
		}
		d.count, d.targets[0], nextActivation = 1, a.continuation, a.parent
	}
	if n.Frontier {
		d.boundary, d.count = boundaryFrontier, 0
	}
	return d, nextActivation, nil
}

// occurrenceGraph checks arbitrary finite DAGs, including joins at different
// discovery depths. IDs are opaque sparse keys; array sizes depend only on count.
func (m *transitionChecker) occurrenceGraph(p TransitionProposal) (*graph, error) {
	if p.Root == 0 || len(p.Nodes) == 0 {
		return nil, refuse(p.Entry, "transition-proposal", "missing occurrence root")
	}
	if err := m.reserveOccurrences(len(p.Nodes)); err != nil {
		return nil, err
	}
	g := &graph{nodes: make([]instruction, len(p.Nodes)), byID: make(map[TransitionOccurrenceID]int, len(p.Nodes))}
	duplicate := -1
	for j, n := range p.Nodes {
		if !m.tick() {
			return nil, m.err
		}
		if n.ID == 0 {
			return nil, refuse(n.PC, "transition-proposal", "zero occurrence ID")
		}
		_, exists := g.byID[n.ID]
		if exists && duplicate < 0 {
			duplicate = j
		}
		if len(n.Successors) > 2 {
			return nil, refuse(n.PC, "transition-proposal", "extra successor slots")
		}
		if !exists {
			g.byID[n.ID] = j
		}
		g.nodes[j] = instruction{id: n.ID, pc: n.PC, size: n.Size, count: uint8(len(n.Successors)), parent: -1}
	}
	root, ok := g.byID[p.Root]
	if !ok || g.nodes[root].pc != m.root.entry {
		return nil, refuse(p.Entry, "transition-proposal", "root differs from independently selected entry")
	}
	for j, n := range p.Nodes {
		if !m.tick() {
			return nil, m.err
		}
		for edge, id := range n.Successors {
			next, ok := g.byID[id]
			if !ok {
				next = -1
			}
			g.nodes[j].next[edge] = next
		}
	}
	ctx := &relationContext{Context: m.ctx, meter: m.valueBuilder}
	queue, err := g.establishParents(ctx, root)
	if err != nil {
		return nil, err
	}
	if duplicate >= 0 {
		n := g.nodes[duplicate]
		return nil, g.failureInstruction(n, refuse(n.pc, "transition-proposal", "duplicate occurrence ID"))
	}
	for j, n := range g.nodes {
		if !m.tick() {
			return nil, m.err
		}
		for edge, next := range n.next[:n.count] {
			if next >= 0 {
				continue
			}
			pc := n.pc
			if d, err := decodeTransitionBoundary(m.im, n.pc, ^uint64(0)); err == nil && edge < int(d.count) {
				pc = d.targets[edge]
			}
			r := refuse(pc, "transition-proposal", "missing successor occurrence")
			g.failureInstruction(n, r)
			if pc != n.pc {
				r.Path = append(r.Path, pc)
			}
			return nil, r
		}
		i, _, err := decodeBytes(m.im, n.pc)
		if err != nil {
			return nil, g.failureInstruction(n, err)
		}
		g.nodes[j].size = uint8(i.Len)
	}
	// Structural occupancy precedes semantic form interpretation. The same
	// shared occupancy helper also protects discovery in the other domains.
	occupancy := newInstructionOccupancy()
	for _, j := range queue {
		if !m.tick() {
			return nil, m.err
		}
		n := g.nodes[j]
		if err := occupancy.add(n.pc, n.size); err != nil {
			return nil, g.failureInstruction(n, err)
		}
	}
	activations := map[TransitionActivationID]transitionActivation{0: {entry: m.root.entry}}
	assigned := make([]bool, len(g.nodes))
	assigned[root] = true
	after, bypass, err := m.endpointReach(g, root, p.After)
	if err != nil {
		return nil, err
	}
	cutID := TransitionOccurrenceID(0)
	// Activation transport is structural and needs only a root-connected work
	// queue, not symbolic execution. Every incoming slot checks agreement even
	// if another predecessor has already visited the destination. Scheduling
	// separately establishes the strictly decreasing execution rank below.
	for _, j := range queue {
		if !m.tick() {
			return nil, m.err
		}
		n, ins := p.Nodes[j], &g.nodes[j]
		if !assigned[j] {
			return nil, g.failureInstruction(*ins, refuse(n.PC, "transition-context", "unrooted activation"))
		}
		selected := !m.retainedPrefix[n.ID] && n.PC == p.Cut && n.ID != p.After && !n.Frontier
		if p.After != 0 {
			selected = selected && after[j]
			if selected && bypass[j] {
				return nil, g.failureInstruction(*ins, refuse(n.PC, "transition-anchor", "cut has a path bypassing its anchor"))
			}
		}
		d, activation, err := m.decodeOccurrence(n, ins.activation, selected, activations)
		if err != nil {
			return nil, g.failureInstruction(*ins, err)
		}
		if n.ID == p.After && (d.boundary != boundaryNone || d.count == 0 || len(n.Successors) == 0 || m.returnAnchor == n.ID && d.inst.Op != x86asm.RET) {
			return nil, g.failureInstruction(*ins, refuse(n.PC, "transition-anchor", "anchor must execute its actual transfer"))
		}
		if d.size != n.Size || int(d.count) != len(n.Successors) {
			return nil, g.failureInstruction(*ins, refuse(n.PC, "transition-proposal", "decoded extent or successor slots differ"))
		}
		ins.inst, ins.boundary = d.inst, d.boundary
		if d.boundary == boundaryCut {
			if cutID != 0 {
				return nil, g.failureInstruction(*ins, refuse(n.PC, "transition-cut", "cut is not one common occurrence"))
			}
			cutID = n.ID
		}
		if d.boundary == boundaryNone && d.count == 0 {
			return nil, g.failureInstruction(*ins, refuse(n.PC, "transition-cut", "unclosed path"))
		}
		for edge, next := range ins.next[:ins.count] {
			to := &g.nodes[next]
			if to.pc != d.targets[edge] {
				return nil, g.failureInstruction(*ins, refuse(n.PC, "transition-proposal", "decoded successor target differs"))
			}
			if assigned[next] && to.activation != activation {
				return nil, g.failureInstruction(*to, refuse(to.pc, "transition-context", "join has incompatible activations"))
			}
			to.activation, assigned[next] = activation, true
		}
	}
	if err := g.validate(&relationContext{Context: m.ctx, meter: m.valueBuilder}, root); err != nil {
		return nil, err
	}
	if cutID == 0 {
		return nil, refuse(p.Cut, "transition-cut", "cut is not a reachable decoded boundary")
	}
	m.activations = activations
	mode := TransitionNumericFirstHit
	if p.After != 0 {
		mode = TransitionFirstAfter
	}
	m.endpoint = TransitionEndpoint{Mode: mode, Anchor: p.After, Cut: cutID}
	return g, nil
}

// Derive the region after the anchor from all supplied slots, then validate every
// slot against decoded transfers in occurrenceGraph. A common cut cannot borrow
// "after" from one incoming path while another bypasses the anchor entirely.
func (m *transitionChecker) endpointReach(g *graph, root int, anchor TransitionOccurrenceID) ([]bool, []bool, error) {
	if anchor == 0 {
		return nil, nil, nil
	}
	a, ok := g.byID[anchor]
	if !ok {
		return nil, nil, refuse(m.pc, "transition-anchor", "anchor occurrence absent")
	}
	walk := func(seeds []int, stop int) ([]bool, error) {
		seen := make([]bool, len(g.nodes))
		queue := make([]int, 0, len(g.nodes))
		for _, j := range seeds {
			if !seen[j] {
				seen[j] = true
				queue = append(queue, j)
			}
		}
		for at := 0; at < len(queue); at++ {
			if !m.tick() {
				return nil, m.err
			}
			j := queue[at]
			if j == stop {
				continue
			}
			n := g.nodes[j]
			for _, next := range n.next[:n.count] {
				if !seen[next] {
					seen[next] = true
					queue = append(queue, next)
				}
			}
		}
		return seen, nil
	}
	after, err := walk(g.nodes[a].next[:g.nodes[a].count], -1)
	if err != nil {
		return nil, nil, err
	}
	bypass, err := walk([]int{root}, a)
	return after, bypass, err
}

func captureTransitionOptions(options []TransitionOptions, l TransitionLimits, work *int) (TransitionOptions, error) {
	if len(options) > 1 {
		return TransitionOptions{}, refuse(0, "transition-proposal", "multiple discovery options")
	}
	var o TransitionOptions
	if len(options) != 0 {
		o = options[0]
	}
	if o.MaxOccurrences < 0 || o.MaxOccurrences > l.Instructions || len(o.Expansions) > l.Instructions || len(o.Expansions) > l.LiveStateBytes/128 {
		return o, refuse(0, "transition-budget", "discovery inventory exceeds limits")
	}
	if err := transitionCopyWork(work, l.Work, len(o.Expansions)); err != nil {
		return o, err
	}
	o.Expansions = slices.Clone(o.Expansions)
	return o, nil
}

type discoveryPoint struct {
	pc         uint64
	activation TransitionActivationID
	depth      int
}

// discoverTransition proposes a witness only. The same occurrenceGraph checks
// both acyclic discovery and bounded unfolding; discovery contributes no premise.
func (m *transitionChecker) discoverTransition(cut uint64, o TransitionOptions, prior *checkedTransition, after TransitionOccurrenceID) (TransitionProposal, error) {
	if len(o.Expansions) > (m.limits.LiveStateBytes-m.liveStateBytes)/128 {
		return TransitionProposal{}, refuse(cut, "transition-budget", "discovery choice storage")
	}
	m.liveStateBytes += len(o.Expansions) * 128
	p := TransitionProposal{ImageDigest: m.im.digest, Entry: m.root.entry, Cut: cut, Root: 1}
	activations := map[TransitionActivationID]transitionActivation{0: {entry: m.root.entry}}
	usedIDs := make(map[TransitionOccurrenceID]bool)
	startID, startPC, startActivation := p.Root, p.Entry, TransitionActivationID(0)
	if prior != nil {
		if err := m.retainPrefix(*prior); err != nil {
			return TransitionProposal{}, err
		}
		var err error
		p, err = captureTransitionProposal(prior.witness, m.limits, &m.work)
		if err != nil {
			return TransitionProposal{}, err
		}
		g, err := m.occurrenceGraph(p)
		if err != nil {
			return TransitionProposal{}, err
		}
		activations = m.activations
		p.Cut = cut
		p.After = after
		startID, startPC, startActivation = prior.bound.Boundary.ID, prior.bound.Boundary.PC, prior.bound.Boundary.Context
		for _, n := range g.nodes {
			usedIDs[n.id] = true
		}
	} else {
		if err := m.reserveOccurrences(1); err != nil {
			return p, err
		}
		p.Nodes = []TransitionNode{{ID: 1, PC: p.Entry}}
		usedIDs[1] = true
	}
	nextID := TransitionOccurrenceID(1)
	fresh := func() TransitionOccurrenceID {
		for usedIDs[nextID] {
			nextID++
		}
		id := nextID
		usedIDs[id] = true
		return id
	}
	indices := make(map[TransitionOccurrenceID]int, len(p.Nodes))
	for j, n := range p.Nodes {
		indices[n.ID] = j
	}
	queue := []discoveryPoint{{pc: startPC, activation: startActivation}}
	ids := []TransitionOccurrenceID{startID}
	byPoint := map[discoveryPoint]TransitionOccurrenceID{queue[0]: startID}
	if after != 0 && startPC == cut {
		delete(byPoint, queue[0])
	}
	usedChoices := make([]bool, len(o.Expansions))
	for at := 0; at < len(queue); at++ {
		if !m.tick() {
			return p, m.err
		}
		point, id := queue[at], ids[at]
		stop := point.pc == cut && id != after
		n := TransitionNode{ID: id, PC: point.pc}
		for j, e := range o.Expansions {
			if !m.tick() {
				return p, m.err
			}
			if e.PC == n.PC && (e.AllActivations || e.Context == point.activation) && (e.ID == 0 || e.ID == id) {
				if n.Expanded {
					return p, refuse(n.PC, "transition-expansion", "duplicate transfer expansion")
				}
				n.Expanded, usedChoices[j] = true, true
			}
		}
		if stop {
			n.Expanded = false
		}
		if o.MaxOccurrences > 0 && point.depth >= o.MaxOccurrences && !stop {
			// Only selected/admitted transfers become frontiers. Unselected
			// optional forms retain their separate unsupported-boundary choice.
			i, _, err := decodeBytes(m.im, point.pc)
			if err != nil {
				return p, err
			}
			if !TransitionExpansionRequired(i) || n.Expanded {
				d, err := decodeTransitionBoundary(m.im, point.pc, ^uint64(0))
				if err != nil {
					return p, err
				}
				n.Frontier = d.boundary == boundaryNone && (i.Op != x86asm.RET || point.activation != 0)
			}
		}
		d, activation, err := m.decodeOccurrence(n, point.activation, stop, activations)
		if err != nil {
			return p, err
		}
		n.Size = d.size
		if o.MaxOccurrences == 0 && d.inst.Op == x86asm.CALL && d.boundary == boundaryNone {
			for a := point.activation; ; a = activations[a].parent {
				if !m.tick() {
					return p, m.err
				}
				if activations[a].entry == d.targets[0] {
					return p, refuse(point.pc, "acyclic-control", "recursive discovery requires an unfolding bound")
				}
				if a == 0 {
					break
				}
			}
		}
		for _, pc := range d.targets[:d.count] {
			key := discoveryPoint{pc: pc, activation: activation}
			if o.MaxOccurrences > 0 && pc != cut {
				key.depth = point.depth + 1
			}
			next, exists := byPoint[key]
			if !exists {
				if len(p.Nodes) >= m.limits.Instructions {
					return p, refuse(pc, "transition-budget", "instruction graph budget")
				}
				if err := m.reserveOccurrences(1); err != nil {
					return p, err
				}
				next = fresh()
				byPoint[key] = next
				indices[next] = len(p.Nodes)
				p.Nodes = append(p.Nodes, TransitionNode{ID: next, PC: pc})
				queue, ids = append(queue, key), append(ids, next)
			}
			n.Successors = append(n.Successors, next)
		}
		p.Nodes[indices[id]] = n
	}
	for j, used := range usedChoices {
		if !m.tick() {
			return p, m.err
		}
		if !used {
			return p, refuse(o.Expansions[j].PC, "transition-expansion", "unused transfer expansion")
		}
	}
	if _, err := m.occurrenceGraph(p); err != nil {
		return p, err
	}
	return p, nil
}

// Freeze every old executed/excluded disposition before endpoint recognition.
// In particular, exclusion is not a prior execution of its numeric PC. Only the
// opaque predecessor supplies this prefix; proposals cannot label a newly
// feasible target occurrence as old execution or an established exclusion.
func (m *transitionChecker) retainPrefix(prior checkedTransition) error {
	n := len(prior.witness.Nodes) - 1
	if n < 0 || n > m.limits.Instructions || n > (m.limits.LiveStateBytes-m.liveStateBytes)/64 {
		return refuse(m.pc, "transition-budget", "retained terminal index")
	}
	m.liveStateBytes += 64 * n
	m.retainedPrefix = make(map[TransitionOccurrenceID]bool, n)
	for _, b := range prior.witness.Nodes {
		if !m.tick() {
			return m.err
		}
		if b.ID != prior.bound.Boundary.ID {
			m.retainedPrefix[b.ID] = true
		}
	}
	return nil
}

// ProposeTransitionContinuation extends the predecessor's exact owned witness.
// Its common cut becomes the suffix root; all other old IDs and edges survive.
func ProposeTransitionContinuation(ctx context.Context, predecessor TransitionCertificate, cut uint64, options ...TransitionOptions) (TransitionProposal, error) {
	return proposeTransitionContinuation(ctx, predecessor, cut, false, options)
}

// ProposeNextTransitionContinuation selects the first target encounter after the
// predecessor's actual unexecuted boundary executes. Equal target/anchor PCs
// require a distinct later occurrence. Checking independently enforces this
// locator and retains original state, exclusions and the cumulative account.
func ProposeNextTransitionContinuation(ctx context.Context, predecessor TransitionCertificate, cut uint64, options ...TransitionOptions) (TransitionProposal, error) {
	return proposeTransitionContinuation(ctx, predecessor, cut, true, options)
}

func proposeTransitionContinuation(ctx context.Context, predecessor TransitionCertificate, cut uint64, next bool, options []TransitionOptions) (TransitionProposal, error) {
	if predecessor.checked == nil {
		return TransitionProposal{}, refuse(cut, "transition-predecessor", "missing checked predecessor")
	}
	prior := predecessor.checked
	work := prior.work
	o, err := captureTransitionOptions(options, prior.limits, &work)
	if err != nil {
		return TransitionProposal{}, err
	}
	m, err := newTransitionChecker(ctx, prior.image, transitionRoot{prior.bound.Entry, prior.bound.ConditionalRegion}, prior.limits, work)
	if err != nil {
		return TransitionProposal{}, err
	}
	after := TransitionOccurrenceID(0)
	if next {
		after = prior.bound.Boundary.ID
	} else {
		if err := m.advancingCut(*prior, cut); err != nil {
			return TransitionProposal{}, err
		}
	}
	return m.discoverTransition(cut, o, prior, after)
}
