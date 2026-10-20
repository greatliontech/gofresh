package nativeproof

import (
	"context"
	"slices"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// TransitionCallByte associates a callee entry byte with the actual caller byte.
// Current uses parent-root coordinates and retains complete pointer lanes.
type TransitionCallByte struct{ Input, Current TransitionByte }

// TransitionCallWord associates a callee's arbitrary input word with the same
// current bytes used by its byte associations. It introduces no new input.
type TransitionCallWord struct {
	Input   TransitionWord
	Current TransitionValue
}

// TransitionCallOccurrence identifies one exact child witness occurrence in the
// checked parent-root replay. Specialization may drop accesses; the association
// does not imply equal access counts or a constant access-index displacement.
type TransitionCallOccurrence struct{ Input, Current TransitionOccurrenceID }

// TransitionCallBound projects applicability of one exact conditional return
// theorem. ChildEntry and Successor retain the original caller root. Registers,
// Memory, Words and Predicates associate callee inputs with the actual body-entry
// state; they are not an output-expression evaluator or source-call transport.
// Flags retains definedness even where an architectural value is unprojected.
type TransitionCallBound struct {
	ID                 TransitionOccurrenceID
	Call, Continuation uint64
	Activation         TransitionActivationID
	StackShift         int64
	// Geometry is the checked association from callee storage to actual caller storage.
	Geometry  TransitionGeometryAssociation
	Inputs    [16]br.Term
	Registers [16]TransitionValue
	Memory    []TransitionCallByte
	Words     []TransitionCallWord
	// Occurrences includes every child witness node, including excluded and
	// frontier nodes and terminal RET, but not the new parent continuation.
	Occurrences     []TransitionCallOccurrence
	InputPredicates TransitionPredicates
	Predicates      TransitionPredicates
	// InputDirection is the exact callee entry DF; Direction associates it with
	// the actual body-entry DF, without introducing a new input.
	InputDirection br.Term
	Direction      br.Term
	Flags          TransitionFlags
	InputFS        br.Term
	Thread         TransitionThread
	InputVectors   TransitionVectors
	Vectors        TransitionVectors
	SSE            TransitionSSEContext
	ChildEntry     TransitionBound
	Successor      TransitionBound
}

// TransitionCallCertificate establishes exact-callee applicability and an actual
// CALL/body/RET successor. Its zero value grants no authority. It does not connect
// typed source arguments, represented globals, or source occurrence identities.
type TransitionCallCertificate struct{ checked *checkedTransitionCall }

type checkedTransitionCall struct {
	callee      TransitionReturnCertificate
	entry       TransitionCertificate
	successor   TransitionCertificate
	application TransitionCallBound
	proofs      []br.Witness
}

// AppliesTo tests the identity of the exact completed theorem, not equal image
// bytes, endpoint addresses, projections or independently reconstructed evidence.
func (c TransitionCallCertificate) AppliesTo(callee TransitionReturnCertificate) bool {
	return c.checked != nil && callee.checked != nil && c.checked.callee.checked == callee.checked
}

// Callee returns the immutable completed theorem whose premises were established.
func (c TransitionCallCertificate) Callee() (TransitionReturnCertificate, bool) {
	if c.checked == nil {
		return TransitionReturnCertificate{}, false
	}
	return c.checked.callee, true
}

// Successor returns checked parent-root evidence stopped at the unexecuted
// continuation. All actual residual memory and ordered effects remain present.
func (c TransitionCallCertificate) Successor() (TransitionCertificate, bool) {
	if c.checked == nil {
		return TransitionCertificate{}, false
	}
	return c.checked.successor, true
}

// Bound returns cloned containers; modifying them cannot alter the certificate.
func (c TransitionCallCertificate) Bound() (TransitionCallBound, bool) {
	if c.checked == nil {
		return TransitionCallBound{}, false
	}
	b := c.checked.application
	b.Memory = slices.Clone(b.Memory)
	b.Words = slices.Clone(b.Words)
	b.Occurrences = slices.Clone(b.Occurrences)
	b.ChildEntry, _ = c.checked.entry.Bound()
	b.Successor, _ = c.checked.successor.Bound()
	return b, true
}

// BoundFor requires the exact immutable image owner of the checked caller.
func (c TransitionCallCertificate) BoundFor(im *Image) (TransitionCallBound, bool) {
	if c.checked == nil || !sameImage(c.checked.successor.checked.image, im) {
		return TransitionCallBound{}, false
	}
	return c.Bound()
}

// CheckTransitionCallReturn applies a completed conditional callee theorem at an
// actual direct CALL boundary. It proves every child premise from the current
// caller state, then replays to the actual return under the unchanged caller
// interface. Discovery, dependency imports, proofs and replay share the caller's
// cumulative account; failure cannot mutate either input certificate.
func CheckTransitionCallReturn(ctx context.Context, caller TransitionCertificate, callee TransitionReturnCertificate) (TransitionCallCertificate, error) {
	return checkTransitionApplication(ctx, caller, callee, false)
}

// CheckTransitionActiveReturn applies the exact callee theorem at its entry
// already reached within the innermost active CALL. The owned prefix establishes
// any wrapper and tail transfers. Inputs and preserved registers are relative to
// that actual body entry; control storage is protected since the initiating CALL.
// All dependencies and work share the entered certificate's cumulative account.
func CheckTransitionActiveReturn(ctx context.Context, entered TransitionCertificate, callee TransitionReturnCertificate) (TransitionCallCertificate, error) {
	return checkTransitionApplication(ctx, entered, callee, true)
}

func checkTransitionApplication(ctx context.Context, caller TransitionCertificate, callee TransitionReturnCertificate, active bool) (TransitionCallCertificate, error) {
	if ctx == nil || caller.checked == nil || callee.checked == nil {
		return TransitionCallCertificate{}, refuse(0, "transition-application", "missing context or checked caller/callee")
	}
	if err := ctx.Err(); err != nil {
		return TransitionCallCertificate{}, err
	}
	prior := *caller.checked
	child := callee.checked.prefix.checked
	b := prior.bound
	if b.Rules != TransitionRules || child.bound.Rules != b.Rules || !sameImage(prior.image, child.image) {
		return TransitionCallCertificate{}, refuse(b.Boundary.PC, "transition-application", "callee rules or immutable image owner differ")
	}
	if err := transitionCopyWork(&prior.work, prior.limits.Work, 3); err != nil {
		return TransitionCallCertificate{}, err
	}
	if active {
		if b.Boundary.PC != child.bound.Entry || len(b.Frames) == 0 {
			return TransitionCallCertificate{}, refuse(b.Boundary.PC, "transition-application", "callee entry or active invocation missing")
		}
	} else {
		i, raw, err := transitionEncoding(prior.image, b.Boundary.PC)
		if err != nil {
			return TransitionCallCertificate{}, err
		}
		if i.Op != x86asm.CALL {
			return TransitionCallCertificate{}, refuse(b.Boundary.PC, "transition-application", "caller boundary is not a direct CALL")
		}
		if err := validateTransitionForm(b.Boundary.PC, i, raw); err != nil {
			return TransitionCallCertificate{}, err
		}
		d, err := decodeTransitionBoundary(prior.image, b.Boundary.PC, 0)
		if err != nil {
			return TransitionCallCertificate{}, err
		}
		if d.count != 1 || d.targets[0] != child.bound.Entry || child.bound.Interface.ReturnContext == nil || child.bound.Interface.ReturnContext.Target != b.Boundary.PC+uint64(i.Len) {
			return TransitionCallCertificate{}, refuse(b.Boundary.PC, "transition-application", "encoded target or continuation differs from callee interface")
		}
	}
	// Import the independent theorem, including construction cost and terminal
	// dependencies, before doing application work. Immutable sharing saves copies,
	// not the retained-evidence or cumulative work account.
	if err := transitionCopyWork(&prior.work, prior.limits.Work, callee.checked.work); err != nil {
		return TransitionCallCertificate{}, err
	}
	dep, err := newTransitionChecker(ctx, prior.image, transitionRoot{entry: child.bound.Entry, region: true}, prior.limits, prior.work)
	if err != nil {
		return TransitionCallCertificate{}, err
	}
	if err := dep.inherit(*child); err != nil {
		return TransitionCallCertificate{}, err
	}
	for _, v := range callee.checked.state.Registers {
		if err := dep.importTerm(v.Value); err != nil {
			return TransitionCallCertificate{}, err
		}
	}
	for _, v := range callee.checked.state.Vectors {
		for _, root := range []br.Term{v.Lo, v.Hi} {
			if root.Valid() {
				if err := dep.importTerm(root); err != nil {
					return TransitionCallCertificate{}, err
				}
			}
		}
	}
	if err := dep.importTerm(callee.checked.access.Value); err != nil {
		return TransitionCallCertificate{}, err
	}
	if err := dep.importTerm(callee.checked.state.Direction); err != nil {
		return TransitionCallCertificate{}, err
	}
	for _, proof := range callee.checked.proofs {
		left, right := proof.Roots()
		for _, root := range []br.Term{left, right} {
			if err := dep.importTerm(root); err != nil {
				return TransitionCallCertificate{}, err
			}
		}
		dep.justifications = append(dep.justifications, proof)
	}
	retained, err := dep.applicationEvidenceBytes(child.bound)
	if err != nil {
		return TransitionCallCertificate{}, err
	}
	prior.work = dep.work
	if retained >= prior.limits.LiveStateBytes {
		return TransitionCallCertificate{}, refuse(b.Boundary.PC, "transition-budget", "retained callee application evidence")
	}
	prior.limits.LiveStateBytes -= retained
	if len(dep.depth) >= prior.limits.Nodes {
		return TransitionCallCertificate{}, refuse(b.Boundary.PC, "transition-budget", "retained callee expression dependencies")
	}
	prior.limits.Nodes -= len(dep.depth)
	var entry TransitionCertificate
	var m *transitionChecker
	if active {
		m, err = newTransitionChecker(ctx, prior.image, transitionRoot{entry: b.Entry, region: b.ConditionalRegion}, prior.limits, prior.work)
		if err == nil {
			err = m.inherit(prior)
		}
		if err == nil {
			m.pc, m.occurrence, m.activation = b.Boundary.PC, b.Boundary.ID, b.Boundary.Context
			// Keep the reduced dependency allowances, not caller.checked.limits.
			prior.work = m.work
			entry = TransitionCertificate{&prior}
		}
	} else {
		var proposal TransitionProposal
		proposal, err = applicationEntryProposal(&prior, child.bound.Entry)
		if err == nil {
			entry, m, err = applicationContinue(ctx, prior, proposal, 0)
		}
	}
	if err != nil {
		return TransitionCallCertificate{}, err
	}
	if len(m.frames) == 0 {
		return TransitionCallCertificate{}, refuse(b.Boundary.PC, "transition-application", "missing active invocation")
	}
	frame := m.frames[len(m.frames)-1]
	activation, continuation := frame.Context, frame.Return
	sp, ok := m.pointers[RSP].(AddressPointer)
	_, original := m.bound.Geometry.OriginalStack(sp)
	if !ok || !original || sp != frame.Slot || frame.ID == 0 || activation != TransitionActivationID(frame.ID) || entry.checked.bound.Boundary.Context != activation || child.bound.Interface.ReturnContext == nil || child.bound.Interface.ReturnContext.Target != continuation {
		return TransitionCallCertificate{}, refuse(b.Boundary.PC, "transition-application", "active control slot or continuation differs from callee interface")
	}
	if !active && (frame.ID != b.Boundary.ID || frame.Call != b.Boundary.PC || len(m.frames) != len(b.Frames)+1 || !slices.Equal(m.frames[:len(b.Frames)], b.Frames)) {
		return TransitionCallCertificate{}, refuse(b.Boundary.PC, "transition-application", "CALL did not establish the expected child activation")
	}
	parentFrames := m.frames[:len(m.frames)-1]
	parentContext := TransitionActivationID(0)
	if len(parentFrames) != 0 {
		parentContext = parentFrames[len(parentFrames)-1].Context
	}
	controlStart, err := m.applicationControlStart(entry.checked.witness, frame, parentContext)
	if err != nil {
		return TransitionCallCertificate{}, err
	}
	returnedOffset, ok := signedPlus(sp.offset, 8)
	if !ok {
		return TransitionCallCertificate{}, refuse(frame.Call, "transition-application", "control-slot extent overflow")
	}
	a := TransitionCallBound{ID: frame.ID, Call: frame.Call, Continuation: continuation, Activation: activation, StackShift: sp.offset}
	proofStart := len(m.justifications)
	if err := m.applicationPremises(child.bound, &a); err != nil {
		return TransitionCallCertificate{}, err
	}
	proofs := slices.Clone(m.justifications[proofStart:])
	// Retain the child-entry relation and associations beside the successor.
	// Reduce its available live allowance permanently so future continuations
	// cannot forget application evidence. Inputs keep their original limits.
	entryBytes, err := m.applicationEvidenceBytes(entry.checked.bound)
	if err != nil {
		return TransitionCallCertificate{}, err
	}
	if entryBytes > m.limits.LiveStateBytes-m.liveStateBytes {
		return TransitionCallCertificate{}, refuse(m.pc, "transition-budget", "retained child-entry evidence")
	}
	advanced := *entry.checked
	advanced.bound = cloneTransitionBound(entry.checked.bound)
	// The owned stack pointer is a checked scalar/provenance invariant, not an equality
	// guessed from bits. Re-express the actual body-entry RSP in its parent-root
	// coordinate so child guards use the same modular affine spelling as their
	// established entry bounds, including chains of SUB and implicit CALL pushes.
	// The original child-entry certificate and association retain the actual term.
	advanced.bound.Registers[RSP].Value = m.bound.Origin
	if sp.offset != 0 {
		advanced.bound.Registers[RSP].Value = m.binary(br.Add, m.bound.Origin, m.con(br.Bits(64), uint64(sp.offset)))
	}
	if m.err != nil {
		return TransitionCallCertificate{}, m.err
	}
	advanced.work = m.work
	advanced.justifications = slices.Clone(m.justifications)
	advanced.limits.LiveStateBytes -= entryBytes
	if len(m.depth) >= advanced.limits.Nodes {
		return TransitionCallCertificate{}, refuse(m.pc, "transition-budget", "retained child-entry expression dependencies")
	}
	advanced.limits.Nodes -= len(m.depth)
	advanced.work = m.work
	replayProposal, occurrences, err := applicationCalleeProposal(ctx, &advanced, *child, continuation)
	if err != nil {
		return TransitionCallCertificate{}, err
	}
	successor, replay, err := applicationContinue(ctx, advanced, replayProposal, replayProposal.After)
	if err != nil {
		return TransitionCallCertificate{}, err
	}
	end := successor.checked.bound
	if end.Boundary.Context != parentContext || !slices.Equal(end.Frames, parentFrames) || end.Registers[RSP].Pointer != b.Geometry.stackPointer(returnedOffset) {
		return TransitionCallCertificate{}, refuse(continuation, "transition-application", "return failed to consume child activation and restore parent context")
	}
	if child.bound.Interface.PrivateFrame != nil {
		if err := replay.checkPrivateLifetimeHistory(); err != nil {
			return TransitionCallCertificate{}, err
		}
	}
	if err := replay.applicationProtectedSlot(controlStart, activation, sp.offset); err != nil {
		return TransitionCallCertificate{}, err
	}
	for _, r := range child.bound.Interface.ReturnContext.Preserved {
		if !replay.tick() {
			return TransitionCallCertificate{}, replay.err
		}
		if end.Registers[r].Pointer != a.Registers[r].Pointer {
			return TransitionCallCertificate{}, refuse(continuation, "transition-application-preserved", "replay did not restore caller provenance")
		}
		// The exact applicable return theorem already establishes original bits
		// and lineage restoration. Replay preserves the specialized provenance;
		// no separate incomplete scalar-normalization search is an authority source.
	}
	if !replay.tick() {
		return TransitionCallCertificate{}, replay.err
	}
	// Scans after finish are part of the published successor's cumulative work.
	finished := *successor.checked
	finished.work = replay.work
	finished.justifications = slices.Clone(replay.justifications)
	successor.checked = &finished
	a.Occurrences = occurrences
	return TransitionCallCertificate{&checkedTransitionCall{callee: callee, entry: entry, successor: successor, application: a, proofs: proofs}}, nil
}

// Internal discovery uses the same checker/meter as replay. Unlike a public
// proposal, the graph here already comes from independently decoded owned bytes.
func applicationContinue(ctx context.Context, prior checkedTransition, proposal TransitionProposal, returnAnchor TransitionOccurrenceID) (TransitionCertificate, *transitionChecker, error) {
	m, err := newTransitionChecker(ctx, prior.image, transitionRoot{entry: prior.bound.Entry, region: prior.bound.ConditionalRegion}, prior.limits, prior.work)
	if err != nil {
		return TransitionCertificate{}, nil, err
	}
	m.returnAnchor = returnAnchor
	c, err := m.continueTransition(prior, proposal)
	return c, m, err
}

// Recover the actual initiating CALL and its one control store from the retained
// checked prefix. Its target may be a wrapper, not the later theorem entry.
func (m *transitionChecker) applicationControlStart(witness TransitionProposal, frame TransitionFrame, parent TransitionActivationID) (int, error) {
	i, raw, err := transitionEncoding(m.im, frame.Call)
	if err != nil {
		return 0, err
	}
	if err := validateTransitionForm(frame.Call, i, raw); err != nil {
		return 0, err
	}
	if i.Op != x86asm.CALL || frame.Return != frame.Call+uint64(i.Len) {
		return 0, refuse(frame.Call, "transition-application", "active frame lacks an actual CALL and return extent")
	}
	nodeFound, instructionFound := false, false
	for _, node := range witness.Nodes {
		if !m.tick() {
			return 0, m.err
		}
		if node.ID == frame.ID {
			nodeFound = node.PC == frame.Call && int(node.Size) == i.Len && node.Expanded && !node.Frontier && len(node.Successors) == 1
		}
	}
	for _, instruction := range m.bound.Instructions {
		if !m.tick() {
			return 0, m.err
		}
		if instruction.ID == frame.ID {
			instructionFound = instruction.Start == frame.Call && instruction.End == frame.Return && instruction.Context == parent
		}
	}
	_, original := m.bound.Geometry.OriginalStack(frame.Slot)
	if !nodeFound || !instructionFound || !original {
		return 0, refuse(frame.Call, "transition-application", "initiating CALL missing from retained occurrence evidence")
	}
	start := -1
	for j, access := range m.bound.Accesses {
		if !m.tick() {
			return 0, m.err
		}
		if access.ID != frame.ID {
			continue
		}
		value := access.Value.View()
		if start >= 0 || access.PC != frame.Call || access.Context != parent || access.Kind != FrameWrite || access.Bytes != (TransitionExtent{m.bound.Geometry.stackLocation(frame.Slot.offset), 8}) || value.Op != br.Constant || value.Sort != br.Bits(64) || value.Immediate != frame.Return {
			return 0, refuse(frame.Call, "transition-application", "initiating CALL lacks its exact control store")
		}
		start = j + 1
	}
	if start < 0 {
		return 0, refuse(frame.Call, "transition-application", "initiating CALL control store missing")
	}
	return start, m.err
}

// Only the initiating CALL's store is excluded. Every subsequent descendant
// write counts, including wrappers before body entry and unchanged-value stores.
func (m *transitionChecker) applicationProtectedSlot(start int, activation TransitionActivationID, shift int64) error {
	slot := TransitionExtent{m.bound.Geometry.stackLocation(shift), 8}
	for _, access := range m.bound.Accesses[start:] {
		if !m.tick() {
			return m.err
		}
		descendant := false
		for at := access.Context; at != 0; {
			if !m.tick() {
				return m.err
			}
			if at == activation {
				descendant = true
				break
			}
			a, ok := m.activations[at]
			if !ok {
				return refuse(access.PC, "transition-application", "missing checked activation ancestry")
			}
			at = a.parent
		}
		overlaps, err := m.bound.Geometry.Overlaps(access.Bytes, slot)
		if err != nil {
			return err
		}
		if descendant && access.Kind == FrameWrite && overlaps {
			return refuse(access.PC, "transition-application-protected", "child write overlaps incoming control storage")
		}
	}
	return m.err
}

// Reserve conservative retained-container and expression storage. Immutable
// handles may be shared, but their dependency cost stays in the successor limit.
func (m *transitionChecker) applicationEvidenceBytes(b TransitionBound) (int, error) {
	bytes := max(8192, geometryStorageBytes(len(b.Geometry.root.imageViews)))
	if bytes > m.limits.LiveStateBytes {
		return 0, refuse(m.pc, "transition-budget", "application geometry storage")
	}
	for _, n := range []int{len(m.depth), len(b.InitialMemory), len(b.Memory), len(b.Words), len(b.Instructions), len(b.Accesses), len(b.PrimitiveEffects), len(b.Abstractions), len(b.Frames), len(b.Expansions), len(b.ExcludedOrigins), len(b.ExcludedBoundaries), len(m.justifications), len(b.Interface.Regions), len(b.Interface.ImageRegions), len(b.Interface.EntryImagePointers), len(b.Interface.EntryWordUpperBounds)} {
		for range n {
			if !m.tick() {
				return 0, m.err
			}
			if bytes > m.limits.LiveStateBytes-4096 {
				return 0, refuse(m.pc, "transition-budget", "application dependency storage")
			}
			bytes += 4096
		}
	}
	return bytes, nil
}

func applicationEntryProposal(prior *checkedTransition, target uint64) (TransitionProposal, error) {
	p, err := captureTransitionProposal(prior.witness, prior.limits, &prior.work)
	if err != nil {
		return p, err
	}
	if len(p.Nodes) >= prior.limits.Instructions || len(p.Nodes)+1 > prior.limits.LiveStateBytes/4096 {
		return p, refuse(target, "transition-budget", "CALL entry occurrence storage")
	}
	if err := transitionCopyWork(&prior.work, prior.limits.Work, len(p.Nodes), 2); err != nil {
		return p, err
	}
	used := make(map[TransitionOccurrenceID]bool, len(p.Nodes))
	for _, n := range p.Nodes {
		used[n.ID] = true
	}
	id := TransitionOccurrenceID(1)
	for used[id] {
		id++
	}
	i, _, err := decodeBytes(prior.image, target)
	if err != nil {
		return p, err
	}
	for j := range p.Nodes {
		if p.Nodes[j].ID == prior.bound.Boundary.ID {
			p.Nodes[j].Expanded = true
			p.Nodes[j].Successors = []TransitionOccurrenceID{id}
		}
	}
	p.Nodes = append(p.Nodes, TransitionNode{ID: id, PC: target, Size: uint8(i.Len)})
	p.Cut = target
	p.After = prior.bound.Boundary.ID
	return p, nil
}

// Embed the complete callee witness injectively. The old child-entry boundary
// supplies its root identity; all other callee occurrences and the parent
// continuation receive fresh IDs. The checker rederives every activation and
// executes the actual terminal RET against the current protected control word.
func applicationCalleeProposal(ctx context.Context, prior *checkedTransition, child checkedTransition, continuation uint64) (TransitionProposal, []TransitionCallOccurrence, error) {
	// The exported association remains beside the successor after the temporary
	// embedding map is gone. Reserve that storage permanently before allocation.
	if len(child.witness.Nodes) >= prior.limits.LiveStateBytes/32 {
		return TransitionProposal{}, nil, refuse(continuation, "transition-budget", "retained occurrence associations")
	}
	prior.limits.LiveStateBytes -= len(child.witness.Nodes) * 32
	count := len(prior.witness.Nodes) + len(child.witness.Nodes)
	if count > prior.limits.Instructions || count > prior.limits.LiveStateBytes/4096 {
		return TransitionProposal{}, nil, refuse(continuation, "transition-budget", "callee occurrence embedding")
	}
	if err := transitionCopyWork(&prior.work, prior.limits.Work, count, len(child.witness.Nodes), len(child.witness.Nodes)); err != nil {
		return TransitionProposal{}, nil, err
	}
	p, err := captureTransitionProposal(prior.witness, prior.limits, &prior.work)
	if err != nil {
		return p, nil, err
	}
	used := make(map[TransitionOccurrenceID]bool, count)
	for _, n := range p.Nodes {
		used[n.ID] = true
	}
	next := TransitionOccurrenceID(1)
	fresh := func() TransitionOccurrenceID {
		for used[next] {
			next++
		}
		id := next
		used[id] = true
		return id
	}
	ids := map[TransitionOccurrenceID]TransitionOccurrenceID{child.witness.Root: prior.bound.Boundary.ID}
	for _, n := range child.witness.Nodes {
		if n.ID != child.witness.Root {
			ids[n.ID] = fresh()
		}
	}
	occurrences := make([]TransitionCallOccurrence, 0, len(child.witness.Nodes))
	for _, n := range child.witness.Nodes {
		occurrences = append(occurrences, TransitionCallOccurrence{Input: n.ID, Current: ids[n.ID]})
	}
	after := fresh()
	if err := transitionCopyWork(&prior.work, prior.limits.Work, len(child.bound.ExcludedBoundaries)*3); err != nil {
		return p, nil, err
	}
	excluded := make(map[TransitionOccurrenceID]bool, len(child.bound.ExcludedBoundaries))
	for _, b := range child.bound.ExcludedBoundaries {
		excluded[b.ID] = true
	}
	for _, n := range child.witness.Nodes {
		if err := ctx.Err(); err != nil {
			return p, nil, err
		}
		oldID := n.ID
		// Recheck classification when moving evidence into an actual activation.
		// An encoded transfer excluded for lack of root control context may now
		// be supported. Keep it deferred, with its full actual incoming guard
		// independently reproved false by replay. Unselected optional forms stay
		// unselected; available semantics never force expansion of dead arms.
		if excluded[oldID] && !n.Frontier {
			i, _, err := decodeBytes(prior.image, n.PC)
			if err != nil {
				return p, nil, err
			}
			if !TransitionExpansionRequired(i) || n.Expanded {
				d, err := decodeTransitionBoundary(prior.image, n.PC, ^uint64(0))
				if err != nil {
					return p, nil, err
				}
				if d.boundary == boundaryNone {
					n.Frontier = true
				}
			}
		}
		n.ID = ids[oldID]
		n.Successors = slices.Clone(n.Successors)
		for j, id := range n.Successors {
			n.Successors[j] = ids[id]
		}
		if oldID == child.bound.Boundary.ID {
			n.Successors = []TransitionOccurrenceID{after}
		}
		if oldID == child.witness.Root {
			for j := range p.Nodes {
				if p.Nodes[j].ID == n.ID {
					p.Nodes[j] = n
					break
				}
			}
		} else {
			p.Nodes = append(p.Nodes, n)
		}
	}
	i, _, err := decodeBytes(prior.image, continuation)
	if err != nil {
		return p, nil, err
	}
	p.Nodes = append(p.Nodes, TransitionNode{ID: after, PC: continuation, Size: uint8(i.Len)})
	p.Cut = continuation
	p.After = ids[child.bound.Boundary.ID]
	return p, occurrences, nil
}
