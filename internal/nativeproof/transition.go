package nativeproof

import (
	"context"
	"fmt"
	"math/bits"
	"slices"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

type transitionChecker struct {
	*valueBuilder
	im                         *Image
	root                       transitionRoot
	face                       TransitionInterface
	limits                     TransitionLimits
	lo, hi                     uint64
	bound                      TransitionBound
	state                      symbolicState
	pointers                   [16]TransitionPointer
	memory                     map[TransitionLocation]TransitionByte
	liveStateBytes, stateBytes int
	exclusions                 []br.Witness
	justifications             []br.Witness
	activation                 TransitionActivationID
	occurrence                 TransitionOccurrenceID
	activations                map[TransitionActivationID]transitionActivation
	retainedPrefix             map[TransitionOccurrenceID]bool
	endpoint                   TransitionEndpoint
	witness                    TransitionProposal
	frames                     []TransitionFrame
	thread                     TransitionThread
	vectors                    TransitionVectors
	direction                  br.Term
	completingReturn, returned bool
	returnAnchor               TransitionOccurrenceID
}

func transitionLimits(l TransitionLimits) (TransitionLimits, error) {
	var err error
	l.RelationLimits, err = relationLimits(l.RelationLimits)
	if err != nil {
		return l, err
	}
	if l.Regions == 0 {
		l.Regions = 64
	}
	if l.Bytes == 0 {
		l.Bytes = 65536
	}
	if l.LiveStateBytes == 0 {
		l.LiveStateBytes = 256 << 20
	}
	if l.LiveStateBytes < 1 || l.LiveStateBytes > 1<<30 {
		return l, fmt.Errorf("invalid transition live-state limit")
	}
	if l.Regions < 1 || l.Regions > 256 || l.Bytes < 1 || l.Bytes > 1<<20 {
		return l, fmt.Errorf("invalid transition memory limits")
	}
	return l, nil
}

// The root is selected independently of the untrusted graph inventory. Only the
// ELF wrapper obtains it from the header; region roots retain conditional scope.
type transitionRoot struct {
	entry  uint64
	region bool
}

func newTransitionChecker(ctx context.Context, im *Image, root transitionRoot, l TransitionLimits, work int) (*transitionChecker, error) {
	if ctx == nil {
		return nil, refuse(0, "transition-context", "missing context")
	}
	if im == nil || len(im.data) == 0 {
		return nil, refuse(0, "image-binding", "missing constructed image")
	}
	if !root.region && root.entry != im.entry {
		return nil, refuse(root.entry, "transition-root", "ELF root differs from image entry")
	}
	m := &transitionChecker{im: im, root: root, limits: l, valueBuilder: &valueBuilder{ctx: ctx, limits: l.RelationLimits, work: work, pc: root.entry, depth: make(map[br.Term]int)}}
	if !m.tick() {
		return nil, m.err
	}
	if _, err := im.instructionBytes(root.entry); err != nil {
		return nil, err
	}
	return m, nil
}

// ProposeTransition discovers candidate coverage from the ELF-declared entry.
// Its cut is only a proposed locator; no instruction count or symbol extent is
// a successful endpoint. CheckTransition independently reconstructs all bytes.
// Numeric cuts select the first hit and require a unique activation in the
// stopped graph. Unselected TransitionExpansionRequired forms remain structural terminals,
// with no execution or successor inspection. Expansion choices select search
// only; their use and actual supported operand forms are checked later.
func ProposeTransition(ctx context.Context, im *Image, cut uint64, limits TransitionLimits, options ...TransitionOptions) (TransitionProposal, error) {
	im = im.snapshot()
	var entry uint64
	if im != nil {
		entry = im.entry
	}
	return proposeRootedTransition(ctx, im, transitionRoot{entry: entry}, cut, limits, options)
}

// ProposeRegionTransition discovers candidate coverage from an explicitly
// selected conditional entry in the original image. It establishes no reachability
// from the ELF entry. CheckRegionTransition independently binds entry and bytes.
func ProposeRegionTransition(ctx context.Context, im *Image, entry, cut uint64, limits TransitionLimits, options ...TransitionOptions) (TransitionProposal, error) {
	return proposeRootedTransition(ctx, im.snapshot(), transitionRoot{entry: entry, region: true}, cut, limits, options)
}

func proposeRootedTransition(ctx context.Context, im *Image, root transitionRoot, cut uint64, limits TransitionLimits, options []TransitionOptions) (TransitionProposal, error) {
	l, err := transitionLimits(limits)
	if err != nil {
		return TransitionProposal{}, refuse(0, "transition-budget", err.Error())
	}
	work := 0
	o, err := captureTransitionOptions(options, l, &work)
	if err != nil {
		return TransitionProposal{}, err
	}
	m, err := newTransitionChecker(ctx, im, root, l, work)
	if err != nil {
		return TransitionProposal{}, err
	}
	return m.discoverTransition(cut, o, nil, 0)
}

// CheckTransition derives a universally quantified conditional ELF-entry-to-cut
// machine-state relation. It owns caller containers before context callbacks,
// validates joint nonemptiness of the origin/memory predicates, and re-decodes the
// entire proposed graph. No expected outputs, sampled stack base, source association
// or return/callee interface are inputs. Failure yields no partial certificate.
func CheckTransition(ctx context.Context, im *Image, face TransitionInterface, proposal TransitionProposal, limits TransitionLimits) (TransitionCertificate, error) {
	im = im.snapshot()
	var entry uint64
	if im != nil {
		entry = im.entry
	}
	return checkRootedTransition(ctx, im, transitionRoot{entry: entry}, face, proposal, limits)
}

// CheckRegionTransition checks a conditional entry-to-cut relation in the original
// owned image. Entry is selected independently of proposal.Entry. It supplies no
// ELF-entry reachability, omitted-prefix or source association. Root-loading image
// initialization is refused: current memory starts under the explicit entry
// relations and declared permissions, with all remaining bytes arbitrary.
func CheckRegionTransition(ctx context.Context, im *Image, entry uint64, face TransitionInterface, proposal TransitionProposal, limits TransitionLimits) (TransitionCertificate, error) {
	return checkRootedTransition(ctx, im.snapshot(), transitionRoot{entry: entry, region: true}, face, proposal, limits)
}

func checkRootedTransition(ctx context.Context, im *Image, root transitionRoot, face TransitionInterface, proposal TransitionProposal, limits TransitionLimits) (TransitionCertificate, error) {
	if proposal.After != 0 {
		return TransitionCertificate{}, refuse(proposal.Cut, "transition-anchor", "fresh root cannot inherit an anchor")
	}
	l, err := transitionLimits(limits)
	if err != nil {
		return TransitionCertificate{}, refuse(0, "transition-budget", err.Error())
	}
	if len(face.Regions) > l.Regions || len(face.ImageRegions) > l.Regions-len(face.Regions) || len(face.Words) > l.Bytes/8 || len(face.EntryImagePointers) > 15 || len(face.EntryWordUpperBounds) > l.Bytes/8 {
		return TransitionCertificate{}, refuse(0, "transition-budget", "input inventory exceeds limits")
	}
	work := 0
	if face.PrivateFrame != nil {
		if err := transitionCopyWork(&work, l.Work, 1); err != nil {
			return TransitionCertificate{}, err
		}
	}
	if face.ReturnContext != nil {
		if len(face.ReturnContext.Preserved) > 15 {
			return TransitionCertificate{}, refuse(0, "transition-budget", "return-context input inventory")
		}
		if returnContextBytes(face.ReturnContext) > l.LiveStateBytes {
			return TransitionCertificate{}, refuse(0, "transition-budget", "incoming return context storage")
		}
		if err := transitionCopyWork(&work, l.Work, 1, len(face.ReturnContext.Preserved)); err != nil {
			return TransitionCertificate{}, err
		}
	}
	if err := transitionCopyWork(&work, l.Work, len(face.Regions), len(face.ImageRegions), len(face.Words), len(face.EntryImagePointers), len(face.EntryWordUpperBounds)); err != nil {
		return TransitionCertificate{}, err
	}
	proposal, err = captureTransitionProposal(proposal, l, &work)
	if err != nil {
		return TransitionCertificate{}, err
	}
	face = cloneTransitionInterface(face)
	m, err := newTransitionChecker(ctx, im, root, l, work)
	if err != nil {
		return TransitionCertificate{}, err
	}
	if proposal.Entry != root.entry || proposal.ImageDigest != im.digest {
		return TransitionCertificate{}, refuse(root.entry, "transition-proposal", "image or independently selected entry differs")
	}
	m.face = face
	m.witness = proposal
	m.bound = TransitionBound{ImageDigest: im.digest, Rules: TransitionRules, Entry: root.entry, ConditionalRegion: root.region, Interface: face}
	if err := m.validate(); err != nil {
		return TransitionCertificate{}, err
	}
	g, err := m.occurrenceGraph(proposal)
	if err != nil {
		return TransitionCertificate{}, err
	}
	if err := m.validateReturnTargetGraph(g); err != nil {
		return TransitionCertificate{}, err
	}
	if err := m.validatePrivateDeadlineGraph(g); err != nil {
		return TransitionCertificate{}, err
	}
	if err := m.initial(); err != nil {
		return TransitionCertificate{}, err
	}
	return m.finish(g, 0)
}

// CheckTransitionContinuation extends opaque checked evidence to a new cut. The
// proposal inventories the FULL original entry-to-new-cut graph. Only the
// suffix executes, starting with the predecessor's unexecuted boundary. Original
// terms, permissions, origin domain and normalized limits are inherited exactly;
// the result is conditional on the mapping and interference premises holding over
// the entire longer scope. A parent's theorem does not observe their stability.
// Caller containers are captured before any context callback. Failure publishes
// no certificate and cannot change the predecessor or an independent sibling.
func CheckTransitionContinuation(ctx context.Context, predecessor TransitionCertificate, proposal TransitionProposal) (TransitionCertificate, error) {
	if predecessor.checked == nil {
		return TransitionCertificate{}, refuse(0, "transition-predecessor", "missing checked predecessor")
	}
	prior := *predecessor.checked
	if prior.bound.Rules != TransitionRules {
		return TransitionCertificate{}, refuse(0, "transition-predecessor", "unrecognized complete transition rules")
	}
	work := prior.work
	proposal, err := captureTransitionProposal(proposal, prior.limits, &work)
	if err != nil {
		return TransitionCertificate{}, err
	}
	m, err := newTransitionChecker(ctx, prior.image, transitionRoot{entry: prior.bound.Entry, region: prior.bound.ConditionalRegion}, prior.limits, work)
	if err != nil {
		return TransitionCertificate{}, err
	}
	if proposal.Entry != prior.bound.Entry || proposal.ImageDigest != prior.bound.ImageDigest {
		return TransitionCertificate{}, refuse(proposal.Entry, "transition-proposal", "image or retained root entry differs")
	}
	c, err := m.continueTransition(prior, proposal)
	return c, err
}

// Numeric continuation advances beyond every previously executed address.
// Anchored continuation and actual-call application instead retain the explicitly
// selected anchor, with the same exact-prefix, transfer and resource checks.
func (m *transitionChecker) advancingCut(prior checkedTransition, cut uint64) error {
	if cut == prior.bound.Boundary.PC {
		return refuse(cut, "transition-continuation", "cut must advance beyond predecessor")
	}
	for _, span := range prior.bound.Instructions {
		if !m.tick() {
			return m.err
		}
		if cut >= span.Start && cut < span.End {
			return refuse(cut, "transition-continuation", "cut intersects executed predecessor")
		}
	}
	return nil
}

func (m *transitionChecker) continueTransition(prior checkedTransition, proposal TransitionProposal) (TransitionCertificate, error) {
	if proposal.After == 0 {
		if err := m.advancingCut(prior, proposal.Cut); err != nil {
			return TransitionCertificate{}, err
		}
	} else if proposal.After != prior.bound.Boundary.ID && (m.returnAnchor == 0 || proposal.After != m.returnAnchor) {
		return TransitionCertificate{}, refuse(proposal.Cut, "transition-anchor", "anchor is not the checked predecessor boundary")
	}
	m.witness = proposal
	if err := m.retainPrefix(prior); err != nil {
		return TransitionCertificate{}, err
	}
	g, err := m.occurrenceGraph(proposal)
	if err != nil {
		return TransitionCertificate{}, err
	}
	start, err := m.continuationStart(g, prior)
	if err != nil {
		return TransitionCertificate{}, err
	}
	if err := m.inherit(prior); err != nil {
		return TransitionCertificate{}, err
	}
	if err := m.validateReturnTargetGraph(g); err != nil {
		return TransitionCertificate{}, err
	}
	if err := m.validatePrivateDeadlineGraph(g); err != nil {
		return TransitionCertificate{}, err
	}
	return m.finish(g, start)
}

func (m *transitionChecker) finish(g *graph, start int) (TransitionCertificate, error) {
	// A state is owned by exactly one pending node or the current transfer. Forks
	// copy, joins consume, and single-successor edges move ownership.
	if len(g.nodes) > (m.limits.LiveStateBytes-m.liveStateBytes)/8 {
		return TransitionCertificate{}, refuse(m.pc, "transition-budget", "live node-state inventory")
	}
	m.liveStateBytes += 8 * len(g.nodes)
	states := make([]*transitionNodeState, len(g.nodes))
	states[g.order[start]] = m.takeState()
	var cutState *transitionNodeState
	for _, idx := range g.order[start:] {
		ins := g.nodes[idx]
		m.pc = ins.pc
		m.activation, m.occurrence = ins.activation, ins.id
		if !m.tick() {
			return TransitionCertificate{}, g.failureInstruction(ins, m.err)
		}
		s := states[idx]
		states[idx] = nil
		if s == nil {
			return TransitionCertificate{}, refuse(ins.pc, "transition-cut", "missing incoming state")
		}
		m.installState(s)
		if ins.boundary == boundaryCut {
			i, bytes, err := decodeBytes(m.im, ins.pc)
			if err != nil {
				return TransitionCertificate{}, g.failureInstruction(ins, err)
			}
			m.bound.Boundary = CutBoundary{ID: ins.id, PC: ins.pc, Context: ins.activation, Instruction: i, Bytes: append([]byte(nil), bytes...)}
			m.bound.CutGuard = m.state.path
			cutState = m.takeState()
			continue
		}
		if ins.boundary == boundaryUnsupported || ins.boundary == boundaryFrontier {
			w, err := m.proveFalseGuard(m.state.path)
			if err != nil {
				if r, ok := err.(*Refusal); ok && ins.boundary == boundaryFrontier && r.Premise == "transition-guard" {
					err = refuse(ins.pc, "transition-frontier", "residual supported transfer has no checked false incoming guard")
				}
				return TransitionCertificate{}, g.failureInstruction(ins, err)
			}
			i, raw, err := decodeBytes(m.im, ins.pc)
			if err != nil {
				return TransitionCertificate{}, g.failureInstruction(ins, err)
			}
			if err := m.reserveExclusion(); err != nil {
				return TransitionCertificate{}, err
			}
			b := ExcludedBoundary{CutBoundary: CutBoundary{ID: ins.id, PC: ins.pc, Context: ins.activation, Instruction: i, Bytes: append([]byte(nil), raw...)}, Guard: m.state.path, Frontier: ins.boundary == boundaryFrontier}
			m.bound.ExcludedBoundaries = append(m.bound.ExcludedBoundaries, b)
			m.exclusions = append(m.exclusions, w)
			m.memory = nil
			m.liveStateBytes -= m.stateBytes
			continue
		}
		guard := m.state.path
		// Literal false is independently evident. Other guards retain their
		// transfers even if a stronger solver might prove them impossible.
		if !literalBool(guard, 0) {
			if err := m.step(ins.inst, ins.size); err != nil {
				return TransitionCertificate{}, g.failureInstruction(ins, err)
			}
		}
		m.bound.Instructions = append(m.bound.Instructions, GuardedInstruction{ID: ins.id, Span: Span{ins.pc, ins.pc + uint64(ins.size)}, Guard: guard, Context: ins.activation})
		if m.witness.Nodes[idx].Expanded {
			m.bound.Expansions = append(m.bound.Expansions, TransitionExpansion{ID: ins.id, PC: ins.pc, Context: ins.activation})
		}
		s = m.takeState()
		var predicate br.Term
		if ins.count == 2 {
			predicate = m.transitionPredicate(ins.inst.Op, s.scalar, s.flags)
		}
		for edge, next := range ins.next[:ins.count] {
			incoming := s
			if edge+1 < int(ins.count) {
				incoming = m.copyState(s)
				if m.err != nil {
					return TransitionCertificate{}, m.err
				}
			}
			if ins.count == 2 {
				p := predicate
				if edge == 0 {
					p = m.not(p)
				}
				incoming.scalar.path = m.and(guard, p)
			}
			m.mergeState(&states[next], incoming)
		}
		if m.err != nil {
			return TransitionCertificate{}, g.failureInstruction(ins, m.err)
		}
	}
	if cutState == nil {
		return TransitionCertificate{}, refuse(m.pc, "transition-cut", "missing cut state")
	}
	m.installState(cutState)
	m.bound.Endpoint = m.endpoint
	m.pc, m.activation = m.bound.Boundary.PC, m.bound.Boundary.Context
	m.occurrence = m.bound.Boundary.ID
	m.bound.Thread = m.thread
	m.bound.Vectors = m.vectors
	m.bound.Direction = m.direction
	for range m.frames {
		if !m.tick() {
			return TransitionCertificate{}, m.err
		}
	}
	m.bound.Frames = append([]TransitionFrame(nil), m.frames...)
	for r := range m.state.regs {
		if !m.tick() {
			return TransitionCertificate{}, m.err
		}
		m.bound.Registers[r] = TransitionValue{m.state.regs[r], m.pointers[r]}
	}
	m.bound.Memory = m.projectMemory()
	if !m.tick() {
		return TransitionCertificate{}, m.err
	}
	// Complete-cut induction, rather than propositional normalization: the root
	// condition is EntryPredicate (or the predecessor's exact proved-total cut condition).
	// Each fork above produces G&!P and G&P, each join consumes their complete
	// incoming union, and the acyclic schedule processes every such edge exactly
	// once. All terminals other than this cut have checked false incoming guards.
	// Thus every admitted valuation contributes to this exact CutGuard. No graph
	// closure assertion substitutes a literal true or discards a transfer.
	return TransitionCertificate{&checkedTransition{witness: m.witness, image: m.im, bound: m.bound, limits: m.limits, work: m.work, flags: m.state.flags, exclusions: m.exclusions, justifications: m.justifications, coverageGuard: m.bound.CutGuard}}, nil
}

func (m *transitionChecker) projectMemory() []TransitionByte {
	if !m.tick() {
		return nil
	}
	bytes := make([]TransitionByte, 0, len(m.memory))
	for _, b := range m.memory {
		if !m.tick() {
			return nil
		}
		bytes = append(bytes, b)
	}
	// Reserve comparison-scale sorting work independently of randomized map
	// iteration. Cancellation/budget failure stops before entering the sort.
	for range 4 * bits.Len(uint(len(bytes))) {
		for range bytes {
			if !m.tick() {
				return nil
			}
		}
	}
	slices.SortFunc(bytes, func(a, b TransitionByte) int {
		n, err := m.bound.Geometry.Compare(a.TransitionLocation, b.TransitionLocation)
		if err != nil {
			m.err = err
		}
		return n
	})
	return bytes
}

func (m *transitionChecker) initial() error {
	m.builder, m.scope = br.NewBuilder(m.limits.Nodes), br.NewScope()
	m.truth, m.falsity = m.con(br.Bool(), 1), m.con(br.Bool(), 0)
	m.state.path, m.state.present = m.truth, true
	for r := range m.state.regs {
		m.state.regs[r] = m.scratch(br.Bits(64))
		m.bound.Preserved[r] = ^uint64(0)
	}
	for f := range m.state.flags {
		m.state.flags[f] = m.scratch(br.Bool())
	}
	m.bound.InitialPredicates = TransitionPredicates{m.state.flags[flagCarry], m.state.flags[flagZero], m.state.flags[flagLess]}
	m.direction = m.scratch(br.Bool())
	m.bound.InitialDirection = m.direction
	m.bound.Origin = m.state.regs[RSP]
	m.bound.InitialRegisters = m.state.regs
	if m.face.Conditions.SSE == SSEModel {
		m.vectors = m.initialSSEVectors()
		m.bound.InitialVectors = m.vectors
		m.bound.SSE = TransitionSSEContext{MXCSRPreserved: true, UpperVectorsPreserved: true}
	}
	if m.face.Conditions.Syscall != "" {
		m.bound.InitialFS = m.scratch(br.Bits(64))
		m.thread = TransitionThread{FS: TransitionValue{Value: m.bound.InitialFS}, SelectorPreserved: true}
	}
	f := TransitionFlag{Preserved: true, Defined: true}
	m.bound.Flags = TransitionFlags{f, f, f, f, f, f}
	total := 0
	for _, r := range m.face.Regions {
		total += int(r.Bytes.End - r.Bytes.Start)
	}
	for _, r := range m.face.ImageRegions {
		total += int(r.End - r.Start)
	}
	if err := m.reserveState(total); err != nil {
		return err
	}
	if err := m.reserveGeometry(); err != nil {
		return err
	}
	m.bound.Geometry = newTransitionGeometry(m.im, m.face, m.bound.Origin)
	m.pointers[RSP] = m.bound.Geometry.stackPointer(0)
	m.memory = make(map[TransitionLocation]TransitionByte)
	for _, r := range m.face.Regions {
		for off := r.Bytes.Start; off < r.Bytes.End; off++ {
			if !m.tick() {
				return m.err
			}
			key := m.bound.Geometry.stackLocation(off)
			if _, exists := m.memory[key]; !exists {
				m.memory[key] = TransitionByte{TransitionLocation: key, Value: m.scratch(br.Bits(8))}
			}
		}
	}
	for _, r := range m.face.ImageRegions {
		for addr := r.Start; addr < r.End; addr++ {
			if !m.tick() {
				return m.err
			}
			key := m.bound.Geometry.imageLocation(int64(addr))
			if _, exists := m.memory[key]; !exists {
				var value br.Term
				if v, known := m.initialImageByte(addr); known {
					value = m.con(br.Bits(8), uint64(v))
				} else {
					value = m.scratch(br.Bits(8))
				}
				m.memory[key] = TransitionByte{TransitionLocation: key, Value: value}
			}
		}
	}
	for _, off := range m.face.Words {
		a := m.scratch(br.Bits(64))
		m.bound.Words = append(m.bound.Words, TransitionWord{TransitionExtent{m.bound.Geometry.stackLocation(off), 8}, a})
		for j := 0; j < 8; j++ {
			key := m.bound.Geometry.stackLocation(off + int64(j))
			m.memory[key] = TransitionByte{TransitionLocation: key, Value: m.extract(a, j*8, 8)}
		}
	}
	if err := m.initialEntryRelations(); err != nil {
		return err
	}
	if err := m.initialReturnContext(); err != nil {
		return err
	}
	m.bound.InitialMemory = m.projectMemory()
	return m.err
}

func (m *transitionChecker) advance(pointer TransitionPointer, delta int64) (TransitionPointer, error) {
	if m.bound.Geometry.root == nil || !sameImage(m.bound.Geometry.root.image, m.im) {
		return nil, refuse(m.pc, "transition-provenance", "address lacks the checked origin")
	}
	p, _, failure := m.bound.Geometry.pointerRange(pointer, delta, 0, m.pc)
	if failure != nil {
		return nil, failure
	}
	return p, nil
}

func (m *transitionChecker) ripPointer(disp int64, size uint8) (TransitionPointer, error) {
	next, ok := plus(m.pc, uint64(size))
	address, valid := relative(next, disp)
	if !ok || next >= 1<<47 || !valid || address >= 1<<47 {
		return nil, refuse(m.pc, "transition-image", "RIP-relative address wraps or is noncanonical")
	}
	load, err := m.imageLoad(Span{address, address}, true)
	if err != nil {
		return nil, err
	}
	return m.bound.Geometry.imagePointer(load, address), nil
}

func (m *transitionChecker) address(mem x86asm.Mem, kind AccessKind, width int, size uint8) (TransitionLocation, error) {
	var p TransitionPointer
	var err error
	if mem.Segment == x86asm.FS {
		p, err = m.advance(m.thread.FS.Pointer, mem.Disp)
	} else if mem.Base == x86asm.RIP {
		p, err = m.ripPointer(mem.Disp, size)
	} else {
		base, _ := fullRegister(mem.Base)
		p, err = m.advance(m.pointers[base.reg], mem.Disp)
	}
	if err != nil {
		return TransitionLocation{}, err
	}
	return m.accessPointer(p, kind, width)
}

func (m *transitionChecker) accessPointer(p TransitionPointer, kind AccessKind, width int) (TransitionLocation, error) {
	if width <= 0 {
		return TransitionLocation{}, refuse(m.pc, "transition-provenance", "access lacks current memory provenance")
	}
	address, end, failure := m.bound.Geometry.pointerRange(p, 0, int64(width), m.pc)
	if failure != nil {
		return TransitionLocation{}, failure
	}
	if address.isImage() {
		if !m.imagePermission(Span{uint64(address.offset), uint64(end)}, kind) {
			if m.err != nil {
				return TransitionLocation{}, m.err
			}
			return TransitionLocation{}, refuse(m.pc, "transition-permission", "full image access lacks declared permission")
		}
		return m.bound.Geometry.imageLocation(address.offset), nil
	}
	span := RelativeSpan{address.offset, end}
	if kind == FrameWrite && m.face.ReturnContext != nil && span.Start < 8 && span.End > 0 {
		return TransitionLocation{}, refuse(m.pc, "transition-return-protected", "write overlaps the incoming continuation control word")
	}
	if !m.permission(span, kind) {
		if m.err != nil {
			return TransitionLocation{}, m.err
		}
		return TransitionLocation{}, refuse(m.pc, "transition-permission", "full access lacks declared permission")
	}
	return m.bound.Geometry.stackLocation(address.offset), nil
}

func (m *transitionChecker) recordAccess(off TransitionLocation, width int, kind AccessKind, value br.Term) {
	if !m.tick() {
		return
	}
	m.bound.Accesses = append(m.bound.Accesses, TransitionAccess{ID: m.occurrence, PC: m.pc, Context: m.activation, Kind: kind, Bytes: TransitionExtent{off, int64(width)}, Value: value})
}

func (m *transitionChecker) load(off TransitionLocation, width int, kind AccessKind) TransitionValue {
	v := m.memoryValue(off, width)
	m.recordAccess(off, width, kind, v.Value)
	return v
}

// memoryValue assembles the current byte relation without an executed access.
// Entry relations and actual loads must use exactly the same overlapping bytes.
func (m *transitionChecker) memoryValue(off TransitionLocation, width int) TransitionValue {
	var lanes [8]pointerLane[TransitionPointer]
	var v br.Term
	for j := 0; j < width; j++ {
		key := off.add(int64(j))
		b := m.memory[key]
		lanes[j] = pointerLane[TransitionPointer]{b.Pointer, b.PointerLane}
		if j == 0 {
			v = b.Value
		} else {
			v = m.make(br.Concat, br.Bits((j+1)*8), 0, v, b.Value)
		}
	}
	var pointer TransitionPointer
	if width == 8 {
		pointer = orderedPointer(lanes[:])
	}
	return TransitionValue{v, pointer}
}

func (m *transitionChecker) store(off TransitionLocation, v TransitionValue, width int) {
	m.recordAccess(off, width, FrameWrite, v.Value)
	if width != 8 {
		v.Pointer = nil
	}
	for j := 0; j < width; j++ {
		b := TransitionByte{TransitionLocation: off.add(int64(j)), Value: m.extract(v.Value, j*8, 8), Pointer: v.Pointer}
		if v.Pointer != nil {
			b.PointerLane = uint8(j)
		}
		// Replace every byte, including provenance; overlapping stores cannot
		// retain overwritten lanes even when scalar bits happen to agree.
		m.memory[b.TransitionLocation] = b
	}
}

func (m *transitionChecker) step(i operation, size uint8) error {
	if i.Op == x86asm.CLD {
		m.direction = m.falsity
		return m.err
	}
	if i.Op == x86asm.INC || i.Op == x86asm.SHL || i.Op == x86asm.SBB {
		return m.scalarTail(i)
	}
	if i.Op == x86asm.AND {
		if r, ok := i.Args[0].(x86asm.Reg); ok {
			if a, valid := register(r); valid && a.width == 32 {
				return m.scalarTail(i)
			}
		}
	}
	if isTransitionSSE(i.Op) {
		return m.sseStep(i, size, &m.vectors, m.face.Conditions.SSE)
	}
	if (i.Op == x86asm.AND || i.Op == x86asm.OR) && i.MemBytes == 1 {
		return m.lockedLogical(i, size)
	}
	if i.Op == x86asm.CMPXCHG {
		return m.lockedCompareExchange(i, size)
	}
	if i.Op == x86asm.XCHG || i.Op == x86asm.XADD {
		return m.lockedExchange(i, size)
	}
	if isTransitionSet(i.Op) {
		return m.setConditionByte(i, size)
	}
	if i.Op == x86asm.CALL || i.Op == x86asm.PUSH || i.Op == x86asm.POP || i.Op == x86asm.RET {
		return m.stackStep(i, size)
	}
	if i.Op == x86asm.SYSCALL {
		return m.archSetFS(size)
	}
	if i.Op == x86asm.CPUID {
		return m.cpuid()
	}
	if i.Op == x86asm.JMP || i.Op == x86asm.NOP || condition(i.Op) != 0 || i.Op == x86asm.JP || i.Op == x86asm.JNP {
		return nil
	}
	if i.Op == x86asm.CMP || i.Op == x86asm.TEST {
		// The established register-only domain retains only the predicates its
		// conditions consume. Full flag projections are needed for the new byte
		// and memory transfers; deriving unused flags here would change its
		// existing expression-resource frontier.
		if reg, ok := i.Args[0].(x86asm.Reg); ok && i.MemBytes == 0 {
			a, _ := register(reg)
			if a.width != 8 {
				if err := m.valueBuilder.transfer(m.pc, i, &m.state); err != nil {
					return err
				}
				f := TransitionFlag{Defined: true}
				m.bound.Flags = TransitionFlags{f, f, f, f, f, f}
				m.bound.Flags.CF.Value, m.bound.Flags.ZF.Value = m.state.flags[flagCarry], m.state.flags[flagZero]
				if i.Op == x86asm.TEST {
					m.bound.Flags.OF.Value, m.bound.Flags.SF.Value = m.falsity, m.state.flags[flagLess]
					m.bound.Flags.AF = TransitionFlag{}
				}
				if right, full := fullRegister(i.Args[1]); i.Op == x86asm.CMP && a.width == 64 && full {
					if _, err := m.refineOriginCompare(
						TransitionValue{Value: m.state.regs[a.reg], Pointer: m.pointers[a.reg]},
						TransitionValue{Value: m.state.regs[right.reg], Pointer: m.pointers[right.reg]}); err != nil {
						return err
					}
				}
				return m.err
			}
		}
		return m.compareOrTest(i, size)
	}
	if i.Op == x86asm.MOV {
		if mem, ok := i.Args[0].(x86asm.Mem); ok {
			off, err := m.address(mem, FrameWrite, i.MemBytes, size)
			if err != nil {
				return err
			}
			v := TransitionValue{}
			if r, ok := i.Args[1].(x86asm.Reg); ok {
				a, _ := register(r)
				v.Value = m.read(&m.state, a)
				if a.width == 64 {
					v.Pointer = m.pointers[a.reg]
				}
			} else {
				v.Value = m.con(br.Bits(i.MemBytes*8), uint64(i.Args[1].(x86asm.Imm))&mask(i.MemBytes*8))
			}
			m.store(off, v, i.MemBytes)
			return m.err
		}
	}
	a, _ := register(i.Args[0].(x86asm.Reg))
	if a.width == 32 {
		m.bound.Preserved[a.reg] = 0
	} else {
		m.bound.Preserved[a.reg] &^= mask(a.width) << a.shift
	}
	var p TransitionPointer
	switch i.Op {
	case x86asm.MOV:
		if mem, ok := i.Args[1].(x86asm.Mem); ok {
			off, err := m.address(mem, FrameRead, i.MemBytes, size)
			if err != nil {
				return err
			}
			v := m.load(off, i.MemBytes, FrameRead)
			m.write(&m.state, a, v.Value)
			m.pointers[a.reg] = v.Pointer
			return m.err
		}
		if src, ok := fullRegister(i.Args[1]); ok {
			p = m.pointers[src.reg]
		}
	case x86asm.LEA:
		mem := i.Args[1].(x86asm.Mem)
		if mem.Base == x86asm.RIP {
			var err error
			p, err = m.ripPointer(mem.Disp, size)
			if err != nil {
				return err
			}
			// RIP is not a GPR. Its exact decoded next PC supplies this scalar,
			// separately from the shared base-register LEA interpreter.
			m.state.regs[a.reg] = m.con(br.Bits(64), uint64(p.(AddressPointer).offset))
			m.pointers[a.reg] = p
			return m.err
		}
		base, _ := fullRegister(mem.Base)
		if addressCapability(m.pointers[base.reg]) != nil {
			var err error
			p, err = m.advance(m.pointers[base.reg], mem.Disp)
			if err != nil {
				return err
			}
		}
	case x86asm.SUB, x86asm.ADD:
		imm, immediate := i.Args[1].(x86asm.Imm)
		delta := int64(imm)
		if i.Op == x86asm.SUB {
			delta = -delta
		} // checked signed imm8/imm32
		if immediate && addressCapability(m.pointers[a.reg]) != nil {
			var err error
			p, err = m.advance(m.pointers[a.reg], delta)
			if err != nil {
				return err
			}
		}
		if i.Op == x86asm.ADD {
			var right br.Term
			if immediate {
				right = m.con(br.Bits(a.width), uint64(imm)&mask(a.width))
			} else {
				src, _ := register(i.Args[1].(x86asm.Reg))
				right = m.read(&m.state, src)
			}
			r := m.add(m.read(&m.state, a), right)
			m.write(&m.state, a, r.Value)
			m.bound.Flags = r.Flags
			m.setPredicates(r.Predicates)
			m.pointers[a.reg] = p
			return m.err
		}
		// SUB defines all six arithmetic flags. Their values are deliberately
		// unprojected; shared scalar transfer retains the accurate private CF,
		// ZF and SF!=OF predicates for continuation.
		f := TransitionFlag{Defined: true}
		m.bound.Flags = TransitionFlags{f, f, f, f, f, f}
	case x86asm.AND:
		old, stack := m.pointers[a.reg].(AddressPointer)
		k := -uint64(i.Args[1].(x86asm.Imm))
		d, ok := alignmentOffset(old.offset, m.face.Origin.Modulus, m.face.Origin.Residue, k)
		_, original := m.bound.Geometry.OriginalStack(old)
		if !stack || !original || !ok {
			return refuse(m.pc, "transition-alignment", "mask or pointer congruence cannot justify alignment")
		}
		if err := m.offset(old.offset); err != nil {
			return err
		}
		if err := m.offset(d); err != nil {
			return err
		}
		p = m.bound.Geometry.stackPointer(d)
		zero := TransitionFlag{Defined: true, Value: m.falsity}
		z := TransitionFlag{Defined: true}
		low, _ := relative(m.lo, d)
		high, _ := relative(m.hi, d)
		if low > 0 {
			z.Value = m.falsity
		} else if high == 0 {
			z.Value = m.truth
		}
		m.bound.Flags = TransitionFlags{CF: zero, OF: zero, SF: zero, ZF: z, PF: TransitionFlag{Defined: true}}
	case x86asm.XOR:
		// The decoder admitted only a 32-bit self-XOR. Its full-width result
		// comes from the shared scalar transfer; AF is undefined, not preserved.
		zero := TransitionFlag{Defined: true, Value: m.falsity}
		one := TransitionFlag{Defined: true, Value: m.truth}
		m.bound.Flags = TransitionFlags{CF: zero, OF: zero, SF: zero, ZF: one, PF: one}
	}
	// All operands, prefixes, widths and immediate extensions were validated by
	// decodeTransition. The shared value interpreter now supplies MOV/LEA/SUB/AND
	// scalar semantics, including self-XOR. Origin rules above justify conditional value/provenance
	// agreement separately; bitrelation.Check accepts no external hypotheses.
	if err := m.valueBuilder.transfer(m.pc, i, &m.state); err != nil {
		return err
	}
	m.pointers[a.reg] = p
	return m.err
}
