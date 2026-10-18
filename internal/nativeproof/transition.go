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
	face                       TransitionInterface
	limits                     TransitionLimits
	lo, hi                     uint64
	bound                      TransitionBound
	state                      symbolicState
	pointers                   [16]TransitionPointer
	memory                     map[TransitionLocation]TransitionByte
	liveStateBytes, stateBytes int
	exclusions                 []br.Witness
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

func newTransitionChecker(ctx context.Context, im *Image, l TransitionLimits, work int) (*transitionChecker, error) {
	if ctx == nil {
		return nil, refuse(0, "transition-context", "missing context")
	}
	if im == nil || len(im.data) == 0 {
		return nil, refuse(0, "image-binding", "missing constructed image")
	}
	m := &transitionChecker{im: im, limits: l, valueBuilder: &valueBuilder{ctx: ctx, limits: l.RelationLimits, work: work, pc: im.entry, depth: make(map[br.Term]int)}}
	if !m.tick() {
		return nil, m.err
	}
	if _, err := im.instructionBytes(im.entry); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *transitionChecker) graph(cut uint64) (*graph, error) {
	g, err := decodeGraphUsing(&relationContext{Context: m.ctx, meter: m.valueBuilder}, m.im.entry, m.limits.Instructions, func(pc uint64) (decodedInstruction, error) {
		m.pc = pc
		return decodeTransitionBoundary(m.im, pc, cut)
	})
	if err != nil {
		return nil, err
	}
	if idx, ok := g.byPC[cut]; !ok || g.nodes[idx].boundary != boundaryCut {
		return nil, refuse(cut, "transition-cut", "cut is not a reachable decoded boundary")
	}
	// Syntactic closure permits the declared cut and candidate unsupported
	// terminals. Neither discovery nor scheduling supplies their false proofs.
	for _, n := range g.nodes {
		if !m.tick() {
			return nil, m.err
		}
		if n.boundary != boundaryCut && n.boundary != boundaryUnsupported && n.count == 0 {
			return nil, refuse(n.pc, "transition-cut", "unclosed prefix path")
		}
	}
	return g, nil
}

// ProposeTransition discovers candidate coverage from the ELF-declared entry.
// Its cut is only a proposed locator; no instruction count or symbol extent is
// a successful endpoint. CheckTransition independently reconstructs all bytes.
func ProposeTransition(ctx context.Context, im *Image, cut uint64, limits TransitionLimits) (TransitionProposal, error) {
	im = im.snapshot()
	l, err := transitionLimits(limits)
	if err != nil {
		return TransitionProposal{}, refuse(0, "transition-budget", err.Error())
	}
	m, err := newTransitionChecker(ctx, im, l, 0)
	if err != nil {
		return TransitionProposal{}, err
	}
	g, err := m.graph(cut)
	if err != nil {
		return TransitionProposal{}, err
	}
	p := TransitionProposal{ImageDigest: im.digest, Entry: im.entry, Cut: cut}
	for _, ins := range g.nodes {
		if !m.tick() {
			return TransitionProposal{}, m.err
		}
		n := Node{PC: ins.pc, Size: ins.size}
		for _, next := range ins.next[:ins.count] {
			n.Successors = append(n.Successors, g.nodes[next].pc)
		}
		p.Nodes = append(p.Nodes, n)
	}
	if !m.tick() {
		return TransitionProposal{}, m.err
	}
	return p, nil
}

// CheckTransition derives a universally quantified conditional ELF-entry-to-cut
// machine-state relation. It owns caller containers before context callbacks,
// validates joint nonemptiness of the origin/memory predicates, and re-decodes the
// entire proposed graph. No expected outputs, sampled stack base, source association
// or return/callee interface are inputs. Failure yields no partial certificate.
func CheckTransition(ctx context.Context, im *Image, face TransitionInterface, proposal TransitionProposal, limits TransitionLimits) (TransitionCertificate, error) {
	im = im.snapshot()
	l, err := transitionLimits(limits)
	if err != nil {
		return TransitionCertificate{}, refuse(0, "transition-budget", err.Error())
	}
	if len(face.Regions) > l.Regions || len(face.ImageRegions) > l.Regions-len(face.Regions) || len(face.Words) > l.Bytes/8 {
		return TransitionCertificate{}, refuse(0, "transition-budget", "input inventory exceeds limits")
	}
	work := 0
	if err := transitionCopyWork(&work, l.Work, len(face.Regions), len(face.ImageRegions), len(face.Words)); err != nil {
		return TransitionCertificate{}, err
	}
	proposal, err = captureTransitionProposal(proposal, l, &work)
	if err != nil {
		return TransitionCertificate{}, err
	}
	face = cloneTransitionInterface(face)
	m, err := newTransitionChecker(ctx, im, l, work)
	if err != nil {
		return TransitionCertificate{}, err
	}
	if proposal.Entry != im.entry || proposal.ImageDigest != im.digest {
		return TransitionCertificate{}, refuse(im.entry, "transition-proposal", "image or ELF entry differs")
	}
	m.face = face
	m.bound = TransitionBound{ImageDigest: im.digest, Rules: TransitionRules, Entry: im.entry, Interface: face}
	if err := m.validate(); err != nil {
		return TransitionCertificate{}, err
	}
	g, err := m.graph(proposal.Cut)
	if err != nil {
		return TransitionCertificate{}, err
	}
	bounded := &relationContext{Context: ctx, meter: m.valueBuilder}
	if err := checkInventory(bounded, g, proposal.Nodes, "transition-proposal"); err != nil {
		return TransitionCertificate{}, err
	}
	if err := m.initial(); err != nil {
		return TransitionCertificate{}, err
	}
	return m.finish(g, 0)
}

// CheckTransitionContinuation extends opaque checked evidence to a new cut. The
// proposal inventories the FULL original ELF-entry-to-new-cut graph. Only the
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
	m, err := newTransitionChecker(ctx, prior.image, prior.limits, work)
	if err != nil {
		return TransitionCertificate{}, err
	}
	if proposal.Entry != prior.bound.Entry || proposal.ImageDigest != prior.bound.ImageDigest {
		return TransitionCertificate{}, refuse(proposal.Entry, "transition-proposal", "image or ELF entry differs")
	}
	if proposal.Cut == prior.bound.Boundary.PC {
		return TransitionCertificate{}, refuse(proposal.Cut, "transition-continuation", "cut must advance beyond predecessor")
	}
	for _, span := range prior.bound.Instructions {
		if !m.tick() {
			return TransitionCertificate{}, m.err
		}
		if proposal.Cut >= span.Start && proposal.Cut < span.End {
			return TransitionCertificate{}, refuse(proposal.Cut, "transition-continuation", "cut intersects executed predecessor")
		}
	}
	g, err := m.graph(proposal.Cut)
	if err != nil {
		return TransitionCertificate{}, err
	}
	if err := checkInventory(&relationContext{Context: ctx, meter: m.valueBuilder}, g, proposal.Nodes, "transition-proposal"); err != nil {
		return TransitionCertificate{}, err
	}
	start, err := m.continuationStart(g, prior)
	if err != nil {
		return TransitionCertificate{}, err
	}
	if err := m.inherit(prior); err != nil {
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
		if !m.tick() {
			return TransitionCertificate{}, g.failure(ins.pc, m.err)
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
				return TransitionCertificate{}, g.failure(ins.pc, err)
			}
			m.bound.Boundary = CutBoundary{PC: ins.pc, Instruction: i, Bytes: append([]byte(nil), bytes...)}
			m.bound.CutGuard = m.state.path
			cutState = m.takeState()
			continue
		}
		if ins.boundary == boundaryUnsupported {
			w, err := m.proveFalseGuard(m.state.path)
			if err != nil {
				return TransitionCertificate{}, g.failure(ins.pc, err)
			}
			i, raw, err := decodeBytes(m.im, ins.pc)
			if err != nil {
				return TransitionCertificate{}, g.failure(ins.pc, err)
			}
			if err := m.reserveExclusion(); err != nil {
				return TransitionCertificate{}, err
			}
			b := ExcludedBoundary{CutBoundary{PC: ins.pc, Instruction: i, Bytes: append([]byte(nil), raw...)}, m.state.path}
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
				return TransitionCertificate{}, g.failure(ins.pc, err)
			}
		}
		m.bound.Instructions = append(m.bound.Instructions, GuardedInstruction{Span{ins.pc, ins.pc + uint64(ins.size)}, guard})
		s = m.takeState()
		var predicate br.Term
		if ins.count == 2 {
			predicate = m.predicate(ins.inst.Op, s.scalar)
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
			return TransitionCertificate{}, g.failure(ins.pc, m.err)
		}
	}
	if cutState == nil {
		return TransitionCertificate{}, refuse(m.pc, "transition-cut", "missing cut state")
	}
	m.installState(cutState)
	for r := range m.state.regs {
		if !m.tick() {
			return TransitionCertificate{}, m.err
		}
		m.bound.Registers[r] = TransitionValue{m.state.regs[r], m.pointers[r]}
	}
	m.bound.Memory = m.projectMemory()
	if !m.tick() {
		return TransitionCertificate{}, g.failure(m.pc, m.err)
	}
	// Complete-cut induction, rather than propositional normalization: the root
	// condition is true (or the predecessor's exact proved-total cut condition).
	// Each fork above produces G&!P and G&P, each join consumes their complete
	// incoming union, and the acyclic schedule processes every such edge exactly
	// once. All terminals other than this cut have checked false incoming guards.
	// Thus every admitted valuation contributes to this exact CutGuard. No graph
	// closure assertion substitutes a literal true or discards a transfer.
	return TransitionCertificate{&checkedTransition{image: m.im, bound: m.bound, limits: m.limits, work: m.work, flags: m.state.flags, exclusions: m.exclusions, coverageGuard: m.bound.CutGuard}}, nil
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
		if a.Image != b.Image {
			if a.Image {
				return 1
			}
			return -1
		}
		if a.Offset < b.Offset {
			return -1
		}
		if a.Offset > b.Offset {
			return 1
		}
		return 0
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
	m.bound.Origin = m.state.regs[RSP]
	m.bound.InitialRegisters = m.state.regs
	m.pointers[RSP] = OriginPointer{Origin: m.bound.Origin}
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
	m.memory = make(map[TransitionLocation]TransitionByte)
	for _, r := range m.face.Regions {
		for off := r.Bytes.Start; off < r.Bytes.End; off++ {
			if !m.tick() {
				return m.err
			}
			key := TransitionLocation{Offset: off}
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
			key := TransitionLocation{Image: true, Offset: int64(addr)}
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
		m.bound.Words = append(m.bound.Words, TransitionWord{off, a})
		for j := 0; j < 8; j++ {
			key := TransitionLocation{Offset: off + int64(j)}
			m.memory[key] = TransitionByte{TransitionLocation: key, Value: m.extract(a, j*8, 8)}
		}
	}
	m.bound.InitialMemory = m.projectMemory()
	return m.err
}

func (m *transitionChecker) advance(pointer TransitionPointer, delta int64) (TransitionPointer, error) {
	if p, ok := pointer.(ImagePointer); ok {
		if p.owner != &m.im.data[0] || p.load < 0 || p.load >= len(m.im.loads) {
			return nil, refuse(m.pc, "transition-provenance", "image pointer belongs to another owner")
		}
		load := m.im.loads[p.load]
		address, ok := relative(p.Address, delta)
		if !ok || p.Address < load.va || p.Address > load.end || address < load.va || address > load.end || address >= 1<<47 {
			return nil, refuse(m.pc, "transition-image", "pointer escapes its logical image mapping")
		}
		p.Address = address
		return p, nil
	}
	p, valid := pointer.(OriginPointer)
	if !valid || p.Origin != m.bound.Origin || p.Origin == (br.Term{}) {
		return nil, refuse(m.pc, "transition-provenance", "address lacks the checked origin")
	}
	d, ok := signedPlus(p.Offset, delta)
	if !ok {
		return nil, refuse(m.pc, "transition-origin", "signed offset overflow")
	}
	if err := m.offset(d); err != nil {
		return nil, err
	}
	p.Offset = d
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
	return ImagePointer{Address: address, owner: &m.im.data[0], load: load}, nil
}

func (m *transitionChecker) address(mem x86asm.Mem, kind AccessKind, width int, size uint8) (TransitionLocation, error) {
	var p TransitionPointer
	var err error
	if mem.Base == x86asm.RIP {
		p, err = m.ripPointer(mem.Disp, size)
	} else {
		base, _ := fullRegister(mem.Base)
		p, err = m.advance(m.pointers[base.reg], mem.Disp)
	}
	if err != nil {
		return TransitionLocation{}, err
	}
	if image, ok := p.(ImagePointer); ok {
		end, valid := plus(image.Address, uint64(width))
		if !valid || end > m.im.loads[image.load].end || end > 1<<47 {
			return TransitionLocation{}, refuse(m.pc, "transition-image", "full access escapes logical mapping")
		}
		if !m.imagePermission(Span{image.Address, end}, kind) {
			if m.err != nil {
				return TransitionLocation{}, m.err
			}
			return TransitionLocation{}, refuse(m.pc, "transition-permission", "full image access lacks declared permission")
		}
		span := RelativeSpan{int64(image.Address), int64(end)}
		m.bound.Accesses = append(m.bound.Accesses, TransitionAccess{PC: m.pc, Kind: kind, Bytes: span, Image: true})
		return TransitionLocation{Image: true, Offset: int64(image.Address)}, nil
	}
	stack := p.(OriginPointer)
	end, ok := signedPlus(stack.Offset, int64(width))
	if !ok {
		return TransitionLocation{}, refuse(m.pc, "transition-origin", "access offset overflow")
	}
	if err := m.offset(end); err != nil {
		return TransitionLocation{}, err
	}
	span := RelativeSpan{stack.Offset, end}
	if !m.permission(span, kind) {
		if m.err != nil {
			return TransitionLocation{}, m.err
		}
		return TransitionLocation{}, refuse(m.pc, "transition-permission", "full access lacks declared permission")
	}
	m.bound.Accesses = append(m.bound.Accesses, TransitionAccess{PC: m.pc, Kind: kind, Bytes: span})
	return TransitionLocation{Offset: stack.Offset}, nil
}

func (m *transitionChecker) load(off TransitionLocation, width int) TransitionValue {
	var lanes [8]pointerLane[TransitionPointer]
	var v br.Term
	for j := 0; j < width; j++ {
		key := TransitionLocation{off.Image, off.Offset + int64(j)}
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
	if width != 8 {
		v.Pointer = nil
	}
	for j := 0; j < width; j++ {
		b := TransitionByte{TransitionLocation: TransitionLocation{off.Image, off.Offset + int64(j)}, Value: m.extract(v.Value, j*8, 8), Pointer: v.Pointer}
		if v.Pointer != nil {
			b.PointerLane = uint8(j)
		}
		// Replace every byte, including provenance; overlapping stores cannot
		// retain overwritten lanes even when scalar bits happen to agree.
		m.memory[b.TransitionLocation] = b
	}
}

func (m *transitionChecker) step(i operation, size uint8) error {
	if i.Op == x86asm.CPUID {
		return m.cpuid()
	}
	if i.Op == x86asm.JMP || condition(i.Op) != 0 {
		return nil
	}
	if i.Op == x86asm.CMP || i.Op == x86asm.TEST {
		if err := m.valueBuilder.transfer(m.pc, i, &m.state); err != nil {
			return err
		}
		f := TransitionFlag{Defined: true}
		m.bound.Flags = TransitionFlags{f, f, f, f, f, f}
		m.bound.Flags.CF.Value, m.bound.Flags.ZF.Value = m.state.flags[flagCarry], m.state.flags[flagZero]
		if i.Op == x86asm.TEST {
			m.bound.Flags.OF.Value = m.falsity
			m.bound.Flags.SF.Value = m.state.flags[flagLess]
			m.bound.Flags.AF = TransitionFlag{}
		}
		return m.err
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
			v := m.load(off, i.MemBytes)
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
			m.state.regs[a.reg] = m.con(br.Bits(64), p.(ImagePointer).Address)
			m.pointers[a.reg] = p
			return m.err
		}
		base, _ := fullRegister(mem.Base)
		if m.pointers[base.reg] != nil {
			var err error
			p, err = m.advance(m.pointers[base.reg], mem.Disp)
			if err != nil {
				return err
			}
		}
	case x86asm.SUB:
		delta := -int64(i.Args[1].(x86asm.Imm)) // checked signed imm8/imm32, never MinInt64
		if m.pointers[a.reg] != nil {
			var err error
			p, err = m.advance(m.pointers[a.reg], delta)
			if err != nil {
				return err
			}
		}
		// SUB defines all six arithmetic flags. Their values are deliberately
		// unprojected; shared scalar transfer retains the accurate private CF,
		// ZF and SF!=OF predicates for continuation.
		f := TransitionFlag{Defined: true}
		m.bound.Flags = TransitionFlags{f, f, f, f, f, f}
	case x86asm.AND:
		old, stack := m.pointers[a.reg].(OriginPointer)
		k := -uint64(i.Args[1].(x86asm.Imm))
		d, ok := alignmentOffset(old.Offset, m.face.Origin.Modulus, m.face.Origin.Residue, k)
		if !stack || old.Origin != m.bound.Origin || !ok {
			return refuse(m.pc, "transition-alignment", "mask or pointer congruence cannot justify alignment")
		}
		if err := m.offset(old.Offset); err != nil {
			return err
		}
		if err := m.offset(d); err != nil {
			return err
		}
		p = OriginPointer{old.Origin, d}
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
	}
	// All operands, prefixes, widths and immediate extensions were validated by
	// decodeTransition. The shared value interpreter now supplies MOV/LEA/SUB/AND
	// scalar semantics. Origin rules above justify conditional value/provenance
	// agreement separately; bitrelation.Check accepts no external hypotheses.
	if err := m.valueBuilder.transfer(m.pc, i, &m.state); err != nil {
		return err
	}
	m.pointers[a.reg] = p
	return m.err
}
