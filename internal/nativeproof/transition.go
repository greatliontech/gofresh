package nativeproof

import (
	"bytes"
	"context"
	"fmt"
	"math/bits"
	"slices"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

type transitionChecker struct {
	*valueBuilder
	im       *Image
	face     TransitionInterface
	limits   TransitionLimits
	lo, hi   uint64
	bound    TransitionBound
	state    symbolicState
	pointers [16]OriginPointer
	memory   map[int64]TransitionByte
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
		return decodeTransition(m.im, pc, cut)
	})
	if err != nil {
		return nil, err
	}
	if idx, ok := g.byPC[cut]; !ok || g.nodes[idx].boundary != boundaryCut {
		return nil, refuse(cut, "transition-cut", "cut is not a reachable decoded boundary")
	}
	// This grammar has exactly one successor per executed instruction and the
	// only terminal is the cut. Shared cycle/occupancy checks therefore establish
	// that every maximal path reaches it, without a normal-completion premise.
	for _, n := range g.nodes {
		if !m.tick() {
			return nil, m.err
		}
		if n.boundary != boundaryCut && n.count != 1 {
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
	if len(face.Regions) > l.Regions || len(face.Words) > l.Bytes/8 {
		return TransitionCertificate{}, refuse(0, "transition-budget", "input inventory exceeds limits")
	}
	work := 0
	if err := transitionCopyWork(&work, l.Work, len(face.Regions), len(face.Words)); err != nil {
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
	start := len(prior.bound.Instructions)
	if len(g.order) <= start+1 {
		return TransitionCertificate{}, refuse(proposal.Cut, "transition-continuation", "missing predecessor or suffix")
	}
	for j, span := range prior.bound.Instructions {
		if !m.tick() {
			return TransitionCertificate{}, m.err
		}
		i := g.nodes[g.order[j]]
		if span != (Span{i.pc, i.pc + uint64(i.size)}) || i.boundary != boundaryNone {
			return TransitionCertificate{}, refuse(i.pc, "transition-continuation", "executed predecessor is not exact ordered prefix")
		}
	}
	old := prior.bound.Boundary
	next := g.nodes[g.order[start]]
	_, encoded, err := decodeBytes(prior.image, next.pc)
	if err != nil {
		return TransitionCertificate{}, err
	}
	if next.pc != old.PC || int(next.size) != old.Instruction.Len || !bytes.Equal(encoded, old.Bytes) {
		return TransitionCertificate{}, refuse(next.pc, "transition-continuation", "predecessor boundary differs")
	}
	if err := m.inherit(prior); err != nil {
		return TransitionCertificate{}, err
	}
	return m.finish(g, start)
}

func (m *transitionChecker) finish(g *graph, start int) (TransitionCertificate, error) {
	for _, idx := range g.order[start:] {
		ins := g.nodes[idx]
		m.pc = ins.pc
		if !m.tick() {
			return TransitionCertificate{}, g.failure(ins.pc, m.err)
		}
		if ins.boundary == boundaryCut {
			i, bytes, err := decodeBytes(m.im, ins.pc)
			if err != nil {
				return TransitionCertificate{}, g.failure(ins.pc, err)
			}
			m.bound.Boundary = CutBoundary{PC: ins.pc, Instruction: i, Bytes: append([]byte(nil), bytes...)}
			continue
		}
		if err := m.step(ins.inst); err != nil {
			return TransitionCertificate{}, g.failure(ins.pc, err)
		}
		m.bound.Instructions = append(m.bound.Instructions, Span{ins.pc, ins.pc + uint64(ins.size)})
	}
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
	return TransitionCertificate{&checkedTransition{image: m.im, bound: m.bound, limits: m.limits, work: m.work, flags: m.state.flags}}, nil
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
	for r := range m.state.regs {
		m.state.regs[r] = m.scratch(br.Bits(64))
		m.bound.Preserved[r] = ^uint64(0)
	}
	for f := range m.state.flags {
		m.state.flags[f] = m.scratch(br.Bool())
	}
	m.bound.Origin = m.state.regs[RSP]
	m.bound.InitialRegisters = m.state.regs
	m.pointers[RSP] = OriginPointer{Origin: m.bound.Origin}
	f := TransitionFlag{Preserved: true, Defined: true}
	m.bound.Flags = TransitionFlags{f, f, f, f, f, f}
	m.memory = make(map[int64]TransitionByte)
	for _, r := range m.face.Regions {
		for off := r.Bytes.Start; off < r.Bytes.End; off++ {
			if !m.tick() {
				return m.err
			}
			if _, exists := m.memory[off]; !exists {
				m.memory[off] = TransitionByte{Offset: off, Value: m.scratch(br.Bits(8))}
			}
		}
	}
	for _, off := range m.face.Words {
		a := m.scratch(br.Bits(64))
		m.bound.Words = append(m.bound.Words, TransitionWord{off, a})
		for j := 0; j < 8; j++ {
			m.memory[off+int64(j)] = TransitionByte{Offset: off + int64(j), Value: m.extract(a, j*8, 8)}
		}
	}
	m.bound.InitialMemory = m.projectMemory()
	return m.err
}

func (m *transitionChecker) advance(p OriginPointer, delta int64) (OriginPointer, error) {
	if p.Origin != m.bound.Origin || p.Origin == (br.Term{}) {
		return OriginPointer{}, refuse(m.pc, "transition-provenance", "address lacks the checked origin")
	}
	d, ok := signedPlus(p.Offset, delta)
	if !ok {
		return OriginPointer{}, refuse(m.pc, "transition-origin", "signed offset overflow")
	}
	if err := m.offset(d); err != nil {
		return OriginPointer{}, err
	}
	p.Offset = d
	return p, nil
}

func (m *transitionChecker) address(mem x86asm.Mem, kind AccessKind) (int64, error) {
	base, _ := fullRegister(mem.Base) // validateTransitionForm established this form.
	p, err := m.advance(m.pointers[base.reg], mem.Disp)
	if err != nil {
		return 0, err
	}
	end, ok := signedPlus(p.Offset, 8)
	if !ok {
		return 0, refuse(m.pc, "transition-origin", "access offset overflow")
	}
	if err := m.offset(end); err != nil {
		return 0, err
	}
	span := RelativeSpan{p.Offset, end}
	if !m.permission(span, kind) {
		if m.err != nil {
			return 0, m.err
		}
		return 0, refuse(m.pc, "transition-permission", "full access lacks declared permission")
	}
	m.bound.Accesses = append(m.bound.Accesses, TransitionAccess{m.pc, kind, span})
	return p.Offset, nil
}

func (m *transitionChecker) load(off int64) TransitionValue {
	var lanes [8]pointerLane[OriginPointer]
	var v br.Term
	for j := 0; j < 8; j++ {
		b := m.memory[off+int64(j)]
		lanes[j] = pointerLane[OriginPointer]{b.Pointer, b.PointerLane}
		if j == 0 {
			v = b.Value
		} else {
			v = m.make(br.Concat, br.Bits((j+1)*8), 0, v, b.Value)
		}
	}
	return TransitionValue{v, orderedPointer(lanes[:])}
}

func (m *transitionChecker) store(off int64, v TransitionValue) {
	for j := 0; j < 8; j++ {
		b := TransitionByte{Offset: off + int64(j), Value: m.extract(v.Value, j*8, 8), Pointer: v.Pointer}
		if v.Pointer.Origin != (br.Term{}) {
			b.PointerLane = uint8(j)
		}
		// Replace every byte, including provenance; overlapping stores cannot
		// retain overwritten lanes even when scalar bits happen to agree.
		m.memory[b.Offset] = b
	}
}

func (m *transitionChecker) step(i operation) error {
	if i.Op == x86asm.JMP {
		return nil
	}
	if i.Op == x86asm.MOV {
		if mem, ok := i.Args[0].(x86asm.Mem); ok {
			off, err := m.address(mem, FrameWrite)
			if err != nil {
				return err
			}
			v := TransitionValue{}
			if a, ok := fullRegister(i.Args[1]); ok {
				v = TransitionValue{m.state.regs[a.reg], m.pointers[a.reg]}
			} else {
				v.Value = m.con(br.Bits(64), uint64(i.Args[1].(x86asm.Imm)))
			}
			m.store(off, v)
			return m.err
		}
	}
	a, _ := register(i.Args[0].(x86asm.Reg))
	m.bound.Preserved[a.reg] = 0
	var p OriginPointer
	switch i.Op {
	case x86asm.MOV:
		if mem, ok := i.Args[1].(x86asm.Mem); ok {
			off, err := m.address(mem, FrameRead)
			if err != nil {
				return err
			}
			v := m.load(off)
			m.state.regs[a.reg], m.pointers[a.reg] = v.Value, v.Pointer
			return m.err
		}
		if src, ok := fullRegister(i.Args[1]); ok {
			p = m.pointers[src.reg]
		}
	case x86asm.LEA:
		mem := i.Args[1].(x86asm.Mem)
		base, _ := fullRegister(mem.Base)
		if m.pointers[base.reg].Origin != (br.Term{}) {
			var err error
			p, err = m.advance(m.pointers[base.reg], mem.Disp)
			if err != nil {
				return err
			}
		}
	case x86asm.SUB:
		delta := -int64(i.Args[1].(x86asm.Imm)) // checked signed imm8/imm32, never MinInt64
		if m.pointers[a.reg].Origin != (br.Term{}) {
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
		old := m.pointers[a.reg]
		k := -uint64(i.Args[1].(x86asm.Imm))
		d, ok := alignmentOffset(old.Offset, m.face.Origin.Modulus, m.face.Origin.Residue, k)
		if old.Origin != m.bound.Origin || !ok {
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
