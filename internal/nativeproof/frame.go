package nativeproof

import (
	"context"
	"fmt"
	"slices"
	"unsafe"

	"golang.org/x/arch/x86/x86asm"
)

type framePointer struct {
	RegionPointer
	known bool
}

// A byte carries provenance only as one lane of an actual full pointer-word
// store (or an explicit initial word premise). Scalar writes erase these facts.
type frameByte struct {
	pointer framePointer
	lane    uint8
}

type frameState struct {
	scalar state
	regs   [16]framePointer
	memory []frameByte
	ready  bool
}

type frameChecker struct {
	context.Context
	im         *Image
	face       FrameInterface
	limits     FrameLimits
	work       int
	pc         uint64
	layout     []Span
	cells      int
	returnSlot Span
	accesses   []FrameAccess
}

func frameLimits(l FrameLimits) (FrameLimits, error) {
	d := DefaultFrameLimits()
	fields := []*int{&l.Instructions, &l.States, &l.Regions, &l.RegionBytes, &l.StateBytes, &l.Work}
	defaults := []int{d.Instructions, d.States, d.Regions, d.RegionBytes, d.StateBytes, d.Work}
	ceilings := []int{4096, 4096, 256, 1 << 20, 128 << 20, 20_000_000}
	for j, p := range fields {
		if *p == 0 {
			*p = defaults[j]
		}
		if *p < 1 || *p > ceilings[j] {
			return FrameLimits{}, fmt.Errorf("invalid frame limit %d", j)
		}
	}
	return l, nil
}

func (m *frameChecker) tick(n int) error {
	if err := m.Context.Err(); err != nil {
		return err
	}
	if n < 0 || n > m.limits.Work-m.work {
		return refuse(m.pc, "frame-budget", "work budget exhausted")
	}
	m.work += n
	return nil
}

func (m *frameChecker) Err() error { return m.tick(1) }

// Frame graph discovery adds only ordinary MOV memory forms, zero-extending
// loads and constant stack SUB. Shared control decoding still determines all
// successors and RET legality; semantic operand validation follows in transfer.
func decodeFrame(im *Image, pc uint64) (decodedInstruction, error) {
	i, b, err := decodeEncoding(im, pc)
	if err != nil {
		return decodedInstruction{}, err
	}
	if i.Op == x86asm.MOVZX || i.Op == x86asm.SUB {
		return decodedInstruction{inst: operation{Op: i.Op, Args: [2]x86asm.Arg{i.Args[0], i.Args[1]}}, size: uint8(i.Len), targets: [2]uint64{pc + uint64(i.Len)}, count: 1}, nil
	}
	if i.Op == x86asm.MOV {
		return decodeControl(pc, i, b)
	}
	return decodeLeaf(pc, i, b)
}

func (m *frameChecker) graph(entry uint64) (*graph, error) {
	g, err := decodeGraphUsing(m, entry, min(m.limits.Instructions, m.limits.States), func(pc uint64) (decodedInstruction, error) {
		m.pc = pc
		return decodeFrame(m.im, pc)
	})
	if r, ok := err.(*Refusal); ok && r.Premise == "relation-budget" {
		r.Premise = "frame-budget"
	}
	return g, err
}

// ProposeFrame discovers an untrusted bounded inventory. CheckFrame re-decodes
// it; neither discovery nor a matching digest establishes a frame. The image
// container is captured before any caller-controlled context callback.
func ProposeFrame(ctx context.Context, im *Image, entry uint64, limits FrameLimits) (FrameProposal, error) {
	im = im.snapshot()
	l, err := frameLimits(limits)
	if err != nil {
		return FrameProposal{}, refuse(entry, "frame-budget", err.Error())
	}
	if ctx == nil {
		return FrameProposal{}, refuse(entry, "frame-context", "missing context")
	}
	m := &frameChecker{Context: ctx, im: im, limits: l, pc: entry}
	g, err := m.graph(entry)
	if err != nil {
		return FrameProposal{}, err
	}
	p := FrameProposal{ImageDigest: im.digest, Entry: entry, Nodes: make([]Node, len(g.nodes))}
	for j, ins := range g.nodes {
		if err := m.tick(1); err != nil {
			return FrameProposal{}, err
		}
		n := Node{PC: ins.pc, Size: ins.size}
		for _, next := range ins.next[:ins.count] {
			n.Successors = append(n.Successors, g.nodes[next].pc)
		}
		p.Nodes[j] = n
	}
	if err := m.tick(1); err != nil {
		return FrameProposal{}, err
	}
	return p, nil
}

// CheckFrame derives a conditional byte-region access/frame bound through every
// path to RET. It owns input slices before callbacks, validates actual image
// mappings and interface consistency, and rechecks the proposed complete graph.
// Calls, loops, syscalls, unknown addresses and unsupported forms refuse. It makes
// no scalar-value or memory-value determinism claim. Cancellation returns nothing.
func CheckFrame(ctx context.Context, im *Image, entry uint64, face FrameInterface, proposal FrameProposal, limits FrameLimits) (FrameCertificate, error) {
	im = im.snapshot()
	l, err := frameLimits(limits)
	if err != nil {
		return FrameCertificate{}, refuse(entry, "frame-budget", err.Error())
	}
	// Bound caller containers before copying, without invoking their callbacks.
	if len(face.Regions) > l.Regions || len(face.Protected) > l.Regions || len(face.Pointers) > 15 || len(face.MemoryPointers) > l.RegionBytes/8 || len(proposal.Nodes) > min(l.Instructions, l.States) {
		return FrameCertificate{}, refuse(entry, "frame-budget", "input inventory exceeds limits")
	}
	for _, n := range proposal.Nodes {
		if len(n.Successors) > 2 {
			return FrameCertificate{}, refuse(entry, "frame-proposal", "too many successors")
		}
	}
	face = cloneFrameInterface(face)
	proposal.Nodes = append([]Node(nil), proposal.Nodes...)
	for j := range proposal.Nodes {
		proposal.Nodes[j].Successors = append([]uint64(nil), proposal.Nodes[j].Successors...)
	}
	if ctx == nil {
		return FrameCertificate{}, refuse(entry, "frame-context", "missing context")
	}
	m := &frameChecker{Context: ctx, im: im, face: face, limits: l, pc: entry}
	if err := m.tick(1); err != nil {
		return FrameCertificate{}, err
	}
	if im == nil || len(im.data) == 0 {
		return FrameCertificate{}, refuse(entry, "image-binding", "missing constructed image")
	}
	if proposal.ImageDigest != im.digest || proposal.Entry != entry {
		return FrameCertificate{}, refuse(entry, "frame-proposal", "image or entry differs")
	}
	if err := m.validate(); err != nil {
		return FrameCertificate{}, err
	}
	g, err := m.graph(entry)
	if err != nil {
		return FrameCertificate{}, err
	}
	if err := checkInventory(m, g, proposal.Nodes, "frame-proposal"); err != nil {
		return FrameCertificate{}, err
	}
	// Dense states make the upper bound independent of map growth or path count.
	// Sizeof inspects only type sizes; no unsafe pointer operation is used.
	bytesPerState := uint64(unsafe.Sizeof(frameState{})) + uint64(m.cells)*uint64(unsafe.Sizeof(frameByte{}))
	if uint64(len(g.nodes)+1)*bytesPerState > uint64(l.StateBytes) {
		return FrameCertificate{}, refuse(entry, "frame-budget", "abstract state byte budget")
	}
	states := make([]frameState, len(g.nodes))
	states[0], err = m.initial()
	if err != nil {
		return FrameCertificate{}, err
	}
	b := FrameBound{ImageDigest: im.digest, Rules: FrameRules, Entry: entry, Interface: face, ReturnedRSP: m.returnSlot.End, Instructions: make([]Span, 0, len(g.nodes))}
	var returned [16]framePointer
	hasReturn := false
	for _, idx := range g.order {
		ins := g.nodes[idx]
		m.pc = ins.pc
		if err := m.tick(1); err != nil {
			return FrameCertificate{}, err
		}
		s := &states[idx]
		i, _, err := decodeEncoding(im, ins.pc)
		if err != nil {
			return FrameCertificate{}, g.failure(ins.pc, err)
		}
		if err := m.transfer(i, s); err != nil {
			return FrameCertificate{}, g.failure(ins.pc, err)
		}
		b.Instructions = append(b.Instructions, Span{ins.pc, ins.pc + uint64(ins.size)})
		if i.Op == x86asm.RET {
			if !hasReturn {
				returned, hasReturn = s.regs, true
			} else {
				for r := range returned {
					returned[r] = joinPointer(returned[r], s.regs[r])
				}
			}
		}
		for _, next := range ins.next[:ins.count] {
			if err := m.merge(&states[next], s); err != nil {
				return FrameCertificate{}, g.failure(ins.pc, err)
			}
		}
		s.memory = nil
	}
	if !hasReturn {
		return FrameCertificate{}, refuse(entry, "frame-return", "no checked return")
	}
	for r, p := range returned {
		if r != int(RSP) && p.known {
			b.ReturnedPointers = append(b.ReturnedPointers, RegisterPointer{Register(r), p.RegionPointer})
		}
	}
	b.Accesses = m.accesses
	if err := m.tick(1); err != nil {
		return FrameCertificate{}, err
	}
	return FrameCertificate{&checkedFrame{im, b}}, nil
}

func overlap(a, b Span) bool { return a.Start < b.End && b.Start < a.End }
func pages(s Span) Span      { return Span{s.Start &^ uint64(4095), (s.End + 4095) &^ uint64(4095)} }

func (m *frameChecker) validate() error {
	f := m.face
	if err := validInterface(m.pc, Interface{Preserved: f.Preserved, Conditions: f.Conditions.Conditions}); err != nil {
		return err
	}
	if !f.Conditions.MemoryMapping || !f.Conditions.NoHiddenAliases || !f.Conditions.UnalignedAccess {
		return refuse(m.pc, "frame-premises", "ordinary stable memory, alias and alignment premises are required")
	}
	bytes := uint64(0)
	for j, r := range f.Regions {
		if err := m.tick(1); err != nil {
			return err
		}
		if r.Bytes.Start >= r.Bytes.End || r.Bytes.End > 1<<47 {
			return refuse(m.pc, "frame-region", "invalid or noncanonical region")
		}
		n := r.Bytes.End - r.Bytes.Start
		if n > uint64(m.limits.RegionBytes)-bytes {
			return refuse(m.pc, "frame-budget", "declared region byte budget")
		}
		bytes += n
		for _, old := range f.Regions[:j] {
			if err := m.tick(1); err != nil {
				return err
			}
			if overlap(r.Bytes, old.Bytes) && (r.Readable != old.Readable || r.Writable != old.Writable || r.Image != old.Image) {
				return refuse(m.pc, "frame-alias", "overlapping byte regions have conflicting permissions or backing")
			}
		}
		if err := m.mapping(r); err != nil {
			return err
		}
		m.layout = append(m.layout, r.Bytes)
	}
	slices.SortFunc(m.layout, func(a, b Span) int {
		if a.Start < b.Start {
			return -1
		}
		if a.Start > b.Start {
			return 1
		}
		return 0
	})
	merged := m.layout[:0]
	for _, span := range m.layout {
		if len(merged) != 0 && span.Start <= merged[len(merged)-1].End {
			merged[len(merged)-1].End = max(merged[len(merged)-1].End, span.End)
		} else {
			merged = append(merged, span)
		}
	}
	m.layout = merged
	for _, span := range merged {
		m.cells += int(span.End - span.Start)
	}
	stack, err := m.pointer(f.Stack)
	if err != nil {
		return err
	}
	if stack.Min != stack.Max || f.Regions[stack.Region].Image {
		return refuse(m.pc, "frame-stack", "stack must be an exact external-region pointer")
	}
	span, err := m.extent(stack, 0, 8)
	if err != nil {
		return err
	}
	if !f.Regions[stack.Region].Readable || span.End >= 1<<47 {
		return refuse(m.pc, "frame-stack", "return slot must be readable with a canonical post-RET RSP")
	}
	m.returnSlot = span
	for _, span := range f.Protected {
		if err := m.tick(1); err != nil {
			return err
		}
		if span.Start >= span.End || span.End > 1<<47 || m.cell(span.Start) < 0 || m.cell(span.End-1) < 0 {
			return refuse(m.pc, "frame-protected", "invalid protected byte extent")
		}
		// A protected range must be wholly in one normalized declared extent.
		covered := false
		for _, region := range m.layout {
			covered = covered || span.Start >= region.Start && span.End <= region.End
		}
		if !covered {
			return refuse(m.pc, "frame-protected", "protected extent crosses an undeclared gap")
		}
	}
	var registers [16]bool
	for _, p := range f.Pointers {
		if err := m.tick(1); err != nil {
			return err
		}
		if p.Register > R15 || p.Register == RSP || registers[p.Register] {
			return refuse(m.pc, "frame-pointer", "invalid or duplicate entry register origin")
		}
		registers[p.Register] = true
		if _, err := m.pointer(p.Pointer); err != nil {
			return err
		}
	}
	for j, p := range f.MemoryPointers {
		if err := m.tick(1); err != nil {
			return err
		}
		if _, err := m.pointer(p.Pointer); err != nil {
			return err
		}
		end, ok := plus(p.Address, 8)
		span := Span{p.Address, end}
		if !ok || overlap(span, m.returnSlot) {
			return refuse(m.pc, "frame-pointer", "initial pointer word overlaps return context or wraps")
		}
		region, err := m.regionAt(span, false)
		if err != nil {
			return err
		}
		if f.Regions[region].Image {
			return refuse(m.pc, "frame-pointer", "initial image pointer contents require a separate checked data relation")
		}
		for _, old := range f.MemoryPointers[:j] {
			if err := m.tick(1); err != nil {
				return err
			}
			if overlap(span, Span{old.Address, old.Address + 8}) {
				return refuse(m.pc, "frame-pointer", "overlapping initial pointer premises")
			}
		}
	}
	return nil
}

func (m *frameChecker) mapping(r ByteRegion) error {
	found := -1
	for j, load := range m.im.loads {
		if err := m.tick(1); err != nil {
			return err
		}
		if !overlap(pages(r.Bytes), pages(Span{load.va, load.end})) {
			continue
		}
		if !r.Image || r.Bytes.Start < load.va || r.Bytes.End > load.end || r.Readable && !load.readable || r.Writable && (!load.writable || load.executable) {
			return refuse(m.pc, "frame-mapping", "region conflicts with actual image mapping or permissions")
		}
		found = j
	}
	if r.Image && found < 0 {
		return refuse(m.pc, "frame-mapping", "image region has no loaded backing")
	}
	if found >= 0 {
		load := m.im.loads[found]
		// Conservatively reject aliases of the load's file pages, including a
		// BSS load's partial-page prefix. No file contents are assumed constant.
		if load.filesz != 0 || load.off%4096 != 0 {
			file := pages(Span{load.off, load.off + load.filesz})
			for j, alias := range m.im.loads {
				if err := m.tick(1); err != nil {
					return err
				}
				if j != found && (alias.filesz != 0 || alias.off%4096 != 0) && overlap(file, pages(Span{alias.off, alias.off + alias.filesz})) {
					return refuse(m.pc, "frame-alias", "image data has another file-page mapping")
				}
			}
		}
	}
	return nil
}

func (m *frameChecker) pointer(p RegionPointer) (framePointer, error) {
	if p.Region < 0 || p.Region >= len(m.face.Regions) || p.Min > p.Max {
		return framePointer{}, refuse(m.pc, "frame-pointer", "invalid pointer region or range")
	}
	r := m.face.Regions[p.Region].Bytes
	if p.Max > r.End-r.Start || r.Start+p.Max >= 1<<47 {
		return framePointer{}, refuse(m.pc, "frame-pointer", "pointer range exceeds its region or canonical addresses")
	}
	return framePointer{p, true}, nil
}

func (m *frameChecker) extent(p framePointer, displacement int64, width int) (Span, error) {
	if !p.known {
		return Span{}, refuse(m.pc, "frame-address", "memory address lacks checked pointer provenance")
	}
	lo, a := relative(p.Min, displacement)
	hi, b := relative(p.Max, displacement)
	end, c := plus(hi, uint64(width))
	r := m.face.Regions[p.Region].Bytes
	if !a || !b || !c || end > r.End-r.Start {
		return Span{}, refuse(m.pc, "frame-bounds", "full access width or pointer arithmetic escapes the region")
	}
	return Span{r.Start + lo, r.Start + end}, nil
}

func (m *frameChecker) regionAt(span Span, write bool) (int, error) {
	for j, r := range m.face.Regions {
		if err := m.tick(1); err != nil {
			return 0, err
		}
		if span.Start >= r.Bytes.Start && span.End <= r.Bytes.End && span.Start < span.End {
			if write && !r.Writable || !write && !r.Readable {
				return 0, refuse(m.pc, "frame-permission", "region permission excludes access")
			}
			return j, nil
		}
	}
	return 0, refuse(m.pc, "frame-bounds", "access is not wholly in declared memory")
}

func (m *frameChecker) cell(address uint64) int {
	offset := 0
	for _, span := range m.layout {
		if address >= span.Start && address < span.End {
			return offset + int(address-span.Start)
		}
		offset += int(span.End - span.Start)
	}
	return -1
}

func (m *frameChecker) initial() (frameState, error) {
	if err := m.tick(m.cells + 16); err != nil {
		return frameState{}, err
	}
	s := frameState{memory: make([]frameByte, m.cells), ready: true}
	// The frame theorem permits all scalar entry bits and loaded scalar bytes.
	// Definedness here bounds only branch support, never input/value determinism.
	for r := range s.scalar.regs {
		s.scalar.regs[r].defined = ^uint64(0)
	}
	for _, p := range m.face.Pointers {
		s.regs[p.Register], _ = m.pointer(p.Pointer)
	}
	s.regs[RSP], _ = m.pointer(m.face.Stack)
	for _, p := range m.face.MemoryPointers {
		ptr, _ := m.pointer(p.Pointer)
		start := m.cell(p.Address)
		for j := 0; j < 8; j++ {
			s.memory[start+j] = frameByte{ptr, uint8(j)}
		}
	}
	return s, nil
}

func joinPointer(a, b framePointer) framePointer {
	if !a.known || !b.known || a.Region != b.Region {
		return framePointer{}
	}
	a.Min, a.Max = min(a.Min, b.Min), max(a.Max, b.Max)
	return a
}

func (m *frameChecker) merge(dst, src *frameState) error {
	if err := m.tick(m.cells + 16); err != nil {
		return err
	}
	if !dst.ready {
		*dst = *src
		dst.memory = append([]frameByte(nil), src.memory...)
		return nil
	}
	dst.scalar = join(dst.scalar, src.scalar)
	for r := range dst.regs {
		dst.regs[r] = joinPointer(dst.regs[r], src.regs[r])
	}
	// Memory retains only identical whole-byte origins. In particular, joining
	// differing byte lanes never manufactures a hybrid pointer-word range.
	for j := range dst.memory {
		if dst.memory[j] != src.memory[j] {
			dst.memory[j] = frameByte{}
		}
	}
	return nil
}
