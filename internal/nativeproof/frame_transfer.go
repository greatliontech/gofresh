package nativeproof

import (
	"math"

	"golang.org/x/arch/x86/x86asm"
)

func (m *frameChecker) address(mem x86asm.Mem, width int, next uint64, s *frameState) (framePointer, Span, error) {
	if mem.Segment != 0 || mem.Index != 0 {
		return framePointer{}, Span{}, refuse(m.pc, "frame-address", "segmented or indexed memory addressing is unsupported")
	}
	if mem.Base == x86asm.RIP {
		start, ok := relative(next, mem.Disp)
		end, endOK := plus(start, uint64(width))
		if !ok || !endOK {
			return framePointer{}, Span{}, refuse(m.pc, "frame-bounds", "RIP-relative address overflow")
		}
		span := Span{start, end}
		for j, r := range m.face.Regions {
			if err := m.tick(1); err != nil {
				return framePointer{}, Span{}, err
			}
			if r.Image && span.Start >= r.Bytes.Start && span.End <= r.Bytes.End {
				p := framePointer{RegionPointer{j, start - r.Bytes.Start, start - r.Bytes.Start}, true}
				return p, span, nil
			}
		}
		return framePointer{}, Span{}, refuse(m.pc, "frame-address", "RIP-relative data lacks a declared actual image region")
	}
	a, ok := register(mem.Base)
	if !ok || a.width != 64 {
		return framePointer{}, Span{}, refuse(m.pc, "frame-address", "memory base is not a full integer register")
	}
	p := s.regs[a.reg]
	span, err := m.extent(p, mem.Disp, width)
	return p, span, err
}

func (m *frameChecker) access(p framePointer, span Span, width int, kind AccessKind) error {
	if err := m.tick(1); err != nil {
		return err
	}
	r := m.face.Regions[p.Region]
	if kind == FrameWrite && !r.Writable || kind != FrameWrite && !r.Readable {
		return refuse(m.pc, "frame-permission", "region permission excludes decoded access")
	}
	if kind == FrameWrite {
		if overlap(span, m.returnSlot) {
			return refuse(m.pc, "frame-return", "write can corrupt protected return context")
		}
		for _, protected := range m.face.Protected {
			if err := m.tick(1); err != nil {
				return err
			}
			if overlap(span, protected) {
				return refuse(m.pc, "frame-protected", "write intersects protected bytes")
			}
		}
	}
	m.accesses = append(m.accesses, FrameAccess{m.pc, kind, span, width})
	return nil
}

func (m *frameChecker) loadPointer(s *frameState, span Span, width int) framePointer {
	if width != 8 || span.End-span.Start != 8 {
		return framePointer{}
	}
	start := m.cell(span.Start)
	return orderedPointer(s.memory[start : start+8])
}

func (m *frameChecker) store(s *frameState, span Span, width int, p framePointer) error {
	n := int(span.End - span.Start)
	if err := m.tick(n); err != nil {
		return err
	}
	start := m.cell(span.Start)
	// Every possibly overwritten byte loses its old fact, even for a partial
	// scalar store or a ranged/aliased destination. Strong provenance updates
	// require an exact eight-byte destination and a full pointer-word source.
	clear(s.memory[start : start+n])
	if width == 8 && n == 8 && p.known {
		for lane := 0; lane < 8; lane++ {
			s.memory[start+lane] = frameByte{p, uint8(lane)}
		}
	}
	return nil
}

func (m *frameChecker) advance(p framePointer, delta int64) (framePointer, error) {
	span, err := m.extent(p, delta, 0)
	if err != nil {
		return framePointer{}, err
	}
	r := m.face.Regions[p.Region].Bytes
	if span.End >= 1<<47 {
		return framePointer{}, refuse(m.pc, "frame-bounds", "pointer arithmetic reaches a noncanonical address")
	}
	p.Min, p.Max = span.Start-r.Start, span.End-r.Start
	return p, nil
}

func (m *frameChecker) stackAdjust(i x86asm.Inst, s *frameState) error {
	var delta int64
	switch i.Op {
	case x86asm.ADD, x86asm.SUB:
		imm, ok := i.Args[1].(x86asm.Imm)
		if !ok {
			return refuse(m.pc, "frame-stack", "stack arithmetic requires a constant displacement")
		}
		delta = int64(imm)
		if i.Op == x86asm.SUB {
			if delta == math.MinInt64 {
				return refuse(m.pc, "frame-stack", "stack displacement overflow")
			}
			delta = -delta
		}
	case x86asm.LEA:
		mem, ok := i.Args[1].(x86asm.Mem)
		if !ok || mem.Base != x86asm.RSP || mem.Index != 0 || mem.Segment != 0 {
			return refuse(m.pc, "frame-stack", "stack LEA requires its own base and a displacement")
		}
		delta = mem.Disp
	default:
		return refuse(m.pc, "frame-stack", "unsupported stack-pointer write")
	}
	p, err := m.advance(s.regs[RSP], delta)
	if err != nil {
		return err
	}
	if p.Min != p.Max || p.Region != m.face.Stack.Region {
		return refuse(m.pc, "frame-stack", "stack adjustment lacks an exact stack origin")
	}
	s.regs[RSP] = p
	s.scalar.regs[RSP] = constant(m.face.Regions[p.Region].Bytes.Start+p.Min, 64)
	if i.Op != x86asm.LEA {
		s.scalar.flags = cf | of | zf | sf | pf
	}
	return nil
}

func (m *frameChecker) transfer(i x86asm.Inst, s *frameState) error {
	if i.Op == x86asm.RET {
		p := s.regs[RSP]
		if !p.known || p.RegionPointer != m.face.Stack {
			return refuse(m.pc, "frame-return", "RET does not use the original stack slot")
		}
		return m.access(p, m.returnSlot, 8, FrameReturnRead)
	}
	protect := Interface{Preserved: m.face.Preserved}
	if reg, ok := i.Args[0].(x86asm.Reg); ok {
		a, valid := register(reg)
		if valid && a.reg == int(RSP) && i.Op != x86asm.CMP {
			if a.width != 64 {
				return refuse(m.pc, "frame-stack", "partial stack-pointer writes are unsupported")
			}
			return m.stackAdjust(i, s)
		}
	}
	if i.Op == x86asm.MOV || i.Op == x86asm.MOVZX {
		if _, memory := i.Args[0].(x86asm.Mem); memory {
			return m.moveMemory(i, s, protect)
		}
		if _, memory := i.Args[1].(x86asm.Mem); memory {
			return m.moveMemory(i, s, protect)
		}
		if i.Op == x86asm.MOVZX {
			return refuse(m.pc, "frame-instruction", "only memory-source zero extension is modeled")
		}
	}
	if i.Op == x86asm.SUB {
		return refuse(m.pc, "frame-instruction", "SUB is modeled only for constant stack adjustment")
	}
	op := operation{Op: i.Op, Args: [2]x86asm.Arg{i.Args[0], i.Args[1]}}
	// The scalar validator supplies the operand, partial-write, preservation and
	// flag semantics. Pointer authority is a separate, stricter domain below.
	var p framePointer
	r, reg := i.Args[0].(x86asm.Reg)
	a, valid := register(r)
	if reg && valid && a.width == 64 {
		switch i.Op {
		case x86asm.MOV:
			if src, ok := i.Args[1].(x86asm.Reg); ok {
				if from, ok := register(src); ok && from.width == 64 {
					p = s.regs[from.reg]
				}
			}
		case x86asm.ADD:
			if delta, ok := i.Args[1].(x86asm.Imm); ok && s.regs[a.reg].known {
				var err error
				p, err = m.advance(s.regs[a.reg], int64(delta))
				if err != nil {
					return err
				}
			}
		case x86asm.LEA:
			if mem, ok := i.Args[1].(x86asm.Mem); ok && mem.Segment == 0 && mem.Index == 0 {
				if base, ok := register(mem.Base); ok && base.width == 64 && s.regs[base.reg].known {
					var err error
					p, err = m.advance(s.regs[base.reg], mem.Disp)
					if err != nil {
						return err
					}
				}
			}
		}
	}
	if err := transfer(m.pc, op, &s.scalar, protect); err != nil {
		return err
	}
	if reg && valid && i.Op != x86asm.CMP {
		s.regs[a.reg] = p
	}
	return nil
}

func (m *frameChecker) moveMemory(i x86asm.Inst, s *frameState, protect Interface) error {
	width := i.MemBytes
	if width != 1 && width != 2 && width != 4 && width != 8 {
		return refuse(m.pc, "frame-instruction", "unsupported memory width")
	}
	next := m.pc + uint64(i.Len)
	if dest, store := i.Args[0].(x86asm.Mem); store {
		if i.Op != x86asm.MOV {
			return refuse(m.pc, "frame-instruction", "only MOV stores are modeled")
		}
		p, span, err := m.address(dest, width, next, s)
		if err != nil {
			return err
		}
		var valuePointer framePointer
		switch src := i.Args[1].(type) {
		case x86asm.Reg:
			a, ok := register(src)
			if !ok || a.width != width*8 {
				return refuse(m.pc, "frame-instruction", "store source width differs")
			}
			if width == 8 {
				valuePointer = s.regs[a.reg]
			}
		case x86asm.Imm:
			// A machine scalar constant does not establish pointer provenance.
		default:
			return refuse(m.pc, "frame-instruction", "store source is not an integer register or immediate")
		}
		if err := m.access(p, span, width, FrameWrite); err != nil {
			return err
		}
		return m.store(s, span, width, valuePointer)
	}
	src, memory := i.Args[1].(x86asm.Mem)
	dest, reg := i.Args[0].(x86asm.Reg)
	a, ok := register(dest)
	if !memory || !reg || !ok || a.reg == int(RSP) {
		return refuse(m.pc, "frame-instruction", "load requires an integer non-stack destination")
	}
	if i.Op == x86asm.MOV && a.width != width*8 || i.Op == x86asm.MOVZX && (width > 2 || a.width != 32 && a.width != 64) {
		return refuse(m.pc, "frame-instruction", "incompatible load widths")
	}
	p, span, err := m.address(src, width, next, s)
	if err != nil {
		return err
	}
	if err := m.access(p, span, width, FrameRead); err != nil {
		return err
	}
	loaded := framePointer{}
	if i.Op == x86asm.MOV && a.width == 64 {
		loaded = m.loadPointer(s, span, width)
	}
	v := value{defined: mask(a.width)}
	if i.Op == x86asm.MOVZX {
		v.zero = mask(a.width) &^ mask(width*8)
	}
	if err := s.scalar.write(m.pc, a, v, protect); err != nil {
		return err
	}
	s.regs[a.reg] = loaded
	return nil
}
