package nativeproof

import "golang.org/x/arch/x86/x86asm"

func (m *valueCallChecker) vector(i x86asm.Inst, s *valueCallState) error {
	if i.Op == x86asm.PMOVMSKB {
		dest, ok := i.Args[0].(x86asm.Reg)
		a, valid := register(dest)
		src, vec := xmm(i.Args[1])
		if !ok || !valid || a.width != 32 || !vec {
			return refuse(m.pc, "instruction-shape", "PMOVMSKB requires GP32 and XMM")
		}
		v := constant(0, 32)
		v.defined &^= 0xffff
		v.zero &^= 0xffff
		for j, b := range s.xmm[src] {
			bit := uint64(1) << uint(j)
			if b.defined&0x80 != 0 {
				v.defined |= bit
			}
			if b.zero&0x80 != 0 {
				v.zero |= bit
			}
			if b.one&0x80 != 0 {
				v.one |= bit
			}
		}
		return m.writeRegister(s, a, v)
	}
	dest, ok := xmm(i.Args[0])
	if !ok {
		return refuse(m.pc, "instruction-shape", "SSE2 requires XMM destination")
	}
	if m.request.Interface.PreservedXMM[dest] {
		return refuse(m.pc, "value-context", "write to preserved XMM register")
	}
	var out [16]value
	switch i.Op {
	case x86asm.MOVQ:
		r, ok := i.Args[1].(x86asm.Reg)
		a, valid := register(r)
		if !ok || !valid || a.width != 64 {
			return refuse(m.pc, "instruction-shape", "MOVQ requires GP64 source")
		}
		v := s.scalar.read(a)
		for j := 0; j < 8; j++ {
			shift := uint(j * 8)
			out[j] = value{v.defined >> shift & 0xff, v.zero >> shift & 0xff, v.one >> shift & 0xff}
		}
		for j := 8; j < 16; j++ {
			out[j] = constant(0, 8)
		}
	case x86asm.MOVDQU:
		mem, ok := i.Args[1].(x86asm.Mem)
		if !ok {
			return refuse(m.pc, "instruction-shape", "MOVDQU requires memory source")
		}
		address, err := m.address(s, mem, m.pc+uint64(i.Len))
		if err != nil {
			return err
		}
		at, err := m.memoryAccess(s, address, 16, FrameRead)
		if err != nil {
			return err
		}
		copy(out[:], s.memory[at:at+16])
	case x86asm.PUNPCKLBW, x86asm.PSHUFD, x86asm.PCMPEQB:
		src, ok := xmm(i.Args[1])
		if !ok {
			return refuse(m.pc, "instruction-shape", "SSE2 source must be XMM")
		}
		left, right := s.xmm[dest], s.xmm[src]
		switch i.Op {
		case x86asm.PUNPCKLBW:
			for j := 0; j < 8; j++ {
				out[j*2], out[j*2+1] = left[j], right[j]
			}
		case x86asm.PSHUFD:
			imm := uint64(i.Args[2].(x86asm.Imm))
			for j := 0; j < 4; j++ {
				source := int(imm >> uint(j*2) & 3)
				copy(out[j*4:j*4+4], right[source*4:source*4+4])
			}
		case x86asm.PCMPEQB:
			for j := range out {
				a, b := left[j], right[j]
				x, xok := knownValue(a, 8)
				y, yok := knownValue(b, 8)
				if src == dest || xok && yok && x == y {
					out[j] = constant(0xff, 8)
				} else if xok && yok || a.zero&b.one|a.one&b.zero != 0 {
					out[j] = constant(0, 8)
				} else {
					if a.defined&b.defined == 0xff {
						out[j] = value{defined: 0xff}
					}
				}
			}
		}
	default:
		return refuse(m.pc, "instruction-semantics", "unsupported SSE2 transfer")
	}
	s.xmm[dest] = out
	m.bound.XMMWrites |= 1 << uint(dest)
	return nil
}
