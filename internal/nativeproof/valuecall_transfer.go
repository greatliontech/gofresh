package nativeproof

import (
	"math/bits"

	"golang.org/x/arch/x86/x86asm"
)

func (m *valueCallChecker) memoryAccess(s *valueCallState, address uint64, width int, kind AccessKind) (int, error) {
	end, ok := plus(address, uint64(width))
	if !ok || end > 1<<47 {
		return 0, refuse(m.pc, "value-address", "full memory access wraps or is noncanonical")
	}
	span := Span{address, end}
	region, err := m.regionAt(span, kind == FrameWrite)
	if err != nil {
		return 0, err
	}
	if kind == FrameWrite && s.inside && overlap(span, Span{s.callerSP - 8, s.callerSP}) {
		return 0, refuse(m.pc, "value-return", "callee write corrupts CALL return context")
	}
	p := framePointer{RegionPointer: RegionPointer{Region: region}, known: true}
	if err := m.access(p, span, width, kind); err != nil {
		return 0, err
	}
	if err := m.tick(width); err != nil {
		return 0, err
	}
	return m.cell(address), nil
}
func (m *valueCallChecker) readMemory(s *valueCallState, address uint64, width int, kind AccessKind) (value, error) {
	at, err := m.memoryAccess(s, address, width, kind)
	if err != nil {
		return value{}, err
	}
	var v value
	for j := 0; j < width; j++ {
		x := s.memory[at+j]
		shift := uint(j * 8)
		v.defined |= x.defined << shift
		v.zero |= x.zero << shift
		v.one |= x.one << shift
	}
	return v, nil
}
func (m *valueCallChecker) writeMemory(s *valueCallState, address uint64, width int, v value) error {
	at, err := m.memoryAccess(s, address, width, FrameWrite)
	if err != nil {
		return err
	}
	for j := 0; j < width; j++ {
		shift := uint(j * 8)
		s.memory[at+j] = value{v.defined >> shift & 0xff, v.zero >> shift & 0xff, v.one >> shift & 0xff}
		if s.inside {
			s.written[at+j] = true
		}
	}
	return nil
}
func (m *valueCallChecker) address(s *valueCallState, mem x86asm.Mem, next uint64) (uint64, error) {
	if mem.Segment != 0 {
		return 0, refuse(m.pc, "value-address", "segment/TLS addressing is unsupported")
	}
	var base uint64
	if mem.Base == x86asm.RIP {
		base = next
	} else if mem.Base != 0 {
		a, ok := register(mem.Base)
		if !ok || a.width != 64 {
			return 0, refuse(m.pc, "value-address", "invalid base register")
		}
		v, known := knownValue(s.scalar.read(a), 64)
		if !known || s.scalar.read(a).defined != ^uint64(0) {
			return 0, refuse(m.pc, "value-address", "base is not a defined exact value")
		}
		base = v
	}
	if mem.Index != 0 {
		a, ok := register(mem.Index)
		if !ok || a.width != 64 || mem.Scale != 1 && mem.Scale != 2 && mem.Scale != 4 && mem.Scale != 8 {
			return 0, refuse(m.pc, "value-address", "invalid index/scale")
		}
		v, known := knownValue(s.scalar.read(a), 64)
		if !known || s.scalar.read(a).defined != ^uint64(0) || v > ^uint64(0)/uint64(mem.Scale) {
			return 0, refuse(m.pc, "value-address", "unknown or overflowing index")
		}
		var good bool
		base, good = plus(base, v*uint64(mem.Scale))
		if !good {
			return 0, refuse(m.pc, "value-address", "base/index overflow")
		}
	}
	address, ok := relative(base, mem.Disp)
	if !ok || address >= 1<<47 {
		return 0, refuse(m.pc, "value-address", "address displacement wraps or is noncanonical")
	}
	return address, nil
}
func (m *valueCallChecker) writeRegister(s *valueCallState, a alias, v value) error {
	if err := s.scalar.write(m.pc, a, v, Interface{Preserved: m.face.Preserved}); err != nil {
		return err
	}
	bits := mask(a.width) << a.shift
	if a.width == 32 {
		bits = ^uint64(0)
	}
	m.bound.RegisterWrites[a.reg] |= bits
	return nil
}

func (m *valueCallChecker) step(i x86asm.Inst, b []byte, s *valueCallState) error {
	if prefix, _ := sseEncoding(i.Op); prefix != 0 {
		return m.vector(i, s)
	}
	switch i.Op {
	case x86asm.MOV, x86asm.MOVZX:
		if _, mem := i.Args[0].(x86asm.Mem); mem {
			return m.move(i, s)
		}
		if _, mem := i.Args[1].(x86asm.Mem); mem {
			return m.move(i, s)
		}
		if i.Op == x86asm.MOVZX {
			return refuse(m.pc, "instruction-semantics", "register MOVZX unsupported")
		}
	case x86asm.BSF:
		return m.scan(i, s)
	case x86asm.SHL:
		return m.shiftLeft(i, s)
	case x86asm.TEST:
		return m.test(i, s)
	}
	// Scalar forms use the original transfer validator and known-bit operations.
	// This domain additionally derives concrete flag values when operands suffice.
	if _, err := decodeLeaf(m.pc, i, b); err != nil {
		return err
	}
	if needed := condition(i.Op); needed != 0 {
		known, taken, err := valuePredicate(i.Op, s)
		if err != nil {
			return refuse(m.pc, "value-flags", err.Error())
		}
		r, ok := i.Args[0].(x86asm.Reg)
		a, valid := register(r)
		if !ok || !valid || a.width != 8 {
			return refuse(m.pc, "instruction-shape", "SETcc requires a byte register")
		}
		v := value{defined: 0xff, zero: 0xfe}
		if known {
			v = constant(0, 8)
			if taken {
				v = constant(1, 8)
			}
		}
		return m.writeRegister(s, a, v)
	}
	r, reg := i.Args[0].(x86asm.Reg)
	a, valid := register(r)
	var left, right value
	if reg && valid {
		left = s.scalar.read(a)
		if i.Op != x86asm.LEA && i.Op != x86asm.NOP {
			v, err := operand(m.pc, &s.scalar, i.Args[1], a.width)
			if err != nil {
				return err
			}
			right = v
		}
	}
	oldKnown, oldFlags := s.flagKnown, s.flagValue
	if err := transfer(m.pc, operation{Op: i.Op, Args: [2]x86asm.Arg{i.Args[0], i.Args[1]}}, &s.scalar, Interface{Preserved: m.face.Preserved}); err != nil {
		return err
	}
	if reg && valid && i.Op != x86asm.CMP && i.Op != x86asm.NOP {
		written := mask(a.width) << a.shift
		if a.width == 32 {
			written = ^uint64(0)
		}
		m.bound.RegisterWrites[a.reg] |= written
	}
	switch i.Op {
	case x86asm.CMP, x86asm.ADD:
		s.flagKnown = 0
		s.flagValue = 0
		x, xok := knownValue(left, a.width)
		y, yok := knownValue(right, a.width)
		if xok && yok {
			if i.Op == x86asm.CMP {
				setSubFlags(s, x, y, a.width)
			} else {
				setAddFlags(s, x, y, a.width)
			}
		}
	case x86asm.XOR, x86asm.AND:
		v := s.scalar.read(a)
		setLogicalFlags(s, v, a.width)
	case x86asm.SHR:
		imm := i.Args[1].(x86asm.Imm)
		count := int(uint64(imm) & uint64(a.width-1))
		if count == 0 {
			s.flagKnown, s.flagValue = oldKnown, oldFlags
		} else {
			s.flagKnown = 0
			s.flagValue = 0
			setResultKnownFlags(s, s.scalar.read(a), a.width)
			bit := uint64(1) << uint(count-1)
			if (left.zero|left.one)&bit != 0 {
				s.flagKnown |= cf
				if left.one&bit != 0 {
					s.flagValue |= cf
				}
			}
			if count == 1 {
				bit = uint64(1) << uint(a.width-1)
				if (left.zero|left.one)&bit != 0 {
					s.flagKnown |= of
					if left.one&bit != 0 {
						s.flagValue |= of
					}
				}
			}
		}
	}
	return nil
}

func (m *valueCallChecker) move(i x86asm.Inst, s *valueCallState) error {
	w := i.MemBytes
	if w != 1 && w != 2 && w != 4 && w != 8 {
		return refuse(m.pc, "instruction-shape", "unsupported scalar memory width")
	}
	if mem, store := i.Args[0].(x86asm.Mem); store {
		if i.Op != x86asm.MOV {
			return refuse(m.pc, "instruction-shape", "only MOV stores")
		}
		address, err := m.address(s, mem, m.pc+uint64(i.Len))
		if err != nil {
			return err
		}
		v, err := operand(m.pc, &s.scalar, i.Args[1], w*8)
		if err != nil {
			return err
		}
		return m.writeMemory(s, address, w, v)
	}
	r, ok := i.Args[0].(x86asm.Reg)
	a, valid := register(r)
	mem, memory := i.Args[1].(x86asm.Mem)
	if !ok || !valid || !memory || i.Op == x86asm.MOV && a.width != w*8 || i.Op == x86asm.MOVZX && (w > 2 || a.width != 32 && a.width != 64) {
		return refuse(m.pc, "instruction-shape", "invalid scalar load form")
	}
	address, err := m.address(s, mem, m.pc+uint64(i.Len))
	if err != nil {
		return err
	}
	v, err := m.readMemory(s, address, w, FrameRead)
	if err != nil {
		return err
	}
	if i.Op == x86asm.MOVZX {
		high := mask(a.width) &^ mask(w*8)
		v.zero |= high
		v.defined |= high
	}
	return m.writeRegister(s, a, v)
}

func (m *valueCallChecker) test(i x86asm.Inst, s *valueCallState) error {
	r, ok := i.Args[0].(x86asm.Reg)
	a, valid := register(r)
	if !ok || !valid || a.width != 8 && a.width != 16 && a.width != 32 && a.width != 64 {
		return refuse(m.pc, "instruction-shape", "TEST requires integer operands")
	}
	v, err := operand(m.pc, &s.scalar, i.Args[1], a.width)
	if err != nil {
		return err
	}
	setLogicalFlags(s, and(s.scalar.read(a), v, a.width), a.width)
	return nil
}

func (m *valueCallChecker) scan(i x86asm.Inst, s *valueCallState) error {
	dest, ok := i.Args[0].(x86asm.Reg)
	a, valid := register(dest)
	src, rok := i.Args[1].(x86asm.Reg)
	from, good := register(src)
	if !ok || !valid || !rok || !good || a.width != 32 || from.width != 32 {
		return refuse(m.pc, "instruction-shape", "only register BSF32 is modeled")
	}
	v := s.scalar.read(from)
	x, known := knownValue(v, 32)
	s.scalar.flags = zf
	s.flagKnown = 0
	s.flagValue = 0
	out := value{} // zero-source destination is architecturally undefined
	undefined := true
	if known && v.defined == mask(32) {
		s.flagKnown = zf
		if x == 0 {
			s.flagValue = zf
		} else {
			out = constant(uint64(bits.TrailingZeros32(uint32(x))), 32)
			undefined = false
		}
	} else if v.one != 0 {
		s.flagKnown = zf
		out.defined = mask(32)
		undefined = false
	}
	if err := m.writeRegister(s, a, out); err != nil {
		return err
	}
	// A zero-source BSF does not license even the usual upper-half zero fact:
	// conservatively forget the whole destination register on undefined output.
	if undefined {
		s.scalar.regs[a.reg] = value{}
	}
	return nil
}

func (m *valueCallChecker) shiftLeft(i x86asm.Inst, s *valueCallState) error {
	r, ok := i.Args[0].(x86asm.Reg)
	a, valid := register(r)
	if !ok || !valid || a.width != 32 {
		return refuse(m.pc, "instruction-shape", "only SHL32 is modeled")
	}
	var count uint64
	switch src := i.Args[1].(type) {
	case x86asm.Imm:
		count = uint64(src)
	case x86asm.Reg:
		if src != x86asm.CL {
			return refuse(m.pc, "instruction-shape", "shift count must be CL or immediate")
		}
		v := s.scalar.read(alias{reg: int(RCX), width: 8})
		x, known := knownValue(v, 8)
		if !known || v.defined != 0xff {
			return refuse(m.pc, "value-shift", "shift count is not an exact defined byte")
		}
		count = x
	default:
		return refuse(m.pc, "instruction-shape", "missing shift count")
	}
	n := int(count & 31)
	old := s.scalar.read(a)
	v := shl(old, n, 32)
	if n != 0 {
		s.scalar.flags = resultFlags(v, 32)
		s.flagKnown = 0
		s.flagValue = 0
		setResultKnownFlags(s, v, 32)
		bit := uint64(1) << uint(32-n)
		if old.defined&bit != 0 {
			s.scalar.flags |= cf
		}
		if (old.zero|old.one)&bit != 0 {
			s.flagKnown |= cf
			if old.one&bit != 0 {
				s.flagValue |= cf
			}
		}
		if n == 1 {
			if s.scalar.flags&(cf|sf) == cf|sf {
				s.scalar.flags |= of
			}
			if s.flagKnown&(cf|sf) == cf|sf {
				s.flagKnown |= of
				if (s.flagValue&cf != 0) != (s.flagValue&sf != 0) {
					s.flagValue |= of
				}
			}
		}
	}
	return m.writeRegister(s, a, v)
}

func setResultKnownFlags(s *valueCallState, v value, width int) {
	if x, known := knownValue(v, width); known {
		s.flagKnown |= zf
		if x == 0 {
			s.flagValue |= zf
		}
	}
	bit := uint64(1) << uint(width-1)
	if (v.zero|v.one)&bit != 0 {
		s.flagKnown |= sf
		if v.one&bit != 0 {
			s.flagValue |= sf
		}
	}
	if x, known := knownValue(v, 8); known {
		s.flagKnown |= pf
		if bits.OnesCount8(uint8(x))%2 == 0 {
			s.flagValue |= pf
		}
	}
}
func setLogicalFlags(s *valueCallState, v value, width int) {
	s.scalar.flags = resultFlags(v, width) | cf | of
	s.flagKnown = cf | of
	s.flagValue = 0
	setResultKnownFlags(s, v, width)
}
func setSubFlags(s *valueCallState, x, y uint64, width int) {
	r := (x - y) & mask(width)
	s.flagKnown = cf | of | zf | sf | pf
	s.flagValue = 0
	setResultKnownFlags(s, constant(r, width), width)
	if x < y {
		s.flagValue |= cf
	}
	if ((x^y)&(x^r))&(uint64(1)<<uint(width-1)) != 0 {
		s.flagValue |= of
	}
}
func setAddFlags(s *valueCallState, x, y uint64, width int) {
	r := (x + y) & mask(width)
	s.flagKnown = cf | of | zf | sf | pf
	s.flagValue = 0
	setResultKnownFlags(s, constant(r, width), width)
	if r < x {
		s.flagValue |= cf
	}
	if (^(x^y)&(x^r))&(uint64(1)<<uint(width-1)) != 0 {
		s.flagValue |= of
	}
}
