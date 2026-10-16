package nativeproof

import (
	"fmt"
	"math/bits"

	"golang.org/x/arch/x86/x86asm"
)

// A defined bit is a function only of declared input bits and code constants.
// zero and one additionally identify constant bits. Unknown is arbitrary entry
// state, not a value assumed to be zero. This abstraction proves dependence, not
// the actual function of input values.
type value struct{ defined, zero, one uint64 }
type state struct {
	regs  [16]value
	flags uint8
}

const (
	cf uint8 = 1 << iota
	zf
	sf
	of
	pf
)

func mask(width int) uint64 {
	if width == 64 {
		return ^uint64(0)
	}
	return uint64(1)<<width - 1
}
func constant(v uint64, width int) value { m := mask(width); return value{m, ^v & m, v & m} }
func (a value) trim(width int) value {
	m := mask(width)
	return value{a.defined & m, a.zero & m, a.one & m}
}

func join(a, b state) state {
	for r := range a.regs {
		a.regs[r] = value{a.regs[r].defined & b.regs[r].defined, a.regs[r].zero & b.regs[r].zero, a.regs[r].one & b.regs[r].one}
	}
	a.flags &= b.flags
	return a
}

type alias struct {
	reg          int
	width, shift int
}

func register(r x86asm.Reg) (alias, bool) {
	switch {
	case r >= x86asm.RAX && r <= x86asm.R15:
		return alias{int(r - x86asm.RAX), 64, 0}, true
	case r >= x86asm.EAX && r <= x86asm.R15L:
		return alias{int(r - x86asm.EAX), 32, 0}, true
	case r >= x86asm.AX && r <= x86asm.R15W:
		return alias{int(r - x86asm.AX), 16, 0}, true
	case r >= x86asm.AL && r <= x86asm.BL:
		return alias{int(r - x86asm.AL), 8, 0}, true
	case r >= x86asm.AH && r <= x86asm.BH:
		return alias{int(r - x86asm.AH), 8, 8}, true
	case r >= x86asm.SPB && r <= x86asm.R15B:
		return alias{int(r-x86asm.SPB) + 4, 8, 0}, true
	default:
		return alias{}, false
	}
}

func (s *state) read(a alias) value {
	v := s.regs[a.reg]
	return (value{v.defined >> a.shift, v.zero >> a.shift, v.one >> a.shift}).trim(a.width)
}

func (s *state) write(pc uint64, a alias, v value, face Interface) error {
	m := mask(a.width) << a.shift
	if a.width == 32 {
		m = ^uint64(0)
	}
	if a.reg == int(RSP) {
		return refuse(pc, "return-interface", "instruction writes the stack pointer")
	}
	if face.Preserved[a.reg]&m != 0 {
		return refuse(pc, "preserved-register", fmt.Sprintf("write intersects preserved register %d bits %#x", a.reg, face.Preserved[a.reg]&m))
	}
	v = v.trim(a.width)
	old := s.regs[a.reg]
	s.regs[a.reg] = value{old.defined&^m | v.defined<<a.shift, old.zero&^m | v.zero<<a.shift, old.one&^m | v.one<<a.shift}
	if a.width == 32 {
		s.regs[a.reg].defined |= ^uint64(0xffffffff)
		s.regs[a.reg].zero |= ^uint64(0xffffffff)
	}
	return nil
}

func operand(pc uint64, s *state, arg x86asm.Arg, width int) (value, error) {
	switch v := arg.(type) {
	case x86asm.Reg:
		a, ok := register(v)
		if !ok || a.width != width {
			return value{}, refuse(pc, "instruction-shape", "incompatible register operand")
		}
		return s.read(a), nil
	case x86asm.Imm:
		return constant(uint64(v), width), nil
	case x86asm.Mem:
		return value{}, refuse(pc, "data-memory", "data-memory operand is outside the leaf bound")
	default:
		return value{}, refuse(pc, "instruction-shape", "missing or unsupported scalar operand")
	}
}

func add(a, b value, width int) value {
	// A result bit can depend on every lower input bit through carry. Keeping
	// only the common defined low prefix is conservative even for sparse masks.
	n := bits.TrailingZeros64(^(a.defined & b.defined))
	d := mask(min(n, width))
	known := a.zero | a.one
	otherKnown := b.zero | b.one
	k := min(bits.TrailingZeros64(^(known & otherKnown)), width)
	v := (a.one + b.one) & mask(k)
	return value{d, ^v & mask(k), v}
}

func xor(a, b value, width int) value {
	return (value{a.defined & b.defined, a.zero&b.zero | a.one&b.one, a.zero&b.one | a.one&b.zero}).trim(width)
}

func and(a, b value, width int) value {
	return (value{a.defined&b.defined | a.zero | b.zero, a.zero | b.zero, a.one & b.one}).trim(width)
}

func shl(a value, count, width int) value {
	low := mask(count)
	return (value{a.defined<<count | low, a.zero<<count | low, a.one << count}).trim(width)
}

func shr(a value, count, width int) value {
	high := mask(width) &^ mask(width-count)
	return value{a.defined>>count | high, a.zero>>count | high, a.one >> count}
}

func resultFlags(v value, width int) uint8 {
	var f uint8
	if v.defined&mask(width) == mask(width) {
		f |= zf
	}
	if v.defined&(uint64(1)<<(width-1)) != 0 {
		f |= sf
	}
	if v.defined&0xff == 0xff {
		f |= pf
	}
	return f
}

func condition(op x86asm.Op) uint8 {
	switch op {
	case x86asm.JA, x86asm.JBE, x86asm.SETA, x86asm.SETBE:
		return cf | zf
	case x86asm.JAE, x86asm.JB, x86asm.SETAE, x86asm.SETB:
		return cf
	case x86asm.JE, x86asm.JNE, x86asm.SETE, x86asm.SETNE:
		return zf
	case x86asm.JL, x86asm.JGE, x86asm.SETL, x86asm.SETGE:
		return sf | of
	case x86asm.JLE, x86asm.JG, x86asm.SETLE, x86asm.SETG:
		return zf | sf | of
	default:
		return 0
	}
}

func transfer(pc uint64, i operation, s *state, face Interface) error {
	if needed := condition(i.Op); needed != 0 {
		if s.flags&needed != needed {
			return refuse(pc, "flag-input-bound", "condition consumes undefined or undeclared-entry flags")
		}
		if _, branch := i.Args[0].(x86asm.Rel); branch {
			return nil
		}
		r, ok := i.Args[0].(x86asm.Reg)
		a, valid := register(r)
		if !ok || !valid || a.width != 8 || i.Args[1] != nil {
			return refuse(pc, "instruction-shape", "SETcc requires one byte register")
		}
		// SETcc writes 0 or 1: bit zero is input-defined, the other seven zero.
		return s.write(pc, a, value{0xff, 0xfe, 0}, face)
	}
	switch i.Op {
	case x86asm.RET:
		for reg, wanted := range face.Results {
			if s.regs[reg].defined&wanted != wanted {
				return missingBits(pc, reg, wanted, s.regs[reg].defined)
			}
		}
		return nil
	case x86asm.JMP, x86asm.NOP:
		return nil
	}
	r, ok := i.Args[0].(x86asm.Reg)
	a, valid := register(r)
	if !ok || !valid {
		if _, memory := i.Args[0].(x86asm.Mem); memory {
			return refuse(pc, "data-memory", "memory destination/compare is outside the leaf bound")
		}
		return refuse(pc, "instruction-shape", "requires integer register destination")
	}
	if i.Op != x86asm.MOV && a.width != 32 && a.width != 64 {
		return refuse(pc, "instruction-shape", "arithmetic requires 32 or 64 bits")
	}
	left := s.read(a)
	if i.Op == x86asm.LEA {
		m, ok := i.Args[1].(x86asm.Mem)
		if !ok || m.Segment != 0 {
			return refuse(pc, "instruction-shape", "LEA requires unsegmented address arithmetic")
		}
		v := constant(uint64(m.Disp), a.width)
		for index, reg := range []x86asm.Reg{m.Base, m.Index} {
			if reg == 0 {
				continue
			}
			ref, ok := register(reg)
			if !ok || ref.width != 64 {
				return refuse(pc, "instruction-shape", "LEA base/index must be 64-bit integer registers")
			}
			x := s.read(ref).trim(a.width)
			if index == 1 {
				if m.Scale != 1 && m.Scale != 2 && m.Scale != 4 && m.Scale != 8 {
					return refuse(pc, "instruction-shape", "invalid LEA scale")
				}
				x = shl(x, bits.TrailingZeros8(m.Scale), a.width)
			}
			v = add(v, x, a.width)
		}
		return s.write(pc, a, v, face)
	}
	if i.Op == x86asm.SHR {
		imm, ok := i.Args[1].(x86asm.Imm)
		if !ok {
			return refuse(pc, "instruction-shape", "only immediate shifts are modeled")
		}
		count := int(uint64(imm) & uint64(a.width-1))
		v := shr(left, count, a.width)
		if count != 0 {
			s.flags = resultFlags(v, a.width)
			if left.defined&(uint64(1)<<(count-1)) != 0 {
				s.flags |= cf
			}
			if count == 1 && left.defined&(uint64(1)<<(a.width-1)) != 0 {
				s.flags |= of
			}
		}
		return s.write(pc, a, v, face)
	}
	right, err := operand(pc, s, i.Args[1], a.width)
	if err != nil {
		return err
	}
	var v value
	switch i.Op {
	case x86asm.MOV:
		v = right
	case x86asm.XOR:
		v = xor(left, right, a.width)
		if other, ok := i.Args[1].(x86asm.Reg); ok && other == r {
			v = constant(0, a.width)
		}
		s.flags = resultFlags(v, a.width) | cf | of
	case x86asm.AND:
		v = and(left, right, a.width)
		s.flags = resultFlags(v, a.width) | cf | of
	case x86asm.ADD:
		v = add(left, right, a.width)
		s.flags = resultFlags(v, a.width)
		if left.defined&right.defined&mask(a.width) == mask(a.width) {
			s.flags |= cf | of
		}
	case x86asm.CMP:
		// All modeled comparison flags depend only on the complete operands.
		// Partial-input comparisons conservatively leave all flags unproved.
		s.flags = 0
		if left.defined&right.defined&mask(a.width) == mask(a.width) {
			s.flags = cf | of | zf | sf | pf
		}
		return nil
	default:
		return refuse(pc, "instruction-semantics", "missing transfer rule")
	}
	return s.write(pc, a, v, face)
}
