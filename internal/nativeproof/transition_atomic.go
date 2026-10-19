package nativeproof

import (
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

func (m *transitionChecker) setPredicates(p TransitionPredicates) {
	m.state.flags = [flagCount]br.Term{p.CF, p.ZF, p.SFXorOF}
}

// locked64Address establishes the full read/write extent before any register
// changes, including when the source register is also the addressing base.
func (m *transitionChecker) locked64Address(mem x86asm.Mem, size uint8) (TransitionLocation, error) {
	if m.face.Conditions.Locked64 != Locked64Model {
		return TransitionLocation{}, refuse(m.pc, "transition-primitive-premise", "ordinary aligned locked64 applicability is required")
	}
	off, err := m.address(mem, FrameRead, 8, size)
	if err != nil {
		return TransitionLocation{}, err
	}
	aligned := uint64(off.Offset)&7 == 0
	if !off.Image {
		d := m.face.Origin
		aligned = d.Modulus >= 8 && (d.Residue+uint64(off.Offset))&7 == 0
		// Singleton origin domains can establish alignment without a modulus.
		if m.lo == m.hi {
			aligned = (m.lo+uint64(off.Offset))&7 == 0
		}
	}
	if !aligned {
		return TransitionLocation{}, refuse(m.pc, "transition-alignment", "locked64 requires eight-byte alignment for every origin")
	}
	// An unchanged result still writes. Both permissions apply to the incoming
	// address, regardless of comparison outcome or source/base register aliasing.
	if _, err := m.address(mem, FrameWrite, 8, size); err != nil {
		return TransitionLocation{}, err
	}
	return off, nil
}

func (m *transitionChecker) lockedCompareExchange(i operation, size uint8) error {
	off, err := m.locked64Address(i.Args[0].(x86asm.Mem), size)
	if err != nil {
		return err
	}
	readIndex := len(m.bound.Accesses)
	current := m.load(off, 8, FrameRead)
	src, _ := fullRegister(i.Args[1])
	compare, replacement := m.state.regs[RAX], m.state.regs[src.reg]
	r := m.valueBuilder.compareExchange64(compare, current.Value, replacement)
	if m.err != nil {
		return m.err
	}
	// A merged pointer is valid only if both possible source provenances agree.
	// Scalar equality never manufactures pointer provenance.
	memoryPointer := sameTransitionPointer(m.pointers[src.reg], current.Pointer)
	accumulatorPointer := sameTransitionPointer(m.pointers[RAX], current.Pointer)
	if literalBool(r.Success, 1) {
		memoryPointer, accumulatorPointer = m.pointers[src.reg], m.pointers[RAX]
	} else if literalBool(r.Success, 0) {
		memoryPointer, accumulatorPointer = current.Pointer, current.Pointer
	}
	m.store(off, TransitionValue{r.Memory, memoryPointer}, 8)
	m.state.regs[RAX], m.pointers[RAX], m.bound.Preserved[RAX] = r.Accumulator, accumulatorPointer, 0
	m.bound.Flags = r.Flags
	m.setPredicates(r.Predicates)
	m.bound.PrimitiveEffects = append(m.bound.PrimitiveEffects, LockedCompareExchange64Effect{PC: m.pc, Context: m.activation, ReadAccess: readIndex, WriteAccess: readIndex + 1, Before: current.Value, Compare: compare, Replacement: replacement, After: r.Memory, Accumulator: r.Accumulator, Success: r.Success})
	return m.err
}

func (m *transitionChecker) lockedExchange(i operation, size uint8) error {
	off, err := m.locked64Address(i.Args[0].(x86asm.Mem), size)
	if err != nil {
		return err
	}
	readIndex := len(m.bound.Accesses)
	current := m.load(off, 8, FrameRead)
	src, _ := fullRegister(i.Args[1])
	replacement := m.state.regs[src.reg]
	var register, memory br.Term
	var pointer TransitionPointer
	if i.Op == x86asm.XCHG {
		r := m.exchange64(current.Value, replacement)
		register, memory, pointer = r.Register, r.Memory, m.pointers[src.reg]
		m.bound.PrimitiveEffects = append(m.bound.PrimitiveEffects, LockedExchange64Effect{PC: m.pc, Context: m.activation, ReadAccess: readIndex, WriteAccess: readIndex + 1, Before: current.Value, Replacement: replacement, After: memory, Register: register})
	} else {
		r := m.exchangeAdd64(current.Value, replacement)
		register, memory = r.Register, r.Memory
		// Arbitrary arithmetic does not establish a pointer offset. Exact zero
		// leaves the complete incoming pointer word unchanged.
		if v := replacement.View(); v.Op == br.Constant && v.Immediate == 0 {
			pointer = current.Pointer
		}
		m.bound.Flags = r.Flags
		m.setPredicates(r.Predicates)
		m.bound.PrimitiveEffects = append(m.bound.PrimitiveEffects, LockedExchangeAdd64Effect{PC: m.pc, Context: m.activation, ReadAccess: readIndex, WriteAccess: readIndex + 1, Before: current.Value, Delta: replacement, After: memory, Register: register})
	}
	m.store(off, TransitionValue{Value: memory, Pointer: pointer}, 8)
	m.state.regs[src.reg], m.pointers[src.reg], m.bound.Preserved[src.reg] = register, current.Pointer, 0
	return m.err
}

func sameTransitionPointer(a, b TransitionPointer) TransitionPointer {
	if a == b {
		return a
	}
	return nil
}

func (m *transitionChecker) setConditionByte(i operation, size uint8) error {
	p := TransitionPredicates{m.state.flags[flagCarry], m.state.flags[flagZero], m.state.flags[flagLess]}
	v := m.valueBuilder.setCondition(i.Op, p)
	if mem, ok := i.Args[0].(x86asm.Mem); ok {
		off, err := m.address(mem, FrameWrite, 1, size)
		if err != nil {
			return err
		}
		m.store(off, TransitionValue{Value: v}, 1)
	} else {
		a, _ := register(i.Args[0].(x86asm.Reg))
		m.write(&m.state, a, v)
		m.pointers[a.reg] = nil
		m.bound.Preserved[a.reg] &^= uint64(255) << a.shift
	}
	return m.err
}

func (m *transitionChecker) compareOrTest(i operation, size uint8) error {
	width := 0
	for _, arg := range i.Args {
		if reg, ok := arg.(x86asm.Reg); ok {
			a, _ := register(reg)
			width = a.width
			break
		}
	}
	if width == 0 {
		width = i.MemBytes * 8
	}
	read := func(arg x86asm.Arg) (br.Term, error) {
		switch x := arg.(type) {
		case x86asm.Reg:
			a, _ := register(x)
			return m.read(&m.state, a), m.err
		case x86asm.Imm:
			return m.con(br.Bits(width), uint64(x)&mask(width)), m.err
		case x86asm.Mem:
			off, err := m.address(x, FrameRead, width/8, size)
			if err != nil {
				return br.Term{}, err
			}
			return m.load(off, width/8, FrameRead).Value, m.err
		}
		return br.Term{}, refuse(m.pc, "transition-form", "unsupported predicate operand")
	}
	left, err := read(i.Args[0])
	if err != nil {
		return err
	}
	right, err := read(i.Args[1])
	if err != nil {
		return err
	}
	var p TransitionPredicates
	if i.Op == x86asm.CMP {
		m.bound.Flags, p = m.compareFlags(left, right)
	} else {
		m.bound.Flags, p = m.testFlags(left, right)
	}
	m.setPredicates(p)
	return m.err
}
