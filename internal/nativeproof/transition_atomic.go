package nativeproof

import (
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

func (m *transitionChecker) setPredicates(p TransitionPredicates) {
	m.state.flags = [flagCount]br.Term{p.CF, p.ZF, p.SFXorOF}
}

// lockedAddress establishes the full read/write extent before any register
// changes, including when the source register is also the addressing base.
func (m *transitionChecker) lockedAddress(mem x86asm.Mem, width int, size uint8) (TransitionLocation, error) {
	if m.face.Conditions.LockedMemory != LockedMemoryModel {
		return TransitionLocation{}, refuse(m.pc, "transition-primitive-premise", "ordinary naturally aligned locked-memory applicability is required")
	}
	off, err := m.address(mem, FrameRead, width, size)
	if err != nil {
		return TransitionLocation{}, err
	}
	mask := uint64(width - 1)
	aligned := uint64(off.Offset)&mask == 0
	if !off.Image {
		d := m.face.Origin
		aligned = d.Modulus >= uint64(width) && (d.Residue+uint64(off.Offset))&mask == 0
		// Singleton origin domains can establish alignment without a modulus.
		if m.lo == m.hi {
			aligned = (m.lo+uint64(off.Offset))&mask == 0
		}
	}
	if !aligned {
		return TransitionLocation{}, refuse(m.pc, "transition-alignment", "locked memory requires natural operand alignment for every origin")
	}
	// An unchanged result still writes. Both permissions apply to the incoming
	// address, regardless of comparison outcome or source/base register aliasing.
	if _, err := m.address(mem, FrameWrite, width, size); err != nil {
		return TransitionLocation{}, err
	}
	return off, nil
}

func (m *transitionChecker) lockedCompareExchange(i operation, size uint8) error {
	width := i.MemBytes
	off, err := m.lockedAddress(i.Args[0].(x86asm.Mem), width, size)
	if err != nil {
		return err
	}
	readIndex := len(m.bound.Accesses)
	current := m.load(off, width, FrameRead)
	src, _ := register(i.Args[1].(x86asm.Reg))
	replacement := m.read(&m.state, src)
	r := m.valueBuilder.compareExchange(m.state.regs[RAX], current.Value, replacement)
	if m.err != nil {
		return m.err
	}
	// The comparison remains symbolic; scalar equality supplies no outcome-
	// specific provenance. Full-width results retain only common provenance.
	// CAS32 drops memory and RAX provenance even when its scalar success arm
	// preserves all incoming RAX bits: failure replaces RAX with a narrow value.
	var memoryPointer, accumulatorPointer TransitionPointer
	if width == 8 {
		memoryPointer = sameTransitionPointer(m.pointers[src.reg], current.Pointer)
		accumulatorPointer = sameTransitionPointer(m.pointers[RAX], current.Pointer)
	}
	m.store(off, TransitionValue{r.Memory, memoryPointer}, width)
	m.state.regs[RAX], m.pointers[RAX], m.bound.Preserved[RAX] = r.Accumulator, accumulatorPointer, 0
	m.bound.Flags = r.Flags
	m.setPredicates(r.Predicates)
	m.bound.PrimitiveEffects = append(m.bound.PrimitiveEffects, LockedCompareExchangeEffect{ID: m.occurrence, PC: m.pc, Context: m.activation, Width: width, ReadAccess: readIndex, WriteAccess: readIndex + 1, Before: current.Value, Compare: r.Compare, Replacement: replacement, After: r.Memory, Accumulator: r.Accumulator, Success: r.Success})
	return m.err
}

func (m *transitionChecker) lockedExchange(i operation, size uint8) error {
	off, err := m.lockedAddress(i.Args[0].(x86asm.Mem), 8, size)
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
		m.bound.PrimitiveEffects = append(m.bound.PrimitiveEffects, LockedExchange64Effect{ID: m.occurrence, PC: m.pc, Context: m.activation, ReadAccess: readIndex, WriteAccess: readIndex + 1, Before: current.Value, Replacement: replacement, After: memory, Register: register})
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
		m.bound.PrimitiveEffects = append(m.bound.PrimitiveEffects, LockedExchangeAdd64Effect{ID: m.occurrence, PC: m.pc, Context: m.activation, ReadAccess: readIndex, WriteAccess: readIndex + 1, Before: current.Value, Delta: replacement, After: memory, Register: register})
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

func (m *transitionChecker) lockedLogical(i operation, size uint8) error {
	off, err := m.lockedAddress(i.Args[0].(x86asm.Mem), 1, size)
	if err != nil {
		return err
	}
	readIndex := len(m.bound.Accesses)
	before := m.load(off, 1, FrameRead).Value
	var operand br.Term
	if r, ok := i.Args[1].(x86asm.Reg); ok {
		a, _ := register(r)
		operand = m.read(&m.state, a)
	} else {
		operand = m.con(br.Bits(8), uint64(i.Args[1].(x86asm.Imm))&255)
	}
	r := m.valueBuilder.logical(i.Op, before, operand)
	m.bound.Flags = r.Flags
	m.setPredicates(r.Predicates)
	m.store(off, TransitionValue{Value: r.Value}, 1)
	m.bound.PrimitiveEffects = append(m.bound.PrimitiveEffects, LockedLogicalEffect{ID: m.occurrence, PC: m.pc, Context: m.activation, Kind: i.Op, Width: 1, ReadAccess: readIndex, WriteAccess: readIndex + 1, Before: before, Operand: operand, After: r.Value})
	return m.err
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
	read := func(arg x86asm.Arg) (TransitionValue, error) {
		switch x := arg.(type) {
		case x86asm.Reg:
			a, _ := register(x)
			v := TransitionValue{Value: m.read(&m.state, a)}
			if a.width == 64 {
				v.Pointer = m.pointers[a.reg]
			}
			return v, m.err
		case x86asm.Imm:
			return TransitionValue{Value: m.con(br.Bits(width), uint64(x)&mask(width))}, m.err
		case x86asm.Mem:
			off, err := m.address(x, FrameRead, width/8, size)
			if err != nil {
				return TransitionValue{}, err
			}
			return m.load(off, width/8, FrameRead), m.err
		}
		return TransitionValue{}, refuse(m.pc, "transition-form", "unsupported predicate operand")
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
		m.bound.Flags, p = m.compareFlags(left.Value, right.Value)
	} else {
		m.bound.Flags, p = m.testFlags(left.Value, right.Value)
	}
	m.setPredicates(p)
	if i.Op == x86asm.CMP {
		_, err = m.refineOriginCompare(left, right)
		if err != nil {
			return err
		}
	}
	return m.err
}
