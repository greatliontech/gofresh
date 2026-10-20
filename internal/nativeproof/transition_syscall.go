package nativeproof

import br "github.com/greatliontech/gofresh/internal/bitrelation"

func (m *transitionChecker) archSetFS(size uint8) error {
	c := m.face.Conditions
	if c.Syscall != LinuxAMD64SyscallModel || !m.thread.FS.Value.Valid() {
		return refuse(m.pc, "transition-primitive-premise", "native uninterposed syscall/thread condition is required")
	}
	number, option := m.extract(m.state.regs[RAX], 0, 32), m.extract(m.state.regs[RDI], 0, 32)
	selectors := m.and(m.compare(br.Equal, number, m.con(br.Bits(32), 158)), m.compare(br.Equal, option, m.con(br.Bits(32), 0x1002)))
	ok, err := m.tryFalse(m.and(m.state.path, m.not(selectors)))
	if err != nil {
		return err
	}
	if !ok {
		return refuse(m.pc, "transition-syscall-selector", "actual native syscall/operation selectors are not established")
	}
	ceiling := uint64(1)<<(c.UserAddressBits-1) - 4096
	base, before := m.state.regs[RSI], m.thread.FS
	valid := m.compare(br.ULT, base, m.con(br.Bits(64), ceiling))
	// Pointer/value agreement is a checked invariant of the transition domain,
	// conditional on its origin bounds. These bounds are not hypotheses accepted
	// by bitrelation: this explicit domain rule decides validity only when the
	// entire represented scalar range lies on one side of the syscall ceiling.
	var low, high uint64
	known := false
	switch p := m.pointers[RSI].(type) {
	case AddressPointer:
		if _, err := m.advance(p, 0); err != nil {
			return err
		}
		if p.isImage() {
			low, high = uint64(p.offset), uint64(p.offset)
		} else {
			low, _ = relative(m.lo, p.offset)
			high, _ = relative(m.hi, p.offset)
		}
		known = true
	}
	if known && high < ceiling {
		valid = m.truth
	} else if known && low >= ceiling {
		valid = m.falsity
	}
	result := m.ite(valid, m.con(br.Bits(64), 0), m.con(br.Bits(64), ^uint64(0)))
	after := TransitionValue{Value: m.ite(valid, base, before.Value)}
	success, err := m.tryFalse(m.and(m.state.path, m.not(valid)))
	if err != nil {
		return err
	}
	failure := false
	if success {
		after.Pointer = addressCapability(m.pointers[RSI])
	} else {
		failure, err = m.tryFalse(m.and(m.state.path, valid))
		if err != nil {
			return err
		}
		if failure {
			after.Pointer = before.Pointer
		} else if before.Pointer == m.pointers[RSI] {
			after.Pointer = before.Pointer
		}
	}
	m.bound.PrimitiveEffects = append(m.bound.PrimitiveEffects, ArchSetFSEffect{ID: m.occurrence, PC: m.pc, Context: m.activation, Number: number, Operation: option, Base: base, Valid: valid, Result: result, BeforeFS: before.Value, AfterFS: after.Value})
	m.thread.FS = after
	// Success may replace the selector through either a descriptor or base
	// register. Failure preserves it, but no blanket preservation is inferred
	// unless success is impossible under the current guard.
	m.thread.SelectorPreserved = m.thread.SelectorPreserved && failure
	m.thread.ContextChanged = true
	m.state.regs[RAX], m.state.regs[RCX] = result, m.con(br.Bits(64), m.pc+uint64(size))
	// Full architectural flags are not represented by the three status
	// predicates. Forget R11's deterministic value explicitly, rather than
	// fabricating a Linux nondeterministic outcome or a replacement entry input.
	if !m.tick() {
		return m.err
	}
	v, err := m.builder.Input(br.Bits(64), br.NewScope(), 0)
	if err != nil {
		m.expressionError(err)
		return m.err
	}
	m.remember(v, 1)
	m.state.regs[R11] = v
	m.bound.Abstractions = append(m.bound.Abstractions, TransitionAbstraction{ID: m.occurrence, PC: m.pc, Context: m.activation, Value: v, Predicates: TransitionPredicates{m.state.flags[flagCarry], m.state.flags[flagZero], m.state.flags[flagLess]}})
	for _, reg := range []Register{RAX, RCX, R11} {
		m.pointers[reg], m.bound.Preserved[reg] = nil, 0
	}
	return m.err
}
