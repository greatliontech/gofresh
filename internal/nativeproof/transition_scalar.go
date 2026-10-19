package nativeproof

import (
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// The narrow scalar forms bind the normalized operands back to every encoding
// field. No memory, immediate, operand-size override or extra operand is admitted.
func validateScalarTailForm(pc uint64, i x86asm.Inst, b []byte) error {
	bad := func() error { return refuse(pc, "transition-form", "unsupported scalar encoding or operand form") }
	if err := legalPrefixes(pc, b, i); err != nil {
		return err
	}
	at, rex := 0, byte(0)
	if len(b) > 0 && b[0] >= 0x40 && b[0] <= 0x4f {
		at, rex = 1, b[0]
	}
	if len(b) != at+2 || i.Len != len(b) || i.MemBytes != 0 || b[at+1]&0xc0 != 0xc0 || i.Args[2] != nil || i.Args[3] != nil {
		return bad()
	}
	op, modrm := b[at], b[at+1]
	rm, reg := int(modrm&7)+int(rex&1)*8, int(modrm>>3&7)+int(rex>>2&1)*8
	operand := func(arg x86asm.Arg, index, width int) bool {
		r, ok := arg.(x86asm.Reg)
		a, valid := register(r)
		return ok && valid && a.reg == index && a.width == width && a.shift == 0
	}
	switch i.Op {
	case x86asm.INC:
		if rex&8 == 0 || i.DataSize != 64 || op != 0xff || modrm&0x38 != 0 || !operand(i.Args[0], rm, 64) || i.Args[1] != nil {
			return bad()
		}
	case x86asm.SHL:
		if rex&8 != 0 || i.DataSize != 32 || op != 0xd3 || modrm&0x38 != 0x20 || !operand(i.Args[0], rm, 32) || i.Args[1] != x86asm.CL {
			return bad()
		}
	case x86asm.SBB, x86asm.AND:
		base := byte(0x19)
		if i.Op == x86asm.AND {
			base = 0x21
		}
		if rex&8 != 0 || i.DataSize != 32 || op != base && op != base+2 {
			return bad()
		}
		if op == base+2 {
			rm, reg = reg, rm
		}
		if !operand(i.Args[0], rm, 32) || !operand(i.Args[1], reg, 32) {
			return bad()
		}
	default:
		return bad()
	}
	return nil
}

func (m *transitionChecker) scalarTail(i operation) error {
	a, _ := register(i.Args[0].(x86asm.Reg))
	left := m.read(&m.state, a)
	var r ArithmeticResult
	var pointer TransitionPointer
	switch i.Op {
	case x86asm.INC:
		carry, predicate := m.bound.Flags.CF, m.state.flags[flagCarry]
		r = m.add(left, m.con(br.Bits(64), 1))
		r.Flags.CF, r.Predicates.CF = carry, predicate
		// Arithmetic itself is modular and cannot fault. An unproved affine
		// address offset loses provenance instead of rejecting scalar execution.
		if addressCapability(m.pointers[a.reg]) != nil {
			pointer, _ = m.advance(m.pointers[a.reg], 1)
		}
	case x86asm.SBB:
		carry := m.state.flags[flagCarry]
		if !m.bound.Flags.CF.Defined || carry.Sort() != br.Bool() {
			return refuse(m.pc, "transition-flag", "SBB requires the current defined carry predicate")
		}
		src, _ := register(i.Args[1].(x86asm.Reg))
		r = m.subtractBorrow(left, m.read(&m.state, src), carry)
	case x86asm.AND:
		src, _ := register(i.Args[1].(x86asm.Reg))
		r.Value = m.binary(br.BitAnd, left, m.read(&m.state, src))
		r.Flags, r.Predicates = m.logicalFlags(r.Value)
	case x86asm.SHL:
		// Read CL before writing the destination, especially for ECX itself.
		shift := m.shiftLeft32(left, m.read(&m.state, alias{reg: int(RCX), width: 8}))
		flags, predicates, err := m.shiftFlags(shift)
		if err != nil {
			return err
		}
		r = ArithmeticResult{shift.Value, flags, predicates}
	}
	m.write(&m.state, a, r.Value)
	m.bound.Preserved[a.reg], m.pointers[a.reg] = 0, pointer
	m.bound.Flags = r.Flags
	m.setPredicates(r.Predicates)
	return m.err
}

// shiftFlags projects only guarantees over the complete incoming scope. Side
// proofs use the same retained cumulative checker as unreachable-boundary proofs.
// Predicate availability is independent of individual public flag projections.
func (m *transitionChecker) shiftFlags(r ShiftLeft32Result) (TransitionFlags, TransitionPredicates, error) {
	old := m.bound.Flags
	previous := TransitionPredicates{m.state.flags[flagCarry], m.state.flags[flagZero], m.state.flags[flagLess]}
	prove := func(p br.Term) (bool, error) {
		if m.err != nil {
			return false, m.err
		}
		return m.tryFalse(m.and(m.state.path, m.not(p)))
	}
	zeroOnly, err := prove(r.ZeroCount)
	if err != nil {
		return TransitionFlags{}, TransitionPredicates{}, err
	}
	if zeroOnly {
		return old, previous, nil
	}
	nonzero, err := prove(m.not(r.ZeroCount))
	if err != nil {
		return TransitionFlags{}, TransitionPredicates{}, err
	}
	zeroOrOne, err := prove(m.or(r.ZeroCount, r.OneCount))
	if err != nil {
		return TransitionFlags{}, TransitionPredicates{}, err
	}
	mergeValue := func(before, after br.Term) br.Term {
		if after.Sort() != br.Bool() {
			return br.Term{}
		}
		if nonzero {
			return after
		}
		if before.Sort() != br.Bool() {
			return br.Term{}
		}
		return m.ite(r.ZeroCount, before, after)
	}
	merge := func(before TransitionFlag, after br.Term) TransitionFlag {
		if !before.Defined && !nonzero {
			return TransitionFlag{}
		}
		return TransitionFlag{Defined: true, Value: mergeValue(before.Value, after)}
	}
	f := TransitionFlags{CF: merge(old.CF, r.Carry), SF: merge(old.SF, r.Sign), ZF: merge(old.ZF, r.Zero), PF: merge(old.PF, r.Parity)}
	p := TransitionPredicates{CF: mergeValue(previous.CF, r.Carry), ZF: mergeValue(previous.ZF, r.Zero)}
	if !f.CF.Defined {
		p.CF = br.Term{}
	}
	if !f.ZF.Defined {
		p.ZF = br.Term{}
	}
	if zeroOrOne {
		f.OF = merge(old.OF, r.Overflow)
		if f.SF.Defined && f.OF.Defined {
			p.SFXorOF = mergeValue(previous.SFXorOF, m.different(r.Sign, r.Overflow))
		}
	}
	// AF is undefined on every nonzero count; zero-only returned above.
	return f, p, m.err
}
