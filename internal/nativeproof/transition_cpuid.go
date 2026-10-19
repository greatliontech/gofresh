package nativeproof

import br "github.com/greatliontech/gofresh/internal/bitrelation"

func (m *transitionChecker) cpuid() error {
	if m.face.Conditions.CPUID != CPUIDModel {
		return refuse(m.pc, "transition-primitive-premise", "CPUID architectural-step condition is required")
	}
	// Capture both selectors before any destination changes. Outcomes belong to
	// this verified occurrence, never the entry scratch namespace (which remains
	// closed on continuation). No caller supplies values or outcome identities.
	e := CPUIDEffect{ID: m.occurrence, PC: m.pc, Context: m.activation, Leaf: m.extract(m.state.regs[RAX], 0, 32), Subleaf: m.extract(m.state.regs[RCX], 0, 32)}
	scope := br.NewScope()
	for slot, result := range []*br.Term{&e.ResultsEAX, &e.ResultsEBX, &e.ResultsECX, &e.ResultsEDX} {
		if !m.tick() {
			return m.err
		}
		t, err := m.builder.Input(br.Bits(32), scope, uint64(slot))
		if err != nil {
			m.expressionError(err)
			return m.err
		}
		m.remember(t, 1)
		*result = t
	}
	for j, reg := range []Register{RAX, RBX, RCX, RDX} {
		result := []br.Term{e.ResultsEAX, e.ResultsEBX, e.ResultsECX, e.ResultsEDX}[j]
		m.state.regs[reg] = m.make(br.ZExt, br.Bits(64), 0, result)
		m.pointers[reg], m.bound.Preserved[reg] = nil, 0
	}
	if !m.tick() {
		return m.err
	}
	m.bound.PrimitiveEffects = append(m.bound.PrimitiveEffects, e)
	return m.err
}
