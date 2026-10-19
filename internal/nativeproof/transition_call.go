package nativeproof

import (
	"fmt"
	"slices"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

type transitionActivation struct {
	parent              string
	entry, continuation uint64
}

func callContext(parent string, pc uint64) string { return fmt.Sprintf("%s/%016x", parent, pc) }

func (m *transitionChecker) graph(cut uint64) (*graph, error) { return m.graphPrefix(cut, false) }

func (m *transitionChecker) graphPrefix(cut uint64, prefix bool) (*graph, error) {
	if len(m.expansions) > (m.limits.LiveStateBytes-m.liveStateBytes)/128 {
		return nil, refuse(cut, "transition-budget", "expansion choice storage")
	}
	m.liveStateBytes += 128 * len(m.expansions)
	choices := make(map[programPoint]bool, len(m.expansions))
	for _, e := range m.expansions {
		if !m.tick() {
			return nil, m.err
		}
		p := programPoint{e.PC, e.Context}
		if _, exists := choices[p]; exists {
			return nil, refuse(e.PC, "transition-expansion", "duplicate transfer expansion")
		}
		choices[p] = false
	}
	activations := map[string]transitionActivation{"": {entry: m.root.entry}}
	var boundary *programPoint
	g, err := decodeOccurrenceGraph(&relationContext{Context: m.ctx, meter: m.valueBuilder}, m.root.entry, m.limits.Instructions, func(p programPoint) (decodedInstruction, error) {
		m.pc = p.pc
		// Charge occurrence storage and context strings before retaining them. The
		// prefix reconstruction and suffix share this same aggregate allowance.
		n := 2048 + 2*len(p.context)
		if n > m.limits.LiveStateBytes-m.liveStateBytes {
			return decodedInstruction{}, refuse(p.pc, "transition-budget", "activation graph storage")
		}
		m.liveStateBytes += n
		i, _, err := decodeBytes(m.im, p.pc)
		if err != nil {
			return decodedInstruction{}, err
		}
		if p.pc == cut {
			if boundary != nil && *boundary != p {
				return decodedInstruction{}, refuse(cut, "transition-cut", "numeric first-hit cut has multiple activation contexts")
			}
			copy := p
			boundary = &copy
			return decodedInstruction{boundary: boundaryCut, size: uint8(i.Len)}, nil
		}
		_, expand := choices[p]
		optional := TransitionExpansionRequired(i)
		if expand && !optional {
			return decodedInstruction{}, refuse(p.pc, "transition-expansion", "expansion is not an optional transfer")
		}
		if optional && !expand {
			// This alternative admits no execution or successor transfer. In
			// particular, adding self-XOR semantics must not force discovery into
			// a formerly excluded dead arm's cycle. Only finish's
			// independently checked full incoming false guard can accept it.
			return decodedInstruction{boundary: boundaryUnsupported, size: uint8(i.Len)}, nil
		}
		d, err := decodeTransitionBoundary(m.im, p.pc, cut)
		if err != nil {
			return decodedInstruction{}, err
		}
		if expand && d.boundary != boundaryNone {
			return decodedInstruction{}, refuse(p.pc, "transition-expansion", "selected encoding has no admitted transfer")
		}
		if expand {
			choices[p] = true
		}
		for j := range d.count {
			d.contexts[j] = p.context
		}
		if d.boundary != boundaryNone {
			return d, nil
		}
		switch i.Op {
		case x86asm.CALL:
			target := d.targets[0]
			for at := p.context; ; at = activations[at].parent {
				if !m.tick() {
					return decodedInstruction{}, m.err
				}
				if activations[at].entry == target {
					return decodedInstruction{}, refuse(p.pc, "acyclic-control", "recursive activation is unsupported")
				}
				if at == "" {
					break
				}
			}
			if len(p.context)+17 > m.limits.Work-m.work {
				return decodedInstruction{}, refuse(p.pc, "transition-budget", "activation path work")
			}
			m.work += len(p.context) + 17
			child := callContext(p.context, p.pc)
			activations[child] = transitionActivation{p.context, target, p.pc + uint64(d.size)}
			d.contexts[0] = child
		case x86asm.RET:
			if p.context == "" {
				return decodedInstruction{boundary: boundaryUnsupported, size: d.size}, nil
			}
			a := activations[p.context]
			d.count, d.targets[0], d.contexts[0] = 1, a.continuation, a.parent
		}
		return d, nil
	})
	if err != nil {
		return nil, err
	}
	if boundary == nil {
		return nil, refuse(cut, "transition-cut", "cut is not a reachable decoded boundary")
	}
	if !prefix {
		for _, e := range m.expansions {
			p := programPoint{e.PC, e.Context}
			if !m.tick() {
				return nil, m.err
			}
			if !choices[p] {
				return nil, refuse(p.pc, "transition-expansion", "unused or unreachable transfer expansion")
			}
		}
	}
	for _, n := range g.nodes {
		if !m.tick() {
			return nil, m.err
		}
		if n.boundary == boundaryNone && n.count == 0 {
			return nil, refuse(n.pc, "transition-cut", "unclosed prefix path")
		}
	}
	return g, nil
}

func (m *transitionChecker) setStack(p TransitionPointer, value br.Term) {
	m.pointers[RSP], m.state.regs[RSP], m.bound.Preserved[RSP] = p, value, 0
}

func (m *transitionChecker) stackStep(i operation, size uint8) error {
	old := TransitionValue{m.state.regs[RSP], m.pointers[RSP]}
	sp, ok := old.Pointer.(OriginPointer)
	if !ok || sp.Origin != m.bound.Origin {
		return refuse(m.pc, "transition-stack", "stack lacks the root origin")
	}
	if i.Op == x86asm.PUSH || i.Op == x86asm.CALL {
		p, err := m.advance(old.Pointer, -8)
		if err != nil {
			return err
		}
		off, err := m.accessPointer(p, FrameWrite, 8)
		if err != nil {
			return err
		}
		var v TransitionValue
		if i.Op == x86asm.CALL {
			v.Value = m.con(br.Bits(64), m.pc+uint64(size))
			if len(m.frames) >= m.limits.Instructions {
				return refuse(m.pc, "transition-budget", "active frames")
			}
			bytes := (len(m.frames)+1)*128 + len(m.activation) + 17
			if bytes > m.limits.LiveStateBytes-m.liveStateBytes {
				return refuse(m.pc, "transition-budget", "active frame storage")
			}
			if !m.tick() {
				return m.err
			}
			for range len(m.frames) {
				if !m.tick() {
					return m.err
				}
			}
			m.liveStateBytes += bytes
			if err := transitionCopyWork(&m.work, m.limits.Work, len(m.activation)+17); err != nil {
				return err
			}
			m.frames = append(slices.Clone(m.frames), TransitionFrame{Context: callContext(m.activation, m.pc), Call: m.pc, Return: m.pc + uint64(size), Slot: p.(OriginPointer)})
		} else {
			a, _ := fullRegister(i.Args[0])
			v = TransitionValue{m.state.regs[a.reg], m.pointers[a.reg]}
		}
		// PUSH RSP captures the old value before the implicit decrement.
		m.store(off, v, 8)
		m.setStack(p, m.binary(br.Sub, old.Value, m.con(br.Bits(64), 8)))
		return m.err
	}
	kind := FrameRead
	if i.Op == x86asm.RET {
		kind = FrameReturnRead
	}
	off, err := m.accessPointer(sp, kind, 8)
	if err != nil {
		return err
	}
	v := m.load(off, 8, kind)
	p, err := m.advance(sp, 8)
	if err != nil {
		return err
	}
	if i.Op == x86asm.RET {
		target, root, err := m.activeReturn(sp)
		if err != nil {
			return err
		}
		wrong := m.and(m.state.path, m.not(m.compare(br.Equal, v.Value, m.con(br.Bits(64), target))))
		ok, err := m.tryFalse(wrong)
		if err != nil {
			return err
		}
		if !ok {
			return refuse(m.pc, "transition-return", "actual return word does not establish the active continuation")
		}
		if root {
			m.returned = true
		} else {
			m.frames = m.frames[:len(m.frames)-1]
		}
	}
	m.setStack(p, m.binary(br.Add, old.Value, m.con(br.Bits(64), 8)))
	if i.Op == x86asm.POP {
		a, _ := fullRegister(i.Args[0])
		// POP RSP writes its loaded value after the implicit increment.
		m.state.regs[a.reg], m.pointers[a.reg], m.bound.Preserved[a.reg] = v.Value, v.Pointer, 0
	}
	return m.err
}

// Both actual CALL activations and an explicitly supplied incoming callee
// context use the same RET load, target equality and stack increment above.
func (m *transitionChecker) activeReturn(sp OriginPointer) (uint64, bool, error) {
	if len(m.frames) != 0 {
		frame := m.frames[len(m.frames)-1]
		if m.completingReturn || frame.Context != m.activation || frame.Slot != sp {
			return 0, false, refuse(m.pc, "transition-return", "return stack/context differs from actual CALL")
		}
		return frame.Return, false, nil
	}
	if !m.completingReturn || !m.root.region || m.face.ReturnContext == nil || m.activation != "" || sp != (OriginPointer{Origin: m.bound.Origin}) {
		return 0, false, refuse(m.pc, "transition-return", "missing incoming root context or original control slot")
	}
	return m.face.ReturnContext.Target, true, nil
}
