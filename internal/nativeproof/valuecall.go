package nativeproof

import (
	"context"
	"fmt"
	"slices"
	"unsafe"

	"golang.org/x/arch/x86/x86asm"
)

type valueCallState struct {
	scalar               state
	xmm                  [16][16]value
	flagKnown, flagValue uint8
	memory               []value
	written              []bool
	inside               bool
	callPC, callerSP     uint64
}
type valueCallNode struct {
	pc    uint64
	path  []uint64
	state *valueCallState
}
type valueCallChecker struct {
	*frameChecker
	request   ValueCallRequest
	bound     ValueCallBound
	allocated uint64
	states    int
	starts    map[uint64]bool
	occupied  map[uint64]uint64
	calleePC  map[uint64]bool
	returned  bool
}

// CheckValueCall checks one complete, actual direct call and its preceding
// marshaling fragment. It independently decodes feasible control flow, interpreting
// known bits and immutable byte values. Unknown defined branches are both checked;
// a proved predicate alone can exclude an edge. Reachable cycles and nested calls
// refuse. Limits use FrameLimits plus fixed bounded scalar/XMM domains; there is
// no expression graph, recursive execution or unbounded path unrolling.
func CheckValueCall(ctx context.Context, im *Image, request ValueCallRequest, limits FrameLimits) (ValueCall, error) {
	im = im.snapshot()
	l, err := frameLimits(limits)
	if err != nil {
		return ValueCall{}, refuse(request.Entry, "value-budget", err.Error())
	}
	f := request.Interface
	if len(f.Regions) > l.Regions || len(f.Protected) > l.Regions || len(f.Readonly) > l.Regions || len(f.Results) > l.Regions || len(f.Pointers) > 15 || len(f.Scalars) > 1024 || len(f.StackValues) > l.RegionBytes || len(f.MemoryPointers) > l.RegionBytes/8 {
		return ValueCall{}, refuse(request.Entry, "value-budget", "input inventory exceeds limits")
	}
	request.Interface = cloneValueCallInterface(f)
	f = request.Interface
	if ctx == nil {
		return ValueCall{}, refuse(request.Entry, "value-context", "missing context")
	}
	if err := ctx.Err(); err != nil {
		return ValueCall{}, err
	}
	if im == nil || len(im.data) == 0 {
		return ValueCall{}, refuse(request.Entry, "image-binding", "missing image")
	}
	c := f.Conditions
	if c.Machine != ValueCallMachine || !c.ImageBytesMapped {
		return ValueCall{}, refuse(request.Entry, "value-premises", "enabled SSE2 and immutable loaded-byte premises are required")
	}
	frame := FrameInterface{Regions: f.Regions, Pointers: f.Pointers, MemoryPointers: f.MemoryPointers, Stack: f.Stack, Protected: f.Protected, Preserved: f.Preserved,
		Conditions: FrameConditions{Conditions: Conditions{Machine: MachineModel, InstructionMapping: c.InstructionMapping, EntryInputs: c.EntryState, IsolatedInvocation: c.IsolatedInvocation}, MemoryMapping: c.MemoryMapping, NoHiddenAliases: c.NoHiddenAliases, UnalignedAccess: c.UnalignedAccess}}
	m := &valueCallChecker{frameChecker: &frameChecker{Context: ctx, im: im, face: frame, limits: l, pc: request.Entry}, request: request, starts: map[uint64]bool{}, occupied: map[uint64]uint64{}, calleePC: map[uint64]bool{}}
	if err := m.validateEntry(false); err != nil {
		return ValueCall{}, err
	}
	m.bound = ValueCallBound{ImageDigest: im.digest, Rules: ValueCallRules, Request: request}
	s, err := m.initialValues()
	if err != nil {
		return ValueCall{}, err
	}
	queue := []valueCallNode{{pc: request.Entry, state: s}}
	for len(queue) > 0 {
		n := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for {
			m.pc = n.pc
			if err := m.tick(1); err != nil {
				return ValueCall{}, err
			}
			m.states++
			if m.states > l.States {
				return ValueCall{}, refuse(n.pc, "value-budget", "state/path budget")
			}
			if slices.Contains(n.path, n.pc) {
				return ValueCall{}, m.failure(n, refuse(n.pc, "acyclic-control", "reachable cycle is unsupported"))
			}
			if err := m.charge(uint64(len(n.path)+1) * 8); err != nil {
				return ValueCall{}, err
			}
			if err := m.tick(len(n.path) + 1); err != nil {
				return ValueCall{}, err
			}
			path := make([]uint64, len(n.path)+1)
			copy(path, n.path)
			path[len(n.path)] = n.pc
			n.path = path
			i, b, err := decodeValueCall(im, n.pc)
			if err != nil {
				return ValueCall{}, m.failure(n, err)
			}
			if err := m.record(n, i, b); err != nil {
				return ValueCall{}, m.failure(n, err)
			}
			next := n.pc + uint64(i.Len)
			if i.Op == x86asm.CALL {
				if err := m.call(n, i, b, next); err != nil {
					return ValueCall{}, m.failure(n, err)
				}
				n.pc = request.Target
				continue
			}
			if i.Op == x86asm.RET {
				if _, err := decodeControl(n.pc, i, b); err != nil {
					return ValueCall{}, m.failure(n, err)
				}
				if err := m.finish(n); err != nil {
					return ValueCall{}, m.failure(n, err)
				}
				break
			}
			if i.Op == x86asm.JMP || condition(i.Op) != 0 {
				if _, branch := i.Args[0].(x86asm.Rel); branch {
					d, err := decodeControl(n.pc, i, b)
					if err != nil {
						return ValueCall{}, m.failure(n, err)
					}
					targets := append([]uint64(nil), d.targets[:d.count]...)
					if i.Op != x86asm.JMP {
						known, taken, err := valuePredicate(i.Op, n.state)
						if err != nil {
							return ValueCall{}, m.failure(n, refuse(n.pc, "value-flags", err.Error()))
						}
						if known {
							if taken {
								targets = targets[1:]
							} else {
								targets = targets[:1]
							}
						}
					}
					m.bound.Branches = append(m.bound.Branches, BranchEvidence{n.pc, append([]uint64(nil), targets...)})
					if len(targets) == 2 {
						other, err := m.cloneState(n.state)
						if err != nil {
							return ValueCall{}, err
						}
						queue = append(queue, valueCallNode{pc: targets[1], path: n.path, state: other})
					}
					n.pc = targets[0]
					continue
				}
			}
			if err := m.step(i, b, n.state); err != nil {
				return ValueCall{}, m.failure(n, err)
			}
			n.pc = next
		}
	}
	if !m.returned {
		return ValueCall{}, refuse(request.Entry, "value-return", "no checked call return")
	}
	m.bound.Accesses = append([]FrameAccess(nil), m.accesses...)
	if err := m.tick(1); err != nil {
		return ValueCall{}, err
	}
	return ValueCall{&checkedValueCall{im, m.bound}}, nil
}

func (m *valueCallChecker) failure(n valueCallNode, err error) error {
	if r, ok := err.(*Refusal); ok {
		r.Path = append([]uint64(nil), n.path...)
		if len(r.Path) == 0 || r.Path[len(r.Path)-1] != r.PC {
			r.Path = append(r.Path, r.PC)
		}
	}
	return err
}
func (m *valueCallChecker) charge(n uint64) error {
	if n > uint64(m.limits.StateBytes)-m.allocated {
		return refuse(m.pc, "value-budget", "state/retained-byte allocation budget")
	}
	m.allocated += n
	return nil
}
func (m *valueCallChecker) cloneState(s *valueCallState) (*valueCallState, error) {
	n := uint64(unsafe.Sizeof(valueCallState{})) + uint64(m.cells)*(uint64(unsafe.Sizeof(value{}))+1)
	if err := m.charge(n); err != nil {
		return nil, err
	}
	if err := m.tick(m.cells + 256); err != nil {
		return nil, err
	}
	copy := *s
	copy.memory = append([]value(nil), s.memory...)
	copy.written = append([]bool(nil), s.written...)
	return &copy, nil
}

func (m *valueCallChecker) initialValues() (*valueCallState, error) {
	f := m.request.Interface
	if len(f.Results) == 0 {
		return nil, refuse(m.pc, "value-results", "no memory result projection")
	}
	if err := m.charge(uint64(unsafe.Sizeof(valueCallState{})) + uint64(m.cells)*(uint64(unsafe.Sizeof(value{}))+1)); err != nil {
		return nil, err
	}
	if err := m.tick(m.cells + 256); err != nil {
		return nil, err
	}
	s := &valueCallState{memory: make([]value, m.cells), written: make([]bool, m.cells)}
	for r := range s.scalar.regs {
		s.scalar.regs[r].defined = ^uint64(0)
	}
	s.scalar.flags = cf | zf | sf | of | pf
	for r := range s.xmm {
		for j := range s.xmm[r] {
			s.xmm[r][j].defined = 0xff
		}
	}
	for j := range s.memory {
		s.memory[j].defined = 0xff
	}
	for _, p := range f.Pointers {
		if p.Pointer.Min != p.Pointer.Max {
			return nil, refuse(m.pc, "value-input", "ranged entry pointer is unsupported")
		}
		s.scalar.regs[p.Register] = constant(f.Regions[p.Pointer.Region].Bytes.Start+p.Pointer.Min, 64)
	}
	s.scalar.regs[RSP] = constant(f.Regions[f.Stack.Region].Bytes.Start+f.Stack.Min, 64)
	var seen Masks
	for _, v := range f.Scalars {
		if err := m.tick(1); err != nil {
			return nil, err
		}
		if v.Register > R15 || v.Register == RSP || v.Bits == 0 || v.Value&^v.Bits != 0 || seen[v.Register]&v.Bits != 0 {
			return nil, refuse(m.pc, "value-input", "invalid/overlapping scalar premise")
		}
		old := s.scalar.regs[v.Register]
		if (old.zero&v.Value|old.one&^v.Value)&v.Bits != 0 {
			return nil, refuse(m.pc, "value-input", "scalar premise contradicts pointer origin")
		}
		seen[v.Register] |= v.Bits
		old.zero |= v.Bits &^ v.Value
		old.one |= v.Value
		s.scalar.regs[v.Register] = old
	}
	for j, result := range f.Results {
		width := result.End - result.Start
		if result.Start >= result.End || width != 1 && width != 2 && width != 4 && width != 8 {
			return nil, refuse(m.pc, "value-results", "invalid result width")
		}
		region, err := m.regionAt(result, true)
		if err != nil {
			return nil, err
		}
		if region != f.Stack.Region {
			return nil, refuse(m.pc, "value-results", "results must lie in the declared external stack region")
		}
		for _, old := range f.Results[:j] {
			if err := m.tick(1); err != nil {
				return nil, err
			}
			if overlap(result, old) {
				return nil, refuse(m.pc, "value-results", "overlapping results")
			}
		}
		for _, protected := range f.Protected {
			if overlap(result, protected) {
				return nil, refuse(m.pc, "value-results", "result overlaps protected context")
			}
		}
	}
	for _, p := range f.MemoryPointers {
		if p.Pointer.Min != p.Pointer.Max {
			return nil, refuse(m.pc, "value-input", "ranged memory pointer is unsupported")
		}
		span := Span{p.Address, p.Address + 8}
		if err := m.notResult(span); err != nil {
			return nil, err
		}
		m.seed(s, span, constant(f.Regions[p.Pointer.Region].Bytes.Start+p.Pointer.Min, 64))
	}
	for j, v := range f.StackValues {
		if err := m.tick(1); err != nil {
			return nil, err
		}
		if v.Width != 1 && v.Width != 2 && v.Width != 4 && v.Width != 8 || v.Value&^mask(v.Width*8) != 0 {
			return nil, refuse(m.pc, "value-input", "invalid stack constant width/value")
		}
		end, ok := plus(v.Address, uint64(v.Width))
		if !ok {
			return nil, refuse(m.pc, "value-input", "stack constant overflow")
		}
		span := Span{v.Address, end}
		region, err := m.regionAt(span, false)
		if err != nil {
			return nil, err
		}
		if region != f.Stack.Region {
			return nil, refuse(m.pc, "value-input", "constant is outside the external stack")
		}
		if err := m.notResult(span); err != nil {
			return nil, err
		}
		for _, old := range f.StackValues[:j] {
			if err := m.tick(1); err != nil {
				return nil, err
			}
			if overlap(span, Span{old.Address, old.Address + uint64(old.Width)}) {
				return nil, refuse(m.pc, "value-input", "overlapping stack values")
			}
		}
		for _, p := range f.MemoryPointers {
			if overlap(span, Span{p.Address, p.Address + 8}) {
				return nil, refuse(m.pc, "value-input", "constant overlaps a pointer premise")
			}
		}
		m.seed(s, span, constant(v.Value, v.Width*8))
	}
	var total uint64
	for _, span := range f.Readonly {
		if span.Start >= span.End || span.End-span.Start > uint64(m.limits.RegionBytes)-total {
			return nil, refuse(m.pc, "value-budget", "readonly byte inventory")
		}
		total += span.End - span.Start
		region, err := m.regionAt(span, false)
		if err != nil {
			return nil, err
		}
		if !f.Regions[region].Image || f.Regions[region].Writable {
			return nil, refuse(m.pc, "value-memory", "value span must be declared readonly image memory")
		}
		data, _, err := m.im.readonlyBytes(span.Start, span.End-span.Start, "value-memory", "value-alias")
		if err != nil {
			return nil, err
		}
		if err := m.tick(len(data)); err != nil {
			return nil, err
		}
		at := m.cell(span.Start)
		for j, v := range data {
			s.memory[at+j] = constant(uint64(v), 8)
		}
	}
	return s, nil
}

func (m *valueCallChecker) notResult(span Span) error {
	for _, r := range m.request.Interface.Results {
		if overlap(span, r) {
			return refuse(m.pc, "value-input", "initial value overlaps a derived output")
		}
	}
	return nil
}
func (m *valueCallChecker) seed(s *valueCallState, span Span, v value) {
	at := m.cell(span.Start)
	for j := 0; j < int(span.End-span.Start); j++ {
		s.memory[at+j] = value{v.defined >> uint(8*j) & 0xff, v.zero >> uint(8*j) & 0xff, v.one >> uint(8*j) & 0xff}
	}
}

func (m *valueCallChecker) record(n valueCallNode, i x86asm.Inst, b []byte) error {
	if old, exists := m.calleePC[n.pc]; exists && old != n.state.inside {
		return refuse(n.pc, "instruction-overlap", "caller and callee scopes overlap")
	}
	if !m.starts[n.pc] {
		if len(m.starts) >= m.limits.Instructions {
			return refuse(n.pc, "value-budget", "instruction budget")
		}
		for j := 0; j < i.Len; j++ {
			if owner, used := m.occupied[n.pc+uint64(j)]; used && owner != n.pc {
				return refuse(n.pc, "instruction-overlap", "incompatible instruction boundaries")
			}
		}
		if err := m.charge(uint64(i.Len) + uint64(unsafe.Sizeof(InstructionBytes{}))); err != nil {
			return err
		}
		for j := 0; j < i.Len; j++ {
			m.occupied[n.pc+uint64(j)] = n.pc
		}
		m.starts[n.pc] = true
		m.calleePC[n.pc] = n.state.inside
		m.bound.Instructions = append(m.bound.Instructions, InstructionBytes{Span{n.pc, n.pc + uint64(i.Len)}, append([]byte(nil), b...)})
	}
	return nil
}

func (m *valueCallChecker) call(n valueCallNode, i x86asm.Inst, b []byte, next uint64) error {
	s := n.state
	if s.inside {
		return refuse(n.pc, "value-call", "nested or recursive call is unsupported")
	}
	rel, ok := i.Args[0].(x86asm.Rel)
	target, valid := relative(next, int64(rel))
	if !ok || !valid || len(b) != 5 || b[0] != 0xe8 || i.Args[1] != nil || target != m.request.Target {
		return refuse(n.pc, "value-call", "actual direct target differs")
	}
	if next != m.request.Continuation {
		return refuse(n.pc, "value-call", "actual immediate continuation differs")
	}
	sp, ok := knownValue(s.scalar.regs[RSP], 64)
	if !ok || sp < 8 {
		return refuse(n.pc, "value-call", "CALL stack pointer is unavailable or wraps")
	}
	stack := m.face.Regions[m.face.Stack.Region].Bytes
	if sp-8 < stack.Start || sp > stack.End {
		return refuse(n.pc, "value-call", "CALL push escapes the declared stack region")
	}
	for _, result := range m.request.Interface.Results {
		if overlap(result, Span{sp - 8, sp}) {
			return refuse(n.pc, "value-call", "result overlaps the CALL return slot")
		}
	}
	if err := m.writeMemory(s, sp-8, 8, constant(next, 64)); err != nil {
		return err
	}
	s.inside = true
	s.callPC = n.pc
	s.callerSP = sp
	s.scalar.regs[RSP] = constant(sp-8, 64)
	m.bound.RegisterWrites[RSP] = ^uint64(0)
	return nil
}

func (m *valueCallChecker) finish(n valueCallNode) error {
	s := n.state
	if !s.inside {
		return refuse(n.pc, "value-return", "RET reached without the actual CALL")
	}
	sp, ok := knownValue(s.scalar.regs[RSP], 64)
	if !ok || sp != s.callerSP-8 {
		return refuse(n.pc, "value-return", "callee stack pointer does not address its CALL slot")
	}
	ret, err := m.readMemory(s, sp, 8, FrameReturnRead)
	if err != nil {
		return err
	}
	address, known := knownValue(ret, 64)
	if !known || address != m.request.Continuation {
		return refuse(n.pc, "value-return", "return control value differs")
	}
	var results []MemoryResult
	for _, r := range m.request.Interface.Results {
		if err := m.tick(int(r.End-r.Start) + 1); err != nil {
			return err
		}
		at := m.cell(r.Start)
		var v uint64
		for lane := 0; lane < int(r.End-r.Start); lane++ {
			b, ok := knownValue(s.memory[at+lane], 8)
			if !ok || !s.written[at+lane] {
				return refuse(n.pc, "value-result", "callee has not written a complete known output")
			}
			v |= b << uint(8*lane)
		}
		results = append(results, MemoryResult{r, v})
	}
	if m.returned {
		if !slices.Equal(results, m.bound.Results) || m.bound.Call != s.callPC || m.bound.ReturnedRSP != s.callerSP {
			return refuse(n.pc, "value-result", "terminal paths do not establish one result/interface")
		}
	} else {
		m.bound.Results = results
		m.bound.Call = s.callPC
		m.bound.CalleeEntryRSP = sp
		m.bound.ReturnedRSP = s.callerSP
	}
	i, b, err := decodeValueCall(m.im, address)
	if err != nil {
		return err
	}
	span := Span{address, address + uint64(i.Len)}
	for off := span.Start; off < span.End; off++ {
		if _, used := m.occupied[off]; used {
			return refuse(address, "instruction-overlap", "continuation overlaps executed caller/callee bytes")
		}
	}
	m.bound.Continuation = InstructionBytes{span, append([]byte(nil), b...)}
	m.returned = true
	return nil
}

func knownValue(v value, width int) (uint64, bool) {
	mask := mask(width)
	return v.one & mask, (v.zero|v.one)&mask == mask && v.zero&v.one&mask == 0
}

func valuePredicate(op x86asm.Op, s *valueCallState) (bool, bool, error) {
	need := condition(op)
	if need == 0 || s.scalar.flags&need != need {
		return false, false, fmt.Errorf("condition consumes architecturally undefined flags")
	}
	if s.flagKnown&need != need {
		return false, false, nil
	}
	c, z, sign, o := s.flagValue&cf != 0, s.flagValue&zf != 0, s.flagValue&sf != 0, s.flagValue&of != 0
	switch op {
	case x86asm.JA, x86asm.SETA:
		return true, !c && !z, nil
	case x86asm.JAE, x86asm.SETAE:
		return true, !c, nil
	case x86asm.JB, x86asm.SETB:
		return true, c, nil
	case x86asm.JBE, x86asm.SETBE:
		return true, c || z, nil
	case x86asm.JE, x86asm.SETE:
		return true, z, nil
	case x86asm.JNE, x86asm.SETNE:
		return true, !z, nil
	case x86asm.JL, x86asm.SETL:
		return true, sign != o, nil
	case x86asm.JLE, x86asm.SETLE:
		return true, z || sign != o, nil
	case x86asm.JG, x86asm.SETG:
		return true, !z && sign == o, nil
	case x86asm.JGE, x86asm.SETGE:
		return true, sign == o, nil
	}
	return false, false, fmt.Errorf("unsupported condition")
}
