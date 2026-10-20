package nativeproof

import (
	"context"
	"unsafe"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// TransitionReturnContext declares an incoming conditional callee continuation,
// not an executed CALL. Target is decoded independently in the root's owned
// executable image; it asserts no reachability from an actual caller. The entry
// control word at original RSP contains Target and is protected against all
// writes. Preserved lists distinct full GPRs other than RSP whose original bits
// and provenance must be restored. RSP must return from its original slot and
// advances by eight. Unlisted registers retain their ordinary derived relations.
type TransitionReturnContext struct {
	Target    uint64
	Preserved []Register
}

// NativeReturnedState is the derived terminal state after the actual root RET.
// CalleeTerminated discharges the incoming callee context; it is not an inside-
// callee cut and cannot be passed to CheckTransitionContinuation. PC identifies
// the checked incoming continuation, whose instruction has not executed here.
// Restored records checked full-value AND provenance restoration, independently
// of Preserved's never-written masks. Memory retains residual callee writes.
type NativeReturnedState struct {
	PC               uint64
	CalleeTerminated bool
	Registers        [16]TransitionValue
	Memory           []TransitionByte
	Preserved        Masks
	Restored         []Register
	Flags            TransitionFlags
	// Direction is the actual post-RET DF, not an implicitly restored entry value.
	Direction br.Term
	Thread    TransitionThread
	Vectors   TransitionVectors
	SSE       TransitionSSEContext
}

// TransitionReturnBound is a non-authorizing projection of a complete return
// theorem. Prefix retains the original entry, interface, EntryPredicate, inputs,
// dependencies, excluded boundaries and the state BEFORE RET. Instructions and
// Accesses are the complete cumulative traces INCLUDING RET and its final
// control-slot read. Primitive effects are exactly Prefix.PrimitiveEffects.
// State is the actual post-RET state. Continuation is decoded but unexecuted.
type TransitionReturnBound struct {
	Prefix       TransitionBound
	Instructions []GuardedInstruction
	Accesses     []TransitionAccess
	State        NativeReturnedState
	Continuation TransitionReturnBoundary
}

// TransitionReturnBoundary is the structurally decoded incoming continuation
// interface. It lies outside the completed callee's occurrence DAG: it is neither
// an executed instruction nor another callee cut and carries no occurrence ID.
type TransitionReturnBoundary struct {
	PC          uint64
	Instruction x86asm.Inst
	Bytes       []byte
}

// TransitionReturnCertificate owns a checked conditional terminal relation. Its
// zero value grants no authority and projections cannot construct it. It grants
// no source equivalence, historical execution or ordinary runtime applicability.
type TransitionReturnCertificate struct{ checked *checkedTransitionReturn }

type checkedTransitionReturn struct {
	prefix       TransitionCertificate
	state        NativeReturnedState
	instruction  GuardedInstruction
	access       TransitionAccess
	continuation TransitionReturnBoundary
	proofs       []br.Witness
	work         int
}

// Bound returns owned mutable projections and immutable relation handles.
func (c TransitionReturnCertificate) Bound() (TransitionReturnBound, bool) {
	if c.checked == nil {
		return TransitionReturnBound{}, false
	}
	r := c.checked
	prefix, _ := r.prefix.Bound()
	state := r.state
	state.Memory = append([]TransitionByte(nil), state.Memory...)
	state.Restored = append([]Register(nil), state.Restored...)
	target := r.continuation
	target.Bytes = append([]byte(nil), target.Bytes...)
	return TransitionReturnBound{
		Prefix: prefix, State: state, Continuation: target,
		Instructions: append(append([]GuardedInstruction(nil), prefix.Instructions...), r.instruction),
		Accesses:     append(append([]TransitionAccess(nil), prefix.Accesses...), r.access),
	}, true
}

// BoundFor projects only a return theorem over this exact immutable image owner.
func (c TransitionReturnCertificate) BoundFor(im *Image) (TransitionReturnBound, bool) {
	if c.checked == nil || !sameImage(c.checked.prefix.checked.image, im) {
		return TransitionReturnBound{}, false
	}
	return c.Bound()
}

// Prefix returns the immutable entry-to-before-RET theorem, not a continuation
// from the returned state. It permits inspection of prior instruction effects.
func (c TransitionReturnCertificate) Prefix() (TransitionCertificate, bool) {
	if c.checked == nil {
		return TransitionCertificate{}, false
	}
	return c.checked.prefix, true
}

// RegisterValue projects an actual integer alias in the post-RET state.
func (c TransitionReturnCertificate) RegisterValue(ctx context.Context, reg x86asm.Reg) (br.Term, error) {
	if ctx == nil || c.checked == nil {
		return br.Term{}, refuse(0, "transition-inspection", "missing context or checked return")
	}
	if err := ctx.Err(); err != nil {
		return br.Term{}, err
	}
	return projectTransitionRegister(ctx, c.checked.state.Registers, reg)
}

// InstructionAt decodes an executed occurrence, including the terminal RET.
// The unexecuted continuation contributes no new instruction occurrence.
func (c TransitionReturnCertificate) InstructionAt(ctx context.Context, id TransitionOccurrenceID) (x86asm.Inst, error) {
	if ctx == nil || c.checked == nil {
		return x86asm.Inst{}, refuse(0, "transition-inspection", "missing context or checked return")
	}
	if err := ctx.Err(); err != nil {
		return x86asm.Inst{}, err
	}
	if id == c.checked.instruction.ID {
		return c.checked.prefix.checked.bound.Boundary.Instruction, nil
	}
	return c.checked.prefix.InstructionAt(ctx, id)
}

// EntryValueRegister identifies this certificate's private caller-value lineage.
// It is a substitution coordinate for an independently established caller value
// and provenance, never an address, alias exclusion or new permission.
func (c TransitionCertificate) EntryValueRegister(p TransitionPointer) (Register, bool) {
	v, ok := p.(entryValueLineage)
	if !ok || c.checked == nil || c.checked.bound.Interface.ReturnContext == nil {
		return 0, false
	}
	for _, r := range c.checked.bound.Interface.ReturnContext.Preserved {
		if v.value == c.checked.bound.InitialRegisters[r] {
			return r, true
		}
	}
	return 0, false
}

// CheckTransitionReturn completes an opaque conditional prefix whose common cut
// is the actual root RET. It inherits the entire root resource account, consumes
// no new premises and executes the shared RET transfer without fabricating CALL
// history. Only the distinct terminal certificate is published on success.
func CheckTransitionReturn(ctx context.Context, prefix TransitionCertificate) (TransitionReturnCertificate, error) {
	if prefix.checked == nil {
		return TransitionReturnCertificate{}, refuse(0, "transition-return", "missing checked prefix")
	}
	prior := *prefix.checked
	b := prior.bound
	if b.Rules != TransitionRules || !b.ConditionalRegion || b.Interface.ReturnContext == nil {
		return TransitionReturnCertificate{}, refuse(b.Boundary.PC, "transition-return", "conditional incoming return context is required")
	}
	if len(b.Frames) != 0 || b.Boundary.Context != 0 {
		return TransitionReturnCertificate{}, refuse(b.Boundary.PC, "transition-return", "root return cannot consume an active child context")
	}
	m, err := newTransitionChecker(ctx, prior.image, transitionRoot{entry: b.Entry, region: true}, prior.limits, prior.work)
	if err != nil {
		return TransitionReturnCertificate{}, err
	}
	if err := m.inherit(prior); err != nil {
		return TransitionReturnCertificate{}, err
	}
	m.pc, m.activation, m.occurrence = b.Boundary.PC, 0, b.Boundary.ID
	i, raw, err := transitionEncoding(m.im, m.pc)
	if err != nil {
		return TransitionReturnCertificate{}, err
	}
	if i.Op != x86asm.RET {
		return TransitionReturnCertificate{}, refuse(m.pc, "transition-return", "common cut is not RET")
	}
	if err := validateTransitionForm(m.pc, i, raw); err != nil {
		return TransitionReturnCertificate{}, err
	}
	for _, r := range m.face.ReturnContext.Preserved {
		if !m.tick() {
			return TransitionReturnCertificate{}, m.err
		}
		want, err := m.entryRegisterProvenance(r)
		if err != nil {
			return TransitionReturnCertificate{}, err
		}
		// The closed provenance invariant establishes both bits and provenance:
		// an image/stack arm agrees with its exact scalar address, and a lineage
		// arm means the complete original caller word. Copies and ordered lanes
		// preserve that invariant; numerical coincidence cannot reconstruct it.
		// In particular, a saved/restored register need not have an unwritten bit.
		if m.pointers[r] != want {
			return TransitionReturnCertificate{}, refuse(m.pc, "transition-return-preserved", "required original register value/provenance was not restored")
		}
	}
	target, err := m.returnContinuation()
	if err != nil {
		return TransitionReturnCertificate{}, err
	}
	// Include the complete architectural projection, including modeled vectors,
	// beside conservative allocation slack and the terminal metadata containers.
	terminalBytes := 1024 + int(unsafe.Sizeof(NativeReturnedState{}))
	if terminalBytes > m.limits.LiveStateBytes-m.liveStateBytes {
		return TransitionReturnCertificate{}, refuse(m.pc, "transition-budget", "terminal return state")
	}
	m.liveStateBytes += terminalBytes
	m.completingReturn = true
	if err := m.stackStep(operation{Op: x86asm.RET}, uint8(i.Len)); err != nil {
		return TransitionReturnCertificate{}, err
	}
	state := NativeReturnedState{PC: target.PC, CalleeTerminated: m.returned, Memory: prior.bound.Memory, Flags: m.bound.Flags, Direction: m.direction, Preserved: m.bound.Preserved, Thread: m.thread, Vectors: m.vectors, SSE: m.bound.SSE}
	for r := range state.Registers {
		if !m.tick() {
			return TransitionReturnCertificate{}, m.err
		}
		state.Registers[r] = TransitionValue{Value: m.state.regs[r], Pointer: m.pointers[r]}
	}
	state.Restored = append([]Register(nil), m.face.ReturnContext.Preserved...)
	if !m.tick() {
		return TransitionReturnCertificate{}, m.err
	}
	return TransitionReturnCertificate{&checkedTransitionReturn{
		prefix: prefix, state: state, continuation: target, work: m.work,
		instruction: GuardedInstruction{ID: b.Boundary.ID, Span: Span{m.pc, m.pc + uint64(i.Len)}, Guard: b.CutGuard},
		access:      m.bound.Accesses[len(m.bound.Accesses)-1],
		proofs:      append([]br.Witness(nil), m.justifications[len(prior.justifications):]...),
	}}, nil
}

func returnContextBytes(c *TransitionReturnContext) int {
	return 256 + 64*len(c.Preserved)
}

func (m *transitionChecker) reserveReturnContext() error {
	if m.face.ReturnContext == nil {
		return nil
	}
	bytes := returnContextBytes(m.face.ReturnContext)
	if bytes > m.limits.LiveStateBytes-m.liveStateBytes {
		return refuse(m.pc, "transition-budget", "incoming return context storage")
	}
	m.liveStateBytes += bytes
	return nil
}

func (m *transitionChecker) validateReturnContext() error {
	c := m.face.ReturnContext
	if c == nil {
		return m.err
	}
	if !m.root.region {
		return refuse(m.pc, "transition-return", "incoming callee context requires a conditional-region root")
	}
	if err := m.reserveReturnContext(); err != nil {
		return err
	}
	if err := m.offset(8); err != nil {
		return err
	}
	if !m.permission(RelativeSpan{0, 8}, FrameReturnRead) {
		if m.err != nil {
			return m.err
		}
		return refuse(m.pc, "transition-return", "incoming control slot lacks eight readable bytes")
	}
	for _, w := range m.face.Words {
		if !m.tick() {
			return m.err
		}
		if w < 8 && w+8 > 0 {
			return refuse(m.pc, "transition-return", "arbitrary input word overlaps fixed incoming control bytes")
		}
	}
	var seen [16]bool
	for _, r := range c.Preserved {
		if !m.tick() {
			return m.err
		}
		if r > R15 || r == RSP || seen[r] {
			return refuse(m.pc, "transition-return", "preserved context requires distinct full GPRs other than RSP")
		}
		seen[r] = true
	}
	_, err := m.returnContinuation()
	return err
}

func (m *transitionChecker) returnContinuation() (TransitionReturnBoundary, error) {
	if !m.tick() {
		return TransitionReturnBoundary{}, m.err
	}
	pc := m.face.ReturnContext.Target
	i, raw, err := decodeBytes(m.im, pc)
	if err != nil {
		return TransitionReturnBoundary{}, err
	}
	return TransitionReturnBoundary{PC: pc, Instruction: i, Bytes: append([]byte(nil), raw...)}, nil
}

// A conditional continuation is a separately decoded entry, not caller history.
// Its decode must agree with every overlapping instruction already established
// by the callee's independently reconstructed coverage, including exclusions.
func (m *transitionChecker) validateReturnTargetGraph(g *graph) error {
	if m.face.ReturnContext == nil {
		return nil
	}
	return m.validateDecodedBoundaryGraph(g, m.face.ReturnContext.Target, "transition-return", "continuation conflicts with an established instruction boundary")
}

// Separately declared boundaries use the same image-wide occupancy rule as
// incoming continuations: any overlap must be the exact established instruction.
func (m *transitionChecker) validateDecodedBoundaryGraph(g *graph, pc uint64, premise, detail string) error {
	if !m.tick() {
		return m.err
	}
	_, raw, err := decodeBytes(m.im, pc)
	if err != nil {
		return err
	}
	span := Span{pc, pc + uint64(len(raw))}
	for _, n := range g.nodes {
		if !m.tick() {
			return m.err
		}
		instruction := Span{n.pc, n.pc + uint64(n.size)}
		if overlap(span, instruction) && span != instruction {
			return refuse(pc, premise, detail)
		}
	}
	return nil
}

func (m *transitionChecker) entryRegisterProvenance(r Register) (TransitionPointer, error) {
	for _, p := range m.face.EntryImagePointers {
		if !m.tick() {
			return nil, m.err
		}
		if p.Register == r {
			load, err := m.imageLoad(Span{p.Address, p.Address + 1}, false)
			if err != nil {
				return nil, err
			}
			return m.bound.Geometry.imagePointer(load, p.Address), nil
		}
	}
	return entryValueLineage{value: m.bound.InitialRegisters[r]}, nil
}

func (m *transitionChecker) initialReturnContext() error {
	if m.face.ReturnContext == nil {
		return m.err
	}
	// The control word is an explicit incoming relation, not a CALL write or
	// image-loading fact. Validation excluded overlapping arbitrary word inputs.
	for lane := int64(0); lane < 8; lane++ {
		key := m.bound.Geometry.stackLocation(lane)
		if !m.tick() {
			return m.err
		}
		value := byte(m.face.ReturnContext.Target >> (8 * uint(lane)))
		m.memory[key] = TransitionByte{TransitionLocation: key, Value: m.con(br.Bits(8), uint64(value))}
	}
	for _, r := range m.face.ReturnContext.Preserved {
		p, err := m.entryRegisterProvenance(r)
		if err != nil {
			return err
		}
		m.pointers[r] = p
	}
	return m.err
}
