package nativeproof

import br "github.com/greatliontech/gofresh/internal/bitrelation"

// applicationMachineCompatible is the integration point for additional machine
// state (for example vector state). Extra primitive conditions are harmless only
// when they leave the child's admitted transfer semantics unchanged.
func applicationMachineCompatible(parent, child TransitionConditions, thread TransitionThread) bool {
	if thread.ContextChanged {
		return false // no implicit transport across a changed FS/thread context
	}
	if child.CPUID == "" {
		parent.CPUID = ""
	}
	if child.LockedMemory == "" {
		parent.LockedMemory = ""
	}
	if child.Syscall == "" {
		parent.Syscall, parent.UserAddressBits = "", 0
	}
	if child.SSE == "" {
		parent.SSE = ""
	}
	return parent == child
}

func (m *transitionChecker) applicationPremises(child TransitionBound, a *TransitionCallBound) error {
	f := child.Interface
	if !m.tick() {
		return m.err
	}
	if !applicationMachineCompatible(m.face.Conditions, f.Conditions, m.thread) {
		return refuse(m.pc, "transition-application-machine", "callee machine/primitive context does not follow from caller")
	}
	for _, flag := range []TransitionFlag{m.bound.Flags.CF, m.bound.Flags.OF, m.bound.Flags.SF, m.bound.Flags.ZF, m.bound.Flags.AF, m.bound.Flags.PF} {
		if !m.tick() {
			return m.err
		}
		if !flag.Defined {
			return refuse(m.pc, "transition-application-flags", "callee entry requires every arithmetic flag defined")
		}
	}
	for _, predicate := range m.state.flags {
		if !predicate.Valid() {
			return refuse(m.pc, "transition-application-flags", "current predicate is unavailable")
		}
	}
	low, lowOK := relative(m.lo, a.StackShift)
	high, highOK := relative(m.hi, a.StackShift)
	if !lowOK || !highOK || low < f.Origin.Min || high > f.Origin.Max || m.face.Origin.Modulus%f.Origin.Modulus != 0 || (m.face.Origin.Residue+uint64(a.StackShift))&(f.Origin.Modulus-1) != f.Origin.Residue {
		return refuse(m.pc, "transition-application-origin", "shifted universal origin range or congruence does not imply callee domain")
	}
	envelope, err := applicationShift(f.Envelope, a.StackShift)
	if err != nil {
		return err
	}
	if envelope.Start < m.face.Envelope.Start || envelope.End > m.face.Envelope.End {
		return refuse(m.pc, "transition-application-origin", "shifted callee envelope escapes caller envelope")
	}
	// Full containment proves both grants and page-disjointness: each child
	// external extent is a subset of an already excluded parent external extent.
	// Even a region with neither permission still contributes page exclusions.
	for _, r := range f.Regions {
		span, err := applicationShift(r.Bytes, a.StackShift)
		if err != nil {
			return err
		}
		found := false
		for _, parent := range m.face.Regions {
			if !m.tick() {
				return m.err
			}
			if parent.Bytes.Start <= span.Start && span.End <= parent.Bytes.End && (!r.Readable || parent.Readable) && (!r.Writable || parent.Writable) {
				found = true
				break
			}
		}
		if !found {
			return refuse(m.pc, "transition-application-permission", "complete callee region lacks caller mapping and permissions")
		}
	}
	for _, span := range f.ImageRegions {
		found := false
		for _, parent := range m.face.ImageRegions {
			if !m.tick() {
				return m.err
			}
			if parent.Start <= span.Start && span.End <= parent.End {
				found = true
				break
			}
		}
		if !found {
			return refuse(m.pc, "transition-application-permission", "callee image grant lacks the same owned caller mapping")
		}
	}
	if f.PrivateFrame != nil {
		span, err := applicationShift(f.PrivateFrame.Bytes, a.StackShift)
		if err != nil {
			return err
		}
		if m.face.PrivateFrame == nil || span.Start < m.face.PrivateFrame.Bytes.Start || span.End > m.face.PrivateFrame.Bytes.End {
			return refuse(m.pc, "transition-application-private", "callee private lifetime does not follow from retained parent ownership")
		}
	}
	for _, p := range f.EntryImagePointers {
		if !m.tick() {
			return m.err
		}
		actual, ok := m.pointers[p.Register].(ImagePointer)
		if !ok || actual.owner != &m.im.data[0] || actual.Address != p.Address {
			return refuse(m.pc, "transition-application-pointer", "callee entry pointer lacks current owned provenance")
		}
		if err := m.applicationEstablish(m.compare(br.Equal, m.state.regs[p.Register], m.con(br.Bits(64), p.Address))); err != nil {
			return err
		}
	}
	for _, w := range f.EntryWordUpperBounds {
		if !m.tick() {
			return m.err
		}
		offset, ok := signedPlus(a.StackShift, w.OriginOffset)
		if !ok {
			return refuse(m.pc, "transition-application-origin", "guard origin offset overflow")
		}
		word := m.memoryValue(TransitionLocation{Image: true, Offset: int64(w.Address)}, 8)
		upper := m.bound.Origin
		if offset != 0 {
			upper = m.binary(br.Add, upper, m.con(br.Bits(64), uint64(offset)))
		}
		if err := m.applicationEstablish(m.compare(br.ULT, word.Value, upper)); err != nil {
			return err
		}
	}
	control := m.memoryValue(TransitionLocation{Offset: a.StackShift}, 8)
	if err := m.applicationEstablish(m.compare(br.Equal, control.Value, m.con(br.Bits(64), f.ReturnContext.Target))); err != nil {
		return err
	}
	// Associations specialize all arbitrary callee inputs coherently. They keep
	// the caller's original variables, byte sharing, ordered lanes, and primitive
	// outcomes; no child variable is inserted into the native successor state.
	a.Inputs, a.InputPredicates, a.InputFS = child.InitialRegisters, child.InitialPredicates, child.InitialFS
	a.InputDirection, a.Direction = child.InitialDirection, m.direction
	a.Predicates = TransitionPredicates{m.state.flags[flagCarry], m.state.flags[flagZero], m.state.flags[flagLess]}
	a.Flags, a.Thread = m.bound.Flags, m.thread
	a.InputVectors, a.Vectors, a.SSE = child.InitialVectors, m.bound.Vectors, m.bound.SSE
	if f.Conditions.SSE != "" {
		if !a.SSE.MXCSRPreserved || !a.SSE.UpperVectorsPreserved {
			return refuse(m.pc, "transition-application-machine", "callee SSE context lacks checked preservation")
		}
		for _, vector := range a.Vectors {
			if !m.tick() {
				return m.err
			}
			if !vector.Lo.Valid() || !vector.Hi.Valid() {
				return refuse(m.pc, "transition-application-machine", "callee SSE inputs lack current vector values")
			}
		}
	}
	for r := range a.Registers {
		if !m.tick() {
			return m.err
		}
		a.Registers[r] = TransitionValue{Value: m.state.regs[r], Pointer: m.pointers[r]}
	}
	for _, input := range child.InitialMemory {
		if !m.tick() {
			return m.err
		}
		key := input.TransitionLocation
		if !key.Image {
			var ok bool
			key.Offset, ok = signedPlus(key.Offset, a.StackShift)
			if !ok {
				return refuse(m.pc, "transition-application-origin", "entry byte offset overflow")
			}
		}
		current, ok := m.memory[key]
		if !ok {
			return refuse(m.pc, "transition-application-memory", "callee input byte has no current parent byte")
		}
		a.Memory = append(a.Memory, TransitionCallByte{Input: input, Current: current})
	}
	for _, word := range child.Words {
		if !m.tick() {
			return m.err
		}
		offset, ok := signedPlus(word.Offset, a.StackShift)
		if !ok {
			return refuse(m.pc, "transition-application-origin", "entry word offset overflow")
		}
		a.Words = append(a.Words, TransitionCallWord{Input: word, Current: m.memoryValue(TransitionLocation{Offset: offset}, 8)})
	}
	return m.err
}

func applicationShift(span RelativeSpan, shift int64) (RelativeSpan, error) {
	start, a := signedPlus(span.Start, shift)
	end, b := signedPlus(span.End, shift)
	if !a || !b {
		return RelativeSpan{}, refuse(0, "transition-application-origin", "shifted callee extent overflows")
	}
	return RelativeSpan{Start: start, End: end}, nil
}

func (m *transitionChecker) applicationEstablish(predicate br.Term) error {
	if m.err != nil {
		return m.err
	}
	proved, err := m.tryFalse(m.and(m.state.path, m.not(predicate)))
	if err != nil {
		return err
	}
	if !proved {
		return refuse(m.pc, "transition-application-premise", "callee entry relation does not follow from current caller state")
	}
	return m.err
}
