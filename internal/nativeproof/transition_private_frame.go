package nativeproof

// TransitionPrivateFrame is an optional conditional ownership/lifetime premise
// over scratch bytes below the original RSP. A conditional callee with nil Until
// has sole use through its actual return. An ELF root instead declares a finite
// lifetime ending before the first actual arrival at Until. Neither form proves
// actual process ownership. Throughout the declared lifetime no source-observable
// access may inspect the bytes through a preexisting or newly exposed alias.
// The contents after release remain concrete. A later owner must initialize
// bytes before dependent reads or explicitly establish those reads against the
// retained residual state; release does not restore or invalidate byte values.
//
// This premise is not derived from CALL, permissions, pointer preservation or
// absence of new escapes. Applying a conditional theorem must establish it from
// the caller's actual ownership discipline. It restricts observation/lifetime,
// not numerical equality of arbitrary incoming pointers. Presence grants no
// memory, values, pointer provenance or effect projection. A source projection
// independently checks disjointness, accesses, nonescape and all primitive
// ordering. Generic transition and return evidence always retains every write.
type TransitionPrivateFrame struct {
	Bytes RelativeSpan
	// Until is an independently decoded instruction address, fixed at the ELF
	// root. Arrival ends ownership before that instruction executes; the address
	// need not be reached. Nil is permitted only with a conditional-region root's
	// incoming ReturnContext and retains its actual-return lifetime. Zero is a
	// valid address, not an absent deadline. Continuation never renews ownership.
	Until *uint64
}

func (m *transitionChecker) reservePrivateFrame() error {
	if m.face.PrivateFrame == nil {
		return nil
	}
	if !m.tick() {
		return m.err
	}
	const bytes = 64
	if bytes > m.limits.LiveStateBytes-m.liveStateBytes {
		return refuse(m.pc, "transition-budget", "private-frame premise storage")
	}
	m.liveStateBytes += bytes
	return nil
}

func (m *transitionChecker) validatePrivateFrame() error {
	f := m.face.PrivateFrame
	if f == nil {
		return nil
	}
	if err := m.reservePrivateFrame(); err != nil {
		return err
	}
	if f.Until == nil {
		if !m.root.region || m.face.ReturnContext == nil {
			return refuse(m.pc, "transition-private-frame", "private lifetime requires a conditional incoming return context")
		}
	} else if m.root.region {
		return refuse(m.pc, "transition-private-frame", "finite private lifetime requires an executable-entry root")
	}
	if f.Bytes.Start >= f.Bytes.End || f.Bytes.End > 0 {
		return refuse(m.pc, "transition-private-frame", "private scratch must be nonempty and below incoming control storage")
	}
	if err := m.offset(f.Bytes.Start); err != nil {
		return err
	}
	if err := m.offset(f.Bytes.End); err != nil {
		return err
	}
	if !m.permission(f.Bytes, FrameRead) || !m.permission(f.Bytes, FrameWrite) {
		if m.err != nil {
			return m.err
		}
		return refuse(m.pc, "transition-private-frame", "private premise grants no missing memory permissions")
	}
	return m.err
}

// A deadline is independent structural evidence, including when it lies beyond
// the current cut. Later reconstruction must keep its decode compatible with all
// established occupancy, not merely the instruction selected as the current cut.
func (m *transitionChecker) validatePrivateDeadlineGraph(g *graph) error {
	f := m.face.PrivateFrame
	if f == nil || f.Until == nil {
		return nil
	}
	return m.validateDecodedBoundaryGraph(g, *f.Until, "transition-private-frame", "private deadline conflicts with an established instruction boundary")
}

// Application checks this after spatial containment at the actual post-CALL
// boundary. The CALL itself is already in history, and arrival at the child
// entry also expires ownership even though that instruction has not executed.
func (m *transitionChecker) checkPrivateLifetimeEntry() error {
	f := m.face.PrivateFrame
	if f == nil || f.Until == nil {
		return nil
	}
	if !m.tick() {
		return m.err
	}
	if m.bound.Boundary.PC == *f.Until {
		return refuse(m.pc, "transition-application-private", "private lifetime ended at the current boundary")
	}
	return m.checkPrivateLifetimeHistory()
}

// History is the sole lifetime account: no continuation can reset an arrival.
// Every retained deadline instruction must have a checked false full guard,
// including occurrences in prior activations and on a branch before a join.
// Excluded boundaries already have their own false witnesses. The unexecuted
// final boundary is deliberately absent: an actual child RET may arrive there.
func (m *transitionChecker) checkPrivateLifetimeHistory() error {
	f := m.face.PrivateFrame
	if f == nil || f.Until == nil {
		return nil
	}
	for _, instruction := range m.bound.Instructions {
		if !m.tick() {
			return m.err
		}
		if instruction.Start != *f.Until {
			continue
		}
		proved, err := m.tryFalse(instruction.Guard)
		if err != nil {
			return err
		}
		if !proved {
			return refuse(instruction.Start, "transition-application-private", "earlier private deadline arrival is not excluded")
		}
	}
	return m.err
}
