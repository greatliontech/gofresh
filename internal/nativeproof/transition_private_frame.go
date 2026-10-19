package nativeproof

// TransitionPrivateFrame is an optional conditional ownership/lifetime premise
// over scratch bytes below the original RSP. The caller grants the callee sole
// use of these bytes through its return: no source-observable access may inspect
// them through a preexisting alias or an alias exposed during the invocation.
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
	if !m.root.region || m.face.ReturnContext == nil {
		return refuse(m.pc, "transition-private-frame", "private lifetime requires a conditional incoming return context")
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
