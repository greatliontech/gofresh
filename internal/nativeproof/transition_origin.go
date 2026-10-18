package nativeproof

import (
	"math"
	"slices"
)

func signedPlus(a, b int64) (int64, bool) {
	c := a + b
	return c, !(b > 0 && c < a || b < 0 && c > a)
}

// alignmentOffset proves (S+d)&-k == S+d' under S%modulus=residue.
// The Euclidean remainder is computed without signed overflow, even for MinInt64.
// Canonical/nonwrapping checks on both offsets are separate mandatory side rules.
func alignmentOffset(d int64, modulus, residue, k uint64) (int64, bool) {
	if k == 0 || k&(k-1) != 0 || k > math.MaxInt64 || modulus == 0 || modulus&(modulus-1) != 0 || residue >= modulus || modulus%k != 0 {
		return 0, false
	}
	t := (residue%k + (uint64(d) & (k - 1))) & (k - 1)
	return signedPlus(d, -int64(t))
}

// originRange rounds the inclusive bounds to their declared congruence. This is
// an all-origin range, never the selection of a concrete runtime address.
func originRange(d OriginDomain) (uint64, uint64, bool) {
	if d.Min > d.Max || d.Max >= 1<<47 || d.Modulus == 0 || d.Modulus&(d.Modulus-1) != 0 || d.Modulus > 1<<47 || d.Residue >= d.Modulus {
		return 0, 0, false
	}
	lo, ok := plus(d.Min, (d.Residue-d.Min)&(d.Modulus-1))
	if !ok || lo > d.Max {
		return 0, 0, false
	}
	hi := d.Max - ((d.Max - d.Residue) & (d.Modulus - 1))
	return lo, hi, hi >= lo
}

func (m *transitionChecker) offset(d int64) error {
	if d < m.face.Envelope.Start || d > m.face.Envelope.End {
		return refuse(m.pc, "transition-envelope", "pointer escapes representable address envelope")
	}
	lo, a := relative(m.lo, d)
	hi, b := relative(m.hi, d)
	if !a || !b || lo >= 1<<47 || hi >= 1<<47 {
		return refuse(m.pc, "transition-origin", "address wraps or is noncanonical for an admitted origin")
	}
	return nil
}

func (m *transitionChecker) validate() error {
	if err := m.admitInitialization(); err != nil {
		return err
	}
	c := m.face.Conditions
	if c.Syscall != "" && c.Syscall != LinuxAMD64SyscallModel || c.Syscall == "" && c.UserAddressBits != 0 || c.Syscall != "" && c.UserAddressBits != 48 && c.UserAddressBits != 57 {
		return refuse(m.pc, "transition-primitive-model", "unsupported syscall ABI/address-ceiling configuration")
	}
	if c.CPUID != "" && c.CPUID != CPUIDModel {
		return refuse(m.pc, "transition-primitive-model", "unsupported CPUID model")
	}
	if c.Machine != MachineModel || !c.InstructionMapping || !c.EntryState || !c.IsolatedExecution || !c.MemoryMapping || !c.NoHiddenAliases || !c.UnalignedAccess {
		return refuse(m.pc, "transition-premises", "machine, entry, mapping, alias, alignment and interference premises are required")
	}
	var ok bool
	m.lo, m.hi, ok = originRange(m.face.Origin)
	if !ok {
		return refuse(m.pc, "transition-origin", "empty or invalid bounds/congruence")
	}
	e := m.face.Envelope
	if e.Start > 0 || e.End < 0 || e.Start >= e.End {
		return refuse(m.pc, "transition-envelope", "envelope must contain the origin")
	}
	if err := m.offset(e.Start); err != nil {
		return err
	}
	if err := m.offset(e.End); err != nil {
		return err
	}
	total := uint64(0)
	for j, r := range m.face.Regions {
		if !m.tick() {
			return m.err
		}
		if r.Bytes.Start < e.Start || r.Bytes.End > e.End || r.Bytes.Start >= r.Bytes.End {
			return refuse(m.pc, "transition-region", "invalid relative memory extent")
		}
		n := uint64(r.Bytes.End) - uint64(r.Bytes.Start)
		if n > uint64(m.limits.Bytes)-total {
			return refuse(m.pc, "transition-budget", "declared memory exceeds byte budget")
		}
		total += n
		for _, old := range m.face.Regions[:j] {
			if !m.tick() {
				return m.err
			}
			if r.Bytes.Start < old.Bytes.End && old.Bytes.Start < r.Bytes.End && (r.Readable != old.Readable || r.Writable != old.Writable) {
				return refuse(m.pc, "transition-permission", "overlapping permissions disagree")
			}
		}
		// pages([S+a,S+b)) intersects an image page [L,H) precisely
		// when L-b < S < H-a. Bounds above make this signed arithmetic safe.
		for _, load := range m.im.loads {
			if !m.tick() {
				return m.err
			}
			p := pages(Span{load.va, load.end})
			low := max(int64(m.lo), int64(p.Start)-r.Bytes.End+1)
			high := min(int64(m.hi)+1, int64(p.End)-r.Bytes.Start)
			if low < high {
				m.bound.ExcludedOrigins = append(m.bound.ExcludedOrigins, Span{uint64(low), uint64(high)})
			}
		}
	}
	for _, span := range m.face.ImageRegions {
		if !m.tick() {
			return m.err
		}
		if span.Start >= span.End || span.End > 1<<47 {
			return refuse(m.pc, "transition-image", "invalid absolute memory extent")
		}
		n := span.End - span.Start
		if n > uint64(m.limits.Bytes)-total {
			return refuse(m.pc, "transition-budget", "declared memory exceeds byte budget")
		}
		total += n
		index, err := m.imageLoad(span, false)
		if err != nil {
			return err
		}
		load := m.im.loads[index]
		r := ByteRegion{Bytes: span, Image: true, Readable: load.readable, Writable: load.writable}
		if err := m.im.validateMemoryMapping(m.pc, r, func() error { m.tick(); return m.err }); err != nil {
			return err
		}
	}
	// The intersection of all predicates must be inhabited. Sweep the union of
	// forbidden intervals, skipping entire intervals rather than sampling bases.
	slices.SortFunc(m.bound.ExcludedOrigins, func(a, b Span) int {
		if a.Start < b.Start {
			return -1
		}
		if a.Start > b.Start {
			return 1
		}
		return 0
	})
	candidate := m.lo
	for _, x := range m.bound.ExcludedOrigins {
		if !m.tick() {
			return m.err
		}
		if candidate < x.Start {
			break
		}
		if candidate < x.End {
			candidate = x.End + ((m.face.Origin.Residue - x.End) & (m.face.Origin.Modulus - 1))
		}
	}
	if candidate > m.hi {
		return refuse(m.pc, "transition-origin", "image-page exclusions leave no admissible origin")
	}
	// Word declarations only group arbitrary bytes. They cannot constrain an
	// origin or import an expected scalar/pointer result into the entry state.
	for j, word := range m.face.Words {
		if !m.tick() {
			return m.err
		}
		end, ok := signedPlus(word, 8)
		if !ok || !m.permission(RelativeSpan{word, end}, FrameRead) {
			if m.err != nil {
				return m.err
			}
			return refuse(m.pc, "transition-word", "initial word lacks eight readable bytes")
		}
		for _, old := range m.face.Words[:j] {
			if !m.tick() {
				return m.err
			}
			if word < old+8 && old < end {
				return refuse(m.pc, "transition-word", "overlapping initial words")
			}
		}
	}
	return m.err
}

func (m *transitionChecker) permission(s RelativeSpan, kind AccessKind) bool {
	if s.Start >= s.End {
		return false
	}
	for _, r := range m.face.Regions {
		if !m.tick() {
			return false
		}
		if s.Start >= r.Bytes.Start && s.End <= r.Bytes.End {
			return kind == FrameWrite && r.Writable || (kind == FrameRead || kind == FrameReturnRead) && r.Readable
		}
	}
	return false
}

// imageLoad establishes a logical mapping, not initial data values. A RIP LEA
// must designate an actual byte; subsequent checked arithmetic may reach one-past.
func (m *transitionChecker) imageLoad(span Span, pointer bool) (int, error) {
	for j, load := range m.im.loads {
		if !m.tick() {
			return 0, m.err
		}
		if span.Start >= load.va && span.Start < load.end && span.End <= load.end && (pointer || span.Start < span.End) {
			return j, nil
		}
	}
	return 0, refuse(m.pc, "transition-image", "extent has no owned logical image mapping")
}

func (m *transitionChecker) imagePermission(span Span, kind AccessKind) bool {
	for _, declared := range m.face.ImageRegions {
		if !m.tick() {
			return false
		}
		if span.Start >= declared.Start && span.End <= declared.End && span.Start < span.End {
			index, err := m.imageLoad(span, false)
			if err != nil {
				return false
			}
			load := m.im.loads[index]
			return (kind == FrameRead || kind == FrameReturnRead) && load.readable || kind == FrameWrite && load.writable && !load.executable
		}
	}
	return false
}
