package nativeproof

import (
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// SSEModel identifies ordinary legacy scalar SSE/SSE2 loads and unordered
// comparisons. SSE/SSE2 must be available and enabled with no #UD, #NM or
// layer-visible interposition. Vector and floating control state must be stable
// under the transition's interference premises. It grants no AVX semantics.
// Comparisons separately prove that neither incoming operand is a signaling NaN
// or nonzero subnormal; selecting this model does not assume normal completion.
const SSEModel = "x86-64/ordinary-legacy-sse2@1"

// TransitionVector is the complete low 128-bit XMM value, as two BV64 terms.
// Lo contains bits 63:0 and Hi contains bits 127:64. Neither term represents
// any higher architectural vector bits.
type TransitionVector struct{ Lo, Hi br.Term }

// TransitionVectors retains XMM0 through XMM15 by value. Original entry terms
// remain immutable identities even when a current vector is overwritten.
type TransitionVectors [16]TransitionVector

// TransitionSSEContext describes preserved implicit architectural context under
// SSEModel. MXCSR is unchanged, including existing exception-status bits; no
// initial value, rounding mode, exception mask, DAZ or FTZ setting is invented.
// UpperVectorsPreserved covers architectural vector state outside XMM0..15's
// low 128 bits, including higher lanes and additional registers when present.
// These claims apply only when the SSE model is selected.
type TransitionSSEContext struct {
	MXCSRPreserved, UpperVectorsPreserved bool
}

func isTransitionSSE(op x86asm.Op) bool {
	return op == x86asm.MOVSS || op == x86asm.MOVSD_XMM || op == x86asm.UCOMISS || op == x86asm.UCOMISD
}

func transitionXMM(arg x86asm.Arg) (int, bool) {
	r, ok := arg.(x86asm.Reg)
	return int(r - x86asm.X0), ok && r >= x86asm.X0 && r <= x86asm.X15
}

// validateTransitionSSEForm is an alternative to the integer prefix validator,
// not an exception after that validator. Mandatory F2/F3/66 precedes at most one
// non-W REX. Only 0F 10 memory loads and 0F 2E register comparisons are modeled;
// the MOVSD string mnemonic, stores, register moves and VEX/EVEX forms refuse.
func validateTransitionSSEForm(pc uint64, i x86asm.Inst, b []byte) error {
	bad := func() error {
		return refuse(pc, "transition-form", "unsupported legacy scalar SSE encoding or operand form")
	}
	if !isTransitionSSE(i.Op) || i.Mode != 64 || i.AddrSize != 64 || i.Len != len(b) || i.Args[2] != nil || i.Args[3] != nil {
		return bad()
	}
	prefix, opcode, width := byte(0), byte(0x2e), 32
	switch i.Op {
	case x86asm.MOVSS:
		prefix, opcode = 0xf3, 0x10
	case x86asm.MOVSD_XMM:
		prefix, opcode, width = 0xf2, 0x10, 64
	case x86asm.UCOMISD:
		prefix, width = 0x66, 64
	}
	at := 0
	if prefix != 0 {
		if len(b) == 0 || b[0] != prefix {
			return bad()
		}
		at++
	}
	rex := byte(0)
	if at < len(b) && b[at] >= 0x40 && b[at] <= 0x47 {
		rex = b[at]
		at++
	}
	if len(b) < at+3 || b[at] != 0x0f || b[at+1] != opcode {
		return bad()
	}
	modrm := b[at+2]
	dst, ok := transitionXMM(i.Args[0])
	if !ok || dst != int(modrm>>3&7)+int(rex&4)*2 {
		return bad()
	}
	if opcode == 0x10 {
		mem, ok := i.Args[1].(x86asm.Mem)
		if !ok || modrm&0xc0 == 0xc0 || mem.Segment != 0 || !transitionMemory(mem) || i.MemBytes != width/8 {
			return bad()
		}
	} else {
		src, ok := transitionXMM(i.Args[1])
		if !ok || modrm&0xc0 != 0xc0 || len(b) != at+3 || src != int(modrm&7)+int(rex&1)*8 || i.MemBytes != 0 {
			return bad()
		}
	}
	return nil
}

// sseStep consumes only a form admitted by validateTransitionSSEForm. Vector
// state is passed explicitly so every graph path owns its own by-value array.
func (m *transitionChecker) sseStep(i operation, size uint8, vectors *TransitionVectors, model string) error {
	if model != SSEModel {
		return refuse(m.pc, "transition-sse-premise", "ordinary legacy SSE/SSE2 applicability is required")
	}
	dst, _ := transitionXMM(i.Args[0])
	if i.Op == x86asm.MOVSS || i.Op == x86asm.MOVSD_XMM {
		width := 4
		if i.Op == x86asm.MOVSD_XMM {
			width = 8
		}
		off, err := m.address(i.Args[1].(x86asm.Mem), FrameRead, width, size)
		if err != nil {
			return err
		}
		vectors[dst] = m.sseMemoryVector(m.load(off, width, FrameRead).Value)
		return m.err
	}
	src, _ := transitionXMM(i.Args[1])
	width := 32
	if i.Op == x86asm.UCOMISD {
		width = 64
	}
	r, err := m.checkedSSECompare(vectors[dst].Lo, vectors[src].Lo, width, m.state.path)
	if err != nil {
		return err
	}
	m.bound.Flags = r.Flags
	m.setPredicates(r.Predicates)
	return m.err
}

func (m *valueBuilder) initialSSEVectors() TransitionVectors {
	var vectors TransitionVectors
	for r := range vectors {
		vectors[r] = TransitionVector{m.scratch(br.Bits(64)), m.scratch(br.Bits(64))}
	}
	return vectors
}

// mergeSSEVectors uses the same incoming path as scalar and byte-memory joins.
// The caller has already handled absent and literal-false predecessor states.
func (m *valueBuilder) mergeSSEVectors(dst *TransitionVectors, src TransitionVectors, guard br.Term) {
	for r := range dst {
		if !m.tick() {
			return
		}
		dst[r].Lo = m.ite(guard, src[r].Lo, dst[r].Lo)
		dst[r].Hi = m.ite(guard, src[r].Hi, dst[r].Hi)
	}
}

// importSSEVectors accounts for every immutable entry/current expression before
// continuation construction. Only a selected SSE model supplies these arrays.
func (m *valueBuilder) importSSEVectors(vectors TransitionVectors) error {
	for _, v := range vectors {
		for _, term := range []br.Term{v.Lo, v.Hi} {
			if err := m.importTerm(term); err != nil {
				return err
			}
		}
	}
	return nil
}

// sseMemoryVector is only the legacy memory-to-XMM transfer. Its input is the
// exact BV32/BV64 memory read, not a floating conversion or a register source.
// Register-register MOVSS/MOVSD have different high-lane semantics.
func (m *valueBuilder) sseMemoryVector(value br.Term) TransitionVector {
	if !m.tick() {
		return TransitionVector{}
	}
	if value.Sort() != br.Bits(32) && value.Sort() != br.Bits(64) {
		m.err = refuse(m.pc, "transition-sse", "scalar load requires exactly 32 or 64 memory bits")
		return TransitionVector{}
	}
	lo := value
	if value.Sort() == br.Bits(32) {
		lo = m.make(br.ZExt, br.Bits(64), 0, value)
	}
	return TransitionVector{lo, m.con(br.Bits(64), 0)}
}

type sseComparison struct {
	Flags      TransitionFlags
	Predicates TransitionPredicates
	Excluded   br.Term
}

// sseCompare constructs integer-bitvector IEEE binary32/binary64 relations.
// Excluded is an obligation, not a restriction silently added to the path.
// Only checkedSSECompare may authorize using the resulting flags in a transfer.
func (m *valueBuilder) sseCompare(left, right br.Term, width int) sseComparison {
	if !m.tick() {
		return sseComparison{}
	}
	if (width != 32 && width != 64) || left.Sort() != br.Bits(64) || right.Sort() != br.Bits(64) {
		m.err = refuse(m.pc, "transition-sse", "comparison requires XMM low BV64 lanes and binary32 or binary64 width")
		return sseComparison{}
	}
	fracBits, expBits := 23, 8
	if width == 64 {
		fracBits, expBits = 52, 11
	}
	var classify func(br.Term) (br.Term, br.Term, br.Term)
	classify = func(v br.Term) (nan, excluded, zero br.Term) {
		if !m.tick() {
			return
		}
		// Preserve a join's Boolean structure for the checked guard proof. A
		// classification of ITE(P,A,B) is exactly ITE(P,class(A),class(B));
		// neither arm is dropped or treated as an assumed normal successor.
		// Expression depth and the cumulative work meter bound this traversal.
		if view := v.View(); view.Op == br.ITE {
			an, ab, az := classify(view.Args[1])
			bn, bb, bz := classify(view.Args[2])
			return m.ite(view.Args[0], an, bn), m.ite(view.Args[0], ab, bb), m.ite(view.Args[0], az, bz)
		}
		v = m.extract(v, 0, width)
		fraction := m.extract(v, 0, fracBits)
		exponent := m.extract(v, fracBits, expBits)
		fractionNonzero := m.different(fraction, m.con(fraction.Sort(), 0))
		exponentZero := m.compare(br.Equal, exponent, m.con(exponent.Sort(), 0))
		nan = m.and(m.compare(br.Equal, exponent, m.con(exponent.Sort(), mask(expBits))), fractionNonzero)
		quiet := m.make(br.Nonzero, br.Bool(), 0, m.extract(v, fracBits-1, 1))
		excluded = m.or(m.and(nan, m.not(quiet)), m.and(exponentZero, fractionNonzero))
		zero = m.and(exponentZero, m.not(fractionNonzero))
		return
	}
	lnan, lbad, lzero := classify(left)
	rnan, rbad, rzero := classify(right)
	left, right = m.extract(left, 0, width), m.extract(right, 0, width)
	unordered := m.or(lnan, rnan)
	zeros := m.and(lzero, rzero)
	equal := m.or(m.compare(br.Equal, left, right), zeros)
	// With equal signs the IEEE encoding orders positive magnitudes forward and
	// negative magnitudes backward. Opposite signs order by the left sign, except
	// that the two encodings of zero are equal. NaNs are handled separately.
	lsign, rsign := m.sign(left), m.sign(right)
	less := m.ite(m.different(lsign, rsign), lsign,
		m.ite(lsign, m.compare(br.ULT, right, left), m.compare(br.ULT, left, right)))
	less = m.and(m.not(zeros), less)
	carry := m.or(unordered, less)
	zero := m.or(unordered, equal)
	flags := TransitionFlags{
		CF: definedFlag(carry), ZF: definedFlag(zero), PF: definedFlag(unordered),
		OF: definedFlag(m.falsity), SF: definedFlag(m.falsity), AF: definedFlag(m.falsity),
	}
	return sseComparison{flags, TransitionPredicates{carry, zero, m.falsity}, m.or(lbad, rbad)}
}

// checkedSSECompare proves the complete incoming exceptional-operand condition
// impossible and retains the checked witness through tryFalse. Invalid/denormal
// exceptions are the only floating exceptions of UCOMISS/UCOMISD. Removing both
// classes preserves all MXCSR status and controls regardless of their settings.
// Loads themselves accept every bit pattern, including excluded compare inputs.
func (m *transitionChecker) checkedSSECompare(left, right br.Term, width int, guard br.Term) (sseComparison, error) {
	r := m.sseCompare(left, right, width)
	bad := m.and(guard, r.Excluded)
	if m.err != nil {
		return sseComparison{}, m.err
	}
	ok, err := m.tryFalse(bad)
	if err != nil {
		return sseComparison{}, err
	}
	if !ok {
		return sseComparison{}, refuse(m.pc, "transition-sse-operands", "incoming guard does not exclude signaling NaNs and nonzero subnormals")
	}
	return r, nil
}

// transitionPredicate extends the transition domain only: parity comes from its
// actual projected flag, including joins, rather than a new scalar scratch bit.
func (m *valueBuilder) transitionPredicate(op x86asm.Op, s symbolicState, flags TransitionFlags) br.Term {
	if op != x86asm.JP && op != x86asm.JNP {
		return m.predicate(op, s)
	}
	if !m.tick() {
		return br.Term{}
	}
	if !flags.PF.Defined || flags.PF.Value.Sort() != br.Bool() {
		m.err = refuse(m.pc, "transition-flag", "parity branch requires a defined projected parity value")
		return br.Term{}
	}
	if op == x86asm.JNP {
		return m.not(flags.PF.Value)
	}
	return flags.PF.Value
}
