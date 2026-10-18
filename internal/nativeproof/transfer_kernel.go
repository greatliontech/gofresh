package nativeproof

import (
	"context"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// TransferRules identifies the shared scalar ISA relations. These relations do
// not establish instruction selection, memory applicability, ordering or a frame.
const TransferRules = "gofresh/native-scalar-transfer@1"

// TransferKernel constructs exact scalar instruction relations under one
// cumulative expression/work/depth allowance. It owns no image or certificate:
// each consumer independently checks its instruction normalization, memory,
// provenance, applicability and control obligations. It is not concurrent-safe.
type TransferKernel struct{ meter *valueBuilder }

// NewTransferKernel starts a bounded, context-bound scalar derivation.
func NewTransferKernel(ctx context.Context, limits RelationLimits) (*TransferKernel, error) {
	if ctx == nil {
		return nil, refuse(0, "relation-context", "missing context")
	}
	l, err := relationLimits(limits)
	if err != nil {
		return nil, err
	}
	m := &valueBuilder{ctx: ctx, limits: l, builder: br.NewBuilder(l.Nodes), depth: make(map[br.Term]int)}
	m.truth, m.falsity = m.con(br.Bool(), 1), m.con(br.Bool(), 0)
	if m.err != nil {
		return nil, m.err
	}
	return &TransferKernel{m}, nil
}

func (k *TransferKernel) inputs(terms ...br.Term) error {
	if k == nil || k.meter == nil {
		return refuse(0, "relation-context", "missing transfer kernel")
	}
	for _, t := range terms {
		if !t.Valid() {
			return refuse(0, "relation-semantics", "missing transfer operand")
		}
		if err := k.meter.importTerm(t); err != nil {
			k.meter.err = err
			return err
		}
	}
	return k.meter.err
}

// CompareExchangeResult describes CMPXCHG64's two scalar arms, with flags
// computed from incoming accumulator minus incoming memory in both arms.
// Memory is written even on failure. A consumer must retain that write cycle
// and the operation's lock semantics separately from these value expressions.
type CompareExchangeResult struct {
	Success, Accumulator, Memory br.Term
	Flags                        TransitionFlags
	Predicates                   TransitionPredicates
}

// CompareExchange64 interprets the 64-bit accumulator, current memory and source
// register values. All three are independent inputs; no callee identity is used.
func (k *TransferKernel) CompareExchange64(compare, current, replacement br.Term) (CompareExchangeResult, error) {
	if err := k.inputs(compare, current, replacement); err != nil {
		return CompareExchangeResult{}, err
	}
	if compare.Sort() != br.Bits(64) || current.Sort() != br.Bits(64) || replacement.Sort() != br.Bits(64) {
		return CompareExchangeResult{}, refuse(0, "relation-semantics", "CMPXCHG64 requires three full-width operands")
	}
	r := k.meter.compareExchange64(compare, current, replacement)
	if k.meter.err != nil {
		return CompareExchangeResult{}, k.meter.err
	}
	return r, nil
}

func (m *valueBuilder) compareExchange64(compare, current, replacement br.Term) CompareExchangeResult {
	f, p := m.compareFlags(compare, current)
	return CompareExchangeResult{Success: p.ZF, Accumulator: m.ite(p.ZF, compare, current), Memory: m.ite(p.ZF, replacement, current), Flags: f, Predicates: p}
}

// Compare derives all six subtraction flags without writing either operand.
// The operands must have the same supported width (8, 32 or 64 bits).
func (k *TransferKernel) Compare(left, right br.Term) (TransitionFlags, error) {
	if err := k.scalarInputs(left, right); err != nil {
		return TransitionFlags{}, err
	}
	f, _ := k.meter.compareFlags(left, right)
	if k.meter.err != nil {
		return TransitionFlags{}, k.meter.err
	}
	return f, nil
}

// Test derives logical-test flags without writing either operand. AF is
// undefined, CF/OF are zero, and SF/ZF/PF describe the bitwise conjunction.
func (k *TransferKernel) Test(left, right br.Term) (TransitionFlags, error) {
	if err := k.scalarInputs(left, right); err != nil {
		return TransitionFlags{}, err
	}
	f, _ := k.meter.testFlags(left, right)
	if k.meter.err != nil {
		return TransitionFlags{}, k.meter.err
	}
	return f, nil
}

func (k *TransferKernel) scalarInputs(left, right br.Term) error {
	if err := k.inputs(left, right); err != nil {
		return err
	}
	w := left.Sort().Width()
	if left.Sort() != right.Sort() || w != 8 && w != 32 && w != 64 {
		return refuse(0, "relation-semantics", "incompatible scalar widths")
	}
	return nil
}

// SetCondition returns a canonical zero/one byte for the selected supported
// SETcc predicate. It changes no flag. Absent predicates cannot be consumed.
func (k *TransferKernel) SetCondition(op x86asm.Op, p TransitionPredicates) (br.Term, error) {
	if !isTransitionSet(op) {
		return br.Term{}, refuse(0, "relation-semantics", "unsupported SETcc predicate")
	}
	var required []br.Term
	switch condition(op) {
	case cf:
		required = []br.Term{p.CF}
	case zf:
		required = []br.Term{p.ZF}
	case cf | zf:
		required = []br.Term{p.CF, p.ZF}
	case sf | of:
		required = []br.Term{p.SFXorOF}
	case zf | sf | of:
		required = []br.Term{p.ZF, p.SFXorOF}
	}
	for _, t := range required {
		if t.Sort() != br.Bool() {
			return br.Term{}, refuse(0, "relation-semantics", "missing defined condition predicate")
		}
	}
	if err := k.inputs(required...); err != nil {
		return br.Term{}, err
	}
	v := k.meter.setCondition(op, p)
	if k.meter.err != nil {
		return br.Term{}, k.meter.err
	}
	return v, nil
}

func (m *valueBuilder) setCondition(op x86asm.Op, p TransitionPredicates) br.Term {
	s := symbolicState{flags: [flagCount]br.Term{p.CF, p.ZF, p.SFXorOF}}
	return m.make(br.BoolToBits, br.Bits(8), 0, m.predicate(op, s))
}

func definedFlag(t br.Term) TransitionFlag { return TransitionFlag{Defined: true, Value: t} }

func (m *valueBuilder) parity(value br.Term) br.Term {
	odd := m.falsity
	for bit := 0; bit < 8; bit++ {
		one := m.make(br.Nonzero, br.Bool(), 0, m.extract(value, bit, 1))
		odd = m.different(odd, one)
	}
	return m.not(odd)
}

func (m *valueBuilder) compareFlags(left, right br.Term) (TransitionFlags, TransitionPredicates) {
	result := m.binary(br.Sub, left, right)
	c, z, less := m.compare(br.ULT, left, right), m.compare(br.Equal, left, right), m.compare(br.SLT, left, right)
	sign := m.sign(result)
	overflow := m.and(m.different(m.sign(left), m.sign(right)), m.different(m.sign(left), sign))
	aux := m.compare(br.ULT, m.extract(left, 0, 4), m.extract(right, 0, 4))
	f := TransitionFlags{CF: definedFlag(c), OF: definedFlag(overflow), SF: definedFlag(sign), ZF: definedFlag(z), AF: definedFlag(aux), PF: definedFlag(m.parity(result))}
	return f, TransitionPredicates{c, z, less}
}

func (m *valueBuilder) testFlags(left, right br.Term) (TransitionFlags, TransitionPredicates) {
	result := m.binary(br.BitAnd, left, right)
	z, sign := m.compare(br.Equal, result, m.con(result.Sort(), 0)), m.sign(result)
	f := TransitionFlags{CF: definedFlag(m.falsity), OF: definedFlag(m.falsity), SF: definedFlag(sign), ZF: definedFlag(z), PF: definedFlag(m.parity(result))}
	return f, TransitionPredicates{m.falsity, z, sign}
}

func isTransitionSet(op x86asm.Op) bool {
	switch op {
	case x86asm.SETA, x86asm.SETAE, x86asm.SETB, x86asm.SETBE, x86asm.SETE, x86asm.SETNE, x86asm.SETL, x86asm.SETLE, x86asm.SETG, x86asm.SETGE:
		return true
	}
	return false
}

// RegisterAlias maps an actual integer register spelling to its full register,
// least-significant bit offset and width. Unsupported register classes refuse.
func RegisterAlias(reg x86asm.Reg) (full Register, offset, width int, ok bool) {
	a, ok := register(reg)
	return Register(a.reg), a.shift, a.width, ok
}
