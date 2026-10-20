package nativeproof

import (
	"context"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// TransferRules identifies the shared scalar ISA relations. These relations do
// not establish instruction selection, memory applicability, ordering or a frame.
const TransferRules = "gofresh/native-scalar-transfer@5"

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

// CompareExchangeResult describes CMPXCHG's full BV64 Accumulator and operand-width
// Compare and Memory. Compare is the incoming accumulator's operand-width bits;
// flags describe Compare minus incoming memory in both arms.
// Memory is written even on failure. A consumer must retain that write cycle
// and the operation's lock semantics separately from these value expressions.
type CompareExchangeResult struct {
	Success, Compare, Accumulator, Memory br.Term
	Flags                                 TransitionFlags
	Predicates                            TransitionPredicates
}

// CompareExchange takes full BV64 incoming RAX and matching BV32 or BV64 memory
// and source values. Success preserves all incoming RAX bits; failure replaces
// RAX with current, zero-extended for a 32-bit operation.
func (k *TransferKernel) CompareExchange(accumulator, current, replacement br.Term) (CompareExchangeResult, error) {
	if err := k.inputs(accumulator, current, replacement); err != nil {
		return CompareExchangeResult{}, err
	}
	if accumulator.Sort() != br.Bits(64) || current.Sort() != replacement.Sort() || current.Sort() != br.Bits(32) && current.Sort() != br.Bits(64) {
		return CompareExchangeResult{}, refuse(0, "relation-semantics", "CMPXCHG requires BV64 RAX and matching BV32 or BV64 memory and source operands")
	}
	r := k.meter.compareExchange(accumulator, current, replacement)
	if k.meter.err != nil {
		return CompareExchangeResult{}, k.meter.err
	}
	return r, nil
}

func (m *valueBuilder) compareExchange(accumulator, current, replacement br.Term) CompareExchangeResult {
	compare, failedAccumulator := accumulator, current
	if current.Sort() == br.Bits(32) {
		compare = m.extract(accumulator, 0, 32)
		failedAccumulator = m.make(br.ZExt, br.Bits(64), 0, current)
	}
	f, p := m.compareFlags(compare, current)
	return CompareExchangeResult{Success: p.ZF, Compare: compare, Accumulator: m.ite(p.ZF, accumulator, failedAccumulator), Memory: m.ite(p.ZF, replacement, current), Flags: f, Predicates: p}
}

// ArithmeticResult retains a scalar arithmetic or logical result and its flags.
type ArithmeticResult struct {
	Value      br.Term
	Flags      TransitionFlags
	Predicates TransitionPredicates
}

// Logical derives AND or OR at the operands' common width (8, 32 or 64 bits).
// CF and OF are cleared, SF/ZF/PF describe Value, and AF remains undefined.
func (k *TransferKernel) Logical(op x86asm.Op, left, right br.Term) (ArithmeticResult, error) {
	if op != x86asm.AND && op != x86asm.OR {
		return ArithmeticResult{}, refuse(0, "relation-semantics", "unsupported logical operation")
	}
	if err := k.scalarInputs(left, right); err != nil {
		return ArithmeticResult{}, err
	}
	r := k.meter.logical(op, left, right)
	if k.meter.err != nil {
		return ArithmeticResult{}, k.meter.err
	}
	return r, nil
}

func (m *valueBuilder) logical(op x86asm.Op, left, right br.Term) ArithmeticResult {
	operation := br.BitAnd
	if op == x86asm.OR {
		operation = br.BitOr
	}
	value := m.binary(operation, left, right)
	f, p := m.logicalFlags(value)
	return ArithmeticResult{Value: value, Flags: f, Predicates: p}
}

// Add derives exact addition at the operands' common width (8, 32 or 64 bits).
func (k *TransferKernel) Add(left, right br.Term) (ArithmeticResult, error) {
	if err := k.scalarInputs(left, right); err != nil {
		return ArithmeticResult{}, err
	}
	r := k.meter.add(left, right)
	if k.meter.err != nil {
		return ArithmeticResult{}, k.meter.err
	}
	return r, nil
}

// ExchangeResult relates incoming memory and replacement to the exchanged outputs.
type ExchangeResult struct{ Register, Memory br.Term }

// Exchange64 derives scalar exchange; the consumer separately checks the locked
// memory occurrence, permissions and provenance. Architectural flags are unchanged.
func (k *TransferKernel) Exchange64(current, replacement br.Term) (ExchangeResult, error) {
	if err := k.wordInputs(current, replacement); err != nil {
		return ExchangeResult{}, err
	}
	return k.meter.exchange64(current, replacement), nil
}

// ExchangeAddResult retains the old memory in Register and modular sum in Memory.
type ExchangeAddResult struct {
	Register, Memory br.Term
	Flags            TransitionFlags
	Predicates       TransitionPredicates
}

// ExchangeAdd64 derives XADD's full-width scalar and arithmetic flag relations.
// Its consumer retains the memory write even when the delta is zero.
func (k *TransferKernel) ExchangeAdd64(current, delta br.Term) (ExchangeAddResult, error) {
	if err := k.wordInputs(current, delta); err != nil {
		return ExchangeAddResult{}, err
	}
	r := k.meter.exchangeAdd64(current, delta)
	if k.meter.err != nil {
		return ExchangeAddResult{}, k.meter.err
	}
	return r, nil
}

func (k *TransferKernel) wordInputs(left, right br.Term) error {
	if err := k.inputs(left, right); err != nil {
		return err
	}
	if left.Sort() != br.Bits(64) || right.Sort() != br.Bits(64) {
		return refuse(0, "relation-semantics", "exchange requires two full-width operands")
	}
	return nil
}

func (m *valueBuilder) exchange64(current, replacement br.Term) ExchangeResult {
	return ExchangeResult{Register: current, Memory: replacement}
}

func (m *valueBuilder) exchangeAdd64(current, delta br.Term) ExchangeAddResult {
	r := m.add(current, delta)
	return ExchangeAddResult{Register: current, Memory: r.Value, Flags: r.Flags, Predicates: r.Predicates}
}

func (m *valueBuilder) add(left, right br.Term) ArithmeticResult {
	result := m.binary(br.Add, left, right)
	c, z, sign := m.compare(br.ULT, result, left), m.compare(br.Equal, result, m.con(result.Sort(), 0)), m.sign(result)
	overflow := m.and(m.compare(br.Equal, m.sign(left), m.sign(right)), m.different(m.sign(left), sign))
	aux := m.compare(br.ULT, m.extract(result, 0, 4), m.extract(left, 0, 4))
	f := TransitionFlags{CF: definedFlag(c), OF: definedFlag(overflow), SF: definedFlag(sign), ZF: definedFlag(z), AF: definedFlag(aux), PF: definedFlag(m.parity(result))}
	return ArithmeticResult{Value: result, Flags: f, Predicates: TransitionPredicates{c, z, m.different(sign, overflow)}}
}

// SubtractBorrow derives left-right-carry at a common width of 8, 32 or 64
// bits. Carry is the actual incoming BOOL carry predicate, not a wrapped addend.
func (k *TransferKernel) SubtractBorrow(left, right, carry br.Term) (ArithmeticResult, error) {
	if err := k.scalarInputs(left, right); err != nil {
		return ArithmeticResult{}, err
	}
	if err := k.inputs(carry); err != nil {
		return ArithmeticResult{}, err
	}
	if carry.Sort() != br.Bool() {
		return ArithmeticResult{}, refuse(0, "relation-semantics", "SBB requires a BOOL carry")
	}
	r := k.meter.subtractBorrow(left, right, carry)
	if k.meter.err != nil {
		return ArithmeticResult{}, k.meter.err
	}
	return r, k.meter.err
}

func (m *valueBuilder) subtractBorrow(left, right, carry br.Term) ArithmeticResult {
	result := m.binary(br.Sub, m.binary(br.Sub, left, right), m.make(br.BoolToBits, left.Sort(), 0, carry))
	borrow := func(a, b br.Term) br.Term {
		return m.or(m.compare(br.ULT, a, b), m.and(m.compare(br.Equal, a, b), carry))
	}
	c, z, sign := borrow(left, right), m.compare(br.Equal, result, m.con(result.Sort(), 0)), m.sign(result)
	// Overflow compares the original operands' signs: right+carry may wrap.
	overflow := m.and(m.different(m.sign(left), m.sign(right)), m.different(m.sign(left), sign))
	aux := borrow(m.extract(left, 0, 4), m.extract(right, 0, 4))
	f := TransitionFlags{CF: definedFlag(c), OF: definedFlag(overflow), SF: definedFlag(sign), ZF: definedFlag(z), AF: definedFlag(aux), PF: definedFlag(m.parity(result))}
	return ArithmeticResult{result, f, TransitionPredicates{c, z, m.different(sign, overflow)}}
}

// ShiftLeft32Result retains SHL's masked-count relation. Carry is meaningful
// for nonzero counts and Overflow for count one. Zero counts preserve incoming
// flags; counts greater than one leave OF undefined, and nonzero counts leave
// AF undefined. Consumers must apply those conditions to their incoming state.
type ShiftLeft32Result struct {
	Value, ZeroCount, OneCount          br.Term
	Carry, Overflow, Sign, Zero, Parity br.Term
}

// ShiftLeft32 derives the low 32-bit result from a BV32 operand and incoming
// BV8 CL. It uses only constant shifts and BOOL selection. Register zero extension
// and guarded flag definedness remain consumer obligations, including count zero.
func (k *TransferKernel) ShiftLeft32(value, count br.Term) (ShiftLeft32Result, error) {
	if err := k.inputs(value, count); err != nil {
		return ShiftLeft32Result{}, err
	}
	if value.Sort() != br.Bits(32) || count.Sort() != br.Bits(8) {
		return ShiftLeft32Result{}, refuse(0, "relation-semantics", "SHL32 requires BV32 operand and BV8 count")
	}
	r := k.meter.shiftLeft32(value, count)
	if k.meter.err != nil {
		return ShiftLeft32Result{}, k.meter.err
	}
	return r, k.meter.err
}

func (m *valueBuilder) shiftLeft32(value, count br.Term) ShiftLeft32Result {
	var countBits [5]br.Term
	zero, highZero := m.truth, m.truth
	x := m.make(br.ZExt, br.Bits(33), 0, value)
	for bit := 0; bit < 5; bit++ {
		selected := m.scalarCountBit(count, bit)
		countBits[bit] = selected
		zero = m.and(zero, m.not(selected))
		if bit != 0 {
			highZero = m.and(highZero, m.not(selected))
		}
		x = m.ite(selected, m.make(br.Shl, br.Bits(33), uint64(1<<bit), x), x)
	}
	result := m.extract(x, 0, 32)
	carry := m.make(br.Nonzero, br.Bool(), 0, m.extract(x, 32, 1))
	sign := m.sign(result)
	return ShiftLeft32Result{Value: result,
		ZeroCount: zero,
		OneCount:  m.and(countBits[0], highZero),
		Carry:     carry, Overflow: m.different(sign, carry), Sign: sign,
		Zero: m.compare(br.Equal, result, m.con(br.Bits(32), 0)), Parity: m.parity(result)}
}

// scalarCountBit preserves the Boolean structure of masked and joined counts.
// Reading a bit through conversions, conjunction and ITE is exact; retaining
// that structure lets the existing checked Boolean rewrites prove count-domain
// guarantees without treating a known-bit estimate as proof. Every recursive
// visit consumes the shared work allowance, including visits that fold away.
func (m *valueBuilder) scalarCountBit(value br.Term, bit int) br.Term {
	if !m.tick() {
		return br.Term{}
	}
	v := value.View()
	switch v.Op {
	case br.Constant:
		return m.con(br.Bool(), v.Immediate>>uint(bit)&1)
	case br.Extract:
		return m.scalarCountBit(v.Args[0], bit+int(v.Immediate))
	case br.Trunc:
		return m.scalarCountBit(v.Args[0], bit)
	case br.ZExt:
		if bit >= v.Args[0].Sort().Width() {
			return m.falsity
		}
		return m.scalarCountBit(v.Args[0], bit)
	case br.BitAnd:
		return m.and(m.scalarCountBit(v.Args[0], bit), m.scalarCountBit(v.Args[1], bit))
	case br.ITE:
		return m.ite(v.Args[0], m.scalarCountBit(v.Args[1], bit), m.scalarCountBit(v.Args[2], bit))
	}
	return m.make(br.Nonzero, br.Bool(), 0, m.extract(value, bit, 1))
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
	return m.logicalFlags(result)
}

func (m *valueBuilder) logicalFlags(result br.Term) (TransitionFlags, TransitionPredicates) {
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
