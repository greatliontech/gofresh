// Package bitrelation checks conditional equalities of pure, total scalar
// expressions. It establishes no source selection, instruction coverage, effects,
// exceptions, frame preservation, execution, or runtime-reuse claim. Frontends
// must establish those facts and the correspondence of their actual roots and
// input scopes independently. A well-typed caller-authored term proves nothing
// about an arbitrary program that the caller says it describes.
//
// ConditionalOperation distributes modular Add/Sub and the five bit-vector
// equality/order predicates through either operand's ITE. It preserves the
// exact condition, scoped values, fixed operand, branch order and typed operator.
// Search lifts one conditional at a time after cheap identities, before order
// rewrites can hide it beneath negation. Boolean encoding is not distributed in
// the opposite direction. Generated nodes, depth and proof work remain bounded;
// no branch valuation or execution premise is added by this scalar identity.
//
// ConcatMask distributes a constant bitwise AND mask across Concat's exact low
// and high field widths. Each field keeps its original scoped operand and its
// corresponding mask bits; arbitrary bits disappear only where the mask is zero.
// This scalar equality supplies no register, memory or pointer provenance.
package bitrelation

import (
	"crypto/sha256"
	"encoding/binary"
	"sync/atomic"
)

// Sort is Boolean or an uninterpreted bit vector of width 1 through 64.
// Signedness belongs to operations, not to storage. Its zero value is invalid.
type Sort struct {
	width   uint8
	boolean bool
}

// Bool returns the Boolean sort (distinct from a one-bit vector).
func Bool() Sort { return Sort{boolean: true} }

// Bits returns a bit-vector sort, or an invalid sort for an unsupported width.
func Bits(width int) Sort {
	if width < 1 || width > 64 {
		return Sort{}
	}
	return Sort{width: uint8(width)}
}

// Width returns the vector width, or zero for Boolean and invalid sorts.
func (s Sort) Width() int { return int(s.width) }

// IsBool reports the Boolean sort.
func (s Sort) IsBool() bool { return s.boolean && s.width == 0 }
func (s Sort) valid() bool  { return s.IsBool() || !s.boolean && s.width >= 1 && s.width <= 64 }

// Op identifies a total operation. Shifts use an unsigned constant count: counts
// at least the width yield zero, or the sign fill for AShr. They are not a model
// of a source operation that can panic, or an ISA's masked shift counts.
type Op uint8

const (
	Constant Op = iota + 1
	Variable
	Not
	And
	Or
	ITE
	Equal
	ULT
	ULE
	SLT
	SLE
	Add
	Sub
	BitAnd
	BitOr
	BitXor
	BitNot
	Shl
	LShr
	AShr
	Trunc
	ZExt
	SExt
	Concat
	Extract
	BoolToBits
	Nonzero
)

// Scope is a fresh, opaque variable namespace. Sharing a scope and slot across
// frontends is an explicit input mapping, controlled by their composing owner.
// Labels never identify variables. New scopes never compare equal.
type Scope struct{ id uint64 }

var nextScope atomic.Uint64

// NewScope creates a fresh input namespace. The zero scope is invalid.
func NewScope() Scope {
	id := nextScope.Add(1)
	if id == 0 {
		panic("bitrelation: scope identity exhausted")
	}
	return Scope{id: id}
}

type node struct {
	nodeKey
	digest [32]byte
}

// Term is an immutable, privately owned expression. A zero Term is invalid.
// Replacing a Builder, growing its arena, or editing a projection cannot change it.
type Term struct{ n *node }

// Sort returns this term's sort, or the invalid sort for a zero term.
func (t Term) Sort() Sort {
	if t.n == nil {
		return Sort{}
	}
	return t.n.sort
}

// Valid reports whether this handle was constructed by this package.
func (t Term) Valid() bool { return t.n != nil }

// Digest identifies the actual graph, variable namespaces and scalar rule model.
// It is dependency data, never a proof constructor or an equality test.
func (t Term) Digest() [32]byte {
	if t.n == nil {
		return [32]byte{}
	}
	return t.n.digest
}

// Projection is a caller-owned syntax view. Variable identity consists of Scope,
// Immediate (the slot), Scratch and Sort; scratch cannot alias an input variable.
type Projection struct {
	Op        Op
	Sort      Sort
	Immediate uint64
	Scope     Scope
	Scratch   bool
	Args      []Term
}

// View returns a fresh projection; its operands do not alias mutable storage.
func (t Term) View() Projection {
	if t.n == nil {
		return Projection{}
	}
	n := t.n
	p := Projection{Op: n.op, Sort: n.sort, Immediate: n.imm, Scope: n.scope, Scratch: n.scratch}
	for i := 0; i < int(n.arity); i++ {
		p.Args = append(p.Args, Term{n.args[i]})
	}
	return p
}

type nodeKey struct {
	op      Op
	sort    Sort
	imm     uint64
	scope   Scope
	scratch bool
	args    [3]*node
	arity   uint8
}
type arena struct {
	limit int
	nodes map[nodeKey]*node
}

// Builder owns an append-only, hash-consed arena. Terms do not point back to the
// public Builder container. Builders are not safe for concurrent construction;
// completed terms are safe for concurrent readers and independent checkers.
type Builder struct{ a *arena }

// NewBuilder creates a bounded arena. Zero selects the default node limit.
func NewBuilder(maxNodes int) *Builder {
	if maxNodes == 0 {
		maxNodes = DefaultLimits().Nodes
	}
	return &Builder{a: &arena{limit: maxNodes, nodes: make(map[nodeKey]*node)}}
}

// Const constructs an exact-width constant. Out-of-range bits are refused.
func (b *Builder) Const(s Sort, value uint64) (Term, error) { return b.Make(Constant, s, value) }

// Input constructs a typed input slot in an explicitly supplied namespace.
func (b *Builder) Input(s Sort, scope Scope, slot uint64) (Term, error) {
	return b.variable(s, scope, slot, false)
}

// Scratch constructs arbitrary scratch state, disjoint from typed input slots
// even if the same namespace, slot and sort are supplied.
func (b *Builder) Scratch(s Sort, scope Scope, slot uint64) (Term, error) {
	return b.variable(s, scope, slot, true)
}
func (b *Builder) variable(s Sort, scope Scope, slot uint64, scratch bool) (Term, error) {
	if !s.valid() || scope.id == 0 {
		return Term{}, refuse(Malformed, "invalid variable sort or scope")
	}
	return b.put(nodeKey{op: Variable, sort: s, imm: slot, scope: scope, scratch: scratch})
}

// Make constructs a checked operator. Immediate is zero except for constants,
// shifts and Extract's least-significant bit offset. Concat takes low then high
// operands. BoolToBits explicitly produces canonical 0/1 at its result width;
// Nonzero explicitly tests any vector against zero, asserting no source/ABI
// Boolean validity. Variables must use Input or Scratch. Operands are copied.
func (b *Builder) Make(op Op, s Sort, immediate uint64, args ...Term) (Term, error) {
	k := nodeKey{op: op, sort: s, imm: immediate}
	if len(args) > 3 {
		return Term{}, refuse(Malformed, "too many operands")
	}
	k.arity = uint8(len(args))
	for i, a := range args {
		if !a.Valid() {
			return Term{}, refuse(Malformed, "invalid operand")
		}
		k.args[i] = a.n
	}
	if !validShape(k) {
		return Term{}, refuse(Malformed, "invalid operator, width, immediate or operands")
	}
	return b.put(k)
}

func (b *Builder) put(k nodeKey) (Term, error) {
	if b == nil || b.a == nil {
		return Term{}, refuse(Malformed, "invalid builder")
	}
	a := b.a
	if n := a.nodes[k]; n != nil {
		return Term{n}, nil
	}
	if len(a.nodes) >= a.limit {
		return Term{}, refuse(Budget, "builder node budget")
	}
	n := &node{nodeKey: k}
	h := sha256.New()
	h.Write([]byte(RuleModel))
	var data [21]byte
	data[0] = byte(n.op)
	data[1] = n.sort.width
	if n.sort.boolean {
		data[2] = 1
	}
	if n.scratch {
		data[3] = 1
	}
	data[4] = n.arity
	binary.LittleEndian.PutUint64(data[5:13], n.imm)
	binary.LittleEndian.PutUint64(data[13:21], n.scope.id)
	h.Write(data[:])
	for i := 0; i < int(n.arity); i++ {
		h.Write(n.args[i].digest[:])
	}
	h.Sum(n.digest[:0])
	a.nodes[k] = n
	return Term{n}, nil
}

func validShape(k nodeKey) bool {
	if !k.sort.valid() || k.op == Variable {
		return false
	}
	if k.op != Constant && k.op != Shl && k.op != LShr && k.op != AShr && k.op != Extract && k.imm != 0 {
		return false
	}
	a := k.args
	ar := int(k.arity)
	s := k.sort
	boolArg := func(i int) bool { return a[i] != nil && a[i].sort.IsBool() }
	same := func(i int) bool { return a[i] != nil && a[i].sort == s }
	switch k.op {
	case Constant:
		return ar == 0 && (s.IsBool() && k.imm <= 1 || !s.IsBool() && k.imm & ^mask(s.width) == 0)
	case Not:
		return ar == 1 && s.IsBool() && boolArg(0)
	case And, Or:
		return ar == 2 && s.IsBool() && boolArg(0) && boolArg(1)
	case ITE:
		return ar == 3 && boolArg(0) && same(1) && same(2)
	case Equal:
		return ar == 2 && s.IsBool() && a[0].sort == a[1].sort
	case ULT, ULE, SLT, SLE:
		return ar == 2 && s.IsBool() && !a[0].sort.IsBool() && a[0].sort == a[1].sort
	case Add, Sub, BitAnd, BitOr, BitXor:
		return ar == 2 && !s.IsBool() && same(0) && same(1)
	case BitNot, Shl, LShr, AShr:
		return ar == 1 && !s.IsBool() && same(0)
	case Trunc:
		return ar == 1 && !s.IsBool() && !a[0].sort.IsBool() && s.width < a[0].sort.width
	case ZExt, SExt:
		return ar == 1 && !s.IsBool() && !a[0].sort.IsBool() && s.width > a[0].sort.width
	case Concat:
		return ar == 2 && !s.IsBool() && !a[0].sort.IsBool() && !a[1].sort.IsBool() && int(s.width) == int(a[0].sort.width)+int(a[1].sort.width)
	case Extract:
		return ar == 1 && !s.IsBool() && !a[0].sort.IsBool() && s.width <= a[0].sort.width && k.imm <= uint64(a[0].sort.width-s.width)
	case BoolToBits:
		return ar == 1 && !s.IsBool() && boolArg(0)
	case Nonzero:
		return ar == 1 && s.IsBool() && !a[0].sort.IsBool()
	}
	return false
}

func mask(w uint8) uint64            { return ^uint64(0) >> (64 - w) }
func signed(v uint64, w uint8) int64 { return int64(v<<(64-w)) >> (64 - w) }

// primitive gives the total scalar language's integer semantics. It is shared
// by constant folding and evaluation, not by proposer/checker rule recognition.
func primitive(n *node, a [3]uint64) uint64 {
	var v uint64
	bv := func(b bool) uint64 {
		if b {
			return 1
		}
		return 0
	}
	switch n.op {
	case Constant:
		v = n.imm
	case Not:
		v = bv(a[0] == 0)
	case And:
		v = a[0] & a[1]
	case Or:
		v = a[0] | a[1]
	case ITE:
		if a[0] != 0 {
			v = a[1]
		} else {
			v = a[2]
		}
	case Equal:
		v = bv(a[0] == a[1])
	case ULT:
		v = bv(a[0] < a[1])
	case ULE:
		v = bv(a[0] <= a[1])
	case SLT:
		v = bv(signed(a[0], n.args[0].sort.width) < signed(a[1], n.args[1].sort.width))
	case SLE:
		v = bv(signed(a[0], n.args[0].sort.width) <= signed(a[1], n.args[1].sort.width))
	case Add:
		v = a[0] + a[1]
	case Sub:
		v = a[0] - a[1]
	case BitAnd:
		v = a[0] & a[1]
	case BitOr:
		v = a[0] | a[1]
	case BitXor:
		v = a[0] ^ a[1]
	case BitNot:
		v = ^a[0]
	case Shl:
		v = a[0] << n.imm
	case LShr:
		v = a[0] >> n.imm
	case AShr:
		v = uint64(signed(a[0], n.sort.width) >> n.imm)
	case Trunc, ZExt:
		v = a[0]
	case SExt:
		v = uint64(signed(a[0], n.args[0].sort.width))
	case Concat:
		v = a[0] | a[1]<<n.args[0].sort.width
	case Extract:
		v = a[0] >> n.imm
	case BoolToBits:
		v = a[0]
	case Nonzero:
		v = bv(a[0] != 0)
	}
	if n.sort.IsBool() {
		return v
	}
	return v & mask(n.sort.width)
}
