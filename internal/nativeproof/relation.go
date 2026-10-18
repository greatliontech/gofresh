package nativeproof

import (
	"context"
	"errors"
	"fmt"
	"math/bits"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// ValueRules identifies the conditional native scalar interpretation, together
// with the effect checker and expression-language dependencies it uses.
const ValueRules = "gofresh/native-value@1;" + RuleModel + ";" + br.RuleModel

// InputBinding maps Value's low-to-high bitvector bits to a contiguous register
// interval. Its composing owner establishes the source argument interpretation;
// this declaration itself establishes neither source semantics nor actual use.
type InputBinding struct {
	Register Register
	Offset   int
	Value    br.Term
}

// RegisterValue is one maximal contiguous interval of the declared result mask.
// Value is exactly that bit projection, with no implicit Boolean canonicality or
// signed extension into unspecified high register bits.
type RegisterValue struct {
	Register Register
	Offset   int
	Value    br.Term
}

// RelationLimits bound graph instructions, imported/generated expression nodes,
// work checkpoints and expression depth. Zero selects finite defaults. Depth is
// capped at 512, the shared expression checker's supported depth ceiling.
type RelationLimits struct{ Instructions, Nodes, Work, Depth int }

// DefaultRelationLimits supplies finite construction limits, not proof premises.
func DefaultRelationLimits() RelationLimits {
	return RelationLimits{Instructions: 4096, Nodes: 32768, Work: 1_000_000, Depth: 512}
}

// Relation is an opaque conditional value relation constructed only from actual
// image bytes. It includes the existing effect/frame bound but no source equality,
// invocation provenance, startup/inline coverage or runtime freshness authority.
// Its zero value carries no evidence. There is no unchecked positive constructor.
type Relation struct{ checked *valueRelation }
type valueRelation struct {
	effects Certificate
	inputs  []InputBinding
	results []RegisterValue
}

// Bound returns the checked native scope and whether a relation exists.
func (r Relation) Bound() (Bound, bool) {
	if r.checked == nil {
		return Bound{}, false
	}
	return r.checked.effects.Bound()
}

// Effects returns the exact opaque effect/frame certificate checked while
// deriving this relation. It preserves the certificate's image ownership and
// conditional interface; unlike Bound, it can be consumed by checked composition.
// A zero relation returns a zero certificate with no authority.
func (r Relation) Effects() Certificate {
	if r.checked == nil {
		return Certificate{}
	}
	return r.checked.effects
}

// Rules identifies all semantic rules used by this value relation.
func (r Relation) Rules() string {
	if r.checked == nil {
		return ""
	}
	return ValueRules
}

// Inputs returns a copy of the retained conditional input correspondence.
func (r Relation) Inputs() []InputBinding {
	if r.checked == nil {
		return nil
	}
	return append([]InputBinding(nil), r.checked.inputs...)
}

// Results returns copied projections with immutable expression handles.
func (r Relation) Results() []RegisterValue {
	if r.checked == nil {
		return nil
	}
	return append([]RegisterValue(nil), r.checked.results...)
}

// DeriveRelation independently decodes the entire entry and checks the existing
// effect/frame/input-bound proposition before interpreting values. Inputs must
// cover exactly Interface.Inputs without overlaps; every other entry bit and
// flag starts arbitrary in a fresh scratch namespace. No expected native result
// expression or caller-supplied graph is accepted as instruction authority.
//
// Image and input containers are captured before invoking context callbacks.
// Concurrent mutation during that capture remains the caller's responsibility.
// Limits apply before graph growth and expression construction; exhaustion or
// cancellation returns no partial relation. Only the declared result bits are
// projected, under the same isolated-invocation/return-slot premises as Check.
func DeriveRelation(ctx context.Context, im *Image, entry uint64, face Interface, inputs []InputBinding, limits RelationLimits) (Relation, error) {
	im = im.snapshot()
	// At most one mapping per integer-register bit can be nonoverlapping. Bound
	// the copy before making it, without calling any caller-controlled method.
	if len(inputs) > 16*64 {
		return Relation{}, refuse(entry, "relation-inputs", "too many input intervals")
	}
	owned := append([]InputBinding(nil), inputs...)
	l, err := relationLimits(limits)
	if err != nil {
		return Relation{}, refuse(entry, "relation-budget", err.Error())
	}
	if ctx == nil {
		return Relation{}, refuse(entry, "relation-context", "missing context")
	}
	m := &valueBuilder{ctx: ctx, limits: l, pc: entry, depth: make(map[br.Term]int)}
	if !m.tick() {
		return Relation{}, m.err
	}
	if err := validInterface(entry, face); err != nil {
		return Relation{}, err
	}
	if im == nil || len(im.data) == 0 {
		return Relation{}, refuse(entry, "image-binding", "missing constructed image")
	}
	var covered Masks
	for _, input := range owned {
		width := input.Value.Sort().Width()
		if input.Register > R15 || width == 0 || input.Offset < 0 || input.Offset > 64-width {
			return Relation{}, refuse(entry, "relation-inputs", "invalid register, bit interval or bitvector term")
		}
		mask := mask(width) << input.Offset
		if covered[input.Register]&mask != 0 {
			return Relation{}, refuse(entry, "relation-inputs", "overlapping input intervals")
		}
		covered[input.Register] |= mask
		if err := m.importTerm(input.Value); err != nil {
			return Relation{}, err
		}
	}
	if covered != face.Inputs {
		return Relation{}, refuse(entry, "relation-inputs", "input terms do not exactly cover the declared input bits")
	}
	remaining := l.Nodes - len(m.depth)
	if remaining <= 0 {
		return Relation{}, refuse(entry, "relation-budget", "no expression construction capacity")
	}
	m.builder = br.NewBuilder(remaining)
	m.scope = br.NewScope()
	// The same work meter bounds graph traversal and the effect check. Its Err
	// callback never mutates the caller's image or accepts any partial graph.
	bounded := &relationContext{Context: ctx, meter: m}
	g, err := decodeGraphLimited(bounded, im, entry, l.Instructions)
	if err != nil {
		return Relation{}, err
	}
	effects, err := checkGraph(bounded, im, entry, face, g)
	if err != nil {
		return Relation{}, err
	}
	m.truth = m.con(br.Bool(), 1)
	m.falsity = m.con(br.Bool(), 0)
	states := make([]symbolicState, len(g.nodes))
	initial := &states[0]
	initial.present, initial.path = true, m.truth
	for reg := range initial.regs {
		initial.regs[reg] = m.scratch(br.Bits(64))
	}
	for flag := range initial.flags {
		initial.flags[flag] = m.scratch(br.Bool())
	}
	for _, input := range owned {
		initial.regs[input.Register] = m.insert(initial.regs[input.Register], input.Value, input.Offset)
	}
	var returned symbolicState
	for _, index := range g.order {
		ins := &g.nodes[index]
		m.pc = ins.pc
		if !m.tick() {
			return Relation{}, g.failure(ins.pc, m.err)
		}
		s := states[index]
		if err := m.transfer(ins.pc, ins.inst, &s); err != nil {
			return Relation{}, g.failure(ins.pc, err)
		}
		if m.err != nil {
			return Relation{}, g.failure(ins.pc, m.err)
		}
		if ins.inst.Op == x86asm.RET {
			m.merge(&returned, s)
		} else {
			for edge, next := range ins.next[:ins.count] {
				incoming := s
				if ins.count == 2 {
					predicate := m.predicate(ins.inst.Op, s)
					if edge == 0 {
						predicate = m.not(predicate)
					}
					incoming.path = m.and(s.path, predicate)
				}
				m.merge(&states[next], incoming)
			}
		}
		if m.err != nil {
			return Relation{}, g.failure(ins.pc, m.err)
		}
	}
	var results []RegisterValue
	for reg, observed := range face.Results {
		for observed != 0 {
			offset := bits.TrailingZeros64(observed)
			width := bits.TrailingZeros64(^(observed >> offset))
			value := m.extract(returned.regs[reg], offset, width)
			results = append(results, RegisterValue{Register: Register(reg), Offset: offset, Value: value})
			observed &^= mask(width) << offset
		}
	}
	if !m.tick() {
		return Relation{}, g.failure(m.pc, m.err)
	}
	return Relation{&valueRelation{effects: effects, inputs: owned, results: results}}, nil
}

func relationLimits(l RelationLimits) (RelationLimits, error) {
	d := DefaultRelationLimits()
	if l.Instructions == 0 {
		l.Instructions = d.Instructions
	}
	if l.Nodes == 0 {
		l.Nodes = d.Nodes
	}
	if l.Work == 0 {
		l.Work = d.Work
	}
	if l.Depth == 0 {
		l.Depth = d.Depth
	}
	if l.Instructions < 0 || l.Nodes < 0 || l.Work < 0 || l.Depth < 0 || l.Depth > 512 {
		return l, fmt.Errorf("invalid relation limits")
	}
	return l, nil
}

type relationContext struct {
	context.Context
	meter *valueBuilder
}

func (c *relationContext) Err() error { c.meter.tick(); return c.meter.err }

type valueBuilder struct {
	ctx            context.Context
	limits         RelationLimits
	work           int
	pc             uint64
	err            error
	builder        *br.Builder
	depth          map[br.Term]int
	scope          br.Scope
	scratchSlot    uint64
	truth, falsity br.Term
}

func (m *valueBuilder) tick() bool {
	if m.err != nil {
		return false
	}
	if m.err = m.ctx.Err(); m.err != nil {
		return false
	}
	if m.work >= m.limits.Work {
		m.err = refuse(m.pc, "relation-budget", "construction work budget")
		return false
	}
	m.work++
	return true
}

func (m *valueBuilder) importTerm(root br.Term) error {
	type visit struct {
		term   br.Term
		finish bool
		level  int
	}
	stack := []visit{{term: root, level: 1}}
	for len(stack) > 0 {
		if !m.tick() {
			return m.err
		}
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if v.level > m.limits.Depth {
			return refuse(m.pc, "relation-budget", "input expression depth")
		}
		if m.depth[v.term] != 0 {
			continue
		}
		view := v.term.View()
		if v.finish {
			depth := 1
			for _, arg := range view.Args {
				depth = max(depth, 1+m.depth[arg])
			}
			if depth > m.limits.Depth || len(m.depth) >= m.limits.Nodes {
				return refuse(m.pc, "relation-budget", "input expression nodes/depth")
			}
			m.depth[v.term] = depth
		} else {
			// Every pending frame contributes bounded work and depth. View copies
			// at most three operands; a hostile DAG cannot allocate an unbounded
			// child vector before its budget is examined.
			stack = append(stack, visit{v.term, true, v.level})
			for _, arg := range view.Args {
				stack = append(stack, visit{arg, false, v.level + 1})
			}
		}
	}
	return nil
}

func (m *valueBuilder) make(op br.Op, sort br.Sort, imm uint64, args ...br.Term) br.Term {
	if !m.tick() {
		return br.Term{}
	}
	depth := 1
	for _, arg := range args {
		depth = max(depth, m.depth[arg]+1)
	}
	if depth > m.limits.Depth {
		m.err = refuse(m.pc, "relation-budget", "constructed expression depth")
		return br.Term{}
	}
	t, err := m.builder.Make(op, sort, imm, args...)
	if err != nil {
		m.expressionError(err)
		return br.Term{}
	}
	m.remember(t, depth)
	return t
}

// remember accounts for the union of imported nodes and newly constructed
// nodes. The arena's own bound covers only its allocations, not foreign operands.
func (m *valueBuilder) remember(t br.Term, depth int) {
	if m.depth[t] == 0 && len(m.depth) >= m.limits.Nodes {
		m.err = refuse(m.pc, "relation-budget", "combined expression nodes")
		return
	}
	m.depth[t] = depth
}

func (m *valueBuilder) scratch(sort br.Sort) br.Term {
	if !m.tick() {
		return br.Term{}
	}
	t, err := m.builder.Scratch(sort, m.scope, m.scratchSlot)
	m.scratchSlot++
	if err != nil {
		m.expressionError(err)
		return br.Term{}
	}
	m.remember(t, 1)
	return t
}

func (m *valueBuilder) expressionError(err error) {
	premise := "relation-expression"
	var refusal *br.Refusal
	if errors.As(err, &refusal) && refusal.Code == br.Budget {
		premise = "relation-budget"
	}
	m.err = refuse(m.pc, premise, err.Error())
}

func (m *valueBuilder) con(s br.Sort, v uint64) br.Term        { return m.make(br.Constant, s, v) }
func (m *valueBuilder) binary(op br.Op, a, b br.Term) br.Term  { return m.make(op, a.Sort(), 0, a, b) }
func (m *valueBuilder) compare(op br.Op, a, b br.Term) br.Term { return m.make(op, br.Bool(), 0, a, b) }

// Imported immutable constants need not have the local builder's identity.
// Literal inspection is an exact Boolean rule, not a path satisfiability guess.
func literalBool(t br.Term, value uint64) bool {
	v := t.View()
	return v.Op == br.Constant && v.Sort == br.Bool() && v.Immediate == value
}
func (m *valueBuilder) not(t br.Term) br.Term {
	if literalBool(t, 1) {
		return m.falsity
	}
	if literalBool(t, 0) {
		return m.truth
	}
	return m.make(br.Not, br.Bool(), 0, t)
}
func (m *valueBuilder) and(a, b br.Term) br.Term {
	if literalBool(a, 0) || literalBool(b, 0) {
		return m.falsity
	}
	if literalBool(a, 1) {
		return b
	}
	if literalBool(b, 1) || a == b {
		return a
	}
	return m.make(br.And, br.Bool(), 0, a, b)
}
func (m *valueBuilder) or(a, b br.Term) br.Term {
	if literalBool(a, 1) || literalBool(b, 1) {
		return m.truth
	}
	if literalBool(a, 0) {
		return b
	}
	if literalBool(b, 0) || a == b {
		return a
	}
	return m.make(br.Or, br.Bool(), 0, a, b)
}
func (m *valueBuilder) ite(p, a, b br.Term) br.Term {
	if a == b || literalBool(p, 1) {
		return a
	}
	if literalBool(p, 0) {
		return b
	}
	return m.make(br.ITE, a.Sort(), 0, p, a, b)
}
func (m *valueBuilder) extract(t br.Term, offset, width int) br.Term {
	if m.err != nil {
		return br.Term{}
	}
	if offset == 0 && width == t.Sort().Width() {
		return t
	}
	return m.make(br.Extract, br.Bits(width), uint64(offset), t)
}
func (m *valueBuilder) insert(old, value br.Term, offset int) br.Term {
	if m.err != nil {
		return br.Term{}
	}
	width := value.Sort().Width()
	if offset == 0 && width == 64 {
		return value
	}
	result := value
	if offset > 0 {
		result = m.make(br.Concat, br.Bits(offset+width), 0, m.extract(old, 0, offset), result)
	}
	if offset+width < 64 {
		result = m.make(br.Concat, br.Bits(64), 0, result, m.extract(old, offset+width, 64-offset-width))
	}
	return result
}

const (
	flagCarry = iota
	flagZero
	flagLess
	flagCount
)

type symbolicState struct {
	regs [16]br.Term
	// The supported conditions consume CF, ZF and SF != OF, never SF or OF
	// independently. Retain only those three predicates across instructions and
	// merges; compute sign/overflow locally where their combination is needed.
	// CMP derives flagLess directly from the signed comparison identity.
	flags   [flagCount]br.Term
	path    br.Term
	present bool
}

func (m *valueBuilder) merge(dst *symbolicState, src symbolicState) {
	if !dst.present {
		*dst = src
		return
	}
	for i := range dst.regs {
		if !m.tick() {
			return
		}
		dst.regs[i] = m.ite(src.path, src.regs[i], dst.regs[i])
	}
	for i := range dst.flags {
		if !m.tick() {
			return
		}
		dst.flags[i] = m.ite(src.path, src.flags[i], dst.flags[i])
	}
	dst.path = m.or(dst.path, src.path)
}

func (m *valueBuilder) read(s *symbolicState, a alias) br.Term {
	return m.extract(s.regs[a.reg], a.shift, a.width)
}
func (m *valueBuilder) write(s *symbolicState, a alias, v br.Term) {
	if a.width == 32 {
		s.regs[a.reg] = m.make(br.ZExt, br.Bits(64), 0, v)
		return
	}
	s.regs[a.reg] = m.insert(s.regs[a.reg], v, a.shift)
}
func (m *valueBuilder) sign(t br.Term) br.Term         { return m.compare(br.SLT, t, m.con(t.Sort(), 0)) }
func (m *valueBuilder) different(a, b br.Term) br.Term { return m.not(m.compare(br.Equal, a, b)) }

func (m *valueBuilder) predicate(op x86asm.Op, s symbolicState) br.Term {
	c, z, l := s.flags[flagCarry], s.flags[flagZero], s.flags[flagLess]
	switch op {
	case x86asm.JA, x86asm.SETA:
		return m.not(m.or(c, z))
	case x86asm.JBE, x86asm.SETBE:
		return m.or(c, z)
	case x86asm.JAE, x86asm.SETAE:
		return m.not(c)
	case x86asm.JB, x86asm.SETB:
		return c
	case x86asm.JE, x86asm.SETE:
		return z
	case x86asm.JNE, x86asm.SETNE:
		return m.not(z)
	case x86asm.JL, x86asm.SETL:
		return l
	case x86asm.JGE, x86asm.SETGE:
		return m.not(l)
	case x86asm.JLE, x86asm.SETLE:
		return m.or(z, l)
	case x86asm.JG, x86asm.SETG:
		return m.not(m.or(z, l))
	}
	m.err = refuse(m.pc, "relation-semantics", "missing condition relation")
	return br.Term{}
}

// transfer is a different abstract domain over the same checked operations.
// checkGraph has already validated every operand form, alias width, memory/effect
// exclusion, flag prerequisite and preservation condition. No mnemonic or form
// is admitted here independently of that authority.
func (m *valueBuilder) transfer(pc uint64, i operation, s *symbolicState) error {
	if condition(i.Op) != 0 {
		if _, branch := i.Args[0].(x86asm.Rel); branch {
			return nil
		}
		a, _ := register(i.Args[0].(x86asm.Reg))
		m.write(s, a, m.make(br.BoolToBits, br.Bits(8), 0, m.predicate(i.Op, *s)))
		return m.err
	}
	switch i.Op {
	case x86asm.RET, x86asm.JMP, x86asm.NOP:
		return nil
	}
	a, _ := register(i.Args[0].(x86asm.Reg))
	left := m.read(s, a)
	if i.Op == x86asm.LEA {
		mem := i.Args[1].(x86asm.Mem)
		v := m.con(br.Bits(a.width), uint64(mem.Disp)&mask(a.width))
		for j, reg := range []x86asm.Reg{mem.Base, mem.Index} {
			if reg == 0 {
				continue
			}
			ref, _ := register(reg)
			x := m.extract(s.regs[ref.reg], 0, a.width)
			if j == 1 {
				x = m.make(br.Shl, br.Bits(a.width), uint64(bits.TrailingZeros8(mem.Scale)), x)
			}
			v = m.binary(br.Add, v, x)
		}
		m.write(s, a, v)
		return m.err
	}
	if i.Op == x86asm.SHR {
		count := int(uint64(i.Args[1].(x86asm.Imm)) & uint64(a.width-1))
		v := m.make(br.LShr, br.Bits(a.width), uint64(count), left)
		if count != 0 {
			s.flags[flagCarry] = m.make(br.Nonzero, br.Bool(), 0, m.extract(left, count-1, 1))
			s.flags[flagZero] = m.compare(br.Equal, v, m.con(v.Sort(), 0))
			if count == 1 {
				s.flags[flagLess] = m.different(m.sign(v), m.sign(left))
			} else {
				// OF is undefined, hence SF != OF is arbitrary. The effect
				// checker refuses consuming it until flags are redefined.
				s.flags[flagLess] = m.scratch(br.Bool())
			}
		}
		m.write(s, a, v)
		return m.err
	}
	var right br.Term
	switch arg := i.Args[1].(type) {
	case x86asm.Reg:
		ref, _ := register(arg)
		right = m.read(s, ref)
	case x86asm.Imm:
		right = m.con(br.Bits(a.width), uint64(arg)&mask(a.width))
	default:
		return refuse(pc, "relation-semantics", "missing checked operand relation")
	}
	var v br.Term
	switch i.Op {
	case x86asm.MOV:
		m.write(s, a, right)
		return m.err
	case x86asm.ADD:
		v = m.binary(br.Add, left, right)
	case x86asm.SUB:
		v = m.binary(br.Sub, left, right)
	case x86asm.CMP:
		s.flags[flagCarry] = m.compare(br.ULT, left, right)
		s.flags[flagZero] = m.compare(br.Equal, left, right)
		s.flags[flagLess] = m.compare(br.SLT, left, right)
		return m.err
	case x86asm.AND, x86asm.TEST:
		v = m.binary(br.BitAnd, left, right)
	case x86asm.XOR:
		v = m.binary(br.BitXor, left, right)
	default:
		return refuse(pc, "relation-semantics", "checked operation lacks a value rule")
	}
	s.flags[flagZero] = m.compare(br.Equal, v, m.con(v.Sort(), 0))
	switch i.Op {
	case x86asm.SUB:
		s.flags[flagCarry] = m.compare(br.ULT, left, right)
		s.flags[flagLess] = m.compare(br.SLT, left, right)
	case x86asm.ADD:
		s.flags[flagCarry] = m.compare(br.ULT, v, left)
		sign, leftSign, rightSign := m.sign(v), m.sign(left), m.sign(right)
		overflow := m.and(m.compare(br.Equal, leftSign, rightSign), m.different(sign, leftSign))
		s.flags[flagLess] = m.different(sign, overflow)
	default:
		s.flags[flagCarry] = m.falsity
		s.flags[flagLess] = m.sign(v) // Logical operations clear OF.
	}
	if i.Op != x86asm.TEST {
		m.write(s, a, v)
	}
	return m.err
}
