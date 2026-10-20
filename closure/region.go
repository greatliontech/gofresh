package closure

import (
	"context"
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

const regionRules = "gofresh/source-region-transport@12"

// This kernel is conditional on an immutable, well-typed SSA owner. Selection of
// that owner from source/build inputs is a separate obligation. It never invokes
// a caller-supplied effect oracle or grants application/native authority.
//
// States are disjunctions of WHOLE heaps and environments. Joining individual
// fields would lose the correlation between a registration name and its callback.
// Exceeding the disjunction bound widens the whole state, never constructs a
// Cartesian product that could subsequently be mistaken for exact rows.
type regionKind uint8

const (
	regionUnknown regionKind = iota
	regionConstant
	regionNil
	regionPointer
	regionSlice
	regionCallable
	regionInterface
	regionAggregate
	regionFloat
	regionUnsafePointer
)

type regionObjectKind uint8

const (
	regionGlobal regionObjectKind = iota
	regionAllocation
	regionClosureEnvironment
	regionFormal
	regionUnknownObject
)

// Object identity includes the allocating function context. Allocations in a
// control-flow cycle, formal objects and unknown objects are summaries. Closure
// environments are retained with the callable, including captured cell aliases.
type regionObject struct {
	kind       regionObjectKind
	site       ssa.Value
	context    *ssa.Function
	invocation regionInvocation
}

type regionStep struct {
	field   bool
	index   int64
	summary bool
}

type regionLocation struct {
	object regionObject
	path   []regionStep
}

type regionValue struct {
	// For pointers, typ is the access view. The canonical storage type is
	// derived from location's object/path, never a second mutable type field.
	typ         types.Type
	kind        regionKind
	scalar      constant.Value
	floatBits   uint64
	location    regionLocation
	start       int64
	length      int64
	capacity    int64
	target      *ssa.Function
	environment []regionValue
	elements    []regionValue
}

// An absent register or object is unknown, not bottom or zero. In particular an
// input heap cannot silently assert zero initialization of a selected global.
type regionState struct {
	values map[ssa.Value]regionValue
	memory map[regionObject]regionValue
}

type regionPoint struct {
	block *ssa.BasicBlock
	index int // boundary immediately BEFORE this actual instruction
}

// operand is the actual SSA operand of the instruction at at, not a replacement
// expression or a table found by name. A nil operand is allowed only at a void
// Return, for a conditional heap-construction lemma.
type regionUse struct {
	at      regionPoint
	operand ssa.Value
}

type regionInput struct {
	owner   *ssa.Program
	root    *ssa.Function
	entry   regionPoint
	use     regionUse
	initial regionState
	// A distinct conditional storage antecedent. It is never inferred from the
	// selected sizes, string premises or an observed machine/build label.
	storageModel regionStorageModel
	// These are antecedents, never derived assertions. Even an empty initial heap
	// retains the omitted-prefix/frame obligation when entry is a mid-body cut.
	premises []string
}

// All dimensions bound both proposal and checking. Defaults are deliberately
// small; reaching any work/storage bound refuses rather than accepting a prefix.
// alternatives is the whole-state widening threshold, not a truncated path
// count: crossing it replaces the disjunction by top.
type regionLimits struct {
	nodes, states, locations, alternatives, depth, work int
}

func defaultRegionLimits() regionLimits {
	return regionLimits{nodes: 4096, states: 4096, locations: 4096, alternatives: 32, depth: 32, work: 200000}
}

func (l regionLimits) valid() bool {
	return l.nodes > 0 && l.nodes <= 65536 && l.states > 0 && l.states <= 65536 &&
		l.locations > 0 && l.locations <= 65536 && l.alternatives > 0 && l.alternatives <= 256 &&
		l.depth > 0 && l.depth <= 128 && l.work > 0 && l.work <= 10000000
}

type regionProposal struct {
	input   regionInput
	entries map[*ssa.BasicBlock][]regionState
	calls   []*regionCallProof
}

type regionObservation struct {
	value regionValue
	state regionState
}

// checkedRegion owns every mutable proposal/input container. Its only authority
// is the conditional transfer over this exact scope. SSA/type objects belong to
// the immutable typed owner, not to this packet. There is no endpoint setter.
// Observations may contain unknowns. Possession of the packet is not an exact
// row/operand fact: a consumer must establish its required relation for EVERY
// observation, including the reachable heap and captured environments.
type checkedRegion struct {
	rules        string
	input        regionInput
	observations []regionObservation
	// Only bodies actually checked under their actual input states appear here.
	// Their selected-source and native bindings remain composition obligations.
	calls []*regionCallProof
	// Optional complete finite typed-effect coverage. Retained events come from
	// independently checked transfers; provisional proposer events are discarded.
	trace    *regionEffectTrace
	usage    regionMeter
	contexts map[regionInvocation]regionContextFacts
}

// openObligations is deliberately not a single "closed" bit. The assembly must
// establish each applicable boundary independently before using a local fact.
func (*checkedRegion) openObligations() []string {
	return []string{"selected-source/build binding", "entry-state and omitted-prefix/frame premises", "consuming call and continuation", "concurrency and harness scope", "native correspondence and runtime applicability"}
}

func regionError(message string) error { return fmt.Errorf("source-region transport: %s", message) }

// Keep the actual failed operation and its enclosing call chain for consumers
// that need scoped refusals. Diagnostic text is not an operation classifier.
type regionOperationFailure struct {
	instruction ssa.Instruction
	cause       error
}

func (f *regionOperationFailure) Error() string { return f.cause.Error() }
func (f *regionOperationFailure) Unwrap() error { return f.cause }

type regionMeter struct {
	ctx                 context.Context
	limits              regionLimits
	work, nodes, states int
	locations           int
}

func (m *regionMeter) tick() error {
	if m.ctx != nil {
		if err := m.ctx.Err(); err != nil {
			return err
		}
	}
	m.work++
	if m.work > m.limits.work {
		return regionError("work budget exhausted")
	}
	return nil
}

// Capture is bounded before calling even Context.Err: a custom context can
// mutate caller-owned slices/maps. Cancellation is checked before graph or
// lattice expansion. The immutable SSA owner is a retained input premise.
func regionCapture(input regionInput, proposal *regionProposal, limits regionLimits) (regionInput, *regionProposal, error) {
	return regionCaptureMeter(input, proposal, &regionMeter{limits: limits})
}

func regionCaptureMeter(input regionInput, proposal *regionProposal, m *regionMeter) (regionInput, *regionProposal, error) {
	limits := m.limits
	if !limits.valid() {
		return regionInput{}, nil, regionError("invalid budget")
	}
	copyInput := func(in regionInput) (regionInput, error) {
		if len(in.premises) > limits.nodes {
			return regionInput{}, regionError("premise budget exhausted")
		}
		in.premises = slices.Clone(in.premises)
		var err error
		in.initial, err = m.copyState(in.initial)
		return in, err
	}
	in, err := copyInput(input)
	if err != nil || proposal == nil {
		return in, nil, err
	}
	if len(proposal.entries) > limits.nodes || len(proposal.calls) > limits.nodes-len(proposal.entries) {
		return regionInput{}, nil, regionError("node budget exhausted")
	}
	m.nodes += len(proposal.entries) + len(proposal.calls)
	if m.nodes > limits.nodes {
		return regionInput{}, nil, regionError("node budget exhausted")
	}
	p := &regionProposal{entries: make(map[*ssa.BasicBlock][]regionState, len(proposal.entries))}
	p.input, err = copyInput(proposal.input)
	if err != nil {
		return regionInput{}, nil, err
	}
	for block, states := range proposal.entries {
		if len(states) > limits.alternatives {
			return regionInput{}, nil, regionError("alternative budget exhausted")
		}
		for _, state := range states {
			owned, err := m.copyState(state)
			if err != nil {
				return regionInput{}, nil, err
			}
			p.entries[block] = append(p.entries[block], owned)
		}
	}
	if len(proposal.calls) > limits.nodes {
		return regionInput{}, nil, regionError("call proof budget exhausted")
	}
	for _, call := range proposal.calls {
		if err := m.tick(); err != nil {
			return regionInput{}, nil, err
		}
		if call == nil {
			return regionInput{}, nil, regionError("nil call proof")
		}
		copy := *call
		if len(copy.invocation.path) > limits.depth*96 || len(call.arguments) > limits.nodes {
			return regionInput{}, nil, regionError("call context budget exhausted")
		}
		copy.initial, err = m.copyState(call.initial)
		if err != nil {
			return regionInput{}, nil, err
		}
		copy.arguments = slices.Clone(call.arguments)
		for i, argument := range call.arguments {
			copy.arguments[i], err = m.copyValue(argument, 0)
			if err != nil {
				return regionInput{}, nil, err
			}
		}
		if len(call.entries) > limits.nodes-m.nodes {
			return regionInput{}, nil, regionError("callee node budget exhausted")
		}
		m.nodes += len(call.entries)
		copy.entries = make(map[*ssa.BasicBlock][]regionState, len(call.entries))
		for block, states := range call.entries {
			if len(states) > limits.alternatives {
				return regionInput{}, nil, regionError("callee alternative budget exhausted")
			}
			for _, state := range states {
				owned, err := m.copyState(state)
				if err != nil {
					return regionInput{}, nil, err
				}
				copy.entries[block] = append(copy.entries[block], owned)
			}
		}
		p.calls = append(p.calls, &copy)
	}
	return in, p, nil
}

func (m *regionMeter) copyState(s regionState) (regionState, error) {
	m.states++
	if m.states > m.limits.states || len(s.values) > m.limits.locations || len(s.memory) > m.limits.locations {
		return regionState{}, regionError("state/location budget exhausted")
	}
	r := regionState{values: make(map[ssa.Value]regionValue, len(s.values)), memory: make(map[regionObject]regionValue, len(s.memory))}
	for k, v := range s.values {
		v, err := m.copyValue(v, 0)
		if err != nil {
			return regionState{}, err
		}
		r.values[k] = v
	}
	for k, v := range s.memory {
		if len(k.invocation.path) > m.limits.depth*96 {
			return regionState{}, regionError("object call context budget exhausted")
		}
		v, err := m.copyValue(v, 0)
		if err != nil {
			return regionState{}, err
		}
		r.memory[k] = v
	}
	return r, nil
}

func (m *regionMeter) copyValue(v regionValue, depth int) (regionValue, error) {
	if err := m.tick(); err != nil {
		return regionValue{}, err
	}
	m.locations++
	if depth > m.limits.depth || m.locations > m.limits.locations || len(v.location.path) > m.limits.depth || len(v.location.object.invocation.path) > m.limits.depth*96 ||
		len(v.environment) > m.limits.locations || len(v.elements) > m.limits.locations {
		return regionValue{}, regionError("value/location/depth budget exhausted")
	}
	v.location.path = slices.Clone(v.location.path)
	v.environment = slices.Clone(v.environment)
	v.elements = slices.Clone(v.elements)
	for _, values := range [][]regionValue{v.environment, v.elements} {
		for i := range values {
			var err error
			values[i], err = m.copyValue(values[i], depth+1)
			if err != nil {
				return regionValue{}, err
			}
		}
	}
	return v, nil
}

func regionUnknownValue(t types.Type) regionValue { return regionValue{typ: t} }

func regionOpaqueScalarType(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&(types.IsFloat|types.IsComplex) != 0
}

// No host word width participates in this kernel. Word-sized literal facts are
// restricted to the common 32-bit range; larger build-specific numeric facts
// need a separately bound numeric interpretation. Unknown typed words remain
// universally quantified. Exact floats have their own bit representation.
func regionScalarConstant(t types.Type, value constant.Value) bool {
	if t == nil || value == nil {
		return false
	}
	b, ok := t.Underlying().(*types.Basic)
	if !ok {
		return false
	}
	if b.Info()&types.IsBoolean != 0 {
		return value.Kind() == constant.Bool
	}
	if b.Info()&types.IsString != 0 {
		return value.Kind() == constant.String
	}
	if b.Info()&types.IsInteger == 0 || value.Kind() != constant.Int {
		return false
	}
	bits := uint(32)
	switch b.Kind() {
	case types.Int8, types.Uint8:
		bits = 8
	case types.Int16, types.Uint16:
		bits = 16
	case types.Int64, types.Uint64:
		bits = 64
	}
	if b.Info()&types.IsUnsigned != 0 {
		return constant.Sign(value) >= 0 && constant.BitLen(value) <= int(bits)
	}
	bound := constant.Shift(constant.MakeInt64(1), token.SHL, bits-1)
	return constant.Compare(value, token.LSS, bound) && constant.Compare(value, token.GEQ, constant.UnaryOp(token.SUB, bound, 0))
}

func regionSameValue(a, b regionValue) bool {
	if a.kind != b.kind || !types.Identical(a.typ, b.typ) || a.floatBits != b.floatBits || a.target != b.target || a.start != b.start || a.length != b.length || a.capacity != b.capacity ||
		a.location.object != b.location.object || !slices.Equal(a.location.path, b.location.path) || len(a.elements) != len(b.elements) || len(a.environment) != len(b.environment) {
		return false
	}
	if a.scalar == nil != (b.scalar == nil) || a.scalar != nil && (a.scalar.Kind() != b.scalar.Kind() || !constant.Compare(a.scalar, token.EQL, b.scalar)) {
		return false
	}
	for _, pair := range [][2][]regionValue{{a.elements, b.elements}, {a.environment, b.environment}} {
		for i := range pair[0] {
			if !regionSameValue(pair[0][i], pair[1][i]) {
				return false
			}
		}
	}
	return true
}

// Inclusion is intentionally coarse: only a whole unknown value or exact term
// equality covers a value. In particular, independently merged aggregate fields
// are not silently treated as a relational registration invariant.
func regionValueIncluded(a, b regionValue) bool {
	return types.Identical(a.typ, b.typ) && (b.kind == regionUnknown || regionSameValue(a, b))
}

// proposeRegion constructs an untrusted post-fixpoint candidate. Checking does
// not rerun this worklist: it checks initial inclusion and each actual CFG edge.
func proposeRegion(ctx context.Context, input regionInput, limits regionLimits) (*regionProposal, error) {
	in, _, err := regionCapture(input, nil, limits)
	if err != nil {
		return nil, err
	}
	k, err := newRegionKernel(ctx, in, limits)
	if err != nil {
		return nil, err
	}
	return proposeRegionKernel(k)
}

func proposeRegionKernel(k *regionKernel) (*regionProposal, error) {
	k.session.proposing = true
	entries, err := k.proposeEntries()
	if err != nil {
		return nil, err
	}
	if err := k.meter.ctx.Err(); err != nil {
		return nil, err
	}
	return &regionProposal{input: k.input, entries: entries, calls: k.session.proofs}, nil
}

func (k *regionKernel) proposeEntries() (map[*ssa.BasicBlock][]regionState, error) {
	in := k.input
	entries := map[*ssa.BasicBlock][]regionState{in.entry.block: {in.initial}}
	queue := []*ssa.BasicBlock{in.entry.block}
	queued := map[*ssa.BasicBlock]bool{in.entry.block: true}
	for len(queue) != 0 {
		block := queue[0]
		queue = queue[1:]
		queued[block] = false
		for _, state := range slices.Clone(entries[block]) {
			edges, _, err := k.block(block, state)
			if err != nil {
				return nil, err
			}
			for _, edge := range edges {
				joined, changed, err := k.join(entries[edge.block], edge.state)
				if err != nil {
					return nil, err
				}
				entries[edge.block] = joined
				if changed && !queued[edge.block] {
					queue = append(queue, edge.block)
					queued[edge.block] = true
				}
			}
		}
	}
	if err := k.meter.ctx.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func regionConst(v *ssa.Const) regionValue {
	if v.IsNil() {
		return regionValue{typ: v.Type(), kind: regionNil}
	}
	if value, ok := regionFloatConstant(v.Type(), v.Value); ok {
		return value
	}
	if regionOpaqueScalarType(v.Type()) {
		return regionUnknownValue(v.Type())
	}
	return regionValue{typ: v.Type(), kind: regionConstant, scalar: v.Value}
}

func regionInt(v regionValue) (int64, bool) {
	if v.kind != regionConstant || v.scalar == nil || v.scalar.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(v.scalar)
}

// Strings use the existing immutable scalar representation. Their extent and
// indices count bytes, including NUL and invalid UTF-8, never decoded runes.
// Capture/ownership validation bounds constant storage before any transfer.
func regionString(v regionValue) (string, bool) {
	if v.kind != regionConstant || v.scalar == nil || v.scalar.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(v.scalar), true
}

func regionBool(v regionValue) (bool, bool) {
	if v.kind != regionConstant || v.scalar == nil || v.scalar.Kind() != constant.Bool {
		return false, false
	}
	return constant.BoolVal(v.scalar), true
}

// readRegionLocation is also useful to an assembly inspecting an owned outcome.
// It never follows an unknown/summary path as if it denoted a particular row and
// grants no integer/float reinterpretation without the kernel's storage model.
func readRegionLocation(state regionState, loc regionLocation, typ types.Type) regionValue {
	v, ok := state.memory[loc.object]
	if !ok {
		return regionUnknownValue(typ)
	}
	for _, step := range loc.path {
		if step.summary || v.kind != regionAggregate || step.index < 0 || step.index >= int64(len(v.elements)) {
			return regionUnknownValue(typ)
		}
		v = v.elements[step.index]
	}
	if viewed, ok := regionViewValue(v, typ); ok {
		return viewed
	}
	return regionUnknownValue(typ)
}

func regionInstruction(point regionPoint) ssa.Instruction {
	if point.block == nil || point.index < 0 || point.index >= len(point.block.Instrs) {
		return nil
	}
	return point.block.Instrs[point.index]
}

func regionIsComparison(op token.Token) bool {
	return op == token.EQL || op == token.NEQ || op == token.LSS || op == token.LEQ || op == token.GTR || op == token.GEQ
}
