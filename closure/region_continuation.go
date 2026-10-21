package closure

import (
	"context"
	"go/constant"
	"go/token"
	"go/types"
	"maps"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// These events describe a finite isolated typed region, not an arbitrary
// language effect summary. Each access comes from an actual typed operation or
// an independently checked reference at its exact call. Private reference-frame
// accesses remain in that reference's evidence rather than in this projection.
type regionEffectAccess struct {
	regionEffectOccurrence
	location regionLocation
	write    bool
	value    regionValue
	locked   bool
}

// Allocation is a language initialization/lifetime event, not an ordinary store
// or a claim about native bytes. The initializer can contain typed unknown leaves.
// Identity, storage type and cardinality use the existing object/context model.
// No lifetime end is inferred from an SSA value's last syntactic use.
type regionEffectAllocation struct {
	regionEffectOccurrence
	location    regionLocation
	initializer regionValue
}

type regionExcludedEdge struct {
	regionEffectOccurrence
	branch    *ssa.If
	successor *ssa.BasicBlock
	condition bool
}

type regionCallApplication struct {
	proof   *regionCallProof
	outcome regionObservation
}

type regionEffectTrace struct {
	owner        *regionOccurrenceOwner
	accesses     []regionEffectAccess
	allocations  []regionEffectAllocation
	atomics      []regionAtomicOccurrence
	calls        []regionCallApplication
	instructions []regionEffectOccurrence
	excluded     []regionExcludedEdge
	seen         map[regionEffectOccurrence]bool
}

// The application binds the selected reference and invocation; the occurrence
// retains its actual statement and the corresponding complete trace indices.
type regionAtomicOccurrence struct {
	application *regionCallProof
	atomic      assemblyReferenceAtomic
}

type regionEffectOccurrence struct {
	instruction ssa.Instruction
	invocation  regionInvocation
	owner       *regionOccurrenceOwner
	ordinal     uint64
}

// An executed occurrence in the retained predecessor cannot be executed again by a
// continuation. Static instructions may recur only along independently checked
// CFG edges and then receive the next ordinal. The flattened checked instruction
// order, including child entries/returns, supplies a strictly decreasing remaining
// instruction rank; complete occurrence closure separately rules out truncation.
func (k *regionKernel) effectTransfer(state regionState, instruction ssa.Instruction) error {
	if err := k.meter.tick(); err != nil {
		return err
	}
	occurrence := k.boundaryOccurrence(instruction)
	if occurrence.owner == nil || k.trace.seen[occurrence] {
		return regionError("effect scope lacks an owner or repeats an executed occurrence")
	}
	if k.next >= uint64(k.meter.limits.nodes) || len(k.trace.instructions) >= k.meter.limits.nodes {
		return regionError("effect occurrence budget exhausted")
	}
	k.trace.seen[occurrence] = true
	k.trace.instructions = append(k.trace.instructions, occurrence)
	k.current = occurrence
	k.next++
	var address ssa.Value
	var value regionValue
	write := false
	switch x := instruction.(type) {
	case *ssa.DebugRef, *ssa.Jump, *ssa.Phi:
		return nil
	case *ssa.Alloc:
		object := regionObject{kind: regionAllocation, site: x, context: k.input.root, invocation: k.invocation}
		if !k.singleton(object) {
			return regionError("finite effect allocation is not a fresh singleton")
		}
		return nil
	case *ssa.MakeChan:
		object := regionObject{kind: regionChannelAllocation, site: x, context: k.input.root, invocation: k.invocation}
		if !k.singleton(object) {
			return regionError("finite effect channel allocation is not a fresh singleton")
		}
		return nil
	case *ssa.FieldAddr, *ssa.IndexAddr:
		// The ordinary typed transfer checks bounds and storage provenance;
		// allocation emits its initializer only after deriving it there.
		return nil
	case *ssa.Field, *ssa.Index, *ssa.Extract, *ssa.ChangeType, *ssa.Convert:
		// Projection consumes the selected value, not every sibling in the
		// aggregate being transported. Its typed transfer checks the selection.
		// The ordinary transfer checks the actual projected result in set.
		return nil
	case *ssa.If:
		_, known := regionBool(k.value(state, x.Cond))
		if !known {
			return regionError("finite effect scope has an unresolved branch condition")
		}
		return nil
	case *ssa.BinOp:
		if regionIntegerOperation(x) {
			return k.effectOperands(state, instruction)
		}
		if !regionIsComparison(x.Op) {
			return regionError("finite effect scope requires a supported comparison")
		}
		if err := k.effectComparisonValue(k.value(state, x.X), 0); err != nil {
			return err
		}
		return k.effectComparisonValue(k.value(state, x.Y), 0)
	case *ssa.Call:
		if k.cycle[x.Block()] {
			return regionError("finite effect scope has a recurrent call site")
		}
		if builtin, ok := x.Call.Value.(*ssa.Builtin); ok && (builtin.Name() == "len" || builtin.Name() == "cap") {
			return k.effectOperands(state, instruction)
		}
		target := x.Call.StaticCallee()
		if x.Call.IsInvoke() || target == nil || len(target.Blocks) == 0 && k.session.references[target] == nil {
			return regionError("finite effect scope call has no checkable body or reference")
		}
		return k.effectOperands(state, instruction)
	case *ssa.Return:
		if !k.fullReturns {
			return regionError("prefix effect scope cannot claim return completion")
		}
		return k.effectOperands(state, instruction)
	case *ssa.Store:
		address, value, write = x.Addr, k.value(state, x.Val), true
	case *ssa.UnOp:
		if x.Op == token.NOT {
			return k.effectOperands(state, instruction)
		}
		if x.Op != token.MUL {
			return regionError("finite effect scope has an unsupported unary operation")
		}
		address = x.X
	default:
		return regionError("operation is outside the finite typed effect relation")
	}
	pointer := k.value(state, address)
	if pointer.kind != regionPointer || k.locationType(pointer.location) == nil || !k.singleton(pointer.location.object) {
		return regionError("finite effect access lacks exact singleton typed provenance")
	}
	if !write {
		value = k.readLocation(state, pointer.location, instruction.(ssa.Value).Type())
	}
	if err := k.effectValue(value); err != nil {
		return err
	}
	return k.addEffectAccess(regionEffectAccess{regionEffectOccurrence: occurrence, location: pointer.location, write: write, value: value})
}

// Unknown supported scalar values remain universally quantified. Unsupported
// scalar leaves may be initialized and copied inside aggregates. Evaluating an
// unsupported scalar itself is outside the finite effect grammar. Comparisons
// additionally inspect the by-value leaves they consume, even for an unknown
// aggregate whose abstract value has no element inventory.
func (k *regionKernel) effectValue(value regionValue) error {
	if err := k.meter.tick(); err != nil {
		return err
	}
	if regionOpaqueScalarType(value.typ) && value.kind != regionFloat {
		return regionError("finite effect scope consumes an unsupported scalar")
	}
	return nil
}

func (k *regionKernel) effectComparisonValue(value regionValue, depth int) error {
	if err := k.effectValue(value); err != nil {
		return err
	}
	if depth > k.meter.limits.depth {
		return regionError("effect comparison type depth exhausted")
	}
	child := func(typ types.Type, index int) regionValue {
		if value.kind == regionAggregate && index < len(value.elements) {
			return value.elements[index]
		}
		return regionUnknownValue(typ)
	}
	switch t := value.typ.Underlying().(type) {
	case *types.Array:
		if t.Len() != 0 && value.kind != regionAggregate {
			return k.effectComparisonValue(regionUnknownValue(t.Elem()), depth+1)
		}
		for i := range value.elements {
			if err := k.effectComparisonValue(child(t.Elem(), i), depth+1); err != nil {
				return err
			}
		}
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if err := k.meter.tick(); err != nil {
				return err
			}
			if t.Field(i).Name() != "_" {
				if err := k.effectComparisonValue(child(t.Field(i).Type(), i), depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (k *regionKernel) effectOperands(state regionState, instruction ssa.Instruction) error {
	for _, operand := range instruction.Operands(nil) {
		if operand == nil || *operand == nil {
			continue
		}
		if _, builtin := (*operand).(*ssa.Builtin); builtin {
			continue
		}
		if err := k.effectValue(k.value(state, *operand)); err != nil {
			return err
		}
	}
	return nil
}

func (k *regionKernel) referenceLocation(pointer regionValue, target types.Type) (types.Type, error) {
	storage := k.locationType(pointer.location)
	view, ok := pointer.typ.Underlying().(*types.Pointer)
	if pointer.kind != regionPointer || !ok || !types.Identical(view.Elem(), target) || !k.storageView(pointer.location, target) || !k.singleton(pointer.location.object) {
		return nil, k.storageViewError("reference access lacks exact singleton typed provenance")
	}
	if pointer.location.object.kind == regionGlobal {
		global := pointer.location.object.site.(*ssa.Global) // locationType established its owner and kind.
		object, ok := global.Object().(*types.Var)
		if !ok || object.Pkg() != global.Pkg.Pkg || object.Parent() != global.Pkg.Pkg.Scope() || object.Parent().Lookup(object.Name()) != object {
			return nil, regionError("global access has no exact selected typed declaration")
		}
	}
	for _, step := range pointer.location.path {
		if step.summary {
			return nil, regionError("reference access has an inexact subobject path")
		}
	}
	return storage, nil
}

func (k *regionKernel) addEffectAccess(access regionEffectAccess) error {
	if err := k.meter.tick(); err != nil {
		return err
	}
	if len(k.trace.accesses) >= k.meter.limits.nodes {
		return regionError("effect access budget exhausted")
	}
	k.trace.accesses = append(k.trace.accesses, access)
	return nil
}

// regionProofContext charges the subordinate universal evaluator's cancellation
// checkpoints to the same enclosing work account. It never changes the meaning
// of cancellation or obtains a private uncancellable context.
type regionProofContext struct {
	context.Context
	meter *regionMeter
}

func (c regionProofContext) Err() error { return c.meter.tick() }

// Width is the selected reference ABI's extent, not a host word size. Negative
// language integers become precisely that extent's two's-complement bit pattern.
func regionReferenceWord(value regionValue, width int) (uint64, bool) {
	if value.typ == nil || value.kind != regionConstant || value.scalar == nil || value.scalar.Kind() != constant.Int || width < 1 || width > 8 {
		return 0, false
	}
	basic, ok := value.typ.Underlying().(*types.Basic)
	if !ok || basic.Info()&types.IsInteger == 0 {
		return 0, false
	}
	shift := 64 - width*8
	mask := ^uint64(0) >> shift
	if basic.Info()&types.IsUnsigned == 0 {
		n, ok := constant.Int64Val(value.scalar)
		return uint64(n) & mask, ok && int64(uint64(n)<<shift)>>shift == n
	}
	n, ok := constant.Uint64Val(value.scalar)
	return n, ok && n <= mask
}

func regionReferenceValue(bits uint64, typ types.Type, width int) (regionValue, error) {
	if typ == nil || width < 1 || width > 8 || bits > ^uint64(0)>>(64-width*8) {
		return regionValue{}, regionError("reference value exceeds its selected extent")
	}
	basic, ok := typ.Underlying().(*types.Basic)
	if !ok || basic.Info()&types.IsInteger == 0 {
		return regionValue{}, regionError("reference value lacks a selected integer interpretation")
	}
	value := regionValue{typ: typ, kind: regionConstant, scalar: constant.MakeUint64(bits)}
	if basic.Info()&types.IsUnsigned == 0 {
		shift := 64 - width*8
		value.scalar = constant.MakeInt64(int64(bits<<shift) >> shift)
	}
	return value, nil
}

func (k *regionKernel) callReference(call *ssa.Call, caller regionState, callable regionValue, actual []regionValue) ([]regionState, error) {
	target := callable.target
	reference := k.session.references[target]
	if reference == nil || k.trace == nil || call.Call.IsInvoke() || call.Call.StaticCallee() != target || len(callable.environment) != 0 || len(actual) < 1 || target.Signature.Params().Len() != len(actual) {
		return nil, regionError("reference substitution lacks its exact call interface")
	}
	if err := reference.boundTo(k.session.source, target); err != nil {
		return nil, err
	}
	for i, argument := range actual {
		if !types.Identical(argument.typ, target.Signature.Params().At(i).Type()) {
			return nil, regionError("reference actual argument type differs")
		}
		if err := k.validateValue(argument, 0); err != nil {
			return nil, err
		}
	}
	frame := reference.checked.relation.frame
	storageType, err := k.referenceLocation(actual[0], frame.targetType)
	if err != nil {
		return nil, err
	}
	if !regionAccessType(storageType, frame.targetType) && !k.liveView(caller, actual[0].location, frame.targetType) {
		return nil, k.storageViewError("reference bit view lacks live storage")
	}
	current, cOK := regionReferenceWord(k.readLocation(caller, actual[0].location, frame.targetType), frame.targetWidth)
	if !cOK {
		return nil, k.storageViewError("reference scalar instantiation is not established")
	}
	words := make([]uint64, len(actual)-1)
	for i, argument := range actual[1:] {
		word, ok := regionReferenceWord(argument, frame.arguments[i+1].width)
		if !ok {
			return nil, regionError("reference scalar argument is not an established word")
		}
		words[i] = word
	}
	id, err := k.invocationAt(call, target)
	if err != nil {
		return nil, err
	}
	var proof *regionCallProof
	for _, candidate := range k.session.proofs {
		if err := k.meter.tick(); err != nil {
			return nil, err
		}
		if candidate.at != call || candidate.target != target || candidate.invocation != id || candidate.caller != k.current || candidate.reference != reference || candidate.selection != k.input.selection || candidate.storageModel != k.input.storageModel || candidate.entries != nil || candidate.occurrences != nil || len(candidate.arguments) != len(actual) {
			continue
		}
		if err := k.validateState(candidate.initial); err != nil {
			return nil, err
		}
		forward, err := k.included(caller, candidate.initial)
		if err != nil {
			return nil, err
		}
		backward, err := k.included(candidate.initial, caller)
		if err != nil {
			return nil, err
		}
		same := forward && backward
		for i, argument := range actual {
			same = same && regionSameValue(argument, candidate.arguments[i])
		}
		if same {
			proof = candidate
			break
		}
	}
	if proof == nil {
		if !k.session.proposing {
			return nil, regionError("missing reference proof at the exact call and incoming heap")
		}
		initial, err := k.clone(caller)
		if err != nil {
			return nil, err
		}
		proof = &regionCallProof{at: call, target: target, invocation: id, caller: k.current, initial: initial, reference: reference, arguments: slices.Clone(actual), storageModel: k.input.storageModel, selection: k.input.selection}
		if len(k.session.proofs) >= k.meter.limits.nodes {
			return nil, regionError("reference proof count exhausted")
		}
		k.session.proofs = append(k.session.proofs, proof)
	}
	result, err := reference.evaluate(regionProofContext{k.meter.ctx, k.meter}, current, words...)
	if err != nil {
		return nil, err
	}
	if !types.Identical(result.Result.typ, call.Type()) {
		return nil, regionError("reference result type differs from the actual call")
	}
	if err := k.validateValue(result.Result, 0); err != nil {
		return nil, err
	}
	after, err := k.clone(caller)
	if err != nil {
		return nil, err
	}
	value, err := regionReferenceValue(result.Value, frame.targetType, frame.targetWidth)
	if err != nil {
		return nil, err
	}
	stored, ok := k.viewValue(value, storageType)
	if !ok {
		return nil, regionError("reference result cannot return to canonical typed storage")
	}
	location := actual[0].location
	after.memory[location.object] = regionReplace(after.memory[location.object], location.path, stored)
	after.values[call] = result.Result
	base := len(k.trace.accesses)
	for _, access := range result.Accesses {
		if access.Width != frame.targetWidth {
			return nil, regionError("reference access width differs from selected target")
		}
		value, err := regionReferenceValue(access.Value, frame.targetType, access.Width)
		if err != nil {
			return nil, err
		}
		if err := k.addEffectAccess(regionEffectAccess{regionEffectOccurrence: k.current, location: actual[0].location, write: access.Write, value: value, locked: access.Locked}); err != nil {
			return nil, err
		}
	}
	for _, atomic := range result.Atomics {
		if err := k.meter.tick(); err != nil {
			return nil, err
		}
		if len(k.trace.atomics) >= k.meter.limits.nodes {
			return nil, regionError("atomic occurrence budget exhausted")
		}
		if atomic.Width != frame.targetWidth || atomic.ReadAccess < 0 || atomic.WriteAccess != atomic.ReadAccess+1 || atomic.WriteAccess >= len(result.Accesses) {
			return nil, regionError("reference atomic lacks exact adjacent access ownership")
		}
		read, write := result.Accesses[atomic.ReadAccess], result.Accesses[atomic.WriteAccess]
		if read.Write || !write.Write || !read.Locked || !write.Locked || read.Width != atomic.Width || write.Width != atomic.Width {
			return nil, regionError("reference atomic access interpretation differs")
		}
		atomic.ReadAccess += base
		atomic.WriteAccess += base
		k.trace.atomics = append(k.trace.atomics, regionAtomicOccurrence{application: proof, atomic: atomic})
	}
	// Retained call-time evidence must not share mutable maps with subsequent
	// caller transfers. Values and aggregate paths retain their existing copy-on-write ownership.
	outcome, err := k.clone(after)
	if err != nil {
		return nil, err
	}
	k.trace.calls = append(k.trace.calls, regionCallApplication{proof: proof, outcome: regionObservation{value: result.Result, state: outcome}})
	k.session.used = append(k.session.used, proof)
	return []regionState{after}, nil
}

// checkSourceOperandContinuation starts with the opaque predecessor's checked
// current state. No initial heap, expected result, root, selection or resource
// allowance is supplied by the caller. The new call is an untrusted endpoint.
func checkSourceOperandContinuation(ctx context.Context, predecessor sourceResumablePrefix, call *ssa.Call, references map[*ssa.Function]*assemblyReference) (*sourceOperandPrefix, error) {
	if call == nil || call.Block() == nil || call.Call.IsInvoke() || call.Call.StaticCallee() == nil {
		return nil, regionError("continuation endpoint is not an actual consuming call")
	}
	checked, err := checkSourceEffectContinuation(ctx, predecessor, regionUse{at: regionPoint{call.Block(), slices.Index(call.Block().Instrs, ssa.Instruction(call))}, operand: regionCallBoundaryOperand(call)}, false, references)
	if err != nil {
		return nil, err
	}
	callee, err := checked.binder.bindDeclaration(call.Call.StaticCallee())
	if err != nil {
		return nil, err
	}
	packet := checked.region.packet
	var operands []regionValue
	for _, argument := range call.Call.Args {
		value := checked.checker.value(packet.observations[0].state, argument)
		if err := checked.checker.validateValue(value, 0); err != nil {
			return nil, err
		}
		operands = append(operands, value)
	}
	if err := checked.checker.meter.tick(); err != nil {
		return nil, err
	}
	packet.usage = *checked.checker.meter
	packet.usage.ctx = nil
	core := &sourceEffectPrefix{region: checked.region, binder: checked.binder, checker: checked.checker, prior: checked.prior, boundary: call, cursor: packet.observations[0].occurrence}
	core.self = core
	prefix := &sourceOperandPrefix{sourceEffectPrefix: core, callee: callee, call: call, operands: operands}
	prefix.self = prefix
	return prefix, nil
}

// sourceReturnCompletion includes execution of the selected source return. It
// cannot be used as an operand prefix or resumed inside the completed invocation.
// Native return completion and actual caller applicability remain separate.
type sourceReturnCompletion struct {
	occurrence regionEffectOccurrence
	region     *sourceRegion
	prior      *sourceEffectPrefix
	returned   *ssa.Return
	checker    *regionKernel
	self       *sourceReturnCompletion
}

func (r *sourceReturnCompletion) checkedPacket() *checkedRegion {
	if r == nil || r.self != r || r.prior.checkedPacket() == nil {
		return nil
	}
	packet := checkedSourceEffectPacket(r.region, r.checker)
	if packet == nil || !r.checker.fullReturns || r.prior != r.checker.session.predecessor || len(packet.observations) != 1 || r.occurrence != packet.observations[0].occurrence || r.occurrence.instruction != r.returned || !packet.trace.seen[r.occurrence] || r.occurrence.owner != r.prior.cursor.owner || regionInstruction(packet.input.use.at) != r.returned || packet.input.root != r.prior.region.packet.input.root || packet.input.selection != r.prior.region.packet.input.selection || packet.input.storageModel != r.prior.region.packet.input.storageModel {
		return nil
	}
	return packet
}

func (r *sourceReturnCompletion) liveAllocation(object regionObject, tick func() error) (regionEffectAllocation, bool, error) {
	packet := r.checkedPacket()
	if packet == nil {
		return regionEffectAllocation{}, false, nil
	}
	return liveRegionAllocation(packet, r.checker, r.prior, object, tick)
}

func checkSourceReturnContinuation(ctx context.Context, predecessor sourceResumablePrefix, returned *ssa.Return, references map[*ssa.Function]*assemblyReference) (*sourceReturnCompletion, error) {
	if returned == nil || returned.Block() == nil || len(returned.Results) != 0 {
		return nil, regionError("source return completion requires an actual void return")
	}
	checked, err := checkSourceEffectContinuation(ctx, predecessor, regionUse{at: regionPoint{returned.Block(), slices.Index(returned.Block().Instrs, ssa.Instruction(returned))}}, true, references)
	if err != nil {
		return nil, err
	}
	complete := &sourceReturnCompletion{region: checked.region, prior: checked.prior, returned: returned, checker: checked.checker, occurrence: checked.region.packet.observations[0].occurrence}
	complete.self = complete
	return complete, nil
}

// checkSourceInstructionContinuation stops before an actual non-call,
// non-return instruction. The kernel checks the supplied operand's membership
// and owner; nil observations and invented expected values confer no authority.
func checkSourceInstructionContinuation(ctx context.Context, predecessor sourceResumablePrefix, use regionUse, references map[*ssa.Function]*assemblyReference) (*sourceEffectPrefix, error) {
	switch regionInstruction(use.at).(type) {
	case nil, *ssa.Call, *ssa.Return:
		return nil, regionError("instruction prefix requires an actual non-call, non-return boundary")
	}
	checked, err := checkSourceEffectContinuation(ctx, predecessor, use, false, references)
	if err != nil {
		return nil, err
	}
	prefix := &sourceEffectPrefix{region: checked.region, binder: checked.binder, checker: checked.checker, prior: checked.prior, boundary: regionInstruction(use.at), cursor: checked.region.packet.observations[0].occurrence}
	prefix.self = prefix
	return prefix, nil
}

// The shared check result has no resumable authority. Its constructor turns it
// into either an unexecuted prefix or a consumed return, never both.
type sourceEffectContinuation struct {
	region  *sourceRegion
	binder  *selectedSourceBinder
	checker *regionKernel
	prior   *sourceEffectPrefix
}

// All endpoint kinds share the same current-state, ownership and work account.
// Only a return endpoint enables complete-return checking; it is then consumed
// by the interpreter rather than treated as an unexecuted operand observation.
func checkSourceEffectContinuation(ctx context.Context, receipt sourceResumablePrefix, use regionUse, completion bool, references map[*ssa.Function]*assemblyReference) (*sourceEffectContinuation, error) {
	predecessor := checkedSourcePrefix(receipt)
	endpoint := regionInstruction(use.at)
	if ctx == nil || predecessor == nil || endpoint == nil {
		return nil, regionError("missing source continuation predecessor or endpoint")
	}
	prior := predecessor.region.packet
	if prior.rules != regionRules || len(prior.observations) != 1 || endpoint.Block() == nil || endpoint.Parent() != prior.input.root || endpoint == predecessor.boundary || !prior.usage.limits.valid() || len(references) > prior.usage.limits.nodes {
		return nil, regionError("source continuation scope or cumulative account differs")
	}
	ownedReferences := maps.Clone(references)
	meter := prior.usage
	meter.ctx = ctx
	for target, reference := range ownedReferences {
		if err := meter.tick(); err != nil {
			return nil, err
		}
		if reference == nil {
			return nil, regionError("missing checked assembly reference")
		}
		if err := reference.boundTo(predecessor.binder.source, target); err != nil {
			return nil, err
		}
	}
	at := slices.Index(endpoint.Block().Instrs, endpoint)
	if at < 0 {
		return nil, regionError("continuation endpoint is not an actual instruction")
	}
	in := prior.input
	in.entry, in.use = prior.input.use.at, use
	in.initial = prior.observations[0].state
	in, _, err := regionCaptureMeter(in, nil, &meter)
	if err != nil {
		return nil, err
	}
	newKernel := func(input regionInput) (*regionKernel, error) {
		session := newRegionCallSession(ctx, input, meter.limits)
		session.meter, session.references, session.source = &meter, ownedReferences, predecessor.binder.source
		session.predecessor = predecessor
		for id, facts := range prior.contexts {
			if err := meter.tick(); err != nil {
				return nil, err
			}
			session.contexts[id] = facts
		}
		k, err := newRegionContextKernel(input, session, regionInvocation{}, completion)
		if err != nil {
			return nil, err
		}
		k.trace = &regionEffectTrace{owner: predecessor.cursor.owner, seen: map[regionEffectOccurrence]bool{}}
		k.next = predecessor.cursor.ordinal
		for p := predecessor; p != nil; p = p.prior {
			if err := meter.tick(); err != nil {
				return nil, err
			}
			packet := p.region.packet
			if packet.trace != nil {
				for _, instruction := range packet.trace.instructions {
					if err := meter.tick(); err != nil {
						return nil, err
					}
					k.trace.seen[instruction] = true
				}
			}
		}
		if k.boundaryOccurrence(predecessor.boundary) != predecessor.cursor || k.trace.seen[predecessor.cursor] {
			return nil, regionError("continuation does not inherit its exact unexecuted cursor")
		}
		return k, nil
	}
	proposer, err := newKernel(in)
	if err != nil {
		return nil, err
	}
	proposal, err := proposeRegionKernel(proposer)
	if err != nil {
		return nil, err
	}
	in, proposal, err = regionCaptureMeter(in, proposal, &meter)
	if err != nil {
		return nil, err
	}
	checker, err := newKernel(in)
	if err != nil {
		return nil, err
	}
	packet, err := checkRegionKernel(checker, proposal)
	if err != nil {
		return nil, err
	}
	if len(packet.observations) != 1 {
		return nil, regionError("finite continuation does not have one complete current state")
	}
	if completion {
		rootReturns := 0
		for _, occurrence := range packet.trace.instructions {
			if err := meter.tick(); err != nil {
				return nil, err
			}
			if _, ok := occurrence.instruction.(*ssa.Return); ok && occurrence.invocation == (regionInvocation{}) {
				if occurrence.instruction != endpoint {
					return nil, regionError("source returned through a different endpoint")
				}
				rootReturns++
			}
		}
		if rootReturns != 1 {
			return nil, regionError("source completion did not execute its actual return")
		}
	}
	binder, err := continueSourceBinder(ctx, predecessor.binder)
	if err != nil {
		return nil, err
	}
	selected, err := binder.checkSourceRegion(packet)
	if err != nil {
		return nil, err
	}
	if err := meter.tick(); err != nil {
		return nil, err
	}
	packet.usage = meter
	packet.usage.ctx = nil
	return &sourceEffectContinuation{region: selected, binder: binder, checker: checker, prior: predecessor}, nil
}

// The binder's selected objects and cached entries are immutable; its mutable
// containers and counters belong to each continuation branch independently.
func continueSourceBinder(ctx context.Context, predecessor *selectedSourceBinder) (*selectedSourceBinder, error) {
	b := *predecessor
	b.ctx = ctx
	b.pkgs, b.metas = maps.Clone(b.pkgs), maps.Clone(b.metas)
	b.packages, b.bound, b.callables = maps.Clone(b.packages), maps.Clone(b.bound), maps.Clone(b.callables)
	for range len(b.pkgs) + len(b.metas) + len(b.packages) + len(b.bound) + len(b.callables) {
		if err := b.tick(nil, token.NoPos); err != nil {
			return nil, err
		}
	}
	return &b, nil
}
