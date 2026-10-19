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
	instruction ssa.Instruction
	invocation  regionInvocation
	location    regionLocation
	write       bool
	value       regionValue
	locked      bool
}

// Allocation is a language initialization/lifetime event, not an ordinary store
// or a claim about native bytes. The initializer can contain typed unknown leaves.
// Identity, storage type and cardinality use the existing object/context model.
// No lifetime end is inferred from an SSA value's last syntactic use.
type regionEffectAllocation struct {
	instruction *ssa.Alloc
	invocation  regionInvocation
	location    regionLocation
	initializer regionValue
}

type regionExcludedEdge struct {
	branch     *ssa.If
	invocation regionInvocation
	successor  *ssa.BasicBlock
	condition  bool
}

type regionCallApplication struct {
	proof   *regionCallProof
	outcome regionObservation
}

type regionEffectTrace struct {
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
}

// An instruction in the retained predecessor cannot be executed again by a
// continuation. This is deliberately a finite, acyclic, one-state effect grammar;
// the general inductive region checker remains available without this refinement.
func (k *regionKernel) effectTransfer(state regionState, instruction ssa.Instruction) error {
	if err := k.meter.tick(); err != nil {
		return err
	}
	occurrence := regionEffectOccurrence{instruction, k.invocation}
	if k.trace.seen[occurrence] || len(k.trace.instructions) >= k.meter.limits.nodes {
		return regionError("effect scope repeats an occurrence or exhausts its bound")
	}
	k.trace.seen[occurrence] = true
	k.trace.instructions = append(k.trace.instructions, occurrence)
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
	case *ssa.FieldAddr, *ssa.IndexAddr:
		// The ordinary typed transfer checks bounds and storage provenance;
		// allocation emits its initializer only after deriving it there.
		return nil
	case *ssa.Field, *ssa.Index, *ssa.Extract, *ssa.ChangeType:
		// Projection consumes the selected value, not every sibling in the
		// aggregate being transported. Its typed transfer checks the selection.
		return k.effectValue(regionUnknownValue(instruction.(ssa.Value).Type()))
	case *ssa.If:
		condition, known := regionBool(k.value(state, x.Cond))
		if !known {
			return regionError("finite effect scope has an unresolved branch condition")
		}
		excluded := 0
		if condition {
			excluded = 1
		}
		k.trace.excluded = append(k.trace.excluded, regionExcludedEdge{branch: x, invocation: k.invocation, successor: x.Block().Succs[excluded], condition: condition})
		return nil
	case *ssa.BinOp:
		if !regionIsComparison(x.Op) {
			return regionError("finite effect scope requires a supported comparison")
		}
		return k.effectComparisonType(x.X.Type(), 0)
	case *ssa.Call:
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
		value = readRegionLocation(state, pointer.location, instruction.(ssa.Value).Type())
	}
	if err := k.effectValue(value); err != nil {
		return err
	}
	return k.addEffectAccess(regionEffectAccess{instruction: instruction, invocation: k.invocation, location: pointer.location, write: write, value: value})
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
	if regionOpaqueScalarType(value.typ) {
		return regionError("finite effect scope consumes an unsupported scalar")
	}
	return nil
}

func (k *regionKernel) effectComparisonType(typ types.Type, depth int) error {
	if err := k.effectValue(regionUnknownValue(typ)); err != nil {
		return err
	}
	if depth > k.meter.limits.depth {
		return regionError("effect comparison type depth exhausted")
	}
	switch t := typ.Underlying().(type) {
	case *types.Array:
		if t.Len() != 0 {
			return k.effectComparisonType(t.Elem(), depth+1)
		}
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if err := k.meter.tick(); err != nil {
				return err
			}
			if t.Field(i).Name() != "_" {
				if err := k.effectComparisonType(t.Field(i).Type(), depth+1); err != nil {
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

func (k *regionKernel) effectGlobal(pointer regionValue) (*ssa.Global, error) {
	g, ok := pointer.location.object.site.(*ssa.Global)
	if pointer.kind != regionPointer || pointer.location.object.kind != regionGlobal || len(pointer.location.path) != 0 || !ok || !k.owns(g) || !k.singleton(pointer.location.object) || !types.Identical(k.locationType(pointer.location), types.Typ[types.Uint64]) {
		return nil, regionError("reference access lacks exact singleton uint64 provenance")
	}
	object, ok := g.Object().(*types.Var)
	if !ok || object.Pkg() != g.Pkg.Pkg || object.Parent() != g.Pkg.Pkg.Scope() || object.Parent().Lookup(object.Name()) != object {
		return nil, regionError("global access has no exact selected typed declaration")
	}
	return g, nil
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

func regionReferenceWord(value regionValue) (uint64, bool) {
	if value.kind != regionConstant || value.scalar == nil || value.scalar.Kind() != constant.Int || !assemblyReferenceWordType(value.typ) {
		return 0, false
	}
	if value.typ.Underlying().(*types.Basic).Kind() == types.Int64 {
		n, ok := constant.Int64Val(value.scalar)
		return uint64(n), ok
	}
	return constant.Uint64Val(value.scalar)
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
	if _, err := k.effectGlobal(actual[0]); err != nil {
		return nil, err
	}
	current, cOK := regionUint64(readRegionLocation(caller, actual[0].location, types.Typ[types.Uint64]))
	if !cOK {
		return nil, regionError("reference scalar instantiation is not established")
	}
	words := make([]uint64, len(actual)-1)
	for i, argument := range actual[1:] {
		word, ok := regionReferenceWord(argument)
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
		if candidate.at != call || candidate.target != target || candidate.invocation != id || candidate.reference != reference || len(candidate.entries) != 0 || len(candidate.arguments) != len(actual) {
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
		proof = &regionCallProof{at: call, target: target, invocation: id, initial: initial, reference: reference, arguments: slices.Clone(actual)}
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
	after.memory[actual[0].location.object] = regionValue{typ: types.Typ[types.Uint64], kind: regionConstant, scalar: constant.MakeUint64(result.Value)}
	after.values[call] = result.Result
	base := len(k.trace.accesses)
	for _, access := range result.Accesses {
		value := regionValue{typ: types.Typ[types.Uint64], kind: regionConstant, scalar: constant.MakeUint64(access.Value)}
		if err := k.addEffectAccess(regionEffectAccess{instruction: call, invocation: k.invocation, location: actual[0].location, write: access.Write, value: value, locked: access.Locked}); err != nil {
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
		atomic.ReadAccess += base
		atomic.WriteAccess += base
		k.trace.atomics = append(k.trace.atomics, regionAtomicOccurrence{application: proof, atomic: atomic})
	}
	k.trace.calls = append(k.trace.calls, regionCallApplication{proof: proof, outcome: regionObservation{value: result.Result, state: after}})
	k.session.used = append(k.session.used, proof)
	return []regionState{after}, nil
}

// checkSourceOperandContinuation starts with the opaque predecessor's checked
// current state. No initial heap, expected result, root, selection or resource
// allowance is supplied by the caller. The new call is an untrusted endpoint.
func checkSourceOperandContinuation(ctx context.Context, predecessor *sourceOperandPrefix, call *ssa.Call, references map[*ssa.Function]*assemblyReference) (*sourceOperandPrefix, error) {
	if call == nil || call.Call.IsInvoke() || call.Call.StaticCallee() == nil {
		return nil, regionError("continuation endpoint is not an actual consuming call")
	}
	checked, err := checkSourceEffectContinuation(ctx, predecessor, call, references)
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
	return &sourceOperandPrefix{region: checked.region, callee: callee, call: call, operands: operands, prior: predecessor, binder: checked.binder, checker: checked.checker}, nil
}

// sourceReturnCompletion includes execution of the selected source return. It
// cannot be used as an operand prefix or resumed inside the completed invocation.
// Native return completion and actual caller applicability remain separate.
type sourceReturnCompletion struct {
	region   *sourceRegion
	prior    *sourceOperandPrefix
	returned *ssa.Return
	checker  *regionKernel
}

func (r *sourceReturnCompletion) checkedPacket() *checkedRegion {
	if r == nil || r.prior.checkedPacket() == nil {
		return nil
	}
	packet := checkedSourceEffectPacket(r.region, r.checker)
	if packet == nil || !r.checker.fullReturns || regionInstruction(packet.input.use.at) != r.returned || packet.input.root != r.prior.region.packet.input.root {
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

func checkSourceReturnContinuation(ctx context.Context, predecessor *sourceOperandPrefix, returned *ssa.Return, references map[*ssa.Function]*assemblyReference) (*sourceReturnCompletion, error) {
	if returned == nil || len(returned.Results) != 0 {
		return nil, regionError("source return completion requires an actual void return")
	}
	checked, err := checkSourceEffectContinuation(ctx, predecessor, returned, references)
	if err != nil {
		return nil, err
	}
	return &sourceReturnCompletion{region: checked.region, prior: predecessor, returned: returned, checker: checked.checker}, nil
}

type sourceEffectContinuation struct {
	region  *sourceRegion
	binder  *selectedSourceBinder
	checker *regionKernel
}

// Both endpoint kinds share the same current-state, ownership and work account.
// Only a return endpoint enables complete-return checking; it is then consumed
// by the interpreter rather than treated as an unexecuted operand observation.
func checkSourceEffectContinuation(ctx context.Context, predecessor *sourceOperandPrefix, endpoint ssa.Instruction, references map[*ssa.Function]*assemblyReference) (*sourceEffectContinuation, error) {
	if ctx == nil || predecessor.checkedPacket() == nil || endpoint == nil {
		return nil, regionError("missing source continuation predecessor or endpoint")
	}
	prior := predecessor.region.packet
	if prior.rules != regionRules || len(prior.observations) != 1 || endpoint.Block() == nil || endpoint.Parent() != prior.input.root || endpoint == predecessor.call || !prior.usage.limits.valid() || len(references) > prior.usage.limits.nodes {
		return nil, regionError("source continuation scope or cumulative account differs")
	}
	var operand ssa.Value
	completion := false
	switch at := endpoint.(type) {
	case *ssa.Call:
		if at.Call.IsInvoke() || at.Call.StaticCallee() == nil {
			return nil, regionError("unsupported call endpoint")
		}
		operand = regionCallBoundaryOperand(at)
	case *ssa.Return:
		if len(at.Results) != 0 {
			return nil, regionError("unsupported return endpoint")
		}
		completion = true
	default:
		return nil, regionError("unsupported source endpoint")
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
	in.entry, in.use = prior.input.use.at, regionUse{regionPoint{endpoint.Block(), at}, operand}
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
		k.trace = &regionEffectTrace{seen: map[regionEffectOccurrence]bool{}}
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
	return &sourceEffectContinuation{region: selected, binder: binder, checker: checker}, nil
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
