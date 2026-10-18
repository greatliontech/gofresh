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

// These events describe a finite isolated scalar region, not an arbitrary
// language effect summary. Each access comes from an actual typed operation or
// an independently checked reference at its exact call. Private reference-frame
// accesses remain in that reference's evidence rather than in this projection.
type regionEffectAccess struct {
	instruction ssa.Instruction
	global      *ssa.Global
	write       bool
	value       uint64
	locked      bool
}

type regionExcludedEdge struct {
	branch    *ssa.If
	successor *ssa.BasicBlock
	condition bool
}

type regionReferenceApplication struct {
	proof   *regionCallProof
	current uint64
	value   uint64
	result  bool
}

type regionEffectTrace struct {
	accesses     []regionEffectAccess
	calls        []regionReferenceApplication
	instructions []ssa.Instruction
	excluded     []regionExcludedEdge
	seen         map[ssa.Instruction]bool
}

// An instruction in the retained predecessor cannot be executed again by a
// continuation. This is deliberately a finite, acyclic, one-state effect grammar;
// the general inductive region checker remains available without this refinement.
func (k *regionKernel) effectTransfer(state regionState, instruction ssa.Instruction) error {
	if err := k.meter.tick(); err != nil {
		return err
	}
	if k.trace.seen[instruction] || len(k.trace.instructions) >= k.meter.limits.nodes {
		return regionError("effect scope repeats an occurrence or exhausts its bound")
	}
	k.trace.seen[instruction] = true
	k.trace.instructions = append(k.trace.instructions, instruction)
	var address ssa.Value
	var value regionValue
	write := false
	switch x := instruction.(type) {
	case *ssa.DebugRef, *ssa.Jump, *ssa.Phi:
		return nil
	case *ssa.If:
		condition, known := regionBool(k.value(state, x.Cond))
		if !known {
			return regionError("finite effect scope has an unresolved branch condition")
		}
		excluded := 0
		if condition {
			excluded = 1
		}
		k.trace.excluded = append(k.trace.excluded, regionExcludedEdge{x, x.Block().Succs[excluded], condition})
		return nil
	case *ssa.BinOp:
		if !regionIsComparison(x.Op) {
			return regionError("finite effect scope requires a supported comparison")
		}
		return nil
	case *ssa.Call:
		if x.Call.IsInvoke() || x.Call.StaticCallee() == nil || k.session.references[x.Call.StaticCallee()] == nil {
			return regionError("finite effect scope call has no checked reference")
		}
		return nil
	case *ssa.Store:
		address, value, write = x.Addr, k.value(state, x.Val), true
	case *ssa.UnOp:
		if x.Op == token.NOT {
			return nil
		}
		if x.Op != token.MUL {
			return regionError("finite effect scope has an unsupported unary operation")
		}
		address = x.X
	default:
		return regionError("operation is outside the finite scalar effect relation")
	}
	pointer := k.value(state, address)
	g, err := k.effectGlobal(pointer)
	if err != nil {
		return err
	}
	if !write {
		value = readRegionLocation(state, pointer.location, types.Typ[types.Uint64])
	}
	n, ok := regionUint64(value)
	if !ok {
		return regionError("global access has an unestablished scalar value")
	}
	return k.addEffectAccess(regionEffectAccess{instruction: instruction, global: g, write: write, value: n})
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

func (k *regionKernel) callReference(call *ssa.Call, caller regionState, callable regionValue, actual []regionValue) ([]regionState, error) {
	target := callable.target
	reference := k.session.references[target]
	if reference == nil || k.trace == nil || call.Call.IsInvoke() || call.Call.StaticCallee() != target || len(callable.environment) != 0 || len(actual) != 3 || target.Signature.Params().Len() != len(actual) {
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
	global, err := k.effectGlobal(actual[0])
	if err != nil {
		return nil, err
	}
	current, cOK := regionUint64(readRegionLocation(caller, actual[0].location, types.Typ[types.Uint64]))
	old, oOK := regionUint64(actual[1])
	replacement, nOK := regionUint64(actual[2])
	if !cOK || !oOK || !nOK || !types.Identical(call.Type(), types.Typ[types.Bool]) {
		return nil, regionError("reference scalar instantiation is not established")
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
	result, err := reference.evaluate(regionProofContext{k.meter.ctx, k.meter}, current, old, replacement)
	if err != nil {
		return nil, err
	}
	after, err := k.clone(caller)
	if err != nil {
		return nil, err
	}
	after.memory[actual[0].location.object] = regionValue{typ: types.Typ[types.Uint64], kind: regionConstant, scalar: constant.MakeUint64(result.Value)}
	after.values[call] = regionValue{typ: call.Type(), kind: regionConstant, scalar: constant.MakeBool(result.Result)}
	for _, access := range result.Accesses {
		if err := k.addEffectAccess(regionEffectAccess{instruction: call, global: global, write: access.Write, value: access.Value, locked: access.Locked}); err != nil {
			return nil, err
		}
	}
	k.trace.calls = append(k.trace.calls, regionReferenceApplication{proof, current, result.Value, result.Result})
	k.session.used = append(k.session.used, proof)
	return []regionState{after}, nil
}

// checkSourceOperandContinuation starts with the opaque predecessor's checked
// current state. No initial heap, expected result, root, selection or resource
// allowance is supplied by the caller. The new call is an untrusted endpoint.
func checkSourceOperandContinuation(ctx context.Context, predecessor *sourceOperandPrefix, call *ssa.Call, references map[*ssa.Function]*assemblyReference) (*sourceOperandPrefix, error) {
	if ctx == nil || predecessor == nil || predecessor.region == nil || predecessor.region.packet == nil || predecessor.binder == nil || call == nil {
		return nil, regionError("missing source continuation predecessor or endpoint")
	}
	prior := predecessor.region.packet
	if prior.rules != regionRules || len(prior.observations) != 1 || call.Block() == nil || call.Parent() != prior.input.root || call.Call.IsInvoke() || call.Call.StaticCallee() == nil || call == predecessor.call || !prior.usage.limits.valid() || len(references) > prior.usage.limits.nodes {
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
	at := slices.Index(call.Block().Instrs, ssa.Instruction(call))
	if at < 0 || len(call.Call.Args) == 0 {
		return nil, regionError("continuation endpoint is not an actual consuming call")
	}
	in := prior.input
	in.entry, in.use = prior.input.use.at, regionUse{regionPoint{call.Block(), at}, call.Call.Args[0]}
	in.initial = prior.observations[0].state
	in, _, err := regionCaptureMeter(in, nil, &meter)
	if err != nil {
		return nil, err
	}
	newKernel := func(input regionInput) (*regionKernel, error) {
		session := newRegionCallSession(ctx, input, meter.limits)
		session.meter, session.references, session.source = &meter, ownedReferences, predecessor.binder.source
		for id, facts := range prior.contexts {
			if err := meter.tick(); err != nil {
				return nil, err
			}
			session.contexts[id] = facts
		}
		k, err := newRegionContextKernel(input, session, regionInvocation{}, false)
		if err != nil {
			return nil, err
		}
		k.trace = &regionEffectTrace{seen: map[ssa.Instruction]bool{}}
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
			} else if packet.prefix != nil {
				for _, event := range packet.prefix.events {
					if err := meter.tick(); err != nil {
						return nil, err
					}
					k.trace.seen[event.instruction] = true
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
	binder, err := continueSourceBinder(ctx, predecessor.binder)
	if err != nil {
		return nil, err
	}
	selected, err := binder.checkSourceRegion(packet)
	if err != nil {
		return nil, err
	}
	callee, err := binder.bindDeclaration(call.Call.StaticCallee())
	if err != nil {
		return nil, err
	}
	var operands []regionValue
	for _, argument := range call.Call.Args {
		value := checker.value(packet.observations[0].state, argument)
		if err := checker.validateValue(value, 0); err != nil {
			return nil, err
		}
		operands = append(operands, value)
	}
	if err := meter.tick(); err != nil {
		return nil, err
	}
	packet.usage = meter
	packet.usage.ctx = nil
	return &sourceOperandPrefix{region: selected, callee: callee, call: call, operands: operands, prior: predecessor, binder: binder}, nil
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
