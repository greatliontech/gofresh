package closure

import (
	"context"
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

const regionActivationRules = "gofresh/source-activation-outcomes@1"

// The activation arm is deliberately not a checkedRegion. It covers normal,
// panic and noncompletion alternatives, not strict safety or finite progress.
// The source owner and entry/frame premises retain their ordinary conditional
// meaning; selected native applicability is a separate obligation.
type regionActivationInput struct {
	owner        *ssa.Program
	selection    *program
	root         *ssa.Function
	initial      regionState
	unwind       regionUnwindScope
	storageModel regionStorageModel
	premises     []string
}

func (in regionActivationInput) regionInput() regionInput {
	r := regionInput{owner: in.owner, selection: in.selection, root: in.root, initial: in.initial, unwind: in.unwind, storageModel: in.storageModel, premises: in.premises}
	if in.root != nil && len(in.root.Blocks) != 0 {
		r.entry = regionPoint{in.root.Blocks[0], 0}
	}
	return r
}

type regionActivationRule uint8

const (
	activationStep regionActivationRule = iota
	activationBranch
	activationCall
	activationDrain
	activationBeginPanic
	activationRecover
	activationRecoveryEntry
	activationReturn
	activationEscape
	activationChannelSuccess
	activationNoncompletion
)

// An inference transcript contains actual positions and rule choices only. It
// supplies no result, frame, state invariant or claimed unreachable successor.
// Both discovery and checking enumerate every alternative in canonical order;
// checking validates each event while recomputing the complete typed relation.
type regionActivationEvent struct {
	at         regionPoint
	invocation regionInvocation
	rule       regionActivationRule
	choice     int
	target     *ssa.Function
}

type regionActivationProposal struct {
	input  regionActivationInput
	events []regionActivationEvent
}

type regionActivationEnd uint8

const (
	activationNormal regionActivationEnd = iota
	activationPanicking
	activationStopped
)

// A panic token is distinct from its payload. Tokens are immutable; consumption
// belongs to each correlated invocation alternative, not a shared mutable bit.
type regionActivationPanic struct {
	origin  regionEffectOccurrence
	payload regionValue
}

type regionActivationState struct {
	store regionState
	// Whether this invocation consumed its incoming direct-recovery capability.
	// Its own nested panics have different tokens and cannot set this bit.
	recovered bool
}

type regionActivationOutcome struct {
	kind   regionActivationEnd
	state  regionActivationState
	value  regionValue
	panic  *regionActivationPanic
	origin regionEffectOccurrence
}

type regionActivationCall struct {
	site         ssa.CallInstruction
	dispatch     ssa.Instruction
	registration regionEffectOccurrence
	invocation   regionInvocation
	target       *ssa.Function
}

type checkedRegionActivation struct {
	rules    string
	input    regionActivationInput
	events   []regionActivationEvent
	outcomes []regionActivationOutcome
	calls    []regionActivationCall
	usage    regionMeter
}

// The driver is shared, not the proposed answer. The checker derives all states,
// operands, successors and terminals anew from the independently captured input.
type regionActivationDriver struct {
	meter    *regionMeter
	checking bool
	events   []regionActivationEvent
	cursor   int
	calls    []regionActivationCall
}

func captureRegionActivation(in regionActivationInput, proposal *regionActivationProposal, limits regionLimits) (regionActivationInput, *regionActivationProposal, error) {
	m := &regionMeter{limits: limits}
	copyInput := func(in regionActivationInput) (regionActivationInput, error) {
		r, _, err := regionCaptureMeter(in.regionInput(), nil, m)
		in.initial, in.premises = r.initial, r.premises
		return in, err
	}
	owned, err := copyInput(in)
	if err != nil || proposal == nil {
		return owned, nil, err
	}
	if len(proposal.events) == 0 || len(proposal.events) > limits.nodes {
		return owned, nil, regionError("activation inference count is empty or exceeds budget")
	}
	for _, event := range proposal.events {
		if len(event.invocation.path) > limits.depth*96 {
			return owned, nil, regionError("activation inference context budget exhausted")
		}
	}
	p := &regionActivationProposal{events: slices.Clone(proposal.events)}
	p.input, err = copyInput(proposal.input)
	return owned, p, err
}

func activationKernel(ctx context.Context, in regionActivationInput, limits regionLimits) (*regionKernel, error) {
	if ctx == nil || in.unwind != regionNoActiveUnwind {
		return nil, regionError("activation requires context and explicit no-active-unwind entry")
	}
	r := in.regionInput()
	k, err := newRegionContextKernel(r, newRegionCallSession(ctx, r, limits), regionInvocation{}, true)
	if err == nil && !regionSourceCallBody(in.root) {
		return nil, regionError("activation root lacks an ordinary source body")
	}
	return k, err
}

func proposeRegionActivation(ctx context.Context, input regionActivationInput, limits regionLimits) (*regionActivationProposal, error) {
	in, _, err := captureRegionActivation(input, nil, limits)
	if err != nil {
		return nil, err
	}
	k, err := activationKernel(ctx, in, limits)
	if err != nil {
		return nil, err
	}
	d := &regionActivationDriver{meter: k.meter}
	if _, err := d.walk(k, k.input.entry, regionActivationState{store: k.input.initial}, nil, 0); err != nil {
		return nil, err
	}
	if err := k.meter.tick(); err != nil {
		return nil, err
	}
	return &regionActivationProposal{input: in, events: d.events}, nil
}

func checkRegionActivation(ctx context.Context, input regionActivationInput, proposal *regionActivationProposal, limits regionLimits) (*checkedRegionActivation, error) {
	in, p, err := captureRegionActivation(input, proposal, limits)
	if err != nil {
		return nil, err
	}
	k, err := activationKernel(ctx, in, limits)
	if err != nil {
		return nil, err
	}
	if p == nil || p.input.owner != in.owner || p.input.selection != in.selection || p.input.root != in.root || p.input.unwind != in.unwind || p.input.storageModel != in.storageModel || !slices.Equal(p.input.premises, in.premises) {
		return nil, regionError("activation proposal is not bound to its complete input")
	}
	if err := k.validateState(p.input.initial); err != nil {
		return nil, err
	}
	for _, pair := range [][2]regionState{{in.initial, p.input.initial}, {p.input.initial, in.initial}} {
		same, err := k.included(pair[0], pair[1])
		if err != nil || !same {
			if err == nil {
				err = regionError("activation initial relation differs")
			}
			return nil, err
		}
	}
	d := &regionActivationDriver{meter: k.meter, checking: true, events: p.events}
	outcomes, err := d.walk(k, k.input.entry, regionActivationState{store: k.input.initial}, nil, 0)
	if err != nil {
		return nil, err
	}
	if d.cursor != len(d.events) || len(outcomes) == 0 {
		return nil, regionError("activation has unused inferences or no terminal alternatives")
	}
	if err := k.meter.tick(); err != nil {
		return nil, err
	}
	usage := *k.meter
	usage.ctx, usage.keyCopies, usage.stringCopies, usage.stringAtoms = nil, nil, nil, nil
	return &checkedRegionActivation{rules: regionActivationRules, input: in, events: p.events, outcomes: outcomes, calls: d.calls, usage: usage}, nil
}

func (d *regionActivationDriver) event(k *regionKernel, ins ssa.Instruction, rule regionActivationRule, choice int, target *ssa.Function) (regionEffectOccurrence, error) {
	if err := d.meter.tick(); err != nil {
		return regionEffectOccurrence{}, err
	}
	if ins == nil || ins.Parent() != k.input.root || ins.Block() == nil {
		return regionEffectOccurrence{}, regionError("activation inference lacks actual instruction")
	}
	index := slices.Index(ins.Block().Instrs, ins)
	d.meter.nodes++
	if index < 0 || d.cursor >= d.meter.limits.nodes || d.meter.nodes > d.meter.limits.nodes {
		return regionEffectOccurrence{}, regionError("activation inference position or node budget invalid")
	}
	e := regionActivationEvent{regionPoint{ins.Block(), index}, k.invocation, rule, choice, target}
	if d.checking {
		if d.cursor >= len(d.events) || d.events[d.cursor] != e {
			return regionEffectOccurrence{}, regionError("activation inference omits or changes an actual alternative")
		}
	} else {
		d.events = append(d.events, e)
	}
	occurrence := regionEffectOccurrence{instruction: ins, invocation: k.invocation, ordinal: uint64(d.cursor)}
	d.cursor++
	return occurrence, nil
}

func (d *regionActivationDriver) appendOutcomes(dst, src []regionActivationOutcome) ([]regionActivationOutcome, error) {
	if err := d.meter.tick(); err != nil {
		return nil, err
	}
	d.meter.locations += len(src)
	if len(src) > d.meter.limits.states-len(dst) || d.meter.locations > d.meter.limits.locations {
		return nil, regionError("activation outcome storage budget exhausted")
	}
	return append(dst, src...), nil
}

func (d *regionActivationDriver) walk(k *regionKernel, at regionPoint, state regionActivationState, eligible *regionActivationPanic, depth int) ([]regionActivationOutcome, error) {
	if depth > d.meter.limits.depth {
		return nil, regionError("activation path depth exhausted")
	}
	var err error
	state.store, err = k.clone(state.store)
	if err != nil {
		return nil, err
	}
	for {
		ins := regionInstruction(at)
		if ins == nil || k.cycle[at.block] {
			return nil, regionError("activation has an invalid boundary or reachable cycle")
		}
		if _, err := d.event(k, ins, activationStep, 0, nil); err != nil {
			return nil, err
		}
		next := regionPoint{at.block, at.index + 1}
		switch x := ins.(type) {
		case *ssa.Phi:
			// Ordinary predecessor transfer assigned these simultaneously.
		case *ssa.Jump, *ssa.If:
			edges, err := k.branchEdges(ins, state.store)
			if err != nil {
				return nil, err
			}
			var result []regionActivationOutcome
			for _, edge := range edges {
				if _, err := d.event(k, ins, activationBranch, edge.slot, nil); err != nil {
					return nil, err
				}
				out, err := d.walk(k, regionPoint{edge.block, 0}, regionActivationState{edge.state, state.recovered}, eligible, depth+1)
				if err != nil {
					return nil, err
				}
				result, err = d.appendOutcomes(result, out)
				if err != nil {
					return nil, err
				}
			}
			return result, nil
		case *ssa.Return:
			value, err := k.returnValue(x, state.store)
			if err != nil {
				return nil, err
			}
			origin, err := d.event(k, ins, activationReturn, 0, nil)
			return []regionActivationOutcome{{kind: activationNormal, state: state, value: value, origin: origin}}, err
		case *ssa.Panic:
			payload := k.value(state.store, x.X)
			if payload.kind == regionNil {
				return nil, regionError("explicit nil panic has no selected panic-nil semantics")
			}
			return d.beginPanic(k, ins, state, payload, eligible, depth)
		case *ssa.MakeChan:
			value, err := k.channelConstruction(state.store, x)
			if err != nil {
				return nil, err
			}
			// The logical store is after operand evaluation. Neither this frame nor
			// these alternatives assert allocator success, physical ownership or
			// semantics for an explicitly called runtime routine.
			success, err := k.clone(state.store)
			if err != nil {
				return nil, err
			}
			if err := k.setValue(&success, x, value); err != nil {
				return nil, err
			}
			if _, err := d.event(k, ins, activationChannelSuccess, 0, nil); err != nil {
				return nil, err
			}
			result, err := d.walk(k, next, regionActivationState{success, state.recovered}, eligible, depth+1)
			if err != nil {
				return nil, err
			}
			payload := regionUnknownValue(types.Universe.Lookup("any").Type())
			panics, err := d.beginPanic(k, ins, state, payload, eligible, depth)
			if err != nil {
				return nil, err
			}
			result, err = d.appendOutcomes(result, panics)
			if err != nil {
				return nil, err
			}
			origin, err := d.event(k, ins, activationNoncompletion, 0, nil)
			if err != nil {
				return nil, err
			}
			return d.appendOutcomes(result, []regionActivationOutcome{{kind: activationStopped, origin: origin}})
		case *ssa.RunDefers:
			return d.drain(k, ins, next, state, nil, false, eligible, depth)
		case *ssa.Call:
			if builtin, ok := x.Call.Value.(*ssa.Builtin); ok {
				if builtin.Name() == "recover" {
					if x.Call.IsInvoke() || len(x.Call.Args) != 0 {
						return nil, regionError("invalid builtin recovery")
					}
					value := regionValue{typ: x.Type(), kind: regionNil}
					choice := 0
					if eligible != nil && !state.recovered {
						value = eligible.payload
						value.typ = x.Type()
						state.recovered, choice = true, 1
					}
					if _, err := d.event(k, ins, activationRecover, choice, nil); err != nil {
						return nil, err
					}
					if err := k.setValue(&state.store, x, value); err != nil {
						return nil, err
					}
				} else if err := k.transfer(&state.store, ins); err != nil {
					return nil, &regionOperationFailure{ins, err}
				}
				break
			}
			callable, arguments, err := k.callOperands(x, state.store)
			if err != nil {
				return nil, err
			}
			// An ordinary helper never inherits direct-recovery eligibility.
			outcomes, err := d.invoke(k, x, ins, state.store, callable, arguments, nil, nil, depth)
			if err != nil {
				return nil, err
			}
			var result []regionActivationOutcome
			for _, out := range outcomes {
				var tail []regionActivationOutcome
				if out.kind == activationStopped {
					tail = []regionActivationOutcome{out}
				} else {
					after, err := d.resume(k, state, out)
					if err != nil {
						return nil, err
					}
					if out.kind == activationPanicking {
						tail, err = d.drain(k, ins, regionPoint{}, after, out.panic, false, eligible, depth+1)
					} else {
						if !types.Identical(out.value.typ, x.Type()) {
							return nil, regionError("activation child result type differs")
						}
						if err = k.setValue(&after.store, x, out.value); err == nil {
							tail, err = d.walk(k, next, after, eligible, depth+1)
						}
					}
					if err != nil {
						return nil, err
					}
				}
				result, err = d.appendOutcomes(result, tail)
				if err != nil {
					return nil, err
				}
			}
			return result, nil
		case *ssa.Defer:
			if _, builtin := x.Call.Value.(*ssa.Builtin); builtin {
				return nil, regionError("deferred builtin panic/recover is outside activation grammar")
			}
			if err := k.registerDefer(&state.store, x); err != nil {
				return nil, err
			}
		default:
			if err := k.transfer(&state.store, ins); err != nil {
				return nil, &regionOperationFailure{ins, err}
			}
		}
		at = next
	}
}

func (d *regionActivationDriver) beginPanic(k *regionKernel, ins ssa.Instruction, state regionActivationState, payload regionValue, eligible *regionActivationPanic, depth int) ([]regionActivationOutcome, error) {
	if _, ok := payload.typ.Underlying().(*types.Interface); !ok {
		return nil, regionError("panic payload is not an interface")
	}
	origin, err := d.event(k, ins, activationBeginPanic, 0, nil)
	if err != nil {
		return nil, err
	}
	p := &regionActivationPanic{origin: origin, payload: payload}
	return d.drain(k, ins, regionPoint{}, state, p, false, eligible, depth)
}

// drain pops before dispatch. A normally returning child restores the suspended
// reason unless that child consumed its exact incoming recovery capability. An
// escaping child panic replaces that reason: recovering it here abandons the
// older panic, whereas recovery inside the child returns to the suspended one.
func (d *regionActivationDriver) drain(k *regionKernel, trigger ssa.Instruction, next regionPoint, state regionActivationState, reason *regionActivationPanic, recovered bool, eligible *regionActivationPanic, depth int) ([]regionActivationOutcome, error) {
	if depth > d.meter.limits.depth || !state.store.pending.known {
		return nil, regionError("activation drain has unknown stack or exhausted depth")
	}
	if _, err := d.event(k, trigger, activationDrain, len(state.store.pending.captures), nil); err != nil {
		return nil, err
	}
	if n := len(state.store.pending.captures); n != 0 {
		capture := state.store.pending.captures[n-1]
		state.store.pending.captures = state.store.pending.captures[:n-1]
		outcomes, err := d.invoke(k, capture.site, trigger, state.store, capture.callable, capture.arguments, &capture, reason, depth)
		if err != nil {
			return nil, err
		}
		var result []regionActivationOutcome
		for _, out := range outcomes {
			var tail []regionActivationOutcome
			if out.kind == activationStopped {
				tail = []regionActivationOutcome{out}
			} else {
				after, err := d.resume(k, state, out)
				if err != nil {
					return nil, err
				}
				pending, recovery := reason, recovered
				if out.kind == activationPanicking {
					pending, recovery = out.panic, false
				} else if out.state.recovered {
					if reason == nil {
						return nil, regionError("recovery consumed no incoming panic")
					}
					pending, recovery = nil, true
				}
				tail, err = d.drain(k, trigger, next, after, pending, recovery, eligible, depth+1)
				if err != nil {
					return nil, err
				}
			}
			result, err = d.appendOutcomes(result, tail)
			if err != nil {
				return nil, err
			}
		}
		return result, nil
	}
	if reason != nil {
		origin, err := d.event(k, trigger, activationEscape, 0, nil)
		return []regionActivationOutcome{{kind: activationPanicking, state: state, panic: reason, origin: origin}}, err
	}
	if recovered {
		block := k.input.root.Recover
		if block == nil || block.Parent() != k.input.root || !slices.Contains(k.input.root.Blocks, block) || len(block.Preds) != 0 || len(block.Succs) != 0 || len(block.Instrs) == 0 {
			return nil, regionError("recovered activation lacks its actual recovery entry")
		}
		for i, ins := range block.Instrs {
			if err := d.meter.tick(); err != nil {
				return nil, err
			}
			if i == len(block.Instrs)-1 {
				if _, ok := ins.(*ssa.Return); !ok {
					return nil, regionError("recovery entry lacks terminal return")
				}
			} else if load, ok := ins.(*ssa.UnOp); !ok || load.Op != token.MUL {
				return nil, regionError("unsupported recovery result continuation")
			}
		}
		if _, err := d.event(k, block.Instrs[0], activationRecoveryEntry, 0, nil); err != nil {
			return nil, err
		}
		// This is a second entry, not a predecessor edge. Actual SSA loads read
		// the result cells after all remaining defers, including unnamed cells.
		return d.walk(k, regionPoint{block, 0}, state, eligible, depth+1)
	}
	return d.walk(k, next, state, eligible, depth+1)
}

func (d *regionActivationDriver) resume(k *regionKernel, parent regionActivationState, out regionActivationOutcome) (regionActivationState, error) {
	store, err := k.clone(regionState{values: parent.store.values, memory: out.state.store.memory, pending: parent.store.pending})
	return regionActivationState{store: store, recovered: parent.recovered}, err
}

func (d *regionActivationDriver) invoke(k *regionKernel, call ssa.CallInstruction, dispatch ssa.Instruction, caller regionState, callable regionValue, arguments []regionValue, capture *regionDeferredCall, eligible *regionActivationPanic, depth int) ([]regionActivationOutcome, error) {
	d.meter.applications++
	initial, err := k.callEntry(caller, callable, arguments)
	if err != nil {
		return nil, &regionOperationFailure{call, err}
	}
	id, err := k.invocationDispatch(call, callable.target, capture, dispatch)
	if err != nil {
		return nil, err
	}
	if _, err := d.event(k, dispatch, activationCall, 0, callable.target); err != nil {
		return nil, err
	}
	if len(d.calls) >= d.meter.limits.nodes {
		return nil, regionError("activation call count exhausted")
	}
	application := regionActivationCall{site: call, dispatch: dispatch, invocation: id, target: callable.target}
	if capture != nil {
		application.registration = capture.registration
	}
	d.calls = append(d.calls, application)
	in := k.input
	in.root, in.entry, in.initial = callable.target, regionPoint{callable.target.Blocks[0], 0}, initial
	// Shared typed transfers receive no false no-unwind entry assertion for a
	// child invoked during panic. Recovery authority is solely the capability
	// passed to this activation driver, never this legacy scope field.
	in.unwind = regionUnknownUnwind
	child, err := newRegionContextKernel(in, k.session, id, true)
	if err != nil {
		return nil, err
	}
	k.session.active[callable.target] = true
	defer delete(k.session.active, callable.target)
	return d.walk(child, child.input.entry, regionActivationState{store: child.input.initial}, eligible, depth+1)
}

// A normal projection rechecks the full relation before testing every normal
// alternative. It neither filters discovery nor grants strict/native authority.
// There must be a normal alternative; vacuity cannot certify an expected result.
type regionActivationNormalProjection struct {
	activation *checkedRegionActivation
	value      regionValue
}

func (p *checkedRegionActivation) projectNormal(ctx context.Context, value regionValue) (*regionActivationNormalProjection, error) {
	if p == nil || p.rules != regionActivationRules {
		return nil, regionError("unknown activation evidence")
	}
	// Capture the requested value before any caller-controlled context callback.
	m := &regionMeter{limits: p.usage.limits}
	want, err := m.copyValue(value, 0)
	if err != nil {
		return nil, err
	}
	packet, err := checkRegionActivation(ctx, p.input, &regionActivationProposal{input: p.input, events: p.events}, p.usage.limits)
	if err != nil {
		return nil, err
	}
	// Validate the requested abstract value, charging the check's remaining
	// cumulative allowance rather than granting a new budget to the projection.
	in := packet.input.regionInput()
	session := newRegionCallSession(ctx, in, packet.usage.limits)
	*session.meter = packet.usage
	session.meter.ctx = ctx
	k, err := newRegionContextKernel(in, session, regionInvocation{}, true)
	if err != nil {
		return nil, err
	}
	if err := k.validateValue(want, 0); err != nil {
		return nil, err
	}
	found := false
	for _, out := range packet.outcomes {
		if err := k.chargeValue(out.value); err != nil {
			return nil, err
		}
		if out.kind == activationNormal {
			found = true
			if !regionValueIncluded(out.value, want) {
				return nil, regionError("normal projection omits a checked returned alternative")
			}
		}
	}
	if !found {
		return nil, regionError("normal projection has no returned alternative")
	}
	return &regionActivationNormalProjection{activation: packet, value: want}, nil
}
