package closure

import (
	"context"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

const regionActivationRules = "gofresh/source-activation-outcomes@3"

// The activation arm covers normal, panic and noncompletion alternatives, not
// strict safety or native applicability. A limit is an unexecuted root boundary;
// it remains fixed across every continuation, including partition pauses.
type regionActivationInput struct {
	owner             *ssa.Program
	selection         *program
	root              *ssa.Function
	entry             regionPoint
	limit             *regionUse
	initial           regionState
	unwind            regionUnwindScope
	pendingAntecedent bool
	storageModel      regionStorageModel
	premises          []string
}

func (in regionActivationInput) regionInput() regionInput {
	r := regionInput{owner: in.owner, selection: in.selection, root: in.root, entry: in.entry, initial: in.initial, unwind: in.unwind, pendingAntecedent: in.pendingAntecedent, storageModel: in.storageModel, premises: in.premises}
	if r.entry == (regionPoint{}) && in.root != nil && len(in.root.Blocks) != 0 {
		r.entry = regionPoint{in.root.Blocks[0], 0}
	}
	if in.limit != nil {
		r.use = *in.limit
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
	activationConstructionSuccess
	activationNoncompletion
	activationFrontier
)

// The transcript supplies positions and rule choices, never states, excluded
// successors or outcomes. The checker derives all alternatives independently.
type regionActivationEvent struct {
	at         regionPoint
	invocation regionInvocation
	rule       regionActivationRule
	choice     int
	target     *ssa.Function
}

type regionActivationProposal struct {
	input       regionActivationInput
	events      []regionActivationEvent
	predecessor *checkedRegionActivation
	offset      int
	stop        uint64
}

type regionActivationEnd uint8

const (
	activationNormal regionActivationEnd = iota
	activationPanicking
	activationStopped
)

// Tokens and payload terms are immutable. Consumption belongs to an individual
// correlated activation, never to a bit shared by alternative executions.
type regionActivationPanic struct {
	origin  regionEffectOccurrence
	payload regionValue
}
type regionActivationState struct {
	store     regionState
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

// Only constructors publish checked packets. Mutable containers belong to this
// packet and are not exposed through setters. Continuations clone the private
// snapshot before callbacks; public-to-package projections confer no resume input.
type checkedRegionActivation struct {
	rules    string
	input    regionActivationInput
	events   []regionActivationEvent
	outcomes []regionActivationOutcome
	calls    []regionActivationCall
	usage    regionMeter
	self     *checkedRegionActivation
	snapshot *activationSnapshot
}

func captureRegionActivation(in regionActivationInput, proposal *regionActivationProposal, limits regionLimits) (regionActivationInput, *regionActivationProposal, error) {
	return captureActivationMeter(in, proposal, &regionMeter{limits: limits})
}

// Capture has no Context: even a caller-defined Err callback is too late to
// change the interpreted input, stop, transcript or retained source metadata.
func captureActivationMeter(in regionActivationInput, proposal *regionActivationProposal, m *regionMeter) (regionActivationInput, *regionActivationProposal, error) {
	copyInput := func(in regionActivationInput) (regionActivationInput, error) {
		r, _, err := regionCaptureMeter(in.regionInput(), nil, m)
		in.initial, in.premises = r.initial, r.premises
		if in.limit != nil {
			limit := *in.limit
			in.limit = &limit
		}
		return in, err
	}
	owned, err := copyInput(in)
	if err != nil || proposal == nil {
		return owned, nil, err
	}
	if len(proposal.events) > m.limits.nodes {
		return owned, nil, regionError("activation inference count exceeds budget")
	}
	for _, event := range proposal.events {
		if err := m.tick(); err != nil {
			return owned, nil, err
		}
		if len(event.invocation.path) > m.limits.depth*96 {
			return owned, nil, regionError("activation inference context budget exhausted")
		}
	}
	p := *proposal
	p.events = slices.Clone(proposal.events)
	p.input, err = copyInput(proposal.input)
	return owned, &p, err
}

func activationKernelMeter(ctx context.Context, in regionActivationInput, meter *regionMeter) (*regionKernel, error) {
	if ctx == nil || in.unwind != regionNoActiveUnwind {
		return nil, regionError("activation requires context and explicit no-active-unwind entry")
	}
	r := in.regionInput()
	session := newRegionCallSession(ctx, r, meter.limits)
	session.finite = true
	session.instances = map[regionObject]bool{}
	session.occurrences = map[regionEffectOccurrence]bool{}
	meter.ctx, session.meter = ctx, meter
	k, err := newRegionContextKernel(r, session, regionInvocation{}, in.limit == nil)
	if err == nil && !regionSourceCallBody(in.root) {
		return nil, regionError("activation root lacks an ordinary source body")
	}
	return k, err
}

func sameActivationInput(k *regionKernel, a, b regionActivationInput) error {
	if a.owner != b.owner || a.selection != b.selection || a.root != b.root || a.entry != b.entry || a.unwind != b.unwind || a.pendingAntecedent != b.pendingAntecedent || a.storageModel != b.storageModel || !slices.Equal(a.premises, b.premises) || (a.limit == nil) != (b.limit == nil) || a.limit != nil && *a.limit != *b.limit {
		return regionError("activation proposal is not bound to its complete input")
	}
	if err := k.validateState(b.initial); err != nil {
		return err
	}
	for _, pair := range [][2]regionState{{a.initial, b.initial}, {b.initial, a.initial}} {
		same, err := k.included(pair[0], pair[1])
		if err != nil {
			return err
		}
		if !same {
			return regionError("activation initial relation differs")
		}
	}
	return nil
}

func proposeRegionActivation(ctx context.Context, input regionActivationInput, limits regionLimits) (*regionActivationProposal, error) {
	return proposeRegionActivationSegment(ctx, input, 0, limits)
}
func checkRegionActivation(ctx context.Context, input regionActivationInput, proposal *regionActivationProposal, limits regionLimits) (*checkedRegionActivation, error) {
	return checkRegionActivationSegment(ctx, input, 0, proposal, limits)
}

// stop is an absolute transition count, not a work allowance. Zero runs every
// alternative to a terminal or the immutable scope boundary. A nonzero stop
// deliberately publishes unfinished work, never complete-activation authority.
func proposeRegionActivationSegment(ctx context.Context, input regionActivationInput, stop uint64, limits regionLimits) (*regionActivationProposal, error) {
	meter := &regionMeter{limits: limits}
	in, _, err := captureActivationMeter(input, nil, meter)
	if err != nil {
		return nil, err
	}
	k, err := activationKernelMeter(ctx, in, meter)
	if err != nil {
		return nil, err
	}
	m, err := newActivationMachine(in, k)
	if err != nil {
		return nil, err
	}
	if err := m.run(stop); err != nil {
		return nil, err
	}
	return &regionActivationProposal{input: in, events: m.events, stop: stop}, nil
}

func checkRegionActivationSegment(ctx context.Context, input regionActivationInput, stop uint64, proposal *regionActivationProposal, limits regionLimits) (*checkedRegionActivation, error) {
	meter := &regionMeter{limits: limits}
	in, p, err := captureActivationMeter(input, proposal, meter)
	if err != nil {
		return nil, err
	}
	if p == nil || p.predecessor != nil || p.offset != 0 || p.stop != stop {
		return nil, regionError("activation segment binding differs")
	}
	k, err := activationKernelMeter(ctx, in, meter)
	if err != nil {
		return nil, err
	}
	if err := sameActivationInput(k, in, p.input); err != nil {
		return nil, err
	}
	m, err := newActivationMachine(in, k)
	if err != nil {
		return nil, err
	}
	m.checking, m.proposed = true, p.events
	if err := m.run(stop); err != nil {
		return nil, err
	}
	return m.publish()
}

func (p *checkedRegionActivation) authenticated() bool {
	return p != nil && p.self == p && p.rules == regionActivationRules && p.snapshot != nil && p.usage.limits == p.snapshot.usage.limits
}

func proposeRegionActivationContinuation(ctx context.Context, prior *checkedRegionActivation, stop uint64) (*regionActivationProposal, error) {
	m, _, err := continueActivation(ctx, prior, stop, nil)
	if err != nil {
		return nil, err
	}
	offset := len(m.events)
	if err := m.run(stop); err != nil {
		return nil, err
	}
	return &regionActivationProposal{input: m.input, predecessor: prior, offset: offset, stop: stop, events: slices.Clone(m.events[offset:])}, nil
}

func checkRegionActivationContinuation(ctx context.Context, prior *checkedRegionActivation, stop uint64, proposal *regionActivationProposal) (*checkedRegionActivation, error) {
	if proposal == nil {
		return nil, regionError("missing activation continuation inference")
	}
	m, p, err := continueActivation(ctx, prior, stop, proposal)
	if err != nil {
		return nil, err
	}
	m.checking, m.proposed = true, p.events
	if err := m.run(stop); err != nil {
		return nil, err
	}
	return m.publish()
}

type regionActivationNormalProjection struct {
	activation *checkedRegionActivation
	value      regionValue
}

// Only a completely checked relation can supply a normal projection. Reuse of
// the private checked payload never promotes an unfinished prefix or replays an
// allocation; validation consumes the relation's remaining cumulative allowance.
func (p *checkedRegionActivation) projectNormal(ctx context.Context, value regionValue) (*regionActivationNormalProjection, error) {
	if !p.authenticated() || len(p.snapshot.work)+len(p.snapshot.frontiers) != 0 {
		return nil, regionError("unknown or unfinished activation evidence")
	}
	meter := p.snapshot.usage
	meter.ctx = nil
	want, err := meter.copyValue(value, 0)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, regionError("missing projection context")
	}
	meter.ctx = ctx
	k := p.snapshot.root.kernel(&regionCallSession{meter: &meter, contexts: p.snapshot.contexts, preexisting: p.snapshot.preexisting, finite: true, instances: p.snapshot.instances, occurrences: p.snapshot.occurrences})
	if err := k.validateValue(want, 0); err != nil {
		return nil, err
	}
	found := false
	for _, out := range p.snapshot.outcomes {
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
	return &regionActivationNormalProjection{activation: p, value: want}, nil
}
