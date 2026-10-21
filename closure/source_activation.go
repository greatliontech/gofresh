package closure

import "context"

// sourceActivation retains exact selected ownership for every body actually
// executed by the outcome relation. It is not native correspondence, a strict
// region packet, a process-completion receipt or a subject outcome protocol.
type sourceActivation struct {
	packet *checkedRegionActivation
	root   selectedSourceCallable
	calls  []sourceActivationCall
	binder *selectedSourceBinder
	self   *sourceActivation
}

type sourceActivationCall struct {
	call  regionActivationCall
	bound selectedSourceCallable
}

func checkSourceActivation(ctx context.Context, source computationSource, input regionActivationInput, proposal *regionActivationProposal, sourceLimits selectedSourceLimits, limits regionLimits) (*sourceActivation, error) {
	return checkSourceActivationSegment(ctx, source, input, 0, proposal, sourceLimits, limits)
}

func checkSourceActivationSegment(ctx context.Context, source computationSource, input regionActivationInput, stop uint64, proposal *regionActivationProposal, sourceLimits selectedSourceLimits, limits regionLimits) (*sourceActivation, error) {
	// Source metadata is caller-owned, unlike the immutable selected SSA owner.
	// Capture it before semantic checking can invoke Context.Err.
	capture, err := captureSelectedSource(source, sourceLimits)
	if err != nil {
		return nil, err
	}
	packet, err := checkRegionActivationSegment(ctx, input, stop, proposal, limits)
	if err != nil {
		return nil, err
	}
	b, err := capture.binder(ctx, packet.input.root)
	if err != nil {
		return nil, err
	}
	return b.checkSourceActivation(packet)
}

func checkSourceActivationContinuation(ctx context.Context, prior *sourceActivation, stop uint64, proposal *regionActivationProposal) (*sourceActivation, error) {
	if prior == nil || prior.self != prior || prior.binder == nil {
		return nil, regionError("missing authenticated selected activation predecessor")
	}
	packet, err := checkRegionActivationContinuation(ctx, prior.packet, stop, proposal)
	if err != nil {
		return nil, err
	}
	b, err := continueSourceBinder(ctx, prior.binder)
	if err != nil {
		return nil, err
	}
	return b.checkSourceActivation(packet)
}

func (b *selectedSourceBinder) checkSourceActivation(packet *checkedRegionActivation) (*sourceActivation, error) {
	if !packet.authenticated() {
		return nil, regionError("activation has no authenticated source payload")
	}
	input := packet.snapshot.input
	if input.owner != b.source.prog.Prog || input.selection != nil && input.selection != b.source.prog {
		return nil, regionError("activation has another selected source owner")
	}
	root, err := b.bindCallable(input.root)
	if err != nil {
		return nil, err
	}
	result := &sourceActivation{packet: packet, root: root, binder: b}
	for _, call := range packet.snapshot.calls {
		if err := b.tick(input.root, input.root.Pos()); err != nil {
			return nil, err
		}
		bound, err := b.bindCallable(call.target)
		if err != nil {
			return nil, err
		}
		result.calls = append(result.calls, sourceActivationCall{call: call, bound: bound})
	}
	if err := b.tick(input.root, input.root.Pos()); err != nil {
		return nil, err
	}
	result.self = result
	return result, nil
}
