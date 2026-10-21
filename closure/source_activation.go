package closure

import "context"

// sourceActivation retains exact selected ownership for every body actually
// executed by the outcome relation. It is not native correspondence, a strict
// region packet, a process-completion receipt or a subject outcome protocol.
type sourceActivation struct {
	packet *checkedRegionActivation
	root   selectedSourceCallable
	calls  []sourceActivationCall
}

type sourceActivationCall struct {
	call  regionActivationCall
	bound selectedSourceCallable
}

func checkSourceActivation(ctx context.Context, source computationSource, input regionActivationInput, proposal *regionActivationProposal, sourceLimits selectedSourceLimits, limits regionLimits) (*sourceActivation, error) {
	packet, err := checkRegionActivation(ctx, input, proposal, limits)
	if err != nil {
		return nil, err
	}
	b, err := newSelectedSourceBinder(ctx, source, packet.input.root, sourceLimits)
	if err != nil {
		return nil, err
	}
	return b.checkSourceActivation(packet)
}

func (b *selectedSourceBinder) checkSourceActivation(packet *checkedRegionActivation) (*sourceActivation, error) {
	if packet == nil || packet.rules != regionActivationRules || packet.input.owner != b.source.prog.Prog || packet.input.selection != nil && packet.input.selection != b.source.prog {
		return nil, regionError("activation has another selected source owner")
	}
	root, err := b.bindCallable(packet.input.root)
	if err != nil {
		return nil, err
	}
	result := &sourceActivation{packet: packet, root: root}
	for _, call := range packet.calls {
		if err := b.tick(packet.input.root, packet.input.root.Pos()); err != nil {
			return nil, err
		}
		bound, err := b.bindCallable(call.target)
		if err != nil {
			return nil, err
		}
		result.calls = append(result.calls, sourceActivationCall{call: call, bound: bound})
	}
	if err := b.tick(packet.input.root, packet.input.root.Pos()); err != nil {
		return nil, err
	}
	return result, nil
}
