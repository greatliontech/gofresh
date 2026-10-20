package closure

import "context"

// sourceRegion adds selected callable ownership to a checked conditional region.
// Its packet owns the actual entry states, call contexts and captured environments;
// bindings never replace those facts with a target-name list. All native, frame,
// omitted-prefix, concurrency and harness obligations remain open.
type sourceRegion struct {
	packet *checkedRegion
	root   selectedSourceCallable
	calls  []sourceRegionCall
}

type sourceRegionCall struct {
	call        *regionCallProof
	bound       selectedSourceCallable
	declaration selectedSourceDeclaration
	reference   *assemblyReference
}

func checkSourceRegion(ctx context.Context, source computationSource, input regionInput, proposal *regionProposal, sourceLimits selectedSourceLimits, limits regionLimits) (*sourceRegion, error) {
	if ctx == nil {
		return nil, regionError("source region context is absent")
	}
	// The kernel owns caller containers before its first context callback.
	packet, err := checkRegion(ctx, input, proposal, limits)
	if err != nil {
		return nil, err
	}
	b, err := newSelectedSourceBinder(ctx, source, packet.input.root, sourceLimits)
	if err != nil {
		return nil, err
	}
	return b.checkSourceRegion(packet)
}

// checkSourceRegion composes the checked transport with exact selected ownership.
// A whole-program source consumer shares this binder across its startup phases.
func (b *selectedSourceBinder) checkSourceRegion(packet *checkedRegion) (*sourceRegion, error) {
	if packet == nil || packet.input.selection != nil && packet.input.selection != b.source.prog {
		return nil, regionError("region has another selected layout owner")
	}
	root, err := b.bindCallable(packet.input.root)
	if err != nil {
		return nil, err
	}
	calls, err := b.bindRegionCalls(packet)
	if err != nil {
		return nil, err
	}
	return &sourceRegion{packet: packet, root: root, calls: calls}, nil
}

// The kernel's used list is already transitive. Proposal-only candidates do not
// enter it. Registration uses this seam beside its separate exact init/main
// construction binding; it does not relabel synthetic init as a declaration.
func (b *selectedSourceBinder) bindRegionCalls(packet *checkedRegion) ([]sourceRegionCall, error) {
	if packet == nil || packet.rules != regionRules || packet.input.owner != b.source.prog.Prog {
		return nil, regionError("checked region has another selected source owner")
	}
	var calls []sourceRegionCall
	for _, call := range packet.calls {
		if err := b.tick(packet.input.root, packet.input.root.Pos()); err != nil {
			return nil, err
		}
		if call == nil {
			return nil, regionError("checked region has an absent call dependency")
		}
		if call.reference != nil {
			decl, err := b.bindDeclaration(call.target)
			if err != nil {
				return nil, err
			}
			if err := call.reference.boundTo(b.source, call.target); err != nil {
				return nil, err
			}
			calls = append(calls, sourceRegionCall{call: call, declaration: decl, reference: call.reference})
			continue
		}
		bound, err := b.bindCallable(call.target)
		if err != nil {
			return nil, err
		}
		calls = append(calls, sourceRegionCall{call: call, bound: bound})
	}
	if err := b.tick(packet.input.root, packet.input.root.Pos()); err != nil {
		return nil, err
	}
	return calls, nil
}
