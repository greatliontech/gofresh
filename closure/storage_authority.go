package closure

import (
	"context"
	"fmt"
	"slices"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

// storageSourceEndpoint carries the opaque checker, not a proposed heap.
type storageSourceEndpoint interface {
	storagePacket() *checkedRegion
	liveAllocation(regionObject, func() error) (regionEffectAllocation, bool, error)
}

func (p *sourceOperandPrefix) storagePacket() *checkedRegion    { return p.checkedPacket() }
func (p *sourceEffectPrefix) storagePacket() *checkedRegion     { return p.checkedPacket() }
func (p *sourceReturnCompletion) storagePacket() *checkedRegion { return p.checkedPacket() }

// storageProtectedFootprints retains control slots over the entire native scope,
// including child calls already returned at the endpoint. Saved required caller
// registers cannot be reassigned to source storage either.
func storageProtectedFootprints(ctx context.Context, b nativeproof.TransitionBound) []storageFootprint {
	var out []storageFootprint
	if b.Interface.ReturnContext != nil {
		extent, _ := b.Geometry.ResolveStorage(ctx, nativeproof.StackOffset(0), 8)
		out = append(out, storageFootprint{Bytes: extent})
	}
	for _, access := range b.Accesses {
		protected := access.Kind == nativeproof.FrameReturnRead
		if access.Kind == nativeproof.FrameWrite && b.Interface.ReturnContext != nil {
			for _, register := range b.Interface.ReturnContext.Preserved {
				protected = protected || access.Value == b.InitialRegisters[register]
			}
		}
		if protected {
			out = append(out, storageFootprint{Bytes: access.Bytes})
		}
	}
	for _, frame := range b.Frames {
		extent, _ := b.Geometry.ResolvePointer(ctx, frame.Slot, 0, 8)
		out = append(out, storageFootprint{Bytes: extent})
	}
	return out
}

// checkStorageAuthority checks source lifetime and native applicability after the
// caller has obtained native from BoundFor(proposal.image). A TransitionBound is
// only a projection: this helper does not confer image/certificate ownership.
func checkStorageAuthority(ctx context.Context, endpoint storageSourceEndpoint, native nativeproof.TransitionBound, proposal storageRepresentation, protected []storageFootprint) (*storageLayout, error) {
	if err := chargeStorageGeometry(ctx, native.Geometry); err != nil {
		return nil, err
	}
	var owner *program
	switch source := endpoint.(type) {
	case *sourceOperandPrefix:
		if source.checkedPacket() != nil {
			owner = source.binder.source.prog
		}
	case *sourceEffectPrefix:
		if source.checkedPacket() != nil {
			owner = source.binder.source.prog
		}
	case *sourceReturnCompletion:
		if source.checkedPacket() != nil {
			owner = source.prior.binder.source.prog
		}
	default:
		return nil, fmt.Errorf("storage authority: endpoint is not an owned source computation")
	}
	if owner == nil || proposal.source != owner {
		return nil, fmt.Errorf("storage authority: selected source owner differs")
	}
	native.InitialMemory = slices.Clone(native.InitialMemory)
	native.Memory = slices.Clone(native.Memory)
	layout, err := resolveStorageRepresentation(ctx, proposal, native.Geometry, protected)
	if err != nil {
		return nil, err
	}
	packet := endpoint.storagePacket()
	if err := regionNativeControl(packet); err != nil {
		return nil, err
	}
	if packet == nil || packet.input.owner != layout.representation.source.Prog || len(packet.observations) != 1 || native.Rules != nativeproof.TransitionRules {
		return nil, fmt.Errorf("storage authority: foreign or unchecked endpoint")
	}
	initial := make(map[nativeproof.TransitionLocation]int, len(native.InitialMemory))
	current := make(map[nativeproof.TransitionLocation]int, len(native.Memory))
	for _, memory := range []struct {
		cells  []nativeproof.TransitionByte
		counts map[nativeproof.TransitionLocation]int
	}{{native.InitialMemory, initial}, {native.Memory, current}} {
		for _, cell := range memory.cells {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			memory.counts[cell.TransitionLocation]++
		}
	}
	for object := range layout.objects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if object.kind == regionAllocation {
			_, live, err := endpoint.liveAllocation(object, ctx.Err)
			if err != nil {
				return nil, err
			}
			if !live {
				return nil, fmt.Errorf("storage authority: allocation lacks actual live singleton evidence")
			}
			frame := native.Interface.PrivateFrame
			footprint, _ := layout.objectFootprint(object)
			if frame == nil {
				return nil, fmt.Errorf("storage authority: allocation lacks native private lifetime ownership")
			}
			private, err := native.Geometry.ResolveStorage(ctx, nativeproof.StackOffset(frame.Bytes.Start), frame.Bytes.End-frame.Bytes.Start)
			if err != nil {
				return nil, err
			}
			if contains, err := native.Geometry.Contains(private, footprint.Bytes); err != nil || !contains {
				return nil, fmt.Errorf("storage authority: allocation lacks native private lifetime ownership")
			}
		}
		footprint, _ := layout.objectFootprint(object)
		for offset := int64(0); offset < footprint.Bytes.Width(); offset++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			location, err := footprint.Bytes.Byte(offset)
			if err != nil {
				return nil, err
			}
			if initial[location] != 1 || current[location] != 1 {
				return nil, fmt.Errorf("storage authority: missing or duplicate represented byte")
			}
		}
	}
	return layout, nil
}

// Geometry retains original placement and entry expressions even when current
// register or memory projections no longer mention them. Walk their DAG under
// the same cumulative correspondence context as all other proof work.
func chargeStorageGeometry(ctx context.Context, geometry nativeproof.ActualTransitionGeometry) error {
	if ctx == nil || geometry == (nativeproof.ActualTransitionGeometry{}) {
		return fmt.Errorf("storage authority: missing context or native geometry")
	}
	seen := map[br.Term]bool{}
	pending := geometry.ExpressionRoots()
	for len(pending) != 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		term := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[term] {
			continue
		}
		if !term.Valid() || len(seen) >= 65536 {
			return fmt.Errorf("storage authority: geometry expression bound exceeded")
		}
		seen[term] = true
		pending = append(pending, term.View().Args...)
	}
	return nil
}
