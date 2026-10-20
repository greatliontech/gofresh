package closure

import (
	"context"
	"fmt"
	"slices"

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
func storageProtectedFootprints(b nativeproof.TransitionBound) []storageFootprint {
	var out []storageFootprint
	if b.Interface.ReturnContext != nil {
		out = append(out, storageFootprint{Bytes: nativeproof.RelativeSpan{Start: 0, End: 8}})
	}
	for _, access := range b.Accesses {
		protected := access.Kind == nativeproof.FrameReturnRead
		if access.Kind == nativeproof.FrameWrite && b.Interface.ReturnContext != nil {
			for _, register := range b.Interface.ReturnContext.Preserved {
				protected = protected || access.Value == b.InitialRegisters[register]
			}
		}
		if protected {
			out = append(out, storageFootprint{Image: access.Image, Bytes: access.Bytes})
		}
	}
	for _, frame := range b.Frames {
		out = append(out, storageFootprint{Bytes: nativeproof.RelativeSpan{Start: frame.Slot.Offset, End: frame.Slot.Offset + 8}})
	}
	return out
}

// checkStorageAuthority checks source lifetime and native applicability after the
// caller has obtained native from BoundFor(proposal.image). A TransitionBound is
// only a projection: this helper does not confer image/certificate ownership.
func checkStorageAuthority(ctx context.Context, endpoint storageSourceEndpoint, native nativeproof.TransitionBound, proposal storageRepresentation, protected []storageFootprint) (*storageLayout, error) {
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
	native.Interface.Regions = slices.Clone(native.Interface.Regions)
	native.Interface.ImageRegions = slices.Clone(native.Interface.ImageRegions)
	layout, err := resolveStorageRepresentation(ctx, proposal, protected)
	if err != nil {
		return nil, err
	}
	packet := endpoint.storagePacket()
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
	for object, storage := range layout.objects {
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
			if frame == nil || footprint.Bytes.Start < frame.Bytes.Start || footprint.Bytes.End > frame.Bytes.End {
				return nil, fmt.Errorf("storage authority: allocation lacks native private lifetime ownership")
			}
			origin := native.Interface.Origin
			align := uint64(storage.shape.align)
			if origin.Modulus == 0 || origin.Modulus%align != 0 || (origin.Residue+uint64(storage.base.Offset))%align != 0 {
				return nil, fmt.Errorf("storage authority: retained origin does not establish alignment")
			}
		}
		footprint, _ := layout.objectFootprint(object)
		for offset := footprint.Bytes.Start; offset < footprint.Bytes.End; offset++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			location := nativeproof.TransitionLocation{Image: footprint.Image, Offset: offset}
			if initial[location] != 1 || current[location] != 1 {
				return nil, fmt.Errorf("storage authority: missing or duplicate represented byte")
			}
			mapped := false
			if footprint.Image {
				for _, span := range native.Interface.ImageRegions {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					mapped = mapped || uint64(offset) >= span.Start && uint64(offset) < span.End
				}
			} else {
				for _, region := range native.Interface.Regions {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					// Permissions come from the checked interface; actual read/write
					// accesses are separately authorized by the native theorem.
					mapped = mapped || offset >= region.Bytes.Start && offset < region.Bytes.End && (region.Readable || region.Writable)
				}
			}
			if !mapped {
				return nil, fmt.Errorf("storage authority: extent leaves checked mapping")
			}
		}
	}
	return layout, nil
}
