package closure

import (
	"context"
	"fmt"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/assemblycapture"
)

type assemblyCaptureLimits = assemblycapture.Limits

// selectedAssemblyPacket cannot be constructed from detached provider text.
// Its private action packet and exact typed package instance retain independent
// acquisition and source-owner authority through reference interpretation.
type selectedAssemblyPacket struct {
	owner    *selectedSourceOwner
	provider *packages.Package
	packet   *assemblycapture.Packet
}

func acquireSelectedAssembly(ctx context.Context, owner *selectedSourceOwner, provider *packages.Package, limits assemblycapture.Limits) (*selectedAssemblyPacket, error) {
	if ctx == nil {
		return nil, fmt.Errorf("selected assembly: context absent")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner == nil || owner.selection == nil || owner.prog == nil || provider == nil {
		return nil, fmt.Errorf("selected assembly: source owner or provider absent")
	}
	id, ok := owner.packages[provider]
	if !ok {
		return nil, fmt.Errorf("selected assembly: foreign exact package instance")
	}
	packet, err := assemblycapture.Acquire(ctx, owner.selection, id, limits)
	if err != nil {
		return nil, err
	}
	return &selectedAssemblyPacket{owner: owner, provider: provider, packet: packet}, nil
}

func (p *selectedAssemblyPacket) boundTo(source computationSource, provider *packages.Package) bool {
	return p != nil && p.owner != nil && source.owner == p.owner && source.prog == p.owner.prog && p.provider == provider && p.packet.BoundTo(p.owner.selection, p.owner.packages[provider])
}

func (p *selectedAssemblyPacket) providerTexts() []assemblycapture.Provider {
	if p == nil {
		return nil
	}
	return p.packet.Providers()
}
func (p *selectedAssemblyPacket) selectionEnv() map[string]string {
	if p == nil {
		return nil
	}
	return p.packet.Environment()
}
func (p *selectedAssemblyPacket) selectionFlags() []string {
	if p == nil || p.owner == nil {
		return nil
	}
	return p.owner.selection.Flags()
}
