package dynstate

import (
	"context"
	"go/token"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/trace"
)

func dynstateTarget(p *packages.Package) string {
	if p == nil {
		return ""
	}
	if p.PkgPath != "" {
		return p.PkgPath
	}
	if p.Types != nil {
		return p.Types.Path()
	}
	return ""
}

func emitDischargeReject(ctx context.Context, target, kind, symbol, reason, detail string) {
	if !trace.Enabled(ctx, trace.DomainDynstate, target) {
		return
	}
	trace.Emit(ctx, trace.DomainDynstate, "dynstate.discharge.reject", target,
		trace.String("kind", kind),
		trace.String("symbol", symbol),
		trace.String("reason", reason),
		trace.String("detail", detail),
	)
}

func emitDischargeRejectAt(ctx context.Context, p *packages.Package, target, kind, symbol, reason, detail string, at token.Pos) {
	if !trace.Enabled(ctx, trace.DomainDynstate, target) {
		return
	}
	pos := ""
	if p != nil && p.Fset != nil && at.IsValid() {
		pos = p.Fset.Position(at).String()
	}
	trace.Emit(ctx, trace.DomainDynstate, "dynstate.discharge.reject", target,
		trace.String("kind", kind),
		trace.String("symbol", symbol),
		trace.String("reason", reason),
		trace.String("detail", detail),
		trace.String("pos", pos),
	)
}
