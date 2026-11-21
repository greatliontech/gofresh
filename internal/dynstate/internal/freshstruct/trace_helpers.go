package freshstruct

import (
	"context"
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

func pkgTraceTarget(p *packages.Package) string {
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

func nodePosString(p *packages.Package, at ast.Node) string {
	if p == nil || p.Fset == nil || at == nil || !at.Pos().IsValid() {
		return ""
	}
	return p.Fset.Position(at.Pos()).String()
}

func emitStructMutated(ctx context.Context, p *packages.Package, target string, ref syntaxutil.TypeRef, reason string, at ast.Node) {
	if !trace.Enabled(ctx, trace.DomainDynstate, target) {
		return
	}
	trace.Emit(ctx, trace.DomainDynstate, "dynstate.struct.mutated", target,
		trace.String("struct", ref.Key()),
		trace.String("reason", reason),
		trace.String("pos", nodePosString(p, at)),
	)
}

func emitCapsuleReject(ctx context.Context, p *packages.Package, target, structName, reason string, at ast.Node) {
	if !trace.Enabled(ctx, trace.DomainDynstate, target) {
		return
	}
	trace.Emit(ctx, trace.DomainDynstate, "dynstate.capsule.reject", target,
		trace.String("struct", structName),
		trace.String("reason", reason),
		trace.String("pos", nodePosString(p, at)),
	)
}

func emitExtractEscape(ctx context.Context, p *packages.Package, target, reason, detail string, at ast.Node) {
	if !trace.Enabled(ctx, trace.DomainDynstate, target) {
		return
	}
	trace.Emit(ctx, trace.DomainDynstate, "dynstate.extract.escape", target,
		trace.String("reason", reason),
		trace.String("detail", detail),
		trace.String("pos", nodePosString(p, at)),
	)
}

func emitExtractEscapeType(ctx context.Context, p *packages.Package, target, reason string, typ types.Type, at ast.Node) {
	if !trace.Enabled(ctx, trace.DomainDynstate, target) {
		return
	}
	detail := ""
	if typ != nil {
		detail = typ.String()
	}
	trace.Emit(ctx, trace.DomainDynstate, "dynstate.extract.escape", target,
		trace.String("reason", reason),
		trace.String("detail", detail),
		trace.String("pos", nodePosString(p, at)),
	)
}

func emitExtractEscapeFunc(ctx context.Context, p *packages.Package, target, reason string, fn *types.Func, at ast.Node) {
	if !trace.Enabled(ctx, trace.DomainDynstate, target) {
		return
	}
	detail := ""
	if fn != nil {
		detail = fn.FullName()
	}
	trace.Emit(ctx, trace.DomainDynstate, "dynstate.extract.escape", target,
		trace.String("reason", reason),
		trace.String("detail", detail),
		trace.String("pos", nodePosString(p, at)),
	)
}

func emitAnyBoundaryCross(ctx context.Context, p *packages.Package, target, reason string, typ types.Type, at ast.Node) {
	if !trace.Enabled(ctx, trace.DomainDynstate, target) {
		return
	}
	detail := ""
	if typ != nil {
		detail = typ.String()
	}
	trace.Emit(ctx, trace.DomainDynstate, "dynstate.any_boundary.cross", target,
		trace.String("reason", reason),
		trace.String("detail", detail),
		trace.String("pos", nodePosString(p, at)),
	)
}
