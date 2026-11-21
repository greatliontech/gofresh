package dynstate

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// pkgFlowCache caches lowered flowir.Body representations, lowered expression
// nodes, scoped local memory-alias graphs, and single-write variable summaries
// across all dynamic-state passes on a single package so each declaration in
// p.Syntax is lowered at most once.
type pkgFlowCache struct {
	audited bool
	base    *flowir.PkgCache

	localCarrierAliases map[*flowir.Body]map[types.Object]map[types.Object]bool
	interiorAliases     map[*flowir.Body]map[types.Object]map[types.Object]bool

	declLowerCount int
	missCount      int
}

func newPkgFlowCache(audited bool, p *packages.Package) *pkgFlowCache {
	return newPkgFlowCacheWithIndex(audited, p, nil)
}

func newPkgFlowCacheWithIndex(audited bool, p *packages.Package, idx *refconfine.PkgIndex) *pkgFlowCache {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	var base *flowir.PkgCache
	if idx != nil {
		base = idx.FlowCache(p)
	} else {
		base = flowir.NewPkgCache(p.TypesInfo, p.Types, p.Syntax)
	}
	if base == nil {
		return nil
	}
	return &pkgFlowCache{
		audited:             audited,
		base:                base,
		localCarrierAliases: make(map[*flowir.Body]map[types.Object]map[types.Object]bool),
		interiorAliases:     make(map[*flowir.Body]map[types.Object]map[types.Object]bool),
		declLowerCount:      base.DeclLowerCount,
		missCount:           base.MissCount,
	}
}

func (fc *pkgFlowCache) attachToIndex(idx *refconfine.PkgIndex) {
	if fc != nil && fc.base != nil && idx != nil {
		idx.SetFlowCache(fc.base)
	}
}

func (fc *pkgFlowCache) syncStats() {
	if fc != nil && fc.base != nil {
		fc.declLowerCount = fc.base.DeclLowerCount
		fc.missCount = fc.base.MissCount
	}
}

func (fc *pkgFlowCache) ensureBase(p *packages.Package) *flowir.PkgCache {
	if fc != nil && fc.base != nil {
		return fc.base
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	return flowir.NewPkgCache(p.TypesInfo, p.Types, p.Syntax)
}

func (fc *pkgFlowCache) scopeBody(p *packages.Package, enclosing ast.Node) *flowir.Body {
	switch n := enclosing.(type) {
	case nil:
		return nil
	case *ast.FuncDecl:
		return fc.funcBody(p, n)
	case *ast.FuncLit:
		return fc.litBody(p, n)
	default:
		return fc.body(p, n)
	}
}

func (fc *pkgFlowCache) body(p *packages.Package, node ast.Node) *flowir.Body {
	if node == nil {
		return nil
	}
	if fc != nil && fc.base != nil {
		b := fc.base.Body(node)
		fc.syncStats()
		return b
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	return flowir.LowerNode(p.TypesInfo, p.Types, node)
}

func (fc *pkgFlowCache) funcBody(p *packages.Package, fd *ast.FuncDecl) *flowir.Body {
	if fd == nil || fd.Body == nil {
		return nil
	}
	if fc != nil && fc.base != nil {
		b := fc.base.FuncBody(fd)
		fc.syncStats()
		return b
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	return flowir.LowerFunc(p.TypesInfo, p.Types, fd)
}

func (fc *pkgFlowCache) litBody(p *packages.Package, lit *ast.FuncLit) *flowir.Body {
	if lit == nil || lit.Body == nil {
		return nil
	}
	if fc != nil && fc.base != nil {
		b := fc.base.LitBody(lit)
		fc.syncStats()
		return b
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	return flowir.LowerFuncLit(p.TypesInfo, p.Types, lit)
}

func (fc *pkgFlowCache) exprValue(p *packages.Package, expr ast.Expr) *flowir.Value {
	if expr == nil {
		return nil
	}
	if fc != nil && fc.base != nil {
		return fc.base.ExprValue(expr)
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	b := flowir.LowerNode(p.TypesInfo, p.Types, expr)
	if b == nil || len(b.Ops) != 1 || b.Ops[0].Kind != flowir.OpExpr {
		return nil
	}
	return b.Ops[0].Expr
}

func (fc *pkgFlowCache) scopedLocalCarrierAliases(audited bool, b *flowir.Body, allowObj func(types.Object) bool) map[types.Object]map[types.Object]bool {
	if b == nil {
		return nil
	}
	shares := func(t types.Type) bool {
		return canAliasCarrierType(audited, t)
	}
	if allowObj != nil {
		return flowir.BuildScopedMemAliases(b, allowObj, shares)
	}
	if fc != nil && fc.audited == audited {
		if adj, ok := fc.localCarrierAliases[b]; ok {
			return adj
		}
	}
	adj := flowir.BuildScopedMemAliases(b, syntaxutil.IsLocalVar, shares)
	if fc != nil && fc.audited == audited {
		fc.localCarrierAliases[b] = adj
	}
	return adj
}

func (fc *pkgFlowCache) scopedBodyInteriorAliases(audited bool, b *flowir.Body, exclude map[types.Object]bool) map[types.Object]map[types.Object]bool {
	if b == nil {
		return nil
	}
	shares := sharesMemOrSigOrDynamic(audited)
	hasInteriorExclude := false
	for r := range exclude {
		if v, ok := r.(*types.Var); ok && v != nil && !v.IsField() && !isPkgOrOuterToBody(b, v) {
			hasInteriorExclude = true
			break
		}
	}
	if hasInteriorExclude {
		return flowir.BuildScopedMemAliases(
			b,
			func(obj types.Object) bool {
				v, ok := obj.(*types.Var)
				return ok && v != nil && !v.IsField() && !exclude[v] && !isPkgOrOuterToBody(b, v)
			},
			shares,
		)
	}
	if fc != nil && fc.audited == audited {
		if adj, ok := fc.interiorAliases[b]; ok {
			return adj
		}
	}
	adj := flowir.BuildScopedMemAliases(
		b,
		func(obj types.Object) bool {
			v, ok := obj.(*types.Var)
			return ok && v != nil && !v.IsField() && !isPkgOrOuterToBody(b, v)
		},
		shares,
	)
	if fc != nil && fc.audited == audited {
		fc.interiorAliases[b] = adj
	}
	return adj
}

func (fc *pkgFlowCache) varWriteInfos(p *packages.Package) map[*types.Var]*flowir.VarWriteInfo {
	base := fc.ensureBase(p)
	if base == nil {
		return nil
	}
	res := base.VarWriteInfos()
	fc.syncStats()
	return res
}

func (fc *pkgFlowCache) singleWritePkgGlobalInit(p *packages.Package, gv *types.Var) (*flowir.Value, bool) {
	if gv == nil || p == nil || p.Types == nil || gv.Pkg() != p.Types || gv.Parent() != p.Types.Scope() {
		return nil, false
	}
	base := fc.ensureBase(p)
	if base == nil {
		return nil, false
	}
	val, ok := base.SingleWritePkgGlobalInit(gv)
	fc.syncStats()
	return val, ok
}

func (fc *pkgFlowCache) singleWriteLocalInit(p *packages.Package, fnBody *flowir.Body, lv *types.Var) (*flowir.Value, bool) {
	base := fc.ensureBase(p)
	if base == nil {
		return nil, false
	}
	val, ok := base.SingleWriteLocalInit(fnBody, lv)
	fc.syncStats()
	return val, ok
}

func (fc *pkgFlowCache) varHasExplicitWriteOrAddr(p *packages.Package, v *types.Var) bool {
	base := fc.ensureBase(p)
	if base == nil {
		return true
	}
	res := base.VarHasExplicitWriteOrAddr(v)
	fc.syncStats()
	return res
}
