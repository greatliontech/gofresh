package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// pkgFlowCache caches lowered flowir.Body representations, lowered expression
// nodes, and scoped local memory-alias graphs across all dynamic-state passes
// on a single package so each declaration in p.Syntax is lowered at most once.
type pkgFlowCache struct {
	audited bool
	info    *types.Info
	pkg     *types.Package

	bodies              map[ast.Node]*flowir.Body
	values              map[ast.Expr]*flowir.Value
	localCarrierAliases map[*flowir.Body]map[types.Object]map[types.Object]bool
	interiorAliases     map[*flowir.Body]map[types.Object]map[types.Object]bool

	declLowerCount int
	missCount      int
}

func newPkgFlowCache(audited bool, p *packages.Package) *pkgFlowCache {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	fc := &pkgFlowCache{
		audited:             audited,
		info:                p.TypesInfo,
		pkg:                 p.Types,
		bodies:              make(map[ast.Node]*flowir.Body, len(p.Syntax)*8),
		values:              make(map[ast.Expr]*flowir.Value, len(p.Syntax)*32),
		localCarrierAliases: make(map[*flowir.Body]map[types.Object]map[types.Object]bool),
		interiorAliases:     make(map[*flowir.Body]map[types.Object]map[types.Object]bool),
	}
	for _, file := range p.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				b := flowir.LowerFunc(p.TypesInfo, p.Types, d)
				fc.declLowerCount++
				if b != nil {
					fc.bodies[d] = b
					fc.bodies[d.Body] = b
					fc.indexNestedBodies(b)
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR && d.Tok != token.CONST {
					continue
				}
				b := flowir.LowerNode(p.TypesInfo, p.Types, d)
				fc.declLowerCount++
				if b != nil {
					fc.bodies[d] = b
					fc.indexGenDeclSpecs(d, b)
					fc.indexNestedBodies(b)
				}
			}
		}
	}
	return fc
}

func (fc *pkgFlowCache) indexGenDeclSpecs(gd *ast.GenDecl, b *flowir.Body) {
	if gd == nil || b == nil {
		return
	}
	specOps := map[*ast.ValueSpec][]flowir.Op{}
	for _, op := range b.Ops {
		if vs, ok := op.StmtAST.(*ast.ValueSpec); ok && vs != nil {
			specOps[vs] = append(specOps[vs], op)
		}
	}
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || vs == nil {
			continue
		}
		ops := specOps[vs]
		vsBody := &flowir.Body{
			AST:        vs,
			ScopeStart: vs.Pos(),
			ScopeEnd:   vs.End(),
			BodyStart:  vs.Pos(),
			BodyEnd:    vs.End(),
			Ops:        ops,
		}
		fc.bodies[vs] = vsBody
		if gd.Tok == token.VAR && len(ops) == 1 && ops[0].Kind == flowir.OpAssign && len(ops[0].Srcs) == len(vs.Values) {
			for i, valExpr := range vs.Values {
				if valExpr == nil || ops[0].Srcs[i] == nil {
					continue
				}
				fc.bodies[valExpr] = &flowir.Body{
					AST:        valExpr,
					ScopeStart: valExpr.Pos(),
					ScopeEnd:   valExpr.End(),
					BodyStart:  valExpr.Pos(),
					BodyEnd:    valExpr.End(),
					Ops: []flowir.Op{{
						Kind:    flowir.OpExpr,
						StmtAST: valExpr,
						Expr:    ops[0].Srcs[i],
					}},
				}
			}
		} else if gd.Tok == token.CONST && len(ops) == len(vs.Values) {
			for i, valExpr := range vs.Values {
				if valExpr == nil || ops[i].Kind != flowir.OpExpr || ops[i].Expr == nil {
					continue
				}
				fc.bodies[valExpr] = &flowir.Body{
					AST:        valExpr,
					ScopeStart: valExpr.Pos(),
					ScopeEnd:   valExpr.End(),
					BodyStart:  valExpr.Pos(),
					BodyEnd:    valExpr.End(),
					Ops:        []flowir.Op{ops[i]},
				}
			}
		}
	}
}

func (fc *pkgFlowCache) indexNestedBodies(b *flowir.Body) {
	if fc == nil || b == nil {
		return
	}
	indexVal := func(v *flowir.Value) {
		if v == nil {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			for raw := cur.Raw; raw != nil; {
				if _, exists := fc.values[raw]; !exists || raw == cur.Raw {
					fc.values[raw] = cur
				}
				pe, ok := raw.(*ast.ParenExpr)
				if !ok {
					break
				}
				raw = pe.X
			}
			switch cur.Kind {
			case flowir.ValMakeClosure:
				if cur.Closure != nil {
					if cur.Lit != nil {
						fc.bodies[cur.Lit] = cur.Closure
						if cur.Lit.Body != nil {
							fc.bodies[cur.Lit.Body] = cur.Closure
						}
					}
					fc.indexNestedBodies(cur.Closure)
				}
			case flowir.ValCall:
				if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil {
					if cur.CallAST != nil {
						if lit, ok := syntaxutil.UnparenExpr(cur.CallAST.Fun).(*ast.FuncLit); ok && lit != nil {
							fc.bodies[lit] = cur.IIFE
							if lit.Body != nil {
								fc.bodies[lit.Body] = cur.IIFE
							}
						}
					}
					fc.indexNestedBodies(cur.IIFE)
				}
			}
			return true
		})
	}
	for i := range b.Ops {
		op := &b.Ops[i]
		switch op.Kind {
		case flowir.OpAssign:
			for _, dst := range op.Dsts {
				dst.ForEachChildValue(func(cv *flowir.Value) bool { indexVal(cv); return true })
			}
			for _, src := range op.Srcs {
				indexVal(src)
			}
			if op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
				if op.RangeBody.Block != nil {
					fc.bodies[op.RangeBody.Block] = op.RangeBody
				}
				fc.indexNestedBodies(op.RangeBody)
			}
		case flowir.OpTypeSwitchBind:
			indexVal(op.SwitchSrc)
		case flowir.OpChanSend:
			op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool { indexVal(cv); return true })
			indexVal(op.ChanVal)
			indexVal(op.SendVal)
		case flowir.OpReturn:
			for _, r := range op.Results {
				indexVal(r)
			}
		case flowir.OpDefer:
			indexVal(op.Call)
		case flowir.OpGo:
			if op.StmtAST != nil {
				fc.bodies[op.StmtAST] = &flowir.Body{
					AST:        op.StmtAST,
					ScopeStart: op.StmtAST.Pos(),
					ScopeEnd:   op.StmtAST.End(),
					BodyStart:  op.StmtAST.Pos(),
					BodyEnd:    op.StmtAST.End(),
					Ops: []flowir.Op{{
						Kind:    flowir.OpGo,
						StmtAST: op.StmtAST,
						Call:    op.Call,
					}},
				}
			}
			indexVal(op.Call)
		case flowir.OpExpr:
			indexVal(op.Expr)
		}
	}
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
	if fc != nil {
		if b, ok := fc.bodies[node]; ok {
			return b
		}
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	b := flowir.LowerNode(p.TypesInfo, p.Types, node)
	if fc != nil && b != nil {
		fc.missCount++
		fc.bodies[node] = b
		fc.indexNestedBodies(b)
	}
	return b
}

func (fc *pkgFlowCache) funcBody(p *packages.Package, fd *ast.FuncDecl) *flowir.Body {
	if fd == nil || fd.Body == nil {
		return nil
	}
	if fc != nil {
		if b, ok := fc.bodies[fd]; ok {
			return b
		}
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	b := flowir.LowerFunc(p.TypesInfo, p.Types, fd)
	if fc != nil && b != nil {
		fc.missCount++
		fc.bodies[fd] = b
		fc.bodies[fd.Body] = b
		fc.indexNestedBodies(b)
	}
	return b
}

func (fc *pkgFlowCache) litBody(p *packages.Package, lit *ast.FuncLit) *flowir.Body {
	if lit == nil || lit.Body == nil {
		return nil
	}
	if fc != nil {
		if b, ok := fc.bodies[lit]; ok {
			return b
		}
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	b := flowir.LowerFuncLit(p.TypesInfo, p.Types, lit)
	if fc != nil && b != nil {
		fc.missCount++
		fc.bodies[lit] = b
		fc.bodies[lit.Body] = b
		fc.indexNestedBodies(b)
	}
	return b
}

// exprValue returns the lowered *flowir.Value for expr, hitting the pre-indexed
// value map for all expressions inside package function and var/const
// declarations and falling back to expression lowering only for standalone
// expressions (such as inside type declarations or nil caches).
func (fc *pkgFlowCache) exprValue(p *packages.Package, expr ast.Expr) *flowir.Value {
	if expr == nil {
		return nil
	}
	if fc != nil {
		if v, ok := fc.values[expr]; ok {
			return v
		}
		if b, ok := fc.bodies[expr]; ok && len(b.Ops) == 1 && b.Ops[0].Kind == flowir.OpExpr {
			return b.Ops[0].Expr
		}
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	b := flowir.LowerNode(p.TypesInfo, p.Types, expr)
	if b == nil || len(b.Ops) != 1 || b.Ops[0].Kind != flowir.OpExpr {
		return nil
	}
	v := b.Ops[0].Expr
	if fc != nil && v != nil {
		fc.values[expr] = v
		fc.indexNestedBodies(b)
	}
	return v
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
