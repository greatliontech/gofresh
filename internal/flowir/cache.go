package flowir

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// PkgCache lowers every FuncDecl and VAR/CONST GenDecl across a package's AST
// files once and indexes nested closures, IIFEs, range blocks, ValueSpecs, and
// expressions so refconfine and dynstate passes share one lowered FlowIR
// representation per package.
type PkgCache struct {
	Info *types.Info
	Pkg  *types.Package

	FuncDecls []*ast.FuncDecl
	GenDecls  []*ast.GenDecl

	bodies map[ast.Node]*Body
	values map[ast.Expr]*Value

	varWritesReady bool
	varWrites      map[*types.Var]*VarWriteInfo

	DeclLowerCount int
	MissCount      int
}

// NewPkgCache lowers all function and var/const declarations across files once.
func NewPkgCache(info *types.Info, pkg *types.Package, files []*ast.File) *PkgCache {
	if info == nil {
		return nil
	}
	c := &PkgCache{
		Info:   info,
		Pkg:    pkg,
		bodies: make(map[ast.Node]*Body, len(files)*8),
		values: make(map[ast.Expr]*Value, len(files)*32),
	}
	for _, file := range files {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				b := LowerFunc(info, pkg, d)
				c.DeclLowerCount++
				if b != nil {
					c.FuncDecls = append(c.FuncDecls, d)
					c.bodies[d] = b
					c.bodies[d.Body] = b
					c.indexNestedBodies(b)
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR && d.Tok != token.CONST {
					continue
				}
				b := LowerNode(info, pkg, d)
				c.DeclLowerCount++
				if b != nil {
					c.GenDecls = append(c.GenDecls, d)
					c.bodies[d] = b
					c.indexGenDeclSpecs(d, b)
					c.indexNestedBodies(b)
				}
			}
		}
		c.indexUnindexedFuncLits(file)
	}
	return c
}

func (c *PkgCache) indexUnindexedFuncLits(file *ast.File) {
	if c == nil || file == nil {
		return
	}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.FuncLit)
		if !ok || lit == nil {
			return true
		}
		if _, exists := c.bodies[lit]; !exists {
			if lb := LowerFuncLit(c.Info, c.Pkg, lit); lb != nil {
				c.bodies[lit] = lb
				if lit.Body != nil {
					c.bodies[lit.Body] = lb
				}
				c.indexNestedBodies(lb)
			}
		}
		return true
	})
}

func (c *PkgCache) indexGenDeclSpecs(gd *ast.GenDecl, b *Body) {
	if gd == nil || b == nil {
		return
	}
	specOps := map[*ast.ValueSpec][]Op{}
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
		vsBody := &Body{
			AST:        vs,
			ScopeStart: vs.Pos(),
			ScopeEnd:   vs.End(),
			BodyStart:  vs.Pos(),
			BodyEnd:    vs.End(),
			Ops:        ops,
		}
		c.bodies[vs] = vsBody
		if gd.Tok == token.VAR && len(ops) == 1 && ops[0].Kind == OpAssign && len(ops[0].Srcs) == len(vs.Values) {
			for i, valExpr := range vs.Values {
				if valExpr == nil || ops[0].Srcs[i] == nil {
					continue
				}
				c.bodies[valExpr] = &Body{
					AST:        valExpr,
					ScopeStart: valExpr.Pos(),
					ScopeEnd:   valExpr.End(),
					BodyStart:  valExpr.Pos(),
					BodyEnd:    valExpr.End(),
					Ops: []Op{{
						Kind:    OpExpr,
						StmtAST: valExpr,
						Expr:    ops[0].Srcs[i],
					}},
				}
			}
		} else if gd.Tok == token.CONST && len(ops) == len(vs.Values) {
			for i, valExpr := range vs.Values {
				if valExpr == nil || ops[i].Kind != OpExpr || ops[i].Expr == nil {
					continue
				}
				c.bodies[valExpr] = &Body{
					AST:        valExpr,
					ScopeStart: valExpr.Pos(),
					ScopeEnd:   valExpr.End(),
					BodyStart:  valExpr.Pos(),
					BodyEnd:    valExpr.End(),
					Ops:        []Op{ops[i]},
				}
			}
		}
	}
}

func (c *PkgCache) indexNestedBodies(b *Body) {
	if c == nil || b == nil {
		return
	}
	indexVal := func(v *Value) {
		if v == nil {
			return
		}
		v.WalkValues(func(cur *Value) bool {
			for raw := cur.Raw; raw != nil; {
				if _, exists := c.values[raw]; !exists || raw == cur.Raw {
					c.values[raw] = cur
				}
				pe, ok := raw.(*ast.ParenExpr)
				if !ok {
					break
				}
				raw = pe.X
			}
			switch cur.Kind {
			case ValMakeClosure:
				if cur.Closure != nil {
					if cur.Lit != nil {
						c.bodies[cur.Lit] = cur.Closure
						if cur.Lit.Body != nil {
							c.bodies[cur.Lit.Body] = cur.Closure
						}
					}
					c.indexNestedBodies(cur.Closure)
				}
			case ValCall:
				if cur.CallKind == CallIIFE && cur.IIFE != nil {
					if cur.CallAST != nil {
						if lit, ok := syntaxutil.UnparenExpr(cur.CallAST.Fun).(*ast.FuncLit); ok && lit != nil {
							c.bodies[lit] = cur.IIFE
							if lit.Body != nil {
								c.bodies[lit.Body] = cur.IIFE
							}
						}
					}
					c.indexNestedBodies(cur.IIFE)
				}
			}
			return true
		})
	}
	for i := range b.Ops {
		op := &b.Ops[i]
		op.ForEachValue(func(v *Value) bool { indexVal(v); return true })
		switch op.Kind {
		case OpAssign:
			if op.AssignKind == AssignRange && op.RangeBody != nil {
				if op.RangeBody.Block != nil {
					c.bodies[op.RangeBody.Block] = op.RangeBody
				}
				c.indexNestedBodies(op.RangeBody)
			}
		case OpGo:
			if op.StmtAST != nil {
				c.bodies[op.StmtAST] = &Body{
					AST:        op.StmtAST,
					ScopeStart: op.StmtAST.Pos(),
					ScopeEnd:   op.StmtAST.End(),
					BodyStart:  op.StmtAST.Pos(),
					BodyEnd:    op.StmtAST.End(),
					Ops: []Op{{
						Kind:    OpGo,
						StmtAST: op.StmtAST,
						Call:    op.Call,
					}},
				}
			}
		}
	}
}

// ScopeBody returns the lowered Body for a FuncDecl, FuncLit, or AST node.
func (c *PkgCache) ScopeBody(enclosing ast.Node) *Body {
	switch n := enclosing.(type) {
	case nil:
		return nil
	case *ast.FuncDecl:
		return c.FuncBody(n)
	case *ast.FuncLit:
		return c.LitBody(n)
	default:
		return c.Body(n)
	}
}

// Body returns the lowered Body for node, lowering on demand on cache miss.
func (c *PkgCache) Body(node ast.Node) *Body {
	if node == nil || c == nil || c.Info == nil {
		return nil
	}
	if b, ok := c.bodies[node]; ok {
		return b
	}
	b := LowerNode(c.Info, c.Pkg, node)
	if b != nil {
		c.MissCount++
		c.bodies[node] = b
		c.indexNestedBodies(b)
	}
	return b
}

// FuncBody returns the lowered Body for fd, lowering on demand on cache miss.
func (c *PkgCache) FuncBody(fd *ast.FuncDecl) *Body {
	if fd == nil || fd.Body == nil || c == nil || c.Info == nil {
		return nil
	}
	if b, ok := c.bodies[fd]; ok {
		return b
	}
	b := LowerFunc(c.Info, c.Pkg, fd)
	if b != nil {
		c.MissCount++
		c.bodies[fd] = b
		c.bodies[fd.Body] = b
		c.indexNestedBodies(b)
	}
	return b
}

// LitBody returns the lowered Body for lit, lowering on demand on cache miss.
func (c *PkgCache) LitBody(lit *ast.FuncLit) *Body {
	if lit == nil || lit.Body == nil || c == nil || c.Info == nil {
		return nil
	}
	if b, ok := c.bodies[lit]; ok {
		return b
	}
	b := LowerFuncLit(c.Info, c.Pkg, lit)
	if b != nil {
		c.MissCount++
		c.bodies[lit] = b
		c.bodies[lit.Body] = b
		c.indexNestedBodies(b)
	}
	return b
}

// ExprValue returns the lowered Value for expr, hitting the pre-indexed value
// map for all expressions inside package function and var/const declarations.
func (c *PkgCache) ExprValue(expr ast.Expr) *Value {
	if expr == nil || c == nil || c.Info == nil {
		return nil
	}
	if v, ok := c.values[expr]; ok {
		return v
	}
	if b, ok := c.bodies[expr]; ok && len(b.Ops) == 1 && b.Ops[0].Kind == OpExpr {
		return b.Ops[0].Expr
	}
	b := LowerNode(c.Info, c.Pkg, expr)
	if b == nil || len(b.Ops) != 1 || b.Ops[0].Kind != OpExpr {
		return nil
	}
	v := b.Ops[0].Expr
	if v != nil {
		c.values[expr] = v
		c.indexNestedBodies(b)
	}
	return v
}
