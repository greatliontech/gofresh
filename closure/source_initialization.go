package closure

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
)

// sourceInitialization binds synthetic SSA to the selected language construction.
// It grants no interpretation of imported calls, variable expressions or init
// bodies. Consumers must either interpret them or retain their effects as premises.
type sourceInitialization struct {
	function          *ssa.Function
	guard             *ssa.Global
	blocks            []*ssa.BasicBlock
	imports, explicit []*ssa.Call
	variables         []*types.Var
	initializers      []*types.Initializer
	entry             regionPoint
	suffix            regionPoint
	end               regionUse
}

func (c *selectedSourceBinder) bindInitialization(p *packages.Package) (*sourceInitialization, error) {
	sp := c.source.prog.Prog.Package(p.Types)
	var fn *ssa.Function
	if sp != nil {
		fn = sp.Func("init")
	}
	fail := func() (*sourceInitialization, error) {
		return nil, regionError("selected initialization ownership/CFG disagrees")
	}
	if fn == nil || fn.Pkg != sp || fn.Prog != c.source.prog.Prog || fn.Object() != nil || fn.Syntax() != nil || fn.Signature == nil || fn.Signature.Recv() != nil || fn.Signature.Params().Len() != 0 || fn.Signature.Results().Len() != 0 || len(fn.Params) != 0 || len(fn.FreeVars) != 0 || len(fn.Blocks) != 3 {
		return fail()
	}
	if _, err := c.selectedPackage(fn, p); err != nil {
		return nil, err
	}
	start, body, done := fn.Blocks[0], fn.Blocks[1], fn.Blocks[2]
	if start == nil || body == nil || done == nil || len(start.Instrs) != 2 || len(body.Instrs) < 2 || len(done.Instrs) != 1 || len(start.Succs) != 2 || start.Succs[0] != done || start.Succs[1] != body || len(body.Succs) != 1 || body.Succs[0] != done || len(start.Preds) != 0 || !slices.Equal(body.Preds, []*ssa.BasicBlock{start}) || len(done.Succs) != 0 || len(done.Preds) != 2 || !slices.Contains(done.Preds, start) || !slices.Contains(done.Preds, body) {
		return fail()
	}
	for i, block := range fn.Blocks {
		if block.Parent() != fn || block.Index != i {
			return fail()
		}
		for _, ins := range block.Instrs {
			if err := c.tick(fn, fn.Pos()); err != nil {
				return nil, err
			}
			if ins == nil || ins.Parent() != fn || ins.Block() != block {
				return fail()
			}
		}
	}
	load, ok := start.Instrs[0].(*ssa.UnOp)
	guard, gok := sp.Members["init$guard"].(*ssa.Global)
	branch, bok := start.Instrs[1].(*ssa.If)
	store, sok := body.Instrs[0].(*ssa.Store)
	ret, rok := done.Instrs[0].(*ssa.Return)
	_, jump := body.Instrs[len(body.Instrs)-1].(*ssa.Jump)
	if !ok || !gok || !bok || !sok || !rok || !jump || guard.Pkg != sp || guard.Object() != nil || !types.Identical(guard.Type(), types.NewPointer(types.Typ[types.Bool])) || load.Op != token.MUL || load.X != guard || branch.Cond != load || store.Addr != guard || len(ret.Results) != 0 {
		return fail()
	}
	truth, ok := store.Val.(*ssa.Const)
	if !ok || truth.Value == nil || truth.Value.Kind() != constant.Bool || !constant.BoolVal(truth.Value) {
		return fail()
	}
	r := &sourceInitialization{function: fn, guard: guard, blocks: slices.Clone(fn.Blocks), end: regionUse{at: regionPoint{done, 0}}}
	index := 1
	for _, imported := range p.Types.Imports() {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, err
		}
		if index >= len(body.Instrs) {
			return fail()
		}
		call, ok := body.Instrs[index].(*ssa.Call)
		owner := c.source.prog.Prog.Package(imported)
		if !ok || owner == nil || call.Call.IsInvoke() || call.Call.StaticCallee() != owner.Func("init") || len(call.Call.Args) != 0 {
			return fail()
		}
		r.imports = append(r.imports, call)
		index++
	}
	r.entry = regionPoint{body, index}
	declared := map[*types.Var]ast.Expr{}
	seen := map[*types.Var]bool{}
	var explicit []*ssa.Function
	for _, file := range p.Syntax {
		for _, node := range file.Decls {
			if err := c.tick(fn, node.Pos()); err != nil {
				return nil, err
			}
			switch d := node.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == "init" {
					obj, _ := p.TypesInfo.Defs[d.Name].(*types.Func)
					f := c.source.prog.Prog.FuncValue(obj)
					bound, err := c.bindDeclaration(f)
					if err != nil {
						return nil, err
					}
					if bound.decl != d || bound.pkg != p {
						return fail()
					}
					explicit = append(explicit, f)
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					v, ok := spec.(*ast.ValueSpec)
					if !ok || len(v.Values) != 0 && len(v.Values) != len(v.Names) {
						return fail()
					}
					for i, name := range v.Names {
						if err := c.tick(fn, name.Pos()); err != nil {
							return nil, err
						}
						obj, ok := p.TypesInfo.Defs[name].(*types.Var)
						if !ok || obj.Pkg() != p.Types || obj.Name() == "_" || seen[obj] {
							return fail()
						}
						g, ok := sp.Members[obj.Name()].(*ssa.Global)
						if !ok || g.Pkg != sp || g.Object() != obj || !types.Identical(g.Type(), types.NewPointer(obj.Type())) {
							return fail()
						}
						seen[obj] = true
						r.variables = append(r.variables, obj)
						if len(v.Values) != 0 {
							declared[obj] = v.Values[i]
						}
					}
				}
			}
		}
	}
	for _, init := range p.TypesInfo.InitOrder {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, err
		}
		if init == nil || len(init.Lhs) != 1 || declared[init.Lhs[0]] == nil || declared[init.Lhs[0]] != init.Rhs {
			return fail()
		}
		delete(declared, init.Lhs[0])
		r.initializers = append(r.initializers, init)
	}
	if len(declared) != 0 {
		return fail()
	}
	cut := len(body.Instrs) - 1 - len(explicit)
	if cut < index {
		return fail()
	}
	r.suffix = regionPoint{body, cut}
	for i, target := range explicit {
		call, ok := body.Instrs[cut+i].(*ssa.Call)
		if !ok || call.Call.IsInvoke() || call.Call.StaticCallee() != target || len(call.Call.Args) != 0 {
			return fail()
		}
		r.explicit = append(r.explicit, call)
	}
	writes := 0
	for _, ins := range body.Instrs[index:cut] {
		if err := c.tick(fn, ins.Pos()); err != nil {
			return nil, err
		}
		if s, ok := ins.(*ssa.Store); ok {
			if _, global := s.Addr.(*ssa.Global); global {
				if writes >= len(r.initializers) || s.Addr != sp.Members[r.initializers[writes].Lhs[0].Name()].(*ssa.Global) {
					return fail()
				}
				writes++
			}
		}
		if call, ok := ins.(*ssa.Call); ok && slices.Contains(explicit, call.Call.StaticCallee()) {
			// An additional explicit init cannot hide among variable expressions.
			// These declarations cannot be called by source-language expressions.
			return fail()
		}
	}
	if writes != len(r.initializers) {
		return fail()
	}
	return r, nil
}
