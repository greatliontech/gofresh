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
// Every initializing path in its acyclic graph consumes the exact typed
// initialization order before the common explicit-init suffix and return.
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
	if fn == nil || fn.Pkg != sp || fn.Prog != c.source.prog.Prog || fn.Object() != nil || fn.Syntax() != nil || fn.Signature == nil || fn.Signature.Recv() != nil || fn.Signature.Params().Len() != 0 || fn.Signature.Results().Len() != 0 || len(fn.Params) != 0 || len(fn.FreeVars) != 0 || len(fn.Blocks) < 3 {
		return fail()
	}
	if _, err := c.selectedPackage(fn, p); err != nil {
		return nil, err
	}
	start, body := fn.Blocks[0], fn.Blocks[1]
	if start == nil || body == nil || len(start.Instrs) != 2 || len(body.Instrs) < 2 || len(start.Succs) != 2 || start.Succs[1] != body || len(start.Preds) != 0 || !slices.Equal(body.Preds, []*ssa.BasicBlock{start}) {
		return fail()
	}
	done := start.Succs[0]
	if done == nil || done == start || done == body || len(done.Instrs) != 1 || len(done.Succs) != 0 {
		return fail()
	}
	// Validate the actual graph, not a proposed block count. Each edge appears
	// once in both directions; every instruction has its exact owner, and only
	// the unique common void return may terminate a path. Work also bounds all
	// maps and queues allocated below.
	blocks := map[*ssa.BasicBlock]bool{}
	instructions := map[ssa.Instruction]bool{}
	type edge struct{ from, to *ssa.BasicBlock }
	edges := map[edge]bool{}
	for i, block := range fn.Blocks {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, err
		}
		if block == nil || block.Parent() != fn || block.Index != i || blocks[block] || len(block.Instrs) == 0 {
			return fail()
		}
		blocks[block] = true
		for j, ins := range block.Instrs {
			if err := c.tick(fn, fn.Pos()); err != nil {
				return nil, err
			}
			if ins == nil || ins.Parent() != fn || ins.Block() != block || instructions[ins] {
				return fail()
			}
			instructions[ins] = true
			terminal := false
			switch v := ins.(type) {
			case *ssa.Jump:
				terminal = len(block.Succs) == 1
			case *ssa.If:
				terminal = len(block.Succs) == 2
			case *ssa.Return:
				terminal = block == done && len(v.Results) == 0 && len(block.Succs) == 0
			case *ssa.Panic:
				return fail()
			default:
				if j == len(block.Instrs)-1 {
					return fail()
				}
				continue
			}
			if !terminal || j != len(block.Instrs)-1 {
				return fail()
			}
		}
	}
	pending := map[*ssa.BasicBlock]int{}
	for _, block := range fn.Blocks {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, err
		}
		for _, succ := range block.Succs {
			if err := c.tick(fn, fn.Pos()); err != nil {
				return nil, err
			}
			e := edge{block, succ}
			if !blocks[succ] || edges[e] {
				return fail()
			}
			edges[e] = true
			pending[succ]++
		}
	}
	for _, block := range fn.Blocks {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, err
		}
		for _, pred := range block.Preds {
			if err := c.tick(fn, fn.Pos()); err != nil {
				return nil, err
			}
			e := edge{pred, block}
			if !edges[e] {
				return fail()
			}
			delete(edges, e)
		}
	}
	if len(edges) != 0 {
		return fail()
	}
	// Kahn traversal from the actual entry rejects cycles and detached blocks.
	order := []*ssa.BasicBlock{start}
	for i := 0; i < len(order); i++ {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, err
		}
		for _, succ := range order[i].Succs {
			if err := c.tick(fn, fn.Pos()); err != nil {
				return nil, err
			}
			pending[succ]--
			if pending[succ] == 0 {
				order = append(order, succ)
			}
		}
	}
	if len(order) != len(fn.Blocks) {
		return fail()
	}
	load, ok := start.Instrs[0].(*ssa.UnOp)
	guard, gok := sp.Members["init$guard"].(*ssa.Global)
	branch, bok := start.Instrs[1].(*ssa.If)
	store, sok := body.Instrs[0].(*ssa.Store)
	ret, rok := done.Instrs[0].(*ssa.Return)
	if !ok || !gok || !bok || !sok || !rok || guard.Pkg != sp || guard.Object() != nil || !types.Identical(guard.Type(), types.NewPointer(types.Typ[types.Bool])) || load.Op != token.MUL || load.X != guard || branch.Cond != load || store.Addr != guard || len(ret.Results) != 0 {
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
		if !ok || owner == nil || owner.Func("init") == nil || call.Call.IsInvoke() || call.Call.Value != owner.Func("init") || len(call.Call.Args) != 0 {
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
	// Explicit init declarations form one contiguous common suffix immediately
	// before the jump to the return. With none, the return itself is the cut.
	r.suffix = r.end.at
	if len(explicit) != 0 {
		var tail *ssa.BasicBlock
		for _, pred := range done.Preds {
			if err := c.tick(fn, fn.Pos()); err != nil {
				return nil, err
			}
			if pred != start {
				if tail != nil {
					return fail()
				}
				tail = pred
			}
		}
		if tail == nil || len(tail.Succs) != 1 || tail.Succs[0] != done {
			return fail()
		}
		cut := len(tail.Instrs) - 1 - len(explicit)
		if cut < 0 || tail == body && cut < index {
			return fail()
		}
		r.suffix = regionPoint{tail, cut}
		for i, target := range explicit {
			if err := c.tick(fn, fn.Pos()); err != nil {
				return nil, err
			}
			call, ok := tail.Instrs[cut+i].(*ssa.Call)
			if !ok || call.Call.IsInvoke() || call.Call.Value != target || len(call.Call.Args) != 0 {
				return fail()
			}
			r.explicit = append(r.explicit, call)
		}
	}
	explicitSet := map[*ssa.Function]bool{}
	for _, target := range explicit {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, err
		}
		explicitSet[target] = true
	}
	// A progress value is the exact initialized prefix of typed InitOrder.
	// Compatible joins make this linear in the graph, not in its path count.
	// Alternative branch stores to the same next global are legitimate; equal
	// total store counts with different targets/order are not.
	progress := map[*ssa.BasicBlock]int{body: 0}
	for _, block := range order[1:] {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, err
		}
		writes, reached := progress[block]
		if !reached {
			return fail()
		}
		first, last := 0, len(block.Instrs)
		if block == body {
			first = index
		}
		if block == r.suffix.block {
			last = r.suffix.index
		}
		for _, ins := range block.Instrs[first:last] {
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
			if call, ok := ins.(ssa.CallInstruction); ok && explicitSet[call.Common().StaticCallee()] {
				// Source expressions cannot call explicit init declarations.
				return fail()
			}
		}
		if block == r.suffix.block && writes != len(r.initializers) {
			return fail()
		}
		for _, succ := range block.Succs {
			if err := c.tick(fn, fn.Pos()); err != nil {
				return nil, err
			}
			if previous, exists := progress[succ]; exists && previous != writes {
				return fail()
			}
			progress[succ] = writes
		}
	}
	return r, nil
}
