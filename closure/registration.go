package closure

import (
	"context"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
)

// A registration is a private, source-only conditional construction-to-operand
// receipt. The typed owner is immutable for its lifetime. In particular neither
// this receipt nor a callback's identity establishes a native invocation, startup
// effect bound, or harness behavior.
type registration struct {
	source       computationSource
	selected     *packages.Package
	main         selectedSourceDeclaration
	init         *ssa.Function
	packageInput selectedSourcePackage
	variables    []*types.Var
	initializers []*types.Initializer
	guard        []*ssa.BasicBlock
	imports      []*ssa.Call
	intervening  []*ssa.Call
	construction *checkedRegion
	frame        registrationFrame
	call         *ssa.Call
	arguments    []registrationArgument
	callbacks    []selectedSourceDeclaration
	open         []string
}

// The frame is an OPEN equality premise, with exact endpoints and the entire
// reachable heap retained. Registers and unreachable temporaries of the ending
// initialization frame die. It is not a summary of the explicit calls between
// these points.
type registrationFrame struct {
	from, to regionPoint
	heap     regionState
	dead     []regionObject
}

type registrationArgument struct {
	index  int
	object *types.Var // nil for a concrete value boxed into an interface
	global *ssa.Global
	rows   []regionValue
	value  regionValue
	packet *checkedRegion
}

type registrationLimits struct {
	source selectedSourceLimits
	region regionLimits
}

func defaultRegistrationLimits() registrationLimits {
	return registrationLimits{selectedSourceLimits{work: 262144, depth: 128, bytes: 16 << 20}, defaultRegionLimits()}
}

type registrationChecker struct {
	*selectedSourceBinder
	root   *ssa.Function
	limits regionLimits
	bound  []selectedSourceDeclaration
}

type registrationTable struct {
	object *types.Var
	global *ssa.Global
	init   *types.Initializer
	rows   []regionValue
}

// packageID is a locator, not an approval label. The package must occur exactly
// once in the current loaded inventory and its SSA package must be the program's
// exact Package(Types). No generated marker or testing/callee name grants meaning.
func deriveRegistration(ctx context.Context, source computationSource, packageID string, limits registrationLimits) (*registration, error) {
	if limits == (registrationLimits{}) {
		limits = defaultRegistrationLimits()
	}
	if ctx == nil || source.prog == nil || source.prog.Prog == nil || !limits.region.valid() || limits.source.work <= 0 {
		return nil, regionError("registration has no selected owner or budget")
	}
	var selected *packages.Package
	for i, p := range source.prog.Pkgs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if i >= limits.source.work {
			return nil, regionError("registration selection work budget exhausted")
		}
		if p != nil && p.ID == packageID {
			if selected != nil {
				return nil, regionError("registration selected package is ambiguous")
			}
			selected = p
		}
	}
	if selected == nil || selected.Types == nil {
		return nil, regionError("registration selected package is absent")
	}
	sp := source.prog.Prog.Package(selected.Types)
	if sp == nil || sp.Prog != source.prog.Prog || sp.Pkg != selected.Types {
		return nil, regionError("registration selected SSA package disagrees")
	}
	main := sp.Func("main") // language entry locator, checked against its declaration below
	b, err := newSelectedSourceBinder(ctx, source, main, limits.source)
	if err != nil {
		return nil, err
	}
	c := &registrationChecker{selectedSourceBinder: b, root: main, limits: limits.region}
	decl, err := b.bindDeclaration(main)
	if err != nil {
		return nil, err
	}
	if decl.pkg != selected || selected.Name != "main" || selected.Types.Name() != "main" || main.Signature.Recv() != nil || main.Signature.Params().Len() != 0 || main.Signature.Results().Len() != 0 || len(main.Params) != 0 || len(main.FreeVars) != 0 || len(main.Blocks) == 0 {
		return nil, regionError("registration main is not the selected package entry")
	}
	r := &registration{source: source, selected: selected, main: decl, packageInput: b.packages[selected]}
	tables, entry, end, err := c.bindInitialization(r, sp)
	if err != nil {
		return nil, err
	}
	construction := regionInput{owner: source.prog.Prog, root: r.init, entry: entry, use: end,
		premises: []string{
			"immutable selected typed source/SSA owner; source/compiler lowering correspondence remains open",
			"entry follows the retained guard and imported initialization calls on the initializing branch; their termination, effects, exceptional outcomes and interference remain open",
			"implicit package zero initialization and all omitted-prefix effects are open; absent entry heap facts are unknown",
			"no concurrent mutation during this conditional construction segment",
		}}
	r.construction, err = c.check(construction)
	if err != nil {
		return nil, err
	}
	if len(r.construction.observations) != 1 {
		return nil, regionError("registration construction does not have one exact heap")
	}
	state := r.construction.observations[0].state
	for _, table := range tables {
		if err := c.matchTable(state, table); err != nil {
			return nil, err
		}
	}
	// No initialization-frame register is live across entry to main. Derive the
	// surviving heap from actual global reachability, rather than preserving dead
	// local row objects or accepting a caller's proposed frame summary.
	r.frame, err = c.frame(state, end.at, regionPoint{main.Blocks[0], 0})
	if err != nil {
		return nil, err
	}
	if err := c.consume(r, tables); err != nil {
		return nil, err
	}
	r.callbacks = c.bound
	r.open = []string{
		"source/build snapshot stability and faithful selected typed source-to-SSA lowering",
		"implicit zero initialization, guard entry/skip branch, imported initialization effects, exceptions, termination and callbacks",
		"exact retained live construction-exit to main-entry heap equality across all intervening initialization and frame effects",
		"concurrency, escaped aliases and absence of interfering writes over each checked segment",
		"actual consuming callee, its callbacks, continuation and harness scope/noninterference",
		"selected native implementations, descriptor/callback transport, frames, suspension and resumption",
		"actual invocation, producing evidence, runtime applicability and observation obligations",
	}
	if err := c.tick(main, main.Pos()); err != nil {
		return nil, err
	}
	return r, nil
}

func (c *registrationChecker) check(in regionInput) (*checkedRegion, error) {
	if err := c.tick(c.root, c.root.Pos()); err != nil {
		return nil, err
	}
	p, err := proposeRegion(c.ctx, in, c.limits)
	if err != nil {
		return nil, err
	}
	return checkRegion(c.ctx, in, p, c.limits)
}

func (c *registrationChecker) frame(state regionState, from, to regionPoint) (registrationFrame, error) {
	f := registrationFrame{from: from, to: to, heap: regionState{memory: map[regionObject]regionValue{}}}
	var queue []regionObject
	for object := range state.memory {
		if err := c.tick(c.root, c.root.Pos()); err != nil {
			return registrationFrame{}, err
		}
		if object.kind == regionGlobal {
			queue = append(queue, object)
		}
	}
	var visit func(regionValue) error
	visit = func(value regionValue) error {
		if err := c.tick(c.root, c.root.Pos()); err != nil {
			return err
		}
		if value.kind == regionPointer || value.kind == regionSlice {
			queue = append(queue, value.location.object)
		}
		for _, values := range [][]regionValue{value.elements, value.environment} {
			for _, value := range values {
				if err := visit(value); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for len(queue) != 0 {
		object := queue[0]
		queue = queue[1:]
		if _, seen := f.heap.memory[object]; seen {
			continue
		}
		value, exists := state.memory[object]
		if !exists {
			return registrationFrame{}, regionError("registration frame has an unbound reachable object")
		}
		if object.kind == regionAllocation {
			a, ok := object.site.(*ssa.Alloc)
			if !ok || !a.Heap {
				return registrationFrame{}, regionError("registration live storage belongs to the ending initializer frame")
			}
		}
		f.heap.memory[object] = value
		if err := visit(value); err != nil {
			return registrationFrame{}, err
		}
	}
	for object := range state.memory {
		if _, survives := f.heap.memory[object]; !survives {
			f.dead = append(f.dead, object)
		}
	}
	return f, nil
}

// bindInitialization supplies only the association the declaration binder cannot
// supply: the canonical package initializer has no FuncDecl. Its complete guard,
// direct-import prefix, typed InitOrder stores, explicit-init suffix and CFG must
// agree with that binder's already selected syntax inventory.
func (c *registrationChecker) bindInitialization(r *registration, sp *ssa.Package) ([]registrationTable, regionPoint, regionUse, error) {
	fail := func() ([]registrationTable, regionPoint, regionUse, error) {
		return nil, regionPoint{}, regionUse{}, regionError("selected initialization ownership/CFG disagrees")
	}
	fn := sp.Func("init")
	if fn == nil || fn.Pkg != sp || fn.Prog != c.source.prog.Prog || fn.Object() != nil || fn.Syntax() != nil || fn.Signature == nil || fn.Signature.Recv() != nil || fn.Signature.Params().Len() != 0 || fn.Signature.Results().Len() != 0 || len(fn.Params) != 0 || len(fn.FreeVars) != 0 || len(fn.Blocks) != 3 {
		return fail()
	}
	r.init = fn
	start, body, done := fn.Blocks[0], fn.Blocks[1], fn.Blocks[2]
	if start == nil || body == nil || done == nil || len(start.Instrs) != 2 || len(body.Instrs) < 2 || len(done.Instrs) != 1 || len(start.Succs) != 2 || start.Succs[0] != done || start.Succs[1] != body || len(body.Succs) != 1 || body.Succs[0] != done || len(start.Preds) != 0 || !slices.Equal(body.Preds, []*ssa.BasicBlock{start}) || len(done.Succs) != 0 {
		return fail()
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
	r.guard = []*ssa.BasicBlock{start, body, done}
	index := 1
	for _, imported := range r.selected.Types.Imports() {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, regionPoint{}, regionUse{}, err
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
	entry := regionPoint{body, index}
	declared := map[*types.Var]ast.Expr{}
	var explicit []*ssa.Function
	for _, file := range r.selected.Syntax {
		for _, node := range file.Decls {
			if err := c.tick(fn, node.Pos()); err != nil {
				return nil, regionPoint{}, regionUse{}, err
			}
			switch d := node.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == "init" {
					obj, _ := r.selected.TypesInfo.Defs[d.Name].(*types.Func)
					f := c.source.prog.Prog.FuncValue(obj)
					bound, err := c.bindDeclaration(f)
					if err != nil {
						return nil, regionPoint{}, regionUse{}, err
					}
					if bound.decl != d || bound.pkg != r.selected {
						return fail()
					}
					explicit = append(explicit, f)
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					v := spec.(*ast.ValueSpec)
					if len(v.Values) != 0 && len(v.Values) != len(v.Names) {
						return fail()
					}
					for i, name := range v.Names {
						obj, ok := r.selected.TypesInfo.Defs[name].(*types.Var)
						if !ok || obj.Pkg() != r.selected.Types || obj.Name() == "_" {
							return fail()
						}
						r.variables = append(r.variables, obj)
						if len(v.Values) != 0 {
							declared[obj] = v.Values[i]
						}
					}
				}
			}
		}
	}
	var tables []registrationTable
	for _, init := range r.selected.TypesInfo.InitOrder {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, regionPoint{}, regionUse{}, err
		}
		if init == nil || len(init.Lhs) != 1 || declared[init.Lhs[0]] == nil || declared[init.Lhs[0]] != init.Rhs {
			return fail()
		}
		obj := init.Lhs[0]
		delete(declared, obj)
		g, ok := sp.Members[obj.Name()].(*ssa.Global)
		lit, lok := init.Rhs.(*ast.CompositeLit)
		slice, tok := obj.Type().Underlying().(*types.Slice)
		if !ok || g.Object() != obj || !lok || !tok || !types.Identical(r.selected.TypesInfo.TypeOf(lit), obj.Type()) {
			return fail()
		}
		if _, ok := slice.Elem().Underlying().(*types.Struct); !ok {
			return fail()
		}
		table := registrationTable{object: obj, global: g, init: init}
		for _, expr := range lit.Elts {
			v, err := c.expression(r.selected, expr, 0)
			if err != nil {
				return nil, regionPoint{}, regionUse{}, err
			}
			if !types.Identical(v.typ, slice.Elem()) {
				return fail()
			}
			table.rows = append(table.rows, v)
		}
		tables = append(tables, table)
		r.initializers = append(r.initializers, init)
	}
	if len(declared) != 0 || len(tables) == 0 {
		return fail()
	}
	// The suffix contains every explicit init in source order, then the one
	// edge to return. Nothing inside construction is skipped as a presumed call.
	cut := len(body.Instrs) - 1 - len(explicit)
	if cut < index {
		return fail()
	}
	for i, target := range explicit {
		call, ok := body.Instrs[cut+i].(*ssa.Call)
		if !ok || call.Call.IsInvoke() || call.Call.StaticCallee() != target || len(call.Call.Args) != 0 {
			return fail()
		}
		r.intervening = append(r.intervening, call)
	}
	writes := 0
	for _, ins := range body.Instrs[index:cut] {
		if err := c.tick(fn, ins.Pos()); err != nil {
			return nil, regionPoint{}, regionUse{}, err
		}
		if s, ok := ins.(*ssa.Store); ok {
			if _, global := s.Addr.(*ssa.Global); global {
				if writes >= len(tables) || s.Addr != tables[writes].global {
					return fail()
				}
				writes++
			}
		}
	}
	if writes != len(tables) {
		return fail()
	}
	end := regionUse{at: regionPoint{done, 0}}
	if len(explicit) != 0 {
		end = regionUse{at: regionPoint{body, cut}, operand: r.intervening[0].Call.Value}
	}
	return tables, entry, end, nil
}

// expression is a deliberately small typed construction grammar. It interprets
// constants, exact selected function objects and complete struct literals, not
// names of registration fields or callback signatures. Unsupported initializers
// refuse rather than becoming entry-heap assumptions.
func (c *registrationChecker) expression(p *packages.Package, expr ast.Expr, depth int) (regionValue, error) {
	if err := c.tick(c.root, expr.Pos()); err != nil {
		return regionValue{}, err
	}
	if depth > c.limits.depth {
		return regionValue{}, regionError("registration expression depth exhausted")
	}
	tv, ok := p.TypesInfo.Types[expr]
	if !ok || tv.Type == nil {
		return regionValue{}, regionError("registration expression lacks selected type")
	}
	if tv.Value != nil && regionScalarConstant(tv.Type, tv.Value) {
		return regionValue{typ: tv.Type, kind: regionConstant, scalar: tv.Value}, nil
	}
	if obj, ok := registrationExprObject(p, expr).(*types.Func); ok {
		fn := c.source.prog.Prog.FuncValue(obj)
		bound, err := c.bindDeclaration(fn)
		if err != nil {
			return regionValue{}, err
		}
		if len(fn.FreeVars) != 0 || !types.Identical(fn.Type(), tv.Type) {
			return regionValue{}, regionError("registration callable context disagrees")
		}
		c.bound = append(c.bound, bound)
		return regionValue{typ: tv.Type, kind: regionCallable, target: fn}, nil
	}
	lit, ok := expr.(*ast.CompositeLit)
	s, structType := tv.Type.Underlying().(*types.Struct)
	if !ok || !structType || s.NumFields() > c.limits.locations || len(lit.Elts) != s.NumFields() {
		return regionValue{}, regionError("unsupported registration source construction")
	}
	v := regionValue{typ: tv.Type, kind: regionAggregate, elements: make([]regionValue, s.NumFields())}
	for i, element := range lit.Elts {
		field := i
		if keyed, ok := element.(*ast.KeyValueExpr); ok {
			key, ok := keyed.Key.(*ast.Ident)
			if !ok {
				return regionValue{}, regionError("unsupported registration field key")
			}
			field = -1
			for j := range s.NumFields() {
				if err := c.tick(c.root, key.Pos()); err != nil {
					return regionValue{}, err
				}
				if p.TypesInfo.Uses[key] == s.Field(j) {
					field = j
				}
			}
			element = keyed.Value
		}
		if field < 0 || v.elements[field].typ != nil {
			return regionValue{}, regionError("registration field binding disagrees")
		}
		value, err := c.expression(p, element, depth+1)
		if err != nil {
			return regionValue{}, err
		}
		if !types.Identical(value.typ, s.Field(field).Type()) {
			return regionValue{}, regionError("registration field type disagrees")
		}
		v.elements[field] = value
	}
	return v, nil
}

func registrationExprObject(p *packages.Package, expr ast.Expr) types.Object {
	switch e := expr.(type) {
	case *ast.Ident:
		return p.TypesInfo.Uses[e]
	case *ast.SelectorExpr:
		return p.TypesInfo.Uses[e.Sel]
	}
	return nil
}

func (c *registrationChecker) matchTable(state regionState, table registrationTable) error {
	header := readRegionLocation(state, regionLocation{object: regionObject{kind: regionGlobal, site: table.global}}, table.object.Type())
	return c.matchRows(state, header, table)
}

func (c *registrationChecker) matchRows(state regionState, header regionValue, table registrationTable) error {
	if header.kind != regionSlice || header.length != int64(len(table.rows)) || header.location.object.kind != regionAllocation || header.location.object.context != c.source.prog.Prog.Package(table.object.Pkg()).Func("init") {
		return regionError("registration header does not designate its constructed rows")
	}
	// The allocation is the actual selected literal's construction, not merely
	// another same-typed table holding equal rows. The region proof, not this
	// source coordinate, establishes its contents and transfer to the operand.
	literal, ok := table.init.Rhs.(*ast.CompositeLit)
	allocation, aok := header.location.object.site.(*ssa.Alloc)
	if !ok || !aok || allocation.Pos() != literal.Lbrace || len(header.location.path) != 0 || header.start != 0 || header.capacity != int64(len(table.rows)) {
		return regionError("registration backing is not the selected initializer allocation")
	}
	elem := table.object.Type().Underlying().(*types.Slice).Elem()
	for i, row := range table.rows {
		if err := c.tick(c.root, table.init.Rhs.Pos()); err != nil {
			return err
		}
		loc := header.location
		loc.path = append(slices.Clone(loc.path), regionStep{index: header.start + int64(i)})
		if actual := readRegionLocation(state, loc, elem); !regionSameValue(actual, row) {
			return regionError("registration row/function/environment correlation disagrees with selected initializer")
		}
	}
	return nil
}

func (c *registrationChecker) consume(r *registration, tables []registrationTable) error {
	byObject := map[types.Object]registrationTable{}
	for _, table := range tables {
		byObject[table.object] = table
	}
	// Candidate discovery is syntax-directed. Only a source call with a direct
	// table argument is a candidate; its exact SSA callee and each operand are
	// independently associated below. Multiple candidates are intentionally open.
	var syntax *ast.CallExpr
	var walkErr error
	ast.Inspect(r.main.decl.Body, func(node ast.Node) bool {
		if node == nil || walkErr != nil {
			return false
		}
		if walkErr = c.tick(c.root, node.Pos()); walkErr != nil {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		found := false
		for _, arg := range call.Args {
			_, exists := byObject[registrationExprObject(r.selected, arg)]
			found = found || exists
		}
		if found {
			if syntax != nil {
				walkErr = regionError("ambiguous registration consuming call")
				return false
			}
			syntax = call
		}
		return true
	})
	if walkErr != nil {
		return walkErr
	}
	if syntax == nil {
		return regionError("no actual registration consuming call")
	}
	var point regionPoint
	for _, block := range c.root.Blocks {
		for i, ins := range block.Instrs {
			if err := c.tick(c.root, ins.Pos()); err != nil {
				return err
			}
			if call, ok := ins.(*ssa.Call); ok && call.Pos() == syntax.Lparen {
				if r.call != nil {
					return regionError("ambiguous registration SSA call")
				}
				r.call, point = call, regionPoint{block, i}
			}
		}
	}
	obj, ok := registrationExprObject(r.selected, syntax.Fun).(*types.Func)
	if !ok || r.call == nil || r.call.Call.IsInvoke() || r.call.Call.StaticCallee() != c.source.prog.Prog.FuncValue(obj) || len(r.call.Call.Args) != len(syntax.Args) {
		return regionError("registration consuming call source/SSA association disagrees")
	}
	for i, expr := range syntax.Args {
		operand := r.call.Call.Args[i]
		arg := registrationArgument{index: i}
		table, isTable := byObject[registrationExprObject(r.selected, expr)]
		if isTable {
			load, ok := operand.(*ssa.UnOp)
			if !ok || load.Op != token.MUL || load.X != table.global {
				return regionError("actual consuming operand is not the selected table load")
			}
			arg.object, arg.global, arg.rows = table.object, table.global, table.rows
		} else {
			value, err := c.expression(r.selected, expr, 0)
			if err != nil {
				return err
			}
			boxed, ok := operand.(*ssa.MakeInterface)
			if !ok || !types.Identical(boxed.X.Type(), value.typ) {
				return regionError("registration concrete interface construction disagrees")
			}
			arg.value = regionValue{typ: operand.Type(), kind: regionInterface, elements: []regionValue{value}}
		}
		input := regionInput{owner: c.source.prog.Prog, root: c.root, entry: r.frame.to, use: regionUse{at: point, operand: operand}, initial: r.frame.heap,
			premises: []string{
				"immutable selected typed source/SSA owner; source/compiler lowering correspondence remains open",
				"entry heap equals exactly the retained live construction exit heap after dropping init-frame registers and unreachable temporaries; intervening initialization and frame preservation are open",
				"no concurrent or escaped-alias mutation during this conditional main-to-operand segment",
			}}
		packet, err := c.check(input)
		if err != nil {
			return err
		}
		arg.packet = packet
		for _, observation := range packet.observations {
			if isTable {
				// Match the header itself as well as rows: a distinct, identical
				// lookalike backing is not the initialized object's provenance.
				header := readRegionLocation(r.frame.heap, regionLocation{object: regionObject{kind: regionGlobal, site: table.global}}, table.object.Type())
				if !regionSameValue(observation.value, header) {
					return regionError("registration consuming header has different provenance")
				}
				if err := c.matchRows(observation.state, observation.value, table); err != nil {
					return err
				}
				arg.value = observation.value
			} else if !regionSameValue(observation.value, arg.value) {
				return regionError("registration concrete consuming value disagrees")
			}
		}
		r.arguments = append(r.arguments, arg)
	}
	return nil
}
