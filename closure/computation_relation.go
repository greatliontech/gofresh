package closure

import (
	"context"
	"go/constant"
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/bitrelation"
)

const computationRelationRules = "gofresh/local-source-scalar@1"

// computationRelation is an immutable, pass-local interpretation of selected
// source, NOT a source/native correspondence certificate. No public authority or
// maximal discharge consumes it. The owner is an identity token only: consumers
// must not read mutable program objects through it or reuse this result across
// loads. There is deliberately no constructor from digests or projected terms.
//
// The local language model leaves initialization, harness/dispatch, actual use,
// compiler-selected native binding, producing/current applicability and runtime
// closing unresolved. In-memory fixtures establish only this same local model;
// they cannot manufacture a Hasher snapshot or historical build provenance.
type computationRelation struct {
	owner        *program
	rules        string
	root         computationRelationDependency
	dependencies []computationRelationDependency
	inputs       []bitrelation.Term
	outputs      []bitrelation.Term
	open         computationRelationObligations
}

type computationRelationObligations struct {
	initialization, harness, actualUse, nativeBinding, applicability bool
}

// These are frozen descriptions, not mutable SSA handles. Context arguments are
// the actual substituted terms; callback identities are selected declarations.
type computationRelationDependency struct {
	packageID, function, position string
	source, body                  [32]byte
	wordBits                      int
	arguments                     []bitrelation.Term
	callbacks                     []string
	parameters, results           []computationRelationType
}

// Bit storage alone does not distinguish int8 from uint8. Preserve the selected
// source interpretation beside the terms, especially for a composer's narrow
// input/output projections. A callback has a named type but no scalar sort.
type computationRelationType struct {
	name   string
	sort   bitrelation.Sort
	signed bool
}

type computationRelationLimits struct{ nodes, contexts, work, depth, bytes int }

func defaultComputationRelationLimits() computationRelationLimits {
	return computationRelationLimits{nodes: 65536, contexts: 4096, work: 262144, depth: 128, bytes: 16 << 20}
}

type computationRelationChecker struct {
	*selectedSourceBinder
	builder   *bitrelation.Builder
	contexts  int
	active    map[*ssa.Function]bool
	relations map[*ssa.Function]computationRelationDependency
	deps      []computationRelationDependency
}

// deriveComputationRelation checks the actual source graph, not a proposed pure
// flag, instruction inventory, or caller-authored expression. Each root parameter
// must be a distinct formal Input in the composing owner's explicit scope.
// Internal calls substitute actual terms and exactly resolved callback contexts.
func deriveComputationRelation(ctx context.Context, source computationSource, root *ssa.Function, scope bitrelation.Scope, inputs []bitrelation.Term, limits computationRelationLimits) (*computationRelation, error) {
	if ctx == nil {
		return nil, computationRefusal(root, token.NoPos, "local relation context is absent")
	}
	if limits == (computationRelationLimits{}) {
		limits = defaultComputationRelationLimits()
	}
	if limits.bytes == 0 {
		limits.bytes = defaultComputationRelationLimits().bytes
	}
	if limits.nodes <= 0 || limits.contexts <= 0 || limits.work <= 0 || limits.depth <= 0 || limits.bytes <= 0 {
		return nil, computationRefusal(root, token.NoPos, "invalid local relation budget")
	}
	// Context methods are caller callbacks. Own this bounded slice before even
	// the first Err call; validation, substitution and publication use only it.
	if len(inputs) > limits.nodes || len(inputs) > limits.work {
		return nil, computationRefusal(root, token.NoPos, "local relation input budget exhausted")
	}
	inputs = slices.Clone(inputs)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	binder, err := newSelectedSourceBinder(ctx, source, root, selectedSourceLimits{work: limits.work, depth: limits.depth, bytes: limits.bytes})
	if err != nil {
		return nil, err
	}
	c := &computationRelationChecker{selectedSourceBinder: binder, builder: bitrelation.NewBuilder(limits.nodes), contexts: limits.contexts,
		active: map[*ssa.Function]bool{}, relations: map[*ssa.Function]computationRelationDependency{}}
	entry := &computationContext{fn: root}
	fail := func(err error) (*computationRelation, error) {
		return nil, computationEntryFailure(err, entry, computationSubjectPhase)
	}
	if len(root.Params) > limits.nodes || len(root.Params) > limits.work {
		return fail(computationRefusal(root, root.Pos(), "local relation parameter budget exhausted"))
	}
	if len(inputs) != len(root.Params) || root.Signature.Results().Len() == 0 {
		return fail(computationRefusal(root, root.Pos(), "local relation needs exact scalar input and result arity"))
	}
	entry.bindings = make([]*ssa.Function, len(root.Params))
	used := map[uint64]bool{}
	for _, input := range inputs {
		p := input.View()
		if !input.Valid() || p.Op != bitrelation.Variable || p.Scope != scope || p.Scratch || used[p.Immediate] {
			return fail(computationRefusal(root, root.Pos(), "formal input is not a distinct input in the supplied scope"))
		}
		used[p.Immediate] = true
	}
	outputs, err := c.function(entry, inputs, 0)
	if err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &computationRelation{owner: source.prog, rules: computationRelationRules, root: c.deps[0], dependencies: c.deps,
		inputs: inputs, outputs: slices.Clone(outputs), open: computationRelationObligations{true, true, true, true, true}}, nil
}

// bind is deliberately claim-local: it binds only packages actually used by the
// expression. Unlike declarations it does not assert anything about package
// variables or initializers. Those obligations remain open on the certificate.
// File membership, typed declaration and body ownership are still checked.
func (c *computationRelationChecker) bind(fn *ssa.Function) (computationRelationDependency, *packages.Package, error) {
	var zero computationRelationDependency
	bound, err := c.bindDeclaration(fn)
	if err != nil {
		return zero, nil, err
	}
	p := bound.pkg
	if prior, ok := c.relations[fn]; ok {
		return prior, p, nil
	}
	// Scalar policy is deliberately separate from selected input identity. A
	// region consumer can inventory these boundaries without approving them.
	m := c.metas[p.ID]
	m.ForTest = ""
	if err := computationPackageInputs(m, ""); err != nil {
		return zero, p, computationRefusal(fn, fn.Pos(), err.Error())
	}
	if len(c.packages[p].directives) != 0 {
		return zero, p, computationRefusal(fn, fn.Pos(), "unsupported local implementation directive")
	}
	if bound.decl.Body == nil {
		return zero, p, computationRefusal(fn, fn.Pos(), "selected function body binding disagrees")
	}
	if len(fn.Blocks) == 0 || fn.Synthetic != "" || len(fn.FreeVars) != 0 || parameterizedBody(fn) {
		return zero, p, computationRefusal(fn, fn.Pos(), "selected local body is absent or unsupported")
	}
	word := int(p.TypesSizes.Sizeof(types.Typ[types.Int]) * 8)
	if word != 32 && word != 64 {
		return zero, p, computationRefusal(fn, fn.Pos(), "unsupported selected integer word size")
	}
	for _, block := range fn.Blocks {
		if block == nil {
			return zero, p, computationRefusal(fn, fn.Pos(), "nil local block")
		}
		for _, instruction := range block.Instrs {
			if err := c.tick(fn, fn.Pos()); err != nil {
				return zero, p, err
			}
			if instruction == nil {
				return zero, p, computationRefusal(fn, fn.Pos(), "nil local instruction")
			}
		}
	}
	identity := bound.identity
	dep := computationRelationDependency{packageID: identity.packageID, function: identity.function, position: identity.position, source: identity.source, body: identity.body, wordBits: word}
	for _, param := range fn.Params {
		dep.parameters = append(dep.parameters, computationRelationTypeOf(param.Type(), p.TypesSizes))
	}
	for i := 0; i < fn.Signature.Results().Len(); i++ {
		dep.results = append(dep.results, computationRelationTypeOf(fn.Signature.Results().At(i).Type(), p.TypesSizes))
	}
	c.relations[fn] = dep
	return dep, p, nil
}

func computationRelationTypeOf(t types.Type, sizes types.Sizes) computationRelationType {
	sort, signed := computationRelationSort(t, sizes)
	return computationRelationType{name: types.TypeString(t, func(p *types.Package) string { return p.Path() }), sort: sort, signed: signed}
}

func computationRelationSort(t types.Type, sizes types.Sizes) (bitrelation.Sort, bool) {
	if t == nil || sizes == nil {
		return bitrelation.Sort{}, false
	}
	b, ok := t.Underlying().(*types.Basic)
	if !ok {
		return bitrelation.Sort{}, false
	}
	if b.Kind() == types.Bool {
		return bitrelation.Bool(), false
	}
	switch b.Kind() {
	case types.Int, types.Int8, types.Int16, types.Int32, types.Int64, types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64:
		return bitrelation.Bits(int(sizes.Sizeof(t) * 8)), b.Info()&types.IsUnsigned == 0
	}
	return bitrelation.Sort{}, false
}

func (c *computationRelationChecker) function(current *computationContext, args []bitrelation.Term, depth int) ([]bitrelation.Term, error) {
	fn := current.fn
	fail := func(s string) ([]bitrelation.Term, error) { return nil, computationRefusal(fn, fn.Pos(), s) }
	if err := c.tick(fn, fn.Pos()); err != nil {
		return nil, err
	}
	if depth >= c.limits.depth || len(c.deps) >= c.contexts {
		return fail("local relation context/depth budget exhausted")
	}
	if c.active[fn] {
		return fail("recursive local relation has no induction")
	}
	dep, pkg, err := c.bind(fn)
	if err != nil {
		return nil, err
	}
	if fn.Signature.Recv() != nil || fn.Signature.Variadic() || len(args) != len(fn.Params) || len(current.bindings) != len(args) {
		return fail("unsupported local signature or context arity")
	}
	values := map[ssa.Value][]bitrelation.Term{}
	for i, param := range fn.Params {
		sort, _ := computationRelationSort(param.Type(), pkg.TypesSizes)
		if binding := current.bindings[i]; binding != nil {
			if args[i].Valid() || !types.Identical(param.Type().Underlying(), binding.Signature) {
				return fail("callback context type or argument disagrees")
			}
			dep.callbacks = append(dep.callbacks, binding.String())
		} else if !args[i].Valid() || args[i].Sort() != sort {
			return fail("scalar input sort disagrees with selected parameter")
		}
		values[param] = []bitrelation.Term{args[i]}
	}
	resultSorts := make([]bitrelation.Sort, fn.Signature.Results().Len())
	for i := range resultSorts {
		resultSorts[i], _ = computationRelationSort(fn.Signature.Results().At(i).Type(), pkg.TypesSizes)
		if resultSorts[i] == (bitrelation.Sort{}) {
			return fail("unsupported local scalar result")
		}
	}
	dep.arguments = slices.Clone(args)
	c.deps = append(c.deps, dep)
	c.active[fn] = true
	defer delete(c.active, fn)
	order, err := c.topology(fn)
	if err != nil {
		return nil, err
	}
	dominators := map[*ssa.BasicBlock]map[*ssa.BasicBlock]bool{}
	for _, block := range order {
		dom := map[*ssa.BasicBlock]bool{block: true}
		if len(block.Preds) != 0 {
			for candidate := range dominators[block.Preds[0]] {
				common := true
				for _, pred := range block.Preds {
					if err := c.tick(fn, fn.Pos()); err != nil {
						return nil, err
					}
					common = common && dominators[pred][candidate]
				}
				if common {
					dom[candidate] = true
				}
			}
		}
		dominators[block] = dom
	}
	// All builder errors become structured source failures at the operation.
	var buildErr error
	var at token.Pos = fn.Pos()
	makeTerm := func(op bitrelation.Op, sort bitrelation.Sort, imm uint64, args ...bitrelation.Term) bitrelation.Term {
		if buildErr != nil {
			return bitrelation.Term{}
		}
		t, err := c.builder.Make(op, sort, imm, args...)
		if err != nil {
			buildErr = computationRefusal(fn, at, "local scalar expression: "+err.Error())
		}
		return t
	}
	truth := makeTerm(bitrelation.Constant, bitrelation.Bool(), 1)
	falsity := makeTerm(bitrelation.Constant, bitrelation.Bool(), 0)
	var useBlock *ssa.BasicBlock
	value := func(v ssa.Value) (bitrelation.Term, error) {
		if constantValue, ok := v.(*ssa.Const); ok {
			sort, signed := computationRelationSort(v.Type(), pkg.TypesSizes)
			if constantValue.Value == nil || sort == (bitrelation.Sort{}) {
				return bitrelation.Term{}, computationRefusal(fn, at, "unsupported scalar constant")
			}
			var bits uint64
			if sort.IsBool() {
				if constantValue.Value.Kind() != constant.Bool {
					return bitrelation.Term{}, computationRefusal(fn, at, "invalid Boolean constant")
				}
				if constant.BoolVal(constantValue.Value) {
					bits = 1
				}
			} else {
				v := constant.ToInt(constantValue.Value)
				if v.Kind() != constant.Int {
					return bitrelation.Term{}, computationRefusal(fn, at, "invalid integer constant")
				}
				bound := constant.Shift(constant.MakeInt64(1), token.SHL, uint(sort.Width()))
				min := constant.MakeInt64(0)
				if signed {
					bound = constant.Shift(bound, token.SHR, 1)
					min = constant.UnaryOp(token.SUB, bound, 0)
				}
				if constant.Compare(v, token.LSS, min) || constant.Compare(v, token.GEQ, bound) {
					return bitrelation.Term{}, computationRefusal(fn, at, "typed integer constant is out of range")
				}
				if constant.Sign(v) < 0 {
					n, ok := constant.Int64Val(v)
					if !ok {
						return bitrelation.Term{}, computationRefusal(fn, at, "integer constant is out of range")
					}
					bits = uint64(n)
				} else {
					var ok bool
					bits, ok = constant.Uint64Val(v)
					if !ok {
						return bitrelation.Term{}, computationRefusal(fn, at, "integer constant is out of range")
					}
				}
				bits &= ^uint64(0) >> (64 - sort.Width())
			}
			return makeTerm(bitrelation.Constant, sort, bits), buildErr
		}
		if instruction, ok := v.(ssa.Instruction); ok && !dominators[useBlock][instruction.Block()] {
			return bitrelation.Term{}, computationRefusal(fn, at, "scalar operand does not dominate its use or phi predecessor")
		}
		if ts, ok := values[v]; ok && len(ts) == 1 && ts[0].Valid() {
			return ts[0], nil
		}
		return bitrelation.Term{}, computationRefusal(fn, at, "scalar operand is not an available local value")
	}
	type edge struct{ from, to *ssa.BasicBlock }
	edges := map[edge]bitrelation.Term{}
	paths := map[*ssa.BasicBlock]bitrelation.Term{fn.Blocks[0]: truth}
	var outputs []bitrelation.Term
	returns := 0
	for _, block := range order {
		useBlock = block
		path := paths[block]
		if block != fn.Blocks[0] {
			path = falsity
			for _, pred := range block.Preds {
				path = makeTerm(bitrelation.Or, bitrelation.Bool(), 0, path, edges[edge{pred, block}])
			}
			paths[block] = path
		}
		ordinarySeen := false
		for index, instruction := range block.Instrs {
			at = instruction.Pos()
			if err := c.tick(fn, at); err != nil {
				return nil, err
			}
			if instruction.Block() != block {
				return nil, computationRefusal(fn, at, "instruction belongs to another block")
			}
			if _, phi := instruction.(*ssa.Phi); !phi {
				ordinarySeen = true
			}
			var terms []bitrelation.Term
			switch ins := instruction.(type) {
			case *ssa.Phi:
				if len(ins.Edges) != len(block.Preds) || len(ins.Edges) == 0 {
					return nil, computationRefusal(fn, at, "phi predecessor arity disagrees")
				}
				if ordinarySeen {
					return nil, computationRefusal(fn, at, "phi follows ordinary instruction")
				}
				sort, _ := computationRelationSort(ins.Type(), pkg.TypesSizes)
				var merged bitrelation.Term
				for i, operand := range ins.Edges {
					useBlock = block.Preds[i]
					t, err := value(operand)
					if err != nil {
						return nil, err
					}
					if t.Sort() != sort {
						return nil, computationRefusal(fn, at, "phi scalar sort disagrees")
					}
					if i == 0 {
						merged = t
					} else {
						merged = makeTerm(bitrelation.ITE, sort, 0, edges[edge{block.Preds[i], block}], t, merged)
					}
				}
				useBlock = block
				terms = []bitrelation.Term{merged}
			case *ssa.BinOp:
				x, err := value(ins.X)
				if err != nil {
					return nil, err
				}
				sort, signed := computationRelationSort(ins.X.Type(), pkg.TypesSizes)
				if ins.Op == token.SHL || ins.Op == token.SHR {
					count, ok := ins.Y.(*ssa.Const)
					if !ok || count.Value == nil || count.Value.Kind() != constant.Int || constant.Sign(count.Value) < 0 {
						return nil, computationRefusal(fn, at, "shift count is not a nonnegative fixed integer")
					}
					n, exact := constant.Uint64Val(count.Value)
					if !exact {
						n = 64
					}
					op := bitrelation.Shl
					if ins.Op == token.SHR {
						op = bitrelation.LShr
						if signed {
							op = bitrelation.AShr
						}
					}
					terms = []bitrelation.Term{makeTerm(op, sort, n, x)}
					break
				}
				y, err := value(ins.Y)
				if err != nil {
					return nil, err
				}
				if y.Sort() != x.Sort() {
					return nil, computationRefusal(fn, at, "binary operand sorts disagree")
				}
				op, negate := bitrelation.Op(0), false
				outSort, _ := computationRelationSort(ins.Type(), pkg.TypesSizes)
				switch ins.Op {
				case token.ADD:
					op = bitrelation.Add
				case token.SUB:
					op = bitrelation.Sub
				case token.AND:
					op = bitrelation.BitAnd
				case token.OR:
					op = bitrelation.BitOr
				case token.XOR:
					op = bitrelation.BitXor
				case token.AND_NOT:
					op = bitrelation.BitAnd
					y = makeTerm(bitrelation.BitNot, sort, 0, y)
				case token.EQL:
					op = bitrelation.Equal
				case token.NEQ:
					op = bitrelation.Equal
					negate = true
				case token.LSS, token.GTR:
					op = bitrelation.ULT
					if signed {
						op = bitrelation.SLT
					}
					if ins.Op == token.GTR {
						x, y = y, x
					}
				case token.LEQ, token.GEQ:
					op = bitrelation.ULE
					if signed {
						op = bitrelation.SLE
					}
					if ins.Op == token.GEQ {
						x, y = y, x
					}
				case token.LAND:
					op = bitrelation.And
				case token.LOR:
					op = bitrelation.Or
				case token.MUL:
					// Exact modular shift/add multiplication, with a fixed width-
					// bounded expansion. No arithmetic oracle or overflow premise.
					acc := makeTerm(bitrelation.Constant, sort, 0)
					zero := acc
					for bit := 0; bit < sort.Width(); bit++ {
						if err := c.tick(fn, at); err != nil {
							return nil, err
						}
						mask := makeTerm(bitrelation.Constant, sort, uint64(1)<<bit)
						set := makeTerm(bitrelation.Equal, bitrelation.Bool(), 0, makeTerm(bitrelation.BitAnd, sort, 0, y, mask), mask)
						part := makeTerm(bitrelation.ITE, sort, 0, set, makeTerm(bitrelation.Shl, sort, uint64(bit), x), zero)
						acc = makeTerm(bitrelation.Add, sort, 0, acc, part)
					}
					terms = []bitrelation.Term{acc}
				default:
					return nil, computationRefusal(fn, at, "unsupported or exceptional scalar binary operation")
				}
				if terms == nil {
					t := makeTerm(op, outSort, 0, x, y)
					if negate {
						t = makeTerm(bitrelation.Not, bitrelation.Bool(), 0, t)
					}
					terms = []bitrelation.Term{t}
				}
			case *ssa.UnOp:
				x, err := value(ins.X)
				if err != nil {
					return nil, err
				}
				var t bitrelation.Term
				switch ins.Op {
				case token.NOT:
					t = makeTerm(bitrelation.Not, bitrelation.Bool(), 0, x)
				case token.XOR:
					t = makeTerm(bitrelation.BitNot, x.Sort(), 0, x)
				case token.SUB:
					t = makeTerm(bitrelation.Sub, x.Sort(), 0, makeTerm(bitrelation.Constant, x.Sort(), 0), x)
				default:
					return nil, computationRefusal(fn, at, "unsupported scalar unary operation or memory read")
				}
				terms = []bitrelation.Term{t}
			case *ssa.Convert:
				x, err := value(ins.X)
				if err != nil {
					return nil, err
				}
				sort, _ := computationRelationSort(ins.Type(), pkg.TypesSizes)
				_, signed := computationRelationSort(ins.X.Type(), pkg.TypesSizes)
				if sort.Width() == 0 || x.Sort().Width() == 0 {
					return nil, computationRefusal(fn, at, "unsupported scalar conversion")
				}
				if sort.Width() < x.Sort().Width() {
					x = makeTerm(bitrelation.Trunc, sort, 0, x)
				} else if sort.Width() > x.Sort().Width() {
					op := bitrelation.ZExt
					if signed {
						op = bitrelation.SExt
					}
					x = makeTerm(op, sort, 0, x)
				}
				terms = []bitrelation.Term{x}
			case *ssa.ChangeType:
				x, err := value(ins.X)
				if err != nil {
					return nil, err
				}
				sort, _ := computationRelationSort(ins.Type(), pkg.TypesSizes)
				if x.Sort() != sort {
					return nil, computationRefusal(fn, at, "scalar change-type sort disagrees")
				}
				terms = []bitrelation.Term{x}
			case *ssa.Call:
				child := computationCallContext(ins.Common(), current)
				if child == nil {
					return nil, computationRefusal(fn, at, "call has no exact selected source context")
				}
				childArgs := make([]bitrelation.Term, len(ins.Call.Args))
				for i, arg := range ins.Call.Args {
					if child.bindings[i] == nil {
						childArgs[i], err = value(arg)
						if err != nil {
							return nil, err
						}
					}
				}
				terms, err = c.function(child, childArgs, depth+1)
				if err != nil {
					return nil, computationCallFailure(err, current, child, at)
				}
			case *ssa.Extract:
				if call, ok := ins.Tuple.(*ssa.Call); !ok || !dominators[block][call.Block()] {
					return nil, computationRefusal(fn, at, "tuple call does not dominate extraction")
				}
				tuple, ok := values[ins.Tuple]
				if !ok || ins.Index < 0 || ins.Index >= len(tuple) {
					return nil, computationRefusal(fn, at, "tuple extraction has no checked local call")
				}
				terms = []bitrelation.Term{tuple[ins.Index]}
			case *ssa.If:
				if index != len(block.Instrs)-1 || len(block.Succs) != 2 {
					return nil, computationRefusal(fn, at, "invalid local branch successors")
				}
				cond, err := value(ins.Cond)
				if err != nil {
					return nil, err
				}
				edges[edge{block, block.Succs[0]}] = makeTerm(bitrelation.And, bitrelation.Bool(), 0, path, cond)
				edges[edge{block, block.Succs[1]}] = makeTerm(bitrelation.And, bitrelation.Bool(), 0, path, makeTerm(bitrelation.Not, bitrelation.Bool(), 0, cond))
			case *ssa.Jump:
				if index != len(block.Instrs)-1 || len(block.Succs) != 1 {
					return nil, computationRefusal(fn, at, "invalid local jump successor")
				}
				edges[edge{block, block.Succs[0]}] = path
			case *ssa.Return:
				if index != len(block.Instrs)-1 || len(block.Succs) != 0 || len(ins.Results) != len(resultSorts) {
					return nil, computationRefusal(fn, at, "invalid local return interface")
				}
				returned := make([]bitrelation.Term, len(ins.Results))
				for i, result := range ins.Results {
					returned[i], err = value(result)
					if err != nil {
						return nil, err
					}
					if returned[i].Sort() != resultSorts[i] {
						return nil, computationRefusal(fn, at, "returned scalar sort disagrees")
					}
				}
				if returns == 0 {
					outputs = returned
				} else {
					for i := range outputs {
						outputs[i] = makeTerm(bitrelation.ITE, resultSorts[i], 0, path, returned[i], outputs[i])
					}
				}
				returns++
			default:
				return nil, computationRefusal(fn, at, "instruction outside pure local scalar relation")
			}
			if buildErr != nil {
				return nil, buildErr
			}
			if v, ok := instruction.(ssa.Value); ok {
				values[v] = terms
			}
		}
	}
	if returns == 0 {
		return fail("local relation has no return")
	}
	return outputs, nil
}

// topology validates the entire loader-owned graph, both directions of every
// edge, and all terminals before interpreting values. No proposer can omit a
// branch or a discarded call. Acyclicity makes predecessor conditions complete.
func (c *computationRelationChecker) topology(fn *ssa.Function) ([]*ssa.BasicBlock, error) {
	set := map[*ssa.BasicBlock]bool{}
	for _, b := range fn.Blocks {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, err
		}
		if b == nil || set[b] || b.Parent() != fn {
			return nil, computationRefusal(fn, fn.Pos(), "invalid local block ownership")
		}
		set[b] = true
	}
	if len(fn.Blocks[0].Preds) != 0 {
		return nil, computationRefusal(fn, fn.Pos(), "local entry has predecessors")
	}
	indegree := map[*ssa.BasicBlock]int{}
	for _, b := range fn.Blocks {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, err
		}
		if len(b.Instrs) == 0 {
			return nil, computationRefusal(fn, fn.Pos(), "empty local block")
		}
		switch b.Instrs[len(b.Instrs)-1].(type) {
		case *ssa.If, *ssa.Jump, *ssa.Return:
		default:
			return nil, computationRefusal(fn, fn.Pos(), "local block has no supported terminal")
		}
		for _, pair := range []struct {
			edges     []*ssa.BasicBlock
			successor bool
		}{{b.Succs, true}, {b.Preds, false}} {
			seen := map[*ssa.BasicBlock]bool{}
			for _, other := range pair.edges {
				if err := c.tick(fn, fn.Pos()); err != nil {
					return nil, err
				}
				if !set[other] || seen[other] {
					return nil, computationRefusal(fn, fn.Pos(), "local edge is absent or duplicated")
				}
				seen[other] = true
				back := other.Succs
				if pair.successor {
					back = other.Preds
				}
				matched := false
				for _, candidate := range back {
					if err := c.tick(fn, fn.Pos()); err != nil {
						return nil, err
					}
					if candidate == b {
						matched = true
						break
					}
				}
				if !matched {
					return nil, computationRefusal(fn, fn.Pos(), "local predecessor/successor binding disagrees")
				}
			}
		}
		indegree[b] = len(b.Preds)
	}
	queue := []*ssa.BasicBlock{fn.Blocks[0]}
	for i := 0; i < len(queue); i++ {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return nil, err
		}
		for _, next := range queue[i].Succs {
			indegree[next]--
			if indegree[next] == 0 {
				queue = append(queue, next)
			}
		}
	}
	if len(queue) != len(fn.Blocks) {
		return nil, computationRefusal(fn, fn.Pos(), "cyclic or disconnected local control flow")
	}
	return queue, nil
}
