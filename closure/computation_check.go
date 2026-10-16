package closure

import (
	"context"
	"fmt"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// checkedComputation is a pass-local source-SSA functional effect bound. It says
// nothing about termination, elapsed time, native implementations, observation delivery
// or operation outcomes. Language operations retain their specified exceptions
// and implementation latitude. A consumer still needs checked binding to the
// compiler-selected implementations; available source does not establish it.
type checkedComputation struct {
	functions map[*ssa.Function]bool
}

func computationScalar(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	if !ok {
		return false
	}
	switch basic.Kind() {
	case types.Bool, types.Int, types.Int8, types.Int16, types.Int32, types.Int64,
		types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64, types.String:
		return true
	}
	return false
}

func computationCallback(t types.Type) bool {
	sig, ok := t.Underlying().(*types.Signature)
	if !ok || sig.Recv() != nil || sig.Variadic() || sig.TypeParams().Len() != 0 {
		return false
	}
	for _, tuple := range []*types.Tuple{sig.Params(), sig.Results()} {
		for i := 0; i < tuple.Len(); i++ {
			if !computationScalar(tuple.At(i).Type()) {
				return false
			}
		}
	}
	return true
}

func computationResult(t types.Type) bool {
	if tuple, ok := t.(*types.Tuple); ok {
		for i := 0; i < tuple.Len(); i++ {
			if !computationScalar(tuple.At(i).Type()) {
				return false
			}
		}
		return true
	}
	return computationScalar(t)
}

// checkComputation is the sole owner of the positive source-SSA claim. The
// candidate's inventory cannot hide a block, ignored-result call or initializer: the checker
// reads those obligations from the bound selected source and SSA itself.
func checkComputation(ctx context.Context, source computationSource, root *ssa.Function, cert *computationCertificate) (*checkedComputation, error) {
	decls, inits, err := source.declarations(ctx)
	if err != nil {
		return nil, err
	}
	refuse := func(fn *ssa.Function, premise string) (*checkedComputation, error) {
		return nil, computationRefusal(fn, token.NoPos, premise)
	}
	if root == nil || cert == nil || cert.root == nil || cert.root.fn != root || !decls[root] {
		return refuse(root, "certificate root is not the selected source root")
	}
	for _, binding := range cert.root.bindings {
		if binding != nil {
			return refuse(root, "root callback is caller-provided")
		}
	}
	if len(cert.startup) != len(inits) {
		return refuse(root, "initializer inventory is incomplete")
	}
	for i, init := range inits {
		if cert.startup[i] == nil || cert.startup[i].fn != init {
			return refuse(root, "initializer inventory disagrees with selected source")
		}
	}
	find := func(want *computationContext) (*computationContext, error) {
		for _, candidate := range cert.contexts {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if sameComputationContext(candidate, want) {
				return candidate, nil
			}
		}
		return nil, nil
	}
	for i, candidate := range cert.contexts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if candidate == nil || candidate.fn == nil {
			return refuse(root, "nil function context")
		}
		for _, prior := range cert.contexts[:i] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if sameComputationContext(candidate, prior) {
				return refuse(root, "duplicate function context")
			}
		}
	}
	checked := &checkedComputation{functions: map[*ssa.Function]bool{}}
	state := map[*computationContext]uint8{}
	var visit func(*computationContext) error
	visit = func(want *computationContext) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := find(want)
		if err != nil {
			return err
		}
		if current == nil {
			return computationRefusal(want.fn, token.NoPos, "required callee context is absent")
		}
		fn := current.fn
		if state[current] == 1 {
			return computationRefusal(fn, fn.Pos(), "recursive computation has no inductive proof")
		}
		if state[current] == 2 {
			return nil
		}
		if !decls[fn] || len(fn.Blocks) == 0 || fn.Synthetic != "" || len(fn.FreeVars) != 0 || parameterizedBody(fn) {
			return computationRefusal(fn, fn.Pos(), "selected source body is absent or unsupported")
		}
		if fn.Signature.Recv() != nil || fn.Signature.Variadic() || len(current.bindings) != len(fn.Params) {
			return computationRefusal(fn, fn.Pos(), "unsupported function signature or bindings")
		}
		for i, parameter := range fn.Params {
			binding := current.bindings[i]
			if computationScalar(parameter.Type()) {
				if binding != nil {
					return computationRefusal(fn, parameter.Pos(), "callable binding at a scalar parameter")
				}
			} else if !computationCallback(parameter.Type()) || binding == nil || !types.Identical(parameter.Type().Underlying(), binding.Signature) {
				return computationRefusal(fn, parameter.Pos(), "callback parameter has no exact supported binding")
			}
		}
		if !computationResult(fn.Signature.Results()) {
			return computationRefusal(fn, fn.Pos(), "unsupported result type")
		}
		state[current] = 1
		for _, block := range fn.Blocks {
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, instruction := range block.Instrs {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := checkComputationInstruction(current, instruction, visit); err != nil {
					return err
				}
			}
		}
		state[current] = 2
		checked.functions[fn] = true
		return nil
	}
	for i, entry := range append([]*computationContext{cert.root}, cert.startup...) {
		if err := visit(entry); err != nil {
			phase := computationSubjectPhase
			if i != 0 {
				phase = computationStartupPhase
			}
			return nil, computationEntryFailure(err, entry, phase)
		}
	}
	if len(state) != len(cert.contexts) {
		return refuse(root, "certificate contains unchecked contexts")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return checked, nil
}

func checkComputationInstruction(current *computationContext, instruction ssa.Instruction, visit func(*computationContext) error) error {
	fail := func(premise string) error {
		return computationRefusal(current.fn, instruction.Pos(), premise)
	}
	// Every SSA value used by the accepted operations must be a constant,
	// parameter or a checked instruction in this very body. Globals, free
	// variables and forged cross-body operands never acquire scalar authority.
	for _, operand := range instruction.Operands(nil) {
		if operand == nil || *operand == nil {
			continue
		}
		switch value := (*operand).(type) {
		case *ssa.Const:
			if !computationScalar(value.Type()) {
				return fail("unsupported constant")
			}
		case *ssa.Parameter:
			if value.Parent() != current.fn {
				return fail("operand belongs to another context")
			}
		case *ssa.Function, *ssa.Builtin:
			// Only calls may carry executable operands. Their exact target
			// and callback positions are checked below.
			if _, call := instruction.(*ssa.Call); !call {
				return fail("callable value escapes a checked call")
			}
		case ssa.Instruction:
			if value.Parent() != current.fn || value.Block() == nil {
				return fail("operand has no checked defining instruction")
			}
		default:
			return fail("operand references nonlocal or unsupported state")
		}
	}
	if value, ok := instruction.(ssa.Value); ok && !computationResult(value.Type()) {
		return fail("unsupported instruction result type")
	}
	scalar := func(value ssa.Value) bool { return value != nil && computationScalar(value.Type()) }
	isString := func(value ssa.Value) bool {
		return value != nil && types.Identical(value.Type().Underlying(), types.Typ[types.String])
	}
	switch op := instruction.(type) {
	case *ssa.BinOp:
		if !scalar(op.X) || !scalar(op.Y) {
			return fail("non-scalar binary operation")
		}
		switch op.Op {
		case token.ADD, token.SUB, token.MUL, token.QUO, token.REM,
			token.AND, token.OR, token.XOR, token.SHL, token.SHR, token.AND_NOT,
			token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			return nil
		}
	case *ssa.UnOp:
		if scalar(op.X) && (op.Op == token.NOT || op.Op == token.SUB || op.Op == token.XOR) {
			return nil
		}
	case *ssa.ChangeType:
		if scalar(op.X) {
			return nil
		}
	case *ssa.Convert:
		if scalar(op.X) {
			return nil
		}
	case *ssa.Phi:
		for _, edge := range op.Edges {
			if !scalar(edge) {
				return fail("non-scalar phi")
			}
		}
		return nil
	case *ssa.If:
		if types.Identical(op.Cond.Type().Underlying(), types.Typ[types.Bool]) {
			return nil
		}
	case *ssa.Jump:
		return nil
	case *ssa.Return:
		for _, value := range op.Results {
			if !scalar(value) {
				return fail("non-scalar return")
			}
		}
		return nil
	case *ssa.Extract:
		if computationResult(op.Tuple.Type()) {
			return nil
		}
	case *ssa.Index:
		if isString(op.X) && scalar(op.Index) {
			return nil
		}
	case *ssa.Slice:
		if isString(op.X) && op.Max == nil && (op.Low == nil || scalar(op.Low)) && (op.High == nil || scalar(op.High)) {
			return nil
		}
	case *ssa.Call:
		call := op.Common()
		if builtin, ok := call.Value.(*ssa.Builtin); ok {
			if builtin.Name() == "len" && len(call.Args) == 1 && isString(call.Args[0]) {
				return nil
			}
			return fail("unsupported language builtin")
		}
		child := computationCallContext(call, current)
		if child == nil {
			return fail("call target is not exactly bound")
		}
		for i, argument := range call.Args {
			if computationScalar(child.fn.Params[i].Type()) {
				if !scalar(argument) {
					return fail("non-scalar argument at a scalar parameter")
				}
			} else if child.bindings[i] == nil {
				return fail("callback argument is not exactly bound")
			}
		}
		if err := visit(child); err != nil {
			return computationCallFailure(err, current, child, instruction.Pos())
		}
		return nil
	}
	return fail(fmt.Sprintf("unsupported computation instruction %T", instruction))
}

// coversComputationEffects discharges only symbol-exact function blockers. The
// coarse scan has no receiver identity, so a package-scope function is required;
// a method, global, opaque import or unrelated effect is never erased.
func coversComputationEffects(source computationSource, checked *checkedComputation, effects []externalEffect) bool {
	if checked == nil {
		return false
	}
	for _, effect := range effects {
		if effect.kind != externalEffectUnauditedStandard || effect.packagePath == "" || effect.symbol == "" || effect.unrefinable {
			return false
		}
		found := false
		for _, p := range source.prog.Pkgs {
			if p.PkgPath != effect.packagePath || p.Types == nil {
				continue
			}
			object, ok := p.Types.Scope().Lookup(effect.symbol).(*types.Func)
			if !ok || !checked.functions[source.prog.Prog.FuncValue(object)] {
				return false
			}
			found = true
		}
		if !found {
			return false
		}
	}
	return true
}
