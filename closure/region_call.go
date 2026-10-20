package closure

import (
	"context"
	"fmt"
	"go/ast"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// regionInvocation is an immutable, pass-local call-string coordinate. Only a
// coordinate independently derived from actual instruction/target identities
// enters the session's cardinality registry. A string in an input/proposal never
// supplies that authority. The zero coordinate is the root invocation.
type regionInvocation struct {
	root *ssa.Function
	path string
}

type regionContextFacts struct {
	function *ssa.Function
	cycle    map[*ssa.BasicBlock]bool
	repeated bool
	depth    int
}

// A candidate proposes only entry states and block invariants. There is no
// producer-supplied return, preserved-heap, callback-free, or closed flag.
// Returns and their ENTIRE resulting heaps are derived again by the checker.
type regionCallProof struct {
	at         *ssa.Call
	target     *ssa.Function
	invocation regionInvocation
	initial    regionState
	entries    map[*ssa.BasicBlock][]regionState
	// A checked assembly reference is a distinct closed evidence arm. It carries
	// no proposed successor heap or result and is applied again by the checker.
	reference *assemblyReference
	arguments []regionValue
}

type regionCallSession struct {
	root        *ssa.Function
	meter       *regionMeter
	contexts    map[regionInvocation]regionContextFacts
	preexisting map[regionObject]bool
	active      map[*ssa.Function]bool
	proposing   bool
	proofs      []*regionCallProof
	results     map[*regionCallProof][]regionObservation
	used        []*regionCallProof
	references  map[*ssa.Function]*assemblyReference
	source      computationSource
	// Only the opaque source-continuation constructor supplies this checked
	// predecessor. Its occurrence guard prevents executing retained allocations
	// again. An arbitrary input heap has no predecessor authority.
	predecessor *sourceEffectPrefix
	// Only the startup composer supplies completed roots, after checking every
	// outcome of that phase. Their allocations cannot execute again in this
	// invocation: the new root has a distinct call-string namespace. The ordinary
	// conditional-region API supplies none and retains its conservative rule.
	completed map[*ssa.Function]bool
}

func newRegionCallSession(ctx context.Context, in regionInput, limits regionLimits) *regionCallSession {
	return &regionCallSession{root: in.root, meter: &regionMeter{ctx: ctx, limits: limits}, contexts: map[regionInvocation]regionContextFacts{}, preexisting: map[regionObject]bool{}, active: map[*ssa.Function]bool{in.root: true}, results: map[*regionCallProof][]regionObservation{}}
}

// Source syntax identifies the available language body, not its build/native
// binding. A generic instance must carry its actual origin's syntax; synthetic
// wrappers lacking such a body remain unsupported regardless of their label.
func regionSourceCallBody(fn *ssa.Function) bool {
	if fn == nil || len(fn.Blocks) == 0 {
		return false
	}
	var body *ast.BlockStmt
	switch syntax := fn.Syntax().(type) {
	case *ast.FuncDecl:
		body = syntax.Body
	case *ast.FuncLit:
		body = syntax.Body
	}
	if body == nil {
		return false
	}
	if fn.Synthetic == "" {
		return true
	}
	origin := fn.Origin()
	return origin != nil && origin != fn && origin.Syntax() == fn.Syntax() && len(fn.TypeArgs()) != 0
}

func (k *regionKernel) invocationAt(call *ssa.Call, target *ssa.Function) (regionInvocation, error) {
	parent, ok := k.session.contexts[k.invocation]
	if !ok || parent.function != k.input.root || call.Parent() != k.input.root {
		return regionInvocation{}, regionError("call context is not the actual caller")
	}
	if parent.depth >= k.meter.limits.depth {
		return regionInvocation{}, regionError("call context depth exhausted")
	}
	index := slices.Index(call.Block().Instrs, ssa.Instruction(call))
	if index < 0 {
		return regionInvocation{}, regionError("call is not an actual instruction")
	}
	id := regionInvocation{root: k.session.root, path: k.invocation.path + fmt.Sprintf("/%d:%d:%p", call.Block().Index, index, target)}
	facts := regionContextFacts{function: target, repeated: parent.repeated || k.cycle[call.Block()], depth: parent.depth + 1}
	if old, exists := k.session.contexts[id]; exists {
		if old.function != target || old.repeated != facts.repeated || old.depth != facts.depth {
			return regionInvocation{}, regionError("inconsistent derived call context")
		}
	} else {
		if len(k.session.contexts) >= k.meter.limits.nodes {
			return regionInvocation{}, regionError("call context count exhausted")
		}
		k.session.contexts[id] = facts
	}
	return id, nil
}

func (k *regionKernel) call(call *ssa.Call, caller regionState) ([]regionState, error) {
	if err := k.meter.tick(); err != nil {
		return nil, err
	}
	callable := k.value(caller, call.Call.Value)
	if err := k.validateValue(callable, 0); err != nil {
		return nil, err
	}
	var actual []regionValue
	if call.Call.IsInvoke() {
		target, receiver, err := k.interfaceTarget(call, callable)
		if err != nil {
			return nil, err
		}
		callable = regionValue{typ: target.Type(), kind: regionCallable, target: target}
		actual = append(actual, receiver)
	}
	for _, operand := range call.Call.Args {
		actual = append(actual, k.value(caller, operand))
	}
	if callable.kind == regionCallable && k.session.references[callable.target] != nil {
		return k.callReference(call, caller, callable, actual)
	}
	if callable.kind != regionCallable || !regionSourceCallBody(callable.target) {
		return nil, regionError("call target has no supported ordinary source body")
	}
	target := callable.target
	if k.session.active[target] {
		return nil, regionError("recursive call component has no inductive call proof")
	}
	if len(actual) != len(target.Params) || len(callable.environment) != len(target.FreeVars) {
		return nil, regionError("actual call arguments or closure environment are incomplete")
	}
	id, err := k.invocationAt(call, target)
	if err != nil {
		return nil, err
	}
	initial, err := k.clone(regionState{memory: caller.memory})
	if err != nil {
		return nil, err
	}
	for i, parameter := range target.Params {
		value := actual[i]
		if !types.Identical(parameter.Type(), value.typ) {
			return nil, regionError("actual/formal argument type mismatch")
		}
		initial.values[parameter] = value
	}
	for i, free := range target.FreeVars {
		value := callable.environment[i]
		if !types.Identical(free.Type(), value.typ) {
			return nil, regionError("captured environment type mismatch")
		}
		initial.values[free] = value
	}
	in := regionInput{owner: k.input.owner, root: target, entry: regionPoint{target.Blocks[0], 0}, initial: initial, premises: k.input.premises}
	child, err := newRegionContextKernel(in, k.session, id, true)
	if err != nil {
		return nil, err
	}
	var proof *regionCallProof
	for _, candidate := range k.session.proofs {
		if err := k.meter.tick(); err != nil {
			return nil, err
		}
		if candidate.at != call || candidate.target != target || candidate.invocation != id || candidate.reference != nil {
			continue
		}
		if len(candidate.arguments) != len(actual) {
			continue
		}
		sameArguments := true
		for i, argument := range actual {
			if err := k.chargeValue(argument); err != nil {
				return nil, err
			}
			sameArguments = sameArguments && regionSameValue(argument, candidate.arguments[i])
		}
		if !sameArguments {
			continue
		}
		if err := child.validateState(candidate.initial); err != nil {
			return nil, err
		}
		forward, err := child.included(initial, candidate.initial)
		if err != nil {
			return nil, err
		}
		backward, err := child.included(candidate.initial, initial)
		if err != nil {
			return nil, err
		}
		if forward && backward {
			proof = candidate
			break
		}
	}
	k.session.active[target] = true
	defer delete(k.session.active, target)
	if proof == nil {
		if !k.session.proposing {
			return nil, regionError("missing callee proof for the exact actual input and context")
		}
		if k.trace != nil {
			// Nested checked references also need effect-aware proposal execution.
			// Its events are provisional: checking below replays the body into the
			// parent's trace under the same cumulative meter.
			child.trace = &regionEffectTrace{seen: map[regionEffectOccurrence]bool{}}
		}
		entries, err := child.proposeEntries()
		if err != nil {
			return nil, err
		}
		if len(k.session.proofs) >= k.meter.limits.nodes {
			return nil, regionError("callee proof count exhausted")
		}
		proof = &regionCallProof{at: call, target: target, invocation: id, initial: initial, entries: entries, arguments: slices.Clone(actual)}
		k.session.proofs = append(k.session.proofs, proof)
	}
	outcomes, checked := k.session.results[proof]
	// A finite effect trace must visit this invocation's actual instructions even
	// if an earlier proposal checked its return values. Cached endpoint states do
	// not establish access order or account for discarded reads.
	if k.trace != nil {
		child.trace = k.trace
	}
	if !checked || k.trace != nil {
		outcomes, err = child.checkEntries(proof.entries)
		if err != nil {
			return nil, err
		}
		k.session.results[proof] = outcomes
		if !checked {
			k.session.used = append(k.session.used, proof)
		}
	}
	if k.trace != nil {
		if len(outcomes) != 1 || len(k.trace.calls) >= k.meter.limits.nodes {
			return nil, regionError("finite call effects require one bounded complete returned state")
		}
		k.trace.calls = append(k.trace.calls, regionCallApplication{proof: proof, outcome: outcomes[0]})
	}
	var returned []regionState
	for _, outcome := range outcomes {
		if !types.Identical(outcome.value.typ, call.Type()) {
			return nil, regionError("callee return does not match actual call result")
		}
		// SSA registers are immutable language values. Only they are preserved;
		// the heap is replaced wholesale by the checked callee outcome. There is
		// no implicit frame resurrection for facts a callee widened or changed.
		after, err := k.clone(regionState{values: caller.values, memory: outcome.state.memory})
		if err != nil {
			return nil, err
		}
		after.values[call] = outcome.value
		returned = append(returned, after)
	}
	return returned, nil
}

func (k *regionKernel) returnValue(ret *ssa.Return, state regionState) (regionValue, error) {
	results := k.input.root.Signature.Results()
	if len(ret.Results) != results.Len() {
		return regionValue{}, regionError("return omits actual result values")
	}
	tuple := regionValue{typ: results, kind: regionAggregate}
	for i, operand := range ret.Results {
		value := k.value(state, operand)
		if !types.Identical(value.typ, results.At(i).Type()) {
			return regionValue{}, regionError("return result type mismatch")
		}
		tuple.elements = append(tuple.elements, value)
	}
	if len(tuple.elements) == 1 {
		return tuple.elements[0], nil
	}
	if err := k.validateValue(tuple, 0); err != nil {
		return regionValue{}, err
	}
	return tuple, nil
}
