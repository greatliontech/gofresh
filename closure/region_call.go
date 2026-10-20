package closure

import (
	"context"
	"fmt"
	"go/ast"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// regionInvocation is an immutable, pass-local call-context coordinate. Only a
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

// A source candidate proposes only entry states and block invariants or a finite
// occurrence path, with those two arms mutually exclusive. There is no
// producer-supplied return, preserved-heap, callback-free, or closed flag.
// Returns and resulting heaps are derived again by the checker. A normal-return
// application may additionally preserve incoming facts through a checked write
// frame; the producer supplies neither that frame nor a preserved heap.
type regionCallProof struct {
	caller       regionEffectOccurrence
	selection    *program
	occurrences  *regionOccurrencePath
	at           *ssa.Call
	target       *ssa.Function
	invocation   regionInvocation
	initial      regionState
	storageModel regionStorageModel
	entries      map[*ssa.BasicBlock][]regionState
	// A checked assembly reference is a distinct closed evidence arm. It carries
	// no proposed successor heap or result and is applied again by the checker.
	reference *assemblyReference
	arguments []regionValue
}

type regionCallSession struct {
	exceptional  map[regionExcludedContinuation]bool
	dependencies map[*regionCallProof]map[*regionCallProof]bool
	suspended    []map[ssa.Value]regionValue
	functions    map[*ssa.Function]regionFunctionFacts
	root         *ssa.Function
	meter        *regionMeter
	contexts     map[regionInvocation]regionContextFacts
	preexisting  map[regionObject]bool
	active       map[*ssa.Function]bool
	proposing    bool
	proofs       []*regionCallProof
	byTarget     map[*ssa.Function][]*regionCallProof
	results      map[*regionCallProof][]regionObservation
	frames       map[*regionCallProof]regionWriteFrame
	used         []*regionCallProof
	references   map[*ssa.Function]*assemblyReference
	source       computationSource
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
	return &regionCallSession{frames: map[*regionCallProof]regionWriteFrame{}, functions: map[*ssa.Function]regionFunctionFacts{}, root: in.root, meter: &regionMeter{ctx: ctx, limits: limits}, contexts: map[regionInvocation]regionContextFacts{}, preexisting: map[regionObject]bool{}, active: map[*ssa.Function]bool{in.root: true}, results: map[*regionCallProof][]regionObservation{}}
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
	// Finite cyclic call sites remain refused. Consequently the existing actual
	// call string is injective over admitted activations; the exact caller event
	// binds proof applications without a second activation-identity mechanism.
	if k.trace != nil && (k.cycle[call.Block()] || k.current.instruction != call || k.current.invocation != k.invocation || k.current.owner != k.trace.owner || !k.trace.seen[k.current]) {
		return regionInvocation{}, regionError("call lacks its exact checked invoking occurrence")
	}
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
	// Normal-return summaries intentionally merge activations. Escaping objects
	// are summaries; only independently proved activation-local storage may be
	// strongly initialized. The strict occurrence arm retains exact call strings.
	if k.input.normalReturns {
		id.path = fmt.Sprintf("/summary:%p", target)
		facts.repeated = true
		facts.depth = 1
	}
	if old, exists := k.session.contexts[id]; exists {
		if old.function != target || old.repeated != facts.repeated || old.depth != facts.depth {
			return regionInvocation{}, regionError("inconsistent derived call context")
		}
	} else {
		k.meter.nodes++
		if k.meter.nodes > k.meter.limits.nodes {
			return regionInvocation{}, regionError("call context node budget exhausted")
		}
		if len(k.session.contexts) >= k.meter.limits.nodes {
			return regionInvocation{}, regionError("call context count exhausted")
		}
		k.session.contexts[id] = facts
	}
	return id, nil
}

func (k *regionKernel) call(call *ssa.Call, caller regionState) ([]regionState, error) {
	k.meter.applications++
	if err := k.meter.tick(); err != nil {
		return nil, err
	}
	k.session.suspended = append(k.session.suspended, caller.values)
	defer func() { k.session.suspended = k.session.suspended[:len(k.session.suspended)-1] }()
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
		if k.value(caller, operand).kind == regionUnsafePointer {
			return nil, regionError("unsafe pointer view cannot escape through a call")
		}
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
	if len(k.session.active) >= k.meter.limits.depth {
		return nil, regionError("call stack depth exhausted")
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
	in := regionInput{normalReturns: k.input.normalReturns, owner: k.input.owner, selection: k.input.selection, root: target, entry: regionPoint{target.Blocks[0], 0}, initial: initial, premises: k.input.premises, storageModel: k.input.storageModel}
	child, err := newRegionContextKernel(in, k.session, id, true)
	if err != nil {
		return nil, err
	}
	var proof *regionCallProof
	if k.session.byTarget == nil {
		k.session.byTarget = map[*ssa.Function][]*regionCallProof{}
		for _, p := range k.session.proofs {
			if err := k.meter.tick(); err != nil {
				return nil, err
			}
			k.session.byTarget[p.target] = append(k.session.byTarget[p.target], p)
		}
	}
	candidates := k.session.byTarget[target]
	for _, candidate := range candidates {
		if err := k.meter.tick(); err != nil {
			return nil, err
		}
		if !k.input.normalReturns && candidate.at != call || candidate.target != target || candidate.invocation != id || candidate.caller != k.current || candidate.reference != nil || candidate.selection != k.input.selection || candidate.storageModel != k.input.storageModel {
			continue
		}
		if len(candidate.arguments) != len(actual) {
			continue
		}
		sameArguments := true
		if !k.input.normalReturns {
			for i, argument := range actual {
				if err := k.chargeValue(argument); err != nil {
					return nil, err
				}
				sameArguments = sameArguments && regionSameValue(argument, candidate.arguments[i])
			}
		}
		if !sameArguments && !k.input.normalReturns {
			continue
		}
		if _, checked := k.session.results[candidate]; !checked {
			if err := child.validateState(candidate.initial); err != nil {
				return nil, err
			}
		}
		forward, err := child.included(initial, candidate.initial)
		if err != nil {
			return nil, err
		}
		backward := true
		if !k.input.normalReturns {
			backward, err = child.included(candidate.initial, initial)
			if err != nil {
				return nil, err
			}
		}
		if forward && (backward || k.input.normalReturns) {
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
		if k.input.normalReturns {
			// Discovery may weaken an input; checking below establishes initial
			// inclusion and all transfers for that complete generalized input.
			for _, old := range k.session.byTarget[target] {
				if old.target == target && old.invocation == id && old.reference == nil {
					var err error
					initial, err = child.commonState(initial, old.initial)
					if err != nil {
						return nil, err
					}
				}
			}
			child.input.initial = initial
		}
		if k.trace != nil {
			// Nested checked references also need effect-aware proposal execution.
			// Its events are provisional: checking below replays the body into the
			// parent's trace under the same cumulative meter.
			child.trace = &regionEffectTrace{owner: k.trace.owner, seen: map[regionEffectOccurrence]bool{}}
		}
		entries, occurrences, err := child.proposeFlow()
		if err != nil {
			return nil, err
		}
		if len(k.session.proofs) >= k.meter.limits.nodes {
			return nil, regionError("callee proof count exhausted")
		}
		proof = &regionCallProof{at: call, target: target, invocation: id, caller: k.current, initial: initial, entries: entries, occurrences: occurrences, arguments: slices.Clone(actual), storageModel: k.input.storageModel, selection: k.input.selection}
		k.session.proofs = append(k.session.proofs, proof)
		k.session.byTarget[target] = append(k.session.byTarget[target], proof)
	}
	outcomes, checked := k.session.results[proof]
	if checked {
		k.meter.reused++
	}
	// Cached outcomes cover the summary's entire admitted input, not merely the
	// first actual call that happened to request it. No omitted heap fact is
	// resurrected when applying its whole successor heap.
	child.input.initial = proof.initial
	// A finite effect trace must visit this invocation's actual instructions even
	// if an earlier proposal checked its return values. Cached endpoint states do
	// not establish access order or account for discarded reads.
	if k.trace != nil {
		child.trace = k.trace
		child.next, child.current = 0, regionEffectOccurrence{}
	}
	if !checked || k.trace != nil {
		child.frame = regionWriteFrame{}
		outcomes, err = child.checkFlow(proof.entries, proof.occurrences)
		if err != nil {
			return nil, err
		}
		k.session.results[proof] = outcomes
		k.session.frames[proof] = child.frame
		if k.session.dependencies == nil {
			k.session.dependencies = map[*regionCallProof]map[*regionCallProof]bool{}
		}
		k.session.dependencies[proof] = child.applied
		if !checked {
			k.session.used = append(k.session.used, proof)
		}
	}
	frame := k.session.frames[proof]
	if k.applied == nil {
		k.applied = map[*regionCallProof]bool{}
	}
	k.applied[proof] = true
	if k.input.normalReturns {
		if err := k.mergeFrame(frame); err != nil {
			return nil, err
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
		// SSA registers are immutable language values. Heap facts come from the
		// checked outcome or its independently derived normal-return frame. Facts
		// a callee may have changed are never resurrected from the caller.
		after, err := k.clone(regionState{values: caller.values, memory: outcome.state.memory})
		if err != nil {
			return nil, err
		}
		after.values[call] = outcome.value
		if k.input.normalReturns {
			for object, value := range caller.memory {
				preserved, err := k.framePreserves(frame, object)
				if err != nil {
					return nil, err
				}
				if preserved {
					after.memory[object] = value
				}
			}
		}
		if err := k.trimHeap(&after); err != nil {
			return nil, err
		}
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
		if k.escapingView(value) {
			return regionValue{}, regionError("storage view cannot escape through a return")
		}
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
