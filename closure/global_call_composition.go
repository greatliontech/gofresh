package closure

import (
	"context"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

// The coordinates are private accelerators inside these retained owners. Neither
// the projected bound nor a matching invocation name is an application capability.
type globalCallComposition struct {
	prefix      *sourceOperandPrefix
	application regionCallApplication
	native      nativeproof.TransitionCallCertificate
	bound       nativeproof.TransitionCallBound
	sourceUsage regionMeter
	sourceFence [2]int
	nativeFence [2]int
}

// checkGlobalFunctionCallComposition constructs the enclosing return from the
// actual application, then checks one cumulative source/native effect relation.
// Its deliberately narrow interface supports ordinary zero-argument, void calls.
func checkGlobalFunctionCallComposition(ctx context.Context, source computationSource, root *ssa.Function, image *nativeproof.Image, completed *sourceReturnCompletion, prefix *sourceOperandPrefix, application nativeproof.TransitionCallCertificate, tail nativeproof.TransitionProposal, rho storageRepresentation, options ...globalCorrespondenceLimits) (*globalFunctionCorrespondence, error) {
	fail := func(s string) (*globalFunctionCorrespondence, error) { return nil, globalFunctionError(s) }
	if ctx == nil || source.prog == nil || root == nil || image == nil || rho.image == nil || rho.source != source.prog || completed == nil || prefix == nil {
		return fail("missing actual-call source/image owners")
	}
	limit := 2_000_000
	if len(options) > 1 {
		return fail("more than one proof budget")
	}
	if len(options) == 1 {
		limit = options[0].work
	}
	if limit < 1 || limit > 20_000_000 || len(rho.bindings) > storageMaxBindings || len(root.Params) != 0 {
		return fail("invalid actual-call proof budget or root arguments")
	}
	// Native proposals contain mutable nested containers. Freeze our inputs first,
	// then enter native checking before ANY context callback: its capture happens
	// before its first callback and owns the complete tail, including frontiers.
	ownedImage, representedImage := *image, *rho.image
	rho.image, rho.bindings = &representedImage, slices.Clone(rho.bindings)
	meter := &correspondenceContext{Context: ctx, limit: limit}
	successor, ok := application.Successor()
	if !ok {
		return fail("missing actual native call application")
	}
	continued, err := nativeproof.CheckTransitionContinuation(meter, successor, tail)
	if err != nil {
		return nil, err
	}
	returned, err := nativeproof.CheckTransitionReturn(meter, continued)
	if err != nil {
		return nil, err
	}
	bound, ok := application.BoundFor(&ownedImage)
	if _, represented := application.BoundFor(rho.image); !ok || !represented {
		return fail("actual native call has another image owner")
	}
	if completed.checkedPacket() == nil || prefix.checkedPacket() == nil {
		return fail("missing authenticated source completion or call prefix")
	}
	call := &globalCallComposition{prefix: prefix, native: application, bound: bound}
	return checkGlobalFunctionAccount(meter, source, root, &ownedImage, bound.Successor.Entry, completed, returned, rho, nil, call)
}

func (p *globalFunctionCorrespondence) bindActualCall(ctx context.Context, source computationSource, root *ssa.Function, native nativeproof.TransitionBound) error {
	c := p.call
	prefix := c.prefix
	packet := prefix.checkedPacket()
	if packet == nil || packet.input.root != root || packet.input.selection != source.prog || prefix.binder.source.prog != source.prog || prefix.call.Parent() != root || prefix.call.Call.IsInvoke() || len(prefix.call.Call.Args) != 0 || len(prefix.operands) != 0 {
		return globalFunctionError("actual source call has another selected owner or interface")
	}
	found := false
	for prior := p.source.prior; prior != nil; prior = prior.prior {
		if err := ctx.Err(); err != nil {
			return err
		}
		found = found || prior == prefix.sourceEffectPrefix
	}
	if !found {
		return globalFunctionError("call prefix is not the exact retained predecessor")
	}
	target := prefix.call.Call.StaticCallee()
	selected, selectedOK := prefix.binder.bound[target]
	if target == nil || !selectedOK || selected != prefix.callee || !regionSourceCallBody(target) || len(target.Params) != 0 || len(target.FreeVars) != 0 || target.Signature.Results().Len() != 0 {
		return globalFunctionError("actual source child is not an ordinary zero-argument void call")
	}
	var calls []regionCallApplication
	positions := map[regionEffectOccurrence]int{}
	for _, trace := range p.traces {
		if err := checkStoragePrefixBounds(native, trace); err != nil {
			return err
		}
		if len(trace.instructions) > 65536-len(positions) || len(trace.calls) > 65536-len(calls) {
			return globalFunctionError("actual-call source inventory exceeds bound")
		}
		calls = append(calls, trace.calls...)
		for _, occurrence := range trace.instructions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if _, duplicate := positions[occurrence]; duplicate || !trace.seen[occurrence] {
				return globalFunctionError("actual-call source occurrence is unowned or repeated")
			}
			positions[occurrence] = len(positions)
		}
	}
	for _, application := range calls {
		if err := ctx.Err(); err != nil {
			return err
		}
		proof := application.proof
		if proof != nil && proof.caller == prefix.cursor && proof.at == prefix.call {
			if c.application.proof != nil {
				return globalFunctionError("ambiguous actual source application")
			}
			c.application = application
		}
	}
	proof := c.application.proof
	if proof == nil || proof.target != target || proof.reference != nil || proof.selection != source.prog || proof.storageModel != packet.input.storageModel || len(proof.arguments) != 0 || len(proof.initial.values) != 0 || proof.invocation == prefix.cursor.invocation {
		return globalFunctionError("actual source application target, model or selection differs")
	}
	context, registered := p.source.checker.session.contexts[proof.invocation]
	if !registered || context.function != target || proof.invocation.root != root || c.application.outcome.occurrence.invocation != proof.invocation || c.application.outcome.occurrence.owner != prefix.cursor.owner {
		return globalFunctionError("actual source invocation lacks its checked parent relationship")
	}
	// The ordinary zero-argument child receives exactly the current heap, not the
	// caller's immutable SSA registers or a separately rooted arbitrary state.
	usage := p.source.region.packet.usage
	usage.ctx = ctx
	checker := regionKernel{meter: &usage}
	current := regionState{memory: packet.observations[0].state.memory, pending: regionDeferStack{known: true}}
	for _, pair := range [][2]regionState{{current, proof.initial}, {proof.initial, current}} {
		included, err := checker.included(pair[0], pair[1])
		if err != nil {
			return err
		}
		if !included {
			return globalFunctionError("actual source child initial heap differs from current caller")
		}
	}
	usage.ctx = nil
	c.sourceUsage = usage
	start, starts := positions[prefix.cursor]
	end, ends := positions[c.application.outcome.occurrence]
	ret, returned := c.application.outcome.occurrence.instruction.(*ssa.Return)
	if !starts || !ends || !returned || ret.Parent() != target || end <= start {
		return globalFunctionError("actual source child lacks its complete instruction interval")
	}
	// Calls are recorded postorder. Build checked parent edges first, then walk
	// those edges; lexical path-prefix tests cannot establish descendant authority.
	parents := map[regionInvocation]regionInvocation{}
	for _, application := range calls {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := application.proof
		if q == nil || q.caller.owner != prefix.cursor.owner || q.selection != source.prog || q.storageModel != packet.input.storageModel {
			return globalFunctionError("foreign application in actual source scope")
		}
		if _, exists := parents[q.invocation]; exists {
			return globalFunctionError("repeated source call invocation")
		}
		parents[q.invocation] = q.caller.invocation
	}
	for occurrence, position := range positions {
		inside := false
		for at, depth := occurrence.invocation, 0; at != (regionInvocation{}); depth++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			if at == proof.invocation {
				inside = true
				break
			}
			if depth >= len(parents) {
				return globalFunctionError("cyclic source call parent relationship")
			}
			parent, exists := parents[at]
			if !exists {
				break
			}
			at = parent
		}
		if inside != (position > start && position <= end) {
			return globalFunctionError("source child interval disagrees with checked descendants")
		}
	}
	c.sourceFence = [2]int{start, end + 1}
	c.nativeFence = [2]int{len(c.bound.ChildEntry.Accesses), len(c.bound.Successor.Accesses)}
	if c.nativeFence[0] < 1 || c.nativeFence[1] <= c.nativeFence[0] || c.nativeFence[1] > len(native.Accesses) || c.bound.ChildEntry.Boundary.Context != c.bound.Activation {
		return globalFunctionError("actual native child has an incomplete interval")
	}
	for i, access := range c.bound.Successor.Accesses {
		if err := ctx.Err(); err != nil {
			return err
		}
		if native.Accesses[i].ID != access.ID || native.Accesses[i].Context != access.Context {
			return globalFunctionError("constructed return lost actual native access identities")
		}
	}
	return nil
}

// Check current globals using the ORIGINAL root input relation, and only those
// local bytes that this candidate has physically materialized. A source logical
// initializer cannot turn arbitrary native scratch into an established value.
func (p *globalFunctionCorrespondence) checkCallCheckpoint(ctx context.Context, after bool, known map[nativeproof.TransitionLocation]byte) error {
	state, bound := p.call.application.proof.initial, p.call.bound.ChildEntry
	if after {
		state, bound = p.call.application.outcome.state, p.call.bound.Successor
	}
	if err := p.checkDirection(ctx, bound.InitialDirection, bound.Direction); err != nil {
		return err
	}
	builder := br.NewBuilder(65536)
	if err := p.checkStorageValues(ctx, builder, state, bound.Memory, true); err != nil {
		return err
	}
	for _, binding := range p.representation.bindings {
		if binding.object.kind != regionAllocation {
			continue
		}
		value, live := state.memory[binding.object]
		if !live {
			continue
		}
		_, lanes, err := p.storageValueBytes(ctx, regionEffectAccess{location: regionLocation{object: binding.object}, value: value}, true)
		if err != nil {
			return err
		}
		footprint, _ := p.layout.objectFootprint(binding.object)
		for offset := int64(0); offset < footprint.Bytes.Width(); offset++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			location, _ := footprint.Bytes.Byte(offset)
			materialized, exists := known[location]
			if !exists {
				continue
			}
			logical, exact := lanes[location]
			if !exact || materialized != logical {
				return storageMismatch("materialized local differs at actual call checkpoint")
			}
			extent, _ := footprint.Bytes.Subextent(offset, 1)
			actual, err := storageNativeWord(ctx, builder, bound.Memory, extent, 1)
			if err != nil {
				return err
			}
			if err := p.constant(ctx, actual, uint64(logical)); err != nil {
				return err
			}
		}
	}
	return p.checkStorageFrame(ctx, bound)
}
