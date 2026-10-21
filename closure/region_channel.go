package closure

import (
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// A channel is a logical identity, not addressable source storage. Its immutable
// capacity travels with each reference; no contents, closed state, native layout
// or current-stack separation is inferred. Construction uses Go's conditional
// normal-return contract, not a proof of allocator outcomes.
func (k *regionKernel) channelType(object regionObject) *types.Chan {
	a, ok := object.site.(*ssa.MakeChan)
	if object.kind != regionChannelAllocation || !ok || a == nil || object.context == nil || object.context.Prog != k.input.owner || a.Parent() != object.context || a.Block() == nil || len(a.Block().Instrs) > k.meter.limits.nodes {
		return nil
	}
	for _, instruction := range a.Block().Instrs {
		if k.meter.tick() != nil {
			return nil
		}
		if instruction == a {
			t, _ := a.Type().Underlying().(*types.Chan)
			return t
		}
	}
	return nil
}

// Direction may only narrow; the element type stays the selected exact type.
func regionChannelChange(from, to types.Type) bool {
	if from == nil || to == nil {
		return false
	}
	a, aok := from.Underlying().(*types.Chan)
	b, bok := to.Underlying().(*types.Chan)
	return aok && bok && types.Identical(a.Elem(), b.Elem()) && (a.Dir() == b.Dir() || a.Dir() == types.SendRecv) && types.ConvertibleTo(from, to)
}

func (k *regionKernel) makeChannel(s regionState, x *ssa.MakeChan) (regionValue, error) {
	// A representable capacity does not exclude allocation failure or unwinding.
	// Until those outcomes have a checked relation, only a normal-return
	// postcondition may use the successful construction's identity and capacity.
	if !k.input.normalReturns {
		return regionValue{}, regionError("channel allocation outcomes are unsupported outside normal-return scope")
	}
	return k.channelConstruction(s, x)
}

// channelConstruction is the value on the successful language alternative. Its
// callers separately establish the scope and account for other outcomes.
func (k *regionKernel) channelConstruction(s regionState, x *ssa.MakeChan) (regionValue, error) {
	n, exact := regionInt(k.value(s, x.Size))
	// The common language int range bounds this leaf independently of host or
	// runtime allocation layout. Unknown and exceptional capacities refuse even
	// in normal-return mode; this does not establish that a successful execution
	// exists.
	if !exact || n < 0 || n > 1<<31-1 {
		return regionValue{}, regionError("channel capacity is unknown, negative or outside the bounded int range")
	}
	object := regionObject{kind: regionChannelAllocation, site: x, context: k.input.root, invocation: k.invocation}
	return regionValue{typ: x.Type(), kind: regionChannel, location: regionLocation{object: object}, capacity: n}, nil
}

func (k *regionKernel) channelEquality(a, b regionValue) (bool, bool) {
	if a.kind != regionChannel || b.kind != regionChannel || !k.singleton(a.location.object) || !k.singleton(b.location.object) {
		return false, false
	}
	// Unlike pointers to zero-sized variables, distinct make operations produce
	// distinct channels even when the element type is zero-sized.
	return a.location.object == b.location.object, true
}

func (k *regionKernel) validChannel(v regionValue) bool {
	t, ok := v.typ.Underlying().(*types.Chan)
	allocation := k.channelType(v.location.object)
	return ok && allocation != nil && len(v.location.path) == 0 && types.Identical(t.Elem(), allocation.Elem()) &&
		(t.Dir() == allocation.Dir() || allocation.Dir() == types.SendRecv) && v.capacity >= 0 && v.capacity <= 1<<31-1
}
