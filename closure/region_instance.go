package closure

import (
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// The registry belongs solely to the checked machine and its owned resumptions.
// An incoming coordinate, including one copied from an inspection projection,
// cannot populate it. Legacy kernels therefore reject all dynamic identities.
func (k *regionKernel) validInstance(o regionObject) bool {
	if o.instance == 0 {
		return o.extent == 0
	}
	return k.session != nil && k.session.finite && k.session.instances[o]
}

// Every allocating typed transfer uses this constructor. Instance ordinals name
// actual step events, not proposed loop counts or assumed allocation freshness.
func (k *regionKernel) constructObject(kind regionObjectKind, site ssa.Value, extent int64) (regionObject, error) {
	o := regionObject{kind: kind, site: site, context: k.input.root, invocation: k.invocation, extent: extent}
	if !k.session.finite {
		if extent != 0 || kind == regionSliceAllocation {
			return regionObject{}, regionError("dynamic slice construction requires activation evidence")
		}
		return o, nil
	}
	ins, ok := site.(ssa.Instruction)
	if !ok || ins.Parent() != k.input.root || k.current.instruction != ins || k.current.invocation != k.invocation || !k.session.occurrences[k.current] {
		return regionObject{}, regionError("allocation lacks its actual checked occurrence")
	}
	o.instance = k.current.ordinal + 1
	if k.session.instances[o] || len(k.session.instances) >= k.meter.limits.nodes {
		return regionObject{}, regionError("allocation occurrence repeated or exhausted")
	}
	k.session.instances[o] = true
	return o, nil
}

// makeSlice derives only successful construction's backing and value. The
// activation machine must retain the pre-construction abrupt alternatives before
// invoking it; the ordinary shared transfer supplies no construction authority.
func (k *regionKernel) makeSlice(s *regionState, x *ssa.MakeSlice) (regionValue, error) {
	length, lok := regionInt(k.value(*s, x.Len))
	capacity, cok := regionInt(k.value(*s, x.Cap))
	if !k.session.finite || !lok || !cok || length < 0 || capacity < length || capacity > int64(k.meter.limits.locations) {
		return regionValue{}, regionError("slice construction lacks bounded actual extent")
	}
	o, err := k.constructObject(regionSliceAllocation, x, capacity)
	if err != nil {
		return regionValue{}, err
	}
	value, err := k.zero(types.NewArray(x.Type().Underlying().(*types.Slice).Elem(), capacity), 0)
	if err != nil {
		return regionValue{}, err
	}
	if err := k.writeObject(o); err != nil {
		return regionValue{}, err
	}
	s.memory[o] = value
	return regionValue{typ: x.Type(), kind: regionSlice, location: regionLocation{object: o}, length: length, capacity: capacity}, nil
}
