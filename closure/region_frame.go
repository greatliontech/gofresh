package closure

import "go/types"

// A normal-return frame is derived during checking, never supplied by a
// proposal. It bounds writes only on paths contributing normal successors.
// Excluded exceptional executions retain arbitrary effects.
type regionWriteFrame struct {
	objects map[regionObject]bool
	typed   []types.Type
	maps    []types.Type
}

func regionOpenObject(object regionObject) bool {
	return object.kind == regionFormal || object.kind == regionUnknownObject
}

// Formal and unknown objects may designate any concrete region. Distinct
// concrete object identities remain separate; equal summary identities retain
// all their instances. Stores and call-frame application share this rule.
func regionObjectsMayAlias(a, b regionObject) bool {
	return a == b || regionOpenObject(a) || regionOpenObject(b)
}

func (k *regionKernel) invalidateRegionAliases(s *regionState, target regionObject) error {
	for object := range s.memory {
		if err := k.meter.tick(); err != nil {
			return err
		}
		if regionObjectsMayAlias(target, object) && (target != object || regionOpenObject(target)) {
			delete(s.memory, object)
		}
	}
	return nil
}

// An address without a location supplies no frame separating it from current
// heap facts. The existing unknown-object footprint expresses that uncertainty
// directly, and is applied by the same alias rule as concrete and formal writes.
func (k *regionKernel) havocUnknownStorage(s *regionState) error {
	unknown := regionObject{kind: regionUnknownObject}
	if err := k.writeObject(unknown); err != nil {
		return err
	}
	return k.invalidateRegionAliases(s, unknown)
}

func (k *regionKernel) writeObject(object regionObject) error {
	if !k.input.normalReturns {
		return nil
	}
	if err := k.meter.tick(); err != nil {
		return err
	}
	if !k.frame.objects[object] && len(k.frame.objects) >= k.meter.limits.locations {
		return regionError("write frame object budget exhausted")
	}
	if k.frame.objects == nil {
		k.frame.objects = map[regionObject]bool{}
	}
	k.frame.objects[object] = true
	return nil
}

func (k *regionKernel) addFrameType(dst *[]types.Type, typ types.Type) error {
	for _, old := range *dst {
		if err := k.meter.tick(); err != nil {
			return err
		}
		if types.Identical(typ, old) {
			return nil
		}
	}
	if err := k.meter.tick(); err != nil {
		return err
	}
	if len(*dst) >= k.meter.limits.locations {
		return regionError("write frame type budget exhausted")
	}
	*dst = append(*dst, typ)
	return nil
}

func (k *regionKernel) mergeFrame(frame regionWriteFrame) error {
	for object := range frame.objects {
		if err := k.meter.tick(); err != nil {
			return err
		}
		if err := k.writeObject(object); err != nil {
			return err
		}
	}
	for _, pair := range []struct {
		dst *[]types.Type
		src []types.Type
	}{{&k.frame.typed, frame.typed}, {&k.frame.maps, frame.maps}} {
		for _, typ := range pair.src {
			if err := k.meter.tick(); err != nil {
				return err
			}
			if err := k.addFrameType(pair.dst, typ); err != nil {
				return err
			}
		}
	}
	return nil
}

func (k *regionKernel) framePreserves(frame regionWriteFrame, object regionObject) (bool, error) {
	if err := k.meter.tick(); err != nil {
		return false, err
	}
	if frame.objects[object] {
		return false, nil
	}
	for written := range frame.objects {
		if err := k.meter.tick(); err != nil {
			return false, err
		}
		if regionObjectsMayAlias(object, written) {
			return false, nil
		}
	}
	typ := k.objectType(object)
	if typ == nil {
		return false, nil
	}
	if object.kind == regionMapAllocation {
		for _, written := range frame.maps {
			if err := k.meter.tick(); err != nil {
				return false, err
			}
			if regionMapAliasTypes(typ, written) {
				return false, nil
			}
		}
	} else {
		for _, written := range frame.typed {
			yes, err := k.typedStorageOverlaps(typ, written, 0)
			if err != nil || yes {
				return false, err
			}
		}
	}
	return true, nil
}

func (k *regionKernel) typedStorageOverlaps(t, typ types.Type, depth int) (bool, error) {
	if err := k.meter.tick(); err != nil {
		return false, err
	}
	if depth > k.meter.limits.depth {
		return false, regionError("typed write depth exhausted")
	}
	// An arbitrary incoming pointer may already carry a legal named-type or
	// tag-ignoring pointer conversion from the omitted prefix.
	if regionAccessType(t, typ) || types.IdenticalIgnoreTags(t.Underlying(), typ.Underlying()) {
		return true, nil
	}
	switch u := t.Underlying().(type) {
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			yes, err := k.typedStorageOverlaps(u.Field(i).Type(), typ, depth+1)
			if err != nil || yes {
				return yes, err
			}
		}
	case *types.Array:
		return k.typedStorageOverlaps(u.Elem(), typ, depth+1)
	}
	return false, nil
}
