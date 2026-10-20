package closure

import (
	"go/constant"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// Projections are equality-respecting, by-value, nonblank struct field paths.
// Nil sets denote top. Empty maps have a separate representation, including
// when their key types have no eligible projections. No payload is retained.
type regionKeyProjection struct {
	path    []int
	strings []string
}
type regionMapKeys struct {
	empty       bool
	projections []regionKeyProjection
}

const regionProjectionAlternatives = 32

// Legal map conversions may ignore struct tags while retaining the very same
// backing. Named component types still keep their identity. Both mutation and
// frame checking use this relation, including aliases formed before entry.
func regionMapAliasTypes(a, b types.Type) bool {
	if a == nil || b == nil {
		return false
	}
	_, am := a.Underlying().(*types.Map)
	_, bm := b.Underlying().(*types.Map)
	return am && bm && types.IdenticalIgnoreTags(a.Underlying(), b.Underlying())
}

type regionStringSlice struct {
	first  *string
	length int
}

func (m *regionMeter) copyStrings(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > regionProjectionAlternatives {
		return nil, regionError("string set extent exhausted")
	}
	key := regionStringSlice{&values[0], len(values)}
	if copy := m.stringCopies[key]; copy != nil {
		return copy, nil
	}
	for _, text := range values {
		if len(text) > m.limits.locations {
			return nil, regionError("string-set scalar storage exhausted")
		}
		m.locations++
		if m.stringAtoms == nil {
			m.stringAtoms = map[string]bool{}
		}
		if !m.stringAtoms[text] {
			m.locations += len(text)
			m.stringAtoms[text] = true
		}
		if m.locations > m.limits.locations {
			return nil, regionError("string-set storage budget exhausted")
		}
	}
	copy := slices.Clone(values)
	if m.stringCopies == nil {
		m.stringCopies = map[regionStringSlice][]string{}
	}
	m.stringCopies[key] = copy
	return copy, nil
}

func (m *regionMeter) copyMapKeys(keys *regionMapKeys) (*regionMapKeys, error) {
	if copied := m.keyCopies[keys]; copied != nil {
		return copied, nil
	}
	if len(keys.projections) > m.limits.locations {
		return nil, regionError("map projection budget exhausted")
	}
	r := &regionMapKeys{empty: keys.empty, projections: make([]regionKeyProjection, len(keys.projections))}
	for i, p := range keys.projections {
		if err := m.tick(); err != nil {
			return nil, err
		}
		if len(p.path) > m.limits.depth || len(p.strings) > regionProjectionAlternatives {
			return nil, regionError("map projection extent exhausted")
		}
		m.locations += len(p.path) + 1
		if m.locations > m.limits.locations {
			return nil, regionError("map projection storage exhausted")
		}
		owned, err := m.copyStrings(p.strings)
		if err != nil {
			return nil, err
		}
		r.projections[i] = regionKeyProjection{slices.Clone(p.path), owned}
	}
	if m.keyCopies == nil {
		m.keyCopies = map[*regionMapKeys]*regionMapKeys{}
	}
	m.keyCopies[keys] = r
	return r, nil
}

func regionSameMapKeys(a, b *regionMapKeys) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.empty != b.empty || len(a.projections) != len(b.projections) {
		return false
	}
	for i, p := range a.projections {
		q := b.projections[i]
		if !slices.Equal(p.path, q.path) || !slices.Equal(p.strings, q.strings) {
			return false
		}
	}
	return true
}

func regionMapKeysIncluded(a, b *regionMapKeys) bool {
	if a == nil || b == nil {
		return false
	}
	if a.empty {
		return true
	}
	if b.empty || len(a.projections) != len(b.projections) {
		return false
	}
	for i, p := range a.projections {
		q := b.projections[i]
		if !slices.Equal(p.path, q.path) {
			return false
		}
		if q.strings == nil {
			continue
		}
		if p.strings == nil {
			return false
		}
		for _, s := range p.strings {
			if !slices.Contains(q.strings, s) {
				return false
			}
		}
	}
	return true
}

func regionJoinMapKeys(a, b *regionMapKeys) *regionMapKeys {
	if regionMapKeysIncluded(a, b) {
		return b
	}
	if regionMapKeysIncluded(b, a) {
		return a
	}
	if a.empty {
		return b
	}
	if b.empty {
		return a
	}
	r := &regionMapKeys{projections: make([]regionKeyProjection, len(a.projections))}
	for i, p := range a.projections {
		q := b.projections[i]
		r.projections[i].path = p.path
		if p.strings == nil || q.strings == nil {
			continue
		}
		set := append(slices.Clone(p.strings), q.strings...)
		slices.Sort(set)
		set = slices.Compact(set)
		if len(set) <= regionProjectionAlternatives {
			r.projections[i].strings = set
		}
	}
	return r
}

func (k *regionKernel) mapProjections(typ types.Type) ([]regionKeyProjection, error) {
	var result []regionKeyProjection
	var walk func(types.Type, []int) error
	walk = func(t types.Type, path []int) error {
		if err := k.meter.tick(); err != nil {
			return err
		}
		if len(path) > k.meter.limits.depth || len(result) >= k.meter.limits.locations {
			return regionError("map key type budget exhausted")
		}
		switch t := t.Underlying().(type) {
		case *types.Basic:
			if t.Info()&types.IsString != 0 {
				result = append(result, regionKeyProjection{path: slices.Clone(path)})
			}
		case *types.Struct:
			for i := 0; i < t.NumFields(); i++ {
				if err := k.meter.tick(); err != nil {
					return err
				}
				if t.Field(i).Name() != "_" {
					if err := walk(t.Field(i).Type(), append(slices.Clone(path), i)); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	err := walk(typ, nil)
	return result, err
}

func regionProjectedStrings(v regionValue, path []int) []string {
	for _, i := range path {
		if v.kind != regionAggregate || i < 0 || i >= len(v.elements) {
			return nil
		}
		v = v.elements[i]
	}
	return regionStringChoices(v)
}

func regionStringChoices(v regionValue) []string {
	if v.kind == regionStrings {
		return v.strings
	}
	if text, ok := regionString(v); ok {
		return []string{text}
	}
	return nil
}

func regionStringsIncluded(a, b regionValue) bool {
	if b.kind != regionStrings {
		return false
	}
	choices := regionStringChoices(a)
	if choices == nil {
		return false
	}
	for _, s := range choices {
		if !slices.Contains(b.strings, s) {
			return false
		}
	}
	return true
}

func regionJoinStrings(a, b regionValue) regionValue {
	if regionStringsIncluded(a, b) {
		return b
	}
	if regionStringsIncluded(b, a) {
		return a
	}
	x, y := regionStringChoices(a), regionStringChoices(b)
	if x == nil || y == nil {
		return regionUnknownValue(a.typ)
	}
	values := append(slices.Clone(x), y...)
	slices.Sort(values)
	values = slices.Compact(values)
	if len(values) > regionProjectionAlternatives {
		return regionUnknownValue(a.typ)
	}
	if len(values) == 1 {
		return regionValue{typ: a.typ, kind: regionConstant, scalar: constant.MakeString(values[0])}
	}
	return regionValue{typ: a.typ, kind: regionStrings, strings: values}
}

func (k *regionKernel) mapKeyValue(typ types.Type, key regionValue) (regionValue, error) {
	paths, err := k.mapProjections(typ.Underlying().(*types.Map).Key())
	if err != nil {
		return regionValue{}, err
	}
	for i := range paths {
		paths[i].strings = regionProjectedStrings(key, paths[i].path)
	}
	return regionValue{typ: typ, kind: regionMapContents, keys: &regionMapKeys{projections: paths}}, nil
}

func (k *regionKernel) validateMapKeys(v regionValue) error {
	if v.kind != regionMapContents || v.scalar != nil || v.floatBits != 0 || v.location.object != (regionObject{}) || len(v.location.path) != 0 || v.start != 0 || v.length != 0 || v.capacity != 0 || v.target != nil || len(v.environment) != 0 || len(v.elements) != 0 || len(v.strings) != 0 {
		return regionError("noncanonical map storage payload")
	}
	if v.typ == nil {
		return regionError("map contents lack a type")
	}
	m, ok := v.typ.Underlying().(*types.Map)
	if !ok || v.keys == nil {
		return regionError("map contents lack typed projections")
	}
	if v.keys.empty {
		if len(v.keys.projections) != 0 {
			return regionError("noncanonical empty map")
		}
		return nil
	}
	paths, err := k.mapProjections(m.Key())
	if err != nil {
		return err
	}
	if len(paths) != len(v.keys.projections) {
		return regionError("incomplete map projections")
	}
	for i, p := range v.keys.projections {
		if !slices.Equal(paths[i].path, p.path) || p.strings != nil && (len(p.strings) == 0 || len(p.strings) > regionProjectionAlternatives || !slices.IsSorted(p.strings) || len(slices.Compact(slices.Clone(p.strings))) != len(p.strings)) {
			return regionError("noncanonical map projection")
		}
		for _, text := range p.strings {
			if len(text) > k.meter.limits.locations {
				return regionError("map string budget exhausted")
			}
		}
	}
	return nil
}

// A miss uses just one impossible equality-respecting component. Independent
// components never prove presence or reconstruct a complete key.
func regionMapMiss(contents, key regionValue) bool {
	if contents.kind != regionMapContents || contents.keys == nil {
		return false
	}
	if contents.keys.empty {
		return true
	}
	for _, p := range contents.keys.projections {
		query := regionProjectedStrings(key, p.path)
		if query == nil || p.strings == nil {
			continue
		}
		disjoint := true
		for _, text := range query {
			disjoint = disjoint && !slices.Contains(p.strings, text)
		}
		if disjoint {
			return true
		}
	}
	return false
}

func (k *regionKernel) makeMap(s *regionState, x *ssa.MakeMap) (regionValue, error) {
	if !k.input.normalReturns && x.Reserve != nil {
		n, known := regionInt(k.value(*s, x.Reserve))
		if !known || n < 0 {
			return regionValue{}, regionError("map allocation hint may panic")
		}
	}
	object := regionObject{kind: regionMapAllocation, site: x, context: k.input.root, invocation: k.invocation}
	if err := k.writeObject(object); err != nil {
		return regionValue{}, err
	}
	contents := regionValue{typ: x.Type(), kind: regionMapContents, keys: &regionMapKeys{empty: true}}
	if !k.singleton(object) {
		old, exists := s.memory[object]
		if !exists || old.kind != regionMapContents {
			contents = regionUnknownValue(x.Type())
		} else {
			contents.keys = regionJoinMapKeys(old.keys, contents.keys)
		}
	}
	s.memory[object] = contents
	return regionValue{typ: x.Type(), kind: regionMap, location: regionLocation{object: object}}, nil
}

func (k *regionKernel) updateMap(s *regionState, x *ssa.MapUpdate) error {
	m, key := k.value(*s, x.Map), k.value(*s, x.Key)
	if k.escapingView(key) || k.escapingView(k.value(*s, x.Value)) {
		return regionError("storage view cannot escape through a map")
	}
	if m.kind != regionMap && !k.input.normalReturns {
		return regionError("map update lacks backing identity")
	}
	if total, err := k.equalityTotal(key.typ, true, 0, map[types.Type]bool{}); err != nil || !total {
		if err != nil {
			return err
		}
		return regionError("map key may have incomparable dynamic contents")
	}
	added, err := k.mapKeyValue(m.typ, key)
	if err != nil {
		return err
	}
	if m.kind != regionMap {
		if err := k.addFrameType(&k.frame.maps, m.typ); err != nil {
			return err
		}
		for object, old := range s.memory {
			if err := k.meter.tick(); err != nil {
				return err
			}
			if object.kind == regionMapAllocation && regionMapAliasTypes(old.typ, m.typ) && old.kind == regionMapContents {
				old.keys = regionJoinMapKeys(old.keys, added.keys)
				s.memory[object] = old
			}
		}
		return nil
	}
	if err := k.writeObject(m.location.object); err != nil {
		return err
	}
	old := s.memory[m.location.object]
	if old.kind == regionMapContents {
		added.typ = old.typ
		added.keys = regionJoinMapKeys(old.keys, added.keys)
		s.memory[m.location.object] = added
	}
	return nil
}

func (k *regionKernel) lookupMap(s regionState, x *ssa.Lookup) (regionValue, error) {
	m, key := k.value(s, x.X), k.value(s, x.Index)
	if total, err := k.equalityTotal(key.typ, true, 0, map[types.Type]bool{}); err != nil || !total {
		if err != nil {
			return regionValue{}, err
		}
		return regionValue{}, regionError("map lookup key may panic")
	}
	miss := m.kind == regionNil || m.kind == regionMap && regionMapMiss(s.memory[m.location.object], key)
	mt := x.X.Type().Underlying().(*types.Map)
	value := regionUnknownValue(mt.Elem())
	found := regionUnknownValue(types.Typ[types.Bool])
	if miss {
		var err error
		value, err = k.zero(mt.Elem(), 0)
		if err != nil {
			return regionValue{}, err
		}
		found = regionValue{typ: types.Typ[types.Bool], kind: regionConstant, scalar: constant.MakeBool(false)}
	}
	if x.CommaOk {
		return regionValue{typ: x.Type(), kind: regionAggregate, elements: []regionValue{value, found}}, nil
	}
	return value, nil
}

// The upper bound keeps whole common terms, not independently chosen fields of
// registration rows. Map projections explicitly denote a Cartesian relaxation.
func (k *regionKernel) commonState(a, b regionState) (regionState, error) {
	r, err := k.clone(a)
	if err != nil {
		return regionState{}, err
	}
	join := func(x, y regionValue) regionValue {
		if regionSameValue(x, y) {
			return x
		}
		if k.input.normalReturns && types.Identical(x.typ, y.typ) {
			if b, ok := x.typ.Underlying().(*types.Basic); ok && b.Info()&types.IsString != 0 {
				return regionJoinStrings(x, y)
			}
		}
		if x.kind == regionMapContents && y.kind == regionMapContents && types.Identical(x.typ, y.typ) {
			x.keys = regionJoinMapKeys(x.keys, y.keys)
			return x
		}
		return regionUnknownValue(x.typ)
	}
	for key, x := range r.values {
		if err := k.chargeValue(x); err != nil {
			return regionState{}, err
		}
		y, ok := b.values[key]
		if !ok {
			delete(r.values, key)
		} else {
			v := join(x, y)
			if v.kind == regionUnknown {
				delete(r.values, key)
			} else {
				r.values[key] = v
			}
		}
	}
	for key, x := range r.memory {
		if err := k.chargeValue(x); err != nil {
			return regionState{}, err
		}
		y, ok := b.memory[key]
		if !ok {
			delete(r.memory, key)
		} else {
			v := join(x, y)
			if v.kind == regionUnknown {
				delete(r.memory, key)
			} else {
				r.memory[key] = v
			}
		}
	}
	return r, nil
}
