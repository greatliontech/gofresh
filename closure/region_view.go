package closure

import (
	"go/types"
	"slices"
)

// Scalar views reinterpret the Go type of a cell, not its location or contents.
// Identical underlying scalar types have the same language value domain. This
// deliberately excludes aggregate layouts, pointer reinterpretation and numeric
// conversions between distinct basic types, even when their sizes agree.
func regionScalarView(storage, view types.Type) bool {
	if storage == nil || view == nil {
		return false
	}
	a, ok := storage.Underlying().(*types.Basic)
	if !ok {
		return false
	}
	b, ok := view.Underlying().(*types.Basic)
	return ok && types.Identical(a, b) && a.Info()&(types.IsBoolean|types.IsInteger|types.IsString|types.IsFloat) != 0
}

func regionAccessType(storage, view types.Type) bool {
	return storage != nil && view != nil && (types.Identical(storage, view) || regionScalarView(storage, view))
}

func regionPointerChange(from, to types.Type) bool {
	if from == nil || to == nil {
		return false
	}
	a, ok := from.Underlying().(*types.Pointer)
	if !ok {
		return false
	}
	b, ok := to.Underlying().(*types.Pointer)
	return ok && regionAccessType(a.Elem(), b.Elem()) && types.ConvertibleTo(from, to)
}

// The memory map always carries the storage type derived from its object/path.
// Reads acquire the access type; writes return to the storage type. No second
// object or stored storage-type field is needed for either direction.
func regionViewValue(value regionValue, typ types.Type) (regionValue, bool) {
	if types.Identical(value.typ, typ) {
		return value, true
	}
	if !regionScalarView(value.typ, typ) || value.kind != regionUnknown && value.kind != regionConstant && value.kind != regionFloat {
		return regionValue{}, false
	}
	value.typ = typ
	return value, true
}

// Equal abstract summary locations need not denote the same concrete instance.
// Exact equality is available only for a checked singleton and an exact path.
// Different locations stay unknown: Go permits aliasing of zero-sized objects.
func (k *regionKernel) pointerEquality(a, b regionValue) (bool, bool) {
	if a.kind != regionPointer || b.kind != regionPointer || a.location.object != b.location.object || !slices.Equal(a.location.path, b.location.path) || !k.singleton(a.location.object) {
		return false, false
	}
	for _, step := range a.location.path {
		if step.summary {
			return false, false
		}
	}
	return true, true
}
