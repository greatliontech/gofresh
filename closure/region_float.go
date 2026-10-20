package closure

import (
	"go/constant"
	"go/types"
	"math"
)

// regionStorageModel is an explicit conditional antecedent, not a selected
// implementation verdict. The input's separate selection supplies layouts;
// sizes alone never select these semantics.
// The zero value grants no integer/float bit interpretation.
type regionStorageModel struct {
	interpretation regionStorageInterpretation
}

type regionStorageInterpretation uint8

// This model gives binary32/binary64 and two's-complement integer encodings in
// little-endian storage, with exact same-extent typed accesses. It is conditional
// on actual storage and operations obeying that interpretation; source selection
// and type sizes do not prove its applicability to a machine execution.
const regionIEEE754LittleEndian regionStorageInterpretation = 1

func conditionalRegionStorageModel() regionStorageModel {
	return regionStorageModel{interpretation: regionIEEE754LittleEndian}
}

func (m regionStorageModel) valid(in regionInput) bool {
	return m == (regionStorageModel{}) || m.interpretation == regionIEEE754LittleEndian && in.selection != nil && in.selection.Prog == in.owner
}

func regionFloatWidth(typ types.Type) int {
	if typ == nil {
		return 0
	}
	basic, ok := typ.Underlying().(*types.Basic)
	if ok {
		switch basic.Kind() {
		case types.Float32:
			return 4
		case types.Float64:
			return 8
		}
	}
	return 0
}

func regionFloatConstant(typ types.Type, value constant.Value) (regionValue, bool) {
	width := regionFloatWidth(typ)
	if width == 0 || value == nil || value.Kind() != constant.Float && value.Kind() != constant.Int {
		return regionValue{}, false
	}
	result := regionValue{typ: typ, kind: regionFloat}
	if width == 4 {
		f, _ := constant.Float32Val(value) // Direct target rounding avoids double rounding.
		if math.IsInf(float64(f), 0) {
			return regionValue{}, false
		}
		if f != 0 { // Typed Go constants have unsigned zero, including underflow.
			result.floatBits = uint64(math.Float32bits(f))
		}
	} else {
		f, _ := constant.Float64Val(value)
		if math.IsInf(f, 0) {
			return regionValue{}, false
		}
		if f != 0 {
			result.floatBits = math.Float64bits(f)
		}
	}
	return result, true
}

// regionScalarBits projects a value, not native-storage applicability. Consumers
// establish the selected width, storage model and location relation separately.
func regionScalarBits(value regionValue, width int) (uint64, bool) {
	if value.kind == regionFloat {
		return value.floatBits, regionFloatWidth(value.typ) == width && (width == 8 || width == 4 && value.floatBits <= math.MaxUint32)
	}
	return regionReferenceWord(value, width)
}

func regionFloatEquality(a, b regionValue) (bool, bool) {
	if a.kind != regionFloat || b.kind != regionFloat || !types.Identical(a.typ, b.typ) {
		return false, false
	}
	switch regionFloatWidth(a.typ) {
	case 4:
		return math.Float32frombits(uint32(a.floatBits)) == math.Float32frombits(uint32(b.floatBits)), true
	case 8:
		return math.Float64frombits(a.floatBits) == math.Float64frombits(b.floatBits), true
	}
	return false, false
}

func regionBitViewWidth(typ types.Type) int {
	if width := regionFloatWidth(typ); width != 0 {
		return width
	}
	if typ != nil {
		if basic, ok := typ.Underlying().(*types.Basic); ok {
			switch basic.Kind() {
			case types.Int32, types.Uint32:
				return 4
			case types.Int64, types.Uint64:
				return 8
			}
		}
	}
	return 0
}

func regionBitViewTypes(storage, view types.Type) bool {
	width := regionBitViewWidth(storage)
	return width != 0 && width == regionBitViewWidth(view) && (regionFloatWidth(storage) != 0) != (regionFloatWidth(view) != 0)
}

// storageView checks an exact scalar/subobject extent using the selected owner's
// layout rules. It grants no numeric address, allocation event or native mapping.
// Liveness must additionally come from the current heap at an actual transfer.
func (k *regionKernel) storageView(loc regionLocation, view types.Type) (valid bool) {
	storage := k.locationType(loc)
	if regionAccessType(storage, view) {
		return true
	}
	return k.bitStorageView(loc, view)
}

// Boolean view predicates deliberately expose no partially checked layout. When
// a transfer refuses them, retain cancellation/work exhaustion as the cause.
func (k *regionKernel) storageViewError(message string) error {
	if err := k.meter.tick(); err != nil {
		return err
	}
	return regionError(message)
}

// Even the pointer-to-unsafe half of a round trip establishes selected layout.
// Ordinary named scalar pointer changes do not enter this conditional relation.
func (k *regionKernel) bitStorageView(loc regionLocation, view types.Type) (valid bool) {
	storage := k.locationType(loc)
	model := k.input.storageModel
	if !model.valid(k.input) || model.interpretation != regionIEEE754LittleEndian || k.sizes == nil || regionBitViewWidth(storage) == 0 || regionBitViewWidth(view) == 0 ||
		!regionAccessType(storage, view) && !regionBitViewTypes(storage, view) || !k.singleton(loc.object) {
		return false
	}
	// Selected types/sizes are part of the immutable source-owner premise. The
	// bounded layout walker owns its derived shape; no caller-supplied Sizes is
	// retained in a region input or proposal.
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	m := storageLayoutMeter{ctx: regionProofContext{k.meter.ctx, k.meter}}
	typ, sizes, err := m.objectType(k.input.selection, loc.object)
	if err != nil || typ == nil || sizes == nil {
		return false
	}
	root, err := m.layout(typ, sizes, 0)
	if err != nil {
		return false
	}
	n, offset := root, int64(0)
	for _, step := range loc.path {
		if k.meter.tick() != nil || step.summary || step.index < 0 {
			return false
		}
		if step.field {
			if step.index >= int64(len(n.fields)) {
				return false
			}
			offset += n.fieldOffsets[step.index]
			n = n.fields[step.index]
		} else {
			if n.element == nil || step.index >= n.count {
				return false
			}
			offset += step.index * n.stride
			n = n.element
		}
	}
	w, err := m.layout(view, sizes, 0)
	return err == nil && types.Identical(n.typ, storage) && n.size == int64(regionBitViewWidth(storage)) && w.size == n.size &&
		root.align%n.align == 0 && root.align%w.align == 0 && offset%n.align == 0 && offset%w.align == 0
}

// viewValue is used only after storageView establishes the location relation.
// It changes interpretation, never the canonical object or its owning extent.
func (k *regionKernel) viewValue(value regionValue, typ types.Type) (regionValue, bool) {
	if viewed, ok := regionViewValue(value, typ); ok {
		return viewed, true
	}
	if k.input.storageModel.interpretation != regionIEEE754LittleEndian || !k.input.storageModel.valid(k.input) || !regionBitViewTypes(value.typ, typ) {
		return regionValue{}, false
	}
	if value.kind == regionUnknown {
		return regionUnknownValue(typ), true
	}
	width := regionBitViewWidth(typ)
	bits, ok := regionScalarBits(value, width)
	if !ok {
		return regionValue{}, false
	}
	if regionFloatWidth(typ) != 0 {
		return regionValue{typ: typ, kind: regionFloat, floatBits: bits}, true
	}
	result, err := regionReferenceValue(bits, typ, width)
	return result, err == nil
}

func (k *regionKernel) readLocation(state regionState, loc regionLocation, typ types.Type) regionValue {
	if !k.storageView(loc, typ) {
		return regionUnknownValue(typ)
	}
	value := readRegionLocation(state, loc, k.locationType(loc))
	if viewed, ok := k.viewValue(value, typ); ok {
		return viewed
	}
	return regionUnknownValue(typ)
}

func regionUnsafePointerType(typ types.Type) bool {
	if typ == nil {
		return false
	}
	b, ok := typ.Underlying().(*types.Basic)
	return ok && b.Kind() == types.UnsafePointer
}

// liveView requires an actual resident object and exact path, not merely an
// allocation-shaped pointer. Unsupported aggregates and summaries cannot be
// turned into scalar storage by a cast.
func (k *regionKernel) liveView(state regionState, loc regionLocation, typ types.Type) bool {
	if !k.bitStorageView(loc, typ) {
		return false
	}
	value, exists := state.memory[loc.object]
	for _, step := range loc.path {
		if !exists || step.summary || value.kind != regionAggregate || step.index < 0 || step.index >= int64(len(value.elements)) {
			return false
		}
		value = value.elements[step.index]
	}
	return exists && types.Identical(value.typ, k.locationType(loc))
}

// Exact scalars may escape as ordinary language values. Reinterpreted pointer
// views may pass to checked source bodies, but not into unmodeled storage,
// interfaces, captures or returned pointer lifetimes.
func (k *regionKernel) escapingView(value regionValue) bool {
	if value.kind == regionUnsafePointer {
		return true
	}
	if value.kind == regionPointer {
		p, ok := value.typ.Underlying().(*types.Pointer)
		if !ok || !regionAccessType(k.locationType(value.location), p.Elem()) {
			return true
		}
	}
	for _, item := range value.elements {
		if k.escapingView(item) {
			return true
		}
	}
	return false
}
