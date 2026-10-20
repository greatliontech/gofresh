package closure

import (
	"context"
	"errors"
	"go/constant"
	"go/types"
	"math"
	"reflect"
	"slices"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

func storageFixture(t *testing.T, text string) storageRepresentation {
	t.Helper()
	source := computationFixture(t, text)
	source.prog.Pkgs[0].TypesSizes = types.SizesFor("gc", "amd64")
	return storageRepresentation{source: source.prog, image: correspondenceImage(t, "c3")}
}

func storageGlobal(r storageRepresentation, name string) regionObject {
	return regionObject{kind: regionGlobal, site: r.source.Prog.Package(r.source.Pkgs[0].Types).Members[name].(*ssa.Global)}
}

func storageImageBinding(object regionObject, offset int64) storageBinding {
	return storageBinding{object: object, base: nativeproof.ImageAddress(offset)}
}

func TestStorageRepresentationNestedLayoutAndPadding(t *testing.T) {
	r := storageFixture(t, `type Cell struct { B byte; X uint32 }; type Alias = Cell
		var A [2]Alias; var B uint64; var C byte
		func F() {}`)
	a, b, c := storageGlobal(r, "A"), storageGlobal(r, "B"), storageGlobal(r, "C")
	shapes := map[regionObject]*storageTypeLayout{}
	for _, object := range []regionObject{a, b, c} {
		m := storageLayoutMeter{ctx: t.Context()}
		typ, sizes, err := m.objectType(r.source, object)
		if err != nil {
			t.Fatal(err)
		}
		shapes[object], err = m.layout(typ, sizes, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		location   regionLocation
		start, end int64
	}{
		{regionLocation{object: a}, 0, 16},
		{regionLocation{object: a, path: []regionStep{{index: 1}, {field: true, index: 1}}}, 12, 16},
		{regionLocation{object: a, path: []regionStep{{index: 1}, {field: true}}}, 8, 9},
		{regionLocation{object: b}, 0, 8},
		{regionLocation{object: c}, 0, 1},
	} {
		n, offset, ok := storagePath(shapes[tc.location.object], tc.location.path)
		if !ok || offset != tc.start || offset+n.size != tc.end {
			t.Fatalf("path %+v = %+v/%d, %v", tc.location, n, offset, ok)
		}
	}
	leaves, err := storageLeaves(t.Context(), shapes[a])
	if err != nil || len(leaves) != 4 {
		t.Fatalf("leaves: %v, %v", leaves, err)
	}
	mask := make([]bool, 16)
	for _, leaf := range leaves {
		n, offset, ok := storagePath(shapes[a], leaf.path)
		if !ok || n != leaf.shape || offset != leaf.offset {
			t.Fatal("leaf does not resolve to its owning bytes")
		}
		for i := offset; i < offset+n.size; i++ {
			mask[i] = true
		}
	}
	want := []bool{true, false, false, false, true, true, true, true, true, false, false, false, true, true, true, true}
	if !slices.Equal(mask, want) {
		t.Fatalf("padding became typed bytes: %v", mask)
	}
	// Returned paths are owned; mutating one cannot alter the resolver or peers.
	leaves[0].path[0].index = 99
	again, err := storageLeaves(t.Context(), shapes[a])
	if err != nil || again[0].path[0].index != 0 || leaves[1].path[0].index != 0 {
		t.Fatal("leaf path aliases escaped")
	}
	for _, path := range [][]regionStep{
		{{summary: true}}, {{index: -1}}, {{index: 2}}, {{field: true}},
		{{index: 0}, {field: true, index: 2}}, {{index: 0}, {index: 0}},
	} {
		if _, _, ok := storagePath(shapes[a], path); ok {
			t.Fatalf("invalid/unknown path accepted: %+v", path)
		}
	}
}

func TestStorageSelectedLayoutsAndWidths(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			sizes := types.SizesFor("gc", arch)
			for _, kind := range []types.BasicKind{types.Bool, types.Uint8, types.Int8, types.Uint16, types.Int16, types.Uint32, types.Int32, types.Uint64, types.Int64, types.Uint, types.Int, types.Uintptr, types.Float32, types.Float64} {
				m := storageLayoutMeter{ctx: t.Context()}
				shape, err := m.layout(types.Typ[kind], sizes, 0)
				if err != nil || shape.size != sizes.Sizeof(types.Typ[kind]) {
					t.Fatalf("%v: %+v, %v", kind, shape, err)
				}
			}
			fields := []*types.Var{types.NewField(0, nil, "B", types.Typ[types.Byte], false), types.NewField(0, nil, "X", types.Typ[types.Uint], false)}
			m := storageLayoutMeter{ctx: t.Context()}
			n, err := m.layout(types.NewStruct(fields, nil), sizes, 0)
			word := int64(8)
			if arch == "386" {
				word = 4
			}
			if err != nil || n.fieldOffsets[1] != word || n.size != word*2 {
				t.Fatalf("host layout leaked into %s: %+v, %v", arch, n, err)
			}
		})
	}
	// StdSizes leaves struct tail padding to an array's stride. The resolver
	// must not multiply the unrounded element size to find the second element.
	sizes := &types.StdSizes{WordSize: 8, MaxAlign: 8}
	fields := []*types.Var{types.NewField(0, nil, "X", types.Typ[types.Uint32], false), types.NewField(0, nil, "B", types.Typ[types.Byte], false)}
	typ := types.NewArray(types.NewStruct(fields, nil), 2)
	m := storageLayoutMeter{ctx: t.Context()}
	n, err := m.layout(typ, sizes, 0)
	if err != nil || n.element.size != 5 || n.stride != 8 || n.size != 13 {
		t.Fatalf("selected padded stride: %+v, %v", n, err)
	}
}

func TestStorageRepresentationRefusals(t *testing.T) {
	image, bound := storageGeometryFixture(t, 0)
	for _, name := range []string{"duplicate", "overlap", "negative-image", "canonical-overflow", "misalignment", "foreign", "wrong-space", "missing-sizes", "pointer32", "bindings-budget", "protected-partial", "protected-enclosing", "invalid-protected"} {
		t.Run(name, func(t *testing.T) {
			r := storageFixture(t, `var A uint64; var B uint64; func F() {}`)
			r.image = image
			a, b := storageGlobal(r, "A"), storageGlobal(r, "B")
			r.bindings = []storageBinding{storageImageBinding(a, 0x1000), storageImageBinding(b, 0x2000)}
			var protected []storageFootprint
			switch name {
			case "duplicate":
				r.bindings[1].object = a
			case "overlap":
				r.bindings[1].base = nativeproof.ImageAddress(0x1000)
			case "negative-image":
				r.bindings[0].base = nativeproof.ImageAddress(-8)
			case "canonical-overflow":
				r.bindings[0].base = nativeproof.ImageAddress(1 << 47)
			case "misalignment":
				r.bindings[0].base = nativeproof.ImageAddress(0x1001)
			case "foreign":
				other := storageFixture(t, `var A uint64; func F() {}`)
				r.bindings[0].object = storageGlobal(other, "A")
			case "wrong-space":
				r.bindings[0].base = nativeproof.StackOffset(0x1000)
			case "missing-sizes":
				r.source.Pkgs[0].TypesSizes = nil
			case "pointer32":
				r.source.Pkgs[0].TypesSizes = types.SizesFor("gc", "386")
			case "bindings-budget":
				r.bindings = make([]storageBinding, storageMaxBindings+1)
			case "protected-partial":
				protected = []storageFootprint{{Bytes: storageTestExtent(t, bound.Geometry, nativeproof.ImageAddress(0xfff), 2)}}
			case "protected-enclosing":
				protected = []storageFootprint{{Bytes: storageTestExtent(t, bound.Geometry, nativeproof.ImageAddress(0xfff), 0x1009)}}
			case "invalid-protected":
				protected = []storageFootprint{{}}
			}
			if got, err := resolveStorageRepresentation(t.Context(), r, bound.Geometry, protected); err == nil || got != nil {
				t.Fatalf("bad representation accepted: %+v, %v", got, err)
			}
		})
	}
}

func TestStorageOriginRelativeAndWholeAccess(t *testing.T) {
	r := storageFixture(t, `var A uint64; func F() *uint64 { return new(uint64) }`)
	image, bound := storageGeometryFixture(t, 0)
	r.image = image
	var alloc *ssa.Alloc
	root := r.source.Roots["F"]
	for _, block := range root.Blocks {
		for _, ins := range block.Instrs {
			if a, ok := ins.(*ssa.Alloc); ok {
				alloc = a
			}
		}
	}
	if alloc == nil {
		t.Fatal("fixture lacks an actual allocation")
	}
	a := storageGlobal(r, "A")
	local := regionObject{kind: regionAllocation, site: alloc, context: root}
	// Equal offsets in the two coordinate spaces do not constitute aliasing.
	// This checks layout only: even an escaping Alloc does not obtain lifetime,
	// singleton, origin provenance, or correspondence authority here.
	r.bindings = []storageBinding{storageImageBinding(a, 16), {object: local, base: nativeproof.StackOffset(16)}}
	protected := []storageFootprint{{Bytes: storageTestExtent(t, bound.Geometry, nativeproof.StackOffset(0), 8)}, {Bytes: storageTestExtent(t, bound.Geometry, nativeproof.StackOffset(-24), 8)}}
	layout, err := resolveStorageRepresentation(t.Context(), r, bound.Geometry, protected)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		start, end int64
		class      storageAccessClass
	}{
		{16, 24, storageInside}, {17, 18, storageInside}, {15, 17, storagePartial},
		{23, 25, storagePartial}, {0, 32, storagePartial}, {8, 16, storageDisjoint},
		{24, 32, storageDisjoint}, {16, 16, storagePartial},
	} {
		for _, image := range []bool{true, false} {
			var f storageFootprint
			if tc.start < tc.end {
				f.Bytes = storageTestExtent(t, bound.Geometry, storageTestSelector(image, tc.start), tc.end-tc.start)
			}
			if got := layout.classifyAccess(f); got != tc.class {
				t.Fatalf("classification %+v = %v, want %v", f, got, tc.class)
			}
		}
	}
	for _, image := range []bool{true, false} {
		for _, off := range []int64{15, 16, 23, 24} {
			if got := layout.representedByte(storageTestLocation(t, bound.Geometry, storageTestSelector(image, off))); got != (off >= 16 && off < 24) {
				t.Fatalf("byte membership %v:%d = %v", image, off, got)
			}
		}
	}
	for _, offset := range []int64{0, -24, math.MaxInt64 - 7} {
		r.bindings[1].base = nativeproof.StackOffset(offset)
		if got, err := resolveStorageRepresentation(t.Context(), r, bound.Geometry, protected); err == nil || got != nil {
			t.Fatalf("control/overflow slot accepted: %d", offset)
		}
	}
	// A private-frame local away from the actual control slots is permitted.
	r.bindings[1].base = nativeproof.StackOffset(-16)
	if _, err := resolveStorageRepresentation(t.Context(), r, bound.Geometry, protected); err != nil {
		t.Fatal(err)
	}
	t.Run("candidate-alignment", func(t *testing.T) {
		candidate := r
		candidate.bindings = slices.Clone(r.bindings)
		candidate.bindings[1].base = nativeproof.StackOffset(4)
		// S+4 is aligned only under this authentic root's S%8=4 domain.
		image, aligned := storageGeometryFixture(t, 4)
		candidate.image = image
		resolved, err := resolveStorageRepresentation(t.Context(), candidate, aligned.Geometry, nil)
		if err != nil {
			t.Fatalf("relative offset mistaken for absolute alignment: %v", err)
		}
		f, ok := resolved.objectFootprint(local)
		if !ok || f.Bytes != storageTestExtent(t, aligned.Geometry, nativeproof.StackOffset(4), 8) {
			t.Fatalf("relative candidate footprint = %+v, %v", f, ok)
		}
		// The same offset is an unaligned absolute image address: accepting
		// relative candidates must not remove this independent image check.
		candidate.bindings[0].base = nativeproof.ImageAddress(4)
		if got, err := resolveStorageRepresentation(t.Context(), candidate, aligned.Geometry, nil); err == nil || got != nil {
			t.Fatalf("unaligned image candidate accepted: %+v, %v", got, err)
		}
	})
	foreign := storageFixture(t, `func F() *uint64 { return new(uint64) }`)
	for _, object := range []regionObject{
		{kind: regionAllocation, site: alloc},
		{kind: regionAllocation, site: alloc, context: foreign.source.Roots["F"]},
		{kind: regionAllocation, site: a.site, context: root},
		{kind: regionFormal, site: alloc, context: root},
	} {
		r.bindings[1].object = object
		if _, err := resolveStorageRepresentation(t.Context(), r, bound.Geometry, protected); err == nil {
			t.Fatalf("unowned or unsupported local accepted: %+v", object)
		}
	}
}

type storageCallbackContext struct {
	context.Context
	callback  func()
	remaining int
}

func (c *storageCallbackContext) Err() error {
	if c.remaining > 0 {
		c.remaining--
	} else if c.callback != nil {
		callback := c.callback
		c.callback = nil
		callback()
	}
	return c.Context.Err()
}

func TestStorageFreezeAndCancellation(t *testing.T) {
	r := storageFixture(t, `var A uint64; var B uint64; func F() {}`)
	ownedImage, bound := storageGeometryFixture(t, 0)
	r.image = ownedImage
	a := storageGlobal(r, "A")
	r.bindings = []storageBinding{storageImageBinding(a, 0x1000), storageImageBinding(storageGlobal(r, "B"), 0x3000)}
	image := *r.image
	protected := []storageFootprint{{Bytes: storageTestExtent(t, bound.Geometry, nativeproof.ImageAddress(0x2000), 8)}}
	replacement := storageTestExtent(t, bound.Geometry, nativeproof.ImageAddress(0x1000), 8)
	ctx := &storageCallbackContext{Context: t.Context(), callback: func() {
		r.bindings[0].base = nativeproof.ImageAddress(0x2000)
		r.bindings[1].base = nativeproof.ImageAddress(0x1000)
		*r.image = nativeproof.Image{}
		protected[0].Bytes = replacement
	}}
	layout, err := resolveStorageRepresentation(ctx, r, bound.Geometry, protected)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := layout.objectFootprint(a)
	if !ok || f.Bytes != replacement || layout.representation.bindings[0].base != nativeproof.ImageAddress(0x1000) || !reflect.DeepEqual(*layout.representation.image, image) {
		t.Fatal("callback replaced captured representation")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := resolveStorageRepresentation(canceled, r, bound.Geometry, nil); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("cancellation = %+v, %v", got, err)
	}
	if leaves, err := layout.typedLeaves(canceled, a); !errors.Is(err, context.Canceled) || leaves != nil {
		t.Fatalf("leaf cancellation = %v, %v", leaves, err)
	}
	midway, stop := context.WithCancel(t.Context())
	defer stop()
	ctx = &storageCallbackContext{Context: midway, remaining: 3, callback: stop}
	if got, err := resolveStorageRepresentation(ctx, layout.representation, bound.Geometry, nil); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("mid-resolution cancellation = %+v, %v", got, err)
	}
	called := false
	r.bindings = make([]storageBinding, storageMaxBindings+1)
	ctx.callback = func() { called = true }
	if _, err := resolveStorageRepresentation(ctx, r, bound.Geometry, nil); err == nil || called {
		t.Fatal("container bound was not checked before callback/copy")
	}
}

type storageBadSizes struct {
	types.Sizes
	size, align int64
}

func (s storageBadSizes) Sizeof(types.Type) int64  { return s.size }
func (s storageBadSizes) Alignof(types.Type) int64 { return s.align }

func TestStorageLayoutBounds(t *testing.T) {
	sizes := types.SizesFor("gc", "amd64")
	deep := types.Type(types.Typ[types.Byte])
	for range storageMaxDepth {
		deep = types.NewArray(deep, 1)
	}
	for _, typ := range []types.Type{
		types.NewArray(types.Typ[types.Uint64], math.MaxInt64),
		types.NewArray(types.Typ[types.Uint64], storageMaxBytes),
		types.NewArray(types.Typ[types.Byte], 0), types.NewStruct(nil, nil),
		types.NewArray(types.NewStruct(nil, nil), math.MaxInt64), deep,
		types.Typ[types.String], types.NewPointer(types.Typ[types.Int]),
	} {
		m := storageLayoutMeter{ctx: t.Context()}
		if got, err := m.layout(typ, sizes, 0); err == nil || got != nil {
			t.Fatalf("unbounded/unsupported type accepted: %v", typ)
		}
	}
	for _, bad := range []storageBadSizes{{sizes, -1, 8}, {sizes, 8, 0}, {sizes, 8, -1}, {sizes, 8, 3}, {sizes, math.MaxInt64, 8}} {
		m := storageLayoutMeter{ctx: t.Context()}
		if got, err := m.layout(types.Typ[types.Uint64], bad, 0); err == nil || got != nil {
			t.Fatalf("invalid selected sizes accepted: %+v", bad)
		}
	}
	m := storageLayoutMeter{ctx: t.Context(), work: storageMaxWork}
	if _, err := m.layout(types.Typ[types.Byte], sizes, 0); err == nil {
		t.Fatal("work budget ignored")
	}
	budget := storageLayoutMeter{ctx: t.Context()}
	array, err := budget.layout(types.NewArray(types.Typ[types.Byte], storageMaxBytes), sizes, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := budget.reserveBytes(array.size); err != nil {
		t.Fatal(err)
	}
	if err := budget.reserveBytes(1); err == nil {
		t.Fatal("combined live byte budget ignored")
	}
}

func TestStorageScalarProjection(t *testing.T) {
	for _, tc := range []struct {
		kind  types.BasicKind
		value constant.Value
		want  uint64
		width int
		ok    bool
	}{
		{types.Int8, constant.MakeInt64(-1), 255, 1, true},
		{types.Int16, constant.MakeInt64(-32768), 32768, 2, true},
		{types.Int32, constant.MakeInt64(-2), 0xfffffffe, 4, true},
		{types.Int64, constant.MakeInt64(math.MinInt64), 1 << 63, 8, true},
		{types.Uint64, constant.MakeUint64(math.MaxUint64), math.MaxUint64, 8, true},
		{types.Uint8, constant.MakeInt64(1), 1, 1, true},
		{types.Uint16, constant.MakeInt64(65535), 65535, 2, true},
		{types.Uint32, constant.MakeInt64(0xfedcba98), 0xfedcba98, 4, true},
		{types.Bool, constant.MakeBool(true), 1, 1, true},
		{types.Bool, constant.MakeBool(false), 0, 1, true},
		{types.Uint8, constant.MakeInt64(256), 0, 0, false},
		{types.Uint8, constant.MakeInt64(-1), 0, 0, false},
		{types.Int8, constant.MakeInt64(128), 0, 0, false},
		{types.Int8, constant.MakeInt64(-129), 0, 0, false},
		{types.Float64, constant.MakeFloat64(1), 0, 0, false},
		{types.Bool, constant.MakeInt64(1), 0, 0, false},
	} {
		v := regionValue{kind: regionConstant, typ: types.Typ[tc.kind], scalar: tc.value}
		got, width, ok := storageScalarBits(v, types.SizesFor("gc", "amd64"))
		if got != tc.want || width != tc.width || ok != tc.ok {
			t.Fatalf("%v %v: %x/%d/%v, want %x/%d/%v", v.typ, v.scalar, got, width, ok, tc.want, tc.width, tc.ok)
		}
	}
	for _, kind := range []types.BasicKind{types.Int, types.Uint, types.Uintptr} {
		v := regionValue{kind: regionConstant, typ: types.Typ[kind], scalar: constant.MakeInt64(1)}
		for _, arch := range []string{"386", "amd64"} {
			sizes := types.SizesFor("gc", arch)
			if got, width, ok := storageScalarBits(v, sizes); !ok || got != 1 || int64(width) != sizes.Sizeof(v.typ) {
				t.Fatalf("selected scalar width %s/%v = %d", arch, v.typ, width)
			}
		}
	}
	if _, _, ok := storageScalarBits(regionValue{kind: regionUnknown, typ: types.Typ[types.Uint64]}, types.SizesFor("gc", "amd64")); ok {
		t.Fatal("unknown became initialized bits")
	}
	for _, tc := range []struct {
		kind types.BasicKind
		bits uint64
	}{
		{types.Float32, 0}, {types.Float32, 1 << 31}, {types.Float32, 0xffffffff},
		{types.Float64, 0}, {types.Float64, 1 << 63}, {types.Float64, 0xffffffffffffffff},
	} {
		value := regionValue{kind: regionFloat, typ: types.Typ[tc.kind], floatBits: tc.bits}
		for _, arch := range []string{"386", "amd64"} {
			sizes := types.SizesFor("gc", arch)
			bits, width, exact := storageScalarBits(value, sizes)
			if !exact || bits != tc.bits || int64(width) != sizes.Sizeof(value.typ) {
				t.Fatalf("float bit projection changed payload or selected extent: %s/%v %x/%d/%v", arch, value.typ, bits, width, exact)
			}
		}
	}
	for _, value := range []regionValue{
		{kind: regionFloat, typ: types.Typ[types.Float32], floatBits: 1 << 32},
		{kind: regionFloat, typ: types.Typ[types.Uint64], floatBits: 1},
		{kind: regionUnknown, typ: types.Typ[types.Float64]},
	} {
		if _, _, exact := storageScalarBits(value, types.SizesFor("gc", "amd64")); exact {
			t.Fatal("invalid float representation acquired exact storage bits")
		}
	}
}

func TestStorageNativeLittleEndianProjection(t *testing.T) {
	_, bound := storageGeometryFixture(t, 0)
	extent := storageTestExtent(t, bound.Geometry, nativeproof.StackOffset(16), 8)
	b := br.NewBuilder(4096)
	memory := make([]nativeproof.TransitionByte, 0, 16)
	for lane := range 8 {
		value, _ := b.Const(br.Bits(8), uint64(lane+1))
		other, _ := b.Const(br.Bits(8), 255)
		memory = append(memory, nativeproof.TransitionByte{TransitionLocation: storageTestLocation(t, bound.Geometry, nativeproof.StackOffset(16+lane)), Value: value})
		memory = append(memory, nativeproof.TransitionByte{TransitionLocation: storageTestLocation(t, bound.Geometry, nativeproof.ImageAddress(16+lane)), Value: other})
	}
	for width := 1; width <= 8; width++ {
		part, _ := extent.Subextent(0, int64(width))
		got, err := storageNativeWord(t.Context(), b, memory, part, width)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := b.Const(br.Bits(width*8), uint64(0x0807060504030201)&(math.MaxUint64>>uint(64-width*8)))
		if _, err := br.Prove(t.Context(), got, want, br.Limits{}); err != nil {
			t.Fatalf("little-endian width %d: %v", width, err)
		}
	}
	for _, changed := range [][]nativeproof.TransitionByte{memory[2:], append(slices.Clone(memory), memory[0])} {
		if _, err := storageNativeWord(t.Context(), b, changed, extent, 8); err == nil {
			t.Fatal("missing/duplicate bytes accepted")
		}
	}
	owned := slices.Clone(memory)
	ctx := &storageCallbackContext{Context: t.Context(), callback: func() { owned[0].Value = br.Term{} }}
	if _, err := storageNativeWord(ctx, b, owned, extent, 8); err != nil {
		t.Fatalf("callback replaced native projection: %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := storageNativeWord(canceled, b, memory, extent, 8); !errors.Is(err, context.Canceled) {
		t.Fatalf("native byte cancellation: %v", err)
	}
}
