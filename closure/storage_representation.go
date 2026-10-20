package closure

import (
	"context"
	"fmt"
	"go/types"
	"math"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

// storageRepresentation is a proposal, not placement or allocation evidence.
// Object types and extents have one source of truth: the selected SSA owner.
type storageRepresentation struct {
	source   *program
	image    *nativeproof.Image
	bindings []storageBinding
}

type storageBinding struct {
	object regionObject
	base   nativeproof.TransitionLocation
}

type storageFootprint struct {
	Image bool
	Bytes nativeproof.RelativeSpan
}

type storageAccessClass uint8

const (
	storageDisjoint storageAccessClass = iota
	storageInside
	storagePartial
)

// storageLayout resolves a frozen candidate's coordinates, not its ownership.
// Before using these coordinates as correspondence evidence, the consumer checks
// the actual opaque source endpoints (including allocation instance, singleton,
// lifetime and nonescape facts), image owner, declared mapped memory and retained
// stack origin, including alignment of origin plus offset. Relative offsets need
// not themselves be aligned. Successful layout never initializes native bytes.
type storageLayout struct {
	representation storageRepresentation
	objects        map[regionObject]storageObjectLayout
}

type storageObjectLayout struct {
	base  nativeproof.TransitionLocation
	shape *storageTypeLayout
}

// The derived layout retains padding as gaps between leaves, never as zero bits.
// A leaf's layout supplies no initial bytes or storage-model applicability.
type storageTypeLayout struct {
	typ          types.Type
	size, align  int64
	stride       int64
	count        int64
	element      *storageTypeLayout
	fields       []*storageTypeLayout
	fieldOffsets []int64
}

type storageLeaf struct {
	location  regionLocation
	typ       types.Type
	footprint storageFootprint
}

const (
	storageMaxBindings = 4096
	storageMaxBytes    = 1 << 20
	storageMaxNodes    = 65536
	storageMaxDepth    = 64
	storageMaxWork     = 200000
)

type storageLayoutMeter struct {
	ctx         context.Context
	work, nodes int
}

func (m *storageLayoutMeter) tick() error {
	if m.ctx == nil {
		return fmt.Errorf("storage layout: missing context")
	}
	if err := m.ctx.Err(); err != nil {
		return err
	}
	m.work++
	if m.work > storageMaxWork {
		return fmt.Errorf("storage layout: work budget exhausted")
	}
	return nil
}

// resolveStorageRepresentation checks structural ownership and selected layout.
// It deliberately returns a candidate resolver, not a checked correspondence.
// Only image coordinates establish absolute alignment here. Stack alignment is
// checked by the authority consumer against its retained native origin domain.
// protected must include every actual control slot throughout the composition;
// a private frame is not itself protected, since represented locals may live in it.
func resolveStorageRepresentation(ctx context.Context, proposal storageRepresentation, protected []storageFootprint) (_ *storageLayout, err error) {
	if ctx == nil || proposal.source == nil || proposal.source.Prog == nil || proposal.image == nil || len(proposal.bindings) > storageMaxBindings || len(protected) > storageMaxBindings {
		return nil, fmt.Errorf("storage layout: missing owner or container budget exceeded")
	}
	// Image backing arrays are immutable and private to nativeproof. Freeze both
	// public containers before the first context callback can replace either.
	image := *proposal.image
	proposal.image = &image
	proposal.bindings = slices.Clone(proposal.bindings)
	protected = slices.Clone(protected)
	m := storageLayoutMeter{ctx: ctx}
	result := &storageLayout{representation: proposal, objects: make(map[regionObject]storageObjectLayout, len(proposal.bindings))}
	spans := make([]storageFootprint, 0, len(proposal.bindings))
	var bytes int64
	// Malformed selected sizes may panic rather than return a negative size.
	// Such a selection supplies no usable representation.
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("storage layout: invalid selected type layout")
		}
	}()
	for _, p := range protected {
		if !p.valid() {
			return nil, fmt.Errorf("storage layout: invalid protected extent")
		}
	}
	for _, binding := range proposal.bindings {
		if err := m.tick(); err != nil {
			return nil, err
		}
		if _, duplicate := result.objects[binding.object]; duplicate {
			return nil, fmt.Errorf("storage layout: duplicate object")
		}
		typ, sizes, err := m.objectType(proposal.source, binding.object)
		if err != nil {
			return nil, err
		}
		if typ == nil || sizes == nil || sizes.Sizeof(types.NewPointer(typ)) != 8 {
			return nil, fmt.Errorf("storage layout: unowned object or unsupported pointer width")
		}
		if binding.base.Image != (binding.object.kind == regionGlobal) {
			return nil, fmt.Errorf("storage layout: globals require image and allocations require origin-relative storage")
		}
		shape, err := m.layout(typ, sizes, 0)
		if err != nil {
			return nil, err
		}
		if shape.size > storageMaxBytes-bytes {
			return nil, fmt.Errorf("storage layout: live byte budget exceeded")
		}
		bytes += shape.size
		span, ok := storageSpan(binding.base, shape.size)
		if !ok || binding.base.Image && binding.base.Offset%shape.align != 0 {
			return nil, fmt.Errorf("storage layout: invalid or misaligned extent")
		}
		for _, p := range protected {
			if err := m.tick(); err != nil {
				return nil, err
			}
			if span.overlaps(p) {
				return nil, fmt.Errorf("storage layout: represented object overlaps protected control storage")
			}
		}
		result.objects[binding.object] = storageObjectLayout{base: binding.base, shape: shape}
		spans = append(spans, span)
	}
	// All bindings conservatively remain live for the entire composition. Sorting
	// checks disjointness without a quadratic pairwise object walk.
	slices.SortFunc(spans, func(a, b storageFootprint) int {
		if a.Image != b.Image {
			if a.Image {
				return 1
			}
			return -1
		}
		if a.Bytes.Start < b.Bytes.Start {
			return -1
		}
		if a.Bytes.Start > b.Bytes.Start {
			return 1
		}
		return 0
	})
	for i := 1; i < len(spans); i++ {
		if err := m.tick(); err != nil {
			return nil, err
		}
		if spans[i-1].overlaps(spans[i]) {
			return nil, fmt.Errorf("storage layout: overlapping live objects")
		}
	}
	if err := m.tick(); err != nil {
		return nil, err
	}
	return result, nil
}

// Reuse the region kernel's canonical object-type rule. This checks SSA owner
// membership only; an Alloc instruction is not proof of a fresh dynamic instance.
func (m *storageLayoutMeter) objectType(source *program, object regionObject) (types.Type, types.Sizes, error) {
	if source == nil || source.Prog == nil || object.kind != regionGlobal && object.kind != regionAllocation {
		return nil, nil, nil
	}
	// Canonical membership uses linear instruction/block scans. Charge their
	// lengths before entering that rule so an enormous owned body cannot bypass
	// the resolver's work bound or postpone cancellation without limit.
	if a, ok := object.site.(*ssa.Alloc); ok && a != nil && a.Block() != nil && object.context != nil {
		for _, count := range []int{len(a.Block().Instrs), len(object.context.Blocks)} {
			if count > storageMaxWork-m.work {
				return nil, nil, fmt.Errorf("storage layout: owner work budget exhausted")
			}
			m.work += count
		}
	}
	k := regionKernel{input: regionInput{owner: source.Prog}}
	typ := k.objectType(object)
	if typ == nil {
		return nil, nil, nil
	}
	var pkg *types.Package
	if g, ok := object.site.(*ssa.Global); ok {
		pkg = g.Pkg.Pkg
	} else {
		a := object.site.(*ssa.Alloc)
		if object.context.Pkg == nil || source.Prog.Package(object.context.Pkg.Pkg) != object.context.Pkg || !slices.Contains(object.context.Blocks, a.Block()) {
			return nil, nil, nil
		}
		pkg = object.context.Pkg.Pkg
	}
	var sizes types.Sizes
	for _, p := range source.Pkgs {
		if err := m.tick(); err != nil {
			return nil, nil, err
		}
		if p != nil && p.Types == pkg {
			if sizes != nil || p.TypesSizes == nil {
				return nil, nil, nil
			}
			sizes = p.TypesSizes
		}
	}
	return typ, sizes, nil
}

func (m *storageLayoutMeter) layout(typ types.Type, sizes types.Sizes, depth int) (*storageTypeLayout, error) {
	if err := m.tick(); err != nil {
		return nil, err
	}
	m.nodes++
	if typ == nil || sizes == nil || depth >= storageMaxDepth || m.nodes > storageMaxNodes {
		return nil, fmt.Errorf("storage layout: type depth or node budget exceeded")
	}
	n := &storageTypeLayout{typ: typ}
	// Descend before calling Sizeof/Alignof: go/types itself has no depth or
	// work limit. Reject enormous arrays/structs before allocating their layout.
	switch t := typ.Underlying().(type) {
	case *types.Basic:
		if t.Info()&types.IsUntyped != 0 || t.Info()&(types.IsBoolean|types.IsInteger|types.IsFloat) == 0 {
			return nil, fmt.Errorf("storage layout: unsupported scalar storage")
		}
	case *types.Array:
		if t.Len() <= 0 || t.Len() > storageMaxBytes {
			return nil, fmt.Errorf("storage layout: empty or oversized array")
		}
		var err error
		n.element, err = m.layout(t.Elem(), sizes, depth+1)
		if err != nil {
			return nil, err
		}
		n.count = t.Len()
		// Array stride rounds the selected element size to selected alignment;
		// using Sizeof(element) alone fails for padded custom selected layouts.
		n.stride = n.element.size
		if rem := n.stride % n.element.align; rem != 0 {
			n.stride += n.element.align - rem
		}
		if n.stride > storageMaxBytes/n.count {
			return nil, fmt.Errorf("storage layout: array extent budget exceeded")
		}
	case *types.Struct:
		if t.NumFields() == 0 || t.NumFields() > storageMaxNodes-m.nodes {
			return nil, fmt.Errorf("storage layout: empty struct or field budget exceeded")
		}
		fields := make([]*types.Var, t.NumFields())
		n.fields = make([]*storageTypeLayout, t.NumFields())
		for i := range fields {
			fields[i] = t.Field(i)
			var err error
			n.fields[i], err = m.layout(fields[i].Type(), sizes, depth+1)
			if err != nil {
				return nil, err
			}
		}
		n.fieldOffsets = sizes.Offsetsof(fields)
		if len(n.fieldOffsets) != len(fields) {
			return nil, fmt.Errorf("storage layout: invalid field offsets")
		}
	default:
		return nil, fmt.Errorf("storage layout: unsupported storage type")
	}
	n.size, n.align = sizes.Sizeof(typ), sizes.Alignof(typ)
	if n.size <= 0 || n.size > storageMaxBytes || n.align <= 0 || n.align > storageMaxBytes || n.align&(n.align-1) != 0 {
		return nil, fmt.Errorf("storage layout: invalid size or alignment")
	}
	if n.element != nil && (n.count-1)*n.stride+n.element.size > n.size {
		return nil, fmt.Errorf("storage layout: elements exceed array extent")
	}
	var end int64
	for i, field := range n.fields {
		offset := n.fieldOffsets[i]
		if offset < end || offset%field.align != 0 || field.size > n.size || offset > n.size-field.size {
			return nil, fmt.Errorf("storage layout: invalid field extent")
		}
		end = offset + field.size
	}
	if n.element == nil && n.fields == nil && (n.size > 8 || n.size != 1 && n.size != 2 && n.size != 4 && n.size != 8) {
		return nil, fmt.Errorf("storage layout: unsupported scalar width")
	}
	return n, nil
}

func storageSpan(base nativeproof.TransitionLocation, width int64) (storageFootprint, bool) {
	if width <= 0 || base.Offset > math.MaxInt64-width {
		return storageFootprint{}, false
	}
	f := storageFootprint{Image: base.Image, Bytes: nativeproof.RelativeSpan{Start: base.Offset, End: base.Offset + width}}
	return f, f.valid()
}

func (f storageFootprint) valid() bool {
	return f.Bytes.Start < f.Bytes.End && (!f.Image || f.Bytes.Start >= 0 && f.Bytes.End <= 1<<47)
}

func (f storageFootprint) overlaps(g storageFootprint) bool {
	return f.Image == g.Image && f.Bytes.Start < g.Bytes.End && g.Bytes.Start < f.Bytes.End
}

func (r *storageLayout) objectFootprint(object regionObject) (storageFootprint, bool) {
	if r == nil {
		return storageFootprint{}, false
	}
	o, ok := r.objects[object]
	if !ok {
		return storageFootprint{}, false
	}
	return storageSpan(o.base, o.shape.size)
}

func (r *storageLayout) locationFootprint(location regionLocation) (storageFootprint, bool) {
	if r == nil || len(location.path) >= storageMaxDepth {
		return storageFootprint{}, false
	}
	o, ok := r.objects[location.object]
	if !ok {
		return storageFootprint{}, false
	}
	n, offset := o.shape, int64(0)
	for _, step := range location.path {
		if step.summary || step.index < 0 {
			return storageFootprint{}, false
		}
		if step.field {
			if step.index >= int64(len(n.fields)) {
				return storageFootprint{}, false
			}
			offset += n.fieldOffsets[step.index]
			n = n.fields[step.index]
		} else {
			if n.element == nil || step.index >= n.count {
				return storageFootprint{}, false
			}
			offset += step.index * n.stride
			n = n.element
		}
	}
	o.base.Offset += offset // bounded by the already checked owning extent
	return storageSpan(o.base, n.size)
}

// classifyAccess considers the full access, including padding and intersections
// that begin outside an object. An access spanning several objects is partial.
// Invalid accesses also refuse the disjoint/administrative classification.
func (r *storageLayout) classifyAccess(access storageFootprint) storageAccessClass {
	if r == nil || !access.valid() {
		return storagePartial
	}
	for object := range r.objects {
		f, _ := r.objectFootprint(object)
		if f.overlaps(access) {
			if f.Bytes.Start <= access.Bytes.Start && access.Bytes.End <= f.Bytes.End {
				return storageInside
			}
			return storagePartial
		}
	}
	return storageDisjoint
}

func (r *storageLayout) representedByte(location nativeproof.TransitionLocation) bool {
	f, ok := storageSpan(location, 1)
	return ok && r.classifyAccess(f) == storageInside
}

// typedLeaves returns owned paths and typed scalar footprints. The complement
// inside objectFootprint is padding with unknown bytes, not implicit zeros.
func (r *storageLayout) typedLeaves(ctx context.Context, object regionObject) ([]storageLeaf, error) {
	if r == nil {
		return nil, fmt.Errorf("storage layout: missing resolver")
	}
	o, ok := r.objects[object]
	if !ok {
		return nil, fmt.Errorf("storage layout: unrepresented object")
	}
	m := storageLayoutMeter{ctx: ctx}
	var leaves []storageLeaf
	var walk func(*storageTypeLayout, int64, []regionStep) error
	walk = func(n *storageTypeLayout, offset int64, path []regionStep) error {
		if err := m.tick(); err != nil {
			return err
		}
		if n.element != nil {
			for i := int64(0); i < n.count; i++ {
				if err := walk(n.element, offset+i*n.stride, append(path, regionStep{index: i})); err != nil {
					return err
				}
			}
		} else if n.fields != nil {
			for i, field := range n.fields {
				if err := walk(field, offset+n.fieldOffsets[i], append(path, regionStep{field: true, index: int64(i)})); err != nil {
					return err
				}
			}
		} else {
			if len(leaves) >= storageMaxNodes {
				return fmt.Errorf("storage layout: leaf budget exceeded")
			}
			base := o.base
			base.Offset += offset
			f, _ := storageSpan(base, n.size)
			leaves = append(leaves, storageLeaf{location: regionLocation{object: object, path: slices.Clone(path)}, typ: n.typ, footprint: f})
		}
		return nil
	}
	if err := walk(o.shape, 0, nil); err != nil {
		return nil, err
	}
	return leaves, nil
}

// storageScalarBits projects a known typed value to its selected little-endian
// storage bits. Boolean values use a byte containing 0 or 1, not arbitrary bits
// of a logical one-bit sort. Negative integers use their width's two's complement.
// Float bits use the conditional IEEE model retained by the source proof; this
// projection does not discharge its selected-implementation applicability.
func storageScalarBits(value regionValue, sizes types.Sizes) (uint64, int, bool) {
	if sizes == nil || value.typ == nil {
		return 0, 0, false
	}
	t, ok := value.typ.Underlying().(*types.Basic)
	if !ok || t.Info()&types.IsUntyped != 0 {
		return 0, 0, false
	}
	width := sizes.Sizeof(value.typ)
	if width != 1 && width != 2 && width != 4 && width != 8 {
		return 0, 0, false
	}
	if t.Info()&types.IsBoolean != 0 {
		boolean, exact := regionBool(value)
		if !exact || width != 1 {
			return 0, 0, false
		}
		if boolean {
			return 1, 1, true
		}
		return 0, 1, true
	}
	result, ok := regionScalarBits(value, int(width))
	if !ok {
		return 0, 0, false
	}
	return result, int(width), true
}

// storageNativeWord reads one to eight bytes in the native little-endian model.
// Coordinates include their space: equal image and stack offsets never alias.
// The caller separately proves accessibility and source/native value equality.
func storageNativeWord(ctx context.Context, builder *br.Builder, memory []nativeproof.TransitionByte, base nativeproof.TransitionLocation, width int) (br.Term, error) {
	if ctx == nil || builder == nil || width < 1 || width > 8 || len(memory) > storageMaxBytes {
		return br.Term{}, fmt.Errorf("storage projection: invalid width or byte budget")
	}
	if _, ok := storageSpan(base, int64(width)); !ok {
		return br.Term{}, fmt.Errorf("storage projection: invalid extent")
	}
	// Do not allow a context callback to replace bytes while they are read.
	memory = slices.Clone(memory)
	var lanes [8]br.Term
	m := storageLayoutMeter{ctx: ctx}
	for _, cell := range memory {
		if err := m.tick(); err != nil {
			return br.Term{}, err
		}
		if cell.Image != base.Image || cell.Offset < base.Offset || cell.Offset >= base.Offset+int64(width) {
			continue
		}
		lane := cell.Offset - base.Offset
		if lanes[lane].Valid() || cell.Value.Sort() != br.Bits(8) {
			return br.Term{}, fmt.Errorf("storage projection: duplicate or invalid byte")
		}
		lanes[lane] = cell.Value
	}
	var word br.Term
	for i := range width {
		if err := m.tick(); err != nil {
			return br.Term{}, err
		}
		if !lanes[i].Valid() {
			return br.Term{}, fmt.Errorf("storage projection: missing byte")
		}
		if i == 0 {
			word = lanes[i]
		} else {
			var err error
			word, err = builder.Make(br.Concat, br.Bits(8*(i+1)), 0, word, lanes[i])
			if err != nil {
				return br.Term{}, err
			}
		}
	}
	return word, nil
}
