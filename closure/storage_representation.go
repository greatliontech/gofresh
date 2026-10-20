package closure

import (
	"context"
	"fmt"
	"go/types"
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
	base   nativeproof.StorageSelector
}

type storageFootprint struct {
	Bytes nativeproof.TransitionExtent
}

type storageAccessClass uint8

const (
	storageDisjoint storageAccessClass = iota
	storageInside
	storagePartial
)

// storageLayout binds a frozen proposal to canonical extents from authenticated
// native geometry. It checks mapping, alignment, overlap and control protection.
// The consumer still establishes actual source allocation instances, singleton,
// lifetime and nonescape facts. Successful layout never initializes native bytes.
type storageLayout struct {
	representation storageRepresentation
	geometry       nativeproof.ActualTransitionGeometry
	objects        map[regionObject]storageObjectLayout
}

type storageObjectLayout struct {
	bytes nativeproof.TransitionExtent
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
	bytes       int64
}

func (m *storageLayoutMeter) reserveBytes(size int64) error {
	if size <= 0 || size > storageMaxBytes-m.bytes {
		return fmt.Errorf("storage layout: live byte budget exceeded")
	}
	m.bytes += size
	return nil
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

// resolveStorageRepresentation checks selected layout against native geometry
// obtained from the exact certificate's BoundFor projection. A resolved layout
// supplies neither source lifetime evidence nor checked correspondence.
// protected must include every actual control slot throughout the composition;
// a private frame is not itself protected, since represented locals may live in it.
func resolveStorageRepresentation(ctx context.Context, proposal storageRepresentation, geometry nativeproof.ActualTransitionGeometry, protected []storageFootprint) (_ *storageLayout, err error) {
	if ctx == nil || geometry == (nativeproof.ActualTransitionGeometry{}) || proposal.source == nil || proposal.source.Prog == nil || proposal.image == nil || len(proposal.bindings) > storageMaxBindings || len(protected) > storageMaxBindings {
		return nil, fmt.Errorf("storage layout: missing owner or container budget exceeded")
	}
	// Image backing arrays are immutable and private to nativeproof. Freeze both
	// public containers before the first context callback can replace either.
	image := *proposal.image
	proposal.image = &image
	proposal.bindings = slices.Clone(proposal.bindings)
	protected = slices.Clone(protected)
	m := storageLayoutMeter{ctx: ctx}
	result := &storageLayout{representation: proposal, geometry: geometry, objects: make(map[regionObject]storageObjectLayout, len(proposal.bindings))}
	spans := make([]storageFootprint, 0, len(proposal.bindings))
	// Malformed selected sizes may panic rather than return a negative size.
	// Such a selection supplies no usable representation.
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("storage layout: invalid selected type layout")
		}
	}()
	for _, p := range protected {
		if valid, e := geometry.Contains(p.Bytes, p.Bytes); e != nil || !valid {
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
		_, image := binding.base.(nativeproof.ImageAddress)
		_, stack := binding.base.(nativeproof.StackOffset)
		if image != (binding.object.kind == regionGlobal) || !image && !stack {
			return nil, fmt.Errorf("storage layout: globals require image and allocations require origin-relative storage")
		}
		shape, err := m.layout(typ, sizes, 0)
		if err != nil {
			return nil, err
		}
		if err := m.reserveBytes(shape.size); err != nil {
			return nil, err
		}
		extent, e := geometry.ResolveStorage(ctx, binding.base, shape.size)
		if e != nil {
			return nil, fmt.Errorf("storage layout: invalid extent: %w", e)
		}
		aligned, e := geometry.CheckAlignment(extent, shape.align)
		if e != nil || !aligned {
			return nil, fmt.Errorf("storage layout: invalid or misaligned extent")
		}
		span := storageFootprint{Bytes: extent}
		for _, p := range protected {
			if err := m.tick(); err != nil {
				return nil, err
			}
			overlaps, e := geometry.Overlaps(span.Bytes, p.Bytes)
			if e != nil || overlaps {
				return nil, fmt.Errorf("storage layout: represented object overlaps protected control storage")
			}
		}
		result.objects[binding.object] = storageObjectLayout{bytes: extent, shape: shape}
		spans = append(spans, span)
	}
	// All bindings conservatively remain live for the entire composition. Sorting
	// checks disjointness without a quadratic pairwise object walk.
	slices.SortFunc(spans, func(a, b storageFootprint) int {
		order, _ := geometry.Compare(a.Bytes.Start(), b.Bytes.Start()) // both resolved above
		return order
	})
	for i := 1; i < len(spans); i++ {
		if err := m.tick(); err != nil {
			return nil, err
		}
		overlaps, e := geometry.Overlaps(spans[i-1].Bytes, spans[i].Bytes)
		if e != nil || overlaps {
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

func (f storageFootprint) valid() bool {
	return f.Bytes.Width() > 0
}

func (r *storageLayout) contains(outer, inner nativeproof.TransitionExtent) bool {
	ok, err := r.geometry.Contains(outer, inner)
	return err == nil && ok
}

func (r *storageLayout) ordered(a, b nativeproof.TransitionLocation) bool {
	order, err := r.geometry.Compare(a, b)
	return err == nil && order <= 0
}

func (r *storageLayout) stackExtent(extent nativeproof.TransitionExtent) bool {
	selector, err := r.geometry.Describe(extent.Start())
	_, stack := selector.(nativeproof.StackOffset)
	return err == nil && stack && r.contains(extent, extent)
}

func (r *storageLayout) objectFootprint(object regionObject) (storageFootprint, bool) {
	if r == nil {
		return storageFootprint{}, false
	}
	o, ok := r.objects[object]
	if !ok {
		return storageFootprint{}, false
	}
	return storageFootprint{Bytes: o.bytes}, true
}

func (r *storageLayout) locationFootprint(location regionLocation) (storageFootprint, bool) {
	if r == nil || len(location.path) >= storageMaxDepth {
		return storageFootprint{}, false
	}
	o, ok := r.objects[location.object]
	if !ok {
		return storageFootprint{}, false
	}
	n, offset, ok := storagePath(o.shape, location.path)
	if !ok {
		return storageFootprint{}, false
	}
	extent, err := o.bytes.Subextent(offset, n.size)
	return storageFootprint{Bytes: extent}, err == nil
}

// storagePath resolves only selected type structure, without native authority.
func storagePath(n *storageTypeLayout, path []regionStep) (*storageTypeLayout, int64, bool) {
	if n == nil || len(path) >= storageMaxDepth {
		return nil, 0, false
	}
	var offset int64
	for _, step := range path {
		if step.summary || step.index < 0 {
			return nil, 0, false
		}
		if step.field {
			if step.index >= int64(len(n.fields)) {
				return nil, 0, false
			}
			offset += n.fieldOffsets[step.index]
			n = n.fields[step.index]
		} else {
			if n.element == nil || step.index >= n.count {
				return nil, 0, false
			}
			offset += step.index * n.stride
			n = n.element
		}
	}
	return n, offset, true
}

// classifyAccess considers the full access, including padding and intersections
// that begin outside an object. An access spanning several objects is partial.
// Invalid accesses also refuse the disjoint/administrative classification.
func (r *storageLayout) classifyAccess(access storageFootprint) storageAccessClass {
	if r == nil || !access.valid() {
		return storagePartial
	}
	if valid, err := r.geometry.Contains(access.Bytes, access.Bytes); err != nil || !valid {
		return storagePartial
	}
	for object := range r.objects {
		f, _ := r.objectFootprint(object)
		overlaps, err := r.geometry.Overlaps(f.Bytes, access.Bytes)
		if err != nil {
			return storagePartial
		}
		if overlaps {
			if inside, err := r.geometry.Contains(f.Bytes, access.Bytes); err == nil && inside {
				return storageInside
			}
			return storagePartial
		}
	}
	return storageDisjoint
}

func (r *storageLayout) representedByte(location nativeproof.TransitionLocation) bool {
	if r == nil {
		return false
	}
	for _, object := range r.objects {
		start, e1 := r.geometry.Compare(object.bytes.Start(), location)
		end, e2 := r.geometry.Compare(location, object.bytes.End())
		if e1 == nil && e2 == nil && start <= 0 && end < 0 {
			return true
		}
	}
	return false
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
	structural, err := storageLeaves(ctx, o.shape)
	if err != nil {
		return nil, err
	}
	leaves := make([]storageLeaf, 0, len(structural))
	for _, leaf := range structural {
		extent, err := o.bytes.Subextent(leaf.offset, leaf.shape.size)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, storageLeaf{location: regionLocation{object: object, path: leaf.path}, typ: leaf.shape.typ, footprint: storageFootprint{Bytes: extent}})
	}
	return leaves, nil
}

type storageStructuralLeaf struct {
	shape  *storageTypeLayout
	offset int64
	path   []regionStep
}

// storageLeaves enumerates only selected type paths and offsets. Native storage
// is resolved separately against the owning certificate's geometry.
func storageLeaves(ctx context.Context, shape *storageTypeLayout) ([]storageStructuralLeaf, error) {
	if shape == nil {
		return nil, fmt.Errorf("storage layout: missing type")
	}
	m := storageLayoutMeter{ctx: ctx}
	var leaves []storageStructuralLeaf
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
			leaves = append(leaves, storageStructuralLeaf{shape: n, offset: offset, path: slices.Clone(path)})
		}
		return nil
	}
	if err := walk(shape, 0, nil); err != nil {
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
// Canonical keys retain their owned backing; arbitrary numeric coordinates
// cannot select bytes, and alternate views of one backing read the same lanes.
// The caller separately proves accessibility and source/native value equality.
func storageNativeWord(ctx context.Context, builder *br.Builder, memory []nativeproof.TransitionByte, extent nativeproof.TransitionExtent, width int) (br.Term, error) {
	if ctx == nil || builder == nil || width < 1 || width > 8 || len(memory) > storageMaxBytes {
		return br.Term{}, fmt.Errorf("storage projection: invalid width or byte budget")
	}
	if extent.Width() != int64(width) {
		return br.Term{}, fmt.Errorf("storage projection: invalid extent")
	}
	// Do not allow a context callback to replace bytes while they are read.
	memory = slices.Clone(memory)
	var lanes [8]br.Term
	indices := make(map[nativeproof.TransitionLocation]int, width)
	for i := range width {
		key, err := extent.Byte(int64(i))
		if err != nil {
			return br.Term{}, err
		}
		indices[key] = i
	}
	m := storageLayoutMeter{ctx: ctx}
	for _, cell := range memory {
		if err := m.tick(); err != nil {
			return br.Term{}, err
		}
		lane, present := indices[cell.TransitionLocation]
		if !present {
			continue
		}
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
