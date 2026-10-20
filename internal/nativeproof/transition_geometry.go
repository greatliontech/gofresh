package nativeproof

import (
	"cmp"
	"context"
	"unsafe"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

// StorageSelector is an untrusted coordinate, never a pointer, value or permission.
// Its closed vocabulary describes only original-stack offsets and image addresses.
type StorageSelector interface{ storageSelector() }

// StackOffset proposes a signed byte offset from the original stack origin.
type StackOffset int64

func (StackOffset) storageSelector() {}

// ImageAddress proposes an absolute image byte address. Negative values are invalid.
type ImageAddress int64

func (ImageAddress) storageSelector() {}

type backingRole uint8

const (
	stackBacking backingRole = iota + 1
	imageBacking
)

type transitionBacking struct {
	geometry *transitionGeometry
	role     backingRole
}

type addressView struct {
	backing *transitionBacking
	bounds  RelativeSpan
	load    int
}

// transitionGeometry is immutable after root construction. Views preserve the
// arithmetic domain; canonical backing coordinates preserve byte aliasing.
type transitionGeometry struct {
	origin            br.Term
	face              TransitionInterface
	image             *Image
	stack, imageBytes transitionBacking
	stackView         addressView
	imageViews        []addressView
}

// ActualTransitionGeometry identifies one checked root's immutable storage and
// placement premises. Copies retain identity; independently checked roots do not.
// A zero value grants no coordinates. Obtain it from a certificate's BoundFor.
type ActualTransitionGeometry struct{ root *transitionGeometry }

// AddressPointer retains an owned arithmetic view and its checked offset. It is
// comparable and opaque; scalar equality and storage selectors cannot create it.
type AddressPointer struct {
	view   *addressView
	offset int64
}

func (AddressPointer) transitionPointer() {}

// TransitionLocation is an opaque comparable canonical byte coordinate. All
// addressing views of one byte have the same key, including FS-relative views.
type TransitionLocation struct {
	backing *transitionBacking
	offset  int64
}

// TransitionExtent is an opaque comparable, nonempty canonical storage extent.
// It conveys coordinates only, not authority to perform an instruction access.
type TransitionExtent struct {
	start TransitionLocation
	width int64
}

// Start returns the canonical first-byte key. Zero extents return a zero key.
func (e TransitionExtent) Start() TransitionLocation { return e.start }

// Width returns the extent's byte width.
func (e TransitionExtent) Width() int64 { return e.width }

// End returns the canonical exclusive endpoint, not a dereferenceable byte.
func (e TransitionExtent) End() TransitionLocation { return e.start.add(e.width) }

// Byte returns an in-bounds canonical byte key.
func (e TransitionExtent) Byte(index int64) (TransitionLocation, error) {
	if e.start.backing == nil || index < 0 || index >= e.width {
		return TransitionLocation{}, geometryError("byte index outside extent")
	}
	return e.start.add(index), nil
}

// Subextent returns a nonempty contained extent without granting new storage.
func (e TransitionExtent) Subextent(offset, width int64) (TransitionExtent, error) {
	if e.start.backing == nil || offset < 0 || width <= 0 || offset > e.width || width > e.width-offset {
		return TransitionExtent{}, geometryError("subextent outside extent")
	}
	return TransitionExtent{e.start.add(offset), width}, nil
}

func geometryError(detail string) error { return refuse(0, "transition-geometry", detail) }

func (l TransitionLocation) add(delta int64) TransitionLocation {
	return TransitionLocation{l.backing, l.offset + delta}
}

func (l TransitionLocation) isImage() bool { return l.backing != nil && l.backing.role == imageBacking }

func (p AddressPointer) isImage() bool { return p.view != nil && p.view.backing.role == imageBacking }

func (g ActualTransitionGeometry) owns(l TransitionLocation) bool {
	return g.root != nil && (l.backing == &g.root.stack || l.backing == &g.root.imageBytes)
}

func (g ActualTransitionGeometry) ownsPointer(p AddressPointer) bool {
	if g.root == nil || p.view == nil {
		return false
	}
	if p.view == &g.root.stackView {
		return true
	}
	j := p.view.load
	return p.view.backing == &g.root.imageBytes && j >= 0 && j < len(g.root.imageViews) && p.view == &g.root.imageViews[j]
}

// Origin returns the immutable original stack expression, or zero for no geometry.
func (g ActualTransitionGeometry) Origin() br.Term {
	if g.root == nil {
		return br.Term{}
	}
	return g.root.origin
}

// ExpressionRoots returns all placement expression roots in this geometry.
func (g ActualTransitionGeometry) ExpressionRoots() []br.Term {
	if g.root == nil {
		return nil
	}
	return []br.Term{g.root.origin}
}

// OriginalStack recognizes only this root's exact original-stack address view.
// Image pointers and entry-value lineage cannot authorize a stack pivot.
func (g ActualTransitionGeometry) OriginalStack(pointer TransitionPointer) (int64, bool) {
	p, ok := pointer.(AddressPointer)
	return p.offset, ok && g.root != nil && p.view == &g.root.stackView
}

// Describe returns a non-authorizing coordinate projection. A foreign or zero
// key is an error, never an implicit stack coordinate or disjoint storage.
func (g ActualTransitionGeometry) Describe(l TransitionLocation) (StorageSelector, error) {
	if !g.owns(l) {
		return nil, geometryError("foreign storage coordinate")
	}
	if l.isImage() {
		return ImageAddress(l.offset), nil
	}
	return StackOffset(l.offset), nil
}

// PointerDescription is a non-authorizing view of address provenance. Bounds
// retain the actual logical load boundary, including its one-past endpoint.
type PointerDescription struct {
	Coordinate StorageSelector
	Bounds     RelativeSpan
	Load       int
}

// DescribePointer exposes provenance coordinates without creating a capability.
func (g ActualTransitionGeometry) DescribePointer(pointer TransitionPointer) (PointerDescription, error) {
	p, ok := pointer.(AddressPointer)
	if !ok || !g.ownsPointer(p) {
		return PointerDescription{}, geometryError("foreign or nonaddress pointer")
	}
	coordinate, err := g.Describe(TransitionLocation{p.view.backing, p.offset})
	return PointerDescription{coordinate, p.view.bounds, p.view.load}, err
}

// ResolveStorage checks full coverage by the union of declared bytes. It does
// not require one native access grant and supplies neither pointer provenance nor
// permissions. In particular a source aggregate may span adjacent declarations.
func (g ActualTransitionGeometry) ResolveStorage(ctx context.Context, selector StorageSelector, width int64) (TransitionExtent, error) {
	if ctx == nil {
		return TransitionExtent{}, geometryError("missing context")
	}
	if err := ctx.Err(); err != nil {
		return TransitionExtent{}, err
	}
	if g.root == nil || width <= 0 {
		return TransitionExtent{}, geometryError("missing geometry or invalid width")
	}
	var start TransitionLocation
	switch s := selector.(type) {
	case StackOffset:
		start = TransitionLocation{&g.root.stack, int64(s)}
	case ImageAddress:
		if s < 0 {
			return TransitionExtent{}, geometryError("negative image address")
		}
		start = TransitionLocation{&g.root.imageBytes, int64(s)}
	default:
		return TransitionExtent{}, geometryError("unknown storage selector")
	}
	end, ok := signedPlus(start.offset, width)
	if !ok {
		return TransitionExtent{}, geometryError("storage extent overflow")
	}
	// Grow the covered prefix, permitting overlap and arbitrary declaration order.
	for at := start.offset; at < end; {
		next := at
		if start.isImage() {
			for _, r := range g.root.face.ImageRegions {
				if err := ctx.Err(); err != nil {
					return TransitionExtent{}, err
				}
				if int64(r.Start) <= at && at < int64(r.End) {
					next = max(next, min(end, int64(r.End)))
				}
			}
		} else {
			for _, r := range g.root.face.Regions {
				if err := ctx.Err(); err != nil {
					return TransitionExtent{}, err
				}
				if r.Bytes.Start <= at && at < r.Bytes.End {
					next = max(next, min(end, r.Bytes.End))
				}
			}
		}
		if next == at {
			return TransitionExtent{}, geometryError("storage extent has undeclared bytes")
		}
		at = next
	}
	return TransitionExtent{start, width}, nil
}

// ResolvePointer resolves an owned pointer's displacement and full extent while
// preserving its arithmetic view. It performs no executed access and grants no
// permission. One-past of one load cannot transfer authority to an adjacent load.
func (g ActualTransitionGeometry) ResolvePointer(ctx context.Context, pointer TransitionPointer, displacement, width int64) (TransitionExtent, error) {
	if ctx == nil {
		return TransitionExtent{}, geometryError("missing context")
	}
	if err := ctx.Err(); err != nil {
		return TransitionExtent{}, err
	}
	if width <= 0 {
		return TransitionExtent{}, geometryError("foreign pointer or invalid width")
	}
	p, _, failure := g.pointerRange(pointer, displacement, width, 0)
	if failure != nil {
		if failure.Premise == "transition-provenance" {
			return TransitionExtent{}, geometryError("foreign pointer or invalid width")
		}
		return TransitionExtent{}, geometryError("full pointer extent escapes arithmetic view")
	}
	selector, _ := g.Describe(TransitionLocation{p.view.backing, p.offset})
	return g.ResolveStorage(ctx, selector, width)
}

// pointerRange is the owned-view arithmetic judgment shared by coordinate
// resolution and execution. Width zero judges only a pointer, including a
// canonical one-past value; positive widths judge the complete half-open extent.
// It establishes neither declared storage coverage nor an access permission.
//
// The immutable stack view's two envelope endpoints were proved canonical and
// nonwrapping throughout the original origin domain before geometry construction.
// Every enclosed offset inherits that proof by monotonicity. Image view bounds
// come from the owned logical load: its exclusive end may equal 2^47, but that
// endpoint itself is not a canonical pointer. Keeping the original view prevents
// a one-past value from borrowing the adjacent load's authority.
func (g ActualTransitionGeometry) pointerRange(pointer TransitionPointer, displacement, width int64, pc uint64) (AddressPointer, int64, *Refusal) {
	p, ok := pointer.(AddressPointer)
	if !ok || !g.ownsPointer(p) || width < 0 {
		detail := "address lacks the checked origin"
		if width != 0 {
			detail = "access lacks current memory provenance"
		}
		return AddressPointer{}, 0, refuse(pc, "transition-provenance", detail)
	}
	start, ok := signedPlus(p.offset, displacement)
	if !ok {
		return AddressPointer{}, 0, refuse(pc, "transition-origin", "signed offset overflow")
	}
	end, ok := signedPlus(start, width)
	if !ok {
		if p.isImage() {
			return AddressPointer{}, 0, refuse(pc, "transition-image", "full access escapes logical mapping")
		}
		return AddressPointer{}, 0, refuse(pc, "transition-origin", "access offset overflow")
	}
	if p.offset < p.view.bounds.Start || p.offset > p.view.bounds.End || start < p.view.bounds.Start || end > p.view.bounds.End || p.isImage() && start >= 1<<47 {
		if p.isImage() {
			detail := "pointer escapes its logical image mapping"
			if width != 0 {
				detail = "full access escapes logical mapping"
			}
			return AddressPointer{}, 0, refuse(pc, "transition-image", detail)
		}
		return AddressPointer{}, 0, refuse(pc, "transition-envelope", "pointer escapes representable address envelope")
	}
	p.offset = start
	return p, end, nil
}

func (g ActualTransitionGeometry) checkExtent(e TransitionExtent) error {
	if !g.owns(e.start) || e.width <= 0 {
		return geometryError("foreign or empty extent")
	}
	return nil
}

// Overlaps compares canonical storage extents under this root's checked alias
// premises. Foreign extents return an error rather than administrative disjointness.
func (g ActualTransitionGeometry) Overlaps(a, b TransitionExtent) (bool, error) {
	if err := g.checkExtent(a); err != nil {
		return false, err
	}
	if err := g.checkExtent(b); err != nil {
		return false, err
	}
	return a.start.backing == b.start.backing && a.start.offset < b.End().offset && b.start.offset < a.End().offset, nil
}

// Contains reports canonical extent containment, refusing foreign ownership.
func (g ActualTransitionGeometry) Contains(outer, inner TransitionExtent) (bool, error) {
	if err := g.checkExtent(outer); err != nil {
		return false, err
	}
	if err := g.checkExtent(inner); err != nil {
		return false, err
	}
	return outer.start.backing == inner.start.backing && outer.start.offset <= inner.start.offset && inner.End().offset <= outer.End().offset, nil
}

// CheckAlignment establishes alignment throughout the original placement domain.
// Alignment is a positive power of two; it grants no memory access.
func (g ActualTransitionGeometry) CheckAlignment(e TransitionExtent, alignment int64) (bool, error) {
	if err := g.checkExtent(e); err != nil {
		return false, err
	}
	if alignment <= 0 || alignment&(alignment-1) != 0 {
		return false, geometryError("invalid alignment")
	}
	if e.start.isImage() {
		return e.start.offset%alignment == 0, nil
	}
	d := g.root.face.Origin
	lo, hi, valid := originRange(d)
	if valid && lo == hi {
		return (lo+uint64(e.start.offset))&uint64(alignment-1) == 0, nil
	}
	return d.Modulus%uint64(alignment) == 0 && (d.Residue+uint64(e.start.offset))&uint64(alignment-1) == 0, nil
}

// Compare orders owned coordinates deterministically by backing role and offset,
// never by numeric Go pointer order or by an assumed runtime placement.
func (g ActualTransitionGeometry) Compare(a, b TransitionLocation) (int, error) {
	if !g.owns(a) || !g.owns(b) {
		return 0, geometryError("foreign storage coordinate")
	}
	if n := cmp.Compare(a.backing.role, b.backing.role); n != 0 {
		return n, nil
	}
	return cmp.Compare(a.offset, b.offset), nil
}

func newTransitionGeometry(im *Image, face TransitionInterface, origin br.Term) ActualTransitionGeometry {
	r := &transitionGeometry{origin: origin, face: face, image: im}
	r.stack = transitionBacking{r, stackBacking}
	r.imageBytes = transitionBacking{r, imageBacking}
	r.stackView = addressView{&r.stack, face.Envelope, -1}
	r.imageViews = make([]addressView, len(im.loads))
	for j, l := range im.loads {
		r.imageViews[j] = addressView{&r.imageBytes, RelativeSpan{int64(l.va), int64(l.end)}, j}
	}
	return ActualTransitionGeometry{r}
}

// The first state's fixed slack covers the root header and ordinary small view
// tables. Charge larger tables separately before allocation; sharing across
// states does not multiply the one immutable table's storage.
func (m *transitionChecker) reserveGeometry() error {
	const slack = 1024
	room := m.limits.LiveStateBytes - m.liveStateBytes
	bytes := max(0, geometryStorageBytes(len(m.im.loads))-slack)
	if bytes > room {
		return refuse(m.pc, "transition-budget", "owned geometry storage")
	}
	m.liveStateBytes += bytes
	for range m.im.loads {
		if !m.tick() {
			return m.err
		}
	}
	return nil
}

// The owned ELF's program-header count bounds loads before any root is built.
func geometryStorageBytes(loads int) int {
	return int(unsafe.Sizeof(transitionGeometry{})) + loads*int(unsafe.Sizeof(addressView{}))
}

func (g ActualTransitionGeometry) stackLocation(offset int64) TransitionLocation {
	return TransitionLocation{&g.root.stack, offset}
}
func (g ActualTransitionGeometry) imageLocation(address int64) TransitionLocation {
	return TransitionLocation{&g.root.imageBytes, address}
}
func (g ActualTransitionGeometry) stackPointer(offset int64) AddressPointer {
	return AddressPointer{&g.root.stackView, offset}
}
func (g ActualTransitionGeometry) imagePointer(load int, address uint64) AddressPointer {
	return AddressPointer{&g.root.imageViews[load], int64(address)}
}

// TransitionGeometryAssociation is an opaque checked application association.
// It maps callee storage to actual caller storage, preserving shared-byte views.
// Its zero value grants no translation. StackShift projections do not construct it.
type TransitionGeometryAssociation struct {
	input, current ActualTransitionGeometry
	stackShift     int64
}

// Input returns the exact independently rooted callee geometry.
func (a TransitionGeometryAssociation) Input() ActualTransitionGeometry { return a.input }

// Current returns the actual caller-root geometry.
func (a TransitionGeometryAssociation) Current() ActualTransitionGeometry { return a.current }

// ResolveExtent translates a callee-owned canonical extent into actual caller
// storage. Foreign geometry refuses, even if its numeric coordinates coincide.
func (a TransitionGeometryAssociation) ResolveExtent(ctx context.Context, e TransitionExtent) (TransitionExtent, error) {
	if err := a.input.checkExtent(e); err != nil {
		return TransitionExtent{}, err
	}
	location, err := a.associateLocation(e.Start())
	if err != nil {
		return TransitionExtent{}, err
	}
	selector, err := a.current.Describe(location)
	if err != nil {
		return TransitionExtent{}, err
	}
	return a.current.ResolveStorage(ctx, selector, e.Width())
}

func (a TransitionGeometryAssociation) associateLocation(l TransitionLocation) (TransitionLocation, error) {
	if !a.input.owns(l) || a.current.root == nil {
		return TransitionLocation{}, geometryError("foreign association coordinate")
	}
	switch l.backing.role {
	case stackBacking:
		offset, ok := signedPlus(l.offset, a.stackShift)
		if !ok {
			return TransitionLocation{}, geometryError("associated stack offset overflow")
		}
		return a.current.stackLocation(offset), nil
	case imageBacking:
		if !sameImage(a.input.root.image, a.current.root.image) {
			return TransitionLocation{}, geometryError("associated image owner differs")
		}
		return a.current.imageLocation(l.offset), nil
	default:
		return TransitionLocation{}, geometryError("unknown association backing")
	}
}
