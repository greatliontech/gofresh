package closure

import (
	"encoding/binary"
	"testing"

	"github.com/greatliontech/gofresh/internal/nativeproof"
)

func storageTestExtent(t testing.TB, g nativeproof.ActualTransitionGeometry, selector nativeproof.StorageSelector, width int64) nativeproof.TransitionExtent {
	t.Helper()
	e, err := g.ResolveStorage(t.Context(), selector, width)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func storageTestLocation(t testing.TB, g nativeproof.ActualTransitionGeometry, selector nativeproof.StorageSelector) nativeproof.TransitionLocation {
	t.Helper()
	return storageTestExtent(t, g, selector, 1).Start()
}

// This projection is oracle data, never placement or access authority.
func storageTestCoordinate(t testing.TB, g nativeproof.ActualTransitionGeometry, location nativeproof.TransitionLocation) storageByteLocation {
	t.Helper()
	s, err := g.Describe(location)
	if err != nil {
		t.Fatal(err)
	}
	switch s := s.(type) {
	case nativeproof.StackOffset:
		return storageByteLocation{Offset: int64(s)}
	case nativeproof.ImageAddress:
		return storageByteLocation{Image: true, Offset: int64(s)}
	default:
		t.Fatalf("unknown coordinate %T", s)
		return storageByteLocation{}
	}
}

func storageTestSelector(image bool, offset int64) nativeproof.StorageSelector {
	if image {
		return nativeproof.ImageAddress(offset)
	}
	return nativeproof.StackOffset(offset)
}

type storageOracleByte struct {
	nativeproof.TransitionByte
	storageByteLocation
}

func storageTestByte(t testing.TB, g nativeproof.ActualTransitionGeometry, cell nativeproof.TransitionByte) storageOracleByte {
	return storageOracleByte{cell, storageTestCoordinate(t, g, cell.TransitionLocation)}
}

type storageOracleAccess struct {
	nativeproof.TransitionAccess
	Image bool
	Bytes nativeproof.RelativeSpan
}

func storageTestAccess(t testing.TB, g nativeproof.ActualTransitionGeometry, access nativeproof.TransitionAccess) storageOracleAccess {
	at := storageTestCoordinate(t, g, access.Bytes.Start())
	end := storageTestCoordinate(t, g, access.Bytes.End())
	if at.Image != end.Image || end.Offset-at.Offset != access.Bytes.Width() {
		t.Fatal("inconsistent extent projection")
	}
	return storageOracleAccess{access, at.Image, nativeproof.RelativeSpan{Start: at.Offset, End: end.Offset}}
}

func storageTestStack(g nativeproof.ActualTransitionGeometry, pointer nativeproof.TransitionPointer, want int64) bool {
	offset, ok := g.OriginalStack(pointer)
	return ok && offset == want
}

func storageTestImagePointer(g nativeproof.ActualTransitionGeometry, pointer nativeproof.TransitionPointer, want uint64) bool {
	d, err := g.DescribePointer(pointer)
	return err == nil && d.Coordinate == nativeproof.ImageAddress(want)
}

// Every geometry fixture is a real checked native root over owned ELF bytes.
// Its declared stack and image population remains the existing native model.
func storageGeometryFixture(t testing.TB, residue uint64, configure ...func(*nativeproof.TransitionInterface)) (*nativeproof.Image, nativeproof.TransitionBound) {
	t.Helper()
	f := globalNativeImage(t, [2]uint64{0x1000, 0x2000}, [3]uint64{}, 0x1000, 0, nil, "")
	raw := append(f.raw, make([]byte, 0x4000-128)...)
	code := []byte{0xc3, 0x48, 0x8d, 0x4c, 0x24, 0xe8, 0x90}
	copy(raw[4096:], code)
	binary.LittleEndian.PutUint64(raw[64+32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(raw[64+40:], uint64(len(code)))
	binary.LittleEndian.PutUint64(raw[120+32:], 0x4000)
	binary.LittleEndian.PutUint64(raw[120+40:], 0x4000)
	image, err := nativeproof.NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	face := globalNativeFace([]nativeproof.Span{{Start: 0, End: 32}, {Start: 0xff0, End: 0x2010}, {Start: 0x3000, End: 0x3010}})
	face.Origin.Residue = residue
	face.Envelope = nativeproof.RelativeSpan{Start: -128, End: 128}
	face.Regions = []nativeproof.RelativeRegion{{Bytes: face.Envelope, Readable: true, Writable: true}}
	face.EntryImagePointers = []nativeproof.TransitionEntryImagePointer{{Register: nativeproof.R14, Address: 0x1000}}
	for _, change := range configure {
		change(&face)
	}
	proposal, err := nativeproof.ProposeRegionTransition(t.Context(), image, 0x401001, 0x401006, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := nativeproof.CheckRegionTransition(t.Context(), image, 0x401001, face, proposal, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	bound, ok := proof.BoundFor(image)
	if !ok {
		t.Fatal("fixture lost native owner")
	}
	return image, bound
}

func TestStorageGeometryOwnershipAndAggregateCoverage(t *testing.T) {
	r := storageFixture(t, `var A [16]byte; func F(){}`)
	object := storageGlobal(r, "A")
	r.bindings = []storageBinding{storageImageBinding(object, 0x1000)}
	for _, hole := range []bool{false, true} {
		image, bound := storageGeometryFixture(t, 0, func(face *nativeproof.TransitionInterface) {
			start := uint64(0x1008)
			if hole {
				start++
			}
			face.ImageRegions = []nativeproof.Span{{Start: start, End: 0x1010}, {Start: 0x1000, End: 0x1008}}
			if !hole {
				face.ImageRegions = append(face.ImageRegions, nativeproof.Span{Start: 0x1004, End: 0x100c})
			}
		})
		r.image = image
		layout, err := resolveStorageRepresentation(t.Context(), r, bound.Geometry, nil)
		if hole {
			if err == nil || layout != nil {
				t.Fatal("partially mapped aggregate accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal("union-covered aggregate refused", err)
		}
		whole, ok := layout.objectFootprint(object)
		if !ok || whole.Bytes.Width() != 16 {
			t.Fatal("aggregate extent lost")
		}
		_, foreign := storageGeometryFixture(t, 0)
		other := storageTestExtent(t, foreign.Geometry, nativeproof.ImageAddress(0x1000), 16)
		if got := layout.classifyAccess(storageFootprint{Bytes: other}); got != storagePartial {
			t.Fatal("foreign extent classified as disjoint", got)
		}
		if layout.representedByte(other.Start()) {
			t.Fatal("foreign byte acquired representation")
		}
		empty := *layout
		empty.objects = nil
		if empty.classifyAccess(storageFootprint{Bytes: other}) != storagePartial {
			t.Fatal("empty representation treated foreign storage as disjoint")
		}
		if got, err := resolveStorageRepresentation(t.Context(), r, bound.Geometry, []storageFootprint{{Bytes: other}}); err == nil || got != nil {
			t.Fatal("foreign protection accepted")
		}
		if got, err := resolveStorageRepresentation(t.Context(), r, nativeproof.ActualTransitionGeometry{}, nil); err == nil || got != nil {
			t.Fatal("zero geometry accepted")
		}
	}
}

func TestStorageGeometryCumulativeAccount(t *testing.T) {
	_, bound := storageGeometryFixture(t, 0)
	if len(bound.Geometry.ExpressionRoots()) == 0 {
		t.Fatal("fixture has no retained geometry roots")
	}
	meter := &correspondenceContext{Context: t.Context(), limit: 100000}
	if err := chargeStorageGeometry(meter, bound.Geometry); err != nil {
		t.Fatal(err)
	}
	if meter.work == 0 {
		t.Fatal("geometry dependencies escaped the cumulative account")
	}
	meter.limit = meter.work
	if err := chargeStorageGeometry(meter, bound.Geometry); err == nil {
		t.Fatal("geometry reset the exhausted cumulative account")
	}
}
