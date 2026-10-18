package nativeproof

import (
	"math/rand/v2"
	"reflect"
	"sort"
	"testing"
	"testing/quick"
)

type loadingCell struct {
	kind  uint8
	value byte
	file  uint64
}

// This bounded loader oracle materializes page operations and a file-page owner
// census. It never reads Image.loads, initialization coverage, or checker state.
// Unknown is a knowledge class: the supported relation deliberately supplies no
// readonly BSS fact, even for an anonymous page that one loader might zero.
func loadingOracle(t testing.TB, raw []byte, data []interfaceMapping) (map[uint64]loadingCell, []initializedRange) {
	t.Helper()
	loads := append([]interfaceMapping{{start: testEntry, end: testEntry + 1, file: 4096, filesz: 1, read: true, execute: true}}, data...)
	owners := map[uint64]map[int]bool{}
	for j, l := range loads {
		// Iterating mapped pages includes the zero-filesz unaligned prefix.
		for page := l.file / 4096; page*4096 < l.file+l.filesz; page++ {
			if owners[page] == nil {
				owners[page] = map[int]bool{}
			}
			owners[page][j] = true
		}
	}
	cells := map[uint64]loadingCell{}
	for j, l := range loads {
		independent := true
		for _, set := range owners {
			if set[j] && len(set) > 1 {
				independent = false
			}
		}
		// Explicit leading/trailing padding stays unknown and grants no storage.
		for address := l.start / 4096 * 4096; address < ((l.end+4095)/4096)*4096; address++ {
			if _, exists := cells[address]; exists {
				t.Fatal("oracle received overlapping virtual page operations")
			}
			c := loadingCell{}
			if independent && l.read && address >= l.start && address < l.end {
				if address-l.start < l.filesz {
					c = loadingCell{1, raw[l.file+address-l.start], l.file + address - l.start}
				} else if l.write && !l.execute {
					c.kind = 2
				}
			}
			cells[address] = c
		}
	}
	// Under NewImage's page-disjoint nonempty-load admission, the greatest
	// file end and greatest memory end in ANY header prefix belong to its highest
	// virtual load. Thus aggregate clears/remaps cannot reach another load's
	// logical bytes. Check that implication on concrete byte operation extents,
	// including ignored partial clear footprints, rather than inventing an
	// impossible accepted virtual-overlap fixture.
	for n := 1; n <= len(loads); n++ {
		f, m := uint64(0), uint64(0)
		highest := loads[0]
		for _, l := range loads[:n] {
			if l.start > highest.start {
				highest = l
			}
			if l.start+l.filesz > f {
				f = l.start + l.filesz
			}
			if l.end > m {
				m = l.end
			}
		}
		if f < highest.start || m != highest.end {
			t.Fatal("admitted prefix breaks highest-load implication")
		}
		if f == m {
			continue
		}
		// Byte clear, then anonymous page installation. Both can affect every
		// byte in their footprint, regardless of success/partial-clear outcome.
		for _, op := range [][2]uint64{{f, (f + 4095) / 4096 * 4096}, {(f + 4095) / 4096 * 4096, (m + 4095) / 4096 * 4096}} {
			for address := op[0]; address < op[1]; address++ {
				for _, l := range loads {
					if address >= l.start/4096*4096 && address < (l.end+4095)/4096*4096 {
						if l.start != highest.start || address-l.start < l.filesz {
							t.Fatal("aggregate operation interferes with another logical/file range")
						}
					}
				}
			}
		}
	}
	// Compress the concrete classification into maximal same-provenance runs;
	// compare complete endpoints, not a few sampled interior byte values.
	var addresses []uint64
	starts := map[uint64]bool{}
	for _, l := range loads {
		starts[l.start] = true
	}
	for a := range cells {
		addresses = append(addresses, a)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })
	var ranges []initializedRange
	for _, a := range addresses {
		c := cells[a]
		if c.kind == 0 {
			continue
		}
		if len(ranges) > 0 && !starts[a] {
			r := &ranges[len(ranges)-1]
			if r.End == a && r.file == (c.kind == 1) && (!r.file || r.offset+a-r.Start == c.file) {
				r.End++
				continue
			}
		}
		ranges = append(ranges, initializedRange{Span{a, a + 1}, c.kind == 1, c.file})
	}
	return cells, ranges
}

func assertInitializationGeometry(t testing.TB, raw []byte, loads []interfaceMapping, requested int) {
	t.Helper()
	im, face := initializedImage(t, raw, stateFace(16, 0))
	cells, want := loadingOracle(t, raw, loads)
	got := append([]initializedRange(nil), face.Initialization.checked.ranges...)
	sort.Slice(got, func(i, j int) bool { return got[i].Start < got[j].Start })
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("complete initialization coverage differs\ngot %#v\nwant %#v", got, want)
	}
	face.Regions, face.Words = nil, nil
	face.ImageRegions = []Span{{testEntry, testEntry + 1}}
	// Variable full widths and logical/file endpoints, under explicit root byte
	// and expression allowances. Aliased loads are asserted unknown above and
	// independently checked as inaccessible under the shared mapping policy.
	for _, l := range loads {
		alias := false
		for page := l.file / 4096; page*4096 < l.file+l.filesz; page++ {
			for _, other := range loads {
				if other.start != l.start {
					for q := other.file / 4096; q*4096 < other.file+other.filesz; q++ {
						if q == page {
							alias = true
						}
					}
				}
			}
		}
		if alias {
			bad := face
			bad.ImageRegions = []Span{{l.start, l.start + 1}}
			c, err := proveTransition(t, im, im.entry, bad)
			exclusionRefusal(t, c, err, im.entry, "frame-alias", "image data has another file-page mapping")
			continue
		}
		n := min(uint64(requested), l.end-l.start)
		face.ImageRegions = append(face.ImageRegions, Span{l.start, l.start + n}, Span{l.end - 1, l.end})
		if l.filesz > 0 {
			face.ImageRegions = append(face.ImageRegions, Span{l.start + l.filesz - 1, l.start + l.filesz})
		}
		if l.start+l.filesz < l.end {
			face.ImageRegions = append(face.ImageRegions, Span{l.start + l.filesz, l.start + l.filesz + 1})
		}
	}
	initial := stateRawInitial(face, []byte{9, 8, 7, 6})
	initial.initialized = map[stateLocation]bool{}
	for key := range initial.memory {
		if key.image {
			c := cells[uint64(key.off)]
			if c.kind != 0 {
				initial.initialized[key] = true
				initial.memory[key] = stateByte{value: c.value}
			} else {
				// The unknown class includes nonzero values, including readonly
				// BSS after an ignored or partial clear. Zero is not its oracle.
				initial.memory[key] = stateByte{value: byte(uint64(key.off)*37 + 17)}
			}
		}
	}
	declared := 0
	for _, s := range face.ImageRegions {
		declared += int(s.End - s.Start)
	}
	limits := TransitionLimits{Bytes: declared, RelationLimits: RelationLimits{Nodes: 2*declared + 4096, Work: 256*declared + 100000}}
	p := TransitionProposal{ImageDigest: im.digest, Entry: testEntry, Cut: testEntry, Nodes: []Node{{PC: testEntry, Size: 1}}}
	c, err := CheckTransition(t.Context(), im, face, p, limits)
	if err != nil {
		t.Fatal(err)
	}
	stateBindings(t, c, face, initial)
	if declared > 1 {
		tight := limits
		tight.Bytes--
		c, err := CheckTransition(t.Context(), im, face, p, tight)
		exclusionRefusal(t, c, err, testEntry, "transition-budget", "declared memory exceeds byte budget")
	}
	for _, l := range loads {
		bad := face
		bad.ImageRegions = []Span{{l.end, l.end + 1}}
		ownedEnd := false
		for _, other := range loads {
			if l.end >= other.start && l.end < other.end {
				ownedEnd = true
			}
		}
		if !ownedEnd {
			c, err := CheckTransition(t.Context(), im, bad, p, limits)
			exclusionRefusal(t, c, err, testEntry, "transition-image", "extent has no owned logical image mapping")
		}
		if l.start%4096 != 0 {
			bad.ImageRegions = []Span{{l.start - 1, l.start}}
			c, err := CheckTransition(t.Context(), im, bad, p, limits)
			exclusionRefusal(t, c, err, testEntry, "transition-image", "extent has no owned logical image mapping")
		}
	}
}

func initializationGeometry(t testing.TB, seed uint64, width uint16, offset uint16, shape uint8) {
	t.Helper()
	n := 2 + int(shape%3)
	loads := make([]interfaceMapping, n)
	for j := range loads {
		pageOffset := uint64((int(offset) + j*997) % 4096)
		length := uint64(1 + (int(width)+j*4093)%65536)
		fileSize := length * uint64((int(shape)+j)%5) / 4
		if fileSize > length {
			fileSize = length
		}
		if shape&16 != 0 && j == 0 {
			fileSize = 0
		}
		start := uint64(0x700000+j*0x20000) + pageOffset
		loads[j] = interfaceMapping{start: start, end: start + length, file: uint64(0x20000+j*0x20000) + pageOffset, filesz: fileSize, read: true, write: (int(shape)+j)%2 == 0}
	}
	if shape&32 != 0 {
		// Same backing page at disjoint VAs is accepted by NewImage but cannot
		// supply independent initialization coverage. Include zero-filesz aliases.
		length := loads[1].end - loads[1].start
		loads[1].start = loads[1].start/4096*4096 + loads[0].file%4096
		loads[1].end = loads[1].start + length
		loads[1].file = loads[0].file
		if shape&64 != 0 && loads[1].file%4096 != 0 {
			loads[1].filesz = 0
		}
	}
	if shape&8 != 0 {
		// Adjacent virtual page operations, as well as widely separated loads.
		// Keep exact logical widths and file/address page congruence.
		for j := 1; j < len(loads); j++ {
			length := loads[j].end - loads[j].start
			loads[j].start = (loads[j-1].end+4095)/4096*4096 + loads[j].file%4096
			loads[j].end = loads[j].start + length
		}
	}
	rng := rand.New(rand.NewPCG(seed, 0x454c464b))
	rng.Shuffle(n, func(i, j int) { loads[i], loads[j] = loads[j], loads[i] })
	raw := transitionImageELF(t, []byte{0xc3}, loads)
	for _, l := range loads {
		for off := l.file; off < l.file+l.filesz; off++ {
			raw[off] = 0
			if off%3 != 0 {
				raw[off] = byte(off*17 + 1)
			}
		}
	}
	assertInitializationGeometry(t, raw, loads, 1+int(width)%8192)
}

func TestImageInitializationOperationGeometryProperty(t *testing.T) {
	// Interfering virtual page operations are not an admitted initializer
	// population, even when the two logical byte intervals do not overlap.
	for _, reverse := range []bool{false, true} {
		loads := []interfaceMapping{{start: 0x700001, end: 0x700002, file: 0x20001, filesz: 1, read: true, write: true}, {start: 0x700003, end: 0x700004, file: 0x30003, filesz: 1, read: true}}
		if reverse {
			loads[0], loads[1] = loads[1], loads[0]
		}
		_, err := NewImage(t.Context(), transitionImageELF(t, []byte{0xc3}, loads))
		exclusionRefusal(t, TransitionCertificate{}, err, loads[1].start, "image-mapping", "ambiguous overlapping PT_LOAD ranges")
	}
	for _, width := range []uint16{0, 4095, 4096, 8191, 65535} {
		for _, offset := range []uint16{0, 1, 4095} {
			initializationGeometry(t, 17, width, offset, 80)
			initializationGeometry(t, 17, width, offset, 88)
		}
	}
	if err := quick.Check(func(seed uint64, width, offset uint16, shape uint8) bool {
		initializationGeometry(t, seed, width, offset, shape)
		return true
	}, &quick.Config{MaxCount: 24}); err != nil {
		t.Fatal(err)
	}
}

func FuzzImageInitializationOperationGeometry(f *testing.F) {
	for _, shape := range []uint8{0, 1, 16, 32, 40, 64, 88, 96} {
		f.Add(uint64(17), uint16(4095), uint16(1), shape)
	}
	f.Fuzz(func(t *testing.T, seed uint64, width, offset uint16, shape uint8) {
		initializationGeometry(t, seed, width, offset, shape)
	})
}
