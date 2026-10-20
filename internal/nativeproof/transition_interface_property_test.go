package nativeproof

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"math/rand"
	"reflect"
	"slices"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

// These properties exercise the interface part of native-transition's
// symbolic-origins, bound-scope and independent-evidence obligations. They do not
// cover instruction transfer, successor composition, or source startup. A RET at
// the ELF entry is decoded but never executed: no return premise is imported.
//
// Reference arithmetic uses unbounded integers and set subtraction, never the
// checker's offset, rounding, page, permission, or normalization helpers. Image
// extents below are fixture intent, not reconstructed from Image.loads or Bound.
type interfaceImage struct {
	im        *Image
	proposal  TransitionProposal
	entry     uint64
	digest    [32]byte
	loads     [][2]uint64 // half-open logical mapped extents, including zero-fill
	dataLoads []interfaceMapping
}

// Intent for the file-page and permission oracle; never recovered from Image.
type interfaceMapping struct {
	start, end, file, filesz uint64
	read, write, execute     bool
}

func interfaceFixture(t testing.TB, choice uint8) interfaceImage {
	t.Helper()
	x := interfaceImage{entry: testEntry}
	var raw []byte
	switch choice % 5 {
	case 0:
		raw = elfBytes([]byte{0xc3})
		x.loads = [][2]uint64{{testEntry, testEntry + 1}}
	case 1, 4:
		raw = callbackELF(t, "c3", "c3")
		x.loads = [][2]uint64{{testEntry, testEntry + 129}, {descriptorAddress, descriptorAddress + 8}, {descriptorAddress + 4096, descriptorAddress + 4104}}
		if choice%5 == 4 {
			x.entry = callbackEntry
			binary.LittleEndian.PutUint64(raw[24:], x.entry)
		}
	case 2:
		// Same separated LOAD layout as displacementImage, with intent recorded
		// here before NewImage, rather than consulting its mapping inventory.
		raw = callbackELF(t, "c3", "c3")
		raw = append(raw, make([]byte, 8)...)
		for j, address := range []uint64{testBase, testBase + 1<<32} {
			off := 120 + j*56
			binary.LittleEndian.PutUint32(raw[off+4:], 4)
			binary.LittleEndian.PutUint64(raw[off+16:], address)
			binary.LittleEndian.PutUint64(raw[off+32:], 16)
			binary.LittleEndian.PutUint64(raw[off+40:], 16)
		}
		x.loads = [][2]uint64{{testEntry, testEntry + 129}, {testBase, testBase + 16}, {testBase + 1<<32, testBase + 1<<32 + 16}}
	case 3:
		raw = callbackELF(t, "c3", "c3")
		// One file byte at a page's last address and one zero-fill byte on
		// the next page. Both pages exclude origins, regardless of permission.
		binary.LittleEndian.PutUint64(raw[128:], 0x2fff)
		binary.LittleEndian.PutUint64(raw[136:], descriptorAddress+4095)
		binary.LittleEndian.PutUint64(raw[152:], 1)
		binary.LittleEndian.PutUint64(raw[160:], 2)
		binary.LittleEndian.PutUint64(raw[192:], testBase+0x5000)
		x.loads = [][2]uint64{{testEntry, testEntry + 129}, {descriptorAddress + 4095, descriptorAddress + 4097}, {testBase + 0x5000, testBase + 0x5008}}
	}
	var err error
	x.digest = sha256.Sum256(raw)
	x.im, err = NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	x.proposal, err = ProposeTransition(t.Context(), x.im, x.entry, interfacePropertyLimits())
	if err != nil {
		t.Fatal(err)
	}
	return x
}

// The small-interface families retain their cheap 512-byte budget. Sized-state
// and aggregate-word families below parameterize budgets up to the production
// maximum; 512 is not an admissibility restriction of their reference oracle.
func interfacePropertyLimits() TransitionLimits {
	return TransitionLimits{RelationLimits: RelationLimits{Nodes: 16384, Work: 1000000}, Regions: 256, Bytes: 512}
}

func interfaceConditions() TransitionConditions {
	return TransitionConditions{Machine: MachineModel, InstructionMapping: true, EntryState: true, IsolatedExecution: true, MemoryMapping: true, NoHiddenAliases: true, UnalignedAccess: true}
}

type interfaceInterval struct{ lo, hi *big.Int } // inclusive integer interval

func interfaceU(x uint64) *big.Int { return new(big.Int).SetUint64(x) }
func interfaceAdd(a *big.Int, b int64) *big.Int {
	return new(big.Int).Add(a, big.NewInt(b))
}

// Div is Euclidean division, hence floor for positive divisors, including
// negative numerators. Negating floor(-x/m) yields ceil(x/m).
func interfaceCeil(x, m *big.Int) *big.Int {
	return new(big.Int).Neg(new(big.Int).Div(new(big.Int).Neg(x), m))
}

func interfaceCongruent(q interfaceInterval, d OriginDomain) (*big.Int, *big.Int, bool) {
	m, r := interfaceU(d.Modulus), interfaceU(d.Residue)
	firstQ := interfaceCeil(new(big.Int).Sub(q.lo, r), m)
	lastQ := new(big.Int).Div(new(big.Int).Sub(q.hi, r), m)
	first := new(big.Int).Add(new(big.Int).Mul(firstQ, m), r)
	last := new(big.Int).Add(new(big.Int).Mul(lastQ, m), r)
	return first, last, first.Cmp(last) <= 0
}

// Subtract each closed forbidden set from the remaining integer components.
// No sorted candidate sweep, chosen runtime base, or bit-mask rounding is used.
func interfaceSubtract(in []interfaceInterval, forbidden interfaceInterval) []interfaceInterval {
	var out []interfaceInterval
	for _, p := range in {
		if forbidden.hi.Cmp(p.lo) < 0 || forbidden.lo.Cmp(p.hi) > 0 {
			out = append(out, p)
			continue
		}
		if p.lo.Cmp(forbidden.lo) < 0 {
			out = append(out, interfaceInterval{p.lo, interfaceAdd(forbidden.lo, -1)})
		}
		if p.hi.Cmp(forbidden.hi) > 0 {
			out = append(out, interfaceInterval{interfaceAdd(forbidden.hi, 1), p.hi})
		}
	}
	return out
}

func interfacePageExtent(load [2]uint64) interfaceInterval {
	page := big.NewInt(4096)
	lo := new(big.Int).Mul(new(big.Int).Div(interfaceU(load[0]), page), page)
	hi := new(big.Int).Mul(interfaceCeil(interfaceU(load[1]), page), page)
	return interfaceInterval{lo, interfaceAdd(hi, -1)}
}

type interfaceVerdict struct {
	premise string
	base    interfaceInterval
	allowed []interfaceInterval
}

func interfaceOracle(t testing.TB, f TransitionInterface, loads [][2]uint64) interfaceVerdict {
	t.Helper()
	return interfaceOracleLimits(t, f, loads, interfacePropertyLimits())
}

func interfaceOracleLimits(t testing.TB, f TransitionInterface, loads [][2]uint64, l TransitionLimits, mappings ...interfaceMapping) interfaceVerdict {
	t.Helper()
	bad := func(p string) interfaceVerdict { return interfaceVerdict{premise: p} }
	// These families supply explicit, non-default memory limits.
	if l.Bytes < 1 || l.Bytes > 1<<20 || l.Regions < 1 || l.Regions > 256 {
		return bad("transition-budget")
	}
	if len(f.Regions)+len(f.ImageRegions) > l.Regions || len(f.Words) > l.Bytes/8 {
		return bad("transition-budget")
	}
	conditions := f.Conditions
	if conditions.CPUID != "" && conditions.CPUID != CPUIDModel {
		return bad("transition-primitive-model")
	}
	conditions.CPUID = ""
	if conditions != interfaceConditions() {
		return bad("transition-premises")
	}
	d := f.Origin
	ceiling := new(big.Int).Lsh(big.NewInt(1), 47)
	m := interfaceU(d.Modulus)
	if d.Min > d.Max || interfaceU(d.Max).Cmp(ceiling) >= 0 || d.Modulus == 0 || m.Cmp(ceiling) > 0 || d.Residue >= d.Modulus {
		return bad("transition-origin")
	}
	// Dividing out every factor of two is independent of the production
	// positive-power-of-two bit predicate.
	odd := new(big.Int).Set(m)
	for odd.Bit(0) == 0 {
		odd.Div(odd, big.NewInt(2))
	}
	if odd.Cmp(big.NewInt(1)) != 0 {
		return bad("transition-origin")
	}
	lo, hi, inhabited := interfaceCongruent(interfaceInterval{interfaceU(d.Min), interfaceU(d.Max)}, d)
	if d.Max-d.Min <= 256 {
		var first, last uint64
		found := false
		for s := d.Min; s <= d.Max; s++ {
			if s%d.Modulus == d.Residue {
				if !found {
					first = s
				}
				last, found = s, true
			}
		}
		if found != inhabited || found && (lo.Cmp(interfaceU(first)) != 0 || hi.Cmp(interfaceU(last)) != 0) {
			t.Fatal("enumerated bounds disagree with quotient intersection")
		}
	}
	if !inhabited {
		return bad("transition-origin")
	}
	e := f.Envelope
	if e.Start > e.End || e.Start == e.End || e.Start > 0 || e.End < 0 {
		return bad("transition-envelope")
	}
	// This obligation precedes exclusions: image collisions cannot repair
	// noncanonical envelope endpoints at either rounded extreme.
	for _, s := range []*big.Int{lo, hi} {
		for _, off := range []int64{e.Start, e.End} {
			x := interfaceAdd(s, off)
			if x.Sign() < 0 || x.Cmp(ceiling) >= 0 {
				return bad("transition-origin")
			}
		}
	}
	total := new(big.Int)
	for i, r := range f.Regions {
		if r.Bytes.Start >= r.Bytes.End || r.Bytes.Start < e.Start || r.Bytes.End > e.End {
			return bad("transition-region")
		}
		total.Add(total, new(big.Int).Sub(big.NewInt(r.Bytes.End), big.NewInt(r.Bytes.Start)))
		if total.Cmp(big.NewInt(int64(l.Bytes))) > 0 {
			return bad("transition-budget")
		}
		for _, p := range f.Regions[:i] {
			intersectionLow := max(p.Bytes.Start, r.Bytes.Start)
			intersectionHigh := min(p.Bytes.End, r.Bytes.End)
			if intersectionLow < intersectionHigh && (p.Readable != r.Readable || p.Writable != r.Writable) {
				return bad("transition-permission")
			}
		}
	}
	for _, span := range f.ImageRegions {
		if span.Start >= span.End || interfaceU(span.End).Cmp(ceiling) > 0 {
			return bad("transition-image")
		}
		total.Add(total, new(big.Int).Sub(interfaceU(span.End), interfaceU(span.Start)))
		if total.Cmp(big.NewInt(int64(l.Bytes))) > 0 {
			return bad("transition-budget")
		}
		found := -1
		for j, m := range mappings {
			if span.Start >= m.start && span.Start < m.end && span.End <= m.end {
				found = j
			}
		}
		if found < 0 {
			return bad("transition-image")
		}
		m := mappings[found]
		if m.filesz != 0 || m.file%4096 != 0 {
			p := interfacePageExtent([2]uint64{m.file, m.file + m.filesz})
			for j, other := range mappings {
				if j == found || other.filesz == 0 && other.file%4096 == 0 {
					continue
				}
				q := interfacePageExtent([2]uint64{other.file, other.file + other.filesz})
				if p.lo.Cmp(q.hi) <= 0 && q.lo.Cmp(p.hi) <= 0 {
					return bad("frame-alias")
				}
			}
		}
	}
	result := interfaceVerdict{base: interfaceInterval{lo, hi}}
	result.allowed = []interfaceInterval{result.base}
	for _, r := range f.Regions {
		for _, load := range loads {
			page := interfacePageExtent(load)
			// A byte offset in [a,b-1] may equal a mapped-page byte in
			// [L,H]. Their difference set is [L-(b-1),H-a].
			forbidden := interfaceInterval{
				new(big.Int).Sub(page.lo, interfaceAdd(big.NewInt(r.Bytes.End), -1)),
				new(big.Int).Sub(page.hi, big.NewInt(r.Bytes.Start)),
			}
			result.allowed = interfaceSubtract(result.allowed, forbidden)
		}
	}
	inhabited = false
	for _, q := range result.allowed {
		_, _, some := interfaceCongruent(q, d)
		inhabited = inhabited || some
	}
	if d.Max-d.Min <= 256 {
		// A second reference checks every scalar S, using page numbers of
		// absolute first/last bytes rather than translated exclusion sets.
		enumerated := false
		for s := d.Min; s <= d.Max; s++ {
			if s%d.Modulus != d.Residue {
				continue
			}
			valid := true
			for _, r := range f.Regions {
				firstPage := new(big.Int).Div(interfaceAdd(interfaceU(s), r.Bytes.Start), big.NewInt(4096))
				lastByte := new(big.Int).Sub(interfaceAdd(interfaceU(s), r.Bytes.End), big.NewInt(1))
				lastPage := new(big.Int).Div(lastByte, big.NewInt(4096))
				for _, load := range loads {
					if firstPage.Cmp(interfaceU((load[1]-1)/4096)) <= 0 && lastPage.Cmp(interfaceU(load[0]/4096)) >= 0 {
						valid = false
					}
				}
			}
			inSet := false
			for _, q := range result.allowed {
				inSet = inSet || interfaceU(s).Cmp(q.lo) >= 0 && interfaceU(s).Cmp(q.hi) <= 0
			}
			if inSet != valid {
				t.Fatalf("independent references disagree at S=%d: %+v", s, f)
			}
			enumerated = enumerated || valid
		}
		if enumerated != inhabited {
			t.Fatal("enumeration and interval congruence disagree")
		}
	}
	if !inhabited {
		return bad("transition-origin")
	}
	for _, w := range f.Words {
		end := interfaceAdd(big.NewInt(w), 8)
		readable := false
		for _, r := range f.Regions {
			if r.Readable && w >= r.Bytes.Start && end.Cmp(big.NewInt(r.Bytes.End)) <= 0 {
				readable = true
			}
		}
		if !end.IsInt64() || !readable {
			return bad("transition-word")
		}
	}
	// Equal-length integer intervals overlap iff neighbors in start order
	// overlap. This independent O(n log n) reference supports the full word
	// population without reproducing the checker's quadratic pairwise scan.
	orderedWords := slices.Clone(f.Words)
	slices.Sort(orderedWords)
	for i := 1; i < len(orderedWords); i++ {
		if big.NewInt(orderedWords[i]).Cmp(interfaceAdd(big.NewInt(orderedWords[i-1]), 8)) < 0 {
			return bad("transition-word")
		}
	}
	return result
}

func interfaceCheck(t testing.TB, image interfaceImage, face TransitionInterface) (TransitionBound, bool) {
	t.Helper()
	return interfaceCheckLimits(t, image, face, interfacePropertyLimits())
}

func interfaceCheckLimits(t testing.TB, image interfaceImage, face TransitionInterface, limits TransitionLimits) (TransitionBound, bool) {
	t.Helper()
	want := interfaceOracleLimits(t, face, image.loads, limits, image.dataLoads...)
	c, err := CheckTransition(t.Context(), image.im, face, image.proposal, limits)
	b, accepted := c.Bound()
	if want.premise != "" {
		var refusal *Refusal
		if err == nil || accepted || !errors.As(err, &refusal) || refusal.Premise != want.premise {
			t.Fatalf("interface %+v: want %s, got accepted=%v err=%v", face, want.premise, accepted, err)
		}
		return TransitionBound{}, false
	}
	if err != nil || !accepted {
		t.Fatalf("admissible interface %+v refused: %v", face, err)
	}
	if b.Entry != image.entry || b.ImageDigest != image.digest || b.Rules != TransitionRules || !reflect.DeepEqual(b.Interface, face) {
		t.Fatal("image/rule/interface dependency changed")
	}
	if b.Boundary.PC != image.entry || !reflect.DeepEqual(b.Boundary.Bytes, []byte{0xc3}) || b.Boundary.Instruction.Len != 1 || len(b.Instructions) != 0 || len(b.Accesses) != 0 {
		t.Fatal("entry cut acquired execution or lost its decoded boundary")
	}
	actual := []interfaceInterval{want.base}
	for _, excluded := range b.ExcludedOrigins {
		if excluded.Start >= excluded.End || interfaceU(excluded.Start).Cmp(want.base.lo) < 0 || interfaceU(excluded.End-1).Cmp(want.base.hi) > 0 {
			t.Fatal("out-of-domain exclusion", excluded)
		}
		actual = interfaceSubtract(actual, interfaceInterval{interfaceU(excluded.Start), interfaceU(excluded.End - 1)})
	}
	if len(actual) != len(want.allowed) {
		t.Fatalf("projected exclusion union differs: got %v want %v", actual, want.allowed)
	}
	for i := range actual {
		if actual[i].lo.Cmp(want.allowed[i].lo) != 0 || actual[i].hi.Cmp(want.allowed[i].hi) != 0 {
			t.Fatalf("projected exclusion component differs: got %v want %v", actual[i], want.allowed[i])
		}
	}
	interfaceInitialState(t, face, b)
	return b, true
}

type interfaceVariable struct {
	scope   br.Scope
	slot    uint64
	scratch bool
	sort    br.Sort
}

func interfaceInitialState(t testing.TB, f TransitionInterface, b TransitionBound) {
	t.Helper()
	if len(f.EntryImagePointers) == 0 && len(f.EntryWordUpperBounds) == 0 && !literalBool(b.EntryPredicate, 1) {
		t.Fatal("empty entry relations constrained arbitrary entry state")
	}
	// Build the exact byte-key set from the input union, not from either of
	// the checker's memory projections. Only already-budgeted faces reach here.
	want := map[stateLocation]bool{}
	for _, region := range f.Regions {
		for off := region.Bytes.Start; off < region.Bytes.End; off++ {
			want[stateLocation{off: off}] = true
		}
	}
	for _, region := range f.ImageRegions {
		for addr := region.Start; addr < region.End; addr++ {
			want[stateLocation{true, int64(addr)}] = true
		}
	}
	seen := map[interfaceVariable]bool{}
	scope := b.Origin.View().Scope
	variable := func(term br.Term, width int) {
		v := term.View()
		key := interfaceVariable{v.Scope, v.Immediate, v.Scratch, v.Sort}
		if v.Op != br.Variable || v.Sort != br.Bits(width) || v.Scope == (br.Scope{}) || v.Scope != scope || len(v.Args) != 0 || seen[key] {
			t.Fatalf("not a fresh arbitrary %d-bit variable in the origin scope: %+v", width, v)
		}
		seen[key] = true
	}
	for r, term := range b.InitialRegisters {
		variable(term, 64)
		var pointer TransitionPointer
		if r == int(RSP) {
			pointer = b.Geometry.stackPointer(0)
			if b.Origin != term {
				t.Fatal("RSP is not the quantified origin")
			}
		}
		if b.Registers[r] != (TransitionValue{Value: term, Pointer: pointer}) || b.Preserved[r] != math.MaxUint64 {
			t.Fatal("empty prefix changed register or invented provenance", r)
		}
	}
	if len(b.Words) != len(f.Words) {
		t.Fatal("word declaration inventory changed")
	}
	type lane struct {
		word br.Term
		bit  uint64
	}
	lanes := map[int64]lane{}
	for i, off := range f.Words {
		w := b.Words[i]
		if w.Bytes != (TransitionExtent{b.Geometry.stackLocation(off), 8}) {
			t.Fatal("word order or offset changed")
		}
		variable(w.Value, 64)
		for j := int64(0); j < 8; j++ {
			lanes[off+j] = lane{w.Value, uint64(j * 8)}
		}
	}
	if len(b.InitialMemory) != len(want) || len(b.Memory) != len(b.InitialMemory) {
		t.Fatal("empty prefix memory does not equal the interface union")
	}
	for i, byteValue := range b.InitialMemory {
		// Terms are immutable handles: compare each stored byte once rather
		// than recursively traversing expression graphs through reflection.
		if b.Memory[i] != byteValue {
			t.Fatal("empty prefix changed a declared byte")
		}
		key := stateByteLocation(byteValue)
		if !want[key] {
			t.Fatal("extra or duplicate byte", byteValue.offset)
		}
		delete(want, key)
		if byteValue.Pointer != nil || byteValue.PointerLane != 0 || byteValue.Value.Sort() != br.Bits(8) {
			t.Fatal("initial byte acquired pointer meaning or wrong width")
		}
		if w, ok := lanes[byteValue.offset]; ok && !byteValue.isImage() {
			v := byteValue.Value.View()
			if v.Op != br.Extract || v.Immediate != w.bit || len(v.Args) != 1 || v.Args[0] != w.word {
				t.Fatal("grouped bytes do not alias the exact arbitrary word in little-endian order")
			}
		} else {
			variable(byteValue.Value, 8)
		}
	}
	if len(want) != 0 {
		t.Fatal("missing declared byte")
	}
	for _, flag := range []TransitionFlag{b.Flags.CF, b.Flags.OF, b.Flags.SF, b.Flags.ZF, b.Flags.AF, b.Flags.PF} {
		if !flag.Preserved || !flag.Defined || flag.Value.Valid() {
			t.Fatal("empty prefix constrained an arbitrary entry flag")
		}
	}
}

// Full-width fields are decoded without folding, clamping, ordering, or modular
// reduction. Lists use 17-byte region and 8-byte word records; partial records
// are zero-padded. Larger lists retain the first over-limit inventory, which is
// sufficient to exercise budget refusal without allocating attacker-sized maps.
func interfacePayload(regions, words []byte) ([]RelativeRegion, []int64) {
	return interfaceRecords(regions, words, 256, 64)
}

// The limits describe each generator's admitted inventories. Retain one extra
// record so the checker, rather than the generator, exercises the overflow case.
// This is shared input plumbing, not an independent semantic reference oracle.
func interfaceRecords(regions, words []byte, regionLimit, wordLimit int) ([]RelativeRegion, []int64) {
	var rs []RelativeRegion
	var ws []int64
	for len(regions) != 0 && len(rs) <= regionLimit {
		var record [17]byte
		n := copy(record[:], regions)
		regions = regions[n:]
		rs = append(rs, RelativeRegion{RelativeSpan{int64(binary.LittleEndian.Uint64(record[:8])), int64(binary.LittleEndian.Uint64(record[8:16]))}, record[16]&1 != 0, record[16]&2 != 0})
	}
	for len(words) != 0 && len(ws) <= wordLimit {
		var record [8]byte
		n := copy(record[:], words)
		words = words[n:]
		ws = append(ws, int64(binary.LittleEndian.Uint64(record[:])))
	}
	return rs, ws
}

func interfaceEncode(f TransitionInterface) ([]byte, []byte) {
	var regions, words []byte
	for _, r := range f.Regions {
		regions = binary.LittleEndian.AppendUint64(regions, uint64(r.Bytes.Start))
		regions = binary.LittleEndian.AppendUint64(regions, uint64(r.Bytes.End))
		var permissions byte
		if r.Readable {
			permissions |= 1
		}
		if r.Writable {
			permissions |= 2
		}
		regions = append(regions, permissions)
	}
	for _, w := range f.Words {
		words = binary.LittleEndian.AppendUint64(words, uint64(w))
	}
	return regions, words
}

func TestTransitionRecordPopulations(t *testing.T) {
	// The same serialized input feeds populations with different word limits.
	// Each must retain the first excess item rather than silently clipping a
	// malformed inventory back into its admitted range.
	rawRegions := make([]byte, 17*258)
	rawWords := make([]byte, 8*(interfaceMaxBytes/8+2))
	for i := 0; i < len(rawWords)/8; i++ {
		binary.LittleEndian.PutUint64(rawWords[i*8:], uint64(i))
	}
	smallRegions, small := interfacePayload(rawRegions, rawWords)
	largeRegions, large := interfaceRecords(rawRegions, rawWords, 256, interfaceMaxBytes/8)
	if len(smallRegions) != 257 || len(largeRegions) != 257 || len(small) != 65 || len(large) != interfaceMaxBytes/8+1 {
		t.Fatalf("record population changed: regions=%d/%d words=%d/%d", len(smallRegions), len(largeRegions), len(small), len(large))
	}
	if small[64] != 64 || large[len(large)-1] != interfaceMaxBytes/8 || !slices.Equal(small, large[:len(small)]) {
		t.Fatal("record order or first excess item changed")
	}
	regions, words := interfaceRecords([]byte{0xff, 0x80}, []byte{0x81}, 256, 64)
	if len(regions) != 1 || regions[0] != (RelativeRegion{Bytes: RelativeSpan{Start: 0x80ff}}) || len(words) != 1 || words[0] != 0x81 {
		t.Fatal("partial records lost their zero padding", regions, words)
	}
}

func FuzzTransitionInterfaceAdmissibility(f *testing.F) {
	seed := func(face TransitionInterface, image uint8) {
		r, w := interfaceEncode(face)
		f.Add(face.Origin.Min, face.Origin.Max, face.Origin.Modulus, face.Origin.Residue, face.Envelope.Start, face.Envelope.End, r, w, image)
	}
	for image := uint8(0); image < 5; image++ {
		for power := uint(0); power <= 47; power++ {
			modulus := uint64(1) << power
			seed(TransitionInterface{Origin: OriginDomain{1 << 40, 1<<40 + 64, modulus, (1 << 40) % modulus}, Envelope: RelativeSpan{-32, 64}, Regions: []RelativeRegion{{RelativeSpan{-17, 33}, true, true}}, Words: []int64{17, -9, 0}}, image)
		}
		for _, d := range []OriginDomain{
			{0, 0, 1 << 47, 0}, {1<<47 - 2, 1<<47 - 2, 1 << 47, 1<<47 - 2},
			{0, 0, 1 << 48, 0}, {0, 0, 1 << 63, 0},
			{64, 1<<47 - 128, 1, 0}, {65, 1<<47 - 128, 16, 7},
			{testEntry - 1, testEntry + 1, 1, 0}, {testEntry + 4095, testEntry + 4097, 2, 1},
			{0, math.MaxUint64, 1, 0}, {8, 7, 1, 0}, {0, 63, 0, 0}, {0, 63, 3, 0},
			{0, 63, 16, 16}, {1, 15, 16, 0}, {0, 63, math.MaxUint64, math.MaxUint64},
		} {
			seed(TransitionInterface{Origin: d, Envelope: RelativeSpan{0, 1}}, image)
		}
		for _, e := range []RelativeSpan{{math.MinInt64, math.MaxInt64}, {-1, 0}, {0, 0}, {1, 2}, {-2, -1}, {2, -2}} {
			seed(TransitionInterface{Origin: OriginDomain{1<<47 - 1, 1<<47 - 1, 1, 0}, Envelope: e}, image)
		}
		seed(TransitionInterface{Origin: OriginDomain{64, 1<<47 - 128, 32, 7}, Envelope: RelativeSpan{-32, 64}, Regions: []RelativeRegion{{RelativeSpan{-17, 33}, true, true}, {RelativeSpan{-4, 4}, true, true}, {RelativeSpan{40, 42}, false, false}}, Words: []int64{17, -9, 0}}, image)
		seed(TransitionInterface{Origin: OriginDomain{64, 1<<47 - 128, 1, 0}, Envelope: RelativeSpan{-32, 64}, Regions: []RelativeRegion{{RelativeSpan{0, 4}, true, false}, {RelativeSpan{4, 8}, true, false}}, Words: []int64{0}}, image)
	}
	f.Fuzz(func(t *testing.T, low, high, modulus, residue uint64, start, end int64, regions, words []byte, image uint8) {
		rs, ws := interfacePayload(regions, words)
		face := TransitionInterface{Origin: OriginDomain{low, high, modulus, residue}, Envelope: RelativeSpan{start, end}, Regions: rs, Words: ws, Conditions: interfaceConditions()}
		interfaceCheck(t, interfaceFixture(t, image), face)
	})
}

// Unlike the full-interface fuzz target, this family keeps the origin and
// envelope admissible so mutations in arbitrary region/word payloads reach
// their own obligations. Full signed offsets are still decoded verbatim.
func FuzzTransitionInterfaceMemoryAdmissibility(f *testing.F) {
	for _, face := range []TransitionInterface{
		{},
		{Regions: []RelativeRegion{{RelativeSpan{-17, 33}, true, true}}, Words: []int64{17, -9, 0}},
		{Regions: []RelativeRegion{{RelativeSpan{0, 1}, false, false}}},
		{Regions: []RelativeRegion{{RelativeSpan{0, 4}, true, false}, {RelativeSpan{4, 8}, true, false}}, Words: []int64{0}},
		{Regions: []RelativeRegion{{RelativeSpan{0, 16}, true, true}}, Words: []int64{8, 0}},
		{Regions: []RelativeRegion{{RelativeSpan{0, 16}, true, true}}, Words: []int64{7, 0}},
		{Regions: []RelativeRegion{{RelativeSpan{0, 8}, true, false}, {RelativeSpan{0, 8}, true, true}}},
		{Regions: []RelativeRegion{{RelativeSpan{math.MinInt64, math.MaxInt64}, true, true}}, Words: []int64{math.MinInt64, math.MaxInt64}},
		{Regions: []RelativeRegion{{RelativeSpan{-1, 1 << 40}, false, false}}},
		{Regions: []RelativeRegion{{RelativeSpan{0, 256}, false, false}, {RelativeSpan{0, 256}, false, false}}},
		{Regions: []RelativeRegion{{RelativeSpan{0, 256}, false, false}, {RelativeSpan{0, 257}, false, false}}},
	} {
		r, w := interfaceEncode(face)
		for image := uint8(0); image < 5; image++ {
			f.Add(r, w, image)
		}
	}
	for _, count := range []int{256, 257} {
		face := TransitionInterface{}
		for i := 0; i < count; i++ {
			face.Regions = append(face.Regions, RelativeRegion{RelativeSpan{0, 1}, false, false})
		}
		r, w := interfaceEncode(face)
		f.Add(r, w, uint8(0))
	}
	for _, count := range []int{64, 65} {
		face := TransitionInterface{Regions: []RelativeRegion{{RelativeSpan{1, 513}, true, false}}}
		for i := count - 1; i >= 0; i-- {
			face.Words = append(face.Words, 1+int64(i)*8)
		}
		r, w := interfaceEncode(face)
		f.Add(r, w, uint8(0))
	}
	f.Fuzz(func(t *testing.T, regions, words []byte, image uint8) {
		rs, ws := interfacePayload(regions, words)
		face := TransitionInterface{Origin: OriginDomain{1 << 41, 1 << 46, 1, 0}, Envelope: RelativeSpan{-1 << 40, 1 << 40}, Regions: rs, Words: ws, Conditions: interfaceConditions()}
		interfaceCheck(t, interfaceFixture(t, image), face)
	})
}

func TestTransitionInterfacePositiveProperties(t *testing.T) {
	fixtures := make([]interfaceImage, 5)
	for i := range fixtures {
		fixtures[i] = interfaceFixture(t, uint8(i))
	}
	if err := quick.Check(func(seed uint64, shape uint8, payload []byte) bool {
		// Construct a genuinely inhabited wide domain for every exponent,
		// including 47. The guaranteed member is away from all fixture pages;
		// this is a generator, not the reference admissibility calculation.
		pivot := uint64(1<<40) + seed%(1<<40)
		modulus := uint64(1) << (shape % 48)
		face := TransitionInterface{Origin: OriginDomain{64, 1<<47 - 65, modulus, pivot % modulus}, Envelope: RelativeSpan{-32, 64}, Conditions: interfaceConditions()}
		if shape&3 != 0 {
			read, write := seed&1 != 0, seed&2 != 0
			face.Regions = []RelativeRegion{{RelativeSpan{-31, 33}, read, write}}
			for _, p := range payload[:min(len(payload), 255)] {
				off := int64(p%64) - 31
				face.Regions = append(face.Regions, RelativeRegion{RelativeSpan{off, off + 1}, read, write})
			}
			if read {
				// Unaligned, arbitrary declaration order and disjoint groups.
				face.Words = []int64{17, -17, -1}
			}
		}
		x := fixtures[int(shape)%len(fixtures)]
		first, ok := interfaceCheck(t, x, face)
		if !ok {
			t.Fatal("positive generator did not produce an admissible interface")
		}
		second, ok := interfaceCheck(t, x, face)
		if !ok || first.Origin.View().Scope == second.Origin.View().Scope {
			t.Fatal("independent checks borrowed a quantified entry namespace")
		}
		return true
	}, &quick.Config{MaxCount: 192, Rand: rand.New(rand.NewSource(77119))}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionInterfaceFullWidthProperties(t *testing.T) {
	x := interfaceFixture(t, 3)
	if err := quick.Check(func(low, high, modulus, residue uint64, start, end int64, regions, words []byte) bool {
		rs, ws := interfacePayload(regions, words)
		interfaceCheck(t, x, TransitionInterface{Origin: OriginDomain{low, high, modulus, residue}, Envelope: RelativeSpan{start, end}, Regions: rs, Words: ws, Conditions: interfaceConditions()})
		return true
	}, &quick.Config{MaxCount: 256, Rand: rand.New(rand.NewSource(9181))}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionInterfaceSmallDomainProperties(t *testing.T) {
	fixtures := make([]interfaceImage, 5)
	for i := range fixtures {
		fixtures[i] = interfaceFixture(t, uint8(i))
	}
	accepted, refused := 0, 0
	if err := quick.Check(func(selector uint8, jitter int8, width uint8, shape uint64) bool {
		x := fixtures[int(selector)%len(fixtures)]
		load := x.loads[int(shape%uint64(len(x.loads)))]
		// Around both ends of every fixture mapping page, with one-point
		// domains included. Enumerate every origin, not just endpoint samples.
		pageEdge := (load[0] / 4096) * 4096
		if selector&8 != 0 {
			pageEdge = ((load[1] + 4095) / 4096) * 4096
		}
		low := uint64(int64(pageEdge) + int64(jitter))
		modulus := uint64(1) << (selector % 9)
		face := TransitionInterface{Origin: OriginDomain{low, low + uint64(width), modulus, shape % modulus}, Envelope: RelativeSpan{-24, 24}, Conditions: interfaceConditions()}
		for i := 0; i < int(selector%7); i++ {
			a := int64((shape>>uint(i*7))%40) - 20
			face.Regions = append(face.Regions, RelativeRegion{RelativeSpan{a, a + int64(1+(shape>>uint(i*7+3))%4)}, selector&16 != 0, selector&32 != 0})
		}
		_, ok := interfaceCheck(t, x, face)
		if ok {
			accepted++
		} else {
			refused++
		}
		return true
	}, &quick.Config{MaxCount: 384, Rand: rand.New(rand.NewSource(7718))}); err != nil {
		t.Fatal(err)
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("small-domain population lacked both outcomes: %d/%d", accepted, refused)
	}
}

func interfacePair(t testing.TB, x interfaceImage, good, bad TransitionInterface, premise string) {
	t.Helper()
	if _, ok := interfaceCheck(t, x, good); !ok {
		t.Fatal("single-violation pair lacks a positive control")
	}
	want := interfaceOracle(t, bad, x.loads)
	if want.premise != premise {
		t.Fatalf("pair's intended %s violation is masked by %s: %+v", premise, want.premise, bad)
	}
	if _, ok := interfaceCheck(t, x, bad); ok {
		t.Fatal("single violation accepted")
	}
}

func TestTransitionInterfaceSingleViolationProperties(t *testing.T) {
	x := interfaceFixture(t, 0)
	if err := quick.Check(func(seed uint64) bool {
		base := uint64(1<<40) + seed%(1<<30)
		good := TransitionInterface{Origin: OriginDomain{base, base + 32, 1, 0}, Envelope: RelativeSpan{-32, 64}, Regions: []RelativeRegion{{RelativeSpan{-17, 33}, true, true}}, Words: []int64{17, -9}, Conditions: interfaceConditions()}
		cases := []struct {
			premise string
			change  func(*TransitionInterface)
		}{
			{"transition-origin", func(f *TransitionInterface) { f.Origin.Min = f.Origin.Max + 1 }},
			{"transition-origin", func(f *TransitionInterface) { f.Origin.Max = 1 << 47 }},
			{"transition-origin", func(f *TransitionInterface) { f.Origin.Modulus = 0 }},
			{"transition-origin", func(f *TransitionInterface) { f.Origin.Modulus = 3 }},
			{"transition-origin", func(f *TransitionInterface) { f.Origin.Modulus = 1 << 48 }},
			{"transition-origin", func(f *TransitionInterface) { f.Origin.Residue = 1 }},
			{"transition-origin", func(f *TransitionInterface) { f.Envelope.Start = math.MinInt64 }},
			{"transition-origin", func(f *TransitionInterface) { f.Envelope.End = math.MaxInt64 }},
			{"transition-envelope", func(f *TransitionInterface) { f.Envelope = RelativeSpan{1, 64} }},
			{"transition-envelope", func(f *TransitionInterface) { f.Envelope = RelativeSpan{-32, -1} }},
			{"transition-envelope", func(f *TransitionInterface) { f.Envelope = RelativeSpan{0, 0} }},
			{"transition-envelope", func(f *TransitionInterface) { f.Envelope = RelativeSpan{1, -1} }},
			{"transition-region", func(f *TransitionInterface) { f.Regions[0].Bytes.Start = -33 }},
			{"transition-region", func(f *TransitionInterface) { f.Regions[0].Bytes.End = 65 }},
			{"transition-region", func(f *TransitionInterface) { f.Regions[0].Bytes.End = -17 }},
			{"transition-region", func(f *TransitionInterface) { f.Regions[0].Bytes.End = -18 }},
			{"transition-permission", func(f *TransitionInterface) {
				f.Regions = append(f.Regions, RelativeRegion{RelativeSpan{0, 1}, false, true})
			}},
			{"transition-permission", func(f *TransitionInterface) {
				f.Regions = append(f.Regions, RelativeRegion{RelativeSpan{0, 1}, true, false})
			}},
			{"transition-word", func(f *TransitionInterface) { f.Words = append(f.Words, 24) }},
			{"transition-word", func(f *TransitionInterface) { f.Words = append(f.Words, 17) }},
			{"transition-word", func(f *TransitionInterface) { f.Words[0] = 26 }},
			{"transition-word", func(f *TransitionInterface) { f.Words[0] = math.MaxInt64 }},
			{"transition-word", func(f *TransitionInterface) { f.Words[0] = math.MinInt64 }},
			{"transition-word", func(f *TransitionInterface) { f.Regions[0].Readable = false }},
		}
		for _, c := range cases {
			bad := good
			bad.Regions = append([]RelativeRegion(nil), good.Regions...)
			bad.Words = append([]int64(nil), good.Words...)
			c.change(&bad)
			interfacePair(t, x, good, bad, c.premise)
		}
		return true
	}, &quick.Config{MaxCount: 24, Rand: rand.New(rand.NewSource(18813))}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionInterfaceConditionsAndELFEntryProperties(t *testing.T) {
	x := interfaceFixture(t, 4) // ELF entry is the second RET, not testEntry.
	if err := quick.Check(func(seed uint64, machine string) bool {
		origin := uint64(1<<40) + seed%(1<<30)
		good := TransitionInterface{Origin: OriginDomain{origin, origin, 1, 0}, Envelope: RelativeSpan{0, 1}, Conditions: interfaceConditions()}
		for missing := 0; missing < 8; missing++ {
			bad := good
			switch missing {
			case 0:
				bad.Conditions.Machine = ""
			case 1:
				bad.Conditions.InstructionMapping = false
			case 2:
				bad.Conditions.EntryState = false
			case 3:
				bad.Conditions.IsolatedExecution = false
			case 4:
				bad.Conditions.MemoryMapping = false
			case 5:
				bad.Conditions.NoHiddenAliases = false
			case 6:
				bad.Conditions.UnalignedAccess = false
			case 7:
				if machine == MachineModel {
					machine += "?"
				}
				bad.Conditions.Machine = machine
			}
			interfacePair(t, x, good, bad, "transition-premises")
		}
		proposal := x.proposal
		// Both starts are genuine mapped RETs. Even a self-consistent candidate
		// cannot replace the executable format's entry with the other one.
		proposal.Entry, proposal.Cut = testEntry, testEntry
		proposal.Root = 1
		proposal.Nodes = []TransitionNode{{ID: 1, PC: testEntry, Size: 1}}
		c, err := CheckTransition(t.Context(), x.im, good, proposal, interfacePropertyLimits())
		var refusal *Refusal
		if _, ok := c.Bound(); ok || !errors.As(err, &refusal) || refusal.Premise != "transition-proposal" {
			t.Fatalf("candidate replaced actual ELF entry: %v", err)
		}
		return true
	}, &quick.Config{MaxCount: 16, Rand: rand.New(rand.NewSource(7981))}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionInterfacePageUnionProperties(t *testing.T) {
	x := interfaceFixture(t, 0)
	if err := quick.Check(func(reverse bool, permissions uint8) bool {
		for _, distance := range []int64{4095, 4096, 4097} {
			// Translating two one-byte regions yields overlapping, adjacent,
			// or one-integer-separated forbidden sets. The gap in the last
			// case is meaningful only if the congruence admits that integer.
			face := TransitionInterface{Origin: OriginDomain{testEntry, testEntry + uint64(distance) + 4096, 1, 0}, Envelope: RelativeSpan{-8192, 1}, Conditions: interfaceConditions()}
			face.Regions = []RelativeRegion{{RelativeSpan{0, 1}, permissions&1 != 0, permissions&2 != 0}, {RelativeSpan{-distance, -distance + 1}, permissions&1 != 0, permissions&2 != 0}}
			if reverse {
				face.Regions[0], face.Regions[1] = face.Regions[1], face.Regions[0]
			}
			bad := face
			bad.Origin.Max--
			if distance == 4097 {
				// Keep precisely one congruent gap origin, then change only
				// the residue so that the surviving integer is inadmissible.
				face.Origin.Max = testEntry + 8192
				face.Origin.Modulus = 8192
				face.Origin.Residue = (testEntry + 4096) % 8192
				bad = face
				bad.Origin.Residue = testEntry % 8192
			}
			interfacePair(t, x, face, bad, "transition-origin")
		}
		return true
	}, &quick.Config{MaxCount: 32, Rand: rand.New(rand.NewSource(119))}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionInterfaceEveryMappingProperties(t *testing.T) {
	fixtures := make([]interfaceImage, 5)
	for i := range fixtures {
		fixtures[i] = interfaceFixture(t, uint8(i))
	}
	if err := quick.Check(func(delta int8, permissions uint8) bool {
		for _, x := range fixtures {
			for _, load := range x.loads {
				// For every mapped page (not just executable/file-backed
				// bytes), a one-point domain collides even without grants.
				for page := load[0] / 4096; page <= (load[1]-1)/4096; page++ {
					off := int64(delta)
					goodOrigin := uint64(1 << 40)
					good := TransitionInterface{Origin: OriginDomain{goodOrigin, goodOrigin, 1 << 47, goodOrigin}, Envelope: RelativeSpan{-256, 256}, Regions: []RelativeRegion{{RelativeSpan{off, off + 1}, permissions&1 != 0, permissions&2 != 0}}, Conditions: interfaceConditions()}
					bad := good
					badOrigin := uint64(int64(page*4096) - off)
					bad.Origin = OriginDomain{badOrigin, badOrigin, 1 << 47, badOrigin}
					interfacePair(t, x, good, bad, "transition-origin")
				}
			}
		}
		return true
	}, &quick.Config{MaxCount: 24, Rand: rand.New(rand.NewSource(1658))}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionInterfaceRoundedEndpointProperties(t *testing.T) {
	x := interfaceFixture(t, 0)
	if err := quick.Check(func(power uint8) bool {
		modulus := uint64(1) << (1 + power%46)
		// The first invalid power must refuse even when its congruence has
		// an origin. Otherwise an empty intersection could mask a missing
		// upper-modulus rule. The legal 2^47 endpoint is the positive control.
		limitGood := TransitionInterface{Origin: OriginDomain{0, 0, 1 << 47, 0}, Envelope: RelativeSpan{0, 1}, Conditions: interfaceConditions()}
		limitBad := limitGood
		limitBad.Origin.Modulus = uint64(1) << (48 + power%16)
		interfacePair(t, x, limitGood, limitBad, "transition-origin")
		// Raw Min would underflow, but the first congruent origin does not.
		good := TransitionInterface{Origin: OriginDomain{0, modulus, modulus, modulus - 1}, Envelope: RelativeSpan{-int64(modulus - 1), 0}, Conditions: interfaceConditions()}
		bad := good
		bad.Envelope.Start--
		interfacePair(t, x, good, bad, "transition-origin")
		// Raw Max plus End would be noncanonical; rounded Max plus End is
		// the last low-canonical byte. Moving only End one byte must refuse.
		good = TransitionInterface{Origin: OriginDomain{1<<47 - modulus, 1<<47 - 1, modulus, 0}, Envelope: RelativeSpan{0, int64(modulus - 1)}, Conditions: interfaceConditions()}
		bad = good
		bad.Envelope.End++
		interfacePair(t, x, good, bad, "transition-origin")
		// A nonempty scalar interval can still have no congruent integer.
		good = TransitionInterface{Origin: OriginDomain{1, modulus, modulus, 0}, Envelope: RelativeSpan{0, 1}, Conditions: interfaceConditions()}
		bad = good
		bad.Origin.Max--
		interfacePair(t, x, good, bad, "transition-origin")
		return true
	}, &quick.Config{MaxCount: 48, Rand: rand.New(rand.NewSource(8771))}); err != nil {
		t.Fatal(err)
	}
	// S=0 is page-excluded by [S+testEntry,S+testEntry+1). Nevertheless
	// changing the envelope to include -1 must fail its pre-exclusion check;
	// testing only the remaining origins (S>=4096) would incorrectly accept.
	good := TransitionInterface{Origin: OriginDomain{0, 8192, 1, 0}, Envelope: RelativeSpan{0, int64(testEntry + 1)}, Regions: []RelativeRegion{{RelativeSpan{int64(testEntry), int64(testEntry + 1)}, false, false}}, Conditions: interfaceConditions()}
	bad := good
	bad.Envelope.Start = -1
	interfacePair(t, x, good, bad, "transition-origin")
	// The same ordering obligation holds at the upper rounded endpoint.
	last := uint64(1<<47 - 1)
	off := int64(testEntry) - int64(last)
	good = TransitionInterface{Origin: OriginDomain{last - 8192, last, 1, 0}, Envelope: RelativeSpan{off, 0}, Regions: []RelativeRegion{{RelativeSpan{off, off + 1}, false, false}}, Conditions: interfaceConditions()}
	bad = good
	bad.Envelope.End = 1
	interfacePair(t, x, good, bad, "transition-origin")
}

func TestTransitionInterfaceMemoryPopulationProperties(t *testing.T) {
	x := interfaceFixture(t, 2)
	if err := quick.Check(func(seed uint64, offset int8) bool {
		origin := uint64(1<<40) + seed%(1<<30)
		base := TransitionInterface{Origin: OriginDomain{origin, origin, 1, 0}, Envelope: RelativeSpan{-256, 1024}, Conditions: interfaceConditions()}
		// Duplicate lengths count against the budget; union cardinality is
		// independently checked as 256 rather than 512 on the accepted side.
		good := base
		good.Regions = []RelativeRegion{{RelativeSpan{0, 256}, false, false}, {RelativeSpan{0, 256}, false, false}}
		bad := good
		bad.Regions = append(append([]RelativeRegion(nil), good.Regions...), RelativeRegion{RelativeSpan{0, 1}, false, false})
		interfacePair(t, x, good, bad, "transition-budget")
		// Maximum region population is represented directly, and the first
		// over-limit population refuses without byte materialization.
		good = base
		for i := 0; i < 256; i++ {
			good.Regions = append(good.Regions, RelativeRegion{RelativeSpan{0, 1}, false, false})
		}
		bad = good
		bad.Regions = append(append([]RelativeRegion(nil), good.Regions...), good.Regions[0])
		interfacePair(t, x, good, bad, "transition-budget")
		// All 64 budgeted words, ordered backwards, at unaligned addresses.
		good = base
		good.Regions = []RelativeRegion{{RelativeSpan{1, 513}, true, false}}
		for i := int64(63); i >= 0; i-- {
			good.Words = append(good.Words, 1+8*i)
		}
		bad = good
		bad.Words = append(append([]int64(nil), good.Words...), 1)
		interfacePair(t, x, good, bad, "transition-budget")
		// A region of arbitrary large extent stays an interval in the oracle;
		// the checker must reject its sum, not allocate its apparent memory.
		good = base
		good.Envelope = RelativeSpan{0, 1 << 40}
		good.Regions = []RelativeRegion{{RelativeSpan{0, 512}, true, false}}
		bad = good
		bad.Regions = []RelativeRegion{{RelativeSpan{0, int64(513 + seed%(1<<40-513))}, true, false}}
		interfacePair(t, x, good, bad, "transition-budget")
		// Adjacent regions grant no single-region eight-byte word allowance.
		off := int64(offset)
		good = base
		good.Regions = []RelativeRegion{{RelativeSpan{off, off + 8}, true, true}}
		good.Words = []int64{off}
		bad = good
		bad.Regions = []RelativeRegion{{RelativeSpan{off, off + 4}, true, true}, {RelativeSpan{off + 4, off + 8}, true, true}}
		interfacePair(t, x, good, bad, "transition-word")
		// Touching words are disjoint. A one-byte shift creates overlap even
		// though both words remain entirely readable in the same region.
		good.Regions = []RelativeRegion{{RelativeSpan{off, off + 16}, true, true}}
		good.Words = []int64{off + 8, off}
		bad = good
		bad.Words = []int64{off + 7, off}
		interfacePair(t, x, good, bad, "transition-word")
		// Touching permission extents may differ; extending one by a byte
		// produces exactly an overlap conflict, independent of word rules.
		good.Words = nil
		good.Regions = []RelativeRegion{{RelativeSpan{off, off + 4}, true, false}, {RelativeSpan{off + 4, off + 8}, false, true}}
		bad = good
		bad.Regions = []RelativeRegion{{RelativeSpan{off, off + 5}, true, false}, {RelativeSpan{off + 4, off + 8}, false, true}}
		interfacePair(t, x, good, bad, "transition-permission")
		return true
	}, &quick.Config{MaxCount: 12, Rand: rand.New(rand.NewSource(117519))}); err != nil {
		t.Fatal(err)
	}
}

const interfaceMaxBytes = 1 << 20
const interfaceSizedWords = 8192

// Derive resource allowances from the supplied state, including both quadratic
// scans. These are generous upper bounds, not predictions of a particular tick
// count. A zero-instruction RET graph has fixed overhead; bytes need visits,
// fresh variables and two sorting projections; each word needs one variable and
// eight extracts. Registers, Boolean constants and the six arithmetic flags
// bound fixed scalar state. Copy work, permission searches, region pairs, image
// exclusions and word pairs are counted separately. No limit-normalization helper
// or measured checker work enters this calculation.
// The Boolean reports whether the complete allowance fits the host's int
// counters. On failure, negative limits deliberately refuse at the checker
// boundary; zero must not accidentally request a smaller default allowance.
func interfaceStateLimits(f TransitionInterface, image interfaceImage, budget int) (TransitionLimits, bool) {
	r, w := len(f.Regions), len(f.Words)
	total := new(big.Int)
	for _, region := range f.Regions {
		length := new(big.Int).Sub(big.NewInt(region.Bytes.End), big.NewInt(region.Bytes.Start))
		if length.Sign() > 0 {
			total.Add(total, length)
		}
	}
	// Over-budget intervals are refused before initialization. Bounding this
	// arithmetic also prevents a malformed extent from overflowing a Go int.
	n := interfaceMaxBytes + 1
	if total.Cmp(big.NewInt(int64(n))) < 0 {
		n = int(total.Int64())
	}
	levels := 0
	for remaining := n; remaining > 0; remaining /= 2 {
		levels++
	}
	product := func(factors ...int) *big.Int {
		v := big.NewInt(1)
		for _, factor := range factors {
			v.Mul(v, big.NewInt(int64(factor)))
		}
		return v
	}
	pairs := func(count int) *big.Int {
		if count < 2 {
			return new(big.Int)
		}
		return new(big.Int).Div(product(count, count-1), big.NewInt(2))
	}
	nodes := new(big.Int).Add(big.NewInt(int64(2+16+6+n)), product(9, w))
	work := big.NewInt(256)
	for _, term := range []*big.Int{product(8, n), product(16, n, levels), product(32, w), product(8, r), pairs(r), pairs(w), product(w, r), product(2, r, len(image.loads))} {
		work.Add(work, term)
	}
	maxInt := interfaceU(uint64(^uint(0) >> 1))
	l := TransitionLimits{RelationLimits: RelationLimits{Instructions: 1, Nodes: -1, Work: -1, Depth: 2}, Regions: 256, Bytes: budget}
	if nodes.Sign() < 0 || work.Sign() < 0 || nodes.Cmp(maxInt) > 0 || work.Cmp(maxInt) > 0 {
		return l, false
	}
	l.Nodes, l.Work = int(nodes.Int64()), int(work.Int64())
	return l, true
}

// Generate a byte union of exactly size bytes, independently of Bound. Regions
// partition it at word-slot boundaries; declaration order, permissions, word
// selection and word order vary. The final partial slot remains arbitrary bytes.
// Offsets are signed and need not be aligned. An excess word inventory is kept,
// not silently shrunk, so its resource/readability refusal is observable.
func interfaceSizedFace(size, wordCount int, offset int32, layout []byte, seed uint64) TransitionInterface {
	start, end := int64(offset), int64(offset)+int64(size)
	face := TransitionInterface{Origin: OriginDomain{1 << 40, 1 << 41, 1, 0}, Envelope: RelativeSpan{min(0, start), max(1, end)}, Conditions: interfaceConditions()}
	rng := rand.New(rand.NewSource(int64(seed)))
	slots := size / 8
	if size != 0 {
		regions := min(len(layout)+1, 256, max(1, slots))
		for i := 0; i < regions; i++ {
			lo := start + int64(8*(i*slots/regions))
			hi := start + int64(8*((i+1)*slots/regions))
			if i == regions-1 {
				hi = end
			}
			permissions := byte(seed)
			if i < len(layout) {
				permissions = layout[i]
			}
			face.Regions = append(face.Regions, RelativeRegion{RelativeSpan{lo, hi}, wordCount != 0 || permissions&1 != 0, permissions&2 != 0})
		}
		rng.Shuffle(len(face.Regions), func(i, j int) { face.Regions[i], face.Regions[j] = face.Regions[j], face.Regions[i] })
	}
	order := rng.Perm(slots)
	for i := 0; i < wordCount; i++ {
		slot := i
		if i < len(order) {
			slot = order[i]
		}
		face.Words = append(face.Words, start+8*int64(slot))
	}
	return face
}

// The implemented byte domain is every size 0..1MiB+1 and every explicit budget
// 1..1MiB+1. The +1 cases exercise the first over-cap state/configuration. Word
// counts here are 0..8192; the aggregate family below checks the
// entire 0..Bytes/8 inventory. Values outside this documented generator domain
// are skipped rather than folded into different states.
//
// Every successful case calls the root checker and checks the whole initialized
// state, including the 1MiB seed. There is no validate-only substitute here.
func FuzzTransitionInterfaceSizedInitialState(f *testing.F) {
	for _, seed := range []struct {
		size, budget uint32
		words        uint16
		offset       int32
		layout       []byte
	}{
		{513, 513, 0, -257, nil},
		{1024, 1024, 65, -33, []byte{0, 1, 2, 3}},
		{65536, 65536, 129, 100003, []byte{3, 2, 1, 0, 3}},
		{16384, 65536, 2048, -100001, []byte{1, 2, 3}},
		{interfaceMaxBytes, interfaceMaxBytes, 65, -524287, []byte{0, 1, 2, 3}},
		{interfaceMaxBytes + 1, interfaceMaxBytes, 0, 1, nil},
		{513, interfaceMaxBytes + 1, 65, 1, nil},
		{520, 513, 65, 1, nil},
		{0, 1, 0, 0, nil},
	} {
		f.Add(seed.size, seed.budget, seed.words, seed.offset, seed.layout, uint64(91871))
	}
	f.Fuzz(func(t *testing.T, size, budget uint32, words uint16, offset int32, layout []byte, seed uint64) {
		if size > interfaceMaxBytes+1 || budget < 1 || budget > interfaceMaxBytes+1 || words > interfaceSizedWords {
			t.Skip("outside sized-state generator domain")
		}
		x := interfaceFixture(t, uint8(seed))
		face := interfaceSizedFace(int(size), int(words), offset, layout[:min(len(layout), 255)], seed)
		limits, representable := interfaceStateLimits(face, x, int(budget))
		if !representable {
			t.Fatal("sized-state allowance unexpectedly exceeds host counters")
		}
		_, accepted := interfaceCheckLimits(t, x, face, limits)
		want := budget <= interfaceMaxBytes && size <= budget && uint32(words) <= size/8
		if accepted != want {
			t.Fatalf("constructed sized-state acceptance=%v want=%v (size=%d budget=%d words=%d)", accepted, want, size, budget, words)
		}
	})
}

// The aggregate inventory spans 0..131072 words, plus the first over-cap count,
// under explicit budgets 1..1MiB+1. Every representable case is checked as ONE
// whole inventory against the independent interval/congruence/permission oracle,
// with complete initial-state keysets, freshness, word aliases and register
// checks. An accepted aggregate places every word in the same fresh namespace.
// The single maximum seed is also the maximum-aggregate regression; there is no
// duplicate standalone maximum check. Image-layout populations are separate:
// this family uses the fixed one-RET mapping, including at the maximum seed.
//
// Hosts whose int cannot express the derived full allowance check explicit
// refusal and establish no accepted aggregate claim for that case. Generator
// values outside the stated domain are skipped, never folded into smaller cases.
func FuzzTransitionInterfaceAggregateWords(f *testing.F) {
	for _, seed := range [][2]uint32{
		{513, 64}, {520, 65}, {65536, 2048}, {65536, 8192},
		{interfaceMaxBytes, interfaceMaxBytes / 8},
		{interfaceMaxBytes, interfaceMaxBytes/8 + 1},
		{interfaceMaxBytes + 1, interfaceMaxBytes / 8}, {1, 0},
	} {
		f.Add(seed[0], seed[1], int32(100003), uint64(71519))
	}
	f.Fuzz(func(t *testing.T, budget, words uint32, offset int32, seed uint64) {
		if budget < 1 || budget > interfaceMaxBytes+1 || words > interfaceMaxBytes/8+1 {
			t.Skip("outside aggregate-word generator domain")
		}
		x := interfaceFixture(t, 0)
		face := interfaceSizedFace(max(1, 8*int(words)), int(words), offset, nil, seed)
		limits, representable := interfaceStateLimits(face, x, int(budget))
		verdict := interfaceOracleLimits(t, face, x.loads, limits)
		want := budget <= interfaceMaxBytes && words <= budget/8
		if (verdict.premise == "") != want {
			t.Fatalf("word population reference differs from constructed inventory: budget=%d words=%d verdict=%s", budget, words, verdict.premise)
		}
		if !representable {
			interfaceUnrepresentableLimits(t, x, face, limits)
			t.Logf("%d-word aggregate not accepted: host int cannot represent the complete work allowance", words)
			return
		}
		if want && words == interfaceMaxBytes/8 {
			t.Logf("checking one complete maximum aggregate: bytes=%d words=%d Nodes=%d Work=%d", interfaceMaxBytes, words, limits.Nodes, limits.Work)
		}
		_, accepted := interfaceCheckLimits(t, x, face, limits)
		if accepted != want {
			t.Fatal("whole-inventory checker differs from reference")
		}
	})
}

func interfaceUnrepresentableLimits(t testing.TB, x interfaceImage, face TransitionInterface, limits TransitionLimits) {
	t.Helper()
	if limits.Nodes >= 0 || limits.Work >= 0 {
		t.Fatal("unrepresentable resource allowance lost its refusal sentinel")
	}
	c, err := CheckTransition(t.Context(), x.im, face, x.proposal, limits)
	var refusal *Refusal
	if _, accepted := c.Bound(); accepted || !errors.As(err, &refusal) || refusal.Premise != "transition-budget" {
		t.Fatalf("unrepresentable counters supplied acceptance: %v", err)
	}
}

func TestTransitionInterfaceStateLimitArithmetic(t *testing.T) {
	x := interfaceFixture(t, 0)
	face := interfaceSizedFace(interfaceMaxBytes, interfaceMaxBytes/8, 100003, nil, 71519)
	limits, fit := interfaceStateLimits(face, x, interfaceMaxBytes)
	const maxWork uint64 = 8954904842
	const maxNodes uint64 = 2228248
	wantFit := maxWork <= uint64(^uint(0)>>1)
	if fit != wantFit {
		t.Fatalf("maximum budget representable=%v want=%v", fit, wantFit)
	}
	if fit {
		if uint64(limits.Work) != maxWork || uint64(limits.Nodes) != maxNodes {
			t.Fatalf("maximum arithmetic changed: Nodes=%d Work=%d", limits.Nodes, limits.Work)
		}
	} else {
		interfaceUnrepresentableLimits(t, x, face, limits)
	}
	if err := quick.Check(func(count uint16) bool {
		words := int(count) % (interfaceSizedWords + 1)
		f := interfaceSizedFace(max(1, 8*words), words, -33, nil, uint64(count))
		l, representable := interfaceStateLimits(f, x, interfaceMaxBytes)
		if !representable || l.Nodes <= 0 || l.Work <= 0 {
			t.Fatal("bounded materialized population lost its representable allowance")
		}
		return true
	}, &quick.Config{MaxCount: 16, Rand: rand.New(rand.NewSource(57571))}); err != nil {
		t.Fatal(err)
	}
}
