package nativeproof

import (
	"encoding/binary"
	"math"
	"math/big"
	"math/rand"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

// Extend the interface-record grammar with full-width entry-location/offset
// records, independent of instruction encodings. Partial records are zero-padded
// and the first over-budget item remains present so the checker must refuse it.
func interfaceEntryRecords(pointers, bounds []byte, wordLimit int) ([]TransitionEntryImagePointer, []TransitionEntryWordUpperBound) {
	var ps []TransitionEntryImagePointer
	var ws []TransitionEntryWordUpperBound
	for len(pointers) != 0 && len(ps) <= 15 {
		var r [9]byte
		n := copy(r[:], pointers)
		pointers = pointers[n:]
		ps = append(ps, TransitionEntryImagePointer{Register(r[0]), binary.LittleEndian.Uint64(r[1:])})
	}
	for len(bounds) != 0 && len(ws) <= wordLimit {
		var r [16]byte
		n := copy(r[:], bounds)
		bounds = bounds[n:]
		ws = append(ws, TransitionEntryWordUpperBound{binary.LittleEndian.Uint64(r[:8]), int64(binary.LittleEndian.Uint64(r[8:]))})
	}
	return ps, ws
}

func TestTransitionEntryRelationRecordPopulation(t *testing.T) {
	ps, ws := interfaceEntryRecords(make([]byte, 9*17), make([]byte, 16*66), 64)
	if len(ps) != 16 || len(ws) != 65 {
		t.Fatal("entry record grammar hid excess declarations")
	}
	ps, ws = interfaceEntryRecords([]byte{14, 0x80}, []byte{0xff}, 64)
	if ps[0] != (TransitionEntryImagePointer{R14, 128}) || ws[0] != (TransitionEntryWordUpperBound{Address: 255}) {
		t.Fatal("partial entry record changed")
	}
}

func checkEntryInterfaceRecords(t testing.TB, low, high, modulus, residue uint64, pointers, bounds []byte) {
	t.Helper()
	image := imageInterfaceFixture(t, imageStateLoads())
	face := TransitionInterface{Origin: OriginDomain{low, high, modulus, residue}, Envelope: RelativeSpan{0, 1}, Conditions: interfaceConditions(), ImageRegions: []Span{{imageStateAddress, imageStateAddress + 32}}}
	face.EntryImagePointers, face.EntryWordUpperBounds = interfaceEntryRecords(pointers, bounds, 64)
	limits := interfacePropertyLimits()
	// Reuse the independent unbounded-integer interface oracle for the base
	// memory/origin contract, then interpret the new closed grammar independently.
	want := interfaceOracleLimits(t, face, image.loads, limits, image.dataLoads...).premise == ""
	want = want && len(face.EntryImagePointers) <= 15 && len(face.EntryWordUpperBounds) <= 64
	seen := map[Register]bool{}
	for _, p := range face.EntryImagePointers {
		want = want && p.Register <= R15 && p.Register != RSP && !seen[p.Register] && p.Address >= imageStateAddress && p.Address < imageStateAddress+32
		seen[p.Register] = true
	}
	if want && len(face.EntryWordUpperBounds) != 0 {
		lo, hi, _ := interfaceCongruent(interfaceInterval{interfaceU(low), interfaceU(high)}, face.Origin)
		ceiling := new(big.Int).Lsh(big.NewInt(1), 47)
		for _, w := range face.EntryWordUpperBounds {
			addressEnd := new(big.Int).Add(interfaceU(w.Address), big.NewInt(8))
			bottom, top := interfaceAdd(lo, w.OriginOffset), interfaceAdd(hi, w.OriginOffset)
			want = want && w.Address >= imageStateAddress && addressEnd.Cmp(interfaceU(imageStateAddress+32)) <= 0 && bottom.Sign() >= 0 && top.Cmp(ceiling) < 0 && top.Sign() > 0
		}
	}
	c, err := CheckRegionTransition(t.Context(), image.im, testEntry, face, image.proposal, limits)
	if (err == nil) != want || (c.checked != nil) != want {
		t.Fatalf("entry interface %+v want %v, got %v", face, want, err)
	}
	if !want {
		return
	}
	b, _ := c.Bound()
	if len(b.Instructions) != 0 || len(b.Accesses) != 0 || b.EntryPredicate != b.CutGuard {
		t.Fatal("entry relation became execution or changed preservation")
	}
	for _, mask := range b.Preserved {
		if mask != math.MaxUint64 {
			t.Fatal("entry declaration wrote a register")
		}
	}
	for _, v := range b.InitialMemory {
		if v.Value.View().Op != br.Variable {
			t.Fatal("entry relation initialized free current memory")
		}
	}
}

func FuzzTransitionInterfaceEntryRelations(f *testing.F) {
	encode := func(ps []TransitionEntryImagePointer, ws []TransitionEntryWordUpperBound) ([]byte, []byte) {
		var pointers, bounds []byte
		for _, p := range ps {
			pointers = append(pointers, byte(p.Register))
			pointers = binary.LittleEndian.AppendUint64(pointers, p.Address)
		}
		for _, w := range ws {
			bounds = binary.LittleEndian.AppendUint64(bounds, w.Address)
			bounds = binary.LittleEndian.AppendUint64(bounds, uint64(w.OriginOffset))
		}
		return pointers, bounds
	}
	for reg := Register(0); reg <= 16; reg++ {
		for _, off := range []int64{-4097, -4096, -1, 0, 4095, 4096, math.MinInt64, math.MaxInt64} {
			ps, ws := encode([]TransitionEntryImagePointer{{reg, imageStateAddress}}, []TransitionEntryWordUpperBound{{imageStateAddress + 16, off}, {imageStateAddress + 17, off}})
			f.Add(uint64(4096), uint64(1<<47-4096), uint64(16), uint64(0), ps, ws)
		}
	}
	for _, count := range []int{64, 65} {
		ws := make([]TransitionEntryWordUpperBound, count)
		for j := range ws {
			ws[j].Address = imageStateAddress + uint64(j%25)
		}
		ps, words := encode(nil, ws)
		f.Add(uint64(4096), uint64(8192), uint64(16), uint64(0), ps, words)
	}
	f.Fuzz(func(t *testing.T, low, high, modulus, residue uint64, pointers, bounds []byte) {
		checkEntryInterfaceRecords(t, low, high, modulus, residue, pointers, bounds)
	})
}

func TestTransitionEntryRelationOverlappingBytes(t *testing.T) {
	im, face := entryRelationFixture(t, "c3")
	face.EntryWordUpperBounds = []TransitionEntryWordUpperBound{{imageStateAddress + 16, -1}, {imageStateAddress + 17, 0}, {imageStateAddress + 16, 1}}
	c := entryRelationCheck(t, im, face, entryRelationProposal(t, im, testEntry))
	b, _ := c.Bound()
	rng := rand.New(rand.NewSource(73419))
	for sample := 0; sample < 128; sample++ {
		s := uint64(1 << 40)
		v := entryRelationValues(b, s, 0)
		var raw [9]byte
		rng.Read(raw[:])
		if sample%2 == 0 {
			raw[5], raw[6], raw[7], raw[8] = 0, 0, 0, 0
		}
		for _, byteValue := range b.InitialMemory {
			i := byteValue.offset - int64(imageStateAddress+16)
			if i >= 0 && i < int64(len(raw)) {
				v[byteValue.Value] = uint64(raw[i])
			}
		}
		first, second := binary.LittleEndian.Uint64(raw[:8]), binary.LittleEndian.Uint64(raw[1:])
		want := uint64(0)
		if first < s-1 && second < s && first < s+1 {
			want = 1
		}
		if stateEval(t, b.EntryPredicate, v) != want {
			t.Fatal("overlapping antecedents did not share one byte valuation")
		}
	}
}
