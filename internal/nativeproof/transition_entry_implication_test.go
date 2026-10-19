package nativeproof

import (
	"math"
	"math/big"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func checkEntryUpperImplication(t testing.TB, origin, word uint64, offset int64) {
	t.Helper()
	// Mathematical addition is independent of the checker's modular term and
	// canonical-offset helpers. Only domains admitted by entry validation apply.
	upper := new(big.Int).Add(new(big.Int).SetUint64(origin), big.NewInt(offset))
	if origin >= 1<<47 || upper.Sign() < 0 || upper.Cmp(new(big.Int).Lsh(big.NewInt(1), 47)) >= 0 {
		return
	}
	m := &transitionChecker{valueBuilder: &valueBuilder{ctx: t.Context(), limits: DefaultRelationLimits(), builder: br.NewBuilder(1024), depth: make(map[br.Term]int), scope: br.NewScope()}}
	m.truth, m.falsity = m.con(br.Bool(), 1), m.con(br.Bool(), 0)
	m.bound.Origin = m.scratch(br.Bits(64))
	input := m.scratch(br.Bits(64))
	predicate := m.entryWordPredicate(input, offset)
	if m.err != nil {
		t.Fatal(m.err)
	}
	want := new(big.Int).SetUint64(word).Cmp(upper) < 0
	got := stateEval(t, predicate, map[br.Term]uint64{m.bound.Origin: origin, input: word}) != 0
	if got != want {
		t.Fatalf("declared state domain changed: S=%#x word=%#x offset=%d got=%t want=%t", origin, word, offset, got, want)
	}
}

func TestTransitionEntryUpperImplication(t *testing.T) {
	for _, origin := range []uint64{0, 1, 64, 4096, 1 << 40, 1<<47 - 4096, 1<<47 - 1} {
		for _, offset := range []int64{math.MinInt64, -4096, -64, -1, 0, 1, 64, 4096, math.MaxInt64} {
			for _, word := range []uint64{0, 1, origin - 65, origin - 64, origin - 1, origin, origin + 1, math.MaxUint64} {
				checkEntryUpperImplication(t, origin, word, offset)
			}
		}
	}
}

func TestTransitionEntryUpperGuardAndInvalidDomains(t *testing.T) {
	im, face := returnFixture(t, returnFrameCode)
	face.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 24}}
	face.EntryImagePointers = []TransitionEntryImagePointer{{Register: R14, Address: imageStateAddress}}
	face.EntryWordUpperBounds = []TransitionEntryWordUpperBound{{Address: imageStateAddress + 16, OriginOffset: -64}}
	proposal := entryRelationProposal(t, im, testEntry+24, TransitionExpansion{PC: testEntry})
	c, err := CheckRegionTransition(t.Context(), im, testEntry, face, proposal, TransitionLimits{})
	if err != nil {
		t.Fatal("single stronger bound did not establish weaker actual guard", err)
	}
	if _, err := CheckTransitionReturn(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int64{-4096, -4097, math.MinInt64, 4096, math.MaxInt64} {
		bad := cloneTransitionInterface(face)
		bad.EntryWordUpperBounds[0].OriginOffset = offset
		if offset == -4096 {
			// The strongest possible admissible upper endpoint is zero. There is
			// no unsigned word below it, even though addition itself does not wrap.
			bad.Origin.Max = bad.Origin.Min
		}
		got, err := CheckRegionTransition(t.Context(), im, testEntry, bad, proposal, TransitionLimits{})
		transitionRefused(t, got, err)
	}
}

func FuzzTransitionEntryUpperImplication(f *testing.F) {
	for _, seed := range []struct {
		origin, word uint64
		offset       int64
	}{{4096, 4031, -64}, {4096, 4032, -64}, {4096, 4095, -64}, {4096, 4096, 1}, {0, 0, 0}, {1<<47 - 1, 0, -1}, {64, 0, -64}} {
		f.Add(seed.origin, seed.word, seed.offset)
	}
	f.Fuzz(func(t *testing.T, origin, word uint64, offset int64) {
		checkEntryUpperImplication(t, origin, word, offset)
		// Also exercise a nonwrapping nearby bound for arbitrary fuzz bit patterns.
		checkEntryUpperImplication(t, 4096+origin%((1<<47)-8192), word, offset%4096)
	})
}
