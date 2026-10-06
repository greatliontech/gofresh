package resident

import "testing"

// A reading's words are one spelling: the moment, the set and peak,
// the descendants term exactly when there are any, the ceiling exactly
// when one is installed and last; the suffix is the words after an em
// dash; byte counts round to binary units, a value rounding up to the
// next unit rendering in it (REQ-fresh-resident-readings).
func TestWordsAreTheOneSpellingOfAReading(t *testing.T) {
	bare := Set{ProcessBytes: 10 << 20, ProcessPeakBytes: 20 << 20}
	if got, want := Words(bare, "at the start"), "at the start: resident 10 MiB (peak 20 MiB)"; got != want {
		t.Fatalf("Words = %q, want %q", got, want)
	}
	withChildren := Set{ProcessBytes: 10 << 20, ProcessPeakBytes: 20 << 20, Descendants: 3, DescendantsBytes: 300 << 20, DescendantPeakBytes: 150 << 20}
	if got, want := Words(withChildren, "at compile's exit"), "at compile's exit: resident 10 MiB (peak 20 MiB), descendants 300 MiB (3), largest peak 150 MiB"; got != want {
		t.Fatalf("Words with descendants = %q, want %q", got, want)
	}
	withCeiling := Set{ProcessBytes: 10 << 20, ProcessPeakBytes: 20 << 20, Descendants: 1, DescendantsBytes: 5 << 20, DescendantPeakBytes: 5 << 20, CeilingBytes: 3 << 30}
	if got, want := Words(withCeiling, "at the end"), "at the end: resident 10 MiB (peak 20 MiB), descendants 5 MiB (1), largest peak 5 MiB, ceiling 3.0 GiB"; got != want {
		t.Fatalf("Words with a ceiling = %q, want %q", got, want)
	}
	if got, want := Suffix(bare, "at the end"), " — at the end: resident 10 MiB (peak 20 MiB)"; got != want {
		t.Fatalf("Suffix = %q, want %q", got, want)
	}
	for _, tc := range []struct {
		bytes uint64
		want  string
	}{
		{0, "0 B"}, {1023, "1023 B"}, {1 << 10, "1 KiB"}, {1536, "2 KiB"},
		// The round-up cliff, one step each side: 1023.499 KiB stays,
		// 1023.5 KiB rounds up into the next unit.
		{1023<<10 + 511, "1023 KiB"}, {1023<<10 + 512, "1 MiB"},
		{1 << 20, "1 MiB"}, {75 << 20, "75 MiB"},
		{1023<<20 + 511<<10, "1023 MiB"}, {1023<<20 + 512<<10, "1.0 GiB"}, {1<<30 - 1, "1.0 GiB"},
		{1 << 30, "1.0 GiB"}, {3<<30 + 512<<20, "3.5 GiB"},
	} {
		if got := ByteWord(tc.bytes); got != tc.want {
			t.Errorf("ByteWord(%d) = %q, want %q", tc.bytes, got, tc.want)
		}
	}
}
