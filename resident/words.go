package resident

import (
	"fmt"
	"math"
)

// Words is the fleet's one spelling of a reading on a progress line:
// the moment the consumer names ("at the start", "at compile's exit",
// "at the end"), the process's set and peak, its live descendants when
// any (their summed set, their count, the largest single peak), and
// the soft ceiling the process runs under when one is installed
// (REQ-fresh-resident-readings) — so every consumer's line reads the
// same and a reader of one tool's log reads the others'. A zero Set
// renders as zero bytes: the consumer renders a reading only where the
// sampler answered one (Sample's ok).
func Words(set Set, moment string) string {
	words := fmt.Sprintf("%s: resident %s (peak %s)", moment, ByteWord(set.ProcessBytes), ByteWord(set.ProcessPeakBytes))
	if set.Descendants > 0 {
		words += fmt.Sprintf(", descendants %s (%d), largest peak %s", ByteWord(set.DescendantsBytes), set.Descendants, ByteWord(set.DescendantPeakBytes))
	}
	if set.CeilingBytes > 0 {
		words += ", ceiling " + ByteWord(set.CeilingBytes)
	}
	return words
}

// Suffix is Words as a line's tail: " — " then the words.
func Suffix(set Set, moment string) string {
	return " — " + Words(set, moment)
}

// ByteWord renders a byte count in binary units, rounded, with one
// decimal from a gibibyte up: "75 MiB", "1.0 GiB". A value that rounds
// up to the next unit renders in that unit: 1023.6 MiB is "1.0 GiB",
// never "1024 MiB".
func ByteWord(b uint64) string {
	const kib, mib, gib = 1 << 10, 1 << 20, 1 << 30
	switch {
	case b >= gib || math.Round(float64(b)/mib) >= 1024:
		return fmt.Sprintf("%.1f GiB", float64(b)/gib)
	case b >= mib || math.Round(float64(b)/kib) >= 1024:
		return fmt.Sprintf("%.0f MiB", float64(b)/mib)
	case b >= kib:
		return fmt.Sprintf("%.0f KiB", float64(b)/kib)
	}
	return fmt.Sprintf("%d B", b)
}
