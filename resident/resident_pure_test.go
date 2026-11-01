package resident

import (
	"math/rand"
	"testing"
)

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

// The ceiling is half of the room the host has for the process's
// family — what it has available plus what the family already holds —
// so a derivation taken under a held working set never installs a
// ceiling under the live heap (for example, a 16 GiB host, a
// 6 GiB heap, 6 GiB of children, 3 GiB available — 7.5 GiB, where the
// bare halving gave 1.5 GiB), and pages moving between the host's free
// pool and the family leave it unchanged; the children's budget is the
// other half, the room less the ceiling, 0 where the floor consumed the
// room or the host answers nothing; a Reading derives both exactly
// when its walk read the held set (REQ-fresh-resident-readings).
func TestCeilingIsHalfTheFamilysRoom(t *testing.T) {
	known := Reading{Set: Set{ProcessHeldBytes: 4 << 30, DescendantsHeldBytes: 8 << 30, HeldKnown: true}, Host: Memory{TotalBytes: 16 << 30, AvailableBytes: 3 << 30}}
	if c, ok := known.Ceiling(); !ok || c != 7<<30+512<<20 {
		t.Fatalf("Reading.Ceiling = %d %v, want 7.5 GiB true", c, ok)
	}
	if b, ok := known.ChildrenBudget(); !ok || b != 7<<30+512<<20 {
		t.Fatalf("Reading.ChildrenBudget = %d %v, want 7.5 GiB true", b, ok)
	}
	unknown := known
	unknown.Set.HeldKnown = false
	if c, ok := unknown.Ceiling(); ok || c != 0 {
		t.Fatalf("Reading.Ceiling over an unknown held set = %d %v, want 0 false", c, ok)
	}
	if b, ok := unknown.ChildrenBudget(); ok || b != 0 {
		t.Fatalf("Reading.ChildrenBudget over an unknown held set = %d %v, want 0 false", b, ok)
	}
	host := Memory{TotalBytes: 16 << 30, AvailableBytes: 3 << 30}
	if got := ceiling(host, 12<<30); got != 7<<30+512<<20 {
		t.Fatalf("Ceiling under a 12 GiB family with 3 GiB available = %d, want 7.5 GiB", got)
	}
	if got := childrenBudget(host, 12<<30); got != 7<<30+512<<20 {
		t.Fatalf("ChildrenBudget = %d, want the other half (7.5 GiB)", got)
	}
	// The invariance: equal rooms, equal ceilings and budgets, whatever
	// the split between the host's free pool and the family.
	r := rand.New(rand.NewSource(326))
	for i := 0; i < 200; i++ {
		room := uint64(r.Int63n(64<<30)) + 1<<20
		a, b := uint64(r.Int63n(int64(room))), uint64(r.Int63n(int64(room)))
		ma, mb := Memory{TotalBytes: 64 << 30, AvailableBytes: room - a}, Memory{TotalBytes: 64 << 30, AvailableBytes: room - b}
		if ma.AvailableBytes == 0 || mb.AvailableBytes == 0 {
			continue
		}
		if ca, cb := ceiling(ma, a), ceiling(mb, b); ca != cb {
			t.Fatalf("draw %d: room %d split %d/%d → ceilings %d vs %d", i, room, a, b, ca, cb)
		}
		if ba, bb := childrenBudget(ma, a), childrenBudget(mb, b); ba != bb || ba != max(int64(room)-ceiling(ma, a), 0) {
			t.Fatalf("draw %d: budgets %d vs %d (room %d, ceiling %d)", i, ba, bb, room, ceiling(ma, a))
		}
	}
	// The floor consumes a short room: the budget is 0, never negative.
	if got := childrenBudget(Memory{TotalBytes: 2 << 30, AvailableBytes: 300 << 20}, 100<<20); got != 0 {
		t.Fatalf("ChildrenBudget under the floor = %d, want 0", got)
	}
	if got := childrenBudget(Memory{}, 1<<30); got != 0 {
		t.Fatalf("ChildrenBudget of no reading = %d, want 0", got)
	}
	// A host with nothing available is a reading (the kernel clamps
	// availability under pressure): the room is what the family holds.
	pressed := Memory{TotalBytes: 16 << 30}
	if got := ceiling(pressed, 6<<30); got != 3<<30 {
		t.Fatalf("Ceiling with nothing available and 6 GiB held = %d, want 3 GiB", got)
	}
	if got := childrenBudget(pressed, 6<<30); got != 3<<30 {
		t.Fatalf("ChildrenBudget with nothing available and 6 GiB held = %d, want 3 GiB", got)
	}
}

// TestMeminfoParsesTheTwoHostLines pins the host reading's grammar
// (REQ-fresh-resident-readings): MemTotal and MemAvailable in
// kibibytes, both required; a malformed or missing line yields no
// reading rather than a zero one.
func TestMeminfoParsesTheTwoHostLines(t *testing.T) {
	cases := []struct {
		name string
		text string
		want Memory
		ok   bool
	}{
		{"both", "MemTotal:       128000 kB\nMemFree:  5 kB\nMemAvailable:    64000 kB\nBuffers: 1 kB\n", Memory{TotalBytes: 128000 * 1024, AvailableBytes: 64000 * 1024}, true},
		{"missing available", "MemTotal:       128000 kB\nMemFree:  5 kB\n", Memory{}, false},
		{"missing total", "MemAvailable:    64000 kB\n", Memory{}, false},
		{"wrong unit", "MemTotal:       128000 MB\nMemAvailable:    64000 kB\n", Memory{}, false},
		{"not a number", "MemTotal:       lots kB\nMemAvailable:    64000 kB\n", Memory{}, false},
		{"nothing available", "MemTotal:       128000 kB\nMemAvailable:    0 kB\n", Memory{TotalBytes: 128000 * 1024}, true},
		{"no memory", "MemTotal:       0 kB\nMemAvailable:    0 kB\n", Memory{}, false},
		{"empty", "", Memory{}, false},
	}
	for _, c := range cases {
		got, ok := parseMeminfo(c.text)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: parseMeminfo = %+v %v, want %+v %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

// TestStatusParsesTheTwoResidentLines pins the status reading over
// synthetic text: VmRSS and VmHWM in kibibytes become bytes, the held
// set is RssAnon plus RssShmem and known exactly when both are stated
// (a kernel before 4.5 states neither: the reading stands, the held
// set unknown), other lines are ignored, and a missing or malformed
// resident line — or one held line without the other — yields no
// reading rather than a zero one (the reading is absent, never zero
// (REQ-fresh-resident-readings), where the host does not answer).
func TestStatusParsesTheTwoResidentLines(t *testing.T) {
	st, ok := parseStatus("Name:\tstipulator\nVmPeak:\t 9999 kB\nVmHWM:\t  1004 kB\nVmRSS:\t   75 kB\nRssAnon:\t   50 kB\nRssFile:\t   20 kB\nRssShmem:\t   5 kB\nThreads:\t12\n")
	if want := (status{rss: 75 * 1024, peak: 1004 * 1024, held: 55 * 1024, heldKnown: true}); !ok || st != want {
		t.Fatalf("parseStatus = %+v %v, want %+v true", st, ok, want)
	}
	st, ok = parseStatus("VmHWM:\t  1004 kB\nVmRSS:\t   75 kB\n")
	if want := (status{rss: 75 * 1024, peak: 1004 * 1024}); !ok || st != want {
		t.Fatalf("parseStatus of a pre-4.5 status = %+v %v, want %+v true (the held set unknown)", st, ok, want)
	}
	for name, text := range map[string]string{
		"no peak":        "VmRSS:\t 75 kB\nRssAnon:\t 1 kB\nRssShmem:\t 0 kB\n",
		"no rss":         "VmHWM:\t 75 kB\nRssAnon:\t 1 kB\nRssShmem:\t 0 kB\n",
		"no anon":        "VmHWM:\t 75 kB\nVmRSS:\t 75 kB\nRssShmem:\t 0 kB\n",
		"no shmem":       "VmHWM:\t 75 kB\nVmRSS:\t 75 kB\nRssAnon:\t 1 kB\n",
		"malformed anon": "VmHWM:\t 75 kB\nVmRSS:\t 75 kB\nRssAnon:\t x kB\nRssShmem:\t 0 kB\n",
		"wrong unit":     "VmHWM:\t 1 mB\nVmRSS:\t 75 kB\nRssAnon:\t 1 kB\nRssShmem:\t 0 kB\n",
		"not a number":   "VmHWM:\t x kB\nVmRSS:\t 75 kB\nRssAnon:\t 1 kB\nRssShmem:\t 0 kB\n",
		"empty":          "",
		"missing value":  "VmHWM:\nVmRSS:\t 75 kB\nRssAnon:\t 1 kB\nRssShmem:\t 0 kB\n",
		"past bytes":     "VmHWM:\t 18446744073709551615 kB\nVmRSS:\t 75 kB\nRssAnon:\t 1 kB\nRssShmem:\t 0 kB\n",
	} {
		if _, ok := parseStatus(text); ok {
			t.Errorf("%s: parsed a reading from %q", name, text)
		}
	}
}

// TestStatParsesPastTheCommandName pins the stat reading: the fields
// after the parenthesized command name, which may itself carry spaces
// and parentheses, give the state and the parent pid; a short or
// malformed line yields no reading; a zombie or dead state is not live.
func TestStatParsesPastTheCommandName(t *testing.T) {
	for _, comm := range []string{"(stipulator)", "(go test (race) x)", "(a) b)"} {
		ppid, state, ok := parseStat("1234 " + comm + " S 4321 1 1 0 -1 4194560 100 0")
		if !ok || ppid != 4321 || state != 'S' {
			t.Errorf("%q: parseStat = %d %c %v, want 4321 S true", comm, ppid, state, ok)
		}
	}
	for name, line := range map[string]string{
		"no paren":  "1234 stipulator S 4321",
		"short":     "1234 (x) S",
		"bad ppid":  "1234 (x) S x 1 1",
		"bad state": "1234 (x) SS 4321 1",
	} {
		if _, _, ok := parseStat(line); ok {
			t.Errorf("%s: parsed a reading from %q", name, line)
		}
	}
	for state, want := range map[byte]bool{'S': true, 'R': true, 'D': true, 'T': true, 'Z': false, 'X': false} {
		if live(state) != want {
			t.Errorf("live(%c) = %v, want %v", state, !want, want)
		}
	}
}
