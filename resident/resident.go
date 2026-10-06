// Package resident reads a process's resident set: its resident and peak
// resident bytes, and its live descendants — the children a consumer
// spawns (package test binaries, go drivers, a resolver child) and
// theirs — as their count, their summed resident bytes, the largest
// single descendant's own peak, and each direct child's tree; beside it
// the host's memory and the soft ceiling a consumer installs from it.
// It is the fleet's one home for the resident datum every consumer
// states on its progress face (REQ-fresh-resident-readings): a reading
// the host answers, on Linux through /proc; a host that does not
// answer, or a /proc that cannot be listed, yields no sample, and the
// datum is absent rather than zero. A reading walks the whole process
// table once; a consumer takes it at phase transitions and endings, so
// its cost is bounded by those.
package resident

import (
	"math"
	"strconv"
	"strings"
)

// Set is one reading of a process's memory.
type Set struct {
	// ProcessBytes is the process's resident set at the reading.
	ProcessBytes uint64
	// ProcessHeldBytes is the part of the process's resident set the
	// host cannot reclaim — its anonymous and shared-memory pages
	// (RssAnon + RssShmem); the file-backed remainder is the page
	// cache's, counted in the host's own availability already.
	ProcessHeldBytes uint64
	// ProcessPeakBytes is the process's peak resident set as the kernel
	// answers it — the larger of its stored high-water mark and the
	// current set, so two readings need not be monotonic; a reader
	// wanting a monotonic peak keeps its own maximum.
	ProcessPeakBytes uint64
	// Descendants counts the process's live descendants — every process
	// whose parent chain reaches it, zombies and dead processes
	// excluded; DescendantsBytes sums their resident sets at the
	// reading, and DescendantPeakBytes is the largest single
	// descendant's own peak resident set.
	Descendants         int
	DescendantsBytes    uint64
	DescendantPeakBytes uint64
	// DescendantsHeldBytes sums the descendants' held sets (anonymous
	// and shared-memory pages) at the reading.
	DescendantsHeldBytes uint64
	// HeldKnown is true when the reading carries the family's held set:
	// the kernel states the two held lines (4.5 and later), read from
	// the process's own status — every status under one table is the
	// same kernel's, so its descendants' carry them exactly when its own
	// does. On an older kernel the two held sums are 0 and HeldKnown is
	// false — the reading stands, and nothing derives over it.
	HeldKnown bool
	// CeilingBytes is the runtime's soft memory limit in force at the
	// reading — the ceiling InstallCeiling installed, or one an operator
	// or an earlier caller set — 0 when none is in force.
	CeilingBytes uint64
}

// Sample reads the running process's set. ok is false where the host
// does not answer — not Linux, or /proc unreadable — and the Set is then
// the zero value, which no reader renders. A reading carries the
// memory limit in force beside what the kernel answers.
func Sample() (Set, bool) {
	set, ok := sample()
	if !ok {
		return Set{}, false
	}
	set.CeilingBytes = installedCeiling()
	return set, true
}

// statusKeys are the memory lines of a /proc/<pid>/status text every
// reading consumes: the resident set and its peak. heldKeys are the
// two classes the host cannot reclaim (RssAnon and RssShmem), which
// kernels 4.5 and later state: a status carrying neither reads with
// the held set unknown; one carrying either but not both well-formed
// is a memory line the walk cannot read whole, and voids the reading.
var (
	statusKeys = []string{"VmRSS", "VmHWM"}
	heldKeys   = []string{"RssAnon", "RssShmem"}
)

// status is one process's memory lines as the walk reads them: the
// resident set, its peak, and the held set with whether the status
// stated it.
type status struct {
	rss, peak, held uint64
	heldKnown       bool
}

// parseStatus reads a /proc/<pid>/status text, whose memory lines carry
// kibibytes. ok is false unless the resident lines parse and the held
// lines are either both well-formed or both absent.
func parseStatus(text string) (st status, ok bool) {
	m, _, ok := kibibyteLines(text, statusKeys...)
	if !ok {
		return status{}, false
	}
	st = status{rss: m["VmRSS"], peak: m["VmHWM"]}
	h, present, ok := kibibyteLines(text, heldKeys...)
	switch {
	case present == 0:
		return st, true
	case !ok:
		return status{}, false
	}
	st.held, st.heldKnown = h["RssAnon"]+h["RssShmem"], true
	return st, true
}

// parseDescendantStatus reads a live descendant's status: leaving is
// true when the text carries no resident line at all — a process
// between releasing its memory and its exit, nothing resident to count
// (the kernel prints a process's memory lines whole or not at all) —
// and ok is false when a memory line is present but the lines cannot
// be read whole, a live set the walk cannot price.
func parseDescendantStatus(text string) (st status, leaving, ok bool) {
	_, present, _ := kibibyteLines(text, statusKeys...)
	if present == 0 {
		return status{}, true, false
	}
	st, ok = parseStatus(text)
	return st, false, ok
}

// kibibyteLines reads the named "<key>:  <n> kB" lines of a /proc text
// — the one grammar the status and meminfo readings share — into bytes.
// present counts the named keys the text carries (a malformed line
// counts as present); ok is false unless every named key is present and
// well-formed (the unit kB, a count that fits in bytes): a reading is
// absent before it is partial. Lines under other keys are not read.
func kibibyteLines(text string, keys ...string) (values map[string]uint64, present int, ok bool) {
	wanted := make(map[string]bool, len(keys))
	for _, key := range keys {
		wanted[key] = true
	}
	out := make(map[string]uint64, len(keys))
	seen := make(map[string]bool, len(keys))
	malformed := false
	for _, line := range strings.Split(text, "\n") {
		key, rest, found := strings.Cut(line, ":")
		if !found || !wanted[key] {
			continue
		}
		seen[key] = true
		fields := strings.Fields(rest)
		if len(fields) != 2 || fields[1] != "kB" {
			malformed = true
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || n > math.MaxUint64/1024 {
			malformed = true
			continue
		}
		out[key] = n * 1024
	}
	if malformed || len(out) != len(keys) {
		return nil, len(seen), false
	}
	return out, len(seen), true
}

// parseStat reads the parent pid and the state from a /proc/<pid>/stat
// line. The second field, the command name, is parenthesized and may
// itself hold spaces and parentheses, so the fields after it are split
// from the last closing parenthesis: the state is the first of those,
// the parent pid the second. ok is false for any other shape.
func parseStat(line string) (ppid int, state byte, ok bool) {
	i := strings.LastIndexByte(line, ')')
	if i < 0 {
		return 0, 0, false
	}
	fields := strings.Fields(line[i+1:])
	if len(fields) < 2 || len(fields[0]) != 1 {
		return 0, 0, false
	}
	p, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, false
	}
	return p, fields[0][0], true
}

// live reports whether a process in state is a live descendant: a zombie
// (Z) holds no memory and awaits its reaping, a dead process (X) is
// gone; every other state is live.
func live(state byte) bool { return state != 'Z' && state != 'X' }
