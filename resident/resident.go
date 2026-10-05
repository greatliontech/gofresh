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

// parseStatus reads the resident and peak resident bytes from a
// /proc/<pid>/status text, whose VmRSS and VmHWM lines carry kibibytes.
// ok is false unless both lines parse.
func parseStatus(text string) (rss, peak uint64, ok bool) {
	m, _, ok := kibibyteLines(text, "VmRSS", "VmHWM")
	if !ok {
		return 0, 0, false
	}
	return m["VmRSS"], m["VmHWM"], true
}

// parseDescendantStatus reads a live descendant's status: leaving is
// true when the text carries no memory line at all — a process between
// releasing its memory and its exit, nothing resident to count — and
// ok is false when a memory line is present but the pair cannot be
// read whole, a live set the walk cannot price.
func parseDescendantStatus(text string) (rss, peak uint64, leaving, ok bool) {
	m, present, ok := kibibyteLines(text, "VmRSS", "VmHWM")
	if present == 0 {
		return 0, 0, true, false
	}
	if !ok {
		return 0, 0, false, false
	}
	return m["VmRSS"], m["VmHWM"], false, true
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
