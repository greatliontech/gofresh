package resident

import (
	"math"
	"runtime/debug"
	"sync"
)

// Memory is one reading of the host's memory: its total and what it has
// available for new allocations at the reading, as the kernel answers
// them.
type Memory struct {
	TotalBytes     uint64
	AvailableBytes uint64
}

// HostMemory reads the host's memory. ok is false where the host does
// not answer — not Linux, or /proc/meminfo unreadable — and the Memory
// is then the zero value, which no reader consumes: a consumer without
// the reading derives no memory term and installs no ceiling, and says
// so by carrying none.
func HostMemory() (Memory, bool) { return hostMemory() }

// parseMeminfo reads MemTotal and MemAvailable from a /proc/meminfo text,
// whose lines carry kibibytes. ok is false unless both lines parse.
func parseMeminfo(text string) (Memory, bool) {
	m, _, ok := kibibyteLines(text, "MemTotal", "MemAvailable")
	if !ok {
		return Memory{}, false
	}
	return Memory{TotalBytes: m["MemTotal"], AvailableBytes: m["MemAvailable"]}, true
}

// CeilingFloor is the least ceiling derived: a consumer's own live set
// legitimately reaches it (an engine's loads and views), and a ceiling
// below the live set buys continuous collection and nothing else.
const CeilingFloor = int64(1) << 30

// Ceiling derives the soft memory ceiling of one of a consumer's own
// processes from the host's reading at the process's start: half of what
// the host had available — the other half left to the processes the
// consumer spawns — floored at CeilingFloor, so the runtime collects
// against the ceiling instead of growing its slack toward twice the live
// set while child processes need the memory; 0 for a host without the
// reading, which installs no ceiling. The ceiling is soft: the runtime
// exceeds a limit it cannot meet rather than thrash, so it never kills
// and never refuses — a consumer states the ceiling on its progress
// face and derives its own admissions from the readings
// (REQ-fresh-resident-readings).
func Ceiling(m Memory) int64 {
	if m.AvailableBytes == 0 {
		return 0
	}
	return max(int64(m.AvailableBytes/2), CeilingFloor)
}

// operatorLimit is the memory limit in force before the first derivation
// — an operator's GOMEMLIMIT, one an earlier caller installed, or the
// runtime's none — taken once per process so a later derivation is
// judged against that word and never against an earlier derivation of
// its own.
var operatorLimit struct {
	mu    sync.Mutex
	taken bool
	limit int64
}

// operatorCeiling returns the operator's limit, 0 for none.
func operatorCeiling() int64 {
	operatorLimit.mu.Lock()
	defer operatorLimit.mu.Unlock()
	if !operatorLimit.taken {
		operatorLimit.taken = true
		if limit := debug.SetMemoryLimit(-1); limit > 0 && limit != math.MaxInt64 {
			operatorLimit.limit = limit
		}
	}
	return operatorLimit.limit
}

// InstallCeiling derives the running process's ceiling from the host's
// reading at this moment and installs it as the runtime's soft memory
// limit — never above the operator's limit (the one in force before the
// first derivation): a process the operator narrowed stays narrower,
// and a later derivation rises or falls with the host, never pinned by
// an earlier derivation of its own. It returns the installed ceiling, 0
// when the host gave no reading and nothing was installed.
func InstallCeiling() int64 {
	operator := operatorCeiling()
	m, ok := HostMemory()
	if !ok {
		return 0
	}
	c := Ceiling(m)
	if c <= 0 {
		return 0
	}
	if operator > 0 && operator < c {
		c = operator
	}
	debug.SetMemoryLimit(c)
	return c
}

// Reading is the readings a consumer's policy composes — a spawn
// admission's memory term, a server's idle release — in one value: the
// process's set, the host's memory, and the resident bytes of each of
// the process's direct children's trees keyed by the child's pid — a
// child's whole tree attributed to the process the consumer spawned.
type Reading struct {
	Set   Set
	Host  Memory
	Trees map[int]uint64
}

// Readings takes the process's and the host's readings together in one
// walk of the process table, the limit in force riding the set. ok is
// false unless both answer.
func Readings() (Reading, bool) {
	set, trees, ok := sampleTrees()
	if !ok {
		return Reading{}, false
	}
	set.CeilingBytes = installedCeiling()
	m, ok := HostMemory()
	if !ok {
		return Reading{}, false
	}
	return Reading{Set: set, Host: m, Trees: trees}, true
}

// installedCeiling reads the running process's soft memory limit: 0 when
// none is installed (the runtime's default is the maximum int64).
func installedCeiling() uint64 {
	limit := debug.SetMemoryLimit(-1)
	if limit <= 0 || limit == math.MaxInt64 {
		return 0
	}
	return uint64(limit)
}
