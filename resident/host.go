package resident

import (
	"math"
	"os"
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

// wordKind classifies the word in force at the first derivation.
type wordKind int

const (
	// wordNone: no operator word and no limit installed — the derivation
	// installs.
	wordNone wordKind = iota
	// wordPrior: a limit a caller installed before the first derivation
	// — it caps every derivation.
	wordPrior
	// wordOperator: GOMEMLIMIT present and non-empty in the environment
	// at the first derivation (a size, or `off`) — the operator's word,
	// which no derivation overrides; an empty value is no word, as the
	// runtime reads it.
	wordOperator
)

// operatorWord is the word taken once per process at the first
// derivation, so a later derivation is judged against it and never
// against an earlier derivation of its own: its kind and, for a prior
// install, the limit.
var operatorWord struct {
	mu    sync.Mutex
	taken bool
	kind  wordKind
	limit int64
}

// takeWord takes the word in force at the first derivation and returns
// it on every call.
func takeWord() (wordKind, int64) {
	operatorWord.mu.Lock()
	defer operatorWord.mu.Unlock()
	if !operatorWord.taken {
		operatorWord.taken = true
		switch limit := installedCeiling(); {
		case os.Getenv("GOMEMLIMIT") != "":
			operatorWord.kind = wordOperator
		case limit > 0:
			operatorWord.kind, operatorWord.limit = wordPrior, int64(limit)
		}
	}
	return operatorWord.kind, operatorWord.limit
}

// InstallCeiling derives the running process's ceiling from the host's
// reading at this moment and installs it as the runtime's soft memory
// limit — unless the operator's word stands (GOMEMLIMIT present and
// non-empty in the environment at the first derivation — a size, or
// `off`): then nothing is installed and the limit in force is returned
// (0 for none) — and never above a limit a caller installed before the
// first derivation: a process narrowed earlier stays narrower, and a
// later derivation rises or falls with the host, never pinned by an
// earlier derivation of its own. It returns the ceiling in force, 0
// when none is.
func InstallCeiling() int64 {
	kind, prior := takeWord()
	if kind == wordOperator {
		return int64(installedCeiling())
	}
	m, ok := HostMemory()
	if !ok {
		return 0
	}
	c := Ceiling(m)
	if c <= 0 {
		return 0
	}
	if kind == wordPrior && prior < c {
		c = prior
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
