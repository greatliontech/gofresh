package resident

import (
	"math"
	"os"
	"runtime/debug"
	"sync"
)

// Memory is one reading of the host's memory: its total and what it has
// available for new allocations at the reading, as the kernel answers
// them. The zero value is no reading: a host answers a total; what it
// has available may read 0 (the kernel clamps it under pressure), and
// that is a reading.
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
// whose lines carry kibibytes. ok is false unless both lines parse and
// the total is above zero (a host with no memory is no reading, so the
// zero Memory means exactly that).
func parseMeminfo(text string) (Memory, bool) {
	m, _, ok := kibibyteLines(text, "MemTotal", "MemAvailable")
	if !ok || m["MemTotal"] == 0 {
		return Memory{}, false
	}
	return Memory{TotalBytes: m["MemTotal"], AvailableBytes: m["MemAvailable"]}, true
}

// CeilingFloor is the least ceiling derived: a consumer's own live set
// legitimately reaches it (an engine's loads and views), and a ceiling
// below the live set buys continuous collection and nothing else.
const CeilingFloor = int64(1) << 30

// familyRoom is what the host has for a process's family: what it has
// available plus what the family — the process and its descendants —
// holds that the host cannot reclaim (the anonymous and shared-memory
// pages; a file-backed page is the page cache's and counted in the
// host's availability already). The kernel states availability net of
// the held pages, so a derivation taken while the family holds a
// working set must add that set back, or it counts the consumer's own
// pages as the host's unavailability and installs a ceiling under a
// live heap. The room counts what the walk sees, each member's held
// set as its status states it: a page shared among k members is
// counted k−1 times over, and a child still in its vfork window (its
// memory the parent's until it execs) counts the parent's held set
// once more — both transient and small, since Go spawns only to exec;
// and a family's memory the host cannot reclaim that no process holds
// (its unmapped tmpfs files, the kernel's allocations on its behalf)
// reads as the host's, so the room errs low there, never high.
func familyRoom(m Memory, family uint64) uint64 {
	return m.AvailableBytes + family
}

// ceiling is the rule: half of the room the host has for the family —
// the other half left to the processes the consumer spawns — floored
// at CeilingFloor, so the runtime collects against the ceiling instead
// of growing its slack toward twice the live set while child processes
// need the memory; 0 for a host without the reading (the zero Memory),
// which installs no ceiling — a host with nothing available is a
// reading, and the room is then what the family holds. The base is the
// family's room, not the host's bare availability: pages moving between
// the host's free pool and the family's processes leave the derivation
// unchanged, so a later derivation rises or falls with the host's other
// tenants and with the family's memory the walk cannot see
// (familyRoom), never with the family's own held pages. The rule takes
// the held set as a number; Reading.Ceiling is the one caller that
// knows whether the walk read it.
func ceiling(m Memory, family uint64) int64 {
	if m == (Memory{}) {
		return 0
	}
	return max(int64(familyRoom(m, family)/2), CeilingFloor)
}

// childrenBudget is the other half: the room less the ceiling, 0 for a
// host without the reading or a room the floor consumed.
func childrenBudget(m Memory, family uint64) int64 {
	c := ceiling(m, family)
	if c == 0 {
		return 0
	}
	return max(int64(familyRoom(m, family))-c, 0)
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

// InstallCeiling derives the running process's ceiling from one
// reading at this moment — the host's memory and the family's held set
// in one walk (Readings) — and installs it as the runtime's soft memory
// limit — unless the operator's word stands (GOMEMLIMIT present and
// non-empty in the environment at the first derivation — a size, or
// `off`): then nothing is installed and the limit in force is returned
// (0 for none) — and never above a limit a caller installed before the
// first derivation: a process narrowed earlier stays narrower, and a
// later derivation rises or falls with the host, never pinned by an
// earlier derivation of its own. Where the reading is absent — the
// host does not answer, or the process table cannot be walked whole —
// or carries no held set (a kernel before 4.5 states none), the
// derivation does not run: the limit in force stands, returned as it
// is (an earlier derivation's, or none). It returns the ceiling in
// force, 0 when none is.
func InstallCeiling() int64 {
	kind, prior := takeWord()
	if kind == wordOperator {
		return int64(installedCeiling())
	}
	r, ok := Readings()
	if !ok {
		return int64(installedCeiling())
	}
	// A whole reading that carries the held set always derives: the
	// rule answers 0 for the zero Memory alone, which Readings never
	// carries; one without the held set derives nothing (r.Ceiling's
	// ok).
	c, ok := r.Ceiling()
	if !ok {
		return int64(installedCeiling())
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

// held is the family's held set the reading carries — the process's
// own and its descendants' — meaningful only when the walk read it
// (Set.HeldKnown).
func (r Reading) held() uint64 { return r.Set.ProcessHeldBytes + r.Set.DescendantsHeldBytes }

// Ceiling derives the soft memory ceiling of one of a consumer's own
// processes from the reading: half of the room the host has for the
// family (what it has available plus the family's held set), floored
// at CeilingFloor. ok is false when the walk read no held set (a
// kernel before 4.5 states none): nothing derives, and the consumer
// keeps the limit in force. The ceiling is soft: the runtime exceeds a
// limit it cannot meet rather than thrash, so it never kills and never
// refuses — a consumer states the ceiling on its progress face and
// derives its own admissions from the readings
// (REQ-fresh-resident-readings).
func (r Reading) Ceiling() (int64, bool) {
	if !r.Set.HeldKnown {
		return 0, false
	}
	return ceiling(r.Host, r.held()), true
}

// ChildrenBudget derives the other half from the reading: the room the
// host has for the family less the process's own ceiling — what a
// consumer may hand the processes it spawns in total (an oracle tree's
// bound, a spawn admission's memory term: a spawn is admitted against
// the budget less the children's held set), 0 where the floor consumed
// the room. ok is false exactly where Ceiling's is: a budget over a
// held set the walk never read cannot be expressed
// (REQ-fresh-resident-readings).
func (r Reading) ChildrenBudget() (int64, bool) {
	if !r.Set.HeldKnown {
		return 0, false
	}
	return childrenBudget(r.Host, r.held()), true
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
