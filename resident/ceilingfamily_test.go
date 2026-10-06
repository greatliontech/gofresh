package resident

import (
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"testing"
)

// The ceiling is half of the room the host has for the process's
// family — what it has available plus what the family already holds —
// so a derivation taken under a held working set never installs a
// ceiling under the live heap (the review's anchor: a 16 GiB host, a
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

// InstallCeiling counts the family's HELD set — the process's own and
// its descendants' anonymous and shared-memory pages, never their
// file-backed pages nor their peaks — into the room from one reading:
// over a planted table it installs half of available-plus-held; where
// the table cannot be walked, or states no held set (a kernel before
// 4.5), the derivation does not run and the limit in force stands
// (REQ-fresh-resident-readings).
func TestInstallCeilingCountsTheFamilysSet(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the reading has a Linux form only")
	}
	prior := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prior) })
	resetWord := func() {
		operatorWord.mu.Lock()
		operatorWord.taken, operatorWord.kind, operatorWord.limit = false, wordNone, 0
		operatorWord.mu.Unlock()
	}
	resetWord()
	t.Cleanup(resetWord)
	if prior, set := os.LookupEnv("GOMEMLIMIT"); set {
		t.Cleanup(func() { os.Setenv("GOMEMLIMIT", prior) })
		os.Unsetenv("GOMEMLIMIT")
	}
	debug.SetMemoryLimit(math.MaxInt64)
	self := os.Getpid()
	child, other := self+4194304, self+4194305
	// The process: 3 GiB resident of which 1.5 GiB anonymous and
	// 0.5 GiB shmem (1 GiB file-backed), peak 5 GiB; two children: one
	// 1.5 GiB resident / 0.75 GiB anonymous, peak 2 GiB, the other
	// 0.5 GiB resident / 0.25 GiB anonymous, peak 4 GiB. The held set is
	// 3 GiB; with 3 GiB available the room is 6 GiB and the ceiling
	// 3 GiB — a resident-set base would read 5 GiB of family (4 GiB),
	// a peak base more, the bare halving 1.5 GiB under a 3 GiB set.
	root := procTreeHeld(t, map[int][6]int{
		1:     {0, 'S', 1, 1, 1, 0},
		self:  {1, 'S', 3 << 20, 5 << 20, 3 << 19, 1 << 19},
		child: {self, 'S', 3 << 19, 2 << 20, 3 << 18, 0},
		other: {self, 'S', 1 << 19, 4 << 20, 1 << 18, 0},
	})
	if err := os.WriteFile(filepath.Join(root, "meminfo"), []byte("MemTotal:       16777216 kB\nMemAvailable:    3145728 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	priorRoot := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = priorRoot })
	if c := InstallCeiling(); c != 3<<30 || installedCeiling() != 3<<30 {
		t.Fatalf("InstallCeiling over a 3 GiB held set with 3 GiB available = %d (reads back %d), want 3 GiB", c, installedCeiling())
	}
	// The table cannot be walked whole (a live descendant's status
	// present but unreadable): no derivation — the limit in force stands
	// and is returned, whatever the host now says.
	if err := os.WriteFile(filepath.Join(root, "meminfo"), []byte("MemTotal:       16777216 kB\nMemAvailable:    8388608 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, strconv.Itoa(other), "status"), []byte("Name:\tpother\nVmRSS:\tbroken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := InstallCeiling(); c != 3<<30 || installedCeiling() != 3<<30 {
		t.Fatalf("InstallCeiling over an unwalkable table = %d (reads back %d), want the 3 GiB in force kept", c, installedCeiling())
	}
	// A kernel before 4.5 states no held set — every status without
	// the two lines: the reading stands (the set reads, the held set
	// unknown) and nothing derives.
	for pid, lines := range map[int]string{
		self:  "Name:\tself\nVmHWM:\t 5242880 kB\nVmRSS:\t 3145728 kB\n",
		child: "Name:\tpchild\nVmHWM:\t 2097152 kB\nVmRSS:\t 1572864 kB\n",
		other: "Name:\tpother\nVmHWM:\t 4194304 kB\nVmRSS:\t 524288 kB\n",
	} {
		if err := os.WriteFile(filepath.Join(root, strconv.Itoa(pid), "status"), []byte(lines), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set, ok := Sample()
	if !ok || set.HeldKnown || set.Descendants != 2 || set.ProcessBytes != 3<<30 || set.DescendantsBytes != 2<<30 {
		t.Fatalf("Sample over a pre-4.5 table = %+v %v, want the set read with HeldKnown false", set, ok)
	}
	if c := InstallCeiling(); c != 3<<30 || installedCeiling() != 3<<30 {
		t.Fatalf("InstallCeiling over an unknown held set = %d (reads back %d), want the 3 GiB in force kept", c, installedCeiling())
	}
}
