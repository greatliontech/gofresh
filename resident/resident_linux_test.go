//go:build linux

package resident

import (
	"maps"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"testing"
	"time"
)

// procTree writes a synthetic process table: pid → (ppid, state, rss kB,
// hwm kB); a pid with a negative rss has no status file (exited between
// the listing and the read).
func procTree(t *testing.T, procs map[int][4]int) string {
	t.Helper()
	held := map[int][6]int{}
	for pid, p := range procs {
		// The held set equals the resident set unless a pin says
		// otherwise (procTreeHeld): anonymous pages only.
		held[pid] = [6]int{p[0], p[1], p[2], p[3], p[2], 0}
	}
	return procTreeHeld(t, held)
}

// procTreeHeld plants a table whose status lines carry the held set
// too: {ppid, state, rss, hwm, anon, shmem} in kibibytes.
func procTreeHeld(t *testing.T, procs map[int][6]int) string {
	t.Helper()
	root := t.TempDir()
	for pid, p := range procs {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		stat := strconv.Itoa(pid) + " (p" + strconv.Itoa(pid) + ") " + string(rune(p[1])) + " " + strconv.Itoa(p[0]) + " 1 1 0 -1 4194560 100 0\n"
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
		if p[2] < 0 {
			continue
		}
		status := "Name:\tp" + strconv.Itoa(pid) + "\nVmHWM:\t" + strconv.Itoa(p[3]) + " kB\nVmRSS:\t" + strconv.Itoa(p[2]) + " kB\nRssAnon:\t" + strconv.Itoa(p[4]) + " kB\nRssShmem:\t" + strconv.Itoa(p[5]) + " kB\n"
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
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

// TestCeilingIsHalfTheHostsAvailableMemory pins the ceiling's derivation
// and its installation over a family holding nothing
// (REQ-fresh-resident-readings): half of what the host has available,
// the floor, the operator's words; a host without the reading derives
// none and leaves the limit in force (none here), and the installed
// ceiling reads back as the runtime's soft limit — the value the
// resident datum states. The family term is
// TestCeilingIsHalfTheFamilysRoom's.
func TestCeilingIsHalfTheHostsAvailableMemory(t *testing.T) {
	if got := ceiling(Memory{TotalBytes: 16 << 30, AvailableBytes: 6 << 30}, 0); got != 3<<30 {
		t.Fatalf("Ceiling = %d, want half the available memory (%d)", got, int64(3<<30))
	}
	if got := ceiling(Memory{TotalBytes: 16 << 30, AvailableBytes: 600 << 20}, 0); got != ceilingFloor {
		t.Fatalf("Ceiling under a short host = %d, want the floor %d", got, ceilingFloor)
	}
	if got := ceiling(Memory{}, 6<<30); got != 0 {
		t.Fatalf("Ceiling of no reading = %d, want 0", got)
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
	// The environment carries no operator word for the derivation arms
	// (an oracle running this binary sets GOMEMLIMIT on it).
	if prior, set := os.LookupEnv("GOMEMLIMIT"); set {
		t.Cleanup(func() { os.Setenv("GOMEMLIMIT", prior) })
		os.Unsetenv("GOMEMLIMIT")
	}
	debug.SetMemoryLimit(math.MaxInt64)
	if got := installedCeiling(); got != 0 {
		t.Fatalf("installedCeiling under the runtime's default = %d, want 0 (none installed)", got)
	}
	// The synthetic root carries this process holding nothing, so the
	// family term is zero and the derivation reads as half of the
	// host's availability; an absent host reading leaves the limit in
	// force (none here).
	root := procTree(t, map[int][4]int{1: {0, 'S', 1, 1}, os.Getpid(): {1, 'S', 0, 0}})
	priorRoot := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = priorRoot })
	// No meminfo under the root: no reading, nothing installed.
	if c := InstallCeiling(); c != 0 || installedCeiling() != 0 {
		t.Fatalf("InstallCeiling without a host reading installed %d (reads back %d), want nothing", c, installedCeiling())
	}
	if err := os.WriteFile(filepath.Join(root, "meminfo"), []byte("MemTotal:       8388608 kB\nMemAvailable:    4194304 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, ok := HostMemory()
	if !ok || m != (Memory{TotalBytes: 8 << 30, AvailableBytes: 4 << 30}) {
		t.Fatalf("HostMemory = %+v %v, want the synthetic meminfo's two lines", m, ok)
	}
	if c := InstallCeiling(); c != 2<<30 {
		t.Fatalf("InstallCeiling = %d, want half the available memory (%d)", c, int64(2<<30))
	}
	if got := installedCeiling(); got != 2<<30 {
		t.Fatalf("the installed ceiling reads back as %d, want %d", got, int64(2<<30))
	}
	// A later operation's derivation follows the host up as well as
	// down — never pinned by an earlier derivation of its own.
	if err := os.WriteFile(filepath.Join(root, "meminfo"), []byte("MemTotal:       33554432 kB\nMemAvailable:    25165824 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := InstallCeiling(); c != 12<<30 || installedCeiling() != 12<<30 {
		t.Fatalf("a later operation's re-derivation installed %d (reads back %d), want %d", c, installedCeiling(), int64(12<<30))
	}
	// The operator's limit — the one in force before the first
	// derivation — is never widened: a narrower process stays narrower
	// across every later derivation.
	resetWord()
	debug.SetMemoryLimit(1 << 30)
	if c := InstallCeiling(); c != 1<<30 || installedCeiling() != 1<<30 {
		t.Fatalf("InstallCeiling over an operator's narrower limit installed %d (reads back %d), want the narrower %d kept", c, installedCeiling(), int64(1<<30))
	}
	if c := InstallCeiling(); c != 1<<30 {
		t.Fatalf("a second derivation under the operator's limit installed %d, want %d kept", c, int64(1<<30))
	}
	// A limit installed earlier that is wider than the derivation does
	// not widen it: the derivation installs; an earlier word only ever
	// narrows.
	resetWord()
	debug.SetMemoryLimit(16 << 30)
	if c := InstallCeiling(); c != 12<<30 || installedCeiling() != 12<<30 {
		t.Fatalf("InstallCeiling under an earlier wider limit installed %d (reads back %d), want the derived %d", c, installedCeiling(), int64(12<<30))
	}
	// The operator's explicit GOMEMLIMIT replaces the derivation
	// whatever its size — wider or narrower — and `off` installs
	// nothing: the runtime's none stands, 0 is returned, no ceiling is
	// carried, and a later derivation never overrides it; an EMPTY
	// value is no word, as the runtime reads it: the derivation
	// installs.
	for _, tc := range []struct {
		word  string
		limit int64
		want  int64
	}{{"16GiB", 16 << 30, 16 << 30}, {"512MiB", 512 << 20, 512 << 20}, {"off", math.MaxInt64, 0}, {"", math.MaxInt64, 12 << 30}} {
		resetWord()
		t.Setenv("GOMEMLIMIT", tc.word)
		debug.SetMemoryLimit(tc.limit)
		if c := InstallCeiling(); c != tc.want || int64(installedCeiling()) != tc.want {
			t.Fatalf("GOMEMLIMIT=%q: InstallCeiling = %d (reads back %d), want %d", tc.word, c, installedCeiling(), tc.want)
		}
		if c := InstallCeiling(); c != tc.want {
			t.Fatalf("GOMEMLIMIT=%q: a second derivation answered %d, want %d", tc.word, c, tc.want)
		}
	}
	// Under the operator's word the ceiling returned is the one in
	// force NOW — a limit a library installed later rides it.
	resetWord()
	t.Setenv("GOMEMLIMIT", "off")
	debug.SetMemoryLimit(math.MaxInt64)
	if c := InstallCeiling(); c != 0 {
		t.Fatalf("GOMEMLIMIT=off: %d in force", c)
	}
	debug.SetMemoryLimit(4 << 30)
	if c := InstallCeiling(); c != 4<<30 {
		t.Fatalf("GOMEMLIMIT=off with 4 GiB installed later: InstallCeiling = %d, want the limit in force", c)
	}
	// Under `off` the reading carries no ceiling — judged over the real
	// process table (the synthetic root holds no status file; a host
	// answering no reading skips here, as the live-sample arm does).
	resetWord()
	debug.SetMemoryLimit(math.MaxInt64)
	if c := InstallCeiling(); c != 0 {
		t.Fatalf("GOMEMLIMIT=off: %d in force", c)
	}
	procRoot = priorRoot
	if r, ok := Readings(); !ok {
		t.Skip("the host answers no resident reading")
	} else if r.Set.CeilingBytes != 0 {
		t.Fatalf("GOMEMLIMIT=off: the reading carries ceiling %d, want none", r.Set.CeilingBytes)
	}
	procRoot = root
	resetWord()
	debug.SetMemoryLimit(math.MaxInt64)
	// The live sample states the installed ceiling beside the kernel's
	// readings (over the real process table).
	procRoot = priorRoot
	set, ok := Sample()
	if !ok {
		t.Skip("the host answers no resident reading")
	}
	if set.CeilingBytes != installedCeiling() {
		t.Fatalf("Sample carries ceiling %d, want the installed %d", set.CeilingBytes, installedCeiling())
	}
}

func TestHostMemoryAppliesCgroupV2Limits(t *testing.T) {
	procDir := t.TempDir()
	cgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(procDir, "meminfo"), []byte("MemTotal:       16777216 kB\nMemAvailable:   12582912 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(procDir, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "self", "cgroup"), []byte("0::/user.slice/container.scope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	scopeDir := filepath.Join(cgDir, "user.slice", "container.scope")
	if err := os.MkdirAll(scopeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	priorProc, priorCg := procRoot, cgroupRoot
	procRoot, cgroupRoot = procDir, cgDir
	t.Cleanup(func() { procRoot, cgroupRoot = priorProc, priorCg })

	// "max" leaves the host reading uncapped.
	if err := os.WriteFile(filepath.Join(scopeDir, "memory.max"), []byte("max\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := HostMemory(); !ok || got != (Memory{TotalBytes: 16 << 30, AvailableBytes: 12 << 30}) {
		t.Fatalf("HostMemory(max) = %+v %v", got, ok)
	}

	// A 4 GiB limit with 1 GiB current usage caps TotalBytes at 4 GiB and AvailableBytes at 3 GiB.
	if err := os.WriteFile(filepath.Join(scopeDir, "memory.max"), []byte("4294967296\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scopeDir, "memory.current"), []byte("1073741824\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := HostMemory(); !ok || got != (Memory{TotalBytes: 4 << 30, AvailableBytes: 3 << 30}) {
		t.Fatalf("HostMemory(capped) = %+v %v, want 4GiB total / 3GiB available", got, ok)
	}

	// A tighter memory.high (2 GiB) than memory.max (4 GiB) clamps to 2 GiB total / 1 GiB available.
	if err := os.WriteFile(filepath.Join(scopeDir, "memory.high"), []byte("2147483648\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := HostMemory(); !ok || got != (Memory{TotalBytes: 2 << 30, AvailableBytes: 1 << 30}) {
		t.Fatalf("HostMemory(memory.high < memory.max) = %+v %v, want 2GiB total / 1GiB available", got, ok)
	}

	// When the leaf cgroup has "max" on both files, an ancestor / root cgroup limit still clamps.
	if err := os.WriteFile(filepath.Join(scopeDir, "memory.max"), []byte("max\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scopeDir, "memory.high"), []byte("max\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgDir, "memory.max"), []byte("8589934592\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgDir, "memory.current"), []byte("2147483648\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := HostMemory(); !ok || got != (Memory{TotalBytes: 8 << 30, AvailableBytes: 6 << 30}) {
		t.Fatalf("HostMemory(ancestor limit) = %+v %v, want 8GiB total / 6GiB available", got, ok)
	}
}

// TestSampleWalksTheLiveDescendants pins the walk over a synthetic
// table (REQ-fresh-resident-readings): every process whose parent chain reaches the
// sampled one counts — the go driver, the package test binary beneath
// it, a resolver child — summed by resident bytes with the largest
// single descendant's own peak; a zombie, a dead process, a sibling, an
// unrelated process, and a descendant whose status vanished are not
// counted; an unlistable table or an unreadable own status yields no
// reading rather than a zero one.
func TestSampleWalksTheLiveDescendants(t *testing.T) {
	root := procTree(t, map[int][4]int{
		1:   {0, 'S', 1, 1},        // init
		100: {1, 'S', 75, 1004},    // self
		101: {1, 'S', 500, 500},    // a sibling: not a descendant
		200: {100, 'S', 400, 505},  // a resolver child
		201: {100, 'S', 10, 12},    // a go driver
		300: {201, 'R', 900, 950},  // the package test binary beneath it
		301: {201, 'Z', 0, 0},      // a reaped-pending zombie: not live
		302: {300, 'X', 0, 0},      // dead: not live
		303: {300, 'S', -1, 0},     // exited between the listing and the read
		400: {101, 'S', 999, 9999}, // the sibling's child: not ours
	})
	set, trees, ok := sampleAt(root, 100)
	want := Set{ProcessBytes: 75 * 1024, ProcessHeldBytes: 75 * 1024, ProcessPeakBytes: 1004 * 1024, Descendants: 3, DescendantsBytes: (400 + 10 + 900) * 1024, DescendantsHeldBytes: (400 + 10 + 900) * 1024, DescendantPeakBytes: 950 * 1024, HeldKnown: true}
	if !ok || set != want {
		t.Fatalf("sampleAt = %+v %v, want %+v true", set, ok, want)
	}
	// Each direct child's tree is attributed whole: the resolver child
	// alone, the go driver with the test binary beneath it.
	wantTrees := map[int]uint64{200: 400 * 1024, 201: (10 + 900) * 1024}
	if !maps.Equal(trees, wantTrees) {
		t.Fatalf("sampleAt trees = %v, want %v", trees, wantTrees)
	}
	// Two descendants the walk does not count and that void nothing: a
	// live one whose status carries no memory lines (leaving, its memory
	// released) and one whose stat does not parse (no process named).
	for pid, files := range map[string]map[string]string{
		"304": {"stat": "304 (p304) S 300 1 1 0 -1 4194560 100 0\n", "status": "Name:\tp304\nThreads:\t1\n"},
		"305": {"stat": "garbage\n", "status": "Name:\tp305\nVmHWM:\t 5 kB\nVmRSS:\t 5 kB\n"},
	} {
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		for name, text := range files {
			if err := os.WriteFile(filepath.Join(root, pid, name), []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if set, trees, ok := sampleAt(root, 100); !ok || set != want || !maps.Equal(trees, wantTrees) {
		t.Fatalf("a leaving descendant or an unparseable stat changed the reading: %+v %v %v", set, trees, ok)
	}
	// A live descendant whose status carries a memory line the walk
	// cannot read whole is a set it cannot price: the reading voids.
	if err := os.WriteFile(filepath.Join(root, "304", "status"), []byte("Name:\tp304\nVmRSS:\t 5 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if set, _, ok := sampleAt(root, 100); ok || set != (Set{}) {
		t.Fatalf("a half-readable live status answered %+v %v, want no reading", set, ok)
	}
	// A memory line present but malformed — even alone — is the same
	// class: present, unreadable whole, the reading voids (never the
	// leaving class, which has no memory line at all).
	if err := os.WriteFile(filepath.Join(root, "304", "status"), []byte("Name:\tp304\nVmRSS:\t5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if set, _, ok := sampleAt(root, 100); ok || set != (Set{}) {
		t.Fatalf("a malformed live memory line answered %+v %v, want no reading", set, ok)
	}
	if err := os.WriteFile(filepath.Join(root, "304", "status"), []byte("Name:\tp304\nThreads:\t1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if set, _, ok := sampleAt(root, 999); ok || set != (Set{}) {
		t.Fatalf("a process without a status answered %+v %v", set, ok)
	}
	if set, _, ok := sampleAt(filepath.Join(root, "missing"), 100); ok || set != (Set{}) {
		t.Fatalf("an unlistable table answered %+v %v", set, ok)
	}
	// A descendant whose status exists but cannot be read voids the
	// reading: a count missing it would be partial.
	if os.Getuid() != 0 {
		guarded := procTree(t, map[int][4]int{100: {1, 'S', 75, 1004}, 200: {100, 'S', 400, 505}, 201: {100, 'S', 10, 12}})
		if err := os.Chmod(filepath.Join(guarded, "201", "status"), 0o000); err != nil {
			t.Fatal(err)
		}
		if set, _, ok := sampleAt(guarded, 100); ok {
			t.Fatalf("an unreadable descendant status answered a partial %+v", set)
		}
	}
	// The own status readable but the table unlistable — a table that can
	// be traversed but not listed: no reading, never "no descendants".
	lone := t.TempDir()
	if err := os.MkdirAll(filepath.Join(lone, "100"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lone, "100", "status"), []byte("VmHWM:\t2 kB\nVmRSS:\t1 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lone, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(lone, 0o755) })
	if os.Getuid() != 0 {
		if _, err := os.ReadFile(filepath.Join(lone, "100", "status")); err != nil {
			t.Fatalf("the fixture's own status must stay readable through the unlistable table: %v", err)
		}
		if set, _, ok := sampleAt(lone, 100); ok {
			t.Fatalf("an unlistable table beside a readable status answered %+v", set)
		}
	}
}

// TestSampleCountsALiveDescendantChain pins the live reading on the host
// that answers it: the process's own set is positive and bounded by its
// peak, and a shell this process spawned with the sleep beneath it are
// both counted, with resident bytes, until they are reaped.
func TestSampleCountsALiveDescendantChain(t *testing.T) {
	if runtime.GOOS != "linux" {
		if _, ok := Sample(); ok {
			t.Fatal("a host without the /proc reading answered a sample")
		}
		t.Skip("the reading has a Linux form only")
	}
	before, ok := Sample()
	if !ok || before.ProcessBytes == 0 || before.ProcessPeakBytes < before.ProcessBytes {
		t.Fatalf("own sample = %+v %v, want a positive set under its peak", before, ok)
	}
	// The trailing command keeps the shell alive beside its sleep: two
	// descendants, one of them a grandchild.
	child := exec.Command("sh", "-c", "sleep 30; true")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()
	var during Set
	for range 50 { // the shell forks its sleep shortly after starting
		during, ok = Sample()
		if ok && during.Descendants >= before.Descendants+2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ok || during.Descendants < before.Descendants+2 || during.DescendantsBytes <= before.DescendantsBytes || during.DescendantPeakBytes == 0 {
		t.Fatalf("sample beside a live shell and its sleep = %+v (before %+v), want two more descendants with resident bytes and a peak", during, before)
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	after, _ := Sample()
	if after.Descendants > before.Descendants+1 {
		// The orphaned sleep may be re-parented to init rather than to
		// this process; a reaped shell is never counted.
		t.Fatalf("reaped shell still counted: %d descendants, before %d", after.Descendants, before.Descendants)
	}
}

// TestReadingsComposeTheWalkTheHostAndTheCeiling pins the one value a
// consumer's policy reads (REQ-fresh-resident-readings): the process's
// own set with the limit in force riding it, each direct child's tree,
// and the host's memory, from one walk; a host without the memory
// reading answers no Reading at all, never a partial one.
func TestReadingsComposeTheWalkTheHostAndTheCeiling(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the reading has a Linux form only")
	}
	// The fixture's children sit past any live pid (pid_max is at most
	// 4194304), so neither can collide with the test's own.
	self := os.Getpid()
	child, grandchild := self+4194304, self+4194305
	root := procTree(t, map[int][4]int{
		1:          {0, 'S', 1, 1},
		self:       {1, 'S', 75, 1004},
		child:      {self, 'S', 400, 505},
		grandchild: {child, 'S', 10, 12},
	})
	priorRoot := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = priorRoot })
	prior := debug.SetMemoryLimit(5 << 30)
	t.Cleanup(func() { debug.SetMemoryLimit(prior) })
	if r, ok := Readings(); ok {
		t.Fatalf("Readings without a host reading answered %+v", r)
	}
	if err := os.WriteFile(filepath.Join(root, "meminfo"), []byte("MemTotal:       8388608 kB\nMemAvailable:    4194304 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, ok := Readings()
	if !ok {
		t.Fatal("Readings answered nothing over a complete table")
	}
	wantSet := Set{ProcessBytes: 75 * 1024, ProcessHeldBytes: 75 * 1024, ProcessPeakBytes: 1004 * 1024, Descendants: 2, DescendantsBytes: 410 * 1024, DescendantsHeldBytes: 410 * 1024, DescendantPeakBytes: 505 * 1024, CeilingBytes: 5 << 30, HeldKnown: true}
	if r.Set != wantSet {
		t.Fatalf("Readings.Set = %+v, want %+v", r.Set, wantSet)
	}
	if r.Host != (Memory{TotalBytes: 8 << 30, AvailableBytes: 4 << 30}) {
		t.Fatalf("Readings.Host = %+v, want the synthetic meminfo", r.Host)
	}
	if want := map[int]uint64{child: 410 * 1024}; !maps.Equal(r.Trees, want) {
		t.Fatalf("Readings.Trees = %v, want %v", r.Trees, want)
	}
}

func TestSampleAtUsesTaskChildrenWhenPresent(t *testing.T) {
	root := procTree(t, map[int][4]int{
		1:   {0, 'S', 1, 1},
		100: {1, 'S', 75, 1004},
		101: {1, 'S', 500, 500},
		200: {100, 'S', 400, 505},
		201: {100, 'S', 10, 12},
		300: {201, 'R', 900, 950},
	})
	for pid, children := range map[int]string{
		100: "200 201\n",
		200: "",
		201: "300\n",
		300: "",
	} {
		pidStr := strconv.Itoa(pid)
		taskDir := filepath.Join(root, pidStr, "task", pidStr)
		if err := os.MkdirAll(taskDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(taskDir, "children"), []byte(children), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set, trees, ok := sampleAt(root, 100)
	want := Set{ProcessBytes: 75 * 1024, ProcessHeldBytes: 75 * 1024, ProcessPeakBytes: 1004 * 1024, Descendants: 3, DescendantsBytes: (400 + 10 + 900) * 1024, DescendantsHeldBytes: (400 + 10 + 900) * 1024, DescendantPeakBytes: 950 * 1024, HeldKnown: true}
	if !ok || set != want {
		t.Fatalf("sampleAt(task children) = %+v %v, want %+v true", set, ok, want)
	}
	wantTrees := map[int]uint64{200: 400 * 1024, 201: (10 + 900) * 1024}
	if !maps.Equal(trees, wantTrees) {
		t.Fatalf("sampleAt(task children) trees = %v, want %v", trees, wantTrees)
	}
}
