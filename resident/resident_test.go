//go:build linux

package resident

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"testing"
	"time"
)

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
