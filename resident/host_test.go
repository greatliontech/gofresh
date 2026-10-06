package resident

import (
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

// TestMeminfoParsesTheTwoHostLines pins the host reading's grammar
// (REQ-fresh-resident-readings): MemTotal and MemAvailable in
// kibibytes, both required; a malformed or missing line yields no
// reading rather than a zero one.
//
//gofresh:pure
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
		{"empty", "", Memory{}, false},
	}
	for _, c := range cases {
		got, ok := parseMeminfo(c.text)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: parseMeminfo = %+v %v, want %+v %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

// TestCeilingIsHalfTheHostsAvailableMemory pins the ceiling's derivation
// and its installation (REQ-fresh-resident-readings): half of what the host had
// available at the process's start; a host without the reading derives
// none and installs none, and the installed ceiling reads back as the
// runtime's soft limit — the value the resident datum states.
func TestCeilingIsHalfTheHostsAvailableMemory(t *testing.T) {
	if got := Ceiling(Memory{TotalBytes: 16 << 30, AvailableBytes: 6 << 30}); got != 3<<30 {
		t.Fatalf("Ceiling = %d, want half the available memory (%d)", got, 3<<30)
	}
	if got := Ceiling(Memory{TotalBytes: 16 << 30, AvailableBytes: 600 << 20}); got != CeilingFloor {
		t.Fatalf("Ceiling under a short host = %d, want the floor %d", got, CeilingFloor)
	}
	if got := Ceiling(Memory{}); got != 0 {
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
	root := t.TempDir()
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
		t.Fatalf("InstallCeiling = %d, want half the available memory (%d)", c, 2<<30)
	}
	if got := installedCeiling(); got != 2<<30 {
		t.Fatalf("the installed ceiling reads back as %d, want %d", got, 2<<30)
	}
	// A later operation's derivation follows the host up as well as
	// down — never pinned by an earlier derivation of its own.
	if err := os.WriteFile(filepath.Join(root, "meminfo"), []byte("MemTotal:       33554432 kB\nMemAvailable:    25165824 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := InstallCeiling(); c != 12<<30 || installedCeiling() != 12<<30 {
		t.Fatalf("a later operation's re-derivation installed %d (reads back %d), want %d", c, installedCeiling(), 12<<30)
	}
	// The operator's limit — the one in force before the first
	// derivation — is never widened: a narrower process stays narrower
	// across every later derivation.
	resetWord()
	debug.SetMemoryLimit(1 << 30)
	if c := InstallCeiling(); c != 1<<30 || installedCeiling() != 1<<30 {
		t.Fatalf("InstallCeiling over an operator's narrower limit installed %d (reads back %d), want the narrower %d kept", c, installedCeiling(), 1<<30)
	}
	if c := InstallCeiling(); c != 1<<30 {
		t.Fatalf("a second derivation under the operator's limit installed %d, want %d kept", c, 1<<30)
	}
	// A limit installed earlier that is wider than the derivation does
	// not widen it: the derivation installs; an earlier word only ever
	// narrows.
	resetWord()
	debug.SetMemoryLimit(16 << 30)
	if c := InstallCeiling(); c != 12<<30 || installedCeiling() != 12<<30 {
		t.Fatalf("InstallCeiling under an earlier wider limit installed %d (reads back %d), want the derived %d", c, installedCeiling(), 12<<30)
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
