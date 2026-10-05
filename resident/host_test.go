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
	resetOperatorLimit := func() {
		operatorLimit.mu.Lock()
		operatorLimit.taken, operatorLimit.limit = false, 0
		operatorLimit.mu.Unlock()
	}
	resetOperatorLimit()
	t.Cleanup(resetOperatorLimit)
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
	resetOperatorLimit()
	debug.SetMemoryLimit(1 << 30)
	if c := InstallCeiling(); c != 1<<30 || installedCeiling() != 1<<30 {
		t.Fatalf("InstallCeiling over an operator's narrower limit installed %d (reads back %d), want the narrower %d kept", c, installedCeiling(), 1<<30)
	}
	if c := InstallCeiling(); c != 1<<30 {
		t.Fatalf("a second derivation under the operator's limit installed %d, want %d kept", c, 1<<30)
	}
	// An operator's limit wider than the derivation does not widen it:
	// the derivation installs, the operator's word only ever narrows.
	resetOperatorLimit()
	debug.SetMemoryLimit(16 << 30)
	if c := InstallCeiling(); c != 12<<30 || installedCeiling() != 12<<30 {
		t.Fatalf("InstallCeiling under an operator's wider limit installed %d (reads back %d), want the derived %d", c, installedCeiling(), 12<<30)
	}
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
