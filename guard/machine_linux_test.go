//go:build linux

package guard

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestParseCPUInfo(t *testing.T) {
	const x86 = "processor\t: 0\n" +
		"model name\t: AMD Ryzen 9 5950X\n" +
		"physical id\t: 0\ncore id\t\t: 0\n\n" +
		"processor\t: 1\nmodel name\t: AMD Ryzen 9 5950X\n" +
		"physical id\t: 0\ncore id\t\t: 0\n\n" +
		"processor\t: 2\nmodel name\t: AMD Ryzen 9 5950X\n" +
		"physical id\t: 0\ncore id\t\t: 1\n"
	if model, phys, logical := parseCPUInfo(strings.NewReader(x86)); model != "AMD Ryzen 9 5950X" || phys != 2 || logical != 3 {
		t.Errorf("x86: got model=%q phys=%d logical=%d, want %q / 2 / 3", model, phys, logical, "AMD Ryzen 9 5950X")
	}

	// ARM: no "model name" — identity must be composed, never empty.
	const arm = "processor\t: 0\nBogoMIPS\t: 50.00\n" +
		"CPU implementer\t: 0x41\nCPU architecture: 8\n" +
		"CPU variant\t: 0x0\nCPU part\t: 0xd0c\nCPU revision\t: 1\n"
	model, phys, _ := parseCPUInfo(strings.NewReader(arm))
	if model == "" {
		t.Error("arm: empty identity (must compose from CPU implementer/part/...)")
	}
	if !strings.Contains(model, "0xd0c") || !strings.Contains(model, "0x41") {
		t.Errorf("arm: identity missing fields: %q", model)
	}
	if phys < 1 {
		t.Errorf("arm: physical fallback %d", phys)
	}

	// VM without topology fields: physical falls back to logical (>=1).
	const vm = "processor\t: 0\nmodel name\t: Common KVM processor\n"
	if model, phys, _ := parseCPUInfo(strings.NewReader(vm)); model != "Common KVM processor" || phys < 1 {
		t.Errorf("vm: got model=%q phys=%d", model, phys)
	}
}

func TestParseMemTotal(t *testing.T) {
	const mem = "MemTotal:       65809536 kB\nMemFree:         1234 kB\n"
	got, err := parseMemTotal(strings.NewReader(mem))
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(65809536) * 1024; got != want {
		t.Errorf("MemTotal: got %d, want %d", got, want)
	}
	if _, err := parseMemTotal(strings.NewReader("MemFree: 10 kB\n")); err == nil {
		t.Error("expected error when MemTotal absent")
	}
}

// LogicalCores is machine identity, never process affinity: under an
// affinity-restricted child process (taskset -c 0), the gathered count
// must still be the machine's full processor count — runtime.NumCPU in
// that child would report 1 (REQ-guard-machine-transient excludes
// pinning).
func TestLogicalCoresIgnoreProcessAffinity(t *testing.T) {
	if os.Getenv("GOFRESH_AFFINITY_HELPER") == "1" {
		facts, err := CurrentMachineFacts()
		if err != nil {
			fmt.Println("ERR", err)
			os.Exit(1)
		}
		fmt.Println("LOGICAL", facts.LogicalCores, "NUMCPU", runtime.NumCPU())
		os.Exit(0)
	}
	if _, err := exec.LookPath("taskset"); err != nil {
		t.Skip("taskset unavailable")
	}
	full, err := CurrentMachineFacts()
	if err != nil {
		t.Fatal(err)
	}
	if full.LogicalCores < 2 {
		t.Skip("single-logical-CPU machine cannot distinguish affinity")
	}
	cmd := exec.Command("taskset", "-c", "0", os.Args[0], "-test.run", "TestLogicalCoresIgnoreProcessAffinity")
	cmd.Env = append(os.Environ(), "GOFRESH_AFFINITY_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// The helper reporting its own gather failure is a defect; a
		// launch-shaped failure (a cpuset excluding CPU 0 makes taskset
		// itself fail) is an environmental limitation and skips.
		if strings.HasPrefix(string(out), "ERR") {
			t.Fatalf("pinned child gather failed: %s", out)
		}
		t.Skipf("taskset launch failed (restricted environment?): %v\n%s", err, out)
	}
	var logical, numcpu int
	if _, err := fmt.Sscanf(string(out), "LOGICAL %d NUMCPU %d", &logical, &numcpu); err != nil {
		t.Fatalf("helper output %q: %v", out, err)
	}
	if numcpu != 1 {
		t.Skipf("affinity restriction did not take (NumCPU=%d)", numcpu)
	}
	if logical != full.LogicalCores {
		t.Fatalf("pinned child gathered LogicalCores=%d, want the machine's %d — affinity leaked into machine identity", logical, full.LogicalCores)
	}
}

// An unreadable kernel-release source fails the whole gather loud: an
// empty KernelVersion would digest equal at seal and check across a
// kernel change, silently vacating the one fact the file carries
// (REQ-guard-machine; the runtime-input projection digest inherits it).
func TestGatherFactsFailsLoudOnUnreadableKernelRelease(t *testing.T) {
	prev := readKernelRelease
	readKernelRelease = func() (string, error) {
		return "", fmt.Errorf("provenance: injected unreadable osrelease")
	}
	defer func() { readKernelRelease = prev }()
	if _, err := gatherFacts(); err == nil || !strings.Contains(err.Error(), "osrelease") {
		t.Fatalf("gather error = %v, want the unreadable kernel-release source surfaced", err)
	}
}

// The runtime-input allowlist derives from this source list; the list
// itself must name every file the gatherer opens. The literal pin
// catches edits to the LIST — that the gatherer opens nothing beyond
// the list remains a reviewed convention, tracked in
// docs/issues/machine-fact-source-list-unenforced.md.
func TestMachineFactSourcesNameTheGathererReads(t *testing.T) {
	want := []string{"/proc/cpuinfo", "/proc/meminfo", "/proc/sys/kernel/osrelease"}
	if !slices.Equal(MachineFactSources, want) {
		t.Fatalf("MachineFactSources = %v, want %v", MachineFactSources, want)
	}
}
