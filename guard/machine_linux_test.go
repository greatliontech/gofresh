//go:build linux

package guard

import (
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
	if model, phys := parseCPUInfo(strings.NewReader(x86)); model != "AMD Ryzen 9 5950X" || phys != 2 {
		t.Errorf("x86: got model=%q phys=%d, want %q / 2", model, phys, "AMD Ryzen 9 5950X")
	}

	// ARM: no "model name" — identity must be composed, never empty.
	const arm = "processor\t: 0\nBogoMIPS\t: 50.00\n" +
		"CPU implementer\t: 0x41\nCPU architecture: 8\n" +
		"CPU variant\t: 0x0\nCPU part\t: 0xd0c\nCPU revision\t: 1\n"
	model, phys := parseCPUInfo(strings.NewReader(arm))
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
	if model, phys := parseCPUInfo(strings.NewReader(vm)); model != "Common KVM processor" || phys < 1 {
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
