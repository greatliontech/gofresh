//go:build linux

package guard

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

func gatherFacts() (MachineFacts, error) {
	model, phys, logical, err := cpuInfo()
	if err != nil {
		return MachineFacts{}, err
	}
	if model == "" {
		// No identity field for this arch: fail loud rather than let two
		// different machines share an empty-model fingerprint (false-valid).
		return MachineFacts{}, fmt.Errorf("provenance: no CPU identity in /proc/cpuinfo")
	}
	if logical == 0 {
		// A cpuinfo without processor blocks identifies nothing; falling
		// back to the scheduler's view would smuggle process affinity
		// into machine identity (REQ-guard-machine-transient).
		return MachineFacts{}, fmt.Errorf("provenance: no processor entries in /proc/cpuinfo")
	}
	ram, err := memTotal()
	if err != nil {
		return MachineFacts{}, err
	}
	return MachineFacts{
		CPUModel:      model,
		PhysicalCores: phys,
		LogicalCores:  logical,
		TotalRAMBytes: ram,
		OS:            runtime.GOOS,
		KernelVersion: kernelRelease(),
	}, nil
}

func cpuInfo() (string, int, int, error) {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "", 0, 0, fmt.Errorf("provenance: %w", err)
	}
	defer file.Close()
	model, physical, logical := parseCPUInfo(file)
	return model, physical, logical, nil
}

// parseCPUInfo extracts a stable CPU identity and physical-core count from
// /proc/cpuinfo. The identity is "model name" (x86) or, when absent (e.g.
// aarch64), the composed implementer/part/variant/revision fields — so an
// unknown-arch host never yields an empty identity that would collide with a
// different machine. Physical cores = distinct (physical id, core id) pairs,
// falling back to the logical count when topology fields are absent.
func parseCPUInfo(r io.Reader) (model string, physical, logical int) {
	cores := map[string]bool{}
	arm := map[string]string{}
	var curPhys, curCore string
	flush := func() {
		if curPhys != "" && curCore != "" {
			cores[curPhys+":"+curCore] = true
		}
		curPhys, curCore = "", ""
	}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			if strings.TrimSpace(line) == "" {
				flush() // processor-block boundary
			}
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "processor":
			// Logical CPUs counted from the file's own processor blocks:
			// taskset and cpuset pinning never edit /proc/cpuinfo, so the
			// count stays machine identity, never process affinity
			// (REQ-guard-machine-transient excludes pinning).
			logical++
		case "model name", "Model":
			if model == "" {
				model = val
			}
		case "physical id":
			curPhys = val
		case "core id":
			curCore = val
		case "CPU implementer", "CPU part", "CPU variant", "CPU revision":
			// "CPU architecture" is deliberately excluded: alone it does not
			// discriminate microarchitectures, so a host exposing only it would
			// compose a non-empty-but-colliding identity. Without these real
			// fields the identity stays empty → the intended hard error.
			if _, seen := arm[key]; !seen {
				arm[key] = val
			}
		}
	}
	flush()
	physical = len(cores)
	if physical == 0 {
		physical = logical
	}
	if model == "" && len(arm) > 0 {
		model = composeARM(arm)
	}
	return model, physical, logical
}

func composeARM(arm map[string]string) string {
	keys := make([]string, 0, len(arm))
	for k := range arm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + arm[k]
	}
	return strings.Join(parts, " ")
}

func memTotal() (uint64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("provenance: %w", err)
	}
	defer file.Close()
	return parseMemTotal(file)
}

func parseMemTotal(r io.Reader) (uint64, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			if fields := strings.Fields(rest); len(fields) >= 1 {
				kb, err := strconv.ParseUint(fields[0], 10, 64)
				if err != nil {
					return 0, fmt.Errorf("provenance: parse MemTotal: %w", err)
				}
				return kb * 1024, nil
			}
		}
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("provenance: read meminfo: %w", err)
	}
	return 0, fmt.Errorf("provenance: MemTotal not found in /proc/meminfo")
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
