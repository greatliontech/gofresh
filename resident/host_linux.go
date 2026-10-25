//go:build linux

package resident

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// cgroupRoot is the cgroup v2 hierarchy mount point; tests point it at a
// synthetic directory.
var cgroupRoot = "/sys/fs/cgroup"

// hostMemory reads /proc/meminfo under the process table root the
// sampler reads and caps the reading by any active cgroup v2 memory
// limit; an unreadable meminfo file yields no reading.
func hostMemory() (Memory, bool) {
	text, err := os.ReadFile(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return Memory{}, false
	}
	m, ok := parseMeminfo(string(text))
	if !ok {
		return Memory{}, false
	}
	return applyCgroupMemoryLimit(m, procRoot, cgroupRoot), true
}

func applyCgroupMemoryLimit(m Memory, procDir, cgRoot string) Memory {
	data, err := os.ReadFile(filepath.Join(procDir, "self", "cgroup"))
	if err != nil {
		return m
	}
	rel, ok := parseCgroupV2Path(string(data))
	if !ok {
		return m
	}
	root := filepath.Clean(cgRoot)
	for dir := filepath.Join(root, filepath.FromSlash(rel)); ; {
		if limit, ok := readCgroupDirLimit(dir); ok {
			if limit < m.TotalBytes {
				m.TotalBytes = limit
			}
			avail := limit
			if curBytes, err := os.ReadFile(filepath.Join(dir, "memory.current")); err == nil {
				if cur, err := strconv.ParseUint(strings.TrimSpace(string(curBytes)), 10, 64); err == nil {
					if cur < limit {
						avail = limit - cur
					} else {
						avail = 0
					}
				}
			}
			if avail < m.AvailableBytes {
				m.AvailableBytes = avail
			}
		}
		if dir == root {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir || !strings.HasPrefix(parent, root) {
			break
		}
		dir = parent
	}
	return m
}

func readCgroupDirLimit(dir string) (uint64, bool) {
	var best uint64
	var have bool
	for _, name := range []string{"memory.max", "memory.high"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(raw))
		if text == "" || text == "max" {
			continue
		}
		val, err := strconv.ParseUint(text, 10, 64)
		if err != nil || val == 0 {
			continue
		}
		if !have || val < best {
			best = val
			have = true
		}
	}
	return best, have
}

func parseCgroupV2Path(text string) (string, bool) {
	for line := range strings.SplitSeq(text, "\n") {
		if path, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok && strings.HasPrefix(path, "/") {
			return path, true
		}
	}
	return "", false
}
