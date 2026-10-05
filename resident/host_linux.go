//go:build linux

package resident

import (
	"os"
	"path/filepath"
)

// hostMemory reads /proc/meminfo under the process table root the
// sampler reads; an unreadable file yields no reading.
func hostMemory() (Memory, bool) {
	text, err := os.ReadFile(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return Memory{}, false
	}
	return parseMeminfo(string(text))
}
