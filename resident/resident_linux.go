//go:build linux

package resident

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// procRoot is the process table the reading walks; tests point it at a
// synthetic tree.
var procRoot = "/proc"

// sample reads the process table once: the process's own status for its
// resident and peak bytes, every process's stat line for its parent and
// state, then the status of each live descendant for its resident and
// peak bytes. An unlistable table yields no reading; a descendant whose
// files vanish between the listing and the read has exited and is not
// counted; a descendant whose status exists but cannot be read voids
// the reading — a count missing a live descendant would be partial, and
// the datum is absent before it is partial. Two more classes are not
// counted and void nothing, each stated by the clause: a stat that
// cannot be read or does not parse names no process (the table hides
// it, or it is leaving), and a live descendant whose status carries no
// memory line at all is a process between releasing its memory and its
// exit — nothing resident to count; a status carrying a memory line the
// walk cannot read whole voids the reading like one it cannot read.
func sample() (Set, bool) {
	set, _, ok := sampleAt(procRoot, os.Getpid())
	return set, ok
}

// sampleTrees reads the running process's set with its direct children's
// trees attributed.
func sampleTrees() (Set, map[int]uint64, bool) { return sampleAt(procRoot, os.Getpid()) }

// sampleAt reads the table under root for the process self: its Set and
// the resident bytes of each of its direct children's subtrees, keyed by
// the child's pid.
func sampleAt(root string, self int) (Set, map[int]uint64, bool) {
	status, err := os.ReadFile(filepath.Join(root, strconv.Itoa(self), "status"))
	if err != nil {
		return Set{}, nil, false
	}
	own, ok := parseStatus(string(status))
	if !ok {
		return Set{}, nil, false
	}
	set := Set{ProcessBytes: own.rss, ProcessPeakBytes: own.peak, ProcessHeldBytes: own.held, HeldKnown: own.heldKnown}
	trees := map[int]uint64{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return Set{}, nil, false
	}
	// The live children of every parent, from one pass over the table.
	children := map[int][]int{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == self {
			continue
		}
		line, err := os.ReadFile(filepath.Join(root, entry.Name(), "stat"))
		if err != nil {
			// Unreadable or gone: the table hides it, or it is
			// leaving — no process to count.
			continue
		}
		ppid, state, ok := parseStat(string(line))
		if !ok || !live(state) {
			continue
		}
		children[ppid] = append(children[ppid], pid)
	}
	// The descendants, breadth first; a process table has no cycles, and
	// the seen set guards the walk against a pid reused mid-listing.
	// Each descendant is attributed to the direct child whose subtree
	// holds it: a direct child is its own tree's root, a deeper process
	// inherits its parent's root.
	seen := map[int]bool{self: true}
	treeOf := map[int]int{}
	queue := []int{self}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, pid := range children[parent] {
			if seen[pid] {
				continue
			}
			seen[pid] = true
			queue = append(queue, pid)
			tree := pid
			if parent != self {
				tree = treeOf[parent]
			}
			treeOf[pid] = tree
			text, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "status"))
			if exited(err) {
				continue
			}
			if err != nil {
				return Set{}, nil, false
			}
			st, leaving, ok := parseDescendantStatus(string(text))
			if leaving {
				// No memory line at all: the process has released
				// its memory on its way out — not counted.
				continue
			}
			if !ok {
				// A memory line the walk cannot read whole: a live
				// set it cannot price voids the reading.
				return Set{}, nil, false
			}
			set.Descendants++
			set.DescendantsBytes += st.rss
			set.DescendantsHeldBytes += st.held
			set.DescendantPeakBytes = max(set.DescendantPeakBytes, st.peak)
			trees[tree] += st.rss
		}
	}
	return set, trees, true
}

// exited reports whether a /proc read failed because its process is
// gone: the entry vanished, or the kernel answers that no such process
// exists.
func exited(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}
