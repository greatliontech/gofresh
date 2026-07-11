package runtimeinput

import "fmt"

// CommitInspector reports whether a module-relative runtime input's current
// Git-representable state is reproducible at a given ref. The caller supplies it from
// its own git layer, so runtimeinput carries no git dependency: validity never reads
// the commit (REQ-fresh-commit-independent); this is only for dirty evidence.
type CommitInspector interface {
	// ReproducibleAt compares the current identity at moduleRelPath with the regular
	// file, executable mode, symlink target, or directory tree represented at commit.
	ReproducibleAt(commit, moduleRelPath string) (bool, error)
}

// Dirty revalidates state against the current module view, then reports whether it
// names a module-local input whose current Git-representable state is not
// reproducible at commit. A recording backed by such an input is usable for
// working-tree reuse but barred as a baseline (REQ-inputs-dirty). Only
// module-relative inputs are checked; external absolute inputs are outside the
// module's git scope.
func Dirty(state State, moduleDir, commit string, inspector CommitInspector) (bool, error) {
	if inspector == nil {
		return false, fmt.Errorf("runtimeinputs: nil commit inspector")
	}
	if !state.OK || state.Manifest == "" || state.Digest == "" {
		return false, fmt.Errorf("runtimeinputs: incomplete state for dirty inspection")
	}
	current, err := Current(state.Manifest, moduleDir)
	if err != nil {
		return false, err
	}
	if current != state {
		return false, fmt.Errorf("runtimeinputs: state moved before dirty inspection")
	}
	rels, err := ModuleRelPaths(state.Manifest)
	if err != nil {
		return false, err
	}
	dirty := false
	for _, rel := range rels {
		reproducible, err := inspector.ReproducibleAt(commit, rel)
		if err != nil {
			return false, err
		}
		if !reproducible {
			dirty = true
		}
	}
	return dirty, nil
}
