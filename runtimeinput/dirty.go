package runtimeinput

// CommitInspector reports whether a module-relative path was committed at a given
// ref. The caller supplies it from its own git layer, so runtimeinput carries no git
// dependency — validity never reads the commit (REQ-fresh-commit-independent); this
// is only for the dirty determination below.
type CommitInspector interface {
	// ExistsAt reports whether moduleRelPath (slash-separated, relative to the module
	// root) is present — as a file or a directory — in the tree at commit.
	ExistsAt(commit, moduleRelPath string) (bool, error)
}

// Uncommitted reports whether the manifest names a module-local input that is not
// present at commit — gitignored, untracked, or created during the run. Such an
// input is not reproducible from that commit, so a recording backed by it is not
// faithful to its commit and the caller marks it dirty (REQ-inputs-dirty): usable
// for working-tree reuse, barred as a baseline. Only module-relative inputs are
// checked; an external absolute input is outside the module's git and does not bear
// on the recording's faithfulness to its own commit.
func Uncommitted(encoded, commit string, inspector CommitInspector) (bool, error) {
	rels, err := ModuleRelPaths(encoded)
	if err != nil {
		return false, err
	}
	for _, rel := range rels {
		present, err := inspector.ExistsAt(commit, rel)
		if err != nil {
			return false, err
		}
		if !present {
			return true, nil
		}
	}
	return false, nil
}
