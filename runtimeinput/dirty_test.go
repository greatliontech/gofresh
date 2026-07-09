package runtimeinput

import (
	"os"
	"path/filepath"
	"testing"
)

type fakeInspector struct{ committed map[string]bool }

func (f fakeInspector) ExistsAt(commit, rel string) (bool, error) { return f.committed[rel], nil }

// TestUncommitted pins REQ-inputs-dirty: a module-local input present at the commit
// is not uncommitted; one absent at the commit — gitignored, untracked, or created
// during the run — is, so the caller marks the recording dirty.
func TestUncommitted(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "fixture.dat"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := FromTestLog([]byte("# test log\nopen fixture.dat\n"), moduleDir, packageDir)
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	rels, err := ModuleRelPaths(st.Manifest)
	if err != nil || len(rels) == 0 {
		t.Fatalf("ModuleRelPaths: err=%v rels=%v; manifest must carry the module-local input", err, rels)
	}
	rel := rels[0]

	committed := fakeInspector{committed: map[string]bool{rel: true}}
	if u, err := Uncommitted(st.Manifest, "c", committed); err != nil || u {
		t.Errorf("committed input: uncommitted=%v err=%v, want false", u, err)
	}
	absent := fakeInspector{committed: map[string]bool{}}
	if u, err := Uncommitted(st.Manifest, "c", absent); err != nil || !u {
		t.Errorf("absent input: uncommitted=%v err=%v, want true", u, err)
	}
}
