package runtimeinput

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeInspector struct{ reproducible map[string]bool }

func (f fakeInspector) ReproducibleAt(commit, rel string) (bool, error) {
	return f.reproducible[rel], nil
}

// TestDirtyEvidence pins REQ-inputs-dirty: a reproducible module-local input is
// clean; one whose current Git-representable state differs from the commit makes the
// recording dirty.
func TestDirtyEvidence(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "fixture.dat"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := FromTestLog([]byte("# test log\nopen fixture.dat\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	rels, err := ModuleRelPaths(st.Manifest)
	if err != nil || len(rels) == 0 {
		t.Fatalf("ModuleRelPaths: err=%v rels=%v; manifest must carry the module-local input", err, rels)
	}
	rel := rels[0]

	matching := fakeInspector{reproducible: map[string]bool{rel: true}}
	if dirty, err := Dirty(st, moduleDir, "c", matching); err != nil || dirty {
		t.Errorf("reproducible input: dirty=%v err=%v, want false", dirty, err)
	}
	different := fakeInspector{reproducible: map[string]bool{}}
	if dirty, err := Dirty(st, moduleDir, "c", different); err != nil || !dirty {
		t.Errorf("non-reproducible input: dirty=%v err=%v, want true", dirty, err)
	}
}

type inspecting struct {
	present map[string]bool
	fail    map[string]error
	calls   []string
}

func (i *inspecting) ReproducibleAt(_ string, rel string) (bool, error) {
	i.calls = append(i.calls, rel)
	if err := i.fail[rel]; err != nil {
		return false, err
	}
	return i.present[rel], nil
}

func TestMergedManifestDirtyEvidenceIsMonotone(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	for _, name := range []string{"committed.txt", "generated.txt"} {
		if err := os.WriteFile(filepath.Join(packageDir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	committed, err := FromTestLog([]byte("open committed.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker-committed"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	generated, err := FromTestLog([]byte("open generated.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker-generated"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := Merge(moduleDir, committed, generated)
	if err != nil {
		t.Fatal(err)
	}
	inspector := fakeInspector{reproducible: map[string]bool{"pkg/committed.txt": true}}
	dirty, err := Dirty(merged, moduleDir, "commit", inspector)
	if err != nil || !dirty {
		t.Fatalf("merged dirty evidence = %v, %v; want true, nil", dirty, err)
	}
}

func TestDirtyDoesNotHideInspectionFailure(t *testing.T) {
	moduleDir := t.TempDir()
	state, err := FromTestLog([]byte("open absent\nopen broken\n"), moduleDir, moduleDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("inspect failed")
	inspector := &inspecting{present: map[string]bool{}, fail: map[string]error{"broken": wantErr}}
	if dirty, err := Dirty(state, moduleDir, "commit", inspector); !errors.Is(err, wantErr) || dirty {
		t.Fatalf("Dirty = %v, %v; want false, inspect failed", dirty, err)
	}
	if got := strings.Join(inspector.calls, ","); got != "absent,broken" {
		t.Fatalf("inspection calls = %q, want both paths", got)
	}
	if _, err := Dirty(state, moduleDir, "commit", nil); err == nil {
		t.Fatal("nil inspector accepted")
	}
}

func TestDirtyRejectsStateThatMovedBeforeInspection(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	path := filepath.Join(packageDir, "fixture.dat")
	if err := os.WriteFile(path, []byte("recorded"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := FromTestLog([]byte("open fixture.dat\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("commit state"), 0o644); err != nil {
		t.Fatal(err)
	}
	inspector := fakeInspector{reproducible: map[string]bool{"pkg/fixture.dat": true}}
	if dirty, err := Dirty(state, moduleDir, "commit", inspector); err == nil || dirty {
		t.Fatalf("Dirty = %v, %v; want moved-state error", dirty, err)
	}
}

func TestDirtyEnvRevalidatesWithSuppliedEnvironment(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	path := filepath.Join(packageDir, "fixture.dat")
	if err := os.WriteFile(path, []byte("recorded"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", "/ambient/workspace")
	env := []string{"GOWORK=/explicit/workspace"}
	state, err := FromTestLogEnv([]byte("getenv GOWORK\nopen fixture.dat\n"), moduleDir, packageDir, env, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	inspector := fakeInspector{reproducible: map[string]bool{"pkg/fixture.dat": true}}
	if dirty, err := DirtyEnv(state, moduleDir, "commit", inspector, env); err != nil || dirty {
		t.Fatalf("DirtyEnv = %v, %v; want false, nil", dirty, err)
	}
	if dirty, err := Dirty(state, moduleDir, "commit", inspector); err == nil || dirty {
		t.Fatalf("ambient Dirty = %v, %v; want moved-state error", dirty, err)
	}
}
