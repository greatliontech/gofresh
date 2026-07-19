package runtimeinput

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestDescribeDisclosesIdentitySet pins the explanation surface of
// REQ-inputs-path-identities: a manifest's env names, materialized paths, and
// unverifiable dispositions are enumerable — identities only, never values.
func TestDescribeDisclosesIdentitySet(t *testing.T) {
	dir := t.TempDir()
	obs, err := Incomplete(dir, "package-test-binary:describe", "testlog lacks operation outcome evidence")
	if err != nil {
		t.Fatal(err)
	}
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Describe(st.Manifest, dir)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if len(d.Unverifiable) == 0 {
		t.Fatal("incomplete observation's disposition not disclosed")
	}
	if len(d.EnvNames) != 0 || len(d.Paths) != 0 {
		t.Fatalf("incomplete observation disclosed identities: %+v", d)
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A manifest with concrete identities: build one from a testlog observation
	// under the completed-observation contract (process assertion + bracket).
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testdata", "fixture.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket, err := CaptureBracket(dir, []string{"testdata"})
	if err != nil {
		t.Fatal(err)
	}
	log := []byte("getenv HOME\nstat testdata/fixture.json\n")
	fromLog, err := FromTestLog(log, dir, dir, WithCompletedProcess("package-test-binary:describe"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	logState, err := CompletedState(fromLog)
	if err != nil {
		t.Fatal(err)
	}
	ld, err := Describe(logState.Manifest, dir)
	if err != nil {
		t.Fatalf("Describe(testlog): %v", err)
	}
	if !reflect.DeepEqual(ld.EnvNames, []string{"HOME"}) {
		t.Fatalf("env names = %v, want [HOME]", ld.EnvNames)
	}
	wantPath := filepath.Join(abs, "testdata", "fixture.json")
	if !reflect.DeepEqual(ld.Paths, []string{wantPath}) {
		t.Fatalf("paths = %v, want [%s]", ld.Paths, wantPath)
	}
	if _, err := Describe("not-a-manifest", dir); err == nil {
		t.Fatal("malformed manifest described")
	}
}
