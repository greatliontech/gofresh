package runtimeinput

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// touchFuture moves a file's times forward, the way a fresh checkout
// mints fresh modification times.
func touchFuture(t *testing.T, path string) {
	t.Helper()
	future := time.Now().Add(90 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

// An open-observed input binds exactly what an open can expose —
// content, mode, size — so its digest survives a modification-time
// change and the identity revalidates in a second checkout of the
// same content (REQ-inputs-observation-class).
func TestOpenObservedEvidenceTravelsAcrossCheckouts(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	target := filepath.Join(packageDir, "a.txt")
	if err := os.WriteFile(target, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLog([]byte("open a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if !obs.OK || obs.Unverifiable {
		t.Fatalf("observation = %+v", obs)
	}
	m, err := decode(obs.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range m.Paths {
		if entry.Metadata {
			t.Fatalf("open-only entry marked metadata-bound: %+v", entry)
		}
	}
	touchFuture(t, target)
	after, err := Current(obs.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if after != obs.State {
		t.Fatalf("open-observed digest moved on an mtime touch:\n got %+v\nwant %+v", after, obs.State)
	}
	// A second checkout: same content, different root, fresh times.
	secondRoot := filepath.Join(t.TempDir(), "clone")
	if err := os.MkdirAll(filepath.Join(secondRoot, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secondRoot, "pkg", "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	moved, err := Current(obs.Manifest, secondRoot)
	if err != nil {
		t.Fatal(err)
	}
	if moved.Digest != obs.State.Digest || !moved.OK {
		t.Fatalf("open-observed evidence did not travel: %+v vs %+v", moved, obs.State)
	}
}

// A stat-observed input binds the full object state — the recorded
// operation exposed the metadata — so its digest moves with the
// modification time (REQ-inputs-observation-class).
func TestStatObservedEvidenceStaysMetadataBound(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	target := filepath.Join(packageDir, "a.txt")
	if err := os.WriteFile(target, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLog([]byte("stat a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(obs.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || !m.Paths[0].Metadata {
		t.Fatalf("stat entry not metadata-bound: %+v", m.Paths)
	}
	touchFuture(t, target)
	after, err := Current(obs.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if after == obs.State {
		t.Fatal("metadata-bound digest ignored an mtime change")
	}
}

// A stat after an open upgrades the entry in place: one identity, the
// stronger class (REQ-inputs-observation-class).
func TestStatUpgradesAnOpenObservedEntry(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLog([]byte("open a.txt\nstat a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(obs.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || !m.Paths[0].Metadata {
		t.Fatalf("stat did not upgrade the open-recorded entry: %+v", m.Paths)
	}
}

// Merging an open-only observation with a stat observation of the
// same identity keeps the metadata-bound class
// (REQ-inputs-observation-class).
func TestMergeUnionsObservationClasses(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	opened, err := FromTestLog([]byte("open a.txt\n"), moduleDir, packageDir, WithCompletedProcess("opener"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	statted, err := FromTestLog([]byte("stat a.txt\n"), moduleDir, packageDir, WithCompletedProcess("statter"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := Merge(moduleDir, opened, statted)
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(merged.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || !m.Paths[0].Metadata {
		t.Fatalf("merge dropped the metadata-bound class: %+v", m.Paths)
	}
}

// Relative is the persisted portable form: identities under the
// module convert to module-relative, the state revalidates in a
// second checkout of the same content, and the observation class
// rides the conversion (REQ-inputs-relative-identities).
func TestRelativeIdentitiesTravelAcrossCheckoutRoots(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLog([]byte("open a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := Absolute(obs, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := Relative(absolute, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(relative.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range m.Paths {
		if entry.Kind != "rel" {
			t.Fatalf("in-module identity not relative after conversion: %+v", entry)
		}
	}
	secondRoot := filepath.Join(t.TempDir(), "clone")
	if err := os.MkdirAll(filepath.Join(secondRoot, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secondRoot, "pkg", "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	moved, err := Current(relative.Manifest, secondRoot)
	if err != nil {
		t.Fatal(err)
	}
	if moved.Digest != relative.State.Digest || !moved.OK {
		t.Fatalf("relative evidence did not travel: %+v vs %+v", moved, relative.State)
	}
	paths, err := Paths(relative.Manifest, secondRoot)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(secondRoot, "pkg", "a.txt")
	if len(paths) != 1 || paths[0] != want {
		t.Fatalf("relative identity materialized %v, want [%s]", paths, want)
	}
}

// A metadata-bound class rides both identity-kind conversions and the
// round trip unchanged — a conversion must never downgrade an entry
// whose subject observed metadata (REQ-inputs-observation-class,
// REQ-inputs-relative-identities).
func TestConversionsPreserveMetadataClass(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLog([]byte("stat a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	metadataBound := func(label string, o Observation) {
		t.Helper()
		m, err := decode(o.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Paths) != 1 || !m.Paths[0].Metadata {
			t.Fatalf("%s dropped the metadata-bound class: %+v", label, m.Paths)
		}
	}
	metadataBound("observation", obs)
	absolute, err := Absolute(obs, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	metadataBound("Absolute", absolute)
	relative, err := Relative(absolute, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	metadataBound("Relative", relative)
	again, err := Absolute(relative, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	metadataBound("round trip", again)
	if again.State != absolute.State {
		t.Fatalf("metadata-bound round trip diverged:\n got %+v\nwant %+v", again.State, absolute.State)
	}
}

// A conversion that maps two identity kinds onto one identity
// collapses them under the class-union rule instead of minting a
// duplicate the validator refuses (REQ-inputs-observation-class).
func TestConversionCollapsesKindsUnderClassUnion(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	opened, err := FromTestLog([]byte("open a.txt\n"), moduleDir, packageDir, WithCompletedProcess("opener"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	statted, err := FromTestLog([]byte("stat a.txt\n"), moduleDir, packageDir, WithCompletedProcess("statter"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	// Absolutize only one side, then merge under a foreign root: the
	// merged manifest carries the SAME file as a rel identity (open,
	// content-bound) and an abs identity (stat, metadata-bound).
	absStatted, err := Absolute(statted, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := Merge(moduleDir, opened, absStatted)
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(merged.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 2 {
		t.Fatalf("fixture did not produce both kinds: %+v", m.Paths)
	}
	// Relative maps both onto one rel identity: one entry, class union.
	relative, err := Relative(merged, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	m, err = decode(relative.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || !m.Paths[0].Metadata || m.Paths[0].Kind != "rel" {
		t.Fatalf("kind collapse dropped the class union: %+v", m.Paths)
	}
}

// External identities stay absolute through Relative — only the
// module's own surface relativizes (REQ-inputs-relative-identities).
func TestRelativeExternalIdentitiesStayAbsolute(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	external := filepath.Join(t.TempDir(), "external.txt")
	if err := os.WriteFile(external, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLog([]byte("open "+external+"\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	relative, err := Relative(obs, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(relative.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Kind != "abs" || m.Paths[0].Path != external {
		t.Fatalf("external identity did not stay absolute: %+v", m.Paths)
	}
}

// Relative refuses a state that moved since observation, exactly as
// Absolute does (REQ-inputs-relative-identities).
func TestRelativeRefusesMovedState(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	target := filepath.Join(packageDir, "a.txt")
	if err := os.WriteFile(target, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLog([]byte("open a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Relative(obs, moduleDir); err == nil || !strings.Contains(err.Error(), "state moved before relative identity conversion") {
		t.Fatalf("moved state accepted: %v", err)
	}
}

// The two conversions are inverses on states: converting to relative
// and back reproduces the absolute state exactly
// (REQ-inputs-relative-identities, REQ-inputs-absolute-identities).
func TestRelativeRoundTripsWithAbsolute(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLog([]byte("open a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := Absolute(obs, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := Relative(absolute, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Absolute(relative, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if again.State != absolute.State {
		t.Fatalf("round trip diverged:\n got %+v\nwant %+v", again.State, absolute.State)
	}
}
