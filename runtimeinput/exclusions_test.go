package runtimeinput

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExcludedPathsAreNeverRecorded pins REQ-inputs-exclusions: an
// excluded observation records neither a path identity nor a per-path
// disposition, and the digest is blind to the excluded content.
func TestExcludedPathsAreNeverRecorded(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	git := filepath.Join(moduleDir, ".git")
	if err := os.MkdirAll(git, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(git, "HEAD"), []byte("ref: main"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "fixture.txt"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(packageDir, git)
	if err != nil {
		t.Fatal(err)
	}
	log := []byte(
		"open " + filepath.Join(rel, "HEAD") + "\n" +
			"stat " + rel + "\n" +
			"open fixture.txt\n")

	state, err := FromTestLogEnv(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithExcludedPaths(".git"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range m.Paths {
		if strings.Contains(id.Path, ".git") {
			t.Fatalf("excluded identity recorded: %+v", id)
		}
	}
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, ".git") {
			t.Fatalf("excluded path left a disposition: %q", reason)
		}
	}
	if len(m.Paths) != 1 || m.Paths[0].Path == "" {
		t.Fatalf("non-excluded observation lost: %+v", m.Paths)
	}

	// The digest is blind to excluded content: mutate .git, recheck.
	if err := os.WriteFile(filepath.Join(git, "HEAD"), []byte("ref: other"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := Current(state.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if after.Digest != state.Digest {
		t.Fatal("digest moved on excluded content")
	}
}

// TestExclusionBoundaryIsPathSeparator pins the boundary rule: ".git"
// excludes ".git" and ".git/x", never ".gitignore".
func TestExclusionBoundaryIsPathSeparator(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(moduleDir, ".gitignore"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(packageDir, filepath.Join(moduleDir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := FromTestLogEnv([]byte("open "+rel+"\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithExcludedPaths(".git"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != ".gitignore" {
		t.Fatalf("sibling with shared prefix wrongly excluded: %+v", m.Paths)
	}
}

// TestExclusionOfRootListingKeepsChildren pins the exact-identity leg:
// excluding "." drops the root listing, never paths beneath it.
func TestExclusionOfRootListingKeepsChildren(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(moduleDir, "spec.md"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	relRoot, err := filepath.Rel(packageDir, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	relSpec, err := filepath.Rel(packageDir, filepath.Join(moduleDir, "spec.md"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := FromTestLogEnv([]byte("open "+relRoot+"\nopen "+relSpec+"\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithExcludedPaths("."), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "spec.md" {
		t.Fatalf("paths = %+v, want only spec.md (root listing excluded, child kept)", m.Paths)
	}
}

// TestExclusionAbsoluteKind pins absolute-pattern matching against
// absolute identities, kind-scoped.
func TestExclusionAbsoluteKind(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "blob.bin"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "fixture.txt"), []byte("f"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := []byte("open " + filepath.Join(outside, "blob.bin") + "\nopen fixture.txt\n")
	state, err := FromTestLogEnv(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithExcludedPaths(outside), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range m.Paths {
		if strings.Contains(id.Path, "blob.bin") {
			t.Fatalf("excluded absolute identity recorded: %+v", id)
		}
	}
	if len(m.Paths) != 1 {
		t.Fatalf("paths = %+v, want only the module fixture", m.Paths)
	}
}

// TestExcludedChdirStillTracksWorkingDirectory pins the untouched-cwd
// leg of REQ-inputs-exclusions: excluding a chdir target suppresses
// its identity but never breaks relative resolution of later ops.
func TestExcludedChdirStillTracksWorkingDirectory(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	// The layout makes wrong-cwd resolution DISTINGUISHABLE: from the
	// excluded dir, ../kept.txt is deep/kept.txt; from the stale cwd it
	// would be a different identity.
	scratch := filepath.Join(moduleDir, "deep", "scratch")
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "deep", "kept.txt"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(packageDir, scratch)
	if err != nil {
		t.Fatal(err)
	}
	// chdir into the excluded dir, then open a file OUTSIDE the
	// exclusion by a path relative to the new cwd: only correct cwd
	// tracking through the excluded chdir resolves it to deep/kept.txt.
	log := []byte("chdir " + rel + "\nopen ../kept.txt\n")
	state, err := FromTestLogEnv(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithExcludedPaths("deep/scratch"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "deep/kept.txt" {
		t.Fatalf("cwd tracking broken under exclusion: paths = %+v", m.Paths)
	}
	for _, id := range m.Paths {
		if strings.Contains(id.Path, "scratch") {
			t.Fatalf("excluded chdir identity recorded: %+v", id)
		}
	}
}

// TestEmptyExclusionPatternRefused pins the refusal: an empty pattern
// must never silently read as the root listing.
func TestEmptyExclusionPatternRefused(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if _, err := FromTestLogEnv([]byte("open x\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithExcludedPaths(""), WithBracket(testBracket(t, moduleDir))); err == nil {
		t.Fatal("empty exclusion pattern accepted")
	}
}

// An exclusion outranks classification: a path the classifier would
// refuse — an external directory, a volatile OS object — discharges
// silently when excluded, never sealing the observation unverifiable
// (REQ-inputs-exclusions' ordering clause; the field case is a WAL's
// parent-directory fsync walk opening "/").
func TestExcludedPathsOutrankClassificationRefusals(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "fixture.txt"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := []byte(
		"open /\n" +
			"open /proc/sys/net/core/somaxconn\n" +
			"open fixture.txt\n")

	state, err := FromTestLogEnv(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"),
		WithExcludedPaths("/", "/proc/sys/net/core/somaxconn"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, "external directory input") || strings.Contains(reason, "volatile OS input") {
			t.Fatalf("excluded path left a classification refusal: %q", reason)
		}
	}
	for _, id := range m.Paths {
		if id.Path == "/" || strings.Contains(id.Path, "somaxconn") {
			t.Fatalf("excluded identity recorded: %+v", id)
		}
	}

	// Without the exclusion, the same observations refuse — the pin
	// that the discharge comes from the declaration, not from a
	// classifier change.
	state, err = FromTestLogEnv(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err = decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	sawRefusal := false
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, "external directory input: /") || strings.Contains(reason, "volatile OS input") {
			sawRefusal = true
		}
	}
	if !sawRefusal {
		t.Fatal("undeclared classifier-refused paths did not refuse")
	}
}

// The exclusion outranks every per-path disposition, not only
// classification refusals: the existence-binding of an external stat,
// the absence-binding of an absent external stat, and a
// classifier-refused chdir target all discharge when the raw identity
// is excluded — while the chdir's working-directory seal (an
// observation-kind seal, never a per-path disposition) stays
// (REQ-inputs-exclusions' ordering clause).
func TestExclusionOutranksExistenceBindingAndChdir(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(packageDir, "fixture.txt"), []byte("f"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := []byte(
		"open fixture.txt\n" +
			"stat " + outside + "\n" +
			"stat " + filepath.Join(outside, "missing") + "\n" +
			"chdir /\n")

	state, err := FromTestLogEnv(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"),
		WithExcludedPaths(outside, "/"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range m.Paths {
		if strings.Contains(id.Path, outside) || id.Path == "/" {
			t.Fatalf("excluded identity recorded (existence-binding or chdir target): %+v", id)
		}
	}
	sawWdSeal := false
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, "external directory input") {
			t.Fatalf("excluded chdir target left a classification refusal: %q", reason)
		}
		if reason == "working-directory change" {
			sawWdSeal = true
		}
	}
	if !sawWdSeal {
		t.Fatal("excluding the chdir target discharged the working-directory seal itself")
	}
	if len(m.Paths) != 1 || !strings.HasSuffix(m.Paths[0].Path, "fixture.txt") {
		t.Fatalf("non-excluded observation lost: %+v", m.Paths)
	}

	// Without the exclusions the same stats record and the chdir target
	// refuses — the discharge comes from the declaration.
	state, err = FromTestLogEnv(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err = decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	sawBound := false
	for _, id := range m.Paths {
		if strings.Contains(id.Path, outside) {
			sawBound = true
		}
	}
	sawRefusal := false
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, "external directory input: /") {
			sawRefusal = true
		}
	}
	if !sawBound || !sawRefusal {
		t.Fatalf("undeclared arms did not bind/refuse (bound=%v refusal=%v): %+v / %+v", sawBound, sawRefusal, m.Paths, m.Unverifiable)
	}
}
