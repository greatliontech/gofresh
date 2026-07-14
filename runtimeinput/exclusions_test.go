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

	state, err := FromTestLogEnv(log, moduleDir, packageDir, nil, WithExcludedPaths(".git"))
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
	state, err := FromTestLogEnv([]byte("open "+rel+"\n"), moduleDir, packageDir, nil, WithExcludedPaths(".git"))
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
	state, err := FromTestLogEnv([]byte("open "+relRoot+"\nopen "+relSpec+"\n"), moduleDir, packageDir, nil, WithExcludedPaths("."))
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
	state, err := FromTestLogEnv(log, moduleDir, packageDir, nil, WithExcludedPaths(outside))
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
	state, err := FromTestLogEnv(log, moduleDir, packageDir, nil, WithExcludedPaths("deep/scratch"))
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
	if _, err := FromTestLogEnv([]byte("open x\n"), moduleDir, packageDir, nil, WithExcludedPaths("")); err == nil {
		t.Fatal("empty exclusion pattern accepted")
	}
}
