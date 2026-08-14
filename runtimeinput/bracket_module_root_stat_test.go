package runtimeinput

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A stat of a module-interior identity under a module-root bracket
// (root ".") is metadata-spanned exactly as under any narrower root:
// the whole-module fingerprint covers it, so the stat records its
// revalidatable identity instead of sealing "stat metadata input" -
// while a stat under a bracket exclusion keeps sealing, its subtree
// being outside the fingerprint (REQ-inputs-bracket-coverage).
func TestModuleRootBracketCoversInteriorStats(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "config.yaml"), []byte("cfg"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	st, err := FromTestLog([]byte("# test log\nstat config.yaml\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("module-root bracket left an interior stat sealed: %s", st.Reason)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/config.yaml" {
		t.Fatalf("paths = %+v, want the stat's identity recorded", m.Paths)
	}
	// The entry digest binds the observed metadata: a later chmod moves
	// the recorded state toward recomputation, never silent reuse.
	if err := os.Chmod(filepath.Join(packageDir, "config.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	current, err := Current(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if current.Digest == st.Digest {
		t.Fatal("metadata movement did not move the bound digest")
	}

	if err := os.MkdirAll(filepath.Join(moduleDir, "toolstate"), 0o755); err != nil {
		t.Fatal(err)
	}
	excluded, err := CaptureBracketContext(context.Background(), moduleDir, []string{"."},
		WithBracketExcludedPaths("toolstate"))
	if err != nil {
		t.Fatal(err)
	}
	st, err = FromTestLog([]byte("# test log\nstat "+filepath.Join(moduleDir, "toolstate", "cache")+"\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(excluded))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable {
		t.Fatal("a stat under a bracket exclusion escaped its metadata seal")
	}
	// The exclusion is checked before the roots in the stat cover: the
	// excluded identity carries the METADATA seal specifically, not
	// merely the coverage seal - a "." arm ordered above the exclusion
	// loop would drop it.
	sealed, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, reason := range sealed.Unverifiable {
		if reason == "stat metadata input: toolstate/cache" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unverifiable reasons %v carry no metadata seal for the excluded stat", sealed.Unverifiable)
	}
}
