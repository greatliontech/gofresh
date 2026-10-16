package runtimeinput

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

type namespaceAvailabilityCase struct {
	alias, directAtCapture, beforePresent, afterPresent, excludeParent bool
}

// The listing and direct lookup fail independently, without modifying modes or
// inventing returned metadata. All successful namespace reads are real reads.
func checkNamespaceAvailability(t *testing.T, tc namespaceAvailabilityCase) {
	t.Helper()
	dir := t.TempDir()
	parent := filepath.Join(dir, "data")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	physical := filepath.Join(parent, "p")
	logical := physical
	root := "data/p"
	if tc.alias {
		if err := os.Symlink("data", filepath.Join(dir, "alias")); err != nil {
			t.Fatal(err)
		}
		logical, root = filepath.Join(dir, "alias", "p"), "alias/p"
	}
	if tc.beforePresent {
		if err := os.WriteFile(physical, []byte("consumed"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	walk, stat, lstat := walkRuntimeDirectory, statRuntimePath, lstatRuntimePath
	t.Cleanup(func() { walkRuntimeDirectory, statRuntimePath, lstatRuntimePath = walk, stat, lstat })
	current := false
	directAvailable := func() bool { return current != tc.directAtCapture }
	walkRuntimeDirectory = func(path string, visit fs.WalkDirFunc) error {
		if path == parent && directAvailable() {
			return partialRuntimeWalk(path, nil, visit)
		}
		return walk(path, visit)
	}
	statRuntimePath = func(path string) (os.FileInfo, error) {
		if !directAvailable() && (path == physical || path == logical) {
			return nil, &os.PathError{Op: "stat", Path: path, Err: fs.ErrPermission}
		}
		return stat(path)
	}
	lstatRuntimePath = func(path string) (os.FileInfo, error) {
		if !directAvailable() && (path == physical || path == logical) {
			return nil, &os.PathError{Op: "lstat", Path: path, Err: fs.ErrPermission}
		}
		return lstat(path)
	}
	var opts []BracketOption
	if tc.excludeParent {
		opts = append(opts, WithBracketExcludedPaths("data/p"))
		if !tc.alias {
			root = physical
		} // retain the independent child's scope
	}
	b, err := CaptureBracket(t.Context(), dir, []string{"data", root}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	consumed, readErr := os.ReadFile(logical)
	if tc.beforePresent {
		if readErr != nil || string(consumed) != "consumed" {
			t.Fatalf("producing read: %q %v", consumed, readErr)
		}
	} else if !os.IsNotExist(readErr) {
		t.Fatalf("producing absence read: %v", readErr)
	}
	if tc.beforePresent != tc.afterPresent {
		if tc.afterPresent {
			err = os.WriteFile(physical, []byte("consumed"), 0600)
		} else {
			err = os.Remove(physical)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	current = true
	observation, err := FromTestLog([]byte("open "+logical+"\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
	wantMoved := tc.beforePresent != tc.afterPresent && !tc.excludeParent
	if err != nil || !observation.Unverifiable || observation.BracketMoved != wantMoved {
		t.Fatalf("known namespace evidence lost or invented: %+v %v", observation.State, err)
	}
	if err := b.checkSealed(); err != nil {
		t.Fatal("comparison changed captured provenance", err)
	}
}

func TestNamespacePresenceMeetsCompleteListingAbsence(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, control := range []string{"changed", "same present", "same absent", "excluded"} {
			t.Run(fmt.Sprintf("reverse=%t/%s", reverse, control), func(t *testing.T) {
				tc := namespaceAvailabilityCase{directAtCapture: !reverse, beforePresent: !reverse, afterPresent: reverse, excludeParent: control == "excluded"}
				if control == "same present" {
					tc.beforePresent, tc.afterPresent = true, true
				}
				if control == "same absent" {
					tc.beforePresent, tc.afterPresent = false, false
				}
				checkNamespaceAvailability(t, tc)
			})
		}
	}
}

func TestResolvedFinalAbsenceSurvivesAvailabilityShift(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, control := range []string{"changed", "same present", "same absent", "excluded"} {
			t.Run(fmt.Sprintf("reverse=%t/%s", reverse, control), func(t *testing.T) {
				tc := namespaceAvailabilityCase{alias: true, directAtCapture: !reverse, beforePresent: reverse, afterPresent: !reverse, excludeParent: control == "excluded"}
				if control == "same present" {
					tc.beforePresent, tc.afterPresent = true, true
				}
				if control == "same absent" {
					tc.beforePresent, tc.afterPresent = false, false
				}
				checkNamespaceAvailability(t, tc)
			})
		}
	}
}

func TestResolvedAbsenceRequiresTheFinalComponent(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	parent, child := filepath.Join(real, "parent"), filepath.Join(real, "parent", "p")
	b := testBracket(t, dir, "alias/parent/p")
	if b.roots[0].facts.knows(parent, namespaceFact) || b.roots[0].facts.knows(child, namespaceFact) {
		t.Fatal("missing intermediate invented resolved namespace absence")
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if unchanged, moved, reason, err := b.revalidate(t.Context(), dir); err != nil || !unchanged || moved {
		t.Fatalf("ancestor appearance moved the still-absent root: %t %t %q %v", unchanged, moved, reason, err)
	}
	final := testBracket(t, dir, "alias/parent/p")
	if !final.roots[0].facts.knows(child, namespaceFact) {
		t.Fatal("observed final absence lost resolved identity")
	}
	copy := final
	copy.roots = append([]bracketRoot(nil), final.roots...)
	copy.roots[0].facts = clonePathFacts(final.roots[0].facts)
	delete(copy.roots[0].facts.values, pathFact{child, namespaceFact})
	if err := copy.checkSealed(); err == nil {
		t.Fatal("resolved absence provenance not sealed")
	}
}

func TestNamespaceExistenceComparisonIsSymmetric(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p")
	for _, reverse := range []bool{false, true} {
		for _, kind := range []pathFactKind{namespaceFact, followedStatFact} {
			missing, named := newPathFacts(), newPathFacts()
			missing.put(p, kind, "missing")
			named.listing(dir, ".", []string{"p"}, false)
			before := []bracketRoot{{id: pathID{Kind: pathAbs, Path: dir}, facts: missing}}
			after := []bracketRoot{{id: before[0].id, facts: named}}
			if reverse {
				before, after = after, before
			}
			root, err := movedBracketRoot(t.Context(), before, after, nil)
			if err != nil || (root >= 0) != (kind == namespaceFact) {
				t.Fatalf("reverse=%t kind=%d mixed existence meanings: root=%d err=%v", reverse, kind, root, err)
			}
		}
	}
}

func TestMissingAncestorAppearanceDoesNotInventResolutionDrift(t *testing.T) {
	for _, asLink := range []bool{false, true} {
		t.Run(fmt.Sprintf("link=%t", asLink), func(t *testing.T) {
			dir := t.TempDir()
			real, other := filepath.Join(dir, "real"), filepath.Join(dir, "other")
			if err := os.Mkdir(real, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(other, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real", filepath.Join(dir, "alias")); err != nil {
				t.Fatal(err)
			}
			b := testBracket(t, dir, "alias/parent/p")
			parent := filepath.Join(real, "parent")
			var err error
			if asLink {
				err = os.Symlink(other, parent)
			} else {
				err = os.Mkdir(parent, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(dir, "alias", "parent", "p")); !os.IsNotExist(err) {
				t.Fatalf("declared child is not still absent: %v", err)
			}
			if unchanged, moved, reason, err := b.revalidate(t.Context(), dir); err != nil || !unchanged || moved {
				t.Fatalf("unestablished resolution became drift: unchanged=%t moved=%t reason=%q err=%v", unchanged, moved, reason, err)
			}
		})
	}
}
