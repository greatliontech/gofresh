package runtimeinput

import (
	"crypto/sha256"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// partialRuntimeWalk exposes actual entries beside a narrow injected readdir
// error. No metadata or entry type is fabricated, and directory modes stay put.
func partialRuntimeWalk(root string, names []string, visit fs.WalkDirFunc) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	entry := fs.FileInfoToDirEntry(info)
	if err := visit(root, entry, nil); err != nil {
		return err
	}
	if err := visit(root, entry, &os.PathError{Op: "readdir", Path: root, Err: fs.ErrPermission}); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		for _, name := range names {
			if entry.Name() == name {
				if err := visit(filepath.Join(root, name), entry, nil); err != nil && err != fs.SkipDir {
					return err
				}
			}
		}
	}
	return nil
}

func TestOverlappingRootsShareComparableFacts(t *testing.T) {
	for _, scenario := range []string{"appearance", "knowledge shifts", "excluded parent", "captured contradiction"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			data, p := filepath.Join(dir, "data"), filepath.Join(dir, "data", "p")
			if err := os.Mkdir(data, 0700); err != nil {
				t.Fatal(err)
			}
			if scenario == "knowledge shifts" || scenario == "captured contradiction" {
				if err := os.WriteFile(p, []byte("stable"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			walk, stat, lstat := walkRuntimeDirectory, statRuntimePath, lstatRuntimePath
			t.Cleanup(func() { walkRuntimeDirectory, statRuntimePath, lstatRuntimePath = walk, stat, lstat })
			current := false
			walkRuntimeDirectory = func(root string, visit fs.WalkDirFunc) error {
				if root == data {
					if !current && scenario == "captured contradiction" {
						if err := walk(root, visit); err != nil {
							return err
						}
						return os.Remove(p)
					}
					if !current || scenario == "captured contradiction" {
						return partialRuntimeWalk(root, nil, visit)
					}
				}
				return walk(root, visit)
			}
			statRuntimePath = func(path string) (os.FileInfo, error) {
				if current && path == p {
					return nil, &os.PathError{Op: "stat", Path: path, Err: fs.ErrPermission}
				}
				return stat(path)
			}
			lstatRuntimePath = func(path string) (os.FileInfo, error) {
				if current && path == p {
					return nil, &os.PathError{Op: "lstat", Path: path, Err: fs.ErrPermission}
				}
				return lstat(path)
			}
			roots := []string{"data", "data/p"}
			var opts []BracketOption
			if scenario == "excluded parent" {
				roots[1] = p
				opts = append(opts, WithBracketExcludedPaths("data/p"))
			}
			b, err := CaptureBracket(t.Context(), dir, roots, opts...)
			if err != nil {
				t.Fatal(err)
			}
			if scenario != "knowledge shifts" && scenario != "captured contradiction" {
				if _, err := os.ReadFile(p); !os.IsNotExist(err) {
					t.Fatalf("producing absence read: %v", err)
				}
				if err := os.WriteFile(p, []byte("appeared"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			current = true
			observation, err := FromTestLog([]byte("open data/p\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
			if err != nil || observation.BracketMoved != (scenario == "appearance" || scenario == "captured contradiction") || !observation.Unverifiable {
				t.Fatalf("%s: %+v %v", scenario, observation, err)
			}
			if observation.BracketMoved && RefusalClause(observation.Reason) != MovedBracketClause("data") {
				t.Fatalf("lost deterministic contributing-root attribution: %q", observation.Reason)
			}
		})
	}
}

func TestPartialListingRetainsPositiveMembership(t *testing.T) {
	original := walkRuntimeDirectory
	t.Cleanup(func() { walkRuntimeDirectory = original })
	for _, reverse := range []bool{false, true} {
		for _, changed := range []bool{false, true} {
			dir := t.TempDir()
			data := filepath.Join(dir, "data")
			if err := os.Mkdir(data, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(data, "kept"), []byte("stable"), 0600); err != nil {
				t.Fatal(err)
			}
			newPath := filepath.Join(data, "new")
			if !changed || reverse {
				if err := os.WriteFile(newPath, []byte("new"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			walk := walkRuntimeDirectory
			partial := reverse
			walkRuntimeDirectory = func(root string, visit fs.WalkDirFunc) error {
				if root == data && partial {
					return partialRuntimeWalk(root, []string{"new"}, visit)
				}
				return walk(root, visit)
			}
			b := testBracket(t, dir, "data")
			if changed {
				if reverse {
					if err := os.Remove(newPath); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(newPath, []byte("new"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			partial = !reverse
			_, moved, reason, err := b.revalidate(t.Context(), dir)
			walkRuntimeDirectory = walk
			if err != nil || moved != changed || reason == "" {
				t.Fatalf("reverse=%t changed=%t: moved=%t reason=%q err=%v", reverse, changed, moved, reason, err)
			}
		}
	}
}

func TestCrossRootMembershipKeepsExclusionScope(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kept", "excluded"} {
		if err := os.WriteFile(filepath.Join(data, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	walk := walkRuntimeDirectory
	t.Cleanup(func() { walkRuntimeDirectory = walk })
	calls := 0
	walkRuntimeDirectory = func(root string, visit fs.WalkDirFunc) error {
		calls++
		// Absolute roots sort before relative roots. The absolute root's
		// partial listing sees a name deliberately omitted by the relative one.
		if calls%2 == 1 {
			return partialRuntimeWalk(root, []string{"excluded"}, visit)
		}
		return walk(root, visit)
	}
	b, err := CaptureBracket(t.Context(), dir, []string{data, "data"}, WithBracketExcludedPaths("data/excluded"))
	if err != nil {
		t.Fatal(err)
	}
	if _, moved, _, err := b.revalidate(t.Context(), dir); err != nil || moved {
		t.Fatalf("excluded name became known absence: moved=%t err=%v", moved, err)
	}
}

func clonePathFacts(f *pathFacts) *pathFacts {
	if f == nil {
		return nil
	}
	copy := newPathFacts()
	for key, values := range f.values {
		copy.values[key] = slices.Clone(values)
	}
	for directory, listings := range f.listings {
		for _, listing := range listings {
			copy.listing(directory, listing.offset, listing.names, listing.complete)
		}
	}
	return copy
}

func TestFactAccountRetainsContradictionsCanonically(t *testing.T) {
	left, right := newPathFacts(), newPathFacts()
	for _, value := range []string{"type 0", "missing", "type 0"} {
		left.put("p", namespaceFact, value)
	}
	for _, value := range []string{"missing", "type 0"} {
		right.put("p", namespaceFact, value)
	}
	left.listing("d", ".", []string{"b", "a", "a"}, false)
	right.listing("d", ".", []string{"a", "b"}, false)
	hash := func(f *pathFacts) string { h := sha256.New(); f.seal(h); return string(h.Sum(nil)) }
	if hash(left) != hash(right) {
		t.Fatal("set order or duplication changed canonical facts")
	}
	before := []bracketRoot{{id: pathID{Kind: pathRel, Path: "p"}, facts: left}}
	after := []bracketRoot{{id: before[0].id, facts: newPathFacts()}}
	if root, err := movedBracketRoot(t.Context(), before, after, nil); err != nil || root != 0 {
		t.Fatalf("last write erased known contradiction: root=%d err=%v", root, err)
	}
	// Same-value overlap and knowledge loss carry no contradiction.
	clean := newPathFacts()
	clean.put("p", namespaceFact, "type 0")
	before[0].facts = clean
	if root, err := movedBracketRoot(t.Context(), before, after, nil); err != nil || root != -1 {
		t.Fatalf("knowledge loss became movement: root=%d err=%v", root, err)
	}
}

func TestBracketSealBindsMembershipKnowledgeAndScope(t *testing.T) {
	dir := bindingModule(t)
	b := testBracket(t, dir, "data")
	for directory := range b.roots[0].facts.listings {
		for _, field := range []string{"availability", "names", "scope"} {
			copy := b
			copy.roots = append([]bracketRoot(nil), b.roots...)
			copy.roots[0].facts = clonePathFacts(b.roots[0].facts)
			rows := copy.roots[0].facts.listings[directory]
			switch field {
			case "availability":
				rows[0].complete = !rows[0].complete
			case "names":
				rows[0].names = append(rows[0].names, "fabricated")
			case "scope":
				rows[0].offset = "different"
			}
			if err := copy.checkSealed(); err == nil {
				t.Fatalf("membership %s tampering accepted", field)
			}
		}
	}
	if err := b.checkSealed(); err != nil {
		t.Fatal("test copies changed original capture", err)
	}
}
