package runtimeinput

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// bracketTree builds a module tree with file, directory, symlink, and absent
// bracket-root candidates, returning the module directory.
func bracketTree(t *testing.T) string {
	t.Helper()
	moduleDir := filepath.Join(t.TempDir(), "mod")
	data := filepath.Join(moduleDir, "data")
	if err := os.MkdirAll(filepath.Join(data, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "sub", "b.txt"), []byte("beta"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(data, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "top.txt"), []byte("top"), 0o600); err != nil {
		t.Fatal(err)
	}
	return moduleDir
}

// TestBracketCaptureAndRevalidateAgreeOnUnchangedTree pins the
// REQ-inputs-value-binding self-agreement obligation: on an unchanged tree the
// revalidated fingerprint reads as unchanged, capture is deterministic, and
// declared-root normalization makes equivalent declarations one bracket.
func TestBracketCaptureAndRevalidateAgreeOnUnchangedTree(t *testing.T) {
	moduleDir := bracketTree(t)
	external := filepath.Join(t.TempDir(), "ext.txt")
	if err := os.WriteFile(external, []byte("external"), 0o644); err != nil {
		t.Fatal(err)
	}
	roots := []string{"data", "top.txt", "ghost", external}
	bracket, err := CaptureBracket(moduleDir, roots)
	if err != nil {
		t.Fatal(err)
	}
	if bracket.reason != "" {
		t.Fatalf("capture unverifiable: %q", bracket.reason)
	}
	for round := 0; round < 2; round++ {
		unchanged, reason, err := bracket.revalidate(context.Background(), moduleDir)
		if err != nil {
			t.Fatal(err)
		}
		if !unchanged || reason != "" {
			t.Fatalf("unchanged tree revalidated as moved: %q", reason)
		}
	}
	normalized, err := CaptureBracket(moduleDir, []string{"./data", "data", "top.txt", "ghost", "data", external})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.fingerprint != bracket.fingerprint {
		t.Fatal("equivalent root declarations produced distinct fingerprints")
	}
	empty, err := CaptureBracket(moduleDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged, reason, err := empty.revalidate(context.Background(), moduleDir); err != nil || !unchanged {
		t.Fatalf("empty bracket revalidate = %t %q %v", unchanged, reason, err)
	}
}

// TestBracketMovesOnPersistedMutation pins REQ-inputs-value-binding and the
// REQ-inputs-bracket-coverage absence clause: any single persisted mutation
// under a declared root — content alone with metadata restored, metadata
// alone, creation, deletion, a retyped object, a retargeted symlink, or an
// absent root appearing — moves the fingerprint with an attributable reason.
func TestBracketMovesOnPersistedMutation(t *testing.T) {
	external := filepath.Join(t.TempDir(), "ext.txt")
	cases := []struct {
		name   string
		mutate func(t *testing.T, moduleDir string)
	}{
		{"content edit with size and mtime restored", func(t *testing.T, moduleDir string) {
			target := filepath.Join(moduleDir, "data", "a.txt")
			info, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte("alphA"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(target, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
		}},
		{"mtime-only change", func(t *testing.T, moduleDir string) {
			when := time.Now().Add(-time.Hour)
			if err := os.Chtimes(filepath.Join(moduleDir, "data", "a.txt"), when, when); err != nil {
				t.Fatal(err)
			}
		}},
		{"mode-only change", func(t *testing.T, moduleDir string) {
			if err := os.Chmod(filepath.Join(moduleDir, "data", "a.txt"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"file created under root", func(t *testing.T, moduleDir string) {
			if err := os.WriteFile(filepath.Join(moduleDir, "data", "sub", "new.txt"), []byte("new"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"file deleted under root", func(t *testing.T, moduleDir string) {
			if err := os.Remove(filepath.Join(moduleDir, "data", "sub", "b.txt")); err != nil {
				t.Fatal(err)
			}
		}},
		{"file retyped to directory", func(t *testing.T, moduleDir string) {
			target := filepath.Join(moduleDir, "data", "a.txt")
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory root retyped to file", func(t *testing.T, moduleDir string) {
			target := filepath.Join(moduleDir, "data")
			if err := os.RemoveAll(target); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte("flat"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink retargeted", func(t *testing.T, moduleDir string) {
			target := filepath.Join(moduleDir, "data", "link")
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("sub/b.txt", target); err != nil {
				t.Fatal(err)
			}
		}},
		{"file root deleted", func(t *testing.T, moduleDir string) {
			if err := os.Remove(filepath.Join(moduleDir, "top.txt")); err != nil {
				t.Fatal(err)
			}
		}},
		{"file root mtime-only change", func(t *testing.T, moduleDir string) {
			when := time.Now().Add(-time.Hour)
			if err := os.Chtimes(filepath.Join(moduleDir, "top.txt"), when, when); err != nil {
				t.Fatal(err)
			}
		}},
		{"file root mode-only change", func(t *testing.T, moduleDir string) {
			if err := os.Chmod(filepath.Join(moduleDir, "top.txt"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"absent root appears as file", func(t *testing.T, moduleDir string) {
			if err := os.WriteFile(filepath.Join(moduleDir, "ghost"), []byte("boo"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"absent root appears as directory", func(t *testing.T, moduleDir string) {
			if err := os.MkdirAll(filepath.Join(moduleDir, "ghost", "inner"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"external file root edited", func(t *testing.T, moduleDir string) {
			if err := os.WriteFile(external, []byte("moved"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"content mutated through an out-of-root hardlink alias", func(t *testing.T, moduleDir string) {
			// The shared inode's content is read at hash time, so a write
			// through the alias moves the in-root entry's digest.
			alias := filepath.Join(moduleDir, "alias.txt")
			if err := os.Link(filepath.Join(moduleDir, "data", "a.txt"), alias); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(alias, []byte("aliased"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"empty directory created under root", func(t *testing.T, moduleDir string) {
			if err := os.Mkdir(filepath.Join(moduleDir, "data", "emptied"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory mode-only change under root", func(t *testing.T, moduleDir string) {
			if err := os.Chmod(filepath.Join(moduleDir, "data", "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			moduleDir := bracketTree(t)
			if err := os.WriteFile(external, []byte("external"), 0o644); err != nil {
				t.Fatal(err)
			}
			bracket, err := CaptureBracket(moduleDir, []string{"data", "top.txt", "ghost", external})
			if err != nil {
				t.Fatal(err)
			}
			if bracket.reason != "" {
				t.Fatalf("capture unverifiable: %q", bracket.reason)
			}
			tc.mutate(t, moduleDir)
			unchanged, reason, err := bracket.revalidate(context.Background(), moduleDir)
			if err != nil {
				t.Fatal(err)
			}
			if unchanged {
				t.Fatal("persisted mutation revalidated as unchanged")
			}
			if reason == "" {
				t.Fatal("moved bracket carries no attributable reason")
			}
		})
	}
}

// TestBracketExclusionsRemoveSubtreeFromFingerprintAndCoverage pins the
// REQ-inputs-bracket-coverage exclusion clause: mutations inside an excluded
// subtree never move the fingerprint, the excluded identities are uncovered by
// construction, and a sibling mutation outside the exclusion still moves it.
func TestBracketExclusionsRemoveSubtreeFromFingerprintAndCoverage(t *testing.T) {
	moduleDir := bracketTree(t)
	volatile := filepath.Join(moduleDir, "data", "sub")
	bracket, err := CaptureBracket(moduleDir, []string{"data"}, WithBracketExcludedPaths("data/sub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volatile, "b.txt"), []byte("mutated"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volatile, "c.txt"), []byte("created"), 0o644); err != nil {
		t.Fatal(err)
	}
	unchanged, reason, err := bracket.revalidate(context.Background(), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if !unchanged || reason != "" {
		t.Fatalf("excluded-subtree mutation moved the fingerprint: %q", reason)
	}
	for _, id := range []pathID{{Kind: pathRel, Path: "data/sub"}, {Kind: pathRel, Path: "data/sub/b.txt"}} {
		if !excludesIdentity(bracket.exclusions, id) {
			t.Fatalf("excluded identity %q is not uncovered", id.Path)
		}
	}
	if excludesIdentity(bracket.exclusions, pathID{Kind: pathRel, Path: "data/subsidiary"}) {
		t.Fatal("exclusion matched past a non-separator boundary")
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "a.txt"), []byte("mutated"), 0o644); err != nil {
		t.Fatal(err)
	}
	unchanged, reason, err = bracket.revalidate(context.Background(), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged || reason == "" {
		t.Fatalf("non-excluded mutation revalidated as unchanged (reason %q)", reason)
	}

	// A root that is itself excluded contributes nothing: mutations anywhere
	// beneath it leave the fingerprint unmoved.
	rootExcluded, err := CaptureBracket(moduleDir, []string{"data"}, WithBracketExcludedPaths("data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "d.txt"), []byte("noise"), 0o644); err != nil {
		t.Fatal(err)
	}
	if unchanged, reason, err := rootExcluded.revalidate(context.Background(), moduleDir); err != nil || !unchanged {
		t.Fatalf("excluded-root mutation revalidated as moved: %t %q %v", unchanged, reason, err)
	}
}

// TestBracketRootRefusedByHashingSemanticsIsUnverifiable pins the
// REQ-inputs-bracket-coverage refusal clause: a root the manifest hashing
// semantics refuse — an external directory, or a module-relative root
// resolving outside the module — makes the bracket unverifiable with the
// refusing reason rather than silently narrowing coverage, and revalidation
// reports that reason, never unchanged.
func TestBracketRootRefusedByHashingSemanticsIsUnverifiable(t *testing.T) {
	moduleDir := bracketTree(t)
	externalDir := t.TempDir()
	bracket, err := CaptureBracket(moduleDir, []string{"data", externalDir})
	if err != nil {
		t.Fatal(err)
	}
	if bracket.reason == "" || !strings.Contains(bracket.reason, "external directory input") {
		t.Fatalf("external directory root reason = %q", bracket.reason)
	}
	unchanged, reason, err := bracket.revalidate(context.Background(), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged || reason != bracket.reason {
		t.Fatalf("unverifiable bracket revalidate = %t %q", unchanged, reason)
	}

	if err := os.Symlink(externalDir, filepath.Join(moduleDir, "escape")); err != nil {
		t.Fatal(err)
	}
	escaped, err := CaptureBracket(moduleDir, []string{"escape"})
	if err != nil {
		t.Fatal(err)
	}
	if escaped.reason == "" || !strings.Contains(escaped.reason, "external directory input") {
		t.Fatalf("escaping symlink root reason = %q", escaped.reason)
	}
}

// TestBracketRevalidateRefusesForeignModuleViewAndUnsealedBracket pins the
// REQ-inputs-value-binding refusal clause: a bracket interpreted under a
// different module view than its capture, or one capture did not produce, is
// refused rather than read as unchanged.
func TestBracketRevalidateRefusesForeignModuleViewAndUnsealedBracket(t *testing.T) {
	moduleDir := bracketTree(t)
	bracket, err := CaptureBracket(moduleDir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bracket.revalidate(context.Background(), t.TempDir()); err == nil {
		t.Fatal("revalidate accepted a different module view")
	}
	var zero Bracket
	if _, _, err := zero.revalidate(context.Background(), moduleDir); err == nil {
		t.Fatal("revalidate accepted a zero bracket")
	}
	tampered := bracket
	tampered.fingerprint = strings.Repeat("0", len(bracket.fingerprint))
	if _, _, err := tampered.revalidate(context.Background(), moduleDir); err == nil {
		t.Fatal("revalidate accepted a tampered bracket")
	}
	//lint:ignore SA1012 the nil-context refusal is the behavior under pin
	if _, _, err := bracket.revalidate(nil, moduleDir); err == nil {
		t.Fatal("revalidate accepted a nil context")
	}
}

// TestCaptureBracketRejectsMalformedRootsAndPatterns pins declared-root
// identity form (REQ-inputs-bracket-coverage): a root or exclusion pattern
// that can name no identity is refused rather than read as anything.
func TestCaptureBracketRejectsMalformedRootsAndPatterns(t *testing.T) {
	moduleDir := bracketTree(t)
	for _, roots := range [][]string{{""}, {"../outside"}, {".."}, {"bad\nname"}, {"nul\x00byte"}} {
		if _, err := CaptureBracket(moduleDir, roots); err == nil {
			t.Errorf("CaptureBracket accepted roots %q", roots)
		}
	}
	if _, err := CaptureBracket(moduleDir, []string{"data"}, WithBracketExcludedPaths("")); err == nil {
		t.Fatal("CaptureBracket accepted an empty exclusion pattern")
	}
	// Exclusion identities enter the same newline-framed preimage as roots,
	// so framing bytes could alias a different exclusion set.
	for _, pattern := range []string{"bad\nname", "nul\x00byte", "cr\rname"} {
		if _, err := CaptureBracket(moduleDir, []string{"data"}, WithBracketExcludedPaths(pattern)); err == nil {
			t.Errorf("CaptureBracket accepted unrepresentable exclusion %q", pattern)
		}
	}
}

// TestCaptureBracketContextHonorsCancellation covers REQ-inputs-context
// semantics for bracket capture: cancellation is observed between roots and
// within file and directory hashing, without a partial bracket.
func TestCaptureBracketContextHonorsCancellation(t *testing.T) {
	moduleDir := bracketTree(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CaptureBracketContext(canceled, moduleDir, []string{"data"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled capture = %v, want context.Canceled", err)
	}
	for after := 1; after < 8; after++ {
		ctx := &cancelAfterChecks{Context: context.Background(), after: after}
		if _, err := CaptureBracketContext(ctx, moduleDir, []string{"data", "top.txt"}); !errors.Is(err, context.Canceled) {
			t.Fatalf("capture after %d checks = %v, want context.Canceled", after, err)
		}
	}
	//lint:ignore SA1012 the nil-context refusal is the behavior under pin
	if _, err := CaptureBracketContext(nil, moduleDir, []string{"data"}); err == nil {
		t.Fatal("CaptureBracketContext accepted a nil context")
	}
}

// FuzzBracketSinglePersistedMutationMovesFingerprint pins the
// REQ-inputs-value-binding move-detection property over generated trees: a
// captured bracket revalidates as unchanged on the untouched tree, and one
// random persisted mutation, creation, deletion, or retype under a declared
// root moves the fingerprint, while the same mutation under an excluded
// subtree does not (REQ-inputs-bracket-coverage).
func FuzzBracketSinglePersistedMutationMovesFingerprint(f *testing.F) {
	f.Add(uint64(1), uint8(0), false)
	f.Add(uint64(2), uint8(3), false)
	f.Add(uint64(3), uint8(7), true)
	f.Add(uint64(4), uint8(11), true)
	f.Fuzz(func(t *testing.T, seed uint64, pick uint8, excludeSite bool) {
		moduleDir := filepath.Join(t.TempDir(), "mod")
		root := filepath.Join(moduleDir, "data")
		rng := rand.New(rand.NewPCG(seed, 7))
		dirs := []string{root}
		for i, n := 0, rng.IntN(2); i < n; i++ {
			dir := filepath.Join(dirs[rng.IntN(len(dirs))], fmt.Sprintf("d%d", i))
			dirs = append(dirs, dir)
		}
		if err := os.MkdirAll(dirs[len(dirs)-1], 0o755); err != nil {
			t.Fatal(err)
		}
		var files []string
		for i, n := 0, 1+rng.IntN(3); i < n; i++ {
			name := filepath.Join(dirs[rng.IntN(len(dirs))], fmt.Sprintf("f%d.txt", i))
			content := make([]byte, 1+rng.IntN(8))
			for j := range content {
				content[j] = byte('a' + rng.IntN(26))
			}
			if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, content, 0o644); err != nil {
				t.Fatal(err)
			}
			files = append(files, name)
		}
		type mutation struct {
			site  string
			apply func() error
		}
		// confined mutations change nothing outside their site identity, so an
		// exclusion of that identity must blind the fingerprint to them; the
		// structural mutations also move the parent directory's metadata,
		// which stays bracketed even when the mutated object is excluded.
		var confined, structural []mutation
		for _, file := range files {
			confined = append(confined,
				mutation{file, func() error { return os.WriteFile(file, []byte("edited-content"), 0o644) }},
			)
			structural = append(structural,
				mutation{file, func() error { return os.Remove(file) }},
				mutation{file, func() error {
					if err := os.Remove(file); err != nil {
						return err
					}
					return os.Mkdir(file, 0o755)
				}},
			)
		}
		for _, dir := range dirs {
			confined = append(confined, mutation{dir, func() error {
				return os.WriteFile(filepath.Join(dir, "zz-new.txt"), []byte("created"), 0o644)
			}})
		}
		mutations := confined
		if !excludeSite {
			mutations = append(append([]mutation(nil), confined...), structural...)
		}
		chosen := mutations[int(pick)%len(mutations)]
		var opts []BracketOption
		if excludeSite {
			rel, err := filepath.Rel(moduleDir, chosen.site)
			if err != nil {
				t.Fatal(err)
			}
			opts = append(opts, WithBracketExcludedPaths(filepath.ToSlash(rel)))
		}
		bracket, err := CaptureBracket(moduleDir, []string{"data"}, opts...)
		if err != nil {
			t.Fatal(err)
		}
		if bracket.reason != "" {
			t.Fatalf("capture unverifiable: %q", bracket.reason)
		}
		if unchanged, reason, err := bracket.revalidate(context.Background(), moduleDir); err != nil || !unchanged {
			t.Fatalf("untouched tree revalidate = %t %q %v", unchanged, reason, err)
		}
		if err := chosen.apply(); err != nil {
			t.Fatal(err)
		}
		unchanged, reason, err := bracket.revalidate(context.Background(), moduleDir)
		if err != nil {
			t.Fatal(err)
		}
		if excludeSite {
			if !unchanged || reason != "" {
				t.Fatalf("excluded-site mutation moved the fingerprint: %q", reason)
			}
			return
		}
		if unchanged || reason == "" {
			t.Fatalf("persisted mutation at %q revalidated as unchanged (reason %q)", chosen.site, reason)
		}
	})
}
