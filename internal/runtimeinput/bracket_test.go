package runtimeinput

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/render"
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
	bracket, err := ambientCaptureBracket(moduleDir, roots)
	if err != nil {
		t.Fatal(err)
	}
	if bracket.reason != "" {
		t.Fatalf("capture unverifiable: %q", bracket.reason)
	}
	for round := 0; round < 2; round++ {
		unchanged, _, reason, err := bracket.revalidate(context.Background(), moduleDir)
		if err != nil {
			t.Fatal(err)
		}
		if !unchanged || reason != "" {
			t.Fatalf("unchanged tree revalidated as moved: %q", reason)
		}
	}
	normalized, err := ambientCaptureBracket(moduleDir, []string{"./data", "data", "top.txt", "ghost", "data", external})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.seal != bracket.seal {
		t.Fatal("equivalent root declarations produced distinct fingerprints")
	}
	empty, err := ambientCaptureBracket(moduleDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged, _, reason, err := empty.revalidate(context.Background(), moduleDir); err != nil || !unchanged {
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
			bracket, err := ambientCaptureBracket(moduleDir, []string{"data", "top.txt", "ghost", external})
			if err != nil {
				t.Fatal(err)
			}
			if bracket.reason != "" {
				t.Fatalf("capture unverifiable: %q", bracket.reason)
			}
			tc.mutate(t, moduleDir)
			unchanged, _, reason, err := bracket.revalidate(context.Background(), moduleDir)
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
	bracket, err := ambientCaptureBracket(moduleDir, []string{"data"}, WithBracketExcludedPaths("data/sub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volatile, "b.txt"), []byte("mutated"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volatile, "c.txt"), []byte("created"), 0o644); err != nil {
		t.Fatal(err)
	}
	unchanged, _, reason, err := bracket.revalidate(context.Background(), moduleDir)
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
	unchanged, _, reason, err = bracket.revalidate(context.Background(), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged || reason == "" {
		t.Fatalf("non-excluded mutation revalidated as unchanged (reason %q)", reason)
	}

	// A root that is itself excluded contributes nothing: mutations anywhere
	// beneath it leave the fingerprint unmoved.
	rootExcluded, err := ambientCaptureBracket(moduleDir, []string{"data"}, WithBracketExcludedPaths("data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "d.txt"), []byte("noise"), 0o644); err != nil {
		t.Fatal(err)
	}
	if unchanged, _, reason, err := rootExcluded.revalidate(context.Background(), moduleDir); err != nil || !unchanged {
		t.Fatalf("excluded-root mutation revalidated as moved: %t %q %v", unchanged, reason, err)
	}
}

// TestBracketRootRefusedByHashingSemanticsIsUnverifiable pins the
// REQ-inputs-bracket-coverage refusal clause: a root the manifest hashing
// semantics refuse — a module-relative root resolving outside the module —
// makes the bracket unverifiable with the refusing reason rather than
// silently narrowing coverage, and revalidation reports that reason, never
// unchanged.
func TestBracketRootRefusedByHashingSemanticsIsUnverifiable(t *testing.T) {
	moduleDir := bracketTree(t)
	externalDir := t.TempDir()
	if err := os.Symlink(externalDir, filepath.Join(moduleDir, "escape")); err != nil {
		t.Fatal(err)
	}
	escaped, err := ambientCaptureBracket(moduleDir, []string{"data", "escape"})
	if err != nil {
		t.Fatal(err)
	}
	resolvedExternal, err := filepath.EvalSymlinks(externalDir)
	if err != nil {
		t.Fatal(err)
	}
	if escaped.reason == "" || !strings.Contains(escaped.reason, "external directory input") || !strings.Contains(escaped.reason, `recorded path "escape" resolves to `+strconv.Quote(resolvedExternal)+` outside the tree`) {
		t.Fatalf("escaping symlink root reason = %q", escaped.reason)
	}
	unchanged, _, reason, err := escaped.revalidate(context.Background(), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged || reason != escaped.reason {
		t.Fatalf("unverifiable bracket revalidate = %t %q", unchanged, reason)
	}
}

// TestAbsoluteDirectoryRootBindsItsTree pins REQ-inputs-bracket-coverage's
// directory clause for an absolute root: an external directory declared as
// a root — a replace module outside the repository, one surface — walks its
// tree, so a file rewritten, created, or deleted under it during the span
// moves the bracket naming that root, an unchanged tree revalidates
// unchanged, and its walk's membership serves the run-ephemera
// classification exactly as a module-relative root's does.
func TestAbsoluteDirectoryRootBindsItsTree(t *testing.T) {
	moduleDir := bracketTree(t)
	externalDir := filepath.Join(t.TempDir(), "replace")
	if err := os.MkdirAll(filepath.Join(externalDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixed := filepath.Join(externalDir, "sub", "fixed.go")
	if err := os.WriteFile(fixed, []byte("package sub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket, err := ambientCaptureBracket(moduleDir, []string{"data", externalDir})
	if err != nil {
		t.Fatal(err)
	}
	if bracket.reason != "" {
		t.Fatalf("absolute directory root refused: %q", bracket.reason)
	}
	if unchanged, _, reason, err := bracket.revalidate(context.Background(), moduleDir); err != nil || !unchanged {
		t.Fatalf("unchanged external tree revalidated as moved: %t %q %v", unchanged, reason, err)
	}
	var external *bracketRoot
	for i := range bracket.roots {
		if bracket.roots[i].id.Kind == pathAbs {
			external = &bracket.roots[i]
		}
	}
	if external == nil || !external.members["sub/fixed.go"] {
		t.Fatalf("absolute root walk recorded no membership: %+v", external)
	}
	if err := os.WriteFile(fixed, []byte("package sub // edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unchanged, _, reason, err := bracket.revalidate(context.Background(), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged || !strings.Contains(reason, externalDir) {
		t.Fatalf("rewrite under the absolute root: unchanged=%t reason=%q, want moved naming the root", unchanged, reason)
	}
	recaptured, err := ambientCaptureBracket(moduleDir, []string{"data", externalDir})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(externalDir, "new.go"), []byte("package replace\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if unchanged, _, _, err := recaptured.revalidate(context.Background(), moduleDir); err != nil || unchanged {
		t.Fatalf("a file created under the absolute root did not move the bracket: %t %v", unchanged, err)
	}
}

// TestAbsoluteDirectoryRootWalksItsResolvedTree pins REQ-inputs-value-binding's
// full-chain rule for an absolute directory root: a root whose final
// component is a symlink fingerprints the tree beneath its target, never
// the link, so a mid-span rewrite of a file the producer read through the
// link moves the bracket; and REQ-inputs-exclusions holds inside the walk —
// an excluded subtree under an absolute root leaves the fingerprint as it
// leaves coverage.
func TestAbsoluteDirectoryRootWalksItsResolvedTree(t *testing.T) {
	moduleDir := bracketTree(t)
	real := filepath.Join(t.TempDir(), "real")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixed := filepath.Join(real, "sub", "f.go")
	if err := os.WriteFile(fixed, []byte("package sub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	bracket, err := ambientCaptureBracket(moduleDir, []string{"data", link})
	if err != nil {
		t.Fatal(err)
	}
	if bracket.reason != "" {
		t.Fatalf("symlinked absolute root refused: %q", bracket.reason)
	}
	if err := os.WriteFile(fixed, []byte("package sub // edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if unchanged, _, reason, err := bracket.revalidate(context.Background(), moduleDir); err != nil || unchanged {
		t.Fatalf("a rewrite beneath the link's target did not move the bracket: %t %q %v", unchanged, reason, err)
	}

	volatile := filepath.Join(real, "vol")
	if err := os.MkdirAll(volatile, 0o755); err != nil {
		t.Fatal(err)
	}
	excluded, err := ambientCaptureBracket(moduleDir, []string{"data", real}, WithBracketExcludedPaths(filepath.Join(real, "vol")))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volatile, "churn"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if unchanged, _, reason, err := excluded.revalidate(context.Background(), moduleDir); err != nil || !unchanged {
		t.Fatalf("churn under an excluded subtree of an absolute root moved the bracket: %t %q %v", unchanged, reason, err)
	}
	// The exclusion removes its subtree alone: the rest of the absolute
	// tree stays fingerprinted.
	if err := os.WriteFile(fixed, []byte("package sub // edited again\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if unchanged, _, reason, err := excluded.revalidate(context.Background(), moduleDir); err != nil || unchanged {
		t.Fatalf("a rewrite outside the excluded subtree did not move the bracket: %t %q %v", unchanged, reason, err)
	}
}

// An absolute directory root that contains a volatile OS root would walk a
// tree that never holds still: refused at declaration, the dual of a root
// lying under one (REQ-inputs-volatile-os-roots).
func TestAbsoluteRootContainingVolatileOSRootIsRefused(t *testing.T) {
	if len(guard.VolatileOSRoots) == 0 {
		t.Skip("no volatile OS roots on this platform")
	}
	moduleDir := bracketTree(t)
	if _, err := ambientCaptureBracket(moduleDir, []string{"data", filepath.Dir(guard.VolatileOSRoots[0])}); err == nil || !strings.Contains(err.Error(), "filesystem root") {
		t.Fatalf("root above a volatile OS root: %v; want the refusal", err)
	}
	// A link that resolves into a volatile tree passes the lexical
	// refusal and is refused at capture over its target: the bracket
	// is unverifiable, nothing is walked.
	link := filepath.Join(t.TempDir(), "into-volatile")
	if err := os.Symlink(guard.VolatileOSRoots[0], link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	bracket, err := ambientCaptureBracket(moduleDir, []string{"data", link})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bracket.Reason(), "resolves into a volatile OS root") {
		t.Fatalf("link into a volatile tree: reason %q, want the resolved refusal", bracket.Reason())
	}
	if clean, err := ambientCaptureBracket(moduleDir, []string{"data"}); err != nil || clean.Reason() != "" {
		t.Fatalf("a fingerprinted bracket reports a reason: %q, %v", clean.Reason(), err)
	}
}

// The filesystem root is refused on every platform, volatile roots or not:
// nothing walks the whole filesystem.
func TestFilesystemRootIsRefusedAsBracketRoot(t *testing.T) {
	moduleDir := bracketTree(t)
	if _, err := ambientCaptureBracket(moduleDir, []string{"data", string(filepath.Separator)}); err == nil || !strings.Contains(err.Error(), "filesystem root") {
		t.Fatalf("filesystem root: %v; want the refusal", err)
	}
}

// TestBracketRevalidateRefusesForeignModuleViewAndUnsealedBracket pins the
// REQ-inputs-value-binding refusal clause: a bracket interpreted under a
// different module view than its capture, or one capture did not produce, is
// refused rather than read as unchanged.
func TestBracketRevalidateRefusesForeignModuleViewAndUnsealedBracket(t *testing.T) {
	moduleDir := bracketTree(t)
	bracket, err := ambientCaptureBracket(moduleDir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := bracket.revalidate(context.Background(), t.TempDir()); err == nil {
		t.Fatal("revalidate accepted a different module view")
	}
	var zero Bracket
	if _, _, _, err := zero.revalidate(context.Background(), moduleDir); err == nil {
		t.Fatal("revalidate accepted a zero bracket")
	}
	tampered := bracket
	tampered.roots = append([]bracketRoot(nil), bracket.roots...)
	tampered.roots[0].facts = newPathFacts()
	if _, _, _, err := tampered.revalidate(context.Background(), moduleDir); err == nil {
		t.Fatal("revalidate accepted a tampered bracket")
	}
	//lint:ignore SA1012 the nil-context refusal is the behavior under pin
	if _, _, _, err := bracket.revalidate(nil, moduleDir); err == nil {
		t.Fatal("revalidate accepted a nil context")
	}
}

// TestCaptureBracketRejectsMalformedRootsAndPatterns pins declared-root
// identity form (REQ-inputs-bracket-coverage): a root or exclusion pattern
// that can name no identity is refused rather than read as anything.
func TestCaptureBracketRejectsMalformedRootsAndPatterns(t *testing.T) {
	moduleDir := bracketTree(t)
	for _, roots := range [][]string{{""}, {"../outside"}, {".."}, {"bad\nname"}, {"nul\x00byte"}} {
		if _, err := ambientCaptureBracket(moduleDir, roots); err == nil {
			t.Errorf("CaptureBracket accepted roots %q", roots)
		}
	}
	if _, err := ambientCaptureBracket(moduleDir, []string{"data"}, WithBracketExcludedPaths("")); err == nil {
		t.Fatal("CaptureBracket accepted an empty exclusion pattern")
	}
	// Exclusion identities enter the same newline-framed preimage as roots,
	// so framing bytes could alias a different exclusion set.
	for _, pattern := range []string{"bad\nname", "nul\x00byte", "cr\rname"} {
		if _, err := ambientCaptureBracket(moduleDir, []string{"data"}, WithBracketExcludedPaths(pattern)); err == nil {
			t.Errorf("CaptureBracket accepted unrepresentable exclusion %q", pattern)
		}
	}
}

// TestCaptureBracketHonorsCancellation covers REQ-inputs-context
// semantics for bracket capture: cancellation is observed between roots and
// within file and directory hashing, without a partial bracket.
func TestCaptureBracketHonorsCancellation(t *testing.T) {
	moduleDir := bracketTree(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CaptureBracket(canceled, moduleDir, []string{"data"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled capture = %v, want context.Canceled", err)
	}
	for after := 1; after < 8; after++ {
		ctx := &cancelAfterChecks{Context: context.Background(), after: after}
		if _, err := CaptureBracket(ctx, moduleDir, []string{"data", "top.txt"}); !errors.Is(err, context.Canceled) {
			t.Fatalf("capture after %d checks = %v, want context.Canceled", after, err)
		}
	}
	//lint:ignore SA1012 the nil-context refusal is the behavior under pin
	if _, err := CaptureBracket(nil, moduleDir, []string{"data"}); err == nil {
		t.Fatal("CaptureBracket accepted a nil context")
	}
}

// FuzzBracketSinglePersistedMutationMovesFingerprint pins the
// REQ-inputs-value-binding move-detection property over generated trees: a
// captured bracket revalidates as unchanged on the untouched tree, and one
// random persisted mutation, creation, deletion, or retype under a declared
// root moves the fingerprint, while the same mutation under an excluded
// subtree does not (REQ-inputs-bracket-coverage).
func FuzzBracketSinglePersistedMutationMovesFingerprint(f *testing.F) {
	for _, unknown := range []bool{false, true} {
		f.Add(uint64(1), uint8(0), false, unknown)
		f.Add(uint64(2), uint8(3), false, unknown)
		f.Add(uint64(3), uint8(7), true, unknown)
		f.Add(uint64(4), uint8(11), true, unknown)
	}
	f.Fuzz(func(t *testing.T, seed uint64, pick uint8, excludeSite, unknownMember bool) {
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
		// every mutation is confined to its site identity — a directory
		// object contributes membership and mode, never the size and mtime
		// that would let a member's churn leak into its parent — so an
		// exclusion of the mutated identity must blind the fingerprint to
		// any of them, structural mutations included.
		var mutations []mutation
		for _, file := range files {
			mutations = append(mutations,
				mutation{file, func() error { return os.WriteFile(file, []byte("edited-content"), 0o644) }},
				mutation{file, func() error {
					when := time.Now().Add(-2 * time.Hour)
					return os.Chtimes(file, when, when)
				}},
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
			mutations = append(mutations,
				mutation{dir, func() error {
					return os.WriteFile(filepath.Join(dir, "zz-new.txt"), []byte("created"), 0o644)
				}},
				mutation{dir, func() error { return os.Chmod(dir, 0o700) }},
			)
		}
		chosen := mutations[int(pick)%len(mutations)]
		if unknownMember {
			p := filepath.Join(root, "zz-unknown")
			if err := os.WriteFile(p, []byte("unhashable sibling"), 0000); err != nil {
				t.Fatal(err)
			}
			if _, err := os.ReadFile(p); !os.IsPermission(err) {
				t.Skip("requires a read-denied sibling")
			}
		}
		unknown := unknownMember && !(excludeSite && chosen.site == root)
		var opts []BracketOption
		if excludeSite {
			rel, err := filepath.Rel(moduleDir, chosen.site)
			if err != nil {
				t.Fatal(err)
			}
			opts = append(opts, WithBracketExcludedPaths(filepath.ToSlash(rel)))
		}
		bracket, err := ambientCaptureBracket(moduleDir, []string{"data"}, opts...)
		if err != nil {
			t.Fatal(err)
		}
		if (bracket.reason != "") != unknown {
			t.Fatalf("capture unverifiable: %q", bracket.reason)
		}
		if unchanged, moved, reason, err := bracket.revalidate(context.Background(), moduleDir); err != nil || moved || unchanged == unknown || (reason != "") != unknown {
			t.Fatalf("untouched tree revalidate = %t %q %v", unchanged, reason, err)
		}
		if err := chosen.apply(); err != nil {
			t.Fatal(err)
		}
		unchanged, moved, reason, err := bracket.revalidate(context.Background(), moduleDir)
		if err != nil {
			t.Fatal(err)
		}
		if excludeSite {
			if moved || unchanged == unknown || (reason != "") != unknown {
				t.Fatalf("excluded-site mutation moved the fingerprint: %q", reason)
			}
			return
		}
		if unchanged || !moved || reason == "" {
			t.Fatalf("persisted mutation at %q revalidated as unchanged (reason %q)", chosen.site, reason)
		}
	})
}

// A moved-bracket refusal names WHAT moved: members added or removed
// since capture by name, and — when membership held, so a content edit
// moved the digest — the most recently modified members, so a
// parallel-suite interference flake carries its lead instead of only
// the package that flinched (REQ-inputs-value-binding's attributable
// refusal).
func TestBracketMoveAttributionNamesTheMove(t *testing.T) {
	build := func(t *testing.T) (string, string) {
		t.Helper()
		moduleDir := t.TempDir()
		root := filepath.Join(moduleDir, "lib")
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range map[string]string{"a.go": "package lib\n", "b.go": "package lib\n\nvar B = 1\n"} {
			if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		// Distinct, past mtimes so refusal-time recency ranking cannot
		// tie with the edit below.
		old := time.Now().Add(-time.Hour)
		for _, name := range []string{"a.go", "b.go"} {
			if err := os.Chtimes(filepath.Join(root, name), old, old); err != nil {
				t.Fatal(err)
			}
		}
		return moduleDir, root
	}
	capture := func(t *testing.T, moduleDir string) Bracket {
		t.Helper()
		b, err := ambientCaptureBracket(moduleDir, []string{"lib"})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	revalidateReason := func(t *testing.T, b Bracket, moduleDir string) string {
		t.Helper()
		unchanged, _, reason, err := b.revalidate(context.Background(), moduleDir)
		if err != nil {
			t.Fatal(err)
		}
		if unchanged {
			t.Fatal("moved bracket read unchanged")
		}
		return reason
	}

	moduleDir, root := build(t)
	b := capture(t, moduleDir)
	if err := os.WriteFile(filepath.Join(root, "b.go"), []byte("package lib\n\nvar B = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reason := revalidateReason(t, b, moduleDir)
	if !strings.Contains(reason, "recently touched: b.go") {
		t.Fatalf("content-edit refusal = %q, want the edited member ranked first", reason)
	}
	// The recency list is bounded like every list a refusal carries:
	// past the cap it names how many more members moved instead of
	// silently dropping them.
	moduleDir, root = build(t)
	for _, name := range []string{"c.go", "d.go"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("package lib\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b = capture(t, moduleDir)
	for i, name := range []string{"a.go", "b.go", "c.go", "d.go"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("package lib\n\nvar V"+name[:1]+" = "+string(rune('1'+i))+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if reason := revalidateReason(t, b, moduleDir); !strings.Contains(reason, ", and 1 more") || strings.Count(reason, ".go (") != render.ListCap {
		t.Fatalf("four-member content edit = %q, want %d named members and the remainder counted", reason, render.ListCap)
	}

	moduleDir, root = build(t)
	b = capture(t, moduleDir)
	if err := os.WriteFile(filepath.Join(root, "c.go"), []byte("package lib\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if reason := revalidateReason(t, b, moduleDir); !strings.Contains(reason, "added: c.go") {
		t.Fatalf("added-member refusal = %q, want the new member named", reason)
	}

	moduleDir, root = build(t)
	b = capture(t, moduleDir)
	if err := os.Remove(filepath.Join(root, "a.go")); err != nil {
		t.Fatal(err)
	}
	if reason := revalidateReason(t, b, moduleDir); !strings.Contains(reason, "removed: a.go") {
		t.Fatalf("removed-member refusal = %q, want the removed member named", reason)
	}

	// The list caps with the remainder counted, and every emitted name
	// stays manifest-representable: an unrepresentable filename travels
	// quoted, so the attribution can never turn the attributable
	// refusal into a hard manifest-validation error.
	moduleDir, root = build(t)
	b = capture(t, moduleDir)
	for _, name := range []string{"e1.go", "e2.go", "e3.go", "e4.go", "c\nd.go"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("package lib\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reason = revalidateReason(t, b, moduleDir)
	if !strings.Contains(reason, "and 2 more") {
		t.Fatalf("capped added list = %q, want the remainder counted", reason)
	}
	if !utf8.ValidString(reason) || strings.ContainsAny(reason, "\x00\r\n") {
		t.Fatalf("attribution emitted a manifest-unrepresentable reason: %q", reason)
	}
	if !strings.Contains(reason, `"c\nd.go"`) {
		t.Fatalf("unrepresentable filename not quoted into the lead: %q", reason)
	}
}

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
	st, err := ambientFromTestLog([]byte("# test log\nstat config.yaml\n"), moduleDir, packageDir,
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
	current, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if current.Digest == st.Digest {
		t.Fatal("metadata movement did not move the bound digest")
	}

	if err := os.MkdirAll(filepath.Join(moduleDir, "toolstate"), 0o755); err != nil {
		t.Fatal(err)
	}
	excluded, err := CaptureBracket(context.Background(), moduleDir, []string{"."},
		WithBracketExcludedPaths("toolstate"))
	if err != nil {
		t.Fatal(err)
	}
	st, err = ambientFromTestLog([]byte("# test log\nstat "+filepath.Join(moduleDir, "toolstate", "cache")+"\n"), moduleDir, packageDir,
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

func TestBracketMovementSurvivesComposition(t *testing.T) {
	dir := bindingModule(t)
	b := testBracket(t, dir, "data")
	file := filepath.Join(dir, "data", "fixture.txt")
	if err := os.WriteFile(file, []byte("after consumption"), 0600); err != nil {
		t.Fatal(err)
	}
	moved, err := FromTestLog([]byte("open data/fixture.txt\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
	if err != nil {
		t.Fatal(err)
	}
	assertMoved := func(t *testing.T, observation Observation, err error) Observation {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		state, err := CompletedState(observation)
		if err != nil || !state.BracketMoved || !strings.Contains(state.Reason, "observation bracket moved: data") {
			t.Fatalf("lost movement: %+v %v", state, err)
		}
		current, err := Current(t.Context(), state.Manifest, dir, nil)
		if err != nil || current != state {
			t.Fatalf("recheck: %+v %v", current, err)
		}
		return observation
	}
	assertMoved(t, moved, nil)
	abs, err := Absolute(moved, dir, nil)
	abs = assertMoved(t, abs, err)
	rel, err := Relative(abs, dir, nil)
	rel = assertMoved(t, rel, err)
	if rel.State != moved.State {
		t.Fatal("identity roundtrip changed evidence")
	}
	adopted, err := Adopt(moved.Manifest, dir, "adoption", nil)
	assertMoved(t, adopted, err)
	empty, err := Merge(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	incomplete, err := Incomplete(dir, "interrupted", "unknown sibling", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, inputs := range [][]Observation{{moved, empty}, {empty, moved}, {incomplete, moved}, {moved, incomplete}, {moved, moved}} {
		merged, err := Merge(dir, nil, inputs...)
		assertMoved(t, merged, err)
	}
	tampered := moved
	tampered.BracketMoved = false
	if _, err := CompletedState(tampered); err == nil {
		t.Fatal("unsealed movement override accepted")
	}
	// Restoration after the failure was observed cannot erase producing history.
	if err := os.WriteFile(file, []byte("recorded"), 0644); err != nil {
		t.Fatal(err)
	}
	current, err := Current(t.Context(), moved.Manifest, dir, nil)
	if err != nil || !current.BracketMoved {
		t.Fatalf("restored value erased movement: %+v %v", current, err)
	}
	if _, err := Adopt(moved.Manifest, dir, "restored", nil); err == nil {
		t.Fatal("adoption accepted changed values")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if state, err := Current(ctx, moved.Manifest, dir, nil); !errors.Is(err, context.Canceled) || state != (State{}) {
		t.Fatalf("cancelled check supplied evidence: %+v %v", state, err)
	}
}

func TestBracketUnknownDoesNotMaskComparableMovement(t *testing.T) {
	for _, lateUnknown := range []bool{false, true} {
		for _, move := range []bool{false, true} {
			dir := bindingModule(t)
			external := filepath.Join(t.TempDir(), "external")
			if err := os.WriteFile(external, []byte("external"), 0600); err != nil {
				t.Fatal(err)
			}
			unknown := filepath.Join(dir, "a-unknown")
			if lateUnknown {
				if err := os.WriteFile(unknown, []byte("before"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink(external, unknown); err != nil {
				t.Fatal(err)
			}
			b := testBracket(t, dir, "a-unknown", "data")
			if lateUnknown {
				if err := os.Remove(unknown); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(external, unknown); err != nil {
					t.Fatal(err)
				}
			}
			if move {
				if err := os.WriteFile(filepath.Join(dir, "data", "fixture.txt"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			observation, err := FromTestLog([]byte("open data/fixture.txt\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
			// Replacing a regular root with an external symlink is known
			// namespace movement, even though its new content is unhashable.
			if err != nil || !observation.Unverifiable || observation.BracketMoved != (move || lateUnknown) {
				t.Fatalf("lateUnknown=%t move=%t: %+v %v", lateUnknown, move, observation, err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, _, _, err := b.revalidate(ctx, dir); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled unknown bracket: %v", err)
			}
		}
	}
}

func TestBracketMovementIncludesObjectTransitions(t *testing.T) {
	for _, transition := range []string{"appearance", "disappearance", "retype"} {
		t.Run(transition, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "input")
			if transition != "appearance" {
				if err := os.WriteFile(p, []byte("before"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			b := testBracket(t, dir, "input")
			if transition != "appearance" {
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
			}
			if transition == "appearance" {
				if err := os.WriteFile(p, []byte("after"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if transition == "retype" {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			observation, err := FromTestLog([]byte("open input\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
			if err != nil || !observation.BracketMoved {
				t.Fatalf("lost %s: %+v %v", transition, observation, err)
			}
		})
	}
}

func TestMovementManifestCanonicalWireAndDigest(t *testing.T) {
	const raw = `{"v":4,"bracketMoved":true,"unverifiable":["diagnostic"]}`
	encoded := base64.RawURLEncoding.EncodeToString([]byte(raw))
	state, err := Current(t.Context(), encoded, t.TempDir(), nil)
	sum := sha256.Sum256([]byte("version 4\nbracket-moved\nunverifiable diagnostic\n"))
	if err != nil || !state.BracketMoved || state.Manifest != encoded || state.Digest != hex.EncodeToString(sum[:])[:32] {
		t.Fatalf("wire/digest disagreement: %+v %v", state, err)
	}
	for _, invalid := range []string{
		`{"v":4,"bracketMoved":false}`, `{"v":4,"bracketMoved":null}`,
		`{"v":4,"bracketMoved":true,"bracketMoved":true}`,
		`{"v":4,"unverifiable":["diagnostic"],"bracketMoved":true}`,
	} {
		if _, err := decode(base64.RawURLEncoding.EncodeToString([]byte(invalid))); err == nil {
			t.Fatalf("accepted %s", invalid)
		}
	}
	// Text alone is never semantic movement evidence, even when it looks exact.
	text, err := Incomplete(t.TempDir(), "caller", movedBracketClauseForRoot("data"), nil)
	if err != nil || text.BracketMoved {
		t.Fatalf("diagnostic granted guard authority: %+v %v", text, err)
	}
}

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
			if observation.BracketMoved && refusalClause(observation.Reason) != movedBracketClauseForRoot("data") {
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
