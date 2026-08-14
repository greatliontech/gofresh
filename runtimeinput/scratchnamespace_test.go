package runtimeinput

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A read inside a declared scratch namespace, absent at bracket capture
// and absent again at ingest, records neither an identity nor a
// disposition, while a sibling read of real state records normally
// (REQ-inputs-scratch-namespace).
func TestScratchNamespaceAdmitsEndpointAbsentReads(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "input.txt"), []byte("real"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	log := []byte("open input.txt\nopen bench-a1b2c3/data.txt\nstat bench-a1b2c3\n")
	st, err := FromTestLog(log, moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("state unverifiable: %s", st.Reason)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/input.txt" {
		t.Fatalf("paths = %+v, want only the real input", m.Paths)
	}
}

// An absence-probe outside the declared namespace keeps its per-identity
// missing-arm record: the appearance-pin is forfeited only inside the
// declared namespace, never package-wide
// (REQ-inputs-scratch-namespace, REQ-inputs-guard).
func TestScratchNamespacePreservesAbsenceProbesOutsideIt(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	bracket := testBracket(t, moduleDir)
	st, err := FromTestLog([]byte("open tuning.yaml\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/tuning.yaml" {
		t.Fatalf("paths = %+v, want the absence-probe recorded", m.Paths)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "tuning.yaml"), []byte("tuned"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := Current(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if current.Digest == st.Digest {
		t.Fatal("appearance of the probed path did not move the digest")
	}
}

// A pre-existing object the pattern happens to match stays observed: the
// capture membership vetoes the admission, so declared scratch can never
// swallow real pre-run state (REQ-inputs-scratch-namespace).
func TestScratchNamespacePreExistingMatchStaysObserved(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	old := filepath.Join(packageDir, "bench-old")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	st, err := FromTestLog([]byte("open bench-old/keep.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-old/keep.txt" {
		t.Fatalf("paths = %+v, want the pre-existing read recorded", m.Paths)
	}
}

// Scratch that outlives the run stays observed — state present at ingest
// is never per-run scratch — and its persistence has already moved the
// bracket, sealing the observation toward recomputation
// (REQ-inputs-scratch-namespace).
func TestScratchNamespaceSurvivingScratchStaysObserved(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	bracket := testBracket(t, moduleDir)
	leaked := filepath.Join(packageDir, "bench-leak")
	if err := os.MkdirAll(leaked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaked, "out.txt"), []byte("leaked"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := FromTestLog([]byte("open bench-leak/out.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-leak/out.txt" {
		t.Fatalf("paths = %+v, want the surviving scratch recorded", m.Paths)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "observation bracket moved") {
		t.Fatalf("state = %+v, want the persisted scratch to move the bracket", st)
	}
}

// The masquerade direction: pre-existing state the run consumed and
// removed is vetoed by membership AND moves the bracket at revalidation,
// so it can never pass as scratch and the observation seals toward
// recomputation (REQ-inputs-scratch-namespace).
func TestScratchNamespaceConsumedAndRemovedSealsBracket(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	victim := filepath.Join(packageDir, "bench-victim")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, "data.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	if err := os.RemoveAll(victim); err != nil {
		t.Fatal(err)
	}
	st, err := FromTestLog([]byte("open bench-victim/data.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-victim/data.txt" {
		t.Fatalf("paths = %+v, want the consumed input recorded", m.Paths)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "observation bracket moved") {
		t.Fatalf("state = %+v, want the consumption to move the bracket", st)
	}
}

// A namespace whose directory no declared bracket root covers is inert:
// without capture membership nothing can be proven absent-before, so its
// reads keep ordinary classification (REQ-inputs-scratch-namespace).
func TestScratchNamespaceInertWithoutBracketCoverage(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	other := filepath.Join(moduleDir, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir, "pkg")
	st, err := FromTestLog([]byte("open "+filepath.Join(moduleDir, "other", "bench-x", "gone.txt")+"\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("other", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "other/bench-x/gone.txt" {
		t.Fatalf("paths = %+v, want the uncovered read recorded", m.Paths)
	}
}

// A pre-existing namespace-matching symlink into a bracket-EXCLUDED
// subtree must not let consumed-and-removed state bind recordless: the
// exclusion removes the target from the fingerprint, so only the
// matching-child freshness veto stands between the alias and a false
// valid (REQ-inputs-scratch-namespace's matching-child anchor).
func TestScratchNamespaceExcludedSubtreeAliasStaysSealed(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	excl := filepath.Join(packageDir, "excl")
	if err := os.MkdirAll(excl, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(excl, "data.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("excl", filepath.Join(packageDir, "bench-link")); err != nil {
		t.Fatal(err)
	}
	bracket, err := CaptureBracket(moduleDir, []string{"."}, WithBracketExcludedPaths("pkg/excl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(excl, "data.txt")); err != nil {
		t.Fatal(err)
	}
	st, err := FromTestLog([]byte("open bench-link/data.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-link/data.txt" {
		t.Fatalf("paths = %+v, want the aliased consumed input recorded", m.Paths)
	}
	if !st.Unverifiable {
		t.Fatalf("state = %+v, want the excluded-target alias sealed unverifiable", st)
	}
}

// The matching-child anchor vetoes reads BENEATH a pre-existing
// matching object, not merely the object's own identity: an absent
// deeper path under a pre-existing pattern-matching directory stays
// observed (REQ-inputs-scratch-namespace).
func TestScratchNamespacePreExistingMatchVetoesDepth(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.MkdirAll(filepath.Join(packageDir, "bench-old"), 0o755); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	st, err := FromTestLog([]byte("open bench-old/gone.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-old/gone.txt" {
		t.Fatalf("paths = %+v, want the absence-probe under pre-existing state recorded", m.Paths)
	}
}

// A namespace whose directory sits under a bracket exclusion admits
// nothing: the excluded subtree is outside the fingerprint, so pre-run
// absence is unknowable (REQ-inputs-scratch-namespace).
func TestScratchNamespaceUnderBracketExclusionAdmitsNothing(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	sub := filepath.Join(packageDir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	bracket, err := CaptureBracket(moduleDir, []string{"."}, WithBracketExcludedPaths("pkg/sub"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := FromTestLog([]byte("open sub/bench-x/gone.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg/sub", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/sub/bench-x/gone.txt" {
		t.Fatalf("paths = %+v, want the exclusion-shadowed read recorded", m.Paths)
	}
}

// A run-created dangling link ancestor refuses the admission: an
// existing-but-unresolvable component is detectable evidence the
// runtime read escaped (REQ-inputs-scratch-namespace fail-closed
// resolution, dangling arm).
func TestScratchNamespaceDanglingLinkAncestorStaysObserved(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	bracket := testBracket(t, moduleDir)
	if err := os.Symlink("nowhere-at-all", filepath.Join(packageDir, "bench-dang")); err != nil {
		t.Fatal(err)
	}
	st, err := FromTestLog([]byte("open bench-dang/x.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-dang/x.txt" {
		t.Fatalf("paths = %+v, want the dangling-ancestor read recorded", m.Paths)
	}
}

// The seal covers the retained capture listing: a forged member set
// fails the seal exactly as a forged digest would, and member framing
// distinguishes sets that plain newline framing would collide
// (REQ-inputs-value-binding's capture-produced-only rule).
func TestBracketSealCoversCaptureListing(t *testing.T) {
	moduleDir, _ := testDirs(t)
	bracket := testBracket(t, moduleDir)
	if err := bracket.checkSealed(); err != nil {
		t.Fatal(err)
	}
	forged := bracket
	forged.roots = append([]bracketRoot(nil), bracket.roots...)
	forged.roots[0].members = map[string]bool{"forged": true}
	if err := forged.checkSealed(); err == nil {
		t.Fatal("forged capture listing passed the seal")
	}

	a := bracket
	a.roots = []bracketRoot{{id: bracket.roots[0].id, digest: "d", members: map[string]bool{"a\nmember b": true}}}
	b := bracket
	b.roots = []bracketRoot{{id: bracket.roots[0].id, digest: "d", members: map[string]bool{"a": true, "b": true}}}
	if sealBracket(a) == sealBracket(b) {
		t.Fatal("member framing collides distinct capture listings")
	}
}

// A recorded module-relative DIRECTORY entry's digest shares the
// directory carve-out: membership-restored churn inside it leaves the
// digest, a mode change moves it (runtime-input manifest encoding
// term).
func TestRecordedDirectoryDigestSharesCarveOut(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	data := filepath.Join(packageDir, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	st, err := FromTestLog([]byte("open data\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}

	scratch := filepath.Join(data, "churn.txt")
	if err := os.WriteFile(scratch, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(scratch); err != nil {
		t.Fatal(err)
	}
	current, err := Current(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if current.Digest != st.Digest {
		t.Fatal("membership-restored churn moved a recorded directory digest")
	}

	if err := os.Chmod(data, 0o700); err != nil {
		t.Fatal(err)
	}
	current, err = Current(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if current.Digest == st.Digest {
		t.Fatal("directory mode change did not move the recorded digest")
	}
}

// A read whose traversal crosses an existing link escaping the bracket
// root stays observed even when the target is absent and the lexical
// path matches the namespace: the nearest existing ancestor must
// resolve under the covering root's resolved position
// (REQ-inputs-scratch-namespace fail-closed resolution).
func TestScratchNamespaceEscapingLinkStaysObserved(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(packageDir, "bench-link")); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	st, err := FromTestLog([]byte("open bench-link/gone.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-link/gone.txt" {
		t.Fatalf("paths = %+v, want the escaping-link read recorded", m.Paths)
	}
}

// Membership-restored churn — entries created and deleted within the
// span, moving only ancestor directories' own size and mtime — keeps the
// bracket: a directory object contributes membership and mode, never the
// metadata that only counts churn. A directory mode change still moves
// it (REQ-inputs-value-binding).
func TestBracketToleratesRestoredChurnButNotModeChange(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "input.txt"), []byte("real"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)

	scratch := filepath.Join(packageDir, "bench-churn")
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scratch, "tmp.txt"), []byte("scratch"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(scratch); err != nil {
		t.Fatal(err)
	}
	unchanged, reason, err := bracket.revalidate(context.Background(), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if !unchanged {
		t.Fatalf("membership-restored churn moved the bracket: %s", reason)
	}

	if err := os.Chmod(packageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	unchanged, _, err = bracket.revalidate(context.Background(), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged {
		t.Fatal("directory mode change did not move the bracket")
	}
}

// Namespace matching follows os.MkdirTemp semantics: the random string
// replaces the last "*" or is appended, matching is per direct child of
// the declared dir, and depth beneath a matching child is inside the
// namespace (REQ-inputs-scratch-namespace).
func TestScratchNamespaceMatching(t *testing.T) {
	cases := []struct {
		dir, pattern, path string
		want               bool
	}{
		{"pkg", "bench-*", "pkg/bench-123", true},
		{"pkg", "bench-*", "pkg/bench-123/deep/file.txt", true},
		{"pkg", "bench-*", "pkg/bench-", true},
		{"pkg", "bench-*", "pkg/other-123", false},
		{"pkg", "bench-*", "pkg", false},
		{"pkg", "bench-*", "other/bench-123", false},
		{"pkg", "scratch", "pkg/scratch12345", true},
		{"pkg", "scratch", "pkg/scratc", false},
		{"pkg", "pre*post", "pkg/preXpost", true},
		{"pkg", "pre*post", "pkg/prepost", true},
		{"pkg", "pre*post", "pkg/preX", false},
		{".", "bench-*", "bench-9", true},
		{".", "bench-*", "pkg/bench-9", false},
	}
	for _, tc := range cases {
		var cfg testLogConfig
		WithScratchNamespace(tc.dir, tc.pattern)(&cfg)
		if cfg.err != nil {
			t.Fatalf("%s %s: %v", tc.dir, tc.pattern, cfg.err)
		}
		got := cfg.scratchNamespaces[0].matches(pathID{Kind: pathRel, Path: tc.path})
		if got != tc.want {
			t.Errorf("dir=%s pattern=%s path=%s: matches=%v, want %v", tc.dir, tc.pattern, tc.path, got, tc.want)
		}
	}
}

// Malformed namespace declarations are refused loudly rather than read
// as anything (REQ-inputs-scratch-namespace).
func TestScratchNamespaceRejectsMalformedDeclarations(t *testing.T) {
	cases := []struct{ dir, pattern string }{
		{"", "bench-*"},
		{"/abs", "bench-*"},
		{"../up", "bench-*"},
		{"pkg", ""},
		{"pkg", "a/b"},
		{"pkg", "a\nb"},
	}
	for _, tc := range cases {
		var cfg testLogConfig
		WithScratchNamespace(tc.dir, tc.pattern)(&cfg)
		if cfg.err == nil {
			t.Errorf("dir=%q pattern=%q accepted", tc.dir, tc.pattern)
		}
	}
}

// The exported grammar check and the ingest option agree arm for arm: a
// declaration the validator accepts assembles, one it refuses fails the
// ingest with the same error — a producer preflighting at its boundary
// refuses exactly what ingest would degrade on.
func TestValidateScratchNamespaceMatchesOptionValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		dir, pattern string
		wantErr      string
	}{
		"valid":              {dir: "pkg", pattern: "scratch-*"},
		"multi-component":    {dir: "x", pattern: "a/b", wantErr: "single path component"},
		"empty pattern":      {dir: "x", pattern: "", wantErr: "single path component"},
		"absolute dir":       {dir: "/abs", pattern: "p", wantErr: "module-relative"},
		"empty dir":          {dir: "", pattern: "p", wantErr: "module-relative"},
		"escaping dir":       {dir: "../out", pattern: "p", wantErr: "escapes module"},
		"newline in pattern": {dir: "x", pattern: "a\nb", wantErr: "single path component"},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateScratchNamespace(tc.dir, tc.pattern)
			var cfg testLogConfig
			WithScratchNamespace(tc.dir, tc.pattern)(&cfg)
			if tc.wantErr == "" {
				if err != nil || cfg.err != nil {
					t.Fatalf("valid declaration refused: validator %v, option %v", err, cfg.err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validator error = %v, want %q", err, tc.wantErr)
			}
			if cfg.err == nil || cfg.err.Error() != err.Error() {
				t.Fatalf("option and validator disagree: option %v, validator %v", cfg.err, err)
			}
		})
	}
}
