package runtimeinput

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/guard"
)

// completedFromLog builds a completed observation over dir with the bracket
// covering "data" — the shared harness for guard-covered classification pins.
func completedFromLog(t *testing.T, dir, log string, opts ...TestLogOption) Observation {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	bracket, err := CaptureBracket(dir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	opts = append([]TestLogOption{WithCompletedProcess("package-test-binary:guard"), WithBracket(bracket)}, opts...)
	obs, err := FromTestLog([]byte(log), dir, dir, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

// TestGuardCoveredRootsSkipPinnedReads pins REQ-inputs-guard-covered: opens
// and stats provably inside a declared root record no identity and no
// disposition — the fake GOROOT stands for any guard-pinned tree — while the
// same reads without the declaration observe (and stat seals) as before.
func TestGuardCoveredRootsSkipPinnedReads(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(t.TempDir(), "goroot")
	if err := os.MkdirAll(filepath.Join(root, "src", "os"), 0o755); err != nil {
		t.Fatal(err)
	}
	pinned := filepath.Join(root, "src", "os", "file.go")
	if err := os.WriteFile(pinned, []byte("package os\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := "open " + pinned + "\nstat " + pinned + "\n"

	obs := completedFromLog(t, dir, log, WithToolchainRoot(root))
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("guard-covered reads sealed unverifiable: %s", st.Reason)
	}
	d, err := Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 0 || len(d.Unverifiable) != 0 {
		t.Fatalf("guard-covered reads recorded: %+v", d)
	}

	// The identical log without the declaration observes and seals.
	bare := completedFromLog(t, t.TempDir(), log)
	bareState, err := CompletedState(bare)
	if err != nil {
		t.Fatal(err)
	}
	if !bareState.Unverifiable {
		t.Fatal("undeclared out-of-bracket reads did not seal unverifiable")
	}
}

// TestGuardCoveredResolutionIsFailClosed pins the fail-closed boundary: a
// module-local symlink INTO the root stays a mutable observed input, a path
// under the root escaping OUT of it stays observed, and a missing path under
// the root stays observed.
func TestGuardCoveredResolutionIsFailClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "modcache")
	if err := os.MkdirAll(filepath.Join(root, "dep"), 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "dep", "d.go")
	if err := os.WriteFile(inside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "mutable.txt")
	if err := os.WriteFile(outside, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(root, "escape.txt")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}

	t.Run("module symlink into root is observed", func(t *testing.T) {
		dir := t.TempDir()
		link := filepath.Join(dir, "into-root")
		if err := os.Symlink(inside, link); err != nil {
			t.Fatal(err)
		}
		obs := completedFromLog(t, dir, "open "+link+"\n", WithToolchainRoot(root))
		st, err := CompletedState(obs)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Unverifiable {
			t.Fatal("module-local symlink into a guard root skipped observation")
		}
	})
	t.Run("escape out of root is observed", func(t *testing.T) {
		obs := completedFromLog(t, t.TempDir(), "open "+escape+"\n", WithToolchainRoot(root))
		st, err := CompletedState(obs)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Unverifiable {
			t.Fatal("symlink escaping the guard root skipped observation")
		}
	})
	t.Run("ambiguous traversal under root is observed", func(t *testing.T) {
		// Lexical cleaning of a parent traversal may not match the
		// filesystem, so the read is never provably inside the root.
		traversal := root + "/dep/../dep/d.go"
		obs := completedFromLog(t, t.TempDir(), "open "+traversal+"\n", WithToolchainRoot(root))
		st, err := CompletedState(obs)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Unverifiable {
			t.Fatal("ambiguous traversal under the guard root skipped observation")
		}
	})
	t.Run("missing path under root is observed", func(t *testing.T) {
		obs := completedFromLog(t, t.TempDir(), "open "+filepath.Join(root, "gone.go")+"\n", WithToolchainRoot(root))
		st, err := CompletedState(obs)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Unverifiable {
			t.Fatal("unresolvable path under the guard root skipped observation")
		}
	})
}

// TestGuardCoveredSymlinkedRoot pins both root forms: with the declared root
// itself a symlink, reads recorded through either the link or the resolved
// directory are covered.
func TestGuardCoveredSymlinkedRoot(t *testing.T) {
	real := filepath.Join(t.TempDir(), "real-goroot")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	pinned := filepath.Join(real, "a.go")
	if err := os.WriteFile(pinned, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "goroot-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	log := "open " + filepath.Join(link, "a.go") + "\nopen " + pinned + "\n"
	obs := completedFromLog(t, t.TempDir(), log, WithToolchainRoot(link))
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("symlinked-root reads sealed unverifiable: %s", st.Reason)
	}
	d, err := Describe(st.Manifest, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 0 {
		t.Fatalf("symlinked-root reads recorded: %v", d.Paths)
	}
}

// TestGuardCoveredRootValidation pins the option contract: relative, empty,
// or unclean roots are refused at construction.
func TestGuardCoveredRootValidation(t *testing.T) {
	for _, bad := range []string{"", "relative/root", "/unclean//root", "/trail/"} {
		_, err := FromTestLog([]byte(""), t.TempDir(), ".", WithCompletedProcess("package-test-binary:x"), WithToolchainRoot(bad))
		if err == nil || !strings.Contains(err.Error(), "guard-covered root") {
			t.Fatalf("root %q accepted: %v", bad, err)
		}
	}
}

// TestModuleCacheRootExcludesDownloadCache pins the module-cache class
// (REQ-inputs-guard-covered): version-addressed extracted trees skip, while
// the download cache's mutable metadata — version lists, lock files — stays
// observed even though it lies under the declared root.
func TestModuleCacheRootExcludesDownloadCache(t *testing.T) {
	root := filepath.Join(t.TempDir(), "modcache")
	extracted := filepath.Join(root, "example.com", "dep@v1.2.3", "d.go")
	if err := os.MkdirAll(filepath.Dir(extracted), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(extracted, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(root, "cache", "download", "example.com", "dep", "@v", "list")
	if err := os.MkdirAll(filepath.Dir(metadata), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadata, []byte("v1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	obs := completedFromLog(t, t.TempDir(), "open "+extracted+"\nopen "+metadata+"\n", WithModuleCacheRoot(root))
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Describe(st.Manifest, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 1 || d.Paths[0] != metadata {
		t.Fatalf("paths = %v, want exactly the download-cache metadata observed", d.Paths)
	}
	if !st.Unverifiable {
		t.Fatal("out-of-bracket metadata read did not seal unverifiable")
	}
}

// TestGuardCoveredRefusesOutAndBackChain pins the per-link rule: a symlink
// chain that leaves the covered region and re-enters is a mutable rebinding
// point outside every guard, so the read stays observed even though its final
// resolution lands inside the root.
func TestGuardCoveredRefusesOutAndBackChain(t *testing.T) {
	root := filepath.Join(t.TempDir(), "goroot")
	real := filepath.Join(root, "realdir")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "f.go"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	hop := filepath.Join(t.TempDir(), "hop")
	if err := os.Symlink(real, hop); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hop, filepath.Join(root, "hopdir")); err != nil {
		t.Fatal(err)
	}

	obs := completedFromLog(t, t.TempDir(), "open "+filepath.Join(root, "hopdir", "f.go")+"\n", WithToolchainRoot(root))
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable {
		t.Fatal("out-and-back symlink chain skipped observation")
	}
	d, err := Describe(st.Manifest, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 1 {
		t.Fatalf("paths = %v, want the chained read observed", d.Paths)
	}
}

// TestGuardCoveredRelativeAfterChdirStaysObserved pins the untested gate arm:
// a relative read after a working-directory change is never provably inside a
// root, even when its lexical resolution lands there.
func TestGuardCoveredRelativeAfterChdirStaysObserved(t *testing.T) {
	root := filepath.Join(t.TempDir(), "goroot")
	sub := filepath.Join(root, "src")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "f.go"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := "chdir " + sub + "\nopen f.go\n"
	obs := completedFromLog(t, t.TempDir(), log, WithToolchainRoot(root))
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable {
		t.Fatal("relative read after chdir skipped observation")
	}
	d, err := Describe(st.Manifest, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 1 {
		t.Fatalf("paths = %v, want the post-chdir read observed", d.Paths)
	}
}

// TestGuardCoveredUnresolvableRootDeclaresNothing pins resolveGuardRoots'
// fail-closed arm: a declared root that does not exist covers nothing, so
// reads lexically under it stay observed.
func TestGuardCoveredUnresolvableRootDeclaresNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "never-created")
	obs := completedFromLog(t, t.TempDir(), "open "+filepath.Join(root, "f.go")+"\n", WithToolchainRoot(root))
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable {
		t.Fatal("read under an unresolvable root skipped observation")
	}
}

// The build-cache root covers every toolchain-mediated read — the
// mutable action index (-a entries) and root bookkeeping included, which
// per-object immutability could never admit — while the discovered fuzz
// corpus stays observed (REQ-inputs-guard-covered). Without the
// declaration the same reads observe as before, and a symlink escaping
// the root stays observed.
func TestBuildCacheRootCoversToolchainMediatedReads(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(t.TempDir(), "go-build")
	if err := os.MkdirAll(filepath.Join(root, "0d"), 0o755); err != nil {
		t.Fatal(err)
	}
	derived := filepath.Join(root, "0d", "0d1bed3295c5eb6e-d")
	index := filepath.Join(root, "0d", "0d1bed3295c5eb6e-a")
	trim := filepath.Join(root, "trim.txt")
	for _, p := range []string{derived, index, trim} {
		if err := os.WriteFile(p, []byte("cache object"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	log := "open " + derived + "\nopen " + index + "\nopen " + trim + "\nstat " + derived + "\n"

	obs := completedFromLog(t, dir, log, WithBuildCacheRoot(root))
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("build-cache reads sealed unverifiable: %s", st.Reason)
	}
	d, err := Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 0 || len(d.Unverifiable) != 0 {
		t.Fatalf("build-cache reads recorded: %+v", d)
	}

	// The fuzz corpus is the carve-out: discovered machine-local state a
	// -fuzz run consumes semantically, staying observed under the
	// declared root exactly as the module cache's cache/ subtree does.
	if err := os.MkdirAll(filepath.Join(root, "fuzz", "corpus"), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := filepath.Join(root, "fuzz", "corpus", "seed1")
	if err := os.WriteFile(seed, []byte("interesting input"), 0o644); err != nil {
		t.Fatal(err)
	}
	obsFuzz := completedFromLog(t, dir, "open "+seed+"\n", WithBuildCacheRoot(root))
	stFuzz, err := CompletedState(obsFuzz)
	if err != nil {
		t.Fatal(err)
	}
	dFuzz, err := Describe(stFuzz.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dFuzz.Paths)+len(dFuzz.Unverifiable) == 0 {
		t.Fatal("fuzz corpus read skipped — discovered state must stay observed")
	}

	// Undeclared, the identical reads observe.
	obs = completedFromLog(t, dir, log)
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	d, err = Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) == 0 {
		t.Fatal("undeclared build-cache reads recorded nothing")
	}

	// Fail-closed: a link under the root escaping it stays observed.
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("mutable"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "0d", "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	obs = completedFromLog(t, dir, "open "+link+"\n", WithBuildCacheRoot(root))
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	d, err = Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths)+len(d.Unverifiable) == 0 {
		t.Fatal("escaping link skipped — the fail-closed walk must observe it")
	}

	// A relative root is refused exactly as the sibling classes refuse it.
	if _, err := FromTestLog([]byte("open x\n"), dir, dir, WithBuildCacheRoot("relative/path")); err == nil {
		t.Fatal("relative build-cache root accepted")
	}
}

// An ephemeral temp root admits its OWN identity only: the stat and open
// of the root the temp machinery performs record nothing, while a file
// one level deeper — not run-created as far as any evidence shows —
// stays observed, an undeclared root observes as before, and a relative
// declaration is refused (REQ-inputs-ephemeral-root).
func TestEphemeralTempRootAdmitsOnlyItsOwnIdentity(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	deeper := filepath.Join(root, "left-behind.txt")
	if err := os.WriteFile(deeper, []byte("stale state"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := "stat " + root + "\nopen " + root + "\n"

	obs := completedFromLog(t, dir, log, WithEphemeralTempRoot(root))
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("ephemeral root reads sealed unverifiable: %s", st.Reason)
	}
	d, err := Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 0 || len(d.Unverifiable) != 0 {
		t.Fatalf("ephemeral root identity recorded: %+v", d)
	}

	// One level deeper is outside the admission.
	obs = completedFromLog(t, dir, "open "+deeper+"\n", WithEphemeralTempRoot(root))
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	d, err = Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths)+len(d.Unverifiable) == 0 {
		t.Fatal("deeper read skipped — the admission is one identity wide")
	}

	// Undeclared, the root observes (an external directory input).
	obs = completedFromLog(t, dir, log)
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	d, err = Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths)+len(d.Unverifiable) == 0 {
		t.Fatal("undeclared temp root recorded nothing")
	}

	if _, err := FromTestLog([]byte("open x\n"), dir, dir, WithEphemeralTempRoot("relative/tmp")); err == nil {
		t.Fatal("relative ephemeral root accepted")
	}

	// The resolved-form arm is load-bearing (macOS /tmp -> /private/tmp):
	// declaring the LINK admits an open of the REAL root.
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "tmplink")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	obs = completedFromLog(t, dir, "open "+real+"\n", WithEphemeralTempRoot(link))
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	d, err = Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths)+len(d.Unverifiable) != 0 {
		t.Fatalf("resolved-form admission failed: %+v", d)
	}

	// An unresolvable root declares nothing: a read of that very
	// identity still records.
	gone := filepath.Join(t.TempDir(), "never-created")
	obs = completedFromLog(t, dir, "open "+gone+"\n", WithEphemeralTempRoot(gone))
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	d, err = Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths)+len(d.Unverifiable) == 0 {
		t.Fatal("unresolvable root admitted reads")
	}

	// A module-interior root refuses loudly: it would vacate a
	// content-bearing module digest, not an external refusal. The root
	// exists, so the refusal is the interior check itself, not a
	// resolution skip.
	interior := filepath.Join(dir, "testdata")
	if err := os.MkdirAll(interior, 0o755); err != nil {
		t.Fatal(err)
	}
	interiorBracket, err := CaptureBracket(dir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromTestLog([]byte("open "+deeper+"\n"), dir, dir,
		WithCompletedProcess("package-test-binary:guard"), WithBracket(interiorBracket),
		WithEphemeralTempRoot(interior)); err == nil || !strings.Contains(err.Error(), "inside the module tree") {
		t.Fatalf("module-interior ephemeral root error = %v", err)
	}
	// An UNRESOLVABLE interior root refuses identically: the declared
	// form's interiority is checkable without resolution.
	missingBracket, err := CaptureBracket(dir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromTestLog([]byte("open "+deeper+"\n"), dir, dir,
		WithCompletedProcess("package-test-binary:guard"), WithBracket(missingBracket),
		WithEphemeralTempRoot(filepath.Join(dir, "missing"))); err == nil || !strings.Contains(err.Error(), "inside the module tree") {
		t.Fatalf("unresolvable interior root error = %v", err)
	}
}

// The allowlisted machine-fact identities digest as the stable machine
// projection, never as raw content or stat metadata: a record naming
// them revalidates equal on the same machine even though the files'
// bytes and mtimes move on every read (REQ-inputs-machine-identity).
// Linux-only: the identities exist only there.
func TestMachineFactIdentitiesDigestAsStableProjection(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("machine-fact identities are Linux proc files")
	}
	dir := t.TempDir()
	obs := completedFromLog(t, dir, "open /proc/cpuinfo\nopen /proc/meminfo\nopen /proc/sys/kernel/osrelease\n")
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("machine-fact reads sealed unverifiable: %s", st.Reason)
	}
	// Two later recomputations: proc mtimes have moved (they stamp at
	// stat time) and the MHz lines may have — the projection digest
	// must hold all three equal.
	for i := 0; i < 2; i++ {
		cur, err := CurrentEnv(st.Manifest, dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		if cur.Digest != st.Digest {
			t.Fatalf("recomputation %d moved: %s vs %s", i, cur.Digest, st.Digest)
		}
	}
}

// The clause's remaining arms: an ungatherable projection is unhashable
// and unverifiable, never silently skipped; a moved projection moves the
// digest (frame-level: two fingerprints, two frames); and a
// non-allowlisted proc identity keeps ordinary classification.
func TestMachineFactArmsAndContrast(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("machine-fact identities are Linux proc files")
	}
	dir := t.TempDir()

	// Ungatherable: the injected failure surfaces as unverifiable.
	prev := currentMachineFacts
	currentMachineFacts = func() (guard.MachineFacts, error) {
		return guard.MachineFacts{}, errors.New("injected gather failure")
	}
	obs := completedFromLog(t, dir, "open /proc/cpuinfo\n")
	currentMachineFacts = prev
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "unhashable runtime input: /proc/cpuinfo") {
		t.Fatalf("ungatherable projection not surfaced: unverifiable=%v reason=%s", st.Unverifiable, st.Reason)
	}

	// Movement: two distinct projections produce two distinct digests.
	sealDigest := func(facts guard.MachineFacts) string {
		prev := currentMachineFacts
		currentMachineFacts = func() (guard.MachineFacts, error) { return facts, nil }
		defer func() { currentMachineFacts = prev }()
		obs := completedFromLog(t, dir, "open /proc/cpuinfo\n")
		st, err := CompletedState(obs)
		if err != nil {
			t.Fatal(err)
		}
		return st.Digest
	}
	small := guard.MachineFacts{CPUModel: "m", PhysicalCores: 2, LogicalCores: 4, TotalRAMBytes: 1, OS: "linux", KernelVersion: "k"}
	big := small
	big.LogicalCores = 32
	if sealDigest(small) == sealDigest(big) {
		t.Fatal("a changed projection did not move the digest")
	}

	// Contrast: a non-allowlisted proc identity keeps ordinary
	// classification (recorded, bracket-uncovered → unverifiable).
	obs = completedFromLog(t, dir, "open /proc/stat\n")
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	// The assertion pins ORDINARY classification, not mere presence: an
	// allowlist widened to /proc/stat would record it verifiably and
	// still pass a presence check.
	if !st.Unverifiable || !strings.Contains(st.Reason, "not covered by observation bracket: /proc/stat") {
		t.Fatalf("non-allowlisted proc identity lost ordinary classification: unverifiable=%v reason=%s", st.Unverifiable, st.Reason)
	}
}

// The contentless sink device records nothing — reads see EOF, writes
// are discarded, no observable state flows through the identity — while
// its readable-value sibling stays observed and a mere name variant is
// admitted only through lexical cleaning (REQ-inputs-null-sink).
func TestNullSinkRecordsNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the admission is inert on windows: NUL is never an absolute cleaned path")
	}
	dir := t.TempDir()
	obs := completedFromLog(t, dir, "open /dev/null\nstat /dev/null\nopen /dev//null\n")
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("sink reads sealed unverifiable: %s", st.Reason)
	}
	d, err := Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 0 || len(d.Unverifiable) != 0 {
		t.Fatalf("sink reads recorded: %+v", d)
	}

	// The readable-value sibling keeps ordinary classification: the
	// admission is one literal identity, not the device class.
	obs = completedFromLog(t, dir, "open /dev/zero\n")
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "/dev/zero") {
		t.Fatalf("sibling device lost ordinary classification: unverifiable=%v reason=%s", st.Unverifiable, st.Reason)
	}

	// Another name resolving to the same device stays observed: the
	// admission is lexical identity, never device topology.
	link := filepath.Join(t.TempDir(), "null-alias")
	if err := os.Symlink(os.DevNull, link); err != nil {
		t.Fatal(err)
	}
	obs = completedFromLog(t, t.TempDir(), "open "+link+"\n")
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "null-alias") {
		t.Fatalf("sink alias lost ordinary classification: unverifiable=%v reason=%s", st.Unverifiable, st.Reason)
	}
}

// Deeper reads under a declared ephemeral root whose object is absent
// at ingest admit as per-run scratch — state that outlived the run
// would still be present — while a persistent deeper file stays
// observed, an existing escaping link on the path stays observed, and
// the same vanished path without the declaration stays observed
// (REQ-inputs-ephemeral-root).
func TestEphemeralScratchAbsentAtIngestRecordsNothing(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(t.TempDir(), "scratch")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(root, "run123", "deep", "data.txt")
	obs := completedFromLog(t, dir, "open "+gone+"\nstat "+filepath.Join(root, "run123")+"\n", WithEphemeralTempRoot(root))
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("vanished scratch sealed unverifiable: %s", st.Reason)
	}
	d, err := Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 0 || len(d.Unverifiable) != 0 {
		t.Fatalf("vanished scratch recorded: %+v", d)
	}

	// A persistent deeper file is state flowing between runs: observed.
	kept := filepath.Join(root, "kept.txt")
	if err := os.WriteFile(kept, []byte("outlived the run"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs = completedFromLog(t, dir, "open "+kept+"\n", WithEphemeralTempRoot(root))
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	dKept, err := Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dKept.Paths)+len(dKept.Unverifiable) == 0 {
		t.Fatal("persistent deeper file skipped observation")
	}

	// An existing link escaping the root redirects the runtime read
	// outside it: the absent leaf under the link stays observed.
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	obs = completedFromLog(t, dir, "open "+filepath.Join(link, "gone.txt")+"\n", WithEphemeralTempRoot(root))
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable {
		t.Fatal("absent leaf behind an escaping link skipped observation")
	}

	// A DANGLING link ancestor is detectable evidence the runtime read
	// escaped the root: it exists, does not resolve, and must refuse —
	// ascending past it would admit genuine external input.
	dangle := filepath.Join(root, "dangle")
	target := filepath.Join(t.TempDir(), "vanishing")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dangle); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	obs = completedFromLog(t, dir, "open "+filepath.Join(dangle, "gone.txt")+"\n", WithEphemeralTempRoot(root))
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable {
		t.Fatal("absent leaf behind a dangling link skipped observation")
	}

	// Undeclared, the identical vanished path observes and seals.
	obs = completedFromLog(t, dir, "open "+gone+"\n")
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable {
		t.Fatal("undeclared vanished path skipped observation")
	}
}

// A PWD read admits recordless exactly when the frozen environment
// carries PWD equal to the spawn directory — the value is then fully
// determined by the frame identity the record already pins — and seals
// process-local in every other posture (REQ-inputs-unbounded).
func TestPWDAdmitsOnlyWhenPinnedToSpawnDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	fromEnv := func(env []string) (bool, string, Description) {
		t.Helper()
		bracket, err := CaptureBracket(dir, []string{"data"})
		if err != nil {
			t.Fatal(err)
		}
		obs, err := FromTestLogEnv([]byte("getenv PWD\n"), dir, dir, env,
			WithCompletedProcess("package-test-binary:guard"), WithBracket(bracket))
		if err != nil {
			t.Fatal(err)
		}
		st, err := CompletedState(obs)
		if err != nil {
			t.Fatal(err)
		}
		d, err := Describe(st.Manifest, dir)
		if err != nil {
			t.Fatal(err)
		}
		return st.Unverifiable, st.Reason, d
	}

	unv, reason, d := fromEnv([]string{"PWD=" + dir})
	if unv {
		t.Fatalf("truthful PWD sealed: %s", reason)
	}
	if len(d.EnvNames)+len(d.Paths)+len(d.Unverifiable) != 0 {
		t.Fatalf("truthful PWD recorded: %+v", d)
	}

	for name, env := range map[string][]string{
		"divergent": {"PWD=" + filepath.Join(dir, "elsewhere")},
		"absent":    {"HOME=/h"},
	} {
		unv, reason, _ := fromEnv(env)
		if !unv || !strings.Contains(reason, "process-local environment input: PWD") {
			t.Fatalf("%s PWD posture not sealed: unverifiable=%v reason=%s", name, unv, reason)
		}
	}
}

// An external directory's stat binds existence alone: the entry
// revalidates equal while the directory exists, moves when it vanishes
// or becomes a file, and the open/listing form keeps ordinary
// classification (REQ-inputs-external-dir-existence).
func TestExternalDirectoryStatBindsExistence(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "ancestor")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	obs := completedFromLog(t, dir, "stat "+outside+"\n")
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("external dir stat sealed: %s", st.Reason)
	}
	d, err := Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 1 || !strings.Contains(d.Paths[0], "ancestor") || len(d.Unverifiable) != 0 {
		t.Fatalf("existence entry not recorded cleanly: %+v", d)
	}
	for i := 0; i < 2; i++ {
		cur, err := CurrentEnv(st.Manifest, dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		if cur.Digest != st.Digest {
			t.Fatalf("recomputation %d moved while the directory exists", i)
		}
	}
	// Vanishing moves the digest.
	if err := os.RemoveAll(outside); err != nil {
		t.Fatal(err)
	}
	cur, err := CurrentEnv(st.Manifest, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Digest == st.Digest {
		t.Fatal("vanished directory did not move the digest")
	}
	// Becoming a file moves it too.
	if err := os.WriteFile(outside, []byte("now a file"), 0o644); err != nil {
		t.Fatal(err)
	}
	cur, err = CurrentEnv(st.Manifest, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Digest == st.Digest {
		t.Fatal("directory replaced by a file did not move the digest")
	}

	// The open/listing form keeps ordinary classification.
	if err := os.Remove(outside); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	obs = completedFromLog(t, dir, "open "+outside+"\n")
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "external directory input") {
		t.Fatalf("external dir open lost ordinary classification: unverifiable=%v reason=%s", st.Unverifiable, st.Reason)
	}

	// An external FILE stat still seals metadata dependence.
	file := filepath.Join(filepath.Dir(outside), "plain.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs = completedFromLog(t, dir, "stat "+file+"\n")
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable {
		t.Fatal("external file stat lost its seal")
	}
	dFile, err := Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	sealed := false
	for _, reason := range dFile.Unverifiable {
		if strings.Contains(reason, "stat metadata input") {
			sealed = true
		}
	}
	if !sealed {
		t.Fatalf("external file stat lost the metadata seal: %v", dFile.Unverifiable)
	}
}
