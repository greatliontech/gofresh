package runtimeinput

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/outcome"
)

// testEntryDigest satisfies the entry-digest shape for hand-built manifests;
// state computation always recomputes real digests over current content.
const testEntryDigest = "00000000000000000000000000000000"

type cancelAfterChecks struct {
	context.Context
	after, checks int
}

func (c *cancelAfterChecks) Err() error {
	c.checks++
	if c.checks > c.after {
		return context.Canceled
	}
	return nil
}

func TestCurrentHonorsCancellation(t *testing.T) {
	moduleDir := t.TempDir()
	state, err := ambientMerge(moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Current(ctx, state.Manifest, moduleDir, os.Environ()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled current check = %v, want context.Canceled", err)
	}
}

func TestCurrentStopsBetweenInputsAndFileChunks(t *testing.T) {
	moduleDir := t.TempDir()
	encoded, err := encode(manifest{Version: manifestVersion, Env: []envInput{{Name: "A", Digest: testEntryDigest}, {Name: "B", Digest: testEntryDigest}}})
	if err != nil {
		t.Fatal(err)
	}
	envCtx := &cancelAfterChecks{Context: context.Background(), after: 3}
	if _, err := Current(envCtx, encoded, moduleDir, []string{"A=1", "B=2"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("between-environment cancellation = %v, want context.Canceled", err)
	}
	path := filepath.Join(moduleDir, "large")
	if err := os.WriteFile(path, make([]byte, 64*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	fileCtx := &cancelAfterChecks{Context: context.Background(), after: 1}
	if _, err := fileHash(fileCtx, path); !errors.Is(err, context.Canceled) {
		t.Fatalf("file-chunk cancellation = %v, want context.Canceled", err)
	}
	dirCtx := &cancelAfterChecks{Context: context.Background(), after: 1}
	if _, _, _, err := dirHashFiltered(dirCtx, moduleDir, moduleDir, nil, nil, true, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("directory-entry cancellation = %v, want context.Canceled", err)
	}
}

// testBracket captures an observation bracket over roots — the whole module
// by default — for completed-observation construction in tests.
func testBracket(t *testing.T, moduleDir string, roots ...string) Bracket {
	t.Helper()
	if len(roots) == 0 {
		roots = []string{"."}
	}
	bracket, err := ambientCaptureBracket(moduleDir, roots)
	if err != nil {
		t.Fatal(err)
	}
	return bracket
}

func testDirs(t *testing.T) (string, string) {
	t.Helper()
	moduleDir := filepath.Join(t.TempDir(), "mod")
	packageDir := filepath.Join(moduleDir, "pkg")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return moduleDir, packageDir
}

func TestIncompleteObservationIsDistinctAndMergeable(t *testing.T) {
	moduleDir := t.TempDir()
	incomplete, err := ambientIncomplete(moduleDir, "worker", "test process timed out")
	if err != nil {
		t.Fatal(err)
	}
	if !incomplete.OK || !incomplete.Unverifiable || !strings.Contains(incomplete.Reason, "timed out") {
		t.Fatalf("Incomplete = %+v", incomplete)
	}
	empty, err := ambientMerge(moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if incomplete.Manifest == empty.Manifest {
		t.Fatal("incomplete observation equals completed empty observation")
	}
	merged, err := ambientMerge(moduleDir, empty, incomplete)
	if err != nil {
		t.Fatal(err)
	}
	if !merged.Unverifiable || !strings.Contains(merged.Reason, "timed out") {
		t.Fatalf("merged incomplete evidence = %+v", merged)
	}
	if _, err := ambientIncomplete(moduleDir, "worker", " "); err == nil {
		t.Fatal("Incomplete accepted an empty reason")
	}
	for _, reason := range []string{"line\nbreak", "carriage\rreturn", "nul\x00byte", string([]byte{0xff})} {
		if _, err := ambientIncomplete(moduleDir, "worker", reason); err == nil {
			t.Errorf("Incomplete accepted unsafe reason %q", reason)
		}
	}
}

func TestAbsoluteIdentitiesMergeAcrossModuleRoots(t *testing.T) {
	moduleA, packageA := testDirs(t)
	moduleB, packageB := testDirs(t)
	pathA := filepath.Join(packageA, "a.txt")
	pathB := filepath.Join(packageB, "b.txt")
	if err := os.WriteFile(pathA, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := ambientFromTestLog([]byte("open a.txt\n"), moduleA, packageA, WithCompletedProcess("module-a"), WithBracket(testBracket(t, moduleA)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ambientFromTestLog([]byte("open b.txt\n"), moduleB, packageB, WithCompletedProcess("module-b"), WithBracket(testBracket(t, moduleB)))
	if err != nil {
		t.Fatal(err)
	}
	a, err = ambientAbsolute(a, moduleA)
	if err != nil {
		t.Fatal(err)
	}
	b, err = ambientAbsolute(b, moduleB)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := ambientMerge(t.TempDir(), a, b)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := Paths(merged.Manifest, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(paths, []string{pathA, pathB}) {
		t.Fatalf("merged absolute paths = %v, want [%s %s]", paths, pathA, pathB)
	}
}

func TestAbsoluteIdentitiesNeverSuppressUnverifiability(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	external := filepath.Join(t.TempDir(), "external.txt")
	if err := os.WriteFile(external, []byte("external"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(packageDir, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	state, err := ambientFromTestLog([]byte("open link\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable {
		t.Fatal("external symlink target was not unverifiable before conversion")
	}
	converted, err := ambientAbsolute(state, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if !converted.Unverifiable || converted.Reason == "" {
		t.Fatalf("Absolute suppressed unverifiability: %+v", converted)
	}

	regular := filepath.Join(packageDir, "regular.txt")
	if err := os.WriteFile(regular, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err = ambientFromTestLog([]byte("open regular.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regular, []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ambientAbsolute(state, moduleDir); err == nil {
		t.Fatal("Absolute accepted a moved state")
	}
}

func rawManifest(t *testing.T, m manifest) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestEnvDigestChangesWithoutStoringValue(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	t.Setenv("PEW_SECRET_TOKEN", "first-secret")

	st, err := ambientFromTestLog([]byte("# test log\ngetenv PEW_SECRET_TOKEN\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if !st.OK {
		t.Fatal("runtime state not OK")
	}
	manifestJSON, err := base64.RawURLEncoding.DecodeString(st.Manifest)
	if err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if strings.Contains(string(manifestJSON), "first-secret") {
		t.Fatalf("manifest stores env value: %q", manifestJSON)
	}

	same, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current same: %v", err)
	}
	if same.Digest != st.Digest {
		t.Fatalf("same env digest = %q, want %q", same.Digest, st.Digest)
	}

	t.Setenv("PEW_SECRET_TOKEN", "second-secret")
	changed, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current changed: %v", err)
	}
	if changed.Digest == st.Digest {
		t.Fatal("env value change did not move runtime digest")
	}
}

func TestCurrentUsesSuppliedEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOWORK", "/ambient/workspace")
	env := []string{"GOWORK=/explicit/workspace"}
	state, err := FromTestLog([]byte("getenv GOWORK\n"), dir, dir, env, WithCompletedProcess("worker"), WithBracket(testBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	current, err := ambientCurrentEnv(state.Manifest, dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if current != state.State {
		t.Fatalf("explicitly finalized state moved under the same env:\n%+v\n%+v", state, current)
	}
	ambient, err := ambientCurrent(state.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if ambient.Digest == state.Digest {
		t.Fatal("explicit GOWORK state was finalized from ambient GOWORK")
	}
	changed, err := ambientCurrentEnv(state.Manifest, dir, []string{"GOWORK=/other/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	if changed == state.State || changed.Digest == state.Digest {
		t.Fatal("moving supplied GOWORK did not move the runtime-input state")
	}
}

func TestFromTestLogMarksPWDUnverifiable(t *testing.T) {
	dir := t.TempDir()
	state, err := FromTestLog([]byte("getenv PWD\n"), dir, dir, []string{"PWD=/caller"}, WithCompletedProcess("worker"), WithBracket(testBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable || !strings.Contains(state.Reason, "process-local environment input: PWD") {
		t.Fatalf("PWD observation = %+v, want process-local unverifiable evidence", state)
	}
}

func TestEnvironmentStateAbsoluteAndMergeUseSuppliedEnvironment(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "fixture.txt"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", "/ambient/workspace")
	env := []string{"GOWORK=/explicit/workspace"}
	state, err := FromTestLog([]byte("getenv GOWORK\nopen fixture.txt\n"), moduleDir, packageDir, env, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := Absolute(state, moduleDir, env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ambientAbsolute(state, moduleDir); err == nil {
		t.Fatal("ambient Absolute accepted a state finalized under a different environment")
	}
	incomplete, err := Incomplete(moduleDir, "worker-incomplete", "worker interrupted", env)
	if err != nil {
		t.Fatal(err)
	}
	mergeDir := t.TempDir()
	merged, err := Merge(mergeDir, env, absolute, incomplete)
	if err != nil {
		t.Fatal(err)
	}
	current, err := ambientCurrentEnv(merged.Manifest, mergeDir, env)
	if err != nil {
		t.Fatal(err)
	}
	if current != merged.State || !merged.Unverifiable {
		t.Fatalf("merged explicit-environment state = %+v, current = %+v", merged, current)
	}
	if _, err := ambientMerge(mergeDir, absolute, incomplete); err == nil {
		t.Fatal("ambient Merge accepted states finalized under a different environment")
	}
	if _, err := Merge(mergeDir, []string{"GOWORK=/other/workspace"}, absolute); err == nil {
		t.Fatal("Merge accepted a state finalized under a different supplied environment")
	}
}

func TestAmbientConstructionWrappersMatchAmbientEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOWORK", "/ambient/workspace")
	env := os.Environ()
	fromAmbient, err := ambientFromTestLog([]byte("getenv GOWORK\n"), dir, dir, WithCompletedProcess("worker"), WithBracket(testBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fromEnv, err := FromTestLog([]byte("getenv GOWORK\n"), dir, dir, env, WithCompletedProcess("worker"), WithBracket(testBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromAmbient, fromEnv) {
		t.Fatalf("FromTestLog wrapper differs from ambient Env variant:\n%+v\n%+v", fromAmbient, fromEnv)
	}
	incompleteAmbient, err := ambientIncomplete(dir, "worker-incomplete", "interrupted")
	if err != nil {
		t.Fatal(err)
	}
	incompleteEnv, err := Incomplete(dir, "worker-incomplete", "interrupted", env)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(incompleteAmbient, incompleteEnv) {
		t.Fatal("Incomplete wrapper differs from ambient Env variant")
	}
	absoluteAmbient, err := ambientAbsolute(fromAmbient, dir)
	if err != nil {
		t.Fatal(err)
	}
	absoluteEnv, err := Absolute(fromEnv, dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(absoluteAmbient, absoluteEnv) {
		t.Fatal("Absolute wrapper differs from ambient Env variant")
	}
	mergedAmbient, err := ambientMerge(dir, absoluteAmbient, incompleteAmbient)
	if err != nil {
		t.Fatal(err)
	}
	mergedEnv, err := Merge(dir, env, absoluteEnv, incompleteEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(mergedAmbient, mergedEnv) {
		t.Fatal("Merge wrapper differs from ambient Env variant")
	}
}

func TestFileDigestChanges(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	path := filepath.Join(packageDir, "fixture.txt")
	if err := os.WriteFile(path, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := ambientFromTestLog([]byte("# test log\nopen fixture.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if st.Unverifiable {
		t.Fatalf("regular module file marked unverifiable: %s", st.Reason)
	}
	if err := os.WriteFile(path, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if changed.Digest == st.Digest {
		t.Fatal("file content change did not move runtime digest")
	}
}

func TestOpenFileMetadataMovesDigest(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	path := filepath.Join(packageDir, "fixture.txt")
	if err := os.WriteFile(path, []byte("same bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := ambientFromTestLog([]byte("# test log\nopen fixture.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	changed, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if changed.Digest == st.Digest {
		t.Fatal("file metadata change did not move runtime digest")
	}
}

func TestOpenDirectoryEntryMetadataMovesDigest(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	dir := filepath.Join(packageDir, "data")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fixture.txt")
	if err := os.WriteFile(path, []byte("same bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := ambientFromTestLog([]byte("# test log\nopen data\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	changed, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if changed.Digest == st.Digest {
		t.Fatal("directory entry metadata change did not move runtime digest")
	}
}

func TestMissingFileAppearanceMovesDigest(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	path := filepath.Join(packageDir, "later.txt")
	st, err := ambientFromTestLog([]byte("# test log\nopen later.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if err := os.WriteFile(path, []byte("now here"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if changed.Digest == st.Digest {
		t.Fatal("missing file appearance did not move runtime digest")
	}
}

func TestExternalDirectoryIsUnverifiable(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	externalDir := t.TempDir()
	st, err := ambientFromTestLog([]byte("# test log\nopen "+externalDir+"\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "external directory") {
		t.Fatalf("got unverifiable=%v reason=%q, want external directory", st.Unverifiable, st.Reason)
	}
	same, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if same.Digest != st.Digest {
		t.Fatalf("unverifiable manifest digest changed without input change: %q vs %q", same.Digest, st.Digest)
	}
	if !same.Unverifiable {
		t.Fatal("unverifiable marker did not round-trip")
	}
}

func TestStatObservationIsUnverifiable(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	// Only a stat outside every declared bracket root takes the
	// metadata seal (REQ-inputs-unbounded): a covered stat records its
	// identity (TestModuleRootBracketCoversInteriorStats). An uncovered
	// existing file additionally takes the bracket-coverage seal, which
	// wins reason precedence, so the metadata seal is pinned on the
	// manifest's unverifiable list.
	path := filepath.Join(t.TempDir(), "fixture.txt")
	if err := os.WriteFile(path, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := ambientFromTestLog([]byte("# test log\nstat "+path+"\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if !st.Unverifiable {
		t.Fatalf("got unverifiable=%v reason=%q, want the uncovered stat sealed", st.Unverifiable, st.Reason)
	}
	decoded, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	sealed := false
	for _, reason := range decoded.Unverifiable {
		if strings.Contains(reason, "stat metadata") {
			sealed = true
		}
	}
	if !sealed {
		t.Fatalf("unverifiable reasons %v carry no stat-metadata seal", decoded.Unverifiable)
	}
	paths, err := Paths(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(paths, []string{path}) {
		t.Fatalf("stat paths = %v, want [%s]", paths, path)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	cur, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if !cur.Unverifiable {
		t.Fatal("stat metadata manifest became verifiable")
	}
}

func TestSymlinkDirectoryHashesInternalTarget(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	target := filepath.Join(moduleDir, "realdata")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "one.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(packageDir, "data")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	st, err := ambientFromTestLog([]byte("# test log\nopen data\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if st.Unverifiable {
		t.Fatalf("internal symlink dir marked unverifiable: %s", st.Reason)
	}
	if err := os.WriteFile(filepath.Join(target, "two.txt"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if changed.Digest == st.Digest {
		t.Fatal("symlink directory target change did not move runtime digest")
	}
}

func TestSymlinkDirectoryToExternalTargetIsUnverifiable(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	external := t.TempDir()
	link := filepath.Join(packageDir, "data")
	if err := os.Symlink(external, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	st, err := ambientFromTestLog([]byte("# test log\nopen data\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	// Construction records the module-escaping resolution as an uncovered
	// identity; the digest-time external-directory disposition holds on the
	// identity independently of bracket coverage.
	if !st.Unverifiable || !strings.Contains(st.Reason, "not covered by observation bracket: pkg/data") {
		t.Fatalf("got unverifiable=%v reason=%q, want uncovered escaping identity", st.Unverifiable, st.Reason)
	}
	current, err := ambientCurrent(rawManifest(t, manifest{Version: manifestVersion, Paths: []pathInput{{pathID: pathID{Kind: pathRel, Path: "pkg/data"}, Digest: testEntryDigest}}}), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Unverifiable || !strings.Contains(current.Reason, "external directory") {
		t.Fatalf("got unverifiable=%v reason=%q, want external directory", current.Unverifiable, current.Reason)
	}
}

func TestSymlinkFileToExternalTargetIsUnverifiable(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	external := filepath.Join(t.TempDir(), "external.txt")
	if err := os.WriteFile(external, []byte("external"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(packageDir, "data.txt")
	if err := os.Symlink(external, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	st, err := ambientFromTestLog([]byte("open data.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	// Construction records the module-escaping resolution as an uncovered
	// identity; the digest-time external-target disposition holds on the
	// identity independently of bracket coverage.
	if !st.Unverifiable || !strings.Contains(st.Reason, "not covered by observation bracket: pkg/data.txt") {
		t.Fatalf("state = %+v, want uncovered escaping identity", st)
	}
	current, err := ambientCurrent(rawManifest(t, manifest{Version: manifestVersion, Paths: []pathInput{{pathID: pathID{Kind: pathRel, Path: "pkg/data.txt"}, Digest: testEntryDigest}}}), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	resolvedExternal, err := filepath.EvalSymlinks(external)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Unverifiable || !strings.Contains(current.Reason, "external runtime input target") || !strings.Contains(current.Reason, `recorded path "pkg/data.txt" resolves to `+strconv.Quote(resolvedExternal)+` outside the tree`) {
		t.Fatalf("state = %+v, want external target unverifiable", current)
	}
}

func TestUnixBackslashPathRemainsV1Compatible(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("backslash is a path separator on Windows")
	}
	moduleDir, packageDir := testDirs(t)
	name := `a\b`
	if err := os.WriteFile(filepath.Join(packageDir, name), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := ambientFromTestLog([]byte("open "+name+"\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ambientCurrent(st.Manifest, moduleDir); err != nil {
		t.Fatalf("Current rejected package-produced v1 path: %v", err)
	}
}

func TestSymlinkedModuleRootKeepsInternalDirectoryVerifiable(t *testing.T) {
	base := t.TempDir()
	realModule := filepath.Join(base, "realmod")
	realPackage := filepath.Join(realModule, "pkg")
	data := filepath.Join(realPackage, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "fixture.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkModule := filepath.Join(base, "linkmod")
	if err := os.Symlink(realModule, linkModule); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	st, err := ambientFromTestLog([]byte("# test log\nopen data\n"), linkModule, filepath.Join(linkModule, "pkg"), WithCompletedProcess("worker"), WithBracket(testBracket(t, linkModule)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if st.Unverifiable {
		t.Fatalf("symlinked module root marked internal dir unverifiable: %s", st.Reason)
	}
}

func TestChdirResolvesRelativePaths(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	sub := filepath.Join(packageDir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "fixture.txt")
	if err := os.WriteFile(path, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := ambientFromTestLog([]byte("# test log\nchdir sub\nopen fixture.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	reasons := strings.Join(m.Unverifiable, "\n")
	if !st.Unverifiable || !strings.Contains(reasons, "working-directory change") || !strings.Contains(reasons, "relative runtime input after working-directory change") {
		t.Fatalf("chdir observation = %+v reasons=%v, want operation and relative-path dispositions", st, m.Unverifiable)
	}
	if err := os.WriteFile(path, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if changed.Digest == st.Digest {
		t.Fatal("relative path after chdir did not track the target file")
	}
}

// TestCongruentParentTraversalResolvesLexically pins
// REQ-inputs-path-congruence's discharge: a ".." read whose crossed
// directories are all real (non-symlink) directories resolves to its
// lexical cleaning and is observed like any other path input — the
// ubiquitous repo-root-from-package-directory test idiom — while the same
// read crossing a symlinked component stays sealed.
func TestCongruentParentTraversalResolvesLexically(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(moduleDir, "fixture.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := ambientFromTestLog([]byte("# test log\nopen ../fixture.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if st.Unverifiable {
		t.Fatalf("congruent parent traversal sealed the observation: %+v", st)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "fixture.txt"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	cur, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if cur.Digest == st.Digest {
		t.Fatal("congruent traversal did not track the resolved file")
	}
}

// TestTraversalVerificationFailuresStaySealed pins the discharge's
// fail-closed legs beyond the symlink one: crossing a non-directory and
// crossing a vanished component both keep the seal.
func TestTraversalVerificationFailuresStaySealed(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "fixture.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, log := range map[string]string{
		"non-directory crossing": "open fixture.txt/../fixture.txt\n",
		"vanished component":     "open gone/../fixture.txt\n",
	} {
		st, err := ambientFromTestLog([]byte(log), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !st.Unverifiable || !strings.Contains(st.Reason, "ambiguous parent traversal") {
			t.Fatalf("%s = %+v, want the fail-closed seal", name, st)
		}
	}
}

// TestVolatileTraversalRefusesWithoutProbing pins the volatile no-probe
// contract over the discharge (REQ-inputs-volatile-os-roots): a traversal
// crossing a volatile OS root seals without the verifier reading it.
func TestVolatileTraversalRefusesWithoutProbing(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	orig := congruenceProbe
	congruenceProbe = func(p string) (os.FileInfo, error) {
		if volatileOSPath(p) {
			t.Errorf("congruence verifier probed a volatile OS path: %s", p)
		}
		return orig(p)
	}
	t.Cleanup(func() { congruenceProbe = orig })
	st, err := ambientFromTestLog([]byte("open /proc/self/../environ\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable {
		t.Fatalf("volatile traversal = %+v, want sealed", st)
	}
}

// TestSymlinkedWorkingDirectoryTraversalIsUnverifiable pins the crossing
// check over the resolution base itself: a ".." stepping back across a
// symlinked package-directory component cannot be proven congruent and
// keeps the fail-closed seal.
func TestSymlinkedWorkingDirectoryTraversalIsUnverifiable(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(moduleDir, "fixture.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(moduleDir, "linkedpkg")
	if err := os.Symlink(packageDir, linked); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	st, err := ambientFromTestLog([]byte("open ../fixture.txt\n"), moduleDir, linked, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "ambiguous parent traversal") {
		t.Fatalf("symlinked base traversal = %+v, want blocking disposition", st)
	}
}

func TestSymlinkParentTraversalIsUnverifiable(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(packageDir, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	st, err := ambientFromTestLog([]byte("open link/../fixture.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "ambiguous parent traversal") {
		t.Fatalf("symlink parent traversal = %+v, want blocking disposition", st)
	}
}

func TestAbsolutePathAfterChdirDoesNotAcquireRelativeDisposition(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	absolute := filepath.Join(moduleDir, "fixture.txt")
	if err := os.WriteFile(absolute, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := ambientFromTestLog([]byte("chdir .\nopen "+absolute+"\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, "relative runtime input") {
			t.Fatalf("absolute path received relative disposition: %+v", m.Unverifiable)
		}
	}
}

func TestCurrentRejectsRelativePathTraversal(t *testing.T) {
	moduleDir, _ := testDirs(t)
	encoded := rawManifest(t, manifest{Version: manifestVersion, Paths: []pathInput{{pathID: pathID{Kind: pathRel, Path: "../secret.txt"}, Digest: testEntryDigest}}})
	if _, err := ambientCurrent(encoded, moduleDir); err == nil {
		t.Fatal("Current accepted a relative path escaping the module")
	}
}

func TestCurrentRejectsMalformedManifestIdentities(t *testing.T) {
	moduleDir, _ := testDirs(t)
	for _, m := range []manifest{
		{Version: manifestVersion, Env: []envInput{{Name: "BAD\nNAME", Digest: testEntryDigest}}},
		{Version: manifestVersion, Paths: []pathInput{{pathID: pathID{Kind: pathRel, Path: "bad\npath"}, Digest: testEntryDigest}}},
		{Version: manifestVersion, Paths: []pathInput{{pathID: pathID{Kind: pathAbs, Path: "relative"}, Digest: testEntryDigest}}},
	} {
		encoded := rawManifest(t, m)
		if _, err := ambientCurrent(encoded, moduleDir); err == nil {
			t.Fatalf("Current accepted malformed manifest: %+v", m)
		}
	}
}

func TestModuleRelPaths(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "hosts")
	enc, err := encode(manifest{
		Version: manifestVersion,
		Env:     []envInput{{Name: "PEW_X", Digest: testEntryDigest}},
		Paths: []pathInput{
			{pathID: pathID{Kind: pathRel, Path: "data/fixture.txt"}, Digest: testEntryDigest},
			{pathID: pathID{Kind: pathRel, Path: "a.txt"}, Digest: testEntryDigest},
			{pathID: pathID{Kind: pathAbs, Path: abs}, Digest: testEntryDigest},
		},
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := ModuleRelPaths(enc)
	if err != nil {
		t.Fatalf("ModuleRelPaths: %v", err)
	}
	// Only the module-relative (pathRel) inputs; absolute inputs and env excluded.
	want := map[string]bool{"data/fixture.txt": true, "a.txt": true}
	if len(got) != len(want) {
		t.Fatalf("ModuleRelPaths = %v, want the two rel paths only", got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("ModuleRelPaths returned unexpected %q", p)
		}
	}
}

func TestPathsMaterializesRelativeAndExternalIdentities(t *testing.T) {
	parent := t.TempDir()
	moduleDir := filepath.Join(parent, "module")
	if err := os.Mkdir(moduleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(parent)
	external := filepath.Join(t.TempDir(), "external.txt")
	encoded := rawManifest(t, manifest{
		Version: manifestVersion,
		Paths: []pathInput{
			{pathID: pathID{Kind: pathAbs, Path: external}, Digest: testEntryDigest},
			{pathID: pathID{Kind: pathRel, Path: "fixtures/input.txt"}, Digest: testEntryDigest},
		},
	})
	got, err := Paths(encoded, "module")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{external, filepath.Join(moduleDir, "fixtures", "input.txt")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Paths = %v, want %v", got, want)
	}
}

func TestMergeUnionsIndependentProcessManifests(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(packageDir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("MERGE_A", "a")
	t.Setenv("MERGE_B", "b")
	a, err := ambientFromTestLog([]byte("getenv MERGE_A\nopen a.txt\nunknown first\n"), moduleDir, packageDir, WithCompletedProcess("worker-a"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ambientFromTestLog([]byte("getenv MERGE_B\nopen b.txt\nbadline\n"), moduleDir, packageDir, WithCompletedProcess("worker-b"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}

	merged, err := ambientMerge(moduleDir, a, b)
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(merged.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var envNames []string
	for _, entry := range m.Env {
		envNames = append(envNames, entry.Name)
	}
	if got := strings.Join(envNames, ","); got != "MERGE_A,MERGE_B" {
		t.Fatalf("merged env = %q", got)
	}
	if len(m.Paths) != 2 || m.Paths[0].Path != "pkg/a.txt" || m.Paths[1].Path != "pkg/b.txt" {
		t.Fatalf("merged paths = %+v", m.Paths)
	}
	wantReasons := "malformed testlog line,unrecognized testlog op: unknown"
	if got := strings.Join(m.Unverifiable, ","); got != wantReasons || !merged.Unverifiable {
		t.Fatalf("merged unverifiable = %v state=%+v", m.Unverifiable, merged)
	}

	if err := os.WriteFile(filepath.Join(packageDir, "b.txt"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := ambientCurrent(merged.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Digest == merged.Digest {
		t.Fatal("change to second process input did not move merged digest")
	}
}

func TestCompletedObservationRequiresProcessAssertion(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if _, err := ambientFromTestLog([]byte("getenv HOME\n"), moduleDir, packageDir); err == nil {
		t.Fatal("completed log accepted without process assertion")
	}
	for _, process := range []string{"", "line\nbreak", "nul\x00byte", string([]byte{0xff})} {
		if _, err := ambientFromTestLog([]byte("getenv HOME\n"), moduleDir, packageDir, WithCompletedProcess(process), WithBracket(testBracket(t, moduleDir))); err == nil {
			t.Errorf("completed log accepted invalid process %q", process)
		}
	}
}

func TestCompletedObservationRetainsMalformedRecords(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	oversized := append([]byte("unknown "), bytes.Repeat([]byte{'x'}, 70<<10)...)
	oversized = append(oversized, '\n')
	for name, log := range map[string][]byte{
		"unknown header":   []byte("# other\n"),
		"blank record":     []byte("# test log\n\n"),
		"partial record":   []byte("getenv HOME"),
		"carriage return":  []byte("getenv HOME\r\n"),
		"oversized record": oversized,
	} {
		t.Run(name, func(t *testing.T) {
			observation, err := ambientFromTestLog(log, moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
			if err != nil {
				t.Fatal(err)
			}
			if !observation.Unverifiable {
				t.Fatalf("malformed log produced verifiable observation: %+v", observation)
			}
		})
	}
}

func TestMergeRejectsConflictingEvidenceForOneProcess(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	first, err := ambientFromTestLog([]byte("getenv HOME\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ambientIncomplete(moduleDir, "worker", "worker interrupted")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ambientMerge(moduleDir, first, second); err == nil {
		t.Fatal("conflicting evidence for one process was merged")
	}
}

func TestProducerOperationsRejectRecomputedState(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	state, err := ambientCurrent(rawManifest(t, manifest{Version: manifestVersion}), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	forged := Observation{State: state}
	if _, err := ambientMerge(moduleDir, forged); err == nil {
		t.Fatal("merge accepted checker-recomputed state")
	}
	if _, err := ambientAbsolute(forged, moduleDir); err == nil {
		t.Fatal("absolute conversion accepted checker-recomputed state")
	}
	valid, err := ambientFromTestLog([]byte("getenv HOME\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	valid.State = state
	if _, err := ambientMerge(moduleDir, valid); err == nil {
		t.Fatal("merge accepted transplanted state under genuine provenance")
	}
	if _, err := ambientAbsolute(valid, moduleDir); err == nil {
		t.Fatal("absolute conversion accepted transplanted state under genuine provenance")
	}
}

func TestMergeRejectsRelativeAndAbsoluteEvidenceForOneProcess(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "fixture"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	relative, err := ambientFromTestLog([]byte("open fixture\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := ambientAbsolute(relative, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ambientMerge(moduleDir, relative, absolute); err == nil {
		t.Fatal("relative and absolute evidence for one process were merged")
	}
	absoluteAgain, err := ambientAbsolute(absolute, moduleDir)
	if err != nil || !reflect.DeepEqual(absoluteAgain, absolute) {
		t.Fatalf("absolute conversion is not idempotent: %+v != %+v, err=%v", absoluteAgain, absolute, err)
	}
}

func TestAbsolutePreservesCompletedVersusIncompleteOrigin(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	completed, err := ambientFromTestLog([]byte("\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	incomplete, err := ambientIncomplete(moduleDir, "worker", "malformed testlog line")
	if err != nil {
		t.Fatal(err)
	}
	completed, err = ambientAbsolute(completed, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	incomplete, err = ambientAbsolute(incomplete, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != incomplete.State {
		t.Fatalf("test precondition failed: completed=%+v incomplete=%+v", completed.State, incomplete.State)
	}
	if _, err := ambientMerge(moduleDir, completed, incomplete); err == nil {
		t.Fatal("absolute conversion erased completed-versus-incomplete provenance")
	}
}

func TestAbsoluteProcessViewIgnoresUnrelatedMergedProcesses(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(packageDir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a, err := ambientFromTestLog([]byte("open a\n"), moduleDir, packageDir, WithCompletedProcess("worker-a"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ambientFromTestLog([]byte("open b\n"), moduleDir, packageDir, WithCompletedProcess("worker-b"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	whole, err := ambientMerge(moduleDir, a, b)
	if err != nil {
		t.Fatal(err)
	}
	whole, err = ambientAbsolute(whole, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	a, err = ambientAbsolute(a, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ambientMerge(moduleDir, whole, a); err != nil {
		t.Fatalf("unrelated process changed absolute view for worker-a: %v", err)
	}
}

func TestMergeAlgebra(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	states := make([]Observation, 3)
	for i, log := range []string{"getenv C\n", "getenv A\n", "getenv B\n"} {
		var err error
		states[i], err = ambientFromTestLog([]byte(log), moduleDir, packageDir, WithCompletedProcess(fmt.Sprintf("worker-%d", i)), WithBracket(testBracket(t, moduleDir)))
		if err != nil {
			t.Fatal(err)
		}
	}
	merge := func(inputs ...Observation) Observation {
		t.Helper()
		st, err := ambientMerge(moduleDir, inputs...)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	ab := merge(states[0], states[1])
	ba := merge(states[1], states[0])
	if !reflect.DeepEqual(ab, ba) {
		t.Fatalf("merge is not commutative:\n%+v\n%+v", ab, ba)
	}
	aa := merge(states[0], states[0])
	if !reflect.DeepEqual(aa, states[0]) {
		t.Fatalf("merge is not idempotent:\n%+v\n%+v", aa, states[0])
	}
	left := merge(ab, states[2])
	bc := merge(states[1], states[2])
	right := merge(states[0], bc)
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("merge is not associative:\n%+v\n%+v", left, right)
	}
}

func TestMergeZeroIsExplicitEmptyManifest(t *testing.T) {
	moduleDir, _ := testDirs(t)
	st, err := ambientMerge(moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Manifest == "" || st.Digest == "" || !st.OK {
		t.Fatalf("zero merge = %+v, want encoded observation-free state", st)
	}
	m, err := decode(st.Manifest)
	if err != nil || m.Version != manifestVersion || len(m.Env)+len(m.Paths)+len(m.Unverifiable) != 0 {
		t.Fatalf("zero merge manifest = %+v err=%v", m, err)
	}
	if _, err := ambientMerge(moduleDir, Observation{}); err == nil {
		t.Fatal("empty merge input accepted as observation-free manifest")
	}
	nested, err := ambientMerge(moduleDir, st)
	if err != nil || !reflect.DeepEqual(nested, st) {
		t.Fatalf("nested zero merge = %+v, %v; want identity", nested, err)
	}
}

func TestMergeRejectsChildThatMovedBeforeUnion(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	t.Setenv("MERGE_COHERENCE", "first")
	first, err := ambientFromTestLog([]byte("getenv MERGE_COHERENCE\n"), moduleDir, packageDir, WithCompletedProcess("worker-a"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MERGE_COHERENCE", "second")
	second, err := ambientFromTestLog([]byte("getenv MERGE_COHERENCE\n"), moduleDir, packageDir, WithCompletedProcess("worker-b"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ambientMerge(moduleDir, first, second); err == nil {
		t.Fatal("merge accepted child states finalized under different input values")
	}
}

func TestMergeRejectsMalformedAndUnsupportedManifest(t *testing.T) {
	moduleDir, _ := testDirs(t)
	for _, raw := range []string{
		`{"v":4,"future":true}`,
		`{"v":1}`,
	} {
		state := State{
			Manifest: base64.RawURLEncoding.EncodeToString([]byte(raw)),
			Digest:   "supplied",
			OK:       true,
		}
		if _, err := ambientMerge(moduleDir, newObservation(state, "worker", "complete")); err == nil {
			t.Fatalf("Merge accepted %s", raw)
		}
	}
}

func TestManifestEncodingIsCanonical(t *testing.T) {
	got, err := encode(manifest{
		Version: manifestVersion,
		Env:     []envInput{{Name: "B", Digest: testEntryDigest}, {Name: "A", Digest: testEntryDigest}, {Name: "B", Digest: testEntryDigest}},
		Paths: []pathInput{
			{pathID: pathID{Kind: pathRel, Path: "z"}, Digest: testEntryDigest},
			{pathID: pathID{Kind: pathRel, Path: "z"}, Digest: testEntryDigest},
		},
		Unverifiable: []string{"z", "a", "z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantJSON := `{"v":4,"env":[{"n":"A","d":"00000000000000000000000000000000"},{"n":"B","d":"00000000000000000000000000000000"}],"paths":[{"k":"rel","p":"z","d":"00000000000000000000000000000000"}],"unverifiable":["a","z"]}`
	want := base64.RawURLEncoding.EncodeToString([]byte(wantJSON))
	if got != want {
		decoded, _ := base64.RawURLEncoding.DecodeString(got)
		t.Fatalf("encoding = %q (%s), want %q", got, decoded, want)
	}
}

func TestManifestDecoderRejectsUnknownAndTrailingData(t *testing.T) {
	moduleDir, _ := testDirs(t)
	for _, raw := range []string{
		`{"v":4,"future":true}`,
		`{"v":4} {"v":4}`,
		`{"v":4,"paths":[{"k":"rel","p":"tracked"}],"paths":[]}`,
		`{"V":3}`,
	} {
		encoded := base64.RawURLEncoding.EncodeToString([]byte(raw))
		if _, err := ambientCurrent(encoded, moduleDir); err == nil {
			t.Fatalf("Current accepted non-canonical manifest %s", raw)
		}
	}
}

func TestNonUTF8ObservedPathIsUnverifiable(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	for _, tc := range []struct {
		name       string
		log        []byte
		wantReason string
		wantPrefix string
	}{
		{
			name:       "open-rel-non-utf8",
			log:        []byte("open \xff\n"),
			wantReason: "non-UTF-8 runtime input path",
			wantPrefix: `open "\xff" in `,
		},
		{
			name:       "stat-abs-non-utf8",
			log:        []byte("stat /\xffbad\n"),
			wantReason: "non-UTF-8 runtime input path",
			wantPrefix: `stat "/\xffbad" in `,
		},
		{
			name:       "stat-abs-nul-framing",
			log:        []byte("stat /a\x00b\n"),
			wantReason: "unrepresentable runtime input path",
			wantPrefix: `stat "/a\x00b" in `,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := ambientFromTestLog(tc.log, moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
			if err != nil {
				t.Fatal(err)
			}
			// The refusal leads with its class — the state's reason is the
			// clause — and the observation's attribution names the observation
			// with the non-UTF-8 or framing-byte name quoted, so the attribution
			// stays valid UTF-8 (REQ-inputs-refusal-attribution).
			if !st.Unverifiable || st.Reason != tc.wantReason || !strings.HasPrefix(st.Attribution, tc.wantPrefix) {
				t.Fatalf("state = %+v, want reason=%q prefix=%q", st, tc.wantReason, tc.wantPrefix)
			}
			m, err := decode(st.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			if len(m.Paths) != 0 {
				t.Fatalf("manifest normalized invalid path into %+v", m.Paths)
			}
		})
	}
}

func FuzzMergeAlgebra(f *testing.F) {
	f.Add([]byte("a"), []byte("b"), []byte("c"))
	f.Add([]byte("same"), []byte("same"), []byte{})
	f.Add([]byte{1, 'm'}, []byte{2, 'u'}, []byte{3, 'b'})
	f.Add([]byte{3}, []byte{3}, []byte{0})
	f.Fuzz(func(t *testing.T, a, b, c []byte) {
		moduleDir := t.TempDir()
		manifestFor := func(value []byte) Observation {
			t.Helper()
			token := base64.RawURLEncoding.EncodeToString(value)
			// Bracket-binding unverifiable reasons ride the manifest like any
			// other reason: the low bits of the first input byte select the
			// moved-bracket observation-level class and the uncovered
			// per-identity class (REQ-inputs-value-binding).
			unverifiable := []string{"fuzz reason " + token}
			if len(value) > 0 && value[0]&1 != 0 {
				unverifiable = append(unverifiable, "observation bracket moved: fuzzroot"+token)
			}
			if len(value) > 0 && value[0]&2 != 0 {
				unverifiable = append(unverifiable, "runtime input not covered by observation bracket: fuzz/x"+token)
			}
			encoded, err := encode(manifest{
				Version:      manifestVersion,
				Env:          []envInput{{Name: "FUZZ_" + token, Digest: testEntryDigest}},
				Paths:        []pathInput{{pathID: pathID{Kind: pathRel, Path: "fuzz/x" + token}, Digest: testEntryDigest}},
				Unverifiable: unverifiable,
			})
			if err != nil {
				t.Fatal(err)
			}
			state, err := ambientCurrent(encoded, moduleDir)
			if err != nil {
				t.Fatal(err)
			}
			return newObservation(state, "worker-"+token, "complete")
		}
		reasons := func(o Observation) map[string]bool {
			t.Helper()
			m, err := decode(o.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			set := make(map[string]bool, len(m.Unverifiable))
			for _, reason := range m.Unverifiable {
				set[reason] = true
			}
			return set
		}
		merge := func(inputs ...Observation) Observation {
			t.Helper()
			st, err := ambientMerge(moduleDir, inputs...)
			if err != nil {
				t.Fatal(err)
			}
			// The merged union's unverifiable set contains every input's
			// reasons: merge never drops a binding reason
			// (REQ-inputs-merge, REQ-inputs-value-binding).
			got := reasons(st)
			for _, input := range inputs {
				for reason := range reasons(input) {
					if !got[reason] {
						t.Fatalf("merge dropped unverifiable reason %q", reason)
					}
				}
			}
			return st
		}
		ma, mb, mc := manifestFor(a), manifestFor(b), manifestFor(c)
		ab, ba := merge(ma, mb), merge(mb, ma)
		if !reflect.DeepEqual(ab, ba) {
			t.Fatalf("commutativity: %+v != %+v", ab, ba)
		}
		if aa := merge(ma, ma); !reflect.DeepEqual(aa, merge(ma)) {
			t.Fatalf("idempotence: %+v != %+v", aa, merge(ma))
		}
		left := merge(ab, mc)
		bc := merge(mb, mc)
		right := merge(ma, bc)
		if !reflect.DeepEqual(left, right) {
			t.Fatalf("associativity: %+v != %+v", left, right)
		}
		// A completed state without sealed construction provenance — the only
		// way one can lack bracket provenance, since the bracket-gated
		// constructor is the sole completed path — is refused, never merged
		// silently (REQ-inputs-completed-observation).
		if _, err := ambientMerge(moduleDir, Observation{State: ma.State}); err == nil {
			t.Fatal("merge accepted a completed state without construction provenance")
		}
	})
}

func FuzzRuntimeObservationAndPathInvariants(f *testing.F) {
	f.Add("KEY_A", "val1", "sub/data.txt", uint8(0))
	f.Add("KEY_B", "val2", "../outside.txt", uint8(1))
	f.Add("KEY_C", "", "a/../b/file.txt", uint8(2))
	f.Add("KEY_D", "v=1", "dir/child.txt", uint8(3))

	f.Fuzz(func(t *testing.T, rawKey, val, rawPath string, mode uint8) {
		key := "FUZZ_" + strings.Map(func(r rune) rune {
			if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
				return r
			}
			return '_'
		}, rawKey)
		if len(key) > 32 {
			key = key[:32]
		}
		cleanVal := strings.Map(func(r rune) rune {
			if r == 0 || r == '\n' || r == '\r' {
				return '_'
			}
			return r
		}, val)

		cleanRel := "child_" + strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				return r
			}
			return 'x'
		}, rawPath)
		if len(cleanRel) > 24 {
			cleanRel = cleanRel[:24]
		}

		modDir := t.TempDir()
		subDir := filepath.Join(modDir, "sub")
		realChildDir := filepath.Join(subDir, cleanRel)
		symlinkTargetDir := filepath.Join(modDir, "target_a", "target_b")
		if err := os.MkdirAll(realChildDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(symlinkTargetDir, 0o755); err != nil {
			t.Fatal(err)
		}
		linkName := "link_" + cleanRel
		if err := os.Symlink(symlinkTargetDir, filepath.Join(subDir, linkName)); err != nil {
			t.Fatal(err)
		}
		targetFile := filepath.Join(subDir, "data.txt")
		if err := os.WriteFile(targetFile, []byte(cleanVal), 0o644); err != nil {
			t.Fatal(err)
		}

		ambient := []string{key + "=" + cleanVal, "OTHER_VAR=constant"}

		// 1. Observable read set, path congruence, & coherence across FromTestLog, Current, Merge, Adopt
		// (REQ-inputs-observable-read-set, REQ-inputs-path-congruence, REQ-inputs-observation-coherence).
		bracket, err := CaptureBracket(context.Background(), modDir, []string{"."})
		if err != nil {
			t.Fatalf("CaptureBracket: %v", err)
		}
		// A parent traversal across a real directory component resolves congruently to data.txt.
		logText := "# test log\ngetenv " + key + "\nopen " + cleanRel + "/../data.txt\nstat data.txt\n"
		obs1, err := fromTestLog(context.Background(), []byte(logText), modDir, subDir, ambient, WithCompletedProcess("w1"), WithBracket(bracket))
		if err != nil {
			t.Fatalf("fromTestLog valid log: %v", err)
		}
		if !obs1.State.OK || obs1.State.Unverifiable {
			t.Fatalf("expected verifiable complete state for real-dir .. traversal, got %+v", obs1.State)
		}
		// A parent traversal across a symlink component (linkName/../data.txt) is refused as
		// ambiguous parent traversal because lexical .. cancellation diverges from kernel resolution
		// (REQ-inputs-path-congruence).
		symlinkTraversalLog := "# test log\nopen " + linkName + "/../data.txt\n"
		obsSymlink, err := fromTestLog(context.Background(), []byte(symlinkTraversalLog), modDir, subDir, ambient, WithCompletedProcess("w-sym"), WithBracket(bracket))
		if err != nil {
			t.Fatalf("fromTestLog symlink .. traversal: %v", err)
		}
		if !obsSymlink.State.OK || !obsSymlink.State.Unverifiable || !strings.Contains(obsSymlink.State.Reason, "ambiguous parent traversal") {
			t.Fatalf("expected ambiguous parent traversal refusal on symlink/.. path, got %+v", obsSymlink.State)
		}
		curState, err := Current(context.Background(), obs1.Manifest, modDir, ambient)
		if err != nil {
			t.Fatalf("Current on matching ambient: %v", err)
		}
		if curState != obs1.State {
			t.Fatalf("Current state %+v != fromTestLog state %+v", curState, obs1.State)
		}
		adopted, err := Adopt(obs1.Manifest, modDir, "w-adopted", ambient)
		if err != nil {
			t.Fatalf("Adopt on matching ambient: %v", err)
		}
		if adopted.State != obs1.State || adopted.Manifest != obs1.Manifest {
			t.Fatalf("Adopt mismatch: %+v vs %+v", adopted, obs1)
		}
		merged, err := Merge(modDir, ambient, obs1, adopted)
		if err != nil {
			t.Fatalf("Merge on coherent observations: %v", err)
		}
		if merged.State != obs1.State {
			t.Fatalf("idempotent Merge changed state: %+v vs %+v", merged.State, obs1.State)
		}

		// Mutating the observed env var shifts Current state while mutating an
		// unobserved var leaves it invariant.
		shiftedAmbient := []string{key + "=" + cleanVal + "_changed", "OTHER_VAR=constant"}
		shiftedState, err := Current(context.Background(), obs1.Manifest, modDir, shiftedAmbient)
		if err != nil {
			t.Fatalf("Current on shifted ambient: %v", err)
		}
		if shiftedState == obs1.State {
			t.Fatal("mutating observed env key did not shift state")
		}
		unobservedAmbient := []string{key + "=" + cleanVal, "OTHER_VAR=different"}
		unobservedState, err := Current(context.Background(), obs1.Manifest, modDir, unobservedAmbient)
		if err != nil || unobservedState != obs1.State {
			t.Fatalf("unobserved env change shifted state: %+v vs %+v (err=%v)", unobservedState, obs1.State, err)
		}

		// Unverifiable operations (chdir or escaping .. or unknown op) record unsuppressible
		// manifest unverifiability (REQ-inputs-observable-read-set, REQ-inputs-path-congruence).
		var badOp string
		switch mode % 3 {
		case 0:
			badOp = "chdir .\n"
		case 1:
			badOp = "open ../../outside.txt\n"
		default:
			badOp = "customop something\n"
		}
		unverObs, err := fromTestLog(context.Background(), []byte("# test log\n"+badOp), modDir, subDir, ambient, WithCompletedProcess("w2"), WithBracket(bracket))
		if err != nil {
			t.Fatalf("fromTestLog with unverifiable op: %v", err)
		}
		if !unverObs.State.OK || !unverObs.State.Unverifiable {
			t.Fatalf("expected completed unverifiable state for %q, got %+v", badOp, unverObs.State)
		}
		mergedUnver, err := Merge(modDir, ambient, obs1, unverObs)
		if err != nil {
			t.Fatalf("Merge with unverifiable observation: %v", err)
		}
		if !mergedUnver.State.Unverifiable {
			t.Fatalf("Merge suppressed unverifiability from %q: %+v", badOp, mergedUnver.State)
		}

		// 2. Observation disposition & ProducerFrame premises
		// (REQ-inputs-observation-disposition, REQ-inputs-producer-premises).
		inc, err := Incomplete(modDir, "w-inc", "truncated", ambient)
		if err != nil {
			t.Fatalf("Incomplete: %v", err)
		}
		if !inc.State.Unverifiable {
			t.Fatal("Incomplete observation did not report Unverifiable")
		}
		if _, err := CompletedState( Observation{State: obs1.State}); err == nil {
			t.Fatal("CompletedState accepted unsealed observation")
		}
		if st, err := CompletedState(obs1); err != nil || st != obs1.State {
			t.Fatalf("CompletedState on complete observation = (%v, %v)", st, err)
		}
		if HasOutcomeSupport(obs1.Manifest, "example.com/pkg.TestA") {
			t.Fatal("ambient-only observation claimed HasOutcomeSupport without outcome evidence")
		}

		frame := ProducerFrame{
			Root:   modDir,
			PkgDir: subDir,
		}
		receipt, err := frame.Completion("w1", ambient, "")
		if err != nil {
			t.Fatalf("ProducerFrame.Completion: %v", err)
		}
		if _, reason := frame.completionPremise(ProducerIngest{Identity: "w1", Env: ambient, Completion: receipt}); reason != "" {
			t.Fatalf("completionPremise on matching frame = %q", reason)
		}
		if _, reason := frame.completionPremise(ProducerIngest{Identity: "w1", Env: shiftedAmbient, Completion: receipt}); reason == "" {
			t.Fatal("completionPremise accepted receipt under shifted ambient")
		}
	})
}


// A classification refusal names the observation that produced its path
// (REQ-inputs-refusal-attribution): the operation, its quoted logged
// name, and the quoted working directory it resolved in — the process's
// own directory for every operation, the traversal for a name that
// reaches the root — after the clause and its separator, on the
// constructed state's attribution (the first refusal's); the manifest
// carries the clause, one entry per distinct clause, and the state's
// reason is the clause, so a consumer matching the class keeps
// matching; a stat of the root is no refusal
// (REQ-inputs-external-dir-existence).
func TestClassificationRefusalNamesItsObservation(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	depth := strings.Count(filepath.Clean(packageDir), string(filepath.Separator))
	traversal := strings.TrimSuffix(strings.Repeat("../", depth+1), "/")
	log := []byte("open /\n" + "open " + traversal + "\n" + "stat /\n")
	volatile := len(guard.VolatileOSRoots) > 0 // the volatile-OS arm is a Linux shape
	if volatile {
		log = append(log, "stat /proc/stat\n"...)
	}
	log = append(log, "chdir /\n"...) // last: the chdir moves the tracked directory
	state, err := FromTestLog(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	pkg := strconv.Quote(packageDir)
	want := []string{"external directory input: /", "working-directory change"}
	if volatile {
		want = append(want, "volatile OS input: /proc/stat")
	}
	got := append([]string(nil), m.Unverifiable...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unverifiable reasons\n got %q\nwant %q", got, want)
	}
	if !state.Unverifiable || state.Reason != "external directory input: /" {
		t.Fatalf("the state's reason is not the clause: %q", state.Reason)
	}
	// The first refusal in log order names its observation; the
	// traversal's own attribution names the traversal (pinned below).
	if state.Attribution != `open "/" in `+pkg {
		t.Fatalf("the state's attribution is not the first refusal's observation: %q", state.Attribution)
	}
	traversed, err := FromTestLog([]byte("open "+traversal+"\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if traversed.Attribution != `open `+strconv.Quote(traversal)+` in `+pkg {
		t.Fatalf("the traversal's attribution = %q", traversed.Attribution)
	}
	rootBound := false
	for _, id := range m.Paths {
		if id.Path == "/" {
			rootBound = true
		}
	}
	if !rootBound {
		t.Fatalf("the stat of the root bound no existence identity: %+v", m.Paths)
	}
	// No refusal, no attribution: an in-tree open records an identity
	// and adds no reason.
	state, err = FromTestLog([]byte("open fixture.txt\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := decode(state.Manifest); len(m.Unverifiable) != 0 {
		t.Fatalf("an admitted read carried a reason: %q", m.Unverifiable)
	}
	// A working directory the observation refused (non-UTF-8) still
	// attributes representably: the state is unverifiable, never an
	// error (REQ-inputs-observation-disposition).
	state, err = FromTestLog(append(append([]byte("chdir /tmp/"), 0xff), []byte("\nopen ../\n")...), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("a refused working directory made the observation an error: %v", err)
	}
	if !state.Unverifiable {
		t.Fatal("a refused working directory left the observation verifiable")
	}
	m, err = decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	// The state names the sorted manifest's first clause — the open
	// under the refused directory — and its attribution quotes that
	// directory representably.
	if !strings.Contains(state.Attribution, `open "../" in "/tmp/\xff"`) {
		t.Fatalf("the refused directory was not quoted into the attribution: %q", state.Attribution)
	}
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, attributionSeparator) {
			t.Fatalf("an attribution entered the manifest: %q", reason)
		}
	}
}

// The attribution is outside the inputs' identity
// (REQ-inputs-refusal-attribution): one testlog measured from two
// checkouts yields one manifest, one digest, and one reason while the
// attributions name each checkout's own directory; a state derived from
// the recorded manifest reproduces the recorded state whole (the
// attribution lives on the observation, outside the state); a merge and
// the identity conversions carry the attribution of the reason they
// name. The attribution attributes the reason the state names — the
// first clause of the sorted manifest, not the first refusal in log
// order — and a merge whose reason is one contributor's carries that
// contributor's.
func TestAttributionIsOutsideTheInputsIdentity(t *testing.T) {
	log := []byte("open /\nstat /\n")
	var states [2]Observation
	var portables [2]string
	for i := range states {
		moduleDir, packageDir := testDirs(t)
		state, err := FromTestLog(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(state.Attribution, ` in `+strconv.Quote(packageDir)) {
			t.Fatalf("checkout %d: attribution %q does not name its own directory", i, state.Attribution)
		}
		states[i] = state
		derived, err := Current(context.Background(), state.Manifest, moduleDir, nil)
		if err != nil {
			t.Fatal(err)
		}
		if derived != state.State {
			t.Fatalf("checkout %d: the derived state = %+v, want the recorded state whole", i, derived)
		}
		merged, err := Merge(moduleDir, nil, state, state)
		if err != nil {
			t.Fatal(err)
		}
		if merged.Attribution != state.Attribution || merged.Reason != state.Reason {
			t.Fatalf("checkout %d: the merge carried %q / %q", i, merged.Attribution, merged.Reason)
		}
		absolute, err := Absolute(state, moduleDir, nil)
		if err != nil {
			t.Fatal(err)
		}
		relative, err := Relative(absolute, moduleDir, nil)
		if err != nil {
			t.Fatal(err)
		}
		// A conversion converts the directory the attribution names as
		// it converts the identities: module-relative in the portable
		// form, the process's absolute directory again in the absolute
		// form, the operation and name untouched.
		relPkg, err := filepath.Rel(moduleDir, packageDir)
		if err != nil {
			t.Fatal(err)
		}
		portable := strings.TrimSuffix(state.Attribution, strconv.Quote(packageDir)) + strconv.Quote(filepath.ToSlash(relPkg))
		if absolute.Attribution != state.Attribution || relative.Attribution != portable {
			t.Fatalf("checkout %d: the conversions carried %q / %q, want %q / %q", i, absolute.Attribution, relative.Attribution, state.Attribution, portable)
		}
		if back, err := Absolute(relative, moduleDir, nil); err != nil || back.Attribution != state.Attribution {
			t.Fatalf("checkout %d: the absolute form of the portable attribution = %q, %v", i, back.Attribution, err)
		}
		portables[i] = relative.Attribution
		// A directory outside the module keeps its own spelling in
		// both forms: a refusal attributed after a traversal chdir
		// names the directory it happened in.
		left, err := FromTestLog([]byte("chdir /usr\nopen /\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
		if err != nil {
			t.Fatal(err)
		}
		if left.Attribution != `open "/" in "/usr"` {
			t.Fatalf("checkout %d: the traversal's attribution = %q", i, left.Attribution)
		}
		if outside, err := Relative(left, moduleDir, nil); err != nil || outside.Attribution != left.Attribution {
			t.Fatalf("checkout %d: the portable form moved an outside directory: %q, %v", i, outside.Attribution, err)
		}
	}
	// The portable form is the same in every checkout.
	if portables[0] != portables[1] {
		t.Fatalf("the portable attributions differ across checkouts: %q / %q", portables[0], portables[1])
	}
	// Two clauses, log order against sorted order: the state names the
	// sorted manifest's first clause and the attribution is that clause's.
	moduleDir, packageDir := testDirs(t)
	ordered, err := FromTestLog([]byte("open /usr\nopen /\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if ordered.Reason != "external directory input: /" || ordered.Attribution != `open "/" in `+strconv.Quote(packageDir) {
		t.Fatalf("reason %q attributed %q, want the sorted first clause and its own attribution", ordered.Reason, ordered.Attribution)
	}
	// A reason with no attributed refusal carries none, whatever other
	// clause the manifest attributes: the vanished-component traversal
	// sorts first and is no classification refusal.
	unattributed, err := FromTestLog([]byte("open gone/../fixture.txt\nopen /\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(unattributed.Reason, "ambiguous parent traversal") || unattributed.Attribution != "" {
		t.Fatalf("reason %q attributed %q, want the traversal's reason with no attribution", unattributed.Reason, unattributed.Attribution)
	}
	// A merge names the union's first clause and carries the attribution
	// of the contributor whose reason it is, whatever the caller's order.
	usr, err := FromTestLog([]byte("open /usr\n"), moduleDir, packageDir, nil, WithCompletedProcess("usr"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	root, err := FromTestLog([]byte("open /\n"), moduleDir, packageDir, nil, WithCompletedProcess("root"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := Merge(moduleDir, nil, usr, root)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Reason != root.Reason || merged.Attribution != root.Attribution {
		t.Fatalf("merge = %q attributed %q, want the root contributor's", merged.Reason, merged.Attribution)
	}
	if states[0].Manifest != states[1].Manifest || states[0].Digest != states[1].Digest || states[0].Reason != states[1].Reason {
		t.Fatalf("two checkouts' identities differ:\n%+v\n%+v", states[0].State, states[1].State)
	}
	if states[0].Attribution == states[1].Attribution {
		t.Fatalf("two checkouts' attributions agree: %q", states[0].Attribution)
	}
}

// RefusalClause is the split a consumer keys on: the attribution is the
// one well-formed suffix, so a separator inside a quoted name or
// directory, or inside the refused path of an attributed reason, never
// cuts the clause; a reason with no attribution is its own clause, the
// text channel's one residual (an unattributed path ending in the
// attribution's shape) recorded (REQ-inputs-refusal-attribution).
func TestRefusalClauseSurvivesSeparatorsInNames(t *testing.T) {
	sep := attributionSeparator
	cases := []struct{ reason, clause string }{
		{"external directory input: /" + sep + `open "/" in "/pkg"`, "external directory input: /"},
		{"volatile OS input: /proc/a" + sep + "b" + sep + `stat "/proc/a` + sep + `b" in "/pkg"`, "volatile OS input: /proc/a" + sep + "b"},
		{"external directory input: /" + sep + `open "../" in "/home/me/src/Project` + sep + `old/pkg"`, "external directory input: /"},
		{"external directory input: /x" + sep + `open "a` + sep + `open \"b\" in \"c\"" in "/pkg"`, "external directory input: /x"},
		{"external directory input: /mod/escape" + sep + `recorded path "escape" resolves to "/tmp/out` + sep + `side" outside the tree`, "external directory input: /mod/escape"},
		// A refused path carrying a whole attribution-shaped segment
		// followed by more path: the fake does not run to the end.
		{"external directory input: /x" + sep + `open "a" in "b"/c` + sep + `open "/x` + sep + `open \"a\" in \"b\"/c" in "/pkg"`, "external directory input: /x" + sep + `open "a" in "b"/c`},
		// A refused path carrying an unquoted operation word after a
		// separator: an operation without its quoted name is no suffix.
		{"volatile OS input: /proc/a" + sep + "open b" + sep + `stat "/proc/a` + sep + `open b" in "/pkg"`, "volatile OS input: /proc/a" + sep + "open b"},
		{"unhashable runtime input: /x" + sep + "y", "unhashable runtime input: /x" + sep + "y"},
		{"working-directory change", "working-directory change"},
		// The one residual of the text channel, recorded: an UNATTRIBUTED
		// reason whose refused path itself ends in the attribution's
		// shape — a path deliberately named with a quote — is split.
		{"unhashable runtime input: /x" + sep + `open "a" in "b"`, "unhashable runtime input: /x"},
	}
	// The moved-bracket reason: its attribution is the bracketed member
	// list after " [", split from the first bracket whose suffix parses;
	// a bracketed segment that is no member list (a label-less one, an
	// unterminated one, one on another clause) is the reason's own.
	cases = append(cases,
		struct{ reason, clause string }{"observation bracket moved: fixtures [added: a.txt, b.txt]", "observation bracket moved: fixtures"},
		struct{ reason, clause string }{"observation bracket moved: fixtures [added: a.txt; removed: b.txt]", "observation bracket moved: fixtures"},
		struct{ reason, clause string }{"observation bracket moved: fixtures [recently touched: a.txt (2026-10-07T00:00:00Z)]", "observation bracket moved: fixtures"},
		struct{ reason, clause string }{"observation bracket moved: fixtures [data]", "observation bracket moved: fixtures [data]"},
		struct{ reason, clause string }{"observation bracket moved: fixtures [added: a.txt", "observation bracket moved: fixtures [added: a.txt"},
		struct{ reason, clause string }{"observation bracket moved", "observation bracket moved"},
		struct{ reason, clause string }{"external directory input: /x [added: y]", "external directory input: /x [added: y]"},
		// The recorded residual: a root whose own name carries the form
		// garbles the clause from that bracket on, the same on both
		// sides of a consumer's match.
		struct{ reason, clause string }{"observation bracket moved: fix [added: x] [removed: y]", "observation bracket moved: fix"},
		// A member carrying the list's own framing travels quoted, so
		// the list stays splittable.
		struct{ reason, clause string }{`observation bracket moved: fixtures [added: "a; b.txt", "c]d.txt"]`, "observation bracket moved: fixtures"},
		// A member carrying a bare quote travels quoted too: bare, it
		// would pair with a later quoted member's opening quote and
		// swallow that member's separator.
		struct{ reason, clause string }{`observation bracket moved: data [added: "a\"b", "x; y"; removed: z]`, "observation bracket moved: data"},
	)
	for _, name := range []string{"a; b.txt", "c]d.txt", "[e.txt", `a"b`} {
		if got := memberListName(name); got != strconv.Quote(name) {
			t.Fatalf("memberListName(%q) = %q, want it quoted: it carries the member list's framing", name, got)
		}
	}
	if got := memberListName("plain.txt"); got != "plain.txt" {
		t.Fatalf("memberListName(plain.txt) = %q", got)
	}
	// The walk's clauses quote for representability alone: a bracketed
	// or quoted name is an ordinary member name there.
	for _, name := range []string{"data/a[1]", `data/a"b`, "data/a; b"} {
		if got := representableReasonName(name); got != name {
			t.Fatalf("representableReasonName(%q) = %q, want it bare: the list's framing rule is the list's alone", name, got)
		}
	}
	if got := representableReasonName("a\x00b"); got != strconv.Quote("a\x00b") {
		t.Fatalf("representableReasonName(a\\x00b) = %q, want it quoted", got)
	}
	for _, c := range cases {
		if got := RefusalClause(c.reason); got != c.clause {
			t.Errorf("RefusalClause(%q) = %q, want %q", c.reason, got, c.clause)
		}
	}
	if got := RefusalAttribution("observation bracket moved: fixtures [added: a.txt; removed: b.txt]"); got != "added: a.txt; removed: b.txt" {
		t.Fatalf("the moved-bracket attribution = %q, want the member list without its brackets", got)
	}
	// The builder's attribution, pasted after a clause, round-trips
	// through the split for every operation of the one vocabulary; an
	// operation outside it attributes nothing (an empty field), so a
	// consumer's clause match never meets an attribution the split
	// cannot parse.
	for _, op := range attributionOps {
		attribution := operationAttribution(op, "/proc/a"+sep+"b", "/p"+sep+"kg")
		reason := "volatile OS input: /proc/a" + sep + "b" + sep + attribution
		if got := RefusalClause(reason); got != "volatile OS input: /proc/a"+sep+"b" {
			t.Fatalf("the %s attribution does not round-trip: %q -> %q", op, reason, got)
		}
		if got := RefusalAttribution(reason); got != attribution {
			t.Fatalf("the %s attribution's complement = %q, want %q", op, got, attribution)
		}
	}
	// The resolved-target producer's shape round-trips the same way.
	resolved := "external runtime input target: /w/pkg/l" + sep + "ink" + sep + resolvedTargetAttribution("pkg/l"+sep+"ink", "/srv"+sep+"x")
	if RefusalClause(resolved) != "external runtime input target: /w/pkg/l"+sep+"ink" || RefusalAttribution(resolved) != resolvedTargetAttribution("pkg/l"+sep+"ink", "/srv"+sep+"x") {
		t.Fatalf("the resolved-target attribution does not round-trip: %q -> %q / %q", resolved, RefusalClause(resolved), RefusalAttribution(resolved))
	}
	if got := operationAttribution("rename", "/", "/pkg"); got != "" {
		t.Fatalf("an operation outside the vocabulary was attributed: %q", got)
	}
}

// RefusalAttribution is RefusalClause's complement over the one split:
// the well-formed suffix without its separator, "" where the reason
// carries none (a malformed tail is no attribution), and the fake
// tail on the text channel's one residual — an unattributed reason
// whose refused path ends in the attribution's shape — exactly as its
// clause is the truncated one (REQ-inputs-refusal-attribution).
func TestRefusalAttributionIsTheClauseSplitsComplement(t *testing.T) {
	sep := attributionSeparator
	for _, c := range []struct{ reason, attribution string }{
		{`external directory input: /srv` + sep + `open "/srv" in "/w/pkg"`, `open "/srv" in "/w/pkg"`},
		{`external runtime input target: /w/pkg/link` + sep + `recorded path "pkg/link" resolves to "/srv/x" outside the tree`, `recorded path "pkg/link" resolves to "/srv/x" outside the tree`},
		{`volatile OS input: /proc/a` + sep + `b`, ""},
		{`external directory input: /srv`, ""},
		{`external directory input: /a` + sep + `b` + sep + `stat "/a" in "/w"`, `stat "/a" in "/w"`},
		{`unhashable runtime input: /x` + sep + `open "a" in "b"`, `open "a" in "b"`},
	} {
		clause, attribution := RefusalClause(c.reason), RefusalAttribution(c.reason)
		if attribution != c.attribution {
			t.Errorf("RefusalAttribution(%q) = %q, want %q", c.reason, attribution, c.attribution)
		}
		if attribution == "" && clause != c.reason {
			t.Errorf("an unattributed reason %q split its clause to %q", c.reason, clause)
		}
		if attribution != "" && clause+sep+attribution != c.reason {
			t.Errorf("the split of %q does not rejoin: clause %q, attribution %q", c.reason, clause, attribution)
		}
	}
}

// The directory conversion rewrites exactly the operation form and
// passes everything else through — a resolved-target attribution, an
// operation form with trailing text, a string no grammar parses —
// never rewriting a value into a form it was not
// (REQ-inputs-refusal-attribution).
func TestConvertAttributionDirRewritesOnlyTheOperationForm(t *testing.T) {
	upper := func(dir string) string { return strings.ToUpper(dir) }
	for _, c := range []struct{ in, want string }{
		{`open "/x" in "/w/pkg"`, `open "/x" in "/W/PKG"`},
		{`stat "a b" in "rel/dir"`, `stat "a b" in "REL/DIR"`},
		{`open "/x" in "/w/pkg" trailing`, `open "/x" in "/w/pkg" trailing`},
		{`recorded path "pkg/link" resolves to "/srv/x" outside the tree`, `recorded path "pkg/link" resolves to "/srv/x" outside the tree`},
		{`rename "/x" in "/w"`, `rename "/x" in "/w"`},
		{`open /x in "/w"`, `open /x in "/w"`},
		{"", ""},
	} {
		if got := convertAttributionDir(c.in, upper); got != c.want {
			t.Errorf("convertAttributionDir(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A refused path inside the module is spelled module-relative in its
// clause: one tree in two checkouts, each carrying a symbolic link to
// the same external directory and to the same external file, yields one
// manifest, one digest and one reason — the clauses name `escape` and
// `escapefile`, never the checkout's absolute path — while the
// attribution names the recorded path and its target
// (REQ-inputs-refusal-attribution's spelling rule, the identity clause's
// "keyed by what was measured, never by the checkout root").
func TestInModuleRefusedPathSpellsModuleRelative(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var states [2]Observation
	for i := range states {
		moduleDir, packageDir := testDirs(t)
		if err := os.Symlink(outside, filepath.Join(moduleDir, "escape")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, "f.txt"), filepath.Join(moduleDir, "escapefile")); err != nil {
			t.Fatal(err)
		}
		state, err := FromTestLog([]byte("open ../escape\nopen ../escapefile\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "escape", "escapefile")))
		if err != nil {
			t.Fatal(err)
		}
		if !state.Unverifiable {
			t.Fatalf("checkout %d: the escaping links were admitted: %+v", i, state.State)
		}
		for _, abs := range []string{moduleDir, packageDir} {
			if strings.Contains(state.Reason, abs) || strings.Contains(state.Manifest, abs) {
				t.Fatalf("checkout %d: the identity names the checkout %q: reason %q", i, abs, state.Reason)
			}
		}
		// The bracket's capture reaches the hashing pass first and
		// wraps its refusal; the refused path is spelled relative there
		// and the attribution names the recorded path and its target.
		if clause := RefusalClause(state.Reason); !strings.HasSuffix(clause, "external directory input: escape") {
			t.Fatalf("checkout %d: the clause = %q, want the module-relative spelling", i, clause)
		}
		if attribution := RefusalAttribution(state.Reason); attribution != `recorded path "escape" resolves to `+strconv.Quote(outside)+` outside the tree` {
			t.Fatalf("checkout %d: the attribution = %q, want the recorded path and its target", i, attribution)
		}
		states[i] = state
	}
	if states[0].Manifest != states[1].Manifest || states[0].Digest != states[1].Digest || states[0].Reason != states[1].Reason {
		t.Fatalf("two checkouts' identities differ:\n%+v\n%+v", states[0].State, states[1].State)
	}
	// No manifest clause spells the checkout: every refused in-module
	// path is relative there too.
	m, err := decode(states[0].Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Unverifiable) == 0 {
		t.Fatal("the manifest carries no refusal")
	}
	for _, reason := range m.Unverifiable {
		if strings.Contains(RefusalClause(reason), "/") {
			t.Fatalf("a manifest clause spells an in-module path absolute: %q", reason)
		}
	}
	// The file link alone, under a bracket covering it: the target
	// refusal spells it relative as well.
	moduleDir, packageDir := testDirs(t)
	if err := os.Symlink(filepath.Join(outside, "f.txt"), filepath.Join(moduleDir, "escapefile")); err != nil {
		t.Fatal(err)
	}
	file, err := FromTestLog([]byte("open ../escapefile\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "escapefile")))
	if err != nil {
		t.Fatal(err)
	}
	if clause := RefusalClause(file.Reason); !strings.HasSuffix(clause, "external runtime input target: escapefile") {
		t.Fatalf("the file link's clause = %q, want the module-relative spelling", clause)
	}
}

// A module reached through a symlinked prefix spells an escaping link
// relative all the same: the coverage walk resolves the module root
// before following the chain, and the clause names the link as the
// tree spells it, never as the resolved host path.
func TestEscapingLinkSpellsRelativeUnderASymlinkedPrefix(t *testing.T) {
	real := filepath.Join(t.TempDir(), "real")
	if err := os.MkdirAll(filepath.Join(real, "mod", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	view := filepath.Join(t.TempDir(), "view")
	if err := os.Symlink(real, view); err != nil {
		t.Fatal(err)
	}
	moduleDir := filepath.Join(view, "mod")
	packageDir := filepath.Join(moduleDir, "pkg")
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(moduleDir, "escape")); err != nil {
		t.Fatal(err)
	}
	// The bracket root is the link itself: its resolved position holds
	// the input, the link hop lies outside it, and the coverage refusal
	// names the hop.
	state, err := FromTestLog([]byte("open ../escape\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "escape")))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, "(symlink outside every bracket root: escape)") {
			found = true
		}
		if strings.Contains(reason, real) || strings.Contains(reason, view) {
			t.Fatalf("a clause spells the host path: %q", reason)
		}
	}
	if !found {
		t.Fatalf("the escaping link is not named relative: %v", m.Unverifiable)
	}
}

// A moved bracket's member list is its attribution: the manifest
// carries the clause alone (a member's modification time never enters
// the identity) and the observation's attribution field carries the
// list, as a classification refusal's does
// (REQ-inputs-refusal-attribution).
func TestMovedBracketMemberListIsTheAttribution(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.MkdirAll(filepath.Join(moduleDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir, "data")
	// Two members join: a plain name, and one carrying the list's
	// separator, which the writer quotes so the list stays splittable.
	for _, name := range []string{"b.txt", "x; y.txt"} {
		if err := os.WriteFile(filepath.Join(moduleDir, "data", name), []byte("b"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	state, err := FromTestLog([]byte("open ../data/a.txt\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if state.Reason != "observation bracket moved: data" || state.Attribution != `added: b.txt, "x; y.txt"` {
		t.Fatalf("reason %q attributed %q, want the clause alone and the member list", state.Reason, state.Attribution)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, " [") {
			t.Fatalf("a member list entered the manifest: %q", reason)
		}
	}
}

// TestMovedBracketRootSpelledLikeAMemberList pins the root's quoting
// (REQ-inputs-refusal-attribution): a bracket root whose own name
// carries the member list's framing travels quoted, as a member does,
// so the clause keeps the root whole — the split consumes the quoted
// root and reads the list after it — and a sibling root's clause
// differs; the whole-reason forms that collided unquoted (`fix [added:
// x` and `fix [added: x] y` before a member list) split at the list.
func TestMovedBracketRootSpelledLikeAMemberList(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	for _, root := range []string{"fix", "fix [added: x]", "fix [added: x", "fix [added: x] y", `a"b`, "a]b", "a; b", `"x"`} {
		if err := os.MkdirAll(filepath.Join(moduleDir, root), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(moduleDir, root, "a.txt"), []byte("a"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{"fix [added: x]", "fix [added: x", "fix [added: x] y", `a"b`, "a]b", "a; b", `"x"`} {
		bracket := testBracket(t, moduleDir, root)
		if err := os.WriteFile(filepath.Join(moduleDir, root, "b.txt"), []byte("b"), 0o644); err != nil {
			t.Fatal(err)
		}
		state, err := FromTestLog([]byte("open ../"+root+"/a.txt\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
		if err != nil {
			t.Fatal(err)
		}
		want := "observation bracket moved: " + strconv.Quote(root)
		if state.Reason != want || state.Attribution != "added: b.txt" {
			t.Fatalf("root %q: reason %q attributed %q, want %q and the member list", root, state.Reason, state.Attribution, want)
		}
		clause, attribution, ok := splitBracketAttribution(state.Reason + " [" + state.Attribution + "]")
		if !ok || clause != want || attribution != "added: b.txt" {
			t.Fatalf("root %q: the whole reason split to %q / %q (%v), want the quoted root whole", root, clause, attribution, ok)
		}
		if clause == "observation bracket moved: fix" {
			t.Fatalf("root %q collided with the sibling root fix", root)
		}
		// The quoted root's list must be a well-formed attribution:
		// an unterminated or unlabelled list after the root refuses
		// the split whole, never yielding a garbage attribution.
		for _, malformed := range []string{want + " [added: b.txt", want + " [junk]", want + " []"} {
			if c, a, ok := splitBracketAttribution(malformed); ok || c != malformed || a != "" {
				t.Fatalf("root %q: the malformed %q split to %q / %q (%v), want refused whole", root, malformed, c, a, ok)
			}
		}
	}
	// A reason composed before roots were quoted — a bare root beginning
	// with a quote the quoted-root arm cannot parse — splits by the bare
	// scan, the pre-quoting answer; one whose bare root BEGINS with a
	// valid quoted literal followed by more name is refused whole (the
	// recorded choice: falling through would let a quoted root followed
	// by a malformed list mis-split).
	if c, a, ok := splitBracketAttribution(`observation bracket moved: "a [added: b]`); !ok || c != `observation bracket moved: "a` || a != "added: b" {
		t.Fatalf("a pre-quoting reason with a stray quote split to %q / %q (%v), want the bare scan's answer", c, a, ok)
	}
	if legacy := `observation bracket moved: "x" y [added: b]`; true {
		if c, a, ok := splitBracketAttribution(legacy); ok || c != legacy || a != "" {
			t.Fatalf("a pre-quoting reason whose root begins with a quoted literal split to %q / %q (%v), want refused whole", c, a, ok)
		}
	}
	// The exported spelling is the composer's: a plain root bare, a
	// framing-bearing one quoted — a consumer's re-key reads it.
	if MovedBracketClause("fix") != "observation bracket moved: fix" || MovedBracketClause("fix [added: x]") != `observation bracket moved: "fix [added: x]"` {
		t.Fatalf("MovedBracketClause spells %q / %q", MovedBracketClause("fix"), MovedBracketClause("fix [added: x]"))
	}
	// The re-key is idempotent: a pre-quoting bare key of a
	// framing-bearing root re-keys to the quoted spelling; a canonical
	// quoted key and a plain root's key come back unchanged, however
	// often applied; a foreign clause is untouched; the recorded
	// ambiguity — a bare root that is itself a quoted literal of a
	// framing-bearing name — reads as canonical.
	for _, tc := range []struct{ stored, want string }{
		{"observation bracket moved: fix [added: x]", `observation bracket moved: "fix [added: x]"`},
		{`observation bracket moved: "fix [added: x]"`, `observation bracket moved: "fix [added: x]"`},
		{"observation bracket moved: fix", "observation bracket moved: fix"},
		{"observation bracket moved: a; b", `observation bracket moved: "a; b"`},
		{"observation bracket moved", "observation bracket moved"},
		// A stored bare root literally named with quotes around a plain
		// name is not canonical (the spelling would not quote `fix`), so
		// it re-keys to the quoted spelling of its own quoted name.
		{`observation bracket moved: "fix"`, `observation bracket moved: "\"fix\""`},
		{"open /etc/passwd: outside the module", "open /etc/passwd: outside the module"},
		// The recorded ambiguity: a legacy bare root literally named
		// `"fix [added: x]"` is the same text as the canonical key of
		// `fix [added: x]`, so it reads as canonical and is not re-keyed.
		{`observation bracket moved: "fix [added: x]"`, `observation bracket moved: "fix [added: x]"`},
	} {
		got := CanonicalMovedBracketClause(tc.stored)
		if got != tc.want || CanonicalMovedBracketClause(got) != got {
			t.Fatalf("CanonicalMovedBracketClause(%q) = %q (again %q), want %q and a fixed point", tc.stored, got, CanonicalMovedBracketClause(got), tc.want)
		}
	}
	// The sibling root's own clause, unquoted: a plain name travels bare.
	bracket := testBracket(t, moduleDir, "fix")
	if err := os.WriteFile(filepath.Join(moduleDir, "fix", "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := FromTestLog([]byte("open ../fix/a.txt\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if state.Reason != "observation bracket moved: fix" {
		t.Fatalf("the plain root's clause %q, want it bare", state.Reason)
	}
}

// An unhashable member inside the module is spelled module-relative in
// its clause — a FIFO the bracket's walk meets at capture, and a member
// that became a FIFO or unreadable after the record was made, met by
// the hashing pass at revalidation — so one tree in two checkouts
// yields one manifest, one digest and one reason
// (REQ-inputs-refusal-attribution's spelling rule over the hashing
// pass's every refusal).
func TestUnhashableInModuleMembersSpellModuleRelative(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file")
	}
	plant := func(t *testing.T) (moduleDir, packageDir, data string) {
		moduleDir, packageDir = testDirs(t)
		data = filepath.Join(moduleDir, "data")
		if err := os.MkdirAll(data, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"pipe", "secret"} {
			if err := os.WriteFile(filepath.Join(data, name), []byte(name), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return moduleDir, packageDir, data
	}
	same := func(t *testing.T, arm string, states [2]State) {
		t.Helper()
		if states[0].Manifest != states[1].Manifest || states[0].Digest != states[1].Digest || states[0].Reason != states[1].Reason {
			t.Fatalf("%s: two checkouts' identities differ:\n%+v\n%+v", arm, states[0], states[1])
		}
	}

	// The bracket's walk meets the FIFO at capture: the refusal, wrapped
	// as the bracket's, names the member under the root's spelling.
	var walked [2]State
	for i := range walked {
		moduleDir, packageDir, data := plant(t)
		if err := os.Remove(filepath.Join(data, "pipe")); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(data, "pipe"), 0o644); err != nil {
			t.Fatal(err)
		}
		state, err := FromTestLog([]byte("open ../data\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
		if err != nil {
			t.Fatal(err)
		}
		if got := RefusalClause(state.Reason); got != "observation bracket unverifiable: unhashable runtime directory entry: data/pipe" {
			t.Fatalf("checkout %d: the walked clause = %q", i, got)
		}
		if strings.Contains(state.Manifest, moduleDir) {
			t.Fatalf("checkout %d: the manifest names the checkout", i)
		}
		walked[i] = state.State
	}
	same(t, "walked", walked)

	// A member that became unhashable after the record: the hashing
	// pass meets it at revalidation, unwrapped, and spells it relative.
	for _, arm := range []struct {
		name   string
		mutate func(t *testing.T, data string)
		clause string
	}{
		{"pipe", func(t *testing.T, data string) {
			if err := os.Remove(filepath.Join(data, "pipe")); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(filepath.Join(data, "pipe"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "unhashable runtime input: data/pipe"},
		{"secret", func(t *testing.T, data string) {
			if err := os.Chmod(filepath.Join(data, "secret"), 0o000); err != nil {
				t.Fatal(err)
			}
		}, "unhashable runtime input: data/secret"},
	} {
		var derived [2]State
		for i := range derived {
			moduleDir, packageDir, data := plant(t)
			recorded, err := FromTestLog([]byte("open ../data/"+arm.name+"\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
			if err != nil {
				t.Fatal(err)
			}
			if recorded.Unverifiable {
				t.Fatalf("%s, checkout %d: the record refused before the mutation: %q", arm.name, i, recorded.Reason)
			}
			arm.mutate(t, data)
			current, err := Current(context.Background(), recorded.Manifest, moduleDir, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !current.Unverifiable || RefusalClause(current.Reason) != arm.clause {
				t.Fatalf("%s, checkout %d: the revalidated state = %+v, want the clause %q", arm.name, i, current, arm.clause)
			}
			if strings.Contains(current.Reason, moduleDir) {
				t.Fatalf("%s, checkout %d: the reason names the checkout", arm.name, i)
			}
			derived[i] = current
		}
		same(t, arm.name, derived)
	}
}

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

	state, err := FromTestLog(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithExcludedPaths(".git"), WithBracket(testBracket(t, moduleDir)))
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
	after, err := ambientCurrent(state.Manifest, moduleDir)
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
	state, err := FromTestLog([]byte("open "+rel+"\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithExcludedPaths(".git"), WithBracket(testBracket(t, moduleDir)))
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
	state, err := FromTestLog([]byte("open "+relRoot+"\nopen "+relSpec+"\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithExcludedPaths("."), WithBracket(testBracket(t, moduleDir)))
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
	state, err := FromTestLog(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithExcludedPaths(outside), WithBracket(testBracket(t, moduleDir)))
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
	state, err := FromTestLog(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithExcludedPaths("deep/scratch"), WithBracket(testBracket(t, moduleDir)))
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
	if _, err := FromTestLog([]byte("open x\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithExcludedPaths(""), WithBracket(testBracket(t, moduleDir))); err == nil {
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

	state, err := FromTestLog(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"),
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
	state, err = FromTestLog(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
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

	state, err := FromTestLog(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"),
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
	state, err = FromTestLog(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
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

func eligibilityFile(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// Positive cases name physical files even when the host's temp directory is an
// alias (for example /var on Darwin). Alias refusal has its own negative cases.
func eligibilityModule(t *testing.T) (string, string) {
	t.Helper()
	root, pkg := producerModule(t)
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err = filepath.EvalSymlinks(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return root, pkg
}

func eligibilityEnv(pkg string) []string {
	env := producerEnv(pkg)
	for k, v := range map[string]string{"GOENV": "off", "GOFLAGS": "", "GOWORK": "off", "GOTOOLCHAIN": "local"} {
		env = gotool.SetEnv(env, k, v)
	}
	return env
}

func eligibilityObserve(t *testing.T, frame ProducerFrame, log string, in ProducerIngest) Observation {
	t.Helper()
	var err error
	in.Completion, err = frame.Completion(in.Identity, in.Env, "")
	if err != nil {
		t.Fatal(err)
	}
	obs, why, err := frame.ObserveInputs(t.Context(), log, in)
	if err != nil || why != "" || !obs.OK || obs.Unverifiable {
		t.Fatalf("identity-only producer: %+v %q %v", obs, why, err)
	}
	m, err := decode(obs.Manifest)
	if err != nil || m.Outcome != "" || len(m.Subjects) != 0 {
		t.Fatalf("identity-only observation granted outcomes: %+v %v", m, err)
	}
	return obs
}

// The query and the public producer's identity-only guard construction agree.
// These synthetic logs exercise classification, not operation-outcome authority.
func TestFileInputEligibilityMatchesProducer(t *testing.T) {
	root, pkg := eligibilityModule(t)
	outside := t.TempDir()
	build, modules := filepath.Join(outside, "build"), filepath.Join(outside, "modules")
	for _, tc := range []struct {
		name, path, cache, modcache string
		want                        FileInputKind
	}{
		{"ordinary", filepath.Join(outside, "ordinary"), build, modules, RawFileInput},
		{"build-cache", filepath.Join(build, "manifest"), build, modules, ElidedFileInput},
		{"build-fuzz", filepath.Join(build, "fuzz", "manifest"), build, modules, RawFileInput},
		{"module-cache", filepath.Join(modules, "example.com", "m@v1.0.0", "manifest"), build, modules, ElidedFileInput},
		{"module-download", filepath.Join(modules, "cache", "manifest"), build, modules, RawFileInput},
		{"overlapping-cache", filepath.Join(modules, "cache", "nested-build", "manifest"), filepath.Join(modules, "cache", "nested-build"), modules, ElidedFileInput},
		{"overlapping-fuzz", filepath.Join(build, "fuzz", "nested-modules", "manifest"), build, filepath.Join(build, "fuzz", "nested-modules"), ElidedFileInput},
		{"inside-tree", filepath.Join(root, "cache", "manifest"), filepath.Join(root, "cache"), modules, RawFileInput},
		{"cache-equals-tree", filepath.Join(root, "manifest"), root, modules, RawFileInput},
		{"cache-contains-tree", filepath.Join(root, "sibling-manifest"), filepath.Dir(root), modules, RawFileInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := eligibilityFile(t, tc.path)
			env := gotool.SetEnv(gotool.SetEnv(eligibilityEnv(pkg), "GOCACHE", tc.cache), "GOMODCACHE", tc.modcache)
			memo := &Roots{}
			q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: env, Roots: memo})
			if err != nil || q.Kind != tc.want || q.Kind != RawFileInput && q.Reason == "" {
				t.Fatalf("eligibility: %+v %v, want %v", q, err, tc.want)
			}
			frame := CaptureProducerFrame(t.Context(), root, pkg, FrameOptions{BracketPaths: []string{file}})
			obs := eligibilityObserve(t, frame, writeTestlog(t, "open "+file+"\n"), ProducerIngest{Identity: "eligibility-fixture", Env: env, Roots: memo})
			paths, err := Paths(obs.Manifest, root)
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(paths, file) != (tc.want == RawFileInput) {
				t.Fatalf("query and producer disagree: kind=%v paths=%v", q.Kind, paths)
			}
			if err := os.WriteFile(file, []byte("after"), 0o600); err != nil {
				t.Fatal(err)
			}
			current, err := Current(t.Context(), obs.Manifest, root, env)
			if err != nil || current.Unverifiable {
				t.Fatalf("current: %+v %v", current, err)
			}
			if (current.Digest != obs.Digest) != (tc.want == RawFileInput) {
				t.Fatalf("raw byte sensitivity differs from query: kind=%v", q.Kind)
			}
		})
	}
}

func TestFileInputEligibilityEffectiveRootsAndExceptions(t *testing.T) {
	root, pkg := eligibilityModule(t)
	out := t.TempDir()
	cache, modules := filepath.Join(out, "build"), filepath.Join(out, "modules")
	cacheFile := eligibilityFile(t, filepath.Join(cache, "manifest"))
	config := filepath.Join(out, "goenv")
	if err := os.WriteFile(config, []byte("GOCACHE="+cache+"\nGOMODCACHE="+modules+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := gotool.SetEnv(eligibilityEnv(pkg), "GOENV", config)
	env = gotool.UnsetEnv(gotool.UnsetEnv(env, "GOCACHE"), "GOMODCACHE")
	reader := gotool.NewEnvReader(gotool.Runner{}, pkg, env)
	snapshot, err := reader.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Value("GOCACHE") != cache || snapshot.Value("GOMODCACHE") != modules {
		t.Fatal("fixture did not activate effective GOENV roots")
	}
	q, err := FileInputEligibility(t.Context(), root, pkg, cacheFile, FileInputContext{Env: env})
	if err != nil || q.Kind != ElidedFileInput {
		t.Fatalf("effective GOENV cache ignored: %+v %v", q, err)
	}
	// The same physical root reached through its root alias retains coverage.
	alias := filepath.Join(out, "cache-alias")
	if err := os.Symlink(cache, alias); err != nil {
		t.Fatal(err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, cacheFile, FileInputContext{Env: gotool.SetEnv(env, "GOCACHE", alias)})
	if err != nil || q.Kind != ElidedFileInput {
		t.Fatalf("resolved cache root ignored: %+v %v", q, err)
	}
	// An explicit effective environment override wins over the persisted value.
	other := filepath.Join(out, "other-cache")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, cacheFile, FileInputContext{Env: gotool.SetEnv(env, "GOCACHE", other)})
	if err != nil || q.Kind != RawFileInput {
		t.Fatalf("environment override lost: %+v %v", q, err)
	}
	versionFile, err := filepath.EvalSymlinks(filepath.Join(snapshot.Value("GOROOT"), "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, versionFile, FileInputContext{Env: env})
	if err != nil || q.Kind != ElidedFileInput {
		t.Fatalf("toolchain file: %+v %v", q, err)
	}
	toolchainAlias := filepath.Join(out, "toolchain-alias")
	if err := os.Symlink(snapshot.Value("GOROOT"), toolchainAlias); err != nil {
		t.Fatal(err)
	}
	goName := "go"
	if runtime.GOOS == "windows" {
		goName += ".exe"
	}
	realGo := filepath.Join(snapshot.Value("GOROOT"), "bin", goName)
	aliasRunner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		// A launcher on PATH may clear GOROOT. Exercise the selected tool itself
		// with the declared alias, preserving the runner's environment and lifetime.
		cmd.Path, cmd.Args[0] = realGo, realGo
	}}
	aliasEnv := gotool.SetEnv(env, "GOROOT", toolchainAlias)
	aliasSnapshot, err := gotool.NewEnvReader(aliasRunner, pkg, aliasEnv).Snapshot(t.Context())
	if err != nil || aliasSnapshot.Value("GOROOT") != toolchainAlias {
		t.Fatalf("fixture did not activate aliased GOROOT: %q %v", aliasSnapshot.Value("GOROOT"), err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, versionFile, FileInputContext{Env: aliasEnv, Runner: aliasRunner})
	if err != nil || q.Kind != ElidedFileInput {
		t.Fatalf("aliased toolchain root: %+v %v", q, err)
	}
	// A persistent regular file below temp roots is ordinary input, including
	// when the producer declares the minted root rather than inheriting TMPDIR.
	temp := filepath.Join(out, "temp")
	file := eligibilityFile(t, filepath.Join(temp, "persistent"))
	tempEnv := gotool.SetEnv(gotool.SetEnv(env, "TMPDIR", temp), "GOTMPDIR", temp)
	for _, scratch := range []string{"", temp} {
		q, err = FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: tempEnv, ScratchRoot: scratch})
		if err != nil || q.Kind != RawFileInput {
			t.Fatalf("persistent temp file was elided: %+v %v", q, err)
		}
	}
}

// A selected file can also be an input to root resolution. Reading that role
// establishes classification, not a test's consumption of the file as data.
func TestFileInputEligibilityResolutionInputs(t *testing.T) {
	root, pkg := eligibilityModule(t)
	config := eligibilityFile(t, filepath.Join(t.TempDir(), "goenv"))
	env := gotool.UnsetEnv(gotool.SetEnv(eligibilityEnv(pkg), "GOENV", config), "GOCACHE")
	for _, tc := range []struct {
		cache string
		want  FileInputKind
	}{
		{t.TempDir(), RawFileInput},
		{filepath.Dir(config), ElidedFileInput},
	} {
		if err := os.WriteFile(config, []byte("GOCACHE="+tc.cache+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Each query owns a new resolution span after the configuration changes.
		q, err := FileInputEligibility(t.Context(), root, pkg, config, FileInputContext{Env: env})
		if err != nil || q.Kind != tc.want {
			t.Fatalf("selected GOENV configuration: %+v %v, want %v", q, err, tc.want)
		}
		frame := CaptureProducerFrame(t.Context(), root, pkg, FrameOptions{BracketPaths: []string{config}})
		obs := eligibilityObserve(t, frame, writeTestlog(t, ""), ProducerIngest{Identity: "configuration-only", Env: env})
		m, err := decode(obs.Manifest)
		if err != nil || len(m.Paths) != 0 || len(m.Env) != 0 {
			t.Fatalf("root resolution manufactured a consumer observation: %+v %v", m, err)
		}
	}
}

func TestFileInputEligibilityRefusesProjectedAndUnsupported(t *testing.T) {
	root, pkg := eligibilityModule(t)
	env := eligibilityEnv(pkg)
	file := eligibilityFile(t, filepath.Join(t.TempDir(), "manifest"))
	for _, p := range []string{"", "relative", pkg, filepath.Dir(file), file + "-missing", file + "/../manifest", file + "\n", file + "\x00", file + "\xff"} {
		q, err := FileInputEligibility(t.Context(), root, pkg, p, FileInputContext{Env: env})
		if err == nil && (q.Kind != UnverifiableFileInput || q.Reason == "") {
			t.Fatalf("unsupported path %q admitted: %+v", p, q)
		}
	}
	for _, badEnv := range [][]string{nil, {"broken"}, {"PWD=" + pkg, "PWD=" + pkg}} {
		if q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: badEnv}); err == nil || q != (FileEligibility{}) {
			t.Fatalf("invalid environment: %+v %v", q, err)
		}
	}
	for _, badEnv := range [][]string{{}, gotool.UnsetEnv(env, "PWD"), gotool.SetEnv(env, "PWD", root)} {
		q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: badEnv})
		if err != nil || q.Kind != UnverifiableFileInput || q.Reason == "" {
			t.Fatalf("missing/foreign process directory admitted: %+v %v", q, err)
		}
	}
	for _, dirs := range [][2]string{{"relative", pkg}, {root, "relative"}, {root + "-missing", pkg}, {root, file + "-missing"}, {root, filepath.Dir(file)}} {
		q, err := FileInputEligibility(t.Context(), dirs[0], dirs[1], file, FileInputContext{Env: env})
		if err == nil && (q.Kind != UnverifiableFileInput || q.Reason == "") {
			t.Fatalf("invalid directories %v admitted: %+v", dirs, q)
		}
	}
	for _, target := range []string{file, filepath.Dir(file)} {
		link := target + "-link"
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if target != file {
			link = filepath.Join(link, filepath.Base(file))
		}
		q, err := FileInputEligibility(t.Context(), root, pkg, link, FileInputContext{Env: env})
		if err != nil || q.Kind != UnverifiableFileInput || q.Reason == "" {
			t.Fatalf("symlink: %+v %v", q, err)
		}
	}
	if filepath.IsAbs(os.DevNull) {
		q, err := FileInputEligibility(t.Context(), root, pkg, os.DevNull, FileInputContext{Env: env})
		if err != nil || q.Kind != ElidedFileInput || q.Reason == "" {
			t.Fatalf("null sink: %+v %v", q, err)
		}
	}
	if runtime.GOOS == "linux" {
		q, err := FileInputEligibility(t.Context(), root, pkg, "/proc/cpuinfo", FileInputContext{Env: env})
		if err != nil || q.Kind != ProjectedFileInput || q.Reason == "" {
			t.Fatalf("machine projection: %+v %v", q, err)
		}
		probe := classifyProbe
		classifyProbe = func(p string) (os.FileInfo, error) { t.Fatalf("volatile path probed: %s", p); return nil, nil }
		t.Cleanup(func() { classifyProbe = probe })
		q, err = FileInputEligibility(t.Context(), root, pkg, "/proc/self/status", FileInputContext{Env: env})
		if err != nil || q.Kind != UnverifiableFileInput || q.Reason == "" {
			t.Fatalf("volatile: %+v %v", q, err)
		}
	}
}

func TestFileInputEligibilityExclusionPrecedence(t *testing.T) {
	root, pkg := eligibilityModule(t)
	env := eligibilityEnv(pkg)
	file := eligibilityFile(t, filepath.Join(t.TempDir(), "manifest"))
	paths := []string{file, file + "-missing"}
	if runtime.GOOS == "linux" {
		paths = append(paths, "/proc/self/status", "/proc/nonexistent-gofresh-input", "/proc/cpuinfo")
	}
	for _, file := range paths {
		q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: env, ExcludedPaths: []string{file}})
		if err != nil || q.Kind != ElidedFileInput || q.Reason == "" {
			t.Fatalf("excluded %s: %+v %v", file, q, err)
		}
		// Identity-only synthetic log: an excluded observation contributes
		// neither a path nor its classification refusal, even when absent.
		frame := CaptureProducerFrame(t.Context(), root, pkg, FrameOptions{})
		obs := eligibilityObserve(t, frame, writeTestlog(t, "open "+file+"\n"), ProducerIngest{Identity: "excluded", Env: env, ExcludedPaths: []string{file}})
		m, err := decode(obs.Manifest)
		if err != nil || len(m.Paths) != 0 {
			t.Fatalf("excluded path recorded: %+v %v", m, err)
		}
	}
	q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: env, ExcludedPaths: []string{filepath.VolumeName(file) + string(filepath.Separator)}})
	if err != nil || q.Kind != RawFileInput {
		t.Fatalf("root-listing exclusion widened: %+v %v", q, err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, filepath.Join(root, ".git", "HEAD"), FileInputContext{Env: env})
	if err != nil || q.Kind != ElidedFileInput {
		t.Fatalf("facade VCS exclusion lost: %+v %v", q, err)
	}
}

func TestFileInputEligibilityUnavailableRoots(t *testing.T) {
	root, pkg := eligibilityModule(t)
	file := eligibilityFile(t, filepath.Join(t.TempDir(), "manifest"))
	keys := []string{"GOROOT", "GOMODCACHE", "GOCACHE", "GOTMPDIR"}
	for _, missing := range keys {
		t.Run(missing, func(t *testing.T) {
			runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
				// A real go-env document with one required answer omitted.
				cmd.Args = append(cmd.Args[:1], "env", "-json")
				for _, key := range keys {
					if key != missing {
						cmd.Args = append(cmd.Args, key)
					}
				}
			}}
			q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: eligibilityEnv(pkg), Runner: runner})
			if err == nil || q != (FileEligibility{}) {
				t.Fatalf("missing %s granted eligibility: %+v %v", missing, q, err)
			}
		})
	}
}

func TestFileInputEligibilityCancellation(t *testing.T) {
	root, pkg := eligibilityModule(t)
	file := eligibilityFile(t, filepath.Join(t.TempDir(), "manifest"))
	env := eligibilityEnv(pkg)
	if q, err := FileInputEligibility(nil, root, pkg, file, FileInputContext{Env: env}); err == nil || q != (FileEligibility{}) {
		t.Fatalf("nil context: %+v %v", q, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if q, err := FileInputEligibility(ctx, root, pkg, file, FileInputContext{Env: env}); !errors.Is(err, context.Canceled) || q != (FileEligibility{}) {
		t.Fatalf("cancelled entry: %+v %v", q, err)
	}
	for _, elided := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var command *exec.Cmd
		runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
			// Model a runner completing its roots answer despite cancellation.
			// The query must check cancellation after accepting that answer,
			// even on a recordless early return.
			replacement := exec.Command(cmd.Path, cmd.Args[1:]...)
			replacement.Dir, replacement.Env = cmd.Dir, cmd.Env
			*cmd = *replacement
			command = cmd
			cancel()
		}}
		in := FileInputContext{Env: env, Runner: runner}
		if elided {
			in.ExcludedPaths = []string{file}
		}
		q, err := FileInputEligibility(ctx, root, pkg, file, in)
		if command == nil || command.ProcessState == nil || !command.ProcessState.Success() {
			t.Fatal("fixture did not finish the roots command")
		}
		if !errors.Is(err, context.Canceled) || q != (FileEligibility{}) {
			t.Fatalf("cancelled after roots, elided=%v: %+v %v", elided, q, err)
		}
	}
	// Cancellation also dominates pre-probe failures and malformed context.
	for _, tc := range []struct {
		path string
		env  []string
	}{{"relative", env}, {file, nil}} {
		ctx := &cancelAfterChecks{Context: t.Context(), after: 1}
		q, err := FileInputEligibility(ctx, root, pkg, tc.path, FileInputContext{Env: tc.env})
		if !errors.Is(err, context.Canceled) || q != (FileEligibility{}) {
			t.Fatalf("cancelled early refusal: %+v %v", q, err)
		}
	}
	paths := []string{file}
	if runtime.GOOS == "linux" {
		paths = append(paths, "/proc/cpuinfo")
	}
	for _, path := range paths {
		ctx, cancel := context.WithCancel(t.Context())
		probe := classifyProbe
		called := false
		classifyProbe = func(p string) (os.FileInfo, error) {
			called = true
			cancel()
			return probe(p)
		}
		q, err := FileInputEligibility(ctx, root, pkg, path, FileInputContext{Env: env})
		classifyProbe = probe
		cancel()
		if !called || !errors.Is(err, context.Canceled) || q != (FileEligibility{}) {
			t.Fatalf("cancelled after probe of %s: %+v %v", path, q, err)
		}
	}
}

func TestFileInputEligibilityOwnsCallerSlices(t *testing.T) {
	root, pkg := eligibilityModule(t)
	cache := t.TempDir()
	file := eligibilityFile(t, filepath.Join(cache, "manifest"))
	for _, excluded := range []bool{false, true} {
		env := gotool.SetEnv(eligibilityEnv(pkg), "GOCACHE", t.TempDir())
		exclusions := []string{file + "-other"}
		want := RawFileInput
		if excluded {
			exclusions[0], want = file, ElidedFileInput
		}
		called := false
		runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
			called = true
			for i, entry := range env {
				if strings.HasPrefix(entry, "GOCACHE=") {
					env[i] = "GOCACHE=" + cache
				}
				if strings.HasPrefix(entry, "PWD=") {
					env[i] = "PWD=" + root
				}
			}
			if excluded {
				exclusions[0] = file + "-other"
			} else {
				exclusions[0] = file
			}
			if pwd, _ := gotool.LookupEnv(cmd.Env, "PWD"); pwd != pkg {
				t.Fatalf("runner inherited mutated PWD: %q", pwd)
			}
		}}
		q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: env, Runner: runner, ExcludedPaths: exclusions})
		if !called || err != nil || q.Kind != want {
			t.Fatalf("caller mutation changed query, excluded=%v: %+v %v", excluded, q, err)
		}
	}
}

func TestFileInputEligibilityExecution(t *testing.T) {
	const modeKey = "GOFRESH_ELIGIBILITY_CHILD"
	const fileKey = "GOFRESH_ELIGIBILITY_FILE"
	if mode := os.Getenv(modeKey); mode != "" {
		file := os.Getenv(fileKey)
		switch mode {
		case "read":
			data, err := os.ReadFile(file)
			if err != nil || string(data) != "before" {
				t.Fatalf("actual read: %q %v", data, err)
			}
		case "query":
			q, err := FileInputEligibility(t.Context(), os.Getenv("GOFRESH_ELIGIBILITY_ROOT"), os.Getenv("PWD"), file, FileInputContext{Env: os.Environ()})
			if err != nil || q.Kind != RawFileInput {
				t.Fatalf("child query: %+v %v", q, err)
			}
		default:
			t.Fatalf("unknown child mode: %s", mode)
		}
		return
	}
	root, pkg := eligibilityModule(t)
	file := eligibilityFile(t, filepath.Join(t.TempDir(), "manifest"))
	env := gotool.SetEnv(eligibilityEnv(pkg), fileKey, file)
	q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: env})
	if err != nil || q.Kind != RawFileInput {
		t.Fatalf("preflight: %+v %v", q, err)
	}
	// Query and bracket declaration alone add no observed identity. This empty
	// synthetic capture makes only an identity-guard claim, with no outcomes.
	frame := CaptureProducerFrame(t.Context(), root, pkg, FrameOptions{BracketPaths: []string{file}})
	empty := eligibilityObserve(t, frame, writeTestlog(t, ""), ProducerIngest{Identity: "no-open", Env: env})
	m, err := decode(empty.Manifest)
	if err != nil || len(m.Paths) != 0 || len(m.Env) != 0 {
		t.Fatalf("preflight fabricated identities: %+v %v", m, err)
	}
	var observed Observation
	for _, mode := range []string{"query", "read"} {
		childEnv := gotool.SetEnv(gotool.SetEnv(env, modeKey, mode), "GOFRESH_ELIGIBILITY_ROOT", root)
		logPath := filepath.Join(t.TempDir(), "child.testlog")
		cmd, err := (gotool.Runner{}).Program(t.Context(), pkg, childEnv, os.Args[0], "-test.run=^TestFileInputEligibilityExecution$", "-test.testlogfile="+logPath)
		if err != nil {
			t.Fatal(err)
		}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s child: %v\n%s", mode, err, output)
		}
		log, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		hasOpen := slices.Contains(strings.Split(string(log), "\n"), "open "+file)
		if hasOpen != (mode == "read") {
			t.Fatalf("%s selected-file open=%v; log:\n%s", mode, hasOpen, log)
		}
		if mode == "read" {
			observed = eligibilityObserve(t, frame, logPath, ProducerIngest{Identity: "actual-read", Env: childEnv})
			paths, err := Paths(observed.Manifest, root)
			if err != nil || !slices.Contains(paths, file) {
				t.Fatalf("actual open not recorded: %v %v", paths, err)
			}
			m, err := decode(observed.Manifest)
			if err != nil || !slices.ContainsFunc(m.Env, func(e envInput) bool { return e.Name == fileKey }) {
				t.Fatalf("path environment read not recorded: %+v %v", m, err)
			}
			env = childEnv
		}
	}
	if err := os.WriteFile(file, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	current, err := Current(t.Context(), observed.Manifest, root, env)
	if err != nil || current.Unverifiable || current.Digest == observed.Digest {
		t.Fatalf("actual observed content change missed: %+v %v", current, err)
	}
}

// completedFromLog builds a completed observation over dir with the bracket
// covering "data" — the shared harness for guard-covered classification pins.
func completedFromLog(t *testing.T, dir, log string, opts ...TestLogOption) Observation {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	bracket, err := ambientCaptureBracket(dir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	opts = append([]TestLogOption{WithCompletedProcess("package-test-binary:guard"), WithBracket(bracket)}, opts...)
	obs, err := ambientFromTestLog([]byte(log), dir, dir, opts...)
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

	obs := completedFromLog(t, dir, log, withToolchainRoot(root))
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

// An overlapping later root covers what the first admitting root's
// failed leg cannot: a symlink escaping an inner root into an outer
// root that admits the whole chain — a build cache configured inside a
// module cache's covered region — recovers coverage, while the same
// chain with only the inner declaration stays observed
// (REQ-inputs-guard-covered: per-root verdicts, refusal the default).
func TestGuardCoveredOverlappingRootsConsultBeyondFirstMatch(t *testing.T) {
	dir := t.TempDir()
	outer := t.TempDir()
	inner := filepath.Join(outer, "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outer, "target.txt")
	if err := os.WriteFile(target, []byte("pinned"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(inner, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	log := "open " + link + "\n"

	// Inner root first: it admits the path, its resolution escapes it,
	// and the outer root then admits the whole chain.
	obs := completedFromLog(t, dir, log, withToolchainRoot(inner), withToolchainRoot(outer))
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("overlapping outer root not consulted after the inner root's failed leg: %s", st.Reason)
	}

	// The inner declaration alone stays observed: the escape is real.
	only := completedFromLog(t, dir, log, withToolchainRoot(inner))
	onlyState, err := CompletedState(only)
	if err != nil {
		t.Fatal(err)
	}
	if !onlyState.Unverifiable {
		t.Fatal("inner-only escaping chain did not stay observed")
	}

	// Out-and-back: the chain's TARGET is back inside the inner root but
	// an intermediate link lies outside it — the inner root's link leg
	// fails, and the outer root still admits the whole chain.
	backTarget := filepath.Join(inner, "back.txt")
	if err := os.WriteFile(backTarget, []byte("pinned"), 0o644); err != nil {
		t.Fatal(err)
	}
	mid := filepath.Join(outer, "mid-link")
	if err := os.Symlink(backTarget, mid); err != nil {
		t.Fatal(err)
	}
	hop := filepath.Join(inner, "hop.txt")
	if err := os.Symlink(mid, hop); err != nil {
		t.Fatal(err)
	}
	hopLog := "open " + hop + "\n"
	hopObs := completedFromLog(t, dir, hopLog, withToolchainRoot(inner), withToolchainRoot(outer))
	hopState, err := CompletedState(hopObs)
	if err != nil {
		t.Fatal(err)
	}
	if hopState.Unverifiable {
		t.Fatalf("out-and-back chain not recovered by the outer root: %s", hopState.Reason)
	}
	hopOnly := completedFromLog(t, dir, hopLog, withToolchainRoot(inner))
	hopOnlyState, err := CompletedState(hopOnly)
	if err != nil {
		t.Fatal(err)
	}
	if !hopOnlyState.Unverifiable {
		t.Fatal("inner-only out-and-back chain did not stay observed")
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
		obs := completedFromLog(t, dir, "open "+link+"\n", withToolchainRoot(root))
		st, err := CompletedState(obs)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Unverifiable {
			t.Fatal("module-local symlink into a guard root skipped observation")
		}
	})
	t.Run("escape out of root is observed", func(t *testing.T) {
		obs := completedFromLog(t, t.TempDir(), "open "+escape+"\n", withToolchainRoot(root))
		st, err := CompletedState(obs)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Unverifiable {
			t.Fatal("symlink escaping the guard root skipped observation")
		}
	})
	t.Run("ambiguous traversal under root is observed", func(t *testing.T) {
		// A parent traversal crossing a symlinked component cannot be
		// proven congruent with its lexical cleaning
		// (REQ-inputs-path-congruence), so the read is never provably
		// inside the root.
		if err := os.Symlink(filepath.Join(root, "dep"), filepath.Join(root, "deplink")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		traversal := root + "/deplink/../dep/d.go"
		obs := completedFromLog(t, t.TempDir(), "open "+traversal+"\n", withToolchainRoot(root))
		st, err := CompletedState(obs)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Unverifiable {
			t.Fatal("ambiguous traversal under the guard root skipped observation")
		}
	})
	t.Run("congruent traversal under root is guard-covered", func(t *testing.T) {
		// Every crossed component is a real directory, so the traversal
		// resolves lexically (REQ-inputs-path-congruence's discharge) and
		// the read is provably inside the root: covered by the guard,
		// never a recorded observation.
		traversal := root + "/dep/../dep/d.go"
		obs := completedFromLog(t, t.TempDir(), "open "+traversal+"\n", withToolchainRoot(root))
		st, err := CompletedState(obs)
		if err != nil {
			t.Fatal(err)
		}
		if st.Unverifiable {
			t.Fatalf("congruent traversal under the guard root sealed the observation: %+v", st)
		}
	})
	t.Run("missing path under root is observed", func(t *testing.T) {
		obs := completedFromLog(t, t.TempDir(), "open "+filepath.Join(root, "gone.go")+"\n", withToolchainRoot(root))
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
	obs := completedFromLog(t, t.TempDir(), log, withToolchainRoot(link))
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
		_, err := ambientFromTestLog([]byte(""), t.TempDir(), ".", WithCompletedProcess("package-test-binary:x"), withToolchainRoot(bad))
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

	obs := completedFromLog(t, t.TempDir(), "open "+extracted+"\nopen "+metadata+"\n", withModuleCacheRoot(root))
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

	obs := completedFromLog(t, t.TempDir(), "open "+filepath.Join(root, "hopdir", "f.go")+"\n", withToolchainRoot(root))
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
	obs := completedFromLog(t, t.TempDir(), log, withToolchainRoot(root))
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
	obs := completedFromLog(t, t.TempDir(), "open "+filepath.Join(root, "f.go")+"\n", withToolchainRoot(root))
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

	obs := completedFromLog(t, dir, log, withBuildCacheRoot(root))
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
	obsFuzz := completedFromLog(t, dir, "open "+seed+"\n", withBuildCacheRoot(root))
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
	obs = completedFromLog(t, dir, "open "+link+"\n", withBuildCacheRoot(root))
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
	if _, err := ambientFromTestLog([]byte("open x\n"), dir, dir, withBuildCacheRoot("relative/path")); err == nil {
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

	obs := completedFromLog(t, dir, log, withEphemeralTempRoot(root))
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
	obs = completedFromLog(t, dir, "open "+deeper+"\n", withEphemeralTempRoot(root))
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

	if _, err := ambientFromTestLog([]byte("open x\n"), dir, dir, withEphemeralTempRoot("relative/tmp")); err == nil || !strings.Contains(err.Error(), "ephemeral temp root") {
		t.Fatalf("relative ephemeral root accepted or misnamed: %v", err)
	}

	// The resolved-form arm is load-bearing (macOS /tmp -> /private/tmp):
	// declaring the LINK admits an open of the REAL root.
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "tmplink")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	obs = completedFromLog(t, dir, "open "+real+"\n", withEphemeralTempRoot(link))
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
	obs = completedFromLog(t, dir, "open "+gone+"\n", withEphemeralTempRoot(gone))
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
	interiorBracket, err := ambientCaptureBracket(dir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ambientFromTestLog([]byte("open "+deeper+"\n"), dir, dir,
		WithCompletedProcess("package-test-binary:guard"), WithBracket(interiorBracket),
		withEphemeralTempRoot(interior)); err == nil || !strings.Contains(err.Error(), "inside the module tree") {
		t.Fatalf("module-interior ephemeral root error = %v", err)
	}
	// An UNRESOLVABLE interior root refuses identically: the declared
	// form's interiority is checkable without resolution.
	missingBracket, err := ambientCaptureBracket(dir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ambientFromTestLog([]byte("open "+deeper+"\n"), dir, dir,
		WithCompletedProcess("package-test-binary:guard"), WithBracket(missingBracket),
		withEphemeralTempRoot(filepath.Join(dir, "missing"))); err == nil || !strings.Contains(err.Error(), "inside the module tree") {
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
		cur, err := ambientCurrentEnv(st.Manifest, dir, nil)
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

	// Contrast: a non-allowlisted proc identity refuses lexically as a
	// volatile OS input — never probed, never recorded
	// (REQ-inputs-volatile-os-roots). The named reason pins the class:
	// an allowlist widened to /proc/stat would digest the projection
	// verifiably and never carry this reason.
	obs = completedFromLog(t, dir, "open /proc/stat\n")
	st, err = CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "volatile OS input: /proc/stat") {
		t.Fatalf("non-allowlisted proc identity not refused as volatile OS input: unverifiable=%v reason=%s", st.Unverifiable, st.Reason)
	}
}

// A volatile-OS path classifies from the path alone
// (REQ-inputs-volatile-os-roots): open and stat alike refuse with the
// named class, an ABSENT proc path refuses identically — proving no
// probe routes the decision — and /sys shares the carve. No identity
// is recorded, so nothing over these paths is ever digested.
func TestVolatileOSPathsClassifyLexically(t *testing.T) {
	if len(guard.VolatileOSRoots) == 0 {
		t.Skip("no volatile OS surface on this platform")
	}
	dir := t.TempDir()
	// Any classification-time probe of a volatile-OS path is itself a
	// volatile read in an observing parent's evidence: count them.
	var probed []string
	orig := classifyProbe
	classifyProbe = func(p string) (os.FileInfo, error) {
		if volatileOSPath(p) {
			probed = append(probed, p)
		}
		return orig(p)
	}
	t.Cleanup(func() { classifyProbe = orig })
	for _, log := range []string{
		"open /proc/stat\n",
		"stat /proc/stat\n",
		"open /proc/definitely-not-a-real-entry-xyz\n",
		"stat /sys/kernel/anything\n",
	} {
		obs := completedFromLog(t, dir, log)
		st, err := CompletedState(obs)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Unverifiable || !strings.Contains(st.Reason, "volatile OS input: ") {
			t.Fatalf("%q: unverifiable=%v reason=%q, want the lexical volatile-OS refusal", log, st.Unverifiable, st.Reason)
		}
		if strings.Contains(st.Reason, "stat metadata input") || strings.Contains(st.Reason, "external directory") {
			t.Fatalf("%q: probe-routed classification leaked: %q", log, st.Reason)
		}
		// No recorded identity, never digested: the refusal is the whole
		// disposition.
		desc, err := Describe(st.Manifest, dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, dp := range desc.Paths {
			if strings.Contains(dp, "/proc") || strings.Contains(dp, "/sys") {
				t.Fatalf("%q: volatile-OS identity recorded: %s", log, dp)
			}
		}
	}

	// An ephemeral temp root under a volatile OS root refuses at
	// declaration: it would vacate volatile reads recordless while the
	// scratch walk probed them.
	leg, err := ambientCaptureBracket(dir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ambientFromTestLog([]byte("open /proc/stat\n"), dir, dir, WithCompletedProcess("package-test-binary:guard"), WithBracket(leg), withEphemeralTempRoot("/proc/scratch")); err == nil || !strings.Contains(err.Error(), "volatile OS root") {
		t.Fatalf("ephemeral root under /proc accepted: %v", err)
	}

	// A guard root under a volatile OS root is skipped like an
	// unresolvable declaration: the read stays refused as volatile,
	// never admitted recordless through the declared root.
	obsGuard := completedFromLog(t, dir, "open /proc/stat\n", withToolchainRoot("/proc"))
	stGuard, err := CompletedState(obsGuard)
	if err != nil {
		t.Fatal(err)
	}
	if !stGuard.Unverifiable || !strings.Contains(stGuard.Reason, "volatile OS input: /proc/stat") {
		t.Fatalf("guard root under /proc admitted a volatile read: unverifiable=%v reason=%q", stGuard.Unverifiable, stGuard.Reason)
	}

	if len(probed) != 0 {
		t.Fatalf("classification probed volatile-OS paths: %v", probed)
	}

	// A declared bracket root under a volatile OS root fails loud at
	// declaration: its fingerprint could only ever move.
	if _, err := ambientCaptureBracket(dir, []string{"/proc/stat"}); err == nil || !strings.Contains(err.Error(), "volatile OS root") {
		t.Fatalf("bracket root under /proc accepted: %v", err)
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
	obs := completedFromLog(t, dir, "open "+gone+"\nstat "+filepath.Join(root, "run123")+"\n", withEphemeralTempRoot(root))
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
	obs = completedFromLog(t, dir, "open "+kept+"\n", withEphemeralTempRoot(root))
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
	obs = completedFromLog(t, dir, "open "+filepath.Join(link, "gone.txt")+"\n", withEphemeralTempRoot(root))
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
	obs = completedFromLog(t, dir, "open "+filepath.Join(dangle, "gone.txt")+"\n", withEphemeralTempRoot(root))
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

// A truthful PWD read binds its actual environment value; the frame alone is
// not a persisted dependency. Other postures retain their process-local refusal.
func TestPWDAdmitsOnlyWhenPinnedToSpawnDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	fromEnv := func(env []string) (bool, string, Description) {
		t.Helper()
		bracket, err := ambientCaptureBracket(dir, []string{"data"})
		if err != nil {
			t.Fatal(err)
		}
		obs, err := FromTestLog([]byte("getenv PWD\n"), dir, dir, env,
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
	if len(d.EnvNames) != 1 || d.EnvNames[0] != "PWD" || len(d.Paths)+len(d.Unverifiable) != 0 {
		t.Fatalf("truthful PWD is not exactly one environment dependency: %+v", d)
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
		cur, err := ambientCurrentEnv(st.Manifest, dir, nil)
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
	cur, err := ambientCurrentEnv(st.Manifest, dir, nil)
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
	cur, err = ambientCurrentEnv(st.Manifest, dir, nil)
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

// A stat of an absent external identity binds absence alone: recorded,
// no seal, digest stable while absent, staled by appearance - the
// LookPath-miss class - while a PRESENT external file's stat keeps the
// metadata seal (REQ-inputs-absent-stat).
func TestAbsentExternalStatBindsAbsence(t *testing.T) {
	dir := t.TempDir()
	probe := filepath.Join(t.TempDir(), "bin", "git")
	if err := os.MkdirAll(filepath.Dir(probe), 0o755); err != nil {
		t.Fatal(err)
	}
	obs := completedFromLog(t, dir, "stat "+probe+"\n")
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("absent stat sealed: %s", st.Reason)
	}
	d, err := Describe(st.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 1 || len(d.Unverifiable) != 0 {
		t.Fatalf("absence entry not recorded cleanly: %+v", d)
	}
	cur, err := ambientCurrentEnv(st.Manifest, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Digest != st.Digest {
		t.Fatal("recomputation moved while the identity stays absent")
	}
	// Appearance stales.
	if err := os.WriteFile(probe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cur, err = ambientCurrentEnv(st.Manifest, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Digest == st.Digest {
		t.Fatal("appeared identity did not move the digest")
	}
}

// A module tree lying inside a declared ephemeral root does not
// surrender its identities: a module-relative absence-probe keeps its
// missing-arm record — its appearance must stale — while a genuinely
// external absent read under the same root stays admitted
// (REQ-inputs-ephemeral-root).
func TestEphemeralRootNeverSwallowsModuleInteriorReads(t *testing.T) {
	outer := t.TempDir()
	moduleDir := filepath.Join(outer, "mod")
	if err := os.MkdirAll(filepath.Join(moduleDir, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	log := "open " + filepath.Join(moduleDir, "pkg", "sb-1", "out.txt") + "\n" +
		"open " + filepath.Join(outer, "gone", "scratch.txt") + "\n"
	obs, err := ambientFromTestLog([]byte(log), moduleDir, filepath.Join(moduleDir, "pkg"),
		WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)),
		withEphemeralTempRoot(outer))
	if err != nil {
		t.Fatal(err)
	}
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Describe(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 1 || d.Paths[0] != filepath.Join(moduleDir, "pkg", "sb-1", "out.txt") {
		t.Fatalf("paths = %+v, want exactly the module-interior probe recorded", d.Paths)
	}
}

// An alias route into the module — a second symlink under the declared
// root resolving to the module tree — must not re-open what the lexical
// module-interiority gate closed: the ancestor's resolved position is
// refused under the module, so the aliased absence-probe stays recorded
// (REQ-inputs-ephemeral-root).
func TestEphemeralRootRefusesAliasRouteIntoModule(t *testing.T) {
	outer := t.TempDir()
	moduleDir := filepath.Join(outer, "mod")
	if err := os.MkdirAll(filepath.Join(moduleDir, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moduleDir, filepath.Join(outer, "alias")); err != nil {
		t.Fatal(err)
	}
	log := "open " + filepath.Join(outer, "alias", "pkg", "sb-1", "out.txt") + "\n"
	obs, err := ambientFromTestLog([]byte(log), moduleDir, filepath.Join(moduleDir, "pkg"),
		WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)),
		withEphemeralTempRoot(outer))
	if err != nil {
		t.Fatal(err)
	}
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Describe(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths)+len(d.Unverifiable) == 0 {
		t.Fatal("aliased module-interior probe admitted recordless")
	}
}

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
	obs, err := ambientFromTestLog([]byte("open a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
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
	after, err := ambientCurrent(obs.Manifest, moduleDir)
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
	moved, err := ambientCurrent(obs.Manifest, secondRoot)
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
	obs, err := ambientFromTestLog([]byte("stat a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
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
	after, err := ambientCurrent(obs.Manifest, moduleDir)
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
	obs, err := ambientFromTestLog([]byte("open a.txt\nstat a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
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
	opened, err := ambientFromTestLog([]byte("open a.txt\n"), moduleDir, packageDir, WithCompletedProcess("opener"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	statted, err := ambientFromTestLog([]byte("stat a.txt\n"), moduleDir, packageDir, WithCompletedProcess("statter"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := ambientMerge(moduleDir, opened, statted)
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
	obs, err := ambientFromTestLog([]byte("open a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := ambientAbsolute(obs, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := ambientRelative(absolute, moduleDir)
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
	moved, err := ambientCurrent(relative.Manifest, secondRoot)
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
	obs, err := ambientFromTestLog([]byte("stat a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
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
	absolute, err := ambientAbsolute(obs, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	metadataBound("Absolute", absolute)
	relative, err := ambientRelative(absolute, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	metadataBound("Relative", relative)
	again, err := ambientAbsolute(relative, moduleDir)
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
	opened, err := ambientFromTestLog([]byte("open a.txt\n"), moduleDir, packageDir, WithCompletedProcess("opener"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	statted, err := ambientFromTestLog([]byte("stat a.txt\n"), moduleDir, packageDir, WithCompletedProcess("statter"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	// Absolutize only one side, then merge under a foreign root: the
	// merged manifest carries the SAME file as a rel identity (open,
	// content-bound) and an abs identity (stat, metadata-bound).
	absStatted, err := ambientAbsolute(statted, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := ambientMerge(moduleDir, opened, absStatted)
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
	relative, err := ambientRelative(merged, moduleDir)
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
	obs, err := ambientFromTestLog([]byte("open "+external+"\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	relative, err := ambientRelative(obs, moduleDir)
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
	obs, err := ambientFromTestLog([]byte("open a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ambientRelative(obs, moduleDir); err == nil || !strings.Contains(err.Error(), "state moved before relative identity conversion") {
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
	obs, err := ambientFromTestLog([]byte("open a.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := ambientAbsolute(obs, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := ambientRelative(absolute, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ambientAbsolute(relative, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if again.State != absolute.State {
		t.Fatalf("round trip diverged:\n got %+v\nwant %+v", again.State, absolute.State)
	}
}

// Pre-v4 values cannot distinguish demonstrated movement from inferred refusal;
// pre-v3 values may also omit PWD. Even internally sealed history cannot upgrade.
func FuzzHistoricalPWDManifestDoesNotUpgrade(f *testing.F) {
	for version := uint8(1); version <= 3; version++ {
		f.Add([]byte("empty"), false, false, version)
		f.Add([]byte("pwd"), true, false, version)
		f.Add([]byte("supported"), true, true, version)
	}
	f.Fuzz(func(t *testing.T, value []byte, withEnv, supported bool, version uint8) {
		dir := t.TempDir()
		env := []string{"PWD=" + dir, "OBSERVED=" + base64.RawURLEncoding.EncodeToString(value)}
		m := manifest{Version: manifestVersion}
		if withEnv {
			m.Env = []envInput{{Name: "PWD"}, {Name: "OBSERVED"}}
		}
		if supported {
			m.Outcome, m.Subjects = outcome.Method, []string{supportedSubject}
		}
		current, err := stateFromManifest(context.Background(), m, dir, env)
		if err != nil {
			t.Fatal(err)
		}
		fresh := newObservation(current, "fresh", "fixture")
		if _, err := Adopt(current.Manifest, dir, "current", env); err != nil {
			t.Fatalf("current control: %v", err)
		}
		if HasOutcomeSupport(current.Manifest, supportedSubject) != supported {
			t.Fatal("current support control disagrees")
		}
		legacy, err := decode(current.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		legacy.Version = 1 + (int(version)+2)%3
		raw, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		old := newObservation(State{Manifest: encoded, Digest: manifestDigest(legacy), OK: true}, "historical", "fixture")
		if HasOutcomeSupport(encoded, supportedSubject) {
			t.Fatal("historical manifest gained outcome support")
		}
		for name, check := range map[string]func() error{
			"current":         func() error { _, err := Current(context.Background(), encoded, dir, env); return err },
			"adopt":           func() error { _, err := Adopt(encoded, dir, "old", env); return err },
			"absolute":        func() error { _, err := Absolute(old, dir, env); return err },
			"relative":        func() error { _, err := Relative(old, dir, env); return err },
			"merge old first": func() error { _, err := Merge(dir, env, old, fresh); return err },
			"merge old last":  func() error { _, err := Merge(dir, env, fresh, old); return err },
		} {
			if err := check(); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("unsupported manifest version %d", legacy.Version)) {
				t.Fatalf("%s upgraded history: %v", name, err)
			}
		}
		if old.Manifest != encoded {
			t.Fatal("historical bytes changed")
		}
	})
}

func FuzzPWDObservationBindsOnlyTheObservedValue(f *testing.F) {
	f.Add([]byte("unread environment"))
	f.Add([]byte{0, 255, '\n'})
	f.Fuzz(func(t *testing.T, unread []byte) {
		dir := t.TempDir()
		other := filepath.Join(dir, "other")
		if err := os.Mkdir(other, 0o700); err != nil {
			t.Fatal(err)
		}
		env := []string{"PWD=" + dir, "UNREAD=" + base64.RawURLEncoding.EncodeToString(unread)}
		obs, err := FromTestLog([]byte("getenv PWD\ngetenv PWD\n"), dir, dir, env, WithCompletedProcess("worker"), WithBracket(testBracket(t, dir)))
		if err != nil || obs.Unverifiable {
			t.Fatalf("truthful capture: %+v, %v", obs, err)
		}
		d, err := Describe(obs.Manifest, dir)
		if err != nil || !slices.Equal(d.EnvNames, []string{"PWD"}) {
			t.Fatalf("observed names: %+v, %v", d, err)
		}
		for _, same := range [][]string{env, {"PWD=" + dir}, {"UNREAD=other", "PWD=" + dir}} {
			current, err := Current(context.Background(), obs.Manifest, dir, same)
			if err != nil || current != obs.State {
				t.Fatalf("unread value affected PWD: %+v, %v", current, err)
			}
		}
		for _, changed := range [][]string{{"PWD=" + other}, {}, {"PWD="}} {
			current, err := Current(context.Background(), obs.Manifest, dir, changed)
			if err != nil || current.Digest == obs.Digest {
				t.Fatalf("changed PWD did not move: %+v, %v", current, err)
			}
		}
	})
}

// The roots probe serves the answer a cleanly exited process wrote
// beside a descendant's pipe hold when its four values are present; a
// torn answer refuses with the hold named
// (REQ-fresh-go-command-policy).
func TestRootsProbeServesTheSalvagedAnswer(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shim := t.TempDir()
	script := "#!/bin/sh\n\"" + goBinary + "\" \"$@\"\nstatus=$?\nsleep 5 &\nexit $status\n"
	if err := os.WriteFile(filepath.Join(shim, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	runner := gotool.Runner{Containment: &gotool.Containment{WaitDelay: 200 * time.Millisecond}}
	pkgDir := t.TempDir()
	roots, err := resolveRoots(context.Background(), nil, runner, pkgDir, pkgDir, env)
	if err != nil || roots.toolchain == "" {
		t.Fatalf("roots = %+v, %v; want the salvaged answer", roots, err)
	}
	// A torn document, a banner glued before the document, and a
	// document missing a key all refuse — the first two naming the hold.
	for _, wrapper := range []string{
		"#!/bin/sh\nprintf '{\"GOROOT\":'\nsleep 5 &\nexit 0\n",
		"#!/bin/sh\nprintf banner\n\"" + goBinary + "\" \"$@\"\nsleep 5 &\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(shim, "go"), []byte(wrapper), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveRoots(context.Background(), nil, runner, pkgDir, t.TempDir(), env); !errors.Is(err, exec.ErrWaitDelay) {
			t.Fatalf("wrapper %q = %v, want the hold named", wrapper, err)
		}
	}
	partial := "#!/bin/sh\necho '{\"GOROOT\":\"/r\",\"GOMODCACHE\":\"/m\"}'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(shim, "go"), []byte(partial), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveRoots(context.Background(), nil, runner, pkgDir, t.TempDir(), env); err == nil || !strings.Contains(err.Error(), "no GOCACHE") {
		t.Fatalf("a document missing a key = %v, want the key named", err)
	}
}

// usableGuardRoot degrades every unusable setting to no root — cost-only
// — and refuses ".." outright: lexical cleaning across a symlink can
// rebind the referent, the one spurious-admission risk this class
// carries.
func TestUsableGuardRoot(t *testing.T) {
	cases := map[string]string{
		"":                  "",
		"off":               "",
		"relative/root":     "",
		"/x/link/../y":      "",
		"/usr/lib/go/":      "/usr/lib/go",
		"/usr/lib//go":      "/usr/lib/go",
		"/usr/lib/./go":     "/usr/lib/go",
		"/home/u/go/pkgmod": "/home/u/go/pkgmod",
	}
	for in, want := range cases {
		if got := usableGuardRoot(in); got != want {
			t.Errorf("usableGuardRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

// A guard root inside, equal to, or containing the tree — in its given
// or resolved form — declares nothing: it would admit the tree's own
// content as guard-covered (REQ-inputs-guard-covered).
func TestUsableGuardRootOutsideTheTree(t *testing.T) {
	for _, tc := range []struct{ root, tree, want string }{
		{"/repo/.modcache", "/repo", ""},
		{"/repo", "/repo", ""},
		{"/", "/repo", ""},
		{"/home/u", "/home/u/repo", ""},
		{"/home/u/go/pkg/mod", "/home/u/repo", "/home/u/go/pkg/mod"},
		{"/repository", "/repo", "/repository"},
	} {
		if got := usableGuardRootOutside(tc.root, tc.tree); got != tc.want {
			t.Errorf("usableGuardRootOutside(%q, %q) = %q, want %q", tc.root, tc.tree, got, tc.want)
		}
	}
	tree := t.TempDir()
	link := filepath.Join(t.TempDir(), "into-tree")
	if err := os.Symlink(tree, link); err != nil {
		t.Fatal(err)
	}
	if got := usableGuardRootOutside(filepath.Join(link, "cache"), tree); got != "" {
		t.Errorf("a root resolving into the tree was kept: %q", got)
	}
	treeLink := filepath.Join(t.TempDir(), "tree-link")
	if err := os.Symlink(tree, treeLink); err != nil {
		t.Fatal(err)
	}
	if got := usableGuardRootOutside(filepath.Join(tree, "cache"), treeLink); got != "" {
		t.Errorf("a root inside the tree's resolved form was kept: %q", got)
	}
}

// usableTempRoot degrades an in-tree temp root in its given and its
// resolved form (REQ-inputs-ephemeral-root).
func TestUsableTempRoot(t *testing.T) {
	if got := usableTempRoot("/a/link/../y", "/repo"); got != "" {
		t.Errorf("parent traversal kept: %q", got)
	}
	if got := usableTempRoot("/repo/.tmp", "/repo"); got != "" {
		t.Errorf("tree-interior root kept: %q", got)
	}
	if got := usableTempRoot("/scratch/run/", "/repo"); got != "/scratch/run" {
		t.Errorf("usable root: got %q", got)
	}
	tree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tree, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "into-tree")
	if err := os.Symlink(tree, link); err != nil {
		t.Fatal(err)
	}
	if got := usableTempRoot(filepath.Join(link, "sub"), tree); got != "" {
		t.Errorf("resolved-interior root kept: %q", got)
	}
}

// The roots memo is one judged run's: through one Roots, three spellings
// of one package directory and two orderings of one environment pay one
// `go env -json`; PWD alone moves nothing; any other setting is a new
// entry; a nil memo pays every call. The counting shim execs the real
// go by its absolute path, so one probe is one count (a go wrapper that
// re-invoked `go` through PATH would count twice).
func TestRootsMemoizeForTheJudgedRun(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shim := t.TempDir()
	counter := filepath.Join(t.TempDir(), "count")
	script := "#!/bin/sh\necho x >> " + counter + "\nexec \"" + goBinary + "\" \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shim, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	spawns := func() int {
		data, _ := os.ReadFile(counter)
		return strings.Count(string(data), "x")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	reversed := append([]string(nil), env...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	memo := &Roots{}
	ctx := context.Background()
	for _, ask := range []struct {
		dir string
		env []string
	}{{dir, env}, {dir + "/x/..", env}, {link, env}, {dir, reversed}, {dir, gotool.SetEnv(env, "PWD", "/elsewhere")}} {
		roots, err := resolveRoots(ctx, memo, gotool.Runner{}, dir, ask.dir, ask.env)
		if err != nil || roots.toolchain == "" {
			t.Fatalf("resolve %s: %+v, %v", ask.dir, roots, err)
		}
	}
	if n := spawns(); n != 1 {
		t.Fatalf("%d probes for one coordinate and environment, want 1", n)
	}
	if _, err := resolveRoots(ctx, memo, gotool.Runner{}, dir, dir, gotool.SetEnv(env, "ZZZ_ROOTS_MEMO", "1")); err != nil {
		t.Fatal(err)
	}
	if n := spawns(); n != 2 {
		t.Fatalf("%d probes after a changed setting, want 2", n)
	}
	// Two package directories never share an entry.
	if _, err := resolveRoots(ctx, memo, gotool.Runner{}, dir, filepath.Join(dir, "x"), env); err != nil {
		t.Fatal(err)
	}
	if n := spawns(); n != 3 {
		t.Fatalf("%d probes after a second directory, want 3", n)
	}
	// A nil memo pays every call.
	for range 2 {
		if _, err := resolveRoots(ctx, nil, gotool.Runner{}, dir, dir, env); err != nil {
			t.Fatal(err)
		}
	}
	if n := spawns(); n != 5 {
		t.Fatalf("%d probes with a nil memo, want 5 (two unmemoized calls)", n)
	}
}

// The producer ingest reads the memo it carries: two observations
// through one Roots pay one probe; observations carrying none pay one
// each (REQ-inputs-producer-facade).
func TestProducerIngestReadsItsRootsMemo(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shim := t.TempDir()
	counter := filepath.Join(t.TempDir(), "count")
	script := "#!/bin/sh\necho x >> " + counter + "\nexec \"" + goBinary + "\" \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shim, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	root, pkgDir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	env := producerEnv(pkgDir)
	spawns := func() int {
		data, _ := os.ReadFile(counter)
		return strings.Count(string(data), "x")
	}
	observe := func(memo *Roots) {
		t.Helper()
		in := supportedIngest(t, frame, "worker", env)
		in.Roots = memo
		_, reason, err := frame.Observe(context.Background(), writeTestlog(t, ""), in)
		if err != nil || reason != "" {
			t.Fatalf("observe = reason %q, err %v", reason, err)
		}
	}
	before := spawns()
	memo := &Roots{}
	observe(memo)
	observe(memo)
	if n := spawns() - before; n != 1 {
		t.Fatalf("two observations through one memo paid %d probes, want 1", n)
	}
	observe(nil)
	observe(nil)
	if n := spawns() - before; n != 3 {
		t.Fatalf("two memo-less observations paid %d more probes, want 2 (total 3)", n-1)
	}
}

// bindingModule builds a module with a "data" root holding one recorded
// fixture, the smallest surface for value-binding construction tests.
func bindingModule(t *testing.T) string {
	t.Helper()
	moduleDir := filepath.Join(t.TempDir(), "mod")
	if err := os.MkdirAll(filepath.Join(moduleDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "fixture.txt"), []byte("recorded"), 0o644); err != nil {
		t.Fatal(err)
	}
	return moduleDir
}

// manifestReasons decodes a state's manifest and returns its unverifiable
// reasons.
func manifestReasons(t *testing.T, state State) []string {
	t.Helper()
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	return m.Unverifiable
}

// TestCompletedObservationRequiresBracket pins the
// REQ-inputs-completed-observation gate list: completed construction without
// an observation bracket, with a bracket capture did not produce, with one
// captured under a foreign module view, or with a duplicate bracket is a
// construction error, while incomplete construction stays bracketless.
func TestCompletedObservationRequiresBracket(t *testing.T) {
	moduleDir := bindingModule(t)
	log := []byte("open data/fixture.txt\n")
	if _, err := FromTestLog(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker")); err == nil || !strings.Contains(err.Error(), "observation bracket") {
		t.Fatalf("completed construction without a bracket = %v, want missing-bracket error", err)
	}
	if _, err := FromTestLog(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(Bracket{})); err == nil {
		t.Fatal("completed construction accepted a zero bracket")
	}
	foreign := testBracket(t, t.TempDir())
	if _, err := FromTestLog(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(foreign)); err == nil {
		t.Fatal("completed construction accepted a bracket captured under a foreign module view")
	}
	bracket := testBracket(t, moduleDir)
	if _, err := FromTestLog(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket), WithBracket(bracket)); err == nil {
		t.Fatal("completed construction accepted duplicate brackets")
	}
	if _, err := Incomplete(moduleDir, "worker", "interrupted", nil); err != nil {
		t.Fatalf("bracketless incomplete construction = %v, want success", err)
	}
}

// TestRunToIngestWindowMutationSealsObservationUnverifiable pins the
// run-to-ingest window of REQ-inputs-value-binding: an input edited between
// the producing run and observation construction moves the bracket, so the
// observation seals unverifiable naming the moved root, still constructs,
// converts, merges, and checks as unverifiable evidence, and is never bound.
func TestRunToIngestWindowMutationSealsObservationUnverifiable(t *testing.T) {
	moduleDir := bindingModule(t)
	bracket := testBracket(t, moduleDir, "data")
	log := []byte("open data/fixture.txt\n")
	// The edit between run and ingest: the value the run read is gone before
	// the manifest digest ever reads the file.
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "fixture.txt"), []byte("edited between run and ingest"), 0o644); err != nil {
		t.Fatal(err)
	}
	observation, err := FromTestLog(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatalf("moved-bracket observation did not construct: %v", err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable || !strings.Contains(state.Reason, "observation bracket moved: data") {
		t.Fatalf("window-mutated observation = %+v, want moved-root unverifiable", state)
	}
	current, err := ambientCurrentEnv(state.Manifest, moduleDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Unverifiable {
		t.Fatal("current check read a moved-bracket manifest as bound")
	}
	merged, err := Merge(moduleDir, nil, observation)
	if err != nil {
		t.Fatal(err)
	}
	if !merged.Unverifiable {
		t.Fatal("merge read a moved-bracket observation as bound")
	}
	converted, err := Absolute(observation, moduleDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !converted.Unverifiable {
		t.Fatal("absolute conversion read a moved-bracket observation as bound")
	}
}

// TestSymlinkTargetMutationOutsideRootSealsIdentityUncovered pins the
// symlink-escape disposition of REQ-inputs-value-binding: an identity
// lexically under a declared root whose object resolves outside every root is
// uncovered, never bound — the bracket's fingerprint pins only the symlink's
// target string, so a mutation of the out-of-root target leaves the bracket
// unchanged and resolution-based coverage is the only guard.
func TestSymlinkTargetMutationOutsideRootSealsIdentityUncovered(t *testing.T) {
	moduleDir := filepath.Join(t.TempDir(), "mod")
	for _, dir := range []string{"testdata", "fixtures"} {
		if err := os.MkdirAll(filepath.Join(moduleDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(moduleDir, "fixtures", "big.txt")
	if err := os.WriteFile(target, []byte("recorded"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "fixtures", "big.txt"), filepath.Join(moduleDir, "testdata", "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	bracket := testBracket(t, moduleDir, "testdata")
	// The out-of-root target mutates between run and ingest; the symlink's
	// target string — all the root fingerprint observes — is unchanged.
	if err := os.WriteFile(target, []byte("mutated after the run"), 0o644); err != nil {
		t.Fatal(err)
	}
	observation, err := FromTestLog([]byte("open testdata/link\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable {
		t.Fatalf("escaping identity sealed bound: %+v", state)
	}
	reasons := manifestReasons(t, state)
	joined := strings.Join(reasons, "\n")
	if !strings.Contains(joined, "runtime input not covered by observation bracket: testdata/link") {
		t.Fatalf("reasons = %q, want uncovered testdata/link", reasons)
	}
	for _, reason := range reasons {
		if strings.Contains(reason, "observation bracket moved") {
			t.Fatalf("unchanged bracket reported as moved: %q", reason)
		}
	}
}

// TestOutOfRootSymlinkChainSealsIdentityUncovered pins the chain leg of
// REQ-inputs-value-binding: an identity whose walk traverses a symlink
// residing outside every declared root is uncovered, never bound — the
// fingerprint records no target string for an out-of-root link, so a mid-span
// retarget between two in-root objects leaves the bracket unchanged while
// silently rebinding the identity. Both the file-link and the
// directory-component variants seal uncovered, naming the offending link.
func TestOutOfRootSymlinkChainSealsIdentityUncovered(t *testing.T) {
	moduleDir := bindingModule(t)
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "g.txt"), []byte("the other in-root object"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(moduleDir, "other"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(moduleDir, "other", "link")
	if err := os.Symlink(filepath.Join("..", "data", "fixture.txt"), link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Symlink("data", filepath.Join(moduleDir, "otherdir")); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir, "data")
	// Mid-span retarget of the out-of-root link between two in-root objects:
	// the bracket cannot see it, so only the chain check refuses the bind.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "data", "g.txt"), link); err != nil {
		t.Fatal(err)
	}
	observation, err := FromTestLog([]byte("open other/link\nopen otherdir/fixture.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable {
		t.Fatalf("out-of-root chain sealed bound: %+v", state)
	}
	reasons := manifestReasons(t, state)
	joined := strings.Join(reasons, "\n")
	if !strings.Contains(joined, "runtime input not covered by observation bracket: other/link") ||
		!strings.Contains(joined, "symlink outside every bracket root: ") ||
		!strings.Contains(joined, filepath.Join("other", "link")+")") {
		t.Fatalf("reasons = %q, want uncovered other/link naming the out-of-root link", reasons)
	}
	if !strings.Contains(joined, "runtime input not covered by observation bracket: otherdir/fixture.txt") ||
		!strings.Contains(joined, "otherdir)") {
		t.Fatalf("reasons = %q, want uncovered otherdir/fixture.txt naming the out-of-root directory link", reasons)
	}
	for _, reason := range reasons {
		if strings.Contains(reason, "observation bracket moved") {
			t.Fatalf("unchanged bracket reported as moved: %q", reason)
		}
	}
}

// TestInRootSymlinkChainStaysCoveredAndRetargetMovesBracket pins the positive
// side of the chain rule: a within-root link to a within-root target stays
// covered — its target string is in the root fingerprint — and retargeting it
// moves the bracket, which is exactly why the coverage is sound.
func TestInRootSymlinkChainStaysCoveredAndRetargetMovesBracket(t *testing.T) {
	moduleDir := bindingModule(t)
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "alt.txt"), []byte("alternate"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(moduleDir, "data", "link")
	if err := os.Symlink("fixture.txt", link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	bracket := testBracket(t, moduleDir, "data")
	observation, err := FromTestLog([]byte("open data/link\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Unverifiable || observation.Reason != "" {
		t.Fatalf("in-root link chain = %+v, want bound", observation.State)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("alt.txt", link); err != nil {
		t.Fatal(err)
	}
	unchanged, _, reason, err := bracket.revalidate(context.Background(), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged || reason == "" {
		t.Fatalf("in-root link retarget revalidated as unchanged (reason %q)", reason)
	}
}

// TestCoveredObservationBindsAsBefore pins the bound happy path of
// REQ-inputs-value-binding: with an unchanged bracket over the recorded
// roots, a completed observation seals bound exactly as before — including an
// absent input under a root, whose absence the root fingerprint pins.
func TestCoveredObservationBindsAsBefore(t *testing.T) {
	moduleDir := bindingModule(t)
	bracket := testBracket(t, moduleDir, "data")
	observation, err := FromTestLog([]byte("open data/fixture.txt\nopen data/ghost.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if state.Unverifiable || state.Reason != "" || !state.OK {
		t.Fatalf("covered observation = %+v, want bound", state)
	}
}

// TestOutOfRootReadSealsPerIdentityUncovered pins the uncovered-identity
// disposition of REQ-inputs-value-binding: coverage is per declared root,
// never inferred, and the unverifiable reason is per identity — the covered
// sibling in the same observation carries no disposition.
func TestOutOfRootReadSealsPerIdentityUncovered(t *testing.T) {
	moduleDir := bindingModule(t)
	if err := os.WriteFile(filepath.Join(moduleDir, "other.txt"), []byte("out of root"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir, "data")
	observation, err := FromTestLog([]byte("open data/fixture.txt\nopen other.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable {
		t.Fatalf("out-of-root read sealed bound: %+v", state)
	}
	joined := strings.Join(manifestReasons(t, state), "\n")
	if !strings.Contains(joined, "runtime input not covered by observation bracket: other.txt") {
		t.Fatalf("reasons = %q, want uncovered other.txt", joined)
	}
	if strings.Contains(joined, "data/fixture.txt") {
		t.Fatalf("covered identity carries a disposition: %q", joined)
	}
}

// TestExcludedIdentityObservedIsUncovered pins the exclusion leg of
// REQ-inputs-bracket-coverage: an excluded identity a run then observes is
// uncovered, never bound, and so is an identity resolving into the excluded
// subtree — the fingerprint does not observe the object it materializes to.
func TestExcludedIdentityObservedIsUncovered(t *testing.T) {
	moduleDir := bindingModule(t)
	if err := os.MkdirAll(filepath.Join(moduleDir, "data", "vol"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "vol", "scratch.txt"), []byte("volatile"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := "open data/fixture.txt\nopen data/vol/scratch.txt\n"
	spy := filepath.Join(moduleDir, "data", "spy")
	if err := os.Symlink(filepath.Join("vol", "scratch.txt"), spy); err == nil {
		log += "open data/spy\n"
	}
	bracket, err := ambientCaptureBracket(moduleDir, []string{"data"}, WithBracketExcludedPaths("data/vol"))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := FromTestLog([]byte(log), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable {
		t.Fatalf("excluded-identity observation sealed bound: %+v", state)
	}
	joined := strings.Join(manifestReasons(t, state), "\n")
	if !strings.Contains(joined, "runtime input not covered by observation bracket: data/vol/scratch.txt") {
		t.Fatalf("reasons = %q, want uncovered data/vol/scratch.txt", joined)
	}
	if strings.Contains(log, "data/spy") && !strings.Contains(joined, "runtime input not covered by observation bracket: data/spy") {
		t.Fatalf("reasons = %q, want uncovered data/spy resolving into the excluded subtree", joined)
	}
	if strings.Contains(joined, "data/fixture.txt") {
		t.Fatalf("covered identity carries a disposition: %q", joined)
	}
}

// TestBracketCaptureRefusalSealsObservationUnverifiable pins the
// capture-refusal propagation of REQ-inputs-value-binding: a bracket already
// unverifiable at capture seals the observation unverifiable naming the
// capture-refusal reason, while the observation still constructs.
func TestBracketCaptureRefusalSealsObservationUnverifiable(t *testing.T) {
	moduleDir := bindingModule(t)
	if err := os.Symlink(t.TempDir(), filepath.Join(moduleDir, "escape")); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir, "data", "escape")
	observation, err := FromTestLog([]byte("open data/fixture.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable || !strings.Contains(state.Reason, "observation bracket unverifiable: external directory input") {
		t.Fatalf("capture-refused bracket observation = %+v, want attributable unverifiable", state)
	}
}

// TestAbsoluteIdentityCoverageRequiresAbsoluteRoot pins the absolute-identity
// rule of REQ-inputs-value-binding: an absolute identity is covered only when
// it resolves under a declared absolute root's resolved path, else uncovered.
func TestAbsoluteIdentityCoverageRequiresAbsoluteRoot(t *testing.T) {
	moduleDir := bindingModule(t)
	external := filepath.Join(t.TempDir(), "ext.txt")
	if err := os.WriteFile(external, []byte("external"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := []byte("open " + external + "\n")
	covered, err := FromTestLog(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "data", external)))
	if err != nil {
		t.Fatal(err)
	}
	if covered.Unverifiable {
		t.Fatalf("absolute identity under its declared absolute root = %+v, want bound", covered.State)
	}
	uncovered, err := FromTestLog(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "data")))
	if err != nil {
		t.Fatal(err)
	}
	if !uncovered.Unverifiable || !strings.Contains(strings.Join(manifestReasons(t, uncovered.State), "\n"), "runtime input not covered by observation bracket: "+external) {
		t.Fatalf("rootless absolute identity = %+v, want uncovered", uncovered.State)
	}
	// Coverage is lexical-then-resolved from the covering root: an identity
	// lexically under no declared root is uncovered even when its resolution
	// lands under one — its own prefix chain is pinned by nothing.
	alias := filepath.Join(t.TempDir(), "alias.txt")
	if err := os.Symlink(external, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	aliased, err := FromTestLog([]byte("open "+alias+"\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "data", external)))
	if err != nil {
		t.Fatal(err)
	}
	if !aliased.Unverifiable {
		t.Fatalf("aliased identity resolving into a root = %+v, want uncovered", aliased.State)
	}
}

// TestAbsoluteRootThroughSymlinkedPrefixStaysCovered pins the walk frame of
// REQ-inputs-value-binding for absolute identities: the walk is read from the
// covering root's own resolved position, so a symlinked prefix above the root
// — a macOS /var or /tmp, a merged-usr Linux — never uncovers the identity.
// The root is follow-hashed through its full chain, so a prefix-link retarget
// already moves the root digest and needs no residence check.
func TestAbsoluteRootThroughSymlinkedPrefixStaysCovered(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "ext.txt"), []byte("external"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(base, "alias")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	aliased := filepath.Join(base, "alias", "ext.txt")
	moduleDir := bindingModule(t)
	bracket := testBracket(t, moduleDir, "data", aliased)
	observation, err := FromTestLog([]byte("open "+aliased+"\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Unverifiable || observation.Reason != "" {
		t.Fatalf("absolute identity behind a symlinked prefix = %+v, want bound", observation.State)
	}
}

// TestAbsoluteIdentitySubRootChainStaysEnforced pins the residence rule at or
// below an absolute covering root: an out-of-root link traversed below the
// covering root's position is invisible to every fingerprint, so the identity
// seals uncovered naming the link even when the endpoint resolves under a
// declared absolute root.
func TestAbsoluteIdentitySubRootChainStaysEnforced(t *testing.T) {
	rootDir := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(target, []byte("bound object"), 0o644); err != nil {
		t.Fatal(err)
	}
	// hop1 (under the declared directory root) → hop2 (under no root) → target.
	hop2 := filepath.Join(outside, "hop2")
	if err := os.Symlink(target, hop2); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	hop1 := filepath.Join(rootDir, "hop1")
	if err := os.Symlink(hop2, hop1); err != nil {
		t.Fatal(err)
	}
	moduleDir := bindingModule(t)
	// The directory root makes the bracket capture-unverifiable (external
	// directory), which is irrelevant here: the per-identity chain rule must
	// refuse independently.
	bracket := testBracket(t, moduleDir, rootDir, target)
	observation, err := FromTestLog([]byte("open "+hop1+"\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Unverifiable {
		t.Fatalf("sub-root out-of-root chain sealed bound: %+v", observation.State)
	}
	joined := strings.Join(manifestReasons(t, observation.State), "\n")
	if !strings.Contains(joined, "runtime input not covered by observation bracket: "+hop1) ||
		!strings.Contains(joined, "symlink outside every bracket root: "+hop2) {
		t.Fatalf("reasons = %q, want uncovered %s naming out-of-root link %s", joined, hop1, hop2)
	}
}

// bindingReasonObservations builds one observation per binding-reason class
// under one module view: a moved-bracket observation carrying the
// observation-level reason "observation bracket moved: data", an
// uncovered-identity observation carrying the per-identity reason
// "runtime input not covered by observation bracket: other.txt", and a bound
// sibling carrying no reason.
func bindingReasonObservations(t *testing.T, moduleDir string) (moved, uncovered, bound Observation) {
	t.Helper()
	movedBracket := testBracket(t, moduleDir, "data")
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "fixture.txt"), []byte("edited between run and ingest"), 0o644); err != nil {
		t.Fatal(err)
	}
	moved, err := FromTestLog([]byte("open data/fixture.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker-moved"), WithBracket(movedBracket))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "other.txt"), []byte("out of root"), 0o644); err != nil {
		t.Fatal(err)
	}
	uncovered, err = FromTestLog([]byte("open other.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker-uncovered"), WithBracket(testBracket(t, moduleDir, "data")))
	if err != nil {
		t.Fatal(err)
	}
	bound, err = FromTestLog([]byte("open data/fixture.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker-bound"), WithBracket(testBracket(t, moduleDir, "data")))
	if err != nil {
		t.Fatal(err)
	}
	if !moved.Unverifiable || !strings.Contains(strings.Join(manifestReasons(t, moved.State), "\n"), "observation bracket moved: data") {
		t.Fatalf("precondition: moved observation = %+v, want moved-bracket reason", moved.State)
	}
	if !uncovered.Unverifiable || !strings.Contains(strings.Join(manifestReasons(t, uncovered.State), "\n"), "runtime input not covered by observation bracket: other.txt") {
		t.Fatalf("precondition: uncovered observation = %+v, want uncovered-identity reason", uncovered.State)
	}
	if bound.Unverifiable || bound.Reason != "" {
		t.Fatalf("precondition: bound sibling = %+v, want bound", bound.State)
	}
	return moved, uncovered, bound
}

// TestBindingReasonsSurviveMergeUnion pins the merge leg of
// REQ-inputs-value-binding under the union clause of REQ-inputs-merge: the
// moved-bracket observation-level reason and the uncovered per-identity
// reason each appear verbatim in the merged manifest's unverifiable set, in
// either merge order, alongside a bound sibling — the merged union's
// unverifiable set contains every input's binding reasons, so merge never
// weakens a binding disposition (REQ-inputs-bracket-coverage).
func TestBindingReasonsSurviveMergeUnion(t *testing.T) {
	moduleDir := bindingModule(t)
	moved, uncovered, bound := bindingReasonObservations(t, moduleDir)
	merged, err := Merge(moduleDir, nil, moved, uncovered, bound)
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := Merge(moduleDir, nil, bound, uncovered, moved)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(merged, reversed) {
		t.Fatalf("binding-reason merge is not commutative:\n%+v\n%+v", merged, reversed)
	}
	got := map[string]bool{}
	for _, reason := range manifestReasons(t, merged.State) {
		got[reason] = true
	}
	for _, input := range []Observation{moved, uncovered, bound} {
		for _, reason := range manifestReasons(t, input.State) {
			if !got[reason] {
				t.Errorf("merge dropped binding reason %q", reason)
			}
		}
	}
	// The moved-bracket reason now carries its attribution suffix
	// (the moved member named), so the class match is by prefix; the
	// uncovered-input class stays verbatim.
	movedClass := false
	for reason := range got {
		if strings.HasPrefix(reason, "observation bracket moved: data") {
			movedClass = true
		}
	}
	if !movedClass || !got["runtime input not covered by observation bracket: other.txt"] {
		t.Fatalf("merged reasons = %v, want both binding classes", got)
	}
	if !merged.Unverifiable {
		t.Fatal("binding-unverifiable union merged as bound")
	}
}

// TestBindingReasonsSurviveAbsoluteConversion pins the conversion leg of
// REQ-inputs-value-binding under REQ-inputs-absolute-identities: absolute
// conversion carries both binding-reason classes into the converted manifest
// verbatim — path identities convert, recorded reasons never do — and the
// converted evidence stays unverifiable, never weakened.
func TestBindingReasonsSurviveAbsoluteConversion(t *testing.T) {
	moduleDir := bindingModule(t)
	moved, uncovered, _ := bindingReasonObservations(t, moduleDir)
	for name, observation := range map[string]Observation{
		"moved":     moved,
		"uncovered": uncovered,
	} {
		converted, err := Absolute(observation, moduleDir, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := map[string]bool{}
		for _, reason := range manifestReasons(t, converted.State) {
			got[reason] = true
		}
		for _, reason := range manifestReasons(t, observation.State) {
			if !got[reason] {
				t.Errorf("%s: absolute conversion dropped binding reason %q", name, reason)
			}
		}
		if !converted.Unverifiable {
			t.Fatalf("%s: absolute conversion weakened the binding disposition", name)
		}
	}
}

// TestBracketNeverWeakensDisposition pins the never-weakens clause of
// REQ-inputs-bracket-coverage as an example: an out-of-root stat's
// metadata seal stands identically with and without the bracket — the
// bracket only ever adds unverifiable reasons. A stat UNDER a declared
// root takes no seal at all (a parse-time admission, not a removal):
// the bracket fingerprint spans content and metadata, and the entry
// digest binds both thereafter (REQ-inputs-unbounded).
func TestBracketNeverWeakensDisposition(t *testing.T) {
	moduleDir := bindingModule(t)
	bracket := testBracket(t, moduleDir, "data")
	observation, err := FromTestLog([]byte("stat other.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Unverifiable || !strings.Contains(strings.Join(manifestReasons(t, observation.State), "\n"), "stat metadata input: other.txt") {
		t.Fatalf("out-of-root stat lost its seal under an unrelated bracket: %+v", observation.State)
	}

	inRoot, err := FromTestLog([]byte("stat data/fixture.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if inRoot.Unverifiable {
		t.Fatalf("declared-root stat sealed: %+v", inRoot.State)
	}
	if len(inRoot.State.Manifest) == 0 {
		t.Fatal("declared-root stat lost its manifest entry")
	}

	// The root's own identity is admitted exactly like its interior.
	rootItself, err := FromTestLog([]byte("stat data\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if rootItself.Unverifiable {
		t.Fatalf("declared root's own stat sealed: %+v", rootItself.State)
	}

	// An excluded subtree under a declared root is unspanned: its stat
	// keeps the attributing metadata seal.
	excluded, err := ambientCaptureBracket(moduleDir, []string{"data"}, WithBracketExcludedPaths("data/sub"))
	if err != nil {
		t.Fatal(err)
	}
	exObs, err := FromTestLog([]byte("stat data/sub/x.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(excluded))
	if err != nil {
		t.Fatal(err)
	}
	if !exObs.Unverifiable || !strings.Contains(strings.Join(manifestReasons(t, exObs.State), "\n"), "stat metadata input: data/sub/x.txt") {
		t.Fatalf("excluded-subtree stat lost its metadata seal: %+v", exObs.State)
	}
}
