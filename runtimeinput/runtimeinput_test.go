package runtimeinput

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

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

func TestCurrentContextHonorsCancellation(t *testing.T) {
	moduleDir := t.TempDir()
	state, err := Merge(moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CurrentEnvContext(ctx, state.Manifest, moduleDir, os.Environ()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled current check = %v, want context.Canceled", err)
	}
}

func TestCurrentContextStopsBetweenInputsAndFileChunks(t *testing.T) {
	moduleDir := t.TempDir()
	encoded, err := encode(manifest{Version: manifestVersion, Env: []string{"A", "B"}})
	if err != nil {
		t.Fatal(err)
	}
	envCtx := &cancelAfterChecks{Context: context.Background(), after: 3}
	if _, err := CurrentEnvContext(envCtx, encoded, moduleDir, []string{"A=1", "B=2"}); !errors.Is(err, context.Canceled) {
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
	if _, _, _, err := dirHash(dirCtx, moduleDir); !errors.Is(err, context.Canceled) {
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
	bracket, err := CaptureBracket(moduleDir, roots)
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
	incomplete, err := Incomplete(moduleDir, "worker", "test process timed out")
	if err != nil {
		t.Fatal(err)
	}
	if !incomplete.OK || !incomplete.Unverifiable || !strings.Contains(incomplete.Reason, "timed out") {
		t.Fatalf("Incomplete = %+v", incomplete)
	}
	empty, err := Merge(moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if incomplete.Manifest == empty.Manifest {
		t.Fatal("incomplete observation equals completed empty observation")
	}
	merged, err := Merge(moduleDir, empty, incomplete)
	if err != nil {
		t.Fatal(err)
	}
	if !merged.Unverifiable || !strings.Contains(merged.Reason, "timed out") {
		t.Fatalf("merged incomplete evidence = %+v", merged)
	}
	if _, err := Incomplete(moduleDir, "worker", " "); err == nil {
		t.Fatal("Incomplete accepted an empty reason")
	}
	for _, reason := range []string{"line\nbreak", "carriage\rreturn", "nul\x00byte", string([]byte{0xff})} {
		if _, err := Incomplete(moduleDir, "worker", reason); err == nil {
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
	a, err := FromTestLog([]byte("open a.txt\n"), moduleA, packageA, WithCompletedProcess("module-a"), WithBracket(testBracket(t, moduleA)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromTestLog([]byte("open b.txt\n"), moduleB, packageB, WithCompletedProcess("module-b"), WithBracket(testBracket(t, moduleB)))
	if err != nil {
		t.Fatal(err)
	}
	a, err = Absolute(a, moduleA)
	if err != nil {
		t.Fatal(err)
	}
	b, err = Absolute(b, moduleB)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := Merge(t.TempDir(), a, b)
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
	state, err := FromTestLog([]byte("open link\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable {
		t.Fatal("external symlink target was not unverifiable before conversion")
	}
	converted, err := Absolute(state, moduleDir)
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
	state, err = FromTestLog([]byte("open regular.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regular, []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Absolute(state, moduleDir); err == nil {
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

	st, err := FromTestLog([]byte("# test log\ngetenv PEW_SECRET_TOKEN\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
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

	same, err := Current(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current same: %v", err)
	}
	if same.Digest != st.Digest {
		t.Fatalf("same env digest = %q, want %q", same.Digest, st.Digest)
	}

	t.Setenv("PEW_SECRET_TOKEN", "second-secret")
	changed, err := Current(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current changed: %v", err)
	}
	if changed.Digest == st.Digest {
		t.Fatal("env value change did not move runtime digest")
	}
}

func TestCurrentEnvUsesSuppliedEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOWORK", "/ambient/workspace")
	env := []string{"GOWORK=/explicit/workspace"}
	state, err := FromTestLogEnv([]byte("getenv GOWORK\n"), dir, dir, env, WithCompletedProcess("worker"), WithBracket(testBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	current, err := CurrentEnv(state.Manifest, dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if current != state.State {
		t.Fatalf("explicitly finalized state moved under the same env:\n%+v\n%+v", state, current)
	}
	ambient, err := Current(state.Manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if ambient.Digest == state.Digest {
		t.Fatal("explicit GOWORK state was finalized from ambient GOWORK")
	}
	changed, err := CurrentEnv(state.Manifest, dir, []string{"GOWORK=/other/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	if changed == state.State || changed.Digest == state.Digest {
		t.Fatal("moving supplied GOWORK did not move the runtime-input state")
	}
}

func TestFromTestLogMarksPWDUnverifiable(t *testing.T) {
	dir := t.TempDir()
	state, err := FromTestLogEnv([]byte("getenv PWD\n"), dir, dir, []string{"PWD=/caller"}, WithCompletedProcess("worker"), WithBracket(testBracket(t, dir)))
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
	state, err := FromTestLogEnv([]byte("getenv GOWORK\nopen fixture.txt\n"), moduleDir, packageDir, env, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := AbsoluteEnv(state, moduleDir, env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Absolute(state, moduleDir); err == nil {
		t.Fatal("ambient Absolute accepted a state finalized under a different environment")
	}
	incomplete, err := IncompleteEnv(moduleDir, "worker-incomplete", "worker interrupted", env)
	if err != nil {
		t.Fatal(err)
	}
	mergeDir := t.TempDir()
	merged, err := MergeEnv(mergeDir, env, absolute, incomplete)
	if err != nil {
		t.Fatal(err)
	}
	current, err := CurrentEnv(merged.Manifest, mergeDir, env)
	if err != nil {
		t.Fatal(err)
	}
	if current != merged.State || !merged.Unverifiable {
		t.Fatalf("merged explicit-environment state = %+v, current = %+v", merged, current)
	}
	if _, err := Merge(mergeDir, absolute, incomplete); err == nil {
		t.Fatal("ambient Merge accepted states finalized under a different environment")
	}
	if _, err := MergeEnv(mergeDir, []string{"GOWORK=/other/workspace"}, absolute); err == nil {
		t.Fatal("MergeEnv accepted a state finalized under a different supplied environment")
	}
}

func TestAmbientConstructionWrappersMatchAmbientEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOWORK", "/ambient/workspace")
	env := os.Environ()
	fromAmbient, err := FromTestLog([]byte("getenv GOWORK\n"), dir, dir, WithCompletedProcess("worker"), WithBracket(testBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fromEnv, err := FromTestLogEnv([]byte("getenv GOWORK\n"), dir, dir, env, WithCompletedProcess("worker"), WithBracket(testBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromAmbient, fromEnv) {
		t.Fatalf("FromTestLog wrapper differs from ambient Env variant:\n%+v\n%+v", fromAmbient, fromEnv)
	}
	incompleteAmbient, err := Incomplete(dir, "worker-incomplete", "interrupted")
	if err != nil {
		t.Fatal(err)
	}
	incompleteEnv, err := IncompleteEnv(dir, "worker-incomplete", "interrupted", env)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(incompleteAmbient, incompleteEnv) {
		t.Fatal("Incomplete wrapper differs from ambient Env variant")
	}
	absoluteAmbient, err := Absolute(fromAmbient, dir)
	if err != nil {
		t.Fatal(err)
	}
	absoluteEnv, err := AbsoluteEnv(fromEnv, dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(absoluteAmbient, absoluteEnv) {
		t.Fatal("Absolute wrapper differs from ambient Env variant")
	}
	mergedAmbient, err := Merge(dir, absoluteAmbient, incompleteAmbient)
	if err != nil {
		t.Fatal(err)
	}
	mergedEnv, err := MergeEnv(dir, env, absoluteEnv, incompleteEnv)
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

	st, err := FromTestLog([]byte("# test log\nopen fixture.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if st.Unverifiable {
		t.Fatalf("regular module file marked unverifiable: %s", st.Reason)
	}
	if err := os.WriteFile(path, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := Current(st.Manifest, moduleDir)
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
	st, err := FromTestLog([]byte("# test log\nopen fixture.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	changed, err := Current(st.Manifest, moduleDir)
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
	st, err := FromTestLog([]byte("# test log\nopen data\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	changed, err := Current(st.Manifest, moduleDir)
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
	st, err := FromTestLog([]byte("# test log\nopen later.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if err := os.WriteFile(path, []byte("now here"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := Current(st.Manifest, moduleDir)
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
	st, err := FromTestLog([]byte("# test log\nopen "+externalDir+"\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "external directory") {
		t.Fatalf("got unverifiable=%v reason=%q, want external directory", st.Unverifiable, st.Reason)
	}
	same, err := Current(st.Manifest, moduleDir)
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
	path := filepath.Join(packageDir, "fixture.txt")
	if err := os.WriteFile(path, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := FromTestLog([]byte("# test log\nstat fixture.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "stat metadata") {
		t.Fatalf("got unverifiable=%v reason=%q, want stat metadata", st.Unverifiable, st.Reason)
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
	cur, err := Current(st.Manifest, moduleDir)
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

	st, err := FromTestLog([]byte("# test log\nopen data\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if st.Unverifiable {
		t.Fatalf("internal symlink dir marked unverifiable: %s", st.Reason)
	}
	if err := os.WriteFile(filepath.Join(target, "two.txt"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := Current(st.Manifest, moduleDir)
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
	st, err := FromTestLog([]byte("# test log\nopen data\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	// Construction records the module-escaping resolution as an uncovered
	// identity; the digest-time external-directory disposition holds on the
	// identity independently of bracket coverage.
	if !st.Unverifiable || !strings.Contains(st.Reason, "not covered by observation bracket: pkg/data") {
		t.Fatalf("got unverifiable=%v reason=%q, want uncovered escaping identity", st.Unverifiable, st.Reason)
	}
	current, err := Current(rawManifest(t, manifest{Version: manifestVersion, Paths: []pathID{{Kind: pathRel, Path: "pkg/data"}}}), moduleDir)
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
	st, err := FromTestLog([]byte("open data.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	// Construction records the module-escaping resolution as an uncovered
	// identity; the digest-time external-target disposition holds on the
	// identity independently of bracket coverage.
	if !st.Unverifiable || !strings.Contains(st.Reason, "not covered by observation bracket: pkg/data.txt") {
		t.Fatalf("state = %+v, want uncovered escaping identity", st)
	}
	current, err := Current(rawManifest(t, manifest{Version: manifestVersion, Paths: []pathID{{Kind: pathRel, Path: "pkg/data.txt"}}}), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Unverifiable || !strings.Contains(current.Reason, "external runtime input target") {
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
	st, err := FromTestLog([]byte("open "+name+"\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Current(st.Manifest, moduleDir); err != nil {
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

	st, err := FromTestLog([]byte("# test log\nopen data\n"), linkModule, filepath.Join(linkModule, "pkg"), WithCompletedProcess("worker"), WithBracket(testBracket(t, linkModule)))
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
	st, err := FromTestLog([]byte("# test log\nchdir sub\nopen fixture.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
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
	changed, err := Current(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if changed.Digest == st.Digest {
		t.Fatal("relative path after chdir did not track the target file")
	}
}

func TestRawParentTraversalIsUnverifiable(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(moduleDir, "fixture.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := FromTestLog([]byte("# test log\nopen ..\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "ambiguous parent traversal") {
		t.Fatalf("parent traversal observation = %+v, want ambiguous disposition", st)
	}
	cur, err := Current(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if cur.Digest != st.Digest {
		t.Fatalf("module root digest changed without input change: %q vs %q", cur.Digest, st.Digest)
	}
}

func TestSymlinkParentTraversalIsUnverifiable(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(packageDir, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	st, err := FromTestLog([]byte("open link/../fixture.txt\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
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
	st, err := FromTestLog([]byte("chdir .\nopen "+absolute+"\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
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
	encoded := rawManifest(t, manifest{Version: manifestVersion, Paths: []pathID{{Kind: pathRel, Path: "../secret.txt"}}})
	if _, err := Current(encoded, moduleDir); err == nil {
		t.Fatal("Current accepted a relative path escaping the module")
	}
}

func TestCurrentRejectsMalformedManifestIdentities(t *testing.T) {
	moduleDir, _ := testDirs(t)
	for _, m := range []manifest{
		{Version: manifestVersion, Env: []string{"BAD\nNAME"}},
		{Version: manifestVersion, Paths: []pathID{{Kind: pathRel, Path: "bad\npath"}}},
		{Version: manifestVersion, Paths: []pathID{{Kind: pathAbs, Path: "relative"}}},
	} {
		encoded := rawManifest(t, m)
		if _, err := Current(encoded, moduleDir); err == nil {
			t.Fatalf("Current accepted malformed manifest: %+v", m)
		}
	}
}

func TestModuleRelPaths(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "hosts")
	enc, err := encode(manifest{
		Version: manifestVersion,
		Env:     []string{"PEW_X"},
		Paths: []pathID{
			{Kind: pathRel, Path: "data/fixture.txt"},
			{Kind: pathRel, Path: "a.txt"},
			{Kind: pathAbs, Path: abs},
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
		Paths: []pathID{
			{Kind: pathAbs, Path: external},
			{Kind: pathRel, Path: "fixtures/input.txt"},
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
	a, err := FromTestLog([]byte("getenv MERGE_A\nopen a.txt\nunknown first\n"), moduleDir, packageDir, WithCompletedProcess("worker-a"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromTestLog([]byte("getenv MERGE_B\nopen b.txt\nbadline\n"), moduleDir, packageDir, WithCompletedProcess("worker-b"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}

	merged, err := Merge(moduleDir, a, b)
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(merged.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.Env, ","); got != "MERGE_A,MERGE_B" {
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
	changed, err := Current(merged.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Digest == merged.Digest {
		t.Fatal("change to second process input did not move merged digest")
	}
}

func TestCompletedObservationRequiresProcessAssertion(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if _, err := FromTestLog([]byte("getenv HOME\n"), moduleDir, packageDir); err == nil {
		t.Fatal("completed log accepted without process assertion")
	}
	for _, process := range []string{"", "line\nbreak", "nul\x00byte", string([]byte{0xff})} {
		if _, err := FromTestLog([]byte("getenv HOME\n"), moduleDir, packageDir, WithCompletedProcess(process), WithBracket(testBracket(t, moduleDir))); err == nil {
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
			observation, err := FromTestLog(log, moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
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
	first, err := FromTestLog([]byte("getenv HOME\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Incomplete(moduleDir, "worker", "worker interrupted")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Merge(moduleDir, first, second); err == nil {
		t.Fatal("conflicting evidence for one process was merged")
	}
}

func TestProducerOperationsRejectRecomputedState(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	state, err := Current(rawManifest(t, manifest{Version: manifestVersion}), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	forged := Observation{State: state}
	if _, err := Merge(moduleDir, forged); err == nil {
		t.Fatal("merge accepted checker-recomputed state")
	}
	if _, err := Absolute(forged, moduleDir); err == nil {
		t.Fatal("absolute conversion accepted checker-recomputed state")
	}
	if _, err := Dirty(forged, moduleDir, "commit", fakeInspector{}); err == nil {
		t.Fatal("dirty inspection accepted checker-recomputed state")
	}
	valid, err := FromTestLog([]byte("getenv HOME\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	valid.State = state
	if _, err := Merge(moduleDir, valid); err == nil {
		t.Fatal("merge accepted transplanted state under genuine provenance")
	}
	if _, err := Absolute(valid, moduleDir); err == nil {
		t.Fatal("absolute conversion accepted transplanted state under genuine provenance")
	}
	if _, err := Dirty(valid, moduleDir, "commit", fakeInspector{}); err == nil {
		t.Fatal("dirty inspection accepted transplanted state under genuine provenance")
	}
}

func TestMergeRejectsRelativeAndAbsoluteEvidenceForOneProcess(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "fixture"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	relative, err := FromTestLog([]byte("open fixture\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := Absolute(relative, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Merge(moduleDir, relative, absolute); err == nil {
		t.Fatal("relative and absolute evidence for one process were merged")
	}
	absoluteAgain, err := Absolute(absolute, moduleDir)
	if err != nil || !reflect.DeepEqual(absoluteAgain, absolute) {
		t.Fatalf("absolute conversion is not idempotent: %+v != %+v, err=%v", absoluteAgain, absolute, err)
	}
}

func TestAbsolutePreservesCompletedVersusIncompleteOrigin(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	completed, err := FromTestLog([]byte("\n"), moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	incomplete, err := Incomplete(moduleDir, "worker", "malformed testlog line")
	if err != nil {
		t.Fatal(err)
	}
	completed, err = Absolute(completed, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	incomplete, err = Absolute(incomplete, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != incomplete.State {
		t.Fatalf("test precondition failed: completed=%+v incomplete=%+v", completed.State, incomplete.State)
	}
	if _, err := Merge(moduleDir, completed, incomplete); err == nil {
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
	a, err := FromTestLog([]byte("open a\n"), moduleDir, packageDir, WithCompletedProcess("worker-a"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromTestLog([]byte("open b\n"), moduleDir, packageDir, WithCompletedProcess("worker-b"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	whole, err := Merge(moduleDir, a, b)
	if err != nil {
		t.Fatal(err)
	}
	whole, err = Absolute(whole, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	a, err = Absolute(a, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Merge(moduleDir, whole, a); err != nil {
		t.Fatalf("unrelated process changed absolute view for worker-a: %v", err)
	}
}

func TestMergeAlgebra(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	states := make([]Observation, 3)
	for i, log := range []string{"getenv C\n", "getenv A\n", "getenv B\n"} {
		var err error
		states[i], err = FromTestLog([]byte(log), moduleDir, packageDir, WithCompletedProcess(fmt.Sprintf("worker-%d", i)), WithBracket(testBracket(t, moduleDir)))
		if err != nil {
			t.Fatal(err)
		}
	}
	merge := func(inputs ...Observation) Observation {
		t.Helper()
		st, err := Merge(moduleDir, inputs...)
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
	st, err := Merge(moduleDir)
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
	if _, err := Merge(moduleDir, Observation{}); err == nil {
		t.Fatal("empty merge input accepted as observation-free manifest")
	}
	nested, err := Merge(moduleDir, st)
	if err != nil || !reflect.DeepEqual(nested, st) {
		t.Fatalf("nested zero merge = %+v, %v; want identity", nested, err)
	}
}

func TestMergeRejectsChildThatMovedBeforeUnion(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	t.Setenv("MERGE_COHERENCE", "first")
	first, err := FromTestLog([]byte("getenv MERGE_COHERENCE\n"), moduleDir, packageDir, WithCompletedProcess("worker-a"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MERGE_COHERENCE", "second")
	second, err := FromTestLog([]byte("getenv MERGE_COHERENCE\n"), moduleDir, packageDir, WithCompletedProcess("worker-b"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Merge(moduleDir, first, second); err == nil {
		t.Fatal("merge accepted child states finalized under different input values")
	}
}

func TestMergeRejectsMalformedAndUnsupportedManifest(t *testing.T) {
	moduleDir, _ := testDirs(t)
	for _, raw := range []string{
		`{"v":1,"future":true}`,
		`{"v":2}`,
	} {
		state := State{
			Manifest: base64.RawURLEncoding.EncodeToString([]byte(raw)),
			Digest:   "supplied",
			OK:       true,
		}
		if _, err := Merge(moduleDir, newObservation(state, "worker", "complete")); err == nil {
			t.Fatalf("Merge accepted %s", raw)
		}
	}
}

func TestManifestEncodingIsCanonical(t *testing.T) {
	got, err := encode(manifest{
		Version: manifestVersion,
		Env:     []string{"B", "A", "B"},
		Paths: []pathID{
			{Kind: pathRel, Path: "z"},
			{Kind: pathRel, Path: "z"},
		},
		Unverifiable: []string{"z", "a", "z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantJSON := `{"v":1,"env":["A","B"],"paths":[{"k":"rel","p":"z"}],"unverifiable":["a","z"]}`
	want := base64.RawURLEncoding.EncodeToString([]byte(wantJSON))
	if got != want {
		decoded, _ := base64.RawURLEncoding.DecodeString(got)
		t.Fatalf("encoding = %q (%s), want %q", got, decoded, want)
	}
}

func TestManifestDecoderRejectsUnknownAndTrailingData(t *testing.T) {
	moduleDir, _ := testDirs(t)
	for _, raw := range []string{
		`{"v":1,"future":true}`,
		`{"v":1} {"v":1}`,
		`{"v":1,"paths":[{"k":"rel","p":"tracked"}],"paths":[]}`,
		`{"V":1}`,
	} {
		encoded := base64.RawURLEncoding.EncodeToString([]byte(raw))
		if _, err := Current(encoded, moduleDir); err == nil {
			t.Fatalf("Current accepted non-v1 manifest %s", raw)
		}
	}
}

func TestNonUTF8ObservedPathIsUnverifiable(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	log := append([]byte("open "), 0xff)
	log = append(log, '\n')
	st, err := FromTestLog(log, moduleDir, packageDir, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable || st.Reason != "non-UTF-8 runtime input path" {
		t.Fatalf("state = %+v, want non-UTF-8 path unverifiable", st)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 0 {
		t.Fatalf("manifest normalized invalid path into %+v", m.Paths)
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
				Env:          []string{"FUZZ_" + token},
				Paths:        []pathID{{Kind: pathRel, Path: "fuzz/x" + token}},
				Unverifiable: unverifiable,
			})
			if err != nil {
				t.Fatal(err)
			}
			state, err := Current(encoded, moduleDir)
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
			st, err := Merge(moduleDir, inputs...)
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
		if _, err := Merge(moduleDir, Observation{State: ma.State}); err == nil {
			t.Fatal("merge accepted a completed state without construction provenance")
		}
	})
}
