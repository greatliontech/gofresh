package runtimeinput

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func testDirs(t *testing.T) (string, string) {
	t.Helper()
	moduleDir := filepath.Join(t.TempDir(), "mod")
	packageDir := filepath.Join(moduleDir, "pkg")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return moduleDir, packageDir
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

	st, err := FromTestLog([]byte("# test log\ngetenv PEW_SECRET_TOKEN\n"), moduleDir, packageDir)
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

func TestFileDigestChanges(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	path := filepath.Join(packageDir, "fixture.txt")
	if err := os.WriteFile(path, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := FromTestLog([]byte("# test log\nopen fixture.txt\n"), moduleDir, packageDir)
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
	st, err := FromTestLog([]byte("# test log\nopen fixture.txt\n"), moduleDir, packageDir)
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
	st, err := FromTestLog([]byte("# test log\nopen data\n"), moduleDir, packageDir)
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
	st, err := FromTestLog([]byte("# test log\nopen later.txt\n"), moduleDir, packageDir)
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
	st, err := FromTestLog([]byte("# test log\nopen "+externalDir+"\n"), moduleDir, packageDir)
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
	st, err := FromTestLog([]byte("# test log\nstat fixture.txt\n"), moduleDir, packageDir)
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "stat metadata") {
		t.Fatalf("got unverifiable=%v reason=%q, want stat metadata", st.Unverifiable, st.Reason)
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

	st, err := FromTestLog([]byte("# test log\nopen data\n"), moduleDir, packageDir)
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
	st, err := FromTestLog([]byte("# test log\nopen data\n"), moduleDir, packageDir)
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "external directory") {
		t.Fatalf("got unverifiable=%v reason=%q, want external directory", st.Unverifiable, st.Reason)
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
	st, err := FromTestLog([]byte("open data.txt\n"), moduleDir, packageDir)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "external runtime input target") {
		t.Fatalf("state = %+v, want external target unverifiable", st)
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
	st, err := FromTestLog([]byte("open "+name+"\n"), moduleDir, packageDir)
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

	st, err := FromTestLog([]byte("# test log\nopen data\n"), linkModule, filepath.Join(linkModule, "pkg"))
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
	st, err := FromTestLog([]byte("# test log\nchdir sub\nopen fixture.txt\n"), moduleDir, packageDir)
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
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

func TestModuleRootDirectoryManifestIsValid(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(moduleDir, "fixture.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := FromTestLog([]byte("# test log\nopen ..\n"), moduleDir, packageDir)
	if err != nil {
		t.Fatalf("FromTestLog: %v", err)
	}
	if st.Unverifiable {
		t.Fatalf("module root directory marked unverifiable: %s", st.Reason)
	}
	cur, err := Current(st.Manifest, moduleDir)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if cur.Digest != st.Digest {
		t.Fatalf("module root digest changed without input change: %q vs %q", cur.Digest, st.Digest)
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
	a, err := FromTestLog([]byte("getenv MERGE_A\nopen a.txt\nunknown first\n"), moduleDir, packageDir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromTestLog([]byte("getenv MERGE_B\nopen b.txt\nbadline\n"), moduleDir, packageDir)
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

func TestMergeAlgebra(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	states := make([]State, 3)
	for i, log := range []string{"getenv C\n", "getenv A\n", "getenv B\n"} {
		var err error
		states[i], err = FromTestLog([]byte(log), moduleDir, packageDir)
		if err != nil {
			t.Fatal(err)
		}
	}
	merge := func(inputs ...State) State {
		t.Helper()
		st, err := Merge(moduleDir, inputs...)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	ab := merge(states[0], states[1])
	ba := merge(states[1], states[0])
	if ab != ba {
		t.Fatalf("merge is not commutative:\n%+v\n%+v", ab, ba)
	}
	aa := merge(states[0], states[0])
	if aa != states[0] {
		t.Fatalf("merge is not idempotent:\n%+v\n%+v", aa, states[0])
	}
	left := merge(ab, states[2])
	bc := merge(states[1], states[2])
	right := merge(states[0], bc)
	if left != right {
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
	if _, err := Merge(moduleDir, State{}); err == nil {
		t.Fatal("empty merge input accepted as observation-free manifest")
	}
}

func TestMergeRejectsChildThatMovedBeforeUnion(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	t.Setenv("MERGE_COHERENCE", "first")
	first, err := FromTestLog([]byte("getenv MERGE_COHERENCE\n"), moduleDir, packageDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MERGE_COHERENCE", "second")
	second, err := FromTestLog([]byte("getenv MERGE_COHERENCE\n"), moduleDir, packageDir)
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
		if _, err := Merge(moduleDir, state); err == nil {
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
	st, err := FromTestLog(log, moduleDir, packageDir)
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
	f.Fuzz(func(t *testing.T, a, b, c []byte) {
		moduleDir := t.TempDir()
		manifestFor := func(value []byte) State {
			t.Helper()
			token := base64.RawURLEncoding.EncodeToString(value)
			encoded, err := encode(manifest{
				Version:      manifestVersion,
				Env:          []string{"FUZZ_" + token},
				Paths:        []pathID{{Kind: pathRel, Path: "fuzz/x" + token}},
				Unverifiable: []string{"fuzz reason " + token},
			})
			if err != nil {
				t.Fatal(err)
			}
			state, err := Current(encoded, moduleDir)
			if err != nil {
				t.Fatal(err)
			}
			return state
		}
		merge := func(inputs ...State) State {
			t.Helper()
			st, err := Merge(moduleDir, inputs...)
			if err != nil {
				t.Fatal(err)
			}
			return st
		}
		ma, mb, mc := manifestFor(a), manifestFor(b), manifestFor(c)
		ab, ba := merge(ma, mb), merge(mb, ma)
		if ab != ba {
			t.Fatalf("commutativity: %+v != %+v", ab, ba)
		}
		if aa := merge(ma, ma); aa != merge(ma) {
			t.Fatalf("idempotence: %+v != %+v", aa, merge(ma))
		}
		left := merge(ab, mc)
		bc := merge(mb, mc)
		right := merge(ma, bc)
		if left != right {
			t.Fatalf("associativity: %+v != %+v", left, right)
		}
	})
}
