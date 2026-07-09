package runtimeinput

import (
	"encoding/base64"
	"os"
	"path/filepath"
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
	encoded, err := encode(manifest{Version: manifestVersion, Paths: []pathID{{Kind: pathRel, Path: "../secret.txt"}}})
	if err != nil {
		t.Fatal(err)
	}
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
		encoded, err := encode(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Current(encoded, moduleDir); err == nil {
			t.Fatalf("Current accepted malformed manifest: %+v", m)
		}
	}
}

func TestModuleRelPaths(t *testing.T) {
	enc, err := encode(manifest{
		Version: manifestVersion,
		Env:     []string{"PEW_X"},
		Paths: []pathID{
			{Kind: pathRel, Path: "data/fixture.txt"},
			{Kind: pathRel, Path: "a.txt"},
			{Kind: pathAbs, Path: "/etc/hosts"},
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
