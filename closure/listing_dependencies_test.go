package closure

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
	"github.com/greatliontech/gofresh/gotool"
)

func TestListingMemoRejectsRetypedSource(t *testing.T) {
	if testing.Short() {
		t.Skip("lists a module across an entry retype")
	}
	isolateProofCache(t)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":    "module example.com/retype\n\ngo 1.27\n",
		"p.go":      "package retype\nvar N = 7\nfunc F() int { return N }\n",
		"extra.go/": "",
	})
	env := listingEnv("", "off")
	snapshot := snapshotFor(t, dir, env)
	const pkg = "example.com/retype"
	first, n, h, err := listFrom(t, dir, pkg, env, snapshot)
	if err != nil || n != 1 {
		t.Fatalf("cold: %d %v", n, err)
	}
	original, err := h.maximalHash(pkg)
	if err != nil {
		t.Fatal(err)
	}
	control, n, _, err := listFrom(t, dir, pkg, env, snapshot)
	if err != nil || n != 0 || !reflect.DeepEqual(first, control) {
		t.Fatalf("warm control: %d %v", n, err)
	}
	if err := os.Remove(filepath.Join(dir, "extra.go")); err != nil {
		t.Fatal(err)
	}
	writeTree(t, dir, map[string]string{"extra.go": "package retype\nfunc init() { N = 17 }\n"})
	warm, n, h, err := listFrom(t, dir, pkg, env, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	warmHash, err := h.maximalHash(pkg)
	if err != nil {
		t.Fatal(err)
	}
	path, err := cachefile.Path(listingDirName, h.listingScope(), pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	cold, coldN, h, err := listFrom(t, dir, pkg, env, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	coldHash, err := h.maximalHash(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || coldN != 1 || !reflect.DeepEqual(warm, cold) || warmHash != coldHash || original == coldHash {
		t.Fatalf("retype: warm spawns=%d cold spawns=%d old=%s warm=%s cold=%s", n, coldN, original, warmHash, coldHash)
	}
}

func TestToolchainListingTracksPreviouslyEmptyEmbedDirectories(t *testing.T) {
	if testing.Short() {
		t.Skip("uses a controlled listing process")
	}
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	isolateProofCache(t)
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"src/strings/p.go":                  "package strings\nimport \"embed\"\n//go:embed testdata\nvar files embed.FS\n",
		"src/strings/testdata/one.txt":      "one",
		"src/strings/testdata/deep/empty/":  "",
		"src/unused/testdata/deep/data.txt": "unselected",
		"src/cmd/tool/p.go":                 "package main\n",
	})
	envFile, listingFile := filepath.Join(root, "env.json"), filepath.Join(root, "listing.json")
	writeJSON := func(path string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(envFile, map[string]string{"GOROOT": root, "GOVERSION": "go1.27.2"})
	pkg := listPkg{ImportPath: "strings", Standard: true, Dir: filepath.Join(root, "src", "strings"), GoFiles: []string{"p.go"}, EmbedFiles: []string{"testdata/one.txt"}, EmbedPatterns: []string{"testdata"}}
	writeJSON(listingFile, pkg)
	listings := 0
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		file := envFile
		if cmd.Args[1] == "list" {
			listings++
			file = listingFile
		}
		cmd.Path = "/bin/sh"
		cmd.Args = []string{"sh", "-c", "cat \"$1\"", "fixture", file}
	}}
	snapshot, err := runner.TakeEnvSnapshot(t.Context(), root, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	read := func() sourceDigests {
		t.Helper()
		d, err := toolchainSourceDigests(t.Context(), runner, root, os.Environ(), snapshot, nil)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	before := read()
	warm := read()
	if !reflect.DeepEqual(before, warm) {
		t.Fatal("unchanged selection moved")
	}
	if stampsTrusted && listings != 1 {
		t.Fatal("unchanged inventory failed to serve")
	}
	// These bytes are neither package discovery nor a selected embed input.
	writeTree(t, root, map[string]string{"src/unused/testdata/deep/data.txt": "changed", "src/cmd/tool/p.go": "package main\n// changed\n"})
	if again := read(); again.Content != before.Content || stampsTrusted && listings != 1 {
		t.Fatal("irrelevant test/tool bytes moved the selection memo")
	}
	writeTree(t, root, map[string]string{"src/strings/testdata/deep/empty/new.txt": "new"})
	pkg.EmbedFiles = append(pkg.EmbedFiles, "testdata/deep/empty/new.txt")
	writeJSON(listingFile, pkg)
	count := listings
	after := read()
	if listings != count+1 || after.Content == before.Content || after.Packages["strings"] == before.Packages["strings"] {
		t.Fatal("previously empty embed branch stayed invisible")
	}
}

func TestListingEntriesTrackSymlinkTargetKinds(t *testing.T) {
	dir, target := t.TempDir(), filepath.Join(t.TempDir(), "target")
	if err := os.Symlink(target, filepath.Join(dir, "input.go")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	read := func() listingEntry {
		t.Helper()
		entries, err := listingEntries(dir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("entries: %+v %v", entries, err)
		}
		return entries[0]
	}
	missing := read()
	if !missing.Dangling || missing.regular() {
		t.Fatalf("dangling: %+v", missing)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := read()
	if directory == missing || directory.Dangling || directory.regular() || directory.TargetType != os.ModeDir {
		t.Fatalf("directory: %+v", directory)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("package p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	regular := read()
	if regular == directory || regular == missing || !regular.regular() {
		t.Fatalf("regular: %+v", regular)
	}
	if again := read(); again != regular {
		t.Fatal("unchanged entry moved")
	}
}

func TestToolchainMemoRejectsIncompleteInventory(t *testing.T) {
	if testing.Short() {
		t.Skip("reads and corrupts a private standard-library memo")
	}
	if !stampsTrusted {
		t.Skip("this platform never serves the listing memo")
	}
	isolateProofCache(t)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/surface\n\ngo 1.27\n"})
	env := listingEnv("", "off")
	snapshot := snapshotFor(t, dir, env)
	flags := []string{"-tags=dup"}
	listings := 0
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 1 && cmd.Args[1] == "list" {
			listings++
		}
	}}
	read := func() sourceDigests {
		t.Helper()
		d, err := toolchainSourceDigests(t.Context(), runner, dir, env, snapshot, flags)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	original := read()
	stringsMemoKey := verifiedPackageMemoKey("strings", original.Packages["strings"])
	verifiedPackageMemo.Store(stringsMemoKey, verifiedPackageVerdict{OK: false})
	t.Cleanup(func() { verifiedPackageMemo.Delete(stringsMemoKey) })
	if toolchainSourceDegradation(snapshot.Value("GOVERSION"), original, nil).audited() {
		t.Fatal("unverified strings control unexpectedly admitted")
	}
	if again := read(); listings != 1 || !reflect.DeepEqual(again, original) {
		t.Fatal("valid unchanged memo did not serve")
	}
	scope := toolchainSourceScope(snapshot, flags, surfaceSeeds())
	path, err := cachefile.Path(sourceDigestsDirName, scope, "listing")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, corrupt := range map[string]func(*surfaceListing){
		"empty":              func(l *surfaceListing) { l.Packages = nil },
		"missing package":    func(l *surfaceListing) { l.Packages = l.Packages[1:] },
		"missing files":      func(l *surfaceListing) { l.Packages[0].Files = nil },
		"missing stamps":     func(l *surfaceListing) { l.Discovery[0].Entries = nil },
		"missing discovery":  func(l *surfaceListing) { l.Discovery = nil },
		"missing commitment": func(l *surfaceListing) { l.Integrity = "" },
		"admission label":    func(l *surfaceListing) { l.Packages[0].Audited = !l.Packages[0].Audited },
	} {
		t.Run(name, func(t *testing.T) {
			var envelope cachefile.Envelope
			if err := json.Unmarshal(data, &envelope); err != nil {
				t.Fatal(err)
			}
			var listing surfaceListing
			if err := json.Unmarshal(envelope.Payload, &listing); err != nil {
				t.Fatal(err)
			}
			corrupt(&listing)
			envelope.Payload, err = json.Marshal(listing)
			if err != nil {
				t.Fatal(err)
			}
			broken, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, broken, 0o600); err != nil {
				t.Fatal(err)
			}
			before := listings
			got := read()
			if listings != before+1 || !reflect.DeepEqual(got, original) || toolchainSourceDegradation(snapshot.Value("GOVERSION"), got, nil).audited() {
				t.Fatal("incomplete inventory served or changed admission")
			}
		})
	}
}
