package closure

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/gotool"
)

// writeTree materialises files under dir (directories created as
// needed; a path ending in "/" is an empty directory).
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for path, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if strings.HasSuffix(path, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// listingMemoModule writes a module whose view package imports a sibling
// carrying an embed tree (with an empty subdirectory), leaves a third
// package unimported, and carries an empty non-package directory the
// tests use as a working directory below the module root.
func listingMemoModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":           "module example.com/lm\n\ngo 1.26\n",
		"a/a.go":           "package a\n\nimport \"example.com/lm/b\"\n\nfunc F() int { return b.G() }\n",
		"b/b.go":           "package b\n\nimport \"embed\"\n\n//go:embed assets\nvar assets embed.FS\n\nfunc G() int {\n\tentries, _ := assets.ReadDir(\"assets\")\n\treturn len(entries)\n}\n",
		"b/assets/one.txt": "one\n",
		"b/assets/empty/":  "",
		"b/NOTES.md":       "notes\n",
		"c/c.go":           "package c\n\nfunc Unrelated() int { return 3 }\n",
		"deep/":            "",
	})
	return dir
}

const listingMemoPkg = "example.com/lm/a"

// listingEnv is a complete environment with the ambient Go settings the
// tests control removed, then set: no go env file, the given GOFLAGS,
// and GOWORK as given ("" lets the toolchain look for a workspace).
func listingEnv(goflags, gowork string) []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key == "GOENV" || key == "GOFLAGS" || key == "GOWORK" {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "GOENV=off", "GOFLAGS="+goflags, "GOWORK="+gowork)
}

// listFrom builds a Hasher over dir from snapshot and lists pkg,
// returning the listing, the number of toolchain spawns it paid, the
// Hasher, and the listing error if any.
func listFrom(t *testing.T, dir, pkg string, env []string, snapshot *gotool.EnvSnapshot, flags ...string) ([]listPkg, int, *Hasher, error) {
	t.Helper()
	h, err := NewAtContextEnvSnapshot(context.Background(), dir, env, snapshot, flags...)
	if err != nil {
		t.Fatal(err)
	}
	spawns := 0
	h.OnProgress(func(phase, _ string) {
		if phase == "list" {
			spawns++
		}
	})
	pkgs, err := h.list(pkg)
	return pkgs, spawns, h, err
}

func listOnce(t *testing.T, dir string, env []string, snapshot *gotool.EnvSnapshot, flags ...string) ([]listPkg, int, *Hasher) {
	t.Helper()
	pkgs, spawns, h, err := listFrom(t, dir, listingMemoPkg, env, snapshot, flags...)
	if err != nil {
		t.Fatal(err)
	}
	return pkgs, spawns, h
}

func snapshotFor(t *testing.T, dir string, env []string) *gotool.EnvSnapshot {
	t.Helper()
	snapshot, err := gotool.TakeEnvSnapshot(context.Background(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// A second Hasher over an unchanged tree serves the listing from the memo
// without a spawn, identical to the spawned one (REQ-closure-listing-memo).
func TestListingMemoServesTheListingWithoutASpawn(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the toolchain over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := listingMemoModule(t)
	env := listingEnv("", "")
	cold, spawns, _ := listOnce(t, dir, env, snapshotFor(t, dir, env))
	if spawns != 1 {
		t.Fatalf("cold listing paid %d spawns, want 1", spawns)
	}
	// A fresh snapshot, as every process takes its own: the scope must
	// render identically for one environment.
	warm, spawns, h := listOnce(t, dir, env, snapshotFor(t, dir, env))
	if spawns != 0 {
		t.Fatalf("warm listing paid %d spawns", spawns)
	}
	if !h.ServedSummary()["listing"][listingMemoPkg] {
		t.Fatalf("served summary lacks the listing: %v", h.ServedSummary())
	}
	if !reflect.DeepEqual(warm, cold) {
		t.Fatalf("served listing differs from the spawned one:\n got %+v\nwant %+v", warm, cold)
	}
	if len(h.fileDigests) == 0 {
		t.Fatal("verification recorded no file digests for the fold")
	}
	// A Hasher without a snapshot has no scope: it spawns.
	if _, spawns, _ := listOnce(t, dir, env, nil); spawns != 1 {
		t.Fatalf("snapshot-less listing paid %d spawns, want 1", spawns)
	}
}

// Every recorded input moves the memo: an edit or a new file in a listed
// package directory, a new file anywhere under an embed tree (an empty
// subdirectory included), a module-file edit, go.sum or a vendor
// manifest appearing, a workspace file appearing on the ancestor chain,
// a module file appearing between the working directory and the module
// root, and a changed flag set all refuse to serve; an edit outside the
// graph serves, and so does an edit to a non-source file in a listed
// directory (the listing reads its name, never its bytes); a flag naming a module file leaves the memo inert; a
// corrupt entry recomputes (REQ-closure-listing-memo).
func TestListingMemoKeyTracksEveryConsultedInput(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the toolchain over it")
	}
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	dir := listingMemoModule(t)
	// The working directory sits below the module root so the absence
	// of a module file between them is a recorded input.
	work := filepath.Join(dir, "deep")
	env := listingEnv("", "")
	snapshot := snapshotFor(t, work, env)
	listOnce(t, work, env, snapshot)
	appendTo := func(rel, text string) func() {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		original, err := os.ReadFile(full)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, append(append([]byte(nil), original...), []byte(text)...), 0o644); err != nil {
			t.Fatal(err)
		}
		return func() { os.WriteFile(full, original, 0o644) }
	}
	create := func(rel, text string) func() {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return func() { os.Remove(full) }
	}
	cases := []struct {
		name   string
		mutate func() func()
		serves bool
	}{
		{"edit inside a listed package", func() func() { return appendTo("b/b.go", "\n// edit\n") }, false},
		{"new file in a listed package", func() func() { return create("b/extra.go", "package b\n") }, false},
		{"new file under the embed tree", func() func() { return create("b/assets/two.txt", "two\n") }, false},
		{"new file in an empty embed subdirectory", func() func() { return create("b/assets/empty/new.txt", "new\n") }, false},
		{"module file edit", func() func() { return appendTo("go.mod", "\n// edit\n") }, false},
		{"go.sum appearing", func() func() { return create("go.sum", "") }, false},
		{"vendor manifest appearing", func() func() { return create("vendor/modules.txt", "") }, false},
		{"workspace file appearing", func() func() { return create("go.work", "go 1.26\n\nuse .\n") }, false},
		{"module file appearing below the root", func() func() { return create("deep/go.mod", "module example.com/deep\n\ngo 1.26\n") }, false},
		{"non-source file edit in a listed package", func() func() { return appendTo("b/NOTES.md", "more\n") }, true},
		{"edit outside the graph", func() func() { return appendTo("c/c.go", "\n// edit\n") }, true},
		{"new file outside the graph", func() func() { return create("c/extra.go", "package c\n") }, true},
	}
	for _, tc := range cases {
		restore := tc.mutate()
		_, spawns, _, err := listFrom(t, work, listingMemoPkg, env, snapshot)
		restore()
		served := err == nil && spawns == 0
		if served != tc.serves {
			t.Fatalf("%s: served=%t (spawns %d, err %v), want served=%t", tc.name, served, spawns, err, tc.serves)
		}
		// Re-store the pristine tree's listing for the next case.
		listOnce(t, work, env, snapshot)
	}
	if _, spawns, _ := listOnce(t, work, env, snapshot, "-tags=x"); spawns != 1 {
		t.Fatalf("a changed flag set paid %d spawns, want 1", spawns)
	}
	modfileEnv := listingEnv("-modfile=go.mod", "")
	modfileSnapshot := snapshotFor(t, dir, modfileEnv)
	listOnce(t, dir, modfileEnv, modfileSnapshot)
	if _, spawns, _ := listOnce(t, dir, modfileEnv, modfileSnapshot); spawns != 1 {
		t.Fatalf("a modfile flag left the memo active: %d spawns", spawns)
	}
	entries, _ := filepath.Glob(filepath.Join(cache, "gofresh", listingDirName, "*.json"))
	if len(entries) == 0 {
		t.Fatal("no listing entries persisted")
	}
	for _, e := range entries {
		if err := os.WriteFile(e, []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, spawns, _ := listOnce(t, work, env, snapshot); spawns != 1 {
		t.Fatalf("a corrupt entry served: %d spawns", spawns)
	}
}

// The module graph's files are inputs whether or not their module
// contributes a package: a workspace's every used module's go.mod, the
// workspace file itself, and the target of a local replacement the main
// module names all refuse to serve when edited (REQ-closure-listing-memo).
func TestListingMemoRecordsTheModuleGraphsFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("builds module fixtures and runs the toolchain over them")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"go.work":     "go 1.26\n\nuse (\n\t./a\n\t./b\n)\n",
		"a/go.mod":    "module example.com/wa\n\ngo 1.26\n",
		"a/a.go":      "package wa\n\nfunc F() int { return 1 }\n",
		"b/go.mod":    "module example.com/wb\n\ngo 1.26\n",
		"b/b.go":      "package wb\n\nfunc G() int { return 2 }\n",
		"rep/go.mod":  "module example.com/rep\n\ngo 1.26\n",
		"rep/r.go":    "package rep\n\nfunc R() int { return 3 }\n",
		"rep2/go.mod": "module example.com/rep2\n\ngo 1.26\n",
		"rep2/r.go":   "package rep2\n\nfunc R() int { return 4 }\n",
	})
	// The replacement is named by a's go.mod but no package of a imports
	// it: its module file is still a graph input.
	// a also replaces the used module b (the standalone-and-workspace
	// pattern), so b's module file is first recorded as a's replacement
	// target; b's own replacement of rep2 must still be scanned.
	if err := os.WriteFile(filepath.Join(root, "a", "go.mod"), []byte("module example.com/wa\n\ngo 1.26\n\nrequire (\n\texample.com/rep v0.0.0\n\texample.com/wb v0.0.0\n)\n\nreplace (\n\texample.com/rep => ../rep\n\texample.com/wb => ../b\n)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b", "go.mod"), []byte("module example.com/wb\n\ngo 1.26\n\nrequire example.com/rep2 v0.0.0\n\nreplace example.com/rep2 => ../rep2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "a")
	env := listingEnv("", "")
	snapshot := snapshotFor(t, work, env)
	if got := snapshot.Value("GOWORK"); got != filepath.Join(root, "go.work") {
		t.Fatalf("GOWORK = %q, want the fixture's workspace file", got)
	}
	list := func() (int, error) {
		_, spawns, _, err := listFrom(t, work, "example.com/wa", env, snapshot)
		return spawns, err
	}
	if spawns, err := list(); err != nil || spawns != 1 {
		t.Fatalf("cold listing: spawns %d, err %v", spawns, err)
	}
	if spawns, err := list(); err != nil || spawns != 0 {
		t.Fatalf("warm listing: spawns %d, err %v", spawns, err)
	}
	for _, rel := range []string{"b/go.mod", "go.work", "rep/go.mod", "rep2/go.mod"} {
		full := filepath.Join(root, filepath.FromSlash(rel))
		original, err := os.ReadFile(full)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, append(append([]byte(nil), original...), []byte("\n// edit\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
		spawns, err := list()
		if err := os.WriteFile(full, original, 0o644); err != nil {
			t.Fatal(err)
		}
		if err == nil && spawns == 0 {
			t.Fatalf("an edit to %s served the stale listing", rel)
		}
		list()
	}
	// A vendor manifest at the workspace root — where `go work vendor`
	// writes it — is a graph input too.
	if err := os.WriteFile(filepath.Join(root, "vendor", "modules.txt"), []byte(""), 0o644); err != nil {
		if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "vendor", "modules.txt"), []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if spawns, err := list(); err == nil && spawns == 0 {
		t.Fatal("a workspace vendor manifest appearing served the stale listing")
	}
}

// A main package whose module path ends in ".test" is a package like
// any other: its own directory is recorded, so a new file there refuses
// to serve — only the requested package's generated test main is
// scaffolding outside the model (REQ-closure-listing-memo).
func TestListingMemoRecordsADotTestModulesOwnDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the toolchain over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":     "module example.test\n\ngo 1.26\n",
		"main.go":    "package main\n\nimport \"example.test/lib\"\n\nfunc main() { _ = lib.L() }\n",
		"lib/lib.go": "package lib\n\nfunc L() int { return 1 }\n",
	})
	env := listingEnv("", "off")
	snapshot := snapshotFor(t, dir, env)
	if _, spawns, _, err := listFrom(t, dir, "example.test", env, snapshot); err != nil || spawns != 1 {
		t.Fatalf("cold: spawns %d, err %v", spawns, err)
	}
	if _, spawns, _, err := listFrom(t, dir, "example.test", env, snapshot); err != nil || spawns != 0 {
		t.Fatalf("warm: spawns %d, err %v", spawns, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extra.go"), []byte("package main\n\nimport _ \"net/http\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, spawns, _, err := listFrom(t, dir, "example.test", env, snapshot); err == nil && spawns == 0 {
		t.Fatal("a new file in the subject's own directory served the stale listing")
	}
}

// A vendored dependency carries no module directory: its tree is
// recorded as mutable-local source under the main module, every path in
// the record is absolute, and the listing serves from any process
// working directory (REQ-closure-listing-memo).
func TestListingMemoServesVendoredTreesFromAnyWorkingDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the toolchain over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":                        "module example.com/vm\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\n",
		"v.go":                          "package vm\n\nimport \"example.com/dep\"\n\nfunc V() int { return dep.D() }\n",
		"vendor/modules.txt":            "# example.com/dep v0.0.0\n## explicit; go 1.26\nexample.com/dep\n",
		"vendor/example.com/dep/dep.go": "package dep\n\nfunc D() int { return 1 }\n",
	})
	env := listingEnv("", "off")
	snapshot := snapshotFor(t, dir, env)
	if _, spawns, _, err := listFrom(t, dir, "example.com/vm", env, snapshot); err != nil || spawns != 1 {
		t.Fatalf("cold: spawns %d, err %v", spawns, err)
	}
	// The module root holds a go.mod: a working-directory-relative record
	// would resolve differently here and refuse.
	t.Chdir(dir)
	if _, spawns, _, err := listFrom(t, dir, "example.com/vm", env, snapshot); err != nil || spawns != 0 {
		t.Fatalf("warm from another working directory: spawns %d, err %v", spawns, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vendor", "example.com", "dep", "dep.go"), []byte("package dep\n\nfunc D() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, spawns, _, err := listFrom(t, dir, "example.com/vm", env, snapshot); err == nil && spawns == 0 {
		t.Fatal("an edit inside the vendor tree served the stale listing")
	}
}

// A listing whose inputs cannot be modelled — no main module contains
// the working directory — is never stored: every pass spawns
// (REQ-closure-listing-memo).
func TestListingMemoStoresNothingWithoutAMainModule(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the toolchain over a module-less directory")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	env := listingEnv("", "off")
	snapshot := snapshotFor(t, dir, env)
	for i := 0; i < 2; i++ {
		_, spawns, _, err := listFrom(t, dir, "fmt", env, snapshot)
		if err != nil || spawns != 1 {
			t.Fatalf("pass %d: spawns %d, err %v — a module-less listing was stored", i, spawns, err)
		}
	}
}

// The record's Go shape is part of the scope: a Hasher whose record type
// differs — as an older binary's would — never decodes this binary's
// entries, and the shape identity is a function of the type alone.
func TestListingScopeCarriesTheRecordShape(t *testing.T) {
	if listingShape != typeShape(reflect.TypeOf(listingRecord{})) {
		t.Fatal("shape identity is not a function of the record type")
	}
	type other struct {
		Version  int
		Files    map[string]string
		Dirs     map[string][]string
		Absent   []string
		Packages []listPkg
		Extra    string
	}
	if typeShape(reflect.TypeOf(other{})) == listingShape {
		t.Fatal("a record type with an extra field has the same shape identity")
	}
	h := &Hasher{snapshot: &gotool.EnvSnapshot{}, dir: "/x"}
	if !strings.Contains(h.listingScope(), "|"+listingShape+"|") {
		t.Fatalf("scope %q does not carry the shape", h.listingScope())
	}
}
