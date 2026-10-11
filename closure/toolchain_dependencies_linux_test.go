package closure

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
	"github.com/greatliontech/gofresh/gotool"
)

func isolatedToolchainSource(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "go")
	cmd := exec.CommandContext(t.Context(), "cp", "-a", "--reflink=auto", runtime.GOROOT(), root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copy: %s %v", out, err)
	}
	t.Setenv("GOROOT", root)
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	return root
}

func TestToolchainListingTracksFIPSAliasSelection(t *testing.T) {
	if testing.Short() {
		t.Skip("clones and retargets a supported FIPS source selection")
	}
	for _, linked := range []bool{false, true} {
		t.Run(map[bool]string{false: "directory", true: "symlink-root"}[linked], func(t *testing.T) {
			testFIPSAliasSelection(t, linked)
		})
	}
}

func testFIPSAliasSelection(t *testing.T, linked bool) {
	t.Helper()
	root := isolatedToolchainSource(t)
	if linked {
		path := filepath.Join(root, "lib", "fips140")
		outside := filepath.Join(t.TempDir(), "fips140")
		if err := os.Rename(path, outside); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOFIPS140", "inprocess")
	cache := t.TempDir()
	t.Setenv("GOMODCACHE", cache)
	t.Cleanup(func() {
		// Go normally makes extracted module directories read-only. They are
		// this fixture's private cache, so restore traversal/removal permissions.
		_ = filepath.WalkDir(cache, func(path string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				return os.Chmod(path, 0o700)
			}
			return err
		})
	})
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/fipsdep\n\ngo 1.27\n"})
	env := listingEnv("-modcacherw", "off")
	snapshot := snapshotFor(t, dir, env)
	read := func() sourceDigests {
		t.Helper()
		d, err := toolchainSourceDigests(t.Context(), gotool.Runner{}, dir, env, snapshot, nil)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	before := read()
	if again := read(); again.Content != before.Content {
		t.Fatal("unchanged FIPS selection moved")
	}
	alias := filepath.Join(root, "lib", "fips140", "inprocess.txt")
	if err := os.WriteFile(alias, []byte("v1.0.0-c2097c7c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	warm := read()
	path, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, surfaceSeeds()), "listing")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil && !(linked && os.IsNotExist(err)) {
		t.Fatal(err)
	}
	cold := read()
	if before.Content == cold.Content || warm.Content != cold.Content {
		t.Fatalf("FIPS retarget: before=%s warm=%s cold=%s", before.Content, warm.Content, cold.Content)
	}
}

func TestSubjectListingRefusesUninventoriedStandardPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs an explicitly importable symlinked standard package")
	}
	root := isolatedToolchainSource(t)
	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"p.go": "package exclusive\nfunc Value() int { return 7 }\n"})
	if err := os.Symlink(outside, filepath.Join(root, "src", "exclusive")); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/symlinkstd\n\ngo 1.27\n", "p.go": "package p\nimport \"exclusive\"\nfunc F() int { return exclusive.Value() }\n"})
	env := listingEnv("", "off")
	h, err := newAtEnv(t.Context(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := h.source.inventory["exclusive"]; found {
		t.Fatal("wildcard unexpectedly inventoried the symlink package")
	}
	if _, err := h.list("example.com/symlinkstd"); err == nil || !strings.Contains(err.Error(), "standard package exclusive is not covered") {
		t.Fatalf("missing source coverage: %v", err)
	}
	// A normal in-module target remains analyzable under the same inventory.
	writeTree(t, dir, map[string]string{"p.go": "package p\nfunc F() int { return 7 }\n"})
	h, err = newAtEnv(t.Context(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.list("example.com/symlinkstd"); err != nil {
		t.Fatal(err)
	}
}

func TestToolchainAdmissionNeedsEveryAuditedRoot(t *testing.T) {
	if testing.Short() {
		t.Skip("omits a required root from wildcard discovery")
	}
	root := isolatedToolchainSource(t)
	outside := filepath.Join(t.TempDir(), "ring")
	path := filepath.Join(root, "src", "container", "ring")
	if err := os.Rename(path, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	h, err := newAtEnv(t.Context(), t.TempDir(), listingEnv("", "off"))
	if err != nil {
		t.Fatal(err)
	}
	if _, found := h.source.inventory["container/ring"]; found {
		t.Fatal("fixture root was still reached by dependency enumeration")
	}
	if h.SelectionAudited() || h.ToolchainContent() != "" || !strings.Contains(h.SelectionNotice(), "required audited standard package container/ring") {
		t.Fatalf("missing audit root admitted: %s", h.SelectionNotice())
	}
}

func TestToolchainListingDoesNotCacheSymlinkSelectionInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("changes followed source and embed selection inputs")
	}
	for _, directoryLink := range []bool{false, true} {
		t.Run(map[bool]string{false: "excluded-file", true: "embedded-directory"}[directoryLink], func(t *testing.T) {
			root := isolatedToolchainSource(t)
			outside := t.TempDir()
			if directoryLink {
				writeTree(t, outside, map[string]string{
					"p.go":           "package stdembed\nimport \"embed\"\n//go:embed assets\nvar Files embed.FS\n",
					"assets/one.txt": "one", "assets/deep/empty/": "",
				})
				if err := os.Symlink(outside, filepath.Join(root, "src", "stdembed")); err != nil {
					t.Fatal(err)
				}
				writeTree(t, root, map[string]string{"src/anchor/p.go": "package anchor\nimport _ \"stdembed\"\n"})
			} else {
				writeTree(t, outside, map[string]string{"extra.go": "//go:build never\n\npackage strings\n"})
				if err := os.Symlink(filepath.Join(outside, "extra.go"), filepath.Join(root, "src", "strings", "extra.go")); err != nil {
					t.Fatal(err)
				}
			}
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{"go.mod": "module example.com/linkselection\n\ngo 1.27\n", "main.go": "package main\nimport (\"fmt\"; \"strings\")\nfunc main() { fmt.Print(strings.Compare(\"a\", \"a\")) }\n"})
			env := listingEnv("", "off")
			snapshot := snapshotFor(t, dir, env)
			listings := 0
			runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
				if cmd.Args[1] == "list" {
					listings++
				}
			}}
			read := func() sourceDigests {
				t.Helper()
				d, err := toolchainSourceDigests(t.Context(), runner, dir, env, snapshot, nil)
				if err != nil {
					t.Fatal(err)
				}
				return d
			}
			before := read()
			if again := read(); again.Content != before.Content {
				t.Fatal("unchanged symlink-bearing selection moved")
			}
			priorListings := listings
			if directoryLink {
				if _, present := before.inventory["stdembed"]; !present {
					t.Fatal("selected symlink package was absent")
				}
				writeTree(t, outside, map[string]string{"assets/deep/empty/new.txt": "new"})
			} else {
				writeTree(t, outside, map[string]string{"extra.go": "package strings\nfunc init() { panic(\"new selected initializer\") }\n"})
				cmd := exec.CommandContext(t.Context(), "go", "run", ".")
				cmd.Dir, cmd.Env = dir, env
				if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "new selected initializer") {
					t.Fatalf("fresh program missed selected initializer: %s %v", out, err)
				}
			}
			after := read()
			if after.Content == before.Content || listings != priorListings+1 {
				t.Fatal("changed symlink target did not move selection")
			}
			if priorListings != 2 {
				t.Fatal("symlink-bearing discovery served an unsupported memo")
			}
			path, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, surfaceSeeds()), "listing")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("unsupported discovery persisted: %v", err)
			}
		})
	}
}
