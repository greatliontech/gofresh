package closure

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure/internal/listing"
	"github.com/greatliontech/gofresh/closure/internal/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

func TestPropHashFilesSensitive(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package p\n")
	write("b.go", "package p\nvar X = 1\n")

	h1, err := hashFiles(dir, []string{"a.go", "b.go"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(h1) != 32 {
		t.Errorf("hash len: got %d", len(h1))
	}

	// Order-insensitive (files sorted internally).
	if h2, _ := hashFiles(dir, []string{"b.go", "a.go"}, nil); h2 != h1 {
		t.Errorf("hash not order-insensitive: %q vs %q", h1, h2)
	}

	// Content change ⇒ different hash (REQ-closure-mutable-local / REQ-closure-coverage at the file level).
	write("b.go", "package p\nvar X = 2\n")
	if h3, _ := hashFiles(dir, []string{"a.go", "b.go"}, nil); h3 == h1 {
		t.Error("hash insensitive to content change")
	}

	// Missing file ⇒ error, never silently skipped.
	if _, err := hashFiles(dir, []string{"missing.go"}, nil); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestContribution(t *testing.T) {
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}

	// Excluded: stdlib, pseudo-package, synthesized test main.
	for _, p := range []listPkg{
		{ImportPath: "fmt", Standard: true},
		{ImportPath: "C"},
		{ImportPath: "example/x.test", Name: "main", Module: &listMod{Main: true}},
	} {
		if c, err := h.contributionFor("example/x", p); err != nil || c != "" {
			t.Errorf("contribution(%s): got %q, %v; want \"\"", p.ImportPath, c, err)
		}
	}

	// An ordinary importable package may legitimately end in .test.
	dotTestDir := t.TempDir()
	writeFile(t, dotTestDir, "dep.go", "package dep\nconst Value = 1\n")
	dotTest, err := h.contribution(listPkg{
		ImportPath: "example/dep.test", Name: "dep", Dir: dotTestDir,
		GoFiles: []string{"dep.go"}, Module: &listMod{Main: true, Dir: dotTestDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dotTest, "src:example/dep.test=") {
		t.Fatalf("ordinary .test package contribution = %q", dotTest)
	}
	commandDotTestDir := t.TempDir()
	writeFile(t, commandDotTestDir, "main.go", "package main\nfunc F() int { return 1 }\n")
	commandDotTest, err := h.contributionFor("example/root", listPkg{
		ImportPath: "example/tool.test", Name: "main", Dir: commandDotTestDir,
		GoFiles: []string{"main.go"}, Module: &listMod{Main: true, Dir: commandDotTestDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(commandDotTest, "src:example/tool.test=") {
		t.Fatalf("ordinary command .test package contribution = %q", commandDotTest)
	}

	// Cache dep (classified on the package Dir under GOMODCACHE): pinned by
	// modpath@version, no file read.
	modDir := filepath.FromSlash("/gomodcache/golang.org/x/tools@v0.46.0")
	c, err := h.contribution(listPkg{
		ImportPath: "golang.org/x/tools/go/ssa",
		Dir:        filepath.Join(modDir, "go", "ssa"),
		Module:     &listMod{Path: "golang.org/x/tools", Version: "v0.46.0", Dir: modDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c, "cache:") || !strings.Contains(c, "golang.org/x/tools@v0.46.0") {
		t.Errorf("cache contribution: %q", c)
	}

	// Vendored dep (Dir outside the cache, Module.Dir empty, not Main) is
	// mutable-local → hashed by content (REQ-closure-mutable-local), not pinned.
	vdir := t.TempDir()
	if err := os.WriteFile(filepath.Join(vdir, "v.go"), []byte("package v\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err = h.contribution(listPkg{
		ImportPath: "vendored/dep", Dir: vdir, GoFiles: []string{"v.go"},
		Module: &listMod{Path: "vendored/dep", Version: "v1.0.0"}, // Dir empty (vendored)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c, "src:vendored/dep=") {
		t.Errorf("vendored dep should hash by content, got %q", c)
	}

	// Main module: hashed by content.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte("package p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err = h.contribution(listPkg{
		ImportPath: "example/p", Dir: dir, GoFiles: []string{"x.go"},
		Module: &listMod{Main: true, Dir: dir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c, "src:example/p=") {
		t.Errorf("src contribution: %q", c)
	}
}

// TestAssemblyPackageHashesWholeDirectory pins the conservative contract for
// assembly-bearing mutable-local packages (REQ-closure-blindspot): the package
// contributes its whole directory, so an edit to ANY file in the directory —
// a header an .s file includes, or a file no build list names — moves the
// contribution, and so the maximal hash the subject widens to.
func TestAssemblyPackageHashesWholeDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "defs.inc", "#define RETVAL $1\n")
	writeFile(t, dir, "asm.s", "#include \"defs.inc\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tMOVQ RETVAL, AX\n\tRET\n")
	writeFile(t, dir, "unlisted.txt", "v1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{ImportPath: "example/p", Dir: dir, SFiles: []string{"asm.s"}, Module: &listMod{Main: true, Dir: dir}}
	base, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution: %v", err)
	}
	writeFile(t, dir, "defs.inc", "#define RETVAL $2\n")
	afterInclude, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after include edit: %v", err)
	}
	if afterInclude == base {
		t.Fatalf("asm include edit did not change contribution: %q", base)
	}
	writeFile(t, dir, "unlisted.txt", "v2\n")
	afterUnlisted, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after unlisted-file edit: %v", err)
	}
	if afterUnlisted == afterInclude {
		t.Fatalf("edit to a file no build list names did not change contribution: %q", afterInclude)
	}
	writeFile(t, dir, "extra.h", "#define EXTRA 1\n")
	afterNew, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after new file: %v", err)
	}
	if afterNew == afterUnlisted {
		t.Fatalf("new file in the package directory did not change contribution: %q", afterUnlisted)
	}
}

// TestAssemblyUnresolvedIncludeHashesWholeDirectory: includes in non-toolchain
// assembly are no longer resolved — an include naming a missing file or an
// absolute path outside the package directory is not an error and is not
// separately tracked. The package hashes its whole directory and every subject
// reaching it is unverifiable via the non-standard-assembly effect
// (REQ-closure-blindspot downgrade arm), so outside-directory content can
// never silently narrow a verdict.
func TestAssemblyUnresolvedIncludeHashesWholeDirectory(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	writeFile(t, outside, "defs.inc", "#define RETVAL $1\n")
	writeFile(t, dir, "asm.s", "#include \"missing.inc\"\n#include \""+filepath.ToSlash(filepath.Join(outside, "defs.inc"))+"\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tRET\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{ImportPath: "example/p", Dir: dir, SFiles: []string{"asm.s"}, Module: &listMod{Main: true, Dir: dir}}
	base, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution with unresolved includes: %v", err)
	}
	if !strings.HasPrefix(base, "src:example/p=") {
		t.Fatalf("contribution = %q, want src:example/p=", base)
	}
	writeFile(t, dir, "asm.s", "#include \"missing.inc\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tRET\n")
	edited, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after in-dir edit: %v", err)
	}
	if edited == base {
		t.Fatalf("in-dir asm edit did not change contribution: %q", base)
	}
}

func TestContributionCgoCallbackHashesPackageFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "include"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"include/cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, filepath.Join("include", "cfg.h"), "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: dir},
	}
	one, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution: %v", err)
	}
	writeFile(t, dir, filepath.Join("include", "cfg.h"), "#define N 2\n")
	two, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after include edit: %v", err)
	}
	if one == two {
		t.Fatalf("cgo nested header edit did not change contribution: %q", one)
	}
}

func TestContributionCgoOutsideIncludeRootFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	outside := filepath.Join(root, "cfg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, outside, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CgoCFLAGS:  []string{"-I${SRCDIR}/../cfg"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include root outside package dir") {
		t.Fatalf("contribution error = %v, want cgo include root outside package dir", err)
	}
}

func TestContributionCgoRelativeIncludeEscapeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"../cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

// TestContributionCgoSystemIncludeSkipped: a system/toolchain header not found in
// the package's in-tree search space is build environment (REQ-closure-coverage) — covered by the
// toolchain and machine guards within the single-machine scope — so it is skipped
// rather than failing closed, both for quoted (`"stdio.h"`) and angle-bracket
// (`<stdio.h>`, `<sys/types.h>`) forms. The package's own C source is still hashed.
func TestContributionCgoSystemIncludeSkipped(t *testing.T) {
	for _, inc := range []string{`"stdio.h"`, `<stdio.h>`, `<sys/types.h>`} {
		t.Run(inc, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
			writeFile(t, dir, "bridge.c", "#include "+inc+"\nvoid bridge(void) { GoCallback(); }\n")
			h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
			pkg := listPkg{
				ImportPath: "example/cgocallback",
				Dir:        dir,
				CgoFiles:   []string{"cg.go"},
				CFiles:     []string{"bridge.c"},
				Module:     &listMod{Main: true, Dir: dir},
			}
			got, err := h.contribution(pkg)
			if err != nil {
				t.Fatalf("contribution: %v, want system include skipped", err)
			}
			if got == "" {
				t.Fatal("contribution empty; want package source hashed")
			}
			// The package's own C source must still be hashed: editing bridge.c moves it.
			writeFile(t, dir, "bridge.c", "#include "+inc+"\nvoid bridge(void) { GoCallback(); GoCallback(); }\n")
			again, err := h.contribution(pkg)
			if err != nil {
				t.Fatalf("contribution after edit: %v", err)
			}
			if got == again {
				t.Fatal("editing in-tree cgo source did not move the contribution")
			}
		})
	}
}

// TestContributionCgoNonPackageIncludeRootFailsClosed: a `-I` root outside the
// package and outside the module cache holds mutable first-party C source the analysis cannot
// prove is version-pinned — a local `replace => ../sibling` header, a `go.work`
// sibling, or an unidentifiable system dir. Editing such a header changes the
// benchmark, so the root must fail closed rather than be skipped (the analysis cannot
// distinguish it from a genuine system root; system headers reached by the
// compiler's default search fail-closed-free via the not-found path). Regression for
// the local-replace false-valid: without it, `#include "api.h"` via the outside-
// module `-I` root would be skipped and an api.h edit would report valid.
func TestContributionCgoNonPackageIncludeRootFailsClosed(t *testing.T) {
	parent := t.TempDir()
	mod := filepath.Join(parent, "mod")
	dir := filepath.Join(mod, "pkg")
	shared := filepath.Join(parent, "shared", "include") // local-replace sibling, outside mod, not under cache
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"api.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, shared, "api.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.Join(parent, "gomodcache")}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CgoCFLAGS:  []string{"-I" + shared},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: mod},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include root outside package dir") {
		t.Fatalf("contribution error = %v, want cgo include root outside package dir", err)
	}
}

// TestContributionCgoCacheIncludeRootAllowed: a `-I` root under GOMODCACHE is a
// version-pinned dependency (REQ-closure-mutable-local) whose C headers ride the cache guard, so it is
// allowed rather than failing closed.
func TestContributionCgoCacheIncludeRootAllowed(t *testing.T) {
	cache := t.TempDir()
	dir := t.TempDir()
	dep := filepath.Join(cache, "dep@v1.0.0", "include")
	if err := os.MkdirAll(dep, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include <dep.h>\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dep, "dep.h", "#define N 1\n")
	h := &Hasher{modCache: cache}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CgoCFLAGS:  []string{"-I" + dep},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: dir},
	}
	if _, err := h.contribution(pkg); err != nil {
		t.Fatalf("contribution: %v, want cache -I root allowed", err)
	}
}

func TestContributionCgoNestedIncIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"local.inc\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "local.inc", "#include \"../cfg.h\"\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoNestedSoHeaderIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"local.so.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "local.so.h", "#include \"../cfg.h\"\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoNestedVersionedSoIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"local.so.1\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "local.so.1", "#include \"../cfg.h\"\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoSplicedIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#\\\ninclude \"../cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoGoPreambleSplicedIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\n// #\\\n// include \"../cfg.h\"\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "void bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoImportFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.m", "#import \"../cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		MFiles:     []string{"bridge.m"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoSymlinkIncludeDirFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	outside := filepath.Join(root, "cfg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"include/cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, outside, "cfg.h", "#define N 1\n")
	if err := os.Symlink(outside, filepath.Join(dir, "include")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoSymlinkIncludeDirDotDotFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"include/../cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, outside, "cfg.h", "#define N 1\n")
	if err := os.Symlink(filepath.Join(outside, "sub"), filepath.Join(dir, "include")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoIncludeRootSymlinkDotDotFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, outside, "cfg.h", "#define N 1\n")
	if err := os.Symlink(filepath.Join(outside, "sub"), filepath.Join(dir, "include")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CgoCFLAGS:  []string{"-I${SRCDIR}/include/.."},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include root outside package dir") {
		t.Fatalf("contribution error = %v, want cgo include root outside package dir", err)
	}
}

func TestContributionCgoMacroIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#define CFG \"../cfg.h\"\n#include CFG\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "unresolved cgo include") {
		t.Fatalf("contribution error = %v, want unresolved cgo include", err)
	}
}

func TestContributionCgoCommentedIncludeDirectiveFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#/**/include \"../cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoMultilineCommentedIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"local.inc\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "local.inc", "/*\n*/ #include \"../cfg.h\"\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoCharConstantDoesNotHideInclude(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "int x = '/*';\n#include \"../cfg.h\"\nint y = '*/';\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoRawStringFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.cc", "const char *x = R\"raw(\"/*)raw\";\n#include \"../cfg.h\"\nconst char *y = R\"raw(*/)raw\";\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CXXFiles:   []string{"bridge.cc"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "unsupported cgo raw string") {
		t.Fatalf("contribution error = %v, want unsupported cgo raw string", err)
	}
}

func TestContributionCgoHeaderRawStringFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.cc", "#include \"local.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "local.h", "const char *x = R\"raw(\"/*)raw\";\n#include \"../cfg.h\"\nconst char *y = R\"raw(*/)raw\";\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CXXFiles:   []string{"bridge.cc"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "unsupported cgo raw string") {
		t.Fatalf("contribution error = %v, want unsupported cgo raw string", err)
	}
}

func TestContributionCgoObjectFileNotScannedAsIncludeSource(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"_cgo_export.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "blob.obj", "#include <not-source.h>\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: dir},
	}
	if _, err := h.contribution(pkg); err != nil {
		t.Fatalf("contribution: %v", err)
	}
}

func TestContributionCgoReferencedObjectIncludeFailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"local.o\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "local.o", "#include \"../cfg.h\"\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: dir},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "unsupported cgo include source") {
		t.Fatalf("contribution error = %v, want unsupported cgo include source", err)
	}
}

func TestContributionCgoSymlinkHeaderHashesTarget(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	outside := filepath.Join(root, "cfg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "include"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"include/cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, outside, "cfg.h", "#define N 1\n")
	if err := os.Symlink(filepath.Join(outside, "cfg.h"), filepath.Join(dir, "include", "cfg.h")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	one, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution: %v", err)
	}
	writeFile(t, outside, "cfg.h", "#define N 2\n")
	two, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after symlink target edit: %v", err)
	}
	if one == two {
		t.Fatalf("symlinked cgo header edit did not change contribution: %q", one)
	}
}

func TestUnderCache(t *testing.T) {
	h := &Hasher{modCache: filepath.FromSlash("/home/u/go/pkg/mod")}
	yes := filepath.FromSlash("/home/u/go/pkg/mod/golang.org/x/tools@v0.46.0")
	if !h.underCache(yes) {
		t.Errorf("underCache(%q) = false", yes)
	}
	no := filepath.FromSlash("/home/u/repo/internal/foo")
	if h.underCache(no) {
		t.Errorf("underCache(%q) = true", no)
	}
	// Prefix-but-not-a-path-segment must not match.
	sib := filepath.FromSlash("/home/u/go/pkg/modificator")
	if h.underCache(sib) {
		t.Errorf("underCache(%q) = true (segment-boundary bug)", sib)
	}
}

// TestPropSourceFilesComplete pins the compiled-file-kind set: dropping a kind (a
// silent under-coverage / false-valid hole) changes the count.
func TestPropSourceFilesComplete(t *testing.T) {
	p := listPkg{
		GoFiles: []string{"g.go"}, CgoFiles: []string{"cg.go"}, CFiles: []string{"c.c"},
		CXXFiles: []string{"cc.cc"}, MFiles: []string{"m.m"}, HFiles: []string{"h.h"},
		FFiles: []string{"f.f"}, SFiles: []string{"s.s"}, SwigFiles: []string{"w.swig"},
		SwigCXXFiles: []string{"wc.swigcxx"}, SysoFiles: []string{"o.syso"}, EmbedFiles: []string{"e.txt"},
	}
	if got := len(p.SourceFiles()); got != 12 {
		t.Errorf("sourceFiles count: got %d, want 12 — a compiled file kind is missing", got)
	}
}

func TestPropMutableLocalContentSensitivity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.go")
	if err := os.WriteFile(path, []byte("package p\nconst Value = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := listPkg{
		ImportPath: "example.com/p",
		Dir:        dir,
		GoFiles:    []string{"p.go"},
		Module:     &listMod{Main: true, Dir: dir},
	}
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	before, err := h.contribution(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("package p\nconst Value = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := h.contribution(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("mutable-local source edit did not move its contribution")
	}
}

// TestParseListError: a package reporting a load Error must fail the parse, never
// be silently dropped from the closure (REQ-fresh-sound).
func TestParseListError(t *testing.T) {
	const stream = `{"ImportPath":"ok/pkg","Dir":"/x","Module":{"Main":true}}
{"ImportPath":"bad/pkg","Error":{"Err":"cannot find package"}}`
	if _, err := listing.Parse(strings.NewReader(stream)); err == nil {
		t.Error("expected error when a package reports a load Error")
	}
}

// TestMaximalHashReal exercises the Tier-1 maximal pipeline against a real
// package (store, which pulls in the benchfmt cache dep), validating determinism
// and cross-module classification (a src: contribution for the main module,
// cache: for benchfmt). maximalHash is the A′ widening target (REQ-closure-blindspot).
func TestMaximalHashReal(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/gotool"
	a, err := h.maximalHash(pkg)
	if err != nil {
		t.Fatalf("maximalHash: %v", err)
	}
	if len(a) != 32 {
		t.Errorf("hash len: got %d (%q)", len(a), a)
	}
	if b, _ := h.maximalHash(pkg); b != a {
		t.Errorf("hash not deterministic: %q vs %q", a, b)
	}
}

// TestListMemoizes pins the per-package listing cache: two calls for the same
// package path return the identical backing slice (proving the second reused the
// memo rather than re-running the `go list` subprocess), and the content is the
// same. The efficiency claim is that N benchmarks in a package pay one listing;
// the observable proxy is memo identity.
func TestListMemoizes(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/gotool"
	first, err := h.list(pkg)
	if err != nil {
		t.Fatalf("list (first): %v", err)
	}
	if len(first) == 0 {
		t.Fatal("list returned no packages")
	}
	second, err := h.list(pkg)
	if err != nil {
		t.Fatalf("list (second): %v", err)
	}
	if len(second) != len(first) {
		t.Fatalf("second listing len %d != first %d", len(second), len(first))
	}
	// Same backing array ⇒ the second call hit the memo, not a fresh subprocess.
	if &first[0] != &second[0] {
		t.Error("list did not memoize: second call returned a distinct slice")
	}
}

func TestListUsesBuildFlags(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/tagged\n\ngo 1.26\n")
	writeFile(t, dir, "selected_default.go", "//go:build !special\n\npackage tagged\n\nfunc Selected() int { return 1 }\n")
	writeFile(t, dir, "selected_special.go", "//go:build special\n\npackage tagged\n\nfunc Selected() int { return 2 }\n")

	h, err := NewAt(dir, "-tags=special")
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := h.list("example.com/tagged")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if p.ImportPath != "example.com/tagged" {
			continue
		}
		if !stringSliceContains(p.GoFiles, "selected_special.go") || stringSliceContains(p.GoFiles, "selected_default.go") {
			t.Fatalf("selected Go files = %v, want only special variant", p.GoFiles)
		}
		return
	}
	t.Fatal("go list omitted the tagged package")
}

// TestAnalysisRootsAnySubject pins the generalized root seam: the analysis
// resolves any top-level function as a subject — a production function, not only
// a Benchmark* — through both the test-variant package (a package that also has
// tests) and the plain-package fallback (a package with no test files), and
// errors clearly on a name that resolves to no function. Before generalization
// the root index held only Benchmark*/TestMain, so a production symbol was
// reported "not found".
func TestAnalysisRootsAnySubject(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// (a) A production function in a package that also has tests: resolved via the
	// test-variant package, which compiles the package WITH its test files and so
	// holds production and test symbols alike.
	const withTests = "github.com/greatliontech/gofresh/internal/gotool"
	a, aReach, err := computeTier2ResultAndReach(h, withTests, "RunIn")
	if err != nil {
		t.Fatalf("analysis of production func RunIn: %v", err)
	}
	if len(aReach) == 0 {
		t.Fatal("empty reachability for a resolvable production subject")
	}
	if again, err := computeTier2Result(h, withTests, "RunIn"); err != nil || !reflect.DeepEqual(again, a) {
		t.Errorf("nondeterministic: %+v vs %+v (err %v)", again, a, err)
	}
	// The projection's total order is what makes the equality above — and
	// the proof diagnostic — deterministic across recomputations.
	if !sort.SliceIsSorted(a.effects, func(i, j int) bool { return effectLess(a.effects[i], a.effects[j]) }) {
		t.Errorf("effect projection is not sorted: %+v", a.effects)
	}

	// (b) A function in a package with NO test files: resolved via the plain-package
	// fallback (no ForTest variant exists).
	const noTests = "github.com/greatliontech/gofresh/closure/fixtures/rootcollision/dep"
	_, bReach, err := computeTier2ResultAndReach(h, noTests, "BenchmarkSame")
	if err != nil {
		t.Fatalf("analysis of func in a no-test package: %v", err)
	}
	if len(bReach) == 0 {
		t.Fatal("empty reachability via the plain-package fallback")
	}

	// A name that resolves to no function is a clear error, not a silent empty root.
	if _, err := computeTier2Result(h, withTests, "NoSuchFunction"); err == nil {
		t.Error("a name resolving to no function: want error, got nil")
	}
}

// TestRecompiledDependencyStaysOutOfSubjectRoots pins subject rooting
// (REQ-closure-analysis): the reachability walk roots at the subject, so the
// candidate-root index for a package must come only from that package's own
// variants. `go list` marks every package recompiled into the test binary with
// ForTest — including an intermediate dependency (a's external test imports r,
// r imports a → "r [a.test]") — but the dependency's top-level functions are
// not subjects of the tested package: a name shared with the tested package
// must not read as an ambiguous root, and a name the tested package never
// declares must be refused, never silently resolved to the dependency's
// closure.
func TestRecompiledDependencyStaysOutOfSubjectRoots(t *testing.T) {
	writeTriangle := func(t *testing.T, aSource, rSource string) string {
		t.Helper()
		dir := t.TempDir()
		for name, content := range map[string]string{
			"go.mod": "module example.com/triangle\n\ngo 1.26\n",
			"a/a.go": aSource,
			// The in-package test file makes "a [a.test]" a distinct variant, so
			// r — importing a, imported by a's external test — is recompiled
			// against it as "r [a.test]" with ForTest set.
			"a/in_test.go":  "package a\n\nimport \"testing\"\n\nfunc TestInternal(t *testing.T) {}\n",
			"a/ext_test.go": "package a_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/triangle/r\"\n)\n\nfunc TestExternal(t *testing.T) { r.Use() }\n",
			"r/r.go":        rSource,
		} {
			path := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		// The assertions below hold vacuously if the recompiled dependency
		// variant stops materializing, so its presence is load-bearing.
		cfg := &packages.Config{
			Mode:  packages.NeedName | packages.NeedForTest | packages.NeedImports | packages.NeedDeps,
			Tests: true,
			Dir:   dir,
		}
		loaded, err := packages.Load(cfg, "example.com/triangle/a")
		if err != nil {
			t.Fatalf("variant guard load: %v", err)
		}
		variant := false
		packages.Visit(loaded, nil, func(p *packages.Package) {
			if p.PkgPath == "example.com/triangle/r" && p.ForTest == "example.com/triangle/a" {
				variant = true
			}
		})
		if !variant {
			t.Fatal("fixture no longer yields the recompiled dependency variant r [a.test]; the assertions below would hold vacuously")
		}
		return dir
	}

	t.Run("shared name is no root collision", func(t *testing.T) {
		dir := writeTriangle(t,
			"package a\n\nfunc G() {}\n",
			"package r\n\nimport \"example.com/triangle/a\"\n\nfunc Use() { a.G() }\n\nfunc G() {}\n",
		)
		h, err := NewAt(dir)
		if err != nil {
			t.Fatalf("NewAt: %v", err)
		}
		_, reach, err := computeTier2ResultAndReach(h, "example.com/triangle/a", "G")
		if err != nil {
			t.Fatalf("analysis of a.G with a same-named dependency symbol: %v", err)
		}
		if len(reach) == 0 {
			t.Fatal("empty reachability for a's own G")
		}
	})

	t.Run("dependency symbol is not rootable under the tested package", func(t *testing.T) {
		dir := writeTriangle(t,
			"package a\n\nfunc A() {}\n",
			"package r\n\nimport \"example.com/triangle/a\"\n\nfunc Use() { a.A() }\n",
		)
		h, err := NewAt(dir)
		if err != nil {
			t.Fatalf("NewAt: %v", err)
		}
		if _, reach, err := computeTier2ResultAndReach(h, "example.com/triangle/a", "A"); err != nil || len(reach) == 0 {
			t.Fatalf("analysis of a.A: reach %v, %v; want a's own subject to resolve", reach, err)
		}
		if _, err := computeTier2Result(h, "example.com/triangle/a", "Use"); err == nil {
			t.Fatal("analysis of a.Use: want an error (a never declares Use), got the recompiled dependency's closure")
		}
	})
}

// TestMethodSubjectsRootAtSpecificMethod pins method-subject resolution: a
// method is named "Type.Method" (matching the consumer symbol grammar with the
// package prefix stripped), resolves through both value- and pointer-receiver
// method sets, roots at that specific method, and errors on a missing method name.
func TestMethodSubjectsRootAtSpecificMethod(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/methodsubject"

	_, valReach, err := computeTier2ResultAndReach(h, pkg, "Adder.Value") // value receiver
	if err != nil {
		t.Fatalf("analysis of value-receiver method Adder.Value: %v", err)
	}
	if len(valReach) == 0 {
		t.Fatal("empty reachability for a method subject")
	}
	_, ptrReach, err := computeTier2ResultAndReach(h, pkg, "Adder.Ptr") // pointer receiver
	if err != nil {
		t.Fatalf("analysis of pointer-receiver method Adder.Ptr: %v", err)
	}
	// The two methods reach distinct helpers, so rooting at the specific method (not
	// the whole type or package) yields distinct reachable sets.
	if maps.Equal(ptrReach, valReach) {
		t.Error("Adder.Value and Adder.Ptr reach identically; not rooting at the specific method")
	}
	if _, err := computeTier2Result(h, pkg, "Adder.Missing"); err == nil {
		t.Error("a missing method name: want error, got nil")
	}
}

// TestGenericMethodSubjectsRootPerMethod pins that method subjects on a generic
// receiver type resolve — the pointer star and generics are dropped from the type
// name (Box[T] → "Box"), and each method roots at its own closure. SSA
// materializes the receiver, so no deferral is needed.
func TestGenericMethodSubjectsRootPerMethod(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/genericmethod"
	_, getReach, err := computeTier2ResultAndReach(h, pkg, "Box.Get") // value receiver on Box[T]
	if err != nil {
		t.Fatalf("analysis of Box.Get: %v", err)
	}
	_, setReach, err := computeTier2ResultAndReach(h, pkg, "Box.Set") // pointer receiver on Box[T]
	if err != nil {
		t.Fatalf("analysis of Box.Set: %v", err)
	}
	if len(getReach) == 0 || len(setReach) == 0 {
		t.Fatal("empty reachability for a generic-receiver method")
	}
	if maps.Equal(getReach, setReach) {
		t.Error("Box.Get and Box.Set reach identically; not rooting at the specific method")
	}
}

// TestTestMainRootedOnlyForTestSubjects pins the harness-root design call
// (REQ-closure-analysis): the test main is a root of a subject's closure only when
// the subject runs through the test harness. A benchmark runs after TestMain setup,
// so file I/O that setup reaches makes the benchmark's closure unverifiable; a
// production function never executes through TestMain, so the same setup is not in
// its closure and it stays verifiable. Rooting the test main unconditionally (the
// prior behavior) would wrongly mark the production subject unverifiable.
func TestTestMainRootedOnlyForTestSubjects(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/harnessroot"

	bench, err := computeTier2Result(h, pkg, "BenchmarkProd")
	if err != nil {
		t.Fatalf("analysis of BenchmarkProd: %v", err)
	}
	if !bench.unverifiable {
		t.Error("test subject: want unverifiable (its closure reaches TestMain's file I/O), got verifiable")
	}

	prod, err := computeTier2Result(h, pkg, "Prod")
	if err != nil {
		t.Fatalf("analysis of Prod: %v", err)
	}
	if prod.unverifiable {
		t.Errorf("production subject: want verifiable (TestMain not in its closure), got unverifiable: %s", prod.reason)
	}
}

// TestClosureIncludesInitRegisteredSideEffectPackage pins REQ-fresh-sound for
// registry patterns: a side-effect import's init can register an implementation
// that the benchmark later observes through package-level state and interface
// dispatch. The analysis roots linked startup code so the registering package
// source is hashed even though the benchmark never names it directly.
func TestClosureIncludesInitRegisteredSideEffectPackage(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const benchPkg = "github.com/greatliontech/gofresh/closure/fixtures/initregistry/bench"
	const codecPkg = "github.com/greatliontech/gofresh/closure/fixtures/initregistry/codec"

	_, reach, err := computeTier2ResultAndReach(h, benchPkg, "BenchmarkDecode")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	// The benchmark dispatches gz.Decode through registry state and an
	// interface without naming codec, so gz.Decode is analyzed only
	// because all package inits are RTA roots; losing that root would
	// leave the registered method's effects invisible
	// (REQ-closure-coverage reference/side-effect closure). The bodies'
	// bytes ride the maximal hash.
	if !reachContains(reach, codecPkg, "Decode") {
		t.Fatalf("init-registered method gz.Decode missing from the subject's reach: %v", reach)
	}
}

func TestReachIncludesTestMainRoot(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/testmainroot"
	_, reach, err := computeTier2ResultAndReach(h, pkg, "BenchmarkTestMainRoot")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !reachContains(reach, "TestMain") || !reachContains(reach, "setup") {
		t.Fatalf("TestMain/setup missing from the subject's reach: %v", reach)
	}
}

func TestAnalysisReachStaysSubjectPrecise(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/direct"
	tr, reach, err := computeTier2ResultAndReach(h, pkg, "BenchmarkDirect")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if tr.widen {
		t.Fatalf("direct fixture widened: %+v", tr)
	}
	if !reachContains(reach, "used") {
		t.Fatalf("subject-reached function missing from the reach: %v", reach)
	}
	if reachContains(reach, "unused") {
		t.Fatalf("subject-unreached function leaked into the reach: %v", reach)
	}
}

func TestBuildIndexTrustsGoListStandardForDotlessModule(t *testing.T) {
	typesPkg := types.NewPackage("myapp", "myapp")
	ssaProg := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)
	a := &tier2Analyzer{
		h:          &Hasher{},
		prog:       &program{Prog: ssaProg},
		metaByPath: map[string]*listPkg{"myapp": &listPkg{ImportPath: "myapp", Standard: false, Module: &listMod{Main: true}}},
	}
	idx := a.buildIndex(&packages.Package{ID: "myapp", PkgPath: "myapp", Types: typesPkg})
	if idx == nil {
		t.Fatal("buildIndex returned nil")
	}
	if idx.std {
		t.Fatalf("dotless package with go-list Standard=false classified std")
	}
}

func TestExternalTestBenchmarkRoots(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/externalbench"
	_, reach, err := computeTier2ResultAndReach(h, pkg, "BenchmarkExternal")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !reachContains(reach, "BenchmarkExternal") {
		t.Fatalf("external test benchmark root missing from the subject's reach: %v", reach)
	}
}

// TestNonToolchainAssemblyReachedPackagesWiden pins the conservative analyzer
// contract (REQ-closure-blindspot): a reached non-toolchain assembly-bearing
// package — mutable-local or cache — is never scanned. It widens the subject
// naming the package and records the "reaches non-standard assembly" effect
// that makes the subject unverifiable and blocks its observability proof.
func TestNonToolchainAssemblyReachedPackagesWiden(t *testing.T) {
	requireConservative := func(t *testing.T, a *tier2Analyzer, pkgID string) {
		t.Helper()
		if !a.widen || a.widenReason != "non-toolchain assembly in "+pkgID {
			t.Fatalf("widen = %v/%q, want non-toolchain assembly in %s", a.widen, a.widenReason, pkgID)
		}
		if !a.unverifiable {
			t.Fatal("non-toolchain assembly did not make the subject unverifiable")
		}
		found := false
		for _, effect := range a.effects {
			if effect.kind == externalEffectNative && effect.reason == "reaches non-standard assembly" {
				found = true
			}
		}
		if !found {
			t.Fatalf("effects = %+v, want native \"reaches non-standard assembly\"", a.effects)
		}
	}

	t.Run("mutable", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "defs.inc", "#define RETVAL $1\n")
		writeFile(t, dir, "asm.s", "#include \"defs.inc\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tMOVQ RETVAL, AX\n\tRET\n")
		idx := &pkgIndex{id: "example.com/mutableasm", mutable: true, meta: &listPkg{Dir: dir, SFiles: []string{"asm.s"}}}
		a := &tier2Analyzer{
			filePkgs: map[*pkgIndex]bool{idx: true},
		}
		if err := a.addReachedPackageFiles(); err != nil {
			t.Fatalf("addReachedPackageFiles: %v", err)
		}
		requireConservative(t, a, "example.com/mutableasm")
	})

	t.Run("cache", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "cache_amd64.s"), []byte("#include \"textflag.h\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL AX\n\tRET\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		typesPkg := types.NewPackage("example.com/cacheasm", "cacheasm")
		idx := &pkgIndex{
			id:    "example.com/cacheasm",
			cache: true,
			meta:  &listPkg{ImportPath: "example.com/cacheasm", Dir: dir, SFiles: []string{"cache_amd64.s"}},
		}
		a := &tier2Analyzer{
			idxByTypes: map[*types.Package]*pkgIndex{typesPkg: idx},
			filePkgs:   map[*pkgIndex]bool{},
		}
		a.scanFunction(&ssa.Function{Pkg: &ssa.Package{Pkg: typesPkg}})
		if err := a.addReachedPackageFiles(); err != nil {
			t.Fatalf("addReachedPackageFiles: %v", err)
		}
		requireConservative(t, a, "example.com/cacheasm")
	})
}

func TestStdWrapperClassBUnverifiable(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/stdwrapper"
	tr, err := computeTier2Result(h, pkg, "BenchmarkTemplateParseFiles")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !tr.unverifiable || !strings.Contains(tr.reason, "file I/O") {
		t.Fatalf("std wrapper Class-B = %v/%q, want file I/O", tr.unverifiable, tr.reason)
	}
}

func TestStdCallbackMethodStaysReached(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/stdcallback"
	_, reach, err := computeTier2ResultAndReach(h, pkg, "BenchmarkSortCallback")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !reachContains(reach, "Less") {
		t.Fatalf("std callback method Less missing from the subject's reach: %v", reach)
	}
}

func TestAnalysisReachesUnverifiable(t *testing.T) {
	// Every benchmark here reaches a Class-B external dependence in its closure
	// (file I/O, filesystem/path mutation, or network), so the closure is
	// unverifiable with the matching reason. File I/O is
	// unverifiable regardless of when it runs relative to the testlog stream: the
	// runtime-input manifest is evidence of observed identities, never a proof
	// that every reachable file-I/O path was covered, so the closure never
	// promotes observed file I/O to valid (REQ-closure-blindspot, REQ-inputs-guard). The fixtures span the
	// pre-testlog window (init/TestMain/CWD-relative) and post-testlog reads, plus
	// path/filesystem mutations and mixed file+network dependence.
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const base = "github.com/greatliontech/gofresh/closure/fixtures/"
	// retainedEffect pins a classified fact that must survive among the
	// subject's effects when a higher-ranked diagnostic is preferred: the
	// unix fixtures reach golang.org/x/sys/unix, whose non-toolchain assembly
	// downgrades the subject (REQ-closure-blindspot) ahead of the file-I/O
	// classification of the wrapper itself.
	for _, tc := range []struct{ pkg, bench, reason, retainedEffect string }{
		{"external", "BenchmarkReadFile", "file I/O", ""},
		{"initfile", "BenchmarkInitFile", "file I/O", ""},
		{"initcwd", "BenchmarkInitCWD", "file I/O", ""},
		{"unixcwd", "BenchmarkUnixCWD", "non-standard assembly", "file I/O"},
		{"initstdhelper", "BenchmarkInitStdHelper", "file I/O", ""},
		{"sharedfile", "BenchmarkSharedFile", "file I/O", ""},
		{"sharedparam", "BenchmarkSharedParam", "file I/O", ""},
		{"sharedglobal", "BenchmarkSharedGlobal", "file I/O", ""},
		{"sharedchdir", "BenchmarkSharedChdir", "file I/O", ""},
		{"sharedfchdir", "BenchmarkSharedFchdir", "file I/O", ""},
		{"unixfchdir", "BenchmarkUnixFchdir", "non-standard assembly", "file I/O"},
		{"openfileread", "BenchmarkOpenFileRead", "file I/O", ""},
		{"openrootread", "BenchmarkRootOpenFileRead", "file I/O", ""},
		{"initdynamic", "BenchmarkInitDynamic", "file I/O", ""},
		{"initstdcallback", "BenchmarkInitStdCallback", "file I/O", ""},
		{"testmainfile", "BenchmarkTestMainFile", "file I/O", ""},
		{"testmainruntimefile", "BenchmarkTestMainRuntimeFile", "file I/O", ""},
		{"pathbinding", "BenchmarkPathBinding", "path mutation", ""},
		{"syscallbinding", "BenchmarkSyscallBinding", "path mutation", ""},
		{"mkdirtemp", "BenchmarkMkdirTemp", "path mutation", ""},
		{"mkdir", "BenchmarkMkdir", "path mutation", ""},
		{"unixatbinding", "BenchmarkUnixAtBinding", "path mutation", ""},
		{"tempdir", "BenchmarkTempDir", "path mutation", ""},
		{"copyfs", "BenchmarkCopyFS", "path mutation", ""},
		{"createtemp", "BenchmarkCreateTemp", "filesystem mutation", ""},
		{"filemutations", "BenchmarkCreate", "filesystem mutation", ""},
		{"filemutations", "BenchmarkOpenFileCreate", "filesystem mutation", ""},
		{"filemutations", "BenchmarkWriteFile", "filesystem mutation", ""},
		{"unixopencreate", "BenchmarkUnixOpenCreate", "filesystem mutation", ""},
		{"mixedexternal", "BenchmarkMixedExternal", "network I/O", ""},
	} {
		t.Run(tc.pkg+"/"+tc.bench, func(t *testing.T) {
			tr, err := computeTier2Result(h, base+tc.pkg, tc.bench)
			if err != nil {
				t.Fatalf("analysis: %v", err)
			}
			if !tr.unverifiable || !strings.Contains(tr.reason, tc.reason) {
				t.Fatalf("unverifiable = %v, reason = %q, want reason containing %q", tr.unverifiable, tr.reason, tc.reason)
			}
			if tc.retainedEffect != "" {
				found := false
				for _, effect := range tr.effects {
					if strings.Contains(effect.reason, tc.retainedEffect) {
						found = true
					}
				}
				if !found {
					t.Fatalf("effects = %+v, want a retained effect containing %q", tr.effects, tc.retainedEffect)
				}
			}
		})
	}
}

func TestTier2RetainsEveryReachedExternalEffect(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/mixedexternal"
	result, err := computeTier2Result(h, pkg, "BenchmarkMixedExternal")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range [][2]string{{"os", "ReadFile"}, {"net", "Dial"}} {
		found := false
		for _, effect := range result.effects {
			found = found || effect.packagePath == want[0] && effect.symbol == want[1]
		}
		if !found {
			t.Errorf("missing reached effect %s.%s from %+v", want[0], want[1], result.effects)
		}
	}
	if !strings.Contains(result.reason, "network I/O") {
		t.Fatalf("legacy diagnostic = %q, want network I/O", result.reason)
	}
}

func TestReadOnlyObservabilityProof(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	const base = "github.com/greatliontech/gofresh/closure/fixtures/"
	for _, tc := range []struct {
		fixture, subject string
		observable       bool
		reason           string
	}{
		{fixture: "observable", subject: "TestReadFile", observable: true},
		{fixture: "observable", subject: "TestGetenv", observable: true},
		{fixture: "observable", subject: "TestLookupEnv", observable: true},
		{fixture: "observable", subject: "TestOpen", observable: true},
		{fixture: "observable", subject: "TestReadDir", observable: true},
		{fixture: "observableopenfile", subject: "TestOpenFile", observable: true},
		{fixture: "harnesslog", subject: "TestReadFileFatal", observable: true},
		{fixture: "harnesslog", subject: "TestReadFileLogAndError", observable: true},
		{fixture: "harnesslog", subject: "TestReadFileSkipAndFail", observable: true},
		{fixture: "harnesslog", subject: "TestLocalTBFatal", observable: true},
		{fixture: "harnesslog", subject: "TestLogOnly", observable: true},
		{fixture: "harnesslog", subject: "TestBoundMethodFatal", observable: true},
		{fixture: "harnessarg", subject: "TestLogEffectfulArgument", reason: "os.ReadFile"},
		{fixture: "harnesssetenv", subject: "TestSetenvStaysBlocked", reason: "testing.Setenv"},
		{fixture: "harnesstb", subject: "TestHelperTBFatal", observable: true},
		{fixture: "harnesstb", subject: "TestHelperTBTwice", observable: true},
		{fixture: "harnesstb", subject: "TestHelperTBRecursive", reason: "interface invoke outside RTA"},
		{fixture: "harnesstbenv", subject: "TestHelperTBSetenv", reason: "interface invoke outside RTA"},
		{fixture: "harnesswrap", subject: "TestQuietWrappedFatal", reason: "interface invoke outside RTA"},
		{fixture: "harnessshared", subject: "TestConsume", reason: "interface invoke outside RTA"},
		{fixture: "harnesssetenv", subject: "TestCleanRead", reason: "package scan: reaches testing.Setenv"},
		{fixture: "observablefresh", subject: "TestTempDirWriteReadCleanup", observable: true},
		{fixture: "observablefresh", subject: "TestTempDirOpenFile", observable: true},
		{fixture: "observablestat", subject: "TestStat"},
		{fixture: "observablemutation", subject: "TestRemove"},
		{fixture: "observableprocess", subject: "TestCommand"},
		{fixture: "observableconcurrent", subject: "TestConcurrentFileRead", reason: "os.Open"},
		{fixture: "observablefresh", subject: "TestRemoveOrdinary", reason: "os.Remove"},
		{fixture: "observablefresh", subject: "TestOpenFileMutatesOrdinary", reason: "reaches os.OpenFile (filesystem mutation)"},
		{fixture: "observablefresh", subject: "TestRemoveNeverCreated", reason: "os.Remove"},
		{fixture: "observablefresh", subject: "TestOpenFileMutatesNeverCreated", reason: "reaches os.OpenFile (filesystem mutation)"},
		{fixture: "observablefresh", subject: "TestOpenDynamicHandleClose", reason: "os.File.Close on an unattributed file handle"},
		{fixture: "observablefresh", subject: "TestOpenFileUnknownFlags", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestOpenFreshDirectoryRead", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestWriteFileUncheckedBeforeRead", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestWriteFileMutationBeforeRead", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestWriteFileMutationAcrossLoop", reason: "testing.TempDir"},
		{fixture: "observablefresh", subject: "TestWriteFileMutationThroughAlias", reason: "os.WriteFile"},
		{fixture: "observablefresh", subject: "TestWriteFileMutationThroughDuplicateJoin", reason: "testing.TempDir"},
		{fixture: "observablefresh", subject: "TestAncestorCleanupBeforeRead", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestJoinParentTraversal", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestReservedDevicePath", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestPathConcatenation", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestGeneratedPathComparison", reason: "testing.TempDir"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperEscape"},
		// The boundary extension admits an ignored parameter — nothing
		// is observed — and the disciplined helper; every refusal shape
		// (mixed callers, recursion, goroutine crossing, global leak)
		// stays refused.
		{fixture: "observablefresh", subject: "TestFreshPathNoopEscape", observable: true},
		{fixture: "observablefresh", subject: "TestFreshPathHelperFullDiscipline", observable: true},
		{fixture: "observablefresh", subject: "TestFreshPathHelperMixedCallers"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperRecursive"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperGoroutine"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperLeak"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperDirectGo"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperInLoop"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperClosureCallee"},
		{fixture: "observablefresh", subject: "TestFreshFileProbeEscape", reason: "reaches os.OpenFile (filesystem mutation)"},
		{fixture: "observablefresh", subject: "TestFreshFileNameEscape", reason: "reaches os.OpenFile (filesystem mutation)"},
		{fixture: "observablefresh", subject: "TestFreshPathGlobalEscape", reason: "testing.TempDir"},
		// The startup caller is invisible to per-subject call-site
		// enumeration by design; the startup walk blocks first, and
		// this row pins that mask (the soundness argument for
		// callers-from-subject-reach-only).
		{fixture: "observablefreshinit", subject: "TestFreshHelperShadowedByStartupCaller", reason: "startup effect"},
		// The unsafe payload is visible only through the named type's
		// underlying structure — no reachable value has an unsafe type
		// directly — so this row discriminates the type walk's
		// underlying edge.
		{fixture: "unsafewrapped", subject: "TestWrappedUnsafeHandle", reason: "unsafe pointer"},
		{fixture: "toolchainread", subject: "TestAccessorAlone", observable: true},
		{fixture: "toolchainread", subject: "TestReadVersion", observable: true},
		{fixture: "toolchainread", subject: "TestOpenUnderToolchain", observable: true},
		{fixture: "toolchainread", subject: "TestReadDirUnderToolchain", observable: true},
		{fixture: "toolchainread", subject: "TestWriteIntoToolchain", reason: "os.WriteFile"},
		{fixture: "toolchainread", subject: "TestDynamicComponent", reason: "os.ReadFile"},
		{fixture: "toolchainruntime", subject: "TestOtherRuntimeSurface", reason: "runtime.NumCPU"},
		{fixture: "toolchainindirect", subject: "TestIndirectRuntimeSurface", reason: "runtime.NumCPU"},
		{fixture: "toolchaininit", subject: "TestReadThroughInitRoot", reason: "startup effect"},
		{fixture: "testmainhelper", subject: "TestRead", observable: true},
		{fixture: "harnessmain", subject: "TestRead", reason: "test-main dispatch on unattributable state"},
		{fixture: "harnessmainlocal", subject: "TestRead", observable: true},
		{fixture: "harnessmainfunc", subject: "TestRead", reason: "test-main dispatch on unattributable state"},
		{fixture: "harnessmainbound", subject: "TestRead", reason: "test-main dispatch on unattributable state"},
		{fixture: "harnessmainthunk", subject: "TestRead", reason: "test-main dispatch on unattributable state"},
		{fixture: "harnessshareddispatch", subject: "TestUseBound", reason: "interface dispatch on unattributable state"},
		{fixture: "harnessshareddispatch", subject: "TestUseThunk", reason: "interface dispatch on unattributable state"},
		{fixture: "harnessshareddispatch", subject: "TestUsePhi", reason: "computed function call"},
		{fixture: "harnessshareddispatch", subject: "TestUseThunkLocal", observable: true},
		{fixture: "harnessshareddispatch", subject: "TestUseThunkPhi", reason: "computed function call"},
		{fixture: "harnessshareddispatch", subject: "TestUseLaunder", reason: "computed function call"},
		{fixture: "harnessmainlaunder", subject: "TestRead", reason: "test-main dispatch on unattributable state"},
		{fixture: "harnesserrshared", subject: "TestUseErrBound", reason: "interface dispatch on unattributable state"},
		{fixture: "harnessmainphi", subject: "TestRead", reason: "test-main dispatch on unattributable state"},
		{fixture: "initglobaldispatch", subject: "TestRead", observable: true},
		// The writer-sink admission: fmt's writer-first print family is
		// Sprint-equivalent when the writer provably pins an audited
		// in-memory sink; every unproven provenance — call results, phi
		// escapes, mixed helper callers — keeps the formatted-output
		// refusal (REQ-closure-observability-analysis).
		{fixture: "fmtsink", subject: "TestFprintfBuffer", observable: true},
		{fixture: "fmtsink", subject: "TestFprintlnBuilder", observable: true},
		{fixture: "fmtsink", subject: "TestFprintfHelperBuffer", observable: true},
		{fixture: "fmtsink", subject: "TestFprintfPhiBuffers", observable: true},
		{fixture: "fmtsink", subject: "TestFprintfCallResult", reason: "fmt.Fprintf"},
		{fixture: "fmtsink", subject: "TestFprintfPhiCallEscape", reason: "fmt.Fprintf"},
		{fixture: "fmtsink", subject: "TestFprintfHelperMixed", reason: "fmt.Fprintf"},
		{fixture: "fmtsink", subject: "TestFprintfLocalWriterType", reason: "fmt.Fprintf"},
		{fixture: "fmtsink", subject: "TestFprintfGlobalBuffer", observable: true},
		{fixture: "fmtsink", subject: "TestFprintfFieldBuffer", observable: true},
		// A dynamic reach in subject flow is never admitted, whatever
		// the arguments carry — the site refuses before the writer is
		// ever consulted.
		{fixture: "fmtsinkvalue", subject: "TestValueFormatBuffer"},
		// The AST scan's Fprint carve-out never unblocks the escaping
		// sink itself: the os.Stdout selector still pre-blocks the
		// package, so a stdout writer refuses before the subject tier.
		{fixture: "fmtsinkstdout", subject: "TestFprintfStdout", reason: "package scan: reaches unaudited standard operation os.Stdout"},
		// Startup flow closes locally constructed writers — an init
		// formatting into its own buffer is pure value computation —
		// while a dynamically reached Fprint keeps its effect
		// regardless of site arguments (the writer-sink admission's
		// static-leg bound) and a writer crossing a call boundary
		// refuses (startup carries no attributed parameter analysis).
		{fixture: "initfmtsink", subject: "TestAfterInitFormat", observable: true},
		{fixture: "initfmtvalue", subject: "TestAfterInitValueFormat", reason: "startup effect: reaches fmt.Fprintf"},
		{fixture: "initfmthelper", subject: "TestAfterInitHelperFormat", reason: "startup effect: reaches fmt.Fprintf"},
		{fixture: "observablebad", subject: "TestOpenStat", reason: "os.File"},
		{fixture: "observablebad", subject: "TestReadDirInfo", reason: "interface invoke"},
		{fixture: "observablecallbackbad", subject: "TestSubtestRead", reason: "fmt.Fprintf"},
		{fixture: "observablebad", subject: "ReadUnattributed", reason: "open subject world"},
		{fixture: "initfile", subject: "TestInitFile", reason: "startup effect"},
		// User test-main flow is startup, not subject time: its effects
		// block the proof (REQ-closure-observability-analysis) — the pin
		// that keeps the test main in the startup provenance roots.
		{fixture: "harnessroot", subject: "BenchmarkProd", reason: "startup effect"},
		{fixture: "mixedexternal", subject: "BenchmarkMixedExternal", reason: "subject reachability"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			subject := Subject{Package: base + tc.fixture, Symbol: tc.subject}
			results, err := h.ComputeObservabilityBatch([]Subject{subject})
			if err != nil {
				t.Fatal(err)
			}
			got := results[subject]
			if got.Observable != tc.observable || tc.reason != "" && !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("observability = %+v, want observable=%v reason containing %q", got, tc.observable, tc.reason)
			}
		})
	}
}

func TestOrdinaryOpenFileRequiresZeroFlags(t *testing.T) {
	if !ordinaryOpenFileFlagsObservable(0) {
		t.Fatal("zero-valued read-only mode was rejected")
	}
	if ordinaryOpenFileFlagsObservable(1 << 40) {
		t.Fatal("target-specific nonzero flag was interpreted with host flag values")
	}
}

func TestOpenFileFlagsUseSelectedGOOS(t *testing.T) {
	env := append([]string(nil), os.Environ()...)
	found := false
	for i, entry := range env {
		if strings.HasPrefix(entry, "GOOS=") {
			env[i] = "GOOS=plan9"
			found = true
		}
	}
	if !found {
		env = append(env, "GOOS=plan9")
	}
	h, err := NewAtContextEnv(context.Background(), "", env)
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/observablefresh"
	subjects := []Subject{
		{Package: pkg, Symbol: "TestTempDirOpenFile"},
		{Package: pkg, Symbol: "TestOpenFileUnknownFlags"},
	}
	results, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if !results[subjects[0]].Observable {
		t.Fatalf("Plan 9 recognized flags = %+v, want observable", results[subjects[0]])
	}
	if results[subjects[1]].Observable {
		t.Fatalf("Plan 9 unknown flags = %+v, want blocked", results[subjects[1]])
	}
}

func TestSubjectProvenanceIncludesTestingCallbacks(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/observablecallbackbad"
	prog, err := h.loadCached(pkg)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: pkg, Symbol: "TestSubtestRead"}
	reachable, err := attributedReachableSets(context.Background(), prog, []Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for fn := range reachable[0].subjectFunctions {
		names = append(names, fn.String())
		if funcPkgPath(fn) == pkg && strings.Contains(fn.Name(), "TestSubtestRead$1") {
			return
		}
	}
	sort.Strings(names)
	t.Fatalf("testing callback was omitted from subject provenance: %v", names)
}

func TestObservabilityBatchMatchesIndependentAnalysis(t *testing.T) {
	// The corpus spans every disposition class the observability fixtures pin —
	// observable subjects, startup and subject effect rejections, callback and
	// concurrency escapes, mutation and process effects — with several subjects
	// sharing one package so shared reachability masks and package effect scans
	// are genuinely exercised (REQ-closure-observability-batch-equivalence).
	const base = "github.com/greatliontech/gofresh/closure/fixtures/"
	subjects := []Subject{
		{Package: base + "observable", Symbol: "TestReadFile"},
		{Package: base + "observable", Symbol: "TestReadDir"},
		{Package: base + "observable", Symbol: "TestGetenv"},
		{Package: base + "observable", Symbol: "TestOpen"},
		{Package: base + "observable", Symbol: "TestLookupEnv"},
		{Package: base + "observablebad", Symbol: "TestOpenStat"},
		{Package: base + "observablebad", Symbol: "TestReadDirInfo"},
		{Package: base + "observablecallbackbad", Symbol: "TestSubtestRead"},
		{Package: base + "observableconcurrent", Symbol: "TestConcurrentFileRead"},
		{Package: base + "observablefresh", Symbol: "TestAncestorCleanupBeforeRead"},
		{Package: base + "observablefresh", Symbol: "TestFreshFileNameEscape"},
		{Package: base + "observablemutation", Symbol: "TestRemove"},
		{Package: base + "observableopenfile", Symbol: "TestOpenFile"},
		{Package: base + "observableprocess", Symbol: "TestCommand"},
		{Package: base + "observablestat", Symbol: "TestStat"},
		{Package: base + "toolchainread", Symbol: "TestReadVersion"},
		{Package: base + "toolchainread", Symbol: "TestWriteIntoToolchain"},
		{Package: base + "toolchainruntime", Symbol: "TestOtherRuntimeSurface"},
		{Package: base + "initfile", Symbol: "TestInitFile"},
		{Package: base + "initfile", Symbol: "BenchmarkInitFile"},
		{Package: base + "harnessmain", Symbol: "TestRead"},
		{Package: base + "harnessmain", Symbol: "TestPlant"},
		{Package: base + "harnesslog", Symbol: "TestReadFileFatal"},
	}
	batchHasher, err := New()
	if err != nil {
		t.Fatal(err)
	}
	batch, err := batchHasher.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[bool]int{}
	for _, subject := range subjects {
		independentHasher, err := New()
		if err != nil {
			t.Fatal(err)
		}
		independent, err := independentHasher.ComputeObservabilityBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		if batch[subject] != independent[subject] {
			t.Errorf("%s.%s batch=%+v independent=%+v", subject.Package, subject.Symbol, batch[subject], independent[subject])
		}
		statuses[independent[subject].Observable]++
	}
	if statuses[true] == 0 || statuses[false] == 0 {
		t.Fatalf("corpus lost its disposition spread: %v", statuses)
	}
	// Subject-local attribution inside one package's shared mask is witnessed
	// only if some package's subjects disagree; a corpus refactor must not
	// silently lose that witness.
	bad1 := batch[Subject{Package: base + "observablebad", Symbol: "TestOpenStat"}]
	bad2 := batch[Subject{Package: base + "observablebad", Symbol: "TestReadDirInfo"}]
	if bad1 == bad2 {
		t.Fatalf("observablebad subjects share one disposition (%+v); the corpus lost its within-package variance witness", bad1)
	}
	if startup := batch[Subject{Package: base + "initfile", Symbol: "TestInitFile"}]; !strings.HasPrefix(startup.Reason, "startup effect:") {
		t.Fatalf("initfile subject = %+v, want a startup-effect rejection", startup)
	}

	// One shared Hasher running the production maximal→observe sequence
	// over warm list and effect caches must yield the same dispositions as
	// the fresh batch above.
	sharedHasher, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sharedHasher.ComputeMaximalBatch(subjects); err != nil {
		t.Fatal(err)
	}
	shared, err := sharedHasher.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		if shared[subject] != batch[subject] {
			t.Errorf("%s.%s shared-sequence=%+v batch=%+v", subject.Package, subject.Symbol, shared[subject], batch[subject])
		}
	}
}

func TestProvenanceReachabilityHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provenanceReachable(ctx, nil, 1, &rta.Result{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("provenanceReachable = %v, want context.Canceled", err)
	}
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/observable"
	prog, err := h.loadCached(pkg)
	if err != nil {
		t.Fatal(err)
	}
	root := prog.Roots["TestReadFile"]
	bounded := &cancelProvenanceContext{Context: context.Background(), remaining: 1}
	if _, err := provenanceReachable(bounded, []*ssa.Function{root}, 1, &rta.Result{Reachable: map[*ssa.Function]uint64{root: 1}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("provenanceReachable during traversal = %v, want context.Canceled", err)
	}
}

type cancelProvenanceContext struct {
	context.Context
	remaining int
}

func (c *cancelProvenanceContext) Err() error {
	if c.remaining == 0 {
		return context.Canceled
	}
	c.remaining--
	return nil
}

func TestTier2ReflectWidens(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/reflectfixture"
	tr, err := computeTier2Result(h, pkg, "BenchmarkReflect")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !tr.widen {
		t.Fatal("reflect dispatch did not widen to Tier-1")
	}
}

func TestTier2GenericInterfaceEscapeAnalyzesMethodBody(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/genericescape"
	tr, err := computeTier2Result(h, pkg, "BenchmarkGenericEscape")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if tr.widen {
		t.Fatalf("generic interface escape widened (imprecise): %+v", tr)
	}
	// Secret is reached only via interface escape (never called → not
	// RTA-reachable); its instantiated object has no decl node, so the
	// origin body must be resolved and scanned — the fixture plants an
	// environment read there, and losing the resolution loses the effect.
	if !hasEffectReason(tr.effects, "reaches os.Getenv (environment input)") {
		t.Fatalf("generic method body reached via interface escape was not analyzed: %+v", tr.effects)
	}
}

func TestTier2ConstGroupAnalyzesWithoutWiden(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/constgroup"
	tr, err := computeTier2Result(h, pkg, "BenchmarkConstGroup")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if tr.widen {
		t.Fatalf("const group fixture widened: %+v", tr)
	}
}

// TestNonToolchainAssemblyWidensAndBlocks pins the conservative contract
// end-to-end (REQ-closure-blindspot): a subject reaching a non-toolchain
// assembly-bearing package widens to the maximal closure (whose hash covers
// the package directory whole), names the assembly as the widening cause, and
// is unverifiable via the "reaches non-standard assembly" effect that blocks
// its observability proof. The assembly is never analyzed for call targets.
func TestNonToolchainAssemblyWidensAndBlocks(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/asmcall"
	tr, err := computeTier2Result(h, pkg, "BenchmarkASMCall")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !tr.widen || !strings.Contains(tr.widenReason, "non-toolchain assembly in "+pkg) {
		t.Fatalf("widen = %v/%q, want non-toolchain assembly in %s", tr.widen, tr.widenReason, pkg)
	}
	if !tr.unverifiable {
		t.Fatal("non-toolchain assembly subject was not unverifiable")
	}
	found := false
	for _, effect := range tr.effects {
		if effect.kind == externalEffectNative && effect.reason == "reaches non-standard assembly" {
			found = true
		}
	}
	if !found {
		t.Fatalf("effects = %+v, want native \"reaches non-standard assembly\"", tr.effects)
	}
}

func TestHasExternalCgo(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags []string
		want  bool
	}{
		{name: "library", flags: []string{"-lm"}, want: true},
		{name: "archive", flags: []string{"${SRCDIR}/libhelper.a"}, want: true},
		{name: "dylib", flags: []string{"/tmp/libhelper.dylib"}, want: true},
		{name: "framework", flags: []string{"-framework", "Security"}, want: true},
		{name: "so", flags: []string{"/tmp/libx.so"}, want: true},
		{name: "versioned so", flags: []string{"/tmp/libx.so.1"}, want: true},
		{name: "internal", flags: []string{"-Iinclude", "-DNAME=1"}, want: false},
		{name: "wl grouped library", flags: []string{"-Wl,-Bstatic,-lfoo,-Bdynamic"}, want: true},
		{name: "wl no-as-needed library", flags: []string{"-Wl,--no-as-needed,-lssl,--pop-state"}, want: true},
		{name: "wl colon library", flags: []string{"-Wl,-Bstatic,-l:libfoo.a"}, want: true},
		{name: "wl non-library", flags: []string{"-Wl,-rpath,/usr/lib"}, want: false},
		{name: "xlinker library", flags: []string{"-Xlinker", "-lfoo"}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasExternalCgo(tc.flags); got != tc.want {
				t.Fatalf("hasExternalCgo(%v) = %v, want %v", tc.flags, got, tc.want)
			}
		})
	}
}

func TestTier2CgoCallbackSourceWidens(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "include"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"_cgo_export.h\"\n#include \"include/cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, filepath.Join("include", "cfg.h"), "#define N 1\n")
	idx := &pkgIndex{
		id:      "example.com/cgocallback",
		mutable: true,
		meta: &listPkg{
			Dir:      dir,
			CgoFiles: []string{"cg.go"},
			CFiles:   []string{"bridge.c"},
		},
	}
	a := &tier2Analyzer{
		filePkgs: map[*pkgIndex]bool{idx: true},
	}

	if err := a.addReachedPackageFiles(); err != nil {
		t.Fatalf("addReachedPackageFiles: %v", err)
	}
	if !a.widen || !strings.Contains(a.widenReason, "cgo callback source") {
		t.Fatalf("widen = %v/%q, want cgo callback source", a.widen, a.widenReason)
	}
}

// TestTier2CgoSystemIncludeSkipped mirrors the contribution-level system-include
// skip on the Tier-2 addReachedPackageFiles path (which shares cgoEscapingInclude):
// a `<stdio.h>` system header is skipped, the package C source is still hashed.
func TestTier2CgoSystemIncludeSkipped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include <stdio.h>\nvoid bridge(void) { GoCallback(); }\n")
	idx := &pkgIndex{
		id:      "example.com/cgocallback",
		mutable: true,
		meta: &listPkg{
			Dir:      dir,
			CgoFiles: []string{"cg.go"},
			CFiles:   []string{"bridge.c"},
			Module:   &listMod{Main: true, Dir: dir},
		},
	}
	a := &tier2Analyzer{filePkgs: map[*pkgIndex]bool{idx: true}}
	if err := a.addReachedPackageFiles(); err != nil {
		t.Fatalf("addReachedPackageFiles: %v, want system include skipped", err)
	}
	if !a.widen || !strings.Contains(a.widenReason, "cgo callback source") {
		t.Fatalf("widen = %v/%q, want the blindspot widen with the system include skipped", a.widen, a.widenReason)
	}
}

func TestTier2CgoOutsideIncludeRootFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	outside := filepath.Join(root, "cfg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, outside, "cfg.h", "#define N 1\n")
	idx := &pkgIndex{
		id:      "example.com/cgocallback",
		mutable: true,
		meta: &listPkg{
			Dir:       dir,
			CgoFiles:  []string{"cg.go"},
			CgoCFLAGS: []string{"-I${SRCDIR}/../cfg"},
			CFiles:    []string{"bridge.c"},
		},
	}
	a := &tier2Analyzer{
		filePkgs: map[*pkgIndex]bool{idx: true},
	}

	if err := a.addReachedPackageFiles(); err == nil || !strings.Contains(err.Error(), "cgo include root outside package dir") {
		t.Fatalf("addReachedPackageFiles error = %v, want cgo include root outside package dir", err)
	}
}

func TestTier2CgoRelativeIncludeEscapeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"../cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	idx := &pkgIndex{
		id:      "example.com/cgocallback",
		mutable: true,
		meta: &listPkg{
			Dir:      dir,
			CgoFiles: []string{"cg.go"},
			CFiles:   []string{"bridge.c"},
		},
	}
	a := &tier2Analyzer{
		filePkgs: map[*pkgIndex]bool{idx: true},
	}

	if err := a.addReachedPackageFiles(); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("addReachedPackageFiles error = %v, want cgo include escapes package dir", err)
	}
}

func TestClassBReasonNetDialContext(t *testing.T) {
	if reason := classBReason("net", "DialContext"); !strings.Contains(reason, "network I/O") {
		t.Fatalf("classBReason(net.DialContext) = %q, want network I/O", reason)
	}
}

func TestTier2CgoExternalLibraryUnverifiable(t *testing.T) {
	// End-to-end (through scanFunction → hasExternalCgoMeta → hasExternalCgo →
	// recordExternalEffect), not just the hasExternalCgo predicate: a plain `-lm` and a
	// grouped linker flag `-Wl,-Bstatic,-lfoo,-Bdynamic` (which hides the `-l` inside
	// one whitespace token) must both mark the closure unverifiable, else the external
	// library could change while the benchmark reports valid (REQ-closure-blindspot).
	for _, ldflags := range [][]string{
		{"-lm"},
		{"-Wl,-Bstatic,-lfoo,-Bdynamic"},
		{"-Wl,--no-as-needed,-lssl,--pop-state"},
	} {
		t.Run(strings.Join(ldflags, " "), func(t *testing.T) {
			typesPkg := types.NewPackage("example.com/cgodep", "cgodep")
			idx := &pkgIndex{
				cache: true,
				meta:  &listPkg{CgoLDFLAGS: ldflags},
			}
			a := &tier2Analyzer{
				idxByTypes: map[*types.Package]*pkgIndex{typesPkg: idx},
				filePkgs:   map[*pkgIndex]bool{},
				scanned:    map[*ssa.Function]bool{},
			}
			a.scanFunction(&ssa.Function{Pkg: &ssa.Package{Pkg: typesPkg}, Blocks: []*ssa.BasicBlock{{}}})
			if !a.unverifiable || !strings.Contains(a.reason, "cgo external library") {
				t.Fatalf("cgo Class-B = %v/%q, want external library", a.unverifiable, a.reason)
			}
		})
	}
}

func TestTier2CgoPkgConfigUnverifiable(t *testing.T) {
	typesPkg := types.NewPackage("example.com/cgodep", "cgodep")
	idx := &pkgIndex{
		cache: true,
		meta:  &listPkg{CgoPkgConfig: []string{"zlib"}},
	}
	a := &tier2Analyzer{
		idxByTypes: map[*types.Package]*pkgIndex{typesPkg: idx},
		filePkgs:   map[*pkgIndex]bool{},
		scanned:    map[*ssa.Function]bool{},
	}

	a.scanFunction(&ssa.Function{Pkg: &ssa.Package{Pkg: typesPkg}, Blocks: []*ssa.BasicBlock{{}}})
	if !a.unverifiable || !strings.Contains(a.reason, "cgo external library") {
		t.Fatalf("pkg-config cgo Class-B = %v/%q, want external library", a.unverifiable, a.reason)
	}
}

func TestTier2WasmImportUnverifiable(t *testing.T) {
	typesPkg := types.NewPackage("example.com/wasmdep", "wasmdep")
	file := &ast.File{
		Name:     ast.NewIdent("wasmdep"),
		Comments: []*ast.CommentGroup{{List: []*ast.Comment{{Text: "//go:wasmimport env imported"}}}},
	}
	ssaProg := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)
	a := &tier2Analyzer{
		h:          &Hasher{},
		prog:       &program{Prog: ssaProg},
		metaByPath: map[string]*listPkg{},
	}
	idx := a.buildIndex(&packages.Package{ID: "example.com/wasmdep", PkgPath: "example.com/wasmdep", Types: typesPkg, Syntax: []*ast.File{file}})
	if idx == nil || !idx.wasmImport {
		t.Fatalf("buildIndex wasmImport = %v, want true", idx != nil && idx.wasmImport)
	}
	a.idxByTypes = map[*types.Package]*pkgIndex{typesPkg: idx}
	a.filePkgs = map[*pkgIndex]bool{}
	a.scanned = map[*ssa.Function]bool{}

	a.scanFunction(&ssa.Function{Pkg: &ssa.Package{Pkg: typesPkg}, Blocks: []*ssa.BasicBlock{{}}})
	if !a.unverifiable || !strings.Contains(a.reason, "go:wasmimport") {
		t.Fatalf("wasmimport Class-B = %v/%q, want go:wasmimport", a.unverifiable, a.reason)
	}
}

func TestTier2InterfaceMethodSetUsesPackageMetadata(t *testing.T) {
	dotlessTypes := types.NewPackage("myapp", "myapp")
	typeName := types.NewTypeName(token.NoPos, dotlessTypes, "T", nil)
	named := types.NewNamed(typeName, types.NewStruct(nil, nil), nil)
	recv := types.NewVar(token.NoPos, dotlessTypes, "", named)
	method := types.NewFunc(token.NoPos, dotlessTypes, "M", types.NewSignatureType(recv, nil, nil, types.NewTuple(), types.NewTuple(), false))
	named.AddMethod(method)
	idx := &pkgIndex{pkg: &packages.Package{Types: dotlessTypes}, mutable: true}
	a := &tier2Analyzer{
		idxByTypes:  map[*types.Package]*pkgIndex{dotlessTypes: idx},
		seenObjects: map[types.Object]bool{},
	}

	a.addInterfaceMethodSet(named)
	if len(a.objectQueue) != 1 || a.objectQueue[0] != method {
		t.Fatalf("dotless package method queue = %v, want M", a.objectQueue)
	}
}

func TestTier2InterfaceMethodSetSeesEmbeddedStructField(t *testing.T) {
	localTypes := types.NewPackage("example.com/local", "local")
	typeName := types.NewTypeName(token.NoPos, localTypes, "E", nil)
	named := types.NewNamed(typeName, types.NewStruct(nil, nil), nil)
	recv := types.NewVar(token.NoPos, localTypes, "", named)
	method := types.NewFunc(token.NoPos, localTypes, "M", types.NewSignatureType(recv, nil, nil, types.NewTuple(), types.NewTuple(), false))
	named.AddMethod(method)
	embedded := types.NewField(token.NoPos, localTypes, "E", named, true)
	concrete := types.NewStruct([]*types.Var{embedded}, []string{""})
	idx := &pkgIndex{pkg: &packages.Package{Types: localTypes}, mutable: true}
	a := &tier2Analyzer{
		idxByTypes:  map[*types.Package]*pkgIndex{localTypes: idx},
		seenObjects: map[types.Object]bool{},
	}

	a.addInterfaceMethodSet(concrete)
	if len(a.objectQueue) != 1 || a.objectQueue[0] != method {
		t.Fatalf("embedded method queue = %v, want E.M", a.objectQueue)
	}
}

func TestTier2InterfaceMethodsUseDeclaringTypeSource(t *testing.T) {
	pkg := types.NewPackage("example.com/cache", "cache")
	method := types.NewFunc(token.NoPos, pkg, "Read", types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false))
	iface := types.NewInterfaceType([]*types.Func{method}, nil)
	iface.Complete()
	name := types.NewTypeName(token.NoPos, pkg, "Reader", nil)
	types.NewNamed(name, iface, nil)
	node := &ast.TypeSpec{Name: ast.NewIdent("Reader")}
	idx := &pkgIndex{decls: map[types.Object]ast.Node{}}

	addTypeDeclaration(idx, name, node)
	if idx.decls[method] != node {
		t.Fatal("interface method was not attributed to its declaring type")
	}
}

func TestTier2CacheDeclarationTraversesMutableReference(t *testing.T) {
	cacheTypes := types.NewPackage("example.com/cachedep", "cachedep")
	localTypes := types.NewPackage("example.com/localdep", "localdep")
	cacheObj := types.NewConst(token.NoPos, cacheTypes, "C", types.Typ[types.Int], nil)
	localObj := types.NewConst(token.NoPos, localTypes, "LocalC", types.Typ[types.Int], nil)
	cacheTypes.Scope().Insert(cacheObj)
	localTypes.Scope().Insert(localObj)
	localIdent := ast.NewIdent("LocalC")
	node := &ast.ValueSpec{Names: []*ast.Ident{ast.NewIdent("C")}, Values: []ast.Expr{localIdent}}
	cacheIdx := &pkgIndex{
		pkg:   &packages.Package{Types: cacheTypes, TypesInfo: &types.Info{Uses: map[*ast.Ident]types.Object{localIdent: localObj}}},
		cache: true,
		decls: map[types.Object]ast.Node{cacheObj: node},
	}
	localIdx := &pkgIndex{pkg: &packages.Package{Types: localTypes}, mutable: true, decls: map[types.Object]ast.Node{}}
	a := &tier2Analyzer{
		idxByTypes:  map[*types.Package]*pkgIndex{cacheTypes: cacheIdx, localTypes: localIdx},
		seenObjects: map[types.Object]bool{},
		seenTypes:   map[types.Type]bool{},
	}

	a.addObject(cacheObj)
	if len(a.objectQueue) != 1 || a.objectQueue[0] != localObj {
		t.Fatalf("cache declaration queue = %v, want localdep.LocalC", a.objectQueue)
	}
}

func TestTier2CacheFunctionTraversesMutableReference(t *testing.T) {
	cacheTypes := types.NewPackage("example.com/cachedep", "cachedep")
	localTypes := types.NewPackage("example.com/localdep", "localdep")
	cacheFn := types.NewFunc(token.NoPos, cacheTypes, "F", types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(types.NewVar(token.NoPos, nil, "", types.Typ[types.Int])), false))
	localObj := types.NewConst(token.NoPos, localTypes, "C", types.Typ[types.Int], nil)
	cacheTypes.Scope().Insert(cacheFn)
	localTypes.Scope().Insert(localObj)
	fnName := ast.NewIdent("F")
	localIdent := ast.NewIdent("C")
	fnDecl := &ast.FuncDecl{
		Name: fnName,
		Type: &ast.FuncType{
			Params:  &ast.FieldList{},
			Results: &ast.FieldList{List: []*ast.Field{{Type: ast.NewIdent("int")}}},
		},
		Body: &ast.BlockStmt{List: []ast.Stmt{&ast.ReturnStmt{Results: []ast.Expr{localIdent}}}},
	}
	info := &types.Info{
		Defs: map[*ast.Ident]types.Object{fnName: cacheFn},
		Uses: map[*ast.Ident]types.Object{localIdent: localObj},
	}
	ssaProg := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)
	ssaPkg := ssaProg.CreatePackage(cacheTypes, []*ast.File{{Name: ast.NewIdent("cachedep"), Decls: []ast.Decl{fnDecl}}}, info, true)
	ssaFn := ssaPkg.Func("F")
	if ssaFn == nil {
		t.Fatal("ssa function F missing")
	}
	ssaFn.Blocks = []*ssa.BasicBlock{{}}
	cacheIdx := &pkgIndex{
		pkg:   &packages.Package{Types: cacheTypes, TypesInfo: info},
		cache: true,
		decls: map[types.Object]ast.Node{cacheFn: fnDecl},
	}
	localIdx := &pkgIndex{pkg: &packages.Package{Types: localTypes}, mutable: true, decls: map[types.Object]ast.Node{}}
	a := &tier2Analyzer{
		idxByTypes:  map[*types.Package]*pkgIndex{cacheTypes: cacheIdx, localTypes: localIdx},
		seenObjects: map[types.Object]bool{},
		seenTypes:   map[types.Type]bool{},
		filePkgs:    map[*pkgIndex]bool{},
		scanned:     map[*ssa.Function]bool{},
	}

	a.scanFunction(ssaFn)
	if len(a.objectQueue) != 1 || a.objectQueue[0] != localObj {
		t.Fatalf("cache function body queue = %v, want localdep.C", a.objectQueue)
	}
}

func TestTier2CacheInitTraversesMutableReference(t *testing.T) {
	cacheTypes := types.NewPackage("example.com/cachedep", "cachedep")
	localTypes := types.NewPackage("example.com/localdep", "localdep")
	localObj := types.NewConst(token.NoPos, localTypes, "C", types.Typ[types.Int], nil)
	localTypes.Scope().Insert(localObj)
	localIdent := ast.NewIdent("C")
	initDecl := &ast.FuncDecl{
		Name: ast.NewIdent("init"),
		Type: &ast.FuncType{Params: &ast.FieldList{}},
		Body: &ast.BlockStmt{List: []ast.Stmt{&ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent("_")},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{localIdent},
		}}},
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{localIdent: localObj}}
	cacheIdx := &pkgIndex{
		pkg:   &packages.Package{Types: cacheTypes, TypesInfo: info},
		cache: true,
		inits: []ast.Node{initDecl},
	}
	localIdx := &pkgIndex{pkg: &packages.Package{Types: localTypes}, mutable: true, decls: map[types.Object]ast.Node{}}
	a := &tier2Analyzer{
		idxByTypes:  map[*types.Package]*pkgIndex{cacheTypes: cacheIdx, localTypes: localIdx},
		seenObjects: map[types.Object]bool{},
		seenTypes:   map[types.Type]bool{},
		filePkgs:    map[*pkgIndex]bool{},
		scanned:     map[*ssa.Function]bool{},
	}

	a.scanFunction(&ssa.Function{Synthetic: "package initializer", Pkg: &ssa.Package{Pkg: cacheTypes}, Blocks: []*ssa.BasicBlock{{}}})
	if len(a.objectQueue) != 1 || a.objectQueue[0] != localObj {
		t.Fatalf("cache init body queue = %v, want localdep.C", a.objectQueue)
	}
}

func TestImportBindingAnalyzesWithoutWiden(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/importbinding"
	tr, err := computeTier2Result(h, pkg, "BenchmarkImportBinding")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if tr.widen {
		t.Fatalf("import binding fixture widened unexpectedly: %+v", tr)
	}
}

func TestTier2ASMTargetInterfaceInvokeWidens(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/asminvoke"
	tr, err := computeTier2Result(h, pkg, "BenchmarkASMInvoke")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !tr.widen {
		t.Fatalf("widen = false, want post-RTA interface dispatch or computed-call widening")
	}
}

func TestTier2GenericPostRTAInvokeWidens(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/genericpostrta"
	tr, err := computeTier2Result(h, pkg, "BenchmarkGenericPostRTA")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !tr.widen {
		t.Fatalf("widen = false, want generic post-RTA dispatch widening")
	}
}

func TestTier2ReflectReferenceScansClassB(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/reflectexternal"
	tr, err := computeTier2Result(h, pkg, "BenchmarkReflectExternal")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !tr.unverifiable || !strings.Contains(tr.reason, "file I/O") {
		t.Fatalf("reflect target Class-B = %v/%q, want file I/O", tr.unverifiable, tr.reason)
	}
}

func TestUnverifiableReasonSelectionIsDeterministic(t *testing.T) {
	effects := []externalEffect{
		symbolExternalEffect(externalEffectFormattedOutput, "fmt", "Print", "reaches fmt.Print (formatted output)"),
		symbolExternalEffect(externalEffectNetwork, "net", "Dial", "reaches net.Dial (network I/O)"),
		symbolExternalEffect(externalEffectFileIO, "os", "ReadFile", "reaches os.ReadFile (file I/O)"),
	}
	first := &tier2Analyzer{}
	for _, effect := range effects {
		first.recordExternalEffect(effect)
	}
	second := &tier2Analyzer{}
	for i := len(effects) - 1; i >= 0; i-- {
		second.recordExternalEffect(effects[i])
	}
	if first.reason != second.reason {
		t.Fatalf("unverifiable reason depends on traversal order: %q != %q", first.reason, second.reason)
	}
	if !strings.Contains(first.reason, "network I/O") {
		t.Fatalf("legacy reason = %q, want the top-ranked network cause", first.reason)
	}
}

// TestEffectCauseRankStrata pins the cause-preference strata boundaries
// themselves — a flatten of any adjacent pair is a diagnostic-semantics
// change that owes an ObservationRTA bump, so it must fail here rather
// than pass silently.
func TestEffectCauseRankStrata(t *testing.T) {
	mutation := symbolExternalEffect(externalEffectPathMutation, "os", "Remove", "reaches os.Remove (path mutation)")
	read := symbolExternalEffect(externalEffectFileIO, "os", "ReadFile", "reaches os.ReadFile (file I/O)")
	output := symbolExternalEffect(externalEffectFormattedOutput, "fmt", "Print", "reaches fmt.Print (formatted output)")
	unaudited := symbolExternalEffect(externalEffectUnauditedStandard, "time", "Now", "reaches unaudited standard operation time.Now")
	harness := harnessLoggingEffect("Log")
	ordered := []externalEffect{mutation, read, output, unaudited, harness}
	for i := 0; i+1 < len(ordered); i++ {
		if effectCauseRank(ordered[i]) <= effectCauseRank(ordered[i+1]) {
			t.Errorf("effectCauseRank(%s) = %d, want above %s (%d)", ordered[i].reason, effectCauseRank(ordered[i]), ordered[i+1].reason, effectCauseRank(ordered[i+1]))
		}
	}
	// The strata drive the legacy projection end to end: a generic read
	// outranks ambient output and the unaudited classification.
	a := &tier2Analyzer{}
	for _, effect := range []externalEffect{unaudited, output, read} {
		a.recordExternalEffect(effect)
	}
	if !strings.Contains(a.reason, "file I/O") {
		t.Fatalf("legacy reason = %q, want the file I/O cause over output and unaudited", a.reason)
	}
	b := &tier2Analyzer{}
	for _, effect := range []externalEffect{unaudited, output} {
		b.recordExternalEffect(effect)
	}
	if !strings.Contains(b.reason, "formatted output") {
		t.Fatalf("legacy reason = %q, want the formatted-output cause over unaudited", b.reason)
	}
}

func TestTypedEffectsAreCompleteAndDiagnosticSelectionIsDeterministic(t *testing.T) {
	effects := []externalEffect{
		symbolExternalEffect(externalEffectFormattedOutput, "fmt", "Print", "reaches fmt.Print (formatted output)"),
		symbolExternalEffect(externalEffectNetwork, "net", "Dial", "reaches net.Dial (network I/O)"),
		symbolExternalEffect(externalEffectFileIO, "os", "ReadFile", "reaches os.ReadFile (file I/O)"),
	}
	first := &tier2Analyzer{}
	for _, effect := range effects {
		first.recordExternalEffect(effect)
	}
	second := &tier2Analyzer{}
	for i := len(effects) - 1; i >= 0; i-- {
		second.recordExternalEffect(effects[i])
	}
	if first.reason != second.reason {
		t.Fatalf("typed effect diagnostic depends on traversal order: %q != %q", first.reason, second.reason)
	}
	if len(first.effects) != len(effects) || len(second.effects) != len(effects) {
		t.Fatalf("typed effects lost: first=%+v second=%+v", first.effects, second.effects)
	}
	for _, want := range effects {
		for _, got := range [][]externalEffect{first.effects, second.effects} {
			found := false
			for _, effect := range got {
				found = found || effect == want
			}
			if !found {
				t.Errorf("missing typed effect %+v from %+v", want, got)
			}
		}
	}
}

func TestPreferredDiagnosticProjectsAfterSecondaryEffectDeduplication(t *testing.T) {
	rdtsc := opaqueExternalEffect(externalEffectNative, "reaches assembly instruction RDTSC (external runtime state)")
	cpuid := opaqueExternalEffect(externalEffectNative, "reaches assembly instruction CPUID (external runtime state)")
	analyzer := &tier2Analyzer{}
	analyzer.recordExternalEffect(rdtsc)
	analyzer.collectExternalEffect(cpuid)
	analyzer.recordExternalEffect(cpuid)
	if analyzer.reason != cpuid.reason {
		t.Fatalf("preferred diagnostic = %q, want later package preference %q", analyzer.reason, cpuid.reason)
	}
	if len(analyzer.effects) != 2 {
		t.Fatalf("deduplicated effects = %+v, want two", analyzer.effects)
	}
}

func TestStandardLinknameTargetIsUnverifiable(t *testing.T) {
	for _, target := range []string{"runtime.nanotime", "sync.runtime_procPin"} {
		analyzer := &tier2Analyzer{objByName: map[string]types.Object{}}
		analyzer.addLinknameTarget(target)
		if !analyzer.unverifiable || !strings.Contains(analyzer.reason, target) {
			t.Fatalf("standard linkname target %s disposition = %v/%q, want unverifiable", target, analyzer.unverifiable, analyzer.reason)
		}
	}
}

func TestUnsafePointerBasicTypeIsDetected(t *testing.T) {
	if !typeUsesUnsafePointer(types.Typ[types.UnsafePointer]) {
		t.Fatal("unsafe.Pointer basic type was not detected")
	}
}

func TestLinknameLocalTargetResolvesWithoutWiden(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/linknamelocal/bench"
	tr, err := computeTier2Result(h, pkg, "BenchmarkLinknameLocal")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if tr.widen {
		t.Fatalf("locally resolvable linkname widened: %+v", tr)
	}
}

func TestTier2ReverseLinknameTargetEnqueued(t *testing.T) {
	upperTypes := types.NewPackage("example.com/upper", "upper")
	lowerTypes := types.NewPackage("example.com/lower", "lower")
	upperG := types.NewFunc(token.NoPos, upperTypes, "g", types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false))
	lowerF := types.NewFunc(token.NoPos, lowerTypes, "f", types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false))
	upperTypes.Scope().Insert(upperG)
	lowerTypes.Scope().Insert(lowerF)
	upperIdx := &pkgIndex{pkg: &packages.Package{Types: upperTypes}, mutable: true, decls: map[types.Object]ast.Node{upperG: &ast.FuncDecl{Name: ast.NewIdent("g")}}}
	lowerIdx := &pkgIndex{pkg: &packages.Package{Types: lowerTypes}, mutable: true, decls: map[types.Object]ast.Node{lowerF: &ast.FuncDecl{Name: ast.NewIdent("f")}}, linknames: map[types.Object]string{lowerF: "example.com/upper.g"}}
	a := &tier2Analyzer{
		prog:             &program{Prog: ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)},
		idxByTypes:       map[*types.Package]*pkgIndex{upperTypes: upperIdx, lowerTypes: lowerIdx},
		objsByLinkTarget: map[string][]types.Object{},
		seenObjects:      map[types.Object]bool{},
		seenTypes:        map[types.Type]bool{},
		filePkgs:         map[*pkgIndex]bool{},
	}
	a.addReverseLinkname("example.com/upper.g", lowerF)

	a.addObject(upperG)
	if len(a.objectQueue) != 1 || a.objectQueue[0] != lowerF {
		t.Fatalf("reverse linkname queue = %v, want lower.f", a.objectQueue)
	}
}

func TestBuildIndexVarLinknameHashesGenDeclDoc(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.go")
	const source = `package p

//go:linkname linked example.com/cachedep.A
var linked int
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	typesPkg, err := new(types.Config).Check("example.com/p", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatalf("type check: %v", err)
	}
	a := &tier2Analyzer{
		h:          &Hasher{},
		prog:       &program{Prog: ssa.NewProgram(fset, ssa.InstantiateGenerics)},
		metaByPath: map[string]*listPkg{},
	}
	idx := a.buildIndex(&packages.Package{ID: "example.com/p", PkgPath: "example.com/p", Dir: dir, Types: typesPkg, TypesInfo: info, Syntax: []*ast.File{file}})
	obj := typesPkg.Scope().Lookup("linked")
	if obj == nil {
		t.Fatal("linked object missing")
	}
	if got := idx.linknames[obj]; got != "example.com/cachedep.A" {
		t.Fatalf("linkname target = %q, want example.com/cachedep.A", got)
	}
	if _, ok := idx.decls[obj].(*ast.GenDecl); !ok {
		t.Fatalf("linked var declaration node = %T, want *ast.GenDecl to include directive doc", idx.decls[obj])
	}
}

func TestBenchmarkRootScopedToTargetPackage(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/rootcollision/bench"
	prog, err := h.loadCached(pkg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Both packages declare a BenchmarkSame; the subject must root at the
	// target package's own benchmark, never the recompiled dependency's.
	root := prog.Roots["BenchmarkSame"]
	if root == nil || !strings.Contains(root.String(), "rootcollision/bench") {
		t.Fatalf("BenchmarkSame root = %v, want the target package's own benchmark", root)
	}
	if strings.Contains(root.String(), "rootcollision/dep") {
		t.Fatalf("BenchmarkSame rooted at the dependency's benchmark: %v", root)
	}
}

// reachContains reports whether any reachable function's name carries every
// given substring.
func reachContains(reach map[string]bool, parts ...string) bool {
	for name := range reach {
		all := true
		for _, part := range parts {
			if !strings.Contains(name, part) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func stringSliceContains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkHashFiles(b *testing.B) {
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte("package p\nvar X = 1\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	files := []string{"x.go"}
	for b.Loop() {
		if _, err := hashFiles(dir, files, nil); err != nil {
			b.Fatal(err)
		}
	}
}
