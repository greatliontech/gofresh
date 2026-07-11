package closure

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

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

	h1, err := hashFiles(dir, []string{"a.go", "b.go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(h1) != 32 {
		t.Errorf("hash len: got %d", len(h1))
	}

	// Order-insensitive (files sorted internally).
	if h2, _ := hashFiles(dir, []string{"b.go", "a.go"}); h2 != h1 {
		t.Errorf("hash not order-insensitive: %q vs %q", h1, h2)
	}

	// Content change ⇒ different hash (REQ-closure-mutable-local / REQ-closure-coverage at the file level).
	write("b.go", "package p\nvar X = 2\n")
	if h3, _ := hashFiles(dir, []string{"a.go", "b.go"}); h3 == h1 {
		t.Error("hash insensitive to content change")
	}

	// Missing file ⇒ error, never silently skipped.
	if _, err := hashFiles(dir, []string{"missing.go"}); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestContribution(t *testing.T) {
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}

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

func TestContributionIncludesASMIncludes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "defs.inc", "#define RETVAL $1\n")
	writeFile(t, dir, "asm.s", "#include \"defs.inc\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tMOVQ RETVAL, AX\n\tRET\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
	pkg := listPkg{ImportPath: "example/p", Dir: dir, SFiles: []string{"asm.s"}, Module: &listMod{Main: true, Dir: dir}}
	one, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution: %v", err)
	}
	writeFile(t, dir, "defs.inc", "#define RETVAL $2\n")
	two, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after include edit: %v", err)
	}
	if one == two {
		t.Fatalf("asm include edit did not change contribution: %q", one)
	}
}

func TestContributionIncludesAbsoluteASMInclude(t *testing.T) {
	dir := t.TempDir()
	includeDir := t.TempDir()
	include := filepath.Join(includeDir, "defs.inc")
	writeFile(t, includeDir, "defs.inc", "#define RETVAL $1\n")
	writeFile(t, dir, "asm.s", "#include \""+filepath.ToSlash(include)+"\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tMOVQ RETVAL, AX\n\tRET\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
	pkg := listPkg{ImportPath: "example/p", Dir: dir, SFiles: []string{"asm.s"}, Module: &listMod{Main: true, Dir: dir}}
	one, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution: %v", err)
	}
	writeFile(t, includeDir, "defs.inc", "#define RETVAL $2\n")
	two, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after include edit: %v", err)
	}
	if one == two {
		t.Fatalf("absolute asm include edit did not change contribution: %q", one)
	}
}

func TestContributionOpaqueASMHashesPackageFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "defs.inc", "#define RETVAL $1\n")
	writeFile(t, dir, "asm.s", "#ifdef WANT\n#define RETVAL $1\n#endif\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tMOVQ RETVAL, AX\n\tRET\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
	pkg := listPkg{ImportPath: "example/p", Dir: dir, SFiles: []string{"asm.s"}, Module: &listMod{Main: true, Dir: dir}}
	one, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution: %v", err)
	}
	writeFile(t, dir, "defs.inc", "#define RETVAL $2\n")
	two, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after include edit: %v", err)
	}
	if one == two {
		t.Fatalf("opaque asm contribution did not include package file defs.inc: %q", one)
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
			h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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

func TestContributionRejectsUnresolvedASMInclude(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "asm.s", "#include \"defs.inc\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tRET\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
	pkg := listPkg{ImportPath: "example/p", Dir: dir, SFiles: []string{"asm.s"}, Module: &listMod{Main: true, Dir: dir}}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "unresolved asm include") {
		t.Fatalf("contribution error = %v, want unresolved asm include", err)
	}
}

func TestContributionAcceptsGeneratedASMInclude(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "asm.s", "#include \"go_asm.h\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tRET\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
	pkg := listPkg{ImportPath: "example/p", Dir: dir, SFiles: []string{"asm.s"}, Module: &listMod{Main: true, Dir: dir}}
	if _, err := h.contribution(pkg); err != nil {
		t.Fatalf("generated go_asm.h include: %v", err)
	}
	_, _, opaque, _, err := asmCallTargets(dir, pkg.SFiles)
	if err != nil {
		t.Fatal(err)
	}
	if opaque {
		t.Fatal("generated go_asm.h constants requested whole-closure widening")
	}
	generated, err := hasGeneratedASMInclude(dir, pkg.SFiles)
	if err != nil {
		t.Fatal(err)
	}
	if !generated {
		t.Fatal("generated go_asm.h include was not attributed to package source")
	}
}

func TestContributionRejectsASMSymlinkIncludeDirDotDot(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cfg.h", "#define RETVAL $1\n")
	writeFile(t, outside, "cfg.h", "#define RETVAL $2\n")
	writeFile(t, dir, "asm.s", "#include \"include/../cfg.h\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tMOVQ RETVAL, AX\n\tRET\n")
	if err := os.Symlink(filepath.Join(outside, "sub"), filepath.Join(dir, "include")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
	pkg := listPkg{ImportPath: "example/p", Dir: dir, SFiles: []string{"asm.s"}, Module: &listMod{Main: true, Dir: dir}}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "unresolved asm include") {
		t.Fatalf("contribution error = %v, want unresolved asm include", err)
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
	if got := len(p.sourceFiles()); got != 12 {
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
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache")}
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

func FuzzClosureFloor(f *testing.F) {
	h, err := New()
	if err != nil {
		f.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/reflectfixture"
	maximal, err := h.maximalHash(pkg)
	if err != nil {
		f.Fatal(err)
	}
	f.Add("arbitrary precise contribution")
	f.Fuzz(func(t *testing.T, contribution string) {
		got, err := h.closureFromTier2(pkg, tier2Result{widen: true, contribs: []string{contribution}})
		if err != nil {
			t.Fatal(err)
		}
		if got.Hash != maximal {
			t.Fatalf("widened hash = %s, maximal = %s", got.Hash, maximal)
		}
	})
}

// TestParseListError: a package reporting a load Error must fail the parse, never
// be silently dropped from the closure (REQ-fresh-sound).
func TestParseListError(t *testing.T) {
	const stream = `{"ImportPath":"ok/pkg","Dir":"/x","Module":{"Main":true}}
{"ImportPath":"bad/pkg","Error":{"Err":"cannot find package"}}`
	if _, err := parseList(strings.NewReader(stream)); err == nil {
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

// TestBatchLoadMatchesPerPackage is the equivalence guard for Prime: a batched
// shared packages.Load must yield, for every benchmark, byte-identical Compute
// output (hash, unverifiable, reason) to the per-package single load. This is what
// makes Prime a sound optimization rather than a behavior change — an under-scoped
// rootsForBinary would shrink a program's package set, drop a registering init
// from RTA's roots, and under-cover the closure (false-valid, REQ-fresh-sound); that shows
// up here as a hash mismatch. The fixtures span the soundness-sensitive paths:
// cross-package init-side-effect registration, init file I/O, an external test
// package, a TestMain root, and reflection.
func TestBatchLoadMatchesPerPackage(t *testing.T) {
	const base = "github.com/greatliontech/gofresh/closure/fixtures/"
	pkgs := []string{
		base + "initregistry/bench",
		base + "initfile",
		base + "external",
		base + "externalbench",       // benchmark lives in the external (package X_test) test package
		base + "rootcollision/bench", // imports rootcollision/dep, also primed (cross-prime-import shape)
		base + "rootcollision/dep",
		base + "testmainroot",
		base + "reflectexternal",
		base + "initdynamic",
	}

	primed, err := New()
	if err != nil {
		t.Fatalf("New (primed): %v", err)
	}
	primed.Prime(pkgs)

	compared := 0
	for _, pkg := range pkgs {
		// Assert the batch actually cached this package: otherwise Compute would
		// fall back to a single load and the comparison would be single-vs-single —
		// a vacuous pass that hides an under-scoped rootsForBinary.
		if _, ok := primed.progs[pkg]; !ok {
			t.Fatalf("Prime did not cache %s; batch path not exercised (test would be vacuous)", pkg)
		}

		// Discover the benchmark names via an independent single-load hasher; the
		// discovery machinery is not what is under test — the hash equivalence is.
		single, err := New()
		if err != nil {
			t.Fatalf("New (single) for %s: %v", pkg, err)
		}
		prog, err := single.loadCached(pkg)
		if err != nil {
			t.Fatalf("single load %s: %v", pkg, err)
		}
		var benches []string
		for name := range prog.roots {
			benches = append(benches, name)
		}
		sort.Strings(benches)
		if len(benches) == 0 {
			t.Fatalf("%s has no benchmarks; fixture cannot exercise the comparison", pkg)
		}

		for _, b := range benches {
			want, errWant := single.Compute(pkg, b)
			got, errGot := primed.Compute(pkg, b)
			if (errWant == nil) != (errGot == nil) {
				t.Errorf("%s.%s: single err=%v, primed err=%v", pkg, b, errWant, errGot)
				continue
			}
			if errWant != nil {
				continue
			}
			if got != want {
				t.Errorf("%s.%s: primed Compute %+v != single %+v", pkg, b, got, want)
			}
			compared++
		}
	}
	if compared == 0 {
		t.Fatal("no benchmarks compared; test is vacuous")
	}
	t.Logf("compared %d benchmark(s) batch-vs-single across %d packages", compared, len(pkgs))
}

// TestRootsForBinaryMatchesSingleLoad pins rootsForBinary's contract structurally:
// the roots it selects for a package out of a batched packages.Load must be
// exactly the roots a single packages.Load(pkg) returns. This is the
// by-construction basis for Prime's equivalence — a selection that is too narrow
// would build a smaller program (a dropped test-main or test variant) and
// under-cover the closure. Unlike the hash-level equivalence test, this observes
// the full root set, so it catches a dropped clause even when that root is
// behaviorally inert for the fixtures at hand.
func TestRootsForBinaryMatchesSingleLoad(t *testing.T) {
	const base = "github.com/greatliontech/gofresh/closure/fixtures/"
	pkgs := []string{
		base + "initregistry/bench",
		base + "external",
		base + "externalbench",       // exercises the ForTest clause: a distinct package X_test root
		base + "rootcollision/bench", // primed alongside its own dependency rootcollision/dep
		base + "rootcollision/dep",
		base + "testmainroot",
		base + "initfile",
	}
	batch, err := packages.Load(loadConfig(context.Background(), ""), pkgs...)
	if err != nil {
		t.Fatalf("batch load: %v", err)
	}
	idSet := func(ps []*packages.Package) map[string]bool {
		m := map[string]bool{}
		for _, p := range ps {
			m[p.ID] = true
		}
		return m
	}
	for _, pkg := range pkgs {
		single, err := packages.Load(loadConfig(context.Background(), ""), pkg)
		if err != nil {
			t.Fatalf("single load %s: %v", pkg, err)
		}
		want := idSet(single)
		got := idSet(rootsForBinary(batch, pkg))
		if len(want) == 0 {
			t.Fatalf("%s: single load returned no roots", pkg)
		}
		if len(got) != len(want) {
			t.Errorf("%s: rootsForBinary selected %d roots, single load returned %d", pkg, len(got), len(want))
		}
		for id := range want {
			if !got[id] {
				t.Errorf("%s: rootsForBinary missing root %q that single load returned", pkg, id)
			}
		}
		for id := range got {
			if !want[id] {
				t.Errorf("%s: rootsForBinary selected extra root %q not in single load", pkg, id)
			}
		}
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

func TestPrimeUsesBuildFlags(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/tagged\n\ngo 1.26\n")
	writeFile(t, dir, "selected_default.go", "//go:build !special\n\npackage tagged\n\nfunc Selected() int { return 1 }\n")
	writeFile(t, dir, "selected_special.go", "//go:build special\n\npackage tagged\n\nfunc Selected() int { return 2 }\n")

	const pkg = "example.com/tagged"
	primed, err := NewAt(dir, "-tags=special")
	if err != nil {
		t.Fatal(err)
	}
	primed.Prime([]string{pkg})
	if _, ok := primed.progs[pkg]; !ok {
		t.Fatal("Prime did not cache the tagged package")
	}
	got, err := primed.Compute(pkg, "Selected")
	if err != nil {
		t.Fatal(err)
	}
	lazy, err := NewAt(dir, "-tags=special")
	if err != nil {
		t.Fatal(err)
	}
	want, err := lazy.Compute(pkg, "Selected")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("primed tagged closure = %+v, lazy tagged closure = %+v", got, want)
	}
}

func TestBuildFlagsDriveASMClosure(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/asmflag\n\ngo 1.26\n")
	writeFile(t, dir, "asmflag.go", "package asmflag\n\nfunc asmEntry()\nfunc Subject() { asmEntry() }\nfunc hook() {}\nfunc helper() {}\n")
	writeFile(t, dir, "asm.s", "#include \"textflag.h\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL ·hook(SB)\n\tRET\n")

	const pkg = "example.com/asmflag"
	plain, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	plainClosure, err := plain.Compute(pkg, "Subject")
	if err != nil {
		t.Fatal(err)
	}
	plainMax, err := plain.maximalHash(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if plainClosure.Hash == plainMax {
		t.Fatal("plain assembly closure widened; flagged comparison would be vacuous")
	}

	flagged, err := NewAt(dir, "-asmflags=all=-D=hook=helper")
	if err != nil {
		t.Fatal(err)
	}
	flaggedClosure, err := flagged.Compute(pkg, "Subject")
	if err != nil {
		t.Fatal(err)
	}
	flaggedMax, err := flagged.maximalHash(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if flaggedClosure.Hash != flaggedMax {
		t.Fatalf("assembly define closure = %s, want maximal %s", flaggedClosure.Hash, flaggedMax)
	}
}

// TestComputeRootsAnySubject pins the generalized root seam: Compute resolves any
// top-level function as a subject — a production function, not only a Benchmark* —
// through both the test-variant package (a package that also has tests) and the
// plain-package fallback (a package with no test files), and errors clearly on a
// name that resolves to no function. Before generalization the root index held only
// Benchmark*/TestMain, so a production symbol was reported "not found".
func TestComputeRootsAnySubject(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// (a) A production function in a package that also has tests: resolved via the
	// test-variant package, which compiles the package WITH its test files and so
	// holds production and test symbols alike.
	const withTests = "github.com/greatliontech/gofresh/internal/gotool"
	a, err := h.Compute(withTests, "RunIn")
	if err != nil {
		t.Fatalf("Compute production func RunIn: %v", err)
	}
	if a.Hash == "" {
		t.Fatal("empty closure hash for a resolvable production subject")
	}
	if again, err := h.Compute(withTests, "RunIn"); err != nil || again.Hash != a.Hash {
		t.Errorf("nondeterministic: %q vs %q (err %v)", again.Hash, a.Hash, err)
	}

	// (b) A function in a package with NO test files: resolved via the plain-package
	// fallback (no ForTest variant exists).
	const noTests = "github.com/greatliontech/gofresh/closure/fixtures/rootcollision/dep"
	b, err := h.Compute(noTests, "BenchmarkSame")
	if err != nil {
		t.Fatalf("Compute func in a no-test package: %v", err)
	}
	if b.Hash == "" {
		t.Fatal("empty closure hash via the plain-package fallback")
	}

	// A name that resolves to no function is a clear error, not a silent empty root.
	if _, err := h.Compute(withTests, "NoSuchFunction"); err == nil {
		t.Error("a name resolving to no function: want error, got nil")
	}
}

// TestComputeRootsMethods pins method-subject resolution: a method is named
// "Type.Method" (matching the consumer symbol grammar with the package prefix
// stripped), resolves through both value- and pointer-receiver method sets, roots
// at that specific method, and errors on a missing method name.
func TestComputeRootsMethods(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/methodsubject"

	val, err := h.Compute(pkg, "Adder.Value") // value receiver
	if err != nil {
		t.Fatalf("Compute value-receiver method Adder.Value: %v", err)
	}
	if val.Hash == "" {
		t.Fatal("empty closure hash for a method subject")
	}
	ptr, err := h.Compute(pkg, "Adder.Ptr") // pointer receiver
	if err != nil {
		t.Fatalf("Compute pointer-receiver method Adder.Ptr: %v", err)
	}
	// The two methods reach distinct helpers, so rooting at the specific method (not
	// the whole type or package) yields distinct closures.
	if ptr.Hash == val.Hash {
		t.Error("Adder.Value and Adder.Ptr hash identically; not rooting at the specific method")
	}
	if _, err := h.Compute(pkg, "Adder.Missing"); err == nil {
		t.Error("a missing method name: want error, got nil")
	}
}

// TestComputeRootsGenericMethods pins that method subjects on a generic receiver
// type resolve — the pointer star and generics are dropped from the type name
// (Box[T] → "Box"), and each method roots at its own closure. SSA materializes the
// receiver, so no deferral is needed.
func TestComputeRootsGenericMethods(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/genericmethod"
	get, err := h.Compute(pkg, "Box.Get") // value receiver on Box[T]
	if err != nil {
		t.Fatalf("Compute Box.Get: %v", err)
	}
	set, err := h.Compute(pkg, "Box.Set") // pointer receiver on Box[T]
	if err != nil {
		t.Fatalf("Compute Box.Set: %v", err)
	}
	if get.Hash == "" || set.Hash == "" {
		t.Fatal("empty closure hash for a generic-receiver method")
	}
	if get.Hash == set.Hash {
		t.Error("Box.Get and Box.Set hash identically; not rooting at the specific method")
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

	bench, err := h.Compute(pkg, "BenchmarkProd")
	if err != nil {
		t.Fatalf("Compute BenchmarkProd: %v", err)
	}
	if !bench.Unverifiable {
		t.Error("test subject: want unverifiable (its closure reaches TestMain's file I/O), got verifiable")
	}

	prod, err := h.Compute(pkg, "Prod")
	if err != nil {
		t.Fatalf("Compute Prod: %v", err)
	}
	if prod.Unverifiable {
		t.Errorf("production subject: want verifiable (TestMain not in its closure), got unverifiable: %s", prod.Reason)
	}
}

// TestComputeIncludesInitRegisteredSideEffectPackage pins REQ-fresh-sound for registry
// patterns: a side-effect import's init can register an implementation that the
// benchmark later observes through package-level state and interface dispatch.
// Tier-2 roots linked startup code so the registering package source is hashed
// even though the benchmark never names it directly.
func TestComputeIncludesInitRegisteredSideEffectPackage(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const benchPkg = "github.com/greatliontech/gofresh/closure/fixtures/initregistry/bench"
	const codecPkg = "github.com/greatliontech/gofresh/closure/fixtures/initregistry/codec"

	cl, err := h.Compute(benchPkg, "BenchmarkDecode")
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if len(cl.Hash) != 32 {
		t.Fatalf("hash len: got %d (%q)", len(cl.Hash), cl.Hash)
	}

	contribs, _, err := h.tier2Contributions(benchPkg, "BenchmarkDecode")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	// The init body must be hashed, but the load-bearing edit for this false-valid
	// is the *registered method* body: the benchmark dispatches gz.Decode through
	// registry state and an interface without naming codec, so gz.Decode is reached
	// only because all package inits are RTA roots. Hashing only the init would
	// leave a gz.Decode body change unhashed (REQ-closure-coverage reference/side-effect closure).
	if !contribHasAll(contribs, codecPkg, "codec.go", ":init=") {
		t.Fatalf("init-registered side-effect package %s init body missing from closure contributions: %v", codecPkg, contribs)
	}
	if !contribHasAll(contribs, codecPkg, "codec.go", "Decode") {
		t.Fatalf("init-registered method gz.Decode missing from closure contributions: %v", contribs)
	}
}

func TestComputeIncludesTestMainRoot(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/testmainroot"
	contribs, _, err := h.tier2Contributions(pkg, "BenchmarkTestMainRoot")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	if !contribContains(contribs, "TestMain") || !contribContains(contribs, "setup") {
		t.Fatalf("TestMain/setup missing from closure contributions: %v", contribs)
	}
}

func TestTier2DeclarationPrecision(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/direct"
	contribs, widened, err := h.tier2Contributions(pkg, "BenchmarkDirect")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	if widened {
		t.Fatalf("direct fixture widened to Tier-1; contributions: %v", contribs)
	}
	for _, want := range []string{"used", "UsedConst", "UsedType"} {
		if !contribContains(contribs, want) {
			t.Fatalf("Tier-2 contribution missing %q: %v", want, contribs)
		}
	}
	for _, notWant := range []string{"unused", "UnusedConst", "UnusedType"} {
		if contribContains(contribs, notWant) {
			t.Fatalf("Tier-2 contribution unexpectedly contains %q: %v", notWant, contribs)
		}
	}
	cl, err := h.Compute(pkg, "BenchmarkDirect")
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	maxHash, err := h.maximalHash(pkg)
	if err != nil {
		t.Fatalf("maximalHash: %v", err)
	}
	if cl.Hash == maxHash {
		t.Fatalf("direct Tier-2 hash unexpectedly equals maximal Tier-1 hash %q", cl.Hash)
	}
}

func TestBuildIndexTrustsGoListStandardForDotlessModule(t *testing.T) {
	typesPkg := types.NewPackage("myapp", "myapp")
	ssaProg := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)
	a := &tier2Analyzer{
		h:          &Hasher{},
		prog:       &program{prog: ssaProg},
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

func TestComputeFindsExternalTestBenchmark(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/externalbench"
	contribs, _, err := h.tier2Contributions(pkg, "BenchmarkExternal")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	if !contribContains(contribs, "BenchmarkExternal") {
		t.Fatalf("external test benchmark root missing from contributions: %v", contribs)
	}
}

func TestTier2PinsLinkedCacheModules(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure"
	contribs, _, err := h.tier2Contributions(pkg, "BenchmarkHashFiles")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	if !contribContains(contribs, "cache:golang.org/x/tools@v0.47.0") {
		t.Fatalf("linked x/tools module version missing from Tier-2 contributions: %v", contribs)
	}
}

func TestTier2ScansReachedCacheASM(t *testing.T) {
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
	if !a.widen || !strings.Contains(a.widenReason, "computed asm call") {
		t.Fatalf("computed cache asm call did not widen: widen=%v reason=%q", a.widen, a.widenReason)
	}
	if len(a.contribs) != 0 {
		t.Fatalf("cache package source was hashed unexpectedly: %v", a.contribs)
	}
}

func TestComputeStdWrapperClassBUnverifiable(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/stdwrapper"
	cl, err := h.Compute(pkg, "BenchmarkTemplateParseFiles")
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !cl.Unverifiable || !strings.Contains(cl.Reason, "file I/O") {
		t.Fatalf("std wrapper Class-B = %v/%q, want file I/O", cl.Unverifiable, cl.Reason)
	}
}

func TestTier2StdCallbackContributesMethod(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/stdcallback"
	contribs, _, err := h.tier2Contributions(pkg, "BenchmarkSortCallback")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	if !contribContains(contribs, "Less") {
		t.Fatalf("std callback method Less missing from contributions: %v", contribs)
	}
}

func TestTier2EmbedFileContribution(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/embedfixture"
	contribs, _, err := h.tier2Contributions(pkg, "BenchmarkEmbed")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	if !contribContains(contribs, "embed:") || !contribContains(contribs, "data.txt") {
		t.Fatalf("embed data file missing from contributions: %v", contribs)
	}
}

func TestComputeReachesUnverifiable(t *testing.T) {
	// Every benchmark here reaches a Class-B external dependence in its closure
	// (file I/O, filesystem/path mutation, or network), so the closure is
	// unverifiable with the matching reason — and still carries a computed hash
	// (unverifiable is a verdict; the hash is always recorded, REQ-guard-recompute). File I/O is
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
	for _, tc := range []struct{ pkg, bench, reason string }{
		{"external", "BenchmarkReadFile", "file I/O"},
		{"initfile", "BenchmarkInitFile", "file I/O"},
		{"initcwd", "BenchmarkInitCWD", "file I/O"},
		{"unixcwd", "BenchmarkUnixCWD", "file I/O"},
		{"initstdhelper", "BenchmarkInitStdHelper", "file I/O"},
		{"sharedfile", "BenchmarkSharedFile", "file I/O"},
		{"sharedparam", "BenchmarkSharedParam", "file I/O"},
		{"sharedglobal", "BenchmarkSharedGlobal", "file I/O"},
		{"sharedchdir", "BenchmarkSharedChdir", "file I/O"},
		{"sharedfchdir", "BenchmarkSharedFchdir", "file I/O"},
		{"unixfchdir", "BenchmarkUnixFchdir", "file I/O"},
		{"openfileread", "BenchmarkOpenFileRead", "file I/O"},
		{"openrootread", "BenchmarkRootOpenFileRead", "file I/O"},
		{"initdynamic", "BenchmarkInitDynamic", "file I/O"},
		{"initstdcallback", "BenchmarkInitStdCallback", "file I/O"},
		{"testmainfile", "BenchmarkTestMainFile", "file I/O"},
		{"testmainruntimefile", "BenchmarkTestMainRuntimeFile", "file I/O"},
		{"pathbinding", "BenchmarkPathBinding", "path mutation"},
		{"syscallbinding", "BenchmarkSyscallBinding", "path mutation"},
		{"mkdirtemp", "BenchmarkMkdirTemp", "path mutation"},
		{"mkdir", "BenchmarkMkdir", "path mutation"},
		{"unixatbinding", "BenchmarkUnixAtBinding", "path mutation"},
		{"tempdir", "BenchmarkTempDir", "path mutation"},
		{"copyfs", "BenchmarkCopyFS", "path mutation"},
		{"createtemp", "BenchmarkCreateTemp", "filesystem mutation"},
		{"filemutations", "BenchmarkCreate", "filesystem mutation"},
		{"filemutations", "BenchmarkOpenFileCreate", "filesystem mutation"},
		{"filemutations", "BenchmarkWriteFile", "filesystem mutation"},
		{"unixopencreate", "BenchmarkUnixOpenCreate", "filesystem mutation"},
		{"mixedexternal", "BenchmarkMixedExternal", "network I/O"},
	} {
		t.Run(tc.pkg+"/"+tc.bench, func(t *testing.T) {
			cl, err := h.Compute(base+tc.pkg, tc.bench)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if !cl.Unverifiable || !strings.Contains(cl.Reason, tc.reason) {
				t.Fatalf("unverifiable = %v, reason = %q, want reason containing %q", cl.Unverifiable, cl.Reason, tc.reason)
			}
			if cl.Hash == "" {
				t.Fatal("unverifiable closure has empty hash")
			}
		})
	}
}

func TestTier2ReflectWidens(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/reflectfixture"
	_, widened, err := h.tier2Contributions(pkg, "BenchmarkReflect")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	if !widened {
		t.Fatal("reflect dispatch did not widen to Tier-1")
	}
	cl, err := h.Compute(pkg, "BenchmarkReflect")
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	maxHash, err := h.maximalHash(pkg)
	if err != nil {
		t.Fatalf("maximalHash: %v", err)
	}
	if cl.Hash != maxHash {
		t.Fatalf("reflect widened hash = %q, want maximal %q", cl.Hash, maxHash)
	}
}

func TestTier2GenericInterfaceEscapeHashesMethodBody(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/genericescape"
	contribs, widened, err := h.tier2Contributions(pkg, "BenchmarkGenericEscape")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	if widened {
		t.Fatalf("generic interface escape widened to Tier-1 (imprecise): %v", contribs)
	}
	// Secret is reached only via interface escape (never called → not RTA-reachable);
	// its instantiated object has no decl node, so the origin body must be hashed.
	if !contribContains(contribs, "Secret") {
		t.Fatalf("generic method body reached via interface escape missing from contributions: %v", contribs)
	}
}

func TestTier2ConstGroupHashesImplicitContext(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/constgroup"
	contribs, widened, err := h.tier2Contributions(pkg, "BenchmarkConstGroup")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	if widened {
		t.Fatalf("const group fixture widened to Tier-1: %v", contribs)
	}
	if !contribContains(contribs, "Seed") || !contribContains(contribs, "Used") {
		t.Fatalf("implicit const group context missing from contributions: %v", contribs)
	}
}

func TestTier2ASMStaticCallAddsGoTarget(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/asmcall"
	tr, err := h.tier2(pkg, "BenchmarkASMCall")
	if err != nil {
		t.Fatalf("tier2: %v", err)
	}
	contribs := tr.contribs
	if tr.widen {
		t.Fatalf("static asm call fixture widened unexpectedly (%s): %v", tr.widenReason, contribs)
	}
	if !contribContains(contribs, "helper") {
		t.Fatalf("asm static call target helper missing from contributions: %v", contribs)
	}
	if !contribContains(contribs, "asm_amd64.s") {
		t.Fatalf("asm source file missing from contributions: %v", contribs)
	}
	cl, err := h.Compute(pkg, "BenchmarkASMCall")
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !cl.Unverifiable || !strings.Contains(cl.Reason, "file I/O") {
		t.Fatalf("asm call target Class-B = %v/%q, want file I/O", cl.Unverifiable, cl.Reason)
	}
}

func TestTier2ASMStaticJumpAddsGoTarget(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/asmcall"
	tr, err := h.tier2(pkg, "BenchmarkASMJump")
	if err != nil {
		t.Fatalf("tier2: %v", err)
	}
	contribs := tr.contribs
	if tr.widen {
		t.Fatalf("static asm jump fixture widened unexpectedly (%s): %v", tr.widenReason, contribs)
	}
	if !contribContains(contribs, "jumpHelper") {
		t.Fatalf("asm static jump target jumpHelper missing from contributions: %v", contribs)
	}
}

func TestTier2ASMMacroAddsGoTarget(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/asmcall"
	tr, err := h.tier2(pkg, "BenchmarkASMMacro")
	if err != nil {
		t.Fatalf("tier2: %v", err)
	}
	if tr.widen {
		t.Fatalf("asm macro fixture widened unexpectedly (%s): %v", tr.widenReason, tr.contribs)
	}
	if !contribContains(tr.contribs, "macroHelper") {
		t.Fatalf("asm macro call target macroHelper missing from contributions: %v", tr.contribs)
	}
}

func TestTier2ASMSymbolComponentMacroAddsGoTarget(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/asmcall"
	tr, err := h.tier2(pkg, "BenchmarkASMComponentMacro")
	if err != nil {
		t.Fatalf("tier2: %v", err)
	}
	if tr.widen {
		t.Fatalf("asm component macro fixture widened unexpectedly (%s): %v", tr.widenReason, tr.contribs)
	}
	if !contribContains(tr.contribs, "componentHelper") {
		t.Fatalf("asm component macro target componentHelper missing from contributions: %v", tr.contribs)
	}
	if contribContains(tr.contribs, "COMPONENT_HELPER") {
		t.Fatalf("asm component macro resolved pre-expanded decoy: %v", tr.contribs)
	}
}

func TestTier2ASMLocalJumpContinuesScanning(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/asmcall"
	tr, err := h.tier2(pkg, "BenchmarkASMLocalJump")
	if err != nil {
		t.Fatalf("tier2: %v", err)
	}
	if tr.widen {
		t.Fatalf("asm local jump fixture widened unexpectedly (%s): %v", tr.widenReason, tr.contribs)
	}
	if !contribContains(tr.contribs, "localJumpHelper") {
		t.Fatalf("asm call after local jump missing from contributions: %v", tr.contribs)
	}
}

func TestASMCallTargetsExpandsParamMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define CALL_GO(x) CALL ·x(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_GO(helper)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsIndirectCallWidens(t *testing.T) {
	// Every register/computed-target call or jump across Go's arches must widen
	// (computed) so the Go function it dispatches cannot change unhashed (REQ-closure-blindspot).
	// The ≥3-field forms (JALR/JIRL) are the ones only isASMIndirectCallOp catches
	// (asmUnknownOpMayHideCall's 2-field and single-op rules miss them); the rest are
	// belt-and-suspenders. Each mnemonic is the sole computed trigger — no (SB)
	// operand on any other line — so the assertion is about that mnemonic alone.
	for _, tc := range []struct {
		name, line   string
		wantComputed bool
		wantTarget   string
	}{
		{"jalr riscv64 (3-field)", "JALR RA, 0(T0)", true, ""},
		{"jirl loong64 (3-field)", "JIRL R1, R12, 0", true, ""},
		{"jr mips", "JR R5", true, ""},
		{"blr arm64", "BLR R0", true, ""},
		{"bctrl ppc64", "BCTRL", true, ""},
		{"bctr ppc64", "BCTR", true, ""},
		{"bx arm", "BX R1", true, ""},
		{"blx arm", "BLX R2", true, ""},
		{"bal mips", "BAL R3", true, ""},
		{"callind", "CALLIND R4", true, ""},
		// Negative: a direct call to a Go symbol still RESOLVES (not over-widened),
		// so precision is preserved for ordinary hand-asm call-outs.
		{"direct bl to symbol", "BL ·helper(SB)", false, "·helper"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "macro.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\t"+tc.line+"\n\tRET\n")
			targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
			if err != nil {
				t.Fatalf("asmCallTargets: %v", err)
			}
			if opaque {
				t.Fatalf("opaque = true, want false")
			}
			if computed != tc.wantComputed {
				t.Fatalf("computed = %v, want %v for %q", computed, tc.wantComputed, tc.line)
			}
			if tc.wantTarget != "" && !stringSliceContains(targets, tc.wantTarget) {
				t.Fatalf("targets = %v, want %q resolved", targets, tc.wantTarget)
			}
		})
	}
}

func TestASMCallTargetsSubstitutesBareSBParamMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define CALL_GO(x) CALL x(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_GO(·helper)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") || stringSliceContains(targets, "x") {
		t.Fatalf("targets = %v, want substituted ·helper only", targets)
	}
}

func TestASMCallTargetsExpandsZeroArgFuncMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define CALL_HELPER() CALL ·helper(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_HELPER()\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsExpandsEmptyObjectMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define EMPTY\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tEMPTY CALL ·helper(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsExpandsWhitespaceMacroSyntax(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "# define CALL_HELPER() CALL ·helper(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_HELPER ()\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsExpandsSplitMacroArgs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define CALL_HELPER() CALL ·helper(SB)\n#define CALL_ARG(x) CALL ·x(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_HELPER( )\n\tCALL_ARG ( helper2 )\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") || !stringSliceContains(targets, "·helper2") {
		t.Fatalf("targets = %v, want ·helper and ·helper2", targets)
	}
}

func TestASMCallTargetsExpandsNestedCommaMacroArg(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define CALL_HELPER(x) CALL ·helper(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_HELPER((1,2))\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsMacroSubstitutesTokensOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define CALL_GO(x) CALL ·xSuffix(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_GO(helper)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·xSuffix") || stringSliceContains(targets, "·helperSuffix") {
		t.Fatalf("targets = %v, want ·xSuffix only", targets)
	}
}

func TestASMCallTargetsExpandsNestedMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define CALL_A(x) CALL_B(x)\n#define CALL_B(x) CALL ·x(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_A(helper)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsExpandsOperandMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define TARGET ·helper(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL TARGET\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsExpandsSymbolOffsetParamMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define CALL_GO(x) CALL ·x+0(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_GO(realHelper)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·realHelper") || stringSliceContains(targets, "·x") {
		t.Fatalf("targets = %v, want substituted ·realHelper only", targets)
	}
}

func TestASMCallTargetsExpandsSymbolComponentMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define NAME helper\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL ·NAME(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") || stringSliceContains(targets, "·NAME") {
		t.Fatalf("targets = %v, want expanded ·helper only", targets)
	}
}

func TestASMCallTargetsIgnoresBlockCommentedMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "/*\n#define NAME helper\n*/\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL ·NAME(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if !computed {
		t.Fatalf("computed = false, want true for macro-like unresolved target")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want commented macro ignored", targets)
	}
}

func TestASMCallTargetsBlockCommentPreservesTokenSeparator(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL/*sep*/·helper(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsExpandsSymbolPrefixMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define pp dep\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL pp·Helper(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "dep·Helper") || stringSliceContains(targets, "pp·Helper") {
		t.Fatalf("targets = %v, want expanded dep·Helper only", targets)
	}
}

func TestASMCallTargetsUnresolvedSymbolPrefixMacroComputed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL PP·helper(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if !computed {
		t.Fatalf("computed = false, want true for macro-like unresolved prefix")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %v, want none", targets)
	}
}

func TestASMCallTargetsSubstitutesSymbolPrefixParamMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define CALLP(P) CALL P·helper(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALLP(realdep)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "realdep·helper") || stringSliceContains(targets, "P·helper") {
		t.Fatalf("targets = %v, want substituted realdep·helper only", targets)
	}
}

func TestASMCallTargetsExpandsDeepMacroChain(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define M1 M2\n#define M2 M3\n#define M3 M4\n#define M4 M5\n#define M5 M6\n#define M6 M7\n#define M7 M8\n#define M8 M9\n#define M9 M10\n#define M10 CALL ·helper(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tM1\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsHonorsMacroRedefinitionOrder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macro.s", "#define CALL_GO CALL ·a(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_GO\n#undef CALL_GO\n#define CALL_GO CALL ·b(SB)\n\tCALL_GO\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·a") || !stringSliceContains(targets, "·b") {
		t.Fatalf("targets = %v, want both ·a and ·b", targets)
	}
}

func TestASMCallTargetsExpandsIncludedMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "callmacro.h", "#define CALL_INCLUDED(x) CALL ·x(SB)\n")
	writeFile(t, dir, "macro.s", "#include \"callmacro.h\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_INCLUDED(helper)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsScansIncludedBody(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "body.h", "\tCALL ·helper(SB)\n")
	writeFile(t, dir, "macro.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n#include \"body.h\"\n\tRET\n")
	targets, computed, opaque, includes, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
	if !stringSliceContains(includes, filepath.Join(dir, "body.h")) {
		t.Fatalf("includes = %v, want body.h", includes)
	}
}

func TestASMCallTargetsScansMacroExpandedInclude(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "body.h", "\tCALL ·helper(SB)\n")
	writeFile(t, dir, "macro.s", "#define LOAD_BODY #include \"body.h\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tLOAD_BODY\n\tRET\n")
	targets, computed, opaque, includes, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
	if !stringSliceContains(includes, filepath.Join(dir, "body.h")) {
		t.Fatalf("includes = %v, want body.h", includes)
	}
}

func TestASMCallTargetsExpandsIncludeOperandMacro(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "body.h", "\tCALL ·helper(SB)\n")
	writeFile(t, dir, "macro.s", "#define HDR \"body.h\"\n#include HDR\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tRET\n")
	targets, computed, opaque, includes, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
	if !stringSliceContains(includes, filepath.Join(dir, "body.h")) {
		t.Fatalf("includes = %v, want body.h", includes)
	}
}

func TestTier2ASMIncludesContributeLocalInclude(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "defs.inc", "#define RETVAL $1\n")
	writeFile(t, dir, "asm.s", "#include \"defs.inc\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tMOVQ RETVAL, AX\n\tRET\n")
	idx := &pkgIndex{id: "example.com/includeasm", mutable: true, meta: &listPkg{Dir: dir, SFiles: []string{"asm.s"}}}
	a := &tier2Analyzer{
		filePkgs:    map[*pkgIndex]bool{idx: true},
		seenContrib: map[string]bool{},
	}

	if err := a.addReachedPackageFiles(); err != nil {
		t.Fatalf("addReachedPackageFiles: %v", err)
	}
	if !contribContains(a.contribs, "include:example.com/includeasm:defs.inc=") {
		t.Fatalf("local asm include missing from contributions: %v", a.contribs)
	}
}

func TestASMCallTargetsIndirectSBComputed(t *testing.T) {
	for _, line := range []string{"CALL *·fp(SB)", "CALL ·table+4(SB)(AX*4)"} {
		t.Run(line, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "indirect.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\t"+line+"\n\tRET\n")
			targets, computed, opaque, _, err := asmCallTargets(dir, []string{"indirect.s"})
			if err != nil {
				t.Fatalf("asmCallTargets: %v", err)
			}
			if !computed {
				t.Fatalf("computed = false, want true")
			}
			if opaque {
				t.Fatalf("opaque = true, want false")
			}
			if len(targets) != 0 {
				t.Fatalf("targets = %v, want none", targets)
			}
		})
	}
}

func TestASMCallTargetsUnknownOpcodeWithSBComputed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macroflag.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_GO ·helper(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macroflag.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if !computed {
		t.Fatalf("computed = false, want true for unresolved opcode macro with SB operand")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %v, want none", targets)
	}
}

func TestASMCallTargetsUnknownOpcodeMacroOperandComputed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macroflag.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_GO TARGET\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macroflag.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if !computed {
		t.Fatalf("computed = false, want true for unresolved opcode macro operand")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %v, want none", targets)
	}
}

func TestASMCallTargetsUnknownOpcodeBareMacroOperandComputed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macroflag.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALLGO TARGET\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macroflag.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if !computed {
		t.Fatalf("computed = false, want true for unresolved opcode macro operand")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %v, want none", targets)
	}
}

func TestASMCallTargetsExternalLowercaseDefineComputed(t *testing.T) {
	t.Setenv("GOFLAGS", "-asmflags=all=-D=hook=helper")
	dir := t.TempDir()
	writeFile(t, dir, "macroflag.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL ·hook(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macroflag.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if !computed {
		t.Fatalf("computed = false, want true for external lowercase symbol define")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %v, want none", targets)
	}
}

func TestASMCallTargetsCallerLowercaseDefineComputed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macroflag.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL ·hook(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macroflag.s"}, "-asmflags=all=-D=hook=helper")
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if !computed {
		t.Fatalf("computed = false, want true for caller-supplied lowercase symbol define")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %v, want none", targets)
	}
}

func TestASMCallTargetsPersistentAndCallerFlags(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "goenv", "GOFLAGS=-asmflags=all=-D=hook=helper\n")
	writeFile(t, dir, "macroflag.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL ·hook(SB)\n\tRET\n")
	t.Setenv("GOENV", filepath.Join(dir, "goenv"))
	oldFlags, hadFlags := os.LookupEnv("GOFLAGS")
	if err := os.Unsetenv("GOFLAGS"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadFlags {
			_ = os.Setenv("GOFLAGS", oldFlags)
		} else {
			_ = os.Unsetenv("GOFLAGS")
		}
	})

	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macroflag.s"}, "-tags=special")
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if !computed {
		t.Fatalf("computed = false, want true with persistent asm flag and explicit tag")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %v, want none", targets)
	}
}

func TestASMCallTargetsUnknownSingleOpcodeComputed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macroflag.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_HELPER\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macroflag.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if !computed {
		t.Fatalf("computed = false, want true for unresolved full-line opcode macro")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %v, want none", targets)
	}
}

func TestASMCallTargetsScansSemicolonStatements(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "semi.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tMOVQ $0, AX; CALL ·helper(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"semi.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsScansLabelPrefixedInstruction(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "label.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\nentry: CALL ·helper(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"label.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsScansStaticBranchLink(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "branch.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tBL ·helper(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"branch.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsScansConditionalBranchLink(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "branch.s", "TEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tBL.NE ·helper(SB)\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"branch.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsScansMacroExpandedSemicolonStatements(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "macrosemi.s", "#define CALL_HELPER MOVQ $0, AX; CALL ·helper(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_HELPER\n\tRET\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macrosemi.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsLineCommentRespectsStringLiteral(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "stringcomment.s", "#define X DATA ·s+0(SB)/8, $\"http://\"; CALL ·helper(SB)\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tX\n\tRET\nGLOBL ·s(SB), 8, $8\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"stringcomment.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·helper") {
		t.Fatalf("targets = %v, want ·helper", targets)
	}
}

func TestASMCallTargetsRepeatsIncludedBodyWithCurrentMacros(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "call.h", "\tCALL_GO\n")
	writeFile(t, dir, "macro.s", "#define CALL_GO CALL ·a(SB)\n#include \"call.h\"\n#undef CALL_GO\n#define CALL_GO CALL ·b(SB)\n#include \"call.h\"\n")
	targets, computed, opaque, _, err := asmCallTargets(dir, []string{"macro.s"})
	if err != nil {
		t.Fatalf("asmCallTargets: %v", err)
	}
	if computed {
		t.Fatalf("computed = true, want false")
	}
	if opaque {
		t.Fatalf("opaque = true, want false")
	}
	if !stringSliceContains(targets, "·a") || !stringSliceContains(targets, "·b") {
		t.Fatalf("targets = %v, want both ·a and ·b", targets)
	}
}

func TestTier2ASMOpaquePreprocessorWidens(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "opaque.s", "#ifdef WANT\n#define CALL_GO CALL ·helper(SB)\n#endif\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL_GO\n\tRET\n")
	idx := &pkgIndex{id: "example.com/opaqueasm", mutable: true, meta: &listPkg{Dir: dir, SFiles: []string{"opaque.s"}}}
	a := &tier2Analyzer{
		filePkgs:    map[*pkgIndex]bool{idx: true},
		seenContrib: map[string]bool{},
	}

	if err := a.addReachedPackageFiles(); err != nil {
		t.Fatalf("addReachedPackageFiles: %v", err)
	}
	if !a.widen || !strings.Contains(a.widenReason, "opaque asm preprocessing") {
		t.Fatalf("widen = %v/%q, want opaque asm preprocessing", a.widen, a.widenReason)
	}
	if a.unverifiable {
		t.Fatalf("unverifiable = true/%q, want false for source-only opaque asm", a.reason)
	}
}

func TestComputeOpaqueASMFallsBackToMaximal(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/opaqueasm"
	cl, err := h.Compute(pkg, "BenchmarkOpaqueASM")
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	maxHash, err := h.maximalHash(pkg)
	if err != nil {
		t.Fatalf("maximalHash: %v", err)
	}
	if cl.Hash != maxHash {
		t.Fatalf("opaque asm hash = %q, want maximal %q", cl.Hash, maxHash)
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
		filePkgs:    map[*pkgIndex]bool{idx: true},
		seenContrib: map[string]bool{},
	}

	if err := a.addReachedPackageFiles(); err != nil {
		t.Fatalf("addReachedPackageFiles: %v", err)
	}
	if !a.widen || !strings.Contains(a.widenReason, "cgo callback source") {
		t.Fatalf("widen = %v/%q, want cgo callback source", a.widen, a.widenReason)
	}
	if !contribContains(a.contribs, "file:example.com/cgocallback:cg.go=") || !contribContains(a.contribs, "file:example.com/cgocallback:bridge.c=") || !contribContains(a.contribs, "file:example.com/cgocallback:include/cfg.h=") {
		t.Fatalf("cgo source files missing from contributions: %v", a.contribs)
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
	a := &tier2Analyzer{filePkgs: map[*pkgIndex]bool{idx: true}, seenContrib: map[string]bool{}}
	if err := a.addReachedPackageFiles(); err != nil {
		t.Fatalf("addReachedPackageFiles: %v, want system include skipped", err)
	}
	if !contribContains(a.contribs, "bridge.c") {
		t.Fatalf("package cgo source missing from contributions: %v", a.contribs)
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
		filePkgs:    map[*pkgIndex]bool{idx: true},
		seenContrib: map[string]bool{},
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
		filePkgs:    map[*pkgIndex]bool{idx: true},
		seenContrib: map[string]bool{},
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
	// markUnverifiable), not just the hasExternalCgo predicate: a plain `-lm` and a
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
		prog:       &program{prog: ssaProg},
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

func TestTier2ASMPrefixedTargetResolvesPackage(t *testing.T) {
	benchTypes := types.NewPackage("example.com/bench", "bench")
	depTypes := types.NewPackage("example.com/dep", "dep")
	helper := types.NewFunc(token.NoPos, depTypes, "Helper", types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false))
	depTypes.Scope().Insert(helper)
	benchIdx := &pkgIndex{pkg: &packages.Package{Name: "bench", Types: benchTypes}}
	depIdx := &pkgIndex{pkg: &packages.Package{Name: "dep", Types: depTypes}}
	a := &tier2Analyzer{
		idxByTypes:  map[*types.Package]*pkgIndex{benchTypes: benchIdx, depTypes: depIdx},
		seenObjects: map[types.Object]bool{},
	}

	a.addASMTarget(benchIdx, "dep·Helper")
	if a.widen {
		t.Fatalf("prefixed asm target widened unexpectedly: %s", a.widenReason)
	}
	if len(a.objectQueue) != 1 || a.objectQueue[0] != helper {
		t.Fatalf("prefixed asm target queue = %v, want Helper", a.objectQueue)
	}
}

func TestTier2ASMPathPrefixedTargetResolvesPackage(t *testing.T) {
	benchTypes := types.NewPackage("example.com/bench", "bench")
	httpTypes := types.NewPackage("net/http", "http")
	get := types.NewFunc(token.NoPos, httpTypes, "Get", types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false))
	httpTypes.Scope().Insert(get)
	benchIdx := &pkgIndex{pkg: &packages.Package{Name: "bench", Types: benchTypes}}
	httpIdx := &pkgIndex{pkg: &packages.Package{Name: "http", Types: httpTypes}, path: "net/http", std: true}
	a := &tier2Analyzer{
		idxByTypes:  map[*types.Package]*pkgIndex{benchTypes: benchIdx, httpTypes: httpIdx},
		idxByPath:   map[string]*pkgIndex{"net/http": httpIdx},
		seenObjects: map[types.Object]bool{},
	}

	a.addASMTarget(benchIdx, "net/http·Get")
	if a.widen {
		t.Fatalf("path-prefixed asm target widened unexpectedly: %s", a.widenReason)
	}
	if len(a.objectQueue) != 1 || a.objectQueue[0] != get {
		t.Fatalf("path-prefixed asm target queue = %v, want net/http.Get", a.objectQueue)
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
		seenTypes:   map[string]bool{},
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
		seenTypes:   map[string]bool{},
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
		seenTypes:   map[string]bool{},
		filePkgs:    map[*pkgIndex]bool{},
		scanned:     map[*ssa.Function]bool{},
	}

	a.scanFunction(&ssa.Function{Synthetic: "package initializer", Pkg: &ssa.Package{Pkg: cacheTypes}, Blocks: []*ssa.BasicBlock{{}}})
	if len(a.objectQueue) != 1 || a.objectQueue[0] != localObj {
		t.Fatalf("cache init body queue = %v, want localdep.C", a.objectQueue)
	}
}

func TestTier2HashesReachedImports(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/importbinding"
	contribs, widened, err := h.tier2Contributions(pkg, "BenchmarkImportBinding")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	if widened {
		t.Fatalf("import binding fixture widened unexpectedly: %v", contribs)
	}
	if !contribContains(contribs, "imports") {
		t.Fatalf("import declaration missing from contributions: %v", contribs)
	}
}

func TestTier2ASMTargetInterfaceInvokeWidens(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/asminvoke"
	tr, err := h.tier2(pkg, "BenchmarkASMInvoke")
	if err != nil {
		t.Fatalf("tier2: %v", err)
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
	tr, err := h.tier2(pkg, "BenchmarkGenericPostRTA")
	if err != nil {
		t.Fatalf("tier2: %v", err)
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
	cl, err := h.Compute(pkg, "BenchmarkReflectExternal")
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !cl.Unverifiable || !strings.Contains(cl.Reason, "file I/O") {
		t.Fatalf("reflect target Class-B = %v/%q, want file I/O", cl.Unverifiable, cl.Reason)
	}
}

func TestUnverifiableReasonSelectionIsDeterministic(t *testing.T) {
	reasons := []string{
		"reaches fmt.Print (formatted output)",
		"reaches net.Dial (network I/O)",
		"reaches os.ReadFile (file I/O)",
	}
	first := &tier2Analyzer{}
	for _, reason := range reasons {
		first.markUnverifiable(reason)
	}
	second := &tier2Analyzer{}
	for i := len(reasons) - 1; i >= 0; i-- {
		second.markUnverifiable(reasons[i])
	}
	if first.reason != second.reason {
		t.Fatalf("unverifiable reason depends on traversal order: %q != %q", first.reason, second.reason)
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

func TestTier2LinknameLocalTargetContributes(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/linknamelocal/bench"
	contribs, _, err := h.tier2Contributions(pkg, "BenchmarkLinknameLocal")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	if !contribContains(contribs, "Hidden") || !contribContains(contribs, "LocalOnly") {
		t.Fatalf("linkname local target declarations missing from contributions: %v", contribs)
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
		prog:             &program{prog: ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)},
		idxByTypes:       map[*types.Package]*pkgIndex{upperTypes: upperIdx, lowerTypes: lowerIdx},
		objsByLinkTarget: map[string][]types.Object{},
		seenObjects:      map[types.Object]bool{},
		seenTypes:        map[string]bool{},
		seenDecls:        map[string]bool{},
		seenPkgs:         map[*pkgIndex]bool{},
		filePkgs:         map[*pkgIndex]bool{},
		seenContrib:      map[string]bool{},
	}
	a.addReverseLinkname("example.com/upper.g", lowerF)

	a.addObject(upperG)
	if len(a.objectQueue) != 1 || a.objectQueue[0] != lowerF {
		t.Fatalf("reverse linkname queue = %v, want lower.f", a.objectQueue)
	}
}

func TestTier2DetachedLinknameDirectiveContributes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.go")
	const source = `package p

//go:linkname f example.com/cachedep.F

func f() {}
`
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
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
		h:                &Hasher{},
		prog:             &program{prog: ssa.NewProgram(fset, ssa.InstantiateGenerics)},
		metaByPath:       map[string]*listPkg{},
		idxByTypes:       map[*types.Package]*pkgIndex{},
		objByName:        map[string]types.Object{},
		objsByLinkTarget: map[string][]types.Object{},
		seenObjects:      map[types.Object]bool{},
		seenTypes:        map[string]bool{},
		seenDecls:        map[string]bool{},
		seenPkgs:         map[*pkgIndex]bool{},
		filePkgs:         map[*pkgIndex]bool{},
		seenContrib:      map[string]bool{},
	}
	idx := a.buildIndex(&packages.Package{ID: "example.com/p", PkgPath: "example.com/p", Dir: dir, Fset: fset, Types: typesPkg, TypesInfo: info, Syntax: []*ast.File{file}})
	a.idxByTypes[typesPkg] = idx
	obj := typesPkg.Scope().Lookup("f")
	if obj == nil {
		t.Fatal("f object missing")
	}

	a.addObject(obj)
	if !contribContains(a.contribs, "linkname") {
		t.Fatalf("detached linkname directive missing from contributions: %v", a.contribs)
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
		prog:       &program{prog: ssa.NewProgram(fset, ssa.InstantiateGenerics)},
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

func TestComputeScopesBenchmarkRootToTargetPackage(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/rootcollision/bench"
	contribs, _, err := h.tier2Contributions(pkg, "BenchmarkSame")
	if err != nil {
		t.Fatalf("tier2Contributions: %v", err)
	}
	if !contribContains(contribs, "RealOnly") {
		t.Fatalf("target benchmark root contribution missing RealOnly: %v", contribs)
	}
	if contribContains(contribs, "DepOnly") {
		t.Fatalf("dependency benchmark root leaked into target closure: %v", contribs)
	}
}

func contribContains(contribs []string, s string) bool {
	for _, c := range contribs {
		if strings.Contains(c, s) {
			return true
		}
	}
	return false
}

func contribHasAll(contribs []string, parts ...string) bool {
	for _, c := range contribs {
		ok := true
		for _, p := range parts {
			if !strings.Contains(c, p) {
				ok = false
				break
			}
		}
		if ok {
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
		if _, err := hashFiles(dir, files); err != nil {
			b.Fatal(err)
		}
	}
}
