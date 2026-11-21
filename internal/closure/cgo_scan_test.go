package closure

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestClassBReasonNetDialContext(t *testing.T) {
	if reason := classBReason("net", "DialContext"); !strings.Contains(reason, "network I/O") {
		t.Fatalf("classBReason(net.DialContext) = %q, want network I/O", reason)
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

func TestContributionCgoOrdinaryStringEndingInRAllowed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cg.go", "package cgotest\n/*\n// C comment inside block preamble mentioning R\"(x)\" and \"OR\"\n#define PREAMBLE_BLOCK_R \"R\"\n*/\n// /* preamble comment mentioning \"OR\" and R\" */\n// #define PREAMBLE_R \"R\"\nimport \"C\"\n\nconst goRaw = `R\"raw(/*)raw\"`\n")
	writeFile(t, dir, "local.h", "#define HDR_R \"META_ECLASS_XOR\"\n")
	writeFile(t, dir, "bridge.c", `
#include "local.h"
/* Comment mentioning "OR" and R" inside a block comment */
// Line comment mentioning "ERR" and R"raw(x)raw"
#define STR_R "R"
void bridge(void) {
	const char *a = "META_DOLLAR";
	const char *b = "\\R";
	const char *escaped = "quoted \"R\" inside string";
	char ch = 'R';
	(void)a;
	(void)b;
	(void)escaped;
	(void)ch;
}
`)
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgotest",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		HFiles:     []string{"local.h"},
		Module:     &listMod{Main: true, Dir: dir},
	}
	if _, err := h.contribution(pkg); err != nil {
		t.Fatalf("contribution error = %v, want nil for ordinary C strings and comments", err)
	}
}

func TestContributionCgoLineCommentBlockStartDoesNotHideInclude(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "// line comment with /* block opener\n#include \"../cfg.h\"\n// closing */ marker\nvoid bridge(void) {}\n")
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

func TestContributionCgoDigitSeparatorDoesNotHideInclude(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.cc", "int n = 1'000; const char *s = \"'/*\";\n#include \"../cfg.h\"\nconst char *t = \"*/\";\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CXXFiles:   []string{"bridge.cc"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoGoPackageCommentDoesNotHidePreambleInclude(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{
			name: "package_comment_before_single_import",
			src:  "// /* package doc comment with unclosed block marker\npackage cgocallback\n\n// #include \"../cfg.h\"\nimport \"C\"\n",
		},
		{
			name: "import_group_doc_before_c_spec_doc",
			src:  "package cgocallback\n\n// /* import group doc with unclosed block marker\nimport (\n\t\"fmt\"\n\n\t// #include \"../cfg.h\"\n\t\"C\"\n)\nvar _ = fmt.Sprintf\n",
		},
		{
			name: "adjacent_block_comments_in_preamble",
			src:  "package cgocallback\n\n/*#include */ /*\"../cfg.h\"*/\nimport \"C\"\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "pkg")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, dir, "cg.go", tc.src)
			writeFile(t, root, "cfg.h", "#define N 1\n")
			h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
			pkg := listPkg{
				ImportPath: "example/cgocallback",
				Dir:        dir,
				CgoFiles:   []string{"cg.go"},
				Module:     &listMod{Main: true, Dir: root},
			}
			if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
				t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
			}
		})
	}
}

func TestContributionCgoIncludeGoFileFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "helper.go", "//go:build ignore\n\npackage cgocallback;\n#include \"../cfg.h\"\n")
	writeFile(t, dir, "bridge.c", "#define package typedef int\n#include \"helper.go\"\nvoid bridge(void) {}\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "unsupported cgo include source") {
		t.Fatalf("contribution error = %v, want unsupported cgo include source", err)
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
