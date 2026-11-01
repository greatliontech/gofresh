package closure

import (
	"context"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"go/types"
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

func cgoNativeFileHasRawString(text string) bool {
	_, raw := stripCComments(text)
	return raw
}

func TestCgoNativeFileHasRawString(t *testing.T) {
	allowed := []struct {
		name string
		text string
	}{
		{
			name: "ordinary_string_ending_in_R",
			text: `fprintf(stderr, "META_DOLLAR");`,
		},
		{
			name: "single_char_R_string",
			text: `#define STR_R "R"`,
		},
		{
			name: "escaped_backslash_before_R",
			text: `static const char *names[] = { "\\R", "OR", "XOR" };`,
		},
		{
			name: "escaped_quotes_around_R_inside_string",
			text: `const char *msg = "expected \"R\" token";`,
		},
		{
			name: "block_and_line_comments_with_R_quote",
			text: "/* See C++11 R\"(...)\" syntax or token \"OR\" */\n// returns \"ERR\" or R\"(x)\" on failure\nint ok = 1;\n",
		},
		{
			name: "char_literal_R_and_escaped_quote",
			text: "char c1 = 'R'; char c2 = '\"'; char c3 = '\\''; const char *s = \"ok\";\n",
		},
		{
			name: "macro_name_ending_in_R_before_quote",
			text: "#define STR_R\"value\"\n",
		},
		{
			name: "digit_separator_before_ordinary_string_with_quote_and_R",
			text: "int n = 1'000'000; int h = 0xFF'FF; const char *s = \"'R\";\n",
		},
		{
			name: "prefixed_char_literals",
			text: "char c1 = u8'\"'; const char *s1 = \"R\";\nchar16_t c2 = u'\"'; const char *s2 = \"R\";\nchar32_t c3 = U'\"'; const char *s3 = \"R\";\nwchar_t c4 = L'\"'; const char *s4 = \"R\";\n",
		},
		{
			name: "keyword_before_char_literal",
			text: "char f(void) { return'\"'; } const char *s = \"R\";\n",
		},
	}
	for _, tc := range allowed {
		if cgoNativeFileHasRawString(tc.text) {
			t.Errorf("%s: cgoNativeFileHasRawString(%q) = true, want false", tc.name, tc.text)
		}
	}

	raw := []struct {
		name string
		text string
	}{
		{
			name: "plain_raw_string",
			text: `const char *x = R"raw(/*)raw";`,
		},
		{
			name: "u8R_raw_string",
			text: `const char *x = u8R"raw(/*)raw";`,
		},
		{
			name: "uR_raw_string",
			text: `const char16_t *x = uR"raw(/*)raw";`,
		},
		{
			name: "UR_raw_string",
			text: `const char32_t *x = UR"raw(/*)raw";`,
		},
		{
			name: "LR_raw_string",
			text: `const wchar_t *x = LR"raw(/*)raw";`,
		},
		{
			name: "raw_string_after_ordinary_string_on_same_line",
			text: `const char *a = "META_DOLLAR"; const char *b = R"raw(/*)raw";`,
		},
		{
			name: "raw_string_after_block_comment",
			text: `/* comment */ const char *b = R"raw(/*)raw";`,
		},
		{
			name: "raw_string_after_digit_separator",
			text: `int n = 1'000; const char *b = R"raw(/*)raw";`,
		},
	}
	for _, tc := range raw {
		if !cgoNativeFileHasRawString(tc.text) {
			t.Errorf("%s: cgoNativeFileHasRawString(%q) = false, want true", tc.name, tc.text)
		}
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
			if !a.unverifiable || !strings.Contains(a.selected.reason, "cgo external library") {
				t.Fatalf("cgo Class-B = %v/%q, want external library", a.unverifiable, a.selected.reason)
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
	if !a.unverifiable || !strings.Contains(a.selected.reason, "cgo external library") {
		t.Fatalf("pkg-config cgo Class-B = %v/%q, want external library", a.unverifiable, a.selected.reason)
	}
}
