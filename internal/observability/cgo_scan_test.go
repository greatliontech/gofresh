package observability

import (
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

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
			if !a.unverifiable || !strings.Contains(a.selected.Reason, "cgo external library") {
				t.Fatalf("cgo Class-B = %v/%q, want external library", a.unverifiable, a.selected.Reason)
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
	if !a.unverifiable || !strings.Contains(a.selected.Reason, "cgo external library") {
		t.Fatalf("pkg-config cgo Class-B = %v/%q, want external library", a.unverifiable, a.selected.Reason)
	}
}
