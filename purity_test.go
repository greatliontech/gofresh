package gofresh

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/packages"
)

// TestScanPureDirectives pins REQ-purity-directive: the scanner marks exactly the
// symbols carrying //gofresh:pure — a function and a method (named "Type.Method") —
// and leaves their directive-less neighbours unmarked.
func TestScanPureDirectives(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	const pkg = "github.com/greatliontech/gofresh/internal/puredirective"
	pred, err := ScanPureDirectives(pkg)
	if err != nil {
		t.Fatalf("ScanPureDirectives: %v", err)
	}
	cases := []struct {
		symbol string
		want   bool
	}{
		{"Asserted", true},
		{"NotAsserted", false},
		{"SpacedDirective", false},
		{"T.Asserted", true},
		{"T.NotAsserted", false},
		// Declared in the external test package ("pkg_test"): the directive must
		// key under the package under test's import path, the path the engine
		// roots the subject under (REQ-purity-directive).
		{"BenchmarkXAsserted", true},
		{"BenchmarkXNotAsserted", false},
	}
	for _, tc := range cases {
		if got := pred(Subject{Package: pkg, Symbol: tc.symbol}); got != tc.want {
			t.Errorf("%s: pure=%v, want %v", tc.symbol, got, tc.want)
		}
	}
}

// TestScanAcceptsUniverseMethodAcrossTestVariants pins the refusal boundary of
// REQ-purity-directive: the ambiguous-subject refusal is for distinct
// declarations collapsing onto one subject identity, never for one declaration
// sighted through two build variants of the same source package. A top-level
// type whose method set holds a position-less universe method — error's Error,
// promoted through interface or struct embedding — is scanned by both the
// production package and its in-package test variant (the scan loads with
// Tests: true); both sightings resolve to the single universe declaration, so
// the scan must succeed rather than manufacture an ambiguity from
// variant-dependent keys.
func TestScanAcceptsUniverseMethodAcrossTestVariants(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/universe\n\ngo 1.26\n",
		"universe.go": "package universe\n\n" +
			"type E = interface{ error }\n\n" +
			"type T struct{ error }\n\n" +
			"//gofresh:pure\nfunc F() {}\n",
		"universe_test.go": "package universe\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) { F() }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pred, err := ScanPureDirectivesIn(dir, "example.com/universe")
	if err != nil {
		t.Fatalf("ScanPureDirectivesIn: %v", err)
	}
	if !pred(Subject{Package: "example.com/universe", Symbol: "F"}) {
		t.Errorf("F: pure=false, want true")
	}
}

// TestScanKeepsRecompiledDependencySubjectsUnderOwnPackage pins the subject
// attribution boundary of the scan (REQ-purity-directive with the subject
// identity of the overview spec): `go list -test` marks every package
// recompiled into a test binary with ForTest — including intermediate
// dependencies — but only the package under test's own variants declare
// subjects of the package under test. A dependency recompiled for the test
// binary (external test of a imports r, r imports a — so r is rebuilt against
// a's test variant) keeps its declarations under its own import path: they
// never appear as subjects of the tested package, and a top-level symbol name
// shared between the two packages is two distinct subjects, not an ambiguity.
func TestScanKeepsRecompiledDependencySubjectsUnderOwnPackage(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.26\n",
		"a/a.go": "package a\n\n//gofresh:pure\nfunc G() {}\n",
		// The in-package test file makes "a [a.test]" a distinct variant, so r —
		// importing a, imported by a's external test — is recompiled against it
		// as "r [a.test]" with ForTest set.
		"a/in_test.go":  "package a\n\nimport \"testing\"\n\nfunc TestInternal(t *testing.T) { G() }\n",
		"a/ext_test.go": "package a_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/m/r\"\n)\n\nfunc TestG(t *testing.T) { r.Use() }\n",
		"r/r.go":        "package r\n\nimport \"example.com/m/a\"\n\nfunc Use() { a.G() }\n\nfunc G() {}\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The attribution assertions below hold vacuously if the recompiled
	// dependency variant ("r [a.test]") stops materializing, so its presence is
	// load-bearing.
	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedForTest | packages.NeedImports | packages.NeedDeps,
		Tests: true,
		Dir:   dir,
	}
	loaded, err := packages.Load(cfg, "example.com/m/a")
	if err != nil {
		t.Fatalf("variant guard load: %v", err)
	}
	variant := false
	packages.Visit(loaded, nil, func(p *packages.Package) {
		if p.PkgPath == "example.com/m/r" && p.ForTest == "example.com/m/a" {
			variant = true
		}
	})
	if !variant {
		t.Fatal("fixture no longer yields the recompiled dependency variant r [a.test]; the attribution assertions below would hold vacuously")
	}
	pred, known, _, _, err := scanSubjectsInWithBuildFlags(context.Background(), dir, nil, "example.com/m/a", "example.com/m/r")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for subject, want := range map[Subject]bool{
		{Package: "example.com/m/a", Symbol: "G"}:   true,
		{Package: "example.com/m/r", Symbol: "G"}:   true,
		{Package: "example.com/m/r", Symbol: "Use"}: true,
		// r's declaration, recompiled as "r [a.test]", is never a subject of a.
		{Package: "example.com/m/a", Symbol: "Use"}: false,
	} {
		if known[subject] != want {
			t.Errorf("known[%s.%s]=%v, want %v", subject.Package, subject.Symbol, known[subject], want)
		}
	}
	if !pred(Subject{Package: "example.com/m/a", Symbol: "G"}) {
		t.Errorf("a.G: pure=false, want true (directive on a's own declaration)")
	}
	if pred(Subject{Package: "example.com/m/r", Symbol: "G"}) {
		t.Errorf("r.G: pure=true, want false (a's directive must not leak to r's same-named symbol)")
	}
}

// TestDeclarationKeysIgnoreBuildVariantIdentity pins the key-derivation
// invariant directly: a position-less declaration derives the same key
// whichever build variant of one source package sights it (production "p" vs
// test variant "p [p.test]" — the two loads under Tests: true), while two
// distinct position-less declarations still derive distinct keys, preserving
// the ambiguous-subject refusal's power (REQ-purity-directive).
func TestDeclarationKeysIgnoreBuildVariantIdentity(t *testing.T) {
	errorType := types.Universe.Lookup("error").Type()
	universeError, _, _ := types.LookupFieldOrMethod(errorType, false, nil, "Error")
	if universeError == nil || universeError.Pos().IsValid() || universeError.Pkg() != nil {
		t.Fatalf("universe error.Error = %v, want a position-less package-less object", universeError)
	}
	production := &packages.Package{ID: "example.com/p", PkgPath: "example.com/p", Fset: token.NewFileSet()}
	variant := &packages.Package{ID: "example.com/p [example.com/p.test]", PkgPath: "example.com/p", Fset: token.NewFileSet()}
	if got, want := objectDeclarationKey(variant, universeError), objectDeclarationKey(production, universeError); got != want {
		t.Errorf("objectDeclarationKey varies by build variant: %q vs %q", got, want)
	}
	// A key-scheme pin, not an end-to-end collision: the subject scan only
	// records *types.Func objects, and error's Error is the sole universe
	// method, so no second position-less declaration is recordable today.
	// The pin keeps the scheme honest for any future one.
	if same := objectDeclarationKey(production, universeError) == objectDeclarationKey(production, types.Universe.Lookup("len")); same {
		t.Errorf("distinct position-less declarations share one key")
	}
	node := ast.NewIdent("f") // token.NoPos: the position-less fallback arm
	if got, want := nodeDeclarationKey(variant, node), nodeDeclarationKey(production, node); got != want {
		t.Errorf("nodeDeclarationKey varies by build variant: %q vs %q", got, want)
	}
}
