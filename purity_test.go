package gofresh

import (
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
