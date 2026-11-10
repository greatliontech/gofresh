package gofresh

import (
	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"slices"
	"testing"
)

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
	if got, want := syntaxutil.ObjectDeclarationKey(variant, universeError), syntaxutil.ObjectDeclarationKey(production, universeError); got != want {
		t.Errorf("ObjectDeclarationKey varies by build variant: %q vs %q", got, want)
	}
	// A key-scheme pin, not an end-to-end collision: the subject scan only
	// records *types.Func objects, and error's Error is the sole universe
	// method, so no second position-less declaration is recordable today.
	// The pin keeps the scheme honest for any future one.
	if same := syntaxutil.ObjectDeclarationKey(production, universeError) == syntaxutil.ObjectDeclarationKey(production, types.Universe.Lookup("len")); same {
		t.Errorf("distinct position-less declarations share one key")
	}
	node := ast.NewIdent("f") // token.NoPos: the position-less fallback arm
	if got, want := syntaxutil.NodeDeclarationKey(variant, node), syntaxutil.NodeDeclarationKey(production, node); got != want {
		t.Errorf("NodeDeclarationKey varies by build variant: %q vs %q", got, want)
	}
}

func TestSessionAcceptsTheResolvedVouchSet(t *testing.T) {
	entries, err := ParseVouchEntries([]string{"example.com/a.b:State", "example.com/dep:Other", "example.com/a.b:State"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(t.Context(), BuildDescription{Directory: t.TempDir(), Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{Vouches: entries, PrepareCommand: hermeticEnvRunner().Prepare})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.dynamicStateVouches) != 2 || !s.dynamicStateVouches["example.com/a.b.State"] || !s.dynamicStateVouches["example.com/dep.Other"] {
		t.Fatal("resolved vouch set changed at session admission")
	}
	for _, value := range []string{"", "example.com/dep:State", "example.com/dep", "example.com/dep.", "example.com/dep.not-a-name", "example.com/pkg/x"} {
		if _, err := canonicalSessionVouches([]string{value}); err == nil {
			t.Fatalf("noncanonical identity admitted: %q", value)
		}
	}
	got, err := canonicalSessionVouches([]string{"example.com/dep.Other", "example.com/a.b.State", "example.com/dep.Other"})
	if err != nil || !slices.Equal(got, []string{"example.com/a.b.State", "example.com/dep.Other"}) {
		t.Fatalf("canonical set: %q %v", got, err)
	}
}

// One entry is IMPORT-PATH:VARIABLE mapped to the dotted identity; a
// missing colon, an empty half, a space in the path, or a variable that
// is not one Go identifier refuses (REQ-vouch-input).
func TestParseVouchEntryGrammar(t *testing.T) {
	if got, err := ParseVouchEntry("golang.org/x/sync/errgroup:Ghost"); err != nil || got != "golang.org/x/sync/errgroup.Ghost" {
		t.Fatalf("entry = %q, %v", got, err)
	}
	if got, err := ParseVouchEntry("a.example/dep/v2:_x9"); err != nil || got != "a.example/dep/v2._x9" {
		t.Fatalf("entry = %q, %v", got, err)
	}
	for _, bad := range []string{"", "nocolon", ":Var", "pkg:", "a b/dep:Var", "a\tb/dep:Var", "a\x7fb/dep:Var", "a\u0085b/dep:Var", "pkg:9x", "pkg:Var.Field", "pkg:Var:More"} {
		if _, err := ParseVouchEntry(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
