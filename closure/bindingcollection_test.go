package closure

import (
	"reflect"
	"slices"
	"testing"

	"github.com/greatliontech/gofresh/closure/internal/compartment"
	"github.com/greatliontech/gofresh/closure/testvariant"
)

// This is a go-list graph fixture: it exercises the collector's CgoFiles
// membership and syntax evidence without invoking a C compiler or claiming
// coverage of cgo-generated code. The pseudo-import C remains unresolved.
func TestCgoFilesEnterBaseBindingEvidence(t *testing.T) {
	const pkg = "example.com/bindings"
	dir := writeTestVariantModule(t, map[string]string{
		"plain.go":  "package p\nfunc Plain() {}\n",
		"cgo.go":    "package p\nimport \"C\"\nfunc Truth() bool { return true }\n",
		"p_test.go": "package p\nfunc Helper() {}\n",
	})
	module := &listMod{Path: pkg, Main: true, Dir: dir}
	h := &Hasher{
		lists: map[string][]listPkg{pkg: {
			{ImportPath: pkg, Name: "p", Dir: dir, Module: module, GoFiles: []string{"plain.go"}, CgoFiles: []string{"cgo.go"}},
			{ImportPath: pkg + " [" + pkg + ".test]", ForTest: pkg, Name: "p", Dir: dir, Module: module, GoFiles: []string{"plain.go", "p_test.go"}, CgoFiles: []string{"cgo.go"}},
		}},
		testVariants: map[string]compartment.Identity{},
		fileDigests:  map[string]string{},
		contents:     map[string]fileBytes{},
	}
	ledger, err := h.TestVariantLedger(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if ledger.BindingStrategy != testvariant.BindingStrategy || len(ledger.BaseFiles) != 2 {
		t.Fatalf("base evidence = %+v, want both GoFiles and CgoFiles", ledger)
	}
	cgo := ledger.BaseFiles[0]
	if cgo.File != "cgo.go" || cgo.Hash != "" || cgo.Embedded || cgo.Bindings == nil || cgo.Bindings.Package != "p" {
		t.Fatalf("cgo base entry = %+v", cgo)
	}
	if !slices.Contains(cgo.Bindings.References, "true") || !reflect.DeepEqual(cgo.Bindings.Imports, []testvariant.TestVariantImport{{Path: "C"}}) {
		t.Fatalf("cgo reference/import evidence = %+v", cgo.Bindings)
	}
	if len(ledger.FileHeaders) != 1 || ledger.FileHeaders[0].File != "p_test.go" {
		t.Fatalf("base cgo file leaked into compartment: %+v", ledger.FileHeaders)
	}
	if testvariant.DiffTestVariantLedgers(ledger, ledger.Clone()).Inert() {
		t.Fatal("unresolved pseudo-import supplied binding proof")
	}
}

// The real in-memory parse memo shares nested slices and pointers. Listing
// resolution must leave those syntax-only entries unresolved for later views,
// and must not rewrite a ledger already returned to a caller.
func TestBindingResolutionPreservesSharedParseMemo(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeTestVariantModule(t, map[string]string{
		"p.go":      "package p\nimport \"example.com/dependency\"\nfunc Base() int { return selected.Value }\n",
		"p_test.go": "package p\nimport \"example.com/dependency\"\nfunc Helper() int { return selected.Value }\n",
	})
	h := &Hasher{fileMemo: newFileMemos(), contents: map[string]fileBytes{}}
	memo := variantParseMemo{h: h, dir: dir, pkgPath: "example.com/p"}
	var first testvariant.TestVariantLedger
	for _, name := range []string{"selected", "renamed", ""} {
		identity, err := compartment.ComputeIdentity(dir, []string{"p_test.go"}, map[string]bool{"p_test.go": true}, nil, nil, h, memo)
		if err != nil {
			t.Fatal(err)
		}
		if err := compartment.AddBaseBindings(&identity, []string{"p.go"}, map[string]string{"example.com/dependency": name}, h, memo); err != nil {
			t.Fatal(err)
		}
		h.flushFileMemos()
		for _, header := range []testvariant.TestVariantFileHeader{identity.Ledger.BaseFiles[0], identity.Ledger.FileHeaders[0]} {
			if got := header.Bindings.Imports[0].Name; got != name {
				t.Fatalf("%s: resolved name %q, want %q", header.File, got, name)
			}
		}
		if len(h.fileMemo.parses[dir]) != 2 {
			t.Fatalf("memo has %d entries, want base and test files", len(h.fileMemo.parses[dir]))
		}
		for key, payload := range h.fileMemo.parses[dir] {
			if payload.Header.Hash == "" || payload.Header.Bindings.Imports[0].Name != "" {
				t.Fatalf("listing resolution contaminated syntax memo %s: %+v", key, payload.Header)
			}
		}
		if name == "selected" {
			first = identity.Ledger
		} else {
			for _, header := range []testvariant.TestVariantFileHeader{first.BaseFiles[0], first.FileHeaders[0]} {
				if header.Bindings.Imports[0].Name != "selected" {
					t.Fatal("later resolution changed first caller's ledger")
				}
			}
			if !h.ServedSummary()["compartment parse"]["example.com/p"] {
				t.Fatal("later pass did not exercise shared memo entries")
			}
		}
		if name == "" && testvariant.DiffTestVariantLedgers(identity.Ledger, identity.Ledger.Clone()).Inert() {
			t.Fatal("unresolved listing reused an earlier binding")
		}
	}
}
