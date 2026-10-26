package testvariant

import (
	"sort"
	"testing"
)

// The ledger's canonical declaration order is total and lexicographic
// over file, kind, receiver, name — the order every persisted ledger
// and every delta carries, so two ledgers of one compartment compare
// declaration by declaration.
func TestLessDeclarationOrdersByFileKindReceiverName(t *testing.T) {
	decl := func(file, kind, receiver, name string) TestVariantDeclaration {
		return TestVariantDeclaration{File: file, Kind: kind, Receiver: receiver, Name: name}
	}
	want := []TestVariantDeclaration{
		decl("a_test.go", "func", "", "B"),
		decl("a_test.go", "func", "", "C"),
		decl("a_test.go", "func", "T", "A"),
		decl("a_test.go", "type", "", "A"),
		decl("b_test.go", "const", "", "A"),
	}
	got := []TestVariantDeclaration{want[4], want[3], want[2], want[1], want[0]}
	sort.Slice(got, func(i, j int) bool { return LessDeclaration(got[i], got[j]) })
	for i := range want {
		if got[i].File != want[i].File || got[i].Kind != want[i].Kind || got[i].Receiver != want[i].Receiver || got[i].Name != want[i].Name {
			t.Fatalf("position %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	for i := range want {
		if LessDeclaration(want[i], want[i]) {
			t.Fatalf("a declaration ordered before itself: %+v", want[i])
		}
	}
}

func TestInertForSubjectCoversReachabilityAndGuardRails(t *testing.T) {
	baseLedger := func() TestVariantLedger {
		return TestVariantLedger{
			BindingStrategy: BindingStrategy,
			BaseFiles: []TestVariantFileHeader{{
				File: "prod.go",
				Bindings: &TestVariantFileBindings{
					Package:    "p",
					References: []string{"ProdFunc", "BaseHook", "BaseType"},
				},
			}},
			FileHeaders: []TestVariantFileHeader{
				{
					File: "a_test.go",
					Hash: "ha1",
					Bindings: &TestVariantFileBindings{
						Package:    "p",
						References: []string{"TestA", "box", "run", "constGov", "constOmit", "errVal", "Error", "fmt", "Sprint", "TestB", "helperB"},
						Imports: []TestVariantImport{
							{Name: "fmt", Path: "fmt"},
							{Name: "strings", Path: "strings"},
						},
					},
				},
				{
					File: "ext_test.go",
					Hash: "he1",
					Bindings: &TestVariantFileBindings{
						Package:    "p_test",
						References: []string{"TestExt", "ExportedHelper"},
					},
				},
			},
			Declarations: []TestVariantDeclaration{
				{File: "a_test.go", Package: "p", Kind: "const", Name: "constGov", Hash: "cg1", References: []string{"constGov"}},
				{File: "a_test.go", Package: "p", Kind: "const", Name: "constOmit", Hash: "co1", References: []string{"constGov", "constOmit"}},
				{File: "a_test.go", Package: "p", Kind: "func", Name: "BaseHook", Hash: "bh1", References: []string{"BaseHook"}},
				{File: "a_test.go", Package: "p", Kind: "func", Name: "ExportedHelper", Hash: "eh1", References: []string{"ExportedHelper"}},
				{File: "a_test.go", Package: "p", Kind: "func", Name: "TestA", Hash: "ta1", References: []string{"TestA", "box", "constOmit", "errVal", "fmt", "Sprint"}},
				{File: "a_test.go", Package: "p", Kind: "func", Name: "TestB", Hash: "tb1", References: []string{"TestB", "helperB"}},
				{File: "a_test.go", Package: "p", Kind: "func", Name: "helperB", Hash: "hb1", References: []string{"helperB", "strings"}},
				{File: "a_test.go", Package: "p", Kind: "method", Receiver: "(*box[T])", Name: "run", Hash: "mr1", References: []string{"box", "run"}},
				{File: "a_test.go", Package: "p", Kind: "method", Receiver: "pair[K, V]", Name: "unused", Hash: "mu1", References: []string{"pair", "unused"}},
				{File: "a_test.go", Package: "p", Kind: "method", Receiver: "errVal", Name: "Error", Hash: "me1", References: []string{"errVal", "Error"}},
				{File: "a_test.go", Package: "p", Kind: "type", Name: "box", Hash: "tbx1", References: []string{"box"}},
				{File: "a_test.go", Package: "p", Kind: "type", Name: "errVal", Hash: "tev1", References: []string{"errVal"}},
				{File: "a_test.go", Package: "p", Kind: "type", Name: "pair", Hash: "tpr1", References: []string{"pair"}},
				{File: "ext_test.go", Package: "p_test", Kind: "func", Name: "TestExt", Hash: "te1", References: []string{"TestExt", "ExportedHelper"}},
			},
		}
	}

	before := baseLedger()
	// 1. Malformed or non-addressable subject symbols fail closed even when DiffTestVariantLedgers(before, before).Inert() is true.
	for _, bad := range []string{"", "init#a_test.go#0", ".Method", "Type.", "a.b.c"} {
		if InertForSubject(before, before, bad) {
			t.Fatalf("InertForSubject(identical, %q) = true, want false", bad)
		}
	}

	// 2. Editing TestB, helperB, and pair[K, V].unused (and dropping unused "strings" import) is inert for TestA, box.run, TestExt, and ProdFunc.
	afterSiblingEdit := before.Clone()
	afterSiblingEdit.FileHeaders[0].Bindings.Imports = []TestVariantImport{{Name: "fmt", Path: "fmt"}}
	var kept []TestVariantDeclaration
	for _, d := range afterSiblingEdit.Declarations {
		switch d.Name {
		case "helperB", "unused":
			continue
		case "TestB":
			d.Hash = "tb2"
		}
		kept = append(kept, d)
	}
	afterSiblingEdit.Declarations = kept
	for _, okSubj := range []string{"TestA", "box.run", "TestExt", "ProdFunc"} {
		if !InertForSubject(before, afterSiblingEdit, okSubj) {
			t.Fatalf("InertForSubject(%q) = false after unrelated sibling edits, want true", okSubj)
		}
	}
	for _, staleSubj := range []string{"TestB", "helperB", "pair.unused", "NonExistent"} {
		if InertForSubject(before, afterSiblingEdit, staleSubj) {
			t.Fatalf("InertForSubject(%q) = true after editing/removing %q, want false", staleSubj, staleSubj)
		}
	}

	// 3. Editing errVal.Error (a method on reachable type errVal, even if TestA never wrote identifier "Error") or (*box[T]).run invalidates TestA.
	afterMethodEdit := afterSiblingEdit.Clone()
	for i := range afterMethodEdit.Declarations {
		if afterMethodEdit.Declarations[i].Name == "Error" {
			afterMethodEdit.Declarations[i].Hash = "me2"
		}
	}
	if InertForSubject(before, afterMethodEdit, "TestA") {
		t.Fatal("editing interface method on reachable type errVal reported inert for TestA")
	}

	// 4. Editing BaseFiles-referenced BaseHook invalidates every subject in the compartment.
	afterBaseHookEdit := afterSiblingEdit.Clone()
	for i := range afterBaseHookEdit.Declarations {
		if afterBaseHookEdit.Declarations[i].Name == "BaseHook" {
			afterBaseHookEdit.Declarations[i].Hash = "bh2"
		}
	}
	if InertForSubject(before, afterBaseHookEdit, "TestA") {
		t.Fatal("editing BaseFiles-referenced BaseHook reported inert for TestA")
	}

	// 5. Replacing or inserting a blank-named const governor ("_") before an omitted-list const ("constOmit") invalidates TestA.
	afterBlankConst := afterSiblingEdit.Clone()
	for i := range afterBlankConst.Declarations {
		if afterBlankConst.Declarations[i].Name == "constOmit" {
			// Same hash, but governing const spec changed to blank "_"
			afterBlankConst.Declarations[i].References = []string{"_", "constOmit"}
		}
	}
	afterBlankConst.Declarations = append(afterBlankConst.Declarations, TestVariantDeclaration{
		File: "a_test.go", Package: "p", Kind: "const", Name: "_", Hash: "cblank1",
	})
	sort.Slice(afterBlankConst.Declarations, func(i, j int) bool {
		return LessDeclaration(afterBlankConst.Declarations[i], afterBlankConst.Declarations[j])
	})
	if InertForSubject(before, afterBlankConst, "TestA") {
		t.Fatal("inserting blank const governor before omitted-list constOmit reported inert for TestA")
	}

	// 6. Editing an existing blank-named const governor ("_") when constOmit already references "_" invalidates TestA.
	beforeWithBlankGov := before.Clone()
	for i := range beforeWithBlankGov.Declarations {
		if beforeWithBlankGov.Declarations[i].Name == "constGov" {
			beforeWithBlankGov.Declarations[i].Name = "_"
			beforeWithBlankGov.Declarations[i].References = nil
		}
		if beforeWithBlankGov.Declarations[i].Name == "constOmit" {
			beforeWithBlankGov.Declarations[i].References = []string{"_", "constOmit"}
		}
	}
	afterEditedBlankGov := beforeWithBlankGov.Clone()
	for i := range afterEditedBlankGov.Declarations {
		if afterEditedBlankGov.Declarations[i].Name == "_" && afterEditedBlankGov.Declarations[i].Kind == "const" {
			afterEditedBlankGov.Declarations[i].Hash = "cg2"
		}
		if afterEditedBlankGov.Declarations[i].Name == "TestB" {
			afterEditedBlankGov.Declarations[i].Hash = "tb2"
		}
	}
	if InertForSubject(beforeWithBlankGov, afterEditedBlankGov, "TestA") {
		t.Fatal("editing blank const governor referenced by constOmit reported inert for TestA")
	}

	// 7. Editing an init, var, directive, or TestMain declaration in the compartment invalidates TestA.
	for _, globalDecl := range []TestVariantDeclaration{
		{File: "a_test.go", Package: "p", Kind: "init", Name: "init", Hash: "g1"},
		{File: "a_test.go", Package: "p", Kind: "var", Name: "pkgState", Hash: "g1"},
		{File: "a_test.go", Package: "p", Kind: "directive", Name: "go:linkname", Hash: "g1"},
		{File: "a_test.go", Package: "p", Kind: "func", Name: "TestMain", Hash: "g1"},
	} {
		withGlobalBefore := before.Clone()
		withGlobalBefore.Declarations = append(withGlobalBefore.Declarations, globalDecl)
		withGlobalAfter := afterSiblingEdit.Clone()
		editedGlobal := globalDecl
		editedGlobal.Hash = "g2"
		withGlobalAfter.Declarations = append(withGlobalAfter.Declarations, editedGlobal)
		if InertForSubject(withGlobalBefore, withGlobalAfter, "TestA") {
			t.Fatalf("editing %s %s reported inert for TestA", globalDecl.Kind, globalDecl.Name)
		}
	}

	// 8. Swapping a reachable import binding ("fmt") invalidates TestA, while TestExt in ext_test.go stays inert.
	afterImportSwap := afterSiblingEdit.Clone()
	afterImportSwap.FileHeaders[0].Bindings.Imports = []TestVariantImport{{Name: "fmt", Path: "example.com/fakefmt"}}
	if InertForSubject(before, afterImportSwap, "TestA") {
		t.Fatal("swapping reachable import fmt reported inert for TestA")
	}
	if !InertForSubject(before, afterImportSwap, "TestExt") {
		t.Fatal("swapping import in a_test.go defeated inertness for TestExt in ext_test.go")
	}
}
