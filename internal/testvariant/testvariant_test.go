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
	for _, okSubj := range []string{"TestA", "box.run", "*box.run", "(*box[T]).run", "box[int].run", "TestExt", "ProdFunc"} {
		if !InertForSubject(before, afterSiblingEdit, okSubj) {
			t.Fatalf("InertForSubject(%q) = false after unrelated sibling edits, want true", okSubj)
		}
	}
	for _, staleSubj := range []string{"TestB", "helperB", "pair.unused", "*pair.unused", "pair[int, string].unused", "NonExistent"} {
		if InertForSubject(before, afterSiblingEdit, staleSubj) {
			t.Fatalf("InertForSubject(%q) = true after editing/removing %q, want false", staleSubj, staleSubj)
		}
	}

	// 2b. A pre-existing //go:linkname directive in before.Declarations fails closed whenever any declaration changes,
	// even if the directive itself is unchanged between before and after.
	beforeWithLinkname := before.Clone()
	beforeWithLinkname.Declarations = append(beforeWithLinkname.Declarations, TestVariantDeclaration{
		File: "a_test.go", Package: "p", Kind: "directive", Name: "go:linkname", Hash: "ln1",
	})
	afterWithLinkname := afterSiblingEdit.Clone()
	afterWithLinkname.Declarations = append(afterWithLinkname.Declarations, TestVariantDeclaration{
		File: "a_test.go", Package: "p", Kind: "directive", Name: "go:linkname", Hash: "ln1",
	})
	if InertForSubject(beforeWithLinkname, afterWithLinkname, "TestA") {
		t.Fatal("pre-existing //go:linkname directive with non-inert delta reported inert for TestA")
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

	// 9. Pure addition (no Changed/Removed) of a blank const governor ("_") when an omitted-list const references "_"
	// must fail BOTH DiffTestVariantLedgers.Inert() and InertForSubject (regression test for bindingsPreserved).
	pureBlankGovBefore := before.Clone()
	pureBlankGovBefore.FileHeaders[0].Bindings.References = append(pureBlankGovBefore.FileHeaders[0].Bindings.References, "_")
	for i := range pureBlankGovBefore.Declarations {
		if pureBlankGovBefore.Declarations[i].Name == "constOmit" {
			pureBlankGovBefore.Declarations[i].References = []string{"_", "constOmit"}
		}
	}
	pureBlankGovAfter := pureBlankGovBefore.Clone()
	pureBlankGovAfter.Declarations = append(pureBlankGovAfter.Declarations, TestVariantDeclaration{
		File: "a_test.go", Package: "p", Kind: "const", Name: "_", Hash: "cblank_pure",
	})
	if DiffTestVariantLedgers(pureBlankGovBefore, pureBlankGovAfter).Inert() {
		t.Fatal("pure addition of blank const governor with '_' in file references reported Delta.Inert() = true")
	}
	if InertForSubject(pureBlankGovBefore, pureBlankGovAfter, "TestA") {
		t.Fatal("pure addition of blank const governor reported InertForSubject(TestA) = true")
	}

	// 10. Pure addition of an exported declaration in base package "p" whose name is referenced in "p_test"
	// must fail BOTH DiffTestVariantLedgers.Inert() and InertForSubject(TestExt).
	extShadowBefore := before.Clone()
	extShadowBefore.FileHeaders[1].Bindings.References = append(extShadowBefore.FileHeaders[1].Bindings.References, "PromotedFromEmbed")
	for i := range extShadowBefore.Declarations {
		if extShadowBefore.Declarations[i].Name == "TestExt" {
			extShadowBefore.Declarations[i].References = append(extShadowBefore.Declarations[i].References, "PromotedFromEmbed")
		}
	}
	extShadowAfter := extShadowBefore.Clone()
	extShadowAfter.Declarations = append(extShadowAfter.Declarations, TestVariantDeclaration{
		File: "a_test.go", Package: "p", Kind: "const", Name: "PromotedFromEmbed", Hash: "pfe1",
	})
	if DiffTestVariantLedgers(extShadowBefore, extShadowAfter).Inert() {
		t.Fatal("pure addition of exported p.PromotedFromEmbed referenced in p_test reported Delta.Inert() = true")
	}
	if InertForSubject(extShadowBefore, extShadowAfter, "TestExt") {
		t.Fatal("pure addition of exported p.PromotedFromEmbed referenced in p_test reported InertForSubject(TestExt) = true")
	}

	// 11. Dot-import drift in a reachable file invalidates subjects in that file, while embedded header change invalidates all.
	afterDotImport := afterSiblingEdit.Clone()
	afterDotImport.FileHeaders[0].Bindings.Imports = append(afterDotImport.FileHeaders[0].Bindings.Imports, TestVariantImport{
		Name: ".", Path: "example.com/dot",
	})
	if InertForSubject(before, afterDotImport, "TestA") {
		t.Fatal("adding dot import to reachable file a_test.go reported inert for TestA")
	}
	afterEmbeddedChange := before.Clone()
	afterEmbeddedChange.FileHeaders = append(afterEmbeddedChange.FileHeaders, TestVariantFileHeader{
		File: "testdata/fixture.txt", Hash: "emb1", Embedded: true,
	})
	if DiffTestVariantLedgers(before, afterEmbeddedChange).Inert() || InertForSubject(before, afterEmbeddedChange, "TestA") {
		t.Fatal("embedded file header addition reported inert")
	}
}

//gofresh:pure
func TestDiffTestVariantLedgersDuplicatePairingPackageRehomingAndClone(t *testing.T) {
	before := TestVariantLedger{
		BindingStrategy: BindingStrategy,
		BaseFiles: []TestVariantFileHeader{{
			File: "prod.go",
			Bindings: &TestVariantFileBindings{
				Package:    "p",
				References: []string{"Prod"},
				Imports:    []TestVariantImport{{Name: "fmt", Path: "fmt"}},
			},
		}},
		FileHeaders: []TestVariantFileHeader{{
			File: "a_test.go",
			Hash: "h1",
			Bindings: &TestVariantFileBindings{
				Package:    "p",
				References: []string{"TestOne"},
			},
		}},
		Declarations: []TestVariantDeclaration{
			{File: "a_test.go", Package: "p", Kind: "init", Name: "init", Hash: "i1"},
			{File: "a_test.go", Package: "p", Kind: "init", Name: "init", Hash: "i2"},
			{File: "a_test.go", Package: "p", Kind: "func", Name: "TestOne", Hash: "t1", References: []string{"TestOne"}},
		},
	}

	// 1. Clone deep-copies slices and pointers so mutating the clone leaves the original untouched.
	cloned := before.Clone()
	cloned.BaseFiles[0].Bindings.References[0] = "MutatedRef"
	cloned.BaseFiles[0].Bindings.Imports[0].Path = "mutated/path"
	cloned.Declarations[2].References[0] = "MutatedDeclRef"
	if before.BaseFiles[0].Bindings.References[0] != "Prod" ||
		before.BaseFiles[0].Bindings.Imports[0].Path != "fmt" ||
		before.Declarations[2].References[0] != "TestOne" {
		t.Fatalf("Clone() aliased underlying slices/pointers: before=%+v", before)
	}

	// 2. Duplicate identity pairing (multiple init functions in a_test.go): keeping i2, editing i1->i3, and adding i4
	// reports 1 Changed (i1->i3) and 1 Added (i4).
	afterInit := before.Clone()
	afterInit.Declarations = []TestVariantDeclaration{
		{File: "a_test.go", Package: "p", Kind: "init", Name: "init", Hash: "i2"},
		{File: "a_test.go", Package: "p", Kind: "init", Name: "init", Hash: "i3"},
		{File: "a_test.go", Package: "p", Kind: "init", Name: "init", Hash: "i4"},
		{File: "a_test.go", Package: "p", Kind: "func", Name: "TestOne", Hash: "t1", References: []string{"TestOne"}},
	}
	deltaInit := DiffTestVariantLedgers(before, afterInit)
	if len(deltaInit.Changed) != 1 || deltaInit.Changed[0].Before.Hash != "i1" || deltaInit.Changed[0].After.Hash != "i3" {
		t.Fatalf("deltaInit.Changed = %+v, want [i1->i3]", deltaInit.Changed)
	}
	if len(deltaInit.Added) != 1 || deltaInit.Added[0].Hash != "i4" || len(deltaInit.Removed) != 0 {
		t.Fatalf("deltaInit Added=%+v Removed=%+v, want Added=[i4] Removed=[]", deltaInit.Added, deltaInit.Removed)
	}

	// 3. Package-clause rename (p -> p_test) re-homes declarations so they report as Removed + Added, never empty delta.
	afterPkgRename := before.Clone()
	afterPkgRename.FileHeaders[0].Bindings.Package = "p_test"
	for i := range afterPkgRename.Declarations {
		afterPkgRename.Declarations[i].Package = "p_test"
	}
	deltaRename := DiffTestVariantLedgers(before, afterPkgRename)
	if deltaRename.Inert() || len(deltaRename.Removed) != 3 || len(deltaRename.Added) != 3 {
		t.Fatalf("package-clause rename delta = %+v, want Inert=false, 3 Removed, 3 Added", deltaRename)
	}
}
