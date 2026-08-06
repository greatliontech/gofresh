package testvariant

import (
	"reflect"
	"sort"
	"testing"
)

// parseLedger builds a one-file ledger straight from source bytes, the same
// parse the compartment computation performs, so positional-semantics
// witnesses need no module or go list round-trip.
func parseLedger(t *testing.T, name, src string) TestVariantLedger {
	t.Helper()
	declarations, header, err := parseTestVariantFile(name, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	ledger := TestVariantLedger{Declarations: declarations, FileHeaders: []TestVariantFileHeader{header}}
	sort.Slice(ledger.Declarations, func(i, j int) bool {
		return lessDeclaration(ledger.Declarations[i], ledger.Declarations[j])
	})
	return ledger
}

// A const inserted mid-group shifts its iota (and implicit-repetition)
// siblings, so the ledger reads the shifted siblings as changed and the delta
// is not inert; appending at the group's end shifts nothing and stays an
// inert add (REQ-closure-test-variant-compartment positional folding).
func TestConstInsertionInsideGroupReadsAsChanged(t *testing.T) {
	const before = "package p\n\nconst (\n\tsizeA = iota\n\tsizeB\n)\n"
	recorded := parseLedger(t, "a_test.go", before)

	inserted := parseLedger(t, "a_test.go", "package p\n\nconst (\n\tsizeA = iota\n\tsizeMid\n\tsizeB\n)\n")
	delta := DiffTestVariantLedgers(recorded, inserted)
	if delta.Inert() {
		t.Fatalf("mid-group const insertion classified inert: %+v", delta)
	}
	changed := map[string]bool{}
	for _, change := range delta.Changed {
		changed[change.After.Name] = true
	}
	if !changed["sizeB"] {
		t.Fatalf("shifted iota sibling not read as changed: %+v", delta)
	}

	appended := parseLedger(t, "a_test.go", before[:len(before)-2]+"\tsizeEnd\n)\n")
	tail := DiffTestVariantLedgers(recorded, appended)
	if !tail.Inert() || len(tail.Added) != 1 || tail.Added[0].Name != "sizeEnd" || len(tail.Changed) != 0 {
		t.Fatalf("group-end const append = %+v (inert=%v), want inert added-only sizeEnd", tail, tail.Inert())
	}
}

// Package-level initialization order is source order for var specs and init
// functions within a file, so a pure reorder — byte-identical declarations —
// reads as changed and defeats inertness
// (REQ-closure-test-variant-compartment positional folding).
func TestInitAndVarReordersReadAsChanged(t *testing.T) {
	initBefore := parseLedger(t, "a_test.go", "package p\n\nfunc init() { order = append(order, 1) }\n\nfunc init() { order = append(order, 2) }\n")
	initAfter := parseLedger(t, "a_test.go", "package p\n\nfunc init() { order = append(order, 2) }\n\nfunc init() { order = append(order, 1) }\n")
	initDelta := DiffTestVariantLedgers(initBefore, initAfter)
	if initDelta.Inert() || len(initDelta.Changed) == 0 {
		t.Fatalf("init reorder delta = %+v (inert=%v), want changed declarations", initDelta, initDelta.Inert())
	}

	varBefore := parseLedger(t, "a_test.go", "package p\n\nvar first = sideEffect(1)\n\nvar second = sideEffect(2)\n")
	varAfter := parseLedger(t, "a_test.go", "package p\n\nvar second = sideEffect(2)\n\nvar first = sideEffect(1)\n")
	varDelta := DiffTestVariantLedgers(varBefore, varAfter)
	if varDelta.Inert() || len(varDelta.Changed) == 0 {
		t.Fatalf("var reorder delta = %+v (inert=%v), want changed declarations", varDelta, varDelta.Inert())
	}
}

// The classified ledger diff carries gofresh's one Go-semantics judgment: an
// added plain function, const, or type is inert for unchanged code; an added
// var, init, TestMain, or method is not — each has a mechanism reaching
// unchanged declarations — and any changed or removed declaration defeats
// inertness outright. Go-file header-only changes never defeat it; a non-Go
// compartment file's movement always does
// (REQ-closure-test-variant-compartment).
func TestLedgerDeltaClassifiesInertness(t *testing.T) {
	base := TestVariantLedger{
		Declarations: []TestVariantDeclaration{
			{File: "a_test.go", Kind: "func", Name: "TestA", Hash: "h1"},
			{File: "a_test.go", Kind: "var", Name: "fixtures", Hash: "h2"},
		},
		FileHeaders: []TestVariantFileHeader{
			{File: "a_test.go", Hash: "header1"},
			{File: "testdata.json", Hash: "data1", Embedded: true},
		},
	}
	withDeclaration := func(declaration TestVariantDeclaration) TestVariantLedger {
		after := base.Clone()
		after.Declarations = append(after.Declarations, declaration)
		return after
	}
	for _, tc := range []struct {
		name  string
		after TestVariantLedger
		inert bool
	}{
		{"added plain func", withDeclaration(TestVariantDeclaration{File: "a_test.go", Kind: "func", Name: "TestB", Hash: "h3"}), true},
		{"added const", withDeclaration(TestVariantDeclaration{File: "a_test.go", Kind: "const", Name: "limit", Hash: "h3"}), true},
		{"added method-free type", withDeclaration(TestVariantDeclaration{File: "a_test.go", Kind: "type", Name: "harness", Hash: "h3"}), true},
		{"added var", withDeclaration(TestVariantDeclaration{File: "a_test.go", Kind: "var", Name: "state", Hash: "h3"}), false},
		{"added init", withDeclaration(TestVariantDeclaration{File: "a_test.go", Kind: "init", Name: "init", Hash: "h3"}), false},
		{"added TestMain", withDeclaration(TestVariantDeclaration{File: "a_test.go", Kind: "func", Name: "TestMain", Hash: "h3"}), false},
		{"added method", withDeclaration(TestVariantDeclaration{File: "a_test.go", Kind: "method", Name: "run", Receiver: "harness", Hash: "h3"}), false},
		{
			"changed declaration",
			TestVariantLedger{
				Declarations: []TestVariantDeclaration{
					{File: "a_test.go", Kind: "func", Name: "TestA", Hash: "h1-edited"},
					{File: "a_test.go", Kind: "var", Name: "fixtures", Hash: "h2"},
				},
				FileHeaders: base.FileHeaders,
			},
			false,
		},
		{
			"removed declaration",
			TestVariantLedger{
				Declarations: base.Declarations[:1],
				FileHeaders:  base.FileHeaders,
			},
			false,
		},
		{
			"go-file header-only change",
			TestVariantLedger{
				Declarations: base.Declarations,
				FileHeaders: []TestVariantFileHeader{
					{File: "a_test.go", Hash: "header1-imports-edited"},
					{File: "testdata.json", Hash: "data1", Embedded: true},
				},
			},
			true,
		},
		{
			"embedded member change",
			TestVariantLedger{
				Declarations: base.Declarations,
				FileHeaders: []TestVariantFileHeader{
					{File: "a_test.go", Hash: "header1"},
					{File: "testdata.json", Hash: "data1-edited", Embedded: true},
				},
			},
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delta := DiffTestVariantLedgers(base, tc.after)
			if delta.Inert() != tc.inert {
				t.Fatalf("Inert() = %v, want %v (delta %+v)", delta.Inert(), tc.inert, delta)
			}
		})
	}
	if delta := DiffTestVariantLedgers(base, base.Clone()); !delta.Inert() || len(delta.Added)+len(delta.Changed)+len(delta.Removed)+len(delta.HeaderChanges) != 0 {
		t.Fatalf("identical ledgers diffed to %+v, want empty inert delta", delta)
	}
}

// The diff itself is deterministic data: recomputation over the same pair is
// identical, entries are ledger-sorted, same-identity declarations (several
// init functions in one file) pair by hash with the surplus classified added
// or removed, and file membership changes surface as header additions and
// removals (REQ-closure-test-variant-compartment).
func TestLedgerDeltaIsDeterministicAndClassifiesMembership(t *testing.T) {
	before := TestVariantLedger{
		Declarations: []TestVariantDeclaration{
			{File: "a_test.go", Kind: "init", Name: "init", Hash: "i1"},
			{File: "a_test.go", Kind: "init", Name: "init", Hash: "i2"},
			{File: "b_test.go", Kind: "func", Name: "TestB", Hash: "b1"},
		},
		FileHeaders: []TestVariantFileHeader{
			{File: "a_test.go", Hash: "ha"},
			{File: "b_test.go", Hash: "hb"},
		},
	}
	after := TestVariantLedger{
		Declarations: []TestVariantDeclaration{
			{File: "a_test.go", Kind: "init", Name: "init", Hash: "i1"},
			{File: "a_test.go", Kind: "init", Name: "init", Hash: "i3"},
			{File: "c_test.go", Kind: "func", Name: "TestC", Hash: "c1"},
		},
		FileHeaders: []TestVariantFileHeader{
			{File: "a_test.go", Hash: "ha"},
			{File: "c_test.go", Hash: "hc"},
		},
	}
	first := DiffTestVariantLedgers(before, after)
	second := DiffTestVariantLedgers(before, after)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("diff not deterministic:\n%+v\n%+v", first, second)
	}
	if len(first.Changed) != 1 || first.Changed[0].Before.Hash != "i2" || first.Changed[0].After.Hash != "i3" {
		t.Fatalf("same-identity pairing = %+v, want i2 -> i3 changed", first.Changed)
	}
	if len(first.Added) != 1 || first.Added[0].Name != "TestC" {
		t.Fatalf("added = %+v, want TestC", first.Added)
	}
	if len(first.Removed) != 1 || first.Removed[0].Name != "TestB" {
		t.Fatalf("removed = %+v, want TestB", first.Removed)
	}
	if len(first.HeaderChanges) != 2 ||
		first.HeaderChanges[0].File != "b_test.go" || first.HeaderChanges[0].After != "" ||
		first.HeaderChanges[1].File != "c_test.go" || first.HeaderChanges[1].Before != "" {
		t.Fatalf("header membership = %+v, want b_test.go removed and c_test.go added", first.HeaderChanges)
	}
	if first.Inert() {
		t.Fatal("delta with changed and removed declarations reported inert")
	}

	// An Embedded flip alone — same file, same hash — is a header change and
	// fails closed: the member's bytes changed roles, not content.
	flipped := DiffTestVariantLedgers(
		TestVariantLedger{FileHeaders: []TestVariantFileHeader{{File: "x_test.go", Hash: "h"}}},
		TestVariantLedger{FileHeaders: []TestVariantFileHeader{{File: "x_test.go", Hash: "h", Embedded: true}}},
	)
	if flipped.Inert() || len(flipped.HeaderChanges) != 1 || !flipped.HeaderChanges[0].Embedded {
		t.Fatalf("embedded flip delta = %+v (inert=%v), want one non-inert embedded header change", flipped, flipped.Inert())
	}
}

// Compiler and linker directives are behavior-bearing from any position, so
// they are ledgered as their own "directive" entries wherever they sit and
// any directive movement defeats inertness; build-constraint text is the one
// exclusion and stays header-benign
// (REQ-closure-test-variant-compartment directive entries).
func TestDirectiveCommentsDefeatInertness(t *testing.T) {
	const base = "package p\n\nvar (\n\tfixtureA = 1\n\tfixtureB = 2\n)\n\nfunc TestF(t *T) {}\n"
	recorded := parseLedger(t, "a_test.go", base)

	debugged := parseLedger(t, "a_test.go", "//go:debug panicnil=1\n\n"+base)
	delta := DiffTestVariantLedgers(recorded, debugged)
	if delta.Inert() || len(delta.Added) != 1 || delta.Added[0].Kind != "directive" || delta.Added[0].Name != "go:debug" {
		t.Fatalf("header //go:debug delta = %+v (inert=%v), want a non-inert added directive", delta, delta.Inert())
	}

	// A floating directive inside a group span sits in no spec range and no
	// header remainder — the directive entry is what keeps the delta honest.
	linked := parseLedger(t, "a_test.go", "package p\n\nvar (\n\tfixtureA = 1\n\t//go:linkname fixtureB other.symbol\n\tfixtureB = 2\n)\n\nfunc TestF(t *T) {}\n")
	delta = DiffTestVariantLedgers(recorded, linked)
	if delta.Inert() {
		t.Fatalf("floating //go:linkname classified inert: %+v", delta)
	}
	named := false
	for _, added := range delta.Added {
		named = named || (added.Kind == "directive" && added.Name == "go:linkname")
	}
	if !named {
		t.Fatalf("floating directive missing from the delta: %+v", delta)
	}

	// Build-constraint text stays header content: no directive entry, and a
	// text-only edit is header-benign.
	constrained := parseLedger(t, "a_test.go", "//go:build linux\n\n"+base)
	reconstrained := parseLedger(t, "a_test.go", "//go:build linux || darwin\n\n"+base)
	for _, declaration := range constrained.Declarations {
		if declaration.Kind == "directive" {
			t.Fatalf("build constraint ledgered as a directive: %+v", declaration)
		}
	}
	delta = DiffTestVariantLedgers(constrained, reconstrained)
	if !delta.Inert() || len(delta.HeaderChanges) != 1 {
		t.Fatalf("build-constraint text edit = %+v (inert=%v), want a header-only inert delta", delta, delta.Inert())
	}
}

// A declaration's doc comment rides its hash — editing only the doc moves the
// declaration entry, not the file header
// (REQ-closure-test-variant-compartment ledger granularity).
func TestDocCommentRidesTheDeclarationHash(t *testing.T) {
	before := parseLedger(t, "a_test.go", "package p\n\nfunc F() {}\n")
	after := parseLedger(t, "a_test.go", "package p\n\n// F does nothing yet.\nfunc F() {}\n")
	if before.Declarations[0].Hash == after.Declarations[0].Hash {
		t.Fatal("doc-comment edit did not move the declaration hash")
	}
	if before.FileHeaders[0].Hash != after.FileHeaders[0].Hash {
		t.Fatal("doc-comment edit moved the file header identity")
	}
}

// The referenced-name list is the syntax-only reference surface: every
// identifier under the declaration — called helpers, selector members,
// receiver and parameter types, locals — deduplicated and sorted, with the
// blank identifier dropped and directive entries carrying none
// (REQ-closure-test-variant-compartment reference surface).
func TestDeclarationReferencesCollectIdentifiersAndSelectors(t *testing.T) {
	const src = "package p\n\n" +
		"//go:generate stub\n" +
		"type suite struct{ n int }\n\n" +
		"func (s *suite) run() int { return helperA() }\n\n" +
		"func TestF(t *T) {\n\tvar local suite\n\t_ = local.run()\n\ts := fmt.Sprint(helperB())\n\t_ = s\n}\n\n" +
		"var (\n\ttableA = helperA()\n\ttableB = helperB()\n)\n"
	ledger := parseLedger(t, "a_test.go", src)
	byName := map[string]TestVariantDeclaration{}
	for _, declaration := range ledger.Declarations {
		byName[declaration.Kind+"/"+declaration.Name] = declaration
	}
	test := byName["func/TestF"]
	for _, want := range []string{"helperB", "run", "suite", "fmt", "Sprint", "local", "TestF"} {
		if !slicesContains(test.References, want) {
			t.Fatalf("TestF references %v, want %q present", test.References, want)
		}
	}
	if slicesContains(test.References, "_") {
		t.Fatalf("blank identifier collected: %v", test.References)
	}
	if !sort.StringsAreSorted(test.References) {
		t.Fatalf("references not sorted: %v", test.References)
	}
	method := byName["method/run"]
	for _, want := range []string{"suite", "helperA"} {
		if !slicesContains(method.References, want) {
			t.Fatalf("method run references %v, want %q present", method.References, want)
		}
	}
	// Grouped specs reference spec-locally: tableA sees helperA, not helperB.
	if got := byName["var/tableA"].References; !slicesContains(got, "helperA") || slicesContains(got, "helperB") {
		t.Fatalf("tableA references %v, want helperA without helperB", got)
	}
	if got := byName["directive/go:generate"].References; len(got) != 0 {
		t.Fatalf("directive carries references: %v", got)
	}
	// Every entry names its declaring file's package clause.
	for key, declaration := range byName {
		if declaration.Package != "p" {
			t.Fatalf("%s carries package %q, want the file's package clause p", key, declaration.Package)
		}
	}
	// Deduplicated: "local" appears twice in TestF's source (declaration
	// and use) and exactly once in its reference list.
	occurrences := 0
	for _, name := range test.References {
		if name == "local" {
			occurrences++
		}
	}
	if occurrences != 1 {
		t.Fatalf("local appears %d times in %v, want deduplication to one", occurrences, test.References)
	}
}

// A const spec with an omitted expression list repeats the group's governing
// list textually, so its compiled code resolves that list's names without
// writing them: the governing spec's references fold into the empty-listed
// sibling, and a later spec with its own list resets the fold
// (REQ-closure-test-variant-compartment reference surface).
func TestImplicitConstRepetitionFoldsGoverningReferences(t *testing.T) {
	const src = "package p\n\nconst (\n\tkindA = otherConst + 1\n\tkindB\n\tkindC = plainConst\n\tkindD\n)\n"
	ledger := parseLedger(t, "a_test.go", src)
	byName := map[string][]string{}
	for _, declaration := range ledger.Declarations {
		byName[declaration.Name] = declaration.References
	}
	if !slicesContains(byName["kindB"], "otherConst") {
		t.Fatalf("kindB references %v, want the governing list's otherConst folded in", byName["kindB"])
	}
	// The governing spec's own name is the load-bearing edge: an edit to
	// the governing list is that entry's own movement, so a consumer walk
	// reaching kindA observes every change kindB textually repeats.
	if !slicesContains(byName["kindB"], "kindA") {
		t.Fatalf("kindB references %v, want the governing spec's own name folded in", byName["kindB"])
	}
	if !slicesContains(byName["kindD"], "plainConst") || slicesContains(byName["kindD"], "otherConst") {
		t.Fatalf("kindD references %v, want plainConst governing without the stale otherConst", byName["kindD"])
	}
	if !sort.StringsAreSorted(byName["kindB"]) {
		t.Fatalf("folded references not sorted: %v", byName["kindB"])
	}

	// A blank-named governor declares nothing a test can write, so the
	// fold's edge to it is the blank name itself: the ledger's "_" entry is
	// a walkable node, and without the edge an empty-listed sibling's
	// repetition of `_ = expr` would be attributable to nothing.
	blank := parseLedger(t, "b_test.go", "package p\n\nconst (\n\t_ = helperA\n\tblankKind\n)\n")
	blankFound := false
	for _, declaration := range blank.Declarations {
		if declaration.Name == "blankKind" {
			blankFound = true
			if !slicesContains(declaration.References, "_") {
				t.Fatalf("blankKind references %v, want the blank governor's ledger edge", declaration.References)
			}
		}
	}
	if !blankFound {
		t.Fatalf("blankKind entry missing from ledger: %+v", blank.Declarations)
	}
}

// A package-clause-only rename re-homes every declaration semantically —
// methods re-attach across same-named types, unexported access changes —
// while leaving every declaration's bytes and the file's declaration set
// untouched. The package clause is part of the diff identity, so the rename
// surfaces as removed and added declarations, never as an empty (inert)
// delta hiding behind a licensed header change
// (REQ-closure-test-variant-compartment).
func TestPackageClauseRenameSurfacesAsMembershipChange(t *testing.T) {
	recorded := parseLedger(t, "a_test.go", "package p\n\nfunc (T) Error() string { return \"\" }\n\nfunc TestF(t *X) {}\n")
	renamed := parseLedger(t, "a_test.go", "package p_test\n\nfunc (T) Error() string { return \"\" }\n\nfunc TestF(t *X) {}\n")
	if got := recorded.Declarations[0].Package; got != "p" {
		t.Fatalf("in-package clause = %q, want p", got)
	}
	if got := renamed.Declarations[0].Package; got != "p_test" {
		t.Fatalf("external clause = %q, want p_test", got)
	}
	delta := DiffTestVariantLedgers(recorded, renamed)
	if len(delta.Removed) != 2 || len(delta.Added) != 2 || delta.Inert() {
		t.Fatalf("clause rename delta = %+v (inert=%v), want every declaration removed and re-added", delta, delta.Inert())
	}
}

// Delta classification never reads the reference surface: two ledgers whose
// declarations differ only in References diff to an empty, inert delta
// (REQ-closure-test-variant-compartment — classification is hash-based).
func TestClassificationIgnoresReferences(t *testing.T) {
	ledger := parseLedger(t, "a_test.go", "package p\n\nfunc TestF(t *T) { helper() }\n\nfunc helper() {}\n")
	doctored := ledger.Clone()
	for i := range doctored.Declarations {
		doctored.Declarations[i].References = []string{"unrelated"}
	}
	delta := DiffTestVariantLedgers(ledger, doctored)
	if len(delta.Added) != 0 || len(delta.Changed) != 0 || len(delta.Removed) != 0 || len(delta.HeaderChanges) != 0 || !delta.Inert() {
		t.Fatalf("reference-only difference classified as movement: %+v", delta)
	}
}

// Equal declaration hashes carry equal reference lists — references derive
// from the bytes the hash folds — and a positional-digest movement
// (a shifted const ordinal) moves the hash while the references, a pure
// function of the spec's own bytes when it carries its own expression
// list, stay identical. The omitted-list fold is the one stated exception,
// pinned by TestImplicitConstRepetitionFoldsGoverningReferences
// (REQ-closure-test-variant-compartment reference surface).
func TestDeclarationReferencesAreAPureFunctionOfTheBytes(t *testing.T) {
	const src = "package p\n\nconst (\n\tkindA = iota\n\tkindB = kindA + 1\n)\n\nfunc TestF(t *T) { _ = kindB }\n"
	first := parseLedger(t, "a_test.go", src)
	second := parseLedger(t, "a_test.go", src)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("parse not deterministic:\n%+v\n%+v", first, second)
	}
	shifted := parseLedger(t, "a_test.go", "package p\n\nconst (\n\tkindZ = iota\n\tkindA = iota\n\tkindB = kindA + 1\n)\n\nfunc TestF(t *T) { _ = kindB }\n")
	pick := func(ledger TestVariantLedger, name string) TestVariantDeclaration {
		for _, declaration := range ledger.Declarations {
			if declaration.Name == name {
				return declaration
			}
		}
		t.Fatalf("%s not in ledger", name)
		return TestVariantDeclaration{}
	}
	before, after := pick(first, "kindB"), pick(shifted, "kindB")
	if len(before.References) == 0 {
		t.Fatalf("kindB carries no references; the equality below would be vacuous")
	}
	if before.Hash == after.Hash {
		t.Fatalf("shifted iota sibling kept its hash")
	}
	if !reflect.DeepEqual(before.References, after.References) {
		t.Fatalf("byte-identical spec's references moved: %v vs %v", before.References, after.References)
	}
}

// Clone hands the caller an isolated ledger: mutating a clone's reference
// list never surfaces through the original.
func TestCloneIsolatesReferences(t *testing.T) {
	ledger := parseLedger(t, "a_test.go", "package p\n\nfunc TestF(t *T) { helper() }\n")
	clone := ledger.Clone()
	for i := range clone.Declarations {
		for j := range clone.Declarations[i].References {
			clone.Declarations[i].References[j] = "mutated"
		}
	}
	if slicesContains(ledger.Declarations[0].References, "mutated") {
		t.Fatalf("clone shares reference backing array with original")
	}
}

func slicesContains(list []string, want string) bool {
	for _, have := range list {
		if have == want {
			return true
		}
	}
	return false
}
