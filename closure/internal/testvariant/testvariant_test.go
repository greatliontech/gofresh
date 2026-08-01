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
