package closure

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
)

func writeTestVariantModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func computeAt(t *testing.T, dir string, subjects ...Subject) map[Subject]Closure {
	t.Helper()
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	closures, err := h.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	return closures
}

func ledgerAt(t *testing.T, dir, pkgPath string) TestVariantLedger {
	t.Helper()
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := h.TestVariantLedger(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

// The partition inverse of
// TestComputeMaximalBatchSharesPackageClosureWithoutSharingIdentity: a sibling
// test added to the package moves only the test-variant compartment, never a
// subject's core maximal hash (REQ-closure-view-maximal,
// REQ-closure-test-variant-compartment).
func TestSiblingTestAdditionMovesCompartmentNotCore(t *testing.T) {
	files := map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      "package partition\n\nfunc F() int { return 1 }\nfunc G() int { return 2 }\n",
		"partition_test.go": "package partition\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	}
	dir := writeTestVariantModule(t, files)
	subjects := []Subject{
		{Package: "example.com/partition", Symbol: "F"},
		{Package: "example.com/partition", Symbol: "G"},
	}
	before := computeAt(t, dir, subjects...)
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte(files["partition_test.go"]+"\nfunc TestG(t *testing.T) {\n\tif G() != 2 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := computeAt(t, dir, subjects...)
	for _, subject := range subjects {
		if before[subject].Hash != after[subject].Hash {
			t.Fatalf("sibling test addition moved core maximal closure for %s", subject.Symbol)
		}
		if before[subject].TestVariants == after[subject].TestVariants {
			t.Fatalf("sibling test addition did not move the compartment for %s", subject.Symbol)
		}
	}
}

// A production edit keeps today's semantics: the core moves; the compartment,
// whose files are untouched, does not (REQ-closure-view-maximal).
func TestProductionEditMovesCoreNotCompartment(t *testing.T) {
	files := map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      "package partition\n\nfunc F() int { return 1 }\n",
		"partition_test.go": "package partition\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	}
	dir := writeTestVariantModule(t, files)
	subject := Subject{Package: "example.com/partition", Symbol: "F"}
	before := computeAt(t, dir, subject)
	if err := os.WriteFile(filepath.Join(dir, "partition.go"), []byte("package partition\n\nfunc F() int { return 3 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := computeAt(t, dir, subject)
	if before[subject].Hash == after[subject].Hash {
		t.Fatal("production edit did not move the core maximal closure")
	}
	if before[subject].TestVariants != after[subject].TestVariants {
		t.Fatal("production edit moved the test-variant compartment")
	}
}

// A test file importing a NEW dependency package moves the core: the new
// package's init behavior enters the test binary, so its node is a core
// contribution even though only test files import it. Importing an
// already-present package moves only the compartment
// (REQ-closure-test-variant-compartment).
func TestNewTestOnlyDependencyMovesCore(t *testing.T) {
	files := map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      "package partition\n\nfunc F() int { return 1 }\n",
		"partition_test.go": "package partition\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
		"dep/dep.go":        "package dep\n\nfunc Two() int { return 2 }\n",
	}
	dir := writeTestVariantModule(t, files)
	subject := Subject{Package: "example.com/partition", Symbol: "F"}
	before := computeAt(t, dir, subject)
	if err := os.WriteFile(filepath.Join(dir, "extra_test.go"), []byte("package partition\n\nimport (\n\t\"testing\"\n\n\t\"example.com/partition/dep\"\n)\n\nfunc TestDep(t *testing.T) {\n\tif dep.Two() != 2 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := computeAt(t, dir, subject)
	if before[subject].Hash == after[subject].Hash {
		t.Fatal("test-only import of a new package did not move the core")
	}
	if before[subject].TestVariants == after[subject].TestVariants {
		t.Fatal("new test file did not move the compartment")
	}

	// The dependency is now present: a further test-only use of it moves the
	// compartment alone — its node already contributes to the core.
	if err := os.WriteFile(filepath.Join(dir, "extra_test.go"), []byte("package partition\n\nimport (\n\t\"testing\"\n\n\t\"example.com/partition/dep\"\n)\n\nfunc TestDep(t *testing.T) {\n\tif dep.Two() != 2 {\n\t\tt.Fatal(\"still broken\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	final := computeAt(t, dir, subject)
	if after[subject].Hash != final[subject].Hash {
		t.Fatal("test edit importing an already-present package moved the core")
	}
	if after[subject].TestVariants == final[subject].TestVariants {
		t.Fatal("test edit did not move the compartment")
	}
}

// A package with no test files has the defined constant compartment identity,
// stable across recomputation (REQ-closure-test-variant-compartment).
func TestNoTestPackageCompartmentIsStableEmptyIdentity(t *testing.T) {
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":  "module example.com/notest\n\ngo 1.26\n",
		"main.go": "package notest\n\nfunc F() int { return 1 }\n",
	})
	subject := Subject{Package: "example.com/notest", Symbol: "F"}
	first := computeAt(t, dir, subject)
	if first[subject].TestVariants != EmptyTestVariantClosure {
		t.Fatalf("no-test compartment = %q, want the defined empty identity %q", first[subject].TestVariants, EmptyTestVariantClosure)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package notest\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := computeAt(t, dir, subject)
	if second[subject].TestVariants != EmptyTestVariantClosure {
		t.Fatalf("no-test compartment drifted to %q after a production edit", second[subject].TestVariants)
	}
	ledger := ledgerAt(t, dir, "example.com/notest")
	if len(ledger.Declarations) != 0 || len(ledger.FileHeaders) != 0 {
		t.Fatalf("no-test ledger = %+v, want empty", ledger)
	}
}

// An external test package's files are test-only whole: they enter the
// compartment and the ledger with their declarations and file header
// (REQ-closure-test-variant-compartment).
func TestExternalTestPackageFilesEnterCompartmentAndLedger(t *testing.T) {
	files := map[string]string{
		"go.mod":      "module example.com/external\n\ngo 1.26\n",
		"external.go": "package external\n\nfunc F() int { return 1 }\n",
	}
	dir := writeTestVariantModule(t, files)
	subject := Subject{Package: "example.com/external", Symbol: "F"}
	before := computeAt(t, dir, subject)
	if err := os.WriteFile(filepath.Join(dir, "external_test.go"), []byte("package external_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/external\"\n)\n\nfunc TestF(t *testing.T) {\n\tif external.F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := computeAt(t, dir, subject)
	if before[subject].Hash != after[subject].Hash {
		t.Fatal("external test file moved the core")
	}
	if before[subject].TestVariants == after[subject].TestVariants {
		t.Fatal("external test file did not move the compartment")
	}
	ledger := ledgerAt(t, dir, "example.com/external")
	if len(ledger.Declarations) != 1 || ledger.Declarations[0].Name != "TestF" || ledger.Declarations[0].Kind != "func" || ledger.Declarations[0].File != "external_test.go" {
		t.Fatalf("external test ledger declarations = %+v, want TestF in external_test.go", ledger.Declarations)
	}
	if len(ledger.FileHeaders) != 1 || ledger.FileHeaders[0].File != "external_test.go" || ledger.FileHeaders[0].Hash == "" {
		t.Fatalf("external test ledger headers = %+v, want one external_test.go header", ledger.FileHeaders)
	}
}

// Editing an existing test function moves the compartment and exactly that
// declaration's ledger hash; appending a test to an existing file adds a
// ledger entry without moving the existing ones or the file header
// (REQ-closure-test-variant-compartment).
func TestLedgerNamesTheEditedAndAppendedDeclarations(t *testing.T) {
	const original = "package ledger\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":         "module example.com/ledger\n\ngo 1.26\n",
		"ledger.go":      "package ledger\n\nfunc F() int { return 1 }\n",
		"ledger_test.go": original,
	})
	const pkg = "example.com/ledger"
	subject := Subject{Package: pkg, Symbol: "F"}
	entry := func(ledger TestVariantLedger, name string) (TestVariantDeclaration, bool) {
		for _, declaration := range ledger.Declarations {
			if declaration.Name == name {
				return declaration, true
			}
		}
		return TestVariantDeclaration{}, false
	}
	before := computeAt(t, dir, subject)
	beforeLedger := ledgerAt(t, dir, pkg)

	// Edit the existing test's body.
	if err := os.WriteFile(filepath.Join(dir, "ledger_test.go"), []byte("package ledger\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"edited\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	edited := computeAt(t, dir, subject)
	editedLedger := ledgerAt(t, dir, pkg)
	if before[subject].TestVariants == edited[subject].TestVariants {
		t.Fatal("edited test did not move the compartment")
	}
	was, _ := entry(beforeLedger, "TestF")
	now, ok := entry(editedLedger, "TestF")
	if !ok || was.Hash == now.Hash {
		t.Fatalf("edited test declaration hash unmoved: %+v -> %+v", was, now)
	}
	if beforeLedger.FileHeaders[0].Hash != editedLedger.FileHeaders[0].Hash {
		t.Fatal("body edit moved the file header identity")
	}

	// Append a new test to the same file: added-only.
	if err := os.WriteFile(filepath.Join(dir, "ledger_test.go"), []byte("package ledger\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"edited\")\n\t}\n}\n\nfunc TestAgain(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"again\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	appendedLedger := ledgerAt(t, dir, pkg)
	if len(appendedLedger.Declarations) != len(editedLedger.Declarations)+1 {
		t.Fatalf("appended ledger = %+v, want one added declaration", appendedLedger.Declarations)
	}
	kept, ok := entry(appendedLedger, "TestF")
	if !ok || kept.Hash != now.Hash {
		t.Fatalf("append moved the existing declaration: %+v -> %+v", now, kept)
	}
	if _, ok := entry(appendedLedger, "TestAgain"); !ok {
		t.Fatalf("appended declaration missing from ledger: %+v", appendedLedger.Declarations)
	}
}

// The ledger is deterministic data: recomputation yields byte-identical
// entries, sorted by (File, Kind, Receiver, Name, Hash) with headers sorted by
// file, whatever order declarations appear in source
// (REQ-closure-test-variant-compartment).
func TestTestVariantLedgerIsDeterministicallySorted(t *testing.T) {
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":    "module example.com/sorted\n\ngo 1.26\n",
		"sorted.go": "package sorted\n\nfunc F() int { return 1 }\n",
		"z_test.go": "package sorted\n\nimport \"testing\"\n\ntype harness struct{ n int }\n\nfunc (h harness) run() int { return h.n }\n\nvar fixtures = []int{1}\n\nconst limit = 3\n\nfunc init() { fixtures = append(fixtures, 2) }\n\nfunc TestZ(t *testing.T) { _ = harness{1}.run() }\n\nfunc TestA(t *testing.T) { _ = fixtures[0] }\n",
		"a_test.go": "package sorted\n\nimport \"testing\"\n\nfunc TestMain(m *testing.M) { m.Run() }\n",
	})
	const pkg = "example.com/sorted"
	first := ledgerAt(t, dir, pkg)
	second := ledgerAt(t, dir, pkg)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("ledger not deterministic:\n%+v\n%+v", first, second)
	}
	for i := 1; i < len(first.Declarations); i++ {
		a, b := first.Declarations[i-1], first.Declarations[i]
		if a.File > b.File || (a.File == b.File && a.Kind > b.Kind) ||
			(a.File == b.File && a.Kind == b.Kind && a.Receiver > b.Receiver) ||
			(a.File == b.File && a.Kind == b.Kind && a.Receiver == b.Receiver && a.Name > b.Name) {
			t.Fatalf("ledger unsorted at %d: %+v then %+v", i, a, b)
		}
	}
	want := map[string]string{
		"TestMain": "func", "TestZ": "func", "TestA": "func",
		"harness": "type", "run": "method", "fixtures": "var", "limit": "const", "init": "init",
	}
	got := map[string]string{}
	for _, declaration := range first.Declarations {
		got[declaration.Name] = declaration.Kind
		if declaration.Name == "run" && declaration.Receiver != "harness" {
			t.Fatalf("method receiver = %q, want harness", declaration.Receiver)
		}
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("ledger kinds = %+v, want %+v", got, want)
	}
	if len(first.FileHeaders) != 2 || first.FileHeaders[0].File != "a_test.go" || first.FileHeaders[1].File != "z_test.go" {
		t.Fatalf("headers = %+v, want per-file entries sorted by file", first.FileHeaders)
	}
}

// Batching subjects shares each package's compartment exactly as it shares the
// core: batch results equal independent per-subject computation for both
// hashes (REQ-closure-batch-equivalence).
func TestComputeMaximalBatchMatchesIndependentComputeForBothHashes(t *testing.T) {
	// a and b share the dependency node: the batch derives its
	// contribution once and both packages' closures consume it — the
	// equivalence against independent computation pins that sharing
	// changes cost, never evidence (REQ-closure-batch-equivalence).
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":      "module example.com/batch\n\ngo 1.26\n",
		"shared/s.go": "package shared\n\nfunc S() int { return 3 }\n",
		"a/a.go":      "package a\n\nimport \"example.com/batch/shared\"\n\nfunc A() int { return shared.S() - 2 }\n",
		"a/a_test.go": "package a\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {\n\tif A() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
		"b/b.go":      "package b\n\nimport \"example.com/batch/shared\"\n\nfunc B() int { return shared.S() - 1 }\n",
	})
	subjects := []Subject{
		{Package: "example.com/batch/a", Symbol: "A"},
		{Package: "example.com/batch/a", Symbol: "TestA"},
		{Package: "example.com/batch/b", Symbol: "B"},
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	batched, batchedSources, err := h.ComputeMaximalBatchWithSources(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		independent := computeAt(t, dir, subject)
		if batched[subject] != independent[subject] {
			t.Fatalf("batched %v = %+v, independent = %+v", subject, batched[subject], independent[subject])
		}
		hIndependent, err := NewAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		_, independentSources, err := hIndependent.ComputeMaximalBatchWithSources([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(batchedSources[subject], independentSources[subject]) {
			t.Fatalf("batched sources for %v = %v, independent = %v", subject, batchedSources[subject], independentSources[subject])
		}
	}
	if batched[subjects[2]].TestVariants != EmptyTestVariantClosure {
		t.Fatalf("no-test package in batch = %q, want empty identity", batched[subjects[2]].TestVariants)
	}
	if batched[subjects[0]].TestVariants != batched[subjects[1]].TestVariants {
		t.Fatal("subjects of one package did not share the compartment")
	}
}

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

// A real dependency package whose import path ends in "_test" is not the
// subject's external test package: recompiled against the test binary it
// shares the suffixed import path shape but compiles from its own directory,
// so it keeps its core contribution and never enters the compartment. Go
// refuses to build this layout (the test import is a cycle), but go list
// still describes it, and hashing must stay fail-safe over it
// (REQ-closure-view-maximal).
func TestDependencyPackageNamedLikeExternalTestKeepsItsCoreContribution(t *testing.T) {
	files := map[string]string{
		"go.mod":           "module example.com/m\n\ngo 1.26\n",
		"foo/foo.go":       "package foo\n\nfunc F() int { return 1 }\n",
		"foo/in_test.go":   "package foo\n\nimport \"testing\"\n\nfunc TestInPackage(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
		"foo/ext_test.go":  "package foo_test\n\nimport (\n\t\"testing\"\n\n\ttrap \"example.com/m/foo_test\"\n)\n\nfunc TestTrap(t *testing.T) {\n\tif trap.Two() != 2 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
		"foo_test/trap.go": "package trap\n\nimport \"example.com/m/foo\"\n\nfunc Two() int { return foo.F() + 1 }\n",
	}
	dir := writeTestVariantModule(t, files)
	subject := Subject{Package: "example.com/m/foo", Symbol: "F"}
	before := computeAt(t, dir, subject)
	ledger := ledgerAt(t, dir, "example.com/m/foo")
	for _, declaration := range ledger.Declarations {
		if declaration.File == "trap.go" {
			t.Fatalf("dependency package file entered the compartment ledger: %+v", ledger.Declarations)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "foo_test/trap.go"), []byte("package trap\n\nimport \"example.com/m/foo\"\n\nfunc Two() int { return foo.F() * 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := computeAt(t, dir, subject)
	if before[subject].Hash == after[subject].Hash {
		t.Fatal("dependency edit did not move the core maximal closure")
	}
	if before[subject].TestVariants != after[subject].TestVariants {
		t.Fatal("dependency edit moved the test-variant compartment")
	}
}

// A package whose core contribution widens to its whole directory (opaque
// assembly) keeps test files in the core as well — sound, merely
// undiscriminated — while the same files also sit in the compartment
// (REQ-closure-test-variant-compartment whole-dir-widening exception).
func TestWidenedCoreKeepsTestFilesUndiscriminated(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("opaque-asm fixture is amd64-only")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/opq\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"asm_amd64.s", "defs.inc", "opaqueasm.go", "opaqueasm_test.go"} {
		content, err := os.ReadFile(filepath.Join("fixtures", "opaqueasm", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	subject := Subject{Package: "example.com/opq", Symbol: "BenchmarkOpaqueASM"}
	before := computeAt(t, dir, subject)
	testPath := filepath.Join(dir, "opaqueasm_test.go")
	source, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(testPath, append(source, []byte("\nfunc sibling() {}\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	after := computeAt(t, dir, subject)
	if before[subject].Hash == after[subject].Hash {
		t.Fatal("widened core did not keep the test file: sibling test edit left the core unmoved")
	}
	if before[subject].TestVariants == after[subject].TestVariants {
		t.Fatal("test file left the compartment under a widened core")
	}
}

// A test-only embedded fixture whose name ends in .go is data, not source:
// it is never parsed (even unparseable bytes analyze fine), contributes no
// declarations, carries an Embedded whole-content header, and its movement
// defeats inertness like any embedded member's
// (REQ-closure-test-variant-compartment compiled-vs-embedded split).
func TestEmbeddedGoFixtureIsDataNotSource(t *testing.T) {
	files := map[string]string{
		"go.mod":              "module example.com/embedded\n\ngo 1.26\n",
		"embedded.go":         "package embedded\n\nfunc F() int { return 1 }\n",
		"embedded_test.go":    "package embedded\n\nimport (\n\t_ \"embed\"\n\t\"testing\"\n)\n\n//go:embed testdata/fixture.go\nvar fixture string\n\n//go:embed testdata/broken.go\nvar broken string\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 || fixture == \"\" || broken == \"\" {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
		"testdata/fixture.go": "package fixture\n\nfunc Fixture() int { return 1 }\n",
		"testdata/broken.go":  "this is not go source at all {{{\n",
	}
	dir := writeTestVariantModule(t, files)
	const pkg = "example.com/embedded"
	before := ledgerAt(t, dir, pkg)
	for _, declaration := range before.Declarations {
		if declaration.File != "embedded_test.go" {
			t.Fatalf("embedded fixture contributed declarations: %+v", before.Declarations)
		}
	}
	embedded := 0
	for _, header := range before.FileHeaders {
		switch header.File {
		case "testdata/fixture.go", "testdata/broken.go":
			if !header.Embedded {
				t.Fatalf("embedded member not marked: %+v", header)
			}
			embedded++
		case "embedded_test.go":
			if header.Embedded {
				t.Fatalf("compiled test file marked embedded: %+v", header)
			}
		}
	}
	if embedded != 2 {
		t.Fatalf("embedded members missing from ledger headers: %+v", before.FileHeaders)
	}
	if err := os.WriteFile(filepath.Join(dir, "testdata/fixture.go"), []byte(files["testdata/fixture.go"]+"\nfunc Extra() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	delta := DiffTestVariantLedgers(before, ledgerAt(t, dir, pkg))
	if delta.Inert() || len(delta.Added) != 0 {
		t.Fatalf("embedded .go fixture edit = %+v (inert=%v), want a non-inert header-only movement", delta, delta.Inert())
	}
}

// A member both compiled and embedded — a sibling test file that an embed
// directive names — keeps its parsed declarations but carries the
// embedded whole-content header: appending an otherwise-inert declaration
// moves bytes an unchanged test reads as data, so the delta is never inert
// (REQ-closure-test-variant-compartment dual membership).
func TestCompiledAndEmbeddedTestFileFailsClosed(t *testing.T) {
	files := map[string]string{
		"go.mod":         "module example.com/dual\n\ngo 1.26\n",
		"dual.go":        "package dual\n\nfunc F() int { return 1 }\n",
		"helper_test.go": "package dual\n\nfunc helperValue() int { return 1 }\n",
		"embed_test.go":  "package dual\n\nimport (\n\t_ \"embed\"\n\t\"testing\"\n)\n\n//go:embed helper_test.go\nvar helperSource string\n\nfunc TestF(t *testing.T) {\n\tif F() != helperValue() || helperSource == \"\" {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	}
	dir := writeTestVariantModule(t, files)
	const pkg = "example.com/dual"
	before := ledgerAt(t, dir, pkg)
	declared := false
	for _, declaration := range before.Declarations {
		declared = declared || (declaration.File == "helper_test.go" && declaration.Name == "helperValue")
	}
	if !declared {
		t.Fatalf("dual member lost its declarations: %+v", before.Declarations)
	}
	for _, header := range before.FileHeaders {
		if header.File == "helper_test.go" && !header.Embedded {
			t.Fatalf("dual member header not marked embedded: %+v", header)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "helper_test.go"), []byte(files["helper_test.go"]+"\nfunc extraHelper() int { return 3 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	delta := DiffTestVariantLedgers(before, ledgerAt(t, dir, pkg))
	if delta.Inert() {
		t.Fatalf("dual-member edit classified inert: %+v", delta)
	}
}

// End to end over real ledgers: a sibling test appended to an existing file
// diffs to an inert added-only delta, and editing that test's body flips the
// judgment (REQ-closure-test-variant-compartment).
func TestLedgerDeltaOverRealLedgers(t *testing.T) {
	const original = "package delta\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":        "module example.com/delta\n\ngo 1.26\n",
		"delta.go":      "package delta\n\nfunc F() int { return 1 }\n",
		"delta_test.go": original,
	})
	const pkg = "example.com/delta"
	recorded := ledgerAt(t, dir, pkg)
	if err := os.WriteFile(filepath.Join(dir, "delta_test.go"), []byte(original+"\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	appended := DiffTestVariantLedgers(recorded, ledgerAt(t, dir, pkg))
	if !appended.Inert() || len(appended.Added) != 1 || appended.Added[0].Name != "TestSibling" {
		t.Fatalf("appended sibling delta = %+v (inert=%v), want inert added-only TestSibling", appended, appended.Inert())
	}
	if err := os.WriteFile(filepath.Join(dir, "delta_test.go"), []byte("package delta\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"edited\")\n\t}\n}\n\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	edited := DiffTestVariantLedgers(recorded, ledgerAt(t, dir, pkg))
	if edited.Inert() || len(edited.Changed) != 1 || edited.Changed[0].After.Name != "TestF" {
		t.Fatalf("edited body delta = %+v (inert=%v), want non-inert with TestF changed", edited, edited.Inert())
	}
}
