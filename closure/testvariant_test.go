package closure

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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
