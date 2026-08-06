package gofresh

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/greatliontech/gofresh/closure"
)

func writePartitionModule(t *testing.T, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const partitionProduction = "package partition\n\nfunc F() int { return 1 }\n"
const partitionTest = "package partition\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"

// A sibling test added to the subject's package stales the recording with the
// stable discriminating reason "test variants" on both check surfaces: the
// core is unmoved, only the compartment drifted, and the consumer — not
// gofresh — decides what that means (REQ-closure-test-variant-compartment).
func TestSiblingTestAdditionStalesAsTestVariants(t *testing.T) {
	dir := writePartitionModule(t, map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      partitionProduction,
		"partition_test.go": partitionTest,
	})
	subject := Subject{Package: "example.com/partition", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := engine.Capture(context.Background(), subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.TestVariantClosure == "" || fingerprint.TestVariantClosure == closure.EmptyTestVariantClosure {
		t.Fatalf("captured compartment = %q, want a non-empty test-file identity", fingerprint.TestVariantClosure)
	}
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte(partitionTest+"\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdict, err := engine.Check(context.Background(), fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "test variants" {
		t.Fatalf("sibling test addition = %+v, want {stale \"test variants\"}", verdict)
	}
	observed, err := engine.CheckObserved(context.Background(), fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Stale || observed.Reason != "test variants" {
		t.Fatalf("observed-policy check = %+v, want {stale \"test variants\"}", observed)
	}
}

// A subject declared in a test file has its own body in the compartment:
// editing the recorded test itself moves the compartment, not the core, and
// the verdict says so (REQ-closure-test-variant-compartment).
func TestTestFileSubjectBodyLivesInCompartment(t *testing.T) {
	dir := writePartitionModule(t, map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      partitionProduction,
		"partition_test.go": partitionTest,
	})
	subject := Subject{Package: "example.com/partition", Symbol: "TestF"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := engine.Capture(context.Background(), subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte("package partition\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"edited body\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdict, err := engine.Check(context.Background(), fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "test variants" {
		t.Fatalf("edited recorded test = %+v, want {stale \"test variants\"}", verdict)
	}
}

// A recording that predates the partition carries no compartment: it fails
// closed to stale even when the core still matches — the one shape where a
// pre-partition core CAN match is a package with no test files
// (REQ-closure-test-variant-compartment).
func TestPrePartitionRecordingFailsClosedAsTestVariants(t *testing.T) {
	dir := writePartitionModule(t, map[string]string{
		"go.mod":  "module example.com/notest\n\ngo 1.26\n",
		"main.go": "package notest\n\nfunc F() int { return 1 }\n",
	})
	subject := Subject{Package: "example.com/notest", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := engine.Capture(context.Background(), subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.TestVariantClosure != closure.EmptyTestVariantClosure {
		t.Fatalf("no-test capture compartment = %q, want the defined empty identity", fingerprint.TestVariantClosure)
	}
	prePartition := fingerprint
	prePartition.TestVariantClosure = ""
	verdict, err := engine.Check(context.Background(), prePartition, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "test variants" {
		t.Fatalf("pre-partition recording = %+v, want fail-closed {stale \"test variants\"}", verdict)
	}
	// Both check surfaces share one evidence ladder: the observed surface
	// fails a pre-partition recording closed identically.
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := view.CheckObserved(context.Background(), prePartition, subject)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Stale || observed.Reason != "test variants" {
		t.Fatalf("observed pre-partition recording = %+v, want fail-closed {stale \"test variants\"}", observed)
	}
	current, err := engine.Check(context.Background(), fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != Valid {
		t.Fatalf("post-partition recording = %+v, want valid", current)
	}
}

// Compartment drift is decided from recorded evidence alone: with the core
// equal, a drifted compartment is stale "test variants" on both check
// surfaces and no precise analysis runs; with both equal, the verdict is
// valid, equally without analysis (REQ-closure-test-variant-compartment,
// REQ-fresh-hierarchical-check).
func TestCompartmentDriftStalesWithoutPreciseAnalysis(t *testing.T) {
	dir := writePartitionModule(t, map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      partitionProduction,
		"partition_test.go": partitionTest,
	})
	subject := Subject{Package: "example.com/partition", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}

	// Both equal: the verdict is served with no precise analysis.
	unchanged, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	analyses := 0
	unchanged.beforePreciseAnalysis = func() { analyses++ }
	verdict, err := unchanged.Check(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid || analyses != 0 {
		t.Fatalf("no-drift check = %+v with %d analyses, want valid without analysis", verdict, analyses)
	}

	// Compartment drift: stale "test variants", no analysis consulted.
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte(partitionTest+"\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drifted, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	analyses = 0
	drifted.beforePreciseAnalysis = func() { analyses++ }
	verdict, err = drifted.Check(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "test variants" || analyses != 0 {
		t.Fatalf("compartment-drift check = %+v with %d analyses, want {stale \"test variants\"} without analysis", verdict, analyses)
	}
	observed, err := drifted.CheckObserved(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Stale || observed.Reason != "test variants" || analyses != 0 {
		t.Fatalf("compartment-drift observed check = %+v with %d analyses, want {stale \"test variants\"} without analysis", observed, analyses)
	}
}

// Core drift takes the ladder's first tier even when the compartment also
// drifted: strictly more drift never improves a verdict, and the reason names
// the core ("closure"), the compartment being compared only under an equal
// core (REQ-closure-test-variant-compartment, REQ-fresh-hierarchical-check).
func TestMixedCoreAndCompartmentDriftStalesOnClosure(t *testing.T) {
	dir := writePartitionModule(t, map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      partitionProduction,
		"sibling.go":        "package partition\n\nfunc Sibling() int { return 1 }\n",
		"partition_test.go": partitionTest,
	})
	subject := Subject{Package: "example.com/partition", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}

	// A production sibling edit AND a sibling-test edit drift both tiers.
	if err := os.WriteFile(filepath.Join(dir, "sibling.go"), []byte("package partition\n\nfunc Sibling() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte(partitionTest+"\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drifted, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := drifted.Check(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" {
		t.Fatalf("mixed-drift check = %+v, want {stale \"closure\"}", verdict)
	}
	observed, err := drifted.CheckObserved(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Stale || observed.Reason != "closure" {
		t.Fatalf("mixed-drift observed check = %+v, want {stale \"closure\"}", observed)
	}
}

// The view serves the compartment ledger from its construction-time snapshot:
// the same bytes the recorded compartment hash folded, unchanged by later
// on-disk edits, so capture-time persistence and check-time diffing read
// coherent data (REQ-closure-test-variant-compartment,
// REQ-fresh-coherent-view).
func TestViewServesTestVariantLedgerFromItsSnapshot(t *testing.T) {
	dir := writePartitionModule(t, map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      partitionProduction,
		"partition_test.go": partitionTest,
	})
	subject := Subject{Package: "example.com/partition", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := view.TestVariantLedger(subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(captured.Declarations) != 1 || captured.Declarations[0].Name != "TestF" || captured.Declarations[0].Kind != "func" {
		t.Fatalf("captured ledger = %+v, want the one recorded test", captured.Declarations)
	}
	// Caller-owned all the way down: mutating a served reference list never
	// surfaces through the view's internal ledger or later callers.
	if len(captured.Declarations[0].References) == 0 {
		t.Fatalf("captured declaration carries no references: %+v", captured.Declarations[0])
	}
	original := captured.Declarations[0].References[0]
	captured.Declarations[0].References[0] = "mutated"
	refetched, err := view.TestVariantLedger(subject)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(refetched.Declarations[0].References, "mutated") {
		t.Fatalf("view ledger shares reference backing arrays with callers: %v", refetched.Declarations[0].References)
	}
	captured.Declarations[0].References[0] = original
	// The compartment's bytes are among the view's exposed source identities,
	// so a producer's provenance covers them like any core member
	// (REQ-fresh-view-source-identities).
	sources, err := view.SourceFilesFor(subject)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(sources, filepath.Join(dir, "partition_test.go")) {
		t.Fatalf("view source identities omit the compartment file: %v", sources)
	}
	if _, err := view.TestVariantLedger(Subject{Package: "example.com/partition", Symbol: "Missing"}); err == nil {
		t.Fatal("ledger served for a subject outside the view")
	}
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte(partitionTest+"\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := view.TestVariantLedger(subject)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(captured, snapshot) {
		t.Fatalf("view ledger moved with a post-construction edit:\n%+v\n%+v", captured, snapshot)
	}
	fresh, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	current, err := fresh.TestVariantLedger(subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Declarations) != 2 {
		t.Fatalf("current ledger = %+v, want the added sibling visible to a fresh view", current.Declarations)
	}
}
