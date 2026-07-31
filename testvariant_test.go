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
	current, err := engine.Check(context.Background(), fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != Valid {
		t.Fatalf("post-partition recording = %+v, want valid", current)
	}
}

// Refined evidence never rescues compartment drift: with the core equal, a
// drifted compartment is stale "test variants" and no precise analysis runs;
// with both equal, the recorded refined disposition still grafts without
// analysis exactly as before — the graft stays keyed to core equality because
// declaration-RTA roots neither sibling tests nor the compartment
// (REQ-closure-test-variant-compartment, REQ-fresh-refinement-disposition).
func TestRefinedEvidenceDoesNotRescueCompartmentDrift(t *testing.T) {
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
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir, WithUnboundedRefinement())
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if recorded.Refinement == (Refinement{}) {
		t.Fatalf("refined capture carries no refinement: %+v", recorded)
	}

	// Both equal: the graft path serves the verdict with no precise analysis.
	unchanged, err := engine.NewView(context.Background(), []Subject{subject}, dir, WithUnboundedRefinement())
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
		t.Fatalf("no-drift refined check = %+v with %d analyses, want valid without analysis", verdict, analyses)
	}

	// Compartment drift: stale "test variants", refinement not consulted.
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte(partitionTest+"\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drifted, err := engine.NewView(context.Background(), []Subject{subject}, dir, WithUnboundedRefinement())
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
		t.Fatalf("compartment-drift refined check = %+v with %d analyses, want {stale \"test variants\"} without analysis", verdict, analyses)
	}
	observed, err := drifted.CheckObserved(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Stale || observed.Reason != "test variants" {
		t.Fatalf("compartment-drift observed check = %+v, want {stale \"test variants\"}", observed)
	}
}

// A refined recording that predates the partition is never rescued: with the
// core drifted, refined evidence would otherwise graft a Valid verdict while
// the record carries no compartment to compare, leaving sibling-test edits
// permanently invisible — so it fails closed to {stale "test variants"} on
// both check surfaces, while the same drift under a recorded compartment
// still rescues (REQ-closure-test-variant-compartment,
// REQ-fresh-hierarchical-check).
func TestRefinedPrePartitionRecordingFailsClosedInsteadOfRescuing(t *testing.T) {
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
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir, WithUnboundedRefinement())
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if recorded.Refinement == (Refinement{}) {
		t.Fatalf("refined capture carries no refinement: %+v", recorded)
	}

	// Core drift F's refined closure does not cover: a production sibling.
	if err := os.WriteFile(filepath.Join(dir, "sibling.go"), []byte("package partition\n\nfunc Sibling() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drifted, err := engine.NewView(context.Background(), []Subject{subject}, dir, WithUnboundedRefinement())
	if err != nil {
		t.Fatal(err)
	}
	rescued, err := drifted.Check(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if rescued.Status != Valid {
		t.Fatalf("post-partition refined recording = %+v, want the rescue this test guards", rescued)
	}

	prePartition := recorded
	prePartition.TestVariantClosure = ""
	verdict, err := drifted.Check(context.Background(), prePartition, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "test variants" {
		t.Fatalf("pre-partition refined recording = %+v, want fail-closed {stale \"test variants\"}", verdict)
	}
	observed, err := drifted.CheckObserved(context.Background(), prePartition, subject)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Stale || observed.Reason != "test variants" {
		t.Fatalf("pre-partition observed-policy check = %+v, want fail-closed {stale \"test variants\"}", observed)
	}
}

// Compartment drift blocks refined rescue even when the core also drifted:
// strictly more drift never flips a stale verdict to valid, so a sibling-test
// edit reads {stale "test variants"} whether or not production drift rides
// along (REQ-closure-test-variant-compartment, REQ-fresh-hierarchical-check).
func TestCompartmentDriftBlocksRefinedRescueAcrossCoreDrift(t *testing.T) {
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
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir, WithUnboundedRefinement())
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}

	// Production drift outside F's refined slice AND a sibling-test edit:
	// without the compartment tier the refined hashes agree and rescue would
	// return valid across the sibling-test movement.
	if err := os.WriteFile(filepath.Join(dir, "sibling.go"), []byte("package partition\n\nfunc Sibling() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte(partitionTest+"\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drifted, err := engine.NewView(context.Background(), []Subject{subject}, dir, WithUnboundedRefinement())
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := drifted.Check(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "test variants" {
		t.Fatalf("mixed-drift refined check = %+v, want {stale \"test variants\"}", verdict)
	}
	observed, err := drifted.CheckObserved(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Stale || observed.Reason != "test variants" {
		t.Fatalf("mixed-drift observed check = %+v, want {stale \"test variants\"}", observed)
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
