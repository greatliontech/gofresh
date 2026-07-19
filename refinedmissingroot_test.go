package gofresh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A production symbol whose package has only an external test variant cannot be
// rooted for refined analysis. Capturing it must succeed with unavailable
// refined evidence, and a batched check containing it must decide every other
// drifted subject by its own analysis instead of marking the whole batch
// "refinement unavailable".
func TestRefinedBatchDegradesUnrootableSubjectLocally(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":      "module example.com/external\n\ngo 1.26\n",
		"external.go": "package external\n\nfunc Ok() bool { return true }\n",
		"external_test.go": `package external_test

import (
	"testing"

	"example.com/external"
)

func TestExternal(t *testing.T) {
	if !external.Ok() {
		t.Fatal("not ok")
	}
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	unrootable := Subject{Package: "example.com/external", Symbol: "Ok"}
	sibling := Subject{Package: "example.com/external", Symbol: "TestExternal"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(context.Background(), []Subject{unrootable, sibling}, dir)
	if err != nil {
		t.Fatal(err)
	}
	unrootableFingerprint, err := producer.CaptureRefined(context.Background(), unrootable)
	if err != nil {
		t.Fatalf("CaptureRefined(unrootable): %v", err)
	}
	if !unrootableFingerprint.Refinement.Unverifiable || !strings.Contains(unrootableFingerprint.Refinement.Reason, "refined analysis unavailable") {
		t.Fatalf("unrootable refinement = %+v, want unavailable-evidence disposition", unrootableFingerprint.Refinement)
	}
	siblingFingerprint, err := producer.CaptureRefined(context.Background(), sibling)
	if err != nil {
		t.Fatalf("CaptureRefined(sibling): %v", err)
	}
	if strings.Contains(siblingFingerprint.Refinement.Reason, "refined analysis unavailable") {
		t.Fatalf("sibling refinement = %+v, want normal analysis undisturbed by the unrootable subject", siblingFingerprint.Refinement)
	}
	// With source unchanged, the degraded recording keeps its recorded
	// fail-closed disposition: unverifiable with the unavailability reason,
	// never valid.
	unchanged, err := producer.CheckRefined(context.Background(), unrootableFingerprint, unrootable)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Status != Unverifiable || !strings.Contains(unchanged.Reason, "refined analysis unavailable") {
		t.Fatalf("no-drift verdict = %+v, want unverifiable via the recorded unavailability", unchanged)
	}
	if err := os.WriteFile(filepath.Join(dir, "external.go"), []byte("package external\n\nfunc Ok() bool { return 1 == 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView(context.Background(), []Subject{unrootable, sibling}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdicts, err := current.CheckRefinedBatch(context.Background(), map[Subject]Fingerprint{
		unrootable: unrootableFingerprint,
		sibling:    siblingFingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	for subject, verdict := range verdicts {
		if strings.Contains(verdict.Reason, "refinement unavailable") {
			t.Fatalf("verdict[%s] = %+v, want subject-local decision, not batch-coupled unavailability", subject.Symbol, verdict)
		}
		if verdict.Status == Valid {
			t.Fatalf("verdict[%s] = %+v, want a safe non-valid verdict after source drift", subject.Symbol, verdict)
		}
	}
	if verdicts[sibling] != (Verdict{Stale, "refinement"}) {
		t.Fatalf("sibling verdict = %+v, want its own refined staleness decision", verdicts[sibling])
	}
}
