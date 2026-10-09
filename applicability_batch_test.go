package gofresh

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestObservedApplicabilityBatchSharesCurrentProofAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("analyzes a multi-subject observed applicability batch")
	}
	ctx := context.Background()
	dir := writeSupportedViewModule(t)
	source := `package observed
import ("os"; "testing")
func TestRead(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }
func TestOther(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }
func TestReadsFile(t *testing.T) { _, _ = os.ReadFile("fixture") }
`
	write := func(text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "observed_test.go"), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(source)
	subjects := []Subject{{"example.com/observed", "TestRead"}, {"example.com/observed", "TestOther"}}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	newView := func() *View {
		t.Helper()
		v, err := engine.NewView(ctx, subjects, dir)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	producer := newView()
	proofs, err := producer.CaptureObservedBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := producer.TestVariantLedger(subjects[0])
	if err != nil {
		t.Fatal(err)
	}
	observation := supportedObservation(t, producer, dir, dir, "both tests", "getenv OUTCOME_VALUE\n")
	for _, subject := range subjects {
		proofs[subject], err = producer.AttachObservation(subject, proofs[subject], observation)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := producer.Validate(ctx); err != nil {
		t.Fatal(err)
	}
	write(source + "\nfunc TestArithmetic(t *testing.T) { if 2+2 != 4 { t.Fatal(\"arithmetic\") } }\n")
	extending := newView()
	for _, subject := range subjects {
		updated, _, verdict, err := extending.CheckObservedInertTestVariantExtension(ctx, proofs[subject], ledger, subject)
		if err != nil || verdict.Status != Valid {
			t.Fatalf("extension: %+v %v", verdict, err)
		}
		proofs[subject] = updated
	}
	checking := newView()
	analyses := 0
	checking.beforePreciseAnalysis = func() { analyses++ }
	verdicts, err := checking.CheckObservedBatch(ctx, proofs)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		if verdicts[subject].Status != Valid {
			t.Fatalf("batch subject %v: %+v", subject, verdicts[subject])
		}
	}
	if analyses != 1 {
		t.Fatalf("batch paid %d precise analyses, want one", analyses)
	}
}
