package gofresh

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/runtimeinput"
)

func TestApplicabilityBatchesPreserveRecordsAndPolicies(t *testing.T) {
	r := rand.New(rand.NewSource(18341))
	for draw := 0; draw < 300; draw++ {
		var checks []applicabilityCheck
		want := map[applicabilityCheck]int{}
		counts := map[bool]map[Subject]int{false: {}, true: {}}
		for n := r.Intn(30); n > 0; n-- {
			check := applicabilityCheck{Fingerprint{RuntimeInputs: fmt.Sprint(r.Intn(5)), RuntimeDigest: fmt.Sprint(r.Intn(5))}, Subject{"p", fmt.Sprint(r.Intn(5))}, r.Intn(2) == 0}
			checks = append(checks, check)
			want[check]++
			counts[check.observed][check.subject]++
		}
		got := map[applicabilityCheck]int{}
		batchCounts := map[bool]int{}
		for _, batch := range batchApplicabilityChecks(checks) {
			batchCounts[batch.observed]++
			for subject, recorded := range batch.recorded {
				got[applicabilityCheck{recorded, subject, batch.observed}]++
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("draw %d lost or changed historical evidence/policy: got %v want %v", draw, got, want)
		}
		for policy, subjects := range counts {
			minimum := 0
			for _, count := range subjects {
				minimum = max(minimum, count)
			}
			if batchCounts[policy] != minimum {
				t.Fatalf("draw %d policy %v used %d batches, need %d", draw, policy, batchCounts[policy], minimum)
			}
		}
	}
}

type applicabilityValidationFixture struct {
	engine     *Engine
	dir, input string
	subjects   []Subject
	recorded   map[Subject]Fingerprint
	fileRecord Fingerprint
	ledger     TestVariantLedger
}

func newApplicabilityValidationFixture(t *testing.T) applicabilityValidationFixture {
	t.Helper()
	ctx := context.Background()
	dir := writeSupportedViewModule(t)
	source := `package observed
import ("os"; "testing")
func TestRead(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }
func TestOther(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }
func PureA() {}
func PureB() {}
func TestReadsFile(t *testing.T) { _, _ = os.ReadFile("fixture") }
`
	path := filepath.Join(dir, "observed_test.go")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{{"example.com/observed", "TestRead"}, {"example.com/observed", "TestOther"}, {"example.com/observed", "PureA"}, {"example.com/observed", "PureB"}}
	engine, err := New(WithDir(dir), WithAssumePure(func(s Subject) bool { return strings.HasPrefix(s.Symbol, "Pure") }))
	if err != nil {
		t.Fatal(err)
	}
	f := applicabilityValidationFixture{engine: engine, dir: dir, subjects: subjects}
	producer := f.view(t)
	observation := supportedObservation(t, producer, dir, dir, "environment subjects", "getenv OUTCOME_VALUE\n")
	recorded, err := producer.CaptureObservedBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		recorded[subject], err = producer.AttachObservation(subject, recorded[subject], observation)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := producer.Validate(ctx); err != nil {
		t.Fatal(err)
	}
	f.recorded = recorded
	f.ledger, err = producer.TestVariantLedger(subjects[0])
	if err != nil {
		t.Fatal(err)
	}
	// Another historical result for PureA guards a different manifest. It was
	// independently valid by explicit purity, without operation-outcome support.
	f.input = filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(f.input, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	bracket, err := runtimeinput.CaptureBracket(ctx, dir, []string{f.input})
	if err != nil {
		t.Fatal(err)
	}
	fileObservation, err := runtimeinput.FromTestLog([]byte("open "+f.input+"\n"), dir, dir, engine.evidenceEnv(), runtimeinput.WithCompletedProcess("pure file guard"), runtimeinput.WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	fileProducer := f.view(t)
	fileRecord, err := fileProducer.CaptureObserved(ctx, subjects[2])
	if err != nil {
		t.Fatal(err)
	}
	f.fileRecord, err = fileProducer.AttachObservation(subjects[2], fileRecord, fileObservation)
	if err != nil {
		t.Fatal(err)
	}
	if err := fileProducer.Validate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(source+"\nfunc TestArithmetic(t *testing.T) {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f applicabilityValidationFixture) view(t *testing.T) *View {
	t.Helper()
	v, err := f.engine.NewView(context.Background(), f.subjects, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f applicabilityValidationFixture) extend(t *testing.T, v *View, subject Subject, record Fingerprint, observed bool) {
	t.Helper()
	_, _, verdict, err := v.checkInertTestVariantExtension(context.Background(), record, f.ledger, subject, observed)
	if err != nil || verdict.Status != Valid {
		t.Fatalf("retain %s: %+v %v", subject.Symbol, verdict, err)
	}
}

func TestApplicabilityValidationDefersUnavailableUntilAllObligationsClose(t *testing.T) {
	if testing.Short() {
		t.Skip("validates retained historical records across a proof cut and runtime drift")
	}
	f := newApplicabilityValidationFixture(t)
	ctx := context.Background()
	for _, observedFile := range []bool{false, true} {
		t.Run(map[bool]string{false: "separate policies", true: "same observed batch"}[observedFile], func(t *testing.T) {
			f.engine.analysisBudget = 0
			if err := os.WriteFile(f.input, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			v := f.view(t)
			f.extend(t, v, f.subjects[0], f.recorded[f.subjects[0]], true)
			f.extend(t, v, f.subjects[2], f.fileRecord, observedFile)
			f.engine.analysisBudget = time.Nanosecond
			if err := v.Validate(ctx); !errors.Is(err, ErrAnalysisUnavailable) {
				t.Fatalf("unchanged cut: %v", err)
			}
			analyses := 0
			viewTestHooks.beforeAnalysis = func() {
				analyses++
				if err := os.WriteFile(f.input, []byte("moved"), 0600); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(func() { viewTestHooks.beforeAnalysis = nil })
			err := v.Validate(ctx)
			if analyses != 1 || !errors.Is(err, ErrViewChanged) || errors.Is(err, ErrAnalysisUnavailable) || !strings.Contains(err.Error(), "PureA") {
				t.Fatalf("later runtime drift masked by A's cut (%d analyses): %v", analyses, err)
			}
		})
	}
}

func TestProducerUnavailabilityDoesNotSkipRetainedApplicability(t *testing.T) {
	if testing.Short() {
		t.Skip("validates mixed producer and historical applicability evidence")
	}
	f := newApplicabilityValidationFixture(t)
	ctx := context.Background()
	v := f.view(t)
	f.extend(t, v, f.subjects[2], f.fileRecord, false)
	observation := supportedObservation(t, v, f.dir, f.dir, "current producer", "getenv OUTCOME_VALUE\n")
	current, err := v.CaptureObservedBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range f.subjects {
		if _, err := v.AttachObservation(subject, current[subject], observation); err != nil {
			t.Fatal(err)
		}
	}
	f.engine.analysisBudget = time.Nanosecond
	if err := v.Validate(ctx); !errors.Is(err, ErrAnalysisUnavailable) {
		t.Fatalf("unchanged mixed cut: %v", err)
	}
	viewTestHooks.beforeAnalysis = func() {
		if err := os.WriteFile(f.input, []byte("moved"), 0600); err != nil {
			t.Error(err)
		}
	}
	defer func() { viewTestHooks.beforeAnalysis = nil }()
	err = v.Validate(ctx)
	if !errors.Is(err, ErrViewChanged) || errors.Is(err, ErrAnalysisUnavailable) || !strings.Contains(err.Error(), "PureA") {
		t.Fatalf("producer cut hid historical runtime drift: %v", err)
	}
}

func TestApplicabilityValidationClosesSourceAfterUnavailableProof(t *testing.T) {
	if testing.Short() {
		t.Skip("moves source at the last runtime comparison after a proof cut")
	}
	f := newApplicabilityValidationFixture(t)
	v := f.view(t)
	f.extend(t, v, f.subjects[0], f.recorded[f.subjects[0]], true)
	f.extend(t, v, f.subjects[2], f.recorded[f.subjects[2]], false)
	f.engine.analysisBudget = time.Nanosecond
	phases := 0
	f.engine.progress = func(p Progress) {
		if p.Phase != "runtime" {
			return
		}
		phases++
		if phases != 4 {
			return
		}
		path := filepath.Join(f.dir, "observed_test.go")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
			return
		}
		if err := os.WriteFile(path, append(data, []byte("\nfunc TestLateAddition(t *testing.T) {}\n")...), 0600); err != nil {
			t.Error(err)
		}
	}
	err := v.Validate(context.Background())
	if phases != 4 || !errors.Is(err, ErrViewChanged) || errors.Is(err, ErrAnalysisUnavailable) {
		t.Fatalf("final source close lost to proof cut (%d runtime phases): %v", phases, err)
	}
}

func TestApplicabilityValidationSharesCompatibleBatches(t *testing.T) {
	if testing.Short() {
		t.Skip("counts validation analysis and runtime windows over retained batches")
	}
	f := newApplicabilityValidationFixture(t)
	v := f.view(t)
	for i, subject := range f.subjects {
		f.extend(t, v, subject, f.recorded[subject], i < 2)
	}
	analyses, windows, runtimePhases := 0, 0, 0
	viewTestHooks.beforeAnalysis = func() { analyses++ }
	viewTestHooks.runtimeWindow = func() { windows++ }
	f.engine.progress = func(p Progress) {
		if p.Phase == "runtime" {
			runtimePhases++
		}
	}
	defer func() { viewTestHooks.beforeAnalysis = nil; viewTestHooks.runtimeWindow = nil }()
	if err := v.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if analyses != 1 || windows != 2 || runtimePhases != 4 {
		t.Fatalf("validation sharing: analyses=%d windows=%d runtime phases=%d; want 1,2,4", analyses, windows, runtimePhases)
	}
	// Count evaluations themselves, not just phase announcements. Each pair
	// carries the identical manifest, which is read once per batch endpoint.
	current := f.view(t)
	read := current.runtimeCheck()
	reads := 0
	current.runtimeCurrent = func(ctx context.Context, manifest, root string) (runtimeinput.State, error) {
		reads++
		return read(ctx, manifest, root)
	}
	if err := v.validateApplicabilityBatches(context.Background(), current, v.applicabilityChecks); err != nil {
		t.Fatal(err)
	}
	if reads != 4 {
		t.Fatalf("four historical records caused %d runtime reads; want one per policy-batch endpoint (4)", reads)
	}
}

func TestApplicabilityValidationPreservesDistinctRecordsOfOneSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("validates distinct historical manifests of the same subject")
	}
	f := newApplicabilityValidationFixture(t)
	for _, fileFirst := range []bool{false, true} {
		if err := os.WriteFile(f.input, []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
		v := f.view(t)
		subject := f.subjects[2]
		records := []Fingerprint{f.recorded[subject], f.fileRecord}
		if fileFirst {
			records[0], records[1] = records[1], records[0]
		}
		for _, record := range records {
			f.extend(t, v, subject, record, false)
		}
		if len(v.applicabilityChecks) != 2 {
			t.Fatalf("lost historical record: %d", len(v.applicabilityChecks))
		}
		if err := v.Validate(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.input, []byte("moved"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := v.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
			t.Fatalf("fileFirst=%v lost distinct manifest: %v", fileFirst, err)
		}
	}
}
