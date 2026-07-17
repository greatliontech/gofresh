package gofresh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/runtimeinput"
)

type cancelAfterChecks struct {
	context.Context
	after, checks int
}

func (c *cancelAfterChecks) Err() error {
	c.checks++
	if c.checks > c.after {
		return context.Canceled
	}
	return nil
}

func writeViewModule(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/view\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeObservedViewModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":           "module example.com/observed\n\ngo 1.26\n",
		"observed_test.go": "package observed\n\nimport (\"os\"; \"testing\")\n\nfunc TestRead(*testing.T) { _, _ = os.ReadFile(\"fixture\") }\nfunc Sibling() int { return 1 }\n",
		"fixture":          "one",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestUnavailableObservationAnalysisIsUnverifiable(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":      "module example.com/external\n\ngo 1.26\n",
		"external.go": "package external\n\nimport \"os\"\n\nfunc Ok() bool { return os.Getenv(\"OK\") == \"\" }\n",
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
	subject := Subject{Package: "example.com/external", Symbol: "Ok"}
	oracle := Subject{Package: "example.com/external", Symbol: "TestExternal"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView([]Subject{subject, oracle}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("observation proof = %+v, want unavailable disposition", fingerprint.ObservationProof)
	}
	oracleFingerprint, err := producer.CaptureObserved(context.Background(), oracle)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(oracleFingerprint.ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("oracle observation proof = %+v, want isolated analyzed disposition", oracleFingerprint.ObservationProof)
	}
	observation, err := runtimeinput.FromTestLog(nil, dir, dir, runtimeinput.WithCompletedProcess("external test"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer.AttachObservation(oracle, oracleFingerprint, observation); err != nil {
		t.Fatal(err)
	}
	if err := producer.ValidateObserved(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView([]Subject{subject, oracle}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := current.CheckObserved(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable {
		t.Fatalf("verdict = %+v, want unverifiable", verdict)
	}
}

func TestObservedCaptureRequiresObservedValidation(t *testing.T) {
	view := &View{capturedObserved: map[Subject]bool{{}: true}}
	if err := view.ValidateContext(context.Background()); !errors.Is(err, ErrObservedValidationRequired) {
		t.Fatalf("ValidateContext = %v, want ErrObservedValidationRequired", err)
	}
	if err := view.ValidateRefined(context.Background()); !errors.Is(err, ErrObservedValidationRequired) {
		t.Fatalf("ValidateRefined = %v, want ErrObservedValidationRequired", err)
	}
}

func TestObservedRefinementRecomputesProofAfterMaximalDrift(t *testing.T) {
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObservedRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.Refinement == (Refinement{}) || !fingerprint.ObservationProof.Observable {
		t.Fatalf("combined fingerprint = %+v", fingerprint)
	}
	observation, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer.AttachObservation(subject, producer.observedFingerprintLocked(subject), observation); err == nil {
		t.Fatal("second runtime observation attachment was accepted")
	}
	if err := producer.ValidateContext(context.Background()); !errors.Is(err, ErrObservedValidationRequired) {
		t.Fatalf("ValidateContext for combined capture = %v, want ErrObservedValidationRequired", err)
	}
	if err := producer.ValidateRefined(context.Background()); !errors.Is(err, ErrObservedValidationRequired) {
		t.Fatalf("ValidateRefined for combined capture = %v, want ErrObservedValidationRequired", err)
	}
	if err := producer.ValidateObserved(context.Background()); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(dir, "observed_test.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte(strings.Replace(string(source), "return 1", "return 2", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := current.CheckObserved(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("combined check after unrelated maximal drift = %+v, want valid", verdict)
	}
}

func TestCheckObservedPropagatesCancellationDuringDriftAnalysis(t *testing.T) {
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObservedRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(dir, "observed_test.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte(strings.Replace(string(source), "return 1", "return 2", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterChecks{Context: context.Background(), after: 1}
	if verdict, err := current.CheckObserved(ctx, fingerprint, subject); !errors.Is(err, context.Canceled) || verdict != (Verdict{}) {
		t.Fatalf("CheckObserved cancellation = %+v, %v; want zero verdict and context.Canceled", verdict, err)
	}
}

func TestUnavailableObservedAnalysisPrefersContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if verdict, err := unavailableObservedAnalysis(ctx, "refinement", errors.New("failed")); !errors.Is(err, context.Canceled) || verdict != (Verdict{}) {
		t.Fatalf("unavailable analysis = %+v, %v; want zero verdict and context.Canceled", verdict, err)
	}
}

func TestObservedFingerprintLiftsOnlyExplicitCompletedEvidence(t *testing.T) {
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.ObservationProof.Observable || !compatibleObservationProof(fingerprint.ObservationProof, fingerprint.ObservationAssertion, subject, fingerprint.MaximalClosure) {
		t.Fatalf("captured proof = %+v", fingerprint.ObservationProof)
	}
	withoutManifest, err := producer.CheckObserved(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if withoutManifest.Status != Unverifiable {
		t.Fatalf("proof without completed manifest = %+v, want unverifiable", withoutManifest)
	}
	observation, err := runtimeinput.FromTestLog([]byte("# test log\nopen fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	if err := producer.ValidateObserved(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	analyses := 0
	current.beforePreciseAnalysis = func() { analyses++ }
	ordinary, err := current.Check(fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.Status != Unverifiable {
		t.Fatalf("ordinary check inferred observation policy: %+v", ordinary)
	}
	observed, err := current.CheckObserved(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Valid {
		t.Fatalf("observed check = %+v, want valid", observed)
	}
	if analyses != 0 {
		t.Fatalf("unchanged-maximal observed check invoked precise analysis %d times, want 0", analyses)
	}
	tampered := fingerprint
	tampered.ObservationProof.Evidence = "tampered"
	verdict, err := current.CheckObserved(context.Background(), tampered, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable {
		t.Fatalf("tampered proof = %+v, want unverifiable", verdict)
	}
	malformed, err := runtimeinput.FromTestLog([]byte("# test log\n\nopen fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker-malformed"))
	if err != nil {
		t.Fatal(err)
	}
	malformedState, err := runtimeinput.CompletedState(malformed)
	if err != nil {
		t.Fatal(err)
	}
	malformedFingerprint := fingerprint
	malformedFingerprint.RuntimeInputs = malformedState.Manifest
	malformedFingerprint.RuntimeDigest = malformedState.Digest
	verdict, err = current.CheckObserved(context.Background(), malformedFingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable {
		t.Fatalf("manifest unverifiability was suppressed: %+v", verdict)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdict, err = current.CheckObserved(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "runtimeinputs" {
		t.Fatalf("changed observed input = %+v, want stale runtimeinputs", verdict)
	}
}

func TestValidateObservedBracketsProofAnalysisWithRuntimeObservation(t *testing.T) {
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	producer.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
		calls++
		if calls == 1 {
			return state, nil
		}
		moved := state
		moved.Digest = "moved"
		return moved, nil
	}
	if err := producer.ValidateObserved(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("ValidateObserved across runtime drift = %v, want ErrViewChanged", err)
	}
	if calls != 2 {
		t.Fatalf("runtime observations = %d, want 2", calls)
	}
}

func TestViewSourceFilesReturnsMaximalMutableInputs(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{{Package: "example.com/view", Symbol: "F"}}, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "view.go")
	files := view.SourceFiles()
	if len(files) == 0 || !slices.Contains(files, want) {
		t.Fatalf("SourceFiles = %v, want %s", files, want)
	}
	files[0] = "changed"
	if slices.Contains(view.SourceFiles(), "changed") {
		t.Fatal("SourceFiles returned mutable view storage")
	}
}

func TestBatchedViewPreservesSubjectFingerprintsAndSourceFiles(t *testing.T) {
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":  "module example.com/view\n\ngo 1.26\n",
		"root.go": "package view\n\nfunc F() {}\nfunc H() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "sub.go"), []byte("package sub\n\nfunc G() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: "example.com/view", Symbol: "F"},
		{Package: "example.com/view", Symbol: "H"},
		{Package: "example.com/view/sub", Symbol: "G"},
	}
	wantByPackage := map[string][]string{
		"example.com/view":     {filepath.Join(dir, "root.go")},
		"example.com/view/sub": {filepath.Join(dir, "sub", "sub.go")},
	}
	batch, err := engine.NewView(subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	var wantUnion []string
	for _, subject := range subjects {
		singleton, err := engine.NewView([]Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		batchedFingerprint, err := batch.Capture(subject)
		if err != nil {
			t.Fatal(err)
		}
		singletonFingerprint, err := singleton.Capture(subject)
		if err != nil {
			t.Fatal(err)
		}
		if batchedFingerprint != singletonFingerprint {
			t.Fatalf("%+v batched fingerprint = %+v, singleton = %+v", subject, batchedFingerprint, singletonFingerprint)
		}
		batchedFiles, err := batch.SourceFilesFor(subject)
		if err != nil {
			t.Fatal(err)
		}
		singletonFiles := singleton.SourceFiles()
		if want := wantByPackage[subject.Package]; !slices.Equal(singletonFiles, want) {
			t.Fatalf("%+v singleton files = %v, want exact source identities %v", subject, singletonFiles, want)
		}
		if !slices.Equal(batchedFiles, singletonFiles) {
			t.Fatalf("%+v batched files = %v, singleton = %v", subject, batchedFiles, singletonFiles)
		}
		wantUnion = append(wantUnion, singletonFiles...)
		batchedFiles[0] = "changed"
		current, err := batch.SourceFilesFor(subject)
		if err != nil || slices.Contains(current, "changed") {
			t.Fatalf("SourceFilesFor returned mutable storage: %v, %v", current, err)
		}
	}
	slices.Sort(wantUnion)
	wantUnion = slices.Compact(wantUnion)
	if got := batch.SourceFiles(); !slices.Equal(got, wantUnion) {
		t.Fatalf("batched source-file union = %v, want %v", got, wantUnion)
	}
	if _, err := batch.SourceFilesFor(Subject{Package: "example.com/view", Symbol: "Missing"}); err == nil {
		t.Fatal("SourceFilesFor accepted a subject outside the view")
	}
}

func TestEngineCheckUsesFreshView(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	t.Setenv("GOGC", "100")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := engine.CaptureFor(subject, dir, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("GOGC", "off"); err != nil {
		t.Fatal(err)
	}
	verdict, err := engine.Check(fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("same Engine after ambient drift = {%s %q}, want valid", verdict.Status, verdict.Reason)
	}
	current, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	verdict, err = current.Check(fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "runtimeconfig" {
		t.Fatalf("new Engine after runtime-config drift = {%s %q}, want {stale runtimeconfig}", verdict.Status, verdict.Reason)
	}
}

func TestCodeViewOmitsMeasurementGuards(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.Guards.Toolchain == "" || fingerprint.Guards.BuildConfig == "" {
		t.Fatalf("code guards missing: %+v", fingerprint.Guards)
	}
	if fingerprint.Guards.Machine != "" || fingerprint.Guards.RuntimeConfig != "" {
		t.Fatalf("code view captured measurement guards: %+v", fingerprint.Guards)
	}
	if _, err := engine.NewViewFor([]Subject{subject}, dir, Kind(99)); err == nil {
		t.Fatal("invalid result kind accepted")
	}
}

func TestResultKindIsBoundToFingerprint(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	measurement, err := engine.NewViewFor([]Subject{subject}, dir, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := measurement.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ResultKind != Measurement {
		t.Fatalf("captured result kind = %d, want measurement", fingerprint.ResultKind)
	}
	code, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := code.Check(fingerprint, subject); err == nil {
		t.Fatal("measurement fingerprint accepted by code-result view")
	}
	if _, err := code.CheckRefined(context.Background(), fingerprint, subject); err == nil {
		t.Fatal("measurement fingerprint accepted by refined code-result view")
	}
	if _, err := code.CheckRefinedBatch(context.Background(), map[Subject]Fingerprint{subject: fingerprint}); err == nil {
		t.Fatal("measurement fingerprint accepted by refined code-result batch")
	}
	reclassified := fingerprint
	reclassified.ResultKind = CodeResult
	if _, err := engine.Check(reclassified, subject, dir); err == nil {
		t.Fatal("measurement guards accepted after result-kind reclassification")
	}
	fingerprint.ResultKind = 0
	if _, err := engine.Check(fingerprint, subject, dir); err == nil {
		t.Fatal("fingerprint with missing result kind accepted")
	}
}

func TestProducerViewValidatesAfterSourceChange(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The producer view remains the immutable pre-run observation.
	verdict, err := view.Check(fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("frozen producer view = {%s %q}, want valid", verdict.Status, verdict.Reason)
	}
	if err := view.Validate(); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate after source edit = %v, want ErrViewChanged", err)
	}
	verdict, err = engine.Check(fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" {
		t.Fatalf("fresh current view = {%s %q}, want {stale closure}", verdict.Status, verdict.Reason)
	}
}

func TestProducerViewRejectsSourceIdentityChangeWithEqualBytes(t *testing.T) {
	dir := t.TempDir()
	for _, dep := range []string{"dep-a", "dep-b"} {
		depDir := filepath.Join(dir, dep)
		if err := os.Mkdir(depDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(depDir, "go.mod"), []byte("module example.com/dep\n\ngo 1.26\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(depDir, "dep.go"), []byte("package dep\n\nfunc F() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	goMod := func(dep string) []byte {
		return []byte("module example.com/view\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\nreplace example.com/dep => ./" + dep + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), goMod("dep-a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nimport \"example.com/dep\"\n\nfunc F() { dep.F() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{{Package: "example.com/view", Symbol: "F"}}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), goMod("dep-b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := view.Validate(); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate after source identity change = %v, want ErrViewChanged", err)
	}
}

func TestNewViewRejectsSourceChangeDuringConstruction(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	var change sync.Once
	engine, err := New(
		WithDir(dir),
		WithAssumePure(func(Subject) bool {
			change.Do(func() {
				if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
					t.Error(err)
				}
			})
			return false
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.NewView([]Subject{subject}, dir); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("NewView during source change = %v, want ErrViewChanged", err)
	}
}

func TestViewDetectsAddedInitializer(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nvar Value int\nfunc F() int { return Value }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "init.go"), []byte("package view\n\nfunc init() { Value = 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := view.Validate(); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate after adding initializer = %v, want ErrViewChanged", err)
	}
}

func TestViewDiscoversSourcePurity(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\n//gofresh:pure\nfunc F() { _, _ = os.ReadFile(\"fixture\") }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("directive-pure view = {%s %q}, want valid", verdict.Status, verdict.Reason)
	}
}

func TestViewAcceptsPromotedMethodSubject(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\ntype Inner struct{}\n\n//gofresh:pure\nfunc (Inner) M() { _, _ = os.ReadFile(\"fixture\") }\n\ntype Outer struct{ Inner }\n")
	subject := Subject{Package: "example.com/view", Symbol: "Outer.M"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("promoted pure method = %+v, want valid", verdict)
	}
	refined, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nimport \"os\"\n\ntype Inner struct{}\n\n//gofresh:pure\nfunc (Inner) M() { _, _ = os.ReadFile(\"fixture\") }\n\ntype Outer struct{ *Inner }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err = current.CheckRefined(context.Background(), refined, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "refinement" {
		t.Fatalf("promoting type edit = %+v, want stale refinement", verdict)
	}
}

func TestImportedPromotedMethodInheritsPurityDirective(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"example.com/view/dep\"\n\ntype Outer struct { dep.Inner }\n")
	if err := os.Mkdir(filepath.Join(dir, "dep"), 0o755); err != nil {
		t.Fatal(err)
	}
	dependency := "package dep\n\nimport \"os\"\n\ntype Inner struct{}\n\n//gofresh:pure\nfunc (Inner) M() { _, _ = os.ReadFile(\"fixture\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "dep", "dep.go"), []byte(dependency), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "Outer.M"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.PurityAssertion != "source directive" {
		t.Fatalf("imported promoted purity = %q, want source directive", fingerprint.PurityAssertion)
	}
	verdict, err := view.Check(fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("imported promoted purity verdict = %+v, want valid", verdict)
	}
}

func TestViewRejectsExternalTestSubjectCollision(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\nfunc F() { _, _ = os.ReadFile(\"fixture\") }\n")
	if err := os.WriteFile(filepath.Join(dir, "external_test.go"), []byte("package view_test\n\n//gofresh:pure\nfunc F() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.NewView([]Subject{{Package: "example.com/view", Symbol: "F"}}, dir)
	if err == nil || !strings.Contains(err.Error(), "ambiguous subject") {
		t.Fatalf("external-test collision accepted: %v", err)
	}
}

func TestSourcePurityRemainsPortableWhenProducerAlsoAsserts(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\n//gofresh:pure\nfunc F() { _, _ = os.ReadFile(\"fixture\") }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	producer, err := New(WithDir(dir), WithAssumePure(func(candidate Subject) bool { return candidate == subject }))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.Capture(subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.PurityAssertion != "caller assertion and source directive" {
		t.Fatalf("producer purity attribution = %q", fingerprint.PurityAssertion)
	}
	consumer, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := consumer.Check(fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("portable source purity verdict = %+v, want valid", verdict)
	}
}

func TestMalformedPurityAttributionCannotOverride(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\nfunc F() { _, _ = os.ReadFile(\"fixture\") }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	producer, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.Capture(subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.PurityAssertion = "corrupt"
	consumer, err := New(WithDir(dir), WithAssumePure(func(candidate Subject) bool { return candidate == subject }))
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := consumer.Check(fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable {
		t.Fatalf("malformed purity attribution verdict = %+v, want unverifiable", verdict)
	}
}

func TestViewMarksCallerSuppliedCallbackUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F(fn func() int) int { return fn() }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "caller-supplied") {
		t.Fatalf("callback subject verdict = %+v, want caller-supplied unverifiable", verdict)
	}
}

func TestViewMarksGenericCallbackUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F[T func() int](fn T) int { return fn() }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable {
		t.Fatalf("generic callback verdict = %+v, want unverifiable", verdict)
	}
}

func TestRefinementRetainsMaximalDispositionForMutableCallbackGlobal(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nvar Callback = func() {}\n\nfunc F() { Callback() }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.CheckRefined(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "caller-supplied") {
		t.Fatalf("mutable callback global verdict = %+v fingerprint=%+v, want retained maximal disposition", verdict, fingerprint)
	}
}

func TestRefinementPropagatesMutableCallbackGlobalFromDependency(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"example.com/view/dep\"\n\nfunc F() { dep.Run() }\n")
	if err := os.Mkdir(filepath.Join(dir, "dep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dep", "dep.go"), []byte("package dep\n\nvar Hook = func() {}\n\nfunc Run() { Hook() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.CheckRefined(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "caller-supplied") {
		t.Fatalf("dependency callback global verdict = %+v, want propagated maximal disposition", verdict)
	}
}

func TestMaximalOrdinaryTestHarnessIsVerifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n")
	if err := os.WriteFile(filepath.Join(dir, "ordinary_test.go"), []byte("package view\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "TestF"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("ordinary test harness verdict = %+v, want valid", verdict)
	}
}

func TestRefinementClassifiesResolvedStandardInterfaceTarget(t *testing.T) {
	dir := writeViewModule(t, "package view\n")
	source := "package view\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) { var value interface{ TempDir() string } = t; _ = value.TempDir() }\n"
	if err := os.WriteFile(filepath.Join(dir, "interface_test.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "TestF"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.Refinement.Unverifiable || !strings.Contains(fingerprint.Refinement.Reason, "testing.TempDir") {
		t.Fatalf("resolved standard interface target = %+v, want testing.TempDir unverifiable", fingerprint.Refinement)
	}
}

func TestRefinementRejectsUnauditedStandardOperation(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"time\"\n\nfunc F() int64 { return time.Now().UnixNano() }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.CheckRefined(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "unaudited standard operation") {
		t.Fatalf("time.Now verdict = %+v, want unaudited-standard unverifiable", verdict)
	}
}

func TestRefinementRejectsRuntimeBackedSyncOperation(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"sync\"\n\nfunc F() any { var pool sync.Pool; pool.Put(1); return pool.Get() }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.Refinement.Unverifiable || !strings.Contains(fingerprint.Refinement.Reason, "sync") {
		t.Fatalf("sync.Pool refinement = %+v, want unverifiable", fingerprint.Refinement)
	}
}

func TestRefinementClassifiesExternalCallbackFromStandardLibrary(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport (\"os\"; \"regexp\")\n\nfunc F() string { return regexp.MustCompile(\".\").ReplaceAllStringFunc(\"X\", os.Getenv) }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.Refinement.Unverifiable || !strings.Contains(fingerprint.Refinement.Reason, "os.Getenv") {
		t.Fatalf("standard-library external callback = %+v, want os.Getenv unverifiable", fingerprint.Refinement)
	}
	if view.refined[subject].Widened {
		t.Fatalf("standard-library callback widened instead of classifying its resolved target: %+v", view.refined[subject])
	}
}

func TestRefinementRejectsRuntimeAddressExposure(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"reflect\"\n\nfunc F() uintptr { value := 0; return reflect.ValueOf(&value).Pointer() }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.Refinement.Unverifiable || !strings.Contains(fingerprint.Refinement.Reason, "reflect") {
		t.Fatalf("reflect.Pointer refinement = %+v, want unverifiable", fingerprint.Refinement)
	}
}

func TestRefinementRejectsUnsafePointerAddressInput(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"unsafe\"\n\nvar Address uintptr\nfunc F() byte { return *(*byte)(unsafe.Pointer(Address)) }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.Refinement.Unverifiable || !strings.Contains(fingerprint.Refinement.Reason, "unsafe") {
		t.Fatalf("unsafe pointer refinement = %+v, want unverifiable", fingerprint.Refinement)
	}
}

func TestRefinementRejectsCPUDispatchedMathForCodeResult(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"math\"\n\nfunc F() uint64 { return math.Float64bits(math.Exp(1.25)) }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.Refinement.Unverifiable || !strings.Contains(fingerprint.Refinement.Reason, "math") {
		t.Fatalf("math.Exp refinement = %+v, want unverifiable", fingerprint.Refinement)
	}
}

func TestRefinementRejectsStandardGlobalState(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\nfunc F() int { return len(os.Args) }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.CheckRefined(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "standard global os.Args") {
		t.Fatalf("os.Args verdict = %+v, want standard-global unverifiable", verdict)
	}
}

func TestViewFreezesRelativeModuleDirectory(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	engine, err := New()
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, ".")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if view.moduleDir != canonical {
		t.Fatalf("view module dir after chdir = %q, want frozen %q", view.moduleDir, canonical)
	}
}

func TestRefinementRejectsFormattedReaderInput(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport (\"fmt\"; \"os\")\n\nfunc F() int { var value int; _, _ = fmt.Fscan(os.Stdin, &value); return value }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.CheckRefined(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "fmt.Fscan") {
		t.Fatalf("fmt.Fscan verdict = %+v, want formatted-input unverifiable", verdict)
	}
}

func TestRefinementRejectsBenchmarkIterationCount(t *testing.T) {
	dir := writeViewModule(t, "package view\n")
	if err := os.WriteFile(filepath.Join(dir, "benchmark_test.go"), []byte("package view\n\nimport \"testing\"\n\nfunc BenchmarkF(b *testing.B) { _ = b.N }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "BenchmarkF"}
	view, err := engine.NewViewFor([]Subject{subject}, dir, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.CheckRefined(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "testing.B.N") {
		t.Fatalf("benchmark iteration verdict = %+v, want test-runtime unverifiable", verdict)
	}
}

func TestRefinementWideningRetainsMaximalAssemblyDisposition(t *testing.T) {
	maximal := closure.Closure{Hash: "subject-salted", Unverifiable: true, Reason: "reaches assembly"}
	refined := closure.Closure{Hash: "unsalted-maximal", Widened: true}
	got := retainMaximalDisposition(maximal, refined, false)
	if !got.Unverifiable || got.Reason != maximal.Reason {
		t.Fatalf("widened refinement disposition = %+v, want retained maximal disposition", got)
	}
}

func TestRefinementAllowsResolvedAssembly(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport _ \"example.com/view/dep\"\n\nfunc F()\n")
	if err := os.Mkdir(filepath.Join(dir, "dep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dep", "dep.go"), []byte("package dep\n\nimport \"os\"\n\nfunc Read() { _, _ = os.ReadFile(\"fixture\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	assembly := "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"
	if err := os.WriteFile(filepath.Join(dir, "view.s"), []byte(assembly), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.Refinement.Unverifiable {
		t.Fatalf("resolved assembly refinement = %+v, want verifiable", fingerprint.Refinement)
	}
}

func TestRefinementRetainsSystemObjectDisposition(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	if err := os.WriteFile(filepath.Join(dir, "view.syso"), []byte("opaque system object"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.Refinement.Unverifiable || !strings.Contains(fingerprint.Refinement.Reason, "system object") {
		t.Fatalf("system-object refinement = %+v, want permanently opaque", fingerprint.Refinement)
	}
}

func TestRefinementRejectsRuntimeDependentAssemblyInstruction(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F()\n")
	assembly := "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRDTSC\n\tRET\n"
	if err := os.WriteFile(filepath.Join(dir, "view.s"), []byte(assembly), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.Refinement.Unverifiable {
		t.Fatalf("runtime-dependent assembly refinement = %+v, want unverifiable", fingerprint.Refinement)
	}
}

func TestRefinementRejectsExternalStateInAssemblyInclude(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F()\n")
	assembly := "#include \"textflag.h\"\n#include \"ops.inc\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"
	if err := os.WriteFile(filepath.Join(dir, "view.s"), []byte(assembly), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ops.inc"), []byte("RDTSC\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.Refinement.Unverifiable {
		t.Fatalf("included external-state assembly = %+v, want unverifiable", fingerprint.Refinement)
	}
}

func TestRefinementRejectsExternalStandardLinknameTarget(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport _ \"unsafe\"\n\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n\nfunc F() int64 { return nanotime() }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.Refinement.Unverifiable {
		t.Fatalf("standard linkname refinement = %+v, want unverifiable", fingerprint.Refinement)
	}
}

func TestRefinementRootsProductionFunctionNamedTestMain(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc TestMain() {}\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "TestMain"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.CaptureRefined(context.Background(), subject); err != nil {
		t.Fatalf("production TestMain was not rootable: %v", err)
	}
}

func TestProductionTestMainSignatureIsNotHarnessSetup(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport (\"os\"; \"testing\")\n\nfunc TestMain(m *testing.M) { _, _ = os.ReadFile(\"fixture\") }\n")
	if err := os.WriteFile(filepath.Join(dir, "view_test.go"), []byte("package view\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "TestF"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.Refinement.Unverifiable {
		t.Fatalf("production TestMain contaminated test subject: %+v", fingerprint.Refinement)
	}
}

func TestRefinedCheckRejectsMalformedEvidenceWhenMaximalMatches(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.Refinement.Strategy = DeclarationRTA
	verdict, err := view.CheckRefined(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "refinement" {
		t.Fatalf("malformed matching refinement = %+v, want stale refinement", verdict)
	}
}

func TestRefinedBatchMarksRuntimeInputDriftStale(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	recorded := map[Subject]Fingerprint{subject: {
		RuntimeInputs: state.Manifest,
		RuntimeDigest: state.Digest,
	}}
	view := &View{moduleDir: dir}
	before, err := view.observeRuntimeInputs(context.Background(), recorded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdicts, err := view.finishRuntimeObservation(context.Background(), recorded, before, map[Subject]Verdict{subject: {Status: Valid}})
	if err != nil {
		t.Fatal(err)
	}
	if got := verdicts[subject]; got.Status != Stale || got.Reason != "runtimeinputs" {
		t.Fatalf("runtime-input drift verdict = %+v, want stale runtimeinputs", got)
	}
}

func TestRuntimeInputDriftIsSubjectLocal(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\nfunc G() {}\n")
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("before"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stateA, err := runtimeinput.FromTestLog([]byte("open a\n"), dir, dir, runtimeinput.WithCompletedProcess("worker-a"))
	if err != nil {
		t.Fatal(err)
	}
	stateB, err := runtimeinput.FromTestLog([]byte("open b\n"), dir, dir, runtimeinput.WithCompletedProcess("worker-b"))
	if err != nil {
		t.Fatal(err)
	}
	f := Subject{Package: "example.com/view", Symbol: "F"}
	g := Subject{Package: "example.com/view", Symbol: "G"}
	recorded := map[Subject]Fingerprint{
		f: {RuntimeInputs: stateA.Manifest, RuntimeDigest: stateA.Digest},
		g: {RuntimeInputs: stateB.Manifest, RuntimeDigest: stateB.Digest},
	}
	view := &View{moduleDir: dir}
	before, err := view.observeRuntimeInputs(context.Background(), recorded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdicts, err := view.finishRuntimeObservation(context.Background(), recorded, before, map[Subject]Verdict{
		f: {Status: Valid},
		g: {Status: Valid},
	})
	if err != nil {
		t.Fatal(err)
	}
	if verdicts[f].Status != Stale || verdicts[g].Status != Valid {
		t.Fatalf("subject-local runtime drift = F:%+v G:%+v, want stale/valid", verdicts[f], verdicts[g])
	}
}

func TestRuntimeInputCheckReobservesBaseView(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := view.Check(fingerprint, subject); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("runtime-input check after base drift = %v, want ErrViewChanged", err)
	}
}

func TestRuntimeInputCheckDetectsMovementBetweenSnapshots(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.RuntimeInputs = "manifest"
	fingerprint.RuntimeDigest = "recorded"
	calls := 0
	view.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
		calls++
		digest := "recorded"
		if calls > 1 {
			digest = "moved"
		}
		return runtimeinput.State{Digest: digest, OK: true}, nil
	}
	verdict, err := view.Check(fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "runtimeinputs" || calls != 2 {
		t.Fatalf("moving runtime input verdict = %+v calls=%d, want stale after two observations", verdict, calls)
	}
}

func TestRuntimeInputDriftDoesNotOverrideStale(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	recorded := map[Subject]Fingerprint{subject: {
		RuntimeInputs: state.Manifest,
		RuntimeDigest: "already-stale",
	}}
	view := &View{moduleDir: dir}
	before, err := view.observeRuntimeInputs(context.Background(), recorded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdicts, err := view.finishRuntimeObservation(context.Background(), recorded, before, map[Subject]Verdict{subject: {Status: Stale, Reason: "closure"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := verdicts[subject]; got.Status != Stale || got.Reason != "closure" {
		t.Fatalf("runtime drift overwrote stale verdict: %+v", got)
	}
}

func TestCancelledContextAbortsUnchangedRuntimeCheck(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	producer, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	current, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := current.CheckRefined(ctx, fingerprint, subject); !errors.Is(err, context.Canceled) {
		t.Fatalf("CheckRefined under cancelled context = %v, want context.Canceled", err)
	}
	verdict, err := current.CheckRefined(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("unchanged runtime check = %+v, want valid", verdict)
	}
}

func TestCheckRefinedBatchHonorsCancellationDuringRuntimeObservation(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\nfunc G() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	f := Subject{Package: "example.com/view", Symbol: "F"}
	g := Subject{Package: "example.com/view", Symbol: "G"}
	producer, err := engine.NewView([]Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[Subject]Fingerprint{}
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"))
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []Subject{f, g} {
		fingerprint, err := producer.CaptureRefined(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint.RuntimeInputs = state.Manifest
		fingerprint.RuntimeDigest = state.Digest
		recorded[subject] = fingerprint
	}
	current, err := engine.NewView([]Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel from inside the first runtime-input observation: the batch must
	// stop between observations with the context error — never observe the
	// second record or finish under a private uncancelled context.
	observations := 0
	current.runtimeCurrent = func(hookCtx context.Context, encoded, moduleDir string) (runtimeinput.State, error) {
		observations++
		cancel()
		return runtimeinput.CurrentContext(hookCtx, encoded, moduleDir)
	}
	if _, err := current.CheckRefinedBatch(ctx, recorded); !errors.Is(err, context.Canceled) {
		t.Fatalf("CheckRefinedBatch cancelled during runtime observation = %v, want context.Canceled", err)
	}
	if observations != 1 {
		t.Fatalf("runtime observations after mid-observation cancel = %d, want 1", observations)
	}
}

func TestCheckRefinedBatchReturnsContextErrorDuringRefinement(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() {}\nfunc G() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Cancellation injected exactly when the drift-forced refinement begins must
	// surface as the context error, never as unverifiable verdicts from a
	// partially cancelled analysis.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	current.beforePreciseAnalysis = cancel
	if _, err := current.CheckRefinedBatch(ctx, map[Subject]Fingerprint{subject: fingerprint}); !errors.Is(err, context.Canceled) {
		t.Fatalf("CheckRefinedBatch cancelled during refinement = %v, want context.Canceled", err)
	}
}

func TestRefinedViewChecksMaximalBeforeDeclarationRTA(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\nfunc F() int { return 1 }\nfunc G() { _, _ = os.ReadFile(\"fixture\") }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	maximalOnly, err := producer.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	refined, err := producer.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if refined.MaximalClosure == "" || refined.Refinement.Strategy != DeclarationRTA || refined.Refinement.Closure == "" {
		t.Fatalf("refined fingerprint is incomplete: %+v", refined)
	}
	if refined.Refinement.Unverifiable {
		t.Fatalf("F inherited sibling G's external dependence: %+v", refined.Refinement)
	}
	if maximalOnly.Refinement != (Refinement{}) {
		t.Fatalf("maximal capture contains refinement: %+v", maximalOnly.Refinement)
	}
	if err := producer.Validate(); !errors.Is(err, ErrRefinedValidationRequired) {
		t.Fatalf("Validate after refined capture = %v, want ErrRefinedValidationRequired", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := producer.ValidateRefined(cancelled); err == nil {
		t.Fatal("ValidateRefined accepted an exhausted caller budget")
	}
	if err := producer.ValidateRefined(context.Background()); err != nil {
		t.Fatalf("ValidateRefined unchanged: %v", err)
	}

	unchanged, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// The precise-analysis seam pins REQ-fresh-hierarchical-check's "does not
	// run refinement analysis" clauses: every verdict below must be decided
	// from recorded evidence alone.
	analyses := 0
	unchanged.beforePreciseAnalysis = func() { analyses++ }
	verdict, err := unchanged.CheckRefined(context.Background(), refined, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("unchanged maximal lost recorded disposition: %+v", verdict)
	}
	incompatible := refined
	incompatible.Refinement.Strategy = "gofresh/unknown@1"
	verdict, err = unchanged.CheckRefined(context.Background(), incompatible, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "refinement" {
		t.Fatalf("incompatible evidence accepted with matching maximal closure: %+v", verdict)
	}
	transferred := refined
	transferred.Refinement.Subject = Subject{Package: "example.com/view", Symbol: "G"}
	transferred.Refinement.Unverifiable = false
	transferred.Refinement.Reason = ""
	verdict, err = unchanged.CheckRefined(context.Background(), transferred, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "refinement" {
		t.Fatalf("transferred refinement accepted with matching maximal closure: %+v", verdict)
	}
	if analyses != 0 {
		t.Fatalf("unchanged-maximal checks invoked precise analysis %d times, want 0", analyses)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nimport \"os\"\n\nfunc F() int { return 1 }\nfunc G() { _, _ = os.ReadFile(\"changed\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err = current.Check(refined, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" {
		t.Fatalf("maximal policy after sibling edit = %+v, want stale closure", verdict)
	}
	verdict, err = current.CheckRefined(context.Background(), refined, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("refined policy after irrelevant sibling edit = %+v, want valid", verdict)
	}
	// A cold view pins that these drifted recordings are refused before any
	// precise analysis: a warm refined cache would mask an analysis invocation
	// from the seam.
	coldCurrent, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	analyses = 0
	coldCurrent.beforePreciseAnalysis = func() { analyses++ }
	verdict, err = coldCurrent.CheckRefined(context.Background(), maximalOnly, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "refinement" {
		t.Fatalf("maximal-only recording after drift = %+v, want stale refinement", verdict)
	}
	incompatible = refined
	incompatible.Refinement.Strategy = "gofresh/unknown@1"
	verdict, err = coldCurrent.CheckRefined(context.Background(), incompatible, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "refinement" {
		t.Fatalf("incompatible refinement after drift = %+v, want stale refinement", verdict)
	}
	if analyses != 0 {
		t.Fatalf("drifted checks without compatible refined evidence invoked precise analysis %d times, want 0", analyses)
	}
	mismatched := refined
	mismatched.Refinement.Closure = "different"
	verdict, err = current.CheckRefined(context.Background(), mismatched, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "refinement" {
		t.Fatalf("refined mismatch after drift = %+v, want stale refinement", verdict)
	}
	cancelledCurrent, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Cancellation injected at the precise-analysis boundary surfaces as the
	// context error, never as a verdict from a partially cancelled analysis.
	analysisCtx, cancelAnalysis := context.WithCancel(context.Background())
	defer cancelAnalysis()
	cancelledCurrent.beforePreciseAnalysis = cancelAnalysis
	if _, err := cancelledCurrent.CheckRefined(analysisCtx, refined, subject); !errors.Is(err, context.Canceled) {
		t.Fatalf("refinement cancelled at the analysis boundary = %v, want context.Canceled", err)
	}
	guardDrift := refined
	guardDrift.Guards.BuildConfig = "different"
	analyses = 0
	cancelledCurrent.beforePreciseAnalysis = func() { analyses++ }
	verdict, err = cancelledCurrent.CheckRefined(context.Background(), guardDrift, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "buildconfig" {
		t.Fatalf("drifted recording with failed known guard = %+v, want stale buildconfig", verdict)
	}
	if analyses != 0 {
		t.Fatalf("failed known guard invoked precise analysis %d times, want 0", analyses)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nimport \"os\"\n\nfunc F() int { return 2 }\nfunc G() { _, _ = os.ReadFile(\"changed\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	relevant, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err = relevant.CheckRefined(context.Background(), refined, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "refinement" {
		t.Fatalf("relevant refined source edit = %+v, want stale refinement", verdict)
	}
}

func TestRefinementDispositionIntegrity(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\nfunc F() { _, _ = os.ReadFile(\"fixture\") }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.Refinement.Unverifiable {
		t.Fatalf("external refinement disposition = %+v, want unverifiable", fingerprint.Refinement)
	}
	fingerprint.Refinement.Unverifiable = false
	fingerprint.Refinement.Reason = ""
	current, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := current.CheckRefined(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "refinement" {
		t.Fatalf("tampered refinement disposition = %+v, want stale refinement", verdict)
	}
}

func TestRefinementEvidenceBindsMaximalGeneration(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	first, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	refined, err := first.CaptureRefined(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nimport \"os\"\n\nfunc F() { _, _ = os.ReadFile(\"fixture\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	maximal, err := second.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	maximal.Refinement = refined.Refinement
	verdict, err := second.CheckRefined(context.Background(), maximal, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "refinement" {
		t.Fatalf("cross-generation refinement splice = %+v, want stale refinement", verdict)
	}
}

func TestRefinedCaptureHonorsExhaustedBudget(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := view.CaptureRefined(ctx, subject); err == nil {
		t.Fatal("CaptureRefined accepted an exhausted caller budget")
	}
}

func TestContextAwareViewConstructionHonorsCancellation(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	_, err = engine.NewViewContext(ctx, []Subject{subject}, dir)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled view construction = %v, want context.Canceled", err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.CheckContext(ctx, fingerprint, subject); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled view check = %v, want context.Canceled", err)
	}
	stale := fingerprint
	stale.MaximalClosure = "moved"
	publicationCtx := &cancelAfterChecks{Context: context.Background(), after: 1}
	if _, err := view.CheckContext(publicationCtx, stale, subject); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled verdict publication = %v, want context.Canceled", err)
	}
	current, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	comparisonCtx := &cancelAfterChecks{Context: context.Background(), after: 2}
	if err := view.compareBaseContext(comparisonCtx, current); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled base comparison = %v, want context.Canceled", err)
	}
	refinedComparisonCtx := &cancelAfterChecks{Context: context.Background(), after: 1}
	if err := compareRefinedContext(refinedComparisonCtx, map[Subject]closure.Closure{subject: {}}, map[Subject]closure.Closure{subject: {}}, []Subject{subject}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled refined comparison = %v, want context.Canceled", err)
	}
	runtimeFingerprint := fingerprint
	runtimeFingerprint.RuntimeInputs = "manifest"
	runtimeFingerprint.RuntimeDigest = "digest"
	runtimeCtx, runtimeCancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	view.runtimeCurrent = func(ctx context.Context, _, _ string) (runtimeinput.State, error) {
		close(started)
		<-ctx.Done()
		return runtimeinput.State{}, ctx.Err()
	}
	done := make(chan error, 1)
	go func() {
		_, err := view.CheckContext(runtimeCtx, runtimeFingerprint, subject)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(30 * time.Second):
		t.Fatal("runtime-input check did not start")
	}
	runtimeCancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runtime-input cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime-input check ignored cancellation")
	}
	if err := view.ValidateContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled view validation = %v, want context.Canceled", err)
	}
	if _, err := view.Capture(subject); !errors.Is(err, ErrViewSealed) {
		t.Fatalf("capture after cancelled validation = %v, want ErrViewSealed", err)
	}
	refinedView, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refinedView.CaptureRefined(context.Background(), subject); err != nil {
		t.Fatal(err)
	}
	if err := refinedView.ValidateContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled maximal validation of refined view = %v, want context.Canceled", err)
	}
}

func TestRefinedCaptureRejectsDriftSinceViewConstruction(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := view.CaptureRefined(context.Background(), subject); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("CaptureRefined after drift = %v, want ErrViewChanged", err)
	}
}

func TestRefinedCaptureRejectsGuardDriftSinceViewConstruction(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	goenv := filepath.Join(t.TempDir(), "goenv")
	if err := os.WriteFile(goenv, []byte("GOFLAGS=-tags=first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOENV", goenv)
	t.Setenv("GOFLAGS", "")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewViewFor([]Subject{subject}, dir, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goenv, []byte("GOFLAGS=-tags=second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := view.CaptureRefined(context.Background(), subject); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("CaptureRefined after guard drift = %v, want ErrViewChanged", err)
	}
}

func TestCancelledRefinementDoesNotWaitForViewLock(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	view.mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := view.CaptureRefined(ctx, subject)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled refinement error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		view.mu.Unlock()
		t.Fatal("cancelled refinement waited for the view lock")
	}
	view.mu.Unlock()
}

func TestRefinedCaptureDoesNotPublishAfterCancellationWhileWaitingForLock(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.CaptureRefined(context.Background(), subject); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	view.mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := view.CaptureRefined(ctx, subject)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	view.mu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("capture after lock-wait cancellation = %v, want context.Canceled", err)
	}
}

func TestValidateRefinedReobservesPurityAfterAnalysis(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	calls := 0
	engine, err := New(
		WithDir(dir),
		WithAssumePure(func(Subject) bool {
			calls++
			return calls > 12
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.CaptureRefined(context.Background(), subject); err != nil {
		t.Fatal(err)
	}
	if err := view.ValidateRefined(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("ValidateRefined after purity drift = %v, want ErrViewChanged", err)
	}
}

func TestValidationSealsViewAgainstLaterCapture(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := view.Capture(subject); !errors.Is(err, ErrViewSealed) {
		t.Fatalf("capture after validation = %v, want ErrViewSealed", err)
	}
	refinedView, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := refinedView.ValidateRefined(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := refinedView.CaptureRefined(context.Background(), subject); !errors.Is(err, ErrViewSealed) {
		t.Fatalf("refined capture after validation = %v, want ErrViewSealed", err)
	}
}

func TestValidationSealsConcurrentRefinedPublication(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := view.captureRefined(context.Background(), subject, func() {
			close(ready)
			<-release
		})
		done <- err
	}()
	select {
	case <-ready:
	case <-time.After(30 * time.Second):
		t.Fatal("refined capture did not reach publication boundary")
	}
	if err := view.Validate(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrViewSealed) {
		t.Fatalf("concurrent capture after validation = %v, want ErrViewSealed", err)
	}
}

func TestRefinedCaptureIsConcurrentSafe(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan Fingerprint, 2)
	errs := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			fingerprint, err := view.CaptureRefined(context.Background(), subject)
			results <- fingerprint
			errs <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first Fingerprint
	for fingerprint := range results {
		if first.MaximalClosure == "" {
			first = fingerprint
			continue
		}
		if fingerprint != first {
			t.Fatalf("concurrent captures differ: %+v != %+v", fingerprint, first)
		}
	}
}

func TestRefinedFingerprintBindsSubjectIdentity(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\nfunc G() int { return 1 }\n")
	f := Subject{Package: "example.com/view", Symbol: "F"}
	g := Subject{Package: "example.com/view", Symbol: "G"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView([]Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprints, err := view.CaptureRefinedBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fingerprints[f].Refinement.Closure == fingerprints[g].Refinement.Closure {
		t.Fatal("distinct subjects shared one refined closure hash")
	}
	current, err := engine.NewView([]Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// A drifted recording carrying the sibling's refined closure must never be
	// served by it: the refined hash is bound to the subject identity.
	drifted := fingerprints[g]
	drifted.MaximalClosure = "different"
	drifted.Refinement.Closure = fingerprints[f].Refinement.Closure
	drifted.Refinement.Evidence = refinementEvidence(drifted.MaximalClosure, drifted.Refinement)
	verdicts, err := current.CheckRefinedBatch(context.Background(), map[Subject]Fingerprint{
		f: fingerprints[f],
		g: drifted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verdicts[f].Status != Valid {
		t.Fatalf("unchanged subject was coupled to sibling drift: %+v", verdicts[f])
	}
	if verdicts[g].Status != Stale || verdicts[g].Reason != "refinement" {
		t.Fatalf("drifted subject carrying the sibling's refined closure = %+v, want stale refinement", verdicts[g])
	}
}

func TestRefinementUnavailabilityIsSubjectLocal(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\nfunc G() int { return 1 }\n")
	f := Subject{Package: "example.com/view", Symbol: "F"}
	g := Subject{Package: "example.com/view", Symbol: "G"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView([]Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprints, err := producer.CaptureRefinedBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView([]Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Breaking the tree after view construction makes the drift-forced
	// refinement analysis unavailable without cancelling the caller's context:
	// the drifted subject degrades to unverifiable while the unchanged sibling,
	// whose evidence needs no current analysis, still answers.
	if err := os.WriteFile(filepath.Join(dir, "broken.go"), []byte("package view\n\nfunc {"), 0o644); err != nil {
		t.Fatal(err)
	}
	drifted := fingerprints[g]
	drifted.MaximalClosure = "different"
	drifted.Refinement.Evidence = refinementEvidence(drifted.MaximalClosure, drifted.Refinement)
	verdicts, err := current.CheckRefinedBatch(context.Background(), map[Subject]Fingerprint{
		f: fingerprints[f],
		g: drifted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verdicts[f].Status != Valid {
		t.Fatalf("unchanged subject was coupled to unavailable refinement: %+v", verdicts[f])
	}
	if verdicts[g].Status != Unverifiable {
		t.Fatalf("drifted subject with unavailable refinement = %+v, want unverifiable", verdicts[g])
	}
}
