package gofresh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

// testObservationBracket captures an observation bracket over roots — the
// whole module by default — for completed-observation construction in tests.
func testObservationBracket(t *testing.T, moduleDir string, roots ...string) runtimeinput.Bracket {
	t.Helper()
	if len(roots) == 0 {
		roots = []string{"."}
	}
	bracket, err := runtimeinput.CaptureBracket(moduleDir, roots)
	if err != nil {
		t.Fatal(err)
	}
	return bracket
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
		"go.mod": "module example.com/observed\n\ngo 1.26\n",
		// Sibling lives in production source so editing it moves the CORE
		// closure: a test-file sibling edit would move only the test-variant
		// compartment and stale as "test variants" instead
		// (REQ-closure-test-variant-compartment).
		"observed.go":      "package observed\n\nfunc Sibling() int { return 1 }\n",
		"observed_test.go": "package observed\n\nimport (\"os\"; \"testing\")\n\nfunc TestRead(*testing.T) { _, _ = os.ReadFile(\"fixture\") }\n",
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
	producer, err := engine.NewView(context.Background(), []Subject{subject, oracle}, dir)
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
	observation, err := runtimeinput.FromTestLog(nil, dir, dir, runtimeinput.WithCompletedProcess("external test"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
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
	if err := producer.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView(context.Background(), []Subject{subject, oracle}, dir)
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
	// One batched capture over both subjects preserves the same isolation: the
	// unrootable subject degrades alone while its package sibling analyzes.
	batchProducer, err := engine.NewView(context.Background(), []Subject{subject, oracle}, dir)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := batchProducer.CaptureObservedBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(batch[subject].ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("batched unrootable proof = %+v, want unavailable disposition", batch[subject].ObservationProof)
	}
	if strings.Contains(batch[oracle].ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("batched oracle proof = %+v, want isolated analyzed disposition", batch[oracle].ObservationProof)
	}
}

func TestObservedRecordingStalesOnMaximalDrift(t *testing.T) {
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.ObservationProof.Observable {
		t.Fatalf("observed fingerprint = %+v", fingerprint)
	}
	observation, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	// A fingerprint that is not byte-identical to the captured proof —
	// here a tampered purity assertion — must refuse attachment: runtime
	// evidence binds only to the exact captured record.
	tampered := fingerprint
	tampered.PurityAssertion = "caller assertion"
	if _, err := producer.AttachObservation(subject, tampered, observation); err == nil {
		t.Fatal("tampered fingerprint accepted a runtime observation attachment")
	}
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer.AttachObservation(subject, producer.observedFingerprintLocked(subject), observation); err == nil {
		t.Fatal("second runtime observation attachment was accepted")
	}
	// One Validate: the view revalidates whatever it captured with no
	// routing sentinel for the caller to interpret.
	if err := producer.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(dir, "observed.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte(strings.Replace(string(source), "return 1", "return 2", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Core drift stales the recording on the closure even under the
	// observed policy: the observation lift rescues unverifiability, never
	// a drifted core.
	verdict, err := current.CheckObserved(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" {
		t.Fatalf("observed check after maximal drift = %+v, want {stale \"closure\"}", verdict)
	}
}

// Cancellation surfacing mid-check returns the context error and a zero
// verdict, never a partial answer — even when the record's evidence alone
// already decided staleness.
func TestCheckObservedPropagatesCancellationMidCheck(t *testing.T) {
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(dir, "observed.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte(strings.Replace(string(source), "return 1", "return 2", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterChecks{Context: context.Background(), after: 1}
	if verdict, err := current.CheckObserved(ctx, fingerprint, subject); !errors.Is(err, context.Canceled) || verdict != (Verdict{}) {
		t.Fatalf("CheckObserved cancellation = %+v, %v; want zero verdict and context.Canceled", verdict, err)
	}
}

// TestObservedProofAdmitsParentTraversalIdentity pins the effects
// admission's testlog-representability bar: a constant read identity
// carrying ".." is admitted — resolvability is the runtime observation's
// obligation under REQ-inputs-path-congruence, discharged or sealed at
// ingest — so the repo-root read idiom no longer blocks the proof, and
// with it the plain tier's file-I/O rescue.
func TestObservedProofAdmitsParentTraversalIdentity(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":       "module example.com/traversal\n\ngo 1.26\n",
		"data/fixture": "one",
		"pkg/pkg.go":   "package pkg\n\nfunc Sibling() int { return 1 }\n",
		"pkg/pkg_test.go": "package pkg\n\nimport (\"os\"; \"testing\")\n\n" +
			"func TestReadsAbove(*testing.T) { _, _ = os.ReadFile(\"../data/fixture\") }\n",
	} {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	subject := Subject{Package: "example.com/traversal/pkg", Symbol: "TestReadsAbove"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.ObservationProof.Observable {
		t.Fatalf("traversal read identity blocked the proof: %+v", fingerprint.ObservationProof)
	}
}

func TestObservedFingerprintLiftsOnlyExplicitCompletedEvidence(t *testing.T) {
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
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
	observation, err := runtimeinput.FromTestLog([]byte("# test log\nopen fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	if err := producer.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	analyses := 0
	current.beforePreciseAnalysis = func() { analyses++ }
	ordinary, err := current.Check(context.Background(), fingerprint, subject)
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
	malformed, err := runtimeinput.FromTestLog([]byte("# test log\n\nopen fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker-malformed"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
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
	if verdict.Status != Stale || !strings.HasPrefix(verdict.Reason, "runtimeinputs") || !strings.Contains(verdict.Reason, "moved: path fixture") {
		t.Fatalf("changed observed input = %+v, want stale runtimeinputs naming the mover", verdict)
	}
}

func TestValidateBracketsProofAnalysisWithRuntimeObservation(t *testing.T) {
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
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
	if err := producer.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate across runtime drift = %v, want ErrViewChanged", err)
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
	view, err := engine.NewView(context.Background(), []Subject{{Package: "example.com/view", Symbol: "F"}}, dir)
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
	batch, err := engine.NewView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	var wantUnion []string
	for _, subject := range subjects {
		singleton, err := engine.NewView(context.Background(), []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		batchedFingerprint, err := batch.Capture(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		singletonFingerprint, err := singleton.Capture(context.Background(), subject)
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
	fingerprint, err := engine.CaptureFor(context.Background(), subject, dir, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("GOGC", "off"); err != nil {
		t.Fatal(err)
	}
	verdict, err := engine.Check(context.Background(), fingerprint, subject, dir)
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
	verdict, err = current.Check(context.Background(), fingerprint, subject, dir)
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.Guards.Toolchain == "" || fingerprint.Guards.BuildConfig == "" {
		t.Fatalf("code guards missing: %+v", fingerprint.Guards)
	}
	if fingerprint.Guards.Machine != "" || fingerprint.Guards.RuntimeConfig != "" {
		t.Fatalf("code view captured measurement guards: %+v", fingerprint.Guards)
	}
	if _, err := engine.NewViewFor(context.Background(), []Subject{subject}, dir, Kind(99)); err == nil {
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
	measurement, err := engine.NewViewFor(context.Background(), []Subject{subject}, dir, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := measurement.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ResultKind != Measurement {
		t.Fatalf("captured result kind = %d, want measurement", fingerprint.ResultKind)
	}
	code, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := code.Check(context.Background(), fingerprint, subject); err == nil {
		t.Fatal("measurement fingerprint accepted by code-result view")
	}
	if _, err := code.CheckBatch(context.Background(), map[Subject]Fingerprint{subject: fingerprint}); err == nil {
		t.Fatal("measurement fingerprint accepted by code-result batch")
	}
	reclassified := fingerprint
	reclassified.ResultKind = CodeResult
	if _, err := engine.Check(context.Background(), reclassified, subject, dir); err == nil {
		t.Fatal("measurement guards accepted after result-kind reclassification")
	}
	fingerprint.ResultKind = 0
	if _, err := engine.Check(context.Background(), fingerprint, subject, dir); err == nil {
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The producer view remains the immutable pre-run observation.
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("frozen producer view = {%s %q}, want valid", verdict.Status, verdict.Reason)
	}
	if err := view.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate after source edit = %v, want ErrViewChanged", err)
	} else if !strings.Contains(err.Error(), "changed ") || !strings.Contains(err.Error(), "view.go") {
		t.Fatalf("drift refusal does not name the moved file: %v", err)
	}
	verdict, err = engine.Check(context.Background(), fingerprint, subject, dir)
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
	view, err := engine.NewView(context.Background(), []Subject{{Package: "example.com/view", Symbol: "F"}}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), goMod("dep-b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := view.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate after source identity change = %v, want ErrViewChanged", err)
	} else if !strings.Contains(err.Error(), "moved: ") ||
		!strings.Contains(err.Error(), "dep-a") || !strings.Contains(err.Error(), "dep-b") {
		t.Fatalf("identity-change refusal does not name the swapped identities: %v", err)
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
	if _, err := engine.NewView(context.Background(), []Subject{subject}, dir); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("NewView during source change = %v, want ErrViewChanged", err)
	}
}

// TestConstructionDriftNamesTheChangedFile pins content-change attribution:
// a mid-construction edit that keeps the source membership identical is
// named through the per-file digests the closure's own reads produced —
// "changed <path>", never a bare refusal.
func TestConstructionDriftNamesTheChangedFile(t *testing.T) {
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
	_, err = engine.NewView(context.Background(), []Subject{subject}, dir)
	if !errors.Is(err, ErrViewChanged) {
		t.Fatalf("NewView during source change = %v, want ErrViewChanged", err)
	}
	if !strings.Contains(err.Error(), "changed ") || !strings.Contains(err.Error(), "view.go") {
		t.Fatalf("construction drift does not name the changed file: %v", err)
	}
}

// TestConstructionDriftNamesTheChangedCompartmentFile pins content-change
// attribution over the test-variant compartment: a mid-construction edit of
// a test-only file is named through the digests the compartment computation
// itself produced, exactly like a core member.
func TestConstructionDriftNamesTheChangedCompartmentFile(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	if err := os.WriteFile(filepath.Join(dir, "extra_test.go"), []byte("package view\n\nimport \"testing\"\n\nfunc TestExtra(t *testing.T) { _ = F() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	var change sync.Once
	engine, err := New(
		WithDir(dir),
		WithAssumePure(func(Subject) bool {
			change.Do(func() {
				if err := os.WriteFile(filepath.Join(dir, "extra_test.go"), []byte("package view\n\nimport \"testing\"\n\nfunc TestExtra(t *testing.T) { _ = F() + 1 }\n"), 0o644); err != nil {
					t.Error(err)
				}
			})
			return false
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.NewView(context.Background(), []Subject{subject}, dir)
	if !errors.Is(err, ErrViewChanged) {
		t.Fatalf("NewView during compartment change = %v, want ErrViewChanged", err)
	}
	if !strings.Contains(err.Error(), "changed ") || !strings.Contains(err.Error(), "extra_test.go") {
		t.Fatalf("compartment drift does not name the changed file: %v", err)
	}
}

func TestViewDetectsAddedInitializer(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nvar Value int\nfunc F() int { return Value }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "init.go"), []byte("package view\n\nfunc init() { Value = 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := view.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("promoted pure method = %+v, want valid", verdict)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nimport \"os\"\n\ntype Inner struct{}\n\n//gofresh:pure\nfunc (Inner) M() { _, _ = os.ReadFile(\"fixture\") }\n\ntype Outer struct{ *Inner }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err = current.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" {
		t.Fatalf("promoting type edit = %+v, want stale closure", verdict)
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.PurityAssertion != "source directive" {
		t.Fatalf("imported promoted purity = %q, want source directive", fingerprint.PurityAssertion)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("imported promoted purity verdict = %+v, want valid", verdict)
	}
}

// An external-test twin's directive must never confer purity on the
// production declaration it collides with: the collapsed identity refuses
// capture — unverifiable evidence naming both declarations, no purity
// attribution — while the view itself builds (the refusal is scoped to
// the subject, REQ-purity-directive).
func TestExternalTestSubjectCollisionRefusesCaptureSubjectLocally(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\nfunc F() { _, _ = os.ReadFile(\"fixture\") }\n")
	if err := os.WriteFile(filepath.Join(dir, "external_test.go"), []byte("package view_test\n\n//gofresh:pure\nfunc F() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatalf("subject-local collision failed the whole view: %v", err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.PurityAssertion != "" {
		t.Fatalf("external twin's directive conferred purity on the collapsed identity: %q", fingerprint.PurityAssertion)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "ambiguous") {
		t.Fatalf("collapsed identity verdict = %+v, want unverifiable naming the collision", verdict)
	}
}

func TestSourcePurityRemainsPortableWhenProducerAlsoAsserts(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\n//gofresh:pure\nfunc F() { _, _ = os.ReadFile(\"fixture\") }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	producer, err := New(WithDir(dir), WithAssumePure(func(candidate Subject) bool { return candidate == subject }))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.Capture(context.Background(), subject, dir)
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
	verdict, err := consumer.Check(context.Background(), fingerprint, subject, dir)
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
	fingerprint, err := producer.Capture(context.Background(), subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.PurityAssertion = "corrupt"
	consumer, err := New(WithDir(dir), WithAssumePure(func(candidate Subject) bool { return candidate == subject }))
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := consumer.Check(context.Background(), fingerprint, subject, dir)
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable {
		t.Fatalf("generic callback verdict = %+v, want unverifiable", verdict)
	}
}

func TestMutableCallbackGlobalIsCallerSuppliedUnverifiable(t *testing.T) {
	// Rebind mutates the callback global outside initialization, making
	// it process-shared dynamic state (REQ-closure-shared-dynamic-state).
	dir := writeViewModule(t, "package view\n\nvar Callback = func() {}\n\nfunc F() { Callback() }\n\nfunc Rebind(f func()) { Callback = f }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") {
		t.Fatalf("mutable callback global verdict = %+v fingerprint=%+v, want the shared-dynamic-state downgrade", verdict, fingerprint)
	}
}

// A dynamic-capable global the program never mutates after
// initialization is ordinary source: the closure hashes its
// initializer, and the subject checks valid instead of downgrading
// (REQ-closure-shared-dynamic-state).
func TestImmutableCallbackGlobalChecksValid(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nvar Callback = func() {}\n\nvar ErrSentinel = error(nil)\n\nfunc F() { Callback() }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("immutable callback global verdict = %+v, want valid", verdict)
	}
}

func TestMutableCallbackGlobalFromDependencyPropagates(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"example.com/view/dep\"\n\nfunc F() { dep.Run() }\n")
	if err := os.Mkdir(filepath.Join(dir, "dep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dep", "dep.go"), []byte("package dep\n\nvar Hook = func() {}\n\nfunc Run() { Hook() }\n\nfunc SetHook(f func()) { Hook = f }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") {
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("ordinary test harness verdict = %+v, want valid", verdict)
	}
}

// A standard-interface call devirtualized onto its resolved concrete target
// is classified by that target, not widened: the observation proof names the
// resolved testing.TempDir effect.
func TestResolvedStandardInterfaceTargetIsClassified(t *testing.T) {
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "testing.TempDir") {
		t.Fatalf("resolved standard interface target = %+v, want testing.TempDir named", fingerprint.ObservationProof)
	}
}

func TestUnauditedStandardOperationIsUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"time\"\n\nfunc F() int64 { return time.Now().UnixNano() }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "time") {
		t.Fatalf("time.Now verdict = %+v, want unverifiable naming time", verdict)
	}
	// The precise classification lives in the observation proof.
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "unaudited standard operation time.Now") {
		t.Fatalf("time.Now proof = %+v, want unaudited-standard classification", fingerprint.ObservationProof)
	}
}

func TestRuntimeBackedSyncOperationIsUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"sync\"\n\nfunc F() any { var pool sync.Pool; pool.Put(1); return pool.Get() }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "sync") {
		t.Fatalf("sync.Pool verdict = %+v, want unverifiable naming sync", verdict)
	}
}

// A callback handed to a standard-library operation is classified by its
// resolved target — the observation proof names os.Getenv — never widened
// into a blanket refusal.
func TestExternalCallbackFromStandardLibraryIsClassified(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport (\"os\"; \"regexp\")\n\nfunc F() string { return regexp.MustCompile(\".\").ReplaceAllStringFunc(\"X\", os.Getenv) }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "os.Getenv") {
		t.Fatalf("standard-library external callback = %+v, want os.Getenv named", fingerprint.ObservationProof)
	}
}

func TestRuntimeAddressExposureIsUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"reflect\"\n\nfunc F() uintptr { value := 0; return reflect.ValueOf(&value).Pointer() }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reflect") {
		t.Fatalf("reflect.Pointer verdict = %+v, want unverifiable naming reflect", verdict)
	}
}

func TestUnsafePointerAddressInputIsUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"unsafe\"\n\nvar Address uintptr\nfunc F() byte { return *(*byte)(unsafe.Pointer(Address)) }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "unsafe") {
		t.Fatalf("unsafe pointer verdict = %+v, want unverifiable naming unsafe", verdict)
	}
}

func TestCPUDispatchedMathIsUnverifiableForCodeResult(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"math\"\n\nfunc F() uint64 { return math.Float64bits(math.Exp(1.25)) }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "math") {
		t.Fatalf("math.Exp verdict = %+v, want unverifiable naming math", verdict)
	}
}

func TestStandardGlobalStateIsUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\nfunc F() int { return len(os.Args) }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "os") {
		t.Fatalf("os.Args verdict = %+v, want unverifiable naming os", verdict)
	}
	// The precise classification lives in the observation proof.
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "unaudited standard operation os.Args") {
		t.Fatalf("os.Args proof = %+v, want os.Args classification", fingerprint.ObservationProof)
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, ".")
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

func TestFormattedReaderInputIsUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport (\"fmt\"; \"os\")\n\nfunc F() int { var value int; _, _ = fmt.Fscan(os.Stdin, &value); return value }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "fmt.Fscan") {
		t.Fatalf("fmt.Fscan verdict = %+v, want formatted-input unverifiable", verdict)
	}
}

func TestBenchmarkIterationCountIsUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n")
	if err := os.WriteFile(filepath.Join(dir, "benchmark_test.go"), []byte("package view\n\nimport \"testing\"\n\nfunc BenchmarkF(b *testing.B) { _ = b.N }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "BenchmarkF"}
	view, err := engine.NewViewFor(context.Background(), []Subject{subject}, dir, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "test runtime configuration") {
		t.Fatalf("benchmark iteration verdict = %+v, want test-runtime unverifiable", verdict)
	}
	// The proof carries the same classification.
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "testing.N (test runtime configuration)") {
		t.Fatalf("benchmark iteration proof = %+v, want test-runtime classification", fingerprint.ObservationProof)
	}
}

// Non-standard assembly is opaque to the observation proof: the package is
// never scanned — even a body of resolved instructions refuses — so
// runtime-dependent instructions can never slip through unaudited.
func TestNonStandardAssemblyBlocksObservationProof(t *testing.T) {
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "non-toolchain assembly") {
		t.Fatalf("non-standard assembly proof = %+v, want refused naming the non-toolchain assembly", fingerprint.ObservationProof)
	}
}

// An opaque system object is permanently unauditable: the subject checks
// unverifiable with the system object named.
func TestSystemObjectRemainsOpaque(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	if err := os.WriteFile(filepath.Join(dir, "view.syso"), []byte("opaque system object"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "system object") {
		t.Fatalf("system-object verdict = %+v, want unverifiable naming the system object", verdict)
	}
	if fingerprint.ObservationProof.Observable {
		t.Fatalf("system-object proof = %+v, want refused", fingerprint.ObservationProof)
	}
}

func TestExternalStandardLinknameTargetBlocksObservationProof(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport _ \"unsafe\"\n\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n\nfunc F() int64 { return nanotime() }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ObservationProof.Observable {
		t.Fatalf("standard linkname proof = %+v, want refused", fingerprint.ObservationProof)
	}
}

// A production function named TestMain is an ordinary subject: the
// observability analysis roots it instead of refusing it as harness setup.
func TestProductionFunctionNamedTestMainIsAnalyzable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc TestMain() {}\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "TestMain"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatalf("production TestMain was not analyzable: %v", err)
	}
	if strings.Contains(fingerprint.ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("production TestMain was not rootable: %+v", fingerprint.ObservationProof)
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.ObservationProof.Observable {
		t.Fatalf("production TestMain contaminated test subject: %+v", fingerprint.ObservationProof)
	}
}

func TestBatchMarksRuntimeInputDriftStale(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
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
	stateA, err := runtimeinput.FromTestLog([]byte("open a\n"), dir, dir, runtimeinput.WithCompletedProcess("worker-a"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	stateB, err := runtimeinput.FromTestLog([]byte("open b\n"), dir, dir, runtimeinput.WithCompletedProcess("worker-b"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := view.Check(context.Background(), fingerprint, subject); !errors.Is(err, ErrViewChanged) {
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
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
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
	verdict, err := view.Check(context.Background(), fingerprint, subject)
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
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
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
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	current, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := current.Check(ctx, fingerprint, subject); !errors.Is(err, context.Canceled) {
		t.Fatalf("Check under cancelled context = %v, want context.Canceled", err)
	}
	verdict, err := current.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("unchanged runtime check = %+v, want valid", verdict)
	}
}

// A deferred-close engine's checks skip the per-check closing base
// observation and return provisional verdicts; the view's validation is
// the one close (REQ-fresh-coherent-view's deferred close). The default
// engine pays each check's own close and refuses an edit itself; the
// deferred engine's check serves the provisional verdict and the same
// edit refuses at validation, discarding it.
func TestDeferredCheckCloseCollapsesBaseObservationsIntoValidation(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\nfunc G() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := Subject{Package: "example.com/view", Symbol: "F"}
	g := Subject{Package: "example.com/view", Symbol: "G"}
	producerEngine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := producerEngine.NewView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[Subject]Fingerprint{}
	for _, subject := range []Subject{f, g} {
		fingerprint, err := producer.Capture(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint.RuntimeInputs = state.Manifest
		fingerprint.RuntimeDigest = state.Digest
		recorded[subject] = fingerprint
	}

	deferredEngine, err := New(WithDir(dir), WithDeferredCheckClose())
	if err != nil {
		t.Fatal(err)
	}
	deferredView, err := deferredEngine.NewView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	defaultView, err := producerEngine.NewView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}

	// On a quiescent tree, the default check pays exactly its one closing
	// base observation and the deferred check pays none; both serve the
	// same valid verdicts.
	observations := 0
	viewTestHooks.observe = func() { observations++ }
	t.Cleanup(func() { viewTestHooks.observe = nil })
	defaultVerdicts, err := defaultView.CheckBatch(context.Background(), recorded)
	if err != nil {
		t.Fatal(err)
	}
	defaultPasses := observations
	observations = 0
	deferredVerdicts, err := deferredView.CheckBatch(context.Background(), recorded)
	if err != nil {
		t.Fatal(err)
	}
	deferredPasses := observations
	viewTestHooks.observe = nil
	if defaultPasses != 1 || deferredPasses != 0 {
		t.Fatalf("closing base observations: default = %d, deferred = %d; want 1 and 0", defaultPasses, deferredPasses)
	}
	for _, subject := range []Subject{f, g} {
		if defaultVerdicts[subject].Status != Valid || deferredVerdicts[subject].Status != Valid {
			t.Fatalf("quiescent verdicts: default %+v, deferred %+v, want both valid", defaultVerdicts[subject], deferredVerdicts[subject])
		}
	}
	// The observed check path defers identically: an observed-class
	// recording's check pays the one closing base observation by default
	// and none under the deferred engine.
	obsProducer, err := producerEngine.NewView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	observedRecorded := map[Subject]Fingerprint{}
	for _, subject := range []Subject{f, g} {
		fingerprint, err := obsProducer.CaptureObserved(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint.RuntimeInputs = state.Manifest
		fingerprint.RuntimeDigest = state.Digest
		observedRecorded[subject] = fingerprint
	}
	observations = 0
	viewTestHooks.observe = func() { observations++ }
	if _, err := defaultView.CheckObservedBatch(context.Background(), observedRecorded); err != nil {
		t.Fatal(err)
	}
	defaultObservedPasses := observations
	observations = 0
	if _, err := deferredView.CheckObservedBatch(context.Background(), observedRecorded); err != nil {
		t.Fatal(err)
	}
	deferredObservedPasses := observations
	viewTestHooks.observe = nil
	if defaultObservedPasses != 1 || deferredObservedPasses != 0 {
		t.Fatalf("observed closing base observations: default = %d, deferred = %d; want 1 and 0", defaultObservedPasses, deferredObservedPasses)
	}

	// The deferred view's one close: validation on the unchanged tree
	// succeeds with a single comparison observation, so the provisional
	// verdicts of both check classes stand at the cost of one pass.
	observations = 0
	viewTestHooks.observe = func() { observations++ }
	if err := deferredView.Validate(context.Background()); err != nil {
		t.Fatalf("deferred close on an unchanged tree: %v", err)
	}
	viewTestHooks.observe = nil
	if observations != 1 {
		t.Fatalf("the deferred close cost %d observations, want 1 — validation's one comparison observation closes every deferred interval", observations)
	}

	// An edit after construction: the default check's own close refuses;
	// the deferred check serves provisionally and the refusal lands at
	// validation, discarding the verdicts with it.
	editedDeferred, err := deferredEngine.NewView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	editedDefault, err := producerEngine.NewView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 1 }\nfunc G() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := editedDefault.CheckBatch(context.Background(), recorded); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("default check across an edit = %v, want ErrViewChanged at the check's own close", err)
	}
	provisional, err := editedDeferred.CheckBatch(context.Background(), recorded)
	if err != nil {
		t.Fatalf("deferred check across an edit = %v, want provisional verdicts", err)
	}
	if provisional[f].Status != Valid {
		t.Fatalf("provisional verdict = %+v, want valid pending the deferred close", provisional[f])
	}
	if err := editedDeferred.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("deferred close across an edit = %v, want ErrViewChanged discarding the provisional verdicts", err)
	}
}

func TestCheckBatchHonorsCancellationDuringRuntimeObservation(t *testing.T) {
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
	producer, err := engine.NewView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[Subject]Fingerprint{}
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []Subject{f, g} {
		fingerprint, err := producer.Capture(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint.RuntimeInputs = state.Manifest
		fingerprint.RuntimeDigest = state.Digest
		recorded[subject] = fingerprint
	}
	current, err := engine.NewView(context.Background(), []Subject{f, g}, dir)
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
	if _, err := current.CheckBatch(ctx, recorded); !errors.Is(err, context.Canceled) {
		t.Fatalf("CheckBatch cancelled during runtime observation = %v, want context.Canceled", err)
	}
	if observations != 1 {
		t.Fatalf("runtime observations after mid-observation cancel = %d, want 1", observations)
	}
}

func TestCaptureObservedBatchReturnsContextErrorAtAnalysisBoundary(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Cancellation injected exactly when the proof analysis begins must
	// surface as the context error, never as fingerprints from a partially
	// cancelled analysis.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	view.beforePreciseAnalysis = cancel
	if _, err := view.CaptureObservedBatch(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("CaptureObservedBatch cancelled at the analysis boundary = %v, want context.Canceled", err)
	}
}

// Check decides from recorded evidence alone — no check surface runs precise
// analysis. Unchanged evidence answers valid, a failing known guard reports
// its own staleness, and any maximal drift is stale "closure" unconditionally:
// there is no precise-analysis rescue of a drifted core
// (REQ-fresh-hierarchical-check).
func TestCheckDecidesFromRecordedEvidenceWithoutPreciseAnalysis(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\nfunc G() int { return 2 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}

	unchanged, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	analyses := 0
	unchanged.beforePreciseAnalysis = func() { analyses++ }
	verdict, err := unchanged.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid || analyses != 0 {
		t.Fatalf("unchanged check = %+v with %d analyses, want valid without analysis", verdict, analyses)
	}
	guardDrift := fingerprint
	guardDrift.Guards.BuildConfig = "different"
	verdict, err = unchanged.Check(context.Background(), guardDrift, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "buildconfig" || analyses != 0 {
		t.Fatalf("failed known guard = %+v with %d analyses, want stale buildconfig without analysis", verdict, analyses)
	}

	// A sibling edit that does not touch F's body still moves the maximal
	// closure: stale "closure", with no analysis attempting a rescue.
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 1 }\nfunc G() int { return 3 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	analyses = 0
	current.beforePreciseAnalysis = func() { analyses++ }
	verdict, err = current.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" || analyses != 0 {
		t.Fatalf("drifted check = %+v with %d analyses, want stale closure without analysis", verdict, analyses)
	}
}

// A cancelled caller context refuses an observed capture before any work.
func TestObservedCaptureHonorsCancelledContext(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := view.CaptureObserved(ctx, subject); !errors.Is(err, context.Canceled) {
		t.Fatalf("CaptureObserved under cancelled context = %v, want context.Canceled", err)
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
	_, err = engine.NewView(ctx, []Subject{subject}, dir)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled view construction = %v, want context.Canceled", err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.Check(ctx, fingerprint, subject); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled view check = %v, want context.Canceled", err)
	}
	stale := fingerprint
	stale.MaximalClosure = "moved"
	publicationCtx := &cancelAfterChecks{Context: context.Background(), after: 1}
	if _, err := view.Check(publicationCtx, stale, subject); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled verdict publication = %v, want context.Canceled", err)
	}
	current, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	comparisonCtx := &cancelAfterChecks{Context: context.Background(), after: 2}
	if err := view.compareBaseContext(comparisonCtx, current); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled base comparison = %v, want context.Canceled", err)
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
		_, err := view.Check(runtimeCtx, runtimeFingerprint, subject)
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
	if err := view.Validate(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled view validation = %v, want context.Canceled", err)
	}
	if _, err := view.Capture(context.Background(), subject); !errors.Is(err, ErrViewSealed) {
		t.Fatalf("capture after cancelled validation = %v, want ErrViewSealed", err)
	}
}

func TestObservedCaptureRejectsDriftSinceViewConstruction(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := view.CaptureObserved(context.Background(), subject); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("CaptureObserved after drift = %v, want ErrViewChanged", err)
	}
}

func TestObservedCaptureRejectsGuardDriftSinceViewConstruction(t *testing.T) {
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
	view, err := engine.NewViewFor(context.Background(), []Subject{subject}, dir, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goenv, []byte("GOFLAGS=-tags=second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := view.CaptureObserved(context.Background(), subject); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("CaptureObserved after guard drift = %v, want ErrViewChanged", err)
	}
}

func TestCancelledObservedCaptureDoesNotWaitForViewLock(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	view.mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := view.CaptureObserved(ctx, subject)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled observed capture error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		view.mu.Unlock()
		t.Fatal("cancelled observed capture waited for the view lock")
	}
	view.mu.Unlock()
}

func TestObservedCaptureDoesNotPublishAfterCancellationWhileWaitingForLock(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Warm the proof analysis so the second capture reaches the lock wait.
	if _, err := view.CaptureObserved(context.Background(), subject); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	view.mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := view.CaptureObserved(ctx, subject)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	view.mu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("capture after lock-wait cancellation = %v, want context.Canceled", err)
	}
}

func TestValidateReobservesPurityAfterAnalysis(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	// The purity assertion flips during Validate's final re-observation
	// and nowhere earlier. Observation count to that point: view
	// construction pair 2, observed capture bracket close 1, validation's
	// seeded read 1 - so the flip lands on observation 5, the validation
	// analysis bracket's closing observation.
	calls := 0
	engine, err := New(
		WithDir(dir),
		WithAssumePure(func(Subject) bool {
			calls++
			return calls > 4
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtimeinput.FromTestLog(nil, dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.AttachObservation(subject, fingerprint, observation); err != nil {
		t.Fatal(err)
	}
	if err := view.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate after purity drift = %v, want ErrViewChanged", err)
	}
}

func TestValidationSealsViewAgainstLaterCapture(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := view.Capture(context.Background(), subject); !errors.Is(err, ErrViewSealed) {
		t.Fatalf("capture after validation = %v, want ErrViewSealed", err)
	}
	observedView, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := observedView.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := observedView.CaptureObserved(context.Background(), subject); !errors.Is(err, ErrViewSealed) {
		t.Fatalf("observed capture after validation = %v, want ErrViewSealed", err)
	}
}

// A capture whose proof analysis is already in flight when validation seals
// the view must refuse at its publication boundary, never publish into a
// sealed view.
func TestValidationSealsConcurrentObservedPublication(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	view.beforePreciseAnalysis = func() {
		close(ready)
		<-release
	}
	go func() {
		_, err := view.CaptureObserved(context.Background(), subject)
		done <- err
	}()
	select {
	case <-ready:
	case <-time.After(30 * time.Second):
		t.Fatal("observed capture did not reach the analysis boundary")
	}
	if err := view.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrViewSealed) {
		t.Fatalf("concurrent capture after validation = %v, want ErrViewSealed", err)
	}
}

func TestObservedCaptureIsConcurrentSafe(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
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
			fingerprint, err := view.CaptureObserved(context.Background(), subject)
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

// An observation proof is bound to the subject it was computed for: a record
// carrying a sibling's proof — even with internally consistent evidence — is
// never served through the observation lift.
func TestObservationProofBindsSubjectIdentity(t *testing.T) {
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	current, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	intact, err := current.CheckObserved(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if intact.Status != Valid {
		t.Fatalf("intact observed record = %+v, want valid through the lift", intact)
	}
	// Rebind the proof to a sibling identity and re-derive its evidence so
	// only the subject binding — not the evidence hash — discriminates.
	spliced := fingerprint
	spliced.ObservationProof.Subject = Subject{Package: "example.com/observed", Symbol: "Sibling"}
	spliced.ObservationProof.Evidence = observationProofEvidence(spliced.MaximalClosure, spliced.ObservationAssertion, spliced.ObservationProof)
	verdict, err := current.CheckObserved(context.Background(), spliced, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status == Valid {
		t.Fatalf("record carrying a sibling's proof = %+v, want the lift denied", verdict)
	}
}

func TestCheckObservedBatchMatchesSingleChecks(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":             "module example.com/batch\n\ngo 1.26\n",
		"a/a.go":             "package a\n\nfunc F() int { return 1 }\n",
		"b/b.go":             "package b\n\nfunc H() int { return 2 }\n",
		"b/observed_test.go": "package b\n\nimport (\"os\"; \"testing\")\n\nfunc TestRead(*testing.T) { _, _ = os.ReadFile(\"fixture\") }\n",
		"b/fixture":          "one",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	aF := Subject{Package: "example.com/batch/a", Symbol: "F"}
	bRead := Subject{Package: "example.com/batch/b", Symbol: "TestRead"}
	bH := Subject{Package: "example.com/batch/b", Symbol: "H"}
	subjects := []Subject{aF, bRead, bH}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	captured := map[Subject]Fingerprint{}
	for _, subject := range subjects {
		fingerprint, err := producer.CaptureObserved(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		captured[subject] = fingerprint
	}
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), filepath.Join(dir, "b"), dir, runtimeinput.WithCompletedProcess("b test"), runtimeinput.WithBracket(testObservationBracket(t, filepath.Join(dir, "b"), ".", filepath.Join(dir, "fixture"))))
	if err != nil {
		t.Fatal(err)
	}
	withRuntime := captured[bRead]
	withRuntime.RuntimeInputs = state.Manifest
	withRuntime.RuntimeDigest = state.Digest
	captured[bRead] = withRuntime

	// The batch mixes disposition classes: a verifiable subject in a pure
	// package, an unverifiable subject served through its observation lift,
	// and an unverifiable sibling with no lift evidence.
	singleView, err := engine.NewView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	batchView, err := engine.NewView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	rounds := []map[Subject]Fingerprint{
		{aF: captured[aF], bRead: captured[bRead], bH: captured[bH]},
	}
	// Tampering the lift-bearing record pins proof denial changing a verdict:
	// intact evidence serves this subject valid through its observation lift.
	tampered := captured[bRead]
	tampered.ObservationProof.Evidence = "tampered"
	guardDrift := captured[aF]
	guardDrift.Guards.BuildConfig = "different"
	maximalOnly := captured[bH]
	maximalOnly.ObservationAssertion = ""
	maximalOnly.ObservationProof = ObservationProof{}
	rounds = append(rounds, map[Subject]Fingerprint{aF: guardDrift, bRead: tampered, bH: maximalOnly})

	observations := 0
	viewTestHooks.observe = func() { observations++ }
	t.Cleanup(func() { viewTestHooks.observe = nil })
	for i, recorded := range rounds {
		singles := map[Subject]Verdict{}
		for subject, fingerprint := range recorded {
			verdict, err := singleView.CheckObserved(context.Background(), fingerprint, subject)
			if err != nil {
				t.Fatal(err)
			}
			singles[subject] = verdict
		}
		observations = 0
		batch, err := batchView.CheckObservedBatch(context.Background(), recorded)
		if err != nil {
			t.Fatal(err)
		}
		for subject := range recorded {
			if batch[subject] != singles[subject] {
				t.Fatalf("round %d: batch verdict for %s.%s = %+v, single = %+v", i, subject.Package, subject.Symbol, batch[subject], singles[subject])
			}
		}
		if i == 0 {
			// The first round genuinely exercises every disposition class:
			// the verifiable subject answers valid, the unverifiable subject
			// is served valid through its observation lift, and the sibling
			// without lift evidence answers unverifiable.
			if singles[aF].Status != Valid {
				t.Fatalf("verifiable subject = %+v, want valid", singles[aF])
			}
			if singles[bRead].Status != Valid {
				t.Fatalf("lift-served observed subject = %+v, want valid", singles[bRead])
			}
			if singles[bH].Status != Unverifiable {
				t.Fatalf("liftless unverifiable subject = %+v, want unverifiable", singles[bH])
			}
			if observations != 1 {
				t.Fatalf("batched observed check performed %d observations, want 1", observations)
			}
		}
		if i == 1 {
			if singles[bRead].Status != Unverifiable {
				t.Fatalf("tampered lift-bearing record = %+v, want unverifiable", singles[bRead])
			}
			if singles[aF].Status != Stale || singles[aF].Reason != "buildconfig" {
				t.Fatalf("guard-drifted record = %+v, want stale buildconfig", singles[aF])
			}
		}
	}

	// An all-unchanged manifest-less batch answers without observations or
	// precise analysis, and a cancelled caller context aborts the batch.
	viewTestHooks.observe = nil
	quietView, err := engine.NewView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	observations = 0
	analyses := 0
	viewTestHooks.observe = func() { observations++ }
	t.Cleanup(func() { viewTestHooks.observe = nil })
	quietView.beforePreciseAnalysis = func() { analyses++ }
	quiet, err := quietView.CheckObservedBatch(context.Background(), map[Subject]Fingerprint{aF: captured[aF]})
	if err != nil {
		t.Fatal(err)
	}
	if quiet[aF].Status != Valid || observations != 0 || analyses != 0 {
		t.Fatalf("all-unchanged batch = %+v with %d observations and %d analyses, want valid with none", quiet[aF], observations, analyses)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := quietView.CheckObservedBatch(cancelled, map[Subject]Fingerprint{aF: captured[aF]}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled observed batch = %v, want context.Canceled", err)
	}
	// Evidence-only staleness — even with a runtime manifest attached — is
	// decided without opening the observation window.
	earlyStale := captured[bRead]
	earlyStale.MaximalClosure = ""
	earlyStale.RuntimeInputs = state.Manifest
	earlyStale.RuntimeDigest = state.Digest
	observations = 0
	early, err := quietView.CheckObservedBatch(context.Background(), map[Subject]Fingerprint{bRead: earlyStale})
	if err != nil {
		t.Fatal(err)
	}
	if got := early[bRead]; got.Status != Stale || got.Reason != "closure" || observations != 0 {
		t.Fatalf("early-stale record = %+v with %d observations, want stale closure with none", got, observations)
	}
}

func TestCheckObservedBatchMarksMovingRuntimeInputStale(t *testing.T) {
	// The undrifted finish must re-observe the runtime window and stale a
	// record whose runtime input moved mid-check even when the before state
	// agreed with the recording. The drifted case pins evidence-only
	// staleness deciding before the window: a drifted core is stale
	// "closure" regardless of window movement. The guard-drift case
	// additionally pins one window semantics across the single and batch
	// forms: an already-stale verdict is not overridden by window movement,
	// in either form.
	for _, scenario := range []string{"unchanged", "drifted", "guard drift"} {
		t.Run(scenario, func(t *testing.T) {
			drift := scenario == "drifted"
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
			producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint, err := producer.CaptureObserved(context.Background(), subject)
			if err != nil {
				t.Fatal(err)
			}
			state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
			if err != nil {
				t.Fatal(err)
			}
			fingerprint.RuntimeInputs = state.Manifest
			fingerprint.RuntimeDigest = state.Digest
			if drift {
				if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() {}\nfunc G() {}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want := Verdict{Stale, "runtimeinputs"}
			if drift {
				want = Verdict{Stale, "closure"}
			}
			if scenario == "guard drift" {
				fingerprint.Guards.BuildConfig = "different"
				want = Verdict{Stale, "buildconfig"}
			}
			movingRuntime := func(v *View) {
				calls := 0
				v.runtimeCurrent = func(ctx context.Context, encoded, moduleDir string) (runtimeinput.State, error) {
					calls++
					if calls == 1 {
						return runtimeinput.CurrentContext(ctx, encoded, moduleDir)
					}
					return runtimeinput.State{}, nil
				}
			}
			current, err := engine.NewView(context.Background(), []Subject{subject}, dir)
			if err != nil {
				t.Fatal(err)
			}
			movingRuntime(current)
			verdicts, err := current.CheckObservedBatch(context.Background(), map[Subject]Fingerprint{subject: fingerprint})
			if err != nil {
				t.Fatal(err)
			}
			if verdicts[subject] != want {
				t.Fatalf("moving runtime input in observed batch = %+v, want %+v", verdicts[subject], want)
			}
			singleView, err := engine.NewView(context.Background(), []Subject{subject}, dir)
			if err != nil {
				t.Fatal(err)
			}
			movingRuntime(singleView)
			single, err := singleView.CheckObserved(context.Background(), fingerprint, subject)
			if err != nil {
				t.Fatal(err)
			}
			if single != verdicts[subject] {
				t.Fatalf("single verdict %+v diverges from batch %+v under a moving window", single, verdicts[subject])
			}
		})
	}
}

func TestAnalysisBudgetExhaustionYieldsUnavailableEvidence(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	budgeted, err := New(WithDir(dir), WithAnalysisBudget(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	// Capture under an exhausted budget still lands a fingerprint carrying an
	// unavailable proof — never an operation error while the caller's context
	// is live, and never observable evidence.
	captureView, err := budgeted.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := captureView.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("budget-exhausted capture proof = %+v, want unavailable disposition", fingerprint.ObservationProof)
	}
}

func TestValidationComparesObservationProofsByAvailabilityClass(t *testing.T) {
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	analyzed := closure.Observability{Observable: true}
	rejected := closure.Observability{Reason: "startup effect: external dependence"}
	unavailableA := closure.Observability{Reason: "observation analysis unavailable: analysis budget exhausted"}
	unavailableB := closure.Observability{Reason: "observation analysis unavailable: load failed"}
	if err := compareObservationProof(subject, unavailableA, analyzed); !errors.Is(err, ErrAnalysisUnavailable) {
		t.Fatalf("unavailable re-establishment of an analyzed proof = %v, want ErrAnalysisUnavailable", err)
	}
	if err := compareObservationProof(subject, unavailableA, unavailableB); err != nil {
		t.Fatalf("two unavailable dispositions with different error text = %v, want consistent", err)
	}
	if err := compareObservationProof(subject, analyzed, unavailableA); err != nil {
		t.Fatalf("unavailable captured proof against current analyzed = %v, want consistent (the recording confers nothing)", err)
	}
	if err := compareObservationProof(subject, rejected, analyzed); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("analyzed dispositions differing = %v, want ErrViewChanged", err)
	}
	if err := compareObservationProof(subject, analyzed, analyzed); err != nil {
		t.Fatalf("identical analyzed dispositions = %v, want consistent", err)
	}
}

func TestBudgetedProducerValidatesUnavailableProof(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir), WithAnalysisBudget(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fingerprint.ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("budgeted capture proof = %+v, want unavailable disposition", fingerprint.ObservationProof)
	}
	observation, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer.AttachObservation(subject, fingerprint, observation); err != nil {
		t.Fatal(err)
	}
	// The captured proof is unavailable, so validation re-establishes it by
	// class regardless of where the fresh budget expires — never a spurious
	// view-changed error from mismatched error text.
	if err := producer.Validate(context.Background()); err != nil {
		t.Fatalf("budgeted validation of an unavailable proof = %v, want success", err)
	}
}

func TestProgressReportsAnalysisPhases(t *testing.T) {
	// A fresh cache: the observability memo legitimately swallows the
	// prove phase on a hit, and this test pins the fresh-analysis
	// sequence.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	var events []Progress
	engine, err := New(WithDir(dir), WithProgress(func(p Progress) { events = append(events, p) }))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	events = nil
	recorded, err := producer.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	phases := map[string]int{}
	for _, event := range events {
		phases[event.Phase]++
		switch event.Phase {
		case "load", "prove":
			if event.Package != subject.Package {
				t.Fatalf("per-package %s event names %q, want %q", event.Phase, event.Package, subject.Package)
			}
		case "observe", "runtime":
			if event.Package != "" {
				t.Fatalf("%s event names a package: %+v", event.Phase, event)
			}
		default:
			t.Fatalf("unknown progress phase %q", event.Phase)
		}
	}
	// A cold observed capture observes once - the analysis bracket opens on
	// the view's agreed facts and reads only at close - opens no runtime
	// window, loads the package program once, and proves once.
	if phases["observe"] != 1 || phases["runtime"] != 0 || phases["load"] != 1 || phases["prove"] != 1 {
		t.Fatalf("progress phases = %v, want observe:1 load:1 prove:1", phases)
	}

	// A manifest-carrying record's window reads once, at close.
	state, err := runtimeinput.FromTestLog(nil, dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	withRuntime := recorded
	withRuntime.RuntimeInputs = state.Manifest
	withRuntime.RuntimeDigest = state.Digest
	runtimeView, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	events = nil
	if _, err := runtimeView.CheckObserved(context.Background(), withRuntime, subject); err != nil {
		t.Fatal(err)
	}
	runtimeEvents := 0
	for _, event := range events {
		if event.Phase == "runtime" {
			runtimeEvents++
		}
	}
	if runtimeEvents != 2 {
		t.Fatalf("runtime-window events = %d, want 2", runtimeEvents)
	}
}

func TestDriftBracketsObserveOncePerSide(t *testing.T) {
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
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	current, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// A runtime-input check's window opens on the view's agreed facts and
	// reads only at close: one fresh observation, with drift across the
	// window still refusing there.
	observations := 0
	viewTestHooks.observe = func() { observations++ }
	t.Cleanup(func() { viewTestHooks.observe = nil })
	if _, err := current.Check(context.Background(), fingerprint, subject); err != nil {
		t.Fatal(err)
	}
	if observations != 1 {
		t.Fatalf("runtime-input check performed %d observations, want 1", observations)
	}
	// The observability analysis uses one close-only bracket: it opens on
	// the view's agreed facts and reads exactly once, at close.
	observations = 0
	if err := current.ensureObservable(context.Background(), []Subject{subject}); err != nil {
		t.Fatal(err)
	}
	if observations != 1 {
		t.Fatalf("proof analysis performed %d observations, want 1", observations)
	}
	// An already-computed proof re-observes nothing.
	observations = 0
	if err := current.ensureObservable(context.Background(), []Subject{subject}); err != nil {
		t.Fatal(err)
	}
	if observations != 0 {
		t.Fatalf("cached proof analysis performed %d observations, want 0", observations)
	}
}

// One knob redirects or disables every persistent memo class, and no
// knob position changes a verdict - the store is a cache, never a
// record (REQ-closure-observability-memo, REQ-closure-dynamic-state-memo).
func TestMemoStoreKnobIsVerdictInvariant(t *testing.T) {
	source := "package view\n\nvar Hooks = map[string]func(){\"k\": func() {}}\n\nfunc F() int { return len(Hooks) }\n"
	verdictUnder := func(t *testing.T, configure func(t *testing.T)) Status {
		t.Helper()
		configure(t)
		dir := writeViewModule(t, source)
		engine, err := New(WithDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		subject := Subject{Package: "example.com/view", Symbol: "F"}
		view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := view.Capture(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		verdict, err := view.Check(context.Background(), fingerprint, subject)
		if err != nil {
			t.Fatal(err)
		}
		return verdict.Status
	}
	restore := func(t *testing.T) {
		t.Cleanup(func() { SetMemoRoot("") })
	}
	base := verdictUnder(t, func(t *testing.T) { restore(t) })

	redirected := t.TempDir()
	got := verdictUnder(t, func(t *testing.T) {
		restore(t)
		SetMemoRoot(redirected)
	})
	if got != base {
		t.Fatalf("redirected store changed the verdict: %v vs %v", got, base)
	}

	forbidden := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", forbidden)
	got = verdictUnder(t, func(t *testing.T) {
		restore(t)
		DisableMemos()
	})
	if got != base {
		t.Fatalf("disabled store changed the verdict: %v vs %v", got, base)
	}
	if entries, err := os.ReadDir(filepath.Join(forbidden, "gofresh")); err == nil && len(entries) > 0 {
		t.Fatalf("disabled store still wrote %d user-cache entries", len(entries))
	}
}

// The redirect contains every persistent write - a pinned-dep fact scan
// lands under the redirected root, never the user cache - and a
// disabled store persists nothing while serving scan-equivalent
// results (REQ-closure-dynamic-state-memo).
func TestMemoStoreKnobContainsPersistentWrites(t *testing.T) {
	forbidden := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", forbidden)
	t.Cleanup(func() { SetMemoRoot("") })
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"
	const scope = DynamicStateStrategy + "|knob-containment|cfg"

	redirected := t.TempDir()
	SetMemoRoot(redirected)
	processFactCache = sync.Map{}
	first := runScan(t, scope, dir, pkg)
	if !first.known[Subject{Package: pkg, Symbol: "Run"}] {
		t.Fatal("scan lost the subject")
	}
	if entries, err := os.ReadDir(filepath.Join(redirected, "gofresh")); err != nil || len(entries) == 0 {
		t.Fatalf("redirected store received no memo writes: %v %v", entries, err)
	}
	if entries, err := os.ReadDir(filepath.Join(forbidden, "gofresh")); err == nil && len(entries) > 0 {
		t.Fatalf("redirect leaked %d entries into the user cache", len(entries))
	}

	countFiles := func(root string) int {
		n := 0
		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				n++
			}
			return nil
		})
		return n
	}
	before := countFiles(redirected)
	DisableMemos()
	processFactCache = sync.Map{}
	second := runScan(t, DynamicStateStrategy+"|knob-disabled|cfg", dir, pkg)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("disabled store is not scan-equivalent:\n first %+v\n second %+v", first, second)
	}
	if after := countFiles(redirected); after != before {
		t.Fatalf("disabled store still wrote: %d files before, %d after", before, after)
	}
	if entries, err := os.ReadDir(filepath.Join(forbidden, "gofresh")); err == nil && len(entries) > 0 {
		t.Fatalf("disabled store wrote %d user-cache entries", len(entries))
	}
}

// An exported registration constructor called only from package-level
// initializers - its own package's and a sibling's - proves init-only
// across the graph, and the registry mutation inside it is startup
// flow; one program-code caller anywhere poisons the proof
// (REQ-closure-shared-dynamic-state's cross-package init-only class).
func TestCrossPackageInitOnlyRegistration(t *testing.T) {
	files := map[string]string{
		"go.mod":       "module example.com/xreg\n\ngo 1.26\n",
		"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc NewKey(name string) string {\n\tHooks[name] = func() {}\n\treturn name\n}\n\nvar _ = NewKey(\"own\")\n\nfunc Count() int { return len(Hooks) }\n",
		"user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.NewKey(\"sibling\")\n\nfunc F() int { return reg.Count() }\n",
	}
	t.Run("initializer-only callers discharge", func(t *testing.T) {
		dir := writeModuleTree(t, files)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - initializer-only registration downgraded", verdict)
		}
	})
	t.Run("explicit generic instantiation discharges", func(t *testing.T) {
		generic := map[string]string{
			"go.mod":       files["go.mod"],
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc NewKey[T any](name string) string {\n\tHooks[name] = func() {}\n\treturn name\n}\n\nvar _ = NewKey[int](\"own\")\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.NewKey[string](\"sibling\")\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, generic)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - explicit instantiation read as a value reference", verdict)
		}
	})
	t.Run("nested literal in attributed function stays program code", func(t *testing.T) {
		lit := map[string]string{"go.mod": files["go.mod"], "reg/reg.go": "package reg\n\nvar Hooks = map[string]func(){}\n\nvar Run func()\n\nfunc Setup(name string) string {\n\tRun = func() { Hooks[name] = func() {} }\n\treturn name\n}\n\nfunc Count() int { return len(Hooks) }\n", "user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.Setup(\"sibling\")\n\nfunc Late() { reg.Run() }\n\nfunc F() int { return reg.Count() }\n"}
		dir := writeModuleTree(t, lit)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - a runtime-callable literal discharged with its function", verdict)
		}
	})
	t.Run("go statement in attributed function stays program code", func(t *testing.T) {
		gost := map[string]string{"go.mod": files["go.mod"], "reg/reg.go": "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc Setup(name string) string {\n\tgo func() { Hooks[name] = func() {} }()\n\treturn name\n}\n\nfunc Count() int { return len(Hooks) }\n", "user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.Setup(\"sibling\")\n\nfunc F() int { return reg.Count() }\n"}
		dir := writeModuleTree(t, gost)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - a goroutine discharged with its function", verdict)
		}
	})
	t.Run("go statement call argument stays program code", func(t *testing.T) {
		// The carrier use sits in the go statement's ARGUMENT list, not
		// nested in a function literal: only the go-statement half of the
		// interiors walk keeps it program code. The goroutine outlives
		// initialization and writes Hooks at runtime, so discharging the
		// escape with the proven function would be unsound.
		goarg := map[string]string{"go.mod": files["go.mod"], "reg/reg.go": "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc spill(m map[string]func()) { m[\"late\"] = func() {} }\n\nfunc Setup(name string) string {\n\tgo spill(Hooks)\n\treturn name\n}\n\nfunc Count() int { return len(Hooks) }\n", "user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.Setup(\"sibling\")\n\nfunc F() int { return reg.Count() }\n"}
		dir := writeModuleTree(t, goarg)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Hooks - a go-statement call argument discharged with its attributed function", verdict)
		}
	})
	t.Run("transitive chain discharges", func(t *testing.T) {
		chain := map[string]string{"go.mod": files["go.mod"], "reg/reg.go": "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc Outer(name string) string { return inner(name) }\n\nfunc inner(name string) string {\n\tHooks[name] = func() {}\n\treturn name\n}\n\nfunc Count() int { return len(Hooks) }\n", "user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.Outer(\"sibling\")\n\nfunc F() int { return reg.Count() }\n"}
		dir := writeModuleTree(t, chain)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the chain did not resolve", verdict)
		}
	})
	t.Run("unproven attributed caller poisons", func(t *testing.T) {
		unproven := map[string]string{"go.mod": files["go.mod"], "reg/reg.go": "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc Outer(name string) string { return inner(name) }\n\nfunc inner(name string) string {\n\tHooks[name] = func() {}\n\treturn name\n}\n\nfunc Count() int { return len(Hooks) }\n", "user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.Outer(\"sibling\")\n\nfunc Caller() string { return reg.Outer(\"late\") }\n\nfunc F() int { return reg.Count() }\n"}
		dir := writeModuleTree(t, unproven)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - an unproven caller resolved", verdict)
		}
	})
	t.Run("program-code caller poisons", func(t *testing.T) {
		poisoned := map[string]string{}
		for k, v := range files {
			poisoned[k] = v
		}
		poisoned["user/user.go"] = "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.NewKey(\"sibling\")\n\nfunc Late() string { return reg.NewKey(\"late\") }\n\nfunc F() int { return reg.Count() }\n"
		dir := writeModuleTree(t, poisoned)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Hooks", verdict)
		}
	})
	t.Run("value reference poisons", func(t *testing.T) {
		poisoned := map[string]string{}
		for k, v := range files {
			poisoned[k] = v
		}
		poisoned["user/user.go"] = "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.NewKey(\"sibling\")\n\nvar Ctor = reg.NewKey\n\nfunc F() int { return reg.Count() }\n"
		dir := writeModuleTree(t, poisoned)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Hooks", verdict)
		}
	})
}

// A carrier escape discharges only by proof, never by init flow - an
// alias outlives initialization in a proven function exactly as in an
// init body. The two proofs: a leak-free callee parameter (deferred to
// composition, cross-package included), and a leak-free range binding
// over the loop body (REQ-closure-shared-dynamic-state).
func TestCarrierEscapeDischarges(t *testing.T) {
	goMod := "module example.com/xesc\n\ngo 1.26\n"
	t.Run("escape through a proven function stays escaped", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nvar stash map[string]func()\n\nfunc Keep(m map[string]func()) { stash = m }\n\nfunc Seed() { Keep(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade - a retaining callee reached through a proven init-only chain aliased the registry into runtime-writable state", verdict)
		}
	})
	t.Run("return escape through a proven function stays escaped", func(t *testing.T) {
		// The carrier is returned, not argument-passed: no parameter
		// proof applies, and the alias lands in the caller's package
		// state - init flow must not launder it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc Grab() map[string]func() { return Hooks }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar G = reg.Grab()\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		// The subject sits in the declaring package: the caller package's
		// own binding additionally fails the environment audit (a call
		// result is an opaque source), and its culprit would front-run
		// the escape this leg pins.
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade - a returned alias discharged with its proven function", verdict)
		}
	})
	t.Run("leak-free consumer discharges the argument escape", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc check(m map[string]func()) {\n\tfor k := range m {\n\t\t_ = k\n\t}\n}\n\nfunc Seed() { check(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a provably leak-free consumer refused the discharge", verdict)
		}
	})
	t.Run("func-typed hook argument stays valid", func(t *testing.T) {
		// A non-alias-handing carrier cannot be rebound through an
		// argument - it must not enter the parameter deferral, whose
		// facts deliberately omit no-reach parameters and would refuse
		// the ubiquitous callback-passing shape.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hook = func() {}\n\nfunc use(f func()) {}\n\nfunc F() { use(Hook) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc G() { reg.F() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "G"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a func-typed hook argument entered the unresolvable deferral", verdict)
		}
	})
	t.Run("bare range over a carrier discharges", func(t *testing.T) {
		// A binding-free range aliases nothing.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Count() int {\n\tn := 0\n\tfor range Registry {\n\t\tn++\n\t}\n\treturn n\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a binding-free range refused", verdict)
		}
	})
	t.Run("declared local alias read discharges", func(t *testing.T) {
		// var-declared bindings track exactly like := bindings.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc peek(m map[string]func()) int {\n\tvar x = m\n\treturn len(x)\n}\n\nfunc Seed() { _ = peek(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a var-declared tracked binding refused the proof", verdict)
		}
	})
	t.Run("declared local alias write refuses", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc poke(m map[string]func()) {\n\tvar x = m\n\tx[\"k\"] = func() {}\n}\n\nfunc Seed() { poke(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want the downgrade - a write through a var-declared binding passed the proof", verdict)
		}
	})
	t.Run("deferred call argument earns the discharge", func(t *testing.T) {
		// A deferred call is synchronous at function exit - the
		// parameter proof bounds the alias exactly as a plain call's.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc check(m map[string]func()) {\n\tfor k := range m {\n\t\t_ = k\n\t}\n}\n\nfunc Seed() { defer check(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a deferred call's argument lost the parameter deferral", verdict)
		}
	})
	t.Run("aliased local read discharges", func(t *testing.T) {
		// The consumer binds the parameter to a local and reads through
		// it - the tracked binding keeps every arm, so the proof holds.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc peek(m map[string]func()) int {\n\tx := m\n\treturn len(x)\n}\n\nfunc Seed() { _ = peek(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a tracked local binding refused the proof it stays inside", verdict)
		}
	})
	t.Run("literal reading an init-local alias discharges", func(t *testing.T) {
		// The nested literal only length-reads the aliased local - the
		// read shapes apply to the alias exactly as to the carrier.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nvar Size func() int\n\nfunc init() {\n\tm := Hooks\n\tSize = func() int { return len(m) }\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a length-read through the init-local alias refused", verdict)
		}
	})
	t.Run("go statement argument keeps the escape", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc check(m map[string]func()) {\n\tfor k := range m {\n\t\t_ = k\n\t}\n}\n\nfunc Seed() { go check(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want the downgrade - a goroutine's argument earned the synchronous deferral", verdict)
		}
	})
	t.Run("unrecognized consumer use refuses", func(t *testing.T) {
		// The parameter appears only inside a composite literal - a shape
		// no enumerated arm classifies; the engine's catch-all ident
		// visit must refuse it, fail-closed.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc hold(m map[string]func()) {\n\tpair := []any{m}\n\t_ = pair\n}\n\nfunc Seed() { hold(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade - an unclassified parameter use passed the leak-free proof", verdict)
		}
	})
	t.Run("cross-package retaining callee refuses", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nvar held map[string]func()\n\nfunc Register(m map[string]func()) { held = m }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Hooks = map[string]func(){}\n\nfunc Seed() { val.Register(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade - a foreign retaining parameter discharged", verdict)
		}
	})
	t.Run("cross-package leak-free callee discharges", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nfunc Check(m map[string]func()) int { return len(m) }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Hooks = map[string]func(){}\n\nfunc Seed() { val.Check(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a foreign leak-free parameter refused the discharge", verdict)
		}
	})
	t.Run("leak-free range binding discharges the iteration", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Labels() []string {\n\tout := []string{}\n\tfor _, e := range Registry {\n\t\tout = append(out, e.Label)\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return len(reg.Labels()) }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a leak-free alias-handing range binding refused the discharge", verdict)
		}
	})
	t.Run("range binding retained beyond the loop refuses", func(t *testing.T) {
		// The binding is copied into a local declared OUTSIDE the loop
		// body - the alias survives where the loop-body arms cannot see
		// its uses, so the proof must refuse.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Last() []string {\n\tvar save entry\n\tfor _, e := range Registry {\n\t\tsave = e\n\t}\n\treturn save.Cols\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return len(reg.Last()) }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - an outside-body retention passed the loop proof", verdict)
		}
	})
	t.Run("leaking range binding keeps the escape", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Columns() []string {\n\tout := []string{}\n\tfor _, e := range Registry {\n\t\tout = append(out, e.Cols...)\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return len(reg.Columns()) }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - an alias-handing field flowed out of the loop unrefused", verdict)
		}
	})
	t.Run("func-field call through the binding discharges", func(t *testing.T) {
		// The registry-of-builders shape: the loop invokes a func-typed
		// field of the binding - the callee receives only its arguments,
		// so the binding proof holds and the pure builder composes.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc double(n int) int { return n * 2 }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: double}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(1)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a func-field call through the binding refused the discharge", verdict)
		}
	})
	t.Run("func-field call handing out the binding refuses", func(t *testing.T) {
		// The call target is fine but an argument hands the callee an
		// alias into carrier state - the argument loop must still refuse.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar Registry []entry\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: width}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a carrier alias handed to a func-field callee passed the loop proof", verdict)
		}
	})
	t.Run("plain-data builder effects stay per-process", func(t *testing.T) {
		// A registered named builder mutating a plain package variable is
		// per-process-deterministic content the whole-graph hash already
		// covers - the discharge composes Valid exactly as the identical
		// static call chain does.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar count int\n\nfunc bump(n int) int {\n\tcount += n\n\treturn count\n}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: bump}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(1)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a named builder's plain-data write refused the discharge", verdict)
		}
	})
	t.Run("non-audited method call through the binding refuses", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nfunc (e entry) Width() int { return len(e.Cols) }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Width()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a non-audited method call through the binding passed the loop proof", verdict)
		}
	})
	t.Run("capture-free literal registration discharges", func(t *testing.T) {
		// The literal references a package-level variable: not a capture -
		// its uses attribute at this site like any program code.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar scale = 2\n\nfunc init() {\n\tRegistry = append(Registry, entry{Cols: []string{\"a\"}, Build: func(n int) int { return n * scale }})\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(1)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a capture-free literal appended in init refused the audit", verdict)
		}
	})
	t.Run("sibling writer poisons a reader-only carrier", func(t *testing.T) {
		// The reader literal is leak-free over its own body, but a sibling
		// literal registered into a different carrier writes the shared
		// environment - one object however many carriers reach it, so the
		// reader's carrier refuses too.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar ReadHooks []func() string\n\nvar WriteHooks []func()\n\nfunc init() {\n\tstate := []string{\"a\"}\n\tReadHooks = []func() string{func() string { return state[0] }}\n\tWriteHooks = []func(){func() { state[0] = \"b\" }}\n}\n\nfunc Read() string {\n\tout := \"\"\n\tfor _, f := range ReadHooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Read() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.ReadHooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.ReadHooks - a sibling writer left the reader's carrier settled", verdict)
		}
	})
	t.Run("aliased environment poisons through the alias set", func(t *testing.T) {
		// A one-line alias of the captured slice hands the goroutine the
		// same backing under another name - the audit closes the alias
		// set over the enclosing body before judging.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc churn(s []string) {\n\tfor i := range s {\n\t\ts[i] = s[i] + \"!\"\n\t}\n}\n\nfunc init() {\n\tstate := []string{\"a\"}\n\talias := state\n\tgo churn(alias)\n\tHooks = []func() string{func() string { return state[0] }}\n}\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - an alias of the captured environment slipped the audit", verdict)
		}
	})
	t.Run("builtin copy registration is a judged store", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = []func() int{nil}\n\nfunc init() {\n\tcounter := 0\n\tcopy(Hooks, []func() int{func() int { counter++; return counter }})\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\tif f != nil {\n\t\t\ttotal += f()\n\t\t}\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a builtin copy smuggled a capturing closure past the audit", verdict)
		}
	})
	t.Run("init-body carrier argument earns the deferral", func(t *testing.T) {
		// The call sits directly in an init body - the exempt region -
		// and defers to the foreign parameter's leak-free fact exactly as
		// program code does.
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nfunc Check(m map[string]func()) int { return len(m) }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Hooks = map[string]func(){}\n\nvar sink int\n\nfunc init() {\n\tsink = val.Check(Hooks)\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an init-body argument to a leak-free foreign parameter refused the deferral", verdict)
		}
	})
	t.Run("init-body carrier argument to a retaining callee escapes", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nvar held map[string]func()\n\nfunc Keep(m map[string]func()) { held = m }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Hooks = map[string]func(){}\n\nfunc init() {\n\tval.Keep(Hooks)\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Hooks - an init-body handout to a retaining callee stayed exempt", verdict)
		}
	})
	t.Run("init-body carrier argument to a method escapes", func(t *testing.T) {
		// No leak-free fact exists for a method callee - the exempt
		// region's handout keeps the fail-closed escape.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype sink struct{ m map[string]func() }\n\nfunc (s *sink) Keep(m map[string]func()) { s.m = m }\n\nvar keeper sink\n\nvar Hooks = map[string]func(){}\n\nfunc init() {\n\tkeeper.Keep(Hooks)\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Hooks - an init-body handout to a method stayed exempt", verdict)
		}
	})
	t.Run("foreign self-append of a judged element discharges", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc init() {\n\treg.Hooks = append(reg.Hooks, func() string { return \"x\" })\n}\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a qualified self-append of a capture-free literal refused the audit", verdict)
		}
	})
	t.Run("foreign-carrier registration is audited by the storing package", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc init() {\n\tstate := []string{\"a\"}\n\treg.Hooks = []func() string{func() string { state[0] = \"b\"; return state[0] }}\n}\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a foreign capturing registration passed the audit", verdict)
		}
	})
	t.Run("method expression and nil registrations stay environment-free", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype calc struct{}\n\nfunc (calc) Double(n int) int { return n * 2 }\n\ntype entry struct {\n\tCols  []string\n\tBuild func(c calc, n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{\n\t\t{Cols: []string{\"a\"}, Build: calc.Double},\n\t\t{Cols: []string{\"b\"}, Build: nil},\n\t}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\tif e.Build != nil {\n\t\t\ttotal += e.Build(calc{}, 1)\n\t\t}\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a method expression or nil registration refused the audit", verdict)
		}
	})
	t.Run("mutation culprit outranks the environment culprit", func(t *testing.T) {
		// One package, two refusals: a registered literal stores into a
		// second carrier (program code - the mutation mark), and the
		// first carrier's registration is itself environment-carrying.
		// The culprit names the mutation.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Extra []func() int\n\nvar Hooks []func() int\n\nfunc init() {\n\tcounter := 0\n\tHooks = []func() int{func() int {\n\t\tcounter++\n\t\tExtra = append(Extra, nil)\n\t\treturn counter\n\t}}\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\ttotal += f()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "is mutated") {
			t.Fatalf("verdict = %+v, want the mutation culprit - the environment culprit outranked a demonstrated mutation", verdict)
		}
	})
	t.Run("param-sourced fill in exempt init flow poisons", func(t *testing.T) {
		// The store sits in an init-only helper - the exempt region, so
		// no escape attribution fires - and the parameter RHS is an
		// opaque source the audit alone refuses.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() int\n\nfunc install(fs []func() int) { Hooks = fs }\n\nfunc init() {\n\tinstall([]func() int{func() int { return 1 }})\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\ttotal += f()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a parameter-sourced fill in exempt init flow passed the audit", verdict)
		}
	})
	t.Run("aliased-local handout to a method in an init body escapes", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype sink struct{ m map[string]func() }\n\nfunc (s *sink) Keep(m map[string]func()) { s.m = m }\n\nvar keeper sink\n\nvar Hooks = map[string]func(){}\n\nfunc init() {\n\tm := Hooks\n\tkeeper.Keep(m)\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Hooks - an aliased init-local handout to a method stayed exempt", verdict)
		}
	})
	t.Run("wrapped carrier argument in an init body escapes", func(t *testing.T) {
		// The carrier rides inside a composite argument - no deferral
		// can resolve it, and the exempt region's fail-closed arm must
		// still see it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype wrap struct{ m map[string]func() }\n\nfunc churn(m map[string]func()) {\n\tfor k := range m {\n\t\tdelete(m, k)\n\t}\n}\n\nfunc hold(w wrap) { go churn(w.m) }\n\nvar Hooks = map[string]func(){}\n\nfunc init() {\n\thold(wrap{m: Hooks})\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Hooks - a wrapped carrier argument slipped the exempt region", verdict)
		}
	})
	t.Run("copied-out carrier alias escapes through its handout", func(t *testing.T) {
		// A builtin copy binds the destination local to the carrier's
		// backing; handing the destination out afterwards is handing the
		// carrier out.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = []map[string]func() int{{\"a\": one}}\n\nfunc one() int { return 1 }\n\nfunc two() int { return 2 }\n\nfunc churn(d []map[string]func() int) {\n\tfor _, m := range d {\n\t\tm[\"a\"] = two\n\t}\n}\n\nfunc init() {\n\tdst := make([]map[string]func() int, 1)\n\tcopy(dst, Hooks)\n\tgo churn(dst)\n}\n\nfunc Read() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Read() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Read"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want a downgrade naming reg.Hooks - a copied-out alias handed to a goroutine stayed settled", verdict)
		}
	})
	t.Run("declared alias joins the alias set", func(t *testing.T) {
		// The var-declaration form of the one-line alias - a declaration
		// binding aliases exactly as an assignment binding does.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc churn(s []string) {\n\tfor i := range s {\n\t\ts[i] = s[i] + \"!\"\n\t}\n}\n\nfunc init() {\n\tstate := []string{\"a\"}\n\tvar alias = state\n\tgo churn(alias)\n\tHooks = []func() string{func() string { return state[0] }}\n}\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a declared alias slipped the closure", verdict)
		}
	})
	t.Run("declared init-local alias is the carrier inside a stored literal", func(t *testing.T) {
		// The var-declaration form of the init-local alias: a stored
		// literal writing through it writes the carrier.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nvar Add func()\n\nfunc init() {\n\tvar m = Hooks\n\tAdd = func() { m[\"k\"] = func() {} }\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want a downgrade naming reg.Hooks - a declared alias write inside a stored literal stayed unattributed", verdict)
		}
	})
	t.Run("store through a pointer alias is audited", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc init() {\n\tstate := []string{\"a\"}\n\tp := &Hooks\n\t*p = []func() string{func() string { state[0] = \"b\"; return state[0] }}\n}\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a pointer-alias store slipped the audit", verdict)
		}
	})
	t.Run("parenthesized copy destination stays bound", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = []map[string]func() int{{\"a\": one}}\n\nfunc one() int { return 1 }\n\nfunc two() int { return 2 }\n\nfunc churn(d []map[string]func() int) {\n\tfor _, m := range d {\n\t\tm[\"a\"] = two\n\t}\n}\n\nfunc init() {\n\tdst := make([]map[string]func() int, 1)\n\tcopy((dst), Hooks)\n\tgo churn(dst)\n}\n\nfunc Read() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Read() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Read"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want a downgrade naming reg.Hooks - a parenthesized copy destination escaped the binding", verdict)
		}
	})
	t.Run("append through a resliced alias is audited", func(t *testing.T) {
		// The append rebinds the local AND writes the new element into
		// the shared backing whenever capacity allows - a store through
		// the alias, never exempt as a rebinding.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = []func(){func() {}}\n\nfunc init() {\n\tstate := 0\n\tm := Hooks[:0]\n\tm = append(m, func() { state++ })\n}\n\nfunc Run() { Hooks[0]() }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() { reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - an append through a resliced alias passed as a rebinding", verdict)
		}
	})
	t.Run("copy into an aliased local is audited", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = []func() int{nil}\n\nfunc init() {\n\tstate := 0\n\tm := Hooks\n\tcopy(m, []func() int{func() int { state++; return state }})\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\tif f != nil {\n\t\t\ttotal += f()\n\t\t}\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a copy into an aliased local passed as a rebinding", verdict)
		}
	})
	t.Run("store through a paren-copied alias is audited", func(t *testing.T) {
		// The destination arrives parenthesized and the capturing store
		// goes through it - the audit's alias resolution must see both.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = []map[string]func() int{{}}\n\nfunc init() {\n\tstate := []string{\"a\"}\n\tdst := make([]map[string]func() int, 1)\n\tcopy((dst), Hooks)\n\tdst[0][\"k\"] = func() int { state[0] = \"b\"; return len(state) }\n}\n\nfunc Read() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Read() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Read"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a capturing store through a paren-copied alias slipped the audit", verdict)
		}
	})
	t.Run("multi-source binding joins every backing to the alias set", func(t *testing.T) {
		// One binding, two sources: the combined slice shares the
		// captured state's backing through the appended elements, and
		// the goroutine writes it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc churn(s [][]string) {\n\tfor _, row := range s {\n\t\trow[0] = row[0] + \"!\"\n\t}\n}\n\nfunc init() {\n\tstate := [][]string{{\"a\"}}\n\tfresh := [][]string{}\n\tcombo := append(fresh, state...)\n\tgo churn(combo)\n\tHooks = []func() string{func() string { return state[0][0] }}\n}\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a multi-source alias binding slipped the closure", verdict)
		}
	})
	t.Run("go-statement argument poisons the captured environment", func(t *testing.T) {
		// The goroutine outlives initialization holding the environment
		// the registered reader captures - fail-closed without judging
		// what the goroutine's callee does with it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc churn(s []string) {\n\tfor i := range s {\n\t\ts[i] = s[i] + \"!\"\n\t}\n}\n\nfunc init() {\n\tstate := []string{\"a\"}\n\tgo churn(state)\n\tHooks = []func() string{func() string { return state[0] }}\n}\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a goroutine holding the captured environment left it settled", verdict)
		}
	})
	t.Run("capturing literal registration refuses every reader", func(t *testing.T) {
		// The environment hole: registered closures share an init-local
		// slice, one writing it, one reading it - subjects in one binary
		// observe order-dependent state under what would otherwise be a
		// closed verdict. The audit refuses the carrier itself, so even a
		// proof-free read path (a func-element range binds nothing of
		// mutable reach) downgrades.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc init() {\n\tstate := []string{\"a\"}\n\tHooks = []func() string{\n\t\tfunc() string { state[0] = state[0] + \"!\"; return \"\" },\n\t\tfunc() string { return state[0] },\n\t}\n}\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a capturing registered closure kept the carrier settled", verdict)
		}
	})
	t.Run("written captured scalar refuses like captured reach", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() int\n\nfunc init() {\n\tcounter := 0\n\tHooks = []func() int{func() int { counter++; return counter }}\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\ttotal += f()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a written captured scalar kept the carrier settled", verdict)
		}
	})
	t.Run("read-only captured scalar stays environment-free", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() int\n\nfunc init() {\n\tbase := 10\n\tHooks = []func() int{func() int { return base }}\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\ttotal += f()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a read-only captured scalar is settled after initialization", verdict)
		}
	})
	t.Run("bound method value registration refuses", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next() int {\n\tc.n++\n\treturn c.n\n}\n\nvar Hooks []func() int\n\nfunc init() {\n\tc := &counter{}\n\tHooks = []func() int{c.Next}\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\ttotal += f()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a bound method value carries its receiver as environment", verdict)
		}
	})
	t.Run("call-result registration refuses as an opaque source", func(t *testing.T) {
		// The values arrive through a function result the audit cannot
		// see into - fail-closed, even though the callee happens to
		// build capture-free literals.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = build()\n\nfunc build() []func() int {\n\treturn []func() int{func() int { return 1 }}\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\ttotal += f()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a call-result registration passed the audit", verdict)
		}
	})
	t.Run("binding argument to a leak-free sibling discharges", func(t *testing.T) {
		// The classifier shape: the loop hands a binding's field to a
		// plain named in-package function; the binding proof defers to
		// that parameter's leak-free fact through the carrier's deferred
		// marks.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc double() int { return 2 }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: double}}\n}\n\nfunc equalCols(a, b []string) bool {\n\tif len(a) != len(b) {\n\t\treturn false\n\t}\n\tfor i := range a {\n\t\tif a[i] != b[i] {\n\t\t\treturn false\n\t\t}\n\t}\n\treturn true\n}\n\nfunc Match(header []string) bool {\n\tfor _, e := range Registry {\n\t\tif equalCols(header, e.Cols) {\n\t\t\treturn true\n\t\t}\n\t}\n\treturn false\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() bool { return reg.Match([]string{\"a\"}) }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a binding argument to a leak-free sibling refused the deferral", verdict)
		}
	})
	t.Run("binding argument to a retaining sibling refuses", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nvar stash [][]string\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc keep(cols []string) bool {\n\tstash = append(stash, cols)\n\treturn true\n}\n\nfunc Match() bool {\n\tfor _, e := range Registry {\n\t\tif keep(e.Cols) {\n\t\t\treturn true\n\t\t}\n\t}\n\treturn false\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() bool { return reg.Match() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a retaining sibling resolved the deferral", verdict)
		}
	})
	t.Run("binding argument to a foreign leak-free parameter discharges", func(t *testing.T) {
		// The deferred marks resolve cross-package at composition.
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nfunc Width(cols []string) int { return len(cols) }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += val.Width(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a foreign leak-free parameter refused the cross-package deferral", verdict)
		}
	})
	t.Run("binding argument to a foreign retaining parameter refuses", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nvar held [][]string\n\nfunc Keep(cols []string) int {\n\theld = append(held, cols)\n\treturn len(held)\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += val.Keep(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a foreign retaining parameter resolved the deferral", verdict)
		}
	})
	t.Run("parameter proof chains through a same-package sibling", func(t *testing.T) {
		// The fact-side fixed point: Sum's parameter proves leak-free
		// because its rooted argument goes to width, itself proven - so
		// a carrier passed cross-package into Sum discharges.
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\ntype Entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc Sum(entries []Entry) int {\n\ttotal := 0\n\tfor _, e := range entries {\n\t\ttotal += width(e.Cols)\n\t}\n\treturn total\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Registry []val.Entry\n\nfunc init() {\n\tRegistry = []val.Entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int { return val.Sum(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the intra-package parameter chain refused the fixed point", verdict)
		}
	})
	t.Run("mutually recursive parameter chain refuses", func(t *testing.T) {
		// Neither parameter proves first - the fixed point is
		// deliberately conservative, and the carrier keeps its escape.
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\ntype Entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nfunc SumA(entries []Entry) int {\n\tif len(entries) == 0 {\n\t\treturn 0\n\t}\n\treturn SumB(entries)\n}\n\nfunc SumB(entries []Entry) int {\n\treturn SumA(entries)\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Registry []val.Entry\n\nfunc init() {\n\tRegistry = []val.Entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int { return val.SumA(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a mutually recursive chain proved itself", verdict)
		}
	})
	t.Run("cross-package parameter chain stays unproven at fact time", func(t *testing.T) {
		// Sum's own parameter proof would need a foreign parameter -
		// even a leak-free one with a same-named local sibling never
		// satisfies the same-package fixed point, so the carrier
		// deferred into Sum keeps its escape.
		files := map[string]string{
			"go.mod":       goMod,
			"lib/lib.go":   "package lib\n\nfunc Width(cols []string) int { return len(cols) }\n",
			"val/val.go":   "package val\n\nimport \"example.com/xesc/lib\"\n\ntype Entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nfunc Width(cols []string) int { return len(cols) }\n\nfunc Sum(entries []Entry) int {\n\ttotal := 0\n\tfor _, e := range entries {\n\t\ttotal += lib.Width(e.Cols)\n\t}\n\treturn total\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Registry []val.Entry\n\nfunc init() {\n\tRegistry = []val.Entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int { return val.Sum(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a cross-package want satisfied the same-package fixed point", verdict)
		}
	})
	t.Run("wrapped goroutine call never defers", func(t *testing.T) {
		// The literal wrap is the same concurrent execution as the
		// direct go statement - both spellings refuse identically.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc Total() int {\n\tfor _, e := range Registry {\n\t\tgo func() { width(e.Cols) }()\n\t}\n\treturn 0\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a goroutine-wrapped call earned the deferral", verdict)
		}
	})
	t.Run("variadic binding arguments clamp to the final parameter", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc joins(sets ...[]string) int {\n\ttotal := 0\n\tfor _, s := range sets {\n\t\ttotal += len(s)\n\t}\n\treturn total\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += joins(e.Cols, e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a variadic binding argument missed the parameter clamp", verdict)
		}
	})
	t.Run("go-statement binding argument never defers", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc Total() int {\n\tfor _, e := range Registry {\n\t\tgo width(e.Cols)\n\t}\n\treturn 0\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a goroutine's binding argument earned the deferral", verdict)
		}
	})
	t.Run("returned binding discharges when every caller contains it", func(t *testing.T) {
		// The lookup shape: an unexported function ranges the registry
		// and returns the matching entry; the caller binds it, reads a
		// no-reach field, and calls the func field - all contained.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc double(n int) int { return n * 2 }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\", Build: double}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc Describe(label string) int {\n\tclass, ok := lookup(label)\n\tif !ok {\n\t\treturn 0\n\t}\n\treturn class.Build(len(class.Label))\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Describe(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a contained returned binding refused the disposition", verdict)
		}
	})
	t.Run("returned binding retained by a caller refuses", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar stash []string\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc Keep(label string) {\n\tclass, _ := lookup(label)\n\tstash = class.Cols\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() { reg.Keep(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a retained returned binding passed the disposition", verdict)
		}
	})
	t.Run("exported returner refuses the disposition", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype Entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []Entry\n\nfunc init() {\n\tRegistry = []Entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Lookup(label string) (Entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn Entry{}, false\n}\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - an exported returner earned the package-local disposition", verdict)
		}
	})
	t.Run("value reference of the returner refuses", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc Finder() func(string) (entry, bool) {\n\treturn lookup\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() bool {\n\t_, ok := reg.Finder()(\"x\")\n\treturn ok\n}\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a value reference of the returner passed the disposition", verdict)
		}
	})
	t.Run("argument-position returner result refuses", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nfunc Note(v any) {}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc first() entry {\n\tfor _, e := range Registry {\n\t\treturn e\n\t}\n\treturn entry{}\n}\n\nfunc Report() { val.Note(first()) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() { reg.Report() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - an argument-position result passed the disposition", verdict)
		}
	})
	t.Run("returned binding propagates through a contained chain", func(t *testing.T) {
		// find re-returns lookup's binding; find's own caller contains -
		// the disposition chains through the package-local fixed point.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc double(n int) int { return n * 2 }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\", Build: double}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc find(label string) (entry, bool) {\n\tclass, ok := lookup(label)\n\treturn class, ok\n}\n\nfunc Describe(label string) int {\n\tclass, ok := find(label)\n\tif !ok {\n\t\treturn 0\n\t}\n\treturn class.Build(1)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Describe(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a contained propagation chain refused the disposition", verdict)
		}
	})
	t.Run("propagation through an exported function refuses", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype Entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []Entry\n\nfunc init() {\n\tRegistry = []Entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (Entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn Entry{}, false\n}\n\nfunc Find(label string) (Entry, bool) {\n\tclass, ok := lookup(label)\n\treturn class, ok\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() bool {\n\t_, ok := reg.Find(\"x\")\n\treturn ok\n}\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - propagation through an exported function passed", verdict)
		}
	})
	t.Run("package-level literal caller is a use site", func(t *testing.T) {
		// The containment scan covers literals stored at package level -
		// a writing use inside one refuses exactly as a function body's
		// would.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nvar Grab = func() {\n\tclass, _ := lookup(\"x\")\n\tclass.Cols[0] = \"z\"\n}\n\nfunc Describe(label string) int {\n\tclass, ok := lookup(label)\n\tif !ok {\n\t\treturn 0\n\t}\n\treturn len(class.Cols)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int {\n\treg.Grab()\n\treturn reg.Describe(\"x\")\n}\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a package-level literal's writing use escaped the containment scan", verdict)
		}
	})
	t.Run("initializer-position returner binding refuses", func(t *testing.T) {
		// A direct initializer-position call binds package variables -
		// an alias-handing result landing anywhere but a blank refuses.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc firstCols() ([]string, bool) {\n\tfor _, e := range Registry {\n\t\treturn e.Cols, true\n\t}\n\treturn nil, false\n}\n\nvar cached, _ = firstCols()\n\nfunc Look() int {\n\tcols, _ := firstCols()\n\treturn len(cols)\n}\n\nfunc Cached() int { return len(cached) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Cached() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Cached"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - an initializer-position alias binding passed containment", verdict)
		}
	})
	t.Run("discarded returner result is contained", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc Touch(label string) int {\n\tlookup(label)\n\treturn len(Registry)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Touch(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a discarded returner result refused containment", verdict)
		}
	})
	t.Run("caller-site literal re-return refuses", func(t *testing.T) {
		// The re-return sits inside a nested literal at the caller site:
		// it chains to the literal's unknowable caller, never to the
		// enclosing function's disposition - and the retained reach
		// through the untracked literal binding must keep the escape.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar stash []string\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc middle() {\n\tget := func() (entry, bool) { return lookup(\"x\") }\n\tclass, _ := get()\n\tstash = class.Cols\n}\n\nfunc Run() { middle() }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() { reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a literal's re-return chained the disposition to the wrong caller", verdict)
		}
	})
	t.Run("method re-return refuses the disposition", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\ntype finder struct{ prefix string }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc (f finder) find(label string) (entry, bool) {\n\treturn lookup(f.prefix + label)\n}\n\nfunc Probe(label string) bool {\n\t_, ok := finder{}.find(label)\n\treturn ok\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() bool { return reg.Probe(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Probe"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a method's re-return earned the disposition", verdict)
		}
	})
	t.Run("bad containment propagates back through the chain", func(t *testing.T) {
		// find re-returns lookup's binding and find's own caller
		// retains - the failure walks back through the dependency edge
		// and lookup's discharge retracts.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar stash []string\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc find(label string) (entry, bool) {\n\tclass, ok := lookup(label)\n\treturn class, ok\n}\n\nfunc Keep(label string) {\n\tclass, _ := find(label)\n\tstash = class.Cols\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() { reg.Keep(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a bad second hop left the first discharged", verdict)
		}
	})
	t.Run("literal return inside the loop never joins the disposition", func(t *testing.T) {
		// An immediately invoked literal returning the binding exits the
		// literal, not the function - its handout is an unknown caller's
		// and the range keeps the strict refusal.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc sneak() []string {\n\tfor _, e := range Registry {\n\t\tgot := func() entry { return e }()\n\t\treturn got.Cols\n\t}\n\treturn nil\n}\n\nfunc Sneak() int {\n\tcols := sneak()\n\treturn len(cols)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return len(reg.Sneak()) }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Sneak"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a literal's return joined the disposition", verdict)
		}
	})
	t.Run("returned binding argument defers through the caller", func(t *testing.T) {
		// The caller hands the returned binding's field to a leak-free
		// named function - the caller-site judgment carries the want to
		// the carrier exactly as a range binding's would.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc Measure(label string) int {\n\tclass, ok := lookup(label)\n\tif !ok {\n\t\treturn 0\n\t}\n\treturn width(class.Cols)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Measure(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a deferred caller-site argument refused the disposition", verdict)
		}
	})
	t.Run("returned binding argument to a retaining callee refuses", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar held [][]string\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc keep(cols []string) int {\n\theld = append(held, cols)\n\treturn len(held)\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc Measure(label string) int {\n\tclass, ok := lookup(label)\n\tif !ok {\n\t\treturn 0\n\t}\n\treturn keep(class.Cols)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Measure(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a retaining callee resolved the caller-site deferral", verdict)
		}
	})
	t.Run("cross-package func-field caller proves leak-free", func(t *testing.T) {
		// The fact side of the same arm: a foreign function ranging its
		// parameter and invoking a func field of each binding records the
		// parameter leak-free, so passing a carrier to it discharges.
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\ntype Entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nfunc Sum(entries []Entry) int {\n\ttotal := 0\n\tfor _, e := range entries {\n\t\ttotal += e.Build(1)\n\t}\n\treturn total\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Registry []val.Entry\n\nfunc double(n int) int { return n * 2 }\n\nfunc init() {\n\tRegistry = []val.Entry{{Cols: []string{\"a\"}, Build: double}}\n}\n\nfunc Total() int { return val.Sum(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a foreign func-field caller refused the leak-free proof", verdict)
		}
	})
}

// A store the composition discharges as init flow must first pass the
// object-closure audit, whichever package's function performs it: a
// graph-proven function rebinding an interface variable to a non-audited
// mutable construction breaks the closure (the discharge of the mutation
// is correct - the ESCAPE must not also discharge), while an audited
// construction through the same shape keeps it
// (REQ-closure-shared-dynamic-state).
func TestProvenInitFlowStoresAuditedForObjectClosure(t *testing.T) {
	t.Run("non-audited store through a proven function breaks the closure", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       "module example.com/xop\n\ngo 1.26\n",
			"reg/reg.go":   "package reg\n\nvar Err error\n\nfunc SetErr(e error) { Err = e }\n\nfunc Get() error { return Err }\n",
			"user/user.go": "package user\n\nimport \"example.com/xop/reg\"\n\ntype impl struct{ N int }\n\nfunc (i *impl) Error() string { return \"boom\" }\n\nvar _ = seed()\n\nfunc seed() bool {\n\treg.SetErr(&impl{})\n\treturn true\n}\n\nfunc F() bool { return reg.Get() == nil }\n",
		}
		dir := writeModuleTree(t, files)
		subject := Subject{Package: "example.com/xop/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Err escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Err - a non-audited store through a proven function kept the variable object-closed", verdict)
		}
	})
	t.Run("audited construction through a proven function keeps the closure", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       "module example.com/xop\n\ngo 1.26\n",
			"reg/reg.go":   "package reg\n\nimport \"errors\"\n\nvar Err error\n\nfunc Boot() { Err = errors.New(\"boot\") }\n\nfunc Get() error { return Err }\n",
			"user/user.go": "package user\n\nimport \"example.com/xop/reg\"\n\nvar _ = seed()\n\nfunc seed() bool {\n\treg.Boot()\n\treturn true\n}\n\nfunc F() bool { return reg.Get() == nil }\n",
		}
		dir := writeModuleTree(t, files)
		subject := Subject{Package: "example.com/xop/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an audited construction through a proven function broke the closure", verdict)
		}
	})
}

func writeModuleTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func captureCheck(t *testing.T, dir string, subject Subject) Verdict {
	t.Helper()
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	return verdict
}

// The three fail-closed mutation shapes the carrier rules must catch
// (REQ-closure-shared-dynamic-state): a package-level function-literal
// mutator, a pointer-receiver method VALUE bind, and read-aliasing of
// a map-carried hook set.
func TestSharedDynamicStateFailClosedShapes(t *testing.T) {
	for name, source := range map[string]string{
		"package-level funclit mutator":      "package view\n\nvar Hook = func() {}\n\nvar Rebind = func() { Hook = func() {} }\n\nfunc F() { Rebind() }\n",
		"pointer-receiver method value bind": "package view\n\ntype Registry struct{ hook func() }\n\nfunc (r *Registry) Set(f func()) { r.hook = f }\n\nvar Reg Registry\n\nfunc F() { set := Reg.Set; set(func() {}) }\n",
		"map read-alias":                     "package view\n\nvar Hooks = map[string]func(){}\n\nfunc F() { m := Hooks; m[\"k\"] = func() {} }\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, source)
			engine, err := New(WithDir(dir))
			if err != nil {
				t.Fatal(err)
			}
			subject := Subject{Package: "example.com/view", Symbol: "F"}
			view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint, err := view.Capture(context.Background(), subject)
			if err != nil {
				t.Fatal(err)
			}
			verdict, err := view.Check(context.Background(), fingerprint, subject)
			if err != nil {
				t.Fatal(err)
			}
			if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") {
				t.Fatalf("verdict = %+v, want the shared-dynamic-state downgrade", verdict)
			}
		})
	}
}

// Writeless reads of alias carriers and object-closed sentinels are not
// mutation: indexing, iteration, length, and comparison discharge, and
// an errors.New sentinel stays closed through an escape
// (REQ-closure-shared-dynamic-state).
func TestSharedDynamicStateWritelessReadsDoNotDowngrade(t *testing.T) {
	for name, source := range map[string]string{
		"sentinel escape into errors.Is":              "package view\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"x\")\n\nfunc F() bool { return errors.Is(nil, ErrX) }\n",
		"sentinel comparison":                         "package view\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"x\")\nvar ErrY = errors.New(\"y\")\n\nfunc F() bool { return ErrX == ErrY }\n",
		"registry map read shapes":                    "package view\n\nvar Hooks = map[string]func(){\"k\": func() {}}\n\nfunc F() int {\n\tif len(Hooks) > 0 {\n\t\tHooks[\"k\"]()\n\t}\n\tn := 0\n\tfor range Hooks {\n\t\tn++\n\t}\n\treturn n\n}\n",
		"non-opaque sentinel comparison":              "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error = &impl{}\n\nfunc F() bool { return ErrX == nil }\n",
		"exported initializer-only helper discharges": "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = Declare(\"k\")\n\nfunc Declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
		"slice capacity read":                         "package view\n\nvar Hooks = make([]func(), 0, 4)\n\nfunc F() int { return cap(Hooks) }\n",
		"read-only method call discharges":            "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int { return r.n }\n\nfunc F() int { return R.Count() }\n",
		"rwmutex rlock read discharges":               "package view\n\nimport \"sync\"\n\ntype reg struct {\n\tmu sync.RWMutex\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int {\n\tr.mu.RLock()\n\tdefer r.mu.RUnlock()\n\treturn r.n\n}\n\nfunc F() int { return R.Count() }\n",
		"aliased sync import discharges":              "package view\n\nimport s \"sync\"\n\ntype reg struct {\n\tmu s.Mutex\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int {\n\tr.mu.Lock()\n\tdefer r.mu.Unlock()\n\treturn r.n\n}\n\nfunc F() int { return R.Count() }\n",
		"mutex-guarded read discharges":               "package view\n\nimport \"sync\"\n\ntype reg struct {\n\tmu sync.Mutex\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int {\n\tr.mu.Lock()\n\tdefer r.mu.Unlock()\n\treturn r.n\n}\n\nfunc F() int { return R.Count() }\n",
		"read-only chain discharges":                  "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int { return r.raw() }\n\nfunc (r *reg) raw() int { return r.n }\n\nfunc F() int { return R.Count() }\n",
		"generic instantiated result discharges":      "package view\n\ntype reg[A comparable] struct {\n\tfn func()\n\tv  A\n}\n\nvar R = &reg[string]{}\n\nfunc (r *reg[A]) Value() A { return r.v }\n\nfunc F() string { return R.Value() }\n",
		"reflect-type result discharges":              "package view\n\nimport \"reflect\"\n\ntype reg struct {\n\tfn func()\n\tt  reflect.Type\n}\n\nvar R = &reg{t: reflect.TypeOf(0)}\n\nfunc (r *reg) Kind() reflect.Type { return r.t }\n\nfunc F() bool { return R.Kind() != nil }\n",
		"value-typed binding stays untainted":         "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{\"k\": 1}}\n\nfunc (r *reg) Pick() int {\n\tx := r.n\n\tif x > 0 {\n\t\treturn x\n\t}\n\tv, ok := r.m[\"k\"]\n\tif ok {\n\t\treturn v\n\t}\n\treturn 0\n}\n\nfunc F() int { return R.Pick() }\n",
		"pairing discriminates positions":             "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc localMap() map[string]int { return map[string]int{} }\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Sum() int {\n\tm2, m := localMap(), r.inner()\n\tm2[\"k\"] = 1\n\treturn len(m) + len(m2)\n}\n\nfunc F() int { return R.Sum() }\n",
		"governed sibling binding discharges":         "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Sum() int {\n\tm := r.inner()\n\treturn len(m)\n}\n\nfunc F() int { return R.Sum() }\n",
		"registry lookup shape discharges":            "package view\n\nimport (\n\t\"reflect\"\n\t\"sync\"\n)\n\ntype entry struct {\n\tattr struct{}\n\ttyp  reflect.Type\n}\n\ntype reg struct {\n\tmu sync.Mutex\n\tfn func()\n\tm  map[string]entry\n}\n\nvar R = &reg{m: map[string]entry{}}\n\nfunc (r *reg) Lookup(name string) (struct{}, reflect.Type, bool) {\n\tr.mu.Lock()\n\tdefer r.mu.Unlock()\n\te, ok := r.m[name]\n\treturn e.attr, e.typ, ok\n}\n\nfunc F() bool {\n\t_, _, ok := R.Lookup(\"k\")\n\treturn ok\n}\n",
		"generic receiver read discharges":            "package view\n\ntype reg[A comparable] struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg[string]{}\n\nfunc (r *reg[A]) Count() int { return r.n }\n\nfunc F() int { return R.Count() }\n",
		"init-only helper registration":               "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = declare(\"k\")\n\nfunc declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
		"helper chain registration":                   "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = declare(\"k\")\n\nfunc declare(name string) bool { return install(name) }\n\nfunc install(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, source)
			engine, err := New(WithDir(dir))
			if err != nil {
				t.Fatal(err)
			}
			subject := Subject{Package: "example.com/view", Symbol: "F"}
			view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint, err := view.Capture(context.Background(), subject)
			if err != nil {
				t.Fatal(err)
			}
			verdict, err := view.Check(context.Background(), fingerprint, subject)
			if err != nil {
				t.Fatal(err)
			}
			if verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid - a writeless read downgraded", verdict)
			}
		})
	}
}

// Escapes of writable carriers and sentinel rebinds stay mutation, and
// the refusal names the owning package and variable
// (REQ-closure-shared-dynamic-state).
func TestSharedDynamicStateEscapesAndRebindsDowngradeWithCulprit(t *testing.T) {
	for name, tc := range map[string]struct{ source, culprit string }{
		"sentinel rebind": {
			source:  "package view\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"x\")\n\nfunc F() { ErrX = errors.New(\"y\") }\n",
			culprit: "example.com/view.ErrX is mutated",
		},
		"mutable-object sentinel escape": {
			source:  "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error = &impl{}\n\nfunc use(err error) error { return err }\n\nfunc F() { _ = use(ErrX) }\n",
			culprit: "example.com/view.ErrX escapes writable",
		},
		"registry map escape": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nfunc take(m map[string]func()) map[string]func() { return m }\n\nfunc F() { _ = take(Hooks) }\n",
			culprit: "example.com/view.Hooks escapes writable",
		},
		"channel range receives": {
			source:  "package view\n\nvar Ch = make(chan func(), 1)\n\nfunc F() { for f := range Ch { f() } }\n",
			culprit: "example.com/view.Ch is mutated",
		},
		"indexed-out alias escapes": {
			source:  "package view\n\nvar Registry = []map[string]func(){{}}\n\nfunc take(m map[string]func()) {}\n\nfunc F() { take(Registry[0]) }\n",
			culprit: "example.com/view.Registry escapes writable",
		},
		"init-nested literal rebind": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar f func()\n\nfunc init() { f = func() { Hooks[\"k\"] = nil } }\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"goroutine-in-init sentinel rebind": {
			source:  "package view\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"x\")\n\nfunc use(err error) {}\n\nfunc init() { go func() { ErrX = errors.New(\"later\") }() }\n\nfunc F() { use(ErrX) }\n",
			culprit: "example.com/view.ErrX is mutated",
		},
		"helper also called from program code": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = declare(\"k\")\n\nfunc declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc Register(name string) { declare(name) }\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper referenced as a value": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = declare(\"k\")\n\nfunc declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nvar Declare = declare\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper stores non-audited sentinel": {
			source:  "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error\n\nvar _ = setup()\n\nfunc setup() bool {\n\tErrX = &impl{}\n\treturn true\n}\n\nfunc use(err error) error { return err }\n\nfunc F() { _ = use(ErrX) }\n",
			culprit: "example.com/view.ErrX escapes writable",
		},
		"initializer-literal reference is program code": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar F2 = func() { declare(\"x\") }\n\nfunc declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"init-body-literal reference is program code": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar Run func()\n\nfunc init() { Run = func() { declare(\"k\") } }\n\nfunc declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper-body-literal reference is program code": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar Run func()\n\nvar _ = declare()\n\nfunc declare() bool {\n\tRun = func() { install(\"k\") }\n\treturn true\n}\n\nfunc install(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper go-statement argument escapes": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = setup()\n\nfunc setup() bool { go mutate(Hooks); return true }\n\nfunc mutate(m map[string]func()) { m[\"k\"] = func() {} }\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks escapes writable",
		},
		"init go-statement argument escapes": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nfunc mutate(m map[string]func()) { m[\"k\"] = func() {} }\n\nfunc init() { go mutate(Hooks) }\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks escapes writable",
		},
		"go literal-call argument escapes": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = setup()\n\nfunc setup() bool {\n\tgo func(m map[string]func()) { m[\"k\"] = func() {} }(Hooks)\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks escapes writable",
		},
		"go-statement callee races program code": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nfunc init() { go declare(\"k\") }\n\nfunc declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"slice-receiver range binding marks": {
			source:  "package view\n\ntype entry struct {\n\tfn func()\n\tn  *int\n}\n\ntype reg []entry\n\nvar R = reg{{fn: func() {}, n: new(int)}}\n\nfunc (r reg) First() *int {\n\tfor _, e := range r {\n\t\treturn e.n\n\t}\n\treturn nil\n}\n\nfunc F() {\n\tp := R.First()\n\t*p = 1\n}\n",
			culprit: "example.com/view.R escapes writable",
		},
		"direct field-store RHS keeps the mark": {
			source:  "package view\n\ntype box struct{ f map[string]int }\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) Outer() int {\n\tvar s box\n\ts.f = r.m\n\ts.f[\"k\"] = 1\n\treturn 0\n}\n\nfunc F() int { return R.Outer() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"shadowed len keeps the mark": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc len(m map[string]int) int { return 0 }\n\nfunc (r *reg) Size() int { return len(r.m) }\n\nfunc F() int { return R.Size() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"mixed parallel assign keeps the mark": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Outer() int {\n\tm, x := r.inner(), 5\n\tm[\"k\"] = x\n\treturn 0\n}\n\nfunc F() int { return R.Outer() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"clean-plus-leaky parallel assign keeps the mark": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n\tn  int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) count() int { return r.n }\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Outer() int {\n\tn, m := r.count(), r.inner()\n\tm[\"k\"] = n\n\treturn 0\n}\n\nfunc F() int { return R.Outer() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"field-store binding keeps the mark": {
			source:  "package view\n\ntype box struct{ f map[string]int }\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Outer() int {\n\tvar s box\n\ts.f = r.inner()\n\ts.f[\"k\"] = 1\n\treturn 0\n}\n\nfunc F() int { return R.Outer() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"leaky sibling call in arg position marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc probe(m map[string]int) int { return len(m) }\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Outer() int { return probe(r.inner()) }\n\nfunc F() int { return R.Outer() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"sibling leaky return launders nothing": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Outer() int {\n\tm := r.inner()\n\tm[\"k\"] = 1\n\treturn 0\n}\n\nfunc F() int { return R.Outer() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"loop-carried taint marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) Set() int {\n\tvar v map[string]int\n\tfor i := 0; i < 2; i++ {\n\t\tif v != nil {\n\t\t\tv[\"k\"] = 1\n\t\t}\n\t\tv = r.m\n\t}\n\treturn 0\n}\n\nfunc F() int { return R.Set() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"assign-form range binding taints": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\ts  []map[string]int\n}\n\nvar R = &reg{s: []map[string]int{{}}}\n\nfunc (r *reg) Set() int {\n\tvar v map[string]int\n\tfor _, v = range r.s {\n\t\t_ = v\n\t}\n\tv[\"k\"] = 1\n\treturn 0\n}\n\nfunc F() int { return R.Set() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"tainted local write marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) Set() int {\n\te := r.m\n\te[\"k\"] = 1\n\treturn 0\n}\n\nfunc F() int { return R.Set() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"tainted arg escape marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc probe(m map[string]int) int { return len(m) }\n\nfunc (r *reg) Peek() int {\n\tv := r.m\n\treturn probe(v)\n}\n\nfunc F() int { return R.Peek() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"local-alias write through method marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) Set() int {\n\tv := r.m\n\tv[\"k\"] = 1\n\treturn 0\n}\n\nfunc F() int { return R.Set() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"returned mutable pointer marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\ts  []*int\n}\n\nvar R = &reg{s: []*int{new(int)}}\n\nfunc (r *reg) Get() *int { return r.s[0] }\n\nfunc F() { p := R.Get(); *p = 1 }\n",
			culprit: "example.com/view.R is mutated",
		},
		"interface-dispatched call keeps the mark": {
			source:  "package view\n\ntype counter interface{ Count() int }\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nfunc (r *reg) Count() int { return r.n }\n\nvar R counter = &reg{}\n\nfunc F() int { return R.Count() }\n",
			culprit: "example.com/view.R escapes writable",
		},
		"chain into writer sibling marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int { return r.bump() }\n\nfunc (r *reg) bump() int {\n\tr.n++\n\treturn r.n\n}\n\nfunc F() int { return R.Count() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"non-mutex sync field use marks": {
			source:  "package view\n\nimport \"sync\"\n\ntype reg struct {\n\tonce sync.Once\n\tfn   func()\n\tn    int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int {\n\tr.once.Do(func() {})\n\treturn r.n\n}\n\nfunc F() int { return R.Count() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"assignment writer method call marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Set(v int) { r.n = v }\n\nfunc F() { R.Set(3) }\n",
			culprit: "example.com/view.R is mutated",
		},
		"writer method call marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Bump() { r.n++ }\n\nfunc F() { R.Bump() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"method value bind keeps the mark": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int { return r.n }\n\nfunc F() int {\n\tg := R.Count\n\treturn g()\n}\n",
			culprit: "example.com/view.R is mutated",
		},
		"alias-returning method call marks": {
			source:  "package view\n\ntype reg struct {\n\thooks map[string]func()\n}\n\nvar R = &reg{hooks: map[string]func(){}}\n\nfunc (r *reg) Hooks() map[string]func() { return r.hooks }\n\nfunc F() int { return len(R.Hooks()) }\n",
			culprit: "example.com/view.R is mutated",
		},
		"receiver-escaping method call marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc probe(v any) int { return 0 }\n\nfunc (r *reg) Count() int { return probe(r) }\n\nfunc F() int { return R.Count() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"method helper never qualifies": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\ntype reg struct{}\n\nvar _ = reg{}.declare(\"k\")\n\nfunc (reg) declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper nested literal mutates as program code": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar Run func()\n\nvar _ = declare()\n\nfunc declare() bool {\n\tRun = func() { Hooks[\"k\"] = nil }\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper reached through disqualified caller": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = inner(\"k\")\n\nfunc inner(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc outer(name string) { inner(name) }\n\nfunc Register(name string) { outer(name) }\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"range-bound init store breaks opacity": {
			source:  "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error\n\nvar errs = []error{&impl{}}\n\nfunc init() { for _, ErrX = range errs {} }\n\nfunc use(err error) error { return err }\n\nfunc F() { _ = use(ErrX) }\n",
			culprit: "example.com/view.ErrX escapes writable",
		},
		"init-local alias captured by a literal marks the carrier": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar Mut func()\n\nfunc init() {\n\tm := Hooks\n\tMut = func() { m[\"x\"] = func() {} }\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"init-local alias handed out by a literal escapes the carrier": {
			// The argument is a local, so the parameter deferral never
			// applies - the alias-carrier ident arm must mark the
			// carrier the local aliases.
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar Mut func()\n\nfunc keep(m map[string]func()) {}\n\nfunc init() {\n\tm := Hooks\n\tMut = func() { keep(m) }\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks escapes writable",
		},
		"chained init-local alias marks the carrier": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar Mut func()\n\nfunc init() {\n\ta := Hooks\n\tb := a\n\tMut = func() { b[\"x\"] = func() {} }\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"indirect init store breaks opacity": {
			// The consumer retains its parameter, so the escape stands
			// and the verdict turns on the opacity the indirect store
			// broke; an empty consumer would discharge the escape by the
			// leak-free parameter proof and never reach opacity at all.
			source:  "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error\n\nfunc init() { p := &ErrX; *p = &impl{} }\n\nfunc use(err error) error { return err }\n\nfunc F() { _ = use(ErrX) }\n",
			culprit: "example.com/view.ErrX escapes writable",
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, tc.source)
			engine, err := New(WithDir(dir))
			if err != nil {
				t.Fatal(err)
			}
			subject := Subject{Package: "example.com/view", Symbol: "F"}
			view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint, err := view.Capture(context.Background(), subject)
			if err != nil {
				t.Fatal(err)
			}
			verdict, err := view.Check(context.Background(), fingerprint, subject)
			if err != nil {
				t.Fatal(err)
			}
			if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") || !strings.Contains(verdict.Reason, tc.culprit) {
				t.Fatalf("verdict = %+v, want the downgrade naming %q", verdict, tc.culprit)
			}
		})
	}
}

// A package with assembly sources stays downgraded through the closure
// tier's native-code and linkage dispositions - the mutation analysis
// needs no foreign-code rule of its own
// (REQ-closure-shared-dynamic-state).
func TestForeignCodePackageKeepsTypeLevelDowngrade(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nvar Hook = func() {}\n\nfunc F() { Hook() }\n")
	if err := os.WriteFile(filepath.Join(dir, "empty_amd64.s"), []byte("// nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable {
		t.Fatalf("verdict = %+v, want the foreign-code downgrade", verdict)
	}
}

// A maximal-only producer validation compares one fresh observation against
// the captured facts instead of paying a construction pair: the compared
// read is never recorded, so a torn read can only refuse
// (REQ-fresh-coherent-view's record/compare asymmetry). Drift detection is
// intact: an edit between capture and validation still refuses.
func TestValidateMaximalReadsOnceAndStillRefusesDrift(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc Sum(a, b int) int { return a + b }\n")
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewViewFor(context.Background(), []Subject{{Package: "example.com/view", Symbol: "Sum"}}, dir, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.Capture(context.Background(), Subject{Package: "example.com/view", Symbol: "Sum"}); err != nil {
		t.Fatal(err)
	}
	observations := 0
	viewTestHooks.observe = func() { observations++ }
	t.Cleanup(func() { viewTestHooks.observe = nil })
	if err := view.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	viewTestHooks.observe = nil
	if observations != 1 {
		t.Fatalf("maximal validation performed %d observation passes, want exactly 1", observations)
	}

	edited, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view2, err := edited.NewViewFor(context.Background(), []Subject{{Package: "example.com/view", Symbol: "Sum"}}, dir, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view2.Capture(context.Background(), Subject{Package: "example.com/view", Symbol: "Sum"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc Sum(a, b int) int { return a + b + 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := view2.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("single-read validation missed the drift: %v", err)
	}
}

// An observed producer lifecycle pays five observation passes: the
// construction pair (facts become the record), the capture bracket's one
// closing observation, the validation view's one seeded read, and the
// validation analysis bracket's one close - comparison-only reads are
// single (REQ-fresh-coherent-view's record/compare asymmetry). Drift
// between capture and validation still refuses through the seeded read.
func TestObservedProducerLifecyclePassEconomy(t *testing.T) {
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	observations := 0
	viewTestHooks.observe = func() { observations++ }
	t.Cleanup(func() { viewTestHooks.observe = nil })
	producer, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("observed test"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer.AttachObservation(subject, fingerprint, observation); err != nil {
		t.Fatal(err)
	}
	if err := producer.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	viewTestHooks.observe = nil
	if observations != 5 {
		t.Fatalf("observed producer lifecycle performed %d observation passes, want 5 (2 construction + 1 capture bracket + 1 seeded read + 1 validation bracket)", observations)
	}

	// Same lifecycle with an edit after capture: the seeded read refuses.
	producer2, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint2, err := producer2.CaptureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation2, err := runtimeinput.FromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("observed test 2"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer2.AttachObservation(subject, fingerprint2, observation2); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "observed.go"), []byte("package observed\n\nfunc Sibling() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	observations = 0
	viewTestHooks.observe = func() { observations++ }
	t.Cleanup(func() { viewTestHooks.observe = nil })
	if err := producer2.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("seeded validation missed capture-to-validate drift: %v", err)
	}
	viewTestHooks.observe = nil
	// The seeded read itself refuses - one observation, no analysis
	// bracket: the seed comparison is what makes the seeded facts
	// record-grade before any validation-time analysis spends work on
	// them (the bracket close would still refuse, one analysis later).
	if observations != 1 {
		t.Fatalf("capture-to-validate drift refused after %d observations, want 1 (the seeded read)", observations)
	}
}

// A sibling view shares the parent's single observation — identical
// fingerprints, zero additional observation passes — while carrying its
// own producer transaction: the parent's validation seal never blocks a
// sibling's attach/validate cycle, and one subject attaches its own
// runtime evidence once per sibling (the per-target transaction shape a
// mutation campaign runs). REQ-fresh-coherent-view: nothing the sibling
// serves is re-read.
func TestSiblingSharesObservationAndIsolatesTransactions(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/sibling\n\ngo 1.26\n",
		"a/a.go": "package a\n\nfunc F() int { return 1 }\n",
		"b/b.go": "package b\n\nfunc G() int { return 2 }\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	aF := Subject{Package: "example.com/sibling/a", Symbol: "F"}
	bG := Subject{Package: "example.com/sibling/b", Symbol: "G"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := engine.NewView(context.Background(), []Subject{aF, bG}, dir)
	if err != nil {
		t.Fatal(err)
	}
	parentF, err := parent.Capture(context.Background(), aF)
	if err != nil {
		t.Fatal(err)
	}

	observations := 0
	viewTestHooks.observe = func() { observations++ }
	t.Cleanup(func() { viewTestHooks.observe = nil })
	siblingOne, err := parent.Sibling([]Subject{aF})
	if err != nil {
		t.Fatal(err)
	}
	siblingTwo, err := parent.Sibling([]Subject{aF, bG})
	if err != nil {
		t.Fatal(err)
	}
	if observations != 0 {
		t.Fatalf("sibling derivation performed %d observations, want 0 — every served fact must be the parent's", observations)
	}
	if _, err := parent.Sibling([]Subject{{Package: "example.com/sibling/a", Symbol: "Absent"}}); err == nil {
		t.Fatal("sibling over a subject outside the parent view derived, want refusal")
	}
	oneF, err := siblingOne.Capture(context.Background(), aF)
	if err != nil {
		t.Fatal(err)
	}
	if oneF != parentF {
		t.Fatalf("sibling fingerprint = %+v, parent = %+v — shared observation must serve identical evidence", oneF, parentF)
	}

	// The parent's validation seals only the parent's transaction.
	if err := parent.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := parent.Capture(context.Background(), aF); err == nil {
		t.Fatal("parent capture after validation succeeded, want the seal")
	}
	if _, err := siblingOne.Capture(context.Background(), aF); err != nil {
		t.Fatalf("sibling capture after the parent's validation: %v", err)
	}
	if err := siblingOne.Validate(context.Background()); err != nil {
		t.Fatalf("sibling validation after the parent's: %v", err)
	}
	// A sealed parent still derives: the facts are construction-time and
	// the sibling's own validation is its drift gate. This parent never
	// captured an observed proof, so the derived sibling's observed
	// capture computes one fresh rather than serving an absent
	// inherited proof.
	sealedSibling, err := parent.Sibling([]Subject{aF})
	if err != nil {
		t.Fatalf("sibling derivation from a sealed parent: %v", err)
	}
	observations = 0
	if _, err := sealedSibling.CaptureObserved(context.Background(), aF); err != nil {
		t.Fatalf("observed capture over a subject the parent never captured: %v", err)
	}
	if observations == 0 {
		t.Fatal("proof-less observed capture completed without observing, want a fresh proof computation")
	}
	// A sibling sealed by its own validation never seals the family, and
	// a single-subject sibling's validation compares against the SUBSET's
	// source union — the parent's wider union would refuse an unchanged
	// tree.
	if _, err := siblingTwo.Capture(context.Background(), bG); err != nil {
		t.Fatalf("second sibling capture after first sibling's validation: %v", err)
	}
	if err := siblingTwo.Validate(context.Background()); err != nil {
		t.Fatalf("second sibling validation: %v", err)
	}

	// Runtime-evidence attachment is per sibling: two siblings attach the
	// same subject's evidence independently, and one sibling attaches a
	// subject once.
	attachParent, err := engine.NewView(context.Background(), []Subject{aF, bG}, dir)
	if err != nil {
		t.Fatal(err)
	}
	observedFPs, err := attachParent.CaptureObservedBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	attachOne, err := attachParent.Sibling([]Subject{aF})
	if err != nil {
		t.Fatal(err)
	}
	attachTwo, err := attachParent.Sibling([]Subject{aF, bG})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtimeinput.IncompleteEnv(dir, "probe", "probe reason", os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attachOne.AttachObservation(aF, observedFPs[aF], observation); err != nil {
		t.Fatalf("first sibling attach: %v", err)
	}
	if _, err := attachTwo.AttachObservation(aF, observedFPs[aF], observation); err != nil {
		t.Fatalf("second sibling attach of the same subject: %v", err)
	}
	if _, err := attachOne.AttachObservation(aF, observedFPs[aF], observation); err == nil {
		t.Fatal("re-attachment on one sibling succeeded, want the once-per-transaction refusal")
	}
	// The campaign's endgame: a sibling of an observed parent attaches
	// its target's runtime evidence and validates through the observed
	// arm on an unchanged tree.
	if _, err := attachTwo.AttachObservation(bG, observedFPs[bG], observation); err != nil {
		t.Fatal(err)
	}
	if err := attachTwo.Validate(context.Background()); err != nil {
		t.Fatalf("observed-arm sibling validation on an unchanged tree: %v", err)
	}
	// Subject order never shapes the narrowed union: a reversed-order
	// sibling over both packages still validates the unchanged tree (the
	// union recipe sorts; an order-carrying union would falsely refuse).
	reversed, err := attachParent.Sibling([]Subject{bG, aF})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reversed.AttachObservation(aF, observedFPs[aF], observation); err != nil {
		t.Fatal(err)
	}
	if _, err := reversed.AttachObservation(bG, observedFPs[bG], observation); err != nil {
		t.Fatal(err)
	}
	if err := reversed.Validate(context.Background()); err != nil {
		t.Fatalf("reversed-order sibling validation on an unchanged tree: %v", err)
	}
}

// A drifted tree refuses a sibling's validation exactly as any view's:
// sharing the parent's recorded facts never weakens the compare side.
func TestSiblingValidationRefusesDrift(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/siblingdrift\n\ngo 1.26\n",
		"a/a.go": "package a\n\nfunc F() int { return 1 }\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	aF := Subject{Package: "example.com/siblingdrift/a", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := engine.NewView(context.Background(), []Subject{aF}, dir)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := parent.Sibling([]Subject{aF})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "a.go"), []byte("package a\n\nfunc F() int { return 3 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sibling.Validate(context.Background()); err == nil {
		t.Fatal("sibling validated a drifted tree, want refusal")
	}
}

// A sibling whose one subject's closure spans two in-module packages
// derives a narrowed union that still covers the full cross-package
// closure and compares equal to a fresh subset observation on an
// unchanged tree. This leg pins the cross-package narrowing only;
// order canonicalization is TestSortedUniqueUnionCanonicalizes' pin —
// every production feeder arrives pre-sorted, so no integration path
// can discriminate the recipe's own sort.
func TestSiblingCrossPackageClosureValidatesUnchangedTree(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/siblingdeps\n\ngo 1.26\n",
		"a/a.go": "package a\n\nimport \"example.com/siblingdeps/b\"\n\nfunc F() int { return b.G() }\n",
		"b/b.go": "package b\n\nfunc G() int { return 2 }\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	aF := Subject{Package: "example.com/siblingdeps/a", Symbol: "F"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := engine.NewView(context.Background(), []Subject{aF}, dir)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := parent.Sibling([]Subject{aF})
	if err != nil {
		t.Fatal(err)
	}
	// Guard against vacuity: the one subject's union must really span
	// both packages, or the cross-package claim above tests nothing.
	var hasA, hasB bool
	for _, f := range sibling.SourceFiles() {
		if strings.HasSuffix(f, filepath.Join("a", "a.go")) {
			hasA = true
		}
		if strings.HasSuffix(f, filepath.Join("b", "b.go")) {
			hasB = true
		}
	}
	if !hasA || !hasB {
		t.Fatalf("cross-package closure union = %v, want both packages' sources", sibling.SourceFiles())
	}
	if err := sibling.Validate(context.Background()); err != nil {
		t.Fatalf("cross-package-closure sibling validation on an unchanged tree: %v", err)
	}
}

// sortedUniqueUnion's sorted, deduplicated output is the union recipe's
// own contract — the canonical form is what lets a derived union compare
// equal to a freshly observed one REGARDLESS of feeder order. Every
// production feeder today happens to arrive pre-sorted (the closure
// layer sorts per-package lists, and per-subject clones are sorted at
// store time), so this pin — not any integration path — is what holds
// the recipe to canonicalizing rather than trusting its callers.
func TestSortedUniqueUnionCanonicalizes(t *testing.T) {
	got := sortedUniqueUnion([][]string{{"b/b.go", "a/a.go"}, {"a/a.go", "c/c.go"}})
	want := []string{"a/a.go", "b/b.go", "c/c.go"}
	if !slices.Equal(got, want) {
		t.Fatalf("sortedUniqueUnion = %v, want %v", got, want)
	}
}

// Within one endpoint phase, records carrying the identical encoded
// manifest evaluate once; the closing endpoint is a fresh instant, so
// movement across the window stays detected
// (REQ-inputs-guard's per-record evaluation collapsed per phase).
func TestRuntimeInputManifestEvaluationSharedPerPhase(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n\nfunc G() int { return 2 }\n")
	f := Subject{Package: "example.com/view", Symbol: "F"}
	g := Subject{Package: "example.com/view", Symbol: "G"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fps, err := view.CaptureBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[Subject]Fingerprint{}
	for s, fp := range fps {
		fp.RuntimeInputs = "shared-manifest"
		fp.RuntimeDigest = "recorded"
		recorded[s] = fp
	}
	calls := 0
	view.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
		calls++
		return runtimeinput.State{Digest: "recorded", OK: true}, nil
	}
	verdicts, err := view.CheckBatch(context.Background(), recorded)
	if err != nil {
		t.Fatal(err)
	}
	// Both records traverse the runtime window - the sharing claim is
	// vacuous if either stales out of it beforehand.
	for s, v := range verdicts {
		if v.Status != Valid {
			t.Fatalf("record %v did not traverse the runtime window: %+v", s, v)
		}
	}
	// Two records, one manifest, two endpoint phases: exactly two
	// evaluations - one per phase, shared across the records.
	if calls != 2 {
		t.Fatalf("shared manifest evaluated %d times across two records and two phases, want 2", calls)
	}
}
