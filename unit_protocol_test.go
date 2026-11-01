package gofresh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

func TestInertApplicabilityRecordGrammar(t *testing.T) {
	f := fullFingerprint()
	f.InertTestVariantApplicability = InertTestVariantApplicability{InertTestVariantExtension, "endpoint"}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	nested := `"inertTestVariantApplicability":{"strategy":"` + InertTestVariantExtension + `","testVariantClosure":"endpoint"}`
	if !strings.Contains(string(data), nested+`,"resultKind":1`) {
		t.Fatalf("native form: %s", data)
	}
	for _, malformed := range []string{
		`null`, `{}`, `{"strategy":"s"}`, `{"testVariantClosure":"v"}`,
		`{"strategy":"","testVariantClosure":"v"}`, `{"strategy":"s","testVariantClosure":""}`,
		`{"strategy":null,"testVariantClosure":"v"}`, `{"strategy":"s","testVariantClosure":null}`,
		`{"strategy":"s","strategy":"s","testVariantClosure":"v"}`,
		`{"strategy":"s","testVariantClosure":"v","testVariantClosure":"v"}`,
		`{"strategy":"s","testVariantClosure":"v","other":1}`,
		`{"testVariantClosure":"v","strategy":"s"}`, `{"strategy":1,"testVariantClosure":"v"}`,
		`{"strategy":"s","testVariantClosure":true}`,
	} {
		bad := strings.Replace(string(data), nested, `"inertTestVariantApplicability":`+malformed, 1)
		var back Fingerprint
		if err := json.Unmarshal([]byte(bad), &back); err == nil || back != (Fingerprint{}) {
			t.Fatalf("accepted %s: %+v %v", bad, back, err)
		}
	}
	for _, partial := range []InertTestVariantApplicability{{Strategy: "s"}, {TestVariantClosure: "v"}} {
		f.InertTestVariantApplicability = partial
		if _, err := json.Marshal(f); err == nil {
			t.Fatal("encoded partial applicability")
		}
	}
	f.InertTestVariantApplicability = InertTestVariantApplicability{"future", f.TestVariantClosure}
	data, err = json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back Fingerprint
	if err := json.Unmarshal(data, &back); err != nil || back != f {
		t.Fatalf("unknown strategy unreadable: %v", err)
	}
	if verdict, failed := recordedEvidenceVerdict(back, closure.Closure{Hash: f.MaximalClosure, TestVariants: f.TestVariantClosure}); !failed || verdict.Status != Stale {
		t.Fatal("unknown strategy served under original hash")
	}
}

func TestInertExtensionRequiresEveryGuardAndRecognizedEvidence(t *testing.T) {
	for name, change := range map[string]func(*Snapshot, *Fingerprint, *TestVariantLedger){
		"core":                      func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { f.MaximalClosure = "moved" },
		"missing core":              func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { f.MaximalClosure = "" },
		"missing compartment":       func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { f.TestVariantClosure = "" },
		"closure derivation":        func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { f.ClosureStrategy = "old" },
		"dynamic derivation":        func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { f.DynamicStateStrategy = "old" },
		"toolchain":                 func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { f.Guards.Toolchain = "old" },
		"toolchain content":         func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { f.ToolchainContent = "other" },
		"missing toolchain content": func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { f.ToolchainContent = "" },
		"build":                     func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { f.Guards.BuildConfig = "old" },
		"machine":                   func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { f.Guards.Machine = "old" },
		"runtime":                   func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { f.Guards.RuntimeConfig = "old" },
		"missing runtime manifest":  func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { f.RuntimeDigest = "orphan" },
		"unknown endpoint": func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) {
			f.InertTestVariantApplicability = InertTestVariantApplicability{"future", "A"}
		},
		"missing binding evidence": func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { l.BindingStrategy = "" },
		"unknown binding evidence": func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) { l.BindingStrategy = "future" },
		"removed declaration": func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) {
			l.Declarations = []TestVariantDeclaration{{File: "p_test.go", Kind: "func", Name: "Removed", Hash: "h"}}
		},
		"external": func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) {
			for s := range v.facts.maximal {
				c := v.facts.closure(s)
				c.External = true
				v.facts.maximal[s] = testSubjectFacts(c)
			}
		},
		"unverifiable": func(v *Snapshot, f *Fingerprint, l *TestVariantLedger) {
			for s := range v.facts.maximal {
				c := v.facts.closure(s)
				c.Unverifiable = true
				c.Reason = "file dependence"
				v.facts.maximal[s] = testSubjectFacts(c)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, observed := range []bool{false, true} {
				v, f, s, l := applicabilityFixture(t)
				change(v, &f, &l)
				updated, ledger, verdict, err := v.checkInertTestVariantExtension(context.Background(), f, l, s, observed)
				if err != nil || verdict.Status == Valid || updated != (Fingerprint{}) || !reflect.DeepEqual(ledger, TestVariantLedger{}) {
					t.Fatalf("refusal leaked pair: %+v %+v %+v %v", updated, ledger, verdict, err)
				}
			}
		})
	}
	for _, pure := range []bool{false, true} {
		v, f, s, l := applicabilityFixture(t)
		if pure {
			c := v.facts.closure(s)
			c.Unverifiable = true
			v.facts.maximal[s] = testSubjectFacts(c)
			v.facts.purity = map[Subject]string{s: "caller assertion"}
			f.PurityAssertion = "caller assertion"
		}
		updated, _, verdict, err := v.checkInertTestVariantExtension(context.Background(), f, l, s, false)
		if err != nil || verdict.Status != Valid {
			t.Fatalf("independently valid ordinary case needs no outcome support: %+v %v", verdict, err)
		}
		if updated.TestVariantClosure != "A" || updated.EffectiveTestVariantClosure() != "B" {
			t.Fatal("producing coordinate was rewritten")
		}
		updated.InertTestVariantApplicability = InertTestVariantApplicability{}
		if updated != f {
			t.Fatal("producing constituents changed")
		}
	}

	t.Run("sibling test edit or removal is inert for subject", func(t *testing.T) {
		v, f, s, prior := applicabilityFixture(t)
		prior.FileHeaders = []TestVariantFileHeader{{
			File:     "p_test.go",
			Hash:     "h1",
			Bindings: &TestVariantFileBindings{Package: "p", References: []string{"BenchmarkEnv", "TestSibling", "helperSibling"}},
		}}
		prior.Declarations = []TestVariantDeclaration{
			{File: "p_test.go", Package: "p", Kind: "func", Name: "BenchmarkEnv", Hash: "b1", References: []string{"BenchmarkEnv"}},
			{File: "p_test.go", Package: "p", Kind: "func", Name: "TestSibling", Hash: "s1", References: []string{"TestSibling", "helperSibling"}},
			{File: "p_test.go", Package: "p", Kind: "func", Name: "helperSibling", Hash: "hs1", References: []string{"helperSibling"}},
		}
		current := prior.Clone()
		// Edit TestSibling and remove helperSibling while leaving BenchmarkEnv untouched.
		current.Declarations = []TestVariantDeclaration{
			{File: "p_test.go", Package: "p", Kind: "func", Name: "BenchmarkEnv", Hash: "b1", References: []string{"BenchmarkEnv"}},
			{File: "p_test.go", Package: "p", Kind: "func", Name: "TestSibling", Hash: "s2", References: []string{"TestSibling"}},
		}
		current.FileHeaders[0].Bindings.References = []string{"BenchmarkEnv", "TestSibling"}
		v.facts.testVariantLedgers[s.Package] = current
		updated, gotLedger, verdict, err := v.checkInertTestVariantExtension(context.Background(), f, prior, s, false)
		if err != nil || verdict.Status != Valid || updated.EffectiveTestVariantClosure() != "B" || !reflect.DeepEqual(gotLedger, current) {
			t.Fatalf("sibling test edit/removal should be inert for %v: verdict=%+v err=%v", s, verdict, err)
		}
	})
}

func TestInertExtensionHonorsSealAndCancellation(t *testing.T) {
	v, f, s, l := applicabilityFixture(t)
	v.sealed = true
	if fp, _, _, err := v.checkInertTestVariantExtension(context.Background(), f, l, s, false); !errors.Is(err, errViewSealed) || fp != (Fingerprint{}) {
		t.Fatalf("sealed publication: %v", err)
	}
	v.sealed = false
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if fp, _, _, err := v.checkInertTestVariantExtension(ctx, f, l, s, false); !errors.Is(err, context.Canceled) || fp != (Fingerprint{}) {
		t.Fatalf("cancelled publication: %v", err)
	}
}

func TestInertExtensionCannotPublishAcrossConcurrentValidation(t *testing.T) {
	for _, observed := range []bool{false, true} {
		v, f, s, l := applicabilityFixture(t)
		v.session.deferredCheckClose = true
		f.RuntimeInputs, f.RuntimeDigest = "recorded input", "digest"
		entered, release := make(chan struct{}), make(chan struct{})
		first := true
		v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
			if first {
				first = false
				close(entered)
				<-release
			}
			return runtimeinput.State{OK: true, Digest: "digest"}, nil
		}
		done := make(chan error, 1)
		go func() {
			updated, ledger, _, err := v.checkInertTestVariantExtension(context.Background(), f, l, s, observed)
			if updated != (Fingerprint{}) || !reflect.DeepEqual(ledger, TestVariantLedger{}) {
				done <- errors.New("published a pair after seal")
				return
			}
			done <- err
		}()
		<-entered
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := v.Validate(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("validation did not seal: %v", err)
		}
		close(release)
		if err := <-done; !errors.Is(err, errViewSealed) {
			t.Fatalf("extension crossed validation: %v", err)
		}
	}
}

func TestInertExtensionRechecksRuntimeAndProofEvidence(t *testing.T) {
	for _, state := range []runtimeinput.State{{}, {OK: true, Digest: "moved"}, {OK: true, Digest: "digest", Unverifiable: true, Reason: "incomplete"}} {
		v, f, s, l := applicabilityFixture(t)
		v.session.deferredCheckClose = true
		f.RuntimeInputs, f.RuntimeDigest = "recorded input", "digest"
		v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) { return state, nil }
		if updated, _, verdict, err := v.checkInertTestVariantExtension(context.Background(), f, l, s, true); err != nil || verdict.Status == Valid || updated != (Fingerprint{}) {
			t.Fatalf("runtime refusal: %+v %v", verdict, err)
		}
	}
	// A manifest changes between the two observations even under deferred close.
	v, f, s, l := applicabilityFixture(t)
	v.session.deferredCheckClose = true
	f.RuntimeInputs, f.RuntimeDigest = "recorded input", "digest"
	calls := 0
	v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
		calls++
		if calls == 1 {
			return runtimeinput.State{OK: true, Digest: "digest"}, nil
		}
		return runtimeinput.State{OK: true, Digest: "moved"}, nil
	}
	if updated, _, verdict, err := v.checkInertTestVariantExtension(context.Background(), f, l, s, false); err != nil || verdict.Status != Stale || updated != (Fingerprint{}) {
		t.Fatalf("moving input served: %+v %v", verdict, err)
	}
}

func TestPackageUnitRefusesIncompatibleScope(t *testing.T) {
	// Membership and package checks are decidable before analysis. These facts
	// deliberately supply no analyzer: an accidental preparation would panic.
	a := Subject{Package: "example.com/a", Symbol: "TestA"}
	b := Subject{Package: a.Package, Symbol: "TestB"}
	c := Subject{Package: "example.com/c", Symbol: "TestC"}
	engine := &engine{executionModel: SingleSubjectExecution}
	snapshot := &Snapshot{session: engine, subjects: []Subject{a, b, c}, packages: []string{a.Package, c.Package}, facts: &observationFacts{}}
	execution := &RuntimeBinding{snapshot: snapshot}
	for _, selected := range [][]Subject{nil, {a, b}, {a, c}, {a, {Package: a.Package, Symbol: "unknown"}}} {
		if u, err := execution.BeginPackage(selected); err == nil || u != nil {
			t.Fatalf("invalid executed scope admitted: %v", selected)
		}
	}
	u, err := execution.BeginPackage([]Subject{a, a})
	if err != nil || !slices.Equal(u.view.subjects, []Subject{a}) {
		t.Fatalf("singleton package scope refused: %v", err)
	}
	engine.executionModel = PackageExecution
	u, err = execution.BeginPackage([]Subject{b, a, b})
	if err != nil || !slices.Equal(u.view.subjects, []Subject{b, a}) {
		t.Fatalf("package scope or order lost: %v", err)
	}
	if _, err := execution.BeginPackage([]Subject{a, c}); err == nil {
		t.Fatal("cross-package process admitted without the singleton assertion")
	}
	u.Abort()
}

func TestProcessAccountIsOwnedDataWithoutProducingCapability(t *testing.T) {
	// Check the actual public value graph, not documentation or field names.
	// Even an embedded capability must not escape through this reporting API.
	forbidden := []reflect.Type{
		reflect.TypeFor[Fingerprint](), reflect.TypeFor[Verdict](),
		reflect.TypeFor[runtimeinput.Observation](), reflect.TypeFor[runtimeinput.OutcomeSupport](),
		reflect.TypeFor[runtimeinput.ProducerFrame](), reflect.TypeFor[Contribution](),
	}
	var inspect func(reflect.Type)
	inspect = func(typ reflect.Type) {
		t.Helper()
		if slices.Contains(forbidden, typ) || typ.NumMethod() != 0 {
			t.Fatalf("process account exposes capability %v", typ)
		}
		switch typ.Kind() {
		case reflect.Struct:
			for i := range typ.NumField() {
				inspect(typ.Field(i).Type)
			}
		case reflect.String, reflect.Bool, reflect.Uint8:
		default:
			t.Fatalf("process account contains non-owned data %v", typ)
		}
	}
	inspect(reflect.TypeFor[ProcessAccount]())
	for _, account := range []func() (ProcessAccount, bool){
		(*Unit)(nil).Account,
		(&Unit{}).Account,
	} {
		if got, ok := account(); ok || got != (ProcessAccount{}) {
			t.Fatalf("uninitialized unit invented an execution: %+v %t", got, ok)
		}
	}
}

func TestProcessAccountRetainsObservationComputedBeforeAbort(t *testing.T) {
	// Model the interleaving between finalization returning and its account
	// being retained: Abort can acquire the unit mutex first. The observation
	// was already computed; recording its facts must grant no closing authority.
	const reason = "process killed"
	observation, err := runtimeinput.Incomplete(t.TempDir(), "terminated-process", reason, []string{})
	if err != nil {
		t.Fatal(err)
	}
	want, err := runtimeinput.CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	terminal := Terminal{Kind: AbnormalCompletion, Reason: reason}
	u := &Unit{
		phase: unitClosing, snapshot: &Snapshot{},
		execution: &unitExecution{process: ProcessDescription{Identity: "terminated-process"},
			artifact: "retained-artifact", ready: true, terminal: terminal, cancel: func() {}},
	}
	u.Abort()
	if err := u.recordObservation(observation, reason); err != nil {
		t.Fatal(err)
	}
	account, ok := u.Account()
	if !ok || account.Process != "terminated-process" || account.Terminal != terminal || account.Observation != IncompleteObservation || account.Inputs != want || account.ObservationReason != reason {
		t.Fatalf("abort suppressed already-computed facts: %+v", account)
	}
	result, err := u.Close(t.Context())
	if !errors.Is(err, errUnitClosed) || !reflect.DeepEqual(result, Finalized{}) {
		t.Fatalf("retaining computed facts reopened the aborted unit: %+v %v", result, err)
	}
}

func TestRuntimeBindingEnvironmentOwnership(t *testing.T) {
	dir := t.TempDir()
	snapshot := &Snapshot{session: &Session{build: BuildDescription{Directory: dir, Environment: []string{"INHERITED=yes", "PWD=wrong"}}}, kind: CodeResult}
	for _, tc := range []struct {
		env  []string
		want []string
	}{
		{nil, []string{"INHERITED=yes", "PWD=" + dir}},
		{[]string{}, []string{"PWD=" + dir}},
		{[]string{"PWD=wrong", "EMPTY="}, []string{"EMPTY=", "PWD=" + dir}},
	} {
		binding := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: tc.env})
		if !slices.Equal(binding.runtime.env, tc.want) {
			t.Fatalf("runtime environment=%q, want %q", binding.runtime.env, tc.want)
		}
	}
	for _, env := range [][]string{{"DUP=1", "DUP=2"}, {"not-an-entry"}, {"=value"}} {
		if b, err := snapshot.BindRuntime(t.Context(), RuntimeDescription{Environment: env}); err == nil || b != nil {
			t.Fatalf("malformed complete environment admitted: %q", env)
		}
	}
	if b, err := snapshot.BindRuntime(nil, RuntimeDescription{}); err == nil || b != nil {
		t.Fatal("nil binding context admitted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if b, err := snapshot.BindRuntime(ctx, RuntimeDescription{}); !errors.Is(err, context.Canceled) || b != nil {
		t.Fatalf("cancelled admission: %v %v", b, err)
	}
	// Every valid ordering and caller mutation has the same canonical owned
	// result. This property covers arbitrary values, including empty values.
	if err := quick.Check(func(value uint64, reverse bool) bool {
		alpha := "ALPHA=" + strings.Repeat("x", int(value%97))
		env := []string{alpha, "BETA=", "PWD=ignored"}
		if reverse {
			slices.Reverse(env)
		}
		b, err := snapshot.BindRuntime(t.Context(), RuntimeDescription{Environment: env})
		if err != nil {
			return false
		}
		want := []string{alpha, "BETA=", "PWD=" + dir}
		for i := range env {
			env[i] = "BROKEN=changed"
		}
		return slices.Equal(b.runtime.env, want) && slices.IsSorted(b.runtime.env) && b.runtime.dir == dir
	}, nil); err != nil {
		t.Fatal(err)
	}
}

// The default deadline constructor preserves both the requested analysis bound
// and the operation's earlier bound/cancellation (REQ-fresh-context). Tests of
// cut provenance may replace the clock; these tests use the real constructor.
func TestAnalysisBoundPreservesDeadlineContract(t *testing.T) {
	prior := viewTestHooks.analysisBound
	viewTestHooks.analysisBound = nil
	t.Cleanup(func() { viewTestHooks.analysisBound = prior })
	parent := context.Background()
	t.Run("requested duration", func(t *testing.T) {
		const budget = time.Minute
		before := time.Now()
		ctx, cancel := analysisBound(parent, budget)
		defer cancel()
		after := time.Now()
		deadline, ok := ctx.Deadline()
		if !ok || deadline.Before(before.Add(budget)) || deadline.After(after.Add(budget)) || ctx.Err() != nil {
			t.Fatalf("deadline = %v/%t, context=%v; want the requested minute", deadline, ok, ctx.Err())
		}
		cancel()
		if ctx.Err() != context.Canceled || parent.Err() != nil {
			t.Fatalf("analysis cancellation: child=%v parent=%v", ctx.Err(), parent.Err())
		}
	})
	t.Run("actual expiry", func(t *testing.T) {
		ctx, cancel := analysisBound(parent, time.Nanosecond)
		defer cancel()
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
			t.Fatal("analysis deadline did not expire")
		}
		if ctx.Err() != context.DeadlineExceeded || parent.Err() != nil {
			t.Fatalf("expiry: child=%v parent=%v", ctx.Err(), parent.Err())
		}
	})
	t.Run("unbounded preserves parent", func(t *testing.T) {
		p, stop := context.WithCancel(parent)
		defer stop()
		ctx, cancel := analysisBound(p, 0)
		cancel()
		if ctx != p || p.Err() != nil {
			t.Fatal("unbounded analysis introduced or cancelled an operation context")
		}
	})
	t.Run("parent cancellation", func(t *testing.T) {
		p, stop := context.WithCancel(parent)
		defer stop()
		ctx, cancel := analysisBound(p, time.Minute)
		defer cancel()
		stop()
		if ctx.Err() != context.Canceled {
			t.Fatalf("operation cancellation = %v", ctx.Err())
		}
	})
	t.Run("earlier parent deadline", func(t *testing.T) {
		deadline := time.Now().Add(time.Minute)
		p, stop := context.WithDeadline(parent, deadline)
		defer stop()
		ctx, cancel := analysisBound(p, 2*time.Minute)
		defer cancel()
		got, ok := ctx.Deadline()
		if !ok || !got.Equal(deadline) {
			t.Fatalf("parent deadline = %v/%t, want %v", got, ok, deadline)
		}
	})
}

func TestApplicabilityBatchesPreserveRecordsAndPolicies(t *testing.T) {
	r := rand.New(rand.NewSource(18341))
	for draw := 0; draw < 300; draw++ {
		var checks []applicabilityCheck
		want := map[applicabilityCheck]int{}
		for n := r.Intn(30); n > 0; n-- {
			check := applicabilityCheck{Fingerprint{RuntimeInputs: fmt.Sprint(r.Intn(5)), RuntimeDigest: fmt.Sprint(r.Intn(5))}, Subject{"p", fmt.Sprint(r.Intn(5))}, r.Intn(2) == 0}
			checks = append(checks, check)
			want[check]++
		}
		got := map[applicabilityCheck]int{}
		for i, record := range applicabilityRecords(checks) {
			check := applicabilityCheck{record.Recorded, record.Subject, record.observed}
			got[check]++
			if check != checks[i] {
				t.Fatalf("draw %d changed candidate order at %d", draw, i)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("draw %d lost or changed historical evidence/policy: got %v want %v", draw, got, want)
		}
	}
}

type applicabilityValidationFixture struct {
	engine     *engine
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
	engine, err := newEngine(withDir(dir), withAssumePure(func(s Subject) bool { return strings.HasPrefix(s.Symbol, "Pure") }))
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
	fileRecord, err := fileProducer.captureObserved(ctx, subjects[2])
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

func (f applicabilityValidationFixture) view(t *testing.T) *Snapshot {
	t.Helper()
	v, err := f.engine.newView(context.Background(), f.subjects, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f applicabilityValidationFixture) extend(t *testing.T, v *Snapshot, subject Subject, record Fingerprint, observed bool) {
	t.Helper()
	_, _, verdict, err := v.checkInertTestVariantExtension(context.Background(), record, f.ledger, subject, observed)
	if err != nil || verdict.Status != Valid {
		t.Fatalf("retain %s: %+v %v", subject.Symbol, verdict, err)
	}
}

// These test adapters expose individual kernel endpoints to drift/authority
// tests without requiring their synthetic records to satisfy source admission.
func (v *Snapshot) observeRuntimeInputs(ctx context.Context, recorded map[Subject]Fingerprint) (map[Subject]runtimeinput.State, error) {
	candidates := orderedCandidates(recorded)
	records := make([]recordCheck, len(candidates))
	results := make([]recordResult, len(candidates))
	for i, candidate := range candidates {
		records[i].Candidate = candidate
		results[i].evaluated = true
	}
	states, err := v.observeRecordInputs(ctx, records, results)
	if err != nil {
		return nil, err
	}
	observed := make(map[Subject]runtimeinput.State, len(candidates))
	for i, candidate := range candidates {
		observed[candidate.Subject] = states[i]
	}
	return observed, nil
}

func (v *Snapshot) finishRuntimeObservation(ctx context.Context, recorded map[Subject]Fingerprint, before map[Subject]runtimeinput.State, verdicts map[Subject]Verdict) (map[Subject]Verdict, error) {
	after, err := v.observeRuntimeInputs(ctx, recorded)
	if err != nil {
		return nil, err
	}
	for subject, fingerprint := range recorded {
		verdicts[subject] = v.runtimeMotion(ctx, Candidate{subject, fingerprint}, verdicts[subject], before[subject], after[subject])
	}
	for subject, verdict := range verdicts {
		verdicts[subject] = v.judgmentFor(subject, verdict)
	}
	return verdicts, nil
}

// TestKeptOnCancelDetailRendersItsCounts pins the kept-on-cancel
// report's rendering: each count with its own noun, singular at one,
// proofs before scans.
func TestKeptOnCancelDetailRendersItsCounts(t *testing.T) {
	for _, row := range []struct {
		proofs, scans int
		want          string
	}{
		{1, 1, "1 observability proof slice and 1 scan persisted this operation; a rerun serves them"},
		{1, 3, "1 observability proof slice and 3 scans persisted this operation; a rerun serves them"},
		{0, 0, "0 observability proof slices and 0 scans persisted this operation; a rerun serves them"},
	} {
		if got := keptOnCancelDetail(row.proofs, row.scans); got != row.want {
			t.Errorf("keptOnCancelDetail(%d, %d) = %q, want %q", row.proofs, row.scans, got, row.want)
		}
	}
}

// Every go command the engine's packages spawn goes through a Runner
// value: gotool exports no free-function spawn (a package-level
// (ctx, dir, env) form a runner value also offers — the forwarders
// gotool once carried are gone, and one returning would re-enter the
// walk here), and an inline plain runner's call appears in no non-test
// source outside gotool itself, so a site cannot bypass the runner it
// was handed by spelling the plain one. A plain Runner value built at
// a site and handed on (the directive scan's) is that site's stated
// choice, outside the walk. The walk reads sources from disk (a
// hand-edit oracle); its logic is pinned over synthetic sources below.
func TestEngineSpawnSitesReadARunner(t *testing.T) {
	free := freeSpawnFunctions(t)
	if len(free) != 0 {
		t.Fatalf("gotool exports free spawn functions %v; every spawn rides a Runner value", free)
	}
	bare, err := bareSpawnSites(".", free)
	if err != nil {
		t.Fatal(err)
	}
	if len(bare) != 0 {
		t.Fatalf("free-function spawns outside gotool: %v", bare)
	}
	loads, err := barePackageLoadSites(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(loads) != 0 {
		t.Fatalf("direct packages.Load calls outside gotool.LoadPackages: %v", loads)
	}
}

// The walk's logic over synthetic sources: the free spawn functions
// are read whatever local name the import takes, an inline plain
// runner's spawn is read, a runner value's own call is not, and a test
// file, a fixture directory, and gotool itself are skipped.
//
//gofresh:pure
func TestBareSpawnWalkReadsTheThreeFreeFunctions(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package a\n\nimport gt \"github.com/greatliontech/gofresh/internal/gotool\"\n\nfunc f(r gt.Runner) {\n\tgt.Run(ctx, d, e)\n\tgt.TakeEnvSnapshot(ctx, d, e)\n\tgt.SampleGoVersion(ctx, d, e)\n\tgt.Runner{}.Run(ctx, d, e)\n\tr.Run(ctx, d, e)\n\tgt.NewEnvReader(r, d, e)\n\tother.Run(ctx)\n}\n")
	write("b.go", "package a\n\nimport \"github.com/greatliontech/gofresh/internal/gotool\"\n\nfunc g() { gotool.Run(ctx, d, e) }\n")
	write("a_test.go", "package a\n\nimport \"github.com/greatliontech/gofresh/internal/gotool\"\n\nfunc h() { gotool.Run(ctx, d, e) }\n")
	write("fixtures/c.go", "package c\n\nimport \"github.com/greatliontech/gofresh/internal/gotool\"\n\nfunc h() { gotool.Run(ctx, d, e) }\n")
	write("internal/gotool/g.go", "package gotool\n\nfunc h() { Run(ctx, d, e) }\n")
	write("d.go", "package a\n\nimport . \"github.com/greatliontech/gofresh/internal/gotool\"\n\nfunc k() { Run(ctx, d, e); other(ctx) }\n")
	got, err := bareSpawnSites(dir, []string{"Run", "TakeEnvSnapshot", "SampleGoVersion"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.go:6 gt.Run", "a.go:7 gt.TakeEnvSnapshot", "a.go:8 gt.SampleGoVersion", "a.go:9 gt.Runner{}.Run", "b.go:5 gotool.Run", "d.go:5 .Run"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("bare sites = %v, want %v", got, want)
	}
}

// freeSpawnFunctions derives the names of gotool's free spawn
// functions from its source: the package-level functions taking
// (ctx, dir, env) — the forms a runner value also offers — so a fourth
// one is read by the walk the day it exists.
func freeSpawnFunctions(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, filepath.Join("internal", "gotool"), func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Params == nil || len(fn.Type.Params.List) < 3 {
					continue
				}
				params := fn.Type.Params.List
				ctxT, ok1 := params[0].Type.(*ast.SelectorExpr)
				dirT, ok2 := params[1].Type.(*ast.Ident)
				envT, ok3 := params[2].Type.(*ast.ArrayType)
				if ok1 && ok2 && ok3 && ctxT.Sel.Name == "Context" && dirT.Name == "string" {
					if elt, ok := envT.Elt.(*ast.Ident); ok && elt.Name == "string" {
						names = append(names, fn.Name.Name)
					}
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

// bareSpawnSites walks the non-test Go sources under root, outside the
// gotool package, for calls of gotool's free spawn functions — through
// whatever local name a file imports the package under — and for an
// inline plain runner's spawn (gotool.Runner{}.Run), which is the same
// bypass spelled differently.
func bareSpawnSites(root string, free []string) ([]string, error) {
	var sites []string
	fset := token.NewFileSet()
	const gotoolPath = "github.com/greatliontech/gofresh/internal/gotool"
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "fixtures" || rel == "gotool" || rel == filepath.Join("internal", "gotool")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		local := ""
		for _, imp := range file.Imports {
			if strings.Trim(imp.Path.Value, "\"") != gotoolPath {
				continue
			}
			local = "gotool"
			if imp.Name != nil {
				local = imp.Name.Name
			}
		}
		if local == "" {
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			line := fset.Position(call.Pos()).Line
			if local == "." {
				// A dot import: the free function is a bare identifier.
				if id, ok := call.Fun.(*ast.Ident); ok && slices.Contains(free, id.Name) {
					sites = append(sites, rel+":"+strconv.Itoa(line)+" ."+id.Name)
				}
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch x := sel.X.(type) {
			case *ast.Ident:
				if x.Name == local && slices.Contains(free, sel.Sel.Name) {
					sites = append(sites, rel+":"+strconv.Itoa(line)+" "+local+"."+sel.Sel.Name)
				}
			case *ast.CompositeLit:
				if typ, ok := x.Type.(*ast.SelectorExpr); ok {
					if pkg, ok := typ.X.(*ast.Ident); ok && pkg.Name == local && typ.Sel.Name == "Runner" && len(x.Elts) == 0 {
						sites = append(sites, rel+":"+strconv.Itoa(line)+" "+local+".Runner{}."+sel.Sel.Name)
					}
				}
			}
			return true
		})
		return nil
	})
	return sites, err
}

// barePackageLoadSites walks the non-test Go sources under root, outside
// the gotool package, for direct calls to x/tools/go/packages.Load so
// every package-loader invocation rides gotool.LoadPackages.
func barePackageLoadSites(root string) ([]string, error) {
	var sites []string
	fset := token.NewFileSet()
	const packagesPath = "github.com/greatliontech/go-x-tools/go/packages"
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "fixtures" || rel == "gotool" || rel == filepath.Join("internal", "gotool")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		local := ""
		for _, imp := range file.Imports {
			if strings.Trim(imp.Path.Value, "\"") != packagesPath {
				continue
			}
			local = "packages"
			if imp.Name != nil {
				local = imp.Name.Name
			}
		}
		if local == "" {
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			line := fset.Position(call.Pos()).Line
			if local == "." {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "Load" {
					sites = append(sites, rel+":"+strconv.Itoa(line)+" .Load")
				}
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == local && sel.Sel.Name == "Load" {
				sites = append(sites, rel+":"+strconv.Itoa(line)+" "+local+".Load")
			}
			return true
		})
		return nil
	})
	return sites, err
}

// The protocol model tests arbitrary submission/abort/cancelled-close sequences.
// It supplies a prepared slot directly: real preparation, normal closing and
// native evidence are exercised by the separate process integration witness.
func FuzzUnitTerminalProtocol(f *testing.F) {
	for _, input := range [][]byte{{0, 1, 2, 3}, {4, 4, 0}, {5, 0}, {0, 0, 5}, {7, 8, 9, 10, 11, 12}} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		u := &Unit{snapshot: &Snapshot{}}
		submit, abort := u.Submit, u.Abort
		closeUnit := func(ctx context.Context) (bool, error) {
			result, err := u.Close(ctx)
			return reflect.DeepEqual(result, Finalized{}), err
		}
		x := &unitExecution{ready: true, cancel: func() {}}
		u.execution = x
		own := Contribution{unit: u, execution: x}
		other := Contribution{unit: &Unit{}, execution: x}
		cases := []struct {
			terminal Terminal
			valid    bool
		}{
			{Terminal{Kind: NormalCompletion}, true},
			{Terminal{Kind: AbnormalCompletion, Reason: "killed"}, true},
			{Terminal{Kind: NeverStarted, Reason: "no slot"}, true},
			{Terminal{}, false},
			{Terminal{Kind: NormalCompletion, Reason: "not normal"}, false},
			{Terminal{Kind: AbnormalCompletion}, false},
			{Terminal{Kind: 255, Reason: "unknown"}, false},
		}
		ended, settled := false, false
		for i, op := range input {
			switch op % 4 {
			case 0, 1:
				candidate := cases[int(op/4)%len(cases)]
				handle := own
				if op%4 == 1 {
					handle = other
				}
				err := submit(handle, candidate.terminal)
				want := !ended && !settled && op%4 == 0 && candidate.valid
				if (err == nil) != want {
					t.Fatalf("step %d: submission accepted=%t want=%t ended=%t settled=%t", i, err == nil, want, ended, settled)
				}
				if want {
					settled = true
				}
			case 2:
				abort()
				ended = true
			case 3:
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				empty, err := closeUnit(ctx)
				want := error(context.Canceled)
				if ended {
					want = errUnitClosed
				}
				if !errors.Is(err, want) || !empty {
					t.Fatalf("step %d: cancelled close returned evidence or wrong cause: %v (want %v)", i, err, want)
				}
				ended = true
			}
		}
	})
}
