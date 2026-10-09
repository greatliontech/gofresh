package gofresh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/runtimeinput"
)

func TestCoverageLocalitySelectsValidationWithoutObservationAttachment(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs and validates whole-program source views")
	}
	ctx := context.Background()
	dir := writeSupportedViewModule(t)
	path := filepath.Join(dir, "observed_test.go")
	source := `package observed
import ("os"; "testing")
func add(a, b int) int { return a+b }
func TestArithmetic(t *testing.T) { if add(1, 2) != 3 { t.Fatal("arithmetic") } }
func TestEnv(t *testing.T) { _ = os.Getenv("GOCOVERDIR") }
`
	if err := os.WriteFile(path, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{{Package: "example.com/observed", Symbol: "TestArithmetic"}, {Package: "example.com/observed", Symbol: "TestEnv"}}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, drift := range []bool{false, true} {
		view, err := engine.NewView(ctx, subjects, dir)
		if err != nil {
			t.Fatal(err)
		}
		proofs, err := view.CaptureCoverageLocality(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(proofs) != len(subjects) {
			t.Fatalf("partial projection: %+v", proofs)
		}
		for i, subject := range subjects {
			got := proofs[subject]
			fp, err := view.Capture(ctx, subject)
			if err != nil {
				t.Fatal(err)
			}
			if (got.Status == CoverageLocalityAdmitted) != (i == 0) || got.Subject != subject || got.Strategy != CoverageLocalityStrategy || got.MaximalClosure != fp.MaximalClosure || got.TestVariantClosure != fp.TestVariantClosure || got.Toolchain != fp.Guards.Toolchain || got.BuildConfig != fp.Guards.BuildConfig || got.ObservationStrategy != ObservationRTA || got.ClosureStrategy != ClosureStrategy || got.DynamicStateStrategy != DynamicStateStrategy {
				t.Fatalf("projection: %+v", got)
			}
		}
		sibling, err := view.Sibling([]Subject{subjects[0]})
		if err != nil {
			t.Fatal(err)
		}
		if !sibling.coverageSelected || len(sibling.capturedObserved) != 0 {
			t.Fatal("sibling lost selection or invented observation assertion")
		}
		if drift {
			if err := os.WriteFile(path, []byte(source+"\nfunc added() {}\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		analyses := 0
		viewTestHooks.beforeAnalysis = func() { analyses++ }
		err = sibling.Validate(ctx)
		viewTestHooks.beforeAnalysis = nil
		if drift && !errors.Is(err, ErrViewChanged) || !drift && err != nil {
			t.Fatalf("drift=%t validation=%v", drift, err)
		}
		if !drift && analyses == 0 {
			t.Fatal("validation failed to re-establish selected locality inventory")
		}
		if _, err := sibling.CaptureCoverageLocality(ctx); !errors.Is(err, ErrViewSealed) {
			t.Fatalf("sealed capture: %v", err)
		}
	}
}

func TestCoverageLocalityBudgetCutRefuses(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs source view with cut precise analysis")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeSupportedViewModule(t)
	engine, err := New(WithDir(dir), WithAnalysisBudget(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := view.CaptureCoverageLocality(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p := proofs[subject]; p.Status != CoverageLocalityRefused || !analysisUnavailable(p.Reason) {
		t.Fatalf("cut projection: %+v", p)
	}
}

func TestCoverageLocalityRejectsMissingSelection(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if got, err := (&View{}).CaptureCoverageLocality(ctx); err == nil || got != nil {
			t.Fatalf("empty selection: %+v %v", got, err)
		}
	}
}

func TestCoverageLocalityRefusesEachCallerDischarge(t *testing.T) {
	subject := Subject{Package: "example.com/p", Symbol: "TestPure"}
	for _, channel := range []string{"none", "vouch", "single", "package"} {
		t.Run(channel, func(t *testing.T) {
			facts := &observationFacts{
				vouchDischarges: map[Subject]string{}, attestationDischarges: map[Subject]string{}, packageProcessDischarges: map[Subject]string{},
			}
			switch channel {
			case "vouch":
				facts.vouchDischarges[subject] = "p.state"
			case "single":
				facts.attestationDischarges[subject] = "p.state"
			case "package":
				facts.packageProcessDischarges[subject] = "p.state"
			}
			v := &View{engine: &Engine{}, subjects: []Subject{subject}, facts: facts,
				observable: map[Subject]closure.Observability{subject: {Observable: true, CoverageLocal: true}}}
			got, err := v.CaptureCoverageLocality(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if (got[subject].Status == CoverageLocalityAdmitted) != (channel == "none") {
				t.Fatalf("%s: %+v", channel, got[subject])
			}
		})
	}
}

func TestMixedLocalityValidationPreparesBeforeObservation(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs selected source views")
	}
	ctx := context.Background()
	dir := writeSupportedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, drift := range []bool{false, true} {
		v, err := engine.NewView(ctx, []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.CaptureCoverageLocality(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := v.CaptureObserved(ctx, subject); err != nil {
			t.Fatal(err)
		}
		if drift {
			if err := os.WriteFile(filepath.Join(dir, "observed_test.go"), []byte("package observed\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		observations := 0
		viewTestHooks.observe = func() { observations++ }
		err = v.Validate(ctx)
		viewTestHooks.observe = nil
		if err == nil || !strings.Contains(err.Error(), "no attached completed observation") || observations != 0 {
			t.Fatalf("drift=%t: err=%v observations=%d", drift, err, observations)
		}
	}
}

func TestMixedLocalityValidationSharesAnalysisAndClosesInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs and validates selected source views")
	}
	ctx := context.Background()
	dir := writeSupportedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"none", "runtime", "source"} {
		v, err := engine.NewView(ctx, []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.CaptureCoverageLocality(ctx); err != nil {
			t.Fatal(err)
		}
		obs := supportedObservation(t, v, dir, dir, "execution", "getenv OUTCOME_VALUE\n")
		fp, err := v.CaptureObserved(ctx, subject)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.AttachObservation(subject, fp, obs); err != nil {
			t.Fatal(err)
		}
		analyses, reads := 0, 0
		viewTestHooks.beforeAnalysis = func() {
			analyses++
			if change == "source" {
				if err := os.WriteFile(filepath.Join(dir, "observed_test.go"), []byte("package observed\n"), 0644); err != nil {
					t.Error(err)
				}
			}
		}
		v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
			reads++
			state := obs.State
			if change == "runtime" && reads == 2 {
				state.Digest = "changed"
			}
			return state, nil
		}
		err = v.Validate(ctx)
		viewTestHooks.beforeAnalysis = nil
		if analyses != 1 {
			t.Fatalf("%s analyses=%d", change, analyses)
		}
		if change == "none" && (err != nil || reads != 2) {
			t.Fatalf("unchanged: %v reads=%d", err, reads)
		}
		if change == "runtime" && (!errors.Is(err, ErrViewChanged) || reads != 2) {
			t.Fatalf("runtime close: %v reads=%d", err, reads)
		}
		if change == "source" && err == nil {
			t.Fatal("source close lost")
		}
	}
}
