package gofresh

import (
	"context"
	"errors"
	"testing"

	"github.com/greatliontech/gofresh/closure"
)

// testSubjectFacts builds synthetic base observations for verdict-ladder tests.
// Production acquires these inputs from ComputeMaximalFactsBatch and the scan;
// no reverse projection can reconstruct a real complete blocker inventory.
func testSubjectFacts(c closure.Closure) subjectFacts {
	f := subjectFacts{
		source: closure.MaximalFacts{
			Identity: closure.MaximalIdentity{Hash: c.Hash, TestVariants: c.TestVariants,
				ToolchainContent: c.ToolchainContent, AdmissionPolicy: c.AdmissionPolicy},
			Diagnostic: c.Reason,
		},
		external: c.External,
	}
	if c.Unverifiable {
		r := &subjectRefusal{
			reason:  c.Reason,
			culprit: Subject{Package: c.Culprit.Package, Symbol: c.Culprit.Symbol},
		}
		switch c.Refusal {
		case closure.OpenWorldRefusal:
			f.openWorld = r
		case closure.SharedDynamicStateRefusal:
			f.sharedState = r
		case closure.AmbiguousSubjectRefusal:
			f.ambiguous = r
		default:
			f.source.Effects = []closure.Blocker{{Reason: c.Reason}}
		}
	}
	return f
}

func TestSubjectFactsHiddenObligations(t *testing.T) {
	s := Subject{Package: "example.com/base", Symbol: "F"}
	base := testSubjectFacts(closure.Closure{Hash: "source", Unverifiable: true, Reason: "effect"})
	base.source.Effects = append(base.source.Effects, closure.Blocker{Kind: closure.BlockerEnvironment, Package: "os", Symbol: "Getenv"})
	base.openWorld = &subjectRefusal{reason: "open"}
	base.sharedState = &subjectRefusal{reason: "shared"}
	base.ambiguous = &subjectRefusal{reason: "ambiguous"}
	base.external = true
	view := &View{subjects: []Subject{s}, facts: &observationFacts{maximal: map[Subject]subjectFacts{s: base}}}
	for _, tc := range []struct {
		name   string
		change func(*subjectFacts)
	}{
		{"source effect", func(f *subjectFacts) { f.source.Effects = f.source.Effects[1:] }},
		{"open world", func(f *subjectFacts) { f.openWorld = nil }},
		{"shared state", func(f *subjectFacts) { f.sharedState = nil }},
		{"ambiguous", func(f *subjectFacts) { f.ambiguous = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			tc.change(&changed)
			// Externality still decides both projections. Comparing only that
			// projection would miss the changed underlying obligation.
			if changed.closure().Reason != base.closure().Reason {
				t.Fatal("test did not hide the changed obligation")
			}
			current := observationFacts{maximal: map[Subject]subjectFacts{s: changed}}
			if err := view.compareObservationContext(t.Context(), current); !errors.Is(err, ErrViewChanged) {
				t.Fatalf("hidden obligation change: %v", err)
			}
			current.cut = map[Subject]bool{s: true}
			want := ErrViewChanged
			if tc.name == "shared state" {
				want = ErrAnalysisUnavailable
			}
			if err := view.compareObservationContext(t.Context(), current); !errors.Is(err, want) {
				t.Fatalf("cut comparison: %v, want %v", err, want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		set  func(*subjectFacts, *subjectRefusal)
		kind closure.RefusalKind
	}{
		{"open", func(f *subjectFacts, r *subjectRefusal) { f.openWorld = r }, closure.OpenWorldRefusal},
		{"shared", func(f *subjectFacts, r *subjectRefusal) { f.sharedState = r }, closure.SharedDynamicStateRefusal},
		{"ambiguous", func(f *subjectFacts, r *subjectRefusal) { f.ambiguous = r }, closure.AmbiguousSubjectRefusal},
	} {
		t.Run("empty diagnostic/"+tc.name, func(t *testing.T) {
			f := testSubjectFacts(closure.Closure{Hash: "source"})
			tc.set(&f, &subjectRefusal{})
			if c := f.closure(); !c.Unverifiable || c.Refusal != tc.kind {
				t.Fatalf("empty diagnostic erased obligation: %+v", c)
			}
		})
	}
}

func TestSubjectFactsProjectionAndSiblingIsolation(t *testing.T) {
	s := Subject{Package: "example.com/base", Symbol: "F"}
	base := testSubjectFacts(closure.Closure{Hash: "source", Unverifiable: true, Reason: "effect"})
	base.openWorld = &subjectRefusal{reason: "open"}
	base.sharedState = &subjectRefusal{reason: "shared"}
	load := &closure.ViewLoad{}
	parent := &View{subjects: []Subject{s}, facts: &observationFacts{
		maximal: map[Subject]subjectFacts{s: base}, source: load,
	}}
	child, err := parent.Sibling([]Subject{s})
	if err != nil {
		t.Fatal(err)
	}
	if child.facts.source != load || !child.facts.maximal[s].equal(base, false) {
		t.Fatal("sibling lost its generation or an underlying obligation")
	}
	projection := child.facts.closure(s)
	projection.Hash, projection.Unverifiable, projection.Reason = "foreign", false, ""
	if !child.facts.maximal[s].equal(base, false) || !parent.facts.maximal[s].equal(base, false) {
		t.Fatal("local projection changed shared facts")
	}
	// Taking a cut may select the unavailable shared-state analysis, but
	// never replaces the first observation's selected-source inputs.
	other := observationFacts{maximal: map[Subject]subjectFacts{s: base}}
	b := other.maximal[s]
	b.sharedState = &subjectRefusal{reason: "cut"}
	b.openWorld = nil // deliberately different; takeCut has no authority over it
	other.maximal[s] = b
	child.facts.takeCut(other, s)
	if child.facts.source != load || child.facts.maximal[s].openWorld != base.openWorld || child.facts.maximal[s].sharedState.reason != "cut" {
		t.Fatal("cut replaced non-discharge inputs")
	}
	if !parent.facts.maximal[s].equal(base, false) {
		t.Fatal("sibling cut mutated parent facts")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := parent.compareObservationContext(cancelled, *parent.facts); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled comparison: %v", err)
	}
}

func TestViewBaseFactsKeepMaskedEffects(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over a fixture with independent simultaneous blockers")
	}
	dir := writeModuleTree(t, map[string]string{
		"go.mod": "module example.com/base\n\ngo 1.26\n",
		"base.go": `package base
import ("os"; "net")
var Hook = func() {}
func Rebind() { Hook = func() {} }
//gofresh:external
func F(callback func()) { callback(); Hook(); _ = os.Getenv("INPUT"); _, _ = net.Dial("tcp", "") }
`,
	})
	e, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	s := Subject{Package: "example.com/base", Symbol: "F"}
	v, err := e.NewView(t.Context(), []Subject{s}, dir)
	if err != nil {
		t.Fatal(err)
	}
	f := v.facts.maximal[s]
	if !f.external || f.openWorld == nil || f.sharedState == nil {
		t.Fatalf("consumer-tier obligations were overwritten: %+v", f)
	}
	env, network := false, false
	for _, effect := range f.source.Effects {
		env = env || effect.Package == "os" && effect.Symbol == "Getenv"
		network = network || effect.Package == "net" && effect.Symbol == "Dial"
	}
	if !env || !network {
		t.Fatalf("masked source obligations lost: %+v", f.source.Effects)
	}
	fp, err := v.Capture(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := v.Check(t.Context(), fp, s)
	if err != nil || verdict.Status != Unverifiable || verdict.Ground.Cause.Kind != ExternalDirectiveCause {
		t.Fatalf("ordinary external projection changed: %+v, %v", verdict, err)
	}
	if err := v.Validate(t.Context()); err != nil {
		t.Fatalf("unchanged complete base did not close: %v", err)
	}
}
