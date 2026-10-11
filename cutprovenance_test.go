package gofresh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// A cut belongs to the immutable observation, including when a subset becomes
// an independently closing producer (REQ-fresh-producer-view, REQ-fresh-context).
func TestSiblingPreservesBudgetCutProvenance(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and cuts one reachability pass")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	const source = "package view\n\nimport \"example.com/cut/gen\"\n\nfunc F() int { return gen.Size() }\n\nfunc Property() { gen.Compile(\"k\") }\n"
	dir := writeModuleTree(t, map[string]string{
		"go.mod":       "module example.com/cut\n\ngo 1.26\n",
		"gen/gen.go":   "package gen\n\nvar memo = map[string]func(){}\n\nfunc Compile(name string) { memo[name] = func() {} }\n\nfunc Size() int { return len(memo) }\n",
		"view.go":      source,
		"pure/pure.go": "package pure\n\nfunc F() int { return 7 }\n",
		"fixture":      "stable",
	})
	const budget = 10 * time.Second
	passes := 0
	viewTestHooks.observe = func() { passes++ }
	viewTestHooks.beforeDischarge = func() {
		if passes == 1 {
			time.Sleep(budget + time.Second)
		}
	}
	t.Cleanup(func() {
		viewTestHooks.observe = nil
		viewTestHooks.beforeDischarge = nil
	})
	engine, err := New(WithDir(dir), WithSingleSubjectExecution(), WithAnalysisBudget(budget))
	if err != nil {
		t.Fatal(err)
	}
	cut := Subject{Package: "example.com/cut", Symbol: "F"}
	pure := Subject{Package: "example.com/cut/pure", Symbol: "F"}
	parent, err := engine.NewView(context.Background(), []Subject{cut, pure}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if passes != 2 || !parent.facts.cut[cut] || parent.facts.cut[pure] {
		t.Fatalf("construction premise: passes=%d cut=%v", passes, parent.facts.cut)
	}
	if err := parent.Validate(context.Background()); !errors.Is(err, ErrAnalysisUnavailable) || errors.Is(err, ErrViewChanged) {
		t.Fatalf("parent on unchanged tree: %v, want cut unavailability", err)
	}
	sibling := func(t *testing.T, from *View, subjects ...Subject) *View {
		t.Helper()
		before := passes
		v, err := from.Sibling(subjects)
		if err != nil {
			t.Fatal(err)
		}
		if passes != before {
			t.Fatal("subset selection performed an observation")
		}
		return v
	}
	assertCut := func(t *testing.T, v *View) {
		t.Helper()
		if err := v.Validate(context.Background()); !errors.Is(err, ErrAnalysisUnavailable) || errors.Is(err, ErrViewChanged) {
			t.Fatalf("sibling on unchanged tree: %v, want cut unavailability", err)
		}
	}
	attach := func(t *testing.T, v *View, fp Fingerprint) {
		t.Helper()
		observation, err := riFromTestLog([]byte("open fixture\n"), dir, dir,
			runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.AttachObservation(cut, fp, observation); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("maximal and nested", func(t *testing.T) {
		first := sibling(t, parent, cut)
		assertCut(t, first)
		assertCut(t, sibling(t, first, cut))
	})
	t.Run("unaffected subset", func(t *testing.T) {
		if err := sibling(t, parent, pure).Validate(context.Background()); err != nil {
			t.Fatalf("uncut subject borrowed another subject's cut: %v", err)
		}
	})
	for _, inherited := range []bool{false, true} {
		t.Run(fmt.Sprintf("observed inherited=%t", inherited), func(t *testing.T) {
			v := sibling(t, parent, cut)
			fp, err := v.CaptureObserved(context.Background(), cut)
			if err != nil {
				t.Fatal(err)
			}
			if fp.SingleSubjectDischarges != "" {
				t.Fatal("cut capture gained a discharge")
			}
			if inherited {
				v = sibling(t, v, cut)
			}
			attach(t, v, fp)
			assertCut(t, v)
		})
	}
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := sibling(t, parent, cut).Validate(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled sibling: %v", err)
		}
	})
	t.Run("runtime movement", func(t *testing.T) {
		v := sibling(t, parent, cut)
		fp, err := v.CaptureObserved(context.Background(), cut)
		if err != nil {
			t.Fatal(err)
		}
		attach(t, v, fp)
		if err := os.WriteFile(filepath.Join(dir, "fixture"), []byte("moved"), 0o644); err != nil {
			t.Fatal(err)
		}
		err = v.Validate(context.Background())
		if !errors.Is(err, ErrViewChanged) || !strings.Contains(err.Error(), "runtime inputs") || errors.Is(err, ErrAnalysisUnavailable) {
			t.Fatalf("runtime drift behind a cut: %v", err)
		}
	})
	t.Run("source movement", func(t *testing.T) {
		v := sibling(t, parent, cut)
		if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte(strings.Replace(source, "return gen.Size()", "return gen.Size() + 1", 1)), 0o644); err != nil {
			t.Fatal(err)
		}
		err := v.Validate(context.Background())
		if !errors.Is(err, ErrViewChanged) || errors.Is(err, ErrAnalysisUnavailable) {
			t.Fatalf("source drift behind a cut: %v", err)
		}
	})
}

// Every nonempty subset keeps exactly its subjects' cut provenance, including
// nested projections and repeated selection. Comparison still distinguishes a
// genuine hash change from discharge availability (REQ-fresh-unit-close).
func FuzzSiblingCutProjection(f *testing.F) {
	f.Add([]byte{1, 0, 3, 2, 7, 4})
	f.Add([]byte{0})
	f.Add([]byte{1, 1, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		if len(data) > 32 {
			data = data[:32]
		}
		parent := &View{facts: &observationFacts{
			maximal: map[Subject]closure.Closure{},
			cut:     map[Subject]bool{},
		}}
		var selected []Subject
		for i, b := range data {
			s := Subject{Package: "example.com/property", Symbol: fmt.Sprintf("F%d", i)}
			parent.subjects = append(parent.subjects, s)
			parent.facts.maximal[s] = closure.Closure{Hash: fmt.Sprintf("hash%d", i), Unverifiable: true, Reason: "refusal"}
			if b&1 != 0 {
				parent.facts.cut[s] = true
			}
			if i == 0 || b&2 != 0 {
				selected = append(selected, s)
			}
		}
		child, err := parent.Sibling(selected)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range parent.subjects {
			included := false
			for _, chosen := range selected {
				included = included || chosen == s
			}
			if got, want := child.facts.cut[s], included && parent.facts.cut[s]; got != want {
				t.Fatalf("cut provenance for %v: got %t want %t", s, got, want)
			}
		}
		nested, err := child.Sibling([]Subject{selected[0], selected[0]})
		if err != nil {
			t.Fatal(err)
		}
		s := selected[0]
		current := *nested.facts
		cl := current.maximal[s]
		cl.Unverifiable, cl.Reason = false, ""
		current.maximal = map[Subject]closure.Closure{s: cl}
		current.cut = nil
		err = nested.compareObservationContext(context.Background(), current)
		if parent.facts.cut[s] {
			if !errors.Is(err, ErrAnalysisUnavailable) || errors.Is(err, ErrViewChanged) {
				t.Fatalf("cut-only difference: %v", err)
			}
		} else if err == nil {
			// The synthetic uncut row retains its reason; changing it without
			// a cut is a real difference, not a licensed neutralization.
			t.Fatal("uncut difference was neutralized")
		}
		cl.Hash = "moved"
		current.maximal[s] = cl
		if err := nested.compareObservationContext(context.Background(), current); !errors.Is(err, ErrViewChanged) {
			t.Fatalf("hash movement: %v", err)
		}
	})
}
