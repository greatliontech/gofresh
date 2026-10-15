package gofresh

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/greatliontech/gofresh/runtimeinput"
)

func TestViewMembershipRefusalsRetainSelectionScope(t *testing.T) {
	if testing.Short() {
		t.Skip("loads a real declared-but-unselected subject")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module example.com/members\n\ngo 1.27.0\n",
		"p.go":   "package members\nfunc F() int { return 1 }\nfunc G() int { return 2 }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	f, g := Subject{Package: "example.com/members", Symbol: "F"}, Subject{Package: "example.com/members", Symbol: "G"}
	all, err := session.Snapshot(t.Context(), []Subject{f, g}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	if declared, err := bindTestRuntime(t, all, RuntimeDescription{}).CurrentFacts(t.Context(), g); err != nil || declared.MaximalClosure == "" {
		t.Fatalf("the excluded subject is not a real declaration: %v", err)
	}
	view, err := all.view.Sibling([]Subject{f})
	if err != nil {
		t.Fatal(err)
	}
	selected := &Snapshot{session: session, view: view}
	bound := bindTestRuntime(t, selected, RuntimeDescription{})
	view.beforePreciseAnalysis = func() { t.Fatal("membership refusal started proof work") }
	observation, err := runtimeinput.Incomplete(dir, "unrelated-process", "no completion", os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"capture":          func() error { _, err := view.Capture(t.Context(), g); return err },
		"observed capture": func() error { _, err := view.CaptureObserved(t.Context(), g); return err },
		"source files":     func() error { _, err := view.SourceFilesFor(g); return err },
		"ledger":           func() error { _, err := view.TestVariantLedger(g); return err },
		"attachment":       func() error { _, err := view.AttachObservation(g, Fingerprint{}, observation); return err },
		"binding facts":    func() error { _, err := bound.CurrentFacts(t.Context(), g); return err },
		"snapshot sources": func() error { _, err := selected.SourceFilesFor(g); return err },
		"snapshot ledger":  func() error { _, err := selected.TestVariantLedger(g); return err },
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			var refusal *UnknownSubjectsError
			if !errors.As(err, &refusal) || refusal.Scope != SelectedView || !slices.Equal(refusal.Subjects, []Subject{g}) {
				t.Fatalf("selected-view refusal lost its typed scope: %T %v", err, err)
			}
		})
	}
	if _, err := bound.CurrentFacts(t.Context(), f); err != nil {
		t.Fatalf("refused projection sealed a valid sibling: %v", err)
	}
}
