package gofresh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure"
)

// The construction pass reports its units — each package's listing and
// closure fold with its position, the shared typed load with its pattern
// count — and a warm precise analysis reports the memo hit that stood in
// for its program load, while an operation returning its caller's
// cancellation reports what the pass persisted.
func TestProgressReportsUnitsServedAndKept(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":      "module example.com/units\n\ngo 1.26\n",
		"a/a.go":      "package a\n\nfunc A() int { return 1 }\n",
		"a/a_test.go": "package a\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {\n\tif A() != 1 {\n\t\tt.Fatal()\n\t}\n}\n",
		"b/b.go":      "package b\n\nfunc B() int { return 2 }\n",
		"b/b_test.go": "package b\n\nimport \"testing\"\n\nfunc TestB(t *testing.T) {\n\tif B() != 2 {\n\t\tt.Fatal()\n\t}\n}\n",
	}
	for path, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a, b := Subject{Package: "example.com/units/a", Symbol: "TestA"}, Subject{Package: "example.com/units/b", Symbol: "TestB"}
	var events []Progress
	engine, err := New(WithDir(dir), WithProgress(func(p Progress) { events = append(events, p) }))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{a, b}, dir)
	if err != nil {
		t.Fatal(err)
	}
	hashes, lists, loads := map[string]Progress{}, map[string]bool{}, 0
	for _, e := range events {
		switch e.Phase {
		case "hash":
			hashes[e.Package] = e
		case "list":
			lists[e.Package] = true
		case "typecheck":
			loads++
			if e.Total < 2 {
				t.Fatalf("typed load reports %d patterns, want the two view packages at least", e.Total)
			}
		}
	}
	for _, pkg := range []string{a.Package, b.Package} {
		if !lists[pkg] {
			t.Fatalf("no list event for %s: %+v", pkg, events)
		}
		h, ok := hashes[pkg]
		if !ok || h.Total != 2 || h.Index < 1 || h.Index > 2 {
			t.Fatalf("hash event for %s = %+v, want index in 1..2 of 2", pkg, h)
		}
	}
	if loads == 0 {
		t.Fatal("no typed-load event on the construction pass")
	}

	// A cold precise analysis loads and proves; the same view's second
	// engine over the same tree serves the proof from the memo and says
	// so instead of loading.
	if _, err := view.CaptureObserved(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	events = nil
	warm, err := New(WithDir(dir), WithProgress(func(p Progress) { events = append(events, p) }))
	if err != nil {
		t.Fatal(err)
	}
	warmView, err := warm.NewView(context.Background(), []Subject{a}, dir)
	if err != nil {
		t.Fatal(err)
	}
	events = nil
	if _, err := warmView.CaptureObserved(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	served, proved, detailed := 0, false, 0
	for _, e := range events {
		if e.Phase == "served" && e.Served == "observability proof" {
			served++
			if e.Index != 1 || e.Detail != "" {
				t.Fatalf("served summary = %+v, want one package counted and no Detail (a consumer printing details must stay silent)", e)
			}
		}
		if e.Phase == "prove" {
			proved = true
		}
		if e.Detail != "" {
			detailed++
		}
	}
	if served != 1 || proved {
		t.Fatalf("warm capture served summaries=%d proved=%t, want exactly one summary and no proof: %+v", served, proved, events)
	}
	if detailed != 0 {
		t.Fatalf("%d Detail-bearing events on a clean warm capture; served must not ride the diagnostic channel", detailed)
	}

	// An operation cancelled mid-analysis reports what the pass
	// persisted before the cancellation.
	cancelled, cancel := context.WithCancel(context.Background())
	viewTestHooks.beforeAnalysis = cancel
	defer func() { viewTestHooks.beforeAnalysis = nil }()
	events = nil
	coldView, err := warm.NewView(context.Background(), []Subject{b}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coldView.CaptureObserved(cancelled, b); err == nil {
		t.Fatal("cancelled capture succeeded")
	}
	reported := 0
	for _, e := range events {
		if e.Phase == "cancelled" && strings.Contains(e.Detail, "persisted this operation") {
			reported++
		}
	}
	if reported != 1 {
		t.Fatalf("kept-on-cancel reports = %d, want exactly one per operation: %+v", reported, events)
	}

	// A non-context failure reports no cancellation.
	viewTestHooks.beforeAnalysis = nil
	events = nil
	if _, err := warm.NewView(context.Background(), []Subject{{Package: a.Package, Symbol: "NoSuch"}}, dir); err == nil {
		t.Fatal("unknown subject built a view")
	}
	for _, e := range events {
		if e.Phase == "cancelled" {
			t.Fatalf("a refusal that is not a cancellation reported one: %+v", e)
		}
	}
}

// The operation boundary reports once however many public operations
// nest: an inner beginOperation on an already-accounted context is a
// no-op finisher, and the outer one emits the served summaries and the
// cancel report over everything its passes accounted.
func TestOperationBoundaryReportsOncePerOperation(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, preparationSource)
	var events []Progress
	engine, err := New(WithDir(dir), WithProgress(func(p Progress) { events = append(events, p) }))
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := closure.NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	hasher.Served("effect scan", "example.com/view")
	outerCtx, outerDone := engine.beginOperation(context.Background())
	innerCtx, innerDone := engine.beginOperation(outerCtx)
	accountPass(innerCtx, hasher)
	cancelled := context.Canceled
	innerDone(&cancelled)
	if len(events) != 0 {
		t.Fatalf("the nested operation reported: %+v", events)
	}
	outerDone(&cancelled)
	served, reports := 0, 0
	for _, e := range events {
		switch e.Phase {
		case "served":
			served++
			if e.Served != "effect scan" || e.Index != 1 || e.Detail != "" {
				t.Fatalf("served summary = %+v", e)
			}
		case "cancelled":
			reports++
		}
	}
	if served != 1 || reports != 1 {
		t.Fatalf("outer operation emitted served=%d cancelled=%d, want one each: %+v", served, reports, events)
	}
}
