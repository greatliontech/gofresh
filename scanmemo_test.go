package gofresh

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// scanMemoModule writes a two-package module whose view package imports
// a sibling and whose subject carries a purity directive, a dynamic mark,
// and an external mark — every scan output class the memo persists.
func scanMemoModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":            "module example.com/scanmemo\n\ngo 1.26\n",
		"dep/dep.go":        "package dep\n\nvar Hooks = map[string]func(){}\n\nfunc Bump() { Hooks[\"x\"] = func() {} }\n\nfunc Add(a, b int) int { return a + b }\n",
		"view/view.go":      "package view\n\nimport \"example.com/scanmemo/dep\"\n\n//gofresh:pure\nfunc Pure(x int) int { return dep.Add(x, 1) }\n\nfunc Mutating() { dep.Bump() }\n\n//gofresh:external\nfunc External() int { return 0 }\n",
		"view/view_test.go": "package view\n\nimport \"testing\"\n\nfunc TestPure(t *testing.T) {\n\tif Pure(1) != 2 {\n\t\tt.Fatal()\n\t}\n}\n",
		"other/other.go":    "package other\n\nfunc Unrelated() int { return 3 }\n",
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
	return dir
}

var scanMemoSubjects = []Subject{
	{Package: "example.com/scanmemo/view", Symbol: "Pure"},
	{Package: "example.com/scanmemo/view", Symbol: "Mutating"},
	{Package: "example.com/scanmemo/view", Symbol: "External"},
	{Package: "example.com/scanmemo/view", Symbol: "TestPure"},
}

// scanOutputs captures a view's scan-derived facts for every subject: the
// projection a served scan must reproduce exactly.
func scanOutputs(t *testing.T, view *View, subjects []Subject) map[Subject]string {
	t.Helper()
	out := map[Subject]string{}
	for _, s := range subjects {
		fp, err := view.Capture(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		out[s] = fp.MaximalClosure + "|" + fp.PurityAssertion + "|" + boolWord(view.facts.maximal[s].Unverifiable) + "|" + view.facts.maximal[s].Reason + "|" + view.facts.vouchDischarges[s] + "|" + view.facts.packageProcessDischarges[s] + "|" + view.facts.attestationDischarges[s]
	}
	return out
}

func boolWord(b bool) string {
	if b {
		return "unverifiable"
	}
	return "verifiable"
}

// A second view over an unchanged tree serves every view package's scan
// from the memo — no typed load — with outputs identical to the cold
// view's (REQ-closure-scan-memo).
func TestScanMemoServesTheWholeScanWithoutATypedLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := scanMemoModule(t)
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	cold, err := engine.NewView(context.Background(), scanMemoSubjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := scanOutputs(t, cold, scanMemoSubjects)
	loads := 0
	viewTestHooks.typedLoad = func() { loads++ }
	defer func() { viewTestHooks.typedLoad = nil }()
	var events []Progress
	warmEngine, err := New(WithDir(dir), WithProgress(func(p Progress) { events = append(events, p) }))
	if err != nil {
		t.Fatal(err)
	}
	warm, err := warmEngine.NewView(context.Background(), scanMemoSubjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	if loads != 0 {
		t.Fatalf("the warm view paid %d typed loads", loads)
	}
	served := 0
	for _, e := range events {
		if e.Phase == "served" && e.Served == "scan" && e.Index == 1 {
			served++
		}
	}
	if served != 1 {
		t.Fatalf("scan served summaries = %d, want one for the view package: %+v", served, events)
	}
	if got := scanOutputs(t, warm, scanMemoSubjects); !reflect.DeepEqual(got, want) {
		t.Fatalf("served scan differs from the cold one:\n got %v\nwant %v", got, want)
	}
	// The outputs themselves carry the marks the memo must reproduce.
	if !strings.Contains(want[scanMemoSubjects[1]], "unverifiable") || !strings.Contains(want[scanMemoSubjects[2]], "external directive") {
		t.Fatalf("fixture no longer exercises the dynamic and external marks: %v", want)
	}
}

// A vouch is load-bearing for the discharges an entry records, so a
// changed vouch set misses; a corrupt entry recomputes.
func TestScanMemoMissesOnVouchChangeAndCorruption(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	dir := scanMemoModule(t)
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.NewView(context.Background(), scanMemoSubjects, dir); err != nil {
		t.Fatal(err)
	}
	loads := 0
	viewTestHooks.typedLoad = func() { loads++ }
	defer func() { viewTestHooks.typedLoad = nil }()
	vouched, err := New(WithDir(dir), WithDynamicStateVouches("example.com/scanmemo/dep:Hooks"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vouched.NewView(context.Background(), scanMemoSubjects, dir); err != nil {
		t.Fatal(err)
	}
	if loads == 0 {
		t.Fatal("a changed vouch set served the unvouched scan")
	}
	// Corrupt every scan entry: the next view recomputes silently.
	entries, _ := filepath.Glob(filepath.Join(cache, "gofresh", "scanfacts", "*.json"))
	if len(entries) == 0 {
		t.Fatal("no scan entries persisted")
	}
	for _, e := range entries {
		if err := os.WriteFile(e, []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	loads = 0
	if _, err := engine.NewView(context.Background(), scanMemoSubjects, dir); err != nil {
		t.Fatal(err)
	}
	if loads == 0 {
		t.Fatal("a corrupt entry served")
	}
}

// The key moves under any edit inside the view package's test-binary
// graph and holds under an edit outside it, so a served scan never
// describes bytes other than the current ones (REQ-closure-scan-memo).
func TestScanMemoKeyTracksTheTestBinaryGraph(t *testing.T) {
	if testing.Short() {
		t.Skip("builds module fixtures and runs the engine over them")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := scanMemoModule(t)
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.NewView(context.Background(), scanMemoSubjects, dir); err != nil {
		t.Fatal(err)
	}
	loads := 0
	viewTestHooks.typedLoad = func() { loads++ }
	defer func() { viewTestHooks.typedLoad = nil }()
	for _, tc := range []struct {
		path   string
		inside bool
	}{
		{"dep/dep.go", true}, {"view/view.go", true}, {"view/view_test.go", true}, {"other/other.go", false},
	} {
		for _, comment := range []string{"a", "second edit"} {
			full := filepath.Join(dir, filepath.FromSlash(tc.path))
			original, err := os.ReadFile(full)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, append(append([]byte(nil), original...), []byte("\n// "+comment+"\n")...), 0o644); err != nil {
				t.Fatal(err)
			}
			loads = 0
			_, err = engine.NewView(context.Background(), scanMemoSubjects, dir)
			if restoreErr := os.WriteFile(full, original, 0o644); restoreErr != nil {
				t.Fatal(restoreErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.inside && loads == 0 {
				t.Fatalf("an edit to %s (inside the graph) served the stale scan", tc.path)
			}
			if !tc.inside && loads != 0 {
				t.Fatalf("an edit to %s (outside the graph) missed the scan memo", tc.path)
			}
		}
	}
}

// leakModule writes a four-package module in which package d owns a
// function-valued variable, a reads it, c rebinds it, and b reaches c:
// a's test binary never links the mutation, b's does.
func leakModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":      "module example.com/leak\n\ngo 1.26\n",
		"a/a.go":      "package a\n\nimport \"example.com/leak/d\"\n\nfunc F() { d.Run() }\n",
		"b/b.go":      "package b\n\nimport \"example.com/leak/c\"\n\nfunc G(f func()) { c.Rebind(f) }\n",
		"c/c.go":      "package c\n\nimport \"example.com/leak/d\"\n\nfunc Rebind(f func()) { d.Callback = f }\n",
		"d/d.go":      "package d\n\nvar Callback = func() {}\n\nfunc Run() { Callback() }\n",
		"a/a_test.go": "package a\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) { F() }\n",
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
	return dir
}

var (
	leakA        = Subject{Package: "example.com/leak/a", Symbol: "F"}
	leakB        = Subject{Package: "example.com/leak/b", Symbol: "G"}
	leakSubjects = []Subject{leakA, leakB}
)

func newLeakView(t *testing.T, dir string, subjects []Subject, opts ...Option) *View {
	t.Helper()
	engine, err := New(append([]Option{WithDir(dir)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// The shared-dynamic-state judgment is per package graph: a view batching
// several packages yields for each exactly what its solitary view yields,
// a mutation linked only by a sibling's binary never opens a package, and
// a pass mixing served and derived packages reproduces the cold outputs
// (REQ-closure-shared-dynamic-state, REQ-closure-scan-memo).
func TestScanMemoComposesEachPackageOverItsOwnGraph(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := leakModule(t)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	batch := scanOutputs(t, newLeakView(t, dir, leakSubjects), leakSubjects)
	if !strings.Contains(batch[leakA], "|verifiable|") {
		t.Fatalf("a mutation linked only by b's binary opened a: %s", batch[leakA])
	}
	if !strings.Contains(batch[leakB], "example.com/leak/d.Callback") {
		t.Fatalf("b's own graph links the mutation yet b is not downgraded on it: %s", batch[leakB])
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	soloA := scanOutputs(t, newLeakView(t, dir, leakSubjects[:1]), leakSubjects[:1])
	soloB := scanOutputs(t, newLeakView(t, dir, leakSubjects[1:]), leakSubjects[1:])
	if soloA[leakA] != batch[leakA] || soloB[leakB] != batch[leakB] {
		t.Fatalf("batched view differs from the solitary views:\nbatch %v\nsolo  %v %v", batch, soloA, soloB)
	}
	// A cache warmed by a's solitary view serves a into the batched pass
	// while b derives — the served half and the derived half agree with
	// the cold batch.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	newLeakView(t, dir, leakSubjects[:1])
	loads := 0
	viewTestHooks.typedLoad = func() { loads++ }
	defer func() { viewTestHooks.typedLoad = nil }()
	var events []Progress
	mixed := newLeakView(t, dir, leakSubjects, WithProgress(func(p Progress) { events = append(events, p) }))
	// One typed load: b derives in the first pass beside the served a;
	// the agreement pass then serves both from the store.
	if loads != 1 {
		t.Fatalf("typed loads = %d, want one for b", loads)
	}
	servedScans := 0
	for _, e := range events {
		if e.Phase == "served" && e.Served == "scan" {
			servedScans += e.Index
		}
	}
	if servedScans != 2 {
		t.Fatalf("scan packages served = %d, want both by the operation's end", servedScans)
	}
	if got := scanOutputs(t, mixed, leakSubjects); !reflect.DeepEqual(got, batch) {
		t.Fatalf("mixed served/derived pass differs from the cold batch:\n got %v\nwant %v", got, batch)
	}
}

// An entry of another shape — a version the reader does not speak —
// recomputes rather than serving (REQ-closure-scan-memo).
func TestScanMemoRefusesAnEntryOfAnotherShape(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	dir := scanMemoModule(t)
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.NewView(context.Background(), scanMemoSubjects, dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := filepath.Glob(filepath.Join(cache, "gofresh", "scanfacts", "*.json"))
	if len(entries) == 0 {
		t.Fatal("no scan entries persisted")
	}
	for _, e := range entries {
		raw, err := os.ReadFile(e)
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Scope   string          `json:"scope"`
			Key     string          `json:"key"`
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if string(payload["version"]) != "1" {
			t.Fatalf("entry %s carries version %s, want 1", e, payload["version"])
		}
		payload["version"] = json.RawMessage("0")
		envelope.Payload, _ = json.Marshal(payload)
		rewritten, _ := json.Marshal(envelope)
		if err := os.WriteFile(e, rewritten, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	loads := 0
	viewTestHooks.typedLoad = func() { loads++ }
	defer func() { viewTestHooks.typedLoad = nil }()
	if _, err := engine.NewView(context.Background(), scanMemoSubjects, dir); err != nil {
		t.Fatal(err)
	}
	if loads == 0 {
		t.Fatal("an entry of another version served")
	}
}

// Every scan output class survives the entry's persisted form: a scan
// projected to entries, marshalled, unmarshalled, and rebuilt is the
// same scan (REQ-closure-scan-memo).
func TestScanEntryRoundTripsEveryOutput(t *testing.T) {
	pkg := "example.com/p"
	s := func(sym string) Subject { return Subject{Package: pkg, Symbol: sym} }
	scan := &subjectScan{
		known: map[Subject]bool{s("A"): true, s("B"): true, s("C"): true}, pure: map[Subject]bool{s("A"): true},
		openWorld: map[Subject]bool{s("B"): true}, external: map[Subject]bool{s("C"): true},
		downgradeReason: map[Subject]string{s("B"): "reason"}, vouchDischarges: map[Subject]string{s("A"): "v"},
		attestationDischarges: map[Subject]string{s("B"): "att"}, packageProcessDischarges: map[Subject]string{s("C"): "pp"},
		ambiguous: map[Subject]string{s("C"): "declared twice"},
	}
	raw, err := json.Marshal(entryOf(scan, pkg))
	if err != nil {
		t.Fatal(err)
	}
	var entry packageScanEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Version != scanEntryVersion {
		t.Fatalf("version %d, want %d", entry.Version, scanEntryVersion)
	}
	got := scanFromEntries(map[string]packageScanEntry{pkg: entry})
	if !reflect.DeepEqual(got, scan) {
		t.Fatalf("round trip lost an output:\n got %+v\nwant %+v", got, scan)
	}
}

// An entry is stored after the attestation-scoped discharges finished
// shaping the scan, so a served scan carries the discharge and its
// record exactly as the cold derivation did (REQ-closure-scan-memo).
func TestScanMemoServesTheDischargedScan(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	for path, content := range map[string]string{
		"go.mod":     "module example.com/view\n\ngo 1.26\n",
		"gen/gen.go": "package gen\n\nvar memo = map[string]func(){}\n\nfunc Compile(name string) { memo[name] = func() {} }\n\nfunc Size() int { return len(memo) }\n",
		"view.go":    "package view\n\nimport \"example.com/view/gen\"\n\nfunc F() int { return gen.Size() }\n\nfunc Property() { gen.Compile(\"k\") }\n",
	} {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	subjects := []Subject{{Package: "example.com/view", Symbol: "F"}, {Package: "example.com/view", Symbol: "Property"}}
	cold := scanOutputs(t, newLeakView(t, dir, subjects, WithSingleSubjectExecution()), subjects)
	if !strings.Contains(cold[subjects[0]], "|verifiable|") || !strings.HasSuffix(cold[subjects[0]], "|example.com/view/gen.memo") {
		t.Fatalf("the attestation did not discharge F's culprit on record: %s", cold[subjects[0]])
	}
	loads := 0
	viewTestHooks.typedLoad = func() { loads++ }
	defer func() { viewTestHooks.typedLoad = nil }()
	warm := scanOutputs(t, newLeakView(t, dir, subjects, WithSingleSubjectExecution()), subjects)
	if loads != 0 {
		t.Fatalf("the warm view paid %d typed loads", loads)
	}
	if !reflect.DeepEqual(warm, cold) {
		t.Fatalf("served discharged scan differs from the cold one:\n got %v\nwant %v", warm, cold)
	}
}
