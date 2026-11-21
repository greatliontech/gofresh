package observability

import (
	"context"
	"encoding/json"

	"fmt"
	"maps"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/closure"
)

func memoModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/memo\n\ngo 1.26\n")
	writeFile(t, dir, "memo.go", "package memo\n\nfunc Pure(x int) int { return x + 1 }\n")
	writeFile(t, dir, "memo_test.go", `package memo

import "testing"

func TestPure(t *testing.T) {
	if Pure(1) != 2 {
		t.Fatal("pure")
	}
}
`)
	return dir
}

// A memoized proof serves byte-equivalent results without loading the
// program (REQ-closure-observability-memo): the second hasher under the
// same scope and unchanged source emits no load or prove events and
// returns identical dispositions.
func TestObservabilityMemoServesEquivalentProofsWithoutLoading(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := memoModule(t)
	subjects := []Subject{
		{Package: "example.com/memo", Symbol: "Pure"},
		{Package: "example.com/memo", Symbol: "TestPure"},
		{Package: "example.com/memo", Symbol: "Missing"},
	}

	first, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	first.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "strategy@1|toolchain|build", BuildConfig: "build"})
	cold, err := first.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}

	second, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	second.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "strategy@1|toolchain|build", BuildConfig: "build"})
	loads := 0
	second.OnProgress(func(phase, _ string) {
		if phase == "load" || phase == "prove" {
			loads++
		}
	})
	second.OnUnit(func(phase, _ string, _, _ int) {
		if phase == "prove" {
			loads++
		}
	})
	warm, err := second.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if loads != 0 {
		t.Fatalf("warm batch emitted %d load/prove events, want the memo to skip the program", loads)
	}
	if len(warm) != len(cold) {
		t.Fatalf("warm results = %d, cold %d", len(warm), len(cold))
	}
	for subject, proof := range cold {
		if warm[subject] != proof {
			t.Fatalf("memoized proof for %s differs: cold %+v, warm %+v", subject.Symbol, proof, warm[subject])
		}
	}
}

// The memo misses on a different scope and on changed source: the key is
// the complete input identity (REQ-closure-observability-memo).
func TestObservabilityMemoMissesOnScopeAndSourceChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := memoModule(t)
	subjects := []Subject{{Package: "example.com/memo", Symbol: "Pure"}}

	first, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	first.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
	if _, err := first.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}

	otherScope, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	otherScope.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-b", BuildConfig: "build"})
	loads := 0
	otherScope.OnUnit(func(phase, _ string, _, _ int) {
		if phase == "prove" {
			loads++
		}
	})
	if _, err := otherScope.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}
	if loads == 0 {
		t.Fatal("a different scope served from the memo")
	}

	src, err := os.ReadFile(filepath.Join(dir, "memo.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memo.go"), append(src, []byte("\nfunc Extra() int { return 9 }\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	moved, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	moved.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
	loads = 0
	moved.OnUnit(func(phase, _ string, _, _ int) {
		if phase == "prove" {
			loads++
		}
	})
	if _, err := moved.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}
	if loads == 0 {
		t.Fatal("changed source served from the memo")
	}

	// Test-only source is part of the analyzed test binary: an edit that
	// moves only the test-variant compartment must miss exactly as a core
	// edit does — the analyzed program's bytes moved.
	testSrc, err := os.ReadFile(filepath.Join(dir, "memo_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memo_test.go"), append(testSrc, []byte("\nfunc TestExtra(t *testing.T) { t.Setenv(\"K\", \"V\") }\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	testMoved, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	testMoved.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
	loads = 0
	testMoved.OnUnit(func(phase, _ string, _, _ int) {
		if phase == "prove" {
			loads++
		}
	})
	if _, err := testMoved.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}
	if loads == 0 {
		t.Fatal("a test-only source change served from the memo")
	}
}

// TestBatchEntriesDiscardStaleTestBinaryKeys pins the key memo's call
// scope: a batch entry must start from an empty test-binary-key memo, or
// an edit between calls on one Hasher could key persistent memo entries
// under a prior generation's identity.
func TestBatchEntriesDiscardStaleTestBinaryKeys(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := memoModule(t)
	subjects := []Subject{{Package: "example.com/memo", Symbol: "Pure"}}

	first, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	first.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
	if _, err := first.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}

	// A pre-armed stale key is discarded at the batch entry, so the batch
	// derives the real key and hits the entry the first pass stored.
	second, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	second.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
	second.SeedCallScopeForTest("example.com/memo", "stale-key", "", "")
	loads := 0
	second.OnProgress(func(phase, _ string) {
		if phase == "load" || phase == "prove" {
			loads++
		}
	})
	second.OnUnit(func(phase, _ string, _, _ int) {
		if phase == "prove" {
			loads++
		}
	})
	if _, err := second.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}
	if loads != 0 {
		t.Fatal("a stale pre-call key defeated the memo hit")
	}
	if second.HasStaleCallScopeForTest("example.com/memo", "stale-key", "") {
		t.Fatal("the observability batch retained a pre-call key generation")
	}

	third, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	third.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
	staleProg := &Program{summaries: programSummaries{nonReadOnlyGlobals: map[*ssa.Global]bool{}}}
	third.progs["example.com/memo"] = staleProg
	third.ResetCallScope()
	if staleProg.summaries.nonReadOnlyGlobals != nil {
		t.Fatal("Prover.ResetCallScope did not clear retained Program.summaries")
	}
	staleProg.summaries.nonReadOnlyGlobals = map[*ssa.Global]bool{}
	third.SeedCallScopeForTest("example.com/memo", "stale-key", "stale-compartment", "")
	batched, _, err := third.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if staleProg.summaries.nonReadOnlyGlobals != nil {
		t.Fatal("Prover.ComputeMaximalBatch did not clear retained Program.summaries")
	}
	if third.HasStaleCallScopeForTest("example.com/memo", "stale-key", "") {
		t.Fatal("the hashing batch retained a pre-call key generation")
	}
	if batched[subjects[0]].TestVariants == "stale-compartment" {
		t.Fatal("the hashing batch served a pre-call compartment identity")
	}
}

// cancelWhenDirNonEmpty cancels every context consult once dir holds an
// entry — deterministic mid-group cancellation landing right after the
// first attribution slice's memo write.
type cancelWhenDirNonEmpty struct{ dir string }

func (c cancelWhenDirNonEmpty) Deadline() (time.Time, bool) { return time.Time{}, false }

func (c cancelWhenDirNonEmpty) Done() <-chan struct{} { return nil }

func (c cancelWhenDirNonEmpty) Value(any) any { return nil }

func (c cancelWhenDirNonEmpty) Err() error {
	entries, err := os.ReadDir(c.dir)
	if err == nil && len(entries) > 0 {
		return context.Canceled
	}
	return nil
}

// TestObservabilityMemoKeepsCompletedSlicesOnDeadline pins the write
// granularity (REQ-closure-observability-memo): a deadline expiring
// mid-group forfeits only the interrupted slice's proofs — every
// completed slice persists and a later pass serves it from the memo.
func TestObservabilityMemoKeepsCompletedSlicesOnDeadline(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheRoot)
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/slices\n\ngo 1.26\n")
	count := maxAttributedSubjects + 2
	var source strings.Builder
	source.WriteString("package slices\n\n")
	subjects := make([]Subject, count)
	for i := range subjects {
		symbol := fmt.Sprintf("F%d", i)
		fmt.Fprintf(&source, "func %s() int { return %d }\n", symbol, i)
		subjects[i] = Subject{Package: "example.com/slices", Symbol: symbol}
	}
	writeFile(t, dir, "slices.go", source.String())

	first, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	first.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
	memoFiles := filepath.Join(cacheRoot, "gofresh", "observability")
	_ = first.WithContext(cancelWhenDirNonEmpty{dir: memoFiles}, func() error {
		if _, err := first.ComputeObservabilityBatch(subjects); err == nil {
			t.Fatal("mid-group cancellation did not surface")
		}
		return nil
	})

	entries, err := os.ReadDir(memoFiles)
	if err != nil || len(entries) != 1 {
		t.Fatalf("memo entries = %v, err %v; want exactly one", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(memoFiles, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var envelope cachefile.Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	var proofs map[string]Observability
	if err := json.Unmarshal(envelope.Payload, &proofs); err != nil {
		t.Fatal(err)
	}
	if len(proofs) != maxAttributedSubjects {
		t.Fatalf("persisted proofs = %d, want the completed slice's %d", len(proofs), maxAttributedSubjects)
	}
	for i := range maxAttributedSubjects {
		if _, ok := proofs[fmt.Sprintf("F%d", i)]; !ok {
			t.Fatalf("completed slice's proof F%d missing from the memo", i)
		}
	}
	for i := maxAttributedSubjects; i < count; i++ {
		if _, ok := proofs[fmt.Sprintf("F%d", i)]; ok {
			t.Fatalf("interrupted slice's proof F%d persisted", i)
		}
	}

	second, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	second.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
	results, err := second.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != count {
		t.Fatalf("resumed batch results = %d, want %d", len(results), count)
	}
}

// The pass counts what it persisted: a cold batch under a memo scope stores
// its proof slice and the pass reports it, so the kept-on-cancel report's
// numbers are the store's, never a constant.
func TestObservabilityBatchCountsPersistedProofs(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := memoModule(t)
	subjects := []Subject{{Package: "example.com/memo", Symbol: "Pure"}, {Package: "example.com/memo", Symbol: "TestPure"}}
	cold, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	cold.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "strategy@1|toolchain|build", BuildConfig: "build"})
	if _, err := cold.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}
	if proofs, _ := cold.Persisted(); proofs != 1 {
		t.Fatalf("cold batch persisted %d proof slices, want the one slice it stored", proofs)
	}
	warm, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	warm.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "strategy@1|toolchain|build", BuildConfig: "build"})
	if _, err := warm.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}
	if proofs, _ := warm.Persisted(); proofs != 0 {
		t.Fatalf("warm batch persisted %d proof slices, want none", proofs)
	}
	if served := warm.ServedSummary()["observability proof"]; !served["example.com/memo"] {
		t.Fatalf("warm batch served = %v, want the package recorded under the observability class", warm.ServedSummary())
	}
}

// A memo entry holding only other subjects of the package serves nothing:
// the requested subject proves and stores, and the pass records no
// observability-proof serve for the package.
func TestObservabilityMemoEntryWithoutTheRequestedSubjectServesNothing(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := memoModule(t)
	cold, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	cold.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "strategy@1|toolchain|build", BuildConfig: "build"})
	if _, err := cold.ComputeObservabilityBatch([]Subject{{Package: "example.com/memo", Symbol: "Pure"}}); err != nil {
		t.Fatal(err)
	}
	sibling, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	sibling.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "strategy@1|toolchain|build", BuildConfig: "build"})
	if _, err := sibling.ComputeObservabilityBatch([]Subject{{Package: "example.com/memo", Symbol: "TestPure"}}); err != nil {
		t.Fatal(err)
	}
	if served := sibling.ServedSummary()["observability proof"]; served["example.com/memo"] {
		t.Fatalf("an entry holding only Pure was reported as serving TestPure: %v", sibling.ServedSummary())
	}
	if proofs, _ := sibling.Persisted(); proofs != 1 {
		t.Fatalf("the unserved subject persisted %d slices, want its own one", proofs)
	}
}

func TestRootedFunctionsAndBinaryRootedFunctionsMemoServeAcrossPasses(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := memoModule(t)
	subjects := []Subject{{Package: "example.com/memo", Symbol: "Pure"}, {Package: "example.com/memo", Symbol: "TestPure"}}
	scope := AnalysisScope{ProofStrategy: "p", Toolchain: "strategy@1|toolchain|build", BuildConfig: "build"}

	cold, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	cold.SetAnalysisScope(scope)
	firstRooted, err := cold.ComputeRootedFunctions(cold.Context(), subjects)
	if err != nil {
		t.Fatal(err)
	}
	firstBinary, err := cold.ComputeBinaryRootedFunctions(cold.Context(), []string{"example.com/memo"})
	if err != nil {
		t.Fatal(err)
	}

	warm, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	warm.SetAnalysisScope(scope)
	secondRooted, err := warm.ComputeRootedFunctions(warm.Context(), subjects)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstRooted, secondRooted) {
		t.Fatalf("warm rooted functions = %+v, want %+v", secondRooted, firstRooted)
	}
	if !warm.ServedSummary()["rooted functions"]["example.com/memo"] {
		t.Fatalf("expected warm ComputeRootedFunctions to record serve: %v", warm.ServedSummary())
	}
	secondBinary, err := warm.ComputeBinaryRootedFunctions(warm.Context(), []string{"example.com/memo"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstBinary, secondBinary) {
		t.Fatalf("warm binary rooted functions = %+v, want %+v", secondBinary, firstBinary)
	}
	if !warm.ServedSummary()["binary rooted functions"]["example.com/memo"] {
		t.Fatalf("expected warm ComputeBinaryRootedFunctions to record serve: %v", warm.ServedSummary())
	}
}

func TestRootedFunctionsBatchEntriesDiscardStaleTestBinaryKeysAndHonorContext(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := memoModule(t)
	subjects := []Subject{{Package: "example.com/memo", Symbol: "Pure"}}
	scope := AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"}

	// Cold observability pass also warms the rooted-functions memo.
	obsHasher, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	obsHasher.SetAnalysisScope(scope)
	if _, err := obsHasher.ComputeObservabilityBatch(subjects); err != nil {
		t.Fatal(err)
	}

	// Stale pre-call keys and contributions on ComputeRootedFunctions are discarded
	// via resetCallScope, so the entry warmed by ComputeObservabilityBatch hits.
	rootedHasher, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	rootedHasher.SetAnalysisScope(scope)
	rootedHasher.SeedCallScopeForTest("example.com/memo", "stale-key", "", "src:example.com/memo=stale")
	if _, err := rootedHasher.ComputeRootedFunctions(rootedHasher.Context(), subjects); err != nil {
		t.Fatal(err)
	}
	if !rootedHasher.ServedSummary()["rooted functions"]["example.com/memo"] {
		t.Fatalf("stale pre-call key defeated rooted-functions memo hit: %v", rootedHasher.ServedSummary())
	}
	if rootedHasher.HasStaleCallScopeForTest("example.com/memo", "stale-key", "src:example.com/memo=stale") {
		t.Fatal("ComputeRootedFunctions retained stale testBinaryKeys")
	}

	// Populate binary rooted memo, then verify ComputeBinaryRootedFunctions also
	// discards stale testBinaryKeys and restores h.Context() after a cancelled call.
	if _, err := obsHasher.ComputeBinaryRootedFunctions(obsHasher.Context(), []string{"example.com/memo"}); err != nil {
		t.Fatal(err)
	}
	binHasher, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	binHasher.SetAnalysisScope(scope)
	binHasher.SeedCallScopeForTest("example.com/memo", "stale-key", "", "")
	if _, err := binHasher.ComputeBinaryRootedFunctions(binHasher.Context(), []string{"example.com/memo"}); err != nil {
		t.Fatal(err)
	}
	if !binHasher.ServedSummary()["binary rooted functions"]["example.com/memo"] {
		t.Fatalf("stale pre-call key defeated binary-rooted-functions memo hit: %v", binHasher.ServedSummary())
	}
	if binHasher.HasStaleCallScopeForTest("example.com/memo", "stale-key", "") {
		t.Fatal("ComputeBinaryRootedFunctions retained stale testBinaryKeys")
	}

	cancelled, cancel := context.WithCancel(binHasher.Context())
	cancel()
	if _, err := binHasher.ComputeRootedFunctions(cancelled, subjects); err == nil {
		t.Fatal("expected cancelled context to fail ComputeRootedFunctions")
	}
	if binHasher.ContextErr() != nil {
		t.Fatal("ComputeRootedFunctions did not restore h.ctx after cancelled call")
	}
	if _, err := binHasher.ComputeBinaryRootedFunctions(cancelled, []string{"example.com/memo"}); err == nil {
		t.Fatal("expected cancelled context to fail ComputeBinaryRootedFunctions")
	}
	if binHasher.ContextErr() != nil {
		t.Fatal("ComputeBinaryRootedFunctions did not restore h.ctx after cancelled call")
	}
}

func TestBatchEntriesDiscardStaleContributionEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/memo\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m.go"), []byte("package memo\n\nfunc M() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/memo", Symbol: "M"}
	h.SeedCallScopeForTest("example.com/memo", "", "", "src:example.com/memo=stale")
	batched, _, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	hFresh, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	independent, _, err := hFresh.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if batched[subject] != independent[subject] {
		t.Fatalf("batch served a pre-call memo generation: %+v vs %+v", batched[subject], independent[subject])
	}
	h2, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2.SeedCallScopeForTest("example.com/memo", "", "", "src:example.com/memo=stale")
	if _, err := h2.ComputeObservabilityBatch([]Subject{{Package: "example.com/memo", Symbol: "M"}}); err != nil {
		t.Fatal(err)
	}
	if h2.HasStaleCallScopeForTest("example.com/memo", "", "src:example.com/memo=stale") {
		t.Fatal("observability batch served or retained a pre-call memo generation")
	}
}

// sync.Map's Load, Store, and LoadOrStore are the audited memo set:
// process-memory operations a subject may reach observably. Its other
// operations keep the unaudited-standard refusal — Range walks an order
// seeded at runtime (REQ-closure-shared-dynamic-state-memo).
func TestSyncMapMemoOperationsAreAuditedAndRangeIsNot(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/syncmemo\n\ngo 1.26\n")
	cases := []struct{ pkg, source, refusal string }{
		{"memo", "package memo\n\nimport \"sync\"\n\nvar m sync.Map\n\nfunc Subject() int {\n\tm.Store(\"k\", 1)\n\tv, _ := m.LoadOrStore(\"k\", 2)\n\tw, _ := m.Load(\"k\")\n\treturn v.(int) + w.(int)\n}\n", ""},
		{"ranged", "package ranged\n\nimport \"sync\"\n\nvar m sync.Map\n\nfunc Subject() int {\n\tm.Store(\"k\", 1)\n\tn := 0\n\tm.Range(func(k, v any) bool {\n\t\tn++\n\t\treturn true\n\t})\n\treturn n\n}\n", "reaches unaudited standard operation sync.Range"},
		// A function-local map: the fold records no effect for the
		// declaration (the type name is the memo set's), and the walk
		// then refuses the subject's own reach — a sync.Map value holds
		// unsafe pointers — whatever operation follows. The type-name
		// admission opens nothing: the walk stands behind it.
		{"local", "package local\n\nimport \"sync\"\n\nfunc Subject() int {\n\tvar m sync.Map\n\tm.Store(\"k\", 1)\n\tv, _ := m.Load(\"k\")\n\treturn v.(int)\n}\n", "unsafe pointer reachable"},
		{"localranged", "package localranged\n\nimport \"sync\"\n\nfunc Subject() int {\n\tvar m sync.Map\n\tn := 0\n\tm.Range(func(k, v any) bool { return true })\n\treturn n\n}\n", "unsafe pointer reachable"},
		{"deleted", "package deleted\n\nimport \"sync\"\n\nvar m sync.Map\n\nfunc Subject() int {\n\tm.Store(\"k\", 1)\n\tm.Delete(\"k\")\n\treturn 1\n}\n", "reaches unaudited standard operation sync.Delete"},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.pkg+"/"+tc.pkg+".go", tc.source)
		subjects = append(subjects, Subject{Package: "example.com/syncmemo/" + tc.pkg, Symbol: "Subject"})
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		proof := proofs[Subject{Package: "example.com/syncmemo/" + tc.pkg, Symbol: "Subject"}]
		if tc.refusal == "" {
			if !proof.Observable || proof.Reason != "" {
				t.Errorf("%s = %+v, want observable", tc.pkg, proof)
			}
			continue
		}
		if proof.Observable || !strings.Contains(proof.Reason, tc.refusal) {
			t.Errorf("%s = %+v, want refused with %q", tc.pkg, proof, tc.refusal)
		}
	}
}

func TestWidenedSubjectsPopulateProgMemosWithoutCrossSubjectTaint(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/widenedmemo\n\ngo 1.26\n")
	writeFile(t, dir, "pkg.go", `package widenedmemo

import "os"

type Stepper interface {
	Step() string
}

type pureStepper struct{ tag string }

func (p pureStepper) Step() string { return p.tag }

type envStepper struct{ key string }

func (e envStepper) Step() string { return os.Getenv(e.key) }

type closedStepBox struct {
	s Stepper
}

func newClosedStepBox(tag string) *closedStepBox {
	return &closedStepBox{s: pureStepper{tag: tag}}
}

var OpenGlobalStepper Stepper

func SetOpenGlobal(s Stepper) {
	OpenGlobalStepper = s
}

func sharedChainLeaf(s Stepper) string {
	return s.Step()
}

func sharedChainMid() string {
	b := newClosedStepBox("mid")
	return sharedChainLeaf(b.s) + ":" + b.s.Step()
}

func WidenedCleanA(f func() string) string {
	return f() + ":" + sharedChainLeaf(pureStepper{tag: "a"}) + ":" + sharedChainMid()
}

func WidenedCleanB(f func() string) string {
	return f() + ":" + sharedChainLeaf(pureStepper{tag: "b"}) + ":" + sharedChainMid()
}

func CallWidenedClean() string {
	return WidenedCleanA(func() string { return "ca" }) + WidenedCleanB(func() string { return "cb" })
}

func dynamicCandidateClean() string { return "dyn" }

func takeAddrAndCallClean(flag bool) string {
	fn := dynamicCandidateClean
	if flag {
		return fn()
	}
	return sharedChainMid()
}

func makeClosureOuter(prefix string) func() string {
	return func() string {
		return prefix + ":" + sharedChainMid()
	}
}

func callMakeClosureOuter() string {
	c := makeClosureOuter("p")
	return c()
}

func UseOpenGlobal() string {
	if OpenGlobalStepper != nil {
		return OpenGlobalStepper.Step()
	}
	return ""
}
`)
	writeFile(t, dir, "pkg_test.go", `package widenedmemo

import "testing"

func TestSoloClean(t *testing.T) {
	if got := CallWidenedClean(); got == "" {
		t.Fatal("empty")
	}
}

func TestAddrTaker(t *testing.T) {
	if got := takeAddrAndCallClean(true); got == "" {
		t.Fatal("empty")
	}
}

func TestClosureCaller(t *testing.T) {
	if got := callMakeClosureOuter(); got == "" {
		t.Fatal("empty")
	}
}

func TestImpureOpenGlobal(t *testing.T) {
	_ = UseOpenGlobal()
}
`)

	pkgPath := "example.com/widenedmemo"
	widenedSubjects := []Subject{
		{Package: pkgPath, Symbol: "WidenedCleanA"},
		{Package: pkgPath, Symbol: "WidenedCleanB"},
	}

	hWidened, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	widenedObs, err := hWidened.ComputeObservabilityBatch(widenedSubjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range widenedSubjects {
		if !widenedObs[s].Observable {
			t.Fatalf("%s observability = %+v, want Observable", s.Symbol, widenedObs[s])
		}
	}
	prog, err := hWidened.loadCached(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	metas, err := hWidened.List(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	base := newTier2Base(hWidened.Hasher, prog, metas)
	reachWidened, err := attributedReachableSets(context.Background(), true, hWidened.PureDelegates(), prog, widenedSubjects)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range reachWidened {
		if !r.enumeratedRoot {
			t.Fatalf("%s enumeratedRoot = false, want true", widenedSubjects[i].Symbol)
		}
	}
	sum := lookupSummaryForProg(prog, true)
	if sum == nil {
		t.Fatal("expected non-nil callerReferenceSummary")
	}
	// Clear summary.progMemos after attributedReachableSets so the assertion
	// below specifically tests widened tier2Reachable (enumRoot != nil) rather
	// than provenanceBFSWithCandidates (enumRoot == nil).
	sum.progMemos = *newDynamicMemoQuad()
	for _, r := range reachWidened {
		res, err := tier2Reachable(hWidened.Hasher, base, r)
		if err != nil {
			t.Fatal(err)
		}
		if res.widen || res.unverifiable || len(res.effects) > 0 {
			t.Fatalf("tier2Reachable(%s) = %+v, want pure", r.subjectRoot.Name(), res)
		}
	}
	if len(sum.progMemos[0].invokeMemo) == 0 || len(sum.progMemos[2].closedDone) == 0 {
		t.Fatalf("widened tier2Reachable did not populate progMemos: progMemos[0].invokeMemo=%d progMemos[2].closedDone=%d",
			len(sum.progMemos[0].invokeMemo), len(sum.progMemos[2].closedDone))
	}

	allSubjects := []Subject{
		{Package: pkgPath, Symbol: "WidenedCleanA"},
		{Package: pkgPath, Symbol: "WidenedCleanB"},
		{Package: pkgPath, Symbol: "CallWidenedClean"},
		{Package: pkgPath, Symbol: "TestSoloClean"},
		{Package: pkgPath, Symbol: "TestAddrTaker"},
		{Package: pkgPath, Symbol: "TestClosureCaller"},
		{Package: pkgPath, Symbol: "TestImpureOpenGlobal"},
	}

	soloWant := make(map[Subject]Observability, len(allSubjects))
	for _, s := range allSubjects {
		soloH, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, err := soloH.ComputeObservabilityBatch([]Subject{s})
		if err != nil {
			t.Fatalf("solo ComputeObservabilityBatch(%s): %v", s.Symbol, err)
		}
		soloWant[s] = got[s]
	}
	if soloWant[Subject{Package: pkgPath, Symbol: "TestImpureOpenGlobal"}].Observable {
		t.Fatal("TestImpureOpenGlobal = Observable, want !Observable")
	}

	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 8; trial++ {
		perm := slices.Clone(allSubjects)
		switch trial {
		case 0:
		case 1:
			slices.Reverse(perm)
		default:
			rng.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })
		}
		batchH, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, err := batchH.ComputeObservabilityBatch(perm)
		if err != nil {
			t.Fatalf("trial %d ComputeObservabilityBatch: %v", trial, err)
		}
		for _, s := range perm {
			if got[s] != soloWant[s] {
				t.Fatalf("trial %d %s: batch = %+v, solo = %+v", trial, s.Symbol, got[s], soloWant[s])
			}
		}
	}
}

func TestEnumRecvAndStructCycleExemptionsNotPoisonedByNegativeProgMemos(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/cyclememo\n\ngo 1.26\n")
	writeFile(t, dir, "pkg.go", `package cyclememo

import "os"

type Hook interface {
	Run() string
}

type pureHook struct{}

func (pureHook) Run() string { return "pure" }

type envHook struct{}

func (envHook) Run() string { return os.Getenv("CYCLE_ENV") }

var OpenHook Hook

type Node struct {
	Next *Node
	H    Hook
}

func NewClosedNodeCycle() *Node {
	n := &Node{H: pureHook{}}
	n.Next = n
	return n
}

func (n *Node) EvalWithExtra(tag Hook) string {
	if n == nil {
		return tag.Run()
	}
	return tag.Run() + ":" + n.H.Run()
}

func CallEvalWithExtra() string {
	n := NewClosedNodeCycle()
	return n.EvalWithExtra(pureHook{})
}

func unclosedHelper(h Hook) string {
	return h.Run()
}

func CallOpenHook() string {
	return unclosedHelper(OpenHook)
}
`)

	pkgPath := "example.com/cyclememo"
	subjects := []Subject{
		{Package: pkgPath, Symbol: "CallOpenHook"},
		{Package: pkgPath, Symbol: "Node.EvalWithExtra"},
		{Package: pkgPath, Symbol: "CallEvalWithExtra"},
	}

	for _, reverse := range []bool{false, true} {
		order := slices.Clone(subjects)
		if reverse {
			slices.Reverse(order)
		}
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, err := h.ComputeObservabilityBatch(order)
		if err != nil {
			t.Fatal(err)
		}
		if got[Subject{Package: pkgPath, Symbol: "CallOpenHook"}].Observable {
			t.Fatalf("reverse=%v: CallOpenHook = Observable, want !Observable", reverse)
		}
		if !got[Subject{Package: pkgPath, Symbol: "Node.EvalWithExtra"}].Observable {
			t.Fatalf("reverse=%v: Node.EvalWithExtra = %+v, want Observable", reverse, got[Subject{Package: pkgPath, Symbol: "Node.EvalWithExtra"}])
		}
		if !got[Subject{Package: pkgPath, Symbol: "CallEvalWithExtra"}].Observable {
			t.Fatalf("reverse=%v: CallEvalWithExtra = %+v, want Observable", reverse, got[Subject{Package: pkgPath, Symbol: "CallEvalWithExtra"}])
		}
	}
}

func TestContextCancelModeMemosRetainedWithoutPollutingValueMode(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/ctxmemo\n\ngo 1.26\n")
	writeFile(t, dir, "pkg.go", `package ctxmemo

import (
	"context"
	"os"
)

type ctxKey struct{}

type Payload interface {
	Read() string
}

type envPayload struct{}

func (envPayload) Read() string { return os.Getenv("CTX_ENV") }

var GlobalOpenPayload Payload = envPayload{}

type closedCtxHolder struct {
	ctx context.Context
}

func newClosedCtxHolder() *closedCtxHolder {
	return &closedCtxHolder{
		ctx: context.WithValue(context.Background(), ctxKey{}, GlobalOpenPayload),
	}
}

func attachPayload(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, GlobalOpenPayload)
}

func checkCancelHop(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx.Err()
	}
	return ctx.Err()
}

func sharedHolderCancelHop() error {
	holder := newClosedCtxHolder()
	return holder.ctx.Err()
}

func CancelOnlyEntry() error {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := attachPayload(base)
	if err := checkCancelHop(ctx); err != nil {
		return err
	}
	if err := sharedHolderCancelHop(); err != nil {
		return err
	}
	return checkCancelHop(ctx)
}

func ValueEscapeEntry() string {
	ctx := attachPayload(context.Background())
	if p, ok := ctx.Value(ctxKey{}).(Payload); ok && p != nil {
		return p.Read()
	}
	return ""
}
`)

	pkgPath := "example.com/ctxmemo"
	cancelSubj := Subject{Package: pkgPath, Symbol: "CancelOnlyEntry"}
	valueSubj := Subject{Package: pkgPath, Symbol: "ValueEscapeEntry"}

	for _, order := range [][]Subject{
		{cancelSubj, valueSubj},
		{valueSubj, cancelSubj},
	} {
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, err := h.ComputeObservabilityBatch(order)
		if err != nil {
			t.Fatal(err)
		}
		if !got[cancelSubj].Observable {
			t.Fatalf("order=%v: CancelOnlyEntry = %+v, want Observable", order, got[cancelSubj])
		}
		if got[valueSubj].Observable {
			t.Fatalf("order=%v: ValueEscapeEntry = %+v, want !Observable", order, got[valueSubj])
		}
		prog, err := h.loadCached(pkgPath)
		if err != nil {
			t.Fatal(err)
		}
		metas, err := h.List(pkgPath)
		if err != nil {
			t.Fatal(err)
		}
		base := newTier2Base(h.Hasher, prog, metas)
		reach, err := attributedReachableSets(context.Background(), true, h.PureDelegates(), prog, order)
		if err != nil {
			t.Fatal(err)
		}
		sum := lookupSummaryForProg(prog, true)
		if sum == nil {
			t.Fatal("expected non-nil callerReferenceSummary")
		}
		sum.progMemos = *newDynamicMemoQuad()
		for i, r := range reach {
			if _, err := tier2Reachable(h.Hasher, base, r); err != nil {
				t.Fatal(err)
			}
			if order[i] == cancelSubj {
				fp := newFreshParamAnalysis(true, h.PureDelegates(), r, nil)
				for site, targets := range r.dynamicTargets {
					if r.functions[site.Parent()] {
						_ = narrowedTargets(site, targets, fp)
					}
				}
				// Subject-local cancel mode (progScope=0, mode=1 -> index 1)
				// retains checkCancelHop's cancel dispatches across repeated calls.
				if len(fp.memoTables[1].invokeMemo) == 0 || len(fp.memoTables[1].closedDone) == 0 {
					t.Fatalf("order=%v: CancelOnlyEntry did not retain subject-local cancel memos in memoTables[1]: invokeMemo=%d closedDone=%d",
						order, len(fp.memoTables[1].invokeMemo), len(fp.memoTables[1].closedDone))
				}
				for site, entry := range fp.memoTables[0].invokeMemo {
					if entry.ok && isContextCancelSite(site) {
						t.Fatalf("order=%v: CancelOnlyEntry polluted subject-local value-mode memoTables[0].invokeMemo at %v",
							order, site)
					}
				}
			}
		}
		if len(sum.progMemos[1].invokeMemo) == 0 || len(sum.progMemos[3].closedDone) == 0 {
			t.Fatalf("order=%v: expected progMemos[1].invokeMemo (%d) and progMemos[3].closedDone (%d) to retain shared cancel targets",
				order, len(sum.progMemos[1].invokeMemo), len(sum.progMemos[3].closedDone))
		}
		for _, idx := range []int{0, 2} {
			for site, entry := range sum.progMemos[idx].invokeMemo {
				if entry.ok && isContextCancelSite(site) {
					t.Fatalf("order=%v: progMemos[%d].invokeMemo polluted by context-cancel site %v", order, idx, site)
				}
			}
		}
	}
}

func TestCalleeCancelModeDoesNotPoisonValueModeCalleeDone(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/calleedone\n\ngo 1.26\n")
	writeFile(t, dir, "pkg.go", `package calleedone

import "context"

type ctxKey struct{}

func openLocalFunc(n int) func() string {
	var f, g func() string
	_ = func() bool { return f == nil && g == nil }
	for i := 0; i < n; i++ {
		f, g = g, f
	}
	return f
}

func attachCancelArtifact(base context.Context, v any) context.Context {
	if v == nil {
		return base
	}
	return context.WithoutCancel(base)
}

func inspectErrThenReturn(base context.Context, wrap bool, n int) context.Context {
	x := context.WithValue(base, ctxKey{}, openLocalFunc(n))
	if wrap {
		return attachCancelArtifact(base, x.Err())
	}
	return x
}

func boundErrThenReturn(base context.Context, wrap bool, n int) context.Context {
	x := context.WithValue(base, ctxKey{}, openLocalFunc(n))
	if wrap {
		return attachCancelArtifact(base, x.Err)
	}
	return x
}

func withCancelThenReturn(base context.Context, wrap bool, n int) context.Context {
	x := context.WithValue(base, ctxKey{}, openLocalFunc(n))
	if wrap {
		_, cancel := context.WithCancel(x)
		return attachCancelArtifact(base, cancel)
	}
	return x
}

func ImpureViaInspectErr(wrap bool, n int) bool {
	ctx := inspectErrThenReturn(context.Background(), wrap, n)
	return ctx.Value(ctxKey{}) != nil
}

func ImpureViaBoundErr(wrap bool, n int) bool {
	ctx := boundErrThenReturn(context.Background(), wrap, n)
	return ctx.Value(ctxKey{}) != nil
}

func ImpureViaWithCancel(wrap bool, n int) bool {
	ctx := withCancelThenReturn(context.Background(), wrap, n)
	return ctx.Value(ctxKey{}) != nil
}

func CleanCancelOnlyAfterInspect(wrap bool, n int) error {
	ctx := inspectErrThenReturn(context.Background(), wrap, n)
	return ctx.Err()
}
`)

	pkgPath := "example.com/calleedone"
	s1 := Subject{Package: pkgPath, Symbol: "ImpureViaInspectErr"}
	s2 := Subject{Package: pkgPath, Symbol: "ImpureViaBoundErr"}
	s3 := Subject{Package: pkgPath, Symbol: "ImpureViaWithCancel"}
	s4 := Subject{Package: pkgPath, Symbol: "CleanCancelOnlyAfterInspect"}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.ComputeObservabilityBatch([]Subject{s1, s2, s3, s4})
	if err != nil {
		t.Fatal(err)
	}
	if got[s1].Observable {
		t.Fatalf("ImpureViaInspectErr = %+v, want !Observable", got[s1])
	}
	if got[s2].Observable {
		t.Fatalf("ImpureViaBoundErr = %+v, want !Observable", got[s2])
	}
	if got[s3].Observable {
		t.Fatalf("ImpureViaWithCancel = %+v, want !Observable", got[s3])
	}
	if !got[s4].Observable {
		t.Fatalf("CleanCancelOnlyAfterInspect = %+v, want Observable", got[s4])
	}
}

func TestSubjMemoPartitionsProgScopeAndPreservesUsedSubjectProvenance(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/subjmemo\n\ngo 1.26\n")
	writeFile(t, dir, "pkg.go", `package subjmemo

import "time"

var OpenGlobalFn func() string

type Holder struct {
	out func() string
}

// makeHolderWithFn evaluates its signature parameter fn both directly in
// subject-local scope (fn(), where perSubjectSigParam == true) and as a
// struct-field store (&Holder{out: fn}, evaluated in progScope == 1 where
// needProgramSites == true includes UnreachedOpenSeeder's OpenGlobalFn).
func makeHolderWithFn(fn func() string) *Holder {
	if fn == nil {
		return nil
	}
	_ = fn()
	return &Holder{out: fn}
}

func UnreachedOpenSeeder() *Holder {
	return makeHolderWithFn(OpenGlobalFn)
}

func EntryPopulateSubjThenReadField() string {
	h := makeHolderWithFn(func() string { return "local" })
	return h.out()
}

func sharedStep(cb func() string) func() string {
	return func() string { return cb() }
}

type StepWrap struct {
	run func() string
}

func makeStepWrap(cb func() string) *StepWrap {
	return &StepWrap{run: sharedStep(cb)}
}

func CleanSubjectUsingStep() string {
	fn := sharedStep(func() string { return "ok" })
	return fn()
}

func ImpureSubjectUsingStep() string {
	w := makeStepWrap(func() string { return time.Now().String() })
	return w.run()
}
`)

	pkgPath := "example.com/subjmemo"
	subjects := []Subject{
		{Package: pkgPath, Symbol: "EntryPopulateSubjThenReadField"},
		{Package: pkgPath, Symbol: "CleanSubjectUsingStep"},
		{Package: pkgPath, Symbol: "ImpureSubjectUsingStep"},
	}

	solo := make(map[Subject]Observability, len(subjects))
	for _, s := range subjects {
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, err := h.ComputeObservabilityBatch([]Subject{s})
		if err != nil {
			t.Fatal(err)
		}
		solo[s] = got[s]
	}
	if solo[Subject{Package: pkgPath, Symbol: "EntryPopulateSubjThenReadField"}].Observable {
		t.Fatal("EntryPopulateSubjThenReadField = Observable, want !Observable")
	}
	if !solo[Subject{Package: pkgPath, Symbol: "CleanSubjectUsingStep"}].Observable {
		t.Fatalf("CleanSubjectUsingStep = %+v, want Observable", solo[Subject{Package: pkgPath, Symbol: "CleanSubjectUsingStep"}])
	}
	if solo[Subject{Package: pkgPath, Symbol: "ImpureSubjectUsingStep"}].Observable {
		t.Fatal("ImpureSubjectUsingStep = Observable, want !Observable")
	}

	for _, reverse := range []bool{false, true} {
		order := slices.Clone(subjects)
		if reverse {
			slices.Reverse(order)
		}
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, err := h.ComputeObservabilityBatch(order)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range order {
			if got[s] != solo[s] {
				t.Fatalf("reverse=%v %s: batch=%+v, solo=%+v", reverse, s.Symbol, got[s], solo[s])
			}
		}
	}
}

func TestEnumStructClosedPartitionsEnumOnlyFromGeneralWalk(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/enumstruct\n\ngo 1.26\n")
	writeFile(t, dir, "pkg.go", `package enumstruct

import "os"

var OpenFunc func() string = func() string { return os.Getenv("ENUM_STRUCT_ENV") }

type InnerPtr struct {
	fn func() string
}

type OuterWithPtr struct {
	inner *InnerPtr
	tag   func() string
}

func SeedUnclosedInner() *InnerPtr {
	return &InnerPtr{fn: OpenFunc}
}

func newOuterWithCleanTag() OuterWithPtr {
	return OuterWithPtr{
		inner: &InnerPtr{fn: OpenFunc},
		tag:   func() string { return "tag" },
	}
}

func ReadOnlyCleanTag() string {
	o := newOuterWithCleanTag()
	return o.tag()
}

func OpenTakeOuter(o OuterWithPtr) string {
	if o.inner != nil && o.inner.fn != nil {
		return o.inner.fn()
	}
	return o.tag()
}

func CallOpenTakeOuter() string {
	return OpenTakeOuter(newOuterWithCleanTag())
}

func makePureFunc() func() string {
	return func() string { return "factory" }
}

type FactoryValue struct {
	fn func() string
}

type FactoryOuter struct {
	v FactoryValue
}

func newFactoryOuter() FactoryOuter {
	return FactoryOuter{v: FactoryValue{fn: makePureFunc()}}
}

func OpenTakeFactory(o FactoryOuter) string {
	return o.v.fn()
}

func CallFactoryDirect() string {
	o := newFactoryOuter()
	return o.v.fn()
}

func CallOpenTakeFactory() string {
	return OpenTakeFactory(newFactoryOuter())
}
`)

	pkgPath := "example.com/enumstruct"
	subjects := []Subject{
		{Package: pkgPath, Symbol: "ReadOnlyCleanTag"},
		{Package: pkgPath, Symbol: "OpenTakeOuter"},
		{Package: pkgPath, Symbol: "CallOpenTakeOuter"},
		{Package: pkgPath, Symbol: "OpenTakeFactory"},
		{Package: pkgPath, Symbol: "CallFactoryDirect"},
		{Package: pkgPath, Symbol: "CallOpenTakeFactory"},
	}

	solo := make(map[Subject]Observability, len(subjects))
	for _, s := range subjects {
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, err := h.ComputeObservabilityBatch([]Subject{s})
		if err != nil {
			t.Fatal(err)
		}
		solo[s] = got[s]
	}
	if !solo[Subject{Package: pkgPath, Symbol: "ReadOnlyCleanTag"}].Observable {
		t.Fatalf("ReadOnlyCleanTag = %+v, want Observable", solo[Subject{Package: pkgPath, Symbol: "ReadOnlyCleanTag"}])
	}
	if solo[Subject{Package: pkgPath, Symbol: "OpenTakeOuter"}].Observable {
		t.Fatal("OpenTakeOuter = Observable, want !Observable")
	}
	if !solo[Subject{Package: pkgPath, Symbol: "CallFactoryDirect"}].Observable {
		t.Fatalf("CallFactoryDirect = %+v, want Observable", solo[Subject{Package: pkgPath, Symbol: "CallFactoryDirect"}])
	}

	rng := rand.New(rand.NewSource(7))
	for trial := 0; trial < 6; trial++ {
		perm := slices.Clone(subjects)
		switch trial {
		case 0:
		case 1:
			slices.Reverse(perm)
		default:
			rng.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })
		}
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, err := h.ComputeObservabilityBatch(perm)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range perm {
			if got[s] != solo[s] {
				t.Fatalf("trial %d %s: batch=%+v, solo=%+v", trial, s.Symbol, got[s], solo[s])
			}
		}
	}
}

func TestEnumMemosPartitionProgScopeAcrossDeadCallerExemption(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/enumdead\n\ngo 1.26\n")
	writeFile(t, dir, "sub/sub.go", `package sub

import "time"

type TimeHook struct{}

func (TimeHook) Run() string { return time.Now().String() }
`)
	writeFile(t, dir, "pkg.go", `package enumdead

import "example.com/enumdead/sub"

type Hook interface {
	Run() string
}

type pureHook struct{}

func (pureHook) Run() string { return "pure" }

type Box struct {
	h Hook
}

func wrapHook(x Hook) Hook { return x }

func deadUnreferencedCaller(in Hook) *Box {
	_ = Hook(sub.TimeHook{})
	OpenB(wrapHook(in))
	return &Box{h: wrapHook(in)}
}

func makeCleanBox() *Box {
	return &Box{h: pureHook{}}
}

func OpenA(b *Box) string {
	return b.h.Run()
}

func OpenB(h Hook) string {
	return h.Run()
}

func LiveCallerA() string {
	return OpenA(makeCleanBox())
}
`)

	pkgPath := "example.com/enumdead"
	subjects := []Subject{
		{Package: pkgPath, Symbol: "OpenA"},
		{Package: pkgPath, Symbol: "OpenB"},
		{Package: pkgPath, Symbol: "LiveCallerA"},
	}

	soloObs := make(map[Subject]Observability, len(subjects))
	soloRooted := make(map[Subject]RootedFunctions, len(subjects))
	for _, s := range subjects {
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		obs, err := h.ComputeObservabilityBatch([]Subject{s})
		if err != nil {
			t.Fatal(err)
		}
		soloObs[s] = obs[s]
		rf, err := h.ComputeRootedFunctions(context.Background(), []Subject{s})
		if err != nil {
			t.Fatal(err)
		}
		soloRooted[s] = rf[s]
	}
	openA := Subject{Package: pkgPath, Symbol: "OpenA"}
	openB := Subject{Package: pkgPath, Symbol: "OpenB"}
	liveA := Subject{Package: pkgPath, Symbol: "LiveCallerA"}
	if soloObs[openA].Observable || !soloRooted[openA].Complete {
		t.Fatalf("OpenA: obs=%+v rooted=%+v, want !Observable (enumRoot != nil) && Complete (enumOnly)", soloObs[openA], soloRooted[openA])
	}
	if !soloObs[liveA].Observable || !soloRooted[liveA].Complete {
		t.Fatalf("LiveCallerA: obs=%+v rooted=%+v, want Observable && Complete", soloObs[liveA], soloRooted[liveA])
	}
	if soloObs[openB].Observable || soloRooted[openB].Complete {
		t.Fatalf("OpenB: obs=%+v rooted=%+v, want !Observable && !Complete (deadUnreferencedCaller passes timeHook)", soloObs[openB], soloRooted[openB])
	}

	for _, reverse := range []bool{false, true} {
		order := slices.Clone(subjects)
		if reverse {
			slices.Reverse(order)
		}
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		obs, err := h.ComputeObservabilityBatch(order)
		if err != nil {
			t.Fatal(err)
		}
		rf, err := h.ComputeRootedFunctions(context.Background(), order)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range order {
			if obs[s] != soloObs[s] {
				t.Fatalf("reverse=%v %s obs: batch=%+v, solo=%+v", reverse, s.Symbol, obs[s], soloObs[s])
			}
			if rf[s].Complete != soloRooted[s].Complete || !maps.Equal(rf[s].Fns, soloRooted[s].Fns) {
				t.Fatalf("reverse=%v %s rooted: batch=%+v, solo=%+v", reverse, s.Symbol, rf[s], soloRooted[s])
			}
		}
	}
}

func TestIsPinnedPackageDirAndPrepareProgramRTASharedProvenance(t *testing.T) {
	if closure.IsPinnedPackageDir(true, "/cache/mod/dep@v1.0.0", "/cache/mod") {
		t.Fatal("main module inside modCache classified as pinned")
	}
	if closure.IsPinnedPackageDir(false, "", "/cache/mod") || closure.IsPinnedPackageDir(false, "/cache/mod/dep@v1.0.0", "") {
		t.Fatal("empty pkgDir or modCache classified as pinned")
	}
	if closure.IsPinnedPackageDir(false, "/cache/mod2/dep@v1.0.0", "/cache/mod") {
		t.Fatal("sibling prefix /cache/mod2 classified as under /cache/mod")
	}
	if !closure.IsPinnedPackageDir(false, "/cache/mod/dep@v1.0.0/sub", "/cache/mod") {
		t.Fatal("module-cache subdirectory not classified as pinned")
	}

	// Verify prepareProgramRTA populates summary unconditionally when audited=false
	// and len(openCandidates)==0, batches >64 InMemoryRootedFunctions subjects, and
	// never treats an uncalled subject root's *ssa.Parameter as dead code on provFP.
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/rtaprep\n\ngo 1.26\n")
	var b strings.Builder
	b.WriteString("package rtaprep\n\nimport \"testing\"\n\n")
	b.WriteString("type Runner interface { Run() }\n\n")
	b.WriteString("type impl struct{}\nfunc (impl) Run() { hitTarget() }\nfunc hitTarget() {}\n\n")
	b.WriteString("func UncalledWithInterfaceParam(r Runner) { r.Run() }\n")
	b.WriteString("func SeedImpl() Runner { return impl{} }\n")
	b.WriteString("func TestSeed(t *testing.T) { _ = SeedImpl() }\n")
	for i := 0; i < 70; i++ {
		b.WriteString("func PureLeaf")
		b.WriteString(strconv.Itoa(i))
		b.WriteString("() int { return ")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(" }\n")
	}
	writeFile(t, dir, "pkg_test.go", b.String())

	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	pkgPath := "example.com/rtaprep"
	prog, err := h.loadCached(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	// Run binaryReachableUnion with audited=false and zero open candidates:
	// prepareProgramRTA must still populate lookupSummaryForProg(prog, false) and provFP.
	binFns, err := binaryReachableUnion(context.Background(), false, nil, prog, []Subject{{Package: pkgPath, Symbol: "TestSeed"}})
	if err != nil {
		t.Fatalf("binaryReachableUnion: %v", err)
	}
	if !binFns.Complete || !binFns.Fns["example.com/rtaprep\x00SeedImpl"] {
		t.Fatalf("binaryReachableUnion missed SeedImpl: %+v", binFns)
	}
	if lookupSummaryForProg(prog, false) == nil {
		t.Fatal("prepareProgramRTA left summary nil when audited=false and openCandidates empty")
	}

	// UncalledWithInterfaceParam is never called in the program, so its parameter r
	// is an uncalled subject root's *ssa.Parameter: provFP must NOT treat it as dead code.
	uncalledSubj := Subject{Package: pkgPath, Symbol: "UncalledWithInterfaceParam"}
	var batch []Subject
	batch = append(batch, uncalledSubj)
	for i := 0; i < 70; i++ {
		batch = append(batch, Subject{Package: pkgPath, Symbol: "PureLeaf" + strconv.Itoa(i)})
	}
	rf, err := h.ComputeRootedFunctions(context.Background(), batch)
	if err != nil {
		t.Fatalf("ComputeRootedFunctions (>64 batch): %v", err)
	}
	if rf[uncalledSubj].Complete {
		t.Fatalf("open-world UncalledWithInterfaceParam unexpectedly marked Complete: %+v", rf[uncalledSubj])
	}
	for i := 0; i < 70; i++ {
		leaf := Subject{Package: pkgPath, Symbol: "PureLeaf" + strconv.Itoa(i)}
		if !rf[leaf].Complete {
			t.Fatalf("%s not Complete in >64 subject batch: %+v", leaf.Symbol, rf[leaf])
		}
	}
}

func TestOpenExportedInterfacePassThroughEnumeratesCallers(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/passthrough\n\ngo 1.26\n")
	writeFile(t, dir, "pkg.go", `package passthrough

import "os"

type Hook interface {
	Run() string
}

type pureHook struct{}

func (pureHook) Run() string { return "pure" }

type unusedEnvHook struct{}

func (unusedEnvHook) Run() string { return os.Getenv("UNUSED_HOOK_ENV") }

func Identity(h Hook) Hook {
	return h
}

func CallIdentity() string {
	return Identity(pureHook{}).Run()
}
`)

	pkgPath := "example.com/passthrough"
	idSubj := Subject{Package: pkgPath, Symbol: "Identity"}
	callSubj := Subject{Package: pkgPath, Symbol: "CallIdentity"}

	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.ComputeObservabilityBatch([]Subject{idSubj, callSubj})
	if err != nil {
		t.Fatal(err)
	}
	if !got[idSubj].Observable {
		t.Fatalf("Identity = %+v, want Observable", got[idSubj])
	}
	if !got[callSubj].Observable {
		t.Fatalf("CallIdentity = %+v, want Observable", got[callSubj])
	}
	prog, err := h.loadCached(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	reach, err := attributedReachableSets(context.Background(), true, h.PureDelegates(), prog, []Subject{idSubj})
	if err != nil {
		t.Fatal(err)
	}
	if len(reach) != 1 || !reach[0].enumeratedRoot {
		t.Fatalf("Identity enumeratedRoot = %v, want true", len(reach) == 1 && reach[0].enumeratedRoot)
	}
}

func TestBitOnlyFreshParamAnalysisDoesNotReadOrWriteSummaryProgMemos(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/bitonlymemo\n\ngo 1.26\n")
	writeFile(t, dir, "pkg.go", `package bitonlymemo

type Runner interface {
	Run() string
}

type pureRunner struct{}

func (pureRunner) Run() string { return "pure" }

func helper(r Runner) string {
	return r.Run()
}

func Entry() string {
	return helper(pureRunner{})
}
`)

	pkgPath := "example.com/bitonlymemo"
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attributedReachableSets(context.Background(), true, h.PureDelegates(), prog, []Subject{{Package: pkgPath, Symbol: "Entry"}}); err != nil {
		t.Fatal(err)
	}
	sum := lookupSummaryForProg(prog, true)
	if sum == nil {
		t.Fatal("expected non-nil summary")
	}
	helperFn := prog.Roots["helper"]
	if helperFn == nil || len(helperFn.Params) != 1 {
		t.Fatalf("unexpected helper root: %v", helperFn)
	}
	bitFP := newBitOnlyFreshParamAnalysis(true, true, h.PureDelegates(), map[string]bool{pkgPath: true}, sum, nil)
	bitFP.inProgramSites = true
	// Seed progMemos[2] (progScope=1, mode=0) with a synthetic closed entry on
	// helperFn.Params[0]: bit-only analyses (programSites == nil) must ignore
	// summary.progMemos and refuse parameter crossing (including dead-caller
	// exemptions) per REQ-closure-observability-property-harness.
	sum.progMemos[2].closedDone[helperFn.Params[0]] = closedMemoEntry{closed: true}
	if subjectClosedDynamicValue(helperFn.Params[0], map[ssa.Value]bool{}, bitFP) {
		t.Fatal("bit-only freshParamAnalysis closed parameter despite programSites == nil")
	}
	// Reset progMemos[2] and verify bit-only evaluation never writes a negative
	// parameter-crossing refusal into summary.progMemos[2].
	delete(sum.progMemos[2].closedDone, helperFn.Params[0])
	_ = subjectClosedDynamicValue(helperFn.Params[0], map[ssa.Value]bool{}, bitFP)
	if _, wrote := sum.progMemos[2].closedDone[helperFn.Params[0]]; wrote {
		t.Fatal("bit-only freshParamAnalysis polluted summary.progMemos[2] with parameter refusal")
	}
}

func TestTupleIndexedCalleeScreeningAdmitsSiblingClosureAndRejectsActiveUses(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/tuplescreen\n\ngo 1.26\n")
	writeFile(t, dir, "pkg.go", `package tuplescreen

import (
	"context"
	"os"
)

type spanKey struct{}

type Hook interface {
	Fire()
}

type envHook struct{}

func (envHook) Fire() { _ = os.Getenv("TUPLE_ENV") }

// Session carries a dynamic Hook field and is stored in a mutable global so
// struct_arg_walk on GlobalSession fails whenever a callee parameter is
// conservatively treated as supplying or affecting tupleIndex 0.
type Session struct {
	count int
	hook  Hook
}

var GlobalSession = &Session{hook: envHook{}}

func OverrideSession(s *Session) {
	GlobalSession = s
}

func (s *Session) recordDone(done *int) {
	if s != nil && done != nil {
		*done = s.count + 1
	}
}

func (s *Session) makeCleanup(cancel context.CancelFunc) func(*int) {
	return func(done *int) {
		cancel()
		s.recordDone(done)
	}
}

func (s *Session) beginOperation(ctx context.Context) (context.Context, func(*int)) {
	if s == nil {
		return ctx, func(*int) {}
	}
	ctx, cancel := context.WithCancel(ctx)
	ctx = context.WithValue(ctx, spanKey{}, s.hook)
	return ctx, func(done *int) {
		cancel()
		s.recordDone(done)
	}
}

func (s *Session) beginForwardNamed(ctx context.Context) (outCtx context.Context, cleanup func(*int)) {
	outCtx, cleanup = s.beginOperation(ctx)
	return
}

func (s *Session) beginFactoryCleanup(ctx context.Context) (context.Context, func(*int)) {
	ctx, cancel := context.WithCancel(ctx)
	return ctx, s.makeCleanup(cancel)
}

func (s *Session) beginInvokedInside(ctx context.Context) (context.Context, func()) {
	fn := func() {
		if s != nil && s.hook != nil {
			s.hook.Fire()
		}
	}
	fn()
	return ctx, fn
}

func (s *Session) beginDeferredInside(ctx context.Context) (context.Context, func()) {
	fn := func() {
		if s != nil && s.hook != nil {
			s.hook.Fire()
		}
	}
	defer fn()
	return ctx, func() {}
}

func (s *Session) beginSameSlot() (func(), func()) {
	fn := func() {
		if s != nil && s.hook != nil {
			s.hook.Fire()
		}
	}
	return fn, fn
}

func CleanDirectBegin() error {
	ctx, _ := GlobalSession.beginOperation(context.Background())
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return ctx.Err()
	}
}

func CleanForwardedBegin() error {
	ctx, _ := GlobalSession.beginForwardNamed(context.Background())
	_, _ = ctx.Deadline()
	return ctx.Err()
}

func CleanFactoryBegin() error {
	ctx, _ := GlobalSession.beginFactoryCleanup(context.Background())
	return ctx.Err()
}

func ImpureValueFromBegin() {
	ctx, _ := GlobalSession.beginOperation(context.Background())
	if h, ok := ctx.Value(spanKey{}).(Hook); ok && h != nil {
		h.Fire()
	}
}

func ImpureInvokedInside() error {
	ctx, _ := GlobalSession.beginInvokedInside(context.Background())
	return ctx.Err()
}

func ImpureDeferredInside() error {
	ctx, _ := GlobalSession.beginDeferredInside(context.Background())
	return ctx.Err()
}

func ImpureSameSlot() {
	fn, _ := GlobalSession.beginSameSlot()
	fn()
}
`)

	pkgPath := "example.com/tuplescreen"
	cases := []struct {
		symbol string
		want   bool
	}{
		{symbol: "CleanDirectBegin", want: true},
		{symbol: "CleanForwardedBegin", want: true},
		{symbol: "CleanFactoryBegin", want: true},
		{symbol: "ImpureValueFromBegin", want: false},
		{symbol: "ImpureInvokedInside", want: false},
		{symbol: "ImpureDeferredInside", want: false},
		{symbol: "ImpureSameSlot", want: false},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		subjects = append(subjects, Subject{Package: pkgPath, Symbol: tc.symbol})
	}

	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		subj := Subject{Package: pkgPath, Symbol: tc.symbol}
		if got[subj].Observable != tc.want {
			t.Fatalf("%s observability = %+v, want Observable=%v", tc.symbol, got[subj], tc.want)
		}
	}

	prog, err := h.loadCached(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	userPaths := map[string]bool{pkgPath: true}
	fp := &freshParamAnalysis{
		ssaProgramIndex: ssaProgramIndex{
			prog:             prog,
			selectionAudited: true,
			userPaths:        userPaths,
			isStd: func(fn *ssa.Function) bool {
				return isStdPkgPath(userPaths, funcPkgPath(fn))
			},
		},
	}
	beginOp := prog.Roots["Session.beginOperation"]
	beginForward := prog.Roots["Session.beginForwardNamed"]
	beginFactory := prog.Roots["Session.beginFactoryCleanup"]
	beginSame := prog.Roots["Session.beginSameSlot"]
	if beginOp == nil || beginForward == nil || beginFactory == nil || beginSame == nil {
		t.Fatalf("missing SSA method roots: beginOp=%v beginForward=%v beginFactory=%v beginSame=%v", beginOp, beginForward, beginFactory, beginSame)
	}
	// beginOperation and beginForwardNamed attach s.hook via context.WithValue
	// to tupleIndex=0: paramMaySupplyTupleDynamicSeen stays true at tupleIndex=0
	// (guarding ctx.Value), while calleeParamMayAffectTupleResult is false at
	// tupleIndex=0 (admitting ctx.Err/Done/Deadline) and true at tupleIndex=1.
	for _, fn := range []*ssa.Function{beginOp, beginForward} {
		if !paramMaySupplyTupleDynamicSeen(true, userPaths, fn.Params[0], nil, 0, make(map[paramTupleKey]bool)) {
			t.Fatalf("%s tupleIndex=0: paramMaySupplyTupleDynamicSeen = false, want true (WithValue carries s.hook)", fn.Name())
		}
		if !paramMaySupplyTupleDynamicSeen(true, userPaths, fn.Params[0], nil, 1, make(map[paramTupleKey]bool)) {
			t.Fatalf("%s tupleIndex=1: paramMaySupplyTupleDynamicSeen = false, want true", fn.Name())
		}
		if calleeParamMayAffectTupleResult(fp, fn, 0, 0, make(map[paramTupleKey]bool)) {
			t.Fatalf("%s tupleIndex=0: calleeParamMayAffectTupleResult = true, want false", fn.Name())
		}
		if !calleeParamMayAffectTupleResult(fp, fn, 0, 1, make(map[paramTupleKey]bool)) {
			t.Fatalf("%s tupleIndex=1: calleeParamMayAffectTupleResult = false, want true", fn.Name())
		}
	}
	// beginFactoryCleanup never touches s on tupleIndex=0, confining s solely
	// to the cleanup closure returned at tupleIndex=1.
	if paramMaySupplyTupleDynamicSeen(true, userPaths, beginFactory.Params[0], nil, 0, make(map[paramTupleKey]bool)) {
		t.Fatal("beginFactoryCleanup tupleIndex=0: paramMaySupplyTupleDynamicSeen = true, want false")
	}
	if !paramMaySupplyTupleDynamicSeen(true, userPaths, beginFactory.Params[0], nil, 1, make(map[paramTupleKey]bool)) {
		t.Fatal("beginFactoryCleanup tupleIndex=1: paramMaySupplyTupleDynamicSeen = false, want true")
	}
	if calleeParamMayAffectTupleResult(fp, beginFactory, 0, 0, make(map[paramTupleKey]bool)) {
		t.Fatal("beginFactoryCleanup tupleIndex=0: calleeParamMayAffectTupleResult = true, want false")
	}
	if !calleeParamMayAffectTupleResult(fp, beginFactory, 0, 1, make(map[paramTupleKey]bool)) {
		t.Fatal("beginFactoryCleanup tupleIndex=1: calleeParamMayAffectTupleResult = false, want true")
	}
	for _, idx := range []int{0, 1} {
		if !paramMaySupplyTupleDynamicSeen(true, userPaths, beginSame.Params[0], nil, idx, make(map[paramTupleKey]bool)) {
			t.Fatalf("beginSameSlot tupleIndex=%d: paramMaySupplyTupleDynamicSeen = false, want true", idx)
		}
		if !calleeParamMayAffectTupleResult(fp, beginSame, 0, idx, make(map[paramTupleKey]bool)) {
			t.Fatalf("beginSameSlot tupleIndex=%d: calleeParamMayAffectTupleResult = false, want true", idx)
		}
	}
}

func TestSubjectRootLeaflessCellCycleBatchEquivalence(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/rootcycle\n\ngo 1.26\n")
	writeFile(t, dir, "pkg.go", `package rootcycle

type Box struct {
	fn func() string
}

func pureLeaf() string { return "leaf" }

func runBox(b *Box) string {
	if b != nil && b.fn != nil {
		return b.fn()
	}
	return ""
}

func SubjectLeaflessCycle(n int) string {
	var f, g func() string
	_ = func() bool { return f == nil && g == nil }
	for i := 0; i < n; i++ {
		f, g = g, f
	}
	return runBox(&Box{fn: f})
}

func SubjectPureStore() string {
	b := &Box{fn: pureLeaf}
	_ = OpenSubjectLeaflessCycle(b, 2)
	_ = SiblingOpenBox(b)
	return runBox(b)
}

func OpenSubjectLeaflessCycle(b *Box, n int) string {
	var f, g func() string
	_ = func() bool { return f == nil && g == nil }
	for i := 0; i < n; i++ {
		f, g = g, f
	}
	_ = &Box{fn: f}
	return runBox(b)
}

func SiblingOpenBox(b *Box) string {
	return runBox(b)
}
`)

	pkgPath := "example.com/rootcycle"
	sCycle := Subject{Package: pkgPath, Symbol: "SubjectLeaflessCycle"}
	sPure := Subject{Package: pkgPath, Symbol: "SubjectPureStore"}
	sOpen := Subject{Package: pkgPath, Symbol: "OpenSubjectLeaflessCycle"}
	sSibling := Subject{Package: pkgPath, Symbol: "SiblingOpenBox"}
	subjects := []Subject{sCycle, sPure, sOpen, sSibling}

	soloObs := make(map[Subject]Observability, len(subjects))
	soloRooted := make(map[Subject]RootedFunctions, len(subjects))
	for _, s := range subjects {
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		obs, err := h.ComputeObservabilityBatch([]Subject{s})
		if err != nil {
			t.Fatal(err)
		}
		soloObs[s] = obs[s]
		rf, err := h.ComputeRootedFunctions(context.Background(), []Subject{s})
		if err != nil {
			t.Fatal(err)
		}
		soloRooted[s] = rf[s]
	}

	for _, s := range subjects {
		if !soloObs[s].Observable || !soloRooted[s].Complete {
			t.Fatalf("solo %s: obs=%+v rooted=%+v, want Observable && Complete", s.Symbol, soloObs[s], soloRooted[s])
		}
	}

	for _, order := range [][]Subject{
		{sCycle, sPure, sOpen, sSibling},
		{sPure, sCycle, sOpen, sSibling},
		{sSibling, sOpen, sCycle, sPure},
		{sOpen, sSibling, sCycle, sPure},
	} {
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		obs, err := h.ComputeObservabilityBatch(order)
		if err != nil {
			t.Fatal(err)
		}
		rf, err := h.ComputeRootedFunctions(context.Background(), order)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range order {
			if obs[s] != soloObs[s] {
				t.Fatalf("order=%v %s obs: batch=%+v, solo=%+v", order, s.Symbol, obs[s], soloObs[s])
			}
			if rf[s].Complete != soloRooted[s].Complete || !maps.Equal(rf[s].Fns, soloRooted[s].Fns) {
				t.Fatalf("order=%v %s rooted: batch=%+v, solo=%+v", order, s.Symbol, rf[s], soloRooted[s])
			}
		}
	}
}
