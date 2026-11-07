package closure

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/closure/internal/compartment"
	"github.com/greatliontech/gofresh/internal/closure/internal/digest"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
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
	second.testBinaryKeys = map[string]string{"example.com/memo": "stale-key"}
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
	if second.testBinaryKeys["example.com/memo"] == "stale-key" {
		t.Fatal("the observability batch retained a pre-call key generation")
	}

	third, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	third.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
	third.testBinaryKeys = map[string]string{"example.com/memo": "stale-key"}
	third.variantScope = map[string]compartment.Identity{"example.com/memo": {Hash: "stale-compartment"}}
	batched, _, err := third.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if third.testBinaryKeys["example.com/memo"] == "stale-key" {
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
	first.ctx = cancelWhenDirNonEmpty{dir: memoFiles}
	if _, err := first.ComputeObservabilityBatch(subjects); err == nil {
		t.Fatal("mid-group cancellation did not surface")
	}

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
	firstRooted, err := cold.ComputeRootedFunctions(cold.ctx, subjects)
	if err != nil {
		t.Fatal(err)
	}
	firstBinary, err := cold.ComputeBinaryRootedFunctions(cold.ctx, []string{"example.com/memo"})
	if err != nil {
		t.Fatal(err)
	}

	warm, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	warm.SetAnalysisScope(scope)
	secondRooted, err := warm.ComputeRootedFunctions(warm.ctx, subjects)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstRooted, secondRooted) {
		t.Fatalf("warm rooted functions = %+v, want %+v", secondRooted, firstRooted)
	}
	if !warm.ServedSummary()["rooted functions"]["example.com/memo"] {
		t.Fatalf("expected warm ComputeRootedFunctions to record serve: %v", warm.ServedSummary())
	}
	secondBinary, err := warm.ComputeBinaryRootedFunctions(warm.ctx, []string{"example.com/memo"})
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
	rootedHasher.testBinaryKeys = map[string]string{"example.com/memo": "stale-key"}
	rootedHasher.contribs = map[string]depContribution{"example.com/memo": {contribution: "src:example.com/memo=stale"}}
	if _, err := rootedHasher.ComputeRootedFunctions(rootedHasher.ctx, subjects); err != nil {
		t.Fatal(err)
	}
	if !rootedHasher.ServedSummary()["rooted functions"]["example.com/memo"] {
		t.Fatalf("stale pre-call key defeated rooted-functions memo hit: %v", rootedHasher.ServedSummary())
	}
	if rootedHasher.testBinaryKeys["example.com/memo"] == "stale-key" {
		t.Fatal("ComputeRootedFunctions retained stale testBinaryKeys")
	}

	// Populate binary rooted memo, then verify ComputeBinaryRootedFunctions also
	// discards stale testBinaryKeys and restores h.ctx after a cancelled call.
	if _, err := obsHasher.ComputeBinaryRootedFunctions(obsHasher.ctx, []string{"example.com/memo"}); err != nil {
		t.Fatal(err)
	}
	binHasher, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	binHasher.SetAnalysisScope(scope)
	binHasher.testBinaryKeys = map[string]string{"example.com/memo": "stale-key"}
	if _, err := binHasher.ComputeBinaryRootedFunctions(binHasher.ctx, []string{"example.com/memo"}); err != nil {
		t.Fatal(err)
	}
	if !binHasher.ServedSummary()["binary rooted functions"]["example.com/memo"] {
		t.Fatalf("stale pre-call key defeated binary-rooted-functions memo hit: %v", binHasher.ServedSummary())
	}
	if binHasher.testBinaryKeys["example.com/memo"] == "stale-key" {
		t.Fatal("ComputeBinaryRootedFunctions retained stale testBinaryKeys")
	}

	cancelled, cancel := context.WithCancel(binHasher.ctx)
	cancel()
	if _, err := binHasher.ComputeRootedFunctions(cancelled, subjects); err == nil {
		t.Fatal("expected cancelled context to fail ComputeRootedFunctions")
	}
	if binHasher.ctx.Err() != nil {
		t.Fatal("ComputeRootedFunctions did not restore h.ctx after cancelled call")
	}
	if _, err := binHasher.ComputeBinaryRootedFunctions(cancelled, []string{"example.com/memo"}); err == nil {
		t.Fatal("expected cancelled context to fail ComputeBinaryRootedFunctions")
	}
	if binHasher.ctx.Err() != nil {
		t.Fatal("ComputeBinaryRootedFunctions did not restore h.ctx after cancelled call")
	}
}

// fileMemoModule writes a package whose plain files carry an effect, and
// whose test file declares a subject beside a helper type.
func fileMemoModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":    "module example.com/fm\n\ngo 1.26\n",
		"p.go":      "package fm\n\nimport \"os\"\n\nfunc P() string { return os.Getenv(\"X\") }\n",
		"helper.go": "package fm\n\nfunc helper() int { return 1 }\n",
		"p_test.go": "package fm\n\nimport \"testing\"\n\ntype fixture struct{ n int }\n\nfunc TestP(t *testing.T) { _ = P(); _ = fixture{helper()} }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

var fileMemoSubjects = []Subject{{Package: "example.com/fm", Symbol: "P"}, {Package: "example.com/fm", Symbol: "TestP"}}

// foldOnce computes the fixture's closures with a fresh Hasher and
// returns them beside the files the pass parsed for its effect scans and
// the compartment members it derived.
func foldOnce(t *testing.T, dir string, memo bool) (map[Subject]Closure, []string, []string) {
	t.Helper()
	got, parsed, derived, _ := foldOnceWithCanonical(t, dir, memo)
	return got, parsed, derived
}

func foldOnceWithCanonical(t *testing.T, dir string, memo bool) (map[Subject]Closure, []string, []string, []string) {
	t.Helper()
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !memo {
		h.fileMemo = nil
	}
	var (
		parsed, derived, canonical []string
		got                        map[Subject]Closure
	)
	withClosureTestHooks(analysisTestHookSet{
		fileParse:      func(path string) { parsed = append(parsed, filepath.Base(path)) },
		variantParse:   func(name string) { derived = append(derived, name) },
		canonicalParse: func(d string) { canonical = append(canonical, filepath.Base(d)) },
	}, func() {
		got, _, err = h.ComputeMaximalBatch(fileMemoSubjects)
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(parsed)
	sort.Strings(derived)
	summary := h.ServedSummary()
	if memo && len(parsed) == 0 && !summary["file scan"]["example.com/fm"] {
		t.Fatal("no file scan parsed and none served")
	}
	return got, parsed, derived, canonical
}

// A warm pass parses nothing: every file's effect scan and every
// compartment member's derivation serve under the file's content digest,
// and the closures equal an unmemoized fold's
// (REQ-closure-effect-scan-memo, REQ-closure-test-variant-ledger).
func TestFileMemosServeEveryParseOnAWarmPass(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := fileMemoModule(t)
	reference, _, _ := foldOnce(t, dir, false)
	cold, parsed, derived := foldOnce(t, dir, true)
	if want := []string{"helper.go", "p.go", "p_test.go"}; !reflect.DeepEqual(parsed, want) {
		t.Fatalf("cold pass parsed %v, want %v", parsed, want)
	}
	if want := []string{"helper.go", "p.go", "p_test.go"}; !reflect.DeepEqual(derived, want) {
		t.Fatalf("cold pass derived %v, want %v", derived, want)
	}
	if !reflect.DeepEqual(cold, reference) {
		t.Fatalf("memoized cold fold differs from the unmemoized one:\n got %+v\nwant %+v", cold, reference)
	}
	warm, parsed, derived := foldOnce(t, dir, true)
	if len(parsed) != 0 || len(derived) != 0 {
		t.Fatalf("warm pass parsed %v and derived %v", parsed, derived)
	}
	if !reflect.DeepEqual(warm, reference) {
		t.Fatalf("served fold differs from the unmemoized one:\n got %+v\nwant %+v", warm, reference)
	}
	if !reference[fileMemoSubjects[0]].Unverifiable {
		t.Fatal("fixture no longer carries the effect the file scan must reproduce")
	}
}

// An edit misses exactly the edited file: its scan re-parses, its
// binding derivation re-derives for base and compartment members, every other
// file still serves, and the fold equals an unmemoized one; a corrupt
// entry recomputes.
func TestFileMemosMissOnlyTheEditedFile(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	dir := fileMemoModule(t)
	foldOnce(t, dir, true)
	edit := func(name string) {
		full := filepath.Join(dir, name)
		original, err := os.ReadFile(full)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, append(append([]byte(nil), original...), []byte("\n// edit\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	edit("helper.go")
	reference, _, _ := foldOnce(t, dir, false)
	got, parsed, derived := foldOnce(t, dir, true)
	if !reflect.DeepEqual(parsed, []string{"helper.go"}) || !reflect.DeepEqual(derived, []string{"helper.go"}) {
		t.Fatalf("after a plain-file edit: parsed %v, derived %v", parsed, derived)
	}
	if !reflect.DeepEqual(got, reference) {
		t.Fatalf("fold after the edit differs from the unmemoized one:\n got %+v\nwant %+v", got, reference)
	}
	edit("p_test.go")
	reference, _, _ = foldOnce(t, dir, false)
	got, parsed, derived = foldOnce(t, dir, true)
	if !reflect.DeepEqual(parsed, []string{"p_test.go"}) || !reflect.DeepEqual(derived, []string{"p_test.go"}) {
		t.Fatalf("after a test-file edit: parsed %v, derived %v", parsed, derived)
	}
	if !reflect.DeepEqual(got, reference) {
		t.Fatalf("fold after the test edit differs from the unmemoized one:\n got %+v\nwant %+v", got, reference)
	}
	for _, sub := range []string{fileScanDirName, variantParseDirName} {
		entries, _ := filepath.Glob(filepath.Join(cache, "gofresh", sub, "*.json"))
		if len(entries) == 0 {
			t.Fatalf("no %s entries persisted", sub)
		}
		for _, e := range entries {
			if err := os.WriteFile(e, []byte("{not json"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	got, parsed, derived = foldOnce(t, dir, true)
	if len(parsed) != 3 || len(derived) != 3 {
		t.Fatalf("after corruption: parsed %v, derived %v", parsed, derived)
	}
	if !reflect.DeepEqual(got, reference) {
		t.Fatalf("fold after corruption differs from the unmemoized one:\n got %+v\nwant %+v", got, reference)
	}
}

// Every scan of the effect-scan corpus survives the persisted form:
// encoded, marshalled, unmarshalled, decoded, it is the same scan.
func TestFileScanPayloadRoundTripsTheCorpus(t *testing.T) {
	dir := t.TempDir()
	parsed := 0
	for name, content := range effectScanCorpusFiles() {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		scan, err := maximalFileEffects(true, path)
		if err != nil {
			continue
		}
		parsed++
		raw, err := json.Marshal(effectScanPayload{Effects: encodeEffects(scan.effects), ImportCandidates: encodeEffects(scan.importCandidates), Selected: scan.preferred})
		if err != nil {
			t.Fatal(err)
		}
		var payload effectScanPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		back := maximalEffectScan{effects: decodeEffects(payload.Effects), importCandidates: decodeEffects(payload.ImportCandidates), preferred: payload.Selected}
		if !reflect.DeepEqual(back, scan) {
			t.Fatalf("%s: round trip changed the scan:\n got %+v\nwant %+v", name, back, scan)
		}
	}
	if parsed < 10 {
		t.Fatalf("the corpus yielded %d parsed scans; the round trip covers too little", parsed)
	}
}

// A package scan key derived twice over an unchanged tree — the
// preparation path, outside any batch call — derives every compartment
// member once: the second derivation serves the first's parses.
func TestCompartmentParsesServeOnTheScanKeyPath(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := fileMemoModule(t)
	var derived []string
	keys := make([]string, 2)
	withClosureTestHooks(analysisTestHookSet{
		variantParse: func(name string) { derived = append(derived, name) },
	}, func() {
		for i := range keys {
			h, err := newAt(dir)
			if err != nil {
				t.Fatal(err)
			}
			if keys[i], err = h.PackageScanKey("example.com/fm"); err != nil {
				t.Fatal(err)
			}
		}
	})
	if keys[0] != keys[1] {
		t.Fatalf("scan keys differ over an unchanged tree: %s vs %s", keys[0], keys[1])
	}
	sort.Strings(derived)
	if !reflect.DeepEqual(derived, []string{"helper.go", "p.go", "p_test.go"}) {
		t.Fatalf("derivations = %v, want each base and test file once", derived)
	}
}

// recordingMemo round-trips every recorded derivation through JSON and
// serves it back, so a served ledger is exactly the persisted form.
type recordingMemo struct{ entries map[string][]byte }

func (m *recordingMemo) Parsed(name, digest string) ([]testvariant.TestVariantDeclaration, testvariant.TestVariantFileHeader, bool) {
	raw, ok := m.entries[name+"\x00"+digest]
	if !ok {
		return nil, testvariant.TestVariantFileHeader{}, false
	}
	var payload variantParsePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		panic(err)
	}
	return payload.Declarations, payload.Header, true
}

func (m *recordingMemo) Record(name, digest string, declarations []testvariant.TestVariantDeclaration, header testvariant.TestVariantFileHeader) {
	raw, err := json.Marshal(variantParsePayload{Declarations: declarations, Header: header})
	if err != nil {
		panic(err)
	}
	m.entries[name+"\x00"+digest] = raw
}

// A compartment identity built from served derivations equals one built
// by parsing, ledger and hash alike — the dual member (compiled and
// embedded) included, whose whole-content header is applied on the
// served path exactly as on the parsed one.
func TestCompartmentParseRoundTripsThroughThePersistedForm(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a_test.go": "package p\n\nimport \"testing\"\n\nconst (\n\tA = iota\n\tB\n)\n\ntype T struct{ n int }\n\nfunc (t T) M() int { return t.n }\n\nvar x = B\n\nfunc init() { x++ }\n\nfunc TestA(t *testing.T) { _ = T{}.M() }\n",
		"b_test.go": "package p_test\n\nimport \"testing\"\n\n//go:embed data.txt\nvar data string\n\nfunc TestB(t *testing.T) { _ = data }\n",
		"data.txt":  "data\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{"a_test.go", "b_test.go", "data.txt"}
	compiled := map[string]bool{"a_test.go": true, "b_test.go": true}
	embedded := map[string]bool{"data.txt": true, "b_test.go": true}
	want, err := compartment.ComputeIdentity(dir, names, compiled, embedded, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	memo := &recordingMemo{entries: map[string][]byte{}}
	if _, err := compartment.ComputeIdentity(dir, names, compiled, embedded, nil, nil, memo); err != nil {
		t.Fatal(err)
	}
	if len(memo.entries) != 2 {
		t.Fatalf("recorded %d derivations, want the two compiled members", len(memo.entries))
	}
	got, err := compartment.ComputeIdentity(dir, names, compiled, embedded, nil, nil, memo)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("served identity differs:\n got %+v\nwant %+v", got, want)
	}
	dual := false
	for _, header := range got.Ledger.FileHeaders {
		if header.File == "b_test.go" {
			dual = header.Embedded && header.Hash == digestOf(t, filepath.Join(dir, "b_test.go"))
		}
	}
	if !dual {
		t.Fatalf("the served dual member lost its whole-content header: %+v", got.Ledger.FileHeaders)
	}
}

func digestOf(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest.Content(content)
}

// A module-cache file takes no per-file entry and no place in the call's
// content cache — its package-level entry is its store — while a
// mutable-local file takes both; and a byte-identical sibling derived in
// the same pass serves from the pending merge without a store serve on
// record.
func TestFileScanGatesModuleCacheFilesAndPendingSiblings(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	cacheRoot := t.TempDir()
	pinnedDir := filepath.Join(cacheRoot, "example.com", "dep@v1.0.0")
	if err := os.MkdirAll(pinnedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	localDir := t.TempDir()
	src := "package p\n\nimport \"os\"\n\nfunc F() string { return os.Getenv(\"X\") }\n"
	pinned := filepath.Join(pinnedDir, "dep.go")
	first, second := filepath.Join(localDir, "a.go"), filepath.Join(localDir, "b.go")
	for _, path := range []string{pinned, first, second} {
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := &Hasher{selectionResolved: true, source: sourceDigests{Content: "content", Policy: "policy"}, modCache: cacheRoot, maximalFiles: map[string]maximalEffectScan{}, fileMemo: newFileMemos(), contents: map[string]fileBytes{}}
	var parsed []string
	withClosureTestHooks(analysisTestHookSet{
		fileParse: func(path string) { parsed = append(parsed, filepath.Base(path)) },
	}, func() {
		want, err := maximalFileEffects(true, pinned)
		if err != nil {
			t.Fatal(err)
		}
		got, err := h.maximalFileEffectsCached("example.com/dep", pinned)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("pinned scan = %+v, want %+v", got, want)
		}
		if _, cached := h.contents[pinned]; cached || len(h.fileMemo.scans.pending) != 0 {
			t.Fatalf("a module-cache file entered the content cache (%t) or the per-file memo (%d dirs pending)", cached, len(h.fileMemo.scans.pending))
		}
		for _, path := range []string{first, second} {
			if got, err := h.maximalFileEffectsCached("example.com/local", path); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("%s: scan = %+v (err %v), want %+v", path, got, err, want)
			}
		}
	})
	if _, cached := h.contents[first]; !cached || len(h.fileMemo.scans.pending[localDir]) != 1 {
		t.Fatalf("the mutable-local files did not enter the content cache (%t) and one pending entry (%d)", cached, len(h.fileMemo.scans.pending[localDir]))
	}
	if !reflect.DeepEqual(parsed, []string{"a.go"}) {
		t.Fatalf("parsed %v, want the first sibling alone", parsed)
	}
	if len(h.ServedSummary()["file scan"]) != 0 {
		t.Fatalf("a pending-sibling hit was reported as a store serve: %v", h.ServedSummary())
	}
}

// TestContributionMemoServesWhatAMissDerives pins the memo's core property
// on both arms: with the memo armed, a second derivation of one node is a
// hit that returns exactly what the miss returned — contribution and files
// alike (REQ-closure-batch-equivalence: sharing changes cost, never
// evidence).
func TestContributionMemoServesWhatAMissDerives(t *testing.T) {
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
	h.contribs = map[string]depContribution{}
	cacheDir := filepath.Join(h.modCache, "example.com", "dep@v1.0.0")
	for _, tc := range []struct {
		name string
		pkg  listPkg
		want string
	}{
		{"mutable", listPkg{ImportPath: "example.com/memo", Dir: dir, GoFiles: []string{"m.go"}, Module: &listMod{Main: true, Dir: dir}}, ""},
		{"cache", listPkg{ImportPath: "example.com/dep", Dir: cacheDir, Module: &listMod{Main: false, Dir: cacheDir}}, "cache:example.com/dep@v1.0.0"},
	} {
		miss, missFiles, err := h.contributionAndFilesFor("", tc.pkg)
		if err != nil {
			t.Fatalf("%s miss: %v", tc.name, err)
		}
		// The cache leg pins the exact pin bytes and that pinned source is
		// never read: a mis-classification or a shifted pin would silently
		// move every closure hash.
		if tc.want != "" && (miss != tc.want || missFiles != nil) {
			t.Fatalf("%s: contribution %q files %v, want %q with no files", tc.name, miss, missFiles, tc.want)
		}
		if _, ok := h.contribs[tc.pkg.ImportPath]; !ok {
			t.Fatalf("%s: the armed memo recorded nothing", tc.name)
		}
		hit, hitFiles, err := h.contributionAndFilesFor("", tc.pkg)
		if err != nil {
			t.Fatalf("%s hit: %v", tc.name, err)
		}
		if hit != miss {
			t.Fatalf("%s: hit contribution %q, miss %q", tc.name, hit, miss)
		}
		if !reflect.DeepEqual(hitFiles, missFiles) {
			t.Fatalf("%s: hit files %v, miss %v", tc.name, hitFiles, missFiles)
		}
		// A served hit and a silent re-derivation are equal by design; a
		// planted sentinel discriminates them — the next call must return
		// the memo's entry, not re-derive.
		h.contribs[tc.pkg.ImportPath] = depContribution{contribution: "sentinel:" + tc.name, files: []string{"sentinel"}}
		served, servedFiles, err := h.contributionAndFilesFor("", tc.pkg)
		if err != nil {
			t.Fatalf("%s sentinel: %v", tc.name, err)
		}
		if served != "sentinel:"+tc.name || !reflect.DeepEqual(servedFiles, []string{"sentinel"}) {
			t.Fatalf("%s: memo lookup bypassed: got %q/%v", tc.name, served, servedFiles)
		}
		h.contribs = map[string]depContribution{}
	}
}

// TestModulePinIsCacheRelativeAndSlashCanonical pins the pin identity's
// exact bytes: the cache-relative module content dir, Clean-normalized.
// The pin feeds every closure hash and persistent memo key, so a silent
// shift here invalidates all of them wholesale.
func TestModulePinIsCacheRelativeAndSlashCanonical(t *testing.T) {
	h := &Hasher{modCache: filepath.Join(string(filepath.Separator), "cache", "mod")}
	root := h.modCache
	for _, tc := range []struct {
		name string
		dir  string
		want string
	}{
		{"under cache", filepath.Join(root, "example.com", "dep@v1.0.0"), "example.com/dep@v1.0.0"},
		{"trailing separator cleans", filepath.Join(root, "example.com", "dep@v1.0.0") + string(filepath.Separator), "example.com/dep@v1.0.0"},
		{"outside cache keeps its identity", filepath.Join(string(filepath.Separator), "elsewhere", "dep"), "/elsewhere/dep"},
		{"the cache root itself is not relativized", root, filepath.ToSlash(root)},
	} {
		if got := h.modulePin(&listMod{Dir: tc.dir}); got != tc.want {
			t.Fatalf("%s: modulePin(%q) = %q, want %q", tc.name, tc.dir, got, tc.want)
		}
	}
}

// TestBatchEntriesDiscardStaleContributionEntries pins the call scope: a
// batch entry must start from an empty memo, or an edit between calls
// could serve a prior generation's contribution.
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
	h.contribs = map[string]depContribution{"example.com/memo": {contribution: "src:example.com/memo=stale"}}
	batched, _, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	independent := computeAt(t, dir, subject)
	if batched[subject] != independent[subject] {
		t.Fatalf("batch served a pre-call memo generation: %+v vs %+v", batched[subject], independent[subject])
	}
	h2, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2.contribs = map[string]depContribution{"example.com/memo": {contribution: "src:example.com/memo=stale"}}
	if _, err := h2.ComputeObservabilityBatch([]Subject{{Package: "example.com/memo", Symbol: "M"}}); err != nil {
		t.Fatal(err)
	}
	if c, ok := h2.contribs["example.com/memo"]; ok && c.contribution == "src:example.com/memo=stale" {
		t.Fatal("observability batch served or retained a pre-call memo generation")
	}
}

func pinnedFixture(t *testing.T, h *Hasher) (listPkg, string) {
	t.Helper()
	moduleDir := filepath.Join(h.modCache, "example.com", "pinned@v1.2.3")
	pkgDir := filepath.Join(moduleDir, "eff")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The directives populate the wire shape's detail and unrefinable
	// fields, so the serve test's DeepEqual pins the full round trip.
	source := "package eff\n\nimport \"os\"\n\n//go:wasmimport host log\n//go:linkname E\nfunc E() { _, _ = os.ReadFile(\"x\") }\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "eff.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := listPkg{
		ImportPath: "example.com/pinned/eff",
		Dir:        pkgDir,
		GoFiles:    []string{"eff.go"},
		Module:     &listMod{Path: "example.com/pinned", Version: "v1.2.3", Dir: moduleDir, Main: false},
	}
	return pkg, pkgDir
}

// TestEffectScanMemoServesPinnedPackagesWithoutReads pins the memo's core
// property (REQ-closure-effect-scan-memo): a pinned package's scan derived
// once serves from the persistent memo with no file reads — proven by
// deleting the files and serving the identical scan from a fresh Hasher.
func TestEffectScanMemoServesPinnedPackagesWithoutReads(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/host\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Steer the fake module cache under the temp tree.
	h.modCache = filepath.Join(dir, "modcache")
	pkg, pkgDir := pinnedFixture(t, h)

	derived, handled, err := h.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("derivation = handled %v, err %v", handled, err)
	}
	if derived.preferred == "" || len(derived.effects) == 0 {
		t.Fatalf("derived scan carries no facts: %+v", derived)
	}
	// Every guard leg runs while the fixture's files are still readable,
	// so a weakened guard genuinely derives and serves rather than
	// escaping through a read error. A module reporting no version takes
	// the read path even when its files sit inside the module cache: its
	// pin would carry no signal. (Reachable listings report no version
	// only for the main and workspace modules; the leg is witnessed here
	// in its own right.)
	unversioned := pkg
	unversioned.Module = &listMod{Path: "example.com/pinned", Dir: filepath.Dir(pkgDir), Main: false}
	if _, handled, err := h.pinnedEffectScan(unversioned); err != nil || handled {
		t.Fatalf("unversioned in-cache package = handled %v, err %v; want unhandled, nil", handled, err)
	}
	// A version-labeled module living outside the module cache (a local
	// replace) and a module without a content dir likewise read.
	dirless := pkg
	dirless.Module = &listMod{Path: "example.com/pinned", Version: "v1.2.3", Main: false}
	if _, handled, err := h.pinnedEffectScan(dirless); err != nil || handled {
		t.Fatalf("dirless module = handled %v, err %v; want unhandled, nil", handled, err)
	}
	if err := os.RemoveAll(pkgDir); err != nil {
		t.Fatal(err)
	}
	h2, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2.modCache = h.modCache
	served, handled, err := h2.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("serve = handled %v, err %v", handled, err)
	}
	if !reflect.DeepEqual(served, derived) {
		t.Fatalf("served scan diverged:\n got %+v\nwant %+v", served, derived)
	}
	// A mutable-local package never enters this memo — with a real,
	// readable file, so a weakened guard would genuinely derive and
	// serve rather than escape through a read error.
	localDir := filepath.Join(dir, "local")
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localDir, "eff.go"), []byte("package eff\n\nimport \"os\"\n\nfunc E() { _, _ = os.ReadFile(\"x\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	local := pkg
	local.Module = &listMod{Main: true, Dir: dir}
	local.Dir = localDir
	if _, handled, err := h2.pinnedEffectScan(local); err != nil || handled {
		t.Fatalf("mutable-local package = handled %v, err %v; want unhandled, nil", handled, err)
	}
	// A synthetic version label on a module outside the cache still reads:
	// the cache-membership leg holds on its own.
	replaced := pkg
	replaced.Module = &listMod{Path: "example.com/pinned", Version: "v1.2.3", Dir: localDir, Main: false}
	replaced.Dir = localDir
	if _, handled, err := h2.pinnedEffectScan(replaced); err != nil || handled {
		t.Fatalf("local-replace package = handled %v, err %v; want unhandled, nil", handled, err)
	}
	// Package-level facts ride the live listing, never the memo: the same
	// key serves a different composite when the build configuration moves
	// a metadata fact (an assembly file selected only under some tags),
	// still with no file reads.
	asm := pkg
	asm.SFiles = []string{"impl_asm.s"}
	withAsm, handled, err := h2.pinnedEffectScan(asm)
	if err != nil || !handled {
		t.Fatalf("assembly-carrying serve = handled %v, err %v", handled, err)
	}
	assembly := opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly").reason
	if !hasEffectReason(withAsm.effects, assembly) {
		t.Fatalf("assembly fact missing from the served composite: %+v", withAsm)
	}
	if hasEffectReason(served.effects, assembly) {
		t.Fatalf("assembly fact leaked into the assembly-free composite: %+v", served)
	}
}

// TestEffectScanMemoFoldMatchesInlineFold pins the byte-equivalence clause
// (REQ-closure-effect-scan-memo) against the inline loop's flat fold on a
// fixture that discriminates: a duplicate effect across two files, competing
// preferred diagnostics, and a package-level fact folding in first. Both the
// miss-path derivation and the memo hit must equal the flat per-item fold.
func TestEffectScanMemoFoldMatchesInlineFold(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/host\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.modCache = filepath.Join(dir, "modcache")
	pkg, pkgDir := pinnedFixture(t, h)
	if err := os.WriteFile(filepath.Join(pkgDir, "more.go"), []byte("package eff\n\nimport \"os\"\n\nfunc F() { _, _ = os.Open(\"y\"); _, _ = os.ReadFile(\"x\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "netimp.go"), []byte("package eff\n\nimport \"net\"\n\nfunc G() { _ = net.Dial }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg.GoFiles = append(pkg.GoFiles, "more.go", "netimp.go")
	pkg.SFiles = []string{"impl_asm.s"}

	flat := maximalPackageExternalEffects(&pkg)
	pkgFactCount := len(flat.effects)
	var rawEffects int
	var preferreds []string
	for _, name := range pkg.GoFiles {
		scan, err := maximalFileEffects(true, filepath.Join(pkgDir, name))
		if err != nil {
			t.Fatal(err)
		}
		rawEffects += len(scan.effects)
		preferreds = append(preferreds, scan.preferred)
		for _, effect := range scan.effects {
			flat.effects = appendExternalEffect(flat.effects, effect)
		}
		for _, candidate := range scan.importCandidates {
			flat.importCandidates = appendExternalEffect(flat.importCandidates, candidate)
		}
		if len(scan.effects) == 0 && len(scan.importCandidates) == 0 && scan.preferred != "" && (flat.preferred == "" || scan.preferred < flat.preferred) {
			flat.preferred = scan.preferred
		}
	}
	if selected := preferredEffectReason(append(append([]externalEffect(nil), flat.effects...), flat.importCandidates...)); selected != "" {
		flat.preferred = selected
	}
	if rawEffects <= len(flat.effects)-pkgFactCount {
		t.Fatalf("fixture does not discriminate dedup: %d raw file effects, %d folded", rawEffects, len(flat.effects)-pkgFactCount)
	}
	if len(preferreds) != 3 || preferreds[0] == preferreds[1] || preferreds[1] == preferreds[2] || preferreds[0] == preferreds[2] {
		t.Fatalf("fixture does not discriminate the preferred fold: %v", preferreds)
	}

	derived, handled, err := h.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("derivation = handled %v, err %v", handled, err)
	}
	if !reflect.DeepEqual(derived, flat) {
		t.Fatalf("miss-path composite diverged from the flat fold:\n got %+v\nwant %+v", derived, flat)
	}
	h2, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2.modCache = h.modCache
	served, handled, err := h2.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("serve = handled %v, err %v", handled, err)
	}
	if !reflect.DeepEqual(served, flat) {
		t.Fatalf("memo hit diverged from the flat fold:\n got %+v\nwant %+v", served, flat)
	}
	// The stored fold carries no package-level facts: deriving under a
	// configuration that selects the assembly file and then serving under
	// one that does not must drop the assembly fact, not replay it.
	var flatNoAsm maximalEffectScan
	for _, name := range pkg.GoFiles {
		scan, err := maximalFileEffects(true, filepath.Join(pkgDir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, effect := range scan.effects {
			flatNoAsm.effects = appendExternalEffect(flatNoAsm.effects, effect)
		}
		for _, candidate := range scan.importCandidates {
			flatNoAsm.importCandidates = appendExternalEffect(flatNoAsm.importCandidates, candidate)
		}
		if len(scan.effects) == 0 && len(scan.importCandidates) == 0 && scan.preferred != "" && (flatNoAsm.preferred == "" || scan.preferred < flatNoAsm.preferred) {
			flatNoAsm.preferred = scan.preferred
		}
	}
	if selected := preferredEffectReason(append(append([]externalEffect(nil), flatNoAsm.effects...), flatNoAsm.importCandidates...)); selected != "" {
		flatNoAsm.preferred = selected
	}
	noAsm := pkg
	noAsm.SFiles = nil
	servedNoAsm, handled, err := h2.pinnedEffectScan(noAsm)
	if err != nil || !handled {
		t.Fatalf("assembly-free serve = handled %v, err %v", handled, err)
	}
	if !reflect.DeepEqual(servedNoAsm, flatNoAsm) {
		t.Fatalf("assembly-free memo hit diverged from the flat file fold:\n got %+v\nwant %+v", servedNoAsm, flatNoAsm)
	}
}

// TestEffectScanMemoMissesOnScopeAndFileSetChange pins the key's
// completeness: a strategy-scope change, the toolchain identity, a file-set
// change, and the Go/cgo partition each miss, and a corrupt entry
// recomputes silently.
func TestEffectScanMemoMissesOnScopeAndFileSetChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	scan := maximalEffectScan{
		preferred:        "reaches net (network I/O)",
		effects:          []externalEffect{{kind: externalEffectFileIO, reason: "reaches os.ReadFile (file I/O)"}},
		importCandidates: []externalEffect{{kind: externalEffectNetwork, packagePath: "net", reason: "reaches net (network I/O)"}},
	}
	key := effectScanKey("example.com/pinned@v1.2.3", "example.com/pinned/eff", []string{"eff.go"}, nil)
	scope := (&Hasher{selectionResolved: true, source: sourceDigests{Content: "content", Policy: "policy"}}).effectScanScope()
	storeEffectScan(effectScanDirName, scope, key, scan)
	if got, ok := loadEffectScan(effectScanDirName, scope, key); !ok || !reflect.DeepEqual(got, scan) {
		t.Fatalf("round trip = %+v ok=%v", got, ok)
	}
	if _, ok := loadEffectScan(effectScanDirName, scope+"-bumped", key); ok {
		t.Fatal("a bumped scan strategy served a prior generation's scan")
	}
	if _, ok := loadEffectScan(effectScanDirName, effectScanStrategy, key); ok {
		t.Fatal("the bare strategy without the analyzing frontend served")
	}
	if _, ok := loadEffectScan(testingScanDirName, scope, key); ok {
		t.Fatal("the sibling testing-scan directory served the effect-scan entry")
	}
	otherFiles := effectScanKey("example.com/pinned@v1.2.3", "example.com/pinned/eff", []string{"eff.go", "extra.go"}, nil)
	if _, ok := loadEffectScan(effectScanDirName, scope, otherFiles); ok {
		t.Fatal("a changed file set served the prior set's scan")
	}
	migrated := effectScanKey("example.com/pinned@v1.2.3", "example.com/pinned/eff", nil, []string{"eff.go"})
	if _, ok := loadEffectScan(effectScanDirName, scope, migrated); ok {
		t.Fatal("a file migrating between the Go and cgo lists served the prior partition's scan")
	}
	path, err := cachefile.Path(effectScanDirName, scope, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadEffectScan(effectScanDirName, scope, key); ok {
		t.Fatal("a corrupt entry served")
	}
}

// A package whose files carry only potential-external fallbacks - no
// effects, no plain always-external candidates - selects the
// lexicographically least fallback, package-wide
// (REQ-closure-observability-cause-order).
func TestPinnedFallbackSelectsLexicographicLeast(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/host\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.modCache = filepath.Join(dir, "modcache")
	pkg, pkgDir := pinnedFixture(t, h)
	for name, source := range map[string]string{
		"only_time.go": "package eff\n\nvar _ = timeJan\n",
		"only_fmt.go":  "package eff\n\nimport \"fmt\"\n\nfunc S(v int) string { return fmt.Sprintf(\"%d\", v) }\n",
		"decl_time.go": "package eff\n\nimport \"time\"\n\nvar timeJan = time.January\n",
	} {
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg.GoFiles = []string{"decl_time.go", "only_fmt.go", "only_time.go"}
	composite, handled, err := h.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("derivation = handled %v, err %v", handled, err)
	}
	if len(composite.effects) != 0 || len(composite.importCandidates) != 0 {
		t.Fatalf("fallback fixture grew effects or candidates: %+v", composite)
	}
	if composite.preferred != "reaches fmt (potential external dependence)" {
		t.Fatalf("fallback selection = %q, want the lexicographic least", composite.preferred)
	}
}

// The persisted effect scan's strategy version is a golden: a bump is a
// conscious change of every persisted effect memo's identity.
func TestEffectScanStrategyVersion(t *testing.T) {
	if effectScanStrategy != "gofresh/effect-scan@28" {
		t.Fatalf("effect-scan strategy = %q, want @28", effectScanStrategy)
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

func testingScanModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/tscan\n\ngo 1.26\n")
	writeFile(t, dir, "scan.go", "package tscan\n\nfunc Pure(x int) int { return x + 1 }\n")
	writeFile(t, dir, "scan_test.go", `package tscan

import "testing"

func TestPure(t *testing.T) {
	_ = t.TempDir()
	if Pure(1) != 2 {
		t.Fatal("pure")
	}
}
`)
	return dir
}

// withTestingScanLoadCount observes the typed scan's own program load; a
// memo hit must never reach it.
func withTestingScanLoadCount(fn func(loads *int)) {
	loads := 0
	withClosureTestHooks(analysisTestHookSet{
		testingTypeOwnLoad: func(string) { loads++ },
	}, func() {
		fn(&loads)
	})
}

// TestTestingScanMemoServesWithoutTypeLoad pins the memo's core property
// (REQ-closure-testing-scan-memo): a scan derived once serves from the
// persistent memo with no type-environment load and byte-equivalent
// results — an effect-free scan included — and without a caller scope the
// memo stays disabled.
func TestTestingScanMemoServesWithoutTypeLoad(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := testingScanModule(t)
	if err := os.MkdirAll(filepath.Join(dir, "plain"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "plain/plain.go", "package plain\n\nfunc P() int { return 0 }\n")
	withTestingScanLoadCount(func(loads *int) {
		first, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		first.SetAnalysisScope(AnalysisScope{ProofStrategy: "strategy@1", Toolchain: "toolchain", BuildConfig: "build"})
		derived, err := first.maximalTestingTypeEffects("example.com/tscan")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 1 {
			t.Fatalf("derivation loads = %d, want 1", *loads)
		}
		if len(derived.effects) == 0 || derived.preferred == "" {
			t.Fatalf("derived scan carries no testing facts: %+v", derived)
		}

		second, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		second.SetAnalysisScope(AnalysisScope{ProofStrategy: "strategy@1", Toolchain: "toolchain", BuildConfig: "build"})
		served, err := second.maximalTestingTypeEffects("example.com/tscan")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 1 {
			t.Fatalf("memo hit loaded the type environment: loads = %d", *loads)
		}
		if !reflect.DeepEqual(served, derived) {
			t.Fatalf("served scan diverged:\n got %+v\nwant %+v", served, derived)
		}

		// Without a caller-supplied scope the memo is disabled: the scan
		// loads even though a matching entry exists under some scope.
		bare, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		bareScan, err := bare.maximalTestingTypeEffects("example.com/tscan")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 2 {
			t.Fatalf("scope-less scan loads = %d, want 2", *loads)
		}
		if !reflect.DeepEqual(bareScan, derived) {
			t.Fatalf("scope-less scan diverged:\n got %+v\nwant %+v", bareScan, derived)
		}

		// An effect-free scan round-trips as a hit: the recorded absence of
		// testing effects serves without a load.
		third, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		third.SetAnalysisScope(AnalysisScope{ProofStrategy: "strategy@1", Toolchain: "toolchain", BuildConfig: "build"})
		emptyDerived, err := third.maximalTestingTypeEffects("example.com/tscan/plain")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 3 {
			t.Fatalf("effect-free derivation loads = %d, want 3", *loads)
		}
		if len(emptyDerived.effects) != 0 || emptyDerived.preferred != "" {
			t.Fatalf("plain package scan carries facts: %+v", emptyDerived)
		}
		fourth, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		fourth.SetAnalysisScope(AnalysisScope{ProofStrategy: "strategy@1", Toolchain: "toolchain", BuildConfig: "build"})
		emptyServed, err := fourth.maximalTestingTypeEffects("example.com/tscan/plain")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 3 {
			t.Fatalf("effect-free memo hit loaded the type environment: loads = %d", *loads)
		}
		if !reflect.DeepEqual(emptyServed, emptyDerived) {
			t.Fatalf("effect-free served scan diverged:\n got %+v\nwant %+v", emptyServed, emptyDerived)
		}

		// A key-derivation failure disables the memo for the package —
		// fail-open to recomputation: the scan still derives, serves nothing
		// from the memo, and persists nothing. The poisoned session list
		// cache fails the closure hash while the scan's own load stays
		// healthy — a single-sided failure.
		cache, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		memoDir := filepath.Join(cache, "gofresh", testingScanDirName)
		before, err := os.ReadDir(memoDir)
		if err != nil {
			t.Fatal(err)
		}
		broken, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		broken.SetAnalysisScope(AnalysisScope{ProofStrategy: "strategy@1", Toolchain: "toolchain", BuildConfig: "build"})
		broken.lists["example.com/tscan"] = []listPkg{{
			ImportPath: "example.com/tscan",
			Dir:        filepath.Join(dir, "missing"),
			GoFiles:    []string{"gone.go"},
			Module:     &listMod{Path: "example.com/tscan", Main: true, Dir: dir},
		}}
		brokenScan, err := broken.maximalTestingTypeEffects("example.com/tscan")
		if err != nil {
			t.Fatalf("fail-open derivation errored: %v", err)
		}
		if *loads != 4 {
			t.Fatalf("fail-open scan loads = %d, want 4 (a failed key must not serve)", *loads)
		}
		if !reflect.DeepEqual(brokenScan, derived) {
			t.Fatalf("fail-open scan diverged:\n got %+v\nwant %+v", brokenScan, derived)
		}
		after, err := os.ReadDir(memoDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(before) {
			t.Fatalf("a failed key derivation persisted an entry: %d -> %d files", len(before), len(after))
		}
	})
}

// TestTestingScanMemoMissesOnScopeAndSourceChange pins the key's
// completeness (REQ-closure-testing-scan-memo): a scope change and a
// test-only source change each miss — the scan reads test-variant
// source, so the compartment axis participates — and a corrupt entry
// recomputes silently.
func TestTestingScanMemoMissesOnScopeAndSourceChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := testingScanModule(t)
	withTestingScanLoadCount(func(loads *int) {
		first, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		first.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
		before, err := first.maximalTestingTypeEffects("example.com/tscan")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 1 {
			t.Fatalf("derivation loads = %d, want 1", *loads)
		}

		otherScope, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		otherScope.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-b", BuildConfig: "build"})
		if _, err := otherScope.maximalTestingTypeEffects("example.com/tscan"); err != nil {
			t.Fatal(err)
		}
		if *loads != 2 {
			t.Fatal("a different scope served from the memo")
		}

		// A test-only edit moves the key and the scan alike.
		testSrc, err := os.ReadFile(filepath.Join(dir, "scan_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "scan_test.go"), append(testSrc, []byte("\nfunc TestExtra(t *testing.T) { t.Setenv(\"K\", \"V\") }\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
		moved, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		moved.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
		after, err := moved.maximalTestingTypeEffects("example.com/tscan")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 3 {
			t.Fatal("a test-only source change served from the memo")
		}
		if !hasEffectReason(after.effects, "reaches testing.Setenv (process or path mutation)") {
			t.Fatalf("post-edit scan misses the new testing effect: %+v", after)
		}
		if reflect.DeepEqual(after, before) {
			t.Fatal("post-edit scan equals the pre-edit scan")
		}

		// Corrupt entries recompute silently.
		cache, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(filepath.Join(cache, "gofresh", testingScanDirName))
		if err != nil || len(entries) == 0 {
			t.Fatalf("memo entries = %v, err %v", entries, err)
		}
		for _, entry := range entries {
			if err := os.WriteFile(filepath.Join(cache, "gofresh", testingScanDirName, entry.Name()), []byte("corrupt"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		recomputed, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		recomputed.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
		if _, err := recomputed.maximalTestingTypeEffects("example.com/tscan"); err != nil {
			t.Fatal(err)
		}
		if *loads != 4 {
			t.Fatal("a corrupt entry served")
		}
	})
}
