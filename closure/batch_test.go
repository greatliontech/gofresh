package closure

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/ssa"
)

const batchIsolationPackage = "github.com/greatliontech/gofresh/closure/fixtures/batchisolation"

func TestAttributedRTAEqualsIndependentRTA(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: batchIsolationPackage, Symbol: "AddressTaker"},
		{Package: batchIsolationPackage, Symbol: "DynamicCaller"},
		{Package: batchIsolationPackage, Symbol: "Materializer"},
		{Package: batchIsolationPackage, Symbol: "Invoker"},
		{Package: batchIsolationPackage, Symbol: "Production"},
		{Package: batchIsolationPackage, Symbol: "BenchmarkHarness"},
	}
	got, err := attributedReachableSets(context.Background(), prog, subjects)
	if err != nil {
		t.Fatal(err)
	}
	for i, subject := range subjects {
		want := independentReachableSet(t, prog, subject.Symbol)
		assertSameReachable(t, subject.Symbol, got[i].functions, want)
	}
}

func TestAttributedRTADynamicFactsRemainIsolated(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: batchIsolationPackage, Symbol: "AddressTaker"},
		{Package: batchIsolationPackage, Symbol: "DynamicCaller"},
		{Package: batchIsolationPackage, Symbol: "Materializer"},
		{Package: batchIsolationPackage, Symbol: "Invoker"},
	}
	reachable, err := attributedReachableSets(context.Background(), prog, subjects)
	if err != nil {
		t.Fatal(err)
	}

	dynamicTarget := prog.Roots["dynamicTarget"]
	if dynamicTarget == nil || !reachable[0].functions[dynamicTarget] {
		t.Fatal("address-taking subject did not reach dynamicTarget")
	}
	if reachable[1].functions[dynamicTarget] {
		t.Fatal("dynamic-call subject inherited another subject's address-taken function")
	}

	concreteMethod := prog.Roots["concrete.Run"]
	if concreteMethod == nil || !reachable[2].functions[concreteMethod] {
		t.Fatal("materializing subject did not reach concrete.Run")
	}
	if reachable[3].functions[concreteMethod] {
		t.Fatal("invoke subject inherited another subject's concrete runtime type")
	}
	nestedMethod := prog.Roots["nested.Exported"]
	if nestedMethod == nil || !reachable[2].functions[nestedMethod] {
		t.Fatal("materializing subject did not reach exported method of recursive runtime type")
	}
	if reachable[3].functions[nestedMethod] {
		t.Fatal("invoke subject inherited another subject's recursive runtime type")
	}

}

func TestTier2UsesOnlyResolvedAttributedDispatch(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		symbol string
		widen  bool
	}{
		{symbol: "KnownDynamic", widen: false},
		{symbol: "CallbackRoot", widen: true},
		{symbol: "Invoker", widen: true},
	} {
		t.Run(tc.symbol, func(t *testing.T) {
			result, err := computeTier2Result(h, batchIsolationPackage, tc.symbol)
			if err != nil {
				t.Fatal(err)
			}
			if result.widen != tc.widen {
				t.Fatalf("widen = %v (%s), want %v", result.widen, result.widenReason, tc.widen)
			}
		})
	}
}

func TestTier2WidensInitializedMutableGlobalDispatch(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	result, err := computeTier2Result(h, "github.com/greatliontech/gofresh/closure/fixtures/globalcallback", "F")
	if err != nil {
		t.Fatal(err)
	}
	if !result.widen {
		t.Fatalf("initialized mutable global did not widen: %+v", result)
	}
}

func TestAttributedRTARootMasks(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: batchIsolationPackage, Symbol: "Production"},
		{Package: batchIsolationPackage, Symbol: "BenchmarkHarness"},
	}
	reachable, err := attributedReachableSets(context.Background(), prog, subjects)
	if err != nil {
		t.Fatal(err)
	}
	startup := prog.Roots["startupHelper"]
	testMainHelper := prog.Roots["testMainHelper"]
	if startup == nil || !reachable[0].functions[startup] || !reachable[1].functions[startup] {
		t.Fatal("initializer root did not propagate to every subject")
	}
	if testMainHelper == nil || reachable[0].functions[testMainHelper] {
		t.Fatal("production subject reached conditional TestMain setup")
	}
	if !reachable[1].functions[testMainHelper] {
		t.Fatal("test-file subject did not reach TestMain setup")
	}
	siblingHelper := prog.Roots["benchmarkSiblingHelper"]
	if siblingHelper == nil || reachable[1].functions[siblingHelper] {
		t.Fatal("selected benchmark reached a sibling through generated harness registration")
	}
}

func TestAttributedRTAHonorsCancellationDuringTraversal(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterContext{Context: context.Background(), remaining: 2}
	_, err = attributedReachableSets(ctx, prog, []Subject{{Package: batchIsolationPackage, Symbol: "Materializer"}})
	if err == nil {
		t.Fatal("attributed RTA ignored cancellation during traversal")
	}
}

func TestTier2ProjectionHonorsCancellationDuringTraversal(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: batchIsolationPackage, Symbol: "Materializer"}
	reachable, err := attributedReachableSets(context.Background(), prog, []Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	metas, err := h.list(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	base := newTier2Base(h, prog, metas)
	h.ctx = &cancelAfterContext{Context: context.Background(), remaining: 3}
	if _, err := h.tier2Reachable(base, reachable[0]); err == nil {
		t.Fatal("tier-2 projection ignored cancellation during traversal")
	}
}

type cancelAfterContext struct {
	context.Context
	remaining int
}

func (c *cancelAfterContext) Err() error {
	if c.remaining == 0 {
		return context.Canceled
	}
	c.remaining--
	return nil
}

func TestObservabilityBatchSplitsAttributedStateAtMaskWidth(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/batchbound\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	source.WriteString("package batchbound\n\n")
	subjects := make([]Subject, maxAttributedSubjects+1)
	for i := range subjects {
		symbol := fmt.Sprintf("F%d", i)
		fmt.Fprintf(&source, "func %s() int { return %d }\n", symbol, i)
		subjects[i] = Subject{Package: "example.com/batchbound", Symbol: symbol}
	}
	if err := os.WriteFile(filepath.Join(dir, "batchbound.go"), []byte(source.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	last := subjects[len(subjects)-1]
	solo, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, err := solo.ComputeObservabilityBatch([]Subject{last})
	if err != nil {
		t.Fatal(err)
	}
	if got[last] != want[last] {
		t.Fatalf("boundary subject proof = %+v, independent = %+v", got[last], want[last])
	}
}

func TestStandardDynamicTargetMasksRemainSubjectLocal(t *testing.T) {
	subjects := []Subject{
		{Package: batchIsolationPackage, Symbol: "TestStandardDynamic"},
		{Package: batchIsolationPackage, Symbol: "Production"},
	}
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	reachable, err := attributedReachableSets(context.Background(), prog, subjects)
	if err != nil {
		t.Fatal(err)
	}
	metas, err := h.list(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	base := newTier2Base(h, prog, metas)
	batched := make([]tier2Result, len(subjects))
	for i, subject := range subjects {
		batched[i], err = h.tier2Reachable(base, reachable[i])
		if err != nil {
			t.Fatalf("batched analysis (%s): %v", subject.Symbol, err)
		}
		independentHasher, err := New()
		if err != nil {
			t.Fatal(err)
		}
		independent, err := computeTier2Result(independentHasher, subject.Package, subject.Symbol)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(batched[i].effects, independent.effects) ||
			batched[i].widen != independent.widen ||
			batched[i].widenReason != independent.widenReason ||
			batched[i].unverifiable != independent.unverifiable ||
			batched[i].reason != independent.reason {
			t.Fatalf("batched %s = %+v, independent = %+v", subject.Symbol, batched[i], independent)
		}
	}
	if !batched[0].unverifiable {
		t.Fatalf("standard dynamic target was verifiable: %+v", batched[0])
	}
}

func independentReachableSet(t *testing.T, prog *program, symbol string) map[*ssa.Function]bool {
	t.Helper()
	root := prog.Roots[symbol]
	if root == nil {
		t.Fatalf("subject root %s not found", symbol)
	}
	roots := []*ssa.Function{root}
	if prog.TestMain != nil && subjectRunsThroughHarness(prog, root) {
		roots = append(roots, prog.TestMain)
	}
	for _, pkg := range prog.Prog.AllPackages() {
		if isGeneratedTestMainPackage(prog, pkg) {
			continue
		}
		if init := pkg.Func("init"); init != nil {
			roots = append(roots, init)
		}
	}
	result := rta.Analyze(roots, false)
	if result == nil {
		t.Fatal("independent RTA returned nil")
	}
	reachable := make(map[*ssa.Function]bool, len(result.Reachable))
	for fn := range result.Reachable {
		reachable[fn] = true
	}
	return reachable
}

func assertSameReachable(t *testing.T, subject string, got, want map[*ssa.Function]bool) {
	t.Helper()
	for fn := range want {
		if !got[fn] {
			t.Errorf("%s: attributed RTA omitted %s", subject, functionName(fn))
		}
	}
	for fn := range got {
		if !want[fn] {
			t.Errorf("%s: attributed RTA added %s", subject, functionName(fn))
		}
	}
}

func functionName(fn *ssa.Function) string {
	if fn == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s (%s)", fn.String(), fn.RelString(nil))
}

// TestWidenReasonIsDeterministic pins the selection rule: the recorded
// widen reason is the lexicographically least of the requested set,
// whatever order the walk fires the requests in — the reason lands
// verbatim in persisted proofs, so it must be a function of the set.
func TestWidenReasonIsDeterministic(t *testing.T) {
	a := &tier2Analyzer{}
	a.requestWiden("zebra cause")
	a.requestWiden("alpha cause")
	a.requestWiden("mid cause")
	if !a.widen || a.widenReason != "alpha cause" {
		t.Fatalf("widenReason = %q, want the lexicographically least of the requested set", a.widenReason)
	}
}
