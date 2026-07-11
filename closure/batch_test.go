package closure

import (
	"context"
	"fmt"
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

	dynamicTarget := prog.roots["dynamicTarget"]
	if dynamicTarget == nil || !reachable[0].functions[dynamicTarget] {
		t.Fatal("address-taking subject did not reach dynamicTarget")
	}
	if reachable[1].functions[dynamicTarget] {
		t.Fatal("dynamic-call subject inherited another subject's address-taken function")
	}

	concreteMethod := prog.roots["concrete.Run"]
	if concreteMethod == nil || !reachable[2].functions[concreteMethod] {
		t.Fatal("materializing subject did not reach concrete.Run")
	}
	if reachable[3].functions[concreteMethod] {
		t.Fatal("invoke subject inherited another subject's concrete runtime type")
	}
	nestedMethod := prog.roots["nested.Exported"]
	if nestedMethod == nil || !reachable[2].functions[nestedMethod] {
		t.Fatal("materializing subject did not reach exported method of recursive runtime type")
	}
	if reachable[3].functions[nestedMethod] {
		t.Fatal("invoke subject inherited another subject's recursive runtime type")
	}

	metas, err := h.list(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	base := newTier2Base(h, prog, metas)
	for _, check := range []struct {
		index int
		name  string
		part  string
	}{
		{index: 1, name: "DynamicCaller", part: "dynamicTarget"},
		{index: 3, name: "Invoker", part: "concreteMethodHelper"},
	} {
		tr, err := h.tier2Reachable(base, reachable[check.index])
		if err != nil {
			t.Fatalf("tier2Reachable(%s): %v", check.name, err)
		}
		if contribHasAll(tr.contribs, batchIsolationPackage, "batchisolation.go", check.part) {
			t.Fatalf("%s closure contains other subject's %s declaration: %v", check.name, check.part, tr.contribs)
		}
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
			result, err := h.tier2(batchIsolationPackage, tc.symbol)
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
	result, err := h.tier2("github.com/greatliontech/gofresh/closure/fixtures/globalcallback", "F")
	if err != nil {
		t.Fatal(err)
	}
	if !result.widen {
		t.Fatalf("initialized mutable global did not widen: %+v", result)
	}
	computed, err := h.Compute("github.com/greatliontech/gofresh/closure/fixtures/globalcallback", "F")
	if err != nil {
		t.Fatal(err)
	}
	if !computed.Widened {
		t.Fatalf("public closure lost widening disposition: %+v", computed)
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
	startup := prog.roots["startupHelper"]
	testMainHelper := prog.roots["testMainHelper"]
	if startup == nil || !reachable[0].functions[startup] || !reachable[1].functions[startup] {
		t.Fatal("initializer root did not propagate to every subject")
	}
	if testMainHelper == nil || reachable[0].functions[testMainHelper] {
		t.Fatal("production subject reached conditional TestMain setup")
	}
	if !reachable[1].functions[testMainHelper] {
		t.Fatal("test-file subject did not reach TestMain setup")
	}
	siblingHelper := prog.roots["benchmarkSiblingHelper"]
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

func TestComputeBatchEqualsIndependentCompute(t *testing.T) {
	subjects := []Subject{
		{Package: batchIsolationPackage, Symbol: "AddressTaker"},
		{Package: batchIsolationPackage, Symbol: "DynamicCaller"},
		{Package: batchIsolationPackage, Symbol: "Materializer"},
		{Package: batchIsolationPackage, Symbol: "Invoker"},
		{Package: batchIsolationPackage, Symbol: "Production"},
		{Package: batchIsolationPackage, Symbol: "BenchmarkHarness"},
		{Package: "github.com/greatliontech/gofresh/closure/fixtures/direct", Symbol: "BenchmarkDirect"},
	}
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.ComputeBatch(append(subjects, subjects[1], subjects[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(subjects) {
		t.Fatalf("ComputeBatch returned %d results for %d distinct subjects", len(got), len(subjects))
	}
	for _, subject := range subjects {
		independent, err := New()
		if err != nil {
			t.Fatal(err)
		}
		want, err := independent.Compute(subject.Package, subject.Symbol)
		if err != nil {
			t.Fatalf("independent Compute(%+v): %v", subject, err)
		}
		if got[subject] != want {
			t.Errorf("ComputeBatch(%+v) = %+v, independent Compute = %+v", subject, got[subject], want)
		}
	}

	empty, err := h.ComputeBatch(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("ComputeBatch(nil) = %v, %v; want empty map, nil", empty, err)
	}
}

func TestStandardDynamicTargetMasksRemainSubjectLocal(t *testing.T) {
	subjects := []Subject{
		{Package: batchIsolationPackage, Symbol: "TestStandardDynamic"},
		{Package: batchIsolationPackage, Symbol: "Production"},
	}
	batchedHasher, err := New()
	if err != nil {
		t.Fatal(err)
	}
	batched, err := batchedHasher.ComputeBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		independentHasher, err := New()
		if err != nil {
			t.Fatal(err)
		}
		independent, err := independentHasher.Compute(subject.Package, subject.Symbol)
		if err != nil {
			t.Fatal(err)
		}
		if batched[subject] != independent {
			t.Fatalf("batched %s = %+v, independent = %+v", subject.Symbol, batched[subject], independent)
		}
	}
	if !batched[subjects[0]].Unverifiable {
		t.Fatalf("standard dynamic target was verifiable: %+v", batched[subjects[0]])
	}
}

func BenchmarkComputeBatch(b *testing.B) {
	subjects := []Subject{
		{Package: batchIsolationPackage, Symbol: "AddressTaker"},
		{Package: batchIsolationPackage, Symbol: "DynamicCaller"},
		{Package: batchIsolationPackage, Symbol: "Materializer"},
		{Package: batchIsolationPackage, Symbol: "Invoker"},
		{Package: batchIsolationPackage, Symbol: "Production"},
		{Package: batchIsolationPackage, Symbol: "BenchmarkHarness"},
	}
	for _, tc := range []struct {
		name  string
		batch bool
	}{
		{name: "batch", batch: true},
		{name: "one-subject-calls"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			h, err := New()
			if err != nil {
				b.Fatal(err)
			}
			h.Prime([]string{batchIsolationPackage})
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if tc.batch {
					if _, err := h.ComputeBatch(subjects); err != nil {
						b.Fatal(err)
					}
					continue
				}
				for _, subject := range subjects {
					if _, err := h.Compute(subject.Package, subject.Symbol); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func independentReachableSet(t *testing.T, prog *program, symbol string) map[*ssa.Function]bool {
	t.Helper()
	root := prog.roots[symbol]
	if root == nil {
		t.Fatalf("subject root %s not found", symbol)
	}
	roots := []*ssa.Function{root}
	if prog.testMain != nil && subjectRunsThroughHarness(prog, root) {
		roots = append(roots, prog.testMain)
	}
	for _, pkg := range prog.prog.AllPackages() {
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
