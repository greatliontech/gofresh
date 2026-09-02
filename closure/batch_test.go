package closure

import (
	"context"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph/rta"

	arta "github.com/greatliontech/gofresh/closure/internal/rta"
	"golang.org/x/tools/go/ssa"
)

const batchIsolationPackage = "github.com/greatliontech/gofresh/closure/fixtures/batchisolation"

func TestAttributedRTAEqualsIndependentRTA(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	got, err := attributedReachableSets(context.Background(), true, prog, subjects)
	if err != nil {
		t.Fatal(err)
	}
	for i, subject := range subjects {
		want := independentReachableSet(t, prog, subject.Symbol)
		assertSameReachable(t, subject.Symbol, got[i].functions, want)
	}
}

func TestAttributedRTADynamicFactsRemainIsolated(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	reachable, err := attributedReachableSets(context.Background(), true, prog, subjects)
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
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	if testing.Short() {
		t.Skip("runs the engine over the fixture corpus")
	}
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
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	reachable, err := attributedReachableSets(context.Background(), true, prog, subjects)
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
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterContext{Context: context.Background(), remaining: 2}
	_, err = attributedReachableSets(ctx, true, prog, []Subject{{Package: batchIsolationPackage, Symbol: "Materializer"}})
	if err == nil {
		t.Fatal("attributed RTA ignored cancellation during traversal")
	}
}

func TestTier2ProjectionHonorsCancellationDuringTraversal(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: batchIsolationPackage, Symbol: "Materializer"}
	reachable, err := attributedReachableSets(context.Background(), true, prog, []Subject{subject})
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
	if testing.Short() {
		t.Skip("builds whole-program SSA and proves observability")
	}
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
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	reachable, err := attributedReachableSets(context.Background(), true, prog, subjects)
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

// A type mentioning a type parameter denotes no runtime type: seeded
// into the walk (the shape that reached the field recover as
// "unsupported analysis shape: T"), it must be skipped wholesale, never
// panicked on — its concrete counterparts enter through their own
// instantiation sites (REQ-closure-analysis).
func TestAttributedRTASkipsTypeParameterShapes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	root := prog.Roots["Production"]
	if root == nil {
		t.Fatal("no Production root")
	}
	tparam := types.NewTypeParam(types.NewTypeName(0, nil, "T", nil), types.NewInterfaceType(nil, nil))
	named := types.NewNamed(types.NewTypeName(0, prog.Pkgs[0].Types, "Box", nil), types.NewStruct(nil, nil), nil)
	named.SetTypeParams([]*types.TypeParam{types.NewTypeParam(types.NewTypeName(0, nil, "U", nil), types.NewInterfaceType(nil, nil))})
	// reviewLocal is the round-1 review's H1 shape: a type declared
	// inside a generic body looks concrete (no own params, no args) and
	// mentions the enclosing parameter only through its underlying -
	// with an embedded interface whose promoted method drives the
	// exported-method walk into a nil MethodValue.
	nestedObj := prog.Pkgs[0].Types.Scope().Lookup("nested")
	if nestedObj == nil {
		t.Fatal("fixture type nested not found")
	}
	msig := types.NewSignatureType(nil, nil, nil, types.NewTuple(),
		types.NewTuple(types.NewVar(0, prog.Pkgs[0].Types, "", nestedObj.Type())), false)
	iface := types.NewInterfaceType([]*types.Func{types.NewFunc(0, prog.Pkgs[0].Types, "M", msig)}, nil)
	iface.Complete()
	ifaceNamed := types.NewNamed(types.NewTypeName(0, prog.Pkgs[0].Types, "ReviewIface", nil), iface, nil)
	localUnderlying := types.NewStruct([]*types.Var{
		types.NewField(0, prog.Pkgs[0].Types, "ReviewIface", ifaceNamed, true),
		types.NewField(0, prog.Pkgs[0].Types, "x", tparam, false),
	}, nil)
	local := types.NewNamed(types.NewTypeName(0, prog.Pkgs[0].Types, "reviewLocal", nil), localUnderlying, nil)
	for _, seed := range []types.Type{tparam, types.NewSlice(tparam), named, local} {
		result, err := arta.Analyze(context.Background(), map[*ssa.Function]uint64{root: 1}, &arta.Seeds{
			RuntimeTypes: []arta.TypeSeed{{Type: seed, Masks: 1}},
		})
		if err != nil {
			t.Fatalf("type-parameter shape %v panicked the walk: %v", seed, err)
		}
		// The skip is WHOLESALE: a param-mentioning type contributes
		// nothing - not even through its method set, whose signature
		// types would otherwise register real concrete types and make
		// their exported methods phantom-reachable (the chunk-132
		// review's refutation of the piecemeal-equivalence claim).
		for fn := range result.Reachable {
			if strings.Contains(fn.String(), "nested") {
				t.Fatalf("seed %v contributed phantom reachability: %s", seed, fn)
			}
		}
	}
}

// One unanalyzable subject degrades alone; a package-scoped
// provocation degrades every subject with the probe's own error; two
// independent subject-scoped offenders on opposite bisection halves
// isolate individually (the conflation that once darkened their 62
// sound siblings); and non-shape failures stay batch-wide
// (REQ-closure-analysis; the chunk-132 review's rounds 1-2).
func TestAttributedBisectionIsolatesUnsupportedShapes(t *testing.T) {
	savedWorker, savedProbe := analyzeAttributedBatch, probePackageScope
	defer func() { analyzeAttributedBatch, probePackageScope = savedWorker, savedProbe }()
	shapeErr := func(sym string) error {
		return fmt.Errorf("closure: attributed reachability: unsupported analysis shape: T (visiting p.%s)", sym)
	}
	sound := func(subjects []Subject) []attributedReachability {
		rows := make([]attributedReachability, len(subjects))
		for i := range rows {
			rows[i] = attributedReachability{openWorld: true}
		}
		return rows
	}
	poisonWorker := func(poisoned map[Subject]bool) func(context.Context, bool, *program, []Subject) ([]attributedReachability, error) {
		return func(ctx context.Context, audited bool, prog *program, subjects []Subject) ([]attributedReachability, error) {
			for _, s := range subjects {
				if poisoned[s] {
					return nil, shapeErr(s.Symbol)
				}
			}
			return sound(subjects), nil
		}
	}
	probePackageScope = func(ctx context.Context, prog *program, subjects []Subject) error { return nil }

	bad1 := Subject{Package: "p", Symbol: "Bad1"}
	bad2 := Subject{Package: "p", Symbol: "Bad2"}
	subjects := []Subject{
		bad1,
		{Package: "p", Symbol: "A"}, {Package: "p", Symbol: "B"},
		{Package: "p", Symbol: "C"},
		bad2,
	}

	// One offender isolates alone.
	analyzeAttributedBatch = poisonWorker(map[Subject]bool{bad1: true})
	rows, err := attributedReachableSets(context.Background(), true, nil, subjects)
	if err != nil || len(rows) != len(subjects) {
		t.Fatalf("single-offender isolation: rows=%d err=%v", len(rows), err)
	}
	for i, s := range subjects {
		if (s == bad1) != (rows[i].unavailable != "") {
			t.Fatalf("single-offender row %d (%v) misdispositioned: %+v", i, s, rows[i])
		}
	}

	// Two offenders on opposite halves isolate individually - the
	// sound siblings keep their evidence.
	analyzeAttributedBatch = poisonWorker(map[Subject]bool{bad1: true, bad2: true})
	rows, err = attributedReachableSets(context.Background(), true, nil, subjects)
	if err != nil || len(rows) != len(subjects) {
		t.Fatalf("two-offender isolation: rows=%d err=%v", len(rows), err)
	}
	for i, s := range subjects {
		offender := s == bad1 || s == bad2
		if offender != (rows[i].unavailable != "") {
			t.Fatalf("two-offender row %d (%v) misdispositioned: %+v", i, s, rows[i])
		}
		// Equality against the offender's own single-subject batch
		// error pins the real guarantee - each row carries the error
		// of the analysis whose only subject was this one. (Real
		// provenance names the VISITED function, not the subject; the
		// fake's symbol-bearing message is its own convention, and
		// the memoized reason substitutes a fixed constant anyway -
		// field attribution rides the diagnostic channel's
		// symbol-prefixed detail.)
		if offender && rows[i].unavailable != shapeErr(s.Symbol).Error() {
			t.Fatalf("offender %v carries a sibling's failure: %q", s, rows[i].unavailable)
		}
	}

	// A package-scoped provocation degrades everything at ONE worker
	// run, each row carrying the probe's own error.
	calls := 0
	analyzeAttributedBatch = func(ctx context.Context, audited bool, prog *program, subjects []Subject) ([]attributedReachability, error) {
		calls++
		return nil, shapeErr("init")
	}
	probePackageScope = func(ctx context.Context, prog *program, subjects []Subject) error {
		return fmt.Errorf("closure: attributed reachability: unsupported analysis shape: T (visiting p.init)")
	}
	rows, err = attributedReachableSets(context.Background(), true, nil, subjects)
	if err != nil {
		t.Fatalf("package-scoped failure surfaced batch-wide: %v", err)
	}
	for i := range rows {
		if !strings.Contains(rows[i].unavailable, "p.init") {
			t.Fatalf("row %d does not carry the package-scoped provenance: %+v", i, rows[i])
		}
	}
	if calls != 1 {
		t.Fatalf("package-scoped failure ran %d worker calls, want 1 (the probe decides)", calls)
	}

	// A non-shape failure keeps the batch-wide error.
	probePackageScope = func(ctx context.Context, prog *program, subjects []Subject) error { return nil }
	analyzeAttributedBatch = func(ctx context.Context, audited bool, prog *program, subjects []Subject) ([]attributedReachability, error) {
		return nil, fmt.Errorf("closure: analysis cancelled: context deadline exceeded")
	}
	if _, err := attributedReachableSets(context.Background(), true, nil, subjects); err == nil {
		t.Fatal("a non-shape failure was swallowed by the bisection")
	}
}
