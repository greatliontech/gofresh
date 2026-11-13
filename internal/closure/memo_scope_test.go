package closure

import (
	"context"
	"maps"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/gotool"
)

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
	metas, err := hWidened.list(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	base := newTier2Base(hWidened, prog, metas)
	reachWidened, err := attributedReachableSets(context.Background(), true, hWidened.source.pureDelegates, prog, widenedSubjects)
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
		res, err := hWidened.tier2Reachable(base, r)
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
		metas, err := h.list(pkgPath)
		if err != nil {
			t.Fatal(err)
		}
		base := newTier2Base(h, prog, metas)
		reach, err := attributedReachableSets(context.Background(), true, h.source.pureDelegates, prog, order)
		if err != nil {
			t.Fatal(err)
		}
		sum := lookupSummaryForProg(prog, true)
		if sum == nil {
			t.Fatal("expected non-nil callerReferenceSummary")
		}
		sum.progMemos = *newDynamicMemoQuad()
		for i, r := range reach {
			if _, err := h.tier2Reachable(base, r); err != nil {
				t.Fatal(err)
			}
			if order[i] == cancelSubj {
				fp := newFreshParamAnalysis(true, h.source.pureDelegates, r, nil)
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

func TestAnalysisScopeScanIncludesRootedStrategyUnderExecutionAttestations(t *testing.T) {
	base := AnalysisScope{
		FactStrategy:     "gofresh/dynamic-state@test",
		Toolchain:        "tc",
		BuildConfig:      "bc",
		toolchainContent: "tcc",
		admissionPolicy:  "ap",
	}
	if base.Facts() == "" {
		t.Fatal("plain Facts() is empty")
	}
	if base.Scan() == "" || strings.Contains(base.Scan(), rootedFunctionsStrategy) {
		t.Fatalf("plain Scan() = %q, want non-empty without %q", base.Scan(), rootedFunctionsStrategy)
	}
	pkgExec := base
	pkgExec.PackageProcess = true
	if pkgExec.Facts() != base.Facts() {
		t.Fatalf("PackageProcess Facts() = %q, want identical to base %q", pkgExec.Facts(), base.Facts())
	}
	if !strings.Contains(pkgExec.Scan(), "|package-process-execution|"+rootedFunctionsStrategy) {
		t.Fatalf("PackageProcess Scan() = %q, want package-process marker and %q", pkgExec.Scan(), rootedFunctionsStrategy)
	}
	singleExec := base
	singleExec.SingleSubject = true
	if singleExec.Facts() != base.Facts() {
		t.Fatalf("SingleSubject Facts() = %q, want identical to base %q", singleExec.Facts(), base.Facts())
	}
	if !strings.Contains(singleExec.Scan(), "|single-subject-execution|"+rootedFunctionsStrategy) {
		t.Fatalf("SingleSubject Scan() = %q, want single-subject marker and %q", singleExec.Scan(), rootedFunctionsStrategy)
	}
	bothExec := base
	bothExec.SingleSubject = true
	bothExec.PackageProcess = true
	if bothExec.Facts() != base.Facts() || !strings.Contains(bothExec.Scan(), "|single-subject-execution|package-process-execution|"+rootedFunctionsStrategy) {
		t.Fatalf("both attestations: Facts=%q Scan=%q, want Facts=%q and both execution markers with %q", bothExec.Facts(), bothExec.Scan(), base.Facts(), rootedFunctionsStrategy)
	}
}

func TestMutableFactKeysTracksModuleGraphAndRejectsModfileFlag(t *testing.T) {
	root := t.TempDir()
	dep1 := filepath.Join(root, "dep1")
	dep2 := filepath.Join(root, "dep2")
	app := filepath.Join(root, "app")
	writeFile(t, dep1, "go.mod", "module example.com/dep\n\ngo 1.26\n")
	writeFile(t, dep1, "dep.go", "package dep\n\nfunc V() int { return 1 }\n")
	writeFile(t, dep2, "go.mod", "module example.com/dep\n\ngo 1.26\n")
	writeFile(t, dep2, "dep.go", "package dep\n\nfunc V() int { return 2 }\n")
	writeFile(t, app, "go.mod", "module example.com/app\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\nreplace example.com/dep => ../dep1\n")
	writeFile(t, app, "app.go", "package app\n\nimport (\n\t_ \"embed\"\n\t\"example.com/dep\"\n)\n\n//go:embed assets/*\nvar _ string\n\nfunc F() int { return dep.V() }\n")
	writeFile(t, app, "excluded.go", "//go:build ignore\n\npackage app\n\nvar IgnoredHook func()\n")
	writeFile(t, filepath.Join(app, "assets"), "one.txt", "one\n")

	h, err := newAt(app)
	if err != nil {
		t.Fatal(err)
	}
	pkgPath := "example.com/app"
	meta, err := h.GraphMetadata(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	preKeys, expectedFiles := h.MutableFactKeys("facts@1", meta, false, pkgPath)
	if preKeys[pkgPath] == "" || !expectedFiles[pkgPath][filepath.Clean(filepath.Join(app, "app.go"))] {
		t.Fatalf("initial MutableFactKeys = (%v, %v), want non-empty key and app.go", preKeys, expectedFiles)
	}
	sameKeys, _ := h.MutableFactKeys("facts@1", meta, true, pkgPath)
	if sameKeys[pkgPath] != preKeys[pkgPath] {
		t.Fatalf("freshDisk MutableFactKeys on unchanged tree = %q, want %q", sameKeys[pkgPath], preKeys[pkgPath])
	}

	// Rewriting go.mod's replace target on disk without reloading metadata must
	// move the freshDisk key immediately.
	writeFile(t, app, "go.mod", "module example.com/app\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\nreplace example.com/dep => ../dep2\n")
	driftedKeys, _ := h.MutableFactKeys("facts@1", meta, true, pkgPath)
	if driftedKeys[pkgPath] == "" || driftedKeys[pkgPath] == preKeys[pkgPath] {
		t.Fatalf("freshDisk MutableFactKeys after go.mod replace edit = %q, want distinct non-empty key from %q", driftedKeys[pkgPath], preKeys[pkgPath])
	}

	// SnapshotScanInputs fails closed on zero value and -modfile, and captures
	// non-empty file digests, absent sentinels, and mutable-local directory entries.
	if (TreeDigestSnapshot{}).MatchesDisk() {
		t.Fatal("zero TreeDigestSnapshot unexpectedly matched disk")
	}
	snap := h.SnapshotScanInputs(pkgPath)
	if !snap.valid || len(snap.files) == 0 || len(snap.absent) == 0 || len(snap.pkgDirs) == 0 {
		t.Fatalf("SnapshotScanInputs = %+v, want valid non-empty files/absent/pkgDirs", snap)
	}
	if !snap.MatchesDisk() {
		t.Fatal("fresh SnapshotScanInputs did not match unchanged disk")
	}
	// Editing a tracked file invalidates MatchesDisk.
	writeFile(t, app, "app.go", "package app\n\nimport (\n\t_ \"embed\"\n\t\"example.com/dep\"\n)\n\n//go:embed assets/*\nvar _ string\n\nfunc F() int { return dep.V() + 1 }\n")
	if snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs matched after app.go content edit")
	}
	writeFile(t, app, "app.go", "package app\n\nimport (\n\t_ \"embed\"\n\t\"example.com/dep\"\n)\n\n//go:embed assets/*\nvar _ string\n\nfunc F() int { return dep.V() }\n")
	if !snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs did not match after restoring app.go")
	}
	// Editing a build-tag-excluded file in place (dropping //go:build ignore)
	// invalidates MatchesDisk via source-ext byte digests.
	writeFile(t, app, "excluded.go", "package app\n\nvar IgnoredHook func()\n")
	if snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs matched after in-place edit of build-tag-excluded excluded.go")
	}
	writeFile(t, app, "excluded.go", "//go:build ignore\n\npackage app\n\nvar IgnoredHook func()\n")
	if !snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs did not match after restoring excluded.go")
	}
	// Adding a file inside an //go:embed directory invalidates MatchesDisk via embedRoots pkgDirs.
	extraAsset := filepath.Join(app, "assets", "two.txt")
	writeFile(t, filepath.Join(app, "assets"), "two.txt", "two\n")
	if snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs matched after adding file under //go:embed directory")
	}
	if err := os.Remove(extraAsset); err != nil {
		t.Fatal(err)
	}
	if !snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs did not match after removing extra embedded file")
	}
	// Adding an untracked *_test.go file in app invalidates MatchesDisk via pkgDirs.
	testPath := filepath.Join(app, "app_test.go")
	writeFile(t, app, "app_test.go", "package app\n")
	if snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs matched after adding app_test.go")
	}
	if err := os.Remove(testPath); err != nil {
		t.Fatal(err)
	}
	// Materializing a previously-absent go.sum invalidates MatchesDisk via absent sentinels.
	goSumPath := filepath.Join(app, "go.sum")
	writeFile(t, app, "go.sum", "")
	if snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs matched after previously-absent go.sum appeared")
	}
	if err := os.Remove(goSumPath); err != nil {
		t.Fatal(err)
	}
	if !snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs did not match after removing go.sum")
	}

	// Passing -modfile disables MutableFactKeys and SnapshotScanInputs so callers fail closed.
	hModfile, err := newAt(app, "-modfile="+filepath.Join(app, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	modfileKeys, modfileFiles := hModfile.MutableFactKeys("facts@1", meta, false, pkgPath)
	if len(modfileKeys) != 0 || len(modfileFiles) != 0 {
		t.Fatalf("MutableFactKeys with -modfile = (%v, %v), want empty", modfileKeys, modfileFiles)
	}
	if hModfile.SnapshotScanInputs(pkgPath).MatchesDisk() {
		t.Fatal("SnapshotScanInputs with -modfile unexpectedly matched disk")
	}

	// Hasher constructed with reader.Dir == "" (current working directory) in a
	// subdirectory of a module inside a go.work workspace must still track both
	// go.work replace edits and intermediate go.mod sentinels.
	sub := filepath.Join(app, "sub")
	writeFile(t, sub, "sub.go", "package sub\n\nimport \"example.com/dep\"\n\nfunc S() int { return dep.V() }\n")
	writeFile(t, root, "go.work", "go 1.26\n\nuse ./app\nreplace example.com/dep => ./dep1\n")
	t.Setenv("GOWORK", "")
	t.Chdir(sub)
	cwdHasher, err := NewAt(context.Background(), &gotool.EnvReader{Dir: "", Env: os.Environ()})
	if err != nil {
		t.Fatal(err)
	}
	subPkg := "example.com/app/sub"
	subMeta, err := cwdHasher.GraphMetadata(subPkg)
	if err != nil {
		t.Fatal(err)
	}
	cwdKeys0, _ := cwdHasher.MutableFactKeys("facts@1", subMeta, false, subPkg)
	if cwdKeys0[subPkg] == "" {
		t.Fatalf("Dir==\"\" MutableFactKeys = %v, want non-empty key", cwdKeys0)
	}
	writeFile(t, root, "go.work", "go 1.26\n\nuse ./app\nreplace example.com/dep => ./dep2\n")
	cwdKeysWorkEdited, _ := cwdHasher.MutableFactKeys("facts@1", subMeta, true, subPkg)
	if cwdKeysWorkEdited[subPkg] == "" || cwdKeysWorkEdited[subPkg] == cwdKeys0[subPkg] {
		t.Fatalf("Dir==\"\" MutableFactKeys after go.work replace edit = %q, want distinct from %q", cwdKeysWorkEdited[subPkg], cwdKeys0[subPkg])
	}
	writeFile(t, root, "go.work", "go 1.26\n\nuse ./app\nreplace example.com/dep => ./dep1\n")
	writeFile(t, sub, "go.mod", "module example.com/app/sub\n\ngo 1.26\n")
	cwdKeysNestedMod, _ := cwdHasher.MutableFactKeys("facts@1", subMeta, true, subPkg)
	if cwdKeysNestedMod[subPkg] == "" || cwdKeysNestedMod[subPkg] == cwdKeys0[subPkg] {
		t.Fatalf("Dir==\"\" MutableFactKeys after nested sub/go.mod appeared = %q, want distinct from %q", cwdKeysNestedMod[subPkg], cwdKeys0[subPkg])
	}
}

func TestIsPinnedPackageDirAndPrepareProgramRTASharedProvenance(t *testing.T) {
	if IsPinnedPackageDir(true, "/cache/mod/dep@v1.0.0", "/cache/mod") {
		t.Fatal("main module inside modCache classified as pinned")
	}
	if IsPinnedPackageDir(false, "", "/cache/mod") || IsPinnedPackageDir(false, "/cache/mod/dep@v1.0.0", "") {
		t.Fatal("empty pkgDir or modCache classified as pinned")
	}
	if IsPinnedPackageDir(false, "/cache/mod2/dep@v1.0.0", "/cache/mod") {
		t.Fatal("sibling prefix /cache/mod2 classified as under /cache/mod")
	}
	if !IsPinnedPackageDir(false, "/cache/mod/dep@v1.0.0/sub", "/cache/mod") {
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
	reach, err := attributedReachableSets(context.Background(), true, h.source.pureDelegates, prog, []Subject{idSubj})
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
	if _, err := attributedReachableSets(context.Background(), true, h.source.pureDelegates, prog, []Subject{{Package: pkgPath, Symbol: "Entry"}}); err != nil {
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
	bitFP := newBitOnlyFreshParamAnalysis(true, true, h.source.pureDelegates, map[string]bool{pkgPath: true}, sum, nil)
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
