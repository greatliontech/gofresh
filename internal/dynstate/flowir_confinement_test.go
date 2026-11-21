package dynstate

import (
	"slices"
	"testing"

	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func TestFlowIRNewExprVsNewTypeAndTypeSwitchImplicitConfinement(t *testing.T) {
	pkg := mustTypecheckPackage(t, "example.com/surface", map[string]string{
		"surface.go": `package surface

func LeakViaNewExpr(s []int) *[]int {
	return new(s)
}

func SafeViaNewType(s []int) *[]int {
	_ = len(s)
	return new([]int)
}

func MutateViaTypeSwitchImplicit(x any) int {
	switch v := x.(type) {
	case []int:
		v[0] = 99
		return len(v)
	case int:
		return v
	default:
		return 0
	}
}

func ReadOnlyViaTypeSwitchImplicit(x any) int {
	switch v := x.(type) {
	case []int:
		return len(v)
	case string:
		return len(v)
	default:
		return 0
	}
}

func ReturnClosureViaNewExpr(in func() int) *func() int {
	return new(in)
}

func ReturnNilFuncPtrViaNewType() *func() int {
	return new(func() int)
}

var globalDirty func() int

func SmuggleViaNewExprLocal() []func() int {
	fns := make([]func() int, 1)
	p := new(fns)
	(*p)[0] = globalDirty
	return fns
}
`,
	})
	fact := FactOf(true, pkg)

	leakNew := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/surface", Name: "LeakViaNewExpr"}, Index: 0}
	safeNew := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/surface", Name: "SafeViaNewType"}, Index: 0}
	if slices.Contains(fact.ParamLeakFree, leakNew) {
		t.Fatalf("ParamLeakFree admitted Go 1.26+ new(expr) escape: %+v", fact.ParamLeakFree)
	}
	if !slices.Contains(fact.ParamLeakFree, safeNew) {
		t.Fatalf("ParamLeakFree rejected zero-allocating new(T): %+v", fact.ParamLeakFree)
	}

	mutSwitch := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/surface", Name: "MutateViaTypeSwitchImplicit"}, Index: 0}
	roSwitch := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/surface", Name: "ReadOnlyViaTypeSwitchImplicit"}, Index: 0}
	if slices.Contains(fact.ParamLeakFree, mutSwitch) {
		t.Fatalf("ParamLeakFree admitted mutation through TypeSwitchStmt implicit case var: %+v", fact.ParamLeakFree)
	}
	if !slices.Contains(fact.ParamLeakFree, roSwitch) {
		t.Fatalf("ParamLeakFree rejected read-only TypeSwitchStmt implicit case var: %+v", fact.ParamLeakFree)
	}

	if !slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/surface", Name: "ReturnClosureViaNewExpr"}) {
		t.Fatalf("ReturnEnvFree rejected caller-judged parameter passed to new(in): %+v", fact.ReturnEnvFree)
	}
	if !slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/surface", Name: "ReturnNilFuncPtrViaNewType"}) {
		t.Fatalf("ReturnEnvFree rejected new(func() int): %+v", fact.ReturnEnvFree)
	}
	if slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/surface", Name: "SmuggleViaNewExprLocal"}) {
		t.Fatalf("ReturnEnvFree admitted backing-slice smuggle through new(fns): %+v", fact.ReturnEnvFree)
	}
}

func TestFlowIRAddressedBaseChainsAndAutoAddrMethodValues(t *testing.T) {
	pkg := mustTypecheckPackage(t, "example.com/addrchain", map[string]string{
		"addr.go": `package addrchain

type sub struct {
	n int
}

func (s *sub) Mut() { s.n++ }

type Holder struct {
	subPtr *sub
	arrPtr *[4]int
	subVal sub
}

func (h *Holder) EscapeDerefScalarAddr() *int {
	return &((*h.subPtr).n)
}

func (h *Holder) EscapeDerefArraySlice() []int {
	return (*h.arrPtr)[:]
}

func (h *Holder) EscapeAutoAddrMethodVal() func() {
	return h.subVal.Mut
}

func (h *Holder) SafeScalarReads() int {
	return (*h.subPtr).n + (*h.arrPtr)[0] + h.subVal.n
}
`,
	})
	fact := FactOf(true, pkg)
	for _, bad := range []string{
		"Holder.EscapeDerefScalarAddr",
		"Holder.EscapeDerefArraySlice",
		"Holder.EscapeAutoAddrMethodVal",
	} {
		fk := syntaxutil.FuncKey{Pkg: "example.com/addrchain", Name: bad}
		if slices.Contains(fact.ReceiverReadOnly, fk) {
			t.Fatalf("ReceiverReadOnly admitted %s: %+v", bad, fact.ReceiverReadOnly)
		}
	}
	want := syntaxutil.FuncKey{Pkg: "example.com/addrchain", Name: "Holder.SafeScalarReads"}
	if !slices.Contains(fact.ReceiverReadOnly, want) {
		t.Fatalf("ReceiverReadOnly rejected Holder.SafeScalarReads: %+v", fact.ReceiverReadOnly)
	}
}

func TestFlowIRSyncNoCopyByValueAndNarrowedSynchronization(t *testing.T) {
	pkg := mustTypecheckPackage(t, "example.com/syncnocopy", map[string]string{
		"sync.go": `package syncnocopy

import "sync"

type innerOnce struct {
	once sync.Once
}

type Guarded struct {
	mu   sync.Mutex
	cond sync.Cond
	emb  *innerOnce
	val  int
}

func (g *Guarded) SafeLockAndSignal() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cond.Signal()
	g.cond.Broadcast()
	return g.val
}

func (g *Guarded) CopyReceiverByValue() int {
	cp := *g
	return cp.val
}

func (g *Guarded) CondWaitDispatchesLocker() int {
	g.cond.Wait()
	return g.val
}

func (g *Guarded) UnqualifiedOnceDo() int {
	g.emb.once.Do(func() {})
	return g.val
}
`,
	})
	fact := FactOf(true, pkg)
	safe := syntaxutil.FuncKey{Pkg: "example.com/syncnocopy", Name: "Guarded.SafeLockAndSignal"}
	if !slices.Contains(fact.ReceiverReadOnly, safe) {
		t.Fatalf("ReceiverReadOnly rejected Guarded.SafeLockAndSignal: %+v", fact.ReceiverReadOnly)
	}
	for _, bad := range []string{
		"Guarded.CopyReceiverByValue",
		"Guarded.CondWaitDispatchesLocker",
		"Guarded.UnqualifiedOnceDo",
	} {
		fk := syntaxutil.FuncKey{Pkg: "example.com/syncnocopy", Name: bad}
		if slices.Contains(fact.ReceiverReadOnly, fk) {
			t.Fatalf("ReceiverReadOnly admitted %s: %+v", bad, fact.ReceiverReadOnly)
		}
	}
}

func TestFlowIRMapKeyCarriersCoArgDisjointnessAndTarjanCycleGate(t *testing.T) {
	pkg := mustTypecheckPackage(t, "example.com/envhard", map[string]string{
		"env.go": `package envhard

type fnKey struct {
	fn *func() int
}

var MapKeyReg = map[fnKey]int{}
var PtrSliceReg []*entry

type entry struct {
	fn func() int
}

var counter int

func init() {
	localCounter := 0
	fn := func() int { localCounter++; return localCounter }
	MapKeyReg[fnKey{fn: &fn}]++
	PtrSliceReg = []*entry{{fn: func() int { localCounter++; return localCounter }}}
}

func fillClean(dst *[]func() int) {
	*dst = append(*dst, func() int { return 1 })
}

func pairClean(a, b map[int]func() int) {
	a[1] = func() int { return 1 }
	b[2] = func() int { return 2 }
}

func CoArgSharedRefuses() map[int]func() int {
	m := map[int]func() int{}
	pairClean(m, m)
	return m
}

func CoArgDisjointAdmits() []func() int {
	a := map[int]func() int{}
	b := map[int]func() int{}
	pairClean(a, b)
	return []func() int{a[1], b[2]}
}

func MutualCycleWithBrokenArm(flag bool) func() int {
	localCounter := 0
	var a, b func() int
	a = b
	if flag {
		b = func() int { localCounter++; return localCounter }
	} else {
		b = a
	}
	return a
}
`,
	})
	fact := FactOf(true, pkg)

	if !slices.Contains(fact.EnvCarrying, "example.com/envhard.MapKeyReg") {
		t.Fatalf("EnvCarrying missed signature-carrying map key store on IncDecStmt: %+v", fact.EnvCarrying)
	}
	if !slices.Contains(fact.EnvCarrying, "example.com/envhard.PtrSliceReg") {
		t.Fatalf("EnvCarrying missed elided-& struct literal element: %+v", fact.EnvCarrying)
	}
	if slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/envhard", Name: "CoArgSharedRefuses"}) {
		t.Fatalf("ReturnEnvFree admitted aliased co-arguments pairClean(&s, &s): %+v", fact.ReturnEnvFree)
	}
	if !slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/envhard", Name: "CoArgDisjointAdmits"}) {
		t.Fatalf("ReturnEnvFree rejected disjoint co-arguments: %+v", fact.ReturnEnvFree)
	}
	if slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/envhard", Name: "MutualCycleWithBrokenArm"}) {
		t.Fatalf("ReturnEnvFree admitted mutual local cycle with environment-carrying branch: %+v", fact.ReturnEnvFree)
	}
}

func TestSettledPackageDataGlobalsCarrierEmbeddingIsolation(t *testing.T) {
	// 1. defaultCols embedded into DirtyRegistry (mutated at runtime) must NOT
	// discharge DirtyRegistry or sibling CleanHooks.
	dirtyPkg := mustTypecheckPackage(t, "example.com/settleddirty", map[string]string{
		"dirty.go": `package settleddirty

type entry struct {
	match func() string
	cols  []string
}

var sharedCols = []string{"a", "b"}

func makeMatch(cols []string) func() string {
	return func() string { return cols[0] }
}

var DirtyRegistry = []entry{{match: makeMatch(sharedCols), cols: sharedCols}}
var SiblingHooks = []func() string{makeMatch(sharedCols)}

func MutateDirty() {
	DirtyRegistry[0].cols[0] = "mutated"
}
`,
	})
	dirtyFact := FactOf(true, dirtyPkg)
	if !slices.Contains(dirtyFact.EnvCarrying, "example.com/settleddirty.DirtyRegistry") {
		t.Fatalf("DirtyRegistry discharged despite runtime mutation of embedded sharedCols: %+v", dirtyFact.EnvCarrying)
	}
	if !slices.Contains(dirtyFact.EnvCarrying, "example.com/settleddirty.SiblingHooks") {
		t.Fatalf("SiblingHooks discharged despite sharedCols being embedded in mutated DirtyRegistry: %+v", dirtyFact.EnvCarrying)
	}

	// 2. cleanCols embedded ONLY in unbroken unexported cleanRegistry discharges
	// cleanRegistry, while refusing cross-carrier SiblingHooks and refusing
	// exported ExportedRegistry (whose embedded slice elements importers could mutate).
	isoPkg := mustTypecheckPackage(t, "example.com/settlediso", map[string]string{
		"iso.go": `package settlediso

import "slices"

type entry struct {
	match func() string
	cols  []string
}

type nestedEntry struct {
	match func() string
	grid  [][]string
}

var cleanCols = []string{"a", "b"}
var expSliceCols = []string{"x", "y"}
var expByValueCols = []string{"v1", "v2"}
var sharedExpCols = []string{"s1", "s2"}
var funcExpCols = []string{"f1", "f2"}
var baseCols = []string{"p", "q"}
var derivedCols = baseCols
var grid2D = [][]string{{"m"}}

func makeMatch(cols []string) func() string {
	return func() string { return cols[0] }
}

func makeGridMatch(g [][]string) func() string {
	return func() string { return g[0][0] }
}

var cleanRegistry = []entry{{match: makeMatch(cleanCols), cols: cleanCols}}
var SiblingHooks = []func() string{makeMatch(cleanCols)}
var SingleExportedRegistry = []entry{{match: makeMatch(expSliceCols), cols: expSliceCols}}
var ExportedByValueEntry = entry{match: makeMatch(expByValueCols), cols: expByValueCols}
var SharedExportedRegistry = []entry{{match: makeMatch(sharedExpCols), cols: sharedExpCols}}
var SharedExportedSibling = []func() string{makeMatch(sharedExpCols)}
var FuncSharedExportedRegistry = []entry{{match: makeMatch(funcExpCols), cols: funcExpCols}}

func ReadFuncExpCols() string {
	return funcExpCols[0]
}

var transitiveRegistry = []entry{{match: makeMatch(derivedCols), cols: derivedCols}}
var TransitiveSibling = []func() string{makeMatch(baseCols)}

var shallowCloneRegistry = []nestedEntry{{match: makeGridMatch(grid2D), grid: slices.Clone(grid2D)}}
var ShallowCloneSibling = []func() string{makeGridMatch(grid2D)}

type mutBox struct{ data []string }

func (b *mutBox) PoisonInPlace() { b.data[0] = "bad" }

func makeBoxMatch(b *mutBox) func() string {
	return func() string { return b.data[0] }
}

var mutBoxGlobal = &mutBox{data: []string{"init"}}
var MutMethodHooks = []func() string{makeBoxMatch(mutBoxGlobal)}

func TriggerMutBox() {
	mutBoxGlobal.PoisonInPlace()
}

func ReadClean() string {
	for _, e := range cleanRegistry {
		return e.match()
	}
	for _, e := range transitiveRegistry {
		return e.match()
	}
	for _, e := range shallowCloneRegistry {
		return e.match()
	}
	return ""
}
`,
	})
	isoFact := FactOf(true, isoPkg)
	if slices.Contains(isoFact.EnvCarrying, "example.com/settlediso.cleanRegistry") {
		t.Fatalf("cleanRegistry refused despite single unbroken unexported carrier embedding: %+v", isoFact.EnvCarrying)
	}
	if !slices.Contains(isoFact.EnvCarrying, "example.com/settlediso.SiblingHooks") {
		t.Fatalf("SiblingHooks admitted cross-carrier embedded global cleanCols: %+v", isoFact.EnvCarrying)
	}
	if slices.Contains(isoFact.EnvCarrying, "example.com/settlediso.SingleExportedRegistry") {
		t.Fatalf("SingleExportedRegistry refused isolated alias-tracked exported carrier embedding: %+v", isoFact.EnvCarrying)
	}
	if !slices.Contains(isoFact.EnvCarrying, "example.com/settlediso.ExportedByValueEntry") {
		t.Fatalf("ExportedByValueEntry admitted by-value exported carrier embedding without dynamic alias tracking: %+v", isoFact.EnvCarrying)
	}
	if !slices.Contains(isoFact.EnvCarrying, "example.com/settlediso.SharedExportedRegistry") ||
		!slices.Contains(isoFact.EnvCarrying, "example.com/settlediso.SharedExportedSibling") {
		t.Fatalf("SharedExportedRegistry/Sibling admitted exported raw embedding alongside sibling reader: %+v", isoFact.EnvCarrying)
	}
	if !slices.Contains(isoFact.EnvCarrying, "example.com/settlediso.FuncSharedExportedRegistry") {
		t.Fatalf("FuncSharedExportedRegistry admitted exported raw embedding alongside function reader: %+v", isoFact.EnvCarrying)
	}
	if slices.Contains(isoFact.EnvCarrying, "example.com/settlediso.transitiveRegistry") {
		t.Fatalf("transitiveRegistry refused single-carrier transitive embedding: %+v", isoFact.EnvCarrying)
	}
	if !slices.Contains(isoFact.EnvCarrying, "example.com/settlediso.TransitiveSibling") {
		t.Fatalf("TransitiveSibling admitted baseCols whose derived global embedded into transitiveRegistry: %+v", isoFact.EnvCarrying)
	}
	if slices.Contains(isoFact.EnvCarrying, "example.com/settlediso.shallowCloneRegistry") {
		t.Fatalf("shallowCloneRegistry refused single-carrier shallow 2D clone embedding: %+v", isoFact.EnvCarrying)
	}
	if !slices.Contains(isoFact.EnvCarrying, "example.com/settlediso.ShallowCloneSibling") {
		t.Fatalf("ShallowCloneSibling admitted shallow-cloned 2D slice across sibling carriers: %+v", isoFact.EnvCarrying)
	}
	if !slices.Contains(isoFact.EnvCarrying, "example.com/settlediso.MutMethodHooks") {
		t.Fatalf("MutMethodHooks admitted global mutated through retention-only receiver method: %+v", isoFact.EnvCarrying)
	}
}

func TestFlowIRCarrierLinksObjectClosedOpaqueVarsAndMemoEviction(t *testing.T) {
	pkg := mustTypecheckPackage(t, "example.com/linksopaque", map[string]string{
		"lo.go": `package linksopaque

import (
	"errors"
	"sync"
)

type sliceAlias []func()

var (
	ClosedErr    = errors.New("sentinel")
	ReExported   = ClosedErr
	BaseSlice    = []func(){func() {}}
	ConvSlice    sliceAlias
	MethodOpaq   error
	memoMap      sync.Map
	cleanMemoMap sync.Map
)

type box struct{}

func (b *box) assignOpaque() {
	MethodOpaq = errors.New("ok")
	fn := func() {
		MethodOpaq = &customMutErr{msg: "bad"}
	}
	fn()
}

type customMutErr struct{ msg string }

func (e *customMutErr) Error() string { return e.msg }

func init() {
	ConvSlice = sliceAlias(BaseSlice)
}

var leakedSink any

func useMemoAddr() string {
	memoMap.Store("k", "v")
	v, _ := memoMap.Load("k")
	leakedSink = &memoMap
	cleanMemoMap.Store("k", "v")
	cv, _ := cleanMemoMap.Load("k")
	if s, ok := cv.(string); ok {
		return s
	}
	s, _ := v.(string)
	return s
}

func TouchMutateConv() string {
	ConvSlice[0] = nil
	if BaseSlice[0] != nil {
		BaseSlice[0]()
	}
	return useMemoAddr()
}
`,
	})
	fact := FactOf(true, pkg)

	// Conversion `ConvSlice = sliceAlias(BaseSlice)` records a CarrierLink.
	wantLink := syntaxutil.CarrierLink{From: "example.com/linksopaque.ConvSlice", To: "example.com/linksopaque.BaseSlice"}
	if !slices.Contains(fact.CarrierLinks, wantLink) {
		t.Fatalf("CarrierLinks missing conversion link %+v: got %+v", wantLink, fact.CarrierLinks)
	}
	// Nested closure inside method assigning non-closed `&customMutErr` breaks MethodOpaq out of Opaque.
	if slices.Contains(fact.Opaque, "example.com/linksopaque.MethodOpaq") || !slices.Contains(fact.OpacityBreaks, "example.com/linksopaque.MethodOpaq") {
		t.Fatalf("Opaque/OpacityBreaks missed non-closed write in method closure: Opaque=%+v OpacityBreaks=%+v", fact.Opaque, fact.OpacityBreaks)
	}
	// `&memoMap` evicts memoMap from data-memo discharge (keeping Mutation/Method AttributedUses), while cleanMemoMap discharges.
	hasMemoMutate := slices.ContainsFunc(fact.AttributedUses, func(u syntaxutil.AttributedUse) bool {
		return u.Key == "example.com/linksopaque.memoMap" && !u.Escape && !u.HasMethod
	})
	hasMemoMethod := slices.ContainsFunc(fact.AttributedUses, func(u syntaxutil.AttributedUse) bool {
		return u.Key == "example.com/linksopaque.memoMap" && u.HasMethod
	})
	hasCleanUse := slices.ContainsFunc(fact.AttributedUses, func(u syntaxutil.AttributedUse) bool {
		return u.Key == "example.com/linksopaque.cleanMemoMap"
	})
	if !hasMemoMutate || !hasMemoMethod {
		t.Fatalf("memoMap escaped `&memoMap` eviction: AttributedUses=%+v", fact.AttributedUses)
	}
	if hasCleanUse {
		t.Fatalf("cleanMemoMap failed pure data-memo discharge: AttributedUses=%+v", fact.AttributedUses)
	}
	// Object-closed ClosedErr and ReExported remain Opaque and do not downgrade at Compose.
	if !slices.Contains(fact.Opaque, "example.com/linksopaque.ClosedErr") || !slices.Contains(fact.Opaque, "example.com/linksopaque.ReExported") {
		t.Fatalf("Opaque omitted ClosedErr or ReExported: %+v", fact.Opaque)
	}
	meta := []GraphPackage{{ImportPath: "example.com/linksopaque", PkgPath: "example.com/linksopaque", Class: MutableLocalPackage}}
	cone := Compose(meta, map[string][]Fact{"example.com/linksopaque": {fact}}, "example.com/linksopaque", nil, false, false)
	for _, rc := range cone.RootCulprits {
		if rc.Key == "example.com/linksopaque.ClosedErr" || rc.Key == "example.com/linksopaque.ReExported" {
			t.Fatalf("object-closed error global downgraded at Compose: %+v", rc)
		}
	}
}

func TestFlowIRReturnAndRegistrationOriginAndDependencyGates(t *testing.T) {
	pkg := mustTypecheckPackage(t, "example.com/origingates", map[string]string{
		"gates.go": `package origingates

import (
	"errors"
	"fmt"
)

var (
	SentinelErr          = errors.New("sentinel")
	DirtyCarrier         = func() func() int { c := 0; return func() int { c++; return c } }()
	DirtyCtorCarrier     = dirtyMaker()
	DirtyMapCarrier      = map[string]func() int{"k": dirtyMaker()}
	CleanCarrier         = func() int { return 7 }
	CleanMapCarrier      = map[string]func() int{}
	LaunderedHook        func() int
	LaunderedCtorHook    func() int
	LaunderedMapCallHook func() int
	SpreadVariadicHook   func() int
	CleanParamHook       func() int
	CleanVariadicHook    func() int
	CleanAliasLenHook    func() int
	ParamHook            func() int
	RangeFuncHook        func() int
	GlobalSnapPtr        = &snap{}
	IndirectBareSlice    = []func() int{func() int { return 0 }}
	MutableGlobal        = []int{1}
)

func getMutableBuf() []int {
	return MutableGlobal
}

func makeBufClosure(buf []int) func() int {
	return func() int { return buf[0] }
}

func SmuggleCallArgDirect() func() int {
	return makeBufClosure(getMutableBuf())
}

func SmuggleCallArgViaLocal() func() int {
	b := getMutableBuf()
	return makeBufClosure(b)
}

func SmuggleClosureRootFromCall() func() int {
	b := getMutableBuf()
	return func() int { return b[0] }
}

func SetupParamHook(fn func() int) {
	ParamHook = func() int { return fn() }
}

func dirtyIter(yield func(func() int) bool) {
	c := 0
	yield(func() int { c++; return c })
}

func setupClean(fn func() int) {
	CleanParamHook = func() int { return fn() }
}

func registerClean(fns ...func() int) {
	CleanVariadicHook = func() int { return fns[0]() }
}

func registerSpread(fns ...func() int) {
	SpreadVariadicHook = func() int { return fns[0]() }
}

func init() {
	localFn := DirtyCarrier
	LaunderedHook = func() int { return localFn() }

	localCtorFn := DirtyCtorCarrier
	LaunderedCtorHook = func() int { return localCtorFn() }

	dm := DirtyMapCarrier
	LaunderedMapCallHook = func() int { return dm["k"]() }

	cm := CleanMapCarrier
	CleanAliasLenHook = func() int { return len(cm) }

	setupClean(CleanCarrier)
	registerClean(CleanCarrier)
	registerSpread(IndirectBareSlice...)

	for f := range dirtyIter {
		RangeFuncHook = func() int { return f() }
	}
}

func dirtyMaker() func() int {
	c := 0
	return func() int { c++; return c }
}

func cleanMaker() func() int {
	return func() int { return 42 }
}

func SharedLocalAcrossParamsAndReturn(p1, p2 []func() int) func() int {
	shared := dirtyMaker()
	p1[0] = shared
	p2[0] = shared
	return shared
}

func SharedCleanAcrossParamsAndReturn(p1, p2 []func() int) func() int {
	shared := cleanMaker()
	p1[0] = shared
	p2[0] = shared
	return shared
}

type snap struct {
	hook func() int
	err  error
}

func NonAliasingErrorSentinelCheck(in error) error {
	if errors.Is(in, SentinelErr) {
		return in
	}
	c := 0
	items := []snap{{err: fmt.Errorf("%w: %v", SentinelErr, in)}}
	items[0].hook = func() int { c++; return c }
	return items[0].err
}

func MutateInteriorPtrViaFreshSliceAndRange() {
	c := 0
	ptrs := []*snap{GlobalSnapPtr}
	for _, ptr := range ptrs {
		ptr.hook = func() int { c++; return c }
	}
}

func MutateIndirectBareSlice() {
	c := 0
	var localSlice []func() int
	p := &localSlice
	*p = IndirectBareSlice
	localSlice[0] = func() int { c++; return c }
}
`,
	})
	fact := FactOf(true, pkg)

	for _, badFn := range []string{
		"SmuggleCallArgDirect",
		"SmuggleCallArgViaLocal",
		"SmuggleClosureRootFromCall",
	} {
		fk := syntaxutil.FuncKey{Pkg: "example.com/origingates", Name: badFn}
		if slices.Contains(fact.ReturnEnvFree, fk) {
			t.Fatalf("ReturnEnvFree admitted %s: %+v", badFn, fact.ReturnEnvFree)
		}
	}

	for _, badVar := range []string{
		"example.com/origingates.LaunderedHook",
		"example.com/origingates.LaunderedMapCallHook",
		"example.com/origingates.SpreadVariadicHook",
		"example.com/origingates.ParamHook",
		"example.com/origingates.RangeFuncHook",
		"example.com/origingates.GlobalSnapPtr",
		"example.com/origingates.IndirectBareSlice",
	} {
		if !slices.Contains(fact.EnvCarrying, badVar) {
			t.Fatalf("EnvCarrying missed %s: %+v", badVar, fact.EnvCarrying)
		}
	}

	for _, cleanVar := range []string{
		"example.com/origingates.SentinelErr",
		"example.com/origingates.CleanParamHook",
		"example.com/origingates.CleanVariadicHook",
		"example.com/origingates.CleanAliasLenHook",
	} {
		if slices.Contains(fact.EnvCarrying, cleanVar) {
			t.Fatalf("%s falsely marked EnvCarrying: %+v", cleanVar, fact.EnvCarrying)
		}
	}

	// LaunderedCtorHook defers to dirtyMaker via EnvCallUses and fails at Compose.
	if !slices.Contains(fact.EnvCallUses, syntaxutil.EnvCallUse{
		Key:    "example.com/origingates.LaunderedCtorHook",
		Callee: syntaxutil.FuncKey{Pkg: "example.com/origingates", Name: "dirtyMaker"},
	}) {
		t.Fatalf("EnvCallUses missed LaunderedCtorHook -> dirtyMaker: %+v", fact.EnvCallUses)
	}
	meta := []GraphPackage{{ImportPath: "example.com/origingates", PkgPath: "example.com/origingates", Class: MutableLocalPackage}}
	cone := Compose(meta, map[string][]Fact{"example.com/origingates": {fact}}, "example.com/origingates", nil, false, false)
	foundLaunderedCtor := false
	for _, rc := range cone.RootCulprits {
		if rc.Key == "example.com/origingates.LaunderedCtorHook" && rc.Verb == CulpritEnvCarrying {
			foundLaunderedCtor = true
		}
	}
	if !foundLaunderedCtor {
		t.Fatalf("Compose failed to downgrade LaunderedCtorHook as CulpritEnvCarrying: %+v", cone.RootCulprits)
	}

	// SharedLocalAcrossParamsAndReturn must prove conditionally on Fact, record
	// dirtyMaker dependency on ParamInsertionDeps(p1), ParamInsertionDeps(p2), and
	// ReturnEnvDeps, and fail ResolveEnvAudit while SharedCleanAcrossParamsAndReturn
	// resolves true on return and both slice parameters.
	sharedFK := syntaxutil.FuncKey{Pkg: "example.com/origingates", Name: "SharedLocalAcrossParamsAndReturn"}
	cleanFK := syntaxutil.FuncKey{Pkg: "example.com/origingates", Name: "SharedCleanAcrossParamsAndReturn"}
	dirtyMakerFK := syntaxutil.FuncKey{Pkg: "example.com/origingates", Name: "dirtyMaker"}
	dirtyMakerTarget := syntaxutil.FuncAuditTarget(dirtyMakerFK)
	if !slices.Contains(fact.ReturnEnvFree, sharedFK) {
		t.Fatalf("Fact.ReturnEnvFree omitted conditional SharedLocalAcrossParamsAndReturn: %+v", fact.ReturnEnvFree)
	}
	if !slices.Contains(fact.ReturnEnvDeps, syntaxutil.FuncDepEdge{Func: sharedFK, Callee: dirtyMakerFK}) {
		t.Fatalf("Fact.ReturnEnvDeps missed dirtyMaker edge on SharedLocalAcrossParamsAndReturn: %+v", fact.ReturnEnvDeps)
	}
	for _, pIdx := range []int{0, 1} {
		pk := syntaxutil.ParamKey{Func: sharedFK, Index: pIdx}
		if !slices.Contains(fact.ParamInsertionFree, pk) {
			t.Fatalf("Fact.ParamInsertionFree omitted conditional param %d: %+v", pIdx, fact.ParamInsertionFree)
		}
		if !slices.Contains(fact.ParamInsertionDeps, syntaxutil.ParamInsertionDepEdge{Param: pk, Dep: dirtyMakerTarget}) {
			t.Fatalf("Fact.ParamInsertionDeps missed dirtyMaker edge on param %d: %+v", pIdx, fact.ParamInsertionDeps)
		}
	}
	envSum := ResolveEnvAudit(map[string][]Fact{"example.com/origingates": {fact}}, nil)
	if envSum.Resolved[sharedFK] {
		t.Fatalf("ResolveEnvAudit admitted SharedLocalAcrossParamsAndReturn despite dirtyMaker dependency")
	}
	if !envSum.Resolved[cleanFK] {
		t.Fatalf("ResolveEnvAudit refused SharedCleanAcrossParamsAndReturn")
	}
	for _, pIdx := range []int{0, 1} {
		pk := syntaxutil.ParamKey{Func: sharedFK, Index: pIdx}
		if envSum.InsResolved[pk] {
			t.Fatalf("ResolveEnvAudit admitted ParamInsertionFree on param %d despite dirtyMaker dependency", pIdx)
		}
		cleanPK := syntaxutil.ParamKey{Func: cleanFK, Index: pIdx}
		if !envSum.InsResolved[cleanPK] {
			t.Fatalf("ResolveEnvAudit refused ParamInsertionFree on clean param %d", pIdx)
		}
	}
}
