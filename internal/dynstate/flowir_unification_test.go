package dynstate

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"pgregory.net/rapid"
)

func TestPkgFlowCacheZeroMissAndDeclarationCountInvariant(t *testing.T) {
	pkg := mustTypecheckPackage(t, "example.com/flowcache", map[string]string{
		"a.go": `package flowcache

import (
	"errors"
	"sync"
)

const (
	cMask0 = 1 << iota
	cMask1
	cPairA, cPairB = 10, 20
)

func makeInitPair() (int, []func()) {
	return 1, []func(){func() {}}
}

var (
	CarrierSlice      = []func(){func() {}}
	ZeroGlobal        []func()
	TupScalar, TupArr = makeInitPair()
	SentinelErr       = errors.New("fixed")
	sharedPool        = sync.Pool{
		New: func() any {
			return make([]byte, 8)
		},
	}
)

type memoDoc struct {
	once sync.Once
	val  string
	err  error
}

func newMemoDoc() *memoDoc {
	return &memoDoc{}
}

func (m *memoDoc) Get() (string, error) {
	m.once.Do(func() {
		m.val = "ready"
	})
	return m.val, m.err
}

var embeddedMemo = newMemoDoc()

func ExternalBodyless(x int) int
`,
		"b.go": `package flowcache

func init() {
	initHelper(CarrierSlice)
}

func initHelper(in []func()) {
	_ = len(in)
}

func GenericRead[T ~[]func()](in T) int {
	return len(in)
}

func ExerciseAllConstructs(ch chan int, box any) (namedOut int) {
	b := sharedPool.Get().([]byte)
	b = b[:0]
	sharedPool.Put(b)
	_, _ = embeddedMemo.Get()
	switch v := box.(type) {
	case []int:
		namedOut += len(v)
	default:
		_ = v
	}
	for i := range TupArr {
		namedOut += i
	}
	cl := func(delta int) int {
		return (func(x int) int { return x + delta })(cMask1)
	}
	go func() {
		_ = GenericRead(CarrierSlice)
	}()
	defer func() {
		_ = SentinelErr
	}()
	namedOut += cl(TupScalar)
	return
}
`,
	})

	wantDeclLowers := 0
	for _, f := range pkg.Syntax {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Body != nil {
					wantDeclLowers++
				}
			case *ast.GenDecl:
				if d.Tok == token.VAR || d.Tok == token.CONST {
					wantDeclLowers++
				}
			}
		}
	}

	fc := newPkgFlowCache(true, pkg)
	if fc == nil {
		t.Fatal("newPkgFlowCache returned nil")
	}
	if fc.declLowerCount != wantDeclLowers {
		t.Fatalf("fc.declLowerCount = %d, want %d", fc.declLowerCount, wantDeclLowers)
	}
	if fc.missCount != 0 {
		t.Fatalf("fc.missCount after construction = %d, want 0", fc.missCount)
	}

	hooks := &syntaxutil.ExplainHookSet{
		Site:             func(*packages.Package, string, string, syntaxutil.FuncKey, bool, token.Pos) {},
		ExportedSeamSite: func(*packages.Package, syntaxutil.FuncKey, string, token.Pos) {},
		Store:            func(*packages.Package, string, token.Pos) {},
		Deferral:         func(*packages.Package, byte, string, syntaxutil.DeferralResolvent, token.Pos) {},
		Refusal:          func(*packages.Package, string, ast.Expr, string) {},
	}
	gotFact := factOfWithCache(true, pkg, fc, false, hooks)
	if fc.missCount != 0 {
		t.Fatalf("fc.missCount after full factOfWithCache = %d, want 0", fc.missCount)
	}
	if fc.declLowerCount != wantDeclLowers {
		t.Fatalf("fc.declLowerCount grew from %d to %d during passes", wantDeclLowers, fc.declLowerCount)
	}

	wantFact := FactOf(true, pkg)
	if !reflect.DeepEqual(gotFact, wantFact) {
		t.Fatalf("factOfWithCache differed from FactOf:\ngot:  %+v\nwant: %+v", gotFact, wantFact)
	}
}

func TestSummaryUsesInitBackingAliasesSiblingFieldsAndKeyReads(t *testing.T) {
	cases := []struct {
		name        string
		audited     bool
		src         string
		wantMutates []string
		noMutates   []string
		wantEscapes []string
		noEscapes   []string
		checkExtra  func(t *testing.T, pkg *packages.Package, fact Fact)
	}{
		{
			name:    "init_ptr_deref_alias_escape_and_double_ptr_mutate",
			audited: true,
			src: `package p

var CarrierEsc = []func(){func() {}}
var CarrierMut = []func(){func() {}}
var CarrierLinkSrc = []func(){func() {}}
var LinkDst any

func escapeSlice(in []func()) {
	LinkDst = in
}

func init() {
	var s []func()
	p := &s
	*p = CarrierEsc
	escapeSlice(s)

	var sl []func()
	pl := &sl
	*pl = CarrierLinkSrc
	LinkDst = sl

	var s2 []func()
	p1 := &s2
	p2 := &p1
	**p2 = CarrierMut
	_ = func() {
		s2[0] = func() {}
	}
}
`,
			wantMutates: []string{"example.com/p.CarrierMut"},
			noMutates:   []string{"example.com/p.CarrierEsc", "example.com/p.CarrierLinkSrc"},
			wantEscapes: []string{"example.com/p.CarrierEsc"},
			noEscapes:   []string{"example.com/p.CarrierMut"},
			checkExtra: func(t *testing.T, _ *packages.Package, fact Fact) {
				wantLink := syntaxutil.CarrierLink{From: "example.com/p.LinkDst", To: "example.com/p.CarrierLinkSrc"}
				if !slices.Contains(fact.CarrierLinks, wantLink) {
					t.Fatalf("CarrierLinks missing %+v: got %+v", wantLink, fact.CarrierLinks)
				}
			},
		},
		{
			name:    "init_shared_slice_header_and_reslice_backing_alias",
			audited: true,
			src: `package p

var CarrierDirect = []func(){func() {}}
var CarrierReslice = []func(){func() {}}
var sink any

func leakAnySlice(in []any) {
	sink = in
}

func init() {
	a := make([]any, 1)
	b := a
	b[0] = CarrierDirect
	leakAnySlice(a)

	c := make([]any, 2)
	d := c[:1]
	d[0] = CarrierReslice
	_ = func() {
		sink = c
	}
}
`,
			wantEscapes: []string{"example.com/p.CarrierDirect", "example.com/p.CarrierReslice"},
		},
		{
			name:    "init_uintptr_unsafe_pointer_roundtrip_and_helper_param_seed",
			audited: true,
			src: `package p

import "unsafe"

var CarrierUnsafe = []func(){func() {}}
var CarrierHelper = []func(){func() {}}
var sink any

func leak(x any) { sink = x }

func helper(in []func()) {
	leak(in)
}

func init() {
	raw := uintptr(unsafe.Pointer(&CarrierUnsafe)) + 0
	ptr := (*[]func())(unsafe.Pointer(raw))
	_ = func() {
		(*ptr)[0] = nil
	}

	var local []func()
	lp := &local
	*lp = CarrierHelper
	helper(local)
}
`,
			wantMutates: []string{"example.com/p.CarrierUnsafe"},
			wantEscapes: []string{"example.com/p.CarrierHelper"},
		},
		{
			name:    "fresh_composite_sibling_scalar_fields_do_not_taint_embedded_carrier",
			audited: true,
			src: `package p

type holder struct {
	c []func()
	n int
}

type ptrHolder struct {
	inner *holder
}

var CleanEmbedded = []func(){func() {}}
var EscapedHolder = []func(){func() {}}
var MutatedInterior = []func(){func() {}}
var GlobalHolderPtr = &holder{}
var sink any

func readInt(x int) int { return x + 1 }

func init() {
	box := &holder{c: CleanEmbedded, n: 1}
	escBox := &holder{c: EscapedHolder, n: 1}
	mutBox := &holder{c: MutatedInterior, n: 1}
	ph := &ptrHolder{inner: GlobalHolderPtr}

	_ = func() {
		box.n = 2
		box.n++
		box.n += 3
		_ = readInt(box.n)
		np := &box.n
		*np = 9

		sink = escBox
		mutBox.c[0] = func() {}
		ph.inner.n = 77
	}
}
`,
			wantMutates: []string{"example.com/p.MutatedInterior", "example.com/p.GlobalHolderPtr"},
			noMutates:   []string{"example.com/p.CleanEmbedded", "example.com/p.EscapedHolder"},
			wantEscapes: []string{"example.com/p.EscapedHolder"},
			noEscapes:   []string{"example.com/p.CleanEmbedded"},
		},
		{
			name:    "lhs_and_range_index_keys_are_rvalue_reads_not_mutations",
			audited: true,
			src: `package p

var CarrierSlice = []func(){func() {}}
var CarrierKey any = "k"
var PredeclaredRangeKey any
var sink int

func init() {
	_ = func() {
		m := map[int]int{}
		m[len(CarrierSlice)] = 10

		ma := map[any]int{}
		ma[CarrierKey] = 20

		table := [][]int{{1, 2}, {3, 4}}
		for _, v := range table[len(CarrierSlice)-1] {
			sink += v
		}

		pairs := []any{"a", "b"}
		for _, PredeclaredRangeKey = range pairs {
		}
	}
}
`,
			wantMutates: []string{"example.com/p.PredeclaredRangeKey"},
			noMutates:   []string{"example.com/p.CarrierSlice", "example.com/p.CarrierKey"},
			wantEscapes: []string{"example.com/p.CarrierKey"},
			noEscapes:   []string{"example.com/p.CarrierSlice"},
		},
		{
			name:    "compound_and_incdec_map_writes_emit_mutation_without_spurious_escape",
			audited: true,
			src: `package p

var Counts = map[any]int{"a": 1}

func Bump() {
	Counts["a"]++
	Counts["b"] += 4
}
`,
			checkExtra: func(t *testing.T, _ *packages.Package, fact Fact) {
				sawMut := false
				for _, u := range fact.AttributedUses {
					if u.Key == "example.com/p.Counts" {
						if u.Escape {
							t.Fatalf("compound/incdec map write emitted spurious Escape AttributedUse: %+v", u)
						}
						sawMut = true
					}
				}
				if !sawMut {
					t.Fatalf("missing mutation AttributedUse on Counts: %+v", fact.AttributedUses)
				}
			},
		},
		{
			name:    "explain_hooks_site_and_deferral_parity",
			audited: true,
			src: `package p

type box struct{ fn func() }

func (b *box) Read() int { return 0 }

var (
	MutGlobal   = []func(){func() {}}
	EscGlobal   = []func(){func() {}}
	ParamGlobal = []func(){func() {}}
	MethGlobal  = &box{}
	sink        any
)

func takeSlice(s []func()) int { return len(s) }

func init() {
	_ = func() {
		MutGlobal[0] = nil
		sink = EscGlobal
	}
}

func AttributedCaller() int {
	_ = MethGlobal.Read()
	return takeSlice(ParamGlobal)
}
`,
			checkExtra: func(t *testing.T, pkg *packages.Package, _ Fact) {
				seenSite := map[string]token.Pos{}
				seenDefer := map[string]byte{}
				hooks := &syntaxutil.ExplainHookSet{
					Site: func(_ *packages.Package, kind, key string, _ syntaxutil.FuncKey, _ bool, pos token.Pos) {
						seenSite[kind+":"+key] = pos
					},
					Deferral: func(_ *packages.Package, kind byte, key string, _ syntaxutil.DeferralResolvent, pos token.Pos) {
						if !pos.IsValid() {
							t.Errorf("invalid pos on deferral %c for %s", kind, key)
						}
						seenDefer[key] = kind
					},
				}
				_ = FactOfWithHooks(true, pkg, false, hooks)
				if !seenSite["mutation:example.com/p.MutGlobal"].IsValid() {
					t.Fatalf("missing valid mutation site hook for MutGlobal: %+v", seenSite)
				}
				if !seenSite["escape:example.com/p.EscGlobal"].IsValid() {
					t.Fatalf("missing valid escape site hook for EscGlobal: %+v", seenSite)
				}
				if seenDefer["example.com/p.ParamGlobal"] != 'p' {
					t.Fatalf("ParamGlobal deferral = %q, want 'p': %+v", seenDefer["example.com/p.ParamGlobal"], seenDefer)
				}
				if seenDefer["example.com/p.MethGlobal"] != 'm' {
					t.Fatalf("MethGlobal deferral = %q, want 'm': %+v", seenDefer["example.com/p.MethGlobal"], seenDefer)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := mustTypecheckPackage(t, "example.com/p", map[string]string{"p.go": tc.src})
			fc := newPkgFlowCache(tc.audited, pkg)
			fact := factOfWithCache(tc.audited, pkg, fc, false, nil)
			if fc.missCount != 0 {
				t.Fatalf("fc.missCount = %d, want 0", fc.missCount)
			}
			for _, want := range tc.wantMutates {
				if !slices.Contains(fact.Mutates, want) {
					t.Fatalf("Mutates missing %s: got %+v", want, fact.Mutates)
				}
			}
			for _, forbid := range tc.noMutates {
				if slices.Contains(fact.Mutates, forbid) {
					t.Fatalf("Mutates falsely included %s: got %+v", forbid, fact.Mutates)
				}
			}
			for _, want := range tc.wantEscapes {
				if !slices.Contains(fact.Escapes, want) {
					t.Fatalf("Escapes missing %s: got %+v", want, fact.Escapes)
				}
			}
			for _, forbid := range tc.noEscapes {
				if slices.Contains(fact.Escapes, forbid) {
					t.Fatalf("Escapes falsely included %s: got %+v", forbid, fact.Escapes)
				}
			}
			if tc.checkExtra != nil {
				tc.checkExtra(t, pkg, fact)
			}
		})
	}
}

func TestUnifiedValueClassifierStoresAndReturnsEdgeCases(t *testing.T) {
	pkg := mustTypecheckPackage(t, "example.com/valclass", map[string]string{
		"val.go": `package valclass

import "unsafe"

func pureTopFn() int { return 42 }

func makeDirty() func() int {
	c := 0
	return func() int { c++; return c }
}

var (
	singleCleanFn      = func() int { return 7 }
	DerivedSingleClean = func() int { return singleCleanFn() }

	ShadowedNilHook   func() int
	UnsafeFuncPtrHook *func() int
	IIFEDirtyHook     func() int
	IIFEParamHook     func() int
	IIFECleanHook     func() int
)

func init() {
	nil := makeDirty()
	ShadowedNilHook = nil

	dirtyLocal := makeDirty()
	raw := unsafe.Pointer(&dirtyLocal)
	UnsafeFuncPtrHook = (*func() int)(raw)

	(func() {
		IIFEDirtyHook = makeDirty()
	})()

	(func(f func() int) {
		IIFEParamHook = f
	})(pureTopFn)

	(func() {
		IIFECleanHook = pureTopFn
	})()
}

func makePtrReader(p *int) func() int {
	return func() int { return *p }
}

func SmuggleFromUnsafePointerParam(p unsafe.Pointer) func() int {
	return makePtrReader((*int)(p))
}

func AppendNilFuncBaseClean() []func() int {
	return append([]func() int(nil), pureTopFn)
}

func AppendBackingSliceVarDirty(backing []func() int) []func() int {
	_ = append(backing[:0], makeDirty())
	return []func() int{pureTopFn}
}

func AppendBackingSliceDirectDirty(backing []func() int) []func() int {
	c := 0
	_ = append(backing[:0], func() int { c++; return c })
	return []func() int{pureTopFn}
}

type methodCarrier struct {
	state int
}

func (m *methodCarrier) Act() int { return m.state }

func actPlain(m *methodCarrier) int { return m.state }

type regBox struct {
	fn func(*methodCarrier) int
}

var (
	NamedFnReg    = []regBox{{fn: actPlain}}
	MethodExprReg = []regBox{{fn: (*methodCarrier).Act}}
)

func MakeBoxIgnoringUncalledClosure() regBox {
	var out regBox
	_ = func() {
		out.fn = (*methodCarrier).Act
	}
	return out
}
`,
	})

	fc := newPkgFlowCache(true, pkg)
	fact := factOfWithCache(true, pkg, fc, false, nil)
	if fc.missCount != 0 {
		t.Fatalf("fc.missCount = %d, want 0", fc.missCount)
	}

	state := Compose(
		[]GraphPackage{{ImportPath: "example.com/valclass", PkgPath: "example.com/valclass"}},
		map[string][]Fact{"example.com/valclass": {fact}},
		"example.com/valclass",
		nil,
		false,
		false,
	)
	hasCulprit := func(sym string) bool {
		return slices.ContainsFunc(state.RootCulprits, func(c Culprit) bool {
			return c.Key == "example.com/valclass."+sym
		})
	}
	for _, bad := range []string{
		"example.com/valclass.ShadowedNilHook",
		"example.com/valclass.UnsafeFuncPtrHook",
		"example.com/valclass.IIFEParamHook",
	} {
		if !slices.Contains(fact.EnvCarrying, bad) {
			t.Fatalf("EnvCarrying missed %s: %+v", bad, fact.EnvCarrying)
		}
	}
	if !slices.ContainsFunc(fact.EnvCallUses, func(u syntaxutil.EnvCallUse) bool {
		return u.Key == "example.com/valclass.IIFEDirtyHook" && u.Callee.Name == "makeDirty"
	}) {
		t.Fatalf("EnvCallUses missed IIFEDirtyHook -> makeDirty: %+v", fact.EnvCallUses)
	}
	if !hasCulprit("IIFEDirtyHook") {
		t.Fatalf("Compose RootCulprits missed IIFEDirtyHook: %+v", state.RootCulprits)
	}
	if slices.Contains(fact.EnvCarrying, "example.com/valclass.IIFECleanHook") ||
		slices.ContainsFunc(fact.EnvCallUses, func(u syntaxutil.EnvCallUse) bool {
			return u.Key == "example.com/valclass.IIFECleanHook"
		}) {
		t.Fatalf("IIFECleanHook falsely marked environment-carrying: EnvCarrying=%+v EnvCallUses=%+v", fact.EnvCarrying, fact.EnvCallUses)
	}
	if slices.Contains(fact.EnvCarrying, "example.com/valclass.DerivedSingleClean") || hasCulprit("DerivedSingleClean") {
		t.Fatalf("falsely marked DerivedSingleClean: EnvCarrying=%+v RootCulprits=%+v", fact.EnvCarrying, state.RootCulprits)
	}

	if slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/valclass", Name: "SmuggleFromUnsafePointerParam"}) {
		t.Fatalf("ReturnEnvFree admitted (*int)(unsafe.Pointer) conversion: %+v", fact.ReturnEnvFree)
	}
	if !slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/valclass", Name: "AppendNilFuncBaseClean"}) {
		t.Fatalf("ReturnEnvFree rejected append([]func() int(nil), pureTopFn): %+v", fact.ReturnEnvFree)
	}
	envRes := ResolveEnvAudit(map[string][]Fact{"example.com/valclass": {fact}}, nil)
	if envRes.InsResolved[syntaxutil.ParamKey{
		Func:  syntaxutil.FuncKey{Pkg: "example.com/valclass", Name: "AppendBackingSliceVarDirty"},
		Index: 0,
	}] {
		t.Fatalf("ResolveEnvAudit.InsResolved admitted spare-capacity append(backing[:0], makeDirty()): %+v", envRes.InsResolved)
	}
	if slices.Contains(fact.ParamInsertionFree, syntaxutil.ParamKey{
		Func:  syntaxutil.FuncKey{Pkg: "example.com/valclass", Name: "AppendBackingSliceDirectDirty"},
		Index: 0,
	}) {
		t.Fatalf("ParamInsertionFree admitted direct dirty closure in spare-capacity append: %+v", fact.ParamInsertionFree)
	}

	// NamedFnReg defers parameter 0 of field "fn" to actPlain (without poisoning),
	// whereas MethodExprReg (`(*methodCarrier).Act`) poisons all parameter slots of field "fn" (Index: -1).
	hasNamedDefer := slices.ContainsFunc(fact.FieldParamDefer, func(fd syntaxutil.FieldParamDefer) bool {
		return fd.Pos.Owner == "example.com/valclass.NamedFnReg" && fd.Pos.Field == "fn" && fd.Param.Func.Name == "actPlain"
	})
	if !hasNamedDefer {
		t.Fatalf("NamedFnReg missing FieldParamDefer to actPlain: %+v", fact.FieldParamDefer)
	}
	if slices.ContainsFunc(fact.FieldParamPoison, func(fp syntaxutil.FieldParamPoison) bool {
		return fp.Owner == "example.com/valclass.NamedFnReg"
	}) {
		t.Fatalf("NamedFnReg unexpectedly poisoned: %+v", fact.FieldParamPoison)
	}
	hasMethodExprFieldPoison := slices.ContainsFunc(fact.FieldParamPoison, func(fp syntaxutil.FieldParamPoison) bool {
		return fp.Owner == "example.com/valclass.MethodExprReg" && fp.HasPos && fp.Field == "fn" && fp.Index == -1
	})
	if !hasMethodExprFieldPoison {
		t.Fatalf("MethodExprReg missing field FieldParamPoison (Index: -1): %+v", fact.FieldParamPoison)
	}

	// MakeBoxIgnoringUncalledClosure returns zero `out` without invoking the local
	// closure; it must NOT descend into the uncalled closure body as a synchronous
	// return-field registrant.
	for _, rfp := range fact.ReturnFieldParamPoison {
		if rfp.Func.Name == "MakeBoxIgnoringUncalledClosure" {
			t.Fatalf("uncalled closure body leaked into ReturnFieldParamPoison: %+v", rfp)
		}
	}
}

func TestCallIIFECarrierAliasesSettledGlobalsAndCompoundCacheIndexing(t *testing.T) {
	// 1. CallIIFE parameter/return carrier aliases, CarrierLinks, transient targets,
	// GenDecl IIFE dirty stores, and exported init-only local-alias escape/goroutine foreclosure.
	srcIIFE := `package iifeedge

type Holder struct {
	fn func() int
}

func (h *Holder) Act() int {
	if h.fn != nil {
		return h.fn()
	}
	return 0
}

type ValueBox struct {
	fn func() int
}

var (
	HooksInitDirect = []func() int{func() int { return 1 }}
	HooksInitLocal  = []func() int{func() int { return 1 }}
	HooksVarDecl       = []func() int{func() int { return 1 }}
	HooksTransient     = []func() int{func() int { return 1 }}
	HooksVariadicOk    = []func() int{func() int { return 1 }}
	HooksVariadicMut   = []func() int{func() int { return 1 }}
	HooksExemptRet     = []func() int{func() int { return 1 }}
	HooksDeferNamedRet = []func() int{func() int { return 1 }}
	HooksMapDelete     = map[string]func() int{"k": func() int { return 1 }}

	InnerHolder = Holder{fn: func() int { return 2 }}
	OuterLinks  = make([]*Holder, 1)

	ValCarrierClean    ValueBox
	ValCarrierEsc      ValueBox
	ValCarrierGo       ValueBox
	ValCarrierMethodGo ValueBox

	MethodLinkBox = Holder{fn: func() int { return 7 }}
	MethodLinkFn  func() int

	extSink any
)

func (v *ValueBox) Toggle() {
	v.fn = func() int { return 4 }
}

func pureValueFn() int { return 3 }

func keepExternal(v any) {
	extSink = v
}

var _ = func(s []func() int) int {
	n := 0
	s[0] = func() int {
		n++
		return n
	}
	return 0
}(HooksVarDecl)

func init() {
	// Direct carrier argument into CallIIFE storing stateful closure.
	func(s []func() int) {
		n := 0
		s[0] = func() int {
			n++
			return n
		}
	}(HooksInitDirect)

	// Local carrier alias passed into CallIIFE storing stateful closure.
	loc := HooksInitLocal
	func(s []func() int) {
		n := 0
		s[0] = func() int {
			n++
			return n
		}
	}(loc)

	// Transient CallIIFE return target storing stateful closure.
	tLoc := HooksTransient
	nt := 0
	(func(x []func() int) []func() int { return x }(tLoc))[0] = func() int {
		nt++
		return nt
	}

	// Non-ellipsis variadic packing: writing v[0] = fresh only mutates the fresh
	// variadic slice backing array (clean), whereas v[0][0] = dirty mutates interior!
	func(v ...[]func() int) {
		v[0] = []func() int{func() int { return 5 }}
	}(HooksVariadicOk)
	func(v ...[]func() int) {
		n := 0
		v[0][0] = func() int {
			n++
			return n
		}
	}(HooksVariadicMut)

	// CarrierLink returned out of CallIIFE into OuterLinks.
	p := &InnerHolder
	OuterLinks[0] = func(h *Holder) *Holder { return h }(p)

	// Non-exempt call receiving carrier via CallIIFE return in init() (both direct
	// return and defer-assigned named return after explicit return nil).
	keepExternal(func() []func() int { return HooksExemptRet }())
	keepExternal(func() (out []func() int) {
		defer func() { out = HooksDeferNamedRet }()
		return nil
	}())

	// CarrierLink via ValMethodVal on carrier receiver.
	MethodLinkFn = MethodLinkBox.Act

	// Exported init-only helpers: clean synchronous &ValCarrier mutation vs
	// escaping, goroutine-mutating, and method-value goroutine-mutating aliases.
	ExportedInitCleanMut()
	ExportedInitEscape()
	ExportedInitGoroutine()
	ExportedInitMethodGo()
}

func ExportedInitCleanMut() {
	p := &ValCarrierClean
	p.fn = pureValueFn
}

func ExportedInitEscape() {
	p := &ValCarrierEsc
	keepExternal(p)
}

func ExportedInitGoroutine() {
	p := &ValCarrierGo
	go func() {
		p.fn = func() int { return 9 }
	}()
}

func ExportedInitMethodGo() {
	f := ValCarrierMethodGo.Toggle
	go func() {
		f()
	}()
}

func RuntimeDeleteViaIIFE() {
	delete((func() map[string]func() int { return HooksMapDelete }()), "k")
}

func CompoundParenCacheCheck(x int) int {
	y := 3
	x += (y)
	return x
}
`
	pkg := mustTypecheckPackage(t, "example.com/iifeedge", map[string]string{"iife.go": srcIIFE})
	fc := newPkgFlowCache(true, pkg)
	fact := factOfWithCache(true, pkg, fc, false, nil)
	if fc.missCount != 0 {
		t.Fatalf("fc.missCount = %d, want 0", fc.missCount)
	}

	for _, wantEnv := range []string{
		"example.com/iifeedge.HooksInitDirect",
		"example.com/iifeedge.HooksInitLocal",
		"example.com/iifeedge.HooksVarDecl",
		"example.com/iifeedge.HooksTransient",
		"example.com/iifeedge.HooksVariadicMut",
	} {
		if !slices.Contains(fact.EnvCarrying, wantEnv) {
			t.Fatalf("expected %s in EnvCarrying, got %+v", wantEnv, fact.EnvCarrying)
		}
	}
	if slices.Contains(fact.EnvCarrying, "example.com/iifeedge.HooksVariadicOk") ||
		slices.Contains(fact.Mutates, "example.com/iifeedge.HooksVariadicOk") {
		t.Fatalf("fresh variadic slice slot write falsely tainted HooksVariadicOk: Mutates=%+v EnvCarrying=%+v", fact.Mutates, fact.EnvCarrying)
	}
	for _, wantEsc := range []string{
		"example.com/iifeedge.HooksExemptRet",
		"example.com/iifeedge.HooksDeferNamedRet",
	} {
		if !slices.Contains(fact.Escapes, wantEsc) {
			t.Fatalf("expected %s in Escapes, got %+v", wantEsc, fact.Escapes)
		}
	}
	hasLink := slices.ContainsFunc(fact.CarrierLinks, func(cl syntaxutil.CarrierLink) bool {
		return cl.From == "example.com/iifeedge.OuterLinks" && cl.To == "example.com/iifeedge.InnerHolder"
	})
	if !hasLink {
		t.Fatalf("expected OuterLinks -> InnerHolder CarrierLink across CallIIFE, got %+v", fact.CarrierLinks)
	}
	hasMethodValLink := slices.ContainsFunc(fact.CarrierLinks, func(cl syntaxutil.CarrierLink) bool {
		return cl.From == "example.com/iifeedge.MethodLinkFn" && cl.To == "example.com/iifeedge.MethodLinkBox"
	})
	if !hasMethodValLink {
		t.Fatalf("expected MethodLinkFn -> MethodLinkBox CarrierLink from ValMethodVal, got %+v", fact.CarrierLinks)
	}
	hasMapDeleteAttr := slices.ContainsFunc(fact.AttributedUses, func(u syntaxutil.AttributedUse) bool {
		return u.Key == "example.com/iifeedge.HooksMapDelete" && u.Func.Name == "RuntimeDeleteViaIIFE" && !u.Escape
	})
	if !hasMapDeleteAttr {
		t.Fatalf("expected RuntimeDeleteViaIIFE mutation on HooksMapDelete via CallIIFE return, got %+v", fact.AttributedUses)
	}

	// Compose under packageProcess=true discharges synchronous non-escaping mutations
	// in exported init-only functions (`ExportedInitCleanMut` -> discharged),
	// whereas `ExportedInitEscape` (`Escape: true`), `ExportedInitGoroutine`
	// (`Literal: true`), and `ExportedInitMethodGo` (`ValMethodVal` + goroutine) MUST refuse
	// and emit site hooks for explain chains!
	siteKinds := map[string]map[string]bool{}
	_ = FactOfWithHooks(true, pkg, false, &syntaxutil.ExplainHookSet{
		Site: func(_ *packages.Package, kind, key string, _ syntaxutil.FuncKey, _ bool, pos token.Pos) {
			if !pos.IsValid() {
				t.Errorf("invalid ExplainHookSet.Site pos for kind=%s key=%s", kind, key)
			}
			if siteKinds[key] == nil {
				siteKinds[key] = map[string]bool{}
			}
			siteKinds[key][kind] = true
		},
	})
	if !siteKinds["example.com/iifeedge.ValCarrierEsc"]["escape"] {
		t.Fatalf("ExplainHookSet.Site missed escape on ValCarrierEsc: %+v", siteKinds)
	}
	if !siteKinds["example.com/iifeedge.ValCarrierGo"]["mutation"] {
		t.Fatalf("ExplainHookSet.Site missed mutation on ValCarrierGo: %+v", siteKinds)
	}
	if !siteKinds["example.com/iifeedge.ValCarrierMethodGo"]["escape"] {
		t.Fatalf("ExplainHookSet.Site missed escape on ValCarrierMethodGo: %+v", siteKinds)
	}

	res := Compose(
		[]GraphPackage{{ImportPath: "example.com/iifeedge", PkgPath: "example.com/iifeedge"}},
		map[string][]Fact{"example.com/iifeedge": {fact}},
		"example.com/iifeedge",
		nil,
		false,
		true,
	)
	if slices.ContainsFunc(res.RootCulprits, func(c Culprit) bool { return c.Key == "example.com/iifeedge.ValCarrierClean" }) {
		t.Fatalf("clean synchronous &ValCarrierClean mutation in exported init-only function falsely refused under packageProcess=true: %+v", res.RootCulprits)
	}
	for _, wantCulprit := range []string{
		"example.com/iifeedge.ValCarrierEsc",
		"example.com/iifeedge.ValCarrierGo",
		"example.com/iifeedge.ValCarrierMethodGo",
	} {
		if !slices.ContainsFunc(res.RootCulprits, func(c Culprit) bool { return c.Key == wantCulprit }) {
			t.Fatalf("expected %s in Compose RootCulprits, got %+v", wantCulprit, res.RootCulprits)
		}
	}

	// Verify AssignCompound `x += (y)` maps `(y)` and `y` in fc.exprValue to the ValPlace
	// operand rather than the synthetic outer ValCompositeExpr (`Raw == nil`).
	var parenRHS ast.Expr
	for _, decl := range pkg.Syntax[0].Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "CompoundParenCacheCheck" {
			for _, st := range fd.Body.List {
				if as, ok := st.(*ast.AssignStmt); ok && as.Tok == token.ADD_ASSIGN {
					parenRHS = as.Rhs[0]
				}
			}
		}
	}
	if parenRHS == nil {
		t.Fatal("failed to locate x += (y) RHS")
	}
	for _, expr := range []ast.Expr{parenRHS, syntaxutil.UnparenExpr(parenRHS)} {
		gotRHSVal := fc.exprValue(pkg, expr)
		if gotRHSVal == nil || gotRHSVal.Kind != flowir.ValPlace || gotRHSVal.Raw == nil {
			t.Fatalf("fc.exprValue(%T) = %+v, want inner ValPlace with non-nil Raw", expr, gotRHSVal)
		}
	}

	// 2. settledPackageDataGlobals must evict globals leaked inside top-level CallIIFE
	// ValueSpecs (`var dummy = func() int { leaked = settledTbl; return 0 }()`) while
	// admitting unmutated settled globals (`cleanSettledTbl`) on the identical helper!
	srcSettled := `package settlediife

var (
	settledTbl      = []int{10, 20}
	cleanSettledTbl = []int{30, 40}
	leaked          []int
	dummy           = func() int {
		leaked = settledTbl
		return 0
	}()
	HookLeak  = makeReader(settledTbl)
	HookClean = makeReader(cleanSettledTbl)
)

func makeReader(s []int) func() int {
	return func() int { return s[0] }
}

func MutateLeaked() {
	leaked[0] = 99
}
`
	pkgSettled := mustTypecheckPackage(t, "example.com/settlediife", map[string]string{"settled.go": srcSettled})
	factSettled := FactOf(true, pkgSettled)
	resSettled := Compose(
		[]GraphPackage{{ImportPath: "example.com/settlediife", PkgPath: "example.com/settlediife"}},
		map[string][]Fact{"example.com/settlediife": {factSettled}},
		"example.com/settlediife",
		nil,
		false,
		false,
	)
	if !slices.ContainsFunc(resSettled.RootCulprits, func(c Culprit) bool { return c.Key == "example.com/settlediife.HookLeak" }) {
		t.Fatalf("expected HookLeak in RootCulprits after CallIIFE settled-data eviction, got EnvCarrying=%+v EnvCallUses=%+v RootCulprits=%+v",
			factSettled.EnvCarrying, factSettled.EnvCallUses, resSettled.RootCulprits)
	}
	if slices.ContainsFunc(resSettled.RootCulprits, func(c Culprit) bool { return c.Key == "example.com/settlediife.HookClean" }) {
		t.Fatalf("clean settled global HookClean falsely flagged in RootCulprits: %+v", resSettled.RootCulprits)
	}
}

func TestDeferNamedReturnConfinementAndInitTransientEscapes(t *testing.T) {
	src := `package deferandinit

type RecvBox struct {
	buf []int
}

func (r *RecvBox) LeakRecvViaIIFEDefer() []int {
	return (func() (out []int) {
		defer func() { out = r.buf }()
		return nil
	})()
}

func (r *RecvBox) CleanRecvLen() int {
	return len(r.buf)
}

func LeakParamViaIIFEDefer(in []int) []int {
	return (func() (out []int) {
		defer func() { out = in }()
		return nil
	})()
}

func LeakParamViaFuncDefer(in []int) (out []int) {
	defer func() { out = in }()
	return nil
}

func CleanParamLen(in []int) int {
	return len(in)
}

func pureTop() int { return 1 }

func ReturnDirtyViaDeferNamedReturn() (out func() int) {
	n := 0
	defer func() {
		out = func() int {
			n++
			return n
		}
	}()
	return pureTop
}

func ReturnCleanNamedReturn() (out func() int) {
	out = pureTop
	defer func() {}()
	return pureTop
}

func ScopedMemAliasViaIIFEDefer() []int {
	dst := (func() (out []int) {
		loc := make([]int, 1)
		defer func() { out = loc }()
		return nil
	})()
	return dst
}

type MutBox struct {
	fn func() int
	n  int
}

func (m *MutBox) Mut() {
	m.n++
}

var (
	ChRecvCarrier        = make(chan func() int, 1)
	ChRangeCarrier       = make(chan func() int, 1)
	IndirectSlotCarrier  = []func() int{pureTop}
	IndirectMapCarrier   = []func() int{pureTop}
	CopyDstCarrier       = []func() int{pureTop}
	ExprMethodCarrier     MutBox
	DeferMethodCarrier    MutBox
	DeferMethodValCarrier MutBox
	RuntimeMethodCarrier  MutBox
	InitIIFERegionVars    = []func() int{pureTop}

	extSlot  = new([]func() int)
	extMap   = map[string][]func() int{}
	extSlice = make([]func() int, 1)
	extFn    func()
)

func getSlot() *[]func() int          { return extSlot }
func getMap() map[string][]func() int { return extMap }
func getDstSlice() []func() int       { return extSlice }
func saveFn(f func())                 { extFn = f }

func calledFromInitIIFE() {
	InitIIFERegionVars[0] = pureTop
}

func RuntimeMethodVal() func() {
	return RuntimeMethodCarrier.Mut
}

type RebindEntry struct {
	Cols []string
	Fn   func() int
}

var (
	RebindRegistry = []RebindEntry{{Cols: []string{"a"}, Fn: pureTop}}
	rebindFallback = []string{"z"}
)

func RebindDerivedLocal() int {
	total := 0
	for _, e := range RebindRegistry {
		c := e.Cols
		c = rebindFallback
		total += len(c)
	}
	return total
}

type SliceRecvEntry struct {
	fn func()
	n  *int
}

type SliceRecvReg []SliceRecvEntry

var SliceRecvCarrier = SliceRecvReg{{fn: func() {}, n: new(int)}}

func (r SliceRecvReg) First() *int {
	for _, e := range r {
		return e.n
	}
	return nil
}

func UseSliceRecvFirst() {
	p := SliceRecvCarrier.First()
	*p = 1
}

func init() {
	_ = <-ChRecvCarrier
	for range ChRangeCarrier {
	}
	*getSlot() = IndirectSlotCarrier
	getMap()["k"] = IndirectMapCarrier
	copy(getDstSlice(), CopyDstCarrier)
	([1]func(){ExprMethodCarrier.Mut}[0])()
	defer (DeferMethodCarrier.Mut)()
	defer saveFn(DeferMethodValCarrier.Mut)
	(func() {
		calledFromInitIIFE()
	})()
}
`
	pkg := mustTypecheckPackage(t, "example.com/deferandinit", map[string]string{"main.go": src})
	fc := newPkgFlowCache(true, pkg)
	fact := factOfWithCache(true, pkg, fc, false, nil)
	if fc.missCount != 0 {
		t.Fatalf("fc.missCount = %d, want 0", fc.missCount)
	}

	// 1. Defer-mutated named return confinement checks across CallIIFE, top-level functions,
	// ReceiverReadOnly, ReturnEnvFree, and BuildScopedMemAliases.
	if slices.Contains(fact.ReceiverReadOnly, syntaxutil.FuncKey{Pkg: "example.com/deferandinit", Name: "RecvBox.LeakRecvViaIIFEDefer"}) {
		t.Fatalf("ReceiverReadOnly admitted receiver slice leaked via CallIIFE defer-assigned named return: %+v", fact.ReceiverReadOnly)
	}
	if !slices.Contains(fact.ReceiverReadOnly, syntaxutil.FuncKey{Pkg: "example.com/deferandinit", Name: "RecvBox.CleanRecvLen"}) {
		t.Fatalf("ReceiverReadOnly rejected CleanRecvLen: %+v", fact.ReceiverReadOnly)
	}
	for _, fnName := range []string{"LeakParamViaIIFEDefer", "LeakParamViaFuncDefer"} {
		pk := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/deferandinit", Name: fnName}, Index: 0}
		if slices.Contains(fact.ParamLeakFree, pk) {
			t.Fatalf("ParamLeakFree admitted %s: %+v", fnName, fact.ParamLeakFree)
		}
	}
	if !slices.Contains(fact.ParamLeakFree, syntaxutil.ParamKey{
		Func:  syntaxutil.FuncKey{Pkg: "example.com/deferandinit", Name: "CleanParamLen"},
		Index: 0,
	}) {
		t.Fatalf("ParamLeakFree rejected CleanParamLen: %+v", fact.ParamLeakFree)
	}
	if slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/deferandinit", Name: "ReturnDirtyViaDeferNamedReturn"}) {
		t.Fatalf("ReturnEnvFree admitted stateful closure assigned in defer after return pureTop: %+v", fact.ReturnEnvFree)
	}
	if !slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/deferandinit", Name: "ReturnCleanNamedReturn"}) {
		t.Fatalf("ReturnEnvFree rejected ReturnCleanNamedReturn: %+v", fact.ReturnEnvFree)
	}

	var aliasFnDecl *ast.FuncDecl
	for _, d := range pkg.Syntax[0].Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "ScopedMemAliasViaIIFEDefer" {
			aliasFnDecl = fd
			break
		}
	}
	if aliasFnDecl == nil {
		t.Fatal("missing ScopedMemAliasViaIIFEDefer")
	}
	aliasBody := fc.funcBody(pkg, aliasFnDecl)
	scoped := flowir.BuildScopedMemAliases(
		aliasBody,
		func(obj types.Object) bool { _, ok := obj.(*types.Var); return ok },
		refconfine.TypeHandsOutMutableReach,
	)
	dstVar := aliasBody.Ops[0].Dsts[0].Obj
	if dstVar == nil || len(scoped[dstVar]) == 0 {
		t.Fatalf("BuildScopedMemAliases failed to link CallIIFE defer-mutated named return out to dst: %+v", scoped)
	}

	// 2. Bare init() channel receives, indirect transient targets, expression-position
	// ValMethodVal, and CallIIFE program-region classification (`calledFromInitIIFE` is NOT initOnly).
	for _, wantEsc := range []string{
		"example.com/deferandinit.ChRecvCarrier",
		"example.com/deferandinit.ChRangeCarrier",
		"example.com/deferandinit.IndirectSlotCarrier",
		"example.com/deferandinit.IndirectMapCarrier",
		"example.com/deferandinit.CopyDstCarrier",
		"example.com/deferandinit.ExprMethodCarrier",
		"example.com/deferandinit.DeferMethodValCarrier",
	} {
		if !slices.Contains(fact.Escapes, wantEsc) {
			t.Fatalf("expected %s in fact.Escapes, got %+v", wantEsc, fact.Escapes)
		}
	}
	hasRuntimeMethodMut := slices.ContainsFunc(fact.AttributedUses, func(u syntaxutil.AttributedUse) bool {
		return u.Key == "example.com/deferandinit.RuntimeMethodCarrier" && u.Func.Name == "RuntimeMethodVal" && !u.Escape
	})
	hasRuntimeMethodEsc := slices.ContainsFunc(fact.AttributedUses, func(u syntaxutil.AttributedUse) bool {
		return u.Key == "example.com/deferandinit.RuntimeMethodCarrier" && u.Func.Name == "RuntimeMethodVal" && u.Escape
	})
	if !hasRuntimeMethodMut || !hasRuntimeMethodEsc {
		t.Fatalf("expected both mutation and escape AttributedUses on RuntimeMethodCarrier, got %+v", fact.AttributedUses)
	}
	defRes := NewDeferralResolution(map[string][]Fact{"example.com/deferandinit": {fact}}, nil)
	helperKey := syntaxutil.FuncKey{Pkg: "example.com/deferandinit", Name: "calledFromInitIIFE"}
	if !defRes.RefRegions[helperKey][syntaxutil.RefRegion{Kind: syntaxutil.RegionProg}] || defRes.InitOnlyFn[helperKey] {
		t.Fatalf("expected calledFromInitIIFE referenced inside init CallIIFE to be RegionProg (not InitOnlyFn) per closure.md: regions=%+v initOnly=%v",
			defRes.RefRegions[helperKey], defRes.InitOnlyFn[helperKey])
	}
	res := Compose(
		[]GraphPackage{{ImportPath: "example.com/deferandinit", PkgPath: "example.com/deferandinit"}},
		map[string][]Fact{"example.com/deferandinit": {fact}},
		"example.com/deferandinit",
		nil,
		false,
		true,
	)
	if !slices.ContainsFunc(res.RootCulprits, func(c Culprit) bool { return c.Key == "example.com/deferandinit.InitIIFERegionVars" }) {
		t.Fatalf("expected InitIIFERegionVars mutated via init CallIIFE helper to remain a RootCulprit, got %+v", res.RootCulprits)
	}
	if slices.ContainsFunc(res.RootCulprits, func(c Culprit) bool { return c.Key == "example.com/deferandinit.DeferMethodCarrier" }) {
		t.Fatalf("retention-free direct method call in init() falsely refused DeferMethodCarrier: %+v", res.RootCulprits)
	}
	if slices.Contains(fact.Mutates, "example.com/deferandinit.RebindRegistry") ||
		slices.ContainsFunc(fact.AttributedUses, func(u syntaxutil.AttributedUse) bool {
			return u.Key == "example.com/deferandinit.RebindRegistry"
		}) {
		t.Fatalf("plain = rebind of carrier-derived bare local falsely marked RebindRegistry: mutates=%+v attr=%+v", fact.Mutates, fact.AttributedUses)
	}
	hasSliceRecvEsc := slices.ContainsFunc(fact.AttributedUses, func(u syntaxutil.AttributedUse) bool {
		return u.Key == "example.com/deferandinit.SliceRecvCarrier" && u.Func.Name == "UseSliceRecvFirst" && u.Escape
	})
	hasSliceRecvMut := slices.ContainsFunc(fact.AttributedUses, func(u syntaxutil.AttributedUse) bool {
		return u.Key == "example.com/deferandinit.SliceRecvCarrier" && u.Func.Name == "UseSliceRecvFirst" && !u.Escape
	})
	if !hasSliceRecvEsc || hasSliceRecvMut {
		t.Fatalf("SliceRecvCarrier.First() deref store must record escape without non-builtin call alias mutation: esc=%v mut=%v attr=%+v",
			hasSliceRecvEsc, hasSliceRecvMut, fact.AttributedUses)
	}
}

func TestPropertyPkgFlowCacheZeroMissAndFactDeterminism(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		nFuncs := rapid.IntRange(1, 4).Draw(rt, "nFuncs")
		usePool := rapid.Bool().Draw(rt, "usePool")
		useOnce := rapid.Bool().Draw(rt, "useOnce")

		file1 := `package cacheprop

import "sync"

var _ sync.Mutex

const (
	c0 = 1 << iota
	c1
)

var (
	GlobalCarrier = []func(){func() {}}
	ZeroCarrier   []func()
)
`
		if usePool {
			file1 += `
var bufPool = sync.Pool{
	New: func() any { return make([]byte, 4) },
}
`
		}
		if useOnce {
			file1 += `
type lazyVal struct {
	once sync.Once
	v    int
}

func (l *lazyVal) Value() int {
	l.once.Do(func() { l.v = c1 })
	return l.v
}
`
		}

		var fnDecls []string
		for i := 0; i < nFuncs; i++ {
			opChoice := rapid.IntRange(0, 4).Draw(rt, fmt.Sprintf("fnOp_%d", i))
			body := "\tlocal := len(GlobalCarrier) + c0\n"
			switch opChoice {
			case 0:
				body += "\tfn := func() int { return local }\n\tlocal += fn()\n"
			case 1:
				body += "\tlocal += (func(x int) int { return x + 1 })(local)\n"
			case 2:
				body += "\tfor idx := range GlobalCarrier { local += idx }\n"
			case 3:
				body += "\tgo func(v int) { _ = v }(local)\n"
			case 4:
				body += "\tvar box any = local\n\tswitch v := box.(type) { case int: local += v; default: _ = v }\n"
			}
			if usePool && i == 0 {
				body += "\tb := bufPool.Get().([]byte)\n\tbufPool.Put(b[:0])\n"
			}
			fnDecls = append(fnDecls, fmt.Sprintf("func Fn%d(in []int) int {\n%s\treturn local + len(in)\n}\n", i, body))
		}

		var file2Forward, file2Reverse string
		file2Forward = "package cacheprop\n\n"
		file2Reverse = "package cacheprop\n\n"
		for i := 0; i < len(fnDecls); i++ {
			file2Forward += fnDecls[i] + "\n"
			file2Reverse += fnDecls[len(fnDecls)-1-i] + "\n"
		}

		pkgA := mustTypecheckPackage(t, "example.com/cacheprop", map[string]string{
			"f1.go": file1,
			"f2.go": file2Forward,
		})
		pkgB := mustTypecheckPackage(t, "example.com/cacheprop", map[string]string{
			"f1.go": file1,
			"f2.go": file2Reverse,
		})

		fcA := newPkgFlowCache(true, pkgA)
		factA := factOfWithCache(true, pkgA, fcA, false, nil)
		if fcA.missCount != 0 {
			rt.Fatalf("fcA.missCount = %d, want 0\nf1:\n%s\nf2:\n%s", fcA.missCount, file1, file2Forward)
		}

		fcB := newPkgFlowCache(true, pkgB)
		factB := factOfWithCache(true, pkgB, fcB, false, nil)
		if fcB.missCount != 0 {
			rt.Fatalf("fcB.missCount = %d, want 0", fcB.missCount)
		}

		if !reflect.DeepEqual(factA, factB) {
			rt.Fatalf("Fact depended on declaration order:\nforward: %+v\nreverse: %+v", factA, factB)
		}
	})
}

func TestPropertyLocalCarrierAliasAndSiblingFieldStateDriftOracle(t *testing.T) {
	// Ground-truth semantic property over init-flow local alias chains captured by
	// runtime closures:
	// - aliasMode selects how an init-flow local reaches `Carrier`:
	//   0: direct rebind `loc := Carrier` (root-header alias)
	//   1: pointer-to-local indirect bind `var loc []func() int; p := &loc; *p = Carrier` (root-header alias)
	//   2: shared slice header `arr := make([][]func() int, 1); alias := arr; alias[0] = Carrier` (interior reach on `arr`)
	//   3: fresh struct holder `box := &holder{c: Carrier, scalar: 1}` (interior reach ONLY on `box`, root header is fresh)
	//   4: CallIIFE parameter bind `func(loc []func() int) { ... }(Carrier)` (root-header alias via parameter)
	// - action selects the operation performed inside a runtime closure on the local:
	//   0: pure scalar sibling / len read ONLY (clean: Carrier neither mutates nor escapes)
	//   1: sibling scalar field write/incdec/compound/scalar-addr on fresh struct holder (clean when aliasMode==3!)
	//   2: interior carrier mutation (`loc[0] = dirty` / `arr[0][0] = dirty` / `box.c[0] = dirty`) -> MUST mark Mutates!
	//   3: escape whole holder/alias to package sink `sink = ...` -> MUST mark Escapes!
	//   4: rvalue map index-key read `m[len(Carrier)] = 1` -> clean!
	rapid.Check(t, func(rt *rapid.T) {
		aliasMode := rapid.IntRange(0, 4).Draw(rt, "aliasMode")
		action := rapid.IntRange(0, 4).Draw(rt, "action")
		if action == 1 && aliasMode != 3 {
			action = 0
		}

		var aliasSetup string
		switch aliasMode {
		case 0:
			aliasSetup = "\tloc := Carrier\n"
		case 1:
			aliasSetup = "\tvar loc []func() int\n\tp := &loc\n\t*p = Carrier\n"
		case 2:
			aliasSetup = "\tarr := make([][]func() int, 1)\n\talias := arr\n\talias[0] = Carrier\n"
		case 3:
			aliasSetup = "\tbox := &holder{c: Carrier, scalar: 1}\n"
		}

		groundTruthTaintsCarrier := false
		var closureAction string
		switch action {
		case 0:
			switch aliasMode {
			case 0, 1, 4:
				closureAction = "\t\t_ = len(loc)\n"
			case 2:
				closureAction = "\t\t_ = len(arr)\n"
			case 3:
				closureAction = "\t\t_ = box.scalar\n"
			}
		case 1:
			closureAction = "\t\tbox.scalar = 10\n\t\tbox.scalar++\n\t\tbox.scalar += 5\n\t\tsp := &box.scalar\n\t\t*sp = 42\n"
		case 2:
			groundTruthTaintsCarrier = true
			switch aliasMode {
			case 0, 1, 4:
				closureAction = "\t\tloc[0] = func() int { return 99 }\n"
			case 2:
				closureAction = "\t\tarr[0][0] = func() int { return 99 }\n"
			case 3:
				closureAction = "\t\tbox.c[0] = func() int { return 99 }\n"
			}
		case 3:
			groundTruthTaintsCarrier = true
			switch aliasMode {
			case 0, 1, 4:
				closureAction = "\t\tsink = loc\n"
			case 2:
				closureAction = "\t\tsink = arr\n"
			case 3:
				closureAction = "\t\tsink = box\n"
			}
		case 4:
			switch aliasMode {
			case 0, 1, 4:
				closureAction = "\t\t_ = len(loc)\n"
			case 2:
				closureAction = "\t\t_ = len(arr)\n"
			case 3:
				closureAction = "\t\t_ = box.scalar\n"
			}
			closureAction += "\t\tm := map[int]int{}\n\t\tm[len(Carrier)] = 7\n"
		}

		var initBody string
		if aliasMode == 4 {
			initBody = fmt.Sprintf("\tfunc(loc []func() int) {\n\t\t_ = func() {\n%s\t\t}\n\t}(Carrier)\n", closureAction)
		} else {
			initBody = fmt.Sprintf("%s\t_ = func() {\n%s\t}\n", aliasSetup, closureAction)
		}

		src := fmt.Sprintf(`package driftprop

type holder struct {
	c      []func() int
	scalar int
}

var Carrier = []func() int{func() int { return 1 }}
var sink any

func init() {
%s}

func Subject() int {
	return Carrier[0]()
}
`, initBody)

		pkg := mustTypecheckPackage(t, "example.com/driftprop", map[string]string{"drift.go": src})
		fc := newPkgFlowCache(true, pkg)
		fact := factOfWithCache(true, pkg, fc, false, nil)
		if fc.missCount != 0 {
			rt.Fatalf("fc.missCount = %d, want 0\n%s", fc.missCount, src)
		}

		carrierFlagged := slices.Contains(fact.Mutates, "example.com/driftprop.Carrier") ||
			slices.Contains(fact.Escapes, "example.com/driftprop.Carrier")

		if groundTruthTaintsCarrier && !carrierFlagged {
			rt.Fatalf("SOUNDNESS FAILURE (aliasMode=%d action=%d): Carrier tainted in ground truth but neither Mutates nor Escapes recorded it!\nfact.Mutates=%+v\nfact.Escapes=%+v\nsrc:\n%s",
				aliasMode, action, fact.Mutates, fact.Escapes, src)
		}
		if !groundTruthTaintsCarrier && carrierFlagged {
			rt.Fatalf("PRECISION FAILURE (aliasMode=%d action=%d): clean sibling/read-only chain falsely flagged Carrier!\nfact.Mutates=%+v\nfact.Escapes=%+v\nsrc:\n%s",
				aliasMode, action, fact.Mutates, fact.Escapes, src)
		}
	})
}

func TestPanicRecoverZeroReturnAndNonLocalAddrBindConfinement(t *testing.T) {
	const src = `package panicedge

import "sync"

type ValBox struct {
	fn func() int
}

var (
	ValCarrierInitPanic       = ValBox{fn: pureFn}
	SliceCarrierTransientIIFE = []func() int{pureFn}
	ValCarrierNamedRet        = ValBox{fn: pureFn}
	ValCarrierClosOuter       = ValBox{fn: pureFn}
	ValCarrierLocalClean      = ValBox{fn: pureFn}
	GlobalBoxSink             *ValBox
	GlobalSliceSink           []int
	GlobalMatrixSink          [][]int
	StoredScalarRet           func() int
)

func pureFn() int { return 1 }

var unknownSource func() func() int

func sinkFn(f func() []int) { _ = f }
func sinkSlice(s []int)     { _ = s }

func initPanicHelper() (out *ValBox) {
	out = &ValCarrierInitPanic
	defer func() {
		_ = recover()
	}()
	panic("boom")
}

func MutateViaPanicIIFEReturn() {
	loc := SliceCarrierTransientIIFE
	(func() (out []func() int) {
		out = loc
		defer func() {
			_ = recover()
		}()
		panic("boom")
	}())[0] = pureFn
}

func init() {
	GlobalBoxSink = initPanicHelper()
	_ = ExportedLeakNamedRet()
	ExportedLeakClosureOuter()
	ExportedCleanLocalAddr()
}

func ExportedLeakNamedRet() (out *ValBox) {
	out = &ValCarrierNamedRet
	return
}

func ExportedLeakClosureOuter() {
	var out *ValBox
	f := func() {
		out = &ValCarrierClosOuter
	}
	f()
	GlobalBoxSink = out
}

func ExportedCleanLocalAddr() {
	p := &ValCarrierLocalClean
	p.fn = pureFn
}

func LeakParamViaPanicRecoverIIFE(x []int) {
	y := func() (out []int) {
		defer func() {
			_ = recover()
			out = x
		}()
		panic("boom")
	}()
	GlobalSliceSink = y
}

func CleanParamPanicRecoverIIFE(x []int) {
	y := func() (out []int) {
		defer func() {
			_ = recover()
			out = make([]int, len(x))
		}()
		panic("boom")
	}()
	GlobalSliceSink = y
}

func LeakParamViaIIFEBackingAlias(x []int) {
	GlobalMatrixSink = func() (out [][]int) {
		out = make([][]int, 1)
		loc := out
		loc[0] = x
		defer func() {
			_ = recover()
		}()
		panic("boom")
	}()
}

func CleanParamIIFEBackingAlias(x []int) {
	GlobalMatrixSink = func() (out [][]int) {
		out = make([][]int, 1)
		loc := out
		loc[0] = make([]int, len(x))
		defer func() {
			_ = recover()
		}()
		panic("boom")
	}()
}

func RetainParamEscapingLocalViaPanicIIFE(x [][]int) {
	GlobalSliceSink = func() (out []int) {
		loc := make([]int, 1)
		x[0] = loc
		defer func() {
			_ = recover()
			out = loc
		}()
		panic("boom")
	}()
}

func RetainParamCleanPanicIIFE(x [][]int) {
	GlobalSliceSink = func() (out []int) {
		loc := make([]int, 1)
		x[0] = loc
		defer func() {
			_ = recover()
			out = make([]int, 1)
		}()
		panic("boom")
	}()
}

type OnceSmuggleIIFEPanic struct {
	once  sync.Once
	slice []int
}

func (r *OnceSmuggleIIFEPanic) Get() []int {
	r.once.Do(func() {
		loc := func() (out []int) {
			defer func() {
				_ = recover()
				out = GlobalSliceSink
			}()
			panic("boom")
		}()
		r.slice = loc
	})
	return r.slice
}

type OnceCleanIIFEPanic struct {
	once  sync.Once
	slice []int
}

func (r *OnceCleanIIFEPanic) Get() []int {
	r.once.Do(func() {
		loc := func() (out []int) {
			defer func() {
				_ = recover()
				out = make([]int, 1)
			}()
			panic("boom")
		}()
		r.slice = loc
	})
	return r.slice
}

type OnceEvictFreshIIFEPanic struct {
	once  sync.Once
	slice []int
}

func (r *OnceEvictFreshIIFEPanic) Get() []int {
	r.once.Do(func() {
		loc := make([]int, 1)
		sinkSlice(func() (out []int) {
			defer func() {
				_ = recover()
				out = loc
			}()
			panic("boom")
		}())
		r.slice = loc
		r.slice[0] = 1
	})
	return r.slice
}

type OnceKeepFreshIIFEPanic struct {
	once  sync.Once
	slice []int
}

func (r *OnceKeepFreshIIFEPanic) Get() []int {
	r.once.Do(func() {
		loc := make([]int, 1)
		sinkSlice(func() (out []int) {
			defer func() {
				_ = recover()
				out = make([]int, 1)
			}()
			panic("boom")
		}())
		r.slice = loc
		r.slice[0] = 1
	})
	return r.slice
}

func BadReturnEnvPanicInDefer() (out func() int) {
	defer func() {
		_ = recover()
		out = unknownSource()
	}()
	panic("boom")
}

func BadReturnEnvPrePanicAssign() (out func() int) {
	out = unknownSource()
	defer func() {
		_ = recover()
	}()
	panic("boom")
}

func BadReturnEnvDeferWithExplicitReturn() (out func() int) {
	defer func() {
		out = unknownSource()
	}()
	return pureFn
}

func CleanAlwaysPanicsUnnamed() func() int {
	panic("unimplemented")
}

func CleanNamedRetOverwritten() (out func() int) {
	out = unknownSource()
	return pureFn
}

func StoreCapturingScalarNamedResult() (out int) {
	StoredScalarRet = func() int { return out }
	panic("boom")
}

func ScopedAliasPanicIIFE() {
	dst := func() (out []int) {
		loc := make([]int, 1)
		defer func() {
			_ = recover()
			out = loc
		}()
		panic("boom")
	}()
	_ = dst
}
`
	pkg := mustTypecheckPackage(t, "example.com/panicedge", map[string]string{"panicedge.go": src})
	fc := newPkgFlowCache(true, pkg)
	fact := factOfWithCache(true, pkg, fc, false, nil)
	if fc.missCount != 0 {
		t.Fatalf("fc.missCount = %d, want 0", fc.missCount)
	}

	// 1. BuildScopedMemAliases across zero-OpReturn panic/recover CallIIFE.
	var aliasFD *ast.FuncDecl
	for _, decl := range pkg.Syntax[0].Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name != nil && fd.Name.Name == "ScopedAliasPanicIIFE" {
			aliasFD = fd
			break
		}
	}
	aliasBody := fc.funcBody(pkg, aliasFD)
	memAdj := flowir.BuildScopedMemAliases(aliasBody, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut)
	var dstObj, outObj, locObj types.Object
	for id, obj := range pkg.TypesInfo.Defs {
		if obj == nil || id.Pos() < aliasFD.Pos() || id.Pos() > aliasFD.End() {
			continue
		}
		switch id.Name {
		case "dst":
			dstObj = obj
		case "out":
			outObj = obj
		case "loc":
			locObj = obj
		}
	}
	if dstObj == nil || outObj == nil || locObj == nil || !memAdj[dstObj][outObj] || !memAdj[outObj][locObj] {
		t.Fatalf("BuildScopedMemAliases failed to link dst <-> out <-> loc across zero-OpReturn CallIIFE: %+v", memAdj)
	}

	// 2. ParamLeakFree across zero-OpReturn panic/recover CallIIFE (both direct tainted named result and externalReaching backing alias).
	leakKey := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: "LeakParamViaPanicRecoverIIFE"}, Index: 0}
	cleanKey := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: "CleanParamPanicRecoverIIFE"}, Index: 0}
	leakBackingKey := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: "LeakParamViaIIFEBackingAlias"}, Index: 0}
	cleanBackingKey := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: "CleanParamIIFEBackingAlias"}, Index: 0}
	if slices.Contains(fact.ParamLeakFree, leakKey) {
		t.Fatalf("LeakParamViaPanicRecoverIIFE falsely proven ParamLeakFree: %+v", fact.ParamLeakFree)
	}
	if !slices.Contains(fact.ParamLeakFree, cleanKey) {
		t.Fatalf("CleanParamPanicRecoverIIFE not proven ParamLeakFree: %+v", fact.ParamLeakFree)
	}
	if slices.Contains(fact.ParamLeakFree, leakBackingKey) {
		t.Fatalf("LeakParamViaIIFEBackingAlias falsely proven ParamLeakFree: %+v", fact.ParamLeakFree)
	}
	if !slices.Contains(fact.ParamLeakFree, cleanBackingKey) {
		t.Fatalf("CleanParamIIFEBackingAlias not proven ParamLeakFree: %+v", fact.ParamLeakFree)
	}
	retainEscKey := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: "RetainParamEscapingLocalViaPanicIIFE"}, Index: 0}
	retainCleanKey := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: "RetainParamCleanPanicIIFE"}, Index: 0}
	if slices.Contains(fact.ParamRetentionFree, retainEscKey) {
		t.Fatalf("RetainParamEscapingLocalViaPanicIIFE falsely proven ParamRetentionFree: %+v", fact.ParamRetentionFree)
	}
	if !slices.Contains(fact.ParamRetentionFree, retainCleanKey) {
		t.Fatalf("RetainParamCleanPanicIIFE not proven ParamRetentionFree: %+v", fact.ParamRetentionFree)
	}

	// 3. ReceiverReadOnly sync.Once top-level smuggle detection and freshLocals eviction across zero-OpReturn CallIIFEs.
	smuggleIIFEMethod := syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: "OnceSmuggleIIFEPanic.Get"}
	cleanIIFEMethod := syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: "OnceCleanIIFEPanic.Get"}
	evictFreshMethod := syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: "OnceEvictFreshIIFEPanic.Get"}
	keepFreshMethod := syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: "OnceKeepFreshIIFEPanic.Get"}
	if slices.Contains(fact.ReceiverReadOnly, smuggleIIFEMethod) {
		t.Fatalf("(*OnceSmuggleIIFEPanic).Get falsely proven ReceiverReadOnly: %+v", fact.ReceiverReadOnly)
	}
	if !slices.Contains(fact.ReceiverReadOnly, cleanIIFEMethod) {
		t.Fatalf("(*OnceCleanIIFEPanic).Get not proven ReceiverReadOnly: %+v", fact.ReceiverReadOnly)
	}
	if slices.Contains(fact.ReceiverReadOnly, evictFreshMethod) {
		t.Fatalf("(*OnceEvictFreshIIFEPanic).Get falsely proven ReceiverReadOnly: %+v", fact.ReceiverReadOnly)
	}
	if !slices.Contains(fact.ReceiverReadOnly, keepFreshMethod) {
		t.Fatalf("(*OnceKeepFreshIIFEPanic).Get not proven ReceiverReadOnly: %+v", fact.ReceiverReadOnly)
	}

	// 4. ReturnEnvFree across zero-OpReturn named-result panic/recover functions vs positive controls.
	for _, badFn := range []string{
		"BadReturnEnvPanicInDefer",
		"BadReturnEnvPrePanicAssign",
		"BadReturnEnvDeferWithExplicitReturn",
	} {
		if slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: badFn}) {
			t.Fatalf("%s falsely proven ReturnEnvFree: %+v", badFn, fact.ReturnEnvFree)
		}
	}
	for _, okFn := range []string{
		"CleanAlwaysPanicsUnnamed",
		"CleanNamedRetOverwritten",
	} {
		if !slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: okFn}) {
			t.Fatalf("%s not proven ReturnEnvFree: %+v", okFn, fact.ReturnEnvFree)
		}
	}

	// 5. enclosingConfinesRoots rejects captured scalar named result on zero-OpReturn function.
	if !slices.Contains(fact.EnvCarrying, "example.com/panicedge.StoredScalarRet") {
		t.Fatalf("StoredScalarRet capturing named result on zero-OpReturn function falsely confined: %+v", fact.EnvCarrying)
	}

	// 6. scanExemptCalls + transient zero-OpReturn CallIIFE mutation + non-RootLocal allowLocalAddrBind.
	if !slices.Contains(fact.Escapes, "example.com/panicedge.ValCarrierInitPanic") {
		t.Fatalf("ValCarrierInitPanic missing from fact.Escapes: %+v", fact.Escapes)
	}
	wantTransientMut := syntaxutil.AttributedUse{
		Func: syntaxutil.FuncKey{Pkg: "example.com/panicedge", Name: "MutateViaPanicIIFEReturn"},
		Key:  "example.com/panicedge.SliceCarrierTransientIIFE",
	}
	if !slices.Contains(fact.AttributedUses, wantTransientMut) {
		t.Fatalf("missing transient zero-OpReturn CallIIFE mutation %+v in %+v", wantTransientMut, fact.AttributedUses)
	}
	res := Compose(
		[]GraphPackage{{ImportPath: "example.com/panicedge", PkgPath: "example.com/panicedge"}},
		map[string][]Fact{"example.com/panicedge": {fact}},
		"example.com/panicedge",
		nil,
		false,
		true,
	)
	for _, wantCulprit := range []string{
		"example.com/panicedge.ValCarrierInitPanic",
		"example.com/panicedge.ValCarrierNamedRet",
		"example.com/panicedge.ValCarrierClosOuter",
	} {
		if !slices.ContainsFunc(res.RootCulprits, func(c Culprit) bool { return c.Key == wantCulprit }) {
			t.Fatalf("expected %s in Compose RootCulprits under packageProcess=true, got %+v", wantCulprit, res.RootCulprits)
		}
	}
	if slices.ContainsFunc(res.RootCulprits, func(c Culprit) bool { return c.Key == "example.com/panicedge.ValCarrierLocalClean" }) {
		t.Fatalf("clean RootLocal &ValCarrierLocalClean falsely refused under packageProcess=true: %+v", res.RootCulprits)
	}
}

func TestNamedResultExplainRefusalHooks(t *testing.T) {
	const src = `package namedrefusal

func pureTop() int { return 1 }

func BrokenDeferCapture() (out func() int) {
	x := 0
	defer func() {
		out = func() int { x++; return x }
	}()
	return pureTop
}

func NakedReturn() (out func() int) {
	out = pureTop
	return
}

func ZeroReturnPanicRecover() (out func() int) {
	defer func() {
		_ = recover()
	}()
	panic("boom")
}

var (
	G1 = BrokenDeferCapture()
	G2 = NakedReturn()
	G3 = ZeroReturnPanicRecover()
)
`
	pkg := mustTypecheckPackage(t, "example.com/namedrefusal", map[string]string{"namedrefusal.go": src})
	type gotRefusal struct {
		clause string
		line   int
	}
	got := map[string][]gotRefusal{}
	hooks := &syntaxutil.ExplainHookSet{
		Refusal: func(p *packages.Package, fn string, e ast.Expr, clause string) {
			line := 0
			if e != nil && e.Pos().IsValid() {
				line = p.Fset.Position(e.Pos()).Line
			}
			got[fn] = append(got[fn], gotRefusal{clause: clause, line: line})
		},
	}
	fact := FactOfWithHooks(true, pkg, false, hooks)
	for _, fn := range []string{"BrokenDeferCapture", "NakedReturn", "ZeroReturnPanicRecover"} {
		if slices.Contains(fact.ReturnEnvFree, syntaxutil.FuncKey{Pkg: "example.com/namedrefusal", Name: fn}) {
			t.Fatalf("%s falsely proven ReturnEnvFree: %+v", fn, fact.ReturnEnvFree)
		}
	}
	wantClauses := map[string]gotRefusal{
		"BrokenDeferCapture":     {clause: "write or capture broke the binding", line: 5},
		"NakedReturn":            {clause: "an unrecognized return shape", line: 15},
		"ZeroReturnPanicRecover": {clause: "an unrecognized return shape", line: 18},
	}
	for fn, want := range wantClauses {
		entries := got[fn]
		if len(entries) == 0 {
			t.Fatalf("missing ExplainHookSet.Refusal callback for %s; got %+v", fn, got)
		}
		if !slices.Contains(entries, want) {
			t.Fatalf("Refusal[%s] = %+v, want entry %+v", fn, entries, want)
		}
	}
}

func TestBareRebindDoesNotContaminateUnaddressedMemAliases(t *testing.T) {
	const src = `package rebindalias

import "errors"

var (
	errAborted         = errors.New("aborted")
	CarrierPtr         = []any{1}
	CarrierArr         = []any{2}
	CarrierStruct      = []any{3}
	CarrierClos        = []any{4}
	CarrierClosArr     = []any{41}
	CarrierClosStruct  = []any{42}
	CarrierComposite   = []any{5}
	CarrierInPlace     = []any{6}
	indirectMatrixSink func([][]any)
)

type roots struct {
	paths []string
}

type session struct {
	roots roots
}

type view struct{}

func (v *view) checkMap() (map[string]int, error) { return nil, nil }

type unit struct {
	sess *session
	v    *view
}

func consumeRoots(_ *roots) {}

func (u *unit) Close() (res int, err error) {
	defer func() {
		err = errAborted
	}()
	s := u.sess
	consumeRoots(&s.roots)
	_, err = u.v.checkMap()
	return 1, err
}

func TrueMutateViaAddressedSlot() {
	var x []any
	p := &x
	q := p
	x = CarrierPtr
	(*q)[0] = 10
}

func TrueMutateViaValueArraySlice() {
	var arr [1][]any
	s := arr[:]
	tSlice := s
	arr = [1][]any{CarrierArr}
	tSlice[0][0] = 20
}

func TrueMutateViaInlineStructFieldAddr() {
	var box struct{ f []any }
	pb := &box.f
	qb := pb
	box = struct{ f []any }{f: CarrierStruct}
	(*qb)[0] = 30
}

var (
	SinkFn       func()
	SinkArrFn    func()
	SinkStructFn func()
)

func init() {
	var x []any
	p := &x
	q := p
	SinkFn = func() {
		(*q)[0] = 40
	}
	x = CarrierClos

	var arr [1][]any
	sa := arr[:]
	ta := sa
	SinkArrFn = func() {
		ta[0][0] = 41
	}
	arr = [1][]any{CarrierClosArr}

	var box struct{ f []any }
	pb := &box.f
	qb := pb
	SinkStructFn = func() {
		(*qb)[0] = 42
	}
	box = struct{ f []any }{f: CarrierClosStruct}

	a := make([][]any, 1)
	b := a
	b[0] = CarrierComposite
	if indirectMatrixSink != nil {
		indirectMatrixSink(a)
	}

	c := make([][]any, 1)
	d := c
	copy(d, [][]any{CarrierInPlace})
	if indirectMatrixSink != nil {
		indirectMatrixSink(c)
	}
}
`
	pkg := mustTypecheckPackage(t, "example.com/rebindalias", map[string]string{"rebindalias.go": src})
	fact := FactOf(true, pkg)

	if !slices.Contains(fact.Opaque, "example.com/rebindalias.errAborted") {
		t.Fatalf("errAborted missing from fact.Opaque: %+v", fact.Opaque)
	}
	if slices.Contains(fact.Mutates, "example.com/rebindalias.errAborted") {
		t.Fatalf("errAborted falsely in fact.Mutates: %+v", fact.Mutates)
	}
	for _, au := range fact.AttributedUses {
		if au.Key == "example.com/rebindalias.errAborted" && !au.Escape {
			t.Fatalf("errAborted falsely attributed as mutated via unaddressed err rebinding: %+v", au)
		}
	}
	for _, closMutKey := range []string{
		"example.com/rebindalias.CarrierClos",
		"example.com/rebindalias.CarrierClosArr",
		"example.com/rebindalias.CarrierClosStruct",
	} {
		if !slices.Contains(fact.Mutates, closMutKey) {
			t.Fatalf("%s missing from fact.Mutates: %+v", closMutKey, fact.Mutates)
		}
	}
	for fn, key := range map[string]string{
		"TrueMutateViaAddressedSlot":         "example.com/rebindalias.CarrierPtr",
		"TrueMutateViaValueArraySlice":       "example.com/rebindalias.CarrierArr",
		"TrueMutateViaInlineStructFieldAddr": "example.com/rebindalias.CarrierStruct",
	} {
		want := syntaxutil.AttributedUse{
			Func: syntaxutil.FuncKey{Pkg: "example.com/rebindalias", Name: fn},
			Key:  key,
		}
		if !slices.Contains(fact.AttributedUses, want) {
			t.Fatalf("missing attributed mutation %+v in %+v", want, fact.AttributedUses)
		}
	}
	for _, escKey := range []string{
		"example.com/rebindalias.CarrierComposite",
		"example.com/rebindalias.CarrierInPlace",
	} {
		if !slices.Contains(fact.Escapes, escKey) {
			t.Fatalf("%s missing from fact.Escapes: %+v", escKey, fact.Escapes)
		}
	}
}

func TestUnsafePointerUintptrAddressAliasingAndConfinement(t *testing.T) {
	src := `package unsafeflow

import (
	"sync"
	"unsafe"
)

var (
	CarrierDirect     = []any{1}
	CarrierStructAddr = []any{2}
	CarrierArith      = []any{3}
	CarrierParamAddr  = []any{4}
	CarrierRetAddr    = []any{5}
	CarrierNamedRet       = []any{6}
	CarrierInitStructFld  = []any{60}
	CarrierMutViaParam    = []any{61}
	CarrierClosureFld     = []any{7}
	CarrierClosureIdx     = []any{8}
	CarrierClosureSubAddr = []any{9}
	CarrierCleanInt       = []any{10}
	FnLinkDirect          = func() int { return 11 }
	FnLinkStruct          = func() int { return 12 }
	FnLinkArith           = func() int { return 13 }
	FnLinkPlainPtr        = func() int { return 14 }
	FnLinkViaStruct       = func() int { return 15 }
	FnRegistry            = make([]func() int, 5)
	DirtyEnvFn            = func() int { return 99 }

	ClosureEscapeFld     func()
	ClosureEscapeIdx     func()
	ClosureEscapeSubAddr func()
	ClosureMutViaParam   func()

	indirectAnySink   func(any)
	indirectUptrSink  func(uintptr)
	indirectPtrSink   func(*uintptr)
	extAddrGlobal     uintptr
	extIntSliceGlobal []int
	settledLeak      = new(int)
	ExportedLeakBox  any = uintptr(unsafe.Pointer(settledLeak))
	SettledUser      = []func() int{derefMaker(settledLeak)}
	settledClean     = new(int)
	SettledCleanUser = []func() int{derefMaker(settledClean)}
)

func derefMaker(p *int) func() int {
	return func() int { return *p }
}

func cleanFn() int { return 1 }

func passUintptr(u uintptr) {
	if indirectUptrSink != nil {
		indirectUptrSink(u)
	}
}

func mutateInitOnlyUintptr(u uintptr) {
	ClosureMutViaParam = func() {
		*(*[]any)(unsafe.Pointer(u)) = nil
	}
}

func retUintptr() uintptr {
	return uintptr(unsafe.Pointer(&CarrierRetAddr))
}

func namedRetUintptr() (u uintptr) {
	u = uintptr(unsafe.Pointer(&CarrierNamedRet))
	return
}

func init() {
	var s1 []any
	u1 := uintptr(unsafe.Pointer(&s1))
	*(*[]any)(unsafe.Pointer(u1)) = CarrierDirect
	if indirectAnySink != nil {
		indirectAnySink(s1)
	}

	var s2 []any
	h2 := struct{ u uintptr }{u: uintptr(unsafe.Pointer(&s2))}
	*(*[]any)(unsafe.Pointer(h2.u)) = CarrierStructAddr
	if indirectAnySink != nil {
		indirectAnySink(s2)
	}

	var s3 []any
	u3 := uintptr(unsafe.Pointer(&s3)) + 0
	*(*[]any)(unsafe.Pointer(u3)) = CarrierArith
	if indirectAnySink != nil {
		indirectAnySink(s3)
	}

	passUintptr(uintptr(unsafe.Pointer(&CarrierParamAddr)))
	mutateInitOnlyUintptr(uintptr(unsafe.Pointer(&CarrierMutViaParam)))
	_ = retUintptr()
	_ = namedRetUintptr()

	hInitFld := struct{ u uintptr }{u: uintptr(unsafe.Pointer(&CarrierInitStructFld))}
	if indirectUptrSink != nil {
		indirectUptrSink(hInitFld.u)
	}

	xFld := CarrierClosureFld
	hFld := struct{ u uintptr }{u: uintptr(unsafe.Pointer(&xFld))}
	ClosureEscapeFld = func() {
		if indirectUptrSink != nil {
			indirectUptrSink(hFld.u)
		}
	}

	xIdx := CarrierClosureIdx
	arrIdx := []uintptr{uintptr(unsafe.Pointer(&xIdx))}
	ClosureEscapeIdx = func() {
		if indirectUptrSink != nil {
			indirectUptrSink(arrIdx[0])
		}
	}

	xSub := CarrierClosureSubAddr
	hSub := struct{ u uintptr }{u: uintptr(unsafe.Pointer(&xSub))}
	ClosureEscapeSubAddr = func() {
		if indirectPtrSink != nil {
			indirectPtrSink(&hSub.u)
		}
	}

	uLink := uintptr(unsafe.Pointer(&FnLinkViaStruct))
	hLink := struct{ u uintptr }{u: uLink}
	FnRegistry[4] = *(*func() int)(unsafe.Pointer(hLink.u))

	var fPlain func() int
	pfPlain := &fPlain
	*pfPlain = FnLinkPlainPtr
	FnRegistry[3] = fPlain

	var f1 func() int
	uf1 := uintptr(unsafe.Pointer(&f1))
	*(*func() int)(unsafe.Pointer(uf1)) = FnLinkDirect
	FnRegistry[0] = f1

	var f2 func() int
	hf2 := struct{ u uintptr }{u: uintptr(unsafe.Pointer(&f2))}
	*(*func() int)(unsafe.Pointer(hf2.u)) = FnLinkStruct
	FnRegistry[1] = f2

	var f3 func() int
	uf3 := uintptr(unsafe.Pointer(&f3)) + 0
	*(*func() int)(unsafe.Pointer(uf3)) = FnLinkArith
	FnRegistry[2] = f3

	cleanBox := struct {
		c []any
		n int
	}{c: CarrierCleanInt, n: 7}
	if indirectAnySink != nil {
		indirectAnySink(cleanBox.n)
	}
}

type AddrHolder struct {
	addr uintptr
}

func (r *AddrHolder) WriteThroughStoredAddr() {
	u := r.addr
	*(*int)(unsafe.Pointer(u)) = 99
}

func LeakUnsafeParamReturn(p unsafe.Pointer) uintptr {
	return uintptr(p)
}

func LeakUnsafeParamCompare(p unsafe.Pointer) bool {
	return uintptr(p) == 0
}

func RetainExtViaTransientMapAndPtr(dst *map[string][]int) {
	box := &[1][]int{nil}
	(*[1][]int)(unsafe.Pointer(box))[0] = extIntSliceGlobal
	m := map[string][]int{}
	(func() map[string][]int { return m }())["k"] = box[0]
	*dst = m
}

func RetainExtViaTransientMapKey(dst *map[*int]int) {
	m := map[*int]int{}
	(func() map[*int]int { return m }())[settledLeak] = 1
	*dst = m
}

type OnceBadExtUintptr struct {
	once  sync.Once
	addrs []uintptr
}

func (o *OnceBadExtUintptr) Get() int {
	o.once.Do(func() {
		u := extAddrGlobal
		s := make([]uintptr, 1)
		s[0] = u
		o.addrs = s
	})
	return len(o.addrs)
}

type OnceBadUnsafeConstruct struct {
	once sync.Once
	data []int
}

func (o *OnceBadUnsafeConstruct) Get() int {
	o.once.Do(func() {
		o.data = *(*[]int)(unsafe.Pointer(uintptr(0)))
	})
	return len(o.data)
}

type OnceBadFreshLocalUnsafeMut struct {
	once sync.Once
	arr  *[1][]int
}

func (o *OnceBadFreshLocalUnsafeMut) Get() int {
	o.once.Do(func() {
		box := &[1][]int{nil}
		(*[1][]int)(unsafe.Pointer(box))[0] = extIntSliceGlobal
		o.arr = box
	})
	return len(o.arr[0])
}

type OnceCleanPureUintptrSlice struct {
	once  sync.Once
	addrs []uintptr
}

func (o *OnceCleanPureUintptrSlice) Get() int {
	o.once.Do(func() {
		var zero uintptr
		s := make([]uintptr, 1)
		s[0] = zero
		o.addrs = s
	})
	return len(o.addrs)
}

func SmuggleReturnViaUnsafeBox() []func() int {
	box := &[1]func() int{cleanFn}
	u := uintptr(unsafe.Pointer(box))
	alias := (*[1]func() int)(unsafe.Pointer(u))
	alias[0] = DirtyEnvFn
	return box[:]
}

func SmuggleReturnDirectUnsafeConvert(u uintptr) []func() int {
	return *(*[]func() int)(unsafe.Pointer(u))
}

func SmuggleConstUnsafeConvert() *FnHolder {
	return (*FnHolder)(unsafe.Pointer(uintptr(1)))
}

type FnHolder struct {
	fns []func() int
}

func (h *FnHolder) Touch() {
	if len(h.fns) > 0 {
		h.fns[0] = DirtyEnvFn
	}
}

func SmuggleMethodRecvUnsafeConvert(p *FnHolder) []func() int {
	((*FnHolder)(unsafe.Pointer(p))).Touch()
	return p.fns
}

func PoisonParamViaUnsafePointer(p unsafe.Pointer) {
	u := uintptr(p)
	alias := (*[1]func() int)(unsafe.Pointer(u))
	alias[0] = DirtyEnvFn
}

func CleanReturnFnSlice() []func() int {
	return []func() int{cleanFn}
}
`
	pkg := mustTypecheckPackage(t, "example.com/unsafeflow", map[string]string{"unsafeflow.go": src})
	fact := FactOf(true, pkg)

	for _, escName := range []string{
		"CarrierDirect",
		"CarrierStructAddr",
		"CarrierArith",
		"CarrierParamAddr",
		"CarrierRetAddr",
		"CarrierNamedRet",
		"CarrierInitStructFld",
		"CarrierClosureFld",
		"CarrierClosureIdx",
		"CarrierClosureSubAddr",
	} {
		key := "example.com/unsafeflow." + escName
		if !slices.Contains(fact.Escapes, key) {
			t.Fatalf("%s missing from fact.Escapes: %+v", key, fact.Escapes)
		}
	}
	if !slices.Contains(fact.Mutates, "example.com/unsafeflow.CarrierMutViaParam") {
		t.Fatalf("CarrierMutViaParam missing from fact.Mutates: %+v", fact.Mutates)
	}
	for _, fnLink := range []string{"FnLinkDirect", "FnLinkStruct", "FnLinkArith", "FnLinkPlainPtr", "FnLinkViaStruct"} {
		wantLink := syntaxutil.CarrierLink{
			From: "example.com/unsafeflow.FnRegistry",
			To:   "example.com/unsafeflow." + fnLink,
		}
		if !slices.Contains(fact.CarrierLinks, wantLink) {
			t.Fatalf("missing CarrierLink %+v in %+v", wantLink, fact.CarrierLinks)
		}
	}
	if slices.Contains(fact.Escapes, "example.com/unsafeflow.CarrierCleanInt") {
		t.Fatalf("CarrierCleanInt falsely escaped via sibling int field: %+v", fact.Escapes)
	}

	for _, badRO := range []string{
		"AddrHolder.WriteThroughStoredAddr",
		"OnceBadExtUintptr.Get",
		"OnceBadUnsafeConstruct.Get",
		"OnceBadFreshLocalUnsafeMut.Get",
	} {
		mk := syntaxutil.FuncKey{Pkg: "example.com/unsafeflow", Name: badRO}
		if slices.Contains(fact.ReceiverReadOnly, mk) {
			t.Fatalf("%v falsely marked ReceiverReadOnly: %+v", mk, fact.ReceiverReadOnly)
		}
	}
	cleanOnce := syntaxutil.FuncKey{Pkg: "example.com/unsafeflow", Name: "OnceCleanPureUintptrSlice.Get"}
	if !slices.Contains(fact.ReceiverReadOnly, cleanOnce) {
		t.Fatalf("%v missing from ReceiverReadOnly: %+v", cleanOnce, fact.ReceiverReadOnly)
	}

	for _, fnName := range []string{"LeakUnsafeParamReturn", "LeakUnsafeParamCompare"} {
		pk := syntaxutil.ParamKey{
			Func:  syntaxutil.FuncKey{Pkg: "example.com/unsafeflow", Name: fnName},
			Index: 0,
		}
		if slices.Contains(fact.ParamLeakFree, pk) {
			t.Fatalf("%v falsely marked ParamLeakFree: %+v", pk, fact.ParamLeakFree)
		}
		if slices.Contains(fact.ParamRetentionFree, pk) {
			t.Fatalf("%v falsely marked ParamRetentionFree: %+v", pk, fact.ParamRetentionFree)
		}
	}
	for _, retainName := range []string{"RetainExtViaTransientMapAndPtr", "RetainExtViaTransientMapKey"} {
		retainTransientPK := syntaxutil.ParamKey{
			Func:  syntaxutil.FuncKey{Pkg: "example.com/unsafeflow", Name: retainName},
			Index: 0,
		}
		if slices.Contains(fact.ParamRetentionFree, retainTransientPK) {
			t.Fatalf("%v falsely marked ParamRetentionFree: %+v", retainTransientPK, fact.ParamRetentionFree)
		}
	}

	for _, badEnv := range []string{
		"SmuggleReturnViaUnsafeBox",
		"SmuggleReturnDirectUnsafeConvert",
		"SmuggleConstUnsafeConvert",
		"SmuggleMethodRecvUnsafeConvert",
	} {
		fk := syntaxutil.FuncKey{Pkg: "example.com/unsafeflow", Name: badEnv}
		if slices.Contains(fact.ReturnEnvFree, fk) {
			t.Fatalf("%v falsely marked ReturnEnvFree: %+v", fk, fact.ReturnEnvFree)
		}
	}
	cleanEnv := syntaxutil.FuncKey{Pkg: "example.com/unsafeflow", Name: "CleanReturnFnSlice"}
	if !slices.Contains(fact.ReturnEnvFree, cleanEnv) {
		t.Fatalf("%v missing from ReturnEnvFree: %+v", cleanEnv, fact.ReturnEnvFree)
	}
	poisonInsPK := syntaxutil.ParamKey{
		Func:  syntaxutil.FuncKey{Pkg: "example.com/unsafeflow", Name: "PoisonParamViaUnsafePointer"},
		Index: 0,
	}
	if slices.Contains(fact.ParamInsertionFree, poisonInsPK) {
		t.Fatalf("%v falsely marked ParamInsertionFree: %+v", poisonInsPK, fact.ParamInsertionFree)
	}
	if !slices.Contains(fact.EnvCarrying, "example.com/unsafeflow.SettledUser") {
		t.Fatalf("SettledUser falsely treated as clean despite unsafe.Pointer export of settledLeak: EnvCarrying=%+v", fact.EnvCarrying)
	}
	if slices.Contains(fact.EnvCarrying, "example.com/unsafeflow.SettledCleanUser") {
		t.Fatalf("SettledCleanUser falsely marked EnvCarrying: EnvCarrying=%+v", fact.EnvCarrying)
	}
}

func TestInitOnlyHelperParamCompositeCarrierStores(t *testing.T) {
	src := `package initparams

var (
	CarrierPtrStore    = []any{1}
	CarrierFnStore     = func() int { return 2 }
	CarrierSliceStore  = []any{3}
	CarrierMapStore    = []any{4}
	CarrierChanStore   = []any{5}
	CarrierCopyStore   = []any{6}
	CarrierAppendStore = []any{7}
	CarrierAliasParam  = []any{8}
	CarrierIIFEParam   = []any{9}
	CarrierPureInt     = []int{10}
	CarrierLocalPtr    = []any{11}

	indirectSink func(any)
)

func setPtr(p *[]any)             { *p = CarrierPtrStore }
func setFnPtr(p *func() int)      { *p = CarrierFnStore }
func setSlice(s [][]any)          { s[0] = CarrierSliceStore }
func setMap(m map[string][]any)   { m["k"] = CarrierMapStore }
func sendChan(ch chan []any)      { ch <- CarrierChanStore }
func copyInto(dst [][]any)        { copy(dst, [][]any{CarrierCopyStore}) }
func appendInto(dst [][]any)      { _ = append(dst, CarrierAppendStore) }
func aliasParam(p *[]any)         { q := p; *q = CarrierAliasParam }
func iifeParam(p *[]any)          { func(q *[]any) { *q = CarrierIIFEParam }(p) }
func pureWrite(s []int)           { s[0] = 42 }
func confinedLocal()              { var s []any; p := &s; *p = CarrierLocalPtr }

func init() {
	var p1 []any
	setPtr(&p1)
	if indirectSink != nil {
		indirectSink(p1)
	}

	var fn func() int
	setFnPtr(&fn)
	if indirectSink != nil {
		indirectSink(fn)
	}

	s := make([][]any, 1)
	setSlice(s)
	if indirectSink != nil {
		indirectSink(s)
	}

	m := map[string][]any{}
	setMap(m)
	if indirectSink != nil {
		indirectSink(m)
	}

	ch := make(chan []any, 1)
	sendChan(ch)
	if indirectSink != nil {
		indirectSink(ch)
	}

	cp := make([][]any, 1)
	copyInto(cp)
	if indirectSink != nil {
		indirectSink(cp)
	}

	ap := make([][]any, 0, 2)
	appendInto(ap)
	if indirectSink != nil {
		indirectSink(ap[:1])
	}

	var p2 []any
	aliasParam(&p2)
	if indirectSink != nil {
		indirectSink(p2)
	}

	var p3 []any
	iifeParam(&p3)
	if indirectSink != nil {
		indirectSink(p3)
	}

	pureWrite(CarrierPureInt)
	confinedLocal()
}
`
	pkg := mustTypecheckPackage(t, "example.com/initparams", map[string]string{"initparams.go": src})
	fact := FactOf(true, pkg)

	for _, escName := range []string{
		"CarrierPtrStore",
		"CarrierFnStore",
		"CarrierSliceStore",
		"CarrierMapStore",
		"CarrierChanStore",
		"CarrierCopyStore",
		"CarrierAppendStore",
		"CarrierAliasParam",
		"CarrierIIFEParam",
	} {
		key := "example.com/initparams." + escName
		if !slices.Contains(fact.Escapes, key) {
			t.Fatalf("%s missing from fact.Escapes: %+v", key, fact.Escapes)
		}
	}
	for _, cleanName := range []string{"CarrierPureInt", "CarrierLocalPtr"} {
		key := "example.com/initparams." + cleanName
		if slices.Contains(fact.Escapes, key) {
			t.Fatalf("%s falsely marked escaped: %+v", key, fact.Escapes)
		}
	}
}

func TestUintptrConfinementAcrossContainersParamsReturnsAndCompileTimeQueries(t *testing.T) {
	const src = `package uintptrconf

import "unsafe"

type AddrWrap struct {
	u uintptr
}

type CarrierObj struct {
	fn    func() int
	u     uintptr
	wraps []AddrWrap
}

func (c *CarrierObj) Wrap() AddrWrap {
	return AddrWrap{u: c.u}
}

func (c *CarrierObj) StoreWrapGlobal() {
	globalWrap = AddrWrap{u: c.u}
}

func (c *CarrierObj) SizeQueriesOnly() uintptr {
	return unsafe.Sizeof(*c) + unsafe.Alignof(c.fn) + unsafe.Offsetof(c.u)
}

func LeakAddrWrap(w AddrWrap) uintptr {
	return w.u
}

func CleanAddrWrap(w AddrWrap) bool {
	return w.u == 0 && unsafe.Sizeof(w) > 0
}

func RetainExtMapKey(m map[uintptr]int) {
	m[extUintptr] = 1
}

var (
	extUintptr      uintptr
	globalWrap      AddrWrap
	CarrierHandout  = &CarrierObj{fn: func() int { return 1 }}
	CarrierSizeOnly = &CarrierObj{fn: func() int { return 2 }}
	CarrierRangeBad = []struct {
		fn func() int
		u  uintptr
	}{{fn: func() int { return 3 }}}
	CarrierRangeClean = []struct {
		fn func() int
		n  int
	}{{fn: func() int { return 4 }, n: 7}}
	CarrierRangeCleanUintptr = []struct {
		fn func() int
		u  uintptr
	}{{fn: func() int { return 5 }, u: 0}}
	CarrierRangeMapKey = map[uintptr]func(){}

	settledCleanWrap   = AddrWrap{u: 0}
	settledHandoutWrap = AddrWrap{u: 0}
	settledLeakedWrap  = AddrWrap{u: 1}
	CleanWrapHolder    func() bool
	LeakedWrapHolder   func() bool
	HandoutWrapHolder  func() uintptr
)

func init() {
	cleanLocal := settledCleanWrap
	CleanWrapHolder = func() bool { return cleanLocal.u == 0 }

	handoutLocal := settledHandoutWrap
	HandoutWrapHolder = func() uintptr { return handoutLocal.u }

	leakedLocal := settledLeakedWrap
	LeakedWrapHolder = func() bool { return leakedLocal.u == 0 }
}

func UseHandoutMethod() {
	w := CarrierHandout.Wrap()
	p := (*int)(unsafe.Pointer(w.u))
	if p != nil {
		*p = 9
	}
}

func UseCompileTimeQueries() uintptr {
	return unsafe.Sizeof(*CarrierSizeOnly) + unsafe.Alignof(CarrierSizeOnly.fn) + unsafe.Offsetof(CarrierSizeOnly.u)
}

func UseRangeUintptrEscape() uintptr {
	for _, elem := range CarrierRangeBad {
		return elem.u
	}
	return 0
}

func UseRangeCleanScalar() int {
	total := 0
	for _, elem := range CarrierRangeClean {
		total += elem.n
	}
	return total
}

func UseRangeCleanUintptrCheck() bool {
	for _, elem := range CarrierRangeCleanUintptr {
		if elem.u != 0 {
			return false
		}
	}
	return true
}

func UseRangeOuterDerefEscape() unsafe.Pointer {
	var u uintptr
	p := &u
	func() {
		for *p = range CarrierRangeMapKey {
		}
	}()
	return unsafe.Pointer(u)
}

func ExposeSettledWrap() unsafe.Pointer {
	return unsafe.Pointer(settledLeakedWrap.u)
}
`
	pkg := mustTypecheckPackage(t, "example.com/uintptrconf", map[string]string{"u.go": src})
	fact := FactOf(true, pkg)

	if !slices.Contains(fact.Mutates, "example.com/uintptrconf.CarrierHandout") &&
		!slices.Contains(fact.Escapes, "example.com/uintptrconf.CarrierHandout") {
		foundAttr := false
		for _, au := range fact.AttributedUses {
			if au.Key == "example.com/uintptrconf.CarrierHandout" {
				foundAttr = true
				break
			}
		}
		if !foundAttr {
			t.Fatalf("CarrierHandout returning AddrWrap{uintptr} was not marked mutated/escaped at call site: %+v", fact)
		}
	}

	if slices.Contains(fact.Mutates, "example.com/uintptrconf.CarrierSizeOnly") ||
		slices.Contains(fact.Escapes, "example.com/uintptrconf.CarrierSizeOnly") {
		t.Fatalf("CarrierSizeOnly falsely marked mutated/escaped on Sizeof/Alignof/Offsetof: %+v", fact)
	}
	for _, au := range fact.AttributedUses {
		if au.Key == "example.com/uintptrconf.CarrierSizeOnly" {
			t.Fatalf("CarrierSizeOnly falsely attributed on Sizeof/Alignof/Offsetof: %+v", au)
		}
	}

	foundRangeBad := slices.Contains(fact.Escapes, "example.com/uintptrconf.CarrierRangeBad")
	for _, au := range fact.AttributedUses {
		if au.Key == "example.com/uintptrconf.CarrierRangeBad" && au.Escape {
			foundRangeBad = true
		}
	}
	if !foundRangeBad {
		t.Fatalf("CarrierRangeBad escaping uintptr range element not marked escaped: %+v", fact)
	}
	for _, au := range fact.AttributedUses {
		if au.Key == "example.com/uintptrconf.CarrierRangeClean" {
			t.Fatalf("CarrierRangeClean falsely marked on scalar range element: %+v", au)
		}
		if au.Key == "example.com/uintptrconf.CarrierRangeCleanUintptr" {
			t.Fatalf("CarrierRangeCleanUintptr falsely marked on confined uintptr range element: %+v", au)
		}
	}
	if slices.Contains(fact.Mutates, "example.com/uintptrconf.CarrierRangeCleanUintptr") ||
		slices.Contains(fact.Escapes, "example.com/uintptrconf.CarrierRangeCleanUintptr") {
		t.Fatalf("CarrierRangeCleanUintptr falsely marked mutated/escaped: %+v", fact)
	}
	foundRangeMapKey := slices.Contains(fact.Escapes, "example.com/uintptrconf.CarrierRangeMapKey")
	for _, au := range fact.AttributedUses {
		if au.Key == "example.com/uintptrconf.CarrierRangeMapKey" && au.Escape {
			foundRangeMapKey = true
		}
	}
	if !foundRangeMapKey {
		t.Fatalf("CarrierRangeMapKey escaping uintptr map key via deref range LHS not marked escaped: %+v", fact)
	}

	if slices.Contains(fact.ReceiverReadOnly, syntaxutil.FuncKey{Pkg: "example.com/uintptrconf", Name: "CarrierObj.StoreWrapGlobal"}) {
		t.Fatalf("CarrierObj.StoreWrapGlobal falsely proven ReceiverReadOnly: %+v", fact.ReceiverReadOnly)
	}
	if !slices.Contains(fact.ReceiverReadOnly, syntaxutil.FuncKey{Pkg: "example.com/uintptrconf", Name: "CarrierObj.SizeQueriesOnly"}) {
		t.Fatalf("CarrierObj.SizeQueriesOnly missing from ReceiverReadOnly: %+v", fact.ReceiverReadOnly)
	}

	leakPK := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/uintptrconf", Name: "LeakAddrWrap"}, Index: 0}
	cleanPK := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/uintptrconf", Name: "CleanAddrWrap"}, Index: 0}
	retainMapPK := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/uintptrconf", Name: "RetainExtMapKey"}, Index: 0}
	if slices.Contains(fact.ParamLeakFree, leakPK) {
		t.Fatalf("LeakAddrWrap falsely proven ParamLeakFree: %+v", fact.ParamLeakFree)
	}
	if !slices.Contains(fact.ParamLeakFree, cleanPK) {
		t.Fatalf("CleanAddrWrap missing from ParamLeakFree: %+v", fact.ParamLeakFree)
	}
	if slices.Contains(fact.ParamRetentionFree, retainMapPK) {
		t.Fatalf("RetainExtMapKey falsely proven ParamRetentionFree: %+v", fact.ParamRetentionFree)
	}
	if !slices.Contains(fact.EnvCarrying, "example.com/uintptrconf.LeakedWrapHolder") {
		t.Fatalf("LeakedWrapHolder missing from EnvCarrying despite unsafe.Pointer(settledLeakedWrap.u): %+v", fact.EnvCarrying)
	}
	if !slices.Contains(fact.EnvCarrying, "example.com/uintptrconf.HandoutWrapHolder") {
		t.Fatalf("HandoutWrapHolder missing from EnvCarrying despite returning captured uintptr: %+v", fact.EnvCarrying)
	}
	if slices.Contains(fact.EnvCarrying, "example.com/uintptrconf.CleanWrapHolder") {
		t.Fatalf("CleanWrapHolder falsely marked EnvCarrying: %+v", fact.EnvCarrying)
	}
}

func TestStringHeaderUnsafeConfinementAndCrossPackageEdges(t *testing.T) {
	meta, pkgs, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
		{
			pkgPath: "example.com/evil",
			src: `package evil

import "unsafe"

func MutateData(s string) {
	if len(s) > 0 {
		*unsafe.StringData(s) = 'X'
	}
}

func MutateHdr(s string) unsafe.Pointer {
	return unsafe.Pointer(&s)
}

func TakeBox(v any) {
	if b, ok := v.(struct{ S string }); ok && len(b.S) > 0 {
		*unsafe.StringData(b.S) = 'Y'
	}
}
`,
		},
		{
			pkgPath: "example.com/hdrunsafe",
			src: `package hdrunsafe

import "unsafe"

type Labeler struct {
	fn   func() int
	name string
}

func (l *Labeler) Name() string {
	return l.name
}

var SharedHdrLabeler = &Labeler{fn: func() int { return 1 }, name: string([]byte{'a'})}

func LeakAndCorrupt() {
	s := SharedHdrLabeler.Name()
	hdr := (**byte)(unsafe.Pointer(&s))
	if len(s) > 0 {
		**hdr = 'Q'
	}
}

func MutateViaHdr(s string) {
	cp := s
	hdr := (**byte)(unsafe.Pointer(&cp))
	if len(cp) > 0 {
		**hdr = 'Q'
	}
}
`,
		},
		{
			pkgPath: "example.com/benign",
			src: `package benign

import "strings"

func CheckNonEmpty(s string) bool {
	return len(strings.TrimSpace(s)) > 0
}
`,
		},
		{
			pkgPath: "example.com/numunsafe",
			src: `package numunsafe

import "unsafe"

type Labeler struct {
	fn   func() int
	name string
}

func (l *Labeler) Name() string {
	return l.name
}

var SharedLabeler = &Labeler{fn: func() int { return 1 }, name: "clean"}

func FloatBits(x float64) uint64 {
	return *(*uint64)(unsafe.Pointer(&x))
}

func ReadCleanLabel() string {
	_ = FloatBits(1.5)
	return SharedLabeler.Name()
}
`,
		},
		{
			pkgPath: "example.com/mid",
			imports: []string{"example.com/evil", "example.com/hdrunsafe", "example.com/benign", "example.com/numunsafe"},
			src: `package mid

import (
	"strings"

	"example.com/benign"
	"example.com/evil"
	"example.com/hdrunsafe"
	_ "example.com/numunsafe"
)

var (
	ExportedStr string
	//gofresh:single-subject
	ExportedAny  any
	unexpExposed string
	unexpPrivate string
)

func ReadExposed() string {
	return unexpExposed
}

func BoxStr(s string) any {
	return s
}

func StoreToAny(s string) {
	ExportedAny = s
}

type Holder struct {
	fn   func() int
	mode string
}

func ExtractMode(h *Holder) string {
	return h.mode
}

func OuterWrapAny(h *Holder) any {
	return ExtractMode(h)
}

func CleanBytesToStringThenEvil(b []byte) {
	s := string(b)
	evil.MutateData(s)
}

func (h *Holder) CleanTrim() string {
	return strings.TrimSpace(h.mode)
}

func (h *Holder) CleanBenignCheck() bool {
	return benign.CheckNonEmpty(h.mode)
}

func (h *Holder) CleanFreshBytesMut() int {
	b := []byte(h.mode)
	if len(b) > 0 {
		b[0] = 'Z'
	}
	s2 := string(b)
	return len(s2)
}

func (h *Holder) CleanPrivateLog() {
	unexpPrivate = h.mode
}

func (h *Holder) BadEvilDirect() {
	evil.MutateData(h.mode)
}

func (h *Holder) BadEvilHdr() {
	hdrunsafe.MutateViaHdr(h.mode)
}

func (h *Holder) BadEvilBox() {
	box := struct{ S string }{S: h.mode}
	evil.TakeBox(box)
}

func (h *Holder) BadExportedGlobal() {
	ExportedStr = h.mode
}

func (h *Holder) BadUnexportedExposedGlobal() {
	unexpExposed = h.mode
}

func (h *Holder) BadLeakToAny() {
	ExportedAny = h.mode
}

func (h *Holder) BadLeakViaBoxHelper() {
	ExportedAny = BoxStr(h.mode)
}

func (h *Holder) BadLeakViaStoreToAny() {
	StoreToAny(h.mode)
}

var (
	CleanCarrier        = &Holder{fn: func() int { return 1 }, mode: string([]byte{'o', 'k'})}
	PrivateCleanCarrier = &Holder{fn: func() int { return 5 }, mode: string([]byte{'o', 'k'})}
	//gofresh:single-subject
	DirtyCarrier     = &Holder{fn: func() int { return 2 }, mode: string([]byte{'o', 'k'})}
	ViaParamDirty    = &Holder{fn: func() int { return 3 }, mode: string([]byte{'o', 'k'})}
	InternalRetDirty = &Holder{fn: func() int { return 4 }, mode: string([]byte{'o', 'k'})}
)

func RunClean() (string, bool, int) {
	CleanCarrier.CleanPrivateLog()
	_ = len(ExtractMode(CleanCarrier))
	return CleanCarrier.CleanTrim(), CleanCarrier.CleanBenignCheck(), CleanCarrier.CleanFreshBytesMut()
}

func runPrivateClean() string {
	return PrivateCleanCarrier.CleanTrim()
}

func InternalRead() string {
	return InternalRetDirty.CleanTrim()
}

func RunDirty() {
	DirtyCarrier.BadEvilDirect()
}

func RunCorruptViaParamHelper() {
	s := ExtractMode(ViaParamDirty)
	evil.MutateData(s)
}

func RunCorruptViaInternalReturn() {
	evil.MutateData(InternalRead())
}
`,
		},
		{
			pkgPath: "example.com/cleanview",
			imports: []string{"example.com/benign", "example.com/evil"},
			src: `package cleanview

import (
	"strings"

	"example.com/benign"
	"example.com/evil"
)

type Box struct {
	fn   func() int
	mode string
}

func Extract(b *Box) string { return b.mode }

func (b *Box) Trim() string { return strings.TrimSpace(b.mode) }

var SharedClean = &Box{fn: func() int { return 7 }, mode: string([]byte{'o', 'k'})}

func ExerciseClean() (string, bool) {
	evil.MutateData(string([]byte{'t', 'm', 'p'}))
	s := Extract(SharedClean)
	return SharedClean.Trim(), benign.CheckNonEmpty(s)
}
`,
		},
	})

	// Whole-system unsafe memory hazard boundary: evil (*unsafe.StringData write
	// and &s unsafe.Pointer escape) and hdrunsafe ((**byte)(unsafe.Pointer(&s))
	// write) are flagged at the whole-package unsafe boundary, whereas benign
	// (stdlib strings), numunsafe (padding-free float64 -> uint64 scalar bitcast),
	// mid, and cleanview have zero un-confined unsafe memory hazards.
	sizes := types.SizesFor("gc", "amd64")
	byTypes := make(map[*types.Package]*packages.Package, len(pkgs))
	for _, p := range pkgs {
		if p != nil && p.Types != nil {
			byTypes[p.Types] = p
		}
	}
	for _, wantHazardPkg := range []string{"example.com/evil", "example.com/hdrunsafe"} {
		if !refconfine.PackageHasUnconfinedUnsafeMemoryHazard(pkgs[wantHazardPkg], sizes, byTypes) {
			t.Fatalf("%s missed by PackageHasUnconfinedUnsafeMemoryHazard", wantHazardPkg)
		}
	}
	for _, wantSafePkg := range []string{"example.com/benign", "example.com/numunsafe", "example.com/mid", "example.com/cleanview"} {
		if refconfine.PackageHasUnconfinedUnsafeMemoryHazard(pkgs[wantSafePkg], sizes, byTypes) {
			t.Fatalf("%s falsely flagged by PackageHasUnconfinedUnsafeMemoryHazard: %s", wantSafePkg, refconfine.PackageUnsafeMemoryHazardReason(pkgs[wantSafePkg], sizes, byTypes))
		}
	}

	// Within dynstate, string values are carrier-free (REQ-closure-shared-dynamic-state-carrier-free):
	// string projections/returns do not taint pointer receivers or parameters unless boxed into
	// dynamic-carrier slots (any) or mutated directly on the carrier struct.
	numFact := facts["example.com/numunsafe"][0]
	if slices.Contains(numFact.Mutates, "example.com/numunsafe.SharedLabeler") ||
		slices.Contains(numFact.Escapes, "example.com/numunsafe.SharedLabeler") {
		t.Fatalf("numeric-only unsafe.Pointer(&float64) falsely tainted string method SharedLabeler.Name(): %+v", numFact)
	}
	numCS := Compose(meta, facts, "example.com/numunsafe", nil, false, false)
	if numCS.Downgraded != "" {
		t.Fatalf("numunsafe falsely downgraded: %+v", numCS)
	}

	hdrFact := facts["example.com/hdrunsafe"][0]
	if !slices.Contains(hdrFact.ReceiverReadOnly, syntaxutil.FuncKey{Pkg: "example.com/hdrunsafe", Name: "Labeler.Name"}) {
		t.Fatalf("Labeler.Name missing from ReceiverReadOnly: %+v", hdrFact.ReceiverReadOnly)
	}
	hdrCS := Compose(meta, facts, "example.com/hdrunsafe", nil, false, false)
	if hdrCS.Downgraded != "" {
		t.Fatalf("hdrunsafe carrier falsely downgraded in dynstate (enforced at whole-system unsafe boundary instead): %+v", hdrCS)
	}

	midFact := facts["example.com/mid"][0]
	cleanBytesPK := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/mid", Name: "CleanBytesToStringThenEvil"}, Index: 0}
	if !slices.Contains(midFact.ParamLeakFree, cleanBytesPK) {
		t.Fatalf("CleanBytesToStringThenEvil#0 missing from ParamLeakFree despite fresh string(b) copy: %+v", midFact.ParamLeakFree)
	}
	extractPK := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/mid", Name: "ExtractMode"}, Index: 0}
	if !slices.Contains(midFact.ParamLeakFree, extractPK) {
		t.Fatalf("ExtractMode#0 missing from ParamLeakFree: %+v", midFact.ParamLeakFree)
	}
	outerWrapPK := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/mid", Name: "OuterWrapAny"}, Index: 0}
	if !slices.Contains(midFact.ParamLeakFree, outerWrapPK) {
		t.Fatalf("OuterWrapAny#0 missing from ParamLeakFree when returning carrier-free string boxed in any: %+v", midFact.ParamLeakFree)
	}

	if slices.Contains(midFact.ReceiverReadOnly, syntaxutil.FuncKey{Pkg: "example.com/mid", Name: "Holder.BadLeakToAny"}) {
		t.Fatalf("Holder.BadLeakToAny unexpectedly admitted on direct rooted-to-interface conversion: %+v", midFact.ReceiverReadOnly)
	}
	for _, cleanMethod := range []string{
		"Holder.CleanTrim",
		"Holder.CleanFreshBytesMut",
		"Holder.CleanPrivateLog",
		"Holder.BadExportedGlobal",
		"Holder.BadUnexportedExposedGlobal",
		"Holder.BadLeakViaBoxHelper",
		"Holder.BadLeakViaStoreToAny",
	} {
		mk := syntaxutil.FuncKey{Pkg: "example.com/mid", Name: cleanMethod}
		if !slices.Contains(midFact.ReceiverReadOnly, mk) {
			t.Fatalf("%v missing from midFact.ReceiverReadOnly: %+v", mk, midFact.ReceiverReadOnly)
		}
	}

	midCS := Compose(meta, facts, "example.com/mid", nil, false, false)
	for _, c := range midCS.RootCulprits {
		if c.Key != "example.com/mid.ExportedAny" {
			t.Fatalf("mid Compose downgraded unexpected string-only carrier %s: %+v", c.Key, midCS.RootCulprits)
		}
	}
	midSingleSubjCS := Compose(meta, facts, "example.com/mid", nil, true, false)
	if midSingleSubjCS.Downgraded != "" {
		t.Fatalf("midSingleSubjCS falsely downgraded string-only carrier uses: %+v", midSingleSubjCS)
	}
	cleanViewCS := Compose(meta, facts, "example.com/cleanview", nil, false, false)
	if cleanViewCS.Downgraded != "" {
		t.Fatalf("cleanview falsely downgraded SharedClean despite benign string use alongside unrelated evil call: %q", cleanViewCS.Downgraded)
	}
}

func TestCarrierLinksAcrossUnsafePointerSliceStringBuiltinsAndMinMax(t *testing.T) {
	const src = `package carrierlinks

import "unsafe"

var (
	SrcAdd       = []func(){func() {}}
	SrcSlice     = []func(){func() {}}
	SrcSliceData = []func(){func() {}}
	SrcMinA      = &struct{ fn func() }{fn: func() {}}
	SrcMinB      = &struct{ fn func() }{fn: func() {}}
	SrcMaxA       = &struct{ fn func() }{fn: func() {}}
	SrcMaxB       = &struct{ fn func() }{fn: func() {}}
	SrcStrBuf     = struct{ fn func(); b [2]byte }{fn: func() {}, b: [2]byte{'a', 'b'}}
	SrcStrCarrier = struct{ fn func(); s string }{fn: func() {}, s: "ab"}
	LenOnly       = []func(){func() {}}
	SizeOnly      = []func(){func() {}}

	DstAdd       unsafe.Pointer
	DstSlice     []func()
	DstSliceData *func()
	DstMin       unsafe.Pointer
	DstMax       unsafe.Pointer
	DstStrBox    *struct{ fn func(); s string }
	DstStrData   unsafe.Pointer
	DstLenGuard  []func()
	DstSizeGuard uintptr
)

func init() {
	DstAdd = unsafe.Add(unsafe.Pointer(&SrcAdd[0]), 0)
	DstSlice = unsafe.Slice(&SrcSlice[0], len(LenOnly))
	DstSliceData = unsafe.SliceData(SrcSliceData)
	DstMin = unsafe.Pointer(min(uintptr(unsafe.Pointer(SrcMinA)), uintptr(unsafe.Pointer(SrcMinB))))
	DstMax = unsafe.Pointer(max(uintptr(unsafe.Pointer(SrcMaxA)), uintptr(unsafe.Pointer(SrcMaxB))))
	DstStrBox = &struct{ fn func(); s string }{s: unsafe.String(&SrcStrBuf.b[0], len(LenOnly))}
	DstStrData = unsafe.Pointer(unsafe.StringData(SrcStrCarrier.s))
	var dummy func()
	DstLenGuard = unsafe.Slice(&dummy, len(LenOnly))
	DstSizeGuard = unsafe.Sizeof(SizeOnly)
}
`
	pkg := mustTypecheckPackage(t, "example.com/carrierlinks", map[string]string{"links.go": src})
	fact := FactOf(true, pkg)

	wantLinks := []syntaxutil.CarrierLink{
		{From: "example.com/carrierlinks.DstAdd", To: "example.com/carrierlinks.SrcAdd"},
		{From: "example.com/carrierlinks.DstSlice", To: "example.com/carrierlinks.SrcSlice"},
		{From: "example.com/carrierlinks.DstSliceData", To: "example.com/carrierlinks.SrcSliceData"},
		{From: "example.com/carrierlinks.DstMin", To: "example.com/carrierlinks.SrcMinA"},
		{From: "example.com/carrierlinks.DstMin", To: "example.com/carrierlinks.SrcMinB"},
		{From: "example.com/carrierlinks.DstMax", To: "example.com/carrierlinks.SrcMaxA"},
		{From: "example.com/carrierlinks.DstMax", To: "example.com/carrierlinks.SrcMaxB"},
		{From: "example.com/carrierlinks.DstStrBox", To: "example.com/carrierlinks.SrcStrBuf"},
		{From: "example.com/carrierlinks.DstStrData", To: "example.com/carrierlinks.SrcStrCarrier"},
	}
	for _, wl := range wantLinks {
		if !slices.Contains(fact.CarrierLinks, wl) {
			t.Fatalf("missing CarrierLink %+v in %+v", wl, fact.CarrierLinks)
		}
	}
	for _, cl := range fact.CarrierLinks {
		if cl.To == "example.com/carrierlinks.LenOnly" || cl.To == "example.com/carrierlinks.SizeOnly" {
			t.Fatalf("spurious CarrierLink from length/Sizeof operand: %+v", cl)
		}
	}
}

func TestRapidUintptrAndCarrierLinkConfinementProperties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		mode := rapid.IntRange(0, 3).Draw(rt, "mode")
		wrapLocal := rapid.Bool().Draw(rt, "wrapLocal")
		addNumUnsafe := rapid.Bool().Draw(rt, "addNumUnsafe")

		helperPkgSrc := `package helper
import "strings"
func Inspect(s string) int { return len(strings.TrimSpace(s)) }
func KeepPtr(p *int) *int { return p }
`
		var useBody string
		wantDowngrade := false

		switch mode {
		case 0: // Clean stdlib + benign cross-pkg + Sizeof/Offsetof + []byte copy
			if wrapLocal {
				useBody = `s := Shared.Mode(); b := []byte(s); if len(b) > 0 { b[0] = 'Q' }; _ = helper.Inspect(s) + int(unsafe.Sizeof(*Shared))`
			} else {
				useBody = `_ = helper.Inspect(Shared.Mode()) + int(unsafe.Offsetof(Shared.fn))`
			}
		case 1: // Mutable pointer field handout via unproven helper
			useBody = `_ = helper.KeepPtr(Shared.Ptr())`
			wantDowngrade = true
		case 2: // uintptr wrapper handout from receiver method reconstructed via unsafe.Pointer
			useBody = `w := Shared.AddrBox(); p := (*int)(unsafe.Pointer(w.U)); if p != nil { *p = 1 }`
			wantDowngrade = true
		case 3: // Init CarrierLink via min/max or unsafe.Add propagating post-init mutation
			useBody = `MutateLinked()`
			wantDowngrade = true
		}

		numFn := ""
		if addNumUnsafe {
			numFn = `func numBitcast(v float64) uint64 { return *(*uint64)(unsafe.Pointer(&v)) }`
		}

		linkDecls := ""
		var vouches map[string]bool
		if mode == 3 {
			vouches = map[string]bool{"example.com/app.LinkedPtr": true}
			initStmt := `LinkedPtr = unsafe.Add(unsafe.Pointer(Shared), 0)`
			if wrapLocal {
				initStmt = `LinkedPtr = unsafe.Pointer(min(uintptr(unsafe.Pointer(Shared)), uintptr(unsafe.Pointer(Shared))))`
			}
			linkDecls = fmt.Sprintf(`
var LinkedPtr unsafe.Pointer
func init() { %s }
func MutateLinked() { *(*int)(LinkedPtr) = 1 }
`, initStmt)
		}

		appSrc := fmt.Sprintf(`package app

import (
	"unsafe"
	"example.com/helper"
)

type AddrBox struct { U uintptr }

type Box struct {
	fn   func() int
	mode string
	ptr  *int
	addr uintptr
}

func (b *Box) Mode() string { return b.mode }
func (b *Box) Ptr() *int { return b.ptr }
func (b *Box) AddrBox() AddrBox { return AddrBox{U: b.addr} }

var Shared = &Box{fn: func() int { return 7 }, mode: string([]byte{'a', 'b'}), ptr: new(int), addr: 0}

%s
%s

func Exercise() {
	_ = helper.Inspect("lit")
	_ = unsafe.Sizeof( uintptr(0) )
	%s
}
`, numFn, linkDecls, useBody)

		meta, pkgs, facts := mustTypecheckOrderedDAG(rt, []orderedPkgSpec{
			{pkgPath: "example.com/helper", src: helperPkgSrc},
			{pkgPath: "example.com/app", imports: []string{"example.com/helper"}, src: appSrc},
		})
		for _, p := range pkgs {
			fc := newPkgFlowCache(true, p)
			_ = factOfWithCache(true, p, fc, false, nil)
			if fc.missCount != 0 {
				rt.Fatalf("pkgFlowCache incurred %d misses on %s", fc.missCount, p.PkgPath)
			}
		}
		cs := Compose(meta, facts, "example.com/app", vouches, false, false)
		if wantDowngrade && cs.Downgraded == "" {
			rt.Fatalf("mode=%d wrapLocal=%v addNumUnsafe=%v falsely admitted clean ConeState!\napp:\n%s\nappFact:%+v", mode, wrapLocal, addNumUnsafe, appSrc, facts["example.com/app"][0])
		}
		if !wantDowngrade && cs.Downgraded != "" {
			rt.Fatalf("mode=%d wrapLocal=%v addNumUnsafe=%v falsely downgraded (%s)!\napp:\n%s\nappFact:%+v", mode, wrapLocal, addNumUnsafe, cs.Downgraded, appSrc, facts["example.com/app"][0])
		}
	})
}

func TestBuildScopedMemAliasesColliderAndIndirectPointerConfinement(t *testing.T) {
	_, _, memoFacts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
		{
			pkgPath: "example.com/memo",
			src: `package memo

import "sync"

type StrMemo struct {
	once sync.Once
	val  string
	err  error
}

func NewStrMemo() *StrMemo {
	return &StrMemo{}
}

func (m *StrMemo) Get() (string, error) {
	m.once.Do(func() {
		m.val, m.err = string([]byte{'o', 'k'}), nil
	})
	return m.val, m.err
}

type UintptrMemo struct {
	once sync.Once
	addr uintptr
	err  error
}

func NewUintptrMemo() *UintptrMemo {
	return &UintptrMemo{}
}

func (m *UintptrMemo) Get() (uintptr, error) {
	m.once.Do(func() {
		m.addr, m.err = 1, nil
	})
	return m.addr, m.err
}
`,
		},
	})
	memoFact := memoFacts["example.com/memo"][0]
	for _, omt := range memoFact.OnceMemoTypes {
		if omt.Type.Name == "UintptrMemo" {
			t.Fatalf("UintptrMemo falsely admitted into OnceMemoTypes: %+v", omt)
		}
	}
	if len(memoFact.OnceMemoTypes) != 1 || memoFact.OnceMemoTypes[0].Type.Name != "StrMemo" {
		t.Fatalf("StrMemo missing in OnceMemoTypes: %+v", memoFact.OnceMemoTypes)
	}

	// Directional value returns (`results[i].verdict = v.makeVerdict()`) and
	// multi-arg slice+error tuple returns (`before, err := v.observeInputs(records, results)`)
	// must NOT create collider memory-alias stars from `results` back into `v` or `records`
	// that would falsely attribute unrelated sibling field stores (`results[i].err = ErrSentinel`)
	// to method calls on `v` (`t := v.tag; t.begin()`), while genuine common-ancestor views
	// (`view := idSlice(local); view[0] = SharedBoxView`) and indirect deref stores
	// (`p := &s2; *p = s1; s1[0] = SharedBoxPtr` and init-closure `*p = s1`) MUST propagate!
	noRevMeta, noRevPkgs, noRevFacts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
		{
			pkgPath: "example.com/norevtrace",
			src: `package norevtrace

func Emit(s string) {
	_ = len(s)
}
`,
		},
		{
			pkgPath: "example.com/norevmem",
			imports: []string{"example.com/norevtrace"},
			src: `package norevmem

import (
	"errors"
	"fmt"

	"example.com/norevtrace"
)

var (
	ErrSentinel          = errors.New("sentinel")
	SharedBoxView        = &boxErr{}
	SharedBoxPtr         = &boxErr{}
	SharedBoxInitClosure = &boxErr{}
	initLinkFn           func()
	initTouchFn          func()
)

type State struct {
	Digest string
	OK     bool
}

type Verdict struct {
	Reason string
}

type record struct {
	pkg string
}

type item struct {
	verdict Verdict
	before  State
	after   State
	err     error
}

type sessTag struct {
	dir string
	n   int
}

func (s *sessTag) begin() {
	s.n++
	norevtrace.Emit(s.dir)
}

type Snap struct {
	tag sessTag
	dir string
}

func (v *Snap) makeVerdict() Verdict {
	return Verdict{Reason: v.dir}
}

func (v *Snap) observeInputs(records []record, results []item) ([]State, error) {
	out := make([]State, len(records))
	for i := range records {
		if results[i].verdict.Reason == "" {
			out[i] = State{Digest: records[i].pkg + v.dir, OK: true}
		}
	}
	return out, nil
}

func (v *Snap) Check(records []record) (results []item, opErr error) {
	t := v.tag
	t.begin()
	results = make([]item, len(records))
	before, err := v.observeInputs(records, results)
	if err != nil {
		return nil, err
	}
	for i := range results {
		results[i].err = fmt.Errorf("%w: %s", ErrSentinel, v.dir)
		results[i].verdict = v.makeVerdict()
	}
	after, err := v.observeInputs(records, results)
	if err != nil {
		return nil, err
	}
	for i := range records {
		r := &results[i]
		r.before, r.after = before[i], after[i]
	}
	return results, nil
}

type boxErr struct {
	err error
	n   int
}

func (b *boxErr) touch() {
	b.n++
}

func idSlice(in []*boxErr) []*boxErr {
	return in
}

func MutateViaViewAndPtr() {
	local := []*boxErr{{}}
	view := idSlice(local)
	view[0] = SharedBoxView
	local[0].touch()

	s1 := []*boxErr{{}}
	var s2 []*boxErr
	p := &s2
	*p = s1
	s1[0] = SharedBoxPtr
	s2[0].touch()
}

func LeakViaPtrToSlice(root []int) [][]int {
	s1 := make([][]int, 1)
	var s2 [][]int
	p := &s2
	*p = s1
	s1[0] = root
	return s2
}

func init() {
	s1 := []*boxErr{{}}
	var s2 []*boxErr
	p := &s2
	initLinkFn = func() {
		*p = s1
	}
	s1[0] = SharedBoxInitClosure
	initTouchFn = func() {
		s2[0].touch()
	}
}
`,
		},
	})
	noRevPkg := noRevPkgs["example.com/norevmem"]
	var checkFD *ast.FuncDecl
	for _, decl := range noRevPkg.Syntax[0].Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name != nil && fd.Name.Name == "Check" {
			checkFD = fd
			break
		}
	}
	checkBody := flowir.LowerFunc(noRevPkg.TypesInfo, noRevPkg.Types, checkFD)
	checkScopedAdj := flowir.BuildScopedMemAliases(checkBody, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut)
	if checkScopedAdj[checkBody.Results[0]][checkBody.Recv] || checkScopedAdj[checkBody.Results[0]][checkBody.Params[0]] {
		t.Fatalf("BuildScopedMemAliases created collider edge from results to v or records: %+v", checkScopedAdj)
	}
	noRevFact := noRevFacts["example.com/norevmem"][0]
	if slices.Contains(noRevFact.ParamLeakFree, syntaxutil.ParamKey{
		Func:  syntaxutil.FuncKey{Pkg: "example.com/norevmem", Name: "LeakViaPtrToSlice"},
		Index: 0,
	}) {
		t.Fatalf("LeakViaPtrToSlice#0 falsely marked ParamLeakFree without interiorWrite closure: %+v", noRevFact.ParamLeakFree)
	}
	noRevCS := Compose(noRevMeta, noRevFacts, "example.com/norevmem", nil, false, false)
	noRevCulprits := map[string]CulpritVerb{}
	for _, c := range noRevCS.RootCulprits {
		noRevCulprits[c.Key] = c.Verb
	}
	if _, bad := noRevCulprits["example.com/norevmem.ErrSentinel"]; bad {
		t.Fatalf("collider tuple call falsely back-aliased ErrSentinel onto t.begin(): %+v (fact=%+v)", noRevCS.RootCulprits, noRevFact)
	}
	for _, wantBad := range []string{
		"example.com/norevmem.SharedBoxView",
		"example.com/norevmem.SharedBoxPtr",
		"example.com/norevmem.SharedBoxInitClosure",
	} {
		if verb, ok := noRevCulprits[wantBad]; !ok || verb != CulpritMutated {
			t.Fatalf("common-ancestor memory sharing missed CulpritMutated on %s: got ok=%v verb=%v culprits=%+v", wantBad, ok, verb, noRevCS.RootCulprits)
		}
	}

	sinkMeta, sinkPkgs, sinkFacts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
		{
			pkgPath: "example.com/sinkleaf",
			src: `package sinkleaf

type ptrHolder struct {
	fn  func()
	ptr *int
}

var (
	escapedPtrMatrix [][]*int
	escapedPtrRow    []*int
)

func LeakViaIndirectCopy(h *ptrHolder) {
	inner := make([]*int, 1)
	s2 := make([][]*int, 1)
	p := make([]*[][]*int, 1)
	p[0] = &s2
	src := [][]*int{inner}
	copy(*p[0], src)
	h.ptr = inner[0]
	escapedPtrMatrix = s2
}

func CleanColliderPtr(h *ptrHolder) {
	clean := make([]*int, 1)
	dirty := make([]*int, 1)
	h.ptr = dirty[0]
	collider := make([][]*int, 2)
	collider[0] = clean
	collider[1] = dirty
	escapedPtrRow = clean
}

func RetainLocalPtr(h *ptrHolder) {
	local := make([]*int, 1)
	h.ptr = local[0]
}

func SneakPtrArraySlice(p *int) *int {
	var arr [1]*int
	copy(arr[:], []*int{p})
	return arr[0]
}
`,
		},
		{
			pkgPath: "example.com/strorigin",
			src: `package strorigin

type cell struct {
	fn func() int
	n  int
}

func (c *cell) inc() {
	c.n++
}

type wrap struct {
	child *cell
}

var (
	SharedPair         = &cell{}
	SharedMethodVal    = &cell{}
	SharedIndirectCopy = &cell{}
)

func pair() ([]*cell, []*cell) {
	s := make([]*cell, 1)
	return s, s
}

func MutatePairAndMethodVal() {
	a, b := pair()
	a[0] = SharedPair
	b[0].inc()

	w := &wrap{child: SharedMethodVal}
	fn := w.child.inc
	fn()
}

func LeakPair(x *cell) []*cell {
	a, b := pair()
	a[0] = x
	return b
}

func init() {
	s1 := make([][]*cell, 1)
	p := make([]*[][]*cell, 1)
	inner := make([]*cell, 1)
	_ = func() {
		p[0] = &s1
		src := [][]*cell{inner}
		copy(*p[0], src)
	}
	_ = func() {
		inner[0].inc()
	}
	s1[0] = make([]*cell, 1)
	s1[0][0] = SharedIndirectCopy
}
`,
		},
	})

	leafPkg := sinkPkgs["example.com/sinkleaf"]
	findBodyAndLocals := func(fnName string) (*flowir.Body, map[string]*types.Var) {
		for _, decl := range leafPkg.Syntax[0].Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name != nil && fd.Name.Name == fnName {
				b := flowir.LowerFunc(leafPkg.TypesInfo, leafPkg.Types, fd)
				vars := map[string]*types.Var{}
				for _, obj := range leafPkg.TypesInfo.Defs {
					if v, ok := obj.(*types.Var); ok && v != nil && b.OwnsVar(v) {
						vars[v.Name()] = v
					}
				}
				return b, vars
			}
		}
		t.Fatalf("missing FuncDecl %s in sinkleaf", fnName)
		return nil, nil
	}
	copyBody, copyVars := findBodyAndLocals("LeakViaIndirectCopy")
	copyAdj := flowir.BuildScopedMemAliases(copyBody, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut)
	if !copyAdj[copyVars["inner"]][copyVars["s2"]] {
		t.Fatalf("BuildScopedMemAliases failed to link inner <-> s2 across indirect copy(*p[0], src): %+v", copyAdj)
	}
	colliderBody, colliderVars := findBodyAndLocals("CleanColliderPtr")
	colliderAdj := flowir.BuildScopedMemAliases(colliderBody, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut)
	if colliderAdj[colliderVars["clean"]][colliderVars["dirty"]] {
		t.Fatalf("BuildScopedMemAliases falsely linked clean <-> dirty across collider container: %+v", colliderAdj)
	}

	leafFact := sinkFacts["example.com/sinkleaf"][0]
	if slices.Contains(leafFact.ParamRetentionFree, syntaxutil.ParamKey{
		Func:  syntaxutil.FuncKey{Pkg: "example.com/sinkleaf", Name: "LeakViaIndirectCopy"},
		Index: 0,
	}) {
		t.Fatalf("LeakViaIndirectCopy#0 falsely marked ParamRetentionFree despite copy(*p[0], src): %+v", leafFact.ParamRetentionFree)
	}
	if !slices.Contains(leafFact.ParamRetentionFree, syntaxutil.ParamKey{
		Func:  syntaxutil.FuncKey{Pkg: "example.com/sinkleaf", Name: "RetainLocalPtr"},
		Index: 0,
	}) {
		t.Fatalf("RetainLocalPtr#0 missing from ParamRetentionFree: %+v", leafFact.ParamRetentionFree)
	}
	if slices.Contains(leafFact.ParamLeakFree, syntaxutil.ParamKey{
		Func:  syntaxutil.FuncKey{Pkg: "example.com/sinkleaf", Name: "SneakPtrArraySlice"},
		Index: 0,
	}) {
		t.Fatalf("SneakPtrArraySlice#0 falsely proven ParamLeakFree: %+v", leafFact.ParamLeakFree)
	}

	originFact := sinkFacts["example.com/strorigin"][0]
	if slices.Contains(originFact.ParamLeakFree, syntaxutil.ParamKey{
		Func:  syntaxutil.FuncKey{Pkg: "example.com/strorigin", Name: "LeakPair"},
		Index: 0,
	}) {
		t.Fatalf("LeakPair#0 falsely marked ParamLeakFree: %+v", originFact.ParamLeakFree)
	}
	originCS := Compose(sinkMeta, sinkFacts, "example.com/strorigin", nil, true, false)
	originCulprits := map[string]CulpritVerb{}
	for _, c := range originCS.RootCulprits {
		originCulprits[c.Key] = c.Verb
	}
	for _, wantMut := range []string{
		"example.com/strorigin.SharedPair",
		"example.com/strorigin.SharedMethodVal",
		"example.com/strorigin.SharedIndirectCopy",
	} {
		if v, ok := originCulprits[wantMut]; !ok || v != CulpritMutated {
			t.Fatalf("expected CulpritMutated on %s, got ok=%v verb=%v culprits=%+v", wantMut, ok, v, originCS.RootCulprits)
		}
	}

	malformedLinkMeta := []GraphPackage{
		{ImportPath: "example.com/clean", PkgPath: "example.com/clean", Class: MutableLocalPackage},
		{ImportPath: "example.com/badimp", PkgPath: "example.com/badimp", Imports: []string{"example.com/clean"}, Class: MutableLocalPackage},
	}
	malformedLinkFacts := map[string][]Fact{
		"example.com/clean": {
			{
				Declares:          []string{"example.com/clean.V"},
				SingleSubjectVars: []string{"example.com/clean.V"},
			},
		},
		"example.com/badimp": {
			{
				CarrierLinks: []syntaxutil.CarrierLink{{From: "example.com/clean.V", To: ""}},
			},
		},
	}
	malformedLinkCS := Compose(malformedLinkMeta, malformedLinkFacts, "example.com/badimp", nil, true, false)
	if !slices.ContainsFunc(malformedLinkCS.RootCulprits, func(c Culprit) bool {
		return c.Key == "example.com/clean.V"
	}) {
		t.Fatalf("Compose failed to mark foreign endpoint of malformed CarrierLinks: %+v", malformedLinkCS)
	}
	if NonVouchDischargedVars(malformedLinkMeta, malformedLinkFacts, true)["example.com/clean.V"] {
		t.Fatalf("NonVouchDischargedVars discharged foreign endpoint of malformed CarrierLinks")
	}
}

func FuzzDynstateFlowIRUnifiedPasses(f *testing.F) {
	seeds := []string{
		`package p; var C = []func(){}; func init() { var s []func(); p := &s; *p = C }`,
		`package p; type B struct{ c []func(); n int }; var C = []func(){}; func init() { b := &B{c: C}; b.n++ }`,
		`package p; var M = map[any]int{"k": 1}; func F() { M["k"] += 2 }`,
		`package p; func Gen[T any](x T) func() T { return func() T { return x } }`,
		`package p; const ( A = iota; B ); var X, Y = 1, 2; func Broken() { nil := 1; _ = nil }`,
		`package p; type V struct{ f func() }; var X = V{}; func F() (out *V) { out = &X; defer func() { _ = recover() }(); panic(1) }`,
		`package p; import "unsafe"; type W struct{ u uintptr; f func() }; var X = &W{}; func F() uintptr { return unsafe.Sizeof(*X) + unsafe.Offsetof(X.u) }`,
		`package p; import "unsafe"; type H struct{ s string; f func() }; var X = &H{}; func F() { s := X.s; if len(s) > 0 { *unsafe.StringData(s) = 'a' } }`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 16<<10 {
			return
		}
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, "fuzz.go", src, parser.ParseComments)
		if file == nil {
			return
		}
		info := &types.Info{
			Types:      make(map[ast.Expr]types.TypeAndValue),
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Implicits:  make(map[ast.Node]types.Object),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
			Scopes:     make(map[ast.Node]*types.Scope),
			Instances:  make(map[*ast.Ident]types.Instance),
		}
		var typeErr error
		tpkg, err := (&types.Config{
			Error:    func(e error) { typeErr = e },
			Importer: importer.Default(),
		}).Check("example.com/fuzz", fset, []*ast.File{file}, info)
		if tpkg == nil {
			return
		}
		pkg := &packages.Package{
			ID:        "example.com/fuzz",
			Name:      file.Name.Name,
			PkgPath:   "example.com/fuzz",
			Fset:      fset,
			Syntax:    []*ast.File{file},
			Types:     tpkg,
			TypesInfo: info,
		}
		hooks := &syntaxutil.ExplainHookSet{
			Site:             func(*packages.Package, string, string, syntaxutil.FuncKey, bool, token.Pos) {},
			ExportedSeamSite: func(*packages.Package, syntaxutil.FuncKey, string, token.Pos) {},
			Store:            func(*packages.Package, string, token.Pos) {},
			Deferral:         func(*packages.Package, byte, string, syntaxutil.DeferralResolvent, token.Pos) {},
			Refusal:          func(*packages.Package, string, ast.Expr, string) {},
		}
		fc := newPkgFlowCache(true, pkg)
		_ = factOfWithCache(true, pkg, fc, false, hooks)
		if parseErr == nil && err == nil && typeErr == nil && fc != nil && fc.missCount != 0 {
			t.Fatalf("well-typed package incurred %d pkgFlowCache misses:\n%s", fc.missCount, src)
		}
	})
}
