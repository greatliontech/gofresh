package dynstate

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"pgregory.net/rapid"
)

type namedSourceFile struct {
	name string
	src  string
}

type testFataler interface {
	Helper()
	Fatalf(format string, args ...any)
}

func mustTypecheckOrderedPackage(t testFataler, pkgPath string, files []namedSourceFile) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	syntax := make([]*ast.File, 0, len(files))
	for _, nf := range files {
		f, err := parser.ParseFile(fset, nf.name, nf.src, parser.ParseComments)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v\n%s", nf.name, err, nf.src)
		}
		syntax = append(syntax, f)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Instances:  make(map[*ast.Ident]types.Instance),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Scopes:     make(map[ast.Node]*types.Scope),
	}
	conf := types.Config{Importer: importer.Default()}
	typesPkg, err := conf.Check(pkgPath, fset, syntax, info)
	if err != nil {
		var allSrc strings.Builder
		for _, nf := range files {
			allSrc.WriteString("// --- " + nf.name + " ---\n" + nf.src + "\n")
		}
		t.Fatalf("types.Check(%s): %v\n%s", pkgPath, err, allSrc.String())
	}
	return &packages.Package{
		ID:        pkgPath,
		PkgPath:   pkgPath,
		Name:      typesPkg.Name(),
		Fset:      fset,
		Syntax:    syntax,
		Types:     typesPkg,
		TypesInfo: info,
		Imports:   syntheticPackageImports(typesPkg, nil),
		Module:    &packages.Module{Path: "example.com/mod"},
	}
}

func composeSinglePkg(pkgPath string, fact Fact, singleSubject, packageProcess bool) ConeState {
	meta := []GraphPackage{{
		ImportPath: pkgPath,
		PkgPath:    pkgPath,
		Class:      MutableLocalPackage,
	}}
	allFacts := map[string][]Fact{
		pkgPath: {fact},
	}
	return Compose(meta, allFacts, pkgPath, nil, singleSubject, packageProcess)
}

func assertFactCanonicalAndValid(t testFataler, fact Fact) {
	t.Helper()
	checkSortedStrings := func(label string, xs []string) {
		if !slices.IsSorted(xs) {
			t.Fatalf("%s not sorted: %+v", label, xs)
		}
		for i, s := range xs {
			if !syntaxutil.ValidFactKey(s) {
				t.Fatalf("%s[%d] invalid key %q", label, i, s)
			}
			if i > 0 && xs[i-1] == s {
				t.Fatalf("%s duplicate key %q", label, s)
			}
		}
	}
	checkSortedStrings("Declares", fact.Declares)
	checkSortedStrings("Mutates", fact.Mutates)
	checkSortedStrings("Escapes", fact.Escapes)
	checkSortedStrings("EnvCarrying", fact.EnvCarrying)
	checkSortedStrings("EnvCallable", fact.EnvCallable)
	checkSortedStrings("SingleSubjectVars", fact.SingleSubjectVars)
	checkSortedStrings("PoolDischarges", fact.PoolDischarges)
	checkSortedStrings("PoolMutates", fact.PoolMutates)
	checkSortedStrings("PoolEscapes", fact.PoolEscapes)
	checkSortedStrings("HarnessDischarges", fact.HarnessDischarges)

	for i, pu := range fact.ParamUses {
		if !pu.Valid() {
			t.Fatalf("ParamUses[%d] invalid: %+v", i, pu)
		}
		if i > 0 && fact.ParamUses[i-1].Compare(pu) >= 0 {
			t.Fatalf("ParamUses not strictly sorted at %d: %+v", i, fact.ParamUses)
		}
	}
	for i, pu := range fact.InitParamUses {
		if !pu.Valid() || !pu.Func.IsZero() {
			t.Fatalf("InitParamUses[%d] invalid or has non-zero Func: %+v", i, pu)
		}
		if i > 0 && fact.InitParamUses[i-1].Compare(pu) >= 0 {
			t.Fatalf("InitParamUses not strictly sorted at %d: %+v", i, fact.InitParamUses)
		}
	}
	for i, au := range fact.AttributedUses {
		if !au.Valid() {
			t.Fatalf("AttributedUses[%d] invalid: %+v", i, au)
		}
		if i > 0 && fact.AttributedUses[i-1].Compare(au) >= 0 {
			t.Fatalf("AttributedUses not strictly sorted at %d: %+v", i, fact.AttributedUses)
		}
	}
	for i, au := range fact.PoolAttributedUses {
		if !au.Valid() {
			t.Fatalf("PoolAttributedUses[%d] invalid: %+v", i, au)
		}
		if i > 0 && fact.PoolAttributedUses[i-1].Compare(au) >= 0 {
			t.Fatalf("PoolAttributedUses not strictly sorted at %d: %+v", i, fact.PoolAttributedUses)
		}
	}

	for i, pk := range fact.ParamLeakFree {
		if !pk.Valid() {
			t.Fatalf("ParamLeakFree[%d] invalid: %+v", i, pk)
		}
		if i > 0 && fact.ParamLeakFree[i-1].Compare(pk) >= 0 {
			t.Fatalf("ParamLeakFree not strictly sorted at %d: %+v", i, fact.ParamLeakFree)
		}
	}
	for i, pk := range fact.ParamRetentionFree {
		if !pk.Valid() {
			t.Fatalf("ParamRetentionFree[%d] invalid: %+v", i, pk)
		}
		if i > 0 && fact.ParamRetentionFree[i-1].Compare(pk) >= 0 {
			t.Fatalf("ParamRetentionFree not strictly sorted at %d: %+v", i, fact.ParamRetentionFree)
		}
	}
	for i, fk := range fact.ReceiverReadOnly {
		if !fk.Valid() {
			t.Fatalf("ReceiverReadOnly[%d] invalid: %+v", i, fk)
		}
		if i > 0 && fact.ReceiverReadOnly[i-1].Compare(fk) >= 0 {
			t.Fatalf("ReceiverReadOnly not strictly sorted at %d: %+v", i, fact.ReceiverReadOnly)
		}
	}
	for i, fk := range fact.ReturnEnvFree {
		if !fk.Valid() {
			t.Fatalf("ReturnEnvFree[%d] invalid: %+v", i, fk)
		}
		if i > 0 && fact.ReturnEnvFree[i-1].Compare(fk) >= 0 {
			t.Fatalf("ReturnEnvFree not strictly sorted at %d: %+v", i, fact.ReturnEnvFree)
		}
	}
	for i, pk := range fact.ParamInsertionFree {
		if !pk.Valid() {
			t.Fatalf("ParamInsertionFree[%d] invalid: %+v", i, pk)
		}
		if i > 0 && fact.ParamInsertionFree[i-1].Compare(pk) >= 0 {
			t.Fatalf("ParamInsertionFree not strictly sorted at %d: %+v", i, fact.ParamInsertionFree)
		}
	}
	envCarryingSet := make(map[string]bool, len(fact.EnvCarrying))
	for _, k := range fact.EnvCarrying {
		envCarryingSet[k] = true
	}
	for i, u := range fact.EnvCarryingFns {
		if !u.Valid() || !envCarryingSet[u.Key] {
			t.Fatalf("EnvCarryingFns[%d] invalid or missing from EnvCarrying: %+v", i, u)
		}
		if i > 0 && fact.EnvCarryingFns[i-1].Compare(u) >= 0 {
			t.Fatalf("EnvCarryingFns not strictly sorted at %d: %+v", i, fact.EnvCarryingFns)
		}
	}
	unattrEnvCalls := map[syntaxutil.EnvCallUse]bool{}
	for _, u := range fact.EnvCallUses {
		if u.Func.IsZero() {
			unattrEnvCalls[u] = true
		}
	}
	for i, u := range fact.EnvCallUses {
		if !u.Valid() {
			t.Fatalf("EnvCallUses[%d] invalid: %+v", i, u)
		}
		if !u.Func.IsZero() && unattrEnvCalls[syntaxutil.EnvCallUse{Key: u.Key, Callee: u.Callee}] {
			t.Fatalf("EnvCallUses[%d] redundant attributed entry alongside unattributed pair: %+v", i, u)
		}
		if i > 0 && fact.EnvCallUses[i-1].Compare(u) >= 0 {
			t.Fatalf("EnvCallUses not strictly sorted at %d: %+v", i, fact.EnvCallUses)
		}
	}
	for i, cl := range fact.CarrierLinks {
		if !cl.Valid() {
			t.Fatalf("CarrierLinks[%d] invalid: %+v", i, cl)
		}
		if i > 0 && fact.CarrierLinks[i-1].Compare(cl) >= 0 {
			t.Fatalf("CarrierLinks not strictly sorted at %d: %+v", i, fact.CarrierLinks)
		}
	}
}

func TestConfinementAndRegistrationMatrix(t *testing.T) {
	const pkgPath = "example.com/matrix"

	t.Run("parameter_leakfree_and_retention_boundaries", func(t *testing.T) {
		pkg := mustTypecheckOrderedPackage(t, pkgPath, []namedSourceFile{{
			name: "params.go",
			src: `package matrix

import "sync"

var globalSink []int

func CleanScalarAndRange(s []int, m map[string]int) int {
	total := len(s) + cap(s) + len(m)
	if v, ok := m["a"]; ok {
		total += v
	}
	for i, x := range s {
		total += i + x
	}
	return total
}

func CleanNewType(s []int) *[]int {
	_ = len(s)
	return new([]int)
}

func DirtyNewExpr(s []int) *[]int {
	return new(s)
}

func DirtySliceWrite(s []int) {
	s[0] = 7
}

func RetentionCleanMapWrite(m map[string]int) {
	m["const"] = globalSink[0]
}

func RetentionDirtyExternalWrite(m map[string][]int) {
	m["ext"] = globalSink
}

func DirtyGoroutine(s []int) {
	go func() { _ = len(s) }()
}

func CleanMutexLock(mu *sync.Mutex) {
	mu.Lock()
	mu.Unlock()
}

func DirtyMutexCopy(mu *sync.Mutex) {
	cp := *mu
	_ = cp
}
`,
		}})
		fact := FactOf(true, pkg)
		assertFactCanonicalAndValid(t, fact)

		pKey := func(fn string, idx int) syntaxutil.ParamKey {
			return syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: pkgPath, Name: fn}, Index: idx}
		}
		cases := []struct {
			fn            string
			idx           int
			wantLeakFree  bool
			wantRetention bool
		}{
			{"CleanScalarAndRange", 0, true, true},
			{"CleanScalarAndRange", 1, true, true},
			{"CleanNewType", 0, true, true},
			{"DirtyNewExpr", 0, false, false},
			{"DirtySliceWrite", 0, false, true},
			{"RetentionCleanMapWrite", 0, false, true},
			{"RetentionDirtyExternalWrite", 0, false, false},
			{"DirtyGoroutine", 0, false, false},
			{"CleanMutexLock", 0, true, true},
			{"DirtyMutexCopy", 0, false, false},
		}
		for _, tc := range cases {
			pk := pKey(tc.fn, tc.idx)
			gotLF := slices.Contains(fact.ParamLeakFree, pk)
			gotRet := gotLF || slices.Contains(fact.ParamRetentionFree, pk)
			if gotLF != tc.wantLeakFree || gotRet != tc.wantRetention {
				t.Fatalf("%s[%d]: got (leakFree=%v, retention=%v), want (%v, %v)",
					tc.fn, tc.idx, gotLF, gotRet, tc.wantLeakFree, tc.wantRetention)
			}
		}
	})

	t.Run("registration_origins_settled_data_and_mutable_data_global_guard", func(t *testing.T) {
		cases := []struct {
			name            string
			src             string
			targetVar       string
			wantEnvCarrying bool
		}{
			{
				name: "clean_settled_unexported_slice_in_closure",
				src: `package matrix
var settled = []int{10, 20}
var Hook func() int
func init() {
	Hook = func() int { return settled[0] }
}
`,
				targetVar:       "example.com/matrix.Hook",
				wantEnvCarrying: false,
			},
			{
				name: "dirty_mutable_data_global_aliased_in_init_rejected",
				src: `package matrix
var DirtyDataBuf = []int{10}
func MutateData() { DirtyDataBuf[0]++ }
var Hook func() int
func init() {
	s := DirtyDataBuf
	Hook = func() int { return s[0] }
}
`,
				targetVar:       "example.com/matrix.Hook",
				wantEnvCarrying: true,
			},
			{
				name: "clean_carrier_alias_len_only_admitted",
				src: `package matrix
var CleanMap = map[string]func() int{}
var SizeHook func() int
func init() {
	m := CleanMap
	SizeHook = func() int { return len(m) }
}
`,
				targetVar:       "example.com/matrix.SizeHook",
				wantEnvCarrying: false,
			},
			{
				name: "carrier_alias_extracting_signature_rejected",
				src: `package matrix
func makeStateful() func() int {
	n := 0
	return func() int { n++; return n }
}
var DirtyMap = map[string]func() int{"k": makeStateful()}
var ExtractHook func() int
func init() {
	m := DirtyMap
	ExtractHook = func() int { return m["k"]() }
}
`,
				targetVar:       "example.com/matrix.ExtractHook",
				wantEnvCarrying: true,
			},
			{
				name: "settled_multi_carrier_embedding_rejected",
				src: `package matrix
type holder struct{ xs []int; fn func() int }
func pure() int { return 1 }
var shared = []int{1, 2}
var H1 = holder{xs: shared, fn: pure}
var H2 = holder{xs: shared, fn: pure}
func makeClosure() func() int {
	xs := shared
	return func() int { return xs[0] }
}
var Hook = makeClosure()
`,
				targetVar:       "example.com/matrix.Hook",
				wantEnvCarrying: true,
			},
			{
				name: "settled_single_subject_directive_carrier_rejected",
				src: `package matrix
type holder struct{ xs []int; fn func() int }
func pure() int { return 1 }
var shared = []int{1, 2}
//gofresh:single-subject
var H1 = holder{xs: shared, fn: pure}
func makeClosure() func() int {
	xs := shared
	return func() int { return xs[0] }
}
var Hook = makeClosure()
`,
				targetVar:       "example.com/matrix.Hook",
				wantEnvCarrying: true,
			},
			{
				name: "spare_capacity_append_laundering_rejected",
				src: `package matrix
func pure() int { return 1 }
func makeDirty() func() int {
	c := 0
	return func() int { c++; return c }
}
var Hook func() int
func init() {
	buf := make([]func() int, 1)
	buf[0] = pure
	_ = append(buf[:0], makeDirty())
	Hook = buf[0]
}
`,
				targetVar:       "example.com/matrix.Hook",
				wantEnvCarrying: true,
			},
			{
				name: "fresh_sibling_value_field_does_not_taint_root_carrier",
				src: `package matrix
type pair struct {
	carrier []func() int
	other   func() int
}
func makeDirty() func() int {
	c := 0
	return func() int { c++; return c }
}
var Target []func() int
func init() {
	p := pair{carrier: Target}
	p.other = makeDirty()
	_ = p
}
`,
				targetVar:       "example.com/matrix.Target",
				wantEnvCarrying: false,
			},
			{
				name: "nested_pointer_field_deref_taints_interior_carrier",
				src: `package matrix
type ptrBox struct {
	p *func() int
}
func makeDirty() func() int {
	c := 0
	return func() int { c++; return c }
}
var Target func() int
func init() {
	b := ptrBox{p: &Target}
	*b.p = makeDirty()
}
`,
				targetVar:       "example.com/matrix.Target",
				wantEnvCarrying: true,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pkg := mustTypecheckOrderedPackage(t, pkgPath, []namedSourceFile{{name: "case.go", src: tc.src}})
				fact := FactOf(true, pkg)
				assertFactCanonicalAndValid(t, fact)
				allFacts := map[string][]Fact{pkgPath: {fact}}
				res := NewDeferralResolution(allFacts, func(Fact) {})
				gotEnv := slices.Contains(fact.EnvCarrying, tc.targetVar)
				for _, u := range fact.EnvCallUses {
					if u.Key == tc.targetVar && !res.EnvFreeResolved[u.Callee] {
						gotEnv = true
					}
				}
				if gotEnv != tc.wantEnvCarrying {
					t.Fatalf("%s: EnvCarrying(%s) = %v, want %v (fact.EnvCarrying=%v, EnvCallUses=%v)",
						tc.name, tc.targetVar, gotEnv, tc.wantEnvCarrying, fact.EnvCarrying, fact.EnvCallUses)
				}
			})
		}
	})
}

// stateDriftScenario pairs a generated valid Go package source with an exact
// operational two-invocation state-drift simulation for Subject() and Mutator().
type stateDriftScenario struct {
	src                string
	selfDrifts         bool
	crossSubjectDrifts bool
}

func generateStateDriftScenario(rt *rapid.T) stateDriftScenario {
	// Compositional choices covering clean patterns and adversarial laundering paths.
	kind := rapid.IntRange(0, 13).Draw(rt, "scenarioKind")
	baseConst := rapid.IntRange(1, 50).Draw(rt, "baseConst")

	switch kind {
	case 0:
		// Pure named function registration + read-only helper.
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
func pureFn() int { return %d }
var Hook func() int = pureFn
func Subject() int { return Hook() }
func Mutator() int { return Hook() }
`, baseConst),
			selfDrifts:         false,
			crossSubjectDrifts: false,
		}

	case 1:
		// Environment-free closure over settled unexported data slice + slices-like fresh copy.
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
var settled = []int{%d, %d}
var Hook func() int
func init() {
	local := settled[0]
	Hook = func() int { return local + settled[1] }
}
func Subject() int { return Hook() }
func Mutator() int { return len(settled) }
`, baseConst, baseConst+3),
			selfDrifts:         false,
			crossSubjectDrifts: false,
		}

	case 2:
		// Clean unexported initOnly helper with non-spread variadic registration.
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
func pureA() int { return %d }
func pureB() int { return 2 }
var Hooks []func() int
func regAll(fs ...func() int) {
	Hooks = append(Hooks, func() int { return fs[0]() + fs[1]() })
}
func init() {
	regAll(pureA, pureB)
}
func Subject() int { return len(Hooks) }
func Mutator() int { return len(Hooks) }
`, baseConst),
			selfDrifts:         false,
			crossSubjectDrifts: false,
		}

	case 3:
		//Clean constructor returning closure over caller-judged parameter.
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
func makeAdder(delta int) func() int {
	return func() int { return delta + %d }
}
var Hook = makeAdder(5)
func Subject() int { return Hook() }
func Mutator() int { return Hook() }
`, baseConst),
			selfDrifts:         false,
			crossSubjectDrifts: false,
		}

	case 4:
		// Direct stateful closure capturing mutated counter -> self-drifts on repeated Subject() calls!
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
var Hook func() int
func init() {
	counter := %d
	Hook = func() int {
		counter++
		return counter
	}
}
func Subject() int { return Hook() }
func Mutator() int { return 0 }
`, baseConst),
			selfDrifts:         true,
			crossSubjectDrifts: true,
		}

	case 5:
		// Sibling closure mutating shared local variable captured by Hook -> self/cross drift!
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
var Hook func() int
var Stepper func()
func init() {
	shared := %d
	Hook = func() int { return shared }
	Stepper = func() { shared++ }
}
func Subject() int { return Hook() }
func Mutator() int { Stepper(); return 1 }
`, baseConst),
			selfDrifts:         false,
			crossSubjectDrifts: true,
		}

	case 6:
		// Mutable data-only slice global aliased in init (`s := dataBuf`), mutated by Mutator!
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
var dataBuf = []int{%d}
var Hook func() int
func init() {
	s := dataBuf
	Hook = func() int { return s[0] }
}
func Subject() int { return Hook() }
func Mutator() int { dataBuf[0]++; return dataBuf[0] }
`, baseConst),
			selfDrifts:         false,
			crossSubjectDrifts: true,
		}

	case 7:
		// Spare-capacity append onto local slice planting stateful closure into Hook!
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
func pureFn() int { return %d }
func dirtyFn() func() int {
	n := 0
	return func() int { n++; return n }
}
var Hook func() int
func init() {
	s := make([]func() int, 1)
	s[0] = pureFn
	_ = append(s[:0], dirtyFn())
	Hook = s[0]
}
func Subject() int { return Hook() }
func Mutator() int { return 0 }
`, baseConst),
			selfDrifts:         true,
			crossSubjectDrifts: true,
		}

	case 8:
		// Builtin copy planting stateful closure into local slice read into Hook!
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
func dirtyFn() func() int {
	n := %d
	return func() int { n++; return n }
}
var Hook func() int
func init() {
	dst := make([]func() int, 1)
	copy(dst, []func() int{dirtyFn()})
	Hook = dst[0]
}
func Subject() int { return Hook() }
func Mutator() int { return 0 }
`, baseConst),
			selfDrifts:         true,
			crossSubjectDrifts: true,
		}

	case 9:
		// Multi-hop pointer dereference in struct (`*b.p = dirtyFn()`) writing Hook!
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
type ptrBox struct { p *func() int }
func dirtyFn() func() int {
	n := %d
	return func() int { n++; return n }
}
var Hook func() int
func init() {
	b := ptrBox{p: &Hook}
	*b.p = dirtyFn()
}
func Subject() int { return Hook() }
func Mutator() int { return 0 }
`, baseConst),
			selfDrifts:         true,
			crossSubjectDrifts: true,
		}

	case 10:
		// Closure extracting callable from non-callable map carrier (`m := MapCar; m["k"]()`)
		// while MapCar also has an unreachable/dead mutation site!
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
func dirtyFn() func() int {
	n := %d
	return func() int { n++; return n }
}
var MapCar = map[string]func() int{"k": dirtyFn()}
var Hook func() int
func init() {
	m := MapCar
	Hook = func() int { return m["k"]() }
}
func Subject() int { return Hook() }
func Mutator() int { MapCar["z"] = nil; return 0 }
`, baseConst),
			selfDrifts:         true,
			crossSubjectDrifts: true,
		}

	case 11:
		// Direct runtime mutation of carrier map in Mutator, observed by len(MapCar) in Subject!
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
func pureFn() int { return %d }
var MapCar = map[string]func() int{}
func Subject() int { return len(MapCar) }
func Mutator() int {
	MapCar["added"] = pureFn
	return len(MapCar)
}
`, baseConst),
			selfDrifts:         false,
			crossSubjectDrifts: true,
		}

	case 12:
		// Spread variadic initOnly helper sharing backing array with exported slice mutated by Mutator!
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
func pureFn() int { return %d }
func altFn() int { return %d }
var Backing = []func() int{pureFn}
var Hook func() int
func installSpread(fs ...func() int) {
	Hook = func() int { return fs[0]() }
}
func init() {
	installSpread(Backing...)
}
func Subject() int { return Hook() }
func Mutator() int {
	Backing[0] = altFn
	return 1
}
`, baseConst, baseConst+99),
			selfDrifts:         false,
			crossSubjectDrifts: true,
		}

	default:
		// Single-write top-level constructor global returning dirty closure captured in init!
		return stateDriftScenario{
			src: fmt.Sprintf(`package gen
func makeDirty() func() int {
	n := %d
	return func() int { n++; return n }
}
var CtorGlobal = makeDirty()
var Hook func() int
func init() {
	fn := CtorGlobal
	Hook = func() int { return fn() }
}
func Subject() int { return Hook() }
func Mutator() int { return 0 }
`, baseConst),
			selfDrifts:         true,
			crossSubjectDrifts: true,
		}
	}
}

func subjectHasSurvivingCulprit(cone ConeState, subjectReach map[string]bool) bool {
	for _, c := range cone.RootCulprits {
		sites, ok := cone.CulpritSites[c.Key]
		if !ok || sites.Unattributed {
			return true
		}
		for fn := range sites.Fns {
			if subjectReach[fn] {
				return true
			}
		}
	}
	return false
}

func TestRapidDynstateSoundnessAgainstStateDriftOracle(t *testing.T) {
	const pkgPath = "example.com/gen"
	t.Run("curated_laundering_and_clean_shapes", func(t *testing.T) {
		rapid.Check(t, func(rt *rapid.T) {
			sc := generateStateDriftScenario(rt)
			pkg := mustTypecheckOrderedPackage(t, pkgPath, []namedSourceFile{{name: "gen.go", src: sc.src}})
			fact := FactOf(true, pkg)
			assertFactCanonicalAndValid(t, fact)

			generalCone := composeSinglePkg(pkgPath, fact, false, false)
			singleSubjCone := composeSinglePkg(pkgPath, fact, true, false)

			if sc.selfDrifts || sc.crossSubjectDrifts {
				if generalCone.Downgraded == "" {
					rt.Fatalf("UNSOUND under GeneralExecution: state drifts (self=%v, cross=%v) but ConeState.Downgraded == \"\"\nSource:\n%s\nFact: %+v",
						sc.selfDrifts, sc.crossSubjectDrifts, sc.src, fact)
				}
			} else {
				if generalCone.Downgraded != "" {
					rt.Fatalf("unexpected false refusal on clean scenario: Downgraded=%q\nSource:\n%s",
						generalCone.Downgraded, sc.src)
				}
			}

			if sc.selfDrifts {
				reach := map[string]bool{
					pkgPath + ".Subject": true,
				}
				if !subjectHasSurvivingCulprit(singleSubjCone, reach) {
					rt.Fatalf("UNSOUND under SingleSubjectExecution: Subject() self-drifts across calls, yet reachability scoping discharged all culprits!\nSource:\n%s\nRootCulprits: %+v\nCulpritSites: %+v",
						sc.src, singleSubjCone.RootCulprits, singleSubjCone.CulpritSites)
				}
			}
		})
	})

	t.Run("compositional_origin_transport_sink_chains", func(t *testing.T) {
		rapid.Check(t, func(rt *rapid.T) {
			originKind := rapid.IntRange(0, 5).Draw(rt, "originKind")
			transportKind := rapid.IntRange(0, 5).Draw(rt, "transportKind")
			sinkKind := rapid.IntRange(0, 5).Draw(rt, "sinkKind")
			kVal := rapid.IntRange(1, 30).Draw(rt, "kVal")

			var topDecls strings.Builder
			var initLines strings.Builder
			var mutLines strings.Builder

			topDecls.WriteString(fmt.Sprintf("func pureBase() int { return %d }\n", kVal))
			topDecls.WriteString("func passThrough(f func() int) func() int { return f }\n")
			topDecls.WriteString("type ptrHolder struct { p *func() int }\n")
			topDecls.WriteString("var settledSlice = []int{11, 22}\n")
			topDecls.WriteString("var mutableData = []int{33}\n")
			topDecls.WriteString("var Hook func() int\n")

			selfDrifts := false
			crossDrifts := false
			originExpr := "pureBase"

			switch originKind {
			case 0:
				originExpr = "pureBase"
			case 1:
				initLines.WriteString(fmt.Sprintf("\tlocScalar := %d\n", kVal))
				originExpr = "func() int { return locScalar + 1 }"
			case 2:
				originExpr = "func() int { return settledSlice[0] }"
			case 3:
				initLines.WriteString("\tcnt := 0\n")
				originExpr = "func() int { cnt++; return cnt }"
				selfDrifts = true
				crossDrifts = true
			case 4:
				topDecls.WriteString("var StepSibling func()\n")
				initLines.WriteString("\tsharedCell := 1\n\tStepSibling = func() { sharedCell++ }\n")
				originExpr = "func() int { return sharedCell }"
				mutLines.WriteString("\tif StepSibling != nil { StepSibling() }\n")
				crossDrifts = true
			case 5:
				initLines.WriteString("\tdataAlias := mutableData\n")
				originExpr = "func() int { return dataAlias[0] }"
				mutLines.WriteString("\tmutableData[0]++\n")
				crossDrifts = true
			}

			valExpr := originExpr
			switch transportKind {
			case 0:
				// Direct expression
			case 1:
				// Constructor call passThrough(origin)
				valExpr = fmt.Sprintf("passThrough(%s)", originExpr)
			case 2:
				// Fresh 1-element slice + spare-capacity append overwrite
				initLines.WriteString("\tspare := make([]func() int, 1)\n\tspare[0] = pureBase\n")
				initLines.WriteString(fmt.Sprintf("\t_ = append(spare[:0], %s)\n", originExpr))
				valExpr = "spare[0]"
			case 3:
				// Builtin copy into fresh local slice
				initLines.WriteString("\tcpDst := make([]func() int, 1)\n")
				initLines.WriteString(fmt.Sprintf("\tcopy(cpDst, []func() int{%s})\n", originExpr))
				valExpr = "cpDst[0]"
			case 4:
				// Go 1.26+ new(expr) dereference
				initLines.WriteString(fmt.Sprintf("\tpNew := new(%s)\n", originExpr))
				valExpr = "*pNew"
			case 5:
				// Type-switch implicit case binding
				initLines.WriteString("\tvar chosen func() int = pureBase\n")
				initLines.WriteString(fmt.Sprintf("\tswitch tv := any(%s).(type) {\n\tcase func() int:\n\t\tchosen = tv\n\t}\n", originExpr))
				valExpr = "chosen"
			}

			switch sinkKind {
			case 0:
				initLines.WriteString(fmt.Sprintf("\tHook = %s\n", valExpr))
			case 1:
				initLines.WriteString(fmt.Sprintf("\tpBare := &Hook\n\t*pBare = %s\n", valExpr))
			case 2:
				initLines.WriteString(fmt.Sprintf("\th := ptrHolder{p: &Hook}\n\t*h.p = %s\n", valExpr))
			case 3:
				topDecls.WriteString("func installOne(fn func() int) { Hook = func() int { return fn() } }\n")
				initLines.WriteString(fmt.Sprintf("\tinstallOne(%s)\n", valExpr))
			case 4:
				topDecls.WriteString("func installVar(fns ...func() int) { Hook = func() int { return fns[0]() } }\n")
				initLines.WriteString(fmt.Sprintf("\tinstallVar(%s)\n", valExpr))
			case 5:
				topDecls.WriteString("var MapSink = map[string]func() int{}\n")
				initLines.WriteString(fmt.Sprintf("\tMapSink[\"k\"] = %s\n\tmAlias := MapSink\n\tHook = func() int { return mAlias[\"k\"]() }\n", valExpr))
			}

			src := fmt.Sprintf("package gen\n\n%s\nfunc init() {\n%s}\n\nfunc Subject() int { return Hook() }\n\nfunc Mutator() int {\n%s\treturn 0\n}\n",
				topDecls.String(), initLines.String(), mutLines.String())

			pkg := mustTypecheckOrderedPackage(t, pkgPath, []namedSourceFile{{name: "comb.go", src: src}})
			fact := FactOf(true, pkg)
			assertFactCanonicalAndValid(t, fact)

			generalCone := composeSinglePkg(pkgPath, fact, false, false)
			singleSubjCone := composeSinglePkg(pkgPath, fact, true, false)

			if selfDrifts || crossDrifts {
				if generalCone.Downgraded == "" {
					rt.Fatalf("UNSOUND compositional chain (origin=%d, transport=%d, sink=%d): drifts (self=%v, cross=%v) yet GeneralExecution clean!\nSource:\n%s\nFact: %+v",
						originKind, transportKind, sinkKind, selfDrifts, crossDrifts, src, fact)
				}
			}
			if selfDrifts {
				reach := map[string]bool{pkgPath + ".Subject": true}
				if !subjectHasSurvivingCulprit(singleSubjCone, reach) {
					rt.Fatalf("UNSOUND compositional chain under SingleSubjectExecution (origin=%d, transport=%d, sink=%d):\nSource:\n%s\nRootCulprits: %+v\nCulpritSites: %+v",
						originKind, transportKind, sinkKind, src, singleSubjCone.RootCulprits, singleSubjCone.CulpritSites)
				}
			}
		})
	})
}

func TestRapidDynstateMetamorphicInvariance(t *testing.T) {
	const pkgPath = "example.com/meta"

	declPool := []string{
		`type box struct { n int; s []int }`,
		`func (b *box) Read() int { return b.n + len(b.s) }`,
		`func (b *box) Write(v int) { b.n = v }`,
		`func HelperRead(xs []int) int { return len(xs) }`,
		`func HelperMut(xs []int) { if len(xs) > 0 { xs[0] = 1 } }`,
		`func MakePure(k int) func() int { return func() int { return k + 1 } }`,
		`func UseHook() int { if ExportedHook != nil { return ExportedHook() }; return len(ExportedMap) }`,
		`func SeedMap() { ExportedMap["a"] = func() int { return 7 } }`,
		`var settledNums = []int{3, 4, 5}`,
		`var ExportedHook func() int = MakePure(2)`,
		`var ExportedMap = map[string]func() int{}`,
	}

	rapid.Check(t, func(rt *rapid.T) {
		// Draw a random permutation of declarations and split across 1..3 files.
		perm := rapid.Permutation(declPool).Draw(rt, "declPerm")
		nFiles := rapid.IntRange(1, 3).Draw(rt, "nFiles")

		singleSrc := "package meta\n\n" + strings.Join(declPool, "\n\n") + "\n"
		pkgCanonical := mustTypecheckOrderedPackage(t, pkgPath, []namedSourceFile{{name: "all.go", src: singleSrc}})
		factCanonical := FactOf(true, pkgCanonical)
		assertFactCanonicalAndValid(t, factCanonical)

		buckets := make([][]string, nFiles)
		for i, d := range perm {
			targetFile := rapid.IntRange(0, nFiles-1).Draw(rt, fmt.Sprintf("bucket_%d", i))
			buckets[targetFile] = append(buckets[targetFile], d)
		}
		splitFiles := make([]namedSourceFile, 0, nFiles)
		for i := 0; i < nFiles; i++ {
			body := "package meta\n\n" + strings.Join(buckets[i], "\n\n") + "\n"
			splitFiles = append(splitFiles, namedSourceFile{
				name: fmt.Sprintf("part_%d.go", i),
				src:  body,
			})
		}
		pkgSplit := mustTypecheckOrderedPackage(t, pkgPath, splitFiles)
		factSplit := FactOf(true, pkgSplit)
		assertFactCanonicalAndValid(t, factSplit)

		// Law 1: Declaration-order & file-split invariance.
		if !reflect.DeepEqual(factCanonical, factSplit) {
			rt.Fatalf("FactOf changed under declaration permutation / file split:\ncanonical: %+v\nsplit:     %+v",
				factCanonical, factSplit)
		}

		coneCanonical := composeSinglePkg(pkgPath, factCanonical, false, false)
		coneSplit := composeSinglePkg(pkgPath, factSplit, false, false)
		if !reflect.DeepEqual(coneCanonical, coneSplit) {
			rt.Fatalf("Compose changed under declaration permutation / file split:\ncanonical: %+v\nsplit:     %+v",
				coneCanonical, coneSplit)
		}

		// Law 2: JSON serialization round-trip preserves Compose verdict identically.
		encoded, err := json.Marshal(factCanonical)
		if err != nil {
			rt.Fatalf("json.Marshal(Fact): %v", err)
		}
		var roundTripped Fact
		if err := json.Unmarshal(encoded, &roundTripped); err != nil {
			rt.Fatalf("json.Unmarshal(Fact): %v", err)
		}
		coneRT := composeSinglePkg(pkgPath, roundTripped, false, false)
		if !reflect.DeepEqual(coneCanonical, coneRT) {
			rt.Fatalf("JSON round-trip altered Compose:\nbefore: %+v\nafter:  %+v", coneCanonical, coneRT)
		}

		// Law 3: Monotonicity under adding a direct carrier mutation function.
		mutFiles := append([]namedSourceFile(nil), splitFiles...)
		mutFiles = append(mutFiles, namedSourceFile{
			name: "extra_mut.go",
			src:  "package meta\nfunc ExtraOverwrite() { ExportedHook = nil }\n",
		})
		pkgMut := mustTypecheckOrderedPackage(t, pkgPath, mutFiles)
		factMut := FactOf(true, pkgMut)
		sawHookMut := slices.Contains(factMut.Mutates, pkgPath+".ExportedHook")
		for _, au := range factMut.AttributedUses {
			if au.Key == pkgPath+".ExportedHook" && !au.Escape && !au.HasMethod {
				sawHookMut = true
				break
			}
		}
		if !sawHookMut {
			rt.Fatalf("expected ExportedHook in Mutates or AttributedUses after adding ExtraOverwrite: mut=%+v attr=%+v",
				factMut.Mutates, factMut.AttributedUses)
		}
		coneMut := composeSinglePkg(pkgPath, factMut, false, false)
		if coneMut.Downgraded == "" {
			rt.Fatalf("expected non-empty Downgraded after adding ExtraOverwrite")
		}
	})
}

func FuzzFactOfAndComposeArbitraryGoSource(f *testing.F) {
	seeds := []string{
		`package p; var H func() int; func init() { x := 1; H = func() int { return x } }`,
		`package p; var M = map[string]func(){}; func S() { M["k"] = func() {} }`,
		`package p; type T struct{ x int }; func (t *T) R() int { return t.x }`,
		`package p; func Gen[S ~[]func()](s S) S { return append(s[:0], nil) }`,
		`package p; var Bad = unknown(); func init() { switch v := any(Bad).(type) { case []int: v[0] = 1 } }`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 16<<10 {
			return
		}
		const pkgPath = "example.com/fuzzdyn"
		fset := token.NewFileSet()
		file, _ := parser.ParseFile(fset, "fuzz.go", src, parser.ParseComments)
		if file == nil {
			return
		}
		info := &types.Info{
			Types:      make(map[ast.Expr]types.TypeAndValue),
			Instances:  make(map[*ast.Ident]types.Instance),
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Implicits:  make(map[ast.Node]types.Object),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
			Scopes:     make(map[ast.Node]*types.Scope),
		}
		cfg := types.Config{
			Error:    func(error) {},
			Importer: importer.Default(),
		}
		typesPkg, _ := cfg.Check(pkgPath, fset, []*ast.File{file}, info)
		if typesPkg == nil {
			return
		}
		pkg := &packages.Package{
			ID:        pkgPath,
			PkgPath:   pkgPath,
			Name:      typesPkg.Name(),
			Fset:      fset,
			Syntax:    []*ast.File{file},
			Types:     typesPkg,
			TypesInfo: info,
			Imports:   syntheticPackageImports(typesPkg, nil),
			Module:    &packages.Module{Path: "example.com/mod"},
		}
		for _, audited := range []bool{true, false} {
			fact := FactOf(audited, pkg)
			assertFactCanonicalAndValid(t, fact)
			allFacts := map[string][]Fact{pkgPath: {fact}}
			_ = ResolveEnvAudit(allFacts, func(Fact) {})
			_ = composeSinglePkg(pkgPath, fact, false, false)
			_ = composeSinglePkg(pkgPath, fact, true, false)
			_ = composeSinglePkg(pkgPath, fact, false, true)
		}
	})
}

func checkSingleEncloserTheoremCell(t testing.TB, enclKind, interiorKind, opKind, confMode int, singleSubject bool) {
	t.Helper()
	const pkgPath = "example.com/enclprop"
	var decls strings.Builder
	decls.WriteString("package enclprop\n\nimport \"sync\"\n\n")
	decls.WriteString("var _ sync.Mutex\n")
	decls.WriteString("type runner struct{}\n")
	decls.WriteString("var sinkAny any\n")
	decls.WriteString("var sinkSlice [][]func()\n")
	decls.WriteString("var sinkBox *carrierBox\n")
	decls.WriteString("type carrierBox struct { fn func(); n int }\n")

	var targetVar string
	var opStmt string
	switch opKind {
	case 0:
		decls.WriteString("var Carrier = []func(){}\n")
		targetVar = pkgPath + ".Carrier"
		opStmt = "Carrier = nil"
	case 1:
		decls.WriteString("var Carrier = []func(){}\n")
		targetVar = pkgPath + ".Carrier"
		opStmt = "sinkAny = Carrier"
	case 2:
		decls.WriteString("var Carrier = &carrierBox{}\n")
		targetVar = pkgPath + ".Carrier"
		switch confMode {
		case 0:
			decls.WriteString("func (b *carrierBox) Act() int { return b.n }\n")
		case 1:
			decls.WriteString("func (b *carrierBox) Act() { b.n++ }\n")
		case 2:
			decls.WriteString("func (b *carrierBox) Act() { sinkBox = b }\n")
		}
		opStmt = "Carrier.Act()"
	case 3:
		decls.WriteString("var Carrier = []func(){}\n")
		targetVar = pkgPath + ".Carrier"
		switch confMode {
		case 0:
			decls.WriteString("func callee(s []func()) int { return len(s) }\n")
		case 1:
			decls.WriteString("func callee(s []func()) { if len(s) > 0 { s[0] = nil } }\n")
		case 2:
			decls.WriteString("func callee(s []func()) { sinkSlice = append(sinkSlice, s) }\n")
		}
		opStmt = "callee(Carrier)"
	case 4:
		decls.WriteString("var SharedPool = sync.Pool{New: func() any { return []byte{0} }}\n")
		targetVar = pkgPath + ".SharedPool"
		opStmt = "SharedPool.Put([]byte{1})"
	case 5:
		decls.WriteString("var Carrier = map[int]func(){}\n")
		targetVar = pkgPath + ".Carrier"
		opStmt = "{ n := 0; Carrier[0] = func() { n++ } }"
	case 6:
		decls.WriteString("var Carrier = map[int]func(){}\n")
		decls.WriteString("func makeStateful() func() { n := 0; return func() { n++ } }\n")
		targetVar = pkgPath + ".Carrier"
		opStmt = "Carrier[0] = makeStateful()"
	}

	var bodyStmt string
	switch interiorKind {
	case 0:
		bodyStmt = opStmt
	case 1:
		bodyStmt = "_ = func() { " + opStmt + " }"
	case 2:
		bodyStmt = "go func() { " + opStmt + " }()"
	}

	var wantSiteKey string
	switch enclKind {
	case 0:
		decls.WriteString("func init() { encl() }\n")
		decls.WriteString("func encl() { " + bodyStmt + " }\n")
		wantSiteKey = (syntaxutil.FuncKey{Pkg: pkgPath, Name: "encl"}).SiteKey()
	case 1:
		decls.WriteString("func init() { Encl() }\n")
		decls.WriteString("func Encl() { " + bodyStmt + " }\n")
		wantSiteKey = (syntaxutil.FuncKey{Pkg: pkgPath, Name: "Encl"}).SiteKey()
	case 2:
		decls.WriteString("func init() { Encl() }\n")
		decls.WriteString("func Encl() { " + bodyStmt + " }\n")
		decls.WriteString("func DeadCaller() { Encl() }\n")
		wantSiteKey = (syntaxutil.FuncKey{Pkg: pkgPath, Name: "Encl"}).SiteKey()
	case 3:
		decls.WriteString("func Encl() { " + bodyStmt + " }\n")
		wantSiteKey = (syntaxutil.FuncKey{Pkg: pkgPath, Name: "Encl"}).SiteKey()
	case 4:
		decls.WriteString("func (r *runner) Encl() { " + bodyStmt + " }\n")
		wantSiteKey = (syntaxutil.FuncKey{Pkg: pkgPath, Name: "runner.Encl"}).SiteKey()
	}

	pkg := mustTypecheckOrderedPackage(t, pkgPath, []namedSourceFile{{
		name: "encl.go",
		src:  decls.String(),
	}})
	fact := FactOf(true, pkg)
	assertFactCanonicalAndValid(t, fact)
	cone := composeSinglePkg(pkgPath, fact, singleSubject, false)

	// Ground-truth oracle from the Post-init Reachability Soundness Theorem:
	isLiteral := interiorKind != 0
	isGoStmt := interiorKind == 2
	isInitOnlyPlain := enclKind == 0 || enclKind == 1
	mayRunAtInit := enclKind == 0 || enclKind == 1 || enclKind == 2 || enclKind == 4

	benign := false
	switch opKind {
	case 2:
		benign = confMode == 0
	case 3:
		benign = confMode == 0 && !isGoStmt
	case 4:
		benign = singleSubject
	}
	syncNoOutlive := !isLiteral
	switch opKind {
	case 0:
	case 1:
		syncNoOutlive = false
	case 2, 3:
		if confMode == 2 {
			syncNoOutlive = false
		}
	case 4, 5, 6:
		syncNoOutlive = false
	}

	wantDischargedAtInit := !benign && isInitOnlyPlain && syncNoOutlive
	wantCulprit := !benign && !wantDischargedAtInit
	gotCulprit := false
	for _, c := range cone.RootCulprits {
		if c.Key == targetVar {
			gotCulprit = true
			break
		}
	}
	if gotCulprit != wantCulprit {
		t.Fatalf("encl=%d interior=%d op=%d conf=%d single=%v: gotCulprit=%v, want=%v\nsrc:\n%s\nfact=%+v\ncone=%+v",
			enclKind, interiorKind, opKind, confMode, singleSubject, gotCulprit, wantCulprit, decls.String(), fact, cone)
	}
	if wantCulprit {
		wantUnattributed := mayRunAtInit && !syncNoOutlive
		site := cone.CulpritSites[targetVar]
		if site.Unattributed != wantUnattributed {
			t.Fatalf("encl=%d interior=%d op=%d conf=%d single=%v: site.Unattributed=%v, want=%v\nsrc:\n%s\nsite=%+v",
				enclKind, interiorKind, opKind, confMode, singleSubject, site.Unattributed, wantUnattributed, decls.String(), site)
		}
		if !wantUnattributed && !site.Fns[wantSiteKey] {
			t.Fatalf("encl=%d interior=%d op=%d conf=%d single=%v: expected site.Fns[%q]=true, got %+v",
				enclKind, interiorKind, opKind, confMode, singleSubject, wantSiteKey, site)
		}
	}
}

func TestPropertyAttributedEncloserReachabilityAndForeclosureTheorem(t *testing.T) {
	// 1. Exhaustive deterministic sweep over every single-encloser cell (zero sampling blind spots).
	for enclKind := 0; enclKind <= 4; enclKind++ {
		for interiorKind := 0; interiorKind <= 2; interiorKind++ {
			for opKind := 0; opKind <= 6; opKind++ {
				confModes := []int{0}
				if opKind == 2 || opKind == 3 {
					confModes = []int{0, 1, 2}
				}
				singleModes := []bool{false}
				if opKind == 4 {
					singleModes = []bool{false, true}
				}
				for _, confMode := range confModes {
					for _, singleSubject := range singleModes {
						checkSingleEncloserTheoremCell(t, enclKind, interiorKind, opKind, confMode, singleSubject)
					}
				}
			}
		}
	}

	// 2. Compositional property check over arbitrary multi-function / method call DAGs
	// combining multiple operations on the same dynamic carrier across 3 enclosers.
	rapid.Check(t, func(rt *rapid.T) {
		const pkgPath = "example.com/encldag"
		// Nodes 0, 1: exported plain functions F0, F1; Node 2: method (runner).M2.
		initCalls0 := rapid.Bool().Draw(rt, "initCalls0")
		initCalls1 := rapid.Bool().Draw(rt, "initCalls1")
		initSeedsEnv := rapid.Bool().Draw(rt, "initSeedsEnv")
		edge0to1 := rapid.Bool().Draw(rt, "edge0to1")
		deadCalls0 := rapid.Bool().Draw(rt, "deadCalls0")
		deadCalls1 := rapid.Bool().Draw(rt, "deadCalls1")

		type siteSpec struct {
			active  bool
			literal bool
			opKind  int // 0: Carrier=nil, 1: sinkAny=Carrier, 2: retainParam(Carrier), 3: inplaceParam(Carrier), 4: readParam(Carrier), 5: direct stateful closure, 6: stateful constructor call
		}
		var specs [3]siteSpec
		for i := range specs {
			specs[i] = siteSpec{
				active:  rapid.Bool().Draw(rt, fmt.Sprintf("active_%d", i)),
				literal: rapid.Bool().Draw(rt, fmt.Sprintf("lit_%d", i)),
				opKind:  rapid.IntRange(0, 6).Draw(rt, fmt.Sprintf("op_%d", i)),
			}
		}

		var decls strings.Builder
		decls.WriteString("package encldag\n\n")
		decls.WriteString("type runner struct{}\n")
		decls.WriteString("var sinkAny any\n")
		decls.WriteString("var sinkMaps []map[int]func()\n")
		decls.WriteString("var Carrier = map[int]func(){}\n")
		decls.WriteString("func retainParam(m map[int]func()) { sinkMaps = append(sinkMaps, m) }\n")
		decls.WriteString("func inplaceParam(m map[int]func()) { m[0] = nil }\n")
		decls.WriteString("func readParam(m map[int]func()) int { return len(m) }\n")
		decls.WriteString("func makeStateful() func() { n := 0; return func() { n++ } }\n")

		renderSite := func(sp siteSpec) string {
			if !sp.active {
				return ""
			}
			var stmt string
			switch sp.opKind {
			case 0:
				stmt = "Carrier = nil"
			case 1:
				stmt = "sinkAny = Carrier"
			case 2:
				stmt = "retainParam(Carrier)"
			case 3:
				stmt = "inplaceParam(Carrier)"
			case 4:
				stmt = "_ = readParam(Carrier)"
			case 5:
				stmt = "{ n := 0; Carrier[0] = func() { n++ } }"
			case 6:
				stmt = "Carrier[0] = makeStateful()"
			}
			if sp.literal {
				return "_ = func() { " + stmt + " }\n"
			}
			return stmt + "\n"
		}

		decls.WriteString("func init() {\n")
		if initSeedsEnv {
			decls.WriteString("\t{ n := 0; Carrier[0] = func() { n++ } }\n")
		}
		if initCalls0 {
			decls.WriteString("\tF0()\n")
		}
		if initCalls1 {
			decls.WriteString("\tF1()\n")
		}
		decls.WriteString("}\n")

		decls.WriteString("func F0() {\n")
		if edge0to1 {
			decls.WriteString("\tF1()\n")
		}
		decls.WriteString(renderSite(specs[0]))
		decls.WriteString("}\n")

		decls.WriteString("func F1() {\n")
		decls.WriteString(renderSite(specs[1]))
		decls.WriteString("}\n")

		decls.WriteString("func (r *runner) M2() {\n")
		decls.WriteString(renderSite(specs[2]))
		decls.WriteString("}\n")

		decls.WriteString("func DeadCaller() {\n")
		if deadCalls0 {
			decls.WriteString("\tF0()\n")
		}
		if deadCalls1 {
			decls.WriteString("\tF1()\n")
		}
		decls.WriteString("}\n")

		pkg := mustTypecheckOrderedPackage(t, pkgPath, []namedSourceFile{{
			name: "dag.go",
			src:  decls.String(),
		}})
		fact := FactOf(true, pkg)
		assertFactCanonicalAndValid(t, fact)
		cone := composeSinglePkg(pkgPath, fact, false, false)

		// Whole-graph reachability & init-only classification of F0, F1, runner.M2:
		initReach := [3]bool{
			initCalls0,
			initCalls1 || (initCalls0 && edge0to1),
			true, // method encloser conservatively treated as mayRunAtInit
		}
		nonInitReach := [3]bool{
			deadCalls0,
			deadCalls1 || (deadCalls0 && edge0to1),
			true,
		}
		isInitOnlyPlain := [3]bool{
			initReach[0] && !nonInitReach[0],
			initReach[1] && !nonInitReach[1],
			false,
		}
		siteKeys := [3]string{
			(syntaxutil.FuncKey{Pkg: pkgPath, Name: "F0"}).SiteKey(),
			(syntaxutil.FuncKey{Pkg: pkgPath, Name: "F1"}).SiteKey(),
			(syntaxutil.FuncKey{Pkg: pkgPath, Name: "runner.M2"}).SiteKey(),
		}

		wantCulprit := initSeedsEnv
		wantUnattributed := initSeedsEnv
		wantFns := map[string]bool{}
		for i, sp := range specs {
			if !sp.active || sp.opKind == 4 {
				continue
			}
			// Stateful closure registrations (opKind 5, 6) plant an outliving environment
			// into Carrier and NEVER discharge via initOnlyPlain; method/init-reachable
			// registrations foreclose reachability discharge outright!
			syncNoOutlive := !sp.literal && (sp.opKind == 0 || sp.opKind == 3)
			if isInitOnlyPlain[i] && syncNoOutlive {
				continue
			}
			wantCulprit = true
			if initReach[i] && !syncNoOutlive {
				wantUnattributed = true
			} else {
				wantFns[siteKeys[i]] = true
			}
		}

		targetVar := pkgPath + ".Carrier"
		gotCulprit := false
		for _, c := range cone.RootCulprits {
			if c.Key == targetVar {
				gotCulprit = true
				break
			}
		}
		if gotCulprit != wantCulprit {
			rt.Fatalf("gotCulprit=%v, want=%v\nsrc:\n%s\nfact=%+v\ncone=%+v", gotCulprit, wantCulprit, decls.String(), fact, cone)
		}
		if wantCulprit {
			site := cone.CulpritSites[targetVar]
			if site.Unattributed != wantUnattributed {
				rt.Fatalf("site.Unattributed=%v, want=%v\nsrc:\n%s\nsite=%+v", site.Unattributed, wantUnattributed, decls.String(), site)
			}
			if !wantUnattributed {
				for fn := range wantFns {
					if !site.Fns[fn] {
						rt.Fatalf("missing attributed fn %q in site=%+v\nsrc:\n%s", fn, site, decls.String())
					}
				}
			}
		}
	})
}

const syntheticVerifiedRapidSrc = `package rapid

import (
	"flag"
	"fmt"
	"hash/maphash"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

var flags struct {
	checks   int
	seed     uint64
	failfile string
	debugvis bool
}

var visTmpl = template.Must(template.New("rapid-vis").Parse("{{.Title}}"))

type visTmplData struct {
	Title string
	Style template.CSS
}

func envInt(key string, lookup func(string) (string, bool)) int {
	if v, ok := lookup(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 100
}

func init() {
	flags.checks = envInt("RAPID_CHECKS", os.LookupEnv)
	if v, ok := os.LookupEnv("RAPID_FAILFILE"); ok && v != "" {
		flags.failfile = v
	}
	flag.IntVar(&flags.checks, "rapid.checks", 100, "number of checks")
	flag.Uint64Var(&flags.seed, "rapid.seed", 0, "PRNG seed")
	flag.StringVar(&flags.failfile, "rapid.failfile", "", "failure file")
	flag.BoolVar(&flags.debugvis, "rapid.debugvis", false, "debug vis")
}

var strMapCache sync.Map
var genCache sync.Map

func cachedWords(k string) []string {
	if v, ok := strMapCache.Load(k); ok {
		return v.([]string)
	}
	res := []string{k}
	strMapCache.Store(k, res)
	return res
}

type TB interface {
	Helper()
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	Name() string
}

type tb TB

type T struct {
	tb
	state uint64
	fail  bool
}

func (t *T) Errorf(format string, args ...any) { t.fail = true }

type exampleTB struct{}

func (*exampleTB) Helper()                         {}
func (*exampleTB) Logf(format string, args ...any) {}
func (*exampleTB) Errorf(format string, args ...any) {}
func (*exampleTB) Name() string                    { return "example" }

func baseSeed() uint64 {
	if flags.seed != 0 {
		return flags.seed
	}
	var h maphash.Hash
	h.SetSeed(maphash.MakeSeed())
	return h.Sum64()
}

type generatorImpl[V any] interface {
	value(*T) V
}

type Generator[V any] struct {
	impl generatorImpl[V]
	gen  func(*T) V
}

func newGenerator[V any](impl generatorImpl[V]) *Generator[V] {
	return &Generator[V]{impl: impl}
}

type statelessIntGen struct{}

func (*statelessIntGen) value(t *T) int { return int(t.state >> 33) }

type statelessSliceGen struct {
	items []int
}

func (s *statelessSliceGen) value(t *T) int { return s.items[0] }
func (s *statelessSliceGen) maybeValue() (int, bool) {
	if len(s.items) == 0 {
		return 0, false
	}
	return s.items[0], true
}

var defaultIntGen = newGenerator[int](&statelessIntGen{})

func cachedSliceGen(k string) *Generator[int] {
	if v, ok := genCache.Load(k); ok {
		return v.(*Generator[int])
	}
	impl := &statelessSliceGen{items: []int{1, 2}}
	_ = impl.maybeValue
	g := newGenerator[int](impl)
	genCache.Store(k, g)
	return g
}

func (g *Generator[V]) Draw(t *T, label string) V {
	t.state = t.state*6364136223846793005 + 1442695040888963407
	if g.impl != nil {
		return g.impl.value(t)
	}
	return g.gen(t)
}

func (g *Generator[V]) Example(seed ...int) V {
	s := baseSeed()
	if len(seed) > 0 {
		s = uint64(seed[0])
	}
	return g.Draw(&T{tb: &exampleTB{}, state: s}, "example")
}

func ID[V any](v V) V { return v }

func Int() *Generator[int] {
	return &Generator[int]{gen: func(t *T) int { return int(t.state >> 33) }}
}

func Check(t *testing.T, prop func(*T)) {
	t.Helper()
	checkTB(t, prop)
}

func MakeCheck(prop func(*T)) func(*testing.T) {
	return func(t *testing.T) { checkTB(t, prop) }
}

var failReporter = reportFailure

func reportFailure(tb TB, seed uint64) {
	tb.Errorf("[rapid] failed (seed=%d)", seed)
}

func defaultFailFile(name string) string {
	if flags.failfile != "" {
		return flags.failfile
	}
	return filepath.Join("testdata", "rapid", name)
}

func saveFailFile(filename string, data []byte) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0o775); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".rapid-fail-*")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), filename)
}

func loadFailFiles(name string) {
	matches, err := filepath.Glob(defaultFailFile(name))
	if err != nil {
		return
	}
	for _, m := range matches {
		f, err := os.Open(m)
		if err == nil {
			_ = f.Close()
		}
	}
}

func saveVis(id int) {
	if flags.debugvis {
		f, err := os.Create(fmt.Sprintf("rapid-vis-%d.html", id))
		if err == nil {
			_ = visTmpl.Execute(f, &visTmplData{Title: "ok", Style: template.CSS("body{}")})
			_ = f.Close()
		}
	}
}

func runSynctest(fn func()) {
	ch := make(chan struct{})
	go func() {
		defer func() { ch <- struct{}{} }()
		synctest.Test(&testing.T{}, func(*testing.T) { fn() })
	}()
	<-ch
}

func checkTB(tb TB, prop func(*T)) {
	start := time.Now()
	seed := baseSeed()
	_ = defaultIntGen
	_ = cachedSliceGen("seed")
	_ = ID(1)
	_ = len(cachedWords("seed"))
	loadFailFiles(tb.Name())
	saveVis(0)
	runSynctest(func() {})
	t := &T{tb: tb, state: seed}
	for i := 0; i < flags.checks && !t.fail; i++ {
		prop(t)
	}
	if t.fail {
		_ = saveFailFile(defaultFailFile(tb.Name()), []byte(fmt.Sprintf("seed=%d", t.state)))
		failReporter(tb, t.state)
		return
	}
	_ = io.EOF
	tb.Logf("[rapid] OK, passed %v tests (%v)", flags.checks, time.Since(start))
}
`

func TestHarnessDischargesVerificationAndTamperRefusals(t *testing.T) {
	const rapidPath = "pgregory.net/rapid"
	cleanRapid := mustTypecheckOrderedPackage(t, rapidPath, []namedSourceFile{{
		name: "rapid.go",
		src:  syntheticVerifiedRapidSrc,
	}})
	cleanFact := FactOf(true, cleanRapid)
	assertFactCanonicalAndValid(t, cleanFact)
	if len(cleanFact.HarnessDischarges) == 0 || !reflect.DeepEqual(cleanFact.HarnessDischarges, cleanFact.Declares) {
		t.Fatalf("FactOf(audited=true, cleanRapid) HarnessDischarges = %v, want %v", cleanFact.HarnessDischarges, cleanFact.Declares)
	}

	// 1. Unaudited toolchain refuses HarnessDischarges.
	if unFact := FactOf(false, cleanRapid); len(unFact.HarnessDischarges) != 0 {
		t.Fatalf("FactOf(audited=false) HarnessDischarges = %v, want empty", unFact.HarnessDischarges)
	}

	// 2. Non-harness package path with identical source never earns HarnessDischarges.
	nonHarnessPkg := mustTypecheckOrderedPackage(t, "example.com/notrapid", []namedSourceFile{{
		name: "rapid.go",
		src:  syntheticVerifiedRapidSrc,
	}})
	if nonFact := FactOf(true, nonHarnessPkg); len(nonFact.HarnessDischarges) != 0 {
		t.Fatalf("non-harness package earned HarnessDischarges: %v", nonFact.HarnessDischarges)
	}

	// 3. Compose discharges clean pgregory.net/rapid under both PackageExecution and SingleSubjectExecution
	// without emitting VouchDischarges or AttestationDischarges.
	meta := []GraphPackage{
		{ImportPath: "example.com/user", PkgPath: "example.com/user", Imports: []string{rapidPath}, Class: MutableLocalPackage},
		{ImportPath: rapidPath, PkgPath: rapidPath, Class: PinnedPackage, Pin: "pgregory.net/rapid@v1.3.0"},
	}
	for _, single := range []bool{false, true} {
		cs := Compose(meta, map[string][]Fact{
			"example.com/user": {{}},
			rapidPath:          {cleanFact},
		}, "example.com/user", nil, single, !single)
		if cs.Downgraded != "" || cs.VouchDischarges != "" || cs.AttestationDischarges != "" {
			t.Fatalf("clean rapid Compose(single=%v) = %+v, want clean zero-vouch zero-attestation", single, cs)
		}
		discharged := NonVouchDischargedVars(meta, map[string][]Fact{
			"example.com/user": {{}},
			rapidPath:          {cleanFact},
		}, single)
		for _, k := range cleanFact.Declares {
			if !discharged[k] {
				t.Fatalf("NonVouchDischargedVars(single=%v) missing %q", single, k)
			}
		}
	}

	// 4. Tampered sources (exported global or //go:embed) refuse HarnessDischarges and downgrade Compose.
	for _, tamper := range []struct {
		name  string
		extra string
	}{
		{"exported_generator_global", "var ExportedGen = Int()\n"},
		{"go_embed_directive", "//go:embed rapid.go\nvar rawSrc string\n"},
		{"forbidden_linkname", "//go:linkname bad runtime.nanotime\n"},
	} {
		t.Run(tamper.name, func(t *testing.T) {
			badPkg := mustTypecheckOrderedPackage(t, rapidPath, []namedSourceFile{{
				name: "rapid.go",
				src:  syntheticVerifiedRapidSrc + "\n" + tamper.extra,
			}})
			badFact := FactOf(true, badPkg)
			if len(badFact.HarnessDischarges) != 0 {
				t.Fatalf("%s earned HarnessDischarges: %v", tamper.name, badFact.HarnessDischarges)
			}
			cs := Compose(meta, map[string][]Fact{
				"example.com/user": {{}},
				rapidPath:          {badFact},
			}, "example.com/user", nil, false, true)
			if cs.Downgraded == "" {
				t.Fatalf("%s failed to downgrade Compose: %+v", tamper.name, cs)
			}
		})
	}

	// 5. Cross-variant intersection: if a second variant of pgregory.net/rapid lacks HarnessDischarges, Compose refuses.
	variantWithoutDischarge := cleanFact
	variantWithoutDischarge.HarnessDischarges = nil
	if cs := Compose(meta, map[string][]Fact{
		"example.com/user": {{}},
		rapidPath:          {cleanFact, variantWithoutDischarge},
	}, "example.com/user", nil, false, true); cs.Downgraded == "" {
		t.Fatalf("expected missing variant HarnessDischarges to refuse Compose: %+v", cs)
	}

	// 6. Cross-package DirectVarWrites or foreign-package key tamper in HarnessDischarges refuses Compose.
	targetVar := cleanFact.Declares[0]
	if cs := Compose(meta, map[string][]Fact{
		"example.com/user": {{Mutates: []string{targetVar}, DirectVarWrites: []string{targetVar}}},
		rapidPath:          {cleanFact},
	}, "example.com/user", nil, false, true); cs.Downgraded == "" {
		t.Fatalf("expected DirectVarWrites on %q to evict HarnessDischarges: %+v", targetVar, cs)
	}
	if NonVouchDischargedVars(meta, map[string][]Fact{
		"example.com/user": {{Mutates: []string{targetVar}, DirectVarWrites: []string{targetVar}}},
		rapidPath:          {cleanFact},
	}, false)[targetVar] {
		t.Fatalf("expected DirectVarWrites on %q to evict %q from NonVouchDischargedVars", targetVar, targetVar)
	}
	foreignTamper := cleanFact
	foreignTamper.HarnessDischarges = append(slices.Clone(cleanFact.HarnessDischarges), "example.com/user.SharedGen")
	if cs := Compose(meta, map[string][]Fact{
		"example.com/user": {{Declares: []string{"example.com/user.SharedGen"}, Mutates: []string{"example.com/user.SharedGen"}}},
		rapidPath:          {foreignTamper},
	}, "example.com/user", nil, false, true); cs.Downgraded == "" {
		t.Fatalf("expected foreign key in HarnessDischarges to mark fact malformed and refuse Compose: %+v", cs)
	}
}

func TestInitClosureCarrierLinksAndPropagationMonotonicity(t *testing.T) {
	const pkgPath = "example.com/clink"

	// 1. Admitted environment-free closures capturing init-flow local aliases of dynamic-carrier globals
	// in init() and unexported init-only helpers emit CarrierLinks, so partial
	// --vouch on CleanMap alone still flags SizeHook when CleanMap is mutated!
	for _, tc := range []struct {
		name string
		src  string
	}{
		{
			name: "init_local_alias_capture",
			src: `package clink
var CleanMap = map[string]func() int{}
var SizeHook func() int
func init() {
	m := CleanMap
	SizeHook = func() int { return len(m) }
}
`,
		},
		{
			name: "unexported_init_only_local_alias_capture",
			src: `package clink
var CleanMap = map[string]func() int{}
var SizeHook func() int
func setup() {
	m := CleanMap
	SizeHook = func() int { return len(m) }
}
func init() { setup() }
`,
		},
		{
			name: "init_chained_local_alias_capture",
			src: `package clink
var CleanMap = map[string]func() int{}
var SizeHook func() int
func init() {
	m0 := CleanMap
	m := m0
	SizeHook = func() int { return len(m) }
}
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := mustTypecheckOrderedPackage(t, pkgPath, []namedSourceFile{{name: "clink.go", src: tc.src}})
			fact := FactOf(true, pkg)
			assertFactCanonicalAndValid(t, fact)
			cleanState := composeSinglePkg(pkgPath, fact, false, false)
			if cleanState.Downgraded != "" {
				t.Fatalf("%s clean state unexpectedly downgraded: %+v", tc.name, cleanState)
			}

			// Mutate CleanMap from an importing user package while pinning clink and vouching ONLY CleanMap:
			// CarrierLink must propagate mutation + unattributedMark to SizeHook!
			meta := []GraphPackage{
				{ImportPath: "example.com/user", PkgPath: "example.com/user", Imports: []string{pkgPath}, Class: MutableLocalPackage},
				{ImportPath: pkgPath, PkgPath: pkgPath, Class: PinnedPackage, Pin: pkgPath + "@v1.0.0"},
			}
			userFact := Fact{
				AttributedUses: []syntaxutil.AttributedUse{
					{Func: syntaxutil.FuncKey{Pkg: "example.com/user", Name: "LiveMutate"}, Key: pkgPath + ".CleanMap"},
					// Pre-seed SizeHook with a dead attributed mark to exercise propagateWithUnattributed monotonicity!
					{Func: syntaxutil.FuncKey{Pkg: "example.com/user", Name: "DeadMutateHook"}, Key: pkgPath + ".SizeHook"},
				},
			}
			cs := Compose(meta, map[string][]Fact{
				"example.com/user": {userFact},
				pkgPath:            {fact},
			}, "example.com/user", map[string]bool{pkgPath + ".CleanMap": true}, true, false)
			if !strings.Contains(cs.Downgraded, pkgPath+".SizeHook is mutated") {
				t.Fatalf("%s partial vouch failed to flag linked SizeHook: %+v", tc.name, cs)
			}
			if !cs.CulpritSites[pkgPath+".SizeHook"].Unattributed {
				t.Fatalf("%s CarrierLink propagation failed to force Unattributed=true when target already had dead attributed mark: %+v",
					tc.name, cs.CulpritSites[pkgPath+".SizeHook"])
			}
		})
	}

	// 2. Capturing a //gofresh:single-subject carrier via an init-local alias inside a non-directive target refuses EnvCarrying!
	singleSubjPkg := mustTypecheckOrderedPackage(t, pkgPath, []namedSourceFile{{
		name: "ss.go",
		src: `package clink
//gofresh:single-subject
var SingleMap = map[string]func() int{}
var SizeHook func() int
func init() {
	m := SingleMap
	SizeHook = func() int { return len(m) }
}
`,
	}})
	ssFact := FactOf(true, singleSubjPkg)
	assertFactCanonicalAndValid(t, ssFact)
	if !slices.Contains(ssFact.EnvCarrying, pkgPath+".SizeHook") {
		t.Fatalf("expected non-directive SizeHook capturing single-subject SingleMap to be EnvCarrying: %+v", ssFact)
	}

	// 3. Callable variable populated solely through an unproven constructor call in a dead function
	// still records EnvCallable and keeps Unattributed=true!
	callableCtorPkg := mustTypecheckOrderedPackage(t, pkgPath, []namedSourceFile{{
		name: "cctor.go",
		src: `package clink
var Hook func() int
func makeDirty() func() int { n := 0; return func() int { n++; return n } }
func DeadRegister() { Hook = makeDirty() }
`,
	}})
	ccFact := FactOf(true, callableCtorPkg)
	assertFactCanonicalAndValid(t, ccFact)
	if !slices.Contains(ccFact.EnvCallable, pkgPath+".Hook") {
		t.Fatalf("expected EnvCallable on constructor-populated callable Hook: %+v", ccFact)
	}
	ccState := composeSinglePkg(pkgPath, ccFact, true, false)
	if !ccState.CulpritSites[pkgPath+".Hook"].Unattributed {
		t.Fatalf("expected callable constructor-populated Hook to stay Unattributed=true: %+v", ccState)
	}
}

func TestInterfaceSignatureBoundaryConfinementMatrix(t *testing.T) {
	const pkgPath = "example.com/ifacebox"

	// 1. Source-plane registration & constructor cases: every dirty closure boxed
	// into an interface or narrowed via type-switch must downgrade Hook, while
	// every clean named-function counterpart must stay Valid.
	for _, tc := range []struct {
		name          string
		src           string
		wantDowngrade bool
	}{
		{
			name: "direct_closure_box_local_dirty",
			src: `package ifacebox
var Hook func() int
func init() {
	var n int
	var box any = func() int { n++; return n }
	Hook = func() int {
		_, ok := box.(func() int)
		if ok { return 1 }
		return 0
	}
}
`,
			wantDowngrade: true,
		},
		{
			name: "direct_closure_box_local_clean",
			src: `package ifacebox
func pureOne() int { return 1 }
var Hook func() int
func init() {
	var box any = pureOne
	Hook = func() int {
		_, ok := box.(func() int)
		if ok { return 1 }
		return 0
	}
}
`,
			wantDowngrade: false,
		},
		{
			name: "direct_closure_box_slices_clone_dirty",
			src: `package ifacebox
import "slices"
var Hook func() int
func init() {
	var n int
	s := slices.Clone([]any{func() int { n++; return n }})
	Hook = func() int { return len(s) }
}
`,
			wantDowngrade: true,
		},
		{
			name: "direct_closure_box_slices_clone_clean",
			src: `package ifacebox
import "slices"
func pureOne() int { return 1 }
var Hook func() int
func init() {
	s := slices.Clone([]any{pureOne})
	Hook = func() int { return len(s) }
}
`,
			wantDowngrade: false,
		},
		{
			name: "direct_closure_typeswitch_narrowing_refused",
			src: `package ifacebox
func pureOne() int { return 1 }
var Hook func() int
func init() {
	var box any = pureOne
	switch fn := box.(type) {
	case func() int:
		Hook = func() int { return fn() }
	}
}
`,
			wantDowngrade: true,
		},
		{
			name: "ctor_return_closure_box_local_dirty",
			src: `package ifacebox
func makeHook() func() int {
	var n int
	var box any = func() int { n++; return n }
	return func() int {
		if box != nil { return 1 }
		return 0
	}
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "ctor_return_closure_box_local_clean",
			src: `package ifacebox
func pureOne() int { return 1 }
func makeHook() func() int {
	var box any = pureOne
	return func() int {
		if box != nil { return 1 }
		return 0
	}
}
var Hook = makeHook()
`,
			wantDowngrade: false,
		},
		{
			name: "ctor_return_typeswitch_narrowing_dirty",
			src: `package ifacebox
func makeHook() func() int {
	var n int
	var box any = func() int { n++; return n }
	switch fn := box.(type) {
	case func() int:
		return fn
	}
	return nil
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "ctor_call_arg_interface_conv_dirty",
			src: `package ifacebox
func pureOne() int { return 1 }
func passThrough(x any) func() int {
	if x == nil { return nil }
	return pureOne
}
var Hook func() int
func init() {
	var n int
	Hook = passThrough(any(func() int { n++; return n }))
}
`,
			wantDowngrade: true,
		},
		{
			name: "ctor_call_arg_interface_conv_clean",
			src: `package ifacebox
func pureOne() int { return 1 }
func passThrough(x any) func() int {
	if x == nil { return nil }
	return pureOne
}
var Hook = passThrough(any(pureOne))
`,
			wantDowngrade: false,
		},
		{
			name: "ctor_call_arg_slices_clone_any_dirty",
			src: `package ifacebox
import "slices"
func pureOne() int { return 1 }
func passThrough(xs []any) func() int {
	if len(xs) == 0 { return nil }
	return pureOne
}
var Hook func() int
func init() {
	var n int
	Hook = passThrough(slices.Clone([]any{func() int { n++; return n }}))
}
`,
			wantDowngrade: true,
		},
		{
			name: "ctor_call_arg_slices_clone_any_clean",
			src: `package ifacebox
import "slices"
func pureOne() int { return 1 }
func passThrough(xs []any) func() int {
	if len(xs) == 0 { return nil }
	return pureOne
}
var Hook = passThrough(slices.Clone([]any{pureOne}))
`,
			wantDowngrade: false,
		},
		{
			name: "ctor_call_arg_local_box_dirty",
			src: `package ifacebox
func pureOne() int { return 1 }
func passThrough(x any) func() int {
	if x == nil { return nil }
	return pureOne
}
var Hook func() int
func init() {
	var n int
	var box any = func() int { n++; return n }
	Hook = passThrough(box)
}
`,
			wantDowngrade: true,
		},
		{
			name: "ctor_call_arg_local_box_clean",
			src: `package ifacebox
func pureOne() int { return 1 }
func passThrough(x any) func() int {
	if x == nil { return nil }
	return pureOne
}
var Hook func() int
func init() {
	var box any = pureOne
	Hook = passThrough(box)
}
`,
			wantDowngrade: false,
		},
		{
			name: "insertion_helper_boxed_dirty",
			src: `package ifacebox
func pureOne() int { return 1 }
func putBox(m map[int]func() int, side map[int]any, fn func() int, x any) {
	m[0] = fn
	side[0] = x
}
func makeHook() func() int {
	var n int
	m := map[int]func() int{}
	side := map[int]any{}
	putBox(m, side, pureOne, any(func() int { n++; return n }))
	return m[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "insertion_helper_multi_put_clean",
			src: `package ifacebox
func pureOne() int { return 1 }
func pureTwo() int { return 2 }
func putBox(m map[int]func() int, side map[int]any, k int, fn func() int, x any) {
	m[k] = fn
	side[k] = x
}
func makeHook() func() int {
	m := map[int]func() int{}
	side := map[int]any{}
	putBox(m, side, 0, pureOne, any(pureOne))
	putBox(m, side, 1, pureTwo, any(pureTwo))
	return m[0]
}
var Hook = makeHook()
`,
			wantDowngrade: false,
		},
		{
			name: "insertion_helper_converted_param_clean",
			src: `package ifacebox
func pureOne() int { return 1 }
func putConverted(m map[int]func() int, side map[int]any, fn func() int, x []int) {
	m[0] = fn
	side[0] = any(x)
}
func makeHook() func() int {
	m := map[int]func() int{}
	side := map[int]any{}
	putConverted(m, side, pureOne, []int{1, 2})
	return m[0]
}
var Hook = makeHook()
`,
			wantDowngrade: false,
		},
		{
			name: "insertion_helper_converted_param_mutated_dirty",
			src: `package ifacebox
func pureOne() int { return 1 }
func putConvDirty(m map[int]func() int, side map[int]any, fn func() int, x []any) {
	var n int
	x[0] = any(func() int { n++; return n })
	m[0] = fn
	side[0] = any(x)
}
func makeHook() func() int {
	m := map[int]func() int{}
	side := map[int]any{}
	putConvDirty(m, side, pureOne, make([]any, 1))
	return m[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "insertion_helper_rebound_param_dirty",
			src: `package ifacebox
func pureOne() int { return 1 }
func putRebound(m map[int]func() int, side map[int]any, fn func() int, x any) {
	var n int
	x = any(func() int { n++; return n })
	m[0] = fn
	side[0] = x
}
func makeHook() func() int {
	m := map[int]func() int{}
	side := map[int]any{}
	putRebound(m, side, pureOne, 1)
	return m[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "insertion_helper_builtin_copy_param_dirty",
			src: `package ifacebox
func badCopy(dst []func() int) {
	var n int
	copy(dst, []func() int{func() int { n++; return n }})
}
func makeHook() func() int {
	s := make([]func() int, 1)
	badCopy(s)
	return s[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "insertion_helper_bare_array_param_mutated_dirty",
			src: `package ifacebox
func pureOne() int { return 1 }
func putArrDirty(dst [][1]func() int, x [1]func() int) {
	var n int
	x[0] = func() int { n++; return n }
	dst[0] = x
}
func makeHook() func() int {
	dst := make([][1]func() int, 1)
	putArrDirty(dst, [1]func() int{pureOne})
	return dst[0][0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "insertion_helper_bare_array_param_clean",
			src: `package ifacebox
func pureOne() int { return 1 }
func putArrClean(dst [][1]func() int, x [1]func() int) {
	dst[0] = x
}
func makeHook() func() int {
	dst := make([][1]func() int, 1)
	putArrClean(dst, [1]func() int{pureOne})
	return dst[0][0]
}
var Hook = makeHook()
`,
			wantDowngrade: false,
		},
		{
			name: "insertion_helper_bare_val_struct_param_mutated_dirty",
			src: `package ifacebox
type ValFuncBox struct { F func() int }
func pureOne() int { return 1 }
func putValStructDirty(dst []ValFuncBox, x ValFuncBox) {
	var n int
	x.F = func() int { n++; return n }
	dst[0] = x
}
func makeHook() func() int {
	dst := make([]ValFuncBox, 1)
	putValStructDirty(dst, ValFuncBox{F: pureOne})
	return dst[0].F
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "insertion_helper_bare_any_slice_struct_param_mutated_dirty",
			src: `package ifacebox
type AnyBox struct { S []any }
func pureOne() int { return 1 }
func putAnyBoxDirty(m map[int]func() int, side []AnyBox, fn func() int, b AnyBox) {
	var n int
	b.S[0] = any(func() int { n++; return n })
	m[0] = fn
	side[0] = b
}
func makeHook() func() int {
	m := map[int]func() int{}
	side := make([]AnyBox, 1)
	putAnyBoxDirty(m, side, pureOne, AnyBox{S: make([]any, 1)})
	return m[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "insertion_helper_bare_global_slice_struct_param_mutated_dirty",
			src: `package ifacebox
var GlobalBuf = []int{1}
type DataBox struct { S [][]int }
func pureOne() int { return 1 }
func putDataBoxDirty(m map[int]func() int, side []DataBox, fn func() int, b DataBox) {
	b.S[0] = GlobalBuf
	m[0] = fn
	side[0] = b
}
func makeHook() func() int {
	m := map[int]func() int{}
	side := make([]DataBox, 1)
	putDataBoxDirty(m, side, pureOne, DataBox{S: make([][]int, 1)})
	return m[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "insertion_helper_held_struct_copy_map_mutated_dirty",
			src: `package ifacebox
type MapFuncBox struct { M map[string]func() int }
func pureOne() int { return 1 }
func putMapBoxViaCopyDirty(dst []MapFuncBox, b MapFuncBox) {
	loc := b
	var n int
	loc.M["k"] = func() int { n++; return n }
	dst[0] = b
}
func makeHook() func() int {
	dst := make([]MapFuncBox, 1)
	putMapBoxViaCopyDirty(dst, MapFuncBox{M: map[string]func() int{"k": pureOne}})
	return dst[0].M["k"]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "insertion_helper_slice_param_clean_and_projected_field_clean",
			src: `package ifacebox
type SliceFuncBox struct { S []func() int }
func pureOne() int { return 1 }
func putSliceClean(m map[int][]func() int, s []func() int) {
	m[0] = s
}
func putProjectedClean(m map[int][]func() int, b SliceFuncBox) {
	m[1] = b.S
}
func makeHook() func() int {
	m := map[int][]func() int{}
	putSliceClean(m, []func() int{pureOne})
	putProjectedClean(m, SliceFuncBox{S: []func() int{pureOne}})
	return m[0][0]
}
var Hook = makeHook()
`,
			wantDowngrade: false,
		},
		{
			name: "fresh_launder_array_proj_field_dirty",
			src: `package ifacebox
type SliceBox struct { S []func() int }
func pureOne() int { return 1 }
func sneak(b SliceBox) {
	holder := [1]SliceBox{b}
	s := holder[0].S
	var n int
	s[0] = func() int { n++; return n }
}
func makeHook() func() int {
	b := SliceBox{S: []func() int{pureOne}}
	sneak(b)
	return b.S[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "fresh_launder_map_index_external_slice_dirty",
			src: `package ifacebox
type SliceBox struct { S []func() int }
func pureOne() int { return 1 }
func sneak(b SliceBox) {
	m := map[int][]func() int{0: b.S}
	s := m[0]
	var n int
	s[0] = func() int { n++; return n }
}
func makeHook() func() int {
	b := SliceBox{S: []func() int{pureOne}}
	sneak(b)
	return b.S[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "fresh_launder_held_struct_map_index_external_slice_dirty",
			src: `package ifacebox
type MapSliceBox struct { M map[int][]func() int }
func pureOne() int { return 1 }
func sneak(b MapSliceBox) {
	loc := b
	m := map[int][]func() int{0: loc.M[0]}
	s := m[0]
	var n int
	s[0] = func() int { n++; return n }
}
func makeHook() func() int {
	b := MapSliceBox{M: map[int][]func() int{0: {pureOne}}}
	sneak(b)
	return b.M[0][0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "fresh_launder_range_map_external_slice_dirty",
			src: `package ifacebox
type SliceBox struct { S []func() int }
func pureOne() int { return 1 }
func sneak(b SliceBox) {
	m := map[int][]func() int{0: b.S}
	for _, s := range m {
		var n int
		s[0] = func() int { n++; return n }
	}
}
func makeHook() func() int {
	b := SliceBox{S: []func() int{pureOne}}
	sneak(b)
	return b.S[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "fresh_launder_go126_new_expr_dirty",
			src: `package ifacebox
type SliceBox struct { S []func() int }
func pureOne() int { return 1 }
func sneak(b SliceBox) {
	p := new(b)
	s := p.S
	var n int
	s[0] = func() int { n++; return n }
}
func makeHook() func() int {
	b := SliceBox{S: []func() int{pureOne}}
	sneak(b)
	return b.S[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "fresh_launder_new_ptr_deref_index_dirty",
			src: `package ifacebox
type SliceBox struct { S []func() int }
func pureOne() int { return 1 }
func sneak(b SliceBox) {
	p := new([]func() int)
	*p = b.S
	var n int
	(*p)[0] = func() int { n++; return n }
}
func makeHook() func() int {
	b := SliceBox{S: []func() int{pureOne}}
	sneak(b)
	return b.S[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "fresh_launder_two_hop_slice_dirty",
			src: `package ifacebox
type SliceBox struct { S []func() int }
func pureOne() int { return 1 }
func sneak(b SliceBox) {
	outer := [][][]func() int{{b.S}}
	mid := outer[0]
	s := mid[0]
	var n int
	s[0] = func() int { n++; return n }
}
func makeHook() func() int {
	b := SliceBox{S: []func() int{pureOne}}
	sneak(b)
	return b.S[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "elem_owned_map_comma_ok_slice_clean",
			src: `package ifacebox
func pureOne() int { return 1 }
func makeHook() func() int {
	m := map[int][]func() int{}
	m[0] = make([]func() int, 1)
	s, ok := m[0]
	if ok {
		s[0] = pureOne
	}
	return m[0][0]
}
var Hook = makeHook()
`,
			wantDowngrade: false,
		},
		{
			name: "elem_owned_slice_of_slice_clean",
			src: `package ifacebox
func pureOne() int { return 1 }
func makeHook() func() int {
	outer := [][]func() int{make([]func() int, 1)}
	s := outer[0]
	s[0] = pureOne
	return outer[0][0]
}
var Hook = makeHook()
`,
			wantDowngrade: false,
		},
		{
			name: "elem_owned_cyclic_map_struct_ptr_clean",
			src: `package ifacebox
type PtrBox struct { F func() int }
func pureOne() int { return 1 }
func makeHook() func() int {
	m := map[string]*PtrBox{}
	b, ok := m["k"]
	if !ok {
		b = &PtrBox{}
		m["k"] = b
	}
	b.F = pureOne
	return b.F
}
var Hook = makeHook()
`,
			wantDowngrade: false,
		},
		{
			name: "fresh_launder_cyclic_map_struct_ptr_external_dirty",
			src: `package ifacebox
type PtrBox struct { F func() int }
type MapPtrHolder struct { M map[string]*PtrBox }
func pureOne() int { return 1 }
func sneak(h MapPtrHolder) {
	loc := h
	m := map[string]*PtrBox{"k": loc.M["k"]}
	b, ok := m["k"]
	if !ok {
		b = &PtrBox{}
		m["k"] = b
	}
	var n int
	b.F = func() int { n++; return n }
}
func makeHook() func() int {
	h := MapPtrHolder{M: map[string]*PtrBox{"k": {F: pureOne}}}
	sneak(h)
	return h.M["k"].F
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "resolve_uses_loop_order_ctor_dirty",
			src: `package ifacebox
func pureOne() int { return 1 }
func putFn(dst []func() int, fn func() int) { dst[0] = fn }
func poisonFill(s []func() int) {
	var n int
	s[0] = func() int { n++; return n }
}
func makeHook() func() int {
	dst := []func() int{pureOne}
	s := []func() int{pureOne}
	for i := 0; i < 2; i++ {
		putFn(dst, s[0])
		poisonFill(s)
	}
	return dst[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "resolve_uses_loop_order_insertion_dirty",
			src: `package ifacebox
func pureOne() int { return 1 }
func putFn(dst []func() int, fn func() int) { dst[0] = fn }
func poisonFill(s []func() int) {
	var n int
	s[0] = func() int { n++; return n }
}
func loopInsert(dst []func() int) {
	s := []func() int{pureOne}
	for i := 0; i < 2; i++ {
		putFn(dst, s[0])
		poisonFill(s)
	}
}
func makeHook() func() int {
	dst := []func() int{pureOne}
	loopInsert(dst)
	return dst[0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
		{
			name: "chained_insertion_helper_direct_store_clean",
			src: `package ifacebox
func pureOne() int { return 1 }
func cleanFill(s []func() int, fn func() int) { s[0] = fn }
func outerPut(dst [][]func() int, s []func() int, fn func() int) {
	cleanFill(s, fn)
	dst[0] = s
}
func makeHook() func() int {
	dst := make([][]func() int, 1)
	outerPut(dst, make([]func() int, 1), pureOne)
	return dst[0][0]
}
var Hook = makeHook()
`,
			wantDowngrade: false,
		},
		{
			name: "chained_insertion_helper_call_store_clean",
			src: `package ifacebox
func pureOne() int { return 1 }
func cleanFill(s []func() int, fn func() int) { s[0] = fn }
func putSlice(dst [][]func() int, s []func() int) { dst[0] = s }
func outerPutViaCall(dst [][]func() int, s []func() int, fn func() int) {
	cleanFill(s, fn)
	putSlice(dst, s)
}
func makeHook() func() int {
	dst := make([][]func() int, 1)
	outerPutViaCall(dst, make([]func() int, 1), pureOne)
	return dst[0][0]
}
var Hook = makeHook()
`,
			wantDowngrade: false,
		},
		{
			name: "chained_insertion_helper_poison_dirty",
			src: `package ifacebox
func pureOne() int { return 1 }
func poisonFill(s []func() int) {
	var n int
	s[0] = func() int { n++; return n }
}
func outerPutDirty(dst [][]func() int, s []func() int) {
	poisonFill(s)
	dst[0] = s
}
func makeHook() func() int {
	dst := make([][]func() int, 1)
	outerPutDirty(dst, []func() int{pureOne})
	return dst[0][0]
}
var Hook = makeHook()
`,
			wantDowngrade: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := mustTypecheckOrderedPackage(t, pkgPath, []namedSourceFile{{name: "box.go", src: tc.src}})
			fact := FactOf(true, pkg)
			assertFactCanonicalAndValid(t, fact)
			cs := composeSinglePkg(pkgPath, fact, false, false)
			gotDowngrade := cs.Downgraded != ""
			if gotDowngrade != tc.wantDowngrade {
				t.Fatalf("%s: Downgraded = %q (got %v, want %v), fact=%+v", tc.name, cs.Downgraded, gotDowngrade, tc.wantDowngrade, fact)
			}
		})
	}

	// 2. Sink-plane ParamLeakFree & ReceiverReadOnly cases: non-blank type-assertion
	// and type-switch narrowing into a signature-carrying type must refuse, and
	// conversions over receiver-governed helper results must propagate taint.
	sinkPkg := mustTypecheckOrderedPackage(t, pkgPath, []namedSourceFile{{
		name: "sink.go",
		src: `package ifacebox

type CleanStruct struct{ N int }

func CallAssert(x any) int { return x.(func() int)() }
func BindAssert(x any) int { fn := x.(func() int); return fn() }
func CommaOkBindAssert(x any) int {
	fn, ok := x.(func() int)
	if ok { return fn() }
	return 0
}
func SwitchBind(x any) int {
	switch fn := x.(type) {
	case func() int:
		return fn()
	}
	return 0
}

func BlankAssert(x any) int {
	_ = x.(func() int)
	return 1
}
func CommaOkBlankAssert(x any) int {
	_, ok := x.(func() int)
	if ok { return 1 }
	return 0
}
func UntypedSwitch(x any) int {
	switch x.(type) {
	case func() int:
		return 1
	}
	return 0
}
func StructAssert(x any) int {
	s, ok := x.(*CleanStruct)
	if ok && s != nil { return s.N }
	return 0
}

type MySlice []int
type Holder struct {
	box any
	buf []int
}

func (h *Holder) getSlice() []int { return h.buf }
func (h *Holder) getAny() any { return h.box }
func (h *Holder) CallBox() int { return h.box.(func() int)() }
func (h *Holder) CallHelperBox() int { return h.getAny().(func() int)() }
func (h *Holder) MutateAssertedHelperSlice() {
	s := h.getAny().([]int)
	s[0] = 99
}
func (h *Holder) AliasingConvertedHelperSlice() int {
	s := MySlice(h.getSlice())
	return len(s)
}
func (h *Holder) ReadAssertedHelperSlice() int {
	s := h.getAny().([]int)
	return len(s)
}
func (h *Holder) CommaOkBlankBox() int {
	_, ok := h.box.(func() int)
	if ok { return 1 }
	return 0
}
`,
	}})
	sinkFact := FactOf(true, sinkPkg)
	assertFactCanonicalAndValid(t, sinkFact)
	plf := map[string]bool{}
	for _, pk := range sinkFact.ParamLeakFree {
		plf[pk.Func.Name] = true
	}
	for _, fn := range []string{"CallAssert", "BindAssert", "CommaOkBindAssert", "SwitchBind"} {
		if plf[fn] {
			t.Fatalf("expected %s to NOT be ParamLeakFree: %+v", fn, sinkFact.ParamLeakFree)
		}
	}
	for _, fn := range []string{"BlankAssert", "CommaOkBlankAssert", "UntypedSwitch", "StructAssert"} {
		if !plf[fn] {
			t.Fatalf("expected %s to be ParamLeakFree: %+v", fn, sinkFact.ParamLeakFree)
		}
	}
	rro := map[string]bool{}
	for _, fk := range sinkFact.ReceiverReadOnly {
		rro[fk.Name] = true
	}
	for _, m := range []string{"Holder.CallBox", "Holder.CallHelperBox", "Holder.MutateAssertedHelperSlice", "Holder.AliasingConvertedHelperSlice"} {
		if rro[m] {
			t.Fatalf("expected %s to NOT be ReceiverReadOnly: %+v", m, sinkFact.ReceiverReadOnly)
		}
	}
	for _, m := range []string{"Holder.ReadAssertedHelperSlice", "Holder.CommaOkBlankBox"} {
		if !rro[m] {
			t.Fatalf("expected %s to be ReceiverReadOnly: %+v", m, sinkFact.ReceiverReadOnly)
		}
	}
}

func TestPropertyInterfaceBoundaryStateDriftOracle(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		const pkgPath = "example.com/propiface"
		dirty := rapid.Bool().Draw(rt, "dirty")
		boxShape := rapid.IntRange(0, 12).Draw(rt, "boxShape")
		useKind := rapid.IntRange(0, 3).Draw(rt, "useKind")

		// Model both carrier shapes: `var Hook func() int` (signature carrier) and `var Box any` (interface carrier).
		useBoxGlobal := useKind >= 1

		var src strings.Builder
		src.WriteString("package propiface\n")
		if !useBoxGlobal && boxShape == 1 {
			src.WriteString("import \"slices\"\n")
		}
		src.WriteString("func pureFn() int { return 7 }\n")
		src.WriteString("func putAny(m map[int]func() int, side map[int]any, fn func() int, x any) { m[0] = fn; side[0] = x }\n")
		src.WriteString("func passBox(x any) func() int { if x == nil { return nil }; return pureFn }\n")
		src.WriteString("func callBoxAssert(x any) int { return x.(func() int)() }\n")
		src.WriteString("func callBoxSwitch(x any) int { switch fn := x.(type) { case func() int: return fn() }; return 0 }\n")
		src.WriteString("func checkBoxBlank(x any) int { _, ok := x.(func() int); if ok { return 7 }; return 0 }\n")

		fnExpr := "pureFn"
		if dirty {
			fnExpr = "func() int { n++; return n }"
		}

		if useBoxGlobal {
			src.WriteString("func makeBox() any {\n")
			if dirty {
				src.WriteString("\tvar n int\n")
			}
			src.WriteString("\treturn any(" + fnExpr + ")\n}\n")
			src.WriteString("var Box any = makeBox()\n")
			switch useKind {
			case 1:
				src.WriteString("func Entry() int { return callBoxAssert(Box) }\n")
			case 2:
				src.WriteString("func Entry() int { return callBoxSwitch(Box) }\n")
			case 3:
				src.WriteString("func Entry() int { return checkBoxBlank(Box) }\n")
			}
		} else {
			switch boxShape {
			case 0:
				src.WriteString("var Hook func() int\nfunc init() {\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\tvar b any = " + fnExpr + "\n")
				src.WriteString("\tHook = func() int { _, ok := b.(func() int); if ok { return 7 }; return 0 }\n}\n")
			case 1:
				src.WriteString("var Hook func() int\nfunc init() {\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\ts := slices.Clone([]any{" + fnExpr + "})\n")
				src.WriteString("\tHook = func() int { return len(s) }\n}\n")
			case 2:
				src.WriteString("func makeHook() func() int {\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\tvar b any = " + fnExpr + "\n")
				src.WriteString("\tswitch fn := b.(type) { case func() int: return fn }\n\treturn nil\n}\n")
				src.WriteString("var Hook = makeHook()\n")
			case 3:
				src.WriteString("var Hook func() int\nfunc init() {\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\tHook = passBox(any(" + fnExpr + "))\n}\n")
			case 4:
				src.WriteString("func makeHook() func() int {\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\tm := map[int]func() int{}\n\tside := map[int]any{}\n\tputAny(m, side, pureFn, any(" + fnExpr + "))\n")
				src.WriteString("\treturn m[0]\n}\n")
				src.WriteString("var Hook = makeHook()\n")
			case 5:
				src.WriteString("func makeHook() func() int {\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\tvar b any = " + fnExpr + "\n")
				src.WriteString("\treturn func() int { if b != nil { return 7 }; return 0 }\n}\n")
				src.WriteString("var Hook = makeHook()\n")
			case 6:
				src.WriteString("type ArrFn [1]func() int\nfunc putArr(dst []ArrFn, x ArrFn) {\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\tx[0] = " + fnExpr + "\n\tdst[0] = x\n}\n")
				src.WriteString("func makeHook() func() int {\n\tdst := make([]ArrFn, 1)\n\tputArr(dst, ArrFn{pureFn})\n\treturn dst[0][0]\n}\n")
				src.WriteString("var Hook = makeHook()\n")
			case 7:
				src.WriteString("type ValFuncBox struct { F func() int }\nfunc putValBox(dst []ValFuncBox, x ValFuncBox) {\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\tx.F = " + fnExpr + "\n\tdst[0] = x\n}\n")
				src.WriteString("func makeHook() func() int {\n\tdst := make([]ValFuncBox, 1)\n\tputValBox(dst, ValFuncBox{F: pureFn})\n\treturn dst[0].F\n}\n")
				src.WriteString("var Hook = makeHook()\n")
			case 8:
				src.WriteString("type MapFuncBox struct { M map[string]func() int }\nfunc putMapBox(dst []MapFuncBox, x MapFuncBox) {\n\tloc := x\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\tloc.M[\"k\"] = " + fnExpr + "\n\tdst[0] = x\n}\n")
				src.WriteString("func makeHook() func() int {\n\tdst := make([]MapFuncBox, 1)\n\tputMapBox(dst, MapFuncBox{M: map[string]func() int{\"k\": pureFn}})\n\treturn dst[0].M[\"k\"]\n}\n")
				src.WriteString("var Hook = makeHook()\n")
			case 9:
				src.WriteString("type SliceBox struct { S []func() int }\nfunc sneakArrProj(b SliceBox) {\n\tholder := [1]SliceBox{b}\n\ts := holder[0].S\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\ts[0] = " + fnExpr + "\n}\n")
				src.WriteString("func makeHook() func() int {\n\tb := SliceBox{S: []func() int{pureFn}}\n\tsneakArrProj(b)\n\treturn b.S[0]\n}\n")
				src.WriteString("var Hook = makeHook()\n")
			case 10:
				src.WriteString("type MapSliceBox struct { M map[int][]func() int }\nfunc sneakMapIdx(b MapSliceBox) {\n\tloc := b\n\tm := map[int][]func() int{0: loc.M[0]}\n\ts := m[0]\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\ts[0] = " + fnExpr + "\n}\n")
				src.WriteString("func makeHook() func() int {\n\tb := MapSliceBox{M: map[int][]func() int{0: {pureFn}}}\n\tsneakMapIdx(b)\n\treturn b.M[0][0]\n}\n")
				src.WriteString("var Hook = makeHook()\n")
			case 11:
				src.WriteString("func putFn(dst []func() int, fn func() int) { dst[0] = fn }\nfunc fillSlice(s []func() int) {\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\ts[0] = " + fnExpr + "\n}\n")
				src.WriteString("func makeHook() func() int {\n\tdst := []func() int{pureFn}\n\ts := []func() int{pureFn}\n\tfor i := 0; i < 2; i++ {\n\t\tputFn(dst, s[0])\n\t\tfillSlice(s)\n\t}\n\treturn dst[0]\n}\n")
				src.WriteString("var Hook = makeHook()\n")
			case 12:
				src.WriteString("func cleanFill(s []func() int, fn func() int) { s[0] = fn }\nfunc outerPut(dst [][]func() int, s []func() int, fn func() int) {\n\tcleanFill(s, fn)\n\tdst[0] = s\n}\n")
				src.WriteString("func makeHook() func() int {\n")
				if dirty {
					src.WriteString("\tvar n int\n")
				}
				src.WriteString("\tdst := make([][]func() int, 1)\n\touterPut(dst, make([]func() int, 1), " + fnExpr + ")\n\treturn dst[0][0]\n}\n")
				src.WriteString("var Hook = makeHook()\n")
			}
			src.WriteString("func Entry() int { return Hook() }\n")
		}

		pkg := mustTypecheckOrderedPackage(rt, pkgPath, []namedSourceFile{{name: "gen.go", src: src.String()}})
		fact := FactOf(true, pkg)
		assertFactCanonicalAndValid(rt, fact)
		cs := composeSinglePkg(pkgPath, fact, false, false)

		// Ground-truth state-drift oracle: does calling Entry() twice observe stateful drift?
		drifts := false
		if useBoxGlobal {
			drifts = dirty && (useKind == 1 || useKind == 2)
		} else {
			drifts = dirty && (boxShape == 2 || boxShape >= 6)
		}
		if drifts && cs.Downgraded == "" {
			rt.Fatalf("SOUNDNESS FAILURE: state-drifting program admitted without downgrade!\nsrc:\n%s\nfact: %+v", src.String(), fact)
		}
		// Every dirty shape outside blank-discarded Box must downgrade at the static confinement boundary.
		if dirty && (!useBoxGlobal || useKind != 3) && cs.Downgraded == "" {
			rt.Fatalf("SOUNDNESS FAILURE: stateful boxed/inserted closure admitted without downgrade!\nsrc:\n%s\nfact: %+v", src.String(), fact)
		}
		// Additionally verify precision on known-clean shapes!
		if !dirty && !useBoxGlobal && boxShape != 2 && cs.Downgraded != "" {
			rt.Fatalf("PRECISION FAILURE: clean interface-boxed program downgraded: %+v\nsrc:\n%s", cs, src.String())
		}
		if useBoxGlobal && useKind == 3 && cs.Downgraded != "" {
			rt.Fatalf("PRECISION FAILURE: blank-discarded type assertion on Box downgraded: %+v\nsrc:\n%s", cs, src.String())
		}
	})
}
