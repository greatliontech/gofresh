package rta

import (
	"context"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
)

func TestContainsTypeParamAndStaggeredMasks(t *testing.T) {
	const src = `package p

type Node struct {
	Next *Node
}

func (n *Node) Step() *Node { return n.Next }

type Stepper interface {
	Step() *Node
}

func Gen[T any]() any {
	type Local struct {
		Self *Local
		V    T
	}
	return Local{}
}

func RootA() *Node {
	var s Stepper = &Node{}
	return s.Step()
}

func RootB() *Node {
	var s Stepper = &Node{}
	return s.Step()
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	files := []*ast.File{f}
	pkg := types.NewPackage("example.com/p", "p")
	ssaPkg, _, err := ssautil.BuildPackage(&types.Config{Importer: importer.Default()}, fset, pkg, files, ssa.InstantiateGenerics)
	if err != nil {
		t.Fatalf("BuildPackage: %v", err)
	}
	prog := ssaPkg.Prog

	nodeType := pkg.Scope().Lookup("Node").Type()
	if ContainsTypeParam(nodeType, make(map[types.Type]bool)) {
		t.Fatalf("ContainsTypeParam(Node) = true, want false")
	}

	genFn := ssaPkg.Func("Gen")
	if genFn == nil {
		t.Fatal("missing Gen function")
	}
	var localType types.Type
	for _, b := range genFn.Blocks {
		for _, instr := range b.Instrs {
			if mi, ok := instr.(*ssa.MakeInterface); ok {
				localType = mi.X.Type()
			}
		}
	}
	if localType == nil {
		t.Fatal("missing MakeInterface in Gen")
	}
	if !ContainsTypeParam(localType, make(map[types.Type]bool)) {
		t.Fatalf("ContainsTypeParam(%v) = false, want true", localType)
	}

	if _, err := Analyze(context.Background(), map[*ssa.Function]uint64{genFn: 1}, nil); err == nil {
		t.Fatal("Analyze accepted parameterized origin root Gen")
	}

	rootA := ssaPkg.Func("RootA")
	rootB := ssaPkg.Func("RootB")
	step := prog.LookupMethod(types.NewPointer(nodeType), pkg, "Step")
	if rootA == nil || rootB == nil || step == nil {
		t.Fatalf("missing functions: rootA=%v rootB=%v step=%v", rootA, rootB, step)
	}

	res, err := Analyze(context.Background(), map[*ssa.Function]uint64{
		rootA: 1 << 0,
		rootB: 1 << 1,
	}, &Seeds{
		RuntimeTypes: []TypeSeed{
			{Type: localType, Masks: 1 << 0},
			{Type: nodeType, Masks: 1 << 0},
			{Type: nodeType, Masks: 1 << 1},
		},
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	const wantMask = uint64(1<<0 | 1<<1)
	if got := res.Reachable[step]; got != wantMask {
		t.Fatalf("Reachable[(*Node).Step] = %#b, want %#b", got, wantMask)
	}
}

func TestSkippedUnderlyingDoesNotSynthesizePhantomUnnamedWrapper(t *testing.T) {
	const src = `package p

type Item interface {
	Value() int
}

type baseItem struct{}

func (baseItem) Value() int { return 7 }

type Promoted struct {
	Item
}

func NamedOnly() int {
	var it Item = Promoted{Item: baseItem{}}
	return it.Value()
}

func NamedThenUnnamed() int {
	var a Item = Promoted{Item: baseItem{}}
	var b Item = struct{ Item }{Item: baseItem{}}
	return a.Value() + b.Value()
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	pkg := types.NewPackage("example.com/p", "p")
	ssaPkg, _, err := ssautil.BuildPackage(&types.Config{Importer: importer.Default()}, fset, pkg, []*ast.File{f}, ssa.InstantiateGenerics)
	if err != nil {
		t.Fatalf("BuildPackage: %v", err)
	}
	prog := ssaPkg.Prog
	namedOnly := ssaPkg.Func("NamedOnly")
	namedThenUnnamed := ssaPkg.Func("NamedThenUnnamed")
	promotedType := pkg.Scope().Lookup("Promoted").Type()
	unnamedType := promotedType.Underlying()
	namedWrapper := prog.LookupMethod(promotedType, pkg, "Value")
	unnamedWrapper := prog.LookupMethod(unnamedType, pkg, "Value")

	res, err := Analyze(context.Background(), map[*ssa.Function]uint64{
		namedOnly:        1 << 0,
		namedThenUnnamed: 1 << 1,
	}, nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if got := res.Reachable[namedWrapper]; got != (1<<0 | 1<<1) {
		t.Fatalf("Reachable[(Promoted).Value] = %#b, want %#b", got, 1<<0|1<<1)
	}
	if got := res.Reachable[unnamedWrapper]; got != (1 << 1) {
		t.Fatalf("Reachable[(struct{ Item }).Value] = %#b, want %#b (only NamedThenUnnamed)", got, 1<<1)
	}
}

func TestReflectMethodValueResolutionAndMaskIsolation(t *testing.T) {
	const src = `package p

import (
	"fmt"
	"reflect"
)

type Worker struct{}

func (w *Worker) Act(x int) int { return x + 1 }

type unexportedHolder struct {
	fn func(int) int
}

type embeddedBase struct {
	Fn      func(int) int
	blocked []func(int) int
}

type promotedHolder struct {
	embeddedBase
}

var nilHook func(int) int

func RootTypeAssert() int {
	var anyW any = &Worker{}
	fn := reflect.ValueOf(anyW).Method(0).Interface().(func(int) int)
	return fn(1)
}

func RootSetMap() int {
	var anyW any = &Worker{}
	m := map[string]func(int) int{}
	reflect.ValueOf(m).SetMapIndex(reflect.ValueOf("k"), reflect.ValueOf(anyW).MethodByName("Act"))
	return m["k"](1)
}

func RootFormatOnly() int {
	var anyW any = &Worker{}
	_ = fmt.Sprint(reflect.ValueOf(anyW))
	if nilHook != nil {
		return nilHook(1)
	}
	return 0
}

func RootMethodWithoutUnbox() int {
	var anyW any = &Worker{}
	_ = reflect.ValueOf(anyW).Method(0)
	if nilHook != nil {
		return nilHook(1)
	}
	return 0
}

func RootUnexportedFieldOnly() int {
	var anyW any = &Worker{}
	var anyH any = &unexportedHolder{}
	_ = anyH
	_ = reflect.ValueOf(anyW).Method(0)
	dst := 0
	reflect.ValueOf(&dst).Elem().Set(reflect.ValueOf(1))
	if nilHook != nil {
		return nilHook(1)
	}
	return dst
}

func RootEmbeddedBlockedSliceOnly() int {
	var anyW any = &Worker{}
	type sliceEmbed struct {
		innerSlice
	}
	var _ = sliceEmbed{}
	_ = reflect.ValueOf(anyW).Method(0)
	dst := 0
	reflect.ValueOf(&dst).Elem().Set(reflect.ValueOf(1))
	if nilHook != nil {
		return nilHook(1)
	}
	return dst
}

type innerSlice struct {
	s []func(int) int
}

func RootPromotedExportedField() int {
	var anyW any = &Worker{}
	h := &promotedHolder{}
	reflect.ValueOf(h).Elem().FieldByName("Fn").Set(reflect.ValueOf(anyW).Method(0))
	return h.Fn(1)
}

func RootMethodsIter() int {
	var anyW any = &Worker{}
	for _, mv := range reflect.ValueOf(anyW).Methods() {
		if fn, ok := mv.Interface().(func(int) int); ok {
			return fn(1)
		}
	}
	return 0
}

func RootReflectTypeAssertGeneric() int {
	var anyW any = &Worker{}
	if fn, ok := reflect.TypeAssert[func(int) int](reflect.ValueOf(anyW).Method(0)); ok {
		return fn(1)
	}
	return 0
}

func RootAppendSlice() int {
	var anyW any = &Worker{}
	var s []func(int) int
	s = reflect.Append(reflect.ValueOf(s), reflect.ValueOf(anyW).Method(0)).Interface().([]func(int) int)
	return s[0](1)
}

func RootChanSend() int {
	var anyW any = &Worker{}
	ch := make(chan func(int) int, 1)
	reflect.ValueOf(ch).Send(reflect.ValueOf(anyW).Method(0))
	fn := <-ch
	return fn(1)
}

func RootSetMapDoesNotPolluteStructField() int {
	var anyW any = &Worker{}
	var anyH any = &promotedHolder{}
	_ = anyH
	m := map[string]int{}
	reflect.ValueOf(m).SetMapIndex(reflect.ValueOf("k"), reflect.ValueOf(1))
	_ = reflect.ValueOf(anyW).Method(0)
	if nilHook != nil {
		return nilHook(1)
	}
	return 0
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	pkg := types.NewPackage("example.com/p", "p")
	ssaPkg, _, err := ssautil.BuildPackage(&types.Config{Importer: importer.Default()}, fset, pkg, []*ast.File{f}, ssa.InstantiateGenerics)
	if err != nil {
		t.Fatalf("BuildPackage: %v", err)
	}
	prog := ssaPkg.Prog
	workerPtr := types.NewPointer(pkg.Scope().Lookup("Worker").Type())
	mset := prog.MethodSets.MethodSet(workerPtr)
	if mset.Len() != 1 {
		t.Fatalf("Worker method count = %d, want 1", mset.Len())
	}
	actBound := prog.MethodValue(mset.At(0))
	if actBound == nil {
		t.Fatal("missing (*Worker).Act$bound")
	}

	rootNames := []string{
		"RootTypeAssert",
		"RootSetMap",
		"RootFormatOnly",
		"RootMethodWithoutUnbox",
		"RootUnexportedFieldOnly",
		"RootEmbeddedBlockedSliceOnly",
		"RootPromotedExportedField",
		"RootMethodsIter",
		"RootReflectTypeAssertGeneric",
		"RootAppendSlice",
		"RootChanSend",
		"RootSetMapDoesNotPolluteStructField",
	}
	roots := make(map[*ssa.Function]uint64, len(rootNames))
	dynSites := make(map[string]ssa.CallInstruction, len(rootNames))
	var findIntToIntDynCall func(*ssa.Function) ssa.CallInstruction
	findIntToIntDynCall = func(fn *ssa.Function) ssa.CallInstruction {
		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				if call, ok := ins.(ssa.CallInstruction); ok && !call.Common().IsInvoke() && call.Common().StaticCallee() == nil {
					if _, isBuiltin := call.Common().Value.(*ssa.Builtin); isBuiltin {
						continue
					}
					sig := call.Common().Signature()
					if sig != nil && sig.Params().Len() == 1 && types.Identical(sig.Params().At(0).Type(), types.Typ[types.Int]) {
						return call
					}
				}
			}
		}
		for _, anon := range fn.AnonFuncs {
			if site := findIntToIntDynCall(anon); site != nil {
				return site
			}
		}
		return nil
	}
	for i, name := range rootNames {
		fn := ssaPkg.Func(name)
		if fn == nil {
			t.Fatalf("missing root %s", name)
		}
		roots[fn] = 1 << i
		dynSites[name] = findIntToIntDynCall(fn)
		if dynSites[name] == nil {
			t.Fatalf("missing dynamic call site in %s", name)
		}
	}

	res, err := Analyze(context.Background(), roots, nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	wantResolved := map[string]bool{
		"RootTypeAssert":                      true,
		"RootSetMap":                          true,
		"RootFormatOnly":                      false,
		"RootMethodWithoutUnbox":              false,
		"RootUnexportedFieldOnly":             false,
		"RootEmbeddedBlockedSliceOnly":        false,
		"RootPromotedExportedField":           true,
		"RootMethodsIter":                     true,
		"RootReflectTypeAssertGeneric":        true,
		"RootAppendSlice":                     true,
		"RootChanSend":                        true,
		"RootSetMapDoesNotPolluteStructField": false,
	}
	for i, name := range rootNames {
		mask := uint64(1) << i
		site := dynSites[name]
		got := res.Targets[site][actBound]&mask != 0
		if got != wantResolved[name] {
			t.Fatalf("%s: Targets[site][actBound]&mask = %v (full=%#b), want %v", name, got, res.Targets[site][actBound], wantResolved[name])
		}
	}
}

type mapImporter struct {
	prog *ssa.Program
	pkgs map[string]*types.Package
}

func (m *mapImporter) registerDeps(pkg *types.Package) {
	if pkg == nil || m.prog.Package(pkg) != nil {
		return
	}
	for _, imp := range pkg.Imports() {
		m.registerDeps(imp)
	}
	m.prog.CreatePackage(pkg, nil, nil, true)
}

func (m *mapImporter) Import(path string) (*types.Package, error) {
	if pkg, ok := m.pkgs[path]; ok {
		return pkg, nil
	}
	pkg, err := importer.Default().Import(path)
	if err != nil {
		return nil, err
	}
	m.pkgs[path] = pkg
	m.registerDeps(pkg)
	return pkg, nil
}

func TestClosedMethodValueSigsAndHarnessStdIsolation(t *testing.T) {
	fset := token.NewFileSet()
	prog := ssa.NewProgram(fset, ssa.InstantiateGenerics)
	imp := &mapImporter{prog: prog, pkgs: map[string]*types.Package{}}

	buildMemPkg := func(pkgPath, pkgName, src string) *ssa.Package {
		f, err := parser.ParseFile(fset, pkgName+".go", src, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", pkgPath, err)
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
		tpkg, err := (&types.Config{Importer: imp}).Check(pkgPath, fset, []*ast.File{f}, info)
		if err != nil {
			t.Fatalf("Check(%s): %v", pkgPath, err)
		}
		imp.pkgs[pkgPath] = tpkg
		return prog.CreatePackage(tpkg, []*ast.File{f}, info, true)
	}

	_ = buildMemPkg("stdinner", "stdinner", `package stdinner

type InternalError struct{ msg string }

func (e *InternalError) Error() string { return e.msg }

func MakeErr() error { return &InternalError{msg: "bad"} }

func FormatAny(x any) string {
	if s, ok := x.(interface{ String() string }); ok {
		return s.String()
	}
	return ""
}
`)

	_ = buildMemPkg("example.com/rtaharness/harness", "harness", `package harness

import "stdinner"

type T struct{ v int }

func Check(fn func(*T)) {
	err := stdinner.MakeErr()
	if err != nil {
		_ = err.Error()
	}
	fn(&T{})
}

func FormatAny(x any) string {
	return stdinner.FormatAny(x)
}
`)

	ssaPkg := buildMemPkg("example.com/rtaharness/subj", "subj", `package subj

import (
	"reflect"
	"example.com/rtaharness/harness"
)

type subjErr struct{}

func (subjErr) Error() string { return "ok" }

type customStringer struct{}

func (customStringer) String() string { return "custom" }

type methodHolder struct{ base int }

func (m *methodHolder) Add(x int) int { return m.base + x }
func (m *methodHolder) Sub(x int) string { return "sub" }

func callIntFn(f func(int) int) int { return f(5) }

func RootMethodValueClosure() int {
	m := &methodHolder{base: 10}
	fn := reflect.ValueOf(m).Method(0).Interface().(func(int) int)
	return callIntFn(fn)
}

func RootHarnessErrorAndStringerIsolation() string {
	var out string
	harness.Check(func(*harness.T) {
		var err error = subjErr{}
		out = err.Error() + harness.FormatAny(customStringer{})
	})
	return out
}
`)

	prog.Build()

	rootMV := ssaPkg.Func("RootMethodValueClosure")
	callHelper := ssaPkg.Func("callIntFn")
	rootIso := ssaPkg.Func("RootHarnessErrorAndStringerIsolation")
	if rootMV == nil || callHelper == nil || rootIso == nil {
		t.Fatalf("missing root functions: %v %v %v", rootMV, callHelper, rootIso)
	}
	roots := map[*ssa.Function]uint64{
		rootMV:  1 << 0,
		rootIso: 1 << 1,
	}
	res, err := Analyze(context.Background(), roots, &Seeds{
		HarnessPkg: "example.com/rtaharness/harness",
		UserPkgs:   map[string]bool{"example.com/rtaharness/harness": true, "example.com/rtaharness/subj": true},
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// 1. Closed reflect.Value.Method(0) resolves m.Add via closedMethodValueSigs.
	var mvSite ssa.CallInstruction
	for _, b := range callHelper.Blocks {
		for _, instr := range b.Instrs {
			if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil && site.Common().StaticCallee() == nil {
				mvSite = site
			}
		}
	}
	if mvSite == nil {
		t.Fatalf("missing dynamic call site in callIntFn")
	}
	sawAdd, sawSub := false, false
	for target, m := range res.Targets[mvSite] {
		if m&(1<<0) == 0 {
			continue
		}
		if strings.Contains(target.Name(), "Add") {
			sawAdd = true
		}
		if strings.Contains(target.Name(), "Sub") {
			sawSub = true
		}
	}
	if !sawAdd || sawSub {
		t.Fatalf("method-value closure targets: sawAdd=%v sawSub=%v, want true/false", sawAdd, sawSub)
	}

	// 2. Plane 1 isolation: *stdinner.InternalError must NOT appear on Plane 0
	// error.Error() inside RootHarnessErrorAndStringerIsolation's closure,
	// while customStringer.String MUST promote via FormatAny.
	var sawStdInnerErrOnSubjInvoke, sawCustomStringer bool
	for site, targets := range res.Targets {
		if site.Parent() != nil && strings.HasPrefix(site.Parent().Name(), "RootHarnessErrorAndStringerIsolation$") && site.Common().IsInvoke() {
			for target, m := range targets {
				if m&(1<<1) != 0 && target.Pkg != nil && target.Pkg.Pkg.Path() == "stdinner" {
					sawStdInnerErrOnSubjInvoke = true
				}
			}
		}
		for target, m := range targets {
			if m&(1<<1) != 0 && target.Name() == "String" && target.Pkg != nil && target.Pkg.Pkg.Path() == "example.com/rtaharness/subj" {
				sawCustomStringer = true
			}
		}
	}
	for _, targets := range res.HarnessStdTargets {
		for target, m := range targets {
			if m&(1<<1) != 0 && target.Name() == "String" && target.Pkg != nil && target.Pkg.Pkg.Path() == "example.com/rtaharness/subj" {
				sawCustomStringer = true
			}
		}
	}
	if sawStdInnerErrOnSubjInvoke {
		t.Fatalf("Plane 1 stdinner.InternalError leaked onto Plane 0 subject error.Error() invoke")
	}
	if !sawCustomStringer {
		t.Fatalf("expected user customStringer.String to be reached through harness formatting")
	}
}

func TestContainsTypeParamComprehensive(t *testing.T) {
	if ContainsTypeParam(nil, nil) {
		t.Fatal("ContainsTypeParam(nil) = true, want false")
	}
	if ContainsTypeParam(types.Typ[types.Int], nil) {
		t.Fatal("ContainsTypeParam(int) = true, want false")
	}

	pkg := types.NewPackage("example.com/tp", "tp")
	tpName := types.NewTypeName(token.NoPos, pkg, "T", nil)
	tp := types.NewTypeParam(tpName, types.NewInterfaceType(nil, nil))
	if !ContainsTypeParam(tp, nil) {
		t.Fatal("ContainsTypeParam(TypeParam) = false, want true")
	}

	unionTerm := types.NewTerm(true, types.Typ[types.Int])
	unionType := types.NewUnion([]*types.Term{unionTerm})
	if !ContainsTypeParam(unionType, nil) {
		t.Fatal("ContainsTypeParam(Union) = false, want true")
	}

	constraintIface := types.NewInterfaceType(nil, []types.Type{unionType})
	constraintIface.Complete()
	if !ContainsTypeParam(constraintIface, nil) {
		t.Fatal("ContainsTypeParam(constraint Interface) = false, want true")
	}
	constraintNamedObj := types.NewTypeName(token.NoPos, pkg, "Ordered", nil)
	constraintNamed := types.NewNamed(constraintNamedObj, constraintIface, nil)
	pkg.Scope().Insert(constraintNamedObj)
	if !ContainsTypeParam(constraintNamed, nil) {
		t.Fatal("ContainsTypeParam(package-scope constraint Named) = false, want true")
	}

	for _, w := range []types.Type{
		types.NewPointer(tp),
		types.NewSlice(tp),
		types.NewArray(tp, 4),
		types.NewChan(types.SendRecv, tp),
		types.NewMap(types.Typ[types.String], tp),
		types.NewMap(tp, types.Typ[types.String]),
		types.NewTuple(types.NewVar(token.NoPos, pkg, "x", tp)),
		types.NewStruct([]*types.Var{types.NewVar(token.NoPos, pkg, "F", tp)}, nil),
		types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, pkg, "x", tp)), nil, false),
		types.NewSignatureType(nil, nil, []*types.TypeParam{tp}, nil, nil, false),
	} {
		if !ContainsTypeParam(w, nil) {
			t.Fatalf("ContainsTypeParam(%T) = false, want true", w)
		}
	}

	for _, w := range []types.Type{
		types.NewPointer(types.Typ[types.Int]),
		types.NewSlice(types.Typ[types.String]),
		types.NewArray(types.Typ[types.Byte], 8),
		types.NewChan(types.SendOnly, types.Typ[types.Int]),
		types.NewMap(types.Typ[types.String], types.Typ[types.Int]),
		types.NewTuple(types.NewVar(token.NoPos, pkg, "x", types.Typ[types.Int])),
		types.NewStruct([]*types.Var{types.NewVar(token.NoPos, pkg, "F", types.Typ[types.Int])}, nil),
		types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, pkg, "x", types.Typ[types.Int])), nil, false),
	} {
		if ContainsTypeParam(w, nil) {
			t.Fatalf("ContainsTypeParam(%T) = true, want false", w)
		}
	}

	// Alias cycle with function-local Named containing TypeParam: verifies
	// seen[unaliased] breaks alias cycles and still finds the trailing TypeParam.
	localNamedObj := types.NewTypeName(token.NoPos, pkg, "LocalCyclic", nil)
	localNamed := types.NewNamed(localNamedObj, nil, nil)
	aliasObj := types.NewTypeName(token.NoPos, pkg, "LocalAlias", nil)
	aliasType := types.NewAlias(aliasObj, localNamed)
	localStruct := types.NewStruct([]*types.Var{
		types.NewVar(token.NoPos, pkg, "Self", types.NewPointer(aliasType)),
		types.NewVar(token.NoPos, pkg, "Val", tp),
	}, nil)
	localNamed.SetUnderlying(localStruct)
	if !ContainsTypeParam(aliasType, nil) {
		t.Fatal("ContainsTypeParam(LocalAlias -> LocalCyclic with TypeParam) = false, want true")
	}
}

func TestTypedCallbackTrampolineAssertAndNoBoundSynthesis(t *testing.T) {
	const src = `package p

type Heavy struct{ x int }

func (h *Heavy) M1() int { return h.x }
func (h *Heavy) M2() int { return h.x + 1 }

func startTimer(when int64, f func(any, uintptr), arg any)

func goFunc(arg any, seq uintptr) {
	arg.(func())()
}

func goFuncRecursive(arg any) {
	if arg == nil {
		goFuncRecursive(func() {})
		return
	}
	arg.(func())()
}

func ExportedGoFunc(arg any, seq uintptr) {
	arg.(func())()
}

func (h *Heavy) methodGoFunc(arg any) {
	arg.(func())()
}

func badUntypedCaller(arg any) {
	arg.(func())()
}

func leakTrampolineTarget(arg any, seq uintptr) {
	arg.(func())()
}

func bodyTrampoline(f func(any), arg any) {
	f(arg)
}

func bodyTrampolineTarget(arg any) {
	arg.(func())()
}

func AfterFunc(d int64, f func()) {
	startTimer(d, goFunc, f)
	goFuncRecursive(f)
}

var leakedTrampolineSink any

func TriggerNegativeCases(f func(), untyped any) {
	startTimer(1, ExportedGoFunc, f)
	h := &Heavy{}
	h.methodGoFunc(f)
	badUntypedCaller(untyped)
	leakedTrampolineSink = startTimerLeaked
	startTimerLeaked(1, leakTrampolineTarget, f)
	bodyTrampoline(bodyTrampolineTarget, f)
}

func startTimerLeaked(when int64, f func(any, uintptr), arg any)
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	pkg := types.NewPackage("example.com/tramp", "p")
	ssaPkg, _, err := ssautil.BuildPackage(&types.Config{Importer: importer.Default()}, fset, pkg, []*ast.File{f}, ssa.InstantiateGenerics)
	if err != nil {
		t.Fatalf("BuildPackage: %v", err)
	}

	findTypeAssert := func(fnName string) (*ssa.Function, *ssa.TypeAssert) {
		fn := ssaPkg.Func(fnName)
		if fn == nil {
			t.Fatalf("missing function %s", fnName)
		}
		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				if ta, ok := ins.(*ssa.TypeAssert); ok {
					return fn, ta
				}
			}
		}
		t.Fatalf("missing TypeAssert in %s", fnName)
		return nil, nil
	}

	for _, posName := range []string{"goFunc", "goFuncRecursive"} {
		fn, ta := findTypeAssert(posName)
		if !checkTypedCallbackTrampolineAssert(fn, ta) {
			t.Fatalf("checkTypedCallbackTrampolineAssert(%s) = false, want true", posName)
		}
	}

	for _, negName := range []string{
		"ExportedGoFunc",
		"badUntypedCaller",
		"leakTrampolineTarget",
		"bodyTrampolineTarget",
	} {
		fn, ta := findTypeAssert(negName)
		if checkTypedCallbackTrampolineAssert(fn, ta) {
			t.Fatalf("checkTypedCallbackTrampolineAssert(%s) = true, want false", negName)
		}
	}

	heavyType := pkg.Scope().Lookup("Heavy").Type()
	methodFn := ssaPkg.Prog.LookupMethod(types.NewPointer(heavyType), pkg, "methodGoFunc")
	if methodFn == nil {
		t.Fatal("missing (*Heavy).methodGoFunc")
	}
	var methodTA *ssa.TypeAssert
	for _, b := range methodFn.Blocks {
		for _, ins := range b.Instrs {
			if ta, ok := ins.(*ssa.TypeAssert); ok {
				methodTA = ta
			}
		}
	}
	if methodTA == nil || checkTypedCallbackTrampolineAssert(methodFn, methodTA) {
		t.Fatal("checkTypedCallbackTrampolineAssert((*Heavy).methodGoFunc) = true, want false")
	}

	// Verify that running checkTypedCallbackTrampolineAssert did NOT synthesize
	// $bound wrappers on Heavy's other methods (M1, M2) via MethodValue.
	allFns := ssautil.AllFunctions(ssaPkg.Prog)
	for fn := range allFns {
		if fn != nil && strings.HasSuffix(fn.Name(), "$bound") {
			t.Fatalf("unexpected $bound wrapper synthesized during checkTypedCallbackTrampolineAssert: %s", fn.String())
		}
	}
}

func TestClosedMethodValueSigsAndOnlyDirectCallCallee(t *testing.T) {
	const src = `package p

import "reflect"

var sink reflect.Value

func helperUnbox(v reflect.Value) int {
	if !v.IsValid() {
		return 0
	}
	fn := v.Interface().(func(int) int)
	return fn(3)
}

func variadicSink(vs ...reflect.Value) {}

func ClosedViaHelperAndPhi(x any, cond bool) int {
	v := reflect.ValueOf(x)
	m := v.Method(0)
	if cond {
		m = v.MethodByName("Act")
	}
	return helperUnbox(m)
}

func EscapesToGlobal(x any) {
	sink = reflect.ValueOf(x).Method(0)
}

func EscapesToVariadic(x any) {
	variadicSink(reflect.ValueOf(x).Method(0))
}

func EscapesToIfaceAssert(x any) any {
	return reflect.ValueOf(x).Method(0).Interface().(any)
}

var escapedClosureSink func(int) int

func DirectAndEscapingClosures(base int) int {
	direct := func(y int) int { return base + y }(10)
	escaped := func(y int) int { return base - y }
	escapedClosureSink = escaped
	return direct + escaped(2)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	pkg := types.NewPackage("example.com/mv", "p")
	ssaPkg, _, err := ssautil.BuildPackage(&types.Config{Importer: importer.Default()}, fset, pkg, []*ast.File{f}, ssa.InstantiateGenerics)
	if err != nil {
		t.Fatalf("BuildPackage: %v", err)
	}

	findMethodCalls := func(fnName string) []*ssa.Call {
		fn := ssaPkg.Func(fnName)
		if fn == nil {
			t.Fatalf("missing %s", fnName)
		}
		var out []*ssa.Call
		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				sc, ok := ins.(*ssa.Call)
				if !ok {
					continue
				}
				if callee := sc.Common().StaticCallee(); callee != nil && (callee.Name() == "Method" || callee.Name() == "MethodByName") {
					out = append(out, sc)
				}
			}
		}
		return out
	}

	for _, sc := range findMethodCalls("ClosedViaHelperAndPhi") {
		sigs, ok := computeClosedMethodValueSigs(sc)
		if !ok || len(sigs) != 1 {
			t.Fatalf("computeClosedMethodValueSigs(%v) = (%v, %v), want 1 sig and ok=true", sc, sigs, ok)
		}
	}
	for _, fnName := range []string{"EscapesToGlobal", "EscapesToVariadic", "EscapesToIfaceAssert"} {
		calls := findMethodCalls(fnName)
		if len(calls) != 1 {
			t.Fatalf("%s: method calls = %d, want 1", fnName, len(calls))
		}
		if sigs, ok := computeClosedMethodValueSigs(calls[0]); ok {
			t.Fatalf("%s: computeClosedMethodValueSigs = (%v, true), want ok=false", fnName, sigs)
		}
	}

	closureFn := ssaPkg.Func("DirectAndEscapingClosures")
	var mcs []*ssa.MakeClosure
	for _, b := range closureFn.Blocks {
		for _, ins := range b.Instrs {
			if mc, ok := ins.(*ssa.MakeClosure); ok {
				mcs = append(mcs, mc)
			}
		}
	}
	if len(mcs) != 2 {
		t.Fatalf("MakeClosure count = %d, want 2", len(mcs))
	}
	if !onlyDirectCallCallee(mcs[0]) {
		t.Fatal("onlyDirectCallCallee(direct closure) = false, want true")
	}
	if onlyDirectCallCallee(mcs[1]) {
		t.Fatal("onlyDirectCallCallee(escaped closure) = true, want false")
	}
}

func TestSeedsAddrTakenCandidatePrecisionWithReflectImported(t *testing.T) {
	const src = `package p

import "reflect"

func CandidateDispatched(x int) int { return x + 1 }
func CandidateUnused(x int) int     { return x + 2 }
func InBodyTaken(x int) int         { return x + 3 }

func RootDispatches(fn func(int) int) int {
	_ = reflect.TypeOf(0)
	return fn(10)
}

func RootNilCheckOnly(fn func(int) int) bool {
	_ = reflect.TypeOf(0)
	var local any = InBodyTaken
	_ = local
	return fn == nil
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	pkg := types.NewPackage("example.com/seedprec", "p")
	ssaPkg, _, err := ssautil.BuildPackage(&types.Config{Importer: importer.Default()}, fset, pkg, []*ast.File{f}, ssa.InstantiateGenerics)
	if err != nil {
		t.Fatalf("BuildPackage: %v", err)
	}

	candDispatched := ssaPkg.Func("CandidateDispatched")
	candUnused := ssaPkg.Func("CandidateUnused")
	inBodyTaken := ssaPkg.Func("InBodyTaken")
	rootDispatches := ssaPkg.Func("RootDispatches")
	rootNilCheck := ssaPkg.Func("RootNilCheckOnly")

	res, err := Analyze(context.Background(), map[*ssa.Function]uint64{
		rootDispatches: 1 << 0,
		rootNilCheck:   1 << 1,
	}, &Seeds{
		AddrTaken: map[*ssa.Function]uint64{
			candDispatched: 1 << 0,
			candUnused:     1 << 1,
		},
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if got := res.Reachable[candDispatched]; got != (1 << 0) {
		t.Fatalf("Reachable[CandidateDispatched] = %#b, want %#b", got, 1<<0)
	}
	if got := res.Reachable[candUnused]; got != 0 {
		t.Fatalf("Reachable[CandidateUnused] = %#b, want 0 (undispatched seed candidate must not be forced reachable by reflect import)", got)
	}
	if got := res.Reachable[inBodyTaken]; got != (1 << 1) {
		t.Fatalf("Reachable[InBodyTaken] = %#b, want %#b (in-body address-taken function remains reachable when reflect is imported)", got, 1<<1)
	}
}

func TestPureHarnessInternalStdTypeNestedExclusions(t *testing.T) {
	stdPkg := types.NewPackage("internal/harstd", "harstd")
	ctxPkg := types.NewPackage("context", "context")
	osPkg := types.NewPackage("os", "os")

	ctxObj := types.NewTypeName(token.NoPos, ctxPkg, "Context", nil)
	ctxType := types.NewNamed(ctxObj, types.NewInterfaceType(nil, nil), nil)

	fileObj := types.NewTypeName(token.NoPos, osPkg, "File", nil)
	fileType := types.NewNamed(fileObj, types.NewStruct(nil, nil), nil)

	pureObj := types.NewTypeName(token.NoPos, stdPkg, "PureHelper", nil)
	pureType := types.NewNamed(pureObj, types.NewStruct([]*types.Var{
		types.NewVar(token.NoPos, stdPkg, "n", types.Typ[types.Int]),
	}, nil), nil)

	embedsCtxObj := types.NewTypeName(token.NoPos, stdPkg, "EmbedsCtx", nil)
	embedsCtxType := types.NewNamed(embedsCtxObj, types.NewStruct([]*types.Var{
		types.NewVar(token.NoPos, stdPkg, "ctx", ctxType),
	}, nil), nil)

	holdsFileObj := types.NewTypeName(token.NoPos, stdPkg, "HoldsFile", nil)
	holdsFileType := types.NewNamed(holdsFileObj, types.NewStruct([]*types.Var{
		types.NewVar(token.NoPos, stdPkg, "f", types.NewPointer(fileType)),
	}, nil), nil)

	r := &attributedRTA{
		harnessPkg: "pgregory.net/rapid",
		userPkgs:   map[string]bool{"example.com/user": true},
	}
	if !r.isPureHarnessInternalStdType(pureType) {
		t.Fatal("isPureHarnessInternalStdType(PureHelper) = false, want true")
	}
	if !r.pureHarnessStdTypes[pureType] {
		t.Fatal("expected PureHelper to be memoized in r.pureHarnessStdTypes")
	}
	if r.isPureHarnessInternalStdType(embedsCtxType) {
		t.Fatal("isPureHarnessInternalStdType(EmbedsCtx) = true, want false (nested context.Context must be excluded)")
	}
	if r.isPureHarnessInternalStdType(holdsFileType) {
		t.Fatal("isPureHarnessInternalStdType(HoldsFile) = true, want false (nested *os.File must be excluded)")
	}
}

func TestBatchVsSoloAndExtendEquivalenceProperty(t *testing.T) {
	const src = `package p

type Runner interface {
	Run(int) int
}

type implA struct{}

func (implA) Run(x int) int { return helperA(x) }

type implB struct{}

func (*implB) Run(x int) int { return helperB(x) }

func helperA(x int) int { return x + 1 }
func helperB(x int) int { return x + 2 }
func cb1(x int) int     { return x * 2 }
func cb2(x int) int     { return x * 3 }

func invokeRunner(r Runner, x int) int {
	return r.Run(x)
}

func callDyn(fn func(int) int, x int) int {
	return fn(x)
}

func Subj0() int {
	return invokeRunner(implA{}, 1)
}

func Subj1() int {
	return invokeRunner(&implB{}, 2)
}

func Subj2() int {
	return callDyn(cb1, 3)
}

func Subj3() int {
	return callDyn(cb2, 4) + invokeRunner(implA{}, 5)
}

func Subj4(fn func(int) int, r Runner) int {
	return fn(r.Run(6))
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	pkg := types.NewPackage("example.com/prop", "p")
	ssaPkg, _, err := ssautil.BuildPackage(&types.Config{Importer: importer.Default()}, fset, pkg, []*ast.File{f}, ssa.InstantiateGenerics)
	if err != nil {
		t.Fatalf("BuildPackage: %v", err)
	}

	subjFns := []*ssa.Function{
		ssaPkg.Func("Subj0"),
		ssaPkg.Func("Subj1"),
		ssaPkg.Func("Subj2"),
		ssaPkg.Func("Subj3"),
		ssaPkg.Func("Subj4"),
	}
	cb1Fn := ssaPkg.Func("cb1")
	cb2Fn := ssaPkg.Func("cb2")
	implAType := pkg.Scope().Lookup("implA").Type()
	implBPtrType := types.NewPointer(pkg.Scope().Lookup("implB").Type())

	soloResults := make([]*Result, len(subjFns))
	for i, fn := range subjFns {
		var seeds *Seeds
		if i == 4 {
			seeds = &Seeds{
				AddrTaken: map[*ssa.Function]uint64{cb1Fn: 1},
				RuntimeTypes: []TypeSeed{
					{Type: implBPtrType, Masks: 1},
				},
			}
		}
		res, err := Analyze(context.Background(), map[*ssa.Function]uint64{fn: 1}, seeds)
		if err != nil {
			t.Fatalf("solo Analyze(%d): %v", i, err)
		}
		soloResults[i] = res
	}

	rng := rand.New(rand.NewPCG(0x525441, 0x20261110))
	for iter := range 128 {
		count := 1 + rng.IntN(len(subjFns))
		perm := rng.Perm(len(subjFns))[:count]
		splitAt := 1 + rng.IntN(count)

		batchRoots := make(map[*ssa.Function]uint64, count)
		step1Roots := make(map[*ssa.Function]uint64, splitAt)
		step2Roots := make(map[*ssa.Function]uint64, count-splitAt)
		var batchSeeds, step1Seeds, step2Seeds *Seeds
		usedBits := uint64(0)

		for bitIdx, subjIdx := range perm {
			var bit int
			for {
				bit = rng.IntN(64)
				if usedBits&(uint64(1)<<bit) == 0 {
					usedBits |= uint64(1) << bit
					break
				}
			}
			mask := uint64(1) << bit
			fn := subjFns[subjIdx]
			batchRoots[fn] |= mask
			if bitIdx < splitAt {
				step1Roots[fn] |= mask
			} else {
				step2Roots[fn] |= mask
			}
			if subjIdx == 4 {
				batchSeeds = &Seeds{
					AddrTaken:    map[*ssa.Function]uint64{cb1Fn: mask},
					RuntimeTypes: []TypeSeed{{Type: implBPtrType, Masks: mask}},
				}
				if bitIdx < splitAt {
					step1Seeds = batchSeeds
				} else {
					step2Seeds = batchSeeds
				}
			}
			_ = implAType
			_ = cb2Fn
		}

		batchRes, err := Analyze(context.Background(), batchRoots, batchSeeds)
		if err != nil {
			t.Fatalf("iter %d: batch Analyze: %v", iter, err)
		}

		analyzer := NewAnalyzer()
		extRes, err := analyzer.Extend(context.Background(), step1Roots, step1Seeds)
		if err != nil {
			t.Fatalf("iter %d: Extend step 1: %v", iter, err)
		}
		if len(step2Roots) > 0 || step2Seeds != nil {
			extRes, err = analyzer.Extend(context.Background(), step2Roots, step2Seeds)
			if err != nil {
				t.Fatalf("iter %d: Extend step 2: %v", iter, err)
			}
		}

		for fn, m := range batchRes.Reachable {
			if extRes.Reachable[fn] != m {
				t.Fatalf("iter %d: Extend Reachable[%s] = %#b, want %#b", iter, fn, extRes.Reachable[fn], m)
			}
		}
		for fn, m := range extRes.Reachable {
			if batchRes.Reachable[fn] != m {
				t.Fatalf("iter %d: Batch Reachable[%s] = %#b, want %#b", iter, fn, batchRes.Reachable[fn], m)
			}
		}

		for _, subjIdx := range perm {
			fn := subjFns[subjIdx]
			mask := batchRoots[fn]
			solo := soloResults[subjIdx]
			for rfn, bm := range batchRes.Reachable {
				inBatch := (bm & mask) != 0
				inSolo := solo.Reachable[rfn] != 0
				if inBatch != inSolo {
					t.Fatalf("iter %d subj %d (%s): Reachable[%s] batch=%v solo=%v", iter, subjIdx, fn, rfn, inBatch, inSolo)
				}
			}
			for site, targets := range batchRes.Targets {
				for target, tm := range targets {
					inBatch := (tm & mask) != 0
					inSolo := solo.Targets[site][target] != 0
					if inBatch != inSolo {
						t.Fatalf("iter %d subj %d (%s): Targets[%v][%s] batch=%v solo=%v", iter, subjIdx, fn, site, target, inBatch, inSolo)
					}
				}
			}
		}
	}
}

