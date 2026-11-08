package rta

import (
	"context"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
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
