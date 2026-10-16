package closure

import (
	"context"
	"errors"
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	progpkg "github.com/greatliontech/gofresh/closure/internal/program"
)

func TestRegionInterfaceConcreteOracle(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"method", `type I interface{M()int;Other()int};type S struct{};func(S)M()int{return 1};func(S)Other()int{return 2};func F()int{var x I=S{};return x.M()}`},
		{"receiver", `type I interface{M(S)int};type S struct{X int};func(s S)M(other S)int{return s.X};func F()int{var x I=S{1};return x.M(S{2})}`},
		{"alternatives", `type I interface{M()int};type A struct{X int};type B struct{Y int};func(a A)M()int{return a.X};func(b B)M()int{return b.Y};func F(flag bool)int{var x I=A{1};if flag{x=B{2}};return x.M()}`},
		{"same-type-receivers", `type I interface{M()int};type S struct{X int};func(s S)M()int{return s.X};func F(flag bool)int{var x I=S{1};if flag{x=S{2}};return x.M()}`},
		{"pointer-alias", `type I interface{Set(int)};type S struct{X int};func(s *S)Set(n int){s.X=n};func F()int{s:=S{1};p:=&s.X;var x I=&s;x.Set(2);return *p}`},
		{"nil-pointer-receiver", `type I interface{M()int};type S struct{};func(s *S)M()int{return 3};func F()int{var p *S;var x I=p;return x.M()}`},
		{"nil-pointer-guard", `type I interface{M()int};type S struct{X int};func(s *S)M()int{if s==nil{return 3};return s.X};func F()int{var p *S;var x I=p;return x.M()}`},
		{"non-nil-interface", `type I interface{M()int};type S struct{};func(*S)M()int{return 3};func F()bool{var p *S;var x I=p;_ = x.M();return x!=nil}`},
		{"constructor", `type I interface{M()int};type S struct{X int};func(s *S)M()int{return s.X};func makeValue(x int)I{return &S{x}};func F()[]int{a:=makeValue(1);b:=makeValue(2);return []int{a.M(),b.M()}}`},
		{"interface-change", `type I interface{M()int;N()int};type J interface{M()int};type S struct{X int};func(s S)M()int{return s.X};func(s S)N()int{return 7};func F()int{var x I=S{2};var y J=x;return y.M()}`},
		{"interface-rebind", `type I interface{M()int};type A struct{};type B struct{};func(A)M()int{return 1};func(B)M()int{return 2};func F()[]int{var x I=A{};a:=x.M();x=B{};return []int{a,x.M()}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := regionFixture(t, tc.source)
			checked, _ := proveRegionFixture(t, in)
			for _, out := range checked.observations {
				if !regionTestPrecise(out.value, out.state, 0) {
					t.Fatal("interface relation widened")
				}
			}
			if len(in.root.Params) == 0 {
				assertRegionCovers(t, checked, executeRegionConcrete(t, in))
			} else {
				for _, flag := range []bool{false, true} {
					assertRegionCovers(t, checked, executeRegionConcrete(t, in, flag))
				}
			}
		})
	}
}

func TestRegionInterfaceRefusals(t *testing.T) {
	for _, source := range []string{
		`type I interface{M()int};func F()int{var x I;return x.M()}`,
		`type I interface{M()int};func F(x I)int{return x.M()}`,
		`type I interface{M()int};type S struct{X int};func(s *S)M()int{return s.X};func F()int{var p *S;var x I=p;return x.M()}`,
		`type I interface{M()int};type S struct{X int};func(s S)M()int{return s.X};func F()int{var x I=&S{1};return x.M()}`,
		`type I interface{M()int};type A struct{};func(A)M()int{return 1};type B struct{A};func F()int{var x I=B{};return x.M()}`,
		`type I interface{M()int};type S[T any]struct{X T};func(s S[T])M()int{return 1};func F()int{var x I=S[int]{};return x.M()}`,
		`type I interface{M()int};type S struct{};func(S)M()int;func F()int{var x I=S{};return x.M()}`,
		`type I interface{M()int};type S struct{};func native();func(S)M()int{native();return 1};func F()int{var x I=S{};return x.M()}`,
		`type I interface{M()int};type S struct{};func(s S)M()int{var x I=s;return x.M()};func F()int{var x I=S{};return x.M()}`,
		`type I interface{M()int};type S struct{};func(S)M()int{var x any=[]int{};_ = x==x;return 1};func F()int{var x I=S{};return x.M()}`,
	} {
		t.Run(source, func(t *testing.T) {
			in := regionFixture(t, source)
			if proof, err := proposeRegion(t.Context(), in, defaultRegionLimits()); proof != nil || err == nil {
				t.Fatal("unproved interface operation acquired authority")
			}
		})
	}
}

func TestRegionInterfaceReturnedRowCorrelation(t *testing.T) {
	in := regionFixture(t, `type Row struct{Name string;F func()};func a(){};func b(){};type I interface{Make()Row};type A struct{};type B struct{};func(A)Make()Row{return Row{"a",a}};func(B)Make()Row{return Row{"b",b}};func F(flag bool)Row{var x I=A{};if flag{x=B{}};return x.Make()}`)
	checked, _ := proveRegionFixture(t, in)
	for _, flag := range []bool{false, true} {
		assertRegionCovers(t, checked, executeRegionConcrete(t, in, flag))
	}
	for _, out := range checked.observations {
		row := out.value
		if row.kind != regionAggregate || len(row.elements) != 2 || row.elements[0].kind != regionConstant || row.elements[1].kind != regionCallable {
			t.Fatal("row relation lost precision")
		}
		name := constant.StringVal(row.elements[0].scalar)
		if name != "a" && name != "b" || row.elements[1].target != in.root.Pkg.Func(name) {
			t.Fatal("dispatch formed an independent name/function cross product")
		}
	}
}

func TestRegionInterfaceForgedBindings(t *testing.T) {
	const source = `type I interface{M()int;Other()int};type S struct{X int};func(s S)M()int{return s.X};func(s S)Other()int{return 2};func F()[]int{var x I=S{1};return []int{x.M(),x.Other()}}`
	for _, corruption := range []string{"method", "receiver", "missing"} {
		t.Run(corruption, func(t *testing.T) {
			in := regionFixture(t, source)
			_, proposal := proveRegionFixture(t, in)
			if len(proposal.calls) != 2 {
				t.Fatal("expected two invoke proofs")
			}
			first := proposal.calls[0]
			switch corruption {
			case "method":
				first.target = proposal.calls[1].target
			case "receiver":
				receiver := first.target.Params[0]
				value := first.initial.values[receiver]
				value.elements = []regionValue{{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(9)}}
				first.initial.values[receiver] = value
			case "missing":
				proposal.calls = nil
			}
			if checked, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits()); checked != nil || err == nil {
				t.Fatal("forged interface binding acquired authority")
			}
		})
	}
}

func TestRegionInterfaceMissingCanonicalMethod(t *testing.T) {
	in := regionFixture(t, `type I interface{M()int};func F(x I)int{return x.M()}`)
	foreign := types.NewPackage("example.com/unmaterialized", "foreign")
	typ := types.NewNamed(types.NewTypeName(token.NoPos, foreign, "S", nil), types.NewStruct(nil, nil), nil)
	signature := types.NewSignatureType(types.NewVar(token.NoPos, foreign, "recv", typ), nil, nil, types.NewTuple(), types.NewTuple(types.NewVar(token.NoPos, foreign, "", types.Typ[types.Int])), false)
	method := types.NewFunc(token.NoPos, foreign, "M", signature)
	typ.AddMethod(method)
	parameter := in.root.Params[0]
	in.initial.values = map[ssa.Value]regionValue{parameter: {typ: parameter.Type(), kind: regionInterface, elements: []regionValue{{typ: typ, kind: regionAggregate}}}}
	if in.owner.FuncValue(method) != nil {
		t.Fatal("missing-body test unexpectedly has a canonical function")
	}
	proof, err := proposeRegion(t.Context(), in, defaultRegionLimits())
	if proof != nil || err == nil || !strings.Contains(err.Error(), "canonical SSA method") {
		t.Fatalf("missing canonical method refusal: %v", err)
	}
	if in.owner.FuncValue(method) != nil {
		t.Fatal("checking materialized an absent method")
	}
}

func TestRegionInterfaceScopeOwnershipAndBounds(t *testing.T) {
	in := regionFixture(t, `type I interface{M()int};type S struct{X int};func(s S)M()int{return s.X};func F()int{var x I=S{1};return x.M()}`)
	_, proposal := proveRegionFixture(t, in)
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() {
		for _, proof := range proposal.calls {
			for key, value := range proof.initial.values {
				for i := range value.elements {
					value.elements[i] = regionUnknownValue(value.elements[i].typ)
				}
				delete(proof.initial.values, key)
			}
			proof.target = nil
		}
		proposal.calls = nil
	}}
	checked, err := checkRegion(ctx, in, proposal, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	assertRegionCovers(t, checked, executeRegionConcrete(t, in))
	_, proposal = proveRegionFixture(t, in)
	other := in
	other.use.operand = in.root.Pkg.Func("F")
	if _, err := checkRegion(t.Context(), other, proposal, defaultRegionLimits()); err == nil {
		t.Fatal("invoke proof accepted replacement scope")
	}
	count := &regionCallCountingContext{Context: t.Context()}
	if _, err := checkRegion(count, in, proposal, defaultRegionLimits()); err != nil {
		t.Fatal(err)
	}
	cut := &regionCallCountingContext{Context: t.Context(), stop: count.checks / 2}
	if result, err := checkRegion(cut, in, proposal, defaultRegionLimits()); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled interface proof: %v", err)
	}
	limits := defaultRegionLimits()
	limits.work = 10
	if proof, err := proposeRegion(t.Context(), in, limits); proof != nil || err == nil {
		t.Fatal("interface checking ignored shared work budget")
	}
}

func TestRegionInterfaceMethodSurfaceBudget(t *testing.T) {
	source := `type I interface{M()int};type S struct{};func(S)M()int{return 1};func F()int{var x I=S{};return x.M()}`
	for i := 0; i < 32; i++ {
		source += fmt.Sprintf(";func(S)Unused%d(){}", i)
	}
	in := regionFixture(t, source)
	limits := defaultRegionLimits()
	limits.nodes = 16
	proof, err := proposeRegion(t.Context(), in, limits)
	if proof != nil || err == nil || !strings.Contains(err.Error(), "method count budget") {
		t.Fatalf("method surface escaped its bound: %v", err)
	}
}

func regionInterfaceLoadedInput(t *testing.T, source string) (regionInput, *program) {
	t.Helper()
	dir := t.TempDir()
	const path = "example.com/regioninterface"
	for name, text := range map[string]string{"go.mod": "module " + path + "\n\ngo 1.27\n", "p.go": "package p\n" + source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := progpkg.Load(t.Context(), dir, append(os.Environ(), "GOWORK=off", "GOPACKAGESDRIVER=off"), nil, path)
	if err != nil {
		t.Fatal(err)
	}
	fn := loaded.Roots["F"]
	if fn == nil {
		t.Fatal("loaded function missing")
	}
	in := regionInput{owner: loaded.Prog, root: fn, entry: regionPoint{fn.Blocks[0], 0}, premises: []string{"selected typed owner; source/native applicability open"}}
	for _, block := range fn.Blocks {
		for i, ins := range block.Instrs {
			if ret, ok := ins.(*ssa.Return); ok {
				in.use = regionUse{regionPoint{block, i}, ret.Results[0]}
			}
		}
	}
	return in, loaded
}

func TestRegionInterfaceActualLoadedCustomMethods(t *testing.T) {
	if testing.Short() {
		t.Skip("actual selected package load")
	}
	in, _ := regionInterfaceLoadedInput(t, `type I interface{Get()int};type A struct{X int};type B struct{Y int};func(a A)Get()int{return a.X};func(b *B)Get()int{return b.Y};func F(flag bool)int{var x I=A{1};if flag{x=&B{2}};return x.Get()}`)
	checked, _ := proveRegionFixture(t, in)
	for _, flag := range []bool{false, true} {
		assertRegionCovers(t, checked, executeRegionConcrete(t, in, flag))
	}
	for _, proof := range checked.calls {
		object, ok := proof.target.Object().(*types.Func)
		if !ok || in.owner.FuncValue(object) != proof.target {
			t.Fatal("method is not canonical in loaded owner")
		}
	}
}

func TestRegionInterfaceActualGeneratedMainCoverageSegment(t *testing.T) {
	if testing.Short() {
		t.Skip("actual generated package-test main load")
	}
	dir := t.TempDir()
	const path = "example.com/regioncoverage"
	writeTree(t, dir, map[string]string{"go.mod": "module " + path + "\n\ngo 1.27\n", "p.go": "package p\n", "p_test.go": "package p\nimport \"testing\"\nfunc TestOne(t *testing.T){}\n"})
	loaded, err := progpkg.Load(t.Context(), dir, append(os.Environ(), "GOWORK=off", "GOPACKAGESDRIVER=off"), nil, path)
	if err != nil {
		t.Fatal(err)
	}
	var main *ssa.Function
	for _, pkg := range loaded.Pkgs {
		if pkg.ID == path+".test" {
			main = loaded.Prog.Package(pkg.Types).Func("main")
			t.Logf("selected generated main: %q", pkg.CompiledGoFiles)
		}
	}
	if main == nil {
		t.Fatal("actual generated main missing")
	}
	var call *ssa.Call
	var callPoint regionPoint
	for _, block := range main.Blocks {
		for i, ins := range block.Instrs {
			if candidate, ok := ins.(*ssa.Call); ok {
				target := candidate.Call.StaticCallee()
				if target != nil && target.Pkg != nil && target.Pkg.Pkg.Path() == "testing" && target.Name() == "MainStart" {
					call = candidate
					callPoint = regionPoint{block, i}
				}
			}
		}
	}
	if call == nil || len(call.Call.Args) == 0 {
		t.Fatal("selected MainStart call missing")
	}
	construction := regionInput{owner: loaded.Prog, root: main, entry: regionPoint{main.Blocks[0], 0}, use: regionUse{callPoint, call.Call.Args[0]}, premises: []string{"immutable selected generated main; initialization, interference and native applicability open"}}
	constructed, _ := proveRegionFixture(t, construction)
	if len(constructed.observations) != 1 || constructed.observations[0].value.kind != regionInterface {
		t.Fatal("actual generated dependency operand is not concrete")
	}
	carrier := constructed.observations[0].value
	root := call.Call.StaticCallee()
	var invoke *ssa.Call
	var use regionUse
	hasLaterInit := false
	for _, block := range root.Blocks {
		for i, ins := range block.Instrs {
			if candidate, ok := ins.(*ssa.Call); ok {
				if candidate.Call.IsInvoke() && candidate.Call.Value == root.Params[0] && candidate.Call.Method.Name() == "InitRuntimeCoverage" {
					invoke = candidate
				}
				if fn := candidate.Call.StaticCallee(); fn != nil && fn.Name() == "Init" {
					hasLaterInit = true
				}
			}
			if extract, ok := ins.(*ssa.Extract); ok && invoke != nil && extract.Tuple == invoke && use.at.block == nil {
				use = regionUse{regionPoint{block, i}, invoke}
			}
		}
	}
	if invoke == nil || use.at.block == nil || !hasLaterInit {
		t.Fatal("selected MainStart no longer has the inspected invoke/Extract/Init scope")
	}
	object, index, _ := types.LookupFieldOrMethod(carrier.elements[0].typ, false, invoke.Call.Method.Pkg(), invoke.Call.Method.Name())
	method, ok := object.(*types.Func)
	if !ok || len(index) != 1 {
		t.Fatal("selected dependency method is adjusted or absent")
	}
	callee := loaded.Prog.FuncValue(method)
	if callee == nil {
		t.Fatal("actual canonical coverage method was not materialized")
	}
	t.Logf("selected invoke body: %s at %s", callee, loaded.Prog.Fset.Position(callee.Pos()))
	var body strings.Builder
	callee.WriteTo(&body)
	t.Log(body.String())
	global, ok := callee.Pkg.Members["CoverMode"].(*ssa.Global)
	if !ok {
		t.Fatal("selected coverage-mode entry premise missing")
	}
	readsMode := false
	for _, block := range callee.Blocks {
		for _, ins := range block.Instrs {
			if load, ok := ins.(*ssa.UnOp); ok && load.Op == token.MUL && load.X == global {
				readsMode = true
			}
		}
	}
	if !readsMode {
		t.Fatal("selected method does not read the stated entry premise")
	}
	modeObject := regionObject{kind: regionGlobal, site: global}
	in := regionInput{owner: loaded.Prog, root: root, entry: regionPoint{root.Blocks[0], 0}, use: use,
		initial:  regionState{values: map[ssa.Value]regionValue{root.Params[0]: carrier}, memory: map[regionObject]regionValue{modeObject: {typ: types.Typ[types.String], kind: regionConstant, scalar: constant.MakeString("")}}},
		premises: []string{"dependency receiver equals the checked actual generated-main operand; source/native applicability open", "selected CoverMode is empty at entry and remains protected through this segment; global initialization is not proved", "scope ends before the actual consuming Extract; remaining MainStart, harness, concurrency and native obligations remain open"}}
	checked, _ := proveRegionFixture(t, in)
	if len(checked.calls) != 1 || checked.calls[0].target != callee || regionInstruction(checked.input.use.at) != regionInstruction(use.at) {
		t.Fatal("coverage transport lost actual target or use scope")
	}
	for _, out := range checked.observations {
		v := out.value
		if v.kind != regionAggregate || len(v.elements) != 3 || v.elements[0].kind != regionConstant || constant.StringVal(v.elements[0].scalar) != "" || v.elements[1].kind != regionNil || v.elements[2].kind != regionNil {
			t.Fatal("empty coverage mode did not yield the checked empty/nil/nil tuple")
		}
	}
	// Without the entry premise the same method name grants no empty-mode
	// conclusion. All source branches are still checked and retained.
	in.initial.memory = nil
	in.premises[1] = "selected CoverMode is arbitrary at entry; global initialization is not proved"
	unconditioned, _ := proveRegionFixture(t, in)
	openResult := false
	for _, out := range unconditioned.observations {
		if !regionTestPrecise(out.value, out.state, 0) {
			openResult = true
		}
	}
	if !openResult {
		t.Fatal("method name replaced the missing coverage-mode premise")
	}
}

func FuzzRegionInterfaceReceiverOracle(f *testing.F) {
	f.Add(int8(1), int8(2), false)
	f.Add(int8(-3), int8(7), true)
	for shape := int8(0); shape < 8; shape++ {
		f.Add(shape, int8(4), false)
	}
	f.Fuzz(func(t *testing.T, a, b int8, choose bool) {
		// Bounded grammar: two implementations, 8-bit receiver payloads, both
		// equality operators, and eight comparison shapes. It deliberately
		// includes zero arrays, blank fields, pointer recursion and panicking
		// named/array interface components; it does not sample arbitrary types.
		op := "=="
		if b&1 != 0 {
			op = "!="
		}
		declarations, comparison := "", ""
		panics := false
		switch uint8(a) & 7 {
		case 1:
			declarations = `type C struct{X int};type CA [1]C;`
			comparison = `v:=CA{{1}};`
		case 2:
			declarations = `type C struct{X any};type CA [1]C;`
			comparison = `v:=CA{{X:[]int{}}};`
			panics = true
		case 3:
			comparison = `v:=[0]any{};`
		case 4:
			declarations = `type N struct{Next *N};`
			comparison = `v:=N{};v.Next=&v;`
		case 5:
			comparison = `v:=struct{_ any}{[]int{}};`
		case 6:
			comparison = `v:=[1]any{([]int)(nil)};`
			panics = true
		case 7:
			comparison = `v:=[0]struct{X [1]any}{};`
		}
		if comparison != "" {
			comparison += "_ = v " + op + " v;"
		}
		source := declarations + fmt.Sprintf(`type I interface{Get()int};type A struct{X int};type B struct{Y int};func(a A)Get()int{%sreturn a.X};func(b *B)Get()int{%sreturn b.Y};func F(flag bool)int{var x I=A{%d};if flag{x=&B{%d}};return x.Get()}`, comparison, comparison, a, b)
		in := regionFixture(t, source)
		if panics {
			proof, err := proposeRegion(t.Context(), in, defaultRegionLimits())
			var checked *checkedRegion
			if err == nil {
				checked, err = checkRegion(t.Context(), in, proof, defaultRegionLimits())
			}
			if err == nil || checked != nil {
				t.Fatal("panicking aggregate comparison acquired normal call transport")
			}
			return
		}
		checked, _ := proveRegionFixture(t, in)
		for _, out := range checked.observations {
			if !regionTestPrecise(out.value, out.state, 0) {
				t.Fatal("interface receiver relation widened")
			}
		}
		assertRegionCovers(t, checked, executeRegionConcrete(t, in, choose))
	})
}
