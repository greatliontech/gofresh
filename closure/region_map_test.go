package closure

import (
	"go/constant"
	"go/types"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func TestRegionMapFreshAliasesAndProjections(t *testing.T) {
	for _, text := range []string{
		`type K struct{P,F string};func F()bool{m:=make(map[K]*int);a:=m;a[K{"safe","f"}]=nil;_,ok:=m[K{"absent","f"}];return ok}`,
		`type K struct{P,F string};func F(flag bool)bool{m:=make(map[K]int);if flag{m[K{"a","x"}]=1}else{m[K{"b","y"}]=2};_,ok:=m[K{"absent","x"}];return ok}`,
	} {
		in := regionFixture(t, text)
		c, _ := proveRegionFixture(t, in)
		for _, out := range normalMapObservations(t, c) {
			b, ok := regionBool(out.value)
			if !ok || b {
				t.Fatal("definite missing key not established")
			}
		}
	}
}

func TestRegionMapSelectedCompilerConstruction(t *testing.T) {
	if testing.Short() {
		t.Skip("selected compiler construction")
	}
	source, _ := loadCompilerStartupFixture(t)
	var root *ssa.Function
	for _, p := range source.prog.Prog.AllPackages() {
		if p.Pkg.Path() == "cmd/compile/internal/ssagen" {
			root = p.Func("initIntrinsics")
		}
	}
	if root == nil {
		t.Fatal("selected construction absent")
	}
	in := regionInput{selection: source.prog, owner: source.prog.Prog, root: root, entry: regionPoint{root.Blocks[0], 0}, normalReturns: true, premises: []string{"conditional language normal-return relation; entry memory arbitrary; isolation, intervening preservation and native application open"}}
	limits := defaultRegionLimits()
	limits.nodes, limits.states, limits.locations, limits.work = 65536, 65536, 65536, 10000000
	limits.alternatives = 1
	kernel, err := newRegionKernel(t.Context(), in, limits)
	if err != nil {
		t.Fatal(err)
	}
	p, err := proposeRegionKernel(kernel)
	if err != nil {
		t.Logf("proposal usage work=%d states=%d nodes=%d locations=%d proofs=%d", kernel.meter.work, kernel.meter.states, kernel.meter.nodes, kernel.meter.locations, len(kernel.session.proofs))
		t.Fatal(err)
	}
	t.Logf("proposal usage work=%d states=%d nodes=%d locations=%d proofs=%d retained=%d", kernel.meter.work, kernel.meter.states, kernel.meter.nodes, kernel.meter.locations, len(kernel.session.proofs), len(p.calls))
	packet, err := checkRegion(t.Context(), in, p, limits)
	if err != nil {
		t.Fatal(err)
	}
	packets := []*checkedRegion{packet}
	if len(packet.observations) == 0 {
		t.Fatal("no normal return observations")
	}
	global := root.Pkg.Members["intrinsics"].(*ssa.Global)
	mapType := global.Type().Underlying().(*types.Pointer).Elem()
	keyType := mapType.Underlying().(*types.Map).Key()
	fields := keyType.Underlying().(*types.Struct)
	key := regionValue{typ: keyType, kind: regionAggregate}
	for i := 0; i < fields.NumFields(); i++ {
		v := regionUnknownValue(fields.Field(i).Type())
		if fields.Field(i).Name() == "pkg" {
			v = regionValue{typ: v.typ, kind: regionConstant, scalar: constant.MakeString("unicode/utf16")}
		}
		key.elements = append(key.elements, v)
	}
	for _, out := range packet.observations {
		handle := out.state.memory[regionObject{kind: regionGlobal, site: global}]
		if handle.kind != regionMap || !regionMapMiss(out.state.memory[handle.location.object], key) {
			t.Fatalf("selected destination package exclusion absent: handle=%v contents=%+v", handle.kind, out.state.memory[handle.location.object].keys)
		}
		method, _, _ := types.LookupFieldOrMethod(mapType, false, root.Pkg.Pkg, "lookup")
		lookup := source.prog.Prog.FuncValue(method.(*types.Func))
		use := regionInput{normalReturns: true, selection: source.prog, owner: source.prog.Prog, root: lookup, entry: regionPoint{lookup.Blocks[0], 0}, initial: regionState{values: map[ssa.Value]regionValue{}, memory: out.state.memory}, premises: []string{"conditional normalized lookup key and construction invariant at this use; intervening preservation, actual symbol normalization and application remain open"}}
		for _, param := range lookup.Params {
			if param.Name() == "pkg" {
				use.initial.values[param] = regionValue{typ: param.Type(), kind: regionConstant, scalar: constant.MakeString("unicode/utf16")}
			}
		}
		proposed, err := proposeRegion(t.Context(), use, limits)
		if err != nil {
			t.Fatal(err)
		}
		lookupPacket, err := checkRegion(t.Context(), use, proposed, limits)
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, lookupPacket)
		for _, result := range normalMapObservations(t, lookupPacket) {
			if result.value.kind != regionNil {
				t.Fatal("conditional normalized-key lookup did not miss")
			}
		}
	}
	used := map[string]bool{}
	unique := map[*ssa.Function]bool{root: true}
	for _, call := range packet.calls {
		used[call.target.Name()] = true
		unique[call.target] = true
	}
	for _, name := range []string{"simdAMD64Intrinsics", "simdARM64Intrinsics", "initWasmSIMD"} {
		if !used[name] {
			t.Fatalf("configuration-universal construction omitted %s", name)
		}
	}
	t.Logf("checked construction and normalized lookup; usage %+v calls %d", packet.usage, len(packet.calls))
	named, literals := 0, 0
	for fn := range unique {
		if fn.Parent() == nil {
			named++
		} else {
			literals++
		}
	}
	t.Logf("checked construction functions: named=%d invoked literals=%d", named, literals)
	// The compiler package inventory is larger than the generated-main fixture.
	// Binding remains cumulative and shared by both conditional source lemmas.
	binder, err := newSelectedSourceBinder(t.Context(), source, root, selectedSourceLimits{work: 2000000, depth: 128, bytes: 16 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range packets {
		if _, err := binder.checkSourceRegion(p); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("source binding work=%d bytes=%d", binder.work, binder.bytes)
}
