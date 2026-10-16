package closure

import (
	"context"
	"errors"
	"fmt"
	"go/constant"
	"go/types"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func TestRegionScalarViewsConcreteOracle(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"boolean", `type Lamp bool;func F()bool{x:=false;q:=(*Lamp)(&x);*q=true;return x}`},
		{"reverse-write", `type Lamp bool;func F()bool{x:=false;q:=(*Lamp)(&x);x=true;return bool(*q)}`},
		{"named-to-named", `type Left int;type Right int;func F()Left{x:=Left(1);p:=(*Right)(&x);*p=9;return x}`},
		{"string", `type Label string;func F()string{x:="first";p:=(*Label)(&x);*p="second";return x}`},
		{"field", `type Lamp bool;type S struct{A,B bool};func F()S{x:=S{B:true};p:=(*Lamp)(&x.A);*p=true;return x}`},
		{"index", `type Lamp bool;func F()[]bool{x:=[]bool{false,true};p:=(*Lamp)(&x[0]);*p=true;return x}`},
		{"initializer-call", `type Lamp bool;func initValue(value bool,p *bool)*Lamp{*p=value;return (*Lamp)(p)};func F()bool{x:=false;p:=initValue(true,&x);return bool(*p)}`},
		{"receiver", `type Lamp bool;func(p *Lamp)Set(v bool){*p=Lamp(v)};func F()bool{x:=false;p:=(*Lamp)(&x);p.Set(true);return x}`},
		{"interface-receiver", `type Lamp bool;type Setter interface{Set(bool)};func(p *Lamp)Set(v bool){*p=Lamp(v)};func F()bool{x:=false;var s Setter=(*Lamp)(&x);s.Set(true);return x}`},
		{"capture", `type Lamp bool;func F()bool{x:=false;p:=(*Lamp)(&x);f:=func()bool{return bool(*p)};x=true;return f()}`},
		{"same-address", `type Lamp bool;func F()bool{x:=false;p:=&x;q:=(*Lamp)(p);return p==(*bool)(q)}`},
		{"nil", `type Lamp bool;func cast(p *bool)*Lamp{return (*Lamp)(p)};func F()bool{return cast(nil)==nil}`},
		{"different-inputs", `type Lamp bool;func get(p *Lamp)bool{return bool(*p)};func F()[]bool{x:=false;p:=(*Lamp)(&x);a:=get(p);x=true;return []bool{a,get(p)}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := regionFixture(t, tc.source)
			checked, _ := proveRegionFixture(t, in)
			for _, out := range checked.observations {
				if !regionTestPrecise(out.value, out.state, 0) {
					t.Fatal("scalar view lost an exact result")
				}
			}
			assertRegionCovers(t, checked, executeRegionConcrete(t, in))
		})
	}
}

func TestRegionScalarViewsRefuseUnsupportedAccess(t *testing.T) {
	for _, source := range []string{
		`type A struct{X int};type B struct{X int};func F()*B{x:=new(A);return (*B)(x)}`,
		`type A [1]int;type B [1]int;func F()*B{x:=new(A);return (*B)(x)}`,
		`type Lamp bool;func F()bool{var p *bool;q:=(*Lamp)(p);return bool(*q)}`,
		`type Lamp bool;func F(p *bool)bool{q:=(*Lamp)(p);*q=true;return true}`,
	} {
		t.Run(source, func(t *testing.T) {
			in := regionFixture(t, source)
			if p, err := proposeRegion(t.Context(), in, defaultRegionLimits()); p != nil || err == nil {
				t.Fatal("unsupported view/access acquired a proof")
			}
		})
	}
	// Equal size is not a conversion rule. These are type-level negative controls
	// because the Go checker itself rejects such direct pointer conversions.
	for _, pair := range [][2]types.Type{{types.Typ[types.Int8], types.Typ[types.Uint8]}, {types.Typ[types.Bool], types.Typ[types.Uint8]}, {types.Typ[types.Int], types.Typ[types.Int64]}, {types.Typ[types.UnsafePointer], types.Typ[types.Uintptr]}} {
		if regionPointerChange(types.NewPointer(pair[0]), types.NewPointer(pair[1])) {
			t.Fatal("incompatible pointee types acquired a view", pair)
		}
	}
}

func TestRegionScalarViewForgedLocations(t *testing.T) {
	for _, corruption := range []string{"type", "field", "index", "object"} {
		t.Run(corruption, func(t *testing.T) {
			base := "bool"
			if corruption == "type" {
				base = "int"
			}
			in := regionFixture(t, `type View `+base+`;var cell bool;func F(p *View)int{return 1}`)
			parameter := in.root.Params[0]
			global := in.root.Pkg.Members["cell"].(*ssa.Global)
			loc := regionLocation{object: regionObject{kind: regionGlobal, site: global}}
			switch corruption {
			case "field":
				loc.path = []regionStep{{field: true, index: 0}}
			case "index":
				loc.path = []regionStep{{index: 0}}
			case "object":
				loc.object.kind = regionUnknownObject
			}
			in.initial.values = map[ssa.Value]regionValue{parameter: {typ: parameter.Type(), kind: regionPointer, location: loc}}
			if p, err := proposeRegion(t.Context(), in, defaultRegionLimits()); p != nil || err == nil {
				t.Fatal("forged storage/view relation acquired authority")
			}
		})
	}
}

func TestRegionScalarViewWeakUpdatesAndAliases(t *testing.T) {
	for _, same := range []bool{false, true} {
		t.Run(fmt.Sprintf("equal=%t", same), func(t *testing.T) {
			in := regionFixture(t, `type Lamp bool;var cell bool;func F(p *bool)bool{q:=(*Lamp)(p);*q=true;return cell}`)
			parameter := in.root.Params[0]
			formal := regionObject{kind: regionFormal, site: parameter, context: in.root}
			global := in.root.Pkg.Members["cell"].(*ssa.Global)
			initial := regionValue{typ: types.Typ[types.Bool], kind: regionConstant, scalar: constant.MakeBool(same)}
			in.initial = regionState{values: map[ssa.Value]regionValue{parameter: {typ: parameter.Type(), kind: regionPointer, location: regionLocation{object: formal}}}, memory: map[regionObject]regionValue{formal: initial, {kind: regionGlobal, site: global}: initial}}
			checked, _ := proveRegionFixture(t, in)
			if checked.observations[0].value.kind != regionUnknown {
				t.Fatal("view store through a formal preserved possibly overlapping global facts")
			}
		})
	}
	// A repeated factory allocation remains a summary through every typed view.
	in := regionFixture(t, `type Lamp bool;func factory(v bool)*bool{return &v};func F(again,next bool)*Lamp{var old *Lamp;for again{p:=(*Lamp)(factory(false));*p=true;if old==nil{old=p};again=next;next=false};return old}`)
	checked, _ := proveRegionFixture(t, in)
	for _, args := range [][2]bool{{false, false}, {true, false}, {true, true}} {
		assertRegionCovers(t, checked, executeRegionConcrete(t, in, args[0], args[1]))
	}
	for _, out := range checked.observations {
		for object, value := range out.state.memory {
			if object.kind == regionAllocation && object.context != in.root && value.kind != regionUnknown {
				t.Fatal("view conversion promoted a repeated allocation to singleton storage")
			}
		}
	}
	indexed := regionFixture(t, `type Lamp bool;var cells [2]bool;func F(p *bool)bool{q:=(*Lamp)(p);*q=true;return cells[0]}`)
	global := indexed.root.Pkg.Members["cells"].(*ssa.Global)
	object := regionObject{kind: regionGlobal, site: global}
	parameter := indexed.root.Params[0]
	indexed.initial = regionState{values: map[ssa.Value]regionValue{parameter: {typ: parameter.Type(), kind: regionPointer, location: regionLocation{object: object, path: []regionStep{{summary: true}}}}}, memory: map[regionObject]regionValue{object: {typ: global.Type().Underlying().(*types.Pointer).Elem(), kind: regionAggregate, elements: []regionValue{{typ: types.Typ[types.Bool], kind: regionConstant, scalar: constant.MakeBool(false)}, {typ: types.Typ[types.Bool], kind: regionConstant, scalar: constant.MakeBool(true)}}}}}
	ambiguous, _ := proveRegionFixture(t, indexed)
	if ambiguous.observations[0].value.kind != regionUnknown {
		t.Fatal("view store through a summary index kept an overlapping element fact")
	}
}

func TestRegionScalarViewActualOperandMutation(t *testing.T) {
	in := regionFixture(t, `type Lamp bool;type Reader interface{Get()bool};func(p *Lamp)Get()bool{return bool(*p)};func consume(Reader){};func F(){x:=false;p:=(*Lamp)(&x);x=true;consume(p)}`)
	in = regionAtCall(t, in, "consume", 0)
	checked, proposal := proveRegionFixture(t, in)
	out := checked.observations[0]
	view := out.value.elements[0]
	value := readRegionLocation(out.state, view.location, view.typ.Underlying().(*types.Pointer).Elem())
	if b, known := regionBool(value); !known || !b {
		t.Fatal("actual consuming view retained stale cell contents")
	}
	wrong := in
	wrong.use.operand = in.root.Pkg.Func("consume")
	if packet, err := checkRegion(t.Context(), wrong, proposal, defaultRegionLimits()); packet != nil || err == nil {
		t.Fatal("proof accepted a changed consuming operand")
	}
}

func TestRegionScalarViewSummaryPointersRemainDistinct(t *testing.T) {
	in := regionFixture(t, `type Lamp bool;func factory()*bool{v:=false;return &v};func F()bool{again,next:=true,true;var a,b *Lamp;for again{a=b;b=(*Lamp)(factory());again=next;next=false};return a==b}`)
	checked, _ := proveRegionFixture(t, in)
	concrete := executeRegionConcrete(t, in)
	if concrete != false {
		t.Fatal("two live nonzero-sized allocations did not remain distinct")
	}
	assertRegionCovers(t, checked, concrete)
}

func TestRegionScalarViewOwnershipAndCancellation(t *testing.T) {
	in := regionFixture(t, `type Lamp bool;func F(flag bool)bool{x:=[]bool{false};p:=(*Lamp)(&x[0]);if flag{*p=true};return x[0]}`)
	_, proposal := proveRegionFixture(t, in)
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() {
		for _, states := range proposal.entries {
			for _, state := range states {
				for key, value := range state.values {
					for i := range value.location.path {
						value.location.path[i].summary = true
					}
					state.values[key] = regionUnknownValue(value.typ)
				}
				clear(state.memory)
			}
		}
	}}
	checked, err := checkRegion(ctx, in, proposal, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []bool{false, true} {
		assertRegionCovers(t, checked, executeRegionConcrete(t, in, flag))
	}
	_, proposal = proveRegionFixture(t, in)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if packet, err := checkRegion(cancelled, in, proposal, defaultRegionLimits()); packet != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled view checking: %v", err)
	}
}

func FuzzRegionScalarViewOracle(f *testing.F) {
	f.Add(int8(1), int8(2), false)
	f.Add(int8(-3), int8(7), true)
	f.Fuzz(func(t *testing.T, a, b int8, choose bool) {
		source := fmt.Sprintf(`type First int;type Second int;func set(p *Second,v int){*p=Second(v)};func F(flag bool)[]int{x:=First(%d);p:=(*Second)(&x);if flag{set(p,%d)};return []int{int(x),int(*p)}}`, a, b)
		in := regionFixture(t, source)
		checked, _ := proveRegionFixture(t, in)
		for _, out := range checked.observations {
			if !regionTestPrecise(out.value, out.state, 0) {
				t.Fatal("view result widened")
			}
		}
		assertRegionCovers(t, checked, executeRegionConcrete(t, in, choose))
	})
}

// These helpers compose only checked prefixes at actual call operands. No callee
// return is invented when the endpoint is inside the registration chain.
func regionViewSourcePrefix(t *testing.T, source computationSource, input regionInput) *sourceRegion {
	t.Helper()
	proposal, err := proposeRegion(t.Context(), input, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	// This test binds testing's whole selected package, rather than only the
	// small generated-main package used by the registration default budget.
	sourceLimits := selectedSourceLimits{work: 4 << 20, depth: 128, bytes: 64 << 20}
	checked, err := checkSourceRegion(t.Context(), source, input, proposal, sourceLimits, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	return checked
}

func regionViewStopCall(t *testing.T, input regionInput, name string) (regionInput, *ssa.Call) {
	t.Helper()
	for _, block := range input.root.Blocks {
		for i, ins := range block.Instrs {
			if call, ok := ins.(*ssa.Call); ok {
				target := call.Call.StaticCallee()
				if target != nil && target.Name() == name {
					input.use = regionUse{regionPoint{block, i}, call.Call.Value}
					return input, call
				}
			}
		}
	}
	t.Fatalf("actual call to %s missing in %s", name, input.root)
	return input, nil
}

func regionViewEnterCall(t *testing.T, prefix *sourceRegion, call *ssa.Call) regionInput {
	t.Helper()
	packet := prefix.packet
	if regionInstruction(packet.input.use.at) != call || len(packet.observations) != 1 {
		t.Fatal("handoff is not the actual checked call boundary")
	}
	target := call.Call.StaticCallee()
	if target == nil || len(target.Params) != len(call.Call.Args) {
		t.Fatal("handoff lacks exact canonical target/arguments")
	}
	k, err := newRegionKernel(t.Context(), packet.input, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	out := packet.observations[0]
	initial := regionState{values: map[ssa.Value]regionValue{}, memory: out.state.memory}
	for i, parameter := range target.Params {
		initial.values[parameter] = k.value(out.state, call.Call.Args[i])
	}
	m := regionMeter{limits: defaultRegionLimits()}
	initial, err = m.copyState(initial)
	if err != nil {
		t.Fatal(err)
	}
	return regionInput{owner: packet.input.owner, root: target, entry: regionPoint{target.Blocks[0], 0}, initial: initial, premises: append(slices.Clone(packet.input.premises), "entry arguments and heap are the preceding checked actual call boundary; continuation and applicability remain open")}
}

func TestRegionScalarViewActualFlagRegistration(t *testing.T) {
	if testing.Short() {
		t.Skip("actual selected testing/flag package load")
	}
	const path = "example.com/regionflagview"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module " + path + "\n\ngo 1.27\n", "p.go": "package p\n", "p_test.go": "package p\nimport \"testing\"\nfunc TestOne(t *testing.T){}\n"})
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	loader := newFixturePrograms(t, h)
	loader.supply(t, path)
	metas, err := h.list(path)
	if err != nil {
		t.Fatal(err)
	}
	source := computationSource{prog: loader.loaded, metas: metas}
	var testingPackage *ssa.Package
	for _, pkg := range source.prog.Pkgs {
		if pkg.PkgPath == "testing" {
			testingPackage = source.prog.Prog.Package(pkg.Types)
		}
	}
	if testingPackage == nil {
		t.Fatal("selected testing package missing")
	}
	init := testingPackage.Func("Init")
	guard, ok := testingPackage.Members["initRan"].(*ssa.Global)
	if !ok {
		t.Fatal("selected init guard missing")
	}
	input := regionInput{owner: source.prog.Prog, root: init, entry: regionPoint{init.Blocks[0], 0}, initial: regionState{memory: map[regionObject]regionValue{{kind: regionGlobal, site: guard}: {typ: types.Typ[types.Bool], kind: regionConstant, scalar: constant.MakeBool(false)}}}, premises: []string{"initRan is false on entry; this is a condition, not proof of global initialization", "incoming CommandLine and prior initialization effects are open; selected source/native and harness applicability remain open"}}
	input, call := regionViewStopCall(t, input, "Bool")
	initPrefix := regionViewSourcePrefix(t, source, input)
	if len(call.Call.Args) != 3 || call.Call.Args[0].(*ssa.Const).Value.ExactString() != `"test.short"` {
		t.Fatal("selected first Bool call changed")
	}
	state := initPrefix.packet.observations[0].state
	if b, known := regionBool(readRegionLocation(state, regionLocation{object: regionObject{kind: regionGlobal, site: guard}}, types.Typ[types.Bool])); !known || !b {
		t.Fatal("initialization prefix omitted its prior guard store")
	}
	wrapperInput := regionViewEnterCall(t, initPrefix, call)
	wrapperInput, methodCall := regionViewStopCall(t, wrapperInput, "Bool")
	wrapper := regionViewSourcePrefix(t, source, wrapperInput)
	boolInput := regionViewEnterCall(t, wrapper, methodCall)
	boolInput, boolVarCall := regionViewStopCall(t, boolInput, "BoolVar")
	allocation := regionViewSourcePrefix(t, source, boolInput)
	boolVarInput := regionViewEnterCall(t, allocation, boolVarCall)
	boolVarInput, varCall := regionViewStopCall(t, boolVarInput, "Var")
	if len(varCall.Call.Args) != 4 {
		t.Fatal("actual Var signature changed")
	}
	boolVarInput.use.operand = varCall.Call.Args[1]
	construction := regionViewSourcePrefix(t, source, boolVarInput)
	out := construction.packet.observations[0]
	if out.value.kind != regionInterface || len(out.value.elements) != 1 {
		t.Fatal("actual Var operand is not a concrete value")
	}
	view := out.value.elements[0]
	original := boolVarInput.initial.values[boolVarInput.root.Params[1]]
	if view.kind != regionPointer || view.location.object != original.location.object || !slices.Equal(view.location.path, original.location.path) || types.Identical(view.typ, original.typ) {
		t.Fatal("view split the allocation or lost its changed access type")
	}
	storage := readRegionLocation(out.state, view.location, types.Typ[types.Bool])
	if b, known := regionBool(storage); !known || b {
		t.Fatal("first flag default no longer resides in its original bool cell")
	}
	if len(construction.calls) != 1 || construction.calls[0].call.target.Name() != "newBoolValue" {
		t.Fatal("constructor body was not independently bound and checked")
	}
	if construction.calls[0].bound.identity.body == ([32]byte{}) {
		t.Fatal("constructor lost selected body identity")
	}
	t.Logf("selected path: %s -> %s -> %s -> %s -> %s; endpoint before %s", init, wrapperInput.root, boolInput.root, boolVarInput.root, construction.calls[0].call.target, varCall)
	var body strings.Builder
	construction.calls[0].call.target.WriteTo(&body)
	t.Log(body.String())
	// The receiving scope treats incoming allocations as summaries. Equal old
	// and new values suffice here; the conversion must not grant singletonness.
	k, err := newRegionKernel(t.Context(), boolVarInput, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if k.singleton(view.location.object) {
		t.Fatal("handoff fabricated singleton authority")
	}
	changed := boolVarInput
	m := regionMeter{limits: defaultRegionLimits()}
	changed.initial, err = m.copyState(boolVarInput.initial)
	if err != nil {
		t.Fatal(err)
	}
	changed.initial.values[changed.root.Params[3]] = regionValue{typ: types.Typ[types.Bool], kind: regionConstant, scalar: constant.MakeBool(true)}
	changedPacket, _ := proveRegionFixture(t, changed)
	changedOut := changedPacket.observations[0]
	if readRegionLocation(changedOut.state, changedOut.value.elements[0].location, types.Typ[types.Bool]).kind != regionUnknown {
		t.Fatal("different weak-store value overwrote old possible contents")
	}
	// This segment ends before Var. Moving its boundary to the function return
	// requires all actual Var effects rather than a fabricated BoolVar return.
	whole := boolVarInput
	for _, block := range whole.root.Blocks {
		for i, ins := range block.Instrs {
			if ret, ok := ins.(*ssa.Return); ok && len(ret.Results) == 0 {
				whole.use = regionUse{at: regionPoint{block, i}}
			}
		}
	}
	if p, err := proposeRegion(t.Context(), whole, defaultRegionLimits()); p != nil || err == nil {
		t.Fatal("unsupported flag registration continuation was silently completed")
	}
}
