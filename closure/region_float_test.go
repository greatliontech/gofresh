package closure

import (
	"context"
	"errors"
	"go/constant"
	"go/token"
	"go/types"
	"math"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func regionFloatInput(t testing.TB, text string) (computationSource, regionInput) {
	t.Helper()
	source := relationFixture(t, text, 64)
	root := source.prog.Roots["F"]
	in := regionInput{owner: root.Prog, root: root, entry: regionPoint{root.Blocks[0], 0},
		selection: source.prog, storageModel: conditionalRegionStorageModel(), premises: []string{"conditional source storage; entry and native applicability remain open"}}
	for _, block := range root.Blocks {
		for i, instruction := range block.Instrs {
			if ret, ok := instruction.(*ssa.Return); ok {
				in.use.at = regionPoint{block, i}
				if len(ret.Results) != 0 {
					in.use.operand = ret.Results[0]
				}
			}
		}
	}
	return source, in
}

func TestRegionFloatIdentityAndIEEEEquality(t *testing.T) {
	for _, tc := range []struct {
		name             string
		typ              types.Type
		a, b             uint64
		equal, identical bool
	}{
		{"nan64", types.Typ[types.Float64], 0x7ff8000000000042, 0x7ff8000000000042, false, true},
		{"snan64", types.Typ[types.Float64], 0x7ff0000000000001, 0x7ff0000000000001, false, true},
		{"nan-payload", types.Typ[types.Float64], 0x7ff8000000000001, 0x7ff8000000000002, false, false},
		{"zero64", types.Typ[types.Float64], 0, 1 << 63, true, false},
		{"infinity64", types.Typ[types.Float64], 0x7ff0000000000000, 0x7ff0000000000000, true, true},
		{"subnormal64", types.Typ[types.Float64], 1, 2, false, false},
		{"nan32", types.Typ[types.Float32], 0x7fc00042, 0x7fc00042, false, true},
		{"zero32", types.Typ[types.Float32], 0, 1 << 31, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := regionValue{typ: tc.typ, kind: regionFloat, floatBits: tc.a}
			b := regionValue{typ: tc.typ, kind: regionFloat, floatBits: tc.b}
			if regionSameValue(a, b) != tc.identical || regionValueIncluded(a, b) != tc.identical {
				t.Fatal("abstract identity used numerical equality")
			}
			for _, op := range []string{"==", "!="} {
				in := regionFixture(t, "func F(a,b "+tc.typ.String()+")bool{return a"+op+"b}")
				in.initial.values = map[ssa.Value]regionValue{in.root.Params[0]: a, in.root.Params[1]: b}
				proof, _ := proveRegionFixture(t, in)
				got, known := regionBool(proof.observations[0].value)
				if !known || got != (tc.equal == (op == "==")) {
					t.Fatalf("IEEE %s: %v %v", op, got, known)
				}
			}
		})
	}
}

func TestRegionFloatConstantsAndZero(t *testing.T) {
	for _, tc := range []struct {
		text string
		bits uint64
	}{
		{`func F()float32{return 0x1.000001p0}`, 0x3f800000},
		{`func F()float32{return 0x1.000003p0}`, 0x3f800002},
		{`func F()float64{return 0x1.00000000000008p0}`, 0x3ff0000000000000},
		{`func F()float64{return 0x1.00000000000018p0}`, 0x3ff0000000000002},
		{`func F()float32{return -0x1p-200}`, 0},
		{`func F()float64{return -0x1p-2000}`, 0},
		{`func F()float64{p:=new(float64);return *p}`, 0},
		{`type Number float32;func F()Number{p:=new(Number);return *p}`, 0},
		{`type Number float32;func F()Number{x:=float32(1.5);return Number(x)}`, 0x3fc00000},
	} {
		t.Run(tc.text, func(t *testing.T) {
			in := regionFixture(t, tc.text)
			proof, _ := proveRegionFixture(t, in)
			value := proof.observations[0].value
			if value.kind != regionFloat || value.floatBits != tc.bits || !types.Identical(value.typ, in.use.operand.Type()) {
				t.Fatalf("constant/zero=%+v, want %#x", value, tc.bits)
			}
		})
	}
	// Check target rounding directly too: the SSA frontend may already round a literal.
	for _, literal := range []string{"0x1.000001p0", "0x1.00000100000000000001p0"} {
		v := constant.MakeFromLiteral(literal, token.FLOAT, 0)
		got, ok := regionFloatConstant(types.Typ[types.Float32], v)
		want := uint64(0x3f800000)
		if literal != "0x1.000001p0" {
			want++
		}
		if !ok || got.floatBits != want {
			t.Fatalf("direct target rounding %s: %+v", literal, got)
		}
	}
}

func TestRegionFloatCheckedViewsAndAliases(t *testing.T) {
	for _, tc := range []struct {
		text string
		want uint64
	}{
		{`import "unsafe";func F()uint64{var x uint64=0x8000000000000000;p:=(*float64)(unsafe.Pointer(&x));if *p!=0{panic(1)};return x}`, 1 << 63},
		{`import "unsafe";func F()uint32{x:=uint32(0x7fc00042);p:=(*float32)(unsafe.Pointer(&x));if *p==*p{panic(1)};return x}`, 0x7fc00042},
		{`import "unsafe";func set(p *float64){*p=1.5};func F()uint64{x:=uint64(0);p:=(*float64)(unsafe.Pointer(&x));set(p);return x}`, 0x3ff8000000000000},
		{`import "unsafe";func F()uint32{var x struct{Pad uint64;A [2]float32};p:=(*uint32)(unsafe.Pointer(&x.A[1]));*p=0x80000000;if x.A[1]!=0{panic(1)};return *p}`, 0x80000000},
		{`import "unsafe";type A uint32;type B float32;func F()A{x:=A(0);p:=(*B)(unsafe.Pointer(&x));*p=1.5;return x}`, 0x3fc00000},
	} {
		t.Run(tc.text, func(t *testing.T) {
			_, in := regionFloatInput(t, tc.text)
			proof, _ := proveRegionFixture(t, in)
			got, ok := constant.Uint64Val(proof.observations[0].value.scalar)
			if !ok || got != tc.want || proof.input.storageModel != in.storageModel {
				t.Fatalf("view result %x %v, want %x", got, ok, tc.want)
			}
		})
	}
}

type regionFloatMisalignedSizes struct{ types.Sizes }

func (s regionFloatMisalignedSizes) Alignof(typ types.Type) int64 {
	if regionFloatWidth(typ) == 8 {
		return 16
	}
	return s.Sizes.Alignof(typ)
}

type regionFloatCancelSizes struct {
	types.Sizes
	cancel context.CancelFunc
}

func (s regionFloatCancelSizes) Alignof(typ types.Type) int64 {
	if basic, ok := typ.Underlying().(*types.Basic); ok && basic.Info()&types.IsFloat != 0 {
		s.cancel()
	}
	return s.Sizes.Alignof(typ)
}

func TestRegionFloatLayoutCancellation(t *testing.T) {
	source, in := regionFloatInput(t, `import "unsafe";func F()float64{var x uint64;return *(*float64)(unsafe.Pointer(&x))}`)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	enteredFloat := false
	source.prog.Pkgs[0].TypesSizes = regionFloatCancelSizes{source.prog.Pkgs[0].TypesSizes, func() { enteredFloat = true; cancel() }}
	if proof, err := proposeRegion(ctx, in, defaultRegionLimits()); proof != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("layout cancellation lost: %v", err)
	}
	if !enteredFloat {
		t.Fatal("cancellation did not reach the float storage layout")
	}
}

func TestRegionFloatViewRefusals(t *testing.T) {
	for _, text := range []string{
		`import "unsafe";func F()float64{var x uint32;return *(*float64)(unsafe.Pointer(&x))}`,
		`import "unsafe";func F()float32{var x [2]uint32;return *(*float32)(unsafe.Pointer(&x))}`,
		`import "unsafe";func F()float32{var x uint32;return *(*float32)(unsafe.Pointer(uintptr(unsafe.Pointer(&x))))}`,
		`import "unsafe";func F()uint32{x:=uint32(1);return uint32(*(*float32)(unsafe.Pointer(&x)))}`,
		`import "unsafe";func escape(p *float32)*float32{return p};func F()float32{var x uint32;p:=(*float32)(unsafe.Pointer(&x));return *escape(p)}`,
		`import "unsafe";func F()float32{var x uint32;p:=(*float32)(unsafe.Pointer(&x));q:=new(*float32);*q=p;return **q}`,
	} {
		t.Run(text, func(t *testing.T) {
			_, in := regionFloatInput(t, text)
			if _, err := proposeRegion(t.Context(), in, defaultRegionLimits()); err == nil {
				t.Fatal("unsupported view admitted")
			}
		})
	}
	for _, change := range []string{"absent-model", "foreign-model", "alignment", "missing-sizes", "duplicated-package"} {
		t.Run(change, func(t *testing.T) {
			source, in := regionFloatInput(t, `import "unsafe";func F()float64{var x uint64;return *(*float64)(unsafe.Pointer(&x))}`)
			switch change {
			case "absent-model":
				in.storageModel = regionStorageModel{}
			case "foreign-model":
				other, _ := regionFloatInput(t, `func F(){}`)
				in.selection = other.prog
				in.storageModel = conditionalRegionStorageModel()
			case "alignment":
				source.prog.Pkgs[0].TypesSizes = regionFloatMisalignedSizes{source.prog.Pkgs[0].TypesSizes}
			case "missing-sizes":
				source.prog.Pkgs[0].TypesSizes = nil
			case "duplicated-package":
				source.prog.Pkgs = append(source.prog.Pkgs, source.prog.Pkgs[0])
			}
			if _, err := proposeRegion(t.Context(), in, defaultRegionLimits()); err == nil {
				t.Fatal("unestablished model/layout admitted")
			}
		})
	}
}

func TestRegionFloatProposalModelAndBitForgery(t *testing.T) {
	const text = `import "unsafe";func read(p *float64)float64{return *p};func F()bool{x:=uint64(0x7ff8000000000042);p:=(*float64)(unsafe.Pointer(&x));f:=read(p);return f==f}`
	for _, change := range []string{"stripped-model", "changed-model", "moved-source", "call-model"} {
		t.Run(change, func(t *testing.T) {
			_, in := regionFloatInput(t, text)
			_, proposal := proveRegionFixture(t, in)
			switch change {
			case "stripped-model":
				proposal.input.storageModel = regionStorageModel{}
			case "changed-model":
				proposal.input.storageModel.interpretation++
			case "moved-source":
				copy := *proposal.input.selection
				proposal.input.selection = &copy
			case "call-model":
				proposal.calls[0].storageModel = regionStorageModel{}
			}
			if proof, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits()); err == nil || proof != nil {
				t.Fatal("forged proposal admitted")
			}
		})
	}
	for _, bad := range []regionValue{
		{typ: types.Typ[types.Float32], kind: regionFloat, floatBits: 1 << 32},
		{typ: types.Typ[types.Float32], kind: regionUnknown, floatBits: 1},
		{typ: types.Typ[types.Float32], kind: regionFloat, scalar: constant.MakeInt64(0)},
		{typ: types.Typ[types.Float32], kind: regionConstant, scalar: constant.MakeFloat64(0)},
	} {
		in := regionFixture(t, `func F(x float32)float32{return x}`)
		parameter := in.root.Params[0]
		in.initial.values = map[ssa.Value]regionValue{parameter: {typ: parameter.Type(), kind: regionFloat}}
		_, proposal := proveRegionFixture(t, in)
		proposal.entries[in.entry.block][0].values[parameter] = bad
		if proof, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits()); err == nil || proof != nil {
			t.Fatal("noncanonical float payload admitted", bad)
		}
	}
}

func TestRegionFloatViewLiveProvenance(t *testing.T) {
	_, in := regionFloatInput(t, `import "unsafe";func F()float32{var x struct{A [2]uint32};return *(*float32)(unsafe.Pointer(&x.A[1]))}`)
	proof, _ := proveRegionFixture(t, in)
	k, err := newRegionKernel(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	state := proof.observations[0].state
	var loc regionLocation
	for object := range state.memory {
		loc = regionLocation{object: object, path: []regionStep{{field: true}, {index: 1}}}
	}
	if !k.liveView(state, loc, types.Typ[types.Float32]) {
		t.Fatal("exact live subobject lost")
	}
	if k.liveView(regionState{}, loc, types.Typ[types.Float32]) {
		t.Fatal("allocation-shaped identity supplied liveness")
	}
	for _, path := range [][]regionStep{
		{{field: true}, {index: 1, summary: true}},
		{{field: true}, {index: -1}},
		{{field: true}, {index: 2}},
		{{field: true}, {field: true, index: 1}},
	} {
		bad := loc
		bad.path = path
		if k.liveView(state, bad, types.Typ[types.Float32]) {
			t.Fatal("inexact or mistyped view path admitted", path)
		}
	}
	k.preexisting[loc.object] = true
	if k.liveView(state, loc, types.Typ[types.Float32]) {
		t.Fatal("summary allocation acquired singleton view")
	}
}

func TestRegionFloatIncomingUnsafeAllocationInstance(t *testing.T) {
	_, in := regionFloatInput(t, `import "unsafe";var G *uint64;func F(p unsafe.Pointer)float64{x:=new(uint64);G=x;return *(*float64)(p)}`)
	allocations := storageOracleInstructions[*ssa.Alloc](in.root)
	if len(allocations) != 1 {
		t.Fatal("instance regression lost its allocating site")
	}
	object := regionObject{kind: regionAllocation, site: allocations[0], context: in.root}
	parameter := in.root.Params[0]
	// The incoming pointer may identify an older object from this site. Its
	// unknown contents cannot be replaced by this invocation's new zero object.
	in.initial.values = map[ssa.Value]regionValue{parameter: {typ: parameter.Type(), kind: regionUnsafePointer, location: regionLocation{object: object}}}
	kernel, err := newRegionKernel(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !kernel.preexisting[object] || kernel.singleton(object) {
		t.Fatal("incoming unsafe provenance was mistaken for a fresh allocation")
	}
	proposal, err := proposeRegion(t.Context(), in, defaultRegionLimits())
	if err == nil {
		if proof, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits()); err == nil || proof != nil {
			t.Fatal("old unsafe pointer borrowed newly allocated float zero")
		}
	}
}

func TestRegionFloatFiniteContinuation(t *testing.T) {
	source, in := regionFloatInput(t, `import "unsafe";func Stop(*uint64,bool){};func set(p *float64){*p=1.5};func F(){x:=uint64(0x7ff8000000000042);p:=(*float64)(unsafe.Pointer(&x));Stop(&x,*p!=*p);set(p);Stop(&x,*p==1.5)}`)
	calls := localEffectCalls(t, in.root, "Stop")
	first, err := checkSourceOperandPrefix(t.Context(), source, in.root, calls[0], defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	second, err := checkSourceOperandContinuation(t.Context(), first, calls[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []*sourceOperandPrefix{first, second} {
		if equal, known := regionBool(prefix.operands[1]); !known || !equal || prefix.checkedPacket() == nil || prefix.region.packet.input.storageModel != in.storageModel || prefix.region.packet.input.selection != in.selection {
			t.Fatal("finite float facts or model lost")
		}
	}
	loc := first.operands[0].location
	old := first.checker.readLocation(first.region.packet.observations[0].state, loc, types.Typ[types.Float64])
	now := second.checker.readLocation(second.region.packet.observations[0].state, loc, types.Typ[types.Float64])
	if old.floatBits != 0x7ff8000000000042 || now.floatBits != math.Float64bits(1.5) || len(second.region.packet.calls) == 0 {
		t.Fatal("continuation reset or aliased the predecessor heap")
	}
	// Stripping both input projections still cannot erase the selected antecedent.
	saved := first.region.packet.input.storageModel
	first.region.packet.input.storageModel = regionStorageModel{}
	first.checker.input.storageModel = regionStorageModel{}
	if first.checkedPacket() != nil {
		t.Fatal("opaque receipt accepted stripped model")
	}
	first.region.packet.input.storageModel = saved
	first.checker.input.storageModel = saved
	selection := first.region.packet.input.selection
	foreign := *selection
	first.region.packet.input.selection = &foreign
	first.checker.input.selection = &foreign
	if first.checkedPacket() != nil {
		t.Fatal("opaque receipt borrowed an equal-SSA foreign source model")
	}
	first.region.packet.input.selection = selection
	first.checker.input.selection = selection
	copy := *second.sourceEffectPrefix
	if copy.checkedPacket() != nil {
		t.Fatal("copied receipt acquired continuation authority")
	}
}

func TestRegionFloatFiniteUnsupportedControls(t *testing.T) {
	for _, text := range []string{
		`var x float64;func Stop(bool){};func F(){Stop(x==x)}`,
		`func Stop(bool){};func F(){var x complex128;Stop(x==x)}`,
		`func Stop(bool){};func F(){var x float64;Stop(x+1==x)}`,
		`func Stop(bool){};func F(){var x float64;Stop(uint64(x)==0)}`,
		`func Stop(bool){};func F(){var x float64;var a any=x;Stop(a==a)}`,
	} {
		t.Run(text, func(t *testing.T) {
			source, in := regionFloatInput(t, text)
			if _, err := checkSourceOperandPrefix(t.Context(), source, in.root, localEffectCalls(t, in.root, "Stop")[0], defaultRegistrationLimits()); err == nil {
				t.Fatal("unsupported finite scalar control admitted")
			}
		})
	}
}
