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

func localEffectCalls(t testing.TB, root *ssa.Function, name string) []*ssa.Call {
	t.Helper()
	var calls []*ssa.Call
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			call, ok := instruction.(*ssa.Call)
			if ok && call.Call.StaticCallee() != nil && call.Call.StaticCallee().Name() == name {
				calls = append(calls, call)
			}
		}
	}
	slices.SortFunc(calls, func(a, b *ssa.Call) int { return int(a.Pos() - b.Pos()) })
	if len(calls) == 0 {
		t.Fatalf("missing actual call %s", name)
	}
	return calls
}

func localEffectInteger(t testing.TB, value regionValue, want uint64) {
	t.Helper()
	if value.kind != regionConstant || value.scalar == nil || value.scalar.Kind() != constant.Int {
		t.Fatalf("not an established integer: %+v", value)
	}
	n, exact := constant.Uint64Val(value.scalar)
	if !exact || n != want {
		t.Fatalf("integer %v, want %d", value.scalar, want)
	}
}

func localEffectPrefix(t testing.TB, text string) (computationSource, *sourceOperandPrefix) {
	t.Helper()
	source := relationFixture(t, text, 64)
	root := source.prog.Roots["F"]
	call := localEffectCalls(t, root, "Stop")[0]
	prefix, err := checkSourceOperandPrefix(t.Context(), source, root, call, defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	return source, prefix
}

func TestRegionLocalTypedEffects(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       uint64
		path       []regionStep
		aggregate  bool
	}{
		{"uint32", `func Stop(*uint32,uint32){};func F(){var x uint32;p:=&x;*p=7;Stop(p,*p)}`, 7, nil, false},
		{"array-alias-replacement", `func Stop(*byte,byte){};func F(){var a [4]byte;p:=&a[2];*p=7;a=[4]byte{1,2,9,4};Stop(p,*p)}`, 9, []regionStep{{index: 2}}, true},
		{"nested-field-alias-replacement", `type Inner struct{Bytes [4]byte};type Box struct{Tag uint32;Inner Inner};func Stop(*byte,byte){};func F(){var b Box;p:=&b.Inner.Bytes[2];*p=7;b.Inner=Inner{Bytes:[4]byte{1,2,9,4}};Stop(p,*p)}`, 9, []regionStep{{field: true, index: 1}, {field: true}, {index: 2}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, prefix := localEffectPrefix(t, tc.text)
			packet := prefix.region.packet
			pointer := prefix.operands[0]
			if pointer.kind != regionPointer || pointer.location.object.kind != regionAllocation || !slices.Equal(pointer.location.path, tc.path) {
				t.Fatalf("lost exact local/subobject provenance: %+v", pointer)
			}
			localEffectInteger(t, prefix.operands[1], tc.want)
			current := readRegionLocation(packet.observations[0].state, pointer.location, prefix.operands[1].typ)
			localEffectInteger(t, current, tc.want)
			allocation, live, err := prefix.liveAllocation(pointer.location.object, func() error { return nil })
			if err != nil || !live || allocation.instruction != pointer.location.object.site || allocation.invocation != pointer.location.object.invocation {
				t.Fatalf("lost checked live allocation: live=%v error=%v", live, err)
			}
			last := packet.trace.accesses[len(packet.trace.accesses)-1]
			if last.write || last.location.object != pointer.location.object || !slices.Equal(last.location.path, pointer.location.path) || !types.Identical(last.value.typ, prefix.operands[1].typ) {
				t.Fatal("actual load lost location/type")
			}
			localEffectInteger(t, last.value, tc.want)
			if tc.aggregate {
				found := false
				for _, event := range packet.trace.accesses {
					found = found || event.write && event.value.kind == regionAggregate && event.location.object == pointer.location.object
				}
				if !found {
					t.Fatal("aggregate replacement disappeared from effects")
				}
			} else {
				localEffectInteger(t, allocation.initializer, 0)
			}
		})
	}
}

func TestRegionLocalKnownBranchActualPhi(t *testing.T) {
	_, prefix := localEffectPrefix(t, `func Stop(*uint32,uint32){};func F(){p:=new(uint32);*p=1;var n uint32;if *p==1 {n=7}else{n=9};Stop(p,n)}`)
	localEffectInteger(t, prefix.operands[1], 7)
	if prefix.call.Block() == prefix.region.packet.input.entry.block || len(prefix.region.packet.trace.excluded) != 1 {
		t.Fatal("fixture did not exercise a checked branch beyond entry")
	}
	phis := 0
	for _, occurrence := range prefix.region.packet.trace.instructions {
		if _, ok := occurrence.instruction.(*ssa.Phi); ok {
			phis++
		}
	}
	if phis != 1 {
		t.Fatal("actual merged phi was not checked")
	}
	source := relationFixture(t, `var flag bool;func Stop(uint32){};func F(){var n uint32;if flag {n=7}else{n=9};Stop(n)}`, 64)
	root := source.prog.Roots["F"]
	if _, err := checkSourceOperandPrefix(t.Context(), source, root, localEffectCalls(t, root, "Stop")[0], defaultRegistrationLimits()); err == nil || !strings.Contains(err.Error(), "unresolved branch") {
		t.Fatalf("unexplained branch accepted or refused for wrong cause: %v", err)
	}
}

func TestRegionLocalOrdinaryCallsRetainEntireRelation(t *testing.T) {
	source, prefix := localEffectPrefix(t, `func Stop(*uint32,uint32){};func zero()uint32{return 7};func set(p,q *uint32)uint32{*p=11;*q=13;return *p};func F(){var x,y uint32;a:=zero();b:=set(&x,&y);if a!=7||b!=11{panic(1)};Stop(&x,b)}`)
	localEffectInteger(t, prefix.operands[1], 11)
	trace := prefix.region.packet.trace
	if len(trace.calls) != 2 {
		t.Fatalf("lost ordinary calls: %d", len(trace.calls))
	}
	for _, application := range trace.calls {
		proof := application.proof
		if proof.at.Parent() != source.prog.Roots["F"] || proof.reference != nil || len(proof.arguments) != len(proof.target.Params) {
			t.Fatal("call evidence does not bind actual source body/formals")
		}
		want := uint64(7)
		if proof.target.Name() == "set" {
			want = 11
			if !regionSameValue(proof.arguments[0], prefix.operands[0]) || !regionSameValue(proof.initial.values[proof.target.Params[0]], prefix.operands[0]) {
				t.Fatal("actual local argument not bound to formal")
			}
			localEffectInteger(t, readRegionLocation(application.outcome.state, prefix.operands[0].location, types.Typ[types.Uint32]), 11)
			localEffectInteger(t, readRegionLocation(proof.initial, prefix.operands[0].location, types.Typ[types.Uint32]), 0)
			localEffectInteger(t, readRegionLocation(application.outcome.state, proof.arguments[1].location, types.Typ[types.Uint32]), 13)
			localEffectInteger(t, readRegionLocation(prefix.region.packet.observations[0].state, proof.arguments[1].location, types.Typ[types.Uint32]), 13)
		}
		localEffectInteger(t, application.outcome.value, want)
	}
	_, zero := localEffectPrefix(t, `func Stop(){};func F(){Stop()}`)
	returned := zero.call.Block().Instrs[len(zero.call.Block().Instrs)-1].(*ssa.Return)
	complete, err := checkSourceReturnContinuation(t.Context(), zero, returned, nil)
	if err != nil || complete == nil || len(complete.region.packet.trace.calls) != 1 {
		t.Fatalf("zero-argument call/return completion refused: %v", err)
	}
}

func TestRegionLocalContinuationRetainsAllocationAndCurrentContents(t *testing.T) {
	source, prefix := localEffectPrefix(t, `func Stop(*uint32,uint32){};func F(){var x uint32;x=7;Stop(&x,x);x=9;Stop(&x,x);x=11;Stop(&x,x)}`)
	calls := localEffectCalls(t, source.prog.Roots["F"], "Stop")
	object := prefix.operands[0].location.object
	current := prefix
	for i, want := range []uint64{9, 11} {
		next, err := checkSourceOperandContinuation(t.Context(), current, calls[i+1], nil)
		if err != nil {
			t.Fatal(err)
		}
		if next.operands[0].location.object != object || len(next.region.packet.trace.allocations) != 0 {
			t.Fatal("continuation recreated the existing object")
		}
		localEffectInteger(t, next.operands[1], want)
		allocation, live, err := next.liveAllocation(object, func() error { return nil })
		if err != nil || !live {
			t.Fatalf("continued object lost checked cardinality: %v", err)
		}
		localEffectInteger(t, allocation.initializer, 0)
		current = next
	}
	// A sibling continuation gets its own maps, account and occurrence guard.
	again, err := checkSourceOperandContinuation(t.Context(), prefix, calls[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	localEffectInteger(t, again.operands[1], 9)
	localEffectInteger(t, prefix.operands[1], 7)
	localEffectInteger(t, readRegionLocation(prefix.region.packet.observations[0].state, prefix.operands[0].location, types.Typ[types.Uint32]), 7)
	returned := calls[2].Block().Instrs[len(calls[2].Block().Instrs)-1].(*ssa.Return)
	complete, err := checkSourceReturnContinuation(t.Context(), again, returned, nil)
	if err != nil {
		t.Fatal(err)
	}
	localEffectInteger(t, readRegionLocation(complete.region.packet.observations[0].state, prefix.operands[0].location, types.Typ[types.Uint32]), 11)
	if len(complete.region.packet.trace.allocations) != 0 || len(complete.region.packet.trace.calls) != 2 {
		t.Fatal("source return completion lost actual calls or recreated local storage")
	}
	if _, err := checkSourceOperandContinuation(t.Context(), current, calls[0], nil); err == nil {
		t.Fatal("continuation replayed an earlier occurrence")
	}
	projection := &sourceOperandPrefix{sourceEffectPrefix: &sourceEffectPrefix{region: prefix.region, binder: prefix.binder}, call: prefix.call, operands: prefix.operands}
	if _, err := checkSourceOperandContinuation(t.Context(), projection, calls[1], nil); err == nil {
		t.Fatal("copied projection manufactured an opaque continuation")
	}
	wrongCut := *prefix
	wrongCore := *prefix.sourceEffectPrefix
	wrongCut.sourceEffectPrefix = &wrongCore
	wrongCut.self, wrongCore.self = &wrongCut, &wrongCore
	wrongCut.checker = current.checker
	if _, err := checkSourceOperandContinuation(t.Context(), &wrongCut, calls[1], nil); err == nil {
		t.Fatal("checker from a different cut established predecessor authority")
	}
	// Copying the projection into a new conditional input grants no freshness.
	in := prefix.region.packet.input
	in.entry, in.use = in.use.at, regionUse{at: regionPoint{calls[1].Block(), slices.Index(calls[1].Block().Instrs, ssa.Instruction(calls[1]))}, operand: calls[1].Call.Args[1]}
	in.initial = prefix.region.packet.observations[0].state
	k, err := newRegionKernel(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if k.singleton(object) {
		t.Fatal("copied heap projection forged a fresh singleton")
	}
	proposal, err := proposeRegion(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if packet.observations[0].value.kind != regionUnknown {
		t.Fatal("changing store through caller-owned summary forgot old possible contents")
	}
}

func TestRegionLocalCalleeAllocationSurvivesContinuation(t *testing.T) {
	source, prefix := localEffectPrefix(t, `func Stop(*uint32,uint32){};func makep()*uint32{p:=new(uint32);*p=3;return p};func F(){p:=makep();Stop(p,*p);*p=5;Stop(p,*p)}`)
	object := prefix.operands[0].location.object
	if object.context == source.prog.Roots["F"] || object.invocation == (regionInvocation{}) {
		t.Fatal("fixture lost actual allocating callee context")
	}
	continued, err := checkSourceOperandContinuation(t.Context(), prefix, localEffectCalls(t, source.prog.Roots["F"], "Stop")[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	if continued.operands[0].location.object != object || len(continued.region.packet.trace.allocations) != 0 {
		t.Fatal("callee object identity was reset at the caller cut")
	}
	localEffectInteger(t, continued.operands[1], 5)
	_, live, err := continued.liveAllocation(object, func() error { return nil })
	if err != nil || !live {
		t.Fatalf("retained callee context did not establish singleton: %v", err)
	}
}

func TestRegionLocalReturnRetainsTerminalAllocations(t *testing.T) {
	_, prefix := localEffectPrefix(t, `func Stop(){};func consume(*uint32){};func F(){Stop();p:=new(uint32);*p=17;consume(p)}`)
	block := prefix.call.Block()
	returned := block.Instrs[len(block.Instrs)-1].(*ssa.Return)
	complete, err := checkSourceReturnContinuation(t.Context(), prefix, returned, nil)
	if err != nil {
		t.Fatal(err)
	}
	packet := complete.checkedPacket()
	if packet == nil || len(packet.trace.allocations) != 1 {
		t.Fatal("completed return lost its checked terminal allocation")
	}
	allocation := packet.trace.allocations[0]
	retained, live, err := complete.liveAllocation(allocation.location.object, func() error { return nil })
	if err != nil || !live || retained.instruction != allocation.instruction {
		t.Fatalf("terminal allocation lacks actual checked authority: live=%v error=%v", live, err)
	}
	localEffectInteger(t, retained.initializer, 0)
	localEffectInteger(t, readRegionLocation(packet.observations[0].state, allocation.location, types.Typ[types.Uint32]), 17)
	if _, live, err := prefix.liveAllocation(allocation.location.object, func() error { return nil }); live || err != nil {
		t.Fatal("earlier operand cut claimed a future allocation")
	}
	projection := *complete
	projection.checker = nil
	if projection.checkedPacket() != nil {
		t.Fatal("return heap projection manufactured checked authority")
	}
}

func TestRegionLocalLaterFactoryDoesNotResetEarlierObject(t *testing.T) {
	source, prefix := localEffectPrefix(t, `func Stop(*uint32,uint32){};func makep()*uint32{p:=new(uint32);*p=3;return p};func F(){p:=makep();Stop(p,*p);*p=5;q:=makep();Stop(q,*p)}`)
	continued, err := checkSourceOperandContinuation(t.Context(), prefix, localEffectCalls(t, source.prog.Roots["F"], "Stop")[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	old, fresh := prefix.operands[0].location.object, continued.operands[0].location.object
	if old.site != fresh.site || old.context != fresh.context || old.invocation == fresh.invocation {
		t.Fatal("two allocating invocations collapsed to a shared object")
	}
	localEffectInteger(t, continued.operands[1], 5)
	localEffectInteger(t, readRegionLocation(continued.region.packet.observations[0].state, continued.operands[0].location, types.Typ[types.Uint32]), 3)
	for _, object := range []regionObject{old, fresh} {
		if _, live, err := continued.liveAllocation(object, func() error { return nil }); err != nil || !live {
			t.Fatalf("distinct live invocation lost checked cardinality: %v", err)
		}
	}
}

func TestRegionLocalScalarInitialization(t *testing.T) {
	_, prefix := localEffectPrefix(t, `type Mixed struct{Word uint32;Float float64};func Stop(*Mixed,uint32){};func F(){var x Mixed;x.Word=7;Stop(&x,x.Word)}`)
	localEffectInteger(t, prefix.operands[1], 7)
	object := prefix.operands[0].location.object
	allocation, live, err := prefix.liveAllocation(object, func() error { return nil })
	if err != nil || !live || allocation.initializer.kind != regionAggregate || len(allocation.initializer.elements) != 2 {
		t.Fatalf("mixed allocation lost initialized shape: %+v %v", allocation, err)
	}
	localEffectInteger(t, allocation.initializer.elements[0], 0)
	zero := allocation.initializer.elements[1]
	if bits, width, exact := storageScalarBits(zero, prefix.region.root.pkg.TypesSizes); !exact || bits != 0 || width != 8 {
		t.Fatal("float initialization lost exact positive zero")
	}
	_, scalar := localEffectPrefix(t, `func Stop(bool){};func F(){var x float64;Stop(x==x)}`)
	if value, known := regionBool(scalar.operands[0]); !known || !value {
		t.Fatal("initialized float equality is not derived")
	}
	for _, body := range []string{
		`Stop(Unknown==Unknown)`,
		`var x complex128;Stop(x==x)`,
	} {
		source := relationFixture(t, `var Unknown float64;func Stop(bool){};func F(){`+body+`}`, 64)
		root := source.prog.Roots["F"]
		if _, err := checkSourceOperandPrefix(t.Context(), source, root, localEffectCalls(t, root, "Stop")[0], defaultRegistrationLimits()); err == nil {
			t.Fatal("unknown float or complex consumption acquired an exact finite proof")
		}
	}
	// Copying an aggregate and selecting its supported field does not evaluate
	// an unsupported complex sibling as a scalar expression.
	_, copied := localEffectPrefix(t, `type Mixed struct{Word uint32;Opaque complex128};func Stop(*Mixed,uint32){};func word(x Mixed)uint32{return x.Word};func F(){var x Mixed;x.Word=7;y:=x;Stop(&x,word(y))}`)
	localEffectInteger(t, copied.operands[1], 7)
	broad, _ := proveRegionFixture(t, regionFixture(t, `func F()bool{p:=new(float64);return *p==*p}`))
	if equal, exact := regionBool(broad.observations[0].value); !exact || !equal {
		t.Fatal("broad initialized-float transport lost Go scalar equality")
	}
	unknown, _ := proveRegionFixture(t, regionFixture(t, `func F(x float64)bool{return x==x}`))
	if unknown.observations[0].value.kind != regionUnknown {
		t.Fatal("unknown float was assumed reflexive")
	}
}

func TestRegionLocalMixedInitializationDoesNotPreventAliasWidening(t *testing.T) {
	in := regionFixture(t, `type Mixed struct{Word uint32;Float float64};func F(p *uint32)uint32{x:=new(Mixed);x.Word=7;*p=9;return x.Word}`)
	parameter := in.root.Params[0]
	in.initial.values = map[ssa.Value]regionValue{
		parameter: {typ: parameter.Type(), kind: regionPointer, location: regionLocation{object: regionObject{kind: regionFormal, site: parameter, context: in.root}}},
	}
	packet, _ := proveRegionFixture(t, in)
	if len(packet.observations) != 1 || packet.observations[0].value.kind != regionUnknown {
		t.Fatal("unsupported sibling initialization insulated a supported field from a real unknown-alias write")
	}
}

func TestRegionLocalRepeatedSiteRemainsSummary(t *testing.T) {
	in := regionFixture(t, `func F(again,next bool)*uint32{var old *uint32;for again {p:=new(uint32);*p=7;if old==nil {old=p};again=next;next=false};return old}`)
	checked, proposal := proveRegionFixture(t, in)
	for _, args := range [][2]bool{{true, false}, {true, true}} {
		assertRegionCovers(t, checked, executeRegionConcrete(t, in, args[0], args[1]))
	}
	for _, states := range proposal.entries {
		for _, state := range states {
			for object, value := range state.memory {
				if object.kind == regionAllocation && value.kind != regionUnknown {
					t.Fatal("repeated site reset an earlier escaped object's possible contents")
				}
			}
		}
	}
	// The finite prefix channel does not turn known loop entry into a progress
	// argument or erase the possible repetition of its allocating site.
	source := relationFixture(t, `func Stop(*uint32,uint32){};func F(){for again:=true;again;again=false{p:=new(uint32);*p=7;Stop(p,*p)}}`, 64)
	root := source.prog.Roots["F"]
	if _, err := checkSourceOperandPrefix(t.Context(), source, root, localEffectCalls(t, root, "Stop")[0], defaultRegistrationLimits()); err == nil {
		t.Fatal("finite prefix supplied an unproved loop allocation cardinality")
	}
}

func TestRegionLocalRefusesForeignOwnersAndCumulativeWork(t *testing.T) {
	source, prefix := localEffectPrefix(t, `func Stop(*uint32,uint32){};func F(){var x uint32;x=7;Stop(&x,x);x=9;Stop(&x,x)}`)
	root := source.prog.Roots["F"]
	call := localEffectCalls(t, root, "Stop")[1]
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := checkSourceOperandContinuation(ctx, prefix, call, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("continuation ignored cancellation: %v", err)
	}
	if _, err := checkSourceOperandPrefix(ctx, source, root, prefix.call, defaultRegistrationLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("prefix ignored cancellation: %v", err)
	}
	if _, live, err := prefix.liveAllocation(prefix.operands[0].location.object, ctx.Err); live || !errors.Is(err, context.Canceled) {
		t.Fatalf("allocation retention ignored the consumer's cancellation: live=%v error=%v", live, err)
	}
	other := relationFixture(t, `func Stop(*uint32,uint32){};func F(){var x uint32;Stop(&x,x)}`, 64)
	foreign := localEffectCalls(t, other.prog.Roots["F"], "Stop")[0]
	if _, err := checkSourceOperandContinuation(t.Context(), prefix, foreign, nil); err == nil {
		t.Fatal("foreign endpoint borrowed predecessor")
	}
	if _, err := checkSourceOperandPrefix(t.Context(), other, root, prefix.call, defaultRegistrationLimits()); err == nil {
		t.Fatal("foreign source selection borrowed typed root")
	}
	// Set a work allowance that permits the first check with little room left.
	// It is a limit, not a forged initial state or a replacement outcome.
	limits := defaultRegistrationLimits()
	limits.region.work = prefix.region.packet.usage.work + 1
	bounded, err := checkSourceOperandPrefix(t.Context(), source, root, prefix.call, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkSourceOperandContinuation(t.Context(), bounded, call, nil); err == nil || !strings.Contains(err.Error(), "work budget") {
		t.Fatalf("continuation restarted cumulative allowance: %v", err)
	}
}

func TestRegionLocalCallProofCannotSubstituteArguments(t *testing.T) {
	in := regionFixture(t, `func set(p *uint32,n uint32){*p=n};func F()uint32{var x uint32;set(&x,7);return x}`)
	proposal, err := proposeRegion(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits()); err != nil {
		t.Fatal(err)
	}
	proposal.calls[0].arguments[1] = regionValue{typ: types.Typ[types.Uint32], kind: regionConstant, scalar: constant.MakeUint64(9)}
	if _, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits()); err == nil {
		t.Fatal("callee proof accepted substituted actual argument")
	}
}

func TestRegionLocalCallProofCannotSubstituteEvidenceArm(t *testing.T) {
	in := regionFixture(t, `func value()uint32{return 7};func F()uint32{return value()}`)
	proposal, err := proposeRegion(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits()); err != nil {
		t.Fatal(err)
	}
	proposal.calls[0].reference = &assemblyReference{}
	if _, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits()); err == nil {
		t.Fatal("checked source body conferred an unchecked assembly evidence arm")
	}
}

// Extend the region concrete-oracle grammar's existing allocation, aggregate
// replacement, load, known branch and phi operations into the finite source
// prefix channel. Concrete cells preserve aliases across aggregate replacement;
// the oracle does not use abstract region transfer or effect helpers.
func TestRegionLocalFiniteSourceOracle(t *testing.T) {
	for index := range 4 {
		for _, replacement := range []uint64{0, 7, 255} {
			for _, take := range []bool{false, true} {
				compare := replacement
				if !take {
					compare ^= 1
				}
				text := fmt.Sprintf(`func Stop(byte){};func F(){var a [4]byte;p:=&a[%d];*p=3;a=[4]byte{%d,%d,%d,%d};var n byte;if *p==%d {n=*p}else{n=17};Stop(n)}`, index, replacement, replacement, replacement, replacement, compare)
				source, prefix := localEffectPrefix(t, text)
				in := prefix.region.packet.input
				in.use.operand = prefix.call.Call.Args[0]
				concrete := executeRegionConcrete(t, in).(int64)
				localEffectInteger(t, prefix.operands[0], uint64(concrete))
				if prefix.region.root.function != source.prog.Roots["F"] || len(prefix.region.packet.trace.excluded) != 1 {
					t.Fatal("finite source oracle omitted actual source/path binding")
				}
			}
		}
	}
}
