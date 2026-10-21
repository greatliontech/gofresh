package closure

import (
	"fmt"
	"go/constant"
	"go/types"
	"strconv"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// The registration generator also crosses a cyclic constructor's forward cut.
// The trailing loop remains in the source graph, but neither interpreter runs
// it before observing the actual Stop operand.
func checkScopedRegistrationOracle(t testing.TB, a, b string, swap bool) {
	t.Helper()
	write := ""
	if swap {
		write = `x[0]=Row[func()]{x[0].Name,b,d};x[1].F=a;`
	}
	text := fmt.Sprintf(`type Row[T any] struct{Name string;F T;C *int};var again bool;func a(){};func b(){};func before(){};func Stop([2]Row[func()]){};func F()[2]Row[func()]{for{before();c,d:=new(int),new(int);*c=%d;*d=%d;x:=[2]Row[func()]{{%s,a,c},{%s,b,d}};p:=&x[0].F;%sx[0].F=*p;Stop(x);if !again{return x}}}`, len(a), len(b), strconv.Quote(a), strconv.Quote(b), write)
	in := regionAtCall(t, regionFixture(t, text), "Stop", 0)
	found := false
	for i, instruction := range in.use.at.block.Instrs {
		if _, ok := instruction.(*ssa.Alloc); ok {
			in.entry = regionPoint{in.use.at.block, i}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("scoped registration constructor missing")
	}
	for _, finite := range []bool{false, true} {
		checked, _, _, err := checkLinearLoop(t, in, finite)
		if err != nil {
			t.Fatal(err)
		}
		for _, out := range checked.observations {
			if !regionTestPrecise(out.value, out.state, 0) {
				t.Fatal("scoped registration lost complete row facts")
			}
		}
		assertRegionCovers(t, checked, executeRegionConcrete(t, in))
	}
}

func linearLoopFixture(t testing.TB, text string) regionInput {
	t.Helper()
	in := regionAtCall(t, regionFixture(t, text), "Stop", 0)
	for i, instruction := range in.use.at.block.Instrs {
		if _, ok := instruction.(*ssa.Alloc); ok {
			in.entry = regionPoint{in.use.at.block, i}
			return in
		}
	}
	t.Fatal("constructor allocation missing from consuming block")
	return regionInput{}
}

// The finite arm uses the same actual cut as the invariant arm, rather than the
// whole-function-return interface of occurrenceFixture.
func checkLinearLoop(t testing.TB, in regionInput, finite bool) (*checkedRegion, *regionProposal, *regionKernel, error) {
	t.Helper()
	owner := &regionOccurrenceOwner{}
	newKernel := func(input regionInput) (*regionKernel, error) {
		k, err := newRegionKernel(t.Context(), input, defaultRegionLimits())
		if err == nil && finite {
			k.trace = &regionEffectTrace{owner: owner, seen: map[regionEffectOccurrence]bool{}}
		}
		return k, err
	}
	k, err := newKernel(in)
	if err != nil {
		return nil, nil, nil, err
	}
	p, err := proposeRegionKernel(k)
	if err != nil {
		return nil, nil, k, err
	}
	owned, p, err := regionCapture(in, p, defaultRegionLimits())
	if err != nil {
		return nil, nil, k, err
	}
	k, err = newKernel(owned)
	if err != nil {
		return nil, p, nil, err
	}
	checked, err := checkRegionKernel(k, p)
	return checked, p, k, err
}

func TestRegionStraightLineLoopConstruction(t *testing.T) {
	in := linearLoopFixture(t, `type Box struct{X,Y int;C *[3]bool};func before(){};func Stop(*Box){};func F(again bool)*Box{for{before();p:=new(Box);p.X=7;p.C=new([3]bool);Stop(p);if !again{return p}}}`)
	if in.entry.index == 0 {
		t.Fatal("fixture does not exercise a mid-block entry")
	}
	for _, finite := range []bool{false, true} {
		checked, _, k, err := checkLinearLoop(t, in, finite)
		if err != nil {
			t.Fatal(err)
		}
		out := checked.observations[0]
		if !k.singleton(out.value.location.object) {
			t.Fatal("one scoped constructor lost singleton identity")
		}
		box := out.state.memory[out.value.location.object]
		if box.kind != regionAggregate || len(box.elements) != 3 {
			t.Fatal("constructor lost its initialized fields")
		}
		localEffectInteger(t, box.elements[0], 7)
		localEffectInteger(t, box.elements[1], 0)
		array := box.elements[2]
		if array.kind != regionPointer || !k.singleton(array.location.object) || len(out.state.memory[array.location.object].elements) != 3 {
			t.Fatal("constructed array lost extent or instance identity")
		}
		for _, again := range []bool{false, true} {
			assertRegionCovers(t, checked, executeRegionConcrete(t, in, again))
		}
		if finite && len(checked.trace.allocations) != 2 {
			t.Fatal("finite construction omitted or repeated an allocation")
		}
		// A wider judgment sharing this function cache still encounters the real
		// loop. The narrower scope must not rewrite its function's CFG facts.
		if _, err := newRegionContextKernel(in, k.session, regionInvocation{}, true); err == nil || !strings.Contains(err.Error(), "mid-block entry") {
			t.Fatalf("wider scope borrowed linear cardinality: %v", err)
		}
	}
}

func TestRegionStraightLineScopeBoundaries(t *testing.T) {
	in := linearLoopFixture(t, `func before(){};func Stop(*int){};func F(again bool)*int{for{before();p:=new(int);*p=7;Stop(p);if !again{return p}}}`)
	for _, change := range []func(*regionInput){
		func(in *regionInput) {
			call := in.entry.block.Instrs[0].(*ssa.Call)
			in.use = regionUse{at: regionPoint{in.entry.block, 0}, operand: call.Call.Value}
		},
		func(in *regionInput) {
			for _, block := range in.root.Blocks {
				for i, instruction := range block.Instrs {
					if ret, ok := instruction.(*ssa.Return); ok {
						in.use = regionUse{at: regionPoint{block, i}, operand: ret.Results[0]}
						return
					}
				}
			}
		},
		func(in *regionInput) { in.normalReturns = true },
	} {
		bad := in
		change(&bad)
		if _, err := newRegionKernel(t.Context(), bad, defaultRegionLimits()); err == nil || !strings.Contains(err.Error(), "mid-block entry") {
			t.Fatalf("wider/backward scope acquired a linear claim: %v", err)
		}
	}
	// Instruction ordinals from different blocks are not an ordering relation.
	// This later-numbered cut keeps the block-identity guard independently needed.
	cross := regionAtCall(t, regionFixture(t, `func before(){};func Stop(*int){};func F(done bool)*int{for{before();p:=new(int);*p=7;if done{before();before();before();Stop(p);return p}}}`), "Stop", 0)
	for _, block := range cross.root.Blocks {
		for i, instruction := range block.Instrs {
			if _, ok := instruction.(*ssa.Alloc); ok {
				cross.entry = regionPoint{block, i}
			}
		}
	}
	if cross.entry.block == cross.use.at.block || cross.entry.index == 0 || cross.entry.index > cross.use.at.index {
		t.Fatal("cross-block control does not isolate block identity")
	}
	if _, err := newRegionKernel(t.Context(), cross, defaultRegionLimits()); err == nil || !strings.Contains(err.Error(), "mid-block entry") {
		t.Fatalf("unrelated instruction ordinals erased a backedge: %v", err)
	}
	zero := in
	zero.entry = zero.use.at
	checked, _, _, err := checkLinearLoop(t, zero, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(checked.trace.allocations) != 0 || len(checked.observations[0].state.memory) != 0 || checked.observations[0].value.kind != regionUnknown {
		t.Fatal("empty scope invented its omitted constructor")
	}
}

func TestRegionStraightLineRetainsEarlierAliases(t *testing.T) {
	in := linearLoopFixture(t, `var old *int;func before(){};func Stop(*int){};func F(again bool)*int{for{before();p:=new(int);*p=2;Stop(old);if !again{return p}}}`)
	a := regionInstruction(in.entry).(*ssa.Alloc)
	object := regionObject{kind: regionAllocation, site: a, context: in.root}
	old := in.root.Pkg.Members["old"].(*ssa.Global)
	in.initial = regionState{memory: map[regionObject]regionValue{
		object:                          {typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(1)},
		{kind: regionGlobal, site: old}: {typ: a.Type(), kind: regionPointer, location: regionLocation{object: object}},
	}}
	in.premises = append(in.premises, "old designates a previous iteration's allocation at the same site")
	checked, _, _, err := checkLinearLoop(t, in, false)
	if err != nil {
		t.Fatal(err)
	}
	out := checked.observations[0]
	if value := readRegionLocation(out.state, out.value.location, types.Typ[types.Int]); value.kind != regionUnknown {
		t.Fatal("linear construction reset an earlier represented instance")
	}
	if checked, _, _, err := checkLinearLoop(t, in, true); checked != nil || err == nil || !strings.Contains(err.Error(), "fresh singleton") {
		t.Fatalf("finite construction borrowed earlier-instance ownership: %v", err)
	}
}

func TestRegionStraightLineChildScopes(t *testing.T) {
	for _, body := range []string{`func factory(again bool)*int{return new(int)}`, `func factory(again bool)*int{for{p:=new(int);if !again{return p}}}`} {
		in := regionAtCall(t, regionFixture(t, body+`;func before(){};func Stop(*int){};func F(again bool)*int{for{before();p:=factory(again);Stop(p);if !again{return p}}}`), "Stop", 0)
		for i, instruction := range in.use.at.block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok && call.Call.StaticCallee().Name() == "factory" {
				in.entry = regionPoint{in.use.at.block, i}
			}
		}
		checked, _, _, err := checkLinearLoop(t, in, true)
		if strings.Contains(body, "for{") {
			if err == nil || checked != nil || !strings.Contains(err.Error(), "fresh singleton") {
				t.Fatalf("child recurrence lost at caller cut: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			out := checked.observations[0]
			localEffectInteger(t, out.state.memory[out.value.location.object], 0)
		}
	}
}

func TestRegionStraightLineCopiedStateIsNotContinuation(t *testing.T) {
	in := linearLoopFixture(t, `type Box struct{X int};func before(){};func Stop(*Box){};func After(*Box){};func F(again bool)*Box{for{before();p:=new(Box);p.X=7;Stop(p);p.X=9;After(p);if !again{return p}}}`)
	checked, _, _, err := checkLinearLoop(t, in, true)
	if err != nil {
		t.Fatal(err)
	}
	out := checked.observations[0]
	next := regionAtCall(t, in, "After", 0)
	next.entry = in.use.at
	next.initial = out.state
	k, err := newRegionKernel(t.Context(), next, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if k.singleton(out.value.location.object) {
		t.Fatal("copied state acquired an opaque predecessor's singleton authority")
	}
	continued, _, _, err := checkLinearLoop(t, next, false)
	if err != nil {
		t.Fatal(err)
	}
	if value := continued.observations[0].state.memory[out.value.location.object]; value.kind != regionUnknown {
		t.Fatal("copied earlier-instance state gained a strong field update")
	}
}

func TestRegionStraightLineProposalCannotCrossCut(t *testing.T) {
	in := linearLoopFixture(t, `func before(){};func Stop(*int){};func F(again bool)*int{for{before();p:=new(int);*p=7;Stop(p);if !again{return p}}}`)
	for _, finite := range []bool{false, true} {
		checked, proposal, _, err := checkLinearLoop(t, in, finite)
		if err != nil {
			t.Fatal(err)
		}
		owned, proposal, err := regionCapture(in, proposal, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		k, err := newRegionKernel(t.Context(), owned, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		if finite {
			k.trace = &regionEffectTrace{owner: checked.trace.owner, seen: map[regionEffectOccurrence]bool{}}
			path := proposal.occurrences
			path.nodes = append(path.nodes, path.nodes[len(path.nodes)-1])
		} else {
			proposal.entries[in.root.Blocks[0]] = []regionState{{}}
		}
		if result, err := checkRegionKernel(k, proposal); result != nil || err == nil || !strings.Contains(err.Error(), "unused") {
			t.Fatalf("proposal extended execution beyond the checked cut: %v", err)
		}
	}
}
