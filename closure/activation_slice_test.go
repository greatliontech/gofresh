package closure

import (
	"go/constant"
	"go/types"
	"slices"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

const finiteSliceRecoverySource = `func count()int{return 2};func F()(r int){defer func(){if recover()!=nil{r=9}}();s:=make([]int,count());return len(s)}`

func TestRegionActivationSliceOutcomeProjection(t *testing.T) {
	packet, proposal := proveActivation(t, finiteSliceRecoverySource)
	values := map[int64]int{}
	stopped := 0
	for _, out := range packet.outcomes {
		switch out.kind {
		case activationNormal:
			n, exact := regionInt(out.value)
			if !exact {
				t.Fatal("recovered construction outcome became unknown")
			}
			values[n]++
		case activationStopped:
			stopped++
		default:
			t.Fatal("directly recovered construction panic escaped")
		}
	}
	// The modeled payload is unknown, so direct recover may compare nil or
	// nonnil. Both exact recovered results remain beside actual success.
	if len(values) != 3 || values[2] != 1 || values[9] != 1 || values[0] != 1 || stopped != 1 {
		t.Fatalf("slice construction omitted outcomes: values=%v stopped=%d", values, stopped)
	}
	want := regionValue{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(2)}
	if projection, err := packet.projectNormal(t.Context(), want); err == nil || projection != nil {
		t.Fatal("success-only slice length projected past recovered failure")
	}
	for cut := uint64(1); cut < packet.snapshot.transitions; cut++ {
		_, after := activationPartition(t, packet.input, cut)
		equalActivations(t, packet, after)
	}
	for _, rule := range []regionActivationRule{activationBeginPanic, activationNoncompletion} {
		found := false
		for i, event := range proposal.events {
			if event.rule != rule {
				continue
			}
			found = true
			bad := *proposal
			bad.events = append(slices.Clone(proposal.events[:i]), proposal.events[i+1:]...)
			if got, err := checkRegionActivation(t.Context(), packet.input, &bad, defaultRegionLimits()); err == nil || got != nil {
				t.Fatal("slice construction accepted an omitted abrupt inference")
			}
			break
		}
		if !found {
			t.Fatal("missing actual slice abrupt inference")
		}
	}
	prior, _ := activationPartition(t, packet.input, 1)
	suffix, err := proposeRegionActivationContinuation(t.Context(), prior, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i, event := range suffix.events {
		if event.rule == activationBeginPanic {
			bad := *suffix
			bad.events = append(slices.Clone(suffix.events[:i]), suffix.events[i+1:]...)
			if got, err := checkRegionActivationContinuation(t.Context(), prior, 0, &bad); err == nil || got != nil {
				t.Fatal("partition omitted slice construction panic")
			}
			break
		}
	}
}

func TestRegionActivationSliceFailureFrame(t *testing.T) {
	packet, _ := proveActivation(t, `func size(p *int)int{*p=8;return 2};func F()int{x:=3;p:=&x;defer func(){x+=20}();s:=make([]int,size(p));s[0]=17;return *p+len(s)}`)
	var cell *ssa.Alloc
	var construction *ssa.MakeSlice
	for _, block := range packet.input.root.Blocks {
		for _, ins := range block.Instrs {
			if a, ok := ins.(*ssa.Alloc); ok && types.Identical(a.Type().Underlying().(*types.Pointer).Elem(), types.Typ[types.Int]) {
				cell = a
			}
			if s, ok := ins.(*ssa.MakeSlice); ok {
				construction = s
			}
		}
	}
	if cell == nil || construction == nil {
		t.Fatal("fixture lacks actual alias or slice construction")
	}
	checkFrame := func(s regionState, want int64, pending int) {
		t.Helper()
		pointer := s.values[cell]
		if pointer.kind != regionPointer {
			t.Fatal("pre-existing alias lost")
		}
		n, exact := regionInt(s.memory[pointer.location.object])
		if !exact || n != want || !s.pending.known || len(s.pending.captures) != pending {
			t.Fatalf("operand/defer effects lost: value=%d exact=%v pending=%d", n, exact, len(s.pending.captures))
		}
		if _, exists := s.values[construction]; exists {
			t.Fatal("failed construction produced a slice result")
		}
		for object := range s.memory {
			if object.kind == regionSliceAllocation {
				t.Fatal("failed construction produced success-only backing")
			}
		}
	}
	counts := [3]int{}
	for _, out := range packet.outcomes {
		counts[out.kind]++
		switch out.kind {
		case activationNormal:
			localEffectInteger(t, out.value, 10)
		case activationPanicking:
			checkFrame(out.state.store, 28, 0)
		}
	}
	if counts != [3]int{1, 1, 1} {
		t.Fatalf("incomplete construction coverage: %v", counts)
	}
	seen := map[activationPhase]bool{}
	for cut := uint64(1); cut < packet.snapshot.transitions; cut++ {
		prior, after := activationPartition(t, packet.input, cut)
		equalActivations(t, packet, after)
		for _, job := range prior.snapshot.work {
			phase := job.top().control.phase
			if phase == activationPanicAlternative || phase == activationStopAlternative {
				seen[phase] = true
				checkFrame(job.state(), 8, 1)
			}
		}
	}
	if !seen[activationPanicAlternative] || !seen[activationStopAlternative] {
		t.Fatal("missing pre-construction abrupt frontier")
	}
}

func TestRegionSliceSharedTransferRefuses(t *testing.T) {
	source := relationFixture(t, `func F(n int)[]int{return make([]int,n)}`, 64)
	in := activationInput(source, "F")
	in.initial.values = map[ssa.Value]regionValue{in.root.Params[0]: {typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(2)}}
	var construction *ssa.MakeSlice
	for _, block := range in.root.Blocks {
		for i, ins := range block.Instrs {
			if s, ok := ins.(*ssa.MakeSlice); ok {
				construction = s
			}
			if ret, ok := ins.(*ssa.Return); ok {
				in.limit = &regionUse{at: regionPoint{block, i}, operand: ret.Results[0]}
			}
		}
	}
	for _, normal := range []bool{false, true} {
		legacy := in.regionInput()
		legacy.normalReturns = normal
		k, err := newRegionKernel(t.Context(), legacy, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		s, err := k.clone(k.input.initial)
		if err != nil {
			t.Fatal(err)
		}
		if err := k.transfer(&s, construction); err == nil {
			t.Fatal("shared strict/normal transfer supplied slice construction authority")
		}
	}
}
