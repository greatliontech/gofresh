package closure

import (
	"context"
	"errors"
	"go/ast"
	"go/constant"
	"go/types"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func activationWhole(t testing.TB, in regionActivationInput) *checkedRegionActivation {
	t.Helper()
	p, err := proposeRegionActivation(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	r, err := checkRegionActivation(t.Context(), in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func activationPartition(t testing.TB, in regionActivationInput, cut uint64) (*checkedRegionActivation, *checkedRegionActivation) {
	t.Helper()
	p, err := proposeRegionActivationSegment(t.Context(), in, cut, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	prior, err := checkRegionActivationSegment(t.Context(), in, cut, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := proposeRegionActivationContinuation(t.Context(), prior, 0)
	if err != nil {
		t.Fatal(err)
	}
	after, err := checkRegionActivationContinuation(t.Context(), prior, 0, suffix)
	if err != nil {
		t.Fatal(err)
	}
	return prior, after
}

func equalActivations(t testing.TB, whole, partitioned *checkedRegionActivation) {
	t.Helper()
	for _, pair := range []struct {
		name string
		a, b any
	}{
		{"outcomes", whole.outcomes, partitioned.outcomes},
		{"events", whole.events, partitioned.events},
		{"calls", whole.calls, partitioned.calls},
		{"frontiers", whole.snapshot.frontiers, partitioned.snapshot.frontiers},
		{"contexts", whole.snapshot.contexts, partitioned.snapshot.contexts},
		{"preexisting", whole.snapshot.preexisting, partitioned.snapshot.preexisting},
	} {
		if !reflect.DeepEqual(pair.a, pair.b) {
			t.Fatalf("partition changed %s", pair.name)
		}
	}
	if partitioned.snapshot.transitions != whole.snapshot.transitions || len(partitioned.snapshot.work) != 0 {
		t.Fatal("partition omitted transitions or pending work")
	}
}

// Every machine boundary is exercised, including pre-delivery and between
// consumption of recover and the remainder of the recovering invocation. The
// literal Go oracle separately checks the shared complete relation's meaning.
func TestRegionActivationPartitionEquivalence(t *testing.T) {
	cases := slices.Clone(regionActivationCases)
	cases = append(cases, finiteActivationCases...)
	cases = append(cases, struct{ name, source string }{"queued-channel-alternatives", `var B bool;func child(p *int)int{*p=8;c:=make(chan int,1);return cap(c)};func F()(r int){defer func(){if recover()!=nil{r+=10}}();if B{return 3};x:=1;r=child(&x);return r+x}`})
	phases := map[activationPhase]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := relationFixture(t, tc.source, 64)
			in := activationInput(source, "F")
			whole := activationWhole(t, in)
			for cut := uint64(1); cut < whole.snapshot.transitions; cut++ {
				prior, after := activationPartition(t, in, cut)
				for _, job := range prior.snapshot.work {
					phases[job.top().control.phase] = true
				}
				equalActivations(t, whole, after)
				if _, err := prior.projectNormal(t.Context(), regionUnknownValue(in.root.Signature.Results().At(0).Type())); err == nil {
					t.Fatalf("cut %d projected an unfinished relation", cut)
				}
			}
		})
	}
	for _, phase := range []activationPhase{activationExecute, activationUnwind, activationDeliver, activationPanicAlternative, activationStopAlternative} {
		if !phases[phase] {
			t.Fatalf("missing pause phase %v", phase)
		}
	}
}

func TestRegionActivationContinuationOwnership(t *testing.T) {
	source := relationFixture(t, `func child(p *int)int{*p=8;c:=make(chan int,1);return cap(c)};func F()(r int){defer func(){if recover()!=nil{r+=10}}();x:=1;r=child(&x);return r+x}`, 64)
	in := activationInput(source, "F")
	whole := activationWhole(t, in)
	prior, _ := activationPartition(t, in, whole.snapshot.transitions/2)
	p, err := proposeRegionActivationContinuation(t.Context(), prior, 0)
	if err != nil {
		t.Fatal(err)
	}
	beforeEvents, beforeCalls := slices.Clone(prior.events), slices.Clone(prior.calls)
	beforeUsage := prior.usage
	beforeContexts := maps.Clone(prior.snapshot.contexts)
	jobs := make([]activationJob, len(prior.snapshot.work))
	meter := &regionMeter{limits: defaultRegionLimits()}
	for i, j := range prior.snapshot.work {
		jobs[i], err = cloneActivationJob(j, meter)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []string{"predecessor", "offset", "stop", "omit", "duplicate", "input", "owner", "scope"} {
		t.Run(change, func(t *testing.T) {
			_, bad, err := captureRegionActivation(in, p, defaultRegionLimits())
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "predecessor":
				bad.predecessor = whole
			case "offset":
				bad.offset++
			case "stop":
				bad.stop++
			case "omit":
				bad.events = bad.events[:len(bad.events)-1]
			case "duplicate":
				bad.events = append(bad.events, bad.events[0])
			case "input":
				bad.input.premises = []string{"replacement premise"}
			case "owner":
				bad.input.owner = nil
			case "scope":
				bad.input.entry.index++
			}
			if got, err := checkRegionActivationContinuation(t.Context(), prior, 0, bad); err == nil || got != nil {
				t.Fatal("forged continuation accepted")
			}
		})
	}
	copyPacket := *prior
	if got, err := checkRegionActivationContinuation(t.Context(), &copyPacket, 0, p); err == nil || got != nil {
		t.Fatal("copied packet acquired predecessor authority")
	}
	for _, change := range []string{"rules", "limits"} {
		copyPacket := *prior
		copyPacket.self = &copyPacket
		if change == "rules" {
			copyPacket.rules = "old"
		} else {
			copyPacket.usage.limits.work++
		}
		if got, err := checkRegionActivationContinuation(t.Context(), &copyPacket, 0, p); err == nil || got != nil {
			t.Fatal("altered predecessor accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := checkRegionActivationContinuation(ctx, prior, 0, p); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resume: %v", err)
	}
	counted := &regionCallCountingContext{Context: t.Context()}
	if _, err := checkRegionActivationContinuation(counted, prior, 0, p); err != nil {
		t.Fatal(err)
	}
	interrupted := &regionCallCountingContext{Context: t.Context(), stop: counted.checks / 2}
	if got, err := checkRegionActivationContinuation(interrupted, prior, 0, p); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted resume: %v", err)
	}
	_, owned, err := captureRegionActivation(in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	mutating := &regionMutatingContext{Context: t.Context(), mutate: func() { owned.events[0].rule = activationReturn; owned.input.premises[0] = "changed"; owned.offset++ }}
	first, err := checkRegionActivationContinuation(mutating, prior, 0, owned)
	if err != nil {
		t.Fatal(err)
	}
	second, err := checkRegionActivationContinuation(t.Context(), prior, 0, p)
	if err != nil {
		t.Fatal(err)
	}
	equalActivations(t, whole, first)
	equalActivations(t, whole, second)
	if !reflect.DeepEqual(prior.events, beforeEvents) || !reflect.DeepEqual(prior.calls, beforeCalls) || prior.usage.work != beforeUsage.work || !reflect.DeepEqual(prior.snapshot.contexts, beforeContexts) || !reflect.DeepEqual(prior.snapshot.work, jobs) {
		t.Fatal("continuation changed predecessor")
	}
}

func TestRegionActivationContinuationCumulativeBudget(t *testing.T) {
	source := relationFixture(t, `func F()int{x:=new(int);*x=3;*x+=4;*x+=5;return *x}`, 64)
	in := activationInput(source, "F")
	whole := activationWhole(t, in)
	// Establish the real chain cost, then choose a bound that admits each suffix
	// alone but not the same suffix after the retained prefix's expenditure.
	cut := whole.snapshot.transitions / 2
	prior, after := activationPartition(t, in, cut)
	if after.usage.work <= prior.usage.work || after.usage.work <= whole.usage.work {
		t.Fatal("continuation copy/check work was not charged")
	}
	limits := defaultRegionLimits()
	limits.work = after.usage.work - 1
	p, err := proposeRegionActivationSegment(t.Context(), in, cut, limits)
	if err != nil {
		t.Fatal(err)
	}
	limited, err := checkRegionActivationSegment(t.Context(), in, cut, p, limits)
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := proposeRegionActivationContinuation(t.Context(), prior, 0)
	if err != nil {
		t.Fatal(err)
	}
	suffix.predecessor = limited
	if got, err := checkRegionActivationContinuation(t.Context(), limited, 0, suffix); err == nil || got != nil {
		t.Fatal("resume renewed the predecessor work allowance")
	}
	// Repeated explicit pauses must also consume cumulative storage/work; none
	// can turn exhaustion into an accepted frontier by treating it as a stop.
	current := limited
	for stop := cut + 1; stop < whole.snapshot.transitions; stop++ {
		p, err := proposeRegionActivationContinuation(t.Context(), current, stop)
		if err != nil {
			return
		}
		next, err := checkRegionActivationContinuation(t.Context(), current, stop, p)
		if err != nil {
			return
		}
		current = next
	}
	t.Fatal("partition chain unexpectedly escaped the cumulative allowance")
}

func activationScopedFixture(t testing.TB, text string) regionActivationInput {
	t.Helper()
	source := relationFixture(t, text, 64)
	in := activationInput(source, "F")
	for _, b := range in.root.Blocks {
		for i, ins := range b.Instrs {
			if call, ok := ins.(*ssa.Call); ok && call.Call.StaticCallee() != nil {
				switch call.Call.StaticCallee().Name() {
				case "child":
					in.entry = regionPoint{b, i}
				case "Stop":
					in.limit = &regionUse{at: regionPoint{b, i}, operand: call.Call.Value}
				}
			}
		}
	}
	in.pendingAntecedent = true
	in.initial.pending.known = true
	in.premises = append(in.premises, "conditional mid-body entry, empty pending stack; omitted prefix and incoming values remain unproved")
	if in.limit == nil || in.entry == (regionPoint{}) {
		t.Fatal("missing actual segment")
	}
	return in
}

func TestRegionActivationScopedFrontier(t *testing.T) {
	in := activationScopedFixture(t, `func child()*int{p:=new(int);*p=7;return p};func before(){};func Stop(*int){};func F(again bool){for{before();p:=child();*p=9;a:=make(chan bool,1);b:=make(chan bool);_=a;_=b;Stop(p);if !again{return}}}`)
	whole := activationWhole(t, in)
	if len(whole.snapshot.frontiers) != 1 || len(whole.outcomes) != 4 {
		t.Fatal("scope omitted construction alternatives")
	}
	counts := [3]int{}
	for _, out := range whole.outcomes {
		counts[out.kind]++
	}
	if counts != [3]int{0, 2, 2} {
		t.Fatal(counts)
	}
	j := whole.snapshot.frontiers[0]
	k := j.top().context.kernel(&regionCallSession{meter: &regionMeter{ctx: t.Context(), limits: defaultRegionLimits()}, contexts: whole.snapshot.contexts, preexisting: whole.snapshot.preexisting, finite: true, instances: whole.snapshot.instances, occurrences: whole.snapshot.occurrences})
	call := regionInstruction(in.limit.at).(*ssa.Call)
	p := k.value(j.state(), call.Call.Args[0])
	localEffectInteger(t, j.heap[p.location.object], 9)
	if !k.singleton(p.location.object) {
		t.Fatal("child allocation lost singleton continuity")
	}
	if !whole.snapshot.functions[in.root].cycle[in.entry.block] || !whole.snapshot.contexts[regionInvocation{}].cycle[in.entry.block] {
		t.Fatal("scope changed whole-function recurrence")
	}
	for cut := uint64(1); cut < whole.snapshot.transitions; cut++ {
		_, after := activationPartition(t, in, cut)
		equalActivations(t, whole, after)
	}
	if _, err := whole.projectNormal(t.Context(), regionUnknownValue(types.Typ[types.Int])); err == nil {
		t.Fatal("frontier became terminal")
	}
	if _, err := proposeRegionActivationContinuation(t.Context(), whole, 0); err == nil {
		t.Fatal("hard frontier enlarged its scope")
	}
	for _, kind := range []string{"backward", "cross-block", "whole"} {
		bad := in
		limit := *in.limit
		bad.limit = &limit
		switch kind {
		case "backward":
			bad.limit.at.index = 0
			bad.limit.operand = regionInstruction(bad.limit.at).(*ssa.Call).Call.Value
		case "cross-block":
			for _, b := range in.root.Blocks {
				if b != in.entry.block {
					for i, ins := range b.Instrs {
						if ret, ok := ins.(*ssa.Return); ok {
							bad.limit = &regionUse{at: regionPoint{b, i}}
							_ = ret
						}
					}
				}
			}
		case "whole":
			bad.limit = nil
		}
		if p, err := proposeRegionActivation(t.Context(), bad, defaultRegionLimits()); err == nil || p != nil {
			t.Fatalf("%s widened scoped cardinality", kind)
		}
	}
	cyclic := activationScopedFixture(t, `func child()*int{for{p:=new(int);if p!=nil{return p}}};func before(){};func Stop(*int){};func F(){for{before();p:=child();Stop(p)}}`)
	if p := activationWhole(t, cyclic); len(p.snapshot.frontiers) != 1 || !p.snapshot.functions[cyclic.root.Pkg.Func("child")].cycle[cyclic.root.Pkg.Func("child").Blocks[1]] {
		t.Fatal("finite child did not retain its actual cyclic graph")
	}
}

func TestRegionActivationRetainsEarlierAliases(t *testing.T) {
	in := activationScopedFixture(t, `var old *int;func child(){};func before(){};func Stop(*int){};func F(){for{before();child();p:=new(int);*p=7;Stop(old)}}`)
	var allocation *ssa.Alloc
	for _, ins := range in.entry.block.Instrs {
		if a, ok := ins.(*ssa.Alloc); ok {
			allocation = a
		}
	}
	if allocation == nil {
		t.Fatal("missing allocation")
	}
	object := regionObject{kind: regionAllocation, site: allocation, context: in.root}
	old := in.root.Pkg.Members["old"].(*ssa.Global)
	in.initial.memory = map[regionObject]regionValue{object: {typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(1)}, {kind: regionGlobal, site: old}: {typ: allocation.Type(), kind: regionPointer, location: regionLocation{object: object}}}
	whole := activationWhole(t, in)
	localEffectInteger(t, whole.snapshot.frontiers[0].heap[object], 1)
	_, after := activationPartition(t, in, whole.snapshot.transitions/2)
	equalActivations(t, whole, after)
}

func TestSourceActivationContinuationBindings(t *testing.T) {
	source := relationFixture(t, `func child(p *int){*p=3;panic(1)};func F()(r int){defer func(){if recover()!=nil{r+=4}}();child(&r);r=99;return}`, 64)
	in := activationInput(source, "F")
	whole := activationWhole(t, in)
	for cut := uint64(1); cut < whole.snapshot.transitions; cut++ {
		p, err := proposeRegionActivationSegment(t.Context(), in, cut, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		prior, err := checkSourceActivationSegment(t.Context(), source, in, cut, p, defaultRegistrationLimits().source, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		suffix, err := proposeRegionActivationContinuation(t.Context(), prior.packet, 0)
		if err != nil {
			t.Fatal(err)
		}
		after, err := checkSourceActivationContinuation(t.Context(), prior, 0, suffix)
		if err != nil {
			t.Fatal(err)
		}
		equalActivations(t, whole, after.packet)
		if len(after.calls) != 2 || len(after.calls) != len(after.packet.calls) {
			t.Fatal("old/new body binding omitted")
		}
		for _, c := range after.calls {
			if c.bound.function != c.call.target || c.bound.identity.source == ([32]byte{}) || c.bound.identity.body == ([32]byte{}) {
				t.Fatal("missing selected dependency")
			}
		}
		if after.binder.work <= prior.binder.work {
			t.Fatal("source binding renewed work allowance")
		}
	}
}

func TestSourceBinderLexicalContinuationIsolation(t *testing.T) {
	source := relationFixture(t, `func A()func(){return func(){}};func B()func(){return func(){}};func F(){}`, 64)
	pkg := source.prog.Roots["F"].Pkg
	a, b := pkg.Func("A"), pkg.Func("B")
	prior, err := newSelectedSourceBinder(t.Context(), source, pkg.Func("F"), defaultRegistrationLimits().source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prior.bindCallable(a.AnonFuncs[0]); err != nil {
		t.Fatal(err)
	}
	if len(prior.lexical) != 1 {
		t.Fatal("lexical cache not preinitialized")
	}
	left, err := continueSourceBinder(t.Context(), prior)
	if err != nil {
		t.Fatal(err)
	}
	right, err := continueSourceBinder(t.Context(), prior)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := left.bindCallable(b.AnonFuncs[0]); err != nil {
		t.Fatal(err)
	}
	if len(prior.lexical) != 1 || len(right.lexical) != 1 {
		t.Fatal("new lexical parent mutated predecessor or sibling")
	}
	if _, err := right.bindCallable(b.AnonFuncs[0]); err != nil {
		t.Fatal(err)
	}
	if left.work != right.work || left.bytes != right.bytes {
		t.Fatal("sibling cache pollution changed binding cost")
	}
	if left.work <= prior.work+len(prior.lexical) {
		t.Fatal("lexical clone was not charged")
	}
	// Enough for copying, but not for the new parent's full syntax walk. Both
	// siblings must refuse identically, even after another branch cached B.
	limited := *prior
	limited.limits.work = left.work - 1
	for range 2 {
		branch, err := continueSourceBinder(t.Context(), &limited)
		if err == nil {
			_, err = branch.bindCallable(b.AnonFuncs[0])
		}
		if err == nil {
			t.Fatal("sibling borrowed uncharged lexical walk")
		}
	}
	if _, ok := prior.lexical[b.Syntax().(*ast.FuncDecl)]; ok {
		t.Fatal("prior acquired B")
	}
}

func TestSourceActivationMetadataCapture(t *testing.T) {
	source := relationFixture(t, `func F()int{return 7}`, 64)
	in := activationInput(source, "F")
	p, err := proposeRegionActivation(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(source.metas) == 0 || len(source.metas[0].GoFiles) == 0 {
		t.Fatal("missing source metadata fixture")
	}
	want := source.metas[0].GoFiles[0]
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() { source.metas[0].GoFiles[0] = "forged.go"; source.metas[0].ImportPath = "forged" }}
	bound, err := checkSourceActivation(ctx, source, in, p, defaultRegistrationLimits().source, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if bound.binder.source.metas[0].GoFiles[0] != want {
		t.Fatal("context changed source dependency metadata")
	}
}
