package closure

import (
	"context"
	"errors"
	"fmt"
	"go/constant"
	"go/types"
	"strconv"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func TestRegionChannelConstruction(t *testing.T) {
	for _, text := range []string{
		`func F()bool{c:=make(chan bool);return c!=nil}`,
		`func F()int{var c chan int;return cap(c)}`,
		`func F()int{var c chan int;return len(c)}`,
		`func F()bool{c:=make(chan struct{});d:=make(chan struct{});return c==d}`,
		`func id(c chan int)chan int{return c};func F()bool{c:=make(chan int,3);return id(c)==c}`,
		`type C chan int;func F()int{c:=make(C,7);var d <-chan int=c;return cap(d)}`,
		`func F()int{c:=make(chan int,9);f:=func()int{return cap(c)};return f()}`,
		`func F()bool{c:=make(chan int,9);f:=func()chan int{return c};return f()==c}`,
		`type T struct{signal chan bool; barrier chan bool};func F()bool{t:=new(T);t.signal=make(chan bool,1);t.barrier=make(chan bool);p:=&t.signal;c:=*p;t.signal=t.barrier;return c==*p}`,
		`func F()bool{a:=make(chan int,2);b:=make(chan int,2);return a==b}`,
		`func F(flag bool)int{a,b:=make(chan int,2),make(chan int,3);c:=a;if flag{c=b};return cap(c)}`,
	} {
		t.Run(text, func(t *testing.T) {
			in := regionFixture(t, text)
			// These are postconditions of normal return, not allocation safety.
			in.normalReturns = true
			checked, _ := proveRegionFixture(t, in)
			for _, flag := range []bool{false, true} {
				assertRegionCovers(t, checked, executeRegionConcrete(t, in, flag))
			}
			for _, o := range checked.observations {
				if o.value.kind == regionUnknown {
					t.Fatal("bounded channel computation lost its exact result")
				}
			}
		})
	}
}

func TestRegionChannelRefusals(t *testing.T) {
	for _, tc := range []struct{ text, reason string }{
		{`func F(n int)chan int{return make(chan int,n)}`, "channel capacity"},
		{`func F()chan int{n:=-1;return make(chan int,n)}`, "channel capacity"},
		{`func F()chan int{n:=uint64(1)<<32;return make(chan int,n)}`, "channel capacity"},
		{`func F()int{c:=make(chan int,1);c<-1;return cap(c)}`, "unsupported instruction"},
		{`func F()int{c:=make(chan int);return <-c}`, "unsupported unary"},
		{`func F()int{c:=make(chan int);close(c);return cap(c)}`, "call effects"},
		{`func F()int{c:=make(chan int);select{case <-c:default:};return cap(c)}`, "unsupported instruction"},
		{`func opaque(chan int);func F()int{c:=make(chan int,1);opaque(c);return len(c)}`, "call target"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			in := regionFixture(t, tc.text)
			for _, normal := range []bool{false, true} {
				in.normalReturns = normal
				reason := tc.reason
				if !normal {
					reason = "channel allocation outcomes"
				}
				if p, err := proposeRegion(t.Context(), in, defaultRegionLimits()); err == nil || p != nil || !strings.Contains(err.Error(), reason) {
					t.Fatalf("unsupported channel path (normal=%v): %v; want %s", normal, err, reason)
				}
			}
		})
	}
	in := regionFixture(t, `func F()int{c:=make(chan int,1);return len(c)}`)
	in.normalReturns = true
	checked, _ := proveRegionFixture(t, in)
	if checked.observations[0].value.kind != regionUnknown {
		t.Fatal("channel construction invented stable contents")
	}
	in = regionFixture(t, `func F()int{c:=make(chan int,2147483647);return cap(c)}`)
	in.normalReturns = true
	checked, _ = proveRegionFixture(t, in)
	localEffectInteger(t, checked.observations[0].value, 2147483647)
}

func TestRegionChannelSummaryIdentity(t *testing.T) {
	for _, text := range []string{
		`func makeC()chan int{return make(chan int,2)};func F()bool{a:=makeC();b:=makeC();return a==b}`,
		`func F(again bool)bool{var old,c chan int;for {old=c;c=make(chan int,2);if !again{break}};return old==c}`,
	} {
		in := regionFixture(t, text)
		in.normalReturns = true
		checked, _ := proveRegionFixture(t, in)
		for _, o := range checked.observations {
			if yes, known := regionBool(o.value); known && yes {
				t.Fatal("repeated allocation summary proved distinct concrete channels equal")
			}
		}
	}
	// An earlier instance keeps its capacity even when a later execution of the
	// same summary site chooses a different capacity.
	in := regionFixture(t, `func makeC(n int)chan int{return make(chan int,n)};func F()int{a:=makeC(2);_ = makeC(3);return cap(a)}`)
	in.normalReturns = true
	if p, err := proposeRegion(t.Context(), in, defaultRegionLimits()); p != nil || err == nil || !strings.Contains(err.Error(), "channel capacity") {
		t.Fatalf("merged normal-call capacity requires refusal: %v", err)
	}
	// Separate supported normal-return constructions retain their immutable
	// capacities; a strict incoming relation can transport those facts below.
	in = regionFixture(t, `func F()int{a:=make(chan int,2);_ = make(chan int,3);return cap(a)}`)
	in.normalReturns = true
	checked, _ := proveRegionFixture(t, in)
	localEffectInteger(t, checked.observations[0].value, 2)
}

func TestRegionChannelIncomingCallIdentity(t *testing.T) {
	in := regionFixture(t, `func seed(n int)chan int{return make(chan int,n)};func id(c chan int)chan int{return c};func F(a,b chan int)[3]chan int{return [3]chan int{id(a),id(b),id(a)}}`)
	seed := in.root.Pkg.Func("seed")
	var handles []regionValue
	for _, capacity := range []int64{2, 3} {
		normal := regionInput{owner: in.owner, root: seed, entry: regionPoint{seed.Blocks[0], 0}, normalReturns: true,
			initial: regionState{values: map[ssa.Value]regionValue{seed.Params[0]: {typ: seed.Params[0].Type(), kind: regionConstant, scalar: constant.MakeInt64(capacity)}}}, premises: in.premises}
		c, _ := proveRegionFixture(t, normal)
		handles = append(handles, c.observations[0].value)
	}
	if regionValueIncluded(handles[0], handles[1]) || regionValueIncluded(handles[1], handles[0]) || regionSameValue(handles[0], handles[1]) {
		t.Fatal("different capacities shared one canonical value relation")
	}
	for _, handle := range handles {
		if !regionValueIncluded(handle, handle) || !regionSameValue(handle, handle) {
			t.Fatal("canonical channel value lost reflexive inclusion")
		}
	}
	// These conditional inputs describe existing handles, not strict executions
	// of seed. No allocation or singleton premise is lent to the caller.
	in.initial.values = map[ssa.Value]regionValue{in.root.Params[0]: handles[0], in.root.Params[1]: handles[1]}
	in.premises = append(in.premises, "incoming handles satisfy the two normal-construction value relations; actual construction and allocation success remain open")
	checked, _ := proveRegionFixture(t, in)
	if checked.input.normalReturns || len(checked.calls) != 3 {
		t.Fatal("strict incoming call contexts were merged")
	}
	for _, out := range checked.observations {
		if len(out.value.elements) != 3 {
			t.Fatal("incoming alias result lost exact shape")
		}
		for i, want := range []regionValue{handles[0], handles[1], handles[0]} {
			if !regionSameValue(out.value.elements[i], want) {
				t.Fatal("strict transport lost channel identity or immutable capacity")
			}
		}
	}
}

// Keep channel construction in its own normal-return population. The strict
// registration grammar separately checks exact name/function/row correlation.
func FuzzRegionChannelNormalOracle(f *testing.F) {
	f.Add("first", "second", false)
	f.Add("same", "same", true)
	f.Fuzz(func(t *testing.T, a, b string, swap bool) {
		if len(a) > 64 || len(b) > 64 || strings.ContainsRune(a, 0) || strings.ContainsRune(b, 0) {
			t.Skip()
		}
		text := fmt.Sprintf(`type Row[T any] struct{Name string;F T;C chan struct{}};func a(){};func b(){};func F(flag bool)[]Row[func()]{c,d:=make(chan struct{},%d),make(chan struct{},%d);x:=[]Row[func()]{{%s,a,c},{%s,b,d}};p:=&x[0].F;if flag{x[0]=Row[func()]{x[0].Name,b,d};x[1].F=a};x[0].F=*p;return x}`, len(a), len(b), strconv.Quote(a), strconv.Quote(b))
		in := regionFixture(t, text)
		in.normalReturns = true
		c, _ := proveRegionFixture(t, in)
		for _, out := range c.observations {
			if !regionTestPrecise(out.value, out.state, 0) {
				t.Fatal("normal-return channel row correlation widened")
			}
		}
		assertRegionCovers(t, c, executeRegionConcrete(t, in, swap))
	})
}

func TestRegionChannelContinuation(t *testing.T) {
	// A strict prefix cannot turn conditional construction into continuation
	// authority. The allocation-free nil-channel continuation stays supported.
	source := relationFixture(t, `func Stop(chan bool){};func F(){c:=make(chan bool,3);Stop(c)}`, 64)
	root := source.prog.Roots["F"]
	if p, err := checkSourceOperandPrefix(t.Context(), source, root, localEffectCalls(t, root, "Stop")[0], defaultRegistrationLimits()); p != nil || err == nil || !strings.Contains(err.Error(), "channel allocation outcomes") {
		t.Fatalf("construction supplied strict prefix: %v", err)
	}
	source, prefix := localEffectPrefix(t, `func Stop(chan bool,int,bool){};func id(c chan bool)chan bool{return c};func F(){var c chan bool;Stop(c,cap(c),c==nil);d:=id(c);Stop(d,cap(d),d==nil)}`)
	calls := localEffectCalls(t, source.prog.Roots["F"], "Stop")
	channel := prefix.operands[0]
	if channel.kind != regionNil {
		t.Fatal("nil channel gained allocation identity")
	}
	next, err := checkSourceOperandContinuation(t.Context(), prefix, calls[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !regionSameValue(channel, next.operands[0]) || len(next.region.packet.trace.allocations) != 0 {
		t.Fatal("continuation recreated channel identity")
	}
	localEffectInteger(t, next.operands[1], 0)
	if same, known := regionBool(next.operands[2]); !known || !same {
		t.Fatal("checked predecessor lost nil-channel equality")
	}
	if _, live, err := next.liveAllocation(channel.location.object, func() error { return nil }); err != nil || live {
		t.Fatalf("nil channel manufactured live allocation: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := checkSourceOperandContinuation(ctx, prefix, calls[1], nil); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled continuation: %v", err)
	}
}

func TestRegionChannelForgedFacts(t *testing.T) {
	in := regionFixture(t, `func id(c chan int)chan int{return c};func F(flag bool)int{c:=make(chan int,3);if flag{c=id(c)};return cap(c)}`)
	in.normalReturns = true
	_, proposal := proveRegionFixture(t, in)
	foreign := regionFixture(t, `func F()chan int{return make(chan int,3)}`)
	var channel regionValue
	for _, states := range proposal.entries {
		for _, state := range states {
			for _, v := range state.values {
				if v.kind == regionChannel {
					channel = v
				}
			}
		}
	}
	if channel.kind != regionChannel {
		t.Fatal("fixture has no channel invariant")
	}
	for _, change := range []func(*regionValue){
		func(v *regionValue) { v.capacity++ },
		func(v *regionValue) { v.capacity = -1 },
		func(v *regionValue) { v.length = 1 },
		func(v *regionValue) { v.location.path = []regionStep{{index: 0}} },
		func(v *regionValue) { v.location.object.context = foreign.root },
		func(v *regionValue) {
			v.location.object = regionObject{kind: regionChannelAllocation, site: storageOracleInstructions[*ssa.MakeChan](foreign.root)[0], context: foreign.root}
		},
		func(v *regionValue) { v.location.object.invocation.path = "forged" },
		func(v *regionValue) { v.typ = types.NewChan(types.SendRecv, types.Typ[types.Bool]) },
	} {
		_, p, err := regionCapture(in, proposal, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		for _, states := range p.entries {
			for _, state := range states {
				for key, v := range state.values {
					if v.kind == regionChannel {
						change(&v)
						state.values[key] = v
					}
				}
			}
		}
		if c, err := checkRegion(t.Context(), in, p, defaultRegionLimits()); c != nil || err == nil {
			t.Fatal("forged channel invariant admitted")
		}
	}
	// A channel handle is never a heap cell, even with a matching type.
	bad := in
	bad.initial.memory = map[regionObject]regionValue{channel.location.object: channel}
	if _, err := newRegionKernel(t.Context(), bad, defaultRegionLimits()); err == nil {
		t.Fatal("channel handle manufactured backing storage")
	}
	// Capacity also participates in inclusion/call sharing, not only validation.
	other := channel
	other.capacity++
	if regionValueIncluded(channel, other) || regionValueIncluded(other, channel) || regionSameValue(channel, other) {
		t.Fatal("capacity omitted from value relation")
	}
	k, err := newRegionKernel(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if k.objectType(channel.location.object) != nil || k.locationType(channel.location) != nil {
		t.Fatal("logical channel became addressable storage")
	}
}

func TestRegionChannelNormalFramesAndMapKeys(t *testing.T) {
	for _, tc := range []struct {
		text  string
		known bool
		want  uint64
	}{
		{`type T struct{C chan int};func change(p *T){p.C=make(chan int,5)};func F(p *T)int{q:=new(T);q.C=make(chan int,2);c:=q.C;change(p);return cap(c)}`, true, 2},
		{`type T struct{C chan int};func change(p *T){p.C=make(chan int,5)};func F(p *T)int{q:=new(T);q.C=make(chan int,2);change(p);return cap(q.C)}`, false, 0},
		{`func F()bool{c:=make(chan int);m:=make(map[chan int]bool);m[c]=true;_,ok:=m[c];return ok}`, false, 0},
		{`type K struct{S string;C chan int};func F()bool{c:=make(chan int);m:=make(map[K]bool);m[K{"x",c}]=true;_,ok:=m[K{"x",c}];return ok}`, false, 0},
	} {
		in := regionFixture(t, tc.text)
		in.normalReturns = true
		checked, _ := proveRegionFixture(t, in)
		for _, o := range checked.observations {
			if tc.known {
				localEffectInteger(t, o.value, tc.want)
			} else if o.value.kind != regionUnknown {
				t.Fatalf("invented frame/key fact: %+v", o.value)
			}
		}
	}
}

func TestRegionChannelAllocationEffects(t *testing.T) {
	for _, tc := range []struct{ text, reason string }{
		{`func Stop(chan int){};func F(){c:=make(chan int,2);Stop(c)}`, "channel allocation outcomes"},
		{`func Stop(chan int){};func F(){var c chan int;for i:=uint(0);i<2;i++{c=make(chan int)};Stop(c)}`, "channel allocation outcomes"},
	} {
		source := relationFixture(t, tc.text, 64)
		root := source.prog.Roots["F"]
		if p, err := checkSourceOperandPrefix(t.Context(), source, root, localEffectCalls(t, root, "Stop")[0], defaultRegistrationLimits()); p != nil || err == nil || !strings.Contains(err.Error(), tc.reason) {
			t.Fatalf("finite allocation must refuse unsupported outcomes: %v", err)
		}
	}
	// Cancellation and a spent account cannot produce a partial certificate.
	in := regionFixture(t, `func F()chan int{return make(chan int)}`)
	in.normalReturns = true
	limits := defaultRegionLimits()
	limits.work = 1
	if p, err := proposeRegion(t.Context(), in, limits); p != nil || err == nil {
		t.Fatal("spent account admitted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if p, err := proposeRegion(ctx, in, defaultRegionLimits()); p != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled construction admitted")
	}
	// Independent mutation of captured proposal containers cannot change the
	// already checked packet's allocation facts.
	checked, p := proveRegionFixture(t, in)
	for _, states := range p.entries {
		for _, s := range states {
			clear(s.values)
		}
	}
	if checked.observations[0].value.kind != regionChannel {
		t.Fatal("packet aliases proposal")
	}
}
