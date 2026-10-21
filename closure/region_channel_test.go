package closure

import (
	"context"
	"errors"
	"go/types"
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
		`func makeC()chan int{return make(chan int,2)};func F()bool{a:=makeC();b:=makeC();return a==b}`,
		`func F(flag bool)int{a,b:=make(chan int,2),make(chan int,3);c:=a;if flag{c=b};return cap(c)}`,
	} {
		t.Run(text, func(t *testing.T) {
			in := regionFixture(t, text)
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
				if p, err := proposeRegion(t.Context(), in, defaultRegionLimits()); err == nil || p != nil || !strings.Contains(err.Error(), tc.reason) {
					t.Fatalf("unsupported channel path (normal=%v): %v; want %s", normal, err, tc.reason)
				}
			}
		})
	}
	in := regionFixture(t, `func F()int{c:=make(chan int,1);return len(c)}`)
	checked, _ := proveRegionFixture(t, in)
	if checked.observations[0].value.kind != regionUnknown {
		t.Fatal("channel construction invented stable contents")
	}
	in = regionFixture(t, `func F()int{c:=make(chan int,2147483647);return cap(c)}`)
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
	// Differing inputs may widen to unknown and refuse MakeChan; that cannot
	// produce a false capacity. Strict call contexts retain both exact facts.
	checked, _ := proveRegionFixture(t, in)
	localEffectInteger(t, checked.observations[0].value, 2)
}

func TestRegionChannelContinuation(t *testing.T) {
	source, prefix := localEffectPrefix(t, `type T struct{C chan bool};func Stop(chan bool,int,bool){};func id(c chan bool)chan bool{return c};func F(){p:=new(T);p.C=make(chan bool,3);c:=p.C;Stop(c,cap(c),c==p.C);d:=id(c);Stop(d,cap(d),d==p.C)}`)
	calls := localEffectCalls(t, source.prog.Roots["F"], "Stop")
	channel := prefix.operands[0]
	if channel.kind != regionChannel || channel.capacity != 3 {
		t.Fatal("actual field construction lost channel")
	}
	next, err := checkSourceOperandContinuation(t.Context(), prefix, calls[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !regionSameValue(channel, next.operands[0]) || len(next.region.packet.trace.allocations) != 0 {
		t.Fatal("continuation recreated channel identity")
	}
	localEffectInteger(t, next.operands[1], 3)
	if same, known := regionBool(next.operands[2]); !known || !same {
		t.Fatal("checked predecessor lost channel singleton")
	}
	allocation, live, err := next.liveAllocation(channel.location.object, func() error { return nil })
	if err != nil || !live || !regionSameValue(allocation.initializer, channel) {
		t.Fatalf("channel allocation occurrence lost: %v", err)
	}
	if prefix.checker.objectType(channel.location.object) != nil || prefix.checker.locationType(channel.location) != nil {
		t.Fatal("logical channel became addressable storage")
	}
	in := next.region.packet.input
	in.initial = prefix.region.packet.observations[0].state
	k, err := newRegionKernel(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if k.singleton(channel.location.object) {
		t.Fatal("copied channel facts supplied predecessor authority")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := checkSourceOperandContinuation(ctx, prefix, calls[1], nil); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled continuation: %v", err)
	}
}

func TestRegionChannelForgedFacts(t *testing.T) {
	in := regionFixture(t, `func id(c chan int)chan int{return c};func F(flag bool)int{c:=make(chan int,3);if flag{c=id(c)};return cap(c)}`)
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
	if regionValueIncluded(channel, other) || regionSameValue(channel, other) {
		t.Fatal("capacity omitted from value relation")
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
	_, prefix := localEffectPrefix(t, `func Stop(chan int){};func F(){c:=make(chan int,2);Stop(c)}`)
	trace := prefix.region.packet.trace
	if len(trace.allocations) != 1 || len(trace.accesses) != 0 || trace.allocations[0].instruction.(ssa.Value) != prefix.operands[0].location.object.site {
		t.Fatal("logical construction lost its actual occurrence or invented accesses")
	}
	// Finite effects retain the existing refusal of repeated-site allocation;
	// the ordinary invariant arm above can conservatively summarize it.
	source := relationFixture(t, `func Stop(chan int){};func F(){var c chan int;for i:=uint(0);i<2;i++{c=make(chan int)};Stop(c)}`, 64)
	root := source.prog.Roots["F"]
	_, err := checkSourceOperandPrefix(t.Context(), source, root, localEffectCalls(t, root, "Stop")[0], defaultRegistrationLimits())
	if err == nil || !strings.Contains(err.Error(), "fresh singleton") {
		t.Fatalf("recurrent finite allocation: %v", err)
	}
	// Cancellation and a spent account cannot produce a partial certificate.
	in := regionFixture(t, `func F()chan int{return make(chan int)}`)
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
