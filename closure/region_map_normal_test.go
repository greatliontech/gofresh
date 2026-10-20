package closure

import (
	"context"
	"errors"
	"go/constant"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func normalMapObservations(t testing.TB, c *checkedRegion) []regionObservation {
	t.Helper()
	if len(c.observations) == 0 {
		t.Fatal("expected a reachable normal-return observation")
	}
	return c.observations
}

func TestRegionMapNormalScopeCannotBecomeEffectPrefix(t *testing.T) {
	source := sourceRegionFixture(t, `func sink(x int){};func F(){sink(1)}`, false)
	root := source.prog.Roots["F"]
	var call *ssa.Call
	for _, block := range root.Blocks {
		for _, ins := range block.Instrs {
			if x, ok := ins.(*ssa.Call); ok {
				call = x
			}
		}
	}
	prefix, err := checkSourceOperandPrefix(t.Context(), source, root, call, defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	if prefix.checkedPacket() == nil {
		t.Fatal("control prefix lacks complete effects")
	}
	packet := *prefix.region.packet
	packet.input.normalReturns = true
	prefix.region.packet = &packet
	if prefix.checkedPacket() != nil {
		t.Fatal("normal-return scope acquired complete prefix effects")
	}
}

func TestRegionNormalScopeRejectsCompleteOccurrenceFlow(t *testing.T) {
	in := occurrenceFixture(t, `func F()int{return 7}`)
	proposal, owner := occurrenceProposal(t, in)
	if _, _, err := occurrenceCheck(t, in, proposal, owner); err != nil {
		t.Fatal("complete occurrence control failed", err)
	}
	in.normalReturns = true
	k := occurrenceKernel(t, t.Context(), in, owner, defaultRegionLimits())
	if _, err := k.checkFlow(proposal.entries, proposal.occurrences); err == nil {
		t.Fatal("normal-return scope acquired complete occurrence authority")
	}
}

func proveNormalMap(t testing.TB, text string) (*checkedRegion, *regionProposal, regionInput) {
	t.Helper()
	in := regionFixture(t, text)
	in.normalReturns = true
	p, err := proposeRegion(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	c, err := checkRegion(t.Context(), in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	return c, p, in
}

func TestRegionMapNormalInductionAndCalls(t *testing.T) {
	const prefix = `type K struct{Pkg,Fn string};var G map[K]*int;func add(m map[K]*int,p string){m[K{p,"f"}]=nil};`
	for _, body := range []string{
		`func F(n int)bool{G=make(map[K]*int);for i:=0;i<n;i++{add(G,"safe")};_,ok:=G[K{"bad","f"}];return ok}`,
		`func factory()func(){add(G,"safe");return func(){add(G,"bad")}};func F()bool{G=make(map[K]*int);_ = factory();_,ok:=G[K{"bad","f"}];return ok}`,
		`func F()bool{old:=G;G=make(map[K]*int);_ = old;add(G,"safe");_,ok:=G[K{"bad","f"}];return ok}`,
	} {
		t.Run(body[:min(25, len(body))], func(t *testing.T) {
			c, _, _ := proveNormalMap(t, prefix+body)
			for _, out := range normalMapObservations(t, c) {
				b, known := regionBool(out.value)
				if !known || b {
					t.Fatal("inductive absence lost")
				}
			}
		})
	}
}

func TestRegionMapUnknownAliasAndPayload(t *testing.T) {
	for _, body := range []string{
		`func F(m map[string]*int)bool{m["safe"]=nil;_,ok:=m["bad"];return ok}`,
		`func F()bool{m:=make(map[string]*int);a:=m;a["bad"]=nil;_,ok:=m["bad"];return ok}`,
		`func F()bool{m:=make(map[string]int);m["a"]=1;m["b"]=2;_,ok:=m["a"];return ok}`,
	} {
		in := regionFixture(t, body)
		in.normalReturns = true
		p, err := proposeRegion(t.Context(), in, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		c, err := checkRegion(t.Context(), in, p, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		for _, out := range normalMapObservations(t, c) {
			if b, known := regionBool(out.value); known && !b {
				t.Fatal("unknown/present key claimed absent")
			}
		}
	}
}

func TestRegionMapCommonInformationKeepsUnknown(t *testing.T) {
	in := regionFixture(t, `var G map[string]int;func F(flag bool)bool{if flag{}else{G=make(map[string]int)};_,ok:=G["bad"];return ok}`)
	in.normalReturns = true
	limits := defaultRegionLimits()
	limits.alternatives = 1
	p, err := proposeRegion(t.Context(), in, limits)
	if err != nil {
		t.Fatal(err)
	}
	c, err := checkRegion(t.Context(), in, p, limits)
	if err != nil {
		t.Fatal(err)
	}
	if !regionMayReturnBool(c, true) {
		t.Fatal("missing incoming global fact became an empty map")
	}
}

func TestRegionMapExceptionalScope(t *testing.T) {
	const text = `func opaque();func F(flag bool)bool{m:=make(map[string]int);m["safe"]=1;if flag{opaque();panic("stop")};_,ok:=m["bad"];return ok}`
	c, p, in := proveNormalMap(t, text)
	if len(c.exceptional) == 0 {
		t.Fatal("excluded exceptional continuation was not retained")
	}
	for _, out := range normalMapObservations(t, c) {
		b, known := regionBool(out.value)
		if !known || b {
			t.Fatal("normal outcome missing")
		}
	}
	in.normalReturns = false
	if _, err := checkRegion(t.Context(), in, p, defaultRegionLimits()); err == nil {
		t.Fatal("normal-return evidence acquired stronger scope")
	}
	for _, body := range []string{
		`func opaque();func F()bool{m:=make(map[string]int);opaque();_,ok:=m["bad"];return ok}`,
		`func opaque();func F(){defer func(){recover()}();opaque();panic("stop")}`,
	} {
		in := regionFixture(t, body)
		in.normalReturns = true
		if _, err := proposeRegion(t.Context(), in, defaultRegionLimits()); err == nil {
			t.Fatal("unproved call/recovery accepted")
		}
	}
}

func TestRegionMapForgedBackedgeAndOwnedProjection(t *testing.T) {
	_, p, in := proveNormalMap(t, `func F(n int)bool{m:=make(map[string]int);for i:=0;i<n;i++{m["bad"]=0};_,ok:=m["bad"];return ok}`)
	changed := false
	for _, states := range p.entries {
		for _, state := range states {
			for object, value := range state.memory {
				if value.kind == regionMapContents && !value.keys.empty {
					value.keys = &regionMapKeys{empty: true}
					state.memory[object] = value
					changed = true
				}
			}
		}
	}
	if !changed {
		t.Fatal("fixture lacks its inductive map invariant")
	}
	if _, err := checkRegion(t.Context(), in, p, defaultRegionLimits()); err == nil {
		t.Fatal("forged empty backedge invariant accepted")
	}
	_, p, in = proveNormalMap(t, `func F(flag bool)bool{m:=make(map[string]int);m["safe"]=0;if flag{m["other"]=0};_,ok:=m["bad"];return ok}`)
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() {
		for _, states := range p.entries {
			for _, state := range states {
				for _, value := range state.memory {
					if value.keys != nil {
						for _, projection := range value.keys.projections {
							for i := range projection.strings {
								projection.strings[i] = "bad"
							}
						}
					}
				}
			}
		}
	}}
	c, err := checkRegion(ctx, in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range normalMapObservations(t, c) {
		got, known := regionBool(out.value)
		if !known || got {
			t.Fatal("captured projection borrowed mutable proposal strings")
		}
	}
}

func TestRegionMapEarlierInvocationCannotBeCleared(t *testing.T) {
	in := regionFixture(t, `var old map[string]int;func F()bool{fresh:=make(map[string]int);fresh["safe"]=0;_,ok:=old["bad"];return ok}`)
	in.normalReturns = true
	var allocation *ssa.MakeMap
	for _, block := range in.root.Blocks {
		for _, ins := range block.Instrs {
			if x, ok := ins.(*ssa.MakeMap); ok {
				allocation = x
			}
		}
	}
	if allocation == nil {
		t.Fatal("missing actual map allocation")
	}
	object := regionObject{kind: regionMapAllocation, site: allocation, context: in.root}
	global := in.root.Pkg.Members["old"].(*ssa.Global)
	in.initial.memory = map[regionObject]regionValue{
		object:                             {typ: allocation.Type(), kind: regionMapContents, keys: &regionMapKeys{projections: []regionKeyProjection{{strings: []string{"bad"}}}}},
		{kind: regionGlobal, site: global}: {typ: allocation.Type(), kind: regionMap, location: regionLocation{object: object}},
	}
	p, err := proposeRegion(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	c, err := checkRegion(t.Context(), in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !regionMayReturnBool(c, true) {
		t.Fatal("new allocation cleared an older escaped map instance")
	}
}

func TestRegionMapProposalOwnershipAndCancellation(t *testing.T) {
	_, p, in := proveNormalMap(t, `func F()bool{m:=make(map[string]int);m["safe"]=1;_,ok:=m["bad"];return ok}`)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := checkRegion(ctx, in, p, defaultRegionLimits()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation did not refuse", err)
	}
	other := regionFixture(t, `func F()bool{return false}`)
	other.normalReturns = true
	if _, err := checkRegion(t.Context(), other, p, defaultRegionLimits()); err == nil {
		t.Fatal("foreign owner accepted")
	}
	limits := defaultRegionLimits()
	limits.work = 1
	if _, err := checkRegion(t.Context(), in, p, limits); err == nil {
		t.Fatal("resource refusal missing")
	}
}

func TestRegionMapStoragePayloadCannotHideLanguageValues(t *testing.T) {
	_, p, in := proveNormalMap(t, `func F(flag bool)bool{m:=make(map[string]int);if flag{m["x"]=0};_,ok:=m["y"];return ok}`)
	changed := false
	for _, states := range p.entries {
		for _, state := range states {
			for object, value := range state.memory {
				if value.kind == regionMapContents {
					value.scalar = constant.MakeString("hidden")
					state.memory[object] = value
					changed = true
				}
			}
		}
	}
	if !changed {
		t.Fatal("fixture has no map storage invariant")
	}
	if _, err := checkRegion(t.Context(), in, p, defaultRegionLimits()); err == nil {
		t.Fatal("noncanonical map storage acquired authority")
	}
}
