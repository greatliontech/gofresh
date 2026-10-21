package closure

import (
	"go/constant"
	"go/types"
	"slices"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// These literal programs also run in the independently compiled Go oracle.
// In particular, their expected results are never computed by a region helper.
var finiteActivationCases = []struct{ name, source string }{
	{"finite-pointer-two", `func F()int{var a [2]*int;for i:=0;i<2;i++{p:=new(int);*p=i+7;a[i]=p};*a[1]=19;return *a[0]*100+*a[1]}`},
	{"finite-pointer-three", `func F()int{var a [3]*int;for i:=0;i<3;i++{p:=new(int);*p=i+7;a[i]=p};*a[2]=19;return *a[0]*100+*a[1]*10+*a[2]}`},
	{"finite-map-alias", `func F()int{var a [3]map[string]int;names:=[3]string{"a","b","c"};for i:=0;i<3;i++{m:=make(map[string]int);m[names[i]]=i;a[i]=m};r:=0;if _,ok:=a[0]["c"];!ok{r+=1};if _,ok:=a[1]["a"];!ok{r+=10};if _,ok:=a[2]["b"];!ok{r+=100};return r}`},
	{"finite-slice-alias", `func F()int{var a [3][]int;for i:=0;i<3;i++{s:=make([]int,i+1);s[0]=i+4;a[i]=s};a[2][0]=9;return a[0][0]*100+a[1][0]*10+a[2][0]}`},
	{"finite-slice-recovered", finiteSliceRecoverySource},
	{"finite-phi-simultaneous", `func F()int{a,b:=2,7;for i:=0;i<3;i++{a,b=b,a};return 10*a+b}`},
	{"finite-closure-captures", `func F()int{var a [3]func()int;for i:=0;i<3;i++{v:=i+1;a[i]=func()int{return v}};return a[0]()*100+a[1]()*10+a[2]()}`},
	{"finite-defer-lifo-current-heap", `func F()(r int){x:=0;for i:=0;i<3;i++{v:=i+1;defer func(n int){r=r*10+n+x}(v)};x=4;return}`},
	{"finite-shared-call-actuals", `func finiteActual(p *int,n int)int{*p+=n;return *p};func F()int{x:=0;r:=0;for i:=0;i<3;i++{r=r*10+finiteActual(&x,i+1)};return r}`},
	{"finite-factorial", `func finiteFactorial(n int)int{if n==0{return 1};return n*finiteFactorial(n-1)};func F()int{return finiteFactorial(4)}`},
	{"finite-list-parent", `type finiteNode struct{value int;parent *finiteNode};func finiteList(n int,p *finiteNode)*finiteNode{if n==0{return p};q:=&finiteNode{n,p};return finiteList(n-1,q)};func F()int{p:=finiteList(3,nil);return p.value+10*p.parent.value+100*p.parent.parent.value}`},
	{"finite-recursive-panic", `func finitePanic(n int,p *int){defer func(){*p=*p*10+n}();if n==0{panic(9)};finitePanic(n-1,p);*p=999};func F()(r int){defer func(){if recover()!=nil{r+=10000}}();finitePanic(3,&r);r=999;return}`},
	{"finite-recursive-recover", `func finiteRecover(n int)(r int){defer func(){if recover()!=nil{r=7}}();if n==0{panic(9)};return n+finiteRecover(n-1)};func F()int{return finiteRecover(3)}`},
	{"finite-recursive-replacement-panic", `func finiteReplace(n int,p *int){defer func(){*p=*p*10+n;if n==1{panic(6)}}();if n==0{panic(9)};finiteReplace(n-1,p);*p=999};func F()(r int){defer func(){if recover()!=nil{r+=6000}}();finiteReplace(2,&r);r=999;return}`},
	{"finite-recursive-escaping-replacement", `func finiteEscape(n int){defer func(){if n==1{panic(6)}}();if n==0{panic(9)};finiteEscape(n-1)};func F()int{finiteEscape(2);return 999}`},
	{"finite-arithmetic-overflow", `func F()int{a:=int8(127);b:=int8(-3);a=a*b;a=a-10;if a!=121{return 99};u:=uint64(0xffffffffffffffff);u=u*3;u=u-0xfffffffffffffff0;if u!=13{return 98};return 7}`},
	{"finite-skipped-loop", `func F()int{n:=0;r:=3;for i:=0;i<n;i++{panic(1)};return r}`},
	{"finite-branch-continue", `func F()int{r:=0;for i:=0;i<3;i++{if i==1{continue};r=r*10+i+1};return r}`},
}

var finiteChannelCases = []struct{ name, source string }{
	{"finite-channel-two", `func F()int{var a [2]chan int;for i:=0;i<2;i++{a[i]=make(chan int,i+1)};if a[0]==a[1]{return 999};return 10*cap(a[0])+cap(a[1])}`},
	{"finite-channel-three", `func F()int{var a [3]chan int;for i:=0;i<3;i++{a[i]=make(chan int,i+1)};if a[0]==a[1]||a[0]==a[2]||a[1]==a[2]{return 999};return 100*cap(a[0])+10*cap(a[1])+cap(a[2])}`},
}

func TestRegionActivationFiniteOccurrences(t *testing.T) {
	for _, tc := range finiteActivationCases {
		t.Run(tc.name, func(t *testing.T) {
			packet, proposal := proveActivation(t, tc.source)
			wantOutcomes := 1
			if tc.name == "finite-slice-alias" {
				wantOutcomes = 7 // one normal, three escaping panics, three stopped
			}
			if tc.name == "finite-slice-recovered" {
				wantOutcomes = 4 // success, two recovered payload alternatives, stopped
			}
			if len(packet.snapshot.work)+len(packet.snapshot.frontiers) != 0 || len(packet.outcomes) != wantOutcomes {
				t.Fatal("finite execution did not close every frontier")
			}
			for object := range packet.snapshot.instances {
				if object.instance == 0 || !packet.snapshot.occurrences[regionEffectOccurrence{instruction: object.site.(ssa.Instruction), invocation: object.invocation, ordinal: object.instance - 1}] {
					t.Fatal("allocation is not anchored to its actual checked step")
				}
			}
			// Drop each individual inference, including backedges, phi occurrences,
			// recursive call alternatives and the last return. No omission can close
			// the machine by merely shortening the proposed unfolding.
			for i := range proposal.events {
				bad := *proposal
				bad.events = append(slices.Clone(proposal.events[:i]), proposal.events[i+1:]...)
				if got, err := checkRegionActivation(t.Context(), packet.input, &bad, defaultRegionLimits()); err == nil || got != nil {
					t.Fatalf("omitted occurrence %d accepted", i)
				}
			}
			for i, event := range proposal.events {
				if event.invocation == (regionInvocation{}) {
					continue
				}
				bad := *proposal
				bad.events = slices.Clone(proposal.events)
				bad.events[i].invocation = regionInvocation{}
				if got, err := checkRegionActivation(t.Context(), packet.input, &bad, defaultRegionLimits()); err == nil || got != nil {
					t.Fatal("merged call context accepted")
				}
				break
			}
		})
	}
}

func TestRegionActivationFiniteChannelAliases(t *testing.T) {
	in := activationInput(relationFixture(t, finiteChannelCases[1].source, 64), "F")
	p := activationWhole(t, in)
	normal, panics, stopped := 0, 0, 0
	for _, out := range p.outcomes {
		switch out.kind {
		case activationNormal:
			normal++
			localEffectInteger(t, out.value, 123)
		case activationPanicking:
			panics++
		case activationStopped:
			stopped++
		}
	}
	if normal != 1 || panics != 3 || stopped != 3 {
		t.Fatalf("channel occurrences lost outcomes: %d/%d/%d", normal, panics, stopped)
	}
	for cut := uint64(1); cut < p.snapshot.transitions; cut++ {
		_, after := activationPartition(t, in, cut)
		equalActivations(t, p, after)
	}
}

func TestRegionActivationFiniteCorrelatedAlternatives(t *testing.T) {
	text := `var B bool;func step(n int)int{return n+1};func F()int{n:=2;if B{n=3};r:=0;for i:=0;i<n;i++{r=r*10+step(i)};return r}`
	p, _ := proveActivation(t, text)
	oracle := func(n int) int {
		r := 0
		for i := 0; i < n; i++ {
			r = r*10 + i + 1
		}
		return r
	}
	want := map[int64]bool{int64(oracle(2)): true, int64(oracle(3)): true}
	if len(p.outcomes) != len(want) || len(p.calls) != 5 {
		t.Fatal("finite branches merged or lost their distinct actual dispatches")
	}
	for _, out := range p.outcomes {
		n, exact := regionInt(out.value)
		if out.kind != activationNormal || !exact || !want[n] {
			t.Fatal("whole-state branch correlation lost")
		}
		delete(want, n)
	}
	contexts := map[regionInvocation]bool{}
	for _, call := range p.calls {
		if contexts[call.invocation] {
			t.Fatal("distinct alternative dispatches shared a context")
		}
		contexts[call.invocation] = true
	}
	for cut := uint64(1); cut < p.snapshot.transitions; cut++ {
		_, after := activationPartition(t, p.input, cut)
		equalActivations(t, p, after)
	}
}

func TestRegionActivationFiniteInstanceForgery(t *testing.T) {
	source := relationFixture(t, `func F(p *int)int{for i:=0;i<2;i++{q:=new(int);*q=i;if p==nil{p=q}};return *p}`, 64)
	in := activationInput(source, "F")
	parameter := in.root.Params[0]
	in.initial.values = map[ssa.Value]regionValue{parameter: {typ: parameter.Type(), kind: regionNil}}
	packet := activationWhole(t, in)
	var object regionObject
	for candidate := range packet.snapshot.instances {
		if candidate.kind == regionAllocation {
			object = candidate
			break
		}
	}
	for _, mode := range []string{"copied-instance", "forged-instance", "earlier-static-alias"} {
		t.Run(mode, func(t *testing.T) {
			o := object
			if mode == "forged-instance" {
				o.instance++
			}
			if mode == "earlier-static-alias" {
				o.instance = 0
			}
			value := regionValue{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(41)}
			forged := in
			forged.initial = regionState{values: map[ssa.Value]regionValue{parameter: {typ: parameter.Type(), kind: regionPointer, location: regionLocation{object: o}}}, memory: map[regionObject]regionValue{o: value}}
			if mode == "earlier-static-alias" {
				p := activationWhole(t, forged)
				localEffectInteger(t, p.outcomes[0].value, 41)
				return
			}
			if p, err := proposeRegionActivation(t.Context(), forged, defaultRegionLimits()); err == nil || p != nil {
				t.Fatal("incoming coordinate forged checker-issued freshness")
			}
			legacy := forged.regionInput()
			legacy.normalReturns = true
			if _, err := newRegionKernel(t.Context(), legacy, defaultRegionLimits()); err == nil {
				t.Fatal("legacy normal/strict kernel accepted dynamic instance")
			}
		})
	}
}

func TestRegionActivationFiniteConstructorAuthority(t *testing.T) {
	for _, body := range []string{
		`func F()*int{return new(int)}`,
		`func F()map[string]int{return make(map[string]int)}`,
		`func F()chan int{return make(chan int,1)}`,
		`func F()[]int{n:=func()int{return 2};return make([]int,n())}`,
		`func F()func()int{x:=1;return func()int{return x}}`,
	} {
		p, _ := proveActivation(t, body)
		value := p.outcomes[0].value
		if value.location.object.instance == 0 {
			t.Fatal("constructor did not issue an instance")
		}
		for _, corrupt := range []string{"copy", "ordinal", "extent"} {
			v := value
			if corrupt == "ordinal" {
				v.location.object.instance++
			}
			if corrupt == "extent" {
				v.location.object.extent++
			}
			in := p.input
			in.initial.values = map[ssa.Value]regionValue{value.location.object.site: v}
			if got, err := proposeRegionActivation(t.Context(), in, defaultRegionLimits()); err == nil || got != nil {
				t.Fatalf("%s incoming constructor identity supplied authority: %s", corrupt, body)
			}
			legacy := in.regionInput()
			legacy.normalReturns = true
			if _, err := newRegionKernel(t.Context(), legacy, defaultRegionLimits()); err == nil {
				t.Fatalf("legacy accepted %s constructor identity: %s", corrupt, body)
			}
		}
	}
}

func TestRegionActivationFiniteResidualRefusal(t *testing.T) {
	for _, text := range []string{
		`var B bool;func F()int{for B{};return 1}`,
		`var N int;func finiteUnknown(n int)int{if n==0{return 1};return finiteUnknown(n-1)};func F()int{return finiteUnknown(N)}`,
		`func finiteCycle()int{return finiteCycle()};func F()int{return finiteCycle()}`,
	} {
		in := activationInput(relationFixture(t, text, 64), "F")
		if got, err := proposeRegionActivation(t.Context(), in, defaultRegionLimits()); err == nil || got != nil {
			t.Fatal("residual loop or recursion became complete evidence")
		}
		proposal, err := proposeRegionActivationSegment(t.Context(), in, 3, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		prefix, err := checkRegionActivationSegment(t.Context(), in, 3, proposal, defaultRegionLimits())
		if err != nil || len(prefix.snapshot.work) == 0 {
			t.Fatalf("explicit owned frontier missing: %v", err)
		}
		if _, err := prefix.projectNormal(t.Context(), regionUnknownValue(types.Typ[types.Int])); err == nil {
			t.Fatal("unfinished recurrence acquired terminal authority")
		}
		if got, err := proposeRegionActivationContinuation(t.Context(), prefix, 0); err == nil || got != nil {
			t.Fatal("resumption turned residual recurrence into completion")
		}
	}
}
