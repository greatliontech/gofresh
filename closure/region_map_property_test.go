package closure

import (
	"fmt"
	"testing"
)

func regionMayReturnBool(c *checkedRegion, want bool) bool {
	for _, out := range c.observations {
		got, known := regionBool(out.value)
		if !known || got == want {
			return true
		}
	}
	return false
}

// The oracle uses native Go maps, including nil payloads and key equality. It
// does not share projection, join, abstract transfer or alias helpers.
func FuzzRegionMapProjectionOracle(f *testing.F) {
	f.Add("a", "b", "a", true, false)
	f.Add("safe", "safe", "missing", false, true)
	f.Add("", "\x00", "\x00", true, true)
	f.Fuzz(func(t *testing.T, a, b, query string, branch, alias bool) {
		if len(a) > 64 || len(b) > 64 || len(query) > 64 {
			t.Skip("bounded source literals")
		}
		text := fmt.Sprintf(`type Inner struct{Package string};type K struct{Inner Inner;Name string};func F(flag bool,alias bool)bool{m:=make(map[K]*int);n:=make(map[K]*int);if alias{n=m};pkg:=%q;if flag{pkg=%q};m[K{Inner{%q},"x"}]=nil;n[K{Inner{pkg},"y"}]=nil;_,ok:=m[K{Inner{%q},"y"}];return ok}`, a, b, a, query)
		type inner struct{ Package string }
		type key struct {
			Inner inner
			Name  string
		}
		m := map[key]*int{}
		n := map[key]*int{}
		if alias {
			n = m
		}
		m[key{inner{a}, "x"}] = nil
		pkg := a
		if branch {
			pkg = b
		}
		n[key{inner{pkg}, "y"}] = nil
		_, want := m[key{inner{query}, "y"}]
		in := regionFixture(t, text)
		in.normalReturns = true
		for _, alternatives := range []int{1, defaultRegionLimits().alternatives} {
			limits := defaultRegionLimits()
			limits.alternatives = alternatives
			proposal, err := proposeRegion(t.Context(), in, limits)
			if err != nil {
				t.Fatal(err)
			}
			c, err := checkRegion(t.Context(), in, proposal, limits)
			if err != nil {
				t.Fatal(err)
			}
			if alternatives == 1 && a != b {
				stringsJoined := false
				for _, states := range proposal.entries {
					for _, state := range states {
						for _, v := range state.values {
							stringsJoined = stringsJoined || v.kind == regionStrings
						}
					}
				}
				if !stringsJoined {
					t.Fatal("one-alternative oracle did not exercise string widening")
				}
			}
			if !regionMayReturnBool(c, want) {
				t.Fatalf("abstract relation omitted native lookup result %v", want)
			}
			if query != a && query != b {
				for _, out := range normalMapObservations(t, c) {
					got, known := regionBool(out.value)
					if !known || got {
						t.Fatal("disjoint nested projection did not establish absence")
					}
				}
			}
		}
	})
}

func TestRegionMapFramesDestinationsAndFactories(t *testing.T) {
	for _, text := range []string{
		`type M map[string]int;var G M;func F(p *map[string]int)bool{G=make(M);bad:=make(map[string]int);bad["bad"]=0;*p=bad;_,ok:=G["bad"];return ok}`,
		`type M map[string]int;var G M;func(m M)add(k string){G[k]=0};func F()bool{G=make(M);other:=make(M);other.add("bad");_,ok:=G["bad"];return ok}`,
		`var G map[string]int;func factory()func(){G["bad"]=0;return func(){}};func F()bool{G=make(map[string]int);_ = factory();_,ok:=G["bad"];return ok}`,
		`type M map[string]int;func(m M)alias(dst,src string){if _,ok:=m[src];ok{m[dst]=0}};func F()bool{m:=make(M);m["source"]=0;m.alias("bad","source");_,ok:=m["bad"];return ok}`,
		`func F()bool{m:=make(map[string]int);f:=func(){m["bad"]=0};f();_,ok:=m["bad"];return ok}`,
		`type K struct{_ string;Name string};func F()bool{m:=make(map[K]int);m[K{"a","same"}]=0;_,ok:=m[K{"b","same"}];return ok}`,
		`func F(n int)bool{var old map[string]int;for i:=0;i<n;i++{m:=make(map[string]int);if i==0{old=m;m["bad"]=0}};_,ok:=old["bad"];return ok}`,
	} {
		c, _, _ := proveNormalMap(t, text)
		if !regionMayReturnBool(c, true) {
			t.Fatal("reachable present key claimed absent", text)
		}
	}
	// A summary must retain a new caller cell only through its checked write
	// frame; its body also invalidates that cell when the actual argument aliases.
	for _, text := range []string{
		`func helper(m map[string]int){m["safe"]=0};func F()bool{m:=make(map[string]int);helper(m);f:=func(){m["bad"]=0};helper(m);f();_,ok:=m["bad"];return ok}`,
		`func helper(p *map[string]int,m map[string]int){*p=m};func F()bool{a:=make(map[string]int);b:=make(map[string]int);b["bad"]=0;helper(&a,b);_,ok:=a["bad"];return ok}`,
	} {
		c, _, _ := proveNormalMap(t, text)
		if !regionMayReturnBool(c, true) {
			t.Fatal("checked frame restored a written cell or lost a callable")
		}
	}
}

func TestRegionMapNormalizedLookupCondition(t *testing.T) {
	const text = `type P struct{Path string};var runtimePkg P;func F()bool{m:=make(map[string]int);m["runtime"]=0;p:=&runtimePkg;p.Path="other";key:=p.Path;if p==&runtimePkg{key="runtime"};_,ok:=m[key];return ok}`
	c, _, _ := proveNormalMap(t, text)
	if !regionMayReturnBool(c, true) {
		t.Fatal("raw path exclusion bypassed normalized key")
	}
}

func TestRegionMapNilAndOldBacking(t *testing.T) {
	c, _, _ := proveNormalMap(t, `func F()bool{var m map[string]int;_,ok:=m["x"];return ok}`)
	for _, out := range normalMapObservations(t, c) {
		v, known := regionBool(out.value)
		if !known || v {
			t.Fatal("nil lookup is not a miss")
		}
	}
	c, _, _ = proveNormalMap(t, `func F(){var m map[string]int;m["x"]=1}`)
	if len(c.observations) != 0 {
		t.Fatal("nil map update returned normally")
	}
	c, _, _ = proveNormalMap(t, `func F()bool{m:=make(map[string]int);old:=m;m=make(map[string]int);old["bad"]=0;_,ok:=m["bad"];return ok}`)
	for _, out := range normalMapObservations(t, c) {
		v, known := regionBool(out.value)
		if !known || v {
			t.Fatal("old alias changed fresh backing")
		}
	}
}
