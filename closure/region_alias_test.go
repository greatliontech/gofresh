package closure

import (
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func TestRegionMapTagConvertedIncomingAliases(t *testing.T) {
	type A map[struct {
		S string `kind:"a"`
	}]int
	type B map[struct {
		S string `kind:"b"`
	}]int
	for _, body := range []string{
		`m[struct{S string "kind:\"b\""}{"bad"}]=1`,
		`write(m)`,
		`outer(m);outer(m);outer(m)`,
	} {
		for _, mode := range []string{"separate", "unknown-alias", "known-alias"} {
			alias := mode != "separate"
			g := make(A)
			m := make(B)
			if alias {
				m = B(g)
			}
			m[struct {
				S string `kind:"b"`
			}{"bad"}] = 1
			_, want := g[struct {
				S string `kind:"a"`
			}{"bad"}]
			text := `type A map[struct{S string "kind:\"a\""}]int;type B map[struct{S string "kind:\"b\""}]int;var G A;func seedA()A{return make(A)};func seedB()B{return make(B)};func write(m B){m[struct{S string "kind:\"b\""}{"bad"}]=1};func outer(m B){write(m)};func F(m B)bool{` + body + `;_,ok:=G[struct{S string "kind:\"a\""}{"bad"}];return ok}`
			in := regionFixture(t, text)
			in.normalReturns = true
			backing := func(name string) regionObject {
				fn := in.root.Pkg.Func(name)
				for _, block := range fn.Blocks {
					for _, ins := range block.Instrs {
						if makeMap, ok := ins.(*ssa.MakeMap); ok {
							return regionObject{kind: regionMapAllocation, site: makeMap, context: fn}
						}
					}
				}
				t.Fatal("missing actual incoming allocation site", name)
				return regionObject{}
			}
			a, b := backing("seedA"), backing("seedB")
			global := in.root.Pkg.Members["G"].(*ssa.Global)
			in.initial = regionState{values: map[ssa.Value]regionValue{}, memory: map[regionObject]regionValue{
				a:                                  {typ: a.site.Type(), kind: regionMapContents, keys: &regionMapKeys{empty: true}},
				{kind: regionGlobal, site: global}: {typ: a.site.Type(), kind: regionMap, location: regionLocation{object: a}},
			}}
			in.premises = append(in.premises, "G is initially empty; the incoming map may be a tag-ignoring conversion of G")
			if !alias {
				in.initial.values[in.root.Params[0]] = regionValue{typ: b.site.Type(), kind: regionMap, location: regionLocation{object: b}}
				in.initial.memory[b] = regionValue{typ: b.site.Type(), kind: regionMapContents, keys: &regionMapKeys{empty: true}}
			} else if mode == "known-alias" {
				in.initial.values[in.root.Params[0]] = regionValue{typ: b.site.Type(), kind: regionMap, location: regionLocation{object: a}}
			}
			p, err := proposeRegion(t.Context(), in, defaultRegionLimits())
			if err != nil {
				t.Fatal(err)
			}
			c, err := checkRegion(t.Context(), in, p, defaultRegionLimits())
			if err != nil {
				t.Fatal(err)
			}
			normalMapObservations(t, c)
			if !regionMayReturnBool(c, want) {
				t.Fatalf("tag-converted incoming alias omitted native result %v (%s)", want, body)
			}
			if !alias {
				for _, out := range c.observations {
					got, known := regionBool(out.value)
					if !known || got {
						t.Fatal("separate backing lost its checked frame")
					}
				}
			}
			if strings.Count(body, "outer") > 1 && c.usage.reused == 0 {
				t.Fatal("call-frame control did not reuse checked evidence")
			}
		}
	}
}

func TestRegionMapRejectsEscapingBitViews(t *testing.T) {
	// The concrete execution changes the canonical integer through the map's
	// pointer payload. Projecting that payload away must not preserve zero.
	x := uint64(0)
	m := map[string]*float64{"x": (*float64)(unsafe.Pointer(&x))}
	*m["x"] = 1
	if x == 0 {
		t.Fatal("native collection alias control did not write storage")
	}
	for index, text := range []string{
		`import "unsafe";func F()bool{x:=uint64(0);m:=make(map[string]*float64);m["x"]=(*float64)(unsafe.Pointer(&x));p:=m["x"];*p=1;return x==0}`,
		`import "unsafe";func F(){x:=uint64(0);m:=make(map[string]struct{P *float64});m["x"]=struct{P *float64}{(*float64)(unsafe.Pointer(&x))}}`,
		`import "unsafe";func F(){x:=uint64(0);m:=make(map[*float64]int);m[(*float64)(unsafe.Pointer(&x))]=1}`,
	} {
		_, in := regionFloatInput(t, text)
		in.normalReturns = true
		_, err := proposeRegion(t.Context(), in, defaultRegionLimits())
		if err == nil || !strings.Contains(err.Error(), "storage view cannot escape") {
			t.Fatal("unmodeled collection escape lacked a view refusal", err)
		}
		var failure *regionOperationFailure
		if !errors.As(err, &failure) {
			t.Fatal("escape refusal lost its actual operation", err)
		}
		if index == 1 {
			if _, ok := failure.instruction.(*ssa.Store); !ok {
				t.Fatal("aggregate escape did not fail at its storage boundary", err)
			}
		} else if _, ok := failure.instruction.(*ssa.MapUpdate); !ok {
			t.Fatal("collection escape did not fail at the actual map update", err)
		}
	}
}

func TestRegionUnknownWritesRetainConditionalBitAliases(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		native     func() bool
	}{
		{"widened64", `import "unsafe";func F(flag bool)bool{x,y:=uint64(0),uint64(0);p:=(*float64)(unsafe.Pointer(&x));if flag{p=(*float64)(unsafe.Pointer(&y))};*p=1;return x==0&&y==0}`, func() bool {
			x, y := uint64(0), uint64(0)
			p := (*float64)(unsafe.Pointer(&y))
			*p = 1
			return x == 0 && y == 0
		}},
		{"widened32", `import "unsafe";func F(flag bool)bool{x,y:=uint32(0),uint32(0);p:=(*float32)(unsafe.Pointer(&x));if flag{p=(*float32)(unsafe.Pointer(&y))};*p=1;return x==0&&y==0}`, func() bool {
			x, y := uint32(0), uint32(0)
			p := (*float32)(unsafe.Pointer(&x))
			*p = 1
			return x == 0 && y == 0
		}},
		{"widened-call", `import "unsafe";func set(p *float64){*p=1};func F(flag bool)bool{x,y:=uint64(0),uint64(0);p:=(*float64)(unsafe.Pointer(&x));if flag{p=(*float64)(unsafe.Pointer(&y))};set(p);return x==0&&y==0}`, func() bool {
			x, y := uint64(0), uint64(0)
			set := func(p *float64) { *p = 1 }
			set((*float64)(unsafe.Pointer(&x)))
			return x == 0 && y == 0
		}},
		{"incoming", `var G uint64;func F(p *float64)bool{G=0;*p=1;return G==0}`, func() bool { g := uint64(0); p := (*float64)(unsafe.Pointer(&g)); g = 0; *p = 1; return g == 0 }},
		{"incoming-reverse", `var G float64;func F(p *uint64)bool{G=0;*p=1;return G==0}`, func() bool { g := float64(0); p := (*uint64)(unsafe.Pointer(&g)); *p = 1; return g == 0 }},
		{"incoming-extent", `var G [2]uint32;func F(p *float64)bool{G=[2]uint32{};*p=1;return G[0]==0&&G[1]==0}`, func() bool {
			// No incoming provenance establishes a single canonical leaf.
			var g [2]uint32
			*(*float64)(unsafe.Pointer(&g)) = 1
			return g[0] == 0 && g[1] == 0
		}},
		{"aggregate", `var G struct{Pad uint32;W [2]uint64};func F(p *float64)bool{G=struct{Pad uint32;W [2]uint64}{};*p=1;return G.W[1]==0}`, func() bool {
			var g struct {
				Pad uint32
				W   [2]uint64
			}
			p := (*float64)(unsafe.Pointer(&g.W[1]))
			*p = 1
			return g.W[1] == 0
		}},
		{"nested-reuse", `var G uint64;func set(p *float64){*p=1};func outer(p *float64){set(p)};func F(p *float64)bool{G=0;outer(p);G=0;outer(p);return G==0}`, func() bool {
			g := uint64(0)
			set := func(p *float64) { *p = 1 }
			p := (*float64)(unsafe.Pointer(&g))
			set(p)
			g = 0
			set(p)
			return g == 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.native()
			if want {
				t.Fatal("native bit-view control did not change zero")
			}
			_, in := regionFloatInput(t, tc.text)
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
			normalMapObservations(t, c)
			if !regionMayReturnBool(c, want) {
				t.Fatal("unknown write preserved stale canonical bits")
			}
			if c.input.storageModel != in.storageModel {
				t.Fatal("conditional storage antecedent was dropped")
			}
			if tc.name == "nested-reuse" && c.usage.reused == 0 {
				t.Fatal("bit-view frame was not reused")
			}
		})
	}
}
