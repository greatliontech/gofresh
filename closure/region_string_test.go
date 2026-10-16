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

func TestRegionStringConcreteOracle(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"length-bytes", `func size(s string)int{return len(s)};func F()int{return size("é\x00\xff")}`},
		{"named-length", `type Label string;func size(s Label)int{return len(s)};func F()int{return size("é")}`},
		{"named-slice", `type Label string;func cut(s Label)Label{return s[1:3]};func F()Label{return cut("xéz")}`},
		{"slice-byte-fragment", `func cut(s string)string{return s[1:2]};func F()string{return cut("é")}`},
		{"slice-offset", `func cut(s string)string{return s[1:5][2:3]};func F()string{return cut("abcdef")}`},
		{"slice-index-offset", `func cut(s string)byte{return s[2:4][1]};func F()byte{return cut("abcdef")}`},
		{"byte-not-rune", `type Label string;func at(s Label)byte{return s[1]};func F()byte{return at("é")}`},
		{"nul", `func at(s string)byte{return s[1]};func F()byte{return at("x\x00y")}`},
		{"invalid-utf8", `func at(s string)byte{return s[0]};func F()byte{return at("\xff")}`},
		{"empty", `func cut(s string)string{return s[:]};func F()string{return cut("")}`},
		{"end-empty", `func cut(s string)string{return s[len(s):]};func F()string{return cut("abc")}`},
		{"explicit-end", `func cut(s string)string{return s[3:3]};func F()string{return cut("abc")}`},
		{"default-low", `func cut(s string)string{return s[:2]};func F()string{return cut("abc")}`},
		{"default-high", `func cut(s string)string{return s[1:]};func F()string{return cut("abc")}`},
		{"wide-index-type", `type Index uint64;func at(s string,i Index)byte{return s[i]};func F()byte{return at("ab",1)}`},
		{"named-bounds", `type Index int16;func cut(s string,a,b Index)string{return s[a:b]};func F()string{return cut("abc",1,3)}`},
		{"harmless-library-name", `func HasPrefix(s,p string)bool{return len(s)>=len(p)&&s[:len(p)]==p};func F()bool{return HasPrefix("test.short","-")}`},
		{"shadowed-builtin", `func len(s string)int{return 17};func F()int{return len("abc")}`},
		{"harmless-native-name", `func IndexByteString(s string,c byte)byte{return s[1]};func F()byte{return IndexByteString("ab",0)}`},
		{"arbitrary-name", `func unrelated(s,p string)bool{return len(s)>=len(p)&&s[:len(p)]==p};func F()bool{return unrelated("\x00\xff","\x00")}`},
		{"short-circuit", `func unrelated(s,p string)bool{return len(s)>=len(p)&&s[:len(p)]==p};func F()bool{return unrelated("","-")}`},
		{"empty-prefix", `func unrelated(s,p string)bool{return len(s)>=len(p)&&s[:len(p)]==p};func F()bool{return unrelated("","")}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := regionFixture(t, tc.source)
			checked, _ := proveRegionFixture(t, in)
			for _, out := range checked.observations {
				if out.value.kind != regionConstant || !types.Identical(out.value.typ, in.use.operand.Type()) {
					t.Fatal("string operation lost its exact result or Go type")
				}
			}
			assertRegionCovers(t, checked, executeRegionConcrete(t, in))
		})
	}
}

// Supply actual parameter constants rather than source literals: the frontend
// must retain the operations, including dynamically invalid bounds, in SSA.
func regionStringArguments(in regionInput, text string, bounds ...int64) regionInput {
	in.initial.values = map[ssa.Value]regionValue{}
	for i, p := range in.root.Params {
		var value constant.Value
		if i == 0 {
			value = constant.MakeString(text)
		} else {
			value = constant.MakeInt64(bounds[i-1])
		}
		in.initial.values[p] = regionValue{typ: p.Type(), kind: regionConstant, scalar: value}
	}
	return in
}

func TestRegionStringBounds(t *testing.T) {
	for _, text := range []string{"", "a", "é\x00\xff"} {
		for low := int64(-1); low <= int64(len(text))+1; low++ {
			for high := int64(-1); high <= int64(len(text))+1; high++ {
				t.Run(fmt.Sprintf("%q/%d/%d", text, low, high), func(t *testing.T) {
					in := regionStringArguments(regionFixture(t, `type Label string;func F(s Label,lo,hi int)Label{return s[lo:hi]}`), text, low, high)
					var expected string
					panics := regionStringPanics(func() { expected = text[low:high] })
					p, err := proposeRegion(t.Context(), in, defaultRegionLimits())
					if panics {
						if err == nil || p != nil {
							t.Fatal("panicking string slice acquired a proof")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					checked, err := checkRegion(t.Context(), in, p, defaultRegionLimits())
					if err != nil {
						t.Fatal(err)
					}
					assertRegionStringExact(t, checked, expected)
				})
			}
			in := regionStringArguments(regionFixture(t, `func F(s string,i int)byte{return s[i]}`), text, low)
			var expected int64
			panics := regionStringPanics(func() { expected = int64(text[low]) })
			p, err := proposeRegion(t.Context(), in, defaultRegionLimits())
			if panics {
				if err == nil || p != nil {
					t.Fatal("panicking string index acquired a proof")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				checked, err := checkRegion(t.Context(), in, p, defaultRegionLimits())
				if err != nil {
					t.Fatal(err)
				}
				assertRegionStringExact(t, checked, expected)
			}
		}
	}
	for _, expression := range []string{"s[i]", "s[:i]", "s[i:]"} {
		result := "string"
		if expression == "s[i]" {
			result = "byte"
		}
		in := regionStringArguments(regionFixture(t, "func F(s string,i uint64)"+result+"{return "+expression+"}"), "abc", 0)
		parameter := in.root.Params[1]
		in.initial.values[parameter] = regionValue{typ: parameter.Type(), kind: regionConstant, scalar: constant.MakeUint64(^uint64(0))}
		if p, err := proposeRegion(t.Context(), in, defaultRegionLimits()); p != nil || err == nil {
			t.Fatal("overflowing index wrapped into the string extent")
		}
	}
}

func regionStringPanics(run func()) (panics bool) {
	defer func() { panics = recover() != nil }()
	run()
	return false
}

func assertRegionStringExact(t testing.TB, checked *checkedRegion, expected any) {
	t.Helper()
	if len(checked.observations) != 1 || checked.observations[0].value.kind != regionConstant {
		t.Fatal("string result is not exact")
	}
	assertRegionCovers(t, checked, expected)
}

func TestRegionStringUnknownAndEffects(t *testing.T) {
	for _, source := range []string{
		`func F(s string)byte{return s[0]}`,
		`func F(s string)string{return s[:1]}`,
		`func F(s string)string{return s[:]}`,
		`func F(i int)byte{s:="abc";return s[i]}`,
		`func F(i int)string{s:="abc";return s[i:]}`,
		`func F(i int)string{s:="abc";return s[:i]}`,
		`func check(s,p string)bool{return len(s)>=len(p)&&s[:len(p)]==p};func F(s string)bool{return check(s,"-")}`,
		`func native();func HasPrefix(s,p string)bool{native();return false};func F()bool{return HasPrefix("test.short","-")}`,
		`func check(s,p string)bool{return len(s)>=len(p)&&s[:len(p)]==p};func F()bool{if check("-bad","-"){panic("bad name")};return true}`,
	} {
		t.Run(source, func(t *testing.T) {
			in := regionFixture(t, source)
			if p, err := proposeRegion(t.Context(), in, defaultRegionLimits()); p != nil || err == nil {
				t.Fatal("unproved bounds or reachable panic/effect disappeared")
			}
		})
	}
	in := regionFixture(t, `type Label string;func F(s Label)int{return len(s)}`)
	checked, _ := proveRegionFixture(t, in)
	if checked.observations[0].value.kind != regionUnknown {
		t.Fatal("unknown string length acquired a constant")
	}
	for _, text := range []string{"", "abc", "é\x00\xff"} {
		assertRegionCovers(t, checked, executeRegionConcrete(t, in, text))
	}
}

func TestRegionStringForgedPrefix(t *testing.T) {
	const source = `var g string;func prefix(s,p string)bool{g=s;return len(s)>=len(p)&&s[:len(p)]==p};func consume(string){};func F(s string){if prefix(s,"-"){panic("bad name")};consume(g)}`
	for _, corruption := range []string{"call", "store", "argument", "operand", "excluded-edge"} {
		t.Run(corruption, func(t *testing.T) {
			in := regionStringArguments(regionFixture(t, source), "test.short")
			in = regionAtCall(t, in, "consume", 0)
			checked, p := proveRegionFixture(t, in)
			assertRegionStringExact(t, checked, "test.short")
			switch corruption {
			case "call":
				p.calls = nil
			case "store":
				g := in.root.Pkg.Members["g"].(*ssa.Global)
				// Claim the successor heap still contains a pre-call value.
				for block, states := range p.entries {
					if block != in.entry.block {
						for _, state := range states {
							state.memory[regionObject{kind: regionGlobal, site: g}] = regionValue{typ: types.Typ[types.String], kind: regionConstant, scalar: constant.MakeString("old")}
						}
					}
				}
			case "argument":
				in = regionStringArguments(in, "changed")
			case "operand":
				in.use.operand = in.root.Params[0]
			case "excluded-edge":
				in = regionStringArguments(in, "-bad")
				// Matching the declared input is not permission to reuse the
				// old call proof or omit the now reachable panic branch.
				p.input = in
				p.entries[in.entry.block] = []regionState{in.initial}
			}
			if packet, err := checkRegion(t.Context(), in, p, defaultRegionLimits()); packet != nil || err == nil {
				t.Fatal("forged prefix acquired authority")
			}
		})
	}
}

func TestRegionStringOwnershipAndBounds(t *testing.T) {
	in := regionStringArguments(regionFixture(t, `func F(s string,lo,hi int)string{return s[lo:hi]}`), "abcdef", 2, 4)
	_, p := proveRegionFixture(t, in)
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() {
		clear(in.initial.values)
		clear(p.input.initial.values)
		for _, states := range p.entries {
			for _, state := range states {
				clear(state.values)
			}
		}
	}}
	checked, err := checkRegion(ctx, in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	assertRegionStringExact(t, checked, "cd")
	in = regionStringArguments(in, "abcdef", 2, 4)
	_, p = proveRegionFixture(t, in)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if c, err := checkRegion(cancelled, in, p, defaultRegionLimits()); c != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled string check: %v", err)
	}
	counted := &regionCallCountingContext{Context: t.Context()}
	if _, err := checkRegion(counted, in, p, defaultRegionLimits()); err != nil {
		t.Fatal(err)
	}
	interrupted := &regionCallCountingContext{Context: t.Context(), stop: counted.checks / 2}
	if c, err := checkRegion(interrupted, in, p, defaultRegionLimits()); c != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted string check: %v", err)
	}
	for _, dimension := range []string{"storage", "work"} {
		limits := defaultRegionLimits()
		if dimension == "storage" {
			in = regionStringArguments(in, strings.Repeat("x", limits.locations+1), 0, 1)
		} else {
			in = regionStringArguments(in, "abcdef", 2, 4)
			limits.work = 1
		}
		if c, err := proposeRegion(t.Context(), in, limits); c != nil || err == nil {
			t.Fatal("string budget exhaustion yielded a proof")
		}
	}
}

func FuzzRegionStringOperations(f *testing.F) {
	f.Add("é\x00\xff", int8(1), int8(3), int8(0))
	f.Add("abc", int8(3), int8(3), int8(0))
	f.Add("", int8(0), int8(0), int8(-1))
	f.Add("test.short", int8(0), int8(1), int8(0))
	f.Fuzz(func(t *testing.T, text string, low, high, index int8) {
		if len(text) > 32 {
			text = text[:32]
		}
		// Small signed bounds include both ends and panics without large
		// allocations. Expected results execute Go operations independently.
		lo, hi, at := int64(low%35), int64(high%35), int64(index%35)
		for _, operation := range []string{"len", "slice", "index", "slice-index"} {
			var source string
			var expected any
			var in regionInput
			panics := regionStringPanics(func() {
				switch operation {
				case "len":
					expected = int64(len(text))
				case "slice":
					expected = text[lo:hi]
				case "index":
					expected = int64(text[at])
				case "slice-index":
					expected = int64(text[lo:hi][at])
				}
			})
			switch operation {
			case "len":
				source = `func F(s string,lo,hi,i int)int{return len(s)}`
			case "slice":
				source = `type Label string;func F(s Label,lo,hi,i int)Label{return s[lo:hi]}`
			case "index":
				source = `func F(s string,lo,hi,i int)byte{return s[i]}`
			case "slice-index":
				source = `func F(s string,lo,hi,i int)byte{return s[lo:hi][i]}`
			}
			in = regionStringArguments(regionFixture(t, source), text, lo, hi, at)
			p, err := proposeRegion(t.Context(), in, defaultRegionLimits())
			if panics {
				if err == nil || p != nil {
					t.Fatalf("%s panic acquired proof", operation)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			checked, err := checkRegion(t.Context(), in, p, defaultRegionLimits())
			if err != nil {
				t.Fatal(err)
			}
			assertRegionStringExact(t, checked, expected)
			assertRegionCovers(t, checked, executeRegionConcrete(t, in, text, lo, hi, at))
		}
	})
}

func assertRegionStringActualFlagPrefix(t *testing.T, source computationSource, construction *sourceRegion, varCall *ssa.Call) {
	t.Helper()
	in := regionViewEnterCall(t, construction, varCall)
	in, contains := regionViewStopCall(t, in, "Contains")
	if len(contains.Call.Args) != 2 || contains.Call.Args[0] != in.root.Params[2] {
		t.Fatal("Contains no longer consumes the actual Var name")
	}
	in.use.operand = contains.Call.Args[0]
	prefix := regionViewSourcePrefix(t, source, in)
	assertRegionStringExact(t, prefix.packet, "test.short")
	if prefix.packet.input.initial.values[in.root.Params[0]].kind != regionUnknown {
		t.Fatal("unknown CommandLine receiver acquired an entry/frame fact")
	}
	_, guard := regionViewStopCall(t, in, "HasPrefix")
	_, inner := regionViewStopCall(t, regionInput{root: guard.Call.StaticCallee()}, "HasPrefix")
	if len(prefix.calls) != 2 {
		t.Fatal("first guard did not check both selected source callees")
	}
	for _, call := range []*ssa.Call{guard, inner} {
		found := false
		for _, dependency := range prefix.calls {
			if dependency.call.at == call && dependency.call.target == call.Call.StaticCallee() && dependency.bound.identity.body != ([32]byte{}) {
				found = true
			}
		}
		if !found {
			t.Fatal("first guard lost its actual selected body/context")
		}
	}
	k, err := newRegionKernel(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	out := prefix.packet.observations[0]
	if b, known := regionBool(k.value(out.state, guard)); !known || b {
		t.Fatal("first guard was not derived false from its actual name")
	}
	if !regionMatchesConcrete(k.value(out.state, contains.Call.Args[1]), out.state, "=", 0) {
		t.Fatal("Contains search operand changed")
	}
	if !slices.Equal(prefix.packet.input.premises[:len(construction.packet.input.premises)], construction.packet.input.premises) {
		t.Fatal("prefix discarded incoming initialization/native/harness premises")
	}
	for _, name := range []string{"-bad", "unknown"} {
		changed := in
		m := regionMeter{limits: defaultRegionLimits()}
		changed.initial, err = m.copyState(in.initial)
		if err != nil {
			t.Fatal(err)
		}
		parameter := in.root.Params[2]
		v := regionUnknownValue(parameter.Type())
		if name != "unknown" {
			v.kind, v.scalar = regionConstant, constant.MakeString(name)
		}
		changed.initial.values[parameter] = v
		if p, err := proposeRegion(t.Context(), changed, defaultRegionLimits()); p != nil || err == nil {
			t.Fatal("bad/unknown actual flag name erased a reachable panic/effect")
		} else {
			t.Logf("actual Var name %q refusal: %v", name, err)
		}
	}
	t.Logf("checked actual Var prefix through %s, consuming %s with name test.short and search =", guard, contains)
	// Continue only through actual call boundaries. No Contains/Index result or
	// receiver frame is invented; each source prefix binds the selected root.
	previous, call := prefix, contains
	for _, next := range []string{"Index", "Index", "IndexByte", "IndexByteString"} {
		segment := regionViewEnterCall(t, previous, call)
		var body strings.Builder
		segment.root.WriteTo(&body)
		t.Log(body.String())
		segment, call = regionViewStopCall(t, segment, next)
		segment.use.operand = call.Call.Args[0]
		previous = regionViewSourcePrefix(t, source, segment)
		assertRegionStringExact(t, previous.packet, "test.short")
	}
	nativeInput := previous.packet.input
	k, err = newRegionKernel(t.Context(), nativeInput, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	state := previous.packet.observations[0].state
	if len(call.Call.Args) != 2 || !regionMatchesConcrete(k.value(state, call.Call.Args[1]), state, int64('='), 0) || !types.Identical(call.Call.Args[1].Type(), types.Typ[types.Uint8]) {
		t.Fatal("actual byte-search operand was not the byte =")
	}
	for _, block := range nativeInput.root.Blocks {
		for i, instruction := range block.Instrs {
			if ret, ok := instruction.(*ssa.Return); ok {
				nativeInput.use = regionUse{regionPoint{block, i}, ret.Results[0]}
			}
		}
	}
	if p, err := proposeRegion(t.Context(), nativeInput, defaultRegionLimits()); p != nil || err == nil {
		t.Fatal("native byte-search continuation acquired a summary")
	} else {
		t.Logf("checked prefix ends before %s; continuation refusal: %v", call, err)
	}
}
