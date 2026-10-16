package closure

import (
	"fmt"
	"go/types"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func regionGoComparisonPanics(compare func() bool) (panicked bool) {
	defer func() { panicked = recover() != nil }()
	_ = compare()
	return false
}

func TestRegionAggregateEqualityPanicsRefuse(t *testing.T) {
	type Cell struct{ X any }
	type Array [1]Cell
	type Nested struct{ Cells Array }
	for _, op := range []string{"==", "!="} {
		for _, shape := range []struct {
			name, declarations, value string
			compare                   func() bool
		}{
			{"struct", "", `struct{X any}{[]int{}}`, func() bool {
				v := struct{ X any }{[]int{}}
				if op == "==" {
					return v == v
				}
				return v != v
			}},
			{"nil-slice-field", "", `struct{X any}{([]int)(nil)}`, func() bool {
				v := struct{ X any }{([]int)(nil)}
				if op == "==" {
					return v == v
				}
				return v != v
			}},
			{"named-array", `type Cell struct{X any};type Array [1]Cell;`, `Array{{X:[]int{}}}`, func() bool {
				v := Array{{X: []int{}}}
				if op == "==" {
					return v == v
				}
				return v != v
			}},
			{"nested-named", `type Cell struct{X any};type Array [1]Cell;type Nested struct{Cells Array};`, `Nested{Cells:Array{{X:[]int{}}}}`, func() bool {
				v := Nested{Cells: Array{{X: []int{}}}}
				if op == "==" {
					return v == v
				}
				return v != v
			}},
		} {
			for _, invoke := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/invoke=%t", shape.name, op, invoke), func(t *testing.T) {
					if !regionGoComparisonPanics(shape.compare) {
						t.Fatal("direct Go execution did not reproduce the comparison panic")
					}
					t.Log("direct Go execution reproduced the comparison panic (recovered)")
					body := fmt.Sprintf(`v:=%s;if v %s v{return 1};return 2`, shape.value, op)
					source := shape.declarations + `func helper()int{` + body + `};func F()int{return helper()}`
					if invoke {
						source = shape.declarations + `type I interface{M()int};type S struct{};func(S)M()int{` + body + `};func F()int{var x I=S{};return x.M()}`
					}
					in := regionFixture(t, source)
					if !regionGoComparisonPanics(func() bool { _ = executeRegionConcrete(t, in); return false }) {
						t.Fatal("concrete SSA oracle did not reproduce the direct Go comparison panic")
					}
					proposal, err := proposeRegion(t.Context(), in, defaultRegionLimits())
					var checked *checkedRegion
					if err == nil {
						checked, err = checkRegion(t.Context(), in, proposal, defaultRegionLimits())
					}
					if err == nil || checked != nil {
						t.Fatal("checker accepted ordinary continuations for an aggregate comparison that panics")
					}
				})
			}
		}
	}
}

func TestRegionAggregateEqualityCheckerRejectsTopInvariant(t *testing.T) {
	in := regionFixture(t, `func helper()int{v:=struct{X any}{[]int{}};if v==v{return 1};return 2};func F()int{return helper()}`)
	var call *ssa.Call
	for _, ins := range in.entry.block.Instrs {
		if c, ok := ins.(*ssa.Call); ok {
			call = c
		}
	}
	if call == nil {
		t.Fatal("actual helper call missing")
	}
	k, err := newRegionKernel(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	target := call.Call.StaticCallee()
	id, err := k.invocationAt(call, target)
	if err != nil {
		t.Fatal(err)
	}
	proof := &regionCallProof{at: call, target: target, invocation: id, entries: map[*ssa.BasicBlock][]regionState{}}
	for _, block := range target.Blocks {
		proof.entries[block] = []regionState{{}}
	}
	proposal := &regionProposal{input: in, entries: map[*ssa.BasicBlock][]regionState{in.entry.block: {{}}}, calls: []*regionCallProof{proof}}
	if checked, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits()); checked != nil || err == nil {
		t.Fatal("independent checker accepted a complete top-invariant proof across a panicking comparison")
	}
}

func TestRegionConcreteInterfaceDynamicTypes(t *testing.T) {
	in := regionFixture(t, `type A struct{};type B struct{};func F()any{return A{}}`)
	a := in.root.Pkg.Pkg.Scope().Lookup("A").Type()
	b := in.root.Pkg.Pkg.Scope().Lookup("B").Type()
	iface := in.root.Signature.Results().At(0).Type()
	for _, tc := range []struct {
		name           string
		value          regionValue
		payload        any
		correct, wrong types.Type
	}{
		{"empty-named", regionValue{typ: a, kind: regionAggregate}, []any{}, a, b},
		{"typed-nil", regionValue{typ: types.NewPointer(a), kind: regionNil}, nil, types.NewPointer(a), types.NewPointer(b)},
		{"unknown-payload", regionUnknownValue(a), []any{}, a, b},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := regionValue{typ: iface, kind: regionInterface, elements: []regionValue{tc.value}}
			if !regionMatchesConcrete(value, regionState{}, regionConcreteInterface{typ: tc.correct, value: tc.payload}, 0) {
				t.Fatal("identical dynamic type did not match")
			}
			if regionMatchesConcrete(value, regionState{}, regionConcreteInterface{typ: tc.wrong, value: tc.payload}, 0) {
				t.Fatal("distinct dynamic type matched equal boxed payload")
			}
		})
	}
}

func TestRegionAggregateEqualitySafeControls(t *testing.T) {
	type Cell struct{ X int }
	type Array [2]Cell
	type Link struct {
		Next *Link
		X    int
	}
	for _, op := range []string{"==", "!="} {
		for _, tc := range []struct {
			name, declarations, value, setup string
			equal                            func() bool
		}{
			{"named-array", `type Cell struct{X int};type Array [2]Cell;`, `Array{{1},{2}}`, "", func() bool { v := Array{{1}, {2}}; return v == v }},
			{"recursive-pointer", `type Link struct{Next *Link;X int};`, `Link{X:1}`, `v.Next=&v;`, func() bool { v := Link{X: 1}; v.Next = &v; return v == v }},
			{"pointer-to-interface-aggregate", "", `&struct{X any}{[]int{}}`, "", func() bool { v := &struct{ X any }{[]int{}}; return v == v }},
			{"zero-interface-array", "", `[0]any{}`, "", func() bool { v := [0]any{}; return v == v }},
			{"nested-zero-array", "", `struct{Z [0]struct{X any}}{}`, "", func() bool { v := struct{ Z [0]struct{ X any } }{}; return v == v }},
			{"positive-array-of-zero-arrays", "", `[1][0]any{}`, "", func() bool { v := [1][0]any{}; return v == v }},
			{"blank-interface-field", "", `struct{_ any;X int}{[]int{},1}`, "", func() bool {
				v := struct {
					_ any
					X int
				}{[]int{}, 1}
				return v == v
			}},
		} {
			t.Run(tc.name+"/"+op, func(t *testing.T) {
				if regionGoComparisonPanics(tc.equal) || !tc.equal() {
					t.Fatal("Go control did not compare safely equal")
				}
				source := tc.declarations + fmt.Sprintf(`func F()bool{v:=%s;%sreturn v %s v}`, tc.value, tc.setup, op)
				in := regionFixture(t, source)
				checked, _ := proveRegionFixture(t, in)
				concrete := executeRegionConcrete(t, in)
				if concrete != (op == "==") {
					t.Fatalf("concrete equality=%v, want %t", concrete, op == "==")
				}
				assertRegionCovers(t, checked, concrete)
			})
		}
	}
}

func TestRegionEqualityTypeBounds(t *testing.T) {
	in := regionFixture(t, `func F()bool{return true}`)
	k, err := newRegionKernel(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	// Zero arrays and blank fields suppress evaluation, not Go's static
	// comparability requirement. These metadata queries do not claim that a
	// source comparison of the following incomparable types could type-check.
	for _, typ := range []types.Type{
		types.NewArray(types.NewSlice(types.Typ[types.Int]), 0),
		types.NewStruct([]*types.Var{types.NewField(0, nil, "_", types.NewSlice(types.Typ[types.Int]), false)}, nil),
	} {
		total, err := k.equalityTotal(typ, true, 0, map[types.Type]bool{})
		if err != nil || total {
			t.Fatalf("incomparable type granted totality: total=%t err=%v", total, err)
		}
	}
	var deep types.Type = types.Typ[types.Int]
	for i := 0; i < 8; i++ {
		deep = types.NewArray(deep, 1)
	}
	k.meter.limits.depth = 2
	if total, err := k.equalityTotal(deep, true, 0, map[types.Type]bool{}); total || err == nil {
		t.Fatal("equality traversal ignored depth budget")
	}
	// Malformed by-value recursion cannot occur in checked Go source; the
	// defensive active-set check must nevertheless terminate such metadata.
	cyclic := types.NewNamed(types.NewTypeName(0, nil, "InvalidCycle", nil), nil, nil)
	cyclic.SetUnderlying(types.NewStruct([]*types.Var{types.NewField(0, nil, "X", cyclic, false)}, nil))
	if total, err := k.equalityTotal(cyclic, true, 0, map[types.Type]bool{}); total || err == nil {
		t.Fatal("recursive by-value type did not refuse")
	}
}

func TestRegionConcreteBoxConstructionPreservesDynamicType(t *testing.T) {
	for _, source := range []string{
		`type A struct{};func F()any{return A{}}`,
		`type A struct{};func F()any{var p *A;return p}`,
		`type I interface{M()};type A struct{};func(A)M(){};func F()any{var x I=A{};return x}`,
		`type A struct{};func box()any{return A{}};func F()any{return box()}`,
	} {
		t.Run(source, func(t *testing.T) {
			in := regionFixture(t, source)
			concrete, ok := executeRegionConcrete(t, in).(regionConcreteInterface)
			if !ok {
				t.Fatal("source interface did not produce a concrete box")
			}
			want := in.root.Pkg.Pkg.Scope().Lookup("A").Type()
			if concrete.value == nil {
				want = types.NewPointer(want)
			}
			if !types.Identical(concrete.typ, want) {
				t.Fatalf("boxed dynamic type=%v,want %v", concrete.typ, want)
			}
			checked, _ := proveRegionFixture(t, in)
			assertRegionCovers(t, checked, concrete)
		})
	}
}
