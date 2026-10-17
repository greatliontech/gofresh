package nativeproof

import (
	"context"
	"errors"
	"math"
	"math/big"
	"math/bits"
	"reflect"
	"testing"
	"unicode/utf16"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func inputTerm(t testing.TB, b *br.Builder, scope br.Scope, slot uint64, width int) br.Term {
	t.Helper()
	v, err := b.Input(br.Bits(width), scope, slot)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func relationBindings(t testing.TB, masks Masks) ([]InputBinding, map[Register]br.Term) {
	t.Helper()
	b, scope := br.NewBuilder(4096), br.NewScope()
	var inputs []InputBinding
	terms := make(map[Register]br.Term)
	for reg, mask := range masks {
		if mask == 0 {
			continue
		}
		width := bits.Len64(mask)
		if mask != ^uint64(0)>>(64-width) {
			t.Fatal("test helper expects low contiguous input mask")
		}
		term := inputTerm(t, b, scope, uint64(reg), width)
		inputs = append(inputs, InputBinding{Register: Register(reg), Value: term})
		terms[Register(reg)] = term
	}
	return inputs, terms
}

// Evaluate with independently chosen arbitrary scratch values. Variable identity
// comes from the opaque term itself, never from a printed register/source name.
func evalRelationTerm(t testing.TB, term br.Term, values map[br.Term]uint64, scratch uint64) uint64 {
	t.Helper()
	seen := make(map[br.Term]bool)
	stack := []br.Term{term}
	var assignments []br.Assignment
	for len(stack) > 0 {
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[v] {
			continue
		}
		seen[v] = true
		view := v.View()
		if view.Op == br.Variable {
			value, ok := values[v]
			if !ok {
				if !view.Scratch {
					t.Fatal("unbound non-scratch relation input")
				}
				value = scratch
				if view.Sort.IsBool() {
					value &= 1
				} else {
					value &= mask(view.Sort.Width())
				}
			}
			assignments = append(assignments, br.Assignment{Variable: v, Value: value})
		}
		stack = append(stack, view.Args...)
	}
	v, err := br.Eval(t.Context(), term, assignments, br.Limits{Nodes: 32768, Work: 1_000_000})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type resultInterval struct {
	register      Register
	offset, width int
}

// Enumerate individual declared bits rather than duplicating the production
// trailing-zero/mask-removal algorithm. Adjacent declared bits form one expected
// interval; gaps and register boundaries end it.
func expectedResultIntervals(masks Masks) []resultInterval {
	var want []resultInterval
	for reg, observed := range masks {
		start := -1
		for bit := 0; bit <= 64; bit++ {
			set := bit < 64 && observed&(uint64(1)<<bit) != 0
			if set && start < 0 {
				start = bit
			}
			if !set && start >= 0 {
				want = append(want, resultInterval{Register(reg), start, bit - start})
				start = -1
			}
		}
	}
	return want
}

func assertResultInventory(t testing.TB, masks Masks, results []RegisterValue) {
	t.Helper()
	want := expectedResultIntervals(masks)
	got := make([]resultInterval, 0, len(results))
	for _, result := range results {
		got = append(got, resultInterval{result.Register, result.Offset, result.Value.Sort().Width()})
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("incomplete or changed result inventory: got %+v want %+v", got, want)
	}
}

func TestExpectedResultIntervals(t *testing.T) {
	for _, tt := range []struct {
		masks Masks
		want  []resultInterval
	}{
		{Masks{RAX: math.MaxUint64, RBX: 0xff}, []resultInterval{{RAX, 0, 64}, {RBX, 0, 8}}},
		{Masks{RAX: 0xffffffff, RBX: 0xffffffff}, []resultInterval{{RAX, 0, 32}, {RBX, 0, 32}}},
		{Masks{RAX: 0xff00ff, R15: 1 << 63}, []resultInterval{{RAX, 0, 8}, {RAX, 16, 8}, {R15, 63, 1}}},
		{Masks{}, nil},
	} {
		if got := expectedResultIntervals(tt.masks); !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("got %+v want %+v", got, tt.want)
		}
	}
}

func assertKernelRelation(t testing.TB, im *Image, entry uint64, kernel int) {
	t.Helper()
	k := kernels[kernel]
	inputs, terms := relationBindings(t, k.inputs)
	r, err := DeriveRelation(t.Context(), im, entry, face(k.inputs, k.results), inputs, RelationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	bound, ok := r.Bound()
	if !ok || bound.ImageDigest != im.digest || bound.Entry != entry || r.Rules() != ValueRules {
		t.Fatal("missing complete native relation dependencies")
	}
	results := r.Results()
	assertResultInventory(t, k.results, results)
	for _, x := range []uint64{0, 1, 0x7f, 0xd7ff, 0xd800, 0xdfff, 0xe000, 0x10ffff, 0x110000, 0x1f600, 0x7fffffff, 0x80000000, math.MaxUint64} {
		for _, y := range []uint64{0, 1, 0x8000000000000000, math.MaxUint64} {
			values := make(map[br.Term]uint64)
			for reg, term := range terms {
				value := x
				if reg == RBX {
					value = y
				}
				values[term] = value & mask(term.Sort().Width())
			}
			want := make(map[Register]uint64)
			switch k.name {
			case "Add":
				want[RAX] = x + y
			case "AddCompare":
				want[RAX] = x + y
				if x+y < x {
					want[RBX] = 1
				}
			case "Branch":
				if x < y {
					want[RAX] = x + y
				} else {
					want[RAX] = x ^ y
				}
			case "Normalize":
				runeValue := rune(x)
				if runeValue < 0 || runeValue > 0x10ffff || utf16.IsSurrogate(runeValue) {
					runeValue = 0xfffd
				}
				want[RAX] = uint64(uint32(runeValue))
			case "IsSurrogate":
				if utf16.IsSurrogate(rune(x)) {
					want[RAX] = 1
				}
			case "EncodeRune":
				a, b := utf16.EncodeRune(rune(x))
				want[RAX], want[RBX] = uint64(uint32(a)), uint64(uint32(b))
			case "OnesCount64":
				want[RAX] = uint64(bits.OnesCount64(x))
			}
			for _, output := range results {
				for _, scratch := range []uint64{0, math.MaxUint64} {
					got := evalRelationTerm(t, output.Value, values, scratch)
					if got != want[output.Register] {
						t.Fatalf("%s(%#x,%#x) reg%d scratch=%#x: got %#x want %#x", k.name, x, y, output.Register, scratch, got, want[output.Register])
					}
				}
			}
		}
	}
}

func TestSevenNativeValueRelations(t *testing.T) {
	for j, k := range kernels {
		t.Run(k.name, func(t *testing.T) { assertKernelRelation(t, image(t, hexBytes(t, k.code)), testEntry, j) })
	}
}

func TestDefaultOptimizedNativeValueRelations(t *testing.T) {
	if testing.Short() {
		t.Skip("builds one ordinary optimized native value-relation fixture")
	}
	raw, _, entries := buildCompilerFixture(t)
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	for j, k := range kernels {
		t.Run(k.name, func(t *testing.T) {
			entry, ok := entries[kernelSymbol(k.name)]
			if !ok {
				t.Fatal("missing retained entry")
			}
			assertKernelRelation(t, im, entry, j)
		})
	}
}

func TestRelationExactAliasesAndShiftCounts(t *testing.T) {
	for _, tt := range []struct {
		name, code string
		input      Masks
		result     Masks
		values     map[Register]uint64
		want       uint64
	}{
		{"byte-preserves-high", "b001c3", Masks{RAX: math.MaxUint64}, Masks{RAX: math.MaxUint64}, map[Register]uint64{RAX: 0x123456789abcdef0}, 0x123456789abcde01},
		{"high-byte", "b412c3", Masks{RAX: math.MaxUint64}, Masks{RAX: math.MaxUint64}, map[Register]uint64{RAX: 0x123456789abcdef0}, 0x123456789abc12f0},
		{"word-preserves-high", "66b83412c3", Masks{RAX: math.MaxUint64}, Masks{RAX: math.MaxUint64}, map[Register]uint64{RAX: 0xabcdef1234567890}, 0xabcdef1234561234},
		{"32-zero-extension", "89c8c3", Masks{RCX: 0xffffffff}, Masks{RAX: math.MaxUint64}, map[Register]uint64{RCX: 0xfedcba98}, 0xfedcba98},
		{"high-to-low", "88e0c3", Masks{RAX: math.MaxUint64}, Masks{RAX: 0xff}, map[Register]uint64{RAX: 0x1280}, 0x12},
		{"masked-shift64", "48c1e840c3", Masks{RAX: math.MaxUint64}, Masks{RAX: math.MaxUint64}, map[Register]uint64{RAX: math.MaxUint64}, math.MaxUint64},
		{"masked-shift65", "48c1e841c3", Masks{RAX: math.MaxUint64}, Masks{RAX: math.MaxUint64}, map[Register]uint64{RAX: math.MaxUint64}, math.MaxUint64 >> 1},
		{"masked-shift32", "c1e820c3", Masks{RAX: 0xffffffff}, Masks{RAX: math.MaxUint64}, map[Register]uint64{RAX: 0xffffffff}, 0xffffffff},
		{"lea-wrap", "488d4458ffc3", Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}, Masks{RAX: math.MaxUint64}, map[Register]uint64{RAX: 0, RBX: math.MaxUint64}, math.MaxUint64 - 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			inputs, terms := relationBindings(t, tt.input)
			r, err := DeriveRelation(t.Context(), image(t, hexBytes(t, tt.code)), testEntry, face(tt.input, tt.result), inputs, RelationLimits{})
			if err != nil {
				t.Fatal(err)
			}
			values := make(map[br.Term]uint64)
			for reg, v := range tt.values {
				values[terms[reg]] = v
			}
			if got := evalRelationTerm(t, r.Results()[0].Value, values, math.MaxUint64); got != tt.want {
				t.Fatalf("got %#x want %#x", got, tt.want)
			}
		})
	}
}

func TestRelationSignedDisp32(t *testing.T) {
	f := face(Masks{RAX: math.MaxUint64}, Masks{RAX: math.MaxUint64})
	inputs, terms := relationBindings(t, f.Inputs)
	r, err := DeriveRelation(t.Context(), image(t, hexBytes(t, "488d80f8ffffffc3")), testEntry, f, inputs, RelationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []uint64{8, 0, 1, math.MaxUint64} {
		got := evalRelationTerm(t, r.Results()[0].Value, map[br.Term]uint64{terms[RAX]: x}, math.MaxUint64)
		if want := x - 8; got != want {
			t.Fatalf("LEA RAX,[RAX-8]; RET: x=%#x got=%#x want=%#x", x, got, want)
		}
	}
}

// big.Int supplies independent signed-overflow and unsigned-carry arithmetic.
func arithmeticFlags(op string, x, y uint64, width int) (carry, zero, sign, overflow bool) {
	m := mask(width)
	x &= m
	y &= m
	a, b := new(big.Int).SetUint64(x), new(big.Int).SetUint64(y)
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(width))
	unsigned := new(big.Int)
	if op == "add" {
		unsigned.Add(a, b)
		carry = unsigned.Cmp(modulus) >= 0
	} else {
		unsigned.Sub(a, b)
		carry = unsigned.Sign() < 0
	}
	unsigned.Mod(unsigned, modulus)
	zero = unsigned.Sign() == 0
	sign = unsigned.Bit(width-1) != 0
	if x>>(width-1) != 0 {
		a.Sub(a, modulus)
	}
	if y>>(width-1) != 0 {
		b.Sub(b, modulus)
	}
	signed := new(big.Int)
	if op == "add" {
		signed.Add(a, b)
	} else {
		signed.Sub(a, b)
	}
	max := new(big.Int).Lsh(big.NewInt(1), uint(width-1))
	min := new(big.Int).Neg(new(big.Int).Set(max))
	overflow = signed.Cmp(min) < 0 || signed.Cmp(max) >= 0
	return
}

func TestRelationArithmeticConditionsAgainstBigInts(t *testing.T) {
	for _, width := range []int{32, 64} {
		for _, op := range []string{"add", "cmp"} {
			inputs, terms := relationBindings(t, Masks{RAX: mask(width), RBX: mask(width)})
			for _, condition := range []struct {
				code byte
				want func(bool, bool, bool, bool) bool
			}{
				{0x97, func(c, z, s, o bool) bool { return !c && !z }}, {0x93, func(c, z, s, o bool) bool { return !c }},
				{0x92, func(c, z, s, o bool) bool { return c }}, {0x96, func(c, z, s, o bool) bool { return c || z }},
				{0x94, func(c, z, s, o bool) bool { return z }}, {0x95, func(c, z, s, o bool) bool { return !z }},
				{0x9c, func(c, z, s, o bool) bool { return s != o }}, {0x9e, func(c, z, s, o bool) bool { return z || s != o }},
				{0x9f, func(c, z, s, o bool) bool { return !z && s == o }}, {0x9d, func(c, z, s, o bool) bool { return s == o }},
			} {
				var code []byte
				if width == 64 {
					code = append(code, 0x48)
				}
				if op == "add" {
					code = append(code, 0x01, 0xd8)
				} else {
					code = append(code, 0x39, 0xd8)
				}
				code = append(code, 0x0f, condition.code, 0xc1, 0xc3) // SETcc CL; RET.
				r, err := DeriveRelation(t.Context(), image(t, code), testEntry, face(Masks{RAX: mask(width), RBX: mask(width)}, Masks{RCX: 0xff}), inputs, RelationLimits{})
				if err != nil {
					t.Fatal(err)
				}
				var population []uint64
				for j := uint64(0); j < 16; j++ {
					population = append(population, j)
				}
				population = append(population, mask(width), uint64(1)<<(width-1), (uint64(1)<<(width-1))-1)
				for _, x := range population {
					for _, y := range population {
						c, z, s, o := arithmeticFlags(op, x, y, width)
						want := uint64(0)
						if condition.want(c, z, s, o) {
							want = 1
						}
						got := evalRelationTerm(t, r.Results()[0].Value, map[br.Term]uint64{terms[RAX]: x, terms[RBX]: y}, math.MaxUint64)
						if got != want {
							t.Fatalf("%s%d condition%#x x%#x y%#x got%d want%d", op, width, condition.code, x, y, got, want)
						}
					}
				}
			}
		}
	}
}

func TestRelationIndependentMergesAndMultipleReturns(t *testing.T) {
	inputs, terms := relationBindings(t, Masks{RAX: math.MaxUint64, RCX: math.MaxUint64})
	for _, code := range []string{
		"4883f80074054889cbeb064831db909090c3",
		"4883f80074054831dbeb064889cb909090c3",
		"4883f80074044889cbc34831dbc3",
	} {
		im := image(t, hexBytes(t, code))
		r, err := DeriveRelation(t.Context(), im, testEntry, face(Masks{RAX: math.MaxUint64, RCX: math.MaxUint64}, Masks{RBX: math.MaxUint64}), inputs, RelationLimits{})
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range []uint64{0, 1, math.MaxUint64} {
			for _, y := range []uint64{0, 17, math.MaxUint64} {
				want, _ := runDiamond(t, im, x, y)
				got := evalRelationTerm(t, r.Results()[0].Value, map[br.Term]uint64{terms[RAX]: x, terms[RCX]: y}, 0)
				if got != want {
					t.Fatalf("%s x%d y%d got%d want%d", code, x, y, got, want)
				}
			}
		}
	}
}

func TestRelationLogicalAndShiftConditions(t *testing.T) {
	in := Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}
	inputs, terms := relationBindings(t, in)
	for _, tt := range []struct {
		code string
		want func(uint64, uint64) bool
	}{
		{"4821d80f9cc1c3", func(x, y uint64) bool { return int64(x&y) < 0 }},
		{"4831d80f97c1c3", func(x, y uint64) bool { return x^y != 0 }},
		{"48d1e80f9cc1c3", func(x, y uint64) bool { return x>>63 != 0 }},
		{"48c1e8020f92c1c3", func(x, y uint64) bool { return x&2 != 0 }},
		{"4839d848c1e8400f9cc1c3", func(x, y uint64) bool { return int64(x) < int64(y) }},
	} {
		r, err := DeriveRelation(t.Context(), image(t, hexBytes(t, tt.code)), testEntry, face(in, Masks{RCX: 0xff}), inputs, RelationLimits{})
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range []uint64{0, 1, 2, 3, math.MaxInt64, 1 << 63, math.MaxUint64} {
			for _, y := range []uint64{0, 1, 1 << 63, math.MaxUint64} {
				want := uint64(0)
				if tt.want(x, y) {
					want = 1
				}
				got := evalRelationTerm(t, r.Results()[0].Value, map[br.Term]uint64{terms[RAX]: x, terms[RBX]: y}, math.MaxUint64)
				if got != want {
					t.Fatalf("%s x=%#x y=%#x got%d want%d", tt.code, x, y, got, want)
				}
			}
		}
	}
}

func TestRelationExplicitInputAndResultBitMappings(t *testing.T) {
	b, scope := br.NewBuilder(1024), br.NewScope()
	x := inputTerm(t, b, scope, 0, 8)
	inputs := []InputBinding{{Register: RAX, Offset: 8, Value: x}}
	f := face(Masks{RAX: 0xff00}, Masks{RAX: 0xff})
	r, err := DeriveRelation(t.Context(), image(t, hexBytes(t, "88e0c3")), testEntry, f, inputs, RelationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for v := uint64(0); v < 256; v++ {
		for _, scratch := range []uint64{0, math.MaxUint64} {
			if got := evalRelationTerm(t, r.Results()[0].Value, map[br.Term]uint64{x: v}, scratch); got != v {
				t.Fatalf("high-byte input %d -> %d", v, got)
			}
		}
	}
	// Noncontiguous observed bits produce separate precisely offset projections.
	f.Results[RAX] = 0xff00ff
	f.Inputs[RAX] = 0xffffff
	full := inputTerm(t, b, scope, 1, 24)
	r, err = DeriveRelation(t.Context(), image(t, []byte{0xc3}), testEntry, f, []InputBinding{{Register: RAX, Value: full}}, RelationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	results := r.Results()
	if len(results) != 2 || results[0].Offset != 0 || results[1].Offset != 16 || results[0].Value.Sort() != br.Bits(8) || results[1].Value.Sort() != br.Bits(8) {
		t.Fatal("result projection widened gaps")
	}
	for j, want := range []uint64{0x56, 0x12} {
		if got := evalRelationTerm(t, results[j].Value, map[br.Term]uint64{full: 0x123456}, math.MaxUint64); got != want {
			t.Fatal(got, want)
		}
	}
	// A one-byte SET result cannot authorize a widened whole-register claim:
	// its untouched high bits were never inputs, even though low32 RAX was.
	narrowInputs, _ := relationBindings(t, Masks{RAX: 0xffffffff})
	wide := face(Masks{RAX: 0xffffffff}, Masks{RAX: math.MaxUint64})
	_, err = DeriveRelation(t.Context(), image(t, hexBytes(t, kernels[4].code)), testEntry, wide, narrowInputs, RelationLimits{})
	requireRefusal(t, Certificate{}, err, "result-input-bound")
}

func TestNativeRelationComposesOnlyThroughCheckedEquality(t *testing.T) {
	inputs, terms := relationBindings(t, Masks{RAX: math.MaxUint64, RBX: math.MaxUint64})
	f := face(Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}, Masks{RCX: 0xff})
	im := image(t, hexBytes(t, "4839d80f9cc1c3")) // CMP RAX,RBX; SETL CL.
	r, err := DeriveRelation(t.Context(), im, testEntry, f, inputs, RelationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b := br.NewBuilder(1024)
	predicate, err := b.Make(br.SLT, br.Bool(), 0, terms[RAX], terms[RBX])
	if err != nil {
		t.Fatal(err)
	}
	expected, err := b.Make(br.BoolToBits, br.Bits(8), 0, predicate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := br.Prove(t.Context(), r.Results()[0].Value, expected, br.Limits{}); err != nil {
		t.Fatalf("native/source-independent exact comparison did not join: %v", err)
	}
	// A wrong owner-supplied mapping is a different valid conditional native
	// relation, never evidence for the original source-to-input correspondence.
	swapped := append([]InputBinding(nil), inputs...)
	swapped[0].Value, swapped[1].Value = swapped[1].Value, swapped[0].Value
	wrong, err := DeriveRelation(t.Context(), im, testEntry, f, swapped, RelationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := br.Prove(t.Context(), wrong.Results()[0].Value, expected, br.Limits{}); err == nil {
		t.Fatal("swapped native arguments acquired equality")
	}
	// Another pure body cannot borrow the expected relation merely because the
	// existing native effect/input-bound checker accepts the same interface.
	wrong, err = DeriveRelation(t.Context(), image(t, hexBytes(t, "4839d80f9dc1c3")), testEntry, f, inputs, RelationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := br.Prove(t.Context(), wrong.Results()[0].Value, expected, br.Limits{}); err == nil {
		t.Fatal("different pure body acquired equality")
	}
}

func TestRelationRefusalsAndLimits(t *testing.T) {
	f := face(Masks{RAX: math.MaxUint64}, Masks{RAX: math.MaxUint64})
	inputs, _ := relationBindings(t, f.Inputs)
	for _, tt := range []struct{ code, premise string }{
		{"488b00c3", "data-memory"}, {"ffd1c3", "instruction-semantics"}, {"ebfe", "acyclic-control"},
		{"0f97c0c3", "flag-input-bound"}, {"48c1e8020f9cc0c3", "flag-input-bound"},
		{"4889d8c3", "result-input-bound"},
	} {
		r, err := DeriveRelation(t.Context(), image(t, hexBytes(t, tt.code)), testEntry, f, inputs, RelationLimits{})
		if _, ok := r.Bound(); ok {
			t.Fatal("refused relation escaped")
		}
		requireRefusal(t, Certificate{}, err, tt.premise)
	}
	im := image(t, hexBytes(t, "4883c001c3"))
	for _, l := range []RelationLimits{{Instructions: 1}, {Nodes: 1}, {Work: 1}, {Depth: 1}, {Nodes: -1}, {Depth: 513}} {
		r, err := DeriveRelation(t.Context(), im, testEntry, f, inputs, l)
		if err == nil {
			t.Fatalf("limit accepted: %+v", l)
		}
		if _, ok := r.Bound(); ok {
			t.Fatal("budget supplied relation")
		}
		requireRefusal(t, Certificate{}, err, "relation-budget")
	}
	for _, bad := range [][]InputBinding{nil, append(append([]InputBinding(nil), inputs...), inputs[0]), {{Register: RCX, Value: inputs[0].Value}}, {{Register: RAX, Offset: 1, Value: inputs[0].Value}}} {
		_, err := DeriveRelation(t.Context(), im, testEntry, f, bad, RelationLimits{})
		requireRefusal(t, Certificate{}, err, "relation-inputs")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r, err := DeriveRelation(ctx, im, testEntry, f, inputs, RelationLimits{})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, ok := r.Bound(); ok {
		t.Fatal("cancelled positive")
	}
	// Imported DAGs are bounded too; a caller-owned expression cannot bypass
	// construction limits by handing in an already-allocated deep operand.
	b := br.NewBuilder(1024)
	deep := inputs[0].Value
	one, err := b.Const(br.Bits(64), 1)
	if err != nil {
		t.Fatal(err)
	}
	for j := 0; j < 20; j++ {
		deep, err = b.Make(br.Add, br.Bits(64), 0, deep, one)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = DeriveRelation(t.Context(), im, testEntry, f, []InputBinding{{Register: RAX, Value: deep}}, RelationLimits{Depth: 8})
	requireRefusal(t, Certificate{}, err, "relation-budget")
	_, err = DeriveRelation(t.Context(), im, testEntry, f, []InputBinding{{Register: RAX, Value: deep}}, RelationLimits{Nodes: 8})
	requireRefusal(t, Certificate{}, err, "relation-budget")
}

func TestRelationCancellationDuringConstruction(t *testing.T) {
	in := Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}
	inputs, _ := relationBindings(t, in)
	im := image(t, hexBytes(t, kernels[2].code))
	f := face(in, Masks{RAX: math.MaxUint64})
	count := &imageCallbackContext{Context: t.Context()}
	if _, err := DeriveRelation(count, im, testEntry, f, inputs, RelationLimits{}); err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{2, 17, count.calls / 2, count.calls} {
		ctx := &checkpointContext{Context: t.Context(), remaining: at}
		r, err := DeriveRelation(ctx, im, testEntry, f, inputs, RelationLimits{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("checkpoint%d: %v", at, err)
		}
		if _, ok := r.Bound(); ok {
			t.Fatal("cancelled relation escaped")
		}
	}
}

func FuzzNativeValueBranches(f *testing.F) {
	f.Add(uint64(0), uint64(0), uint64(0))
	f.Add(uint64(math.MaxUint64), uint64(1), uint64(math.MaxUint64))
	f.Add(uint64(1<<63), uint64(math.MaxInt64), uint64(0x12345678))
	f.Fuzz(func(t *testing.T, x, y, scratch uint64) {
		k := kernels[2]
		inputs, terms := relationBindings(t, k.inputs)
		r, err := DeriveRelation(t.Context(), image(t, hexBytes(t, k.code)), testEntry, face(k.inputs, k.results), inputs, RelationLimits{})
		if err != nil {
			t.Fatal(err)
		}
		want := x ^ y
		if x < y {
			want = x + y
		}
		got := evalRelationTerm(t, r.Results()[0].Value, map[br.Term]uint64{terms[RAX]: x, terms[RBX]: y}, scratch)
		if got != want {
			t.Fatalf("branch(%#x,%#x)=%#x want%#x", x, y, got, want)
		}
	})
}

func TestRelationSnapshotsAndPrivateOutputs(t *testing.T) {
	a := image(t, hexBytes(t, "4801d8c3"))
	b := image(t, hexBytes(t, "4831d8c3"))
	f := face(Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}, Masks{RAX: math.MaxUint64})
	inputs, terms := relationBindings(t, f.Inputs)
	count := &imageCallbackContext{Context: t.Context()}
	if _, err := DeriveRelation(count, a, testEntry, f, inputs, RelationLimits{}); err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{1, 8, count.calls} {
		supplied := *a
		bindings := append([]InputBinding(nil), inputs...)
		ctx := &imageCallbackContext{Context: t.Context(), onErr: func(call int) {
			if call == at {
				supplied = *b
				bindings[0].Value = terms[RBX]
			}
		}}
		r, err := DeriveRelation(ctx, &supplied, testEntry, f, bindings, RelationLimits{})
		if err != nil {
			t.Fatal(err)
		}
		supplied = Image{}
		bound, ok := r.Bound()
		if !ok || bound.ImageDigest != a.digest {
			t.Fatal("relation image replaced")
		}
		assertCertificateImage(t, r.checked.effects, a)
		if !reflect.DeepEqual(r.Inputs(), inputs) {
			t.Fatal("input snapshot replaced")
		}
		got := evalRelationTerm(t, r.Results()[0].Value, map[br.Term]uint64{terms[RAX]: 2, terms[RBX]: 3}, 0)
		if got != 5 {
			t.Fatalf("not bound Add: %d", got)
		}
		projection := r.Results()
		projection[0].Value = terms[RBX]
		if r.Results()[0].Value == terms[RBX] {
			t.Fatal("mutable output projection")
		}
	}
}

func BenchmarkNativeValueRelation(b *testing.B) {
	for j, k := range kernels {
		b.Run(k.name, func(b *testing.B) {
			im := image(b, hexBytes(b, k.code))
			inputs, _ := relationBindings(b, k.inputs)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r, err := DeriveRelation(b.Context(), im, testEntry, face(kernels[j].inputs, kernels[j].results), inputs, RelationLimits{})
				if err != nil {
					b.Fatal(err)
				}
				benchmarkRelation = r
			}
		})
	}
}

var benchmarkRelation Relation
