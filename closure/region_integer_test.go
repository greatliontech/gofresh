package closure

import (
	"context"
	"errors"
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"math/big"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func regionIntegerFixture(t testing.TB, source string, op token.Token) *ssa.BinOp {
	t.Helper()
	in := regionFixture(t, source)
	for _, block := range in.root.Blocks {
		for _, instruction := range block.Instrs {
			if binary, ok := instruction.(*ssa.BinOp); ok && binary.Op == op {
				return binary
			}
		}
	}
	t.Fatal("missing actual SSA integer operation")
	return nil
}

func regionIntegerTestKernel(ctx context.Context, word int64) *regionKernel {
	k := &regionKernel{meter: &regionMeter{ctx: ctx, limits: defaultRegionLimits()}}
	if word != 0 {
		k.sizes = &types.StdSizes{WordSize: word, MaxAlign: word}
	}
	return k
}

func regionIntegerTestValue(typ types.Type, text string) regionValue {
	return regionValue{typ: typ, kind: regionConstant, scalar: constant.MakeFromLiteral(text, token.INT, 0)}
}

// The oracle uses mathematical integers and an explicit modulus, independently
// of bitrelation normalization and the production word/value interpretation.
func regionIntegerOracle(bits uint64, width uint, signed bool) *big.Int {
	n := new(big.Int).SetUint64(bits)
	modulus := new(big.Int).Lsh(big.NewInt(1), width)
	n.Mod(n, modulus)
	if signed && n.Bit(int(width-1)) != 0 {
		n.Sub(n, modulus)
	}
	return n
}

func TestRegionIntegerArithmetic(t *testing.T) {
	for _, word := range []int64{0, 4, 8} {
		for _, shape := range []struct {
			name   string
			width  uint
			signed bool
		}{
			{"int8", 8, true}, {"uint8", 8, false},
			{"int16", 16, true}, {"uint16", 16, false},
			{"int32", 32, true}, {"uint32", 32, false},
			{"int64", 64, true}, {"uint64", 64, false},
			{"int", uint(word * 8), true}, {"uint", uint(word * 8), false},
		} {
			if shape.width == 0 {
				continue
			}
			for _, named := range []bool{false, true} {
				t.Run(fmt.Sprintf("word%d/%s/named%v", word, shape.name, named), func(t *testing.T) {
					name, prefix := shape.name, ""
					if named {
						name, prefix = "Number", "type Number "+shape.name+"; "
					}
					add := regionIntegerFixture(t, prefix+fmt.Sprintf("func F(x,y %s) %s { return x+y }", name, name), token.ADD)
					shift := regionIntegerFixture(t, prefix+fmt.Sprintf("func F(x %s,n uint64) %s { return x<<n }", name, name), token.SHL)
					if !regionIntegerOperation(add) || !regionIntegerOperation(shift) {
						t.Fatal("typed arithmetic grammar refused")
					}
					random := rand.New(rand.NewPCG(31, 43))
					values := []uint64{0, 1, 2, ^uint64(0), uint64(1) << (shape.width - 1), uint64(1)<<(shape.width-1) - 1}
					for range 24 {
						values = append(values, random.Uint64())
					}
					modulus := new(big.Int).Lsh(big.NewInt(1), shape.width)
					check := func(op *ssa.BinOp, left, right regionValue, expected *big.Int) {
						t.Helper()
						expected.Mod(expected, modulus)
						if shape.signed && expected.Bit(int(shape.width-1)) != 0 {
							expected.Sub(expected, modulus)
						}
						got, err := regionIntegerTestKernel(t.Context(), word).integerBinary(op, left, right)
						if err != nil || got.kind != regionConstant || !types.Identical(got.typ, op.Type()) || got.scalar.ExactString() != expected.String() {
							t.Fatalf("%s(%s,%s): got %+v, %v; want %s", op.Op, left.scalar, right.scalar, got, err, expected)
						}
					}
					for _, bits := range values {
						x := regionIntegerOracle(bits, shape.width, shape.signed)
						for _, other := range values[:6] {
							y := regionIntegerOracle(other, shape.width, shape.signed)
							check(add, regionIntegerTestValue(add.X.Type(), x.String()), regionIntegerTestValue(add.Y.Type(), y.String()), new(big.Int).Add(x, y))
						}
						for _, count := range []uint64{0, 1, uint64(shape.width - 1), uint64(shape.width), uint64(shape.width + 1), 255, 1 << 32, ^uint64(0)} {
							want := new(big.Int)
							if count < uint64(shape.width) {
								want.Lsh(x, uint(count))
							}
							check(shift, regionIntegerTestValue(shift.X.Type(), x.String()), regionValue{typ: shift.Y.Type(), kind: regionConstant, scalar: constant.MakeUint64(count)}, want)
						}
					}
				})
			}
		}
	}
}

func TestRegionIntegerSelectedConstants(t *testing.T) {
	for _, tc := range []struct {
		kind                types.BasicKind
		text                string
		raw, word32, word64 bool
	}{
		{types.Int, "2147483647", true, true, true},
		{types.Int, "2147483648", false, false, true},
		{types.Int, "-2147483648", true, true, true},
		{types.Int, "-2147483649", false, false, true},
		{types.Int, "9223372036854775807", false, false, true},
		{types.Int, "9223372036854775808", false, false, false},
		{types.Int, "-9223372036854775808", false, false, true},
		{types.Int, "-9223372036854775809", false, false, false},
		{types.Uint, "4294967295", true, true, true},
		{types.Uint, "4294967296", false, false, true},
		{types.Uint, "18446744073709551615", false, false, true},
		{types.Uint, "18446744073709551616", false, false, false},
		{types.Uint, "-1", false, false, false},
		{types.Int64, "9223372036854775807", true, true, true},
		{types.Uint64, "18446744073709551615", true, true, true},
		{types.Uintptr, "4294967296", false, false, false},
	} {
		for i, word := range []int64{0, 4, 8} {
			for _, named := range []bool{false, true} {
				var typ types.Type = types.Typ[tc.kind]
				if named {
					typ = types.NewNamed(types.NewTypeName(token.NoPos, nil, "Number", nil), typ, nil)
				}
				value := regionIntegerTestValue(typ, tc.text)
				got := regionIntegerTestKernel(t.Context(), word).scalarConstant(typ, value.scalar)
				if want := []bool{tc.raw, tc.word32, tc.word64}[i]; got != want {
					t.Errorf("word%d %v %s: got %v, want %v", word, typ, tc.text, got, want)
				}
			}
		}
	}
	invalid := regionIntegerTestKernel(t.Context(), 2)
	if invalid.scalarConstant(types.Typ[types.Int], constant.MakeInt64(1)) {
		t.Fatal("unsupported selected word layout accepted")
	}
	for _, typ := range []types.Type{nil, types.Typ[types.Int], types.Typ[types.Uint]} {
		if regionIntegerTestKernel(t.Context(), 8).scalarConstant(typ, nil) || regionIntegerTestKernel(t.Context(), 8).scalarConstant(typ, constant.MakeBool(true)) {
			t.Fatal("noninteger selected constant accepted")
		}
	}
}

func TestRegionIntegerEvaluatedShiftCount(t *testing.T) {
	for _, word := range []int64{4, 8} {
		in := regionFixture(t, `func F(x int32,n uint) int32 { n=n+1; return x<<n }`)
		var add, shift *ssa.BinOp
		for _, block := range in.root.Blocks {
			for _, instruction := range block.Instrs {
				if binary, ok := instruction.(*ssa.BinOp); ok {
					if binary.Op == token.ADD {
						add = binary
					} else if binary.Op == token.SHL {
						shift = binary
					}
				}
			}
		}
		if add == nil || shift == nil || shift.Y != add {
			t.Fatal("fixture lost evaluated count operand")
		}
		for _, count := range []uint64{30, 31, 32, ^uint64(0) >> (64 - word*8)} {
			k := regionIntegerTestKernel(t.Context(), word)
			value, err := k.integerBinary(add, regionValue{typ: add.X.Type(), kind: regionConstant, scalar: constant.MakeUint64(count)}, regionIntegerTestValue(add.Y.Type(), "1"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := k.integerBinary(shift, regionIntegerTestValue(shift.X.Type(), "1"), value)
			want := "0"
			if count == 30 {
				want = "-2147483648"
			}
			if count == ^uint64(0)>>(64-word*8) {
				want = "1"
			}
			if err != nil || got.scalar.ExactString() != want {
				t.Fatalf("word%d count%d: got %+v, %v; want %s", word, count, got, err, want)
			}
		}
	}
	// A literal is taken from the actual instruction, including a nonnegative
	// signed count. An unrelated caller value cannot replace that literal.
	shift := regionIntegerFixture(t, `func F(x int32) int32 { return x<<int64(32) }`, token.SHL)
	got, err := regionIntegerTestKernel(t.Context(), 0).integerBinary(shift, regionIntegerTestValue(shift.X.Type(), "1"), regionIntegerTestValue(shift.Y.Type(), "1"))
	if err != nil || got.scalar.ExactString() != "0" {
		t.Fatalf("literal count: %+v, %v", got, err)
	}
	shift = regionIntegerFixture(t, `func F(x int32,n int64) int32 { return x<<n }`, token.SHL)
	got, err = regionIntegerTestKernel(t.Context(), 0).integerBinary(shift, regionIntegerTestValue(shift.X.Type(), "1"), regionIntegerTestValue(shift.Y.Type(), "31"))
	if err != nil || got.scalar.ExactString() != "-2147483648" {
		t.Fatalf("signed count: %+v, %v", got, err)
	}
}

func TestRegionIntegerRefusals(t *testing.T) {
	for _, source := range []string{
		`func F(x,y uintptr) uintptr { return x+y }`,
		`func F(x uintptr,n uint64) uintptr { return x<<n }`,
		`func F(x int32,n uintptr) int32 { return x<<n }`,
		`func F(x,y float64) float64 { return x+y }`,
		`func F(x,y string) string { return x+y }`,
	} {
		op := token.ADD
		if strings.Contains(source, "<<") {
			op = token.SHL
		}
		if regionIntegerOperation(regionIntegerFixture(t, source, op)) {
			t.Fatalf("unsupported grammar: %s", source)
		}
	}
	add := regionIntegerFixture(t, `func F(x,y int32) int32 { return x+y }`, token.ADD)
	shift := regionIntegerFixture(t, `func F(x int32,n int64) int32 { return x<<n }`, token.SHL)
	for _, op := range []token.Token{token.SUB, token.MUL, token.QUO, token.SHR, token.AND, token.OR, token.XOR} {
		copy := *add
		copy.Op = op
		if regionIntegerOperation(&copy) {
			t.Fatalf("unsupported operation %s", op)
		}
	}
	if regionIntegerOperation(nil) || regionIntegerOperation(&ssa.BinOp{}) {
		t.Fatal("missing operands accepted")
	}
	for _, tc := range []struct {
		name        string
		op          *ssa.BinOp
		left, right regionValue
	}{
		{"unknown left", add, regionUnknownValue(add.X.Type()), regionIntegerTestValue(add.Y.Type(), "1")},
		{"unknown addend", add, regionIntegerTestValue(add.X.Type(), "1"), regionUnknownValue(add.Y.Type())},
		{"unknown count", shift, regionIntegerTestValue(shift.X.Type(), "1"), regionUnknownValue(shift.Y.Type())},
		{"negative count", shift, regionIntegerTestValue(shift.X.Type(), "1"), regionIntegerTestValue(shift.Y.Type(), "-1")},
		{"out of range count", shift, regionIntegerTestValue(shift.X.Type(), "1"), regionIntegerTestValue(shift.Y.Type(), "9223372036854775808")},
		{"overflow input", add, regionIntegerTestValue(add.X.Type(), "2147483648"), regionIntegerTestValue(add.Y.Type(), "1")},
		{"overflow addend", add, regionIntegerTestValue(add.X.Type(), "1"), regionIntegerTestValue(add.Y.Type(), "2147483648")},
		{"operand type", add, regionIntegerTestValue(types.Typ[types.Int64], "1"), regionIntegerTestValue(add.Y.Type(), "1")},
		{"count type", shift, regionIntegerTestValue(shift.X.Type(), "1"), regionIntegerTestValue(types.Typ[types.Uint64], "1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := regionIntegerTestKernel(t.Context(), 8).integerBinary(tc.op, tc.left, tc.right); err == nil || got.scalar != nil {
				t.Fatalf("refusal returned %+v, %v", got, err)
			}
		})
	}
	for _, name := range []string{"int", "uint"} {
		for _, symbol := range []string{"+", "<<"} {
			op := token.ADD
			if symbol == "<<" {
				op = token.SHL
			}
			binary := regionIntegerFixture(t, fmt.Sprintf("func F(x,y %s) %s { return x%s y }", name, name, symbol), op)
			if !regionIntegerOperation(binary) {
				t.Fatal("word grammar incorrectly depends on selection")
			}
			if _, err := regionIntegerTestKernel(t.Context(), 0).integerBinary(binary, regionIntegerTestValue(binary.X.Type(), "1"), regionIntegerTestValue(binary.Y.Type(), "1")); err == nil {
				t.Fatal("word arithmetic used host width")
			}
		}
	}
	copy := *shift
	copy.Y = ssa.NewConst(constant.MakeInt64(-1), types.Typ[types.Int64])
	if _, err := regionIntegerTestKernel(t.Context(), 8).integerBinary(&copy, regionIntegerTestValue(copy.X.Type(), "1"), regionIntegerTestValue(copy.Y.Type(), "1")); err == nil {
		t.Fatal("negative actual literal count replaced by positive value")
	}
}

func TestRegionIntegerProofResources(t *testing.T) {
	op := regionIntegerFixture(t, `func F(x,y uint64) uint64 { return x+y }`, token.ADD)
	left, right := regionIntegerTestValue(op.X.Type(), "17"), regionIntegerTestValue(op.Y.Type(), "25")
	baseline := regionIntegerTestKernel(t.Context(), 8)
	if _, err := baseline.integerBinary(op, left, right); err != nil {
		t.Fatal(err)
	}
	work := baseline.meter.work
	if work <= 2 {
		t.Fatal("subordinate normalization escaped enclosing meter")
	}
	for _, limit := range []int{1, work - 1} {
		k := regionIntegerTestKernel(t.Context(), 8)
		k.meter.limits.work = limit
		if got, err := k.integerBinary(op, left, right); err == nil || got.scalar != nil {
			t.Fatalf("work%d returned %+v, %v", limit, got, err)
		}
	}
	k := regionIntegerTestKernel(t.Context(), 8)
	k.meter.limits.work = work*2 - 1
	if _, err := k.integerBinary(op, left, right); err != nil {
		t.Fatal(err)
	}
	if _, err := k.integerBinary(op, left, right); err == nil {
		t.Fatal("successive operations restarted the resource account")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := regionIntegerTestKernel(ctx, 8).integerBinary(op, left, right); !errors.Is(err, context.Canceled) || got.scalar != nil {
		t.Fatalf("cancellation: %+v, %v", got, err)
	}
	for _, checkpoint := range []int{2, work - 1} {
		ctx, cancel := context.WithCancel(t.Context())
		counted := &regionIntegerCancelContext{Context: ctx, cancel: cancel, remaining: checkpoint}
		got, err := regionIntegerTestKernel(counted, 8).integerBinary(op, left, right)
		cancel()
		if !errors.Is(err, context.Canceled) || got.scalar != nil {
			t.Fatalf("cancellation at checkpoint %d: %+v, %v", checkpoint, got, err)
		}
	}
	k = regionIntegerTestKernel(t.Context(), 8)
	k.meter.limits.nodes = 1
	if got, err := k.integerBinary(op, left, right); err == nil || got.scalar != nil {
		t.Fatalf("nodes: %+v, %v", got, err)
	}
}

type regionIntegerCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *regionIntegerCancelContext) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestCheckedScalarConstantEndpoints(t *testing.T) {
	b := br.NewBuilder(128)
	x, err := b.Input(br.Bits(32), br.NewScope(), 0)
	if err != nil {
		t.Fatal(err)
	}
	one, err := b.Const(br.Bits(32), 1)
	if err != nil {
		t.Fatal(err)
	}
	two, err := b.Make(br.Add, br.Bits(32), 0, one, one)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := b.Make(br.Add, br.Bits(32), 0, x, two)
	if err != nil {
		t.Fatal(err)
	}
	for _, term := range []br.Term{x, unknown} {
		if _, err := checkedScalarConstant(t.Context(), term, br.DefaultLimits()); err == nil {
			t.Fatal("arbitrary state or a constant subexpression became the root's result")
		}
		m := &assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}
		if _, err := assemblyReferenceConstant(m, term); err == nil || !strings.HasPrefix(err.Error(), "selected assembly reference:") {
			t.Fatalf("assembly diagnostic scope changed: %v", err)
		}
	}
	if got, err := checkedScalarConstant(t.Context(), two, br.DefaultLimits()); err != nil || got != 2 {
		t.Fatalf("exact root: %d, %v", got, err)
	}
	zero, err := b.Make(br.Sub, br.Bits(32), 0, x, x)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := checkedScalarConstant(t.Context(), zero, br.DefaultLimits()); err != nil || got != 0 {
		t.Fatalf("universal cancellation: %d, %v", got, err)
	}
	proposal, err := br.Propose(t.Context(), two, two, br.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := br.Check(t.Context(), two, one, proposal, br.DefaultLimits()); err == nil {
		t.Fatal("unrelated constant endpoint accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := checkedScalarConstant(ctx, two, br.DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("shared helper erased cancellation: %v", err)
	}
}

func TestCheckedScalarConstantCheckerPhase(t *testing.T) {
	b := br.NewBuilder(128)
	one, err := b.Const(br.Bits(32), 1)
	if err != nil {
		t.Fatal(err)
	}
	term, err := b.Make(br.Add, br.Bits(32), 0, one, one)
	if err != nil {
		t.Fatal(err)
	}
	limits := br.DefaultLimits()
	// Measure proposal alone, independently of the helper under test. Measuring
	// the helper would recalibrate downward if it stopped checking its candidate.
	proposalMeter := &regionMeter{ctx: t.Context(), limits: defaultRegionLimits()}
	proposal, err := br.Propose(regionProofContext{Context: t.Context(), meter: proposalMeter}, term, term, limits)
	if err != nil {
		t.Fatal(err)
	}
	candidate := -1
	for i, step := range proposal.Steps {
		if step.Left == term && step.Right.View().Op == br.Constant && step.Right.Sort() == term.Sort() {
			candidate = i
			break
		}
	}
	if candidate < 0 {
		t.Fatal("proposal lacks the root-to-constant candidate")
	}
	endpoint := proposal.Steps[candidate].Right
	if endpoint.View().Immediate != 2 {
		t.Fatal("proposal candidate differs from independent integer sum 1+1")
	}
	witness, err := br.Check(t.Context(), term, endpoint, br.Proof{Steps: proposal.Steps[:candidate+1]}, limits)
	if err != nil {
		t.Fatal(err)
	}
	left, right := witness.Roots()
	if !witness.Valid() || left != term || right != endpoint {
		t.Fatal("independent baseline did not validate the exact candidate endpoints")
	}
	if got, err := checkedScalarConstant(t.Context(), term, limits); err != nil || got != 2 {
		t.Fatalf("positive helper control: got %d, %v; want 2", got, err)
	}
	// Every scanned step, including the candidate, costs one context check.
	// The next checkpoint belongs to Check, not proposal or candidate discovery.
	failAt := proposalMeter.work + candidate + 2
	t.Logf("proposal checkpoints=%d, candidate scan=%d, first checker checkpoint=%d", proposalMeter.work, candidate+1, failAt)
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		counted := &regionIntegerCancelContext{Context: ctx, cancel: cancel, remaining: failAt}
		got, err := checkedScalarConstant(counted, term, limits)
		if !errors.Is(err, context.Canceled) || got != 0 || counted.remaining != 0 {
			t.Fatalf("checker-phase cancellation: got %d, %v, remaining checkpoints %d", got, err, counted.remaining)
		}
	})
	t.Run("exhaustion", func(t *testing.T) {
		meter := &regionMeter{ctx: t.Context(), limits: defaultRegionLimits()}
		meter.limits.work = failAt - 1
		got, err := checkedScalarConstant(regionProofContext{Context: t.Context(), meter: meter}, term, limits)
		var refusal *br.Refusal
		if !errors.As(err, &refusal) || refusal.Code != br.Cancelled || refusal.Cause == nil || refusal.Cause.Error() != regionError("work budget exhausted").Error() || got != 0 || meter.work != failAt {
			t.Fatalf("checker-phase exhaustion: got %d, %v, work %d; want refusal at %d", got, err, meter.work, failAt)
		}
	})
}
