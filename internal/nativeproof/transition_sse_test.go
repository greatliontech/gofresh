package nativeproof

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

func sseTestChecker(t testing.TB) *transitionChecker {
	t.Helper()
	l, err := transitionLimits(TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	m := &transitionChecker{limits: l, valueBuilder: &valueBuilder{
		ctx: t.Context(), limits: l.RelationLimits, builder: br.NewBuilder(l.Nodes),
		depth: make(map[br.Term]int), scope: br.NewScope(),
	}}
	m.truth, m.falsity = m.con(br.Bool(), 1), m.con(br.Bool(), 0)
	return m
}

// The numerical oracle uses Go floating comparisons, not the implementation's
// integer ordering formula. Classification uses magnitude and IsNaN; only the
// signaling/quiet distinction needs its representation bit.
func sseReference(width int, a, b uint64) (bad, carry, zero, parity bool) {
	decode := func(bits uint64) (float64, bool) {
		var value, minNormal float64
		var quiet uint64
		if width == 32 {
			bits = uint64(uint32(bits))
			value = float64(math.Float32frombits(uint32(bits)))
			minNormal, quiet = math.Ldexp(1, -126), 1<<22
		} else {
			value = math.Float64frombits(bits)
			minNormal, quiet = math.Ldexp(1, -1022), 1<<51
		}
		return value, math.IsNaN(value) && bits&quiet == 0 || value != 0 && math.Abs(value) < minNormal
	}
	x, xbad := decode(a)
	y, ybad := decode(b)
	unordered := math.IsNaN(x) || math.IsNaN(y)
	return xbad || ybad, unordered || x < y, unordered || x == y, unordered
}

func sseEdgeBits(width int) []uint64 {
	if width == 32 {
		return []uint64{0, 0x80000000, 1, 0x80000001, 0x007fffff, 0x807fffff,
			0x00800000, 0x80800000, 0x00800001, 0x80800001,
			0x3f800000, 0xbf800000, 0x3f800001, 0xbf800001,
			0x7f7fffff, 0xff7fffff, 0x7f800000, 0xff800000,
			0x7fc00000, 0xffc00000, 0x7fffffff, 0xffffffff,
			0x7f800001, 0xff800001, 0x7fbfffff, 0xffbfffff}
	}
	return []uint64{0, 0x8000000000000000, 1, 0x8000000000000001, 0x000fffffffffffff, 0x800fffffffffffff,
		0x0010000000000000, 0x8010000000000000, 0x0010000000000001, 0x8010000000000001,
		0x3ff0000000000000, 0xbff0000000000000, 0x3ff0000000000001, 0xbff0000000000001,
		0x7fefffffffffffff, 0xffefffffffffffff, 0x7ff0000000000000, 0xfff0000000000000,
		0x7ff8000000000000, 0xfff8000000000000, 0x7fffffffffffffff, 0xffffffffffffffff,
		0x7ff0000000000001, 0xfff0000000000001, 0x7ff7ffffffffffff, 0xfff7ffffffffffff}
}

func sseCheckComparison(t testing.TB, m *transitionChecker, r sseComparison, left, right br.Term, width int, a, b uint64) {
	t.Helper()
	bad, carry, zero, parity := sseReference(width, a, b)
	values := map[br.Term]uint64{left: a, right: b}
	for _, check := range []struct {
		name string
		term br.Term
		want bool
	}{
		{"excluded", r.Excluded, bad}, {"CF", r.Flags.CF.Value, carry},
		{"ZF", r.Flags.ZF.Value, zero}, {"PF", r.Flags.PF.Value, parity},
		{"OF", r.Flags.OF.Value, false}, {"SF", r.Flags.SF.Value, false}, {"AF", r.Flags.AF.Value, false},
		{"signed predicate", r.Predicates.SFXorOF, false},
	} {
		if got := evalRelationTerm(t, check.term, values, 0); got > 1 || (got == 1) != check.want {
			t.Fatalf("binary%d %s(%#x,%#x) = %d, want %v", width, check.name, a, b, got, check.want)
		}
	}
	if m.err != nil {
		t.Fatal(m.err)
	}
}

func TestTransitionSSEComparisonProperties(t *testing.T) {
	for _, width := range []int{32, 64} {
		m := sseTestChecker(t)
		left, right := m.scratch(br.Bits(64)), m.scratch(br.Bits(64))
		r := m.sseCompare(left, right, width)
		for _, f := range []TransitionFlag{r.Flags.CF, r.Flags.ZF, r.Flags.PF, r.Flags.OF, r.Flags.SF, r.Flags.AF} {
			if !f.Defined || f.Preserved || f.Value.Sort() != br.Bool() {
				t.Fatal("comparison did not replace every arithmetic flag with a defined Boolean")
			}
		}
		if r.Predicates.CF != r.Flags.CF.Value || r.Predicates.ZF != r.Flags.ZF.Value {
			t.Fatal("scalar branch predicates differ from projected flags")
		}
		random := rand.New(rand.NewSource(int64(width)))
		for _, a := range sseEdgeBits(width) {
			for _, b := range sseEdgeBits(width) {
				if width == 32 {
					a |= random.Uint64() & 0xffffffff00000000
					b |= random.Uint64() & 0xffffffff00000000
				}
				sseCheckComparison(t, m, r, left, right, width, a, b)
			}
		}
		for range 512 {
			a, b := random.Uint64(), random.Uint64()
			sseCheckComparison(t, m, r, left, right, width, a, b)
			// Random payloads and signs of quiet NaNs are uncommon in an unbiased
			// sample; deliberately include both operand orders and self equality.
			qnan := uint64(0x7ff8000000000000)
			if width == 32 {
				qnan = 0x7fc00000
			}
			sseCheckComparison(t, m, r, left, right, width, a|qnan, b)
			sseCheckComparison(t, m, r, left, right, width, a, b|qnan)
			sseCheckComparison(t, m, r, left, right, width, a, a)
		}
	}
}

func TestTransitionSSECheckedOperandDomain(t *testing.T) {
	for _, width := range []int{32, 64} {
		for _, bits := range sseEdgeBits(width) {
			for _, swap := range []bool{false, true} {
				m := sseTestChecker(t)
				a, b := bits, uint64(0)
				if swap {
					a, b = b, a
				}
				left, right := m.con(br.Bits(64), a), m.con(br.Bits(64), b)
				r, err := m.checkedSSECompare(left, right, width, m.truth)
				bad, _, _, _ := sseReference(width, a, b)
				if bad {
					var refusal *Refusal
					if !errors.As(err, &refusal) || refusal.Premise != "transition-sse-operands" || r.Flags.CF.Value.Valid() || len(m.justifications) != 0 {
						t.Fatalf("binary%d excluded (%#x,%#x) published a relation or failed incorrectly: %v", width, a, b, err)
					}
				} else if err != nil || len(m.justifications) != 1 {
					t.Fatalf("binary%d admitted (%#x,%#x): %v", width, a, b, err)
				}
			}
		}
		m := sseTestChecker(t)
		unknown := m.scratch(br.Bits(64))
		if _, err := m.checkedSSECompare(unknown, unknown, width, m.truth); err == nil {
			t.Fatal("unknown self-compare silently excluded exceptional operands")
		}
	}
}

func TestTransitionSSEGuardedOperandDomain(t *testing.T) {
	for _, width := range []int{32, 64} {
		for _, badBits := range []uint64{1, 0x7ff000007f800001} {
			m := sseTestChecker(t)
			guard := m.scratch(br.Bool())
			zero := m.con(br.Bits(64), 0)
			// The bad operand is reachable outside the actual instruction guard.
			left := m.ite(guard, zero, m.con(br.Bits(64), badBits))
			if _, err := m.checkedSSECompare(left, zero, width, guard); err != nil {
				t.Fatalf("guard-excluded binary%d operand: %v", width, err)
			}
			if len(m.justifications) != 1 {
				t.Fatal("operand exclusion lost checked evidence")
			}
			root, _ := m.justifications[0].Roots()
			if evalRelationTerm(t, root, map[br.Term]uint64{guard: 0}, 0) != 0 || evalRelationTerm(t, root, map[br.Term]uint64{guard: 1}, 0) != 0 {
				t.Fatal("side proof does not exclude the guarded exception condition")
			}
			if _, err := m.checkedSSECompare(left, zero, width, m.not(guard)); err == nil {
				t.Fatal("inverse guard admitted feasible exceptional operand")
			}
		}
	}
}

func TestTransitionSSEJoinedByteOperandDomain(t *testing.T) {
	// A load after a memory join reconstructs a scalar from independently
	// represented bytes with the same path selector. The complete word is one
	// incoming value or the other, never a mixture of their exponent/payload bits.
	for _, width := range []int{32, 64} {
		for _, class := range []string{"quiet-nan", "signaling-nan", "subnormal"} {
			t.Run(fmt.Sprintf("binary%d/%s", width, class), func(t *testing.T) {
				m := sseTestChecker(t)
				guard := m.scratch(br.Bool())
				a, b := uint64(0xffe0e555), uint64(0x80000000)
				quiet := uint64(1) << 22
				if width == 64 {
					a, b = 0xfff8000000000555, 0x8000000000000000
					quiet = uint64(1) << 51
				}
				switch class {
				case "signaling-nan":
					a &^= quiet
				case "subnormal":
					a = 1
				}
				left, right := m.con(br.Bits(width), a), m.con(br.Bits(width), b)
				var word br.Term
				for byteIndex := 0; byteIndex < width/8; byteIndex++ {
					part := m.ite(guard, m.extract(left, byteIndex*8, 8), m.extract(right, byteIndex*8, 8))
					if byteIndex == 0 {
						word = part
					} else {
						word = m.make(br.Concat, br.Bits((byteIndex+1)*8), 0, word, part)
					}
				}
				v := m.sseMemoryVector(word)
				for value, want := range []uint64{b, a} {
					if got := evalRelationTerm(t, v.Lo, map[br.Term]uint64{guard: uint64(value)}, 0); got != want {
						t.Fatalf("joined word = %#x, want %#x", got, want)
					}
				}
				_, err := m.checkedSSECompare(v.Lo, v.Lo, width, m.truth)
				if class == "quiet-nan" {
					if err != nil {
						t.Fatal("quiet NaN or signed zero is a valid comparison operand", err)
					}
				} else {
					var refusal *Refusal
					if !errors.As(err, &refusal) || refusal.Premise != "transition-sse-operands" {
						t.Fatal("joined exceptional operand was not refused", err)
					}
				}
			})
		}
	}
}

func TestTransitionSSEVectorState(t *testing.T) {
	m := sseTestChecker(t)
	original := m.initialSSEVectors()
	seen := map[br.Term]bool{}
	values := map[br.Term]uint64{}
	random := rand.New(rand.NewSource(191))
	for _, v := range original {
		for _, term := range []br.Term{v.Lo, v.Hi} {
			if term.Sort() != br.Bits(64) || term.View().Op != br.Variable || !term.View().Scratch || seen[term] {
				t.Fatal("initial XMM lanes must be distinct arbitrary BV64 variables")
			}
			seen[term], values[term] = true, random.Uint64()
		}
	}
	guard := m.scratch(br.Bool())
	for _, width := range []int{32, 64} {
		for r := range original {
			left, right := original, original
			input := m.scratch(br.Bits(width))
			bits := random.Uint64() & mask(width)
			values[input] = bits
			left[r] = m.sseMemoryVector(input)
			m.mergeSSEVectors(&right, left, guard)
			if left[r].Lo.Sort() != br.Bits(64) || left[r].Hi.Sort() != br.Bits(64) {
				t.Fatal("load lost full XMM width")
			}
			for _, take := range []uint64{0, 1} {
				values[guard] = take
				for reg, v := range right {
					lo, hi := values[original[reg].Lo], values[original[reg].Hi]
					if take == 1 && reg == r {
						lo, hi = bits, 0
					}
					if evalRelationTerm(t, v.Lo, values, 0) != lo || evalRelationTerm(t, v.Hi, values, 0) != hi {
						t.Fatalf("binary%d load/join changed wrong lane at XMM%d, target XMM%d, path %d", width, reg, r, take)
					}
				}
			}
			// A continuation imports both original and current roots without
			// allocating replacement input identities or sharing mutable arrays.
			next := sseTestChecker(t)
			if err := next.importSSEVectors(original); err != nil {
				t.Fatal(err)
			}
			if err := next.importSSEVectors(right); err != nil {
				t.Fatal(err)
			}
			for _, v := range original {
				if !seen[v.Lo] || !seen[v.Hi] || next.depth[v.Lo] == 0 || next.depth[v.Hi] == 0 {
					t.Fatal("load/join/import overwrote original input identities")
				}
			}
		}
	}
	if m.err != nil {
		t.Fatal(m.err)
	}
}

func TestTransitionSSELoadsDoNotClassify(t *testing.T) {
	for _, width := range []int{32, 64} {
		for _, bits := range sseEdgeBits(width) {
			m := sseTestChecker(t)
			value := m.sseMemoryVector(m.con(br.Bits(width), bits))
			if m.err != nil || evalRelationTerm(t, value.Lo, nil, 0) != bits || evalRelationTerm(t, value.Hi, nil, 0) != 0 {
				t.Fatalf("load converted/refused binary%d bits %#x: %v", width, bits, m.err)
			}
		}
	}
}

func TestTransitionSSEParityUsesProjection(t *testing.T) {
	m := sseTestChecker(t)
	guard, p, q := m.scratch(br.Bool()), m.scratch(br.Bool()), m.scratch(br.Bool())
	parity := m.ite(guard, p, q)
	flags := TransitionFlags{PF: definedFlag(parity)}
	jp := m.transitionPredicate(x86asm.JP, symbolicState{}, flags)
	jnp := m.transitionPredicate(x86asm.JNP, symbolicState{}, flags)
	if jp != parity {
		t.Fatal("JP substituted a fresh predicate for actual PF")
	}
	for g := uint64(0); g < 2; g++ {
		for a := uint64(0); a < 2; a++ {
			for b := uint64(0); b < 2; b++ {
				want := b
				if g != 0 {
					want = a
				}
				values := map[br.Term]uint64{guard: g, p: a, q: b}
				if evalRelationTerm(t, jp, values, 0) != want || evalRelationTerm(t, jnp, values, 0) != 1-want {
					t.Fatal("parity branch lost joined path correlation")
				}
			}
		}
	}
	for _, flag := range []TransitionFlag{{Defined: true}, {Value: p}, {Defined: true, Value: m.con(br.Bits(1), 1)}} {
		n := sseTestChecker(t)
		if n.transitionPredicate(x86asm.JP, symbolicState{}, TransitionFlags{PF: flag}).Valid() || n.err == nil {
			t.Fatal("missing, undefined or non-Boolean PF was consumed")
		}
	}
	// Existing scalar branch predicates still use their established identities.
	s := symbolicState{flags: [flagCount]br.Term{p, q, guard}}
	if m.transitionPredicate(x86asm.JB, s, flags) != p || m.transitionPredicate(x86asm.JE, s, flags) != q {
		t.Fatal("parity extension replaced scalar branch semantics")
	}
}

func TestTransitionSSERefusalAndResourceControls(t *testing.T) {
	for _, width := range []int{0, 16, 128} {
		m := sseTestChecker(t)
		v := m.con(br.Bits(64), 0)
		if _, err := m.checkedSSECompare(v, v, width, m.truth); err == nil {
			t.Fatal("unsupported comparison width accepted")
		}
	}
	for _, sort := range []br.Sort{br.Bool(), br.Bits(8), br.Bits(16)} {
		m := sseTestChecker(t)
		if got := m.sseMemoryVector(m.con(sort, 0)); got.Lo.Valid() || m.err == nil {
			t.Fatal("unsupported memory read width accepted")
		}
	}
	for _, resource := range []string{"cancel", "work", "nodes", "depth", "proof-storage"} {
		t.Run(resource, func(t *testing.T) {
			m := sseTestChecker(t)
			v := m.con(br.Bits(64), 0)
			switch resource {
			case "cancel":
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				m.ctx = ctx
			case "work":
				m.valueBuilder.limits.Work = m.work
			case "nodes":
				m.valueBuilder.limits.Nodes = len(m.depth)
			case "depth":
				m.valueBuilder.limits.Depth = 1
			case "proof-storage":
				m.liveStateBytes = m.limits.LiveStateBytes
			}
			r, err := m.checkedSSECompare(v, v, 64, m.truth)
			if err == nil || r.Flags.CF.Value.Valid() || len(m.justifications) != 0 {
				t.Fatalf("%s published partial relation: %v", resource, err)
			}
			if resource == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation became another refusal: %v", err)
			}
		})
	}
}
