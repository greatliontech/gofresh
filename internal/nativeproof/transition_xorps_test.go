package nativeproof

import (
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// This encoder describes fixture intent independently of the production decoder.
func sseXORPSBytes(dst, src int) []byte {
	var b []byte
	if dst >= 8 || src >= 8 {
		b = append(b, 0x40|byte(dst/8)<<2|byte(src/8))
	}
	return append(b, 0x0f, 0x57, 0xc0|byte(dst%8)<<3|byte(src%8))
}

func sseXORPSUnsupported() []string {
	return []string{
		"0f570424", "450f5738", // Memory XORPS.
		"660f57c1", "660fefc1", // XORPD and PXOR are different operations.
		"480f57c1", "4f0f57c1", // REX.W is outside the selected form.
		"40400f57c1", "45450f57c1", // Duplicate REX.
		"f20f57c1", "f30f57c1", "66660f57c1", // Mandatory/duplicate prefixes.
		"f00f57c1", "640f57c1", "670f57c1", // Other legacy prefixes.
		"c5f857c1", "c4e17857c1", "62f17c0857c1", // VEX/EVEX.
		"0f", "0f57", "450f57", // Truncation.
	}
}

func TestTransitionXORPSExactForms(t *testing.T) {
	for dst := 0; dst < 16; dst++ {
		for src := 0; src < 16; src++ {
			raw := sseXORPSBytes(dst, src)
			// Explicit neutral REX and its ignored X bit are admitted by the
			// existing non-W REX contract, as are both register extension bits.
			variants := [][]byte{raw}
			if raw[0] == 0x0f {
				variants = append(variants, append([]byte{0x40}, raw...), append([]byte{0x42}, raw...))
			} else {
				x := slices.Clone(raw)
				x[0] |= 2
				variants = append(variants, x)
			}
			for _, encoded := range variants {
				i, err := x86asm.Decode(encoded, 64)
				if err != nil || i.Op != x86asm.XORPS || i.Args[0] != x86asm.X0+x86asm.Reg(dst) || i.Args[1] != x86asm.X0+x86asm.Reg(src) {
					t.Fatalf("fixture %x lost register intent: %s, %v", encoded, i, err)
				}
				if !TransitionExpansionRequired(i) {
					t.Fatal("XORPS bypassed optional expansion")
				}
				if err := validateTransitionSSEForm(0, i, encoded); err != nil {
					t.Fatalf("XMM%d,XMM%d %x: %v", dst, src, encoded, err)
				}
				for _, extra := range [][]byte{encoded[:len(encoded)-1], append(slices.Clone(encoded), 0x90)} {
					if err := validateTransitionSSEForm(0, i, extra); err == nil {
						t.Fatal("accepted nonexact extent")
					}
				}
				bad := i
				bad.Args[1] = x86asm.X0 + x86asm.Reg((src+1)%16)
				if err := validateTransitionSSEForm(0, bad, encoded); err == nil {
					t.Fatal("accepted source inconsistent with raw ModRM/REX")
				}
				bad = i
				bad.Args[0] = x86asm.X0 + x86asm.Reg((dst+1)%16)
				if err := validateTransitionSSEForm(0, bad, encoded); err == nil {
					t.Fatal("accepted destination inconsistent with raw ModRM/REX")
				}
			}
		}
	}
	for _, text := range sseXORPSUnsupported() {
		raw := hexBytes(t, text)
		i, err := x86asm.Decode(raw, 64)
		if err == nil && validateTransitionSSEForm(0, i, raw) == nil {
			t.Fatalf("accepted unsupported %s (%s)", text, i)
		}
	}
}

func TestTransitionXORPSAllRegisterPairs(t *testing.T) {
	rng := rand.New(rand.NewSource(5757))
	face := sseIntegrationFace()
	face.Conditions.SSE = SSEModel
	for dst := 0; dst < 16; dst++ {
		for src := 0; src < 16; src++ {
			b := sseIntegrationRequire(t, sseXORPSBytes(dst, src), face)
			if len(b.Instructions) != 1 || len(b.Accesses) != 0 || len(b.PrimitiveEffects) != 0 || !slices.Equal(b.Memory, b.InitialMemory) {
				t.Fatal("XORPS omitted instruction or introduced effects")
			}
			for r, v := range b.Registers {
				if v.Value != b.InitialRegisters[r] || b.Preserved[r] != ^uint64(0) {
					t.Fatalf("XORPS changed GPR%d", r)
				}
			}
			if b.Direction != b.InitialDirection || b.Direction.Sort() != br.Bool() {
				t.Fatal("XORPS changed arbitrary incoming direction")
			}
			for _, flag := range []TransitionFlag{b.Flags.CF, b.Flags.ZF, b.Flags.OF, b.Flags.SF, b.Flags.AF, b.Flags.PF} {
				if !flag.Preserved || !flag.Defined {
					t.Fatal("XORPS changed initial flag status")
				}
			}
			for sample := 0; sample < 32; sample++ {
				values := sseIntegrationValues(t, b)
				for _, v := range b.InitialVectors {
					values[v.Lo], values[v.Hi] = rng.Uint64(), rng.Uint64()
				}
				// Deliberate floating edge patterns supplement arbitrary 128-bit
				// vectors; neither lane may be numerically interpreted or zeroed.
				if sample < len(sseEdgeBits(32)) {
					values[b.InitialVectors[dst].Lo] = 0xfff0000000000000 | sseEdgeBits(32)[sample]
				}
				for r, v := range b.Vectors {
					lo, hi := values[b.InitialVectors[r].Lo], values[b.InitialVectors[r].Hi]
					if r == dst {
						lo ^= values[b.InitialVectors[src].Lo]
						hi ^= values[b.InitialVectors[src].Hi]
					}
					if evalRelationTerm(t, v.Lo, values, 0) != lo || evalRelationTerm(t, v.Hi, values, 0) != hi {
						t.Fatalf("XMM%d ^= XMM%d sample%d changed XMM%d incorrectly", dst, src, sample, r)
					}
				}
			}
		}
	}
}

func TestTransitionXORPSPreservesFlagDefinedness(t *testing.T) {
	for raw := 0; raw < 64; raw++ {
		m := sseTestChecker(t)
		vectors := m.initialSSEVectors()
		flags := []*TransitionFlag{&m.bound.Flags.CF, &m.bound.Flags.OF, &m.bound.Flags.SF, &m.bound.Flags.ZF, &m.bound.Flags.AF, &m.bound.Flags.PF}
		for j, flag := range flags {
			*flag = TransitionFlag{Defined: raw&(1<<j) != 0, Preserved: raw&(1<<((j+1)%6)) != 0, Value: m.scratch(br.Bool())}
		}
		for j := range m.state.flags {
			m.state.flags[j] = m.scratch(br.Bool())
		}
		m.direction = m.scratch(br.Bool())
		beforeFlags, beforePredicates, beforeDirection := m.bound.Flags, m.state.flags, m.direction
		i := operation{Op: x86asm.XORPS, Args: [2]x86asm.Arg{x86asm.X15, x86asm.X8}}
		if err := m.sseStep(i, 4, &vectors, SSEModel); err != nil {
			t.Fatal(err)
		}
		if m.bound.Flags != beforeFlags || m.state.flags != beforePredicates || m.direction != beforeDirection || len(m.justifications) != 0 {
			t.Fatal("XORPS changed flags/direction or invoked floating operand proof")
		}
	}
}

func TestTransitionXORPSManufacturesExcludedCompareOperands(t *testing.T) {
	face := sseIntegrationFace()
	face.Conditions.SSE = SSEModel
	for _, right := range []uint64{0x40000000, 0x3f800000} {
		code := append(sseIntegrationStore(0x3f800001, 8), sseIntegrationStore(right, 16)...)
		code = append(code, sseIntegrationLoad(32, 15, 8)...)
		code = append(code, sseIntegrationLoad(32, 9, 16)...)
		code = append(code, sseXORPSBytes(15, 9)...)
		b := sseIntegrationRequire(t, code, face)
		sseIntegrationVectors(t, b, sseIntegrationValues(t, b), map[int]uint64{15: 0x3f800001 ^ right, 9: right})
		c, err := sseIntegrationCheck(t, append(code, sseIntegrationCompare(32, 15, 15)...), face)
		transitionRefused(t, c, err)
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.Premise != "transition-sse-operands" {
			t.Fatal("manufactured exceptional operand failed for unrelated reason", err)
		}
	}
}

func TestTransitionXORPSModelsAndUnsupportedForms(t *testing.T) {
	face := sseIntegrationFace()
	for _, model := range []string{"", "future-sse"} {
		face.Conditions.SSE = model
		c, err := sseIntegrationCheck(t, sseXORPSBytes(15, 9), face)
		transitionRefused(t, c, err)
	}
	face.Conditions.SSE = SSEModel
	for _, raw := range sseXORPSUnsupported() {
		t.Run(raw, func(t *testing.T) {
			c, err := sseIntegrationCheck(t, hexBytes(t, raw), face)
			transitionRefused(t, c, err)
		})
	}
}

func TestTransitionXORPSOptionalExpansion(t *testing.T) {
	face := sseIntegrationFace()
	// Neither a cut nor an independently excluded boundary executes XORPS or
	// requires its optional SSE applicability. Expansion is a search choice.
	for _, raw := range []string{"0f57c1", "450f57ff", "0f570424", "660f57c1", "660fefc1", "480f57c1"} {
		t.Run(raw, func(t *testing.T) {
			xor := hexBytes(t, raw)
			code := append([]byte{0xb8, 0, 0, 0, 0}, xor...)
			im := image(t, code)
			p, err := ProposeTransition(t.Context(), im, testEntry+5, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			c, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c.Bound()
			if len(b.Instructions) != 1 || !slices.Equal(b.Boundary.Bytes, xor) || b.InitialVectors != (TransitionVectors{}) {
				t.Fatal("unexecuted cut acquired SSE semantics")
			}
			// MOV EAX,0; TEST EAX,EAX; JE skips the structural boundary.
			code = append([]byte{0xb8, 0, 0, 0, 0, 0x85, 0xc0, 0x74, byte(len(xor))}, xor...)
			cut := testEntry + uint64(len(code))
			im = image(t, append(code, 0xbb, 0, 0, 0, 0))
			p, err = ProposeTransition(t.Context(), im, cut, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			c, err = CheckTransition(t.Context(), im, face, p, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			b, _ = c.Bound()
			if len(b.Instructions) != 3 || len(b.ExcludedBoundaries) != 1 || !slices.Equal(b.ExcludedBoundaries[0].Bytes, xor) || len(b.Accesses) != 0 || b.InitialVectors != (TransitionVectors{}) {
				t.Fatal("excluded boundary gained execution or effects")
			}
			// The same unexpanded boundary is now feasible and must refuse,
			// even when the executed register form could have been expanded.
			code[1] = 1
			im = image(t, append(code, 0xbb, 0, 0, 0, 0))
			p, err = ProposeTransition(t.Context(), im, cut, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			c, err = CheckTransition(t.Context(), im, face, p, TransitionLimits{})
			transitionRefused(t, c, err)
		})
	}
}

func TestTransitionXORPSCompletedReturn(t *testing.T) {
	code := append(sseXORPSBytes(15, 8), 0xc3)
	im, face := returnFixture(t, fmt.Sprintf("%x", code))
	face.Conditions.SSE = SSEModel
	prefix := returnPrefix(t, im, face, testEntry+uint64(len(code)-1), sseIntegrationExpansions(code[:len(code)-1], testEntry)...)
	returned := checkedReturn(t, prefix)
	b, ok := returned.Bound()
	if !ok || !b.State.CalleeTerminated || b.State.Vectors != b.Prefix.Vectors || b.State.Flags != b.Prefix.Flags || b.State.Direction != b.Prefix.InitialDirection || b.State.SSE != b.Prefix.SSE || !b.State.SSE.MXCSRPreserved || !b.State.SSE.UpperVectorsPreserved {
		t.Fatal("completed return lost XORPS/direction/context state")
	}
	values := sseIntegrationValues(t, b.Prefix)
	for r, v := range b.State.Vectors {
		lo, hi := values[b.Prefix.InitialVectors[r].Lo], values[b.Prefix.InitialVectors[r].Hi]
		if r == 15 {
			lo ^= values[b.Prefix.InitialVectors[8].Lo]
			hi ^= values[b.Prefix.InitialVectors[8].Hi]
		}
		if evalRelationTerm(t, v.Lo, values, 0) != lo || evalRelationTerm(t, v.Hi, values, 0) != hi {
			t.Fatal("completed return restored stale vector state")
		}
	}
}
