package nativeproof

import (
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

func TestTransitionSSEExactForms(t *testing.T) {
	for _, raw := range [][]byte{
		{0xf3, 0x0f, 0x10, 0x04, 0x24},             // MOVSS X0,[RSP]
		{0xf2, 0x45, 0x0f, 0x10, 0x7d, 0x08},       // MOVSD X15,[R13+8]
		{0xf2, 0x0f, 0x10, 0x05, 0x17, 0, 0, 0},    // MOVSD X0,[RIP+23]
		{0xf3, 0x44, 0x0f, 0x10, 0x7c, 0x24, 0xfc}, // MOVSS X15,[RSP-4]
		{0x0f, 0x2e, 0xc1},                         // UCOMISS X0,X1
		{0x66, 0x0f, 0x2e, 0xc1},                   // UCOMISD X0,X1
		{0x45, 0x0f, 0x2e, 0xfe},                   // UCOMISS X15,X14
		{0x66, 0x45, 0x0f, 0x2e, 0xfe},             // UCOMISD X15,X14
	} {
		i, err := x86asm.Decode(raw, 64)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateTransitionSSEForm(0, i, raw); err != nil {
			t.Fatalf("valid %x (%s): %v", raw, i, err)
		}
		if err := validateTransitionSSEForm(0, i, append(append([]byte{}, raw...), 0x90)); err == nil {
			t.Fatal("accepted extra instruction bytes")
		}
	}
	for _, raw := range [][]byte{
		{0xa5}, {0xf3, 0xa5}, // String MOVSD, with and without REP.
		{0xf3, 0x0f, 0x10, 0xc1}, {0xf2, 0x0f, 0x10, 0xc1}, // Register MOV has different high-lane rules.
		{0xf3, 0x0f, 0x11, 0x04, 0x24}, {0xf2, 0x0f, 0x11, 0x04, 0x24},
		{0x0f, 0x2e, 0x04, 0x24}, {0x66, 0x0f, 0x2e, 0x04, 0x24}, // Memory compare.
		{0x0f, 0x2f, 0xc1}, {0x66, 0x0f, 0x2f, 0xc1}, // COMIS also faults on quiet NaNs.
		{0xc5, 0xfa, 0x10, 0x04, 0x24}, {0xc5, 0xf8, 0x2e, 0xc1}, // AVX.
		{0xf3, 0x48, 0x0f, 0x10, 0x04, 0x24}, // Nonselected REX.W spelling.
		{0x48, 0xf3, 0x0f, 0x10, 0x04, 0x24}, // Prefix order.
		{0xf3, 0xf3, 0x0f, 0x10, 0x04, 0x24},
		{0x66, 0xf3, 0x0f, 0x10, 0x04, 0x24},
		{0xf3, 0x64, 0x0f, 0x10, 0x04, 0x24},       // Segment override.
		{0xf3, 0x67, 0x0f, 0x10, 0x04, 0x24},       // Address override.
		{0xf3, 0x0f, 0x10, 0x04, 0x44},             // Indexed memory.
		{0xf3, 0x0f, 0x10, 0x04, 0x25, 0, 0, 0, 0}, // Absolute memory.
		{0xf0, 0x0f, 0x2e, 0xc1},                   // LOCK.
	} {
		i, err := x86asm.Decode(raw, 64)
		if err != nil {
			continue // Invalid structural decode already refuses.
		}
		if err := validateTransitionSSEForm(0, i, raw); err == nil {
			t.Fatalf("unsupported %x (%s) accepted", raw, i)
		}
	}
}

func TestTransitionSSECompareStep(t *testing.T) {
	for _, op := range []x86asm.Op{x86asm.UCOMISS, x86asm.UCOMISD} {
		m := sseTestChecker(t)
		vectors := m.initialSSEVectors()
		// A negative quiet NaN compares unordered; untouched high lanes remain
		// arbitrary even though the low comparison lane is a checked constant.
		vectors[15].Lo = m.con(br.Bits(64), 0xfff80000ffc00000)
		vectors[9].Lo = m.con(br.Bits(64), 0)
		before := vectors
		m.state.path = m.truth
		i := operation{Op: op, Args: [2]x86asm.Arg{x86asm.X15, x86asm.X9}}
		if err := m.sseStep(i, 4, &vectors, ""); err == nil {
			t.Fatal("comparison executed without SSE applicability")
		}
		if err := m.sseStep(i, 4, &vectors, SSEModel); err != nil {
			t.Fatal(err)
		}
		if vectors != before || len(m.bound.Accesses) != 0 || len(m.bound.PrimitiveEffects) != 0 {
			t.Fatal("register comparison changed operands or invented memory/primitive effects")
		}
		for _, flag := range []br.Term{m.bound.Flags.CF.Value, m.bound.Flags.ZF.Value, m.bound.Flags.PF.Value, m.state.flags[flagCarry], m.state.flags[flagZero]} {
			if evalRelationTerm(t, flag, nil, 0) != 1 {
				t.Fatal("unordered compare step lost projected/scalar flags")
			}
		}
		if evalRelationTerm(t, m.state.flags[flagLess], nil, 0) != 0 {
			t.Fatal("comparison invented signed-less flag")
		}
	}
}
