package nativeproof

import (
	"fmt"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

// Exercise the same partial-register insertion, 32-bit read/write and comparison
// roots as MOV AL,[byte]; MOV EDX,255; AND EAX,EDX; CMP EAX,expected; JNE.
// No incoming upper accumulator bit is constrained by the byte load.
func TestByteMaskGuardScalarRoot(t *testing.T) {
	for value := uint64(0); value < 256; value++ {
		kernel, err := NewTransferKernel(t.Context(), RelationLimits{})
		if err != nil {
			t.Fatal(err)
		}
		builder := br.NewBuilder(0)
		scratch, err := builder.Scratch(br.Bits(64), br.NewScope(), 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := kernel.inputs(scratch); err != nil {
			t.Fatal(err)
		}
		m := kernel.meter
		state := symbolicState{}
		state.regs[RAX] = scratch
		al, eax, edx := alias{reg: int(RAX), width: 8}, alias{reg: int(RAX), width: 32}, alias{reg: int(RDX), width: 32}
		m.write(&state, al, m.con(br.Bits(8), value))
		m.write(&state, edx, m.con(br.Bits(32), 255))
		masked := m.binary(br.BitAnd, m.read(&state, eax), m.read(&state, edx))
		m.write(&state, eax, masked)
		guard := m.not(m.compare(br.Equal, m.read(&state, eax), m.con(br.Bits(32), value)))
		if m.err != nil {
			t.Fatal(m.err)
		}
		if _, err := br.Prove(t.Context(), guard, m.falsity, br.Limits{}); err != nil {
			t.Fatalf("byte=%d guard=%s: %v", value, byteMaskTerm(guard), err)
		}
		if _, err := br.Prove(t.Context(), state.regs[RAX], m.con(br.Bits(64), value), br.Limits{}); err != nil {
			t.Fatalf("32-bit write did not erase upper accumulator bits: %v", err)
		}
		for _, incoming := range []uint64{0, ^uint64(0), 0x123456789abcdef0} {
			got, err := br.Eval(t.Context(), state.regs[RAX], []br.Assignment{{Variable: scratch, Value: incoming}}, br.Limits{})
			if err != nil || got != value {
				t.Fatalf("upper scratch %#x: accumulator=%#x want=%#x error=%v", incoming, got, value, err)
			}
		}
	}
}

func byteMaskTerm(term br.Term) string {
	view := term.View()
	names := map[br.Op]string{br.Constant: "const", br.Variable: "scratch", br.Extract: "extract", br.Trunc: "trunc", br.ZExt: "zext", br.Concat: "concat", br.BitAnd: "and", br.Equal: "eq", br.Not: "not"}
	text := fmt.Sprintf("%s%d[%d]", names[view.Op], view.Sort.Width(), view.Immediate)
	for _, argument := range view.Args {
		text += "(" + byteMaskTerm(argument) + ")"
	}
	return text
}
