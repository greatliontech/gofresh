package transitionoracle

import (
	"bytes"
	"encoding/hex"
	"math"
	"math/big"
	"testing"
)

// These are literal encodings, not encoder-generated fixtures. They pin Intel
// operand direction, little-endian order, register extensions, group selectors,
// signed byte/dword extension, zero extension, and ignored bit conventions.
func TestLiteralEncodings(t *testing.T) {
	cases := []struct {
		name, hex string
		i         Intent
		e         Encoding
	}{
		{"mov89", "4889d8", Intent{Operation: MoveRegister, Dst: 0, Src: 3}, Encoding{Form: MOV89, REX: 0x48}},
		{"mov8b", "4f8bc1", Intent{Operation: MoveRegister, Dst: 8, Src: 9}, Encoding{Form: MOV8B, REX: 0x4f}},
		{"store", "4c895a80", Intent{Operation: Store, Src: 11, Base: 2, SignedDisp: -128}, Encoding{Form: MOV89, REX: 0x4c, DispBytes: 1}},
		{"load-r13", "4b8bb501000080", Intent{Operation: Load, Dst: 6, Base: 13, SignedDisp: -2147483647}, Encoding{Form: MOV8B, REX: 0x4b, DispBytes: 4}},
		{"sib-r12", "498b0424", Intent{Operation: Load, Dst: 0, Base: 12}, Encoding{Form: MOV8B, REX: 0x49, SIB: true}},
		{"optional-sib-scale", "4d8984e388776655", Intent{Operation: Store, Src: 8, Base: 11, SignedDisp: 1432778632}, Encoding{Form: MOV89, REX: 0x4d, DispBytes: 4, SIB: true, Scale: 3}},
		{"optional-sib-r13-zero", "498b446500", Intent{Operation: Load, Base: 13}, Encoding{Form: MOV8B, REX: 0x49, DispBytes: 1, SIB: true, Scale: 1}},
		{"mov64", "48b8efcdab8967452301", Intent{Operation: MoveImmediate, Immediate: 0x0123456789abcdef}, Encoding{Form: MOVB8Imm64, REX: 0x48}},
		{"mov64-high-ignored", "4fbf1032547698badcfe", Intent{Operation: MoveImmediate, Dst: 15, Immediate: 0xfedcba9876543210}, Encoding{Form: MOVB8Imm64, REX: 0x4f}},
		{"mov32-low", "b8ffffffff", Intent{Operation: MoveImmediate32, Immediate: 0xffffffff}, Encoding{Form: MOVB8Imm32}},
		{"mov32-high", "41bf00000080", Intent{Operation: MoveImmediate32, Dst: 15, Immediate: 0x80000000}, Encoding{Form: MOVB8Imm32, REX: 0x41}},
		{"c7-sign", "4fc7c000000080", Intent{Operation: MoveImmediate, Dst: 8, Immediate: 0xffffffff80000000}, Encoding{Form: MOVC7, REX: 0x4f}},
		{"c7-store", "4cc784a5ffffffffffffffff", Intent{Operation: StoreImmediate, Base: 5, SignedDisp: -1, Immediate: math.MaxUint64}, Encoding{Form: MOVC7, REX: 0x4c, DispBytes: 4, SIB: true, Scale: 2}},
		{"lea", "4e8d8a78563412", Intent{Operation: LEA, Dst: 9, Base: 2, SignedDisp: 305419896}, Encoding{Form: LEA8D, REX: 0x4e, DispBytes: 4}},
		{"lea-rip-negative", "4f8d3d00000080", Intent{Operation: LEARIP, Dst: 15, SignedDisp: -2147483648}, Encoding{Form: LEA8D, REX: 0x4f, DispBytes: 4}},
		{"lea-rip-positive", "488d3dffffff7f", Intent{Operation: LEARIP, Dst: 7, SignedDisp: 2147483647}, Encoding{Form: LEA8D, REX: 0x48, DispBytes: 4}},
		{"sub8", "4f83ef80", Intent{Operation: Subtract, Dst: 15, Immediate: 0xffffffffffffff80}, Encoding{Form: SUB83, REX: 0x4f}},
		{"sub32", "4881e9ffffff7f", Intent{Operation: Subtract, Dst: 1, Immediate: 0x7fffffff}, Encoding{Form: SUB81, REX: 0x48}},
		{"sub-rax-ignored", "4f2d00000080", Intent{Operation: Subtract, Immediate: 0xffffffff80000000}, Encoding{Form: SUB2D, REX: 0x4f}},
		{"and8", "4f83e3ff", Intent{Operation: And, Dst: 11, Immediate: math.MaxUint64}, Encoding{Form: AND83, REX: 0x4f}},
		{"and32", "4981e278563492", Intent{Operation: And, Dst: 10, Immediate: 0xffffffff92345678}, Encoding{Form: AND81, REX: 0x49}},
		{"and-rax-ignored", "4f25f0ffffff", Intent{Operation: And, Immediate: 0xfffffffffffffff0}, Encoding{Form: AND25, REX: 0x4f}},
		{"jmp8-min", "eb80", Intent{Operation: Jump, SignedDisp: -128}, Encoding{Form: JMPEB}},
		{"jmp8-max", "eb7f", Intent{Operation: Jump, SignedDisp: 127}, Encoding{Form: JMPEB}},
		{"jmp32-min", "e900000080", Intent{Operation: Jump, SignedDisp: -2147483648}, Encoding{Form: JMPE9}},
		{"jmp32-max", "e9ffffff7f", Intent{Operation: Jump, SignedDisp: 2147483647}, Encoding{Form: JMPE9}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := hex.DecodeString(c.hex)
			if err != nil {
				t.Fatal(err)
			}
			d, err := Parse(append(append([]byte{}, b...), 0xff, 0x00, 0x48), 1<<32)
			if err != nil {
				t.Fatal(err)
			}
			if d.Intent != c.i || d.Encoding != c.e || d.Length != len(b) || d.Next != 1<<32+uint64(len(b)) {
				t.Fatalf("decoded %+v; want %+v / %+v, length %d", d, c.i, c.e, len(b))
			}
			got, err := Encode(c.i, c.e)
			if err != nil || !bytes.Equal(got, b) {
				t.Fatalf("encoded %x, %v; want %x", got, err, b)
			}
			if c.i.Operation == Jump {
				assertTarget(t, d, 1<<32)
			}
			for n := 0; n < len(b); n++ {
				if got, err := Parse(b[:n], 1<<32); err == nil || got != (Decoded{}) {
					t.Fatalf("truncation %d: %+v, %v", n, got, err)
				}
			}
		})
	}
}

// The reference uses unbounded signed integers, not the parser's machine-word
// arithmetic. It also checks overflow of NEXT independently of the final target:
// a negative relative branch cannot rescue a wrapped instruction end.
func assertTarget(t testing.TB, d Decoded, pc uint64) {
	t.Helper()
	want := new(big.Int).SetUint64(pc)
	want.Add(want, big.NewInt(int64(d.Length)))
	if !want.IsUint64() || want.Uint64() != d.Next {
		t.Fatalf("instruction end %x; integer rule says %s", d.Next, want)
	}
	want.Add(want, big.NewInt(d.Intent.SignedDisp))
	if !want.IsUint64() || want.Uint64() != d.Target {
		t.Fatalf("target %x; integer rule says %s", d.Target, want)
	}
}

func TestNonwrappingBranches(t *testing.T) {
	cases := []struct {
		bytes  string
		pc     uint64
		valid  bool
		target uint64
	}{
		{"ebfe", 0, true, 0},
		{"ebfd", 0, false, 0},
		{"eb80", 126, true, 0},
		{"eb80", 125, false, 0},
		{"eb00", math.MaxUint64 - 2, true, math.MaxUint64},
		{"eb01", math.MaxUint64 - 2, false, 0},
		{"ebff", math.MaxUint64 - 1, false, 0},
		{"e900000080", 2147483643, true, 0},
		{"e900000080", 2147483642, false, 0},
		{"e9ffffff7f", math.MaxUint64 - 2147483652, true, math.MaxUint64},
		{"e9ffffff7f", math.MaxUint64 - 2147483651, false, 0},
		{"e9ffffffff", math.MaxUint64 - 4, false, 0},
	}
	for _, c := range cases {
		b, _ := hex.DecodeString(c.bytes)
		d, err := Parse(b, c.pc)
		if (err == nil) != c.valid {
			t.Fatalf("%s @ %x: %+v, %v", c.bytes, c.pc, d, err)
		}
		if c.valid {
			if d.Target != c.target {
				t.Fatalf("%s @ %x target %x want %x", c.bytes, c.pc, d.Target, c.target)
			}
			assertTarget(t, d, c.pc)
		} else if d != (Decoded{}) {
			t.Fatalf("partial decoded result on error: %+v", d)
		}
	}
	if _, err := Parse([]byte{0x48, 0x89, 0xc0}, math.MaxUint64-2); err == nil {
		t.Fatal("nonbranch end wrapped")
	}
}
