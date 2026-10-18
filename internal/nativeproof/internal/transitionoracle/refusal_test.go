package transitionoracle

import (
	"encoding/hex"
	"math"
	"testing"
)

func TestExecutedOnlyRefusals(t *testing.T) {
	for _, text := range []string{
		"90", "4890", "66e800000000", "66c3", "c20000", "eb", "e9000000",
		"7800", "0f8800000000", "ffe0", "48ffe0", "488dca",
		"488b042500000000", "498b042500000000", // absent SIB base, even with B.
		"4b8b0424", "488b0400", "4b8bb401000080", // X selects R12 / explicit index.
		"48830000", "48812000000000", // arithmetic memory is not executed here.
		"48c7c800000000", "4883c800", "4881d800000000", // wrong groups.
		"6689c0", "668bc0", "664189c0", "40b800000000", "42b800000000",
		"43b800000000", "44b800000000", "45b800000000", "46b800000000", "47b800000000",
		"674888c0", "67488ac0", "c5f877", "c4e17877", "62f17c4858c0",
		"488b", "488b04", "488b4424", "48b800000000", "41b8000000",
	} {
		b, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		if d, err := Parse(b, 1<<32); err == nil || d != (Decoded{}) {
			t.Errorf("refused %s: %+v %v", text, d, err)
		}
	}
	// Every architectural legacy prefix, every REX byte (including duplicate
	// REX.W), and both size overrides fail before each otherwise valid form.
	// The byte immediately following an instruction is not a prefix of it.
	prefixes := []byte{0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67}
	for p := byte(0x40); p <= 0x4f; p++ {
		prefixes = append(prefixes, p)
	}
	for _, text := range []string{"4889c0", "488b0424", "eb00", "e900000000", "41b800000000", "0fa2"} {
		b, _ := hex.DecodeString(text)
		for _, prefix := range prefixes {
			input := append([]byte{prefix}, b...)
			if d, err := Parse(input, 1<<32); err == nil || d != (Decoded{}) {
				t.Fatalf("prefix %x before %s: %+v %v", prefix, text, d, err)
			}
		}
	}
}

func TestOpcodeAndPrefixPopulation(t *testing.T) {
	// All first bytes, then all opcodes following every REX byte. Trailing
	// zeros supply sufficient payloads but are not themselves extra prefixes.
	for first := 0; first < 256; first++ {
		b := append([]byte{byte(first)}, make([]byte, 14)...)
		valid := first >= 0xb0 && first <= 0xbf || first == 0xeb || first == 0xe9 || first >= 0x72 && first <= 0x77 || first >= 0x7c && first <= 0x7f || first == 0x3d || first == 0xa9 || first == 0x88 || first == 0x89 || first == 0x8a || first == 0x8b || first == 0xc6 || first == 0xc7
		valid = valid || first == 0xe8 || first == 0xc3 || first >= 0x50 && first <= 0x5f
		_, err := Parse(b, 1<<32)
		if (err == nil) != valid {
			t.Fatalf("first byte %x accepted=%v want %v", first, err == nil, valid)
		}
	}
	for rex := 0x40; rex <= 0x4f; rex++ {
		for op := 0; op < 256; op++ {
			// ModRM c0 gives MOV register, C7 /0; arithmetic groups get
			// a separately checked c0|selector below rather than a false
			// claim that every mnemonic's ModRM c0 must be accepted.
			b := append([]byte{byte(rex), byte(op), 0xc0}, make([]byte, 12)...)
			valid := op == 0x89 || op == 0x8b || op == 0xc7 || op == 0x39 || op == 0x3b || op == 0x85 || op == 0xf7 || op == 0x3d || op == 0xa9 || op >= 0xb0 && op <= 0xb7 || op == 0x88 || op == 0x8a || op == 0xc6
			if rex == 0x41 {
				valid = valid || op >= 0xb8 && op <= 0xbf || op >= 0x50 && op <= 0x5f
			}
			if rex >= 0x48 {
				valid = valid || op >= 0xb8 && op <= 0xbf || op == 0x25 || op == 0x2d || op == 0x05 || op == 0x81 || op == 0x83
			} else {
				valid = valid || op >= 0xb0 && op <= 0xb7 || op == 0x88 || op == 0x8a || op == 0xc6
			}
			_, err := Parse(b, 1<<32)
			if (err == nil) != valid {
				t.Fatalf("REX/op %02x %02x accepted=%v want %v", rex, op, err == nil, valid)
			}
		}
	}
}

func TestEncodeRefusesNormalization(t *testing.T) {
	cases := []Descriptor{
		{Intent{Operation: CPUID, Dst: 1}, Encoding{Form: CPUID0FA2}},
		{Intent{Operation: CPUID, Src: 1}, Encoding{Form: CPUID0FA2}},
		{Intent{Operation: CPUID, Base: 1}, Encoding{Form: CPUID0FA2}},
		{Intent{Operation: CPUID, Immediate: 1}, Encoding{Form: CPUID0FA2}},
		{Intent{Operation: CPUID, SignedDisp: 1}, Encoding{Form: CPUID0FA2}},
		{Intent{Operation: CPUID}, Encoding{Form: CPUID0FA2, REX: 0x48}},
		{Intent{Operation: MoveRegister, Dst: 16}, Encoding{Form: MOV89, REX: 0x48}},
		{Intent{Operation: MoveRegister, Src: 255}, Encoding{Form: MOV89, REX: 0x48}},
		{Intent{Operation: Load, Base: 16}, Encoding{Form: MOV8B, REX: 0x48}},
		{Intent{Operation: MoveRegister, Dst: 8}, Encoding{Form: MOV89, REX: 0x48}},
		{Intent{Operation: MoveRegister, Src: 8}, Encoding{Form: MOV89, REX: 0x48}},
		{Intent{Operation: MoveRegister, Base: 1}, Encoding{Form: MOV89, REX: 0x48}},
		{Intent{Operation: MoveRegister, Immediate: 1}, Encoding{Form: MOV89, REX: 0x48}},
		{Intent{Operation: Load, Src: 1}, Encoding{Form: MOV8B, REX: 0x48}},
		{Intent{Operation: Load, Immediate: 1}, Encoding{Form: MOV8B, REX: 0x48}},
		{Intent{Operation: Store, Dst: 1}, Encoding{Form: MOV89, REX: 0x48}},
		{Intent{Operation: StoreImmediate, Src: 1}, Encoding{Form: MOVC7, REX: 0x48}},
		{Intent{Operation: MoveImmediate, Src: 1}, Encoding{Form: MOVC7, REX: 0x48}},
		{Intent{Operation: Jump, Dst: 1}, Encoding{Form: JMPEB}},
		{Intent{Operation: Jump, Immediate: 1}, Encoding{Form: JMPEB}},
		{Intent{Operation: Jump, SignedDisp: 128}, Encoding{Form: JMPEB}},
		{Intent{Operation: Jump, SignedDisp: -129}, Encoding{Form: JMPEB}},
		{Intent{Operation: Jump, SignedDisp: math.MaxInt32 + 1}, Encoding{Form: JMPE9}},
		{Intent{Operation: Jump, SignedDisp: math.MinInt32 - 1}, Encoding{Form: JMPE9}},
		{Intent{Operation: Jump}, Encoding{Form: JMPEB, REX: 0x48}},
		{Intent{Operation: MoveImmediate32, Immediate: 1 << 32}, Encoding{Form: MOVB8Imm32}},
		{Intent{Operation: MoveImmediate32, Dst: 8}, Encoding{Form: MOVB8Imm32}},
		{Intent{Operation: MoveImmediate32}, Encoding{Form: MOVB8Imm32, REX: 0x41}},
		{Intent{Operation: MoveImmediate32}, Encoding{Form: MOVB8Imm32, REX: 0x44}},
		{Intent{Operation: MoveImmediate}, Encoding{Form: MOVB8Imm64, REX: 0x49}},
		{Intent{Operation: MoveImmediate, Immediate: 0x80000000}, Encoding{Form: MOVC7, REX: 0x48}},
		{Intent{Operation: Subtract, Immediate: 128}, Encoding{Form: SUB83, REX: 0x48}},
		{Intent{Operation: Subtract, Immediate: 0xffffffffffffff7f}, Encoding{Form: SUB83, REX: 0x48}},
		{Intent{Operation: And, Immediate: 0x80000000}, Encoding{Form: AND81, REX: 0x48}},
		{Intent{Operation: And, Dst: 8}, Encoding{Form: AND25, REX: 0x49}},
		{Intent{Operation: LEA, Base: 5}, Encoding{Form: LEA8D, REX: 0x48}},
		{Intent{Operation: LEA, Base: 13}, Encoding{Form: LEA8D, REX: 0x49, SIB: true}},
		{Intent{Operation: Load, Base: 4}, Encoding{Form: MOV8B, REX: 0x48}},
		{Intent{Operation: Load}, Encoding{Form: MOV8B, REX: 0x4a, SIB: true}},
		{Intent{Operation: Load}, Encoding{Form: MOV8B, REX: 0x48, SIB: true, Scale: 4}},
		{Intent{Operation: Load}, Encoding{Form: MOV8B, REX: 0x48, Scale: 1}},
		{Intent{Operation: Load}, Encoding{Form: MOV8B, REX: 0x48, DispBytes: 2}},
		{Intent{Operation: Load, SignedDisp: 1}, Encoding{Form: MOV8B, REX: 0x48}},
		{Intent{Operation: Load, SignedDisp: 128}, Encoding{Form: MOV8B, REX: 0x48, DispBytes: 1}},
		{Intent{Operation: Load, SignedDisp: -129}, Encoding{Form: MOV8B, REX: 0x48, DispBytes: 1}},
		{Intent{Operation: Load, SignedDisp: math.MaxInt32 + 1}, Encoding{Form: MOV8B, REX: 0x48, DispBytes: 4}},
		{Intent{Operation: Load, SignedDisp: math.MinInt32 - 1}, Encoding{Form: MOV8B, REX: 0x48, DispBytes: 4}},
		{Intent{Operation: MoveRegister, SignedDisp: 1}, Encoding{Form: MOV89, REX: 0x48}},
		{Intent{Operation: MoveRegister}, Encoding{Form: MOV89, REX: 0x48, DispBytes: 1}},
		{Intent{Operation: MoveRegister}, Encoding{Form: MOV89, REX: 0x48, SIB: true}},
		{Intent{Operation: MoveRegister}, Encoding{Form: MOV89, REX: 0x40}},
		{Intent{Operation: MoveRegister}, Encoding{Form: MOV89, REX: 0x50}},
		{Intent{}, Encoding{}},
		{Intent{Operation: 255}, Encoding{Form: MOV89, REX: 0x48}},
		{Intent{Operation: MoveRegister}, Encoding{Form: 255, REX: 0x48}},
	}
	for _, c := range cases {
		if b, err := Encode(c.Intent, c.Encoding); err == nil || b != nil {
			t.Errorf("accepted/partially encoded %+v: %x %v", c, b, err)
		}
	}
	// Cross every semantic operation with every opcode form: acceptance is
	// exactly the form's declared operand meaning, not a mnemonic fallback.
	compatible := map[Form][]Operation{
		MOV89: {MoveRegister, Store}, MOV8B: {MoveRegister, Load}, MOVB8Imm64: {MoveImmediate}, MOVB8Imm32: {MoveImmediate32},
		MOVC7: {MoveImmediate, StoreImmediate}, LEA8D: {LEA}, SUB83: {Subtract}, SUB81: {Subtract}, SUB2D: {Subtract},
		AND83: {And}, AND81: {And}, AND25: {And}, JMPEB: {Jump}, JMPE9: {Jump},
	}
	for form := MOV89; form <= JMPE9; form++ {
		for op := MoveRegister; op <= Jump; op++ {
			e := Encoding{Form: form, REX: 0x48}
			if form == MOVB8Imm32 || form == JMPEB || form == JMPE9 {
				e.REX = 0
			}
			valid := false
			for _, expected := range compatible[form] {
				valid = valid || op == expected
			}
			_, err := Encode(Intent{Operation: op}, e)
			if (err == nil) != valid {
				t.Errorf("op %d form %d accepted=%v want %v", op, form, err == nil, valid)
			}
		}
	}
}
