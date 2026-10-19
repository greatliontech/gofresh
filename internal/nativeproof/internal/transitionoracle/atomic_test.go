package transitionoracle

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAtomicLiteralForms(t *testing.T) {
	for _, tc := range []struct {
		code string
		i    Intent
		e    Encoding
	}{
		{"488711", Intent{Operation: LockedExchange, Base: 1, Src: 2}, Encoding{Form: XCHG87, REX: 0x48}},
		{"f0488711", Intent{Operation: LockedExchange, Base: 1, Src: 2}, Encoding{Form: LOCKXCHG87, REX: 0x48}},
		{"f0480fc111", Intent{Operation: LockedExchangeAdd, Base: 1, Src: 2}, Encoding{Form: LOCKXADD0FC1, REX: 0x48}},
		{"4801f2", Intent{Operation: AddRegister, Dst: 2, Src: 6}, Encoding{Form: ADD01, REX: 0x48}},
		{"4803d6", Intent{Operation: AddRegister, Dst: 2, Src: 6}, Encoding{Form: ADD03, REX: 0x48}},
		{"0f1f440000", Intent{Operation: NoOp}, Encoding{Form: NOP0F1F, NOPModRM: 0x44}},
		{"660f1f440000", Intent{Operation: NoOp}, Encoding{Form: NOP660F1F, NOPModRM: 0x44}},
		{"f00fb111", Intent{Operation: LockedCompareExchange, Width: 32, Base: 1, Src: 2}, Encoding{Form: LOCKCMPXCHG0FB1}},
		{"f0450fb14d04", Intent{Operation: LockedCompareExchange, Width: 32, Base: 13, Src: 9, SignedDisp: 4}, Encoding{Form: LOCKCMPXCHG0FB1, REX: 0x45, DispBytes: 1}},
		{"f00811", Intent{Operation: LockedOr, Width: 8, Base: 1, Src: 2}, Encoding{Form: LOCKOR08}},
		{"f02021", Intent{Operation: LockedAnd, Width: 8, Base: 1, Src: 0, HighSrc: true}, Encoding{Form: LOCKAND20}},
		{"f08049ff80", Intent{Operation: LockedOrImmediate, Width: 8, Base: 1, SignedDisp: -1, Immediate: 128}, Encoding{Form: LOCKOR80, DispBytes: 1}},
		{"f0418065017f", Intent{Operation: LockedAndImmediate, Width: 8, Base: 13, SignedDisp: 1, Immediate: 127}, Encoding{Form: LOCKAND80, REX: 0x41, DispBytes: 1}},
		{"3831", Intent{Operation: CompareMemory, Width: 8, Base: 1, Src: 2, HighSrc: true}, Encoding{Form: CMP38}},
		{"3a31", Intent{Operation: CompareFromMemory, Width: 8, Base: 1, Dst: 2, HighDst: true}, Encoding{Form: CMP3A}},
		{"807901ff", Intent{Operation: CompareMemoryImmediate, Width: 8, Base: 1, SignedDisp: 1, Immediate: 255}, Encoding{Form: CMP80, DispBytes: 1}},
		{"f0480fb111", Intent{Operation: LockedCompareExchange, Base: 1, Src: 2}, Encoding{Form: LOCKCMPXCHG0FB1, REX: 0x48}},
		{"f04d0fb14df8", Intent{Operation: LockedCompareExchange, Base: 13, Src: 9, SignedDisp: -8}, Encoding{Form: LOCKCMPXCHG0FB1, REX: 0x4d, DispBytes: 1}},
		{"0f94c4", Intent{Operation: SetRegister, Dst: 0, HighDst: true, Width: 8, Condition: 4}, Encoding{Form: SETcc0F90}},
		{"400f94c4", Intent{Operation: SetRegister, Dst: 4, Width: 8, Condition: 4}, Encoding{Form: SETcc0F90, REX: 0x40}},
		{"0f95442409", Intent{Operation: SetMemory, Base: 4, Width: 8, SignedDisp: 9, Condition: 5}, Encoding{Form: SETcc0F90, DispBytes: 1, SIB: true}},
		{"84e1", Intent{Operation: Test, Dst: 1, Src: 0, HighSrc: true, Width: 8}, Encoding{Form: TEST84}},
		{"f6c180", Intent{Operation: TestImmediate, Dst: 1, Width: 8, Immediate: 128}, Encoding{Form: TESTF6}},
		{"a8ff", Intent{Operation: TestImmediate, Width: 8, Immediate: 255}, Encoding{Form: TESTA8}},
		{"48833df8ffffff2a", Intent{Operation: CompareMemoryImmediate, RIP: true, SignedDisp: -8, Immediate: 42}, Encoding{Form: CMP83, REX: 0x48, DispBytes: 4}},
		{"48391424", Intent{Operation: CompareMemory, Base: 4, Src: 2}, Encoding{Form: CMP39, REX: 0x48, SIB: true}},
		{"483b1424", Intent{Operation: CompareFromMemory, Base: 4, Dst: 2}, Encoding{Form: CMP3B, REX: 0x48, SIB: true}},
	} {
		b, err := hex.DecodeString(tc.code)
		if err != nil {
			t.Fatal(err)
		}
		d, err := Parse(b, 1<<32)
		if err != nil || d.Intent != tc.i || d.Encoding != tc.e || d.Length != len(b) {
			t.Fatal(tc.code, d, err)
		}
		encoded, err := Encode(tc.i, tc.e)
		if err != nil || !bytes.Equal(encoded, b) {
			t.Fatal(tc.code, encoded, err)
		}
		for j := 0; j < len(b); j++ {
			if _, err := Parse(b[:j], 1<<32); err == nil {
				t.Fatal("truncation", tc.code, j)
			}
		}
	}
	for _, s := range []string{"480fb111", "f066480fb111", "f0f0480fb111", "f0480fb1d1", "f0480fb1042500000000", "f04b0fb11424", "f2480fb111", "f0480fb011", "0f94c8", "0f90c0", "0f98c0", "660f94c1", "f00f94c1", "6684c1", "f6c9ff", "0f94042500000000", "f080c801", "f02111", "f0662011", "f080710101", "f00fc111", "f0660f1f440000"} {
		b, _ := hex.DecodeString(s)
		if d, err := Parse(b, 0); err == nil || d != (Decoded{}) {
			t.Fatal("accepted unsupported form", s, d, err)
		}
	}
}

func TestRawAtomicAndSetPopulation(t *testing.T) {
	accepted := map[string]bool{}
	prefixes := []int{0}
	for rex := 0x40; rex <= 0x4f; rex++ {
		prefixes = append(prefixes, rex)
	}
	for _, locked := range []bool{false, true} {
		for _, rex := range prefixes {
			for cc := 0; cc < 16; cc++ {
				if locked && cc != 0 {
					continue
				}
				for m := 0; m < 256; m++ {
					mode, selector, low := m/64, m/8%8, m%8
					hasSIB := mode != 3 && low == 4
					n := 1
					if hasSIB {
						n = 256
					}
					for sib := 0; sib < n; sib++ {
						valid := true
						if locked {
							valid = mode != 3
						} else {
							valid = (cc >= 2 && cc <= 7 || cc >= 12) && selector == 0
						}
						if hasSIB && (rex&2 != 0 || sib/8%8 != 4 || mode == 0 && sib%8 == 5) {
							valid = false
						}
						code := []byte{}
						if locked {
							code = append(code, 0xf0)
						}
						if rex != 0 {
							code = append(code, byte(rex))
						}
						op := byte(0x90 + cc)
						if locked {
							op = 0xb1
						}
						code = append(code, 0x0f, op, byte(m))
						if hasSIB {
							code = append(code, byte(sib))
						}
						code = append(code, make([]byte, 8)...)
						d, err := Parse(code, 1<<32)
						if (err == nil) != valid {
							t.Fatalf("%x parsed=%+v err=%v want=%v", code, d, err, valid)
						}
						if valid {
							b, err := Encode(d.Intent, d.Encoding)
							if err != nil || !bytes.Equal(b, code[:d.Length]) {
								t.Fatal("lost spelling", d, err)
							}
							accepted[string(b)] = true
						}
					}
				}
			}
		}
	}
	if len(accepted) != 9480+13210 {
		t.Fatal("atomic raw population", len(accepted))
	}
	for d := range Descriptors {
		if d.Encoding.Form != LOCKCMPXCHG0FB1 && d.Encoding.Form != SETcc0F90 {
			continue
		}
		b, err := Encode(d.Intent, d.Encoding)
		if err != nil || !accepted[string(b)] {
			t.Fatal("descriptor absent from raw grammar", d, err)
		}
		delete(accepted, string(b))
	}
	if len(accepted) != 0 {
		t.Fatal("raw forms absent from descriptors", len(accepted))
	}
}

func FuzzAtomicGrammar(f *testing.F) {
	for _, b := range [][]byte{{0xf0, 0x0f, 0xb1, 0x11}, {0xf0, 0x44, 0x0f, 0xb1, 0x11}, {0xf0, 0x80, 0x09, 0x80}, {0xf0, 0x20, 0x21}, {0x80, 0x39, 0x80}, {0x38, 0x21}, {0x3a, 0x21}, {0x66, 0x0f, 0x1f, 0x44, 0, 0}} {
		f.Add(b)
	}
	for _, b := range [][]byte{{0xf0, 0x48, 0x0f, 0xb1, 0x11}, {0x0f, 0x94, 0xc1}, {0x84, 0xc9}, {0x48, 0x83, 0x39, 42}, {0x48, 0x87, 0x11}, {0xf0, 0x48, 0x0f, 0xc1, 0x11}, {0x48, 0x01, 0xf2}, {0x0f, 0x1f, 0x44, 0, 0}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 15 {
			b = b[:15]
		}
		d, err := Parse(b, 1<<32)
		if err != nil {
			return
		}
		encoded, err := Encode(d.Intent, d.Encoding)
		if err != nil || !bytes.Equal(b[:d.Length], encoded) {
			t.Fatal(d, err)
		}
	})
}
