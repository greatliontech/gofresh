package transitionoracle

import (
	"bytes"
	"testing"
)

func TestClear32EncodingPopulation(t *testing.T) {
	count := 0
	for _, rex := range []byte{0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47} {
		for _, opcode := range []byte{0x31, 0x33} {
			for modrm := 0; modrm < 256; modrm++ {
				var raw []byte
				if rex != 0 {
					raw = append(raw, rex)
				}
				raw = append(raw, opcode, byte(modrm))
				// An independent arithmetic predicate covers every ModRM byte and
				// ignored-X/absent/redundant REX choice in this bounded population.
				r := uint8(modrm/8%8) + 8*((rex/4)%2)
				b := uint8(modrm%8) + 8*(rex%2)
				admitted := modrm >= 192 && r == b
				d, err := Parse(raw, 0x401000)
				if (err == nil) != admitted {
					t.Fatalf("%x admission=%t err=%v", raw, admitted, err)
				}
				if !admitted {
					continue
				}
				count++
				if d.Intent != (Intent{Operation: Clear32, Dst: r}) || d.Length != len(raw) {
					t.Fatal("wrong decoded intent")
				}
				encoded, err := Encode(d.Intent, d.Encoding)
				if err != nil || !bytes.Equal(encoded, raw) {
					t.Fatal("encoding differs", err)
				}
				for n := 0; n < len(raw); n++ {
					if _, err := Parse(raw[:n], 0x401000); err == nil {
						t.Fatal("truncation accepted")
					}
				}
			}
		}
	}
	if count != 80 {
		t.Fatal("population changed", count)
	}
	for _, raw := range [][]byte{{0x31, 0xc0}, {0x45, 0x31, 0xff}, {0x47, 0x33, 0xc9}} {
		if _, err := Parse(raw, 0x401000); err != nil {
			t.Fatal("literal self-XOR refused", err)
		}
	}
}
