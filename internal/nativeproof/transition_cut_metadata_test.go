package nativeproof

import (
	"reflect"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestTransitionCutVectorContext(t *testing.T) {
	for _, tc := range []struct {
		code       string
		opcode     uint32
		arg        x86asm.Arg
		pcrel, off int
	}{
		{"c5f858c1", 0x58c10000, x86asm.X1, 0, 0},
		{"c4e17858c1", 0x58c10000, x86asm.X1, 0, 0},
		{"62f17c4858c1", 0x58c10000, x86asm.Z1, 0, 0},
		{"c5f8580500000000", 0x58050000, x86asm.Mem{Base: x86asm.RIP}, 4, 4},
		{"c4e1785805ffffffff", 0x58050000, x86asm.Mem{Base: x86asm.RIP, Disp: -1}, 4, 5},
		{"62f17c48580500000080", 0x58050000, x86asm.Mem{Base: x86asm.RIP, Disp: -2147483648}, 4, 6},
		{"c5f8580485ffffffff", 0x58048500, x86asm.Mem{Index: x86asm.RAX, Scale: 4, Disp: -1}, 0, 0},
	} {
		t.Run(tc.code, func(t *testing.T) {
			c, err := proveTransition(t, image(t, hexBytes(t, "4889e0"+tc.code)), testEntry+3, transitionFace())
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c.Bound()
			i := b.Boundary.Instruction
			if i.Mode != 64 || i.AddrSize != 64 || i.DataSize != 32 || i.Opcode != tc.opcode || i.PCRel != tc.pcrel || i.PCRelOff != tc.off || !reflect.DeepEqual(i.Args[2], tc.arg) {
				t.Fatalf("incorrect decoded context: %#v; operand=%#v", i, i.Args[2])
			}
		})
	}
}

func TestTransitionCutInvalidPrefixMarker(t *testing.T) {
	for _, code := range []string{"f0c3", "f090", "f04889e0"} {
		i, err := x86asm.Decode(hexBytes(t, code), 64)
		if err != nil || i.Prefix[0]&x86asm.PrefixInvalid == 0 {
			t.Fatalf("missing baseline invalid marker: %#v %v", i, err)
		}
		c, err := proveTransition(t, image(t, hexBytes(t, "4889e0"+code)), testEntry+3, transitionFace())
		transitionRefused(t, c, err)
	}
	// Structural admission retains valid unsupported operations and ignored
	// prefixes. UD2 is a valid instruction whose execution raises #UD.
	for _, code := range []string{"0f0b", "0fa2", "0f05", "c3", "f3c3", "2ec3", "f00100"} {
		_, err := proveTransition(t, image(t, hexBytes(t, "4889e0"+code)), testEntry+3, transitionFace())
		if err != nil {
			t.Fatalf("valid cut %s: %v", code, err)
		}
	}
}
