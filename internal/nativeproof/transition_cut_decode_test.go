package nativeproof

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestTransitionVZEROUPPERCutBoundary(t *testing.T) {
	im := image(t, hexBytes(t, "4889e0c5f877c3"))
	cut := testEntry + 3
	c, err := proveTransition(t, im, cut, transitionFace())
	if err != nil {
		t.Fatal(err)
	}
	b, ok := c.Bound()
	if !ok {
		t.Fatal("missing certificate")
	}
	if b.Boundary.PC != cut || b.Boundary.Instruction.Op != x86asm.VZEROUPPER || b.Boundary.Instruction.Len != 3 || !bytes.Equal(b.Boundary.Bytes, hexBytes(t, "c5f877")) {
		t.Fatalf("published cut: PC=%#x instruction=%#v bytes=%x; want VZEROUPPER length=3 bytes=c5f877", b.Boundary.PC, b.Boundary.Instruction, b.Boundary.Bytes)
	}
	if !reflect.DeepEqual(straightFetches(t, b), []Span{{testEntry, cut}}) || len(b.Accesses) != 0 {
		t.Fatalf("cut or successor executed: instructions=%v accesses=%v", b.Instructions, b.Accesses)
	}
}

// The ISA's operand-free ZO encodings: L selects upper/all, W is ignored,
// and the inverted R/X/B extension bits have no operand to extend.
func vexZeroForms() [][]byte {
	var forms [][]byte
	for _, l := range []byte{0, 4} {
		for _, r := range []byte{0, 0x80} {
			forms = append(forms, []byte{0xc5, r | 0x78 | l, 0x77})
		}
		for rxb := byte(0); rxb < 8; rxb++ {
			for _, w := range []byte{0, 0x80} {
				forms = append(forms, []byte{0xc4, rxb<<5 | 1, w | 0x78 | l, 0x77})
			}
		}
	}
	return forms
}

func TestTransitionVEXZeroCutMetadata(t *testing.T) {
	for _, code := range vexZeroForms() {
		t.Run(fmt.Sprintf("%x", code), func(t *testing.T) {
			// The following bytes would exercise register ModRM, SIB, disp8,
			// disp32, or truncation if incorrectly borrowed by the decoder.
			for _, tail := range []string{"", "c3", "90", "00", "04", "05", "40", "80", "848578563412", "488b0424"} {
				im := image(t, append(hexBytes(t, "4889e0"), append(append([]byte(nil), code...), hexBytes(t, tail)...)...))
				cut := testEntry + 3
				// Supply the ISA-sized proposal independently of the proposer.
				p := TransitionProposal{ImageDigest: im.digest, Entry: testEntry, Cut: cut, Root: 1, Nodes: []TransitionNode{
					{ID: 1, PC: testEntry, Size: 3, Successors: []TransitionOccurrenceID{2}},
					{ID: 2, PC: cut, Size: uint8(len(code))},
				}}
				c, err := CheckTransition(t.Context(), im, transitionFace(), p, TransitionLimits{})
				if err != nil {
					t.Fatalf("tail=%s: %v", tail, err)
				}
				b, ok := c.Bound()
				if !ok || b.Boundary.PC != cut || !bytes.Equal(b.Boundary.Bytes, code) {
					t.Fatalf("tail=%s: boundary=%+v", tail, b.Boundary)
				}
				assertVEXZeroMetadata(t, code, b.Boundary.Instruction)
				if !reflect.DeepEqual(straightFetches(t, b), []Span{{testEntry, cut}}) || len(b.Accesses) != 0 || b.Registers[RAX].Value != b.InitialRegisters[RSP] || !reflect.DeepEqual(b.Memory, b.InitialMemory) {
					t.Fatalf("tail=%s: boundary/successor altered prefix state: %+v", tail, b)
				}
				for r, v := range b.Registers {
					if Register(r) != RAX && v.Value != b.InitialRegisters[r] {
						t.Fatalf("tail=%s: register %d changed", tail, r)
					}
				}
				// The old overlong proposal cannot establish an extra cut byte.
				p.Nodes[1].Size++
				d, err := CheckTransition(t.Context(), im, transitionFace(), p, TransitionLimits{})
				transitionRefused(t, d, err)
			}
		})
	}
}

func assertVEXZeroMetadata(t testing.TB, code []byte, got x86asm.Inst) {
	t.Helper()
	op := x86asm.VZEROUPPER
	if code[len(code)-2]&4 != 0 {
		op = x86asm.VZEROALL
	}
	want := x86asm.Inst{Op: op, Opcode: 0x77000000, Mode: 64, AddrSize: 64, DataSize: 32, Len: len(code)}
	for j, p := range code[:len(code)-1] {
		want.Prefix[j] = x86asm.Prefix(p)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("encoding=%x: retained instruction=%#v, want %#v", code, got, want)
	}
}

func TestVEXZeroDecodeIndependentOfFollowingBytes(t *testing.T) {
	for _, code := range vexZeroForms() {
		for following := -1; following < 256; following++ {
			raw := append([]byte(nil), code...)
			if following >= 0 {
				raw = append(raw, byte(following))
			}
			i, b, err := decodeBytes(image(t, raw), testEntry)
			if err != nil || !bytes.Equal(b, code) {
				t.Fatalf("encoding=%x following=%d: bytes=%x err=%v", code, following, b, err)
			}
			assertVEXZeroMetadata(t, code, i)
		}
	}
}

func TestVEXZeroCutRefusals(t *testing.T) {
	var invalid [][]byte
	for _, code := range vexZeroForms() {
		// Every proper prefix is truncated at the executable mapping's end.
		for n := 0; n < len(code); n++ {
			invalid = append(invalid, code[:n])
		}
		// All other reserved vvvv values and mandatory-prefix selectors.
		for v := byte(0); v < 15; v++ {
			bad := append([]byte(nil), code...)
			bad[len(bad)-2] = bad[len(bad)-2]&^0x78 | v<<3
			invalid = append(invalid, bad)
		}
		for pp := byte(1); pp < 4; pp++ {
			bad := append([]byte(nil), code...)
			bad[len(bad)-2] |= pp
			invalid = append(invalid, bad)
		}
	}
	for _, code := range []string{"c4e07877", "c4e27877", "c4e37877", "62f17c0877", "66c5f877", "f0c5f877", "f2c5f877", "f3c5f877", "48c5f877"} {
		invalid = append(invalid, hexBytes(t, code))
	}
	for _, code := range invalid {
		im := image(t, append(hexBytes(t, "4889e0"), code...))
		c, err := proveTransition(t, im, testEntry+3, transitionFace())
		if err == nil {
			t.Fatalf("malformed/truncated cut accepted: %x", code)
		}
		transitionRefused(t, c, err)
	}
}

func TestVEXZeroRemainsUnexecuted(t *testing.T) {
	for _, code := range vexZeroForms() {
		im := image(t, append(append(hexBytes(t, "4889e0"), code...), 0xc3))
		c, err := proveTransition(t, im, testEntry+3+uint64(len(code)), transitionFace())
		transitionRefused(t, c, err)
		leaf, err := prove(t, im, testEntry+3, face(Masks{}, Masks{}))
		requireRefusal(t, leaf, err, "instruction-prefix")
	}
}

func TestTransitionStructuralCutAdmission(t *testing.T) {
	// A cut is not limited to the transition's executable instruction grammar.
	// The neighboring VEX opcode retains its real ModRM instead of acquiring
	// the operand-free opcode 77 rule.
	for _, tc := range []struct {
		code string
		op   x86asm.Op
	}{
		{"0fa2", x86asm.CPUID},
		{"0f05", x86asm.SYSCALL},
		{"c3", x86asm.RET},
		{"e800000000", x86asm.CALL},
		{"c5f858c1", x86asm.VADDPS},
		{"c4e17858c1", x86asm.VADDPS},
	} {
		code := hexBytes(t, tc.code)
		im := image(t, append(hexBytes(t, "4889e0"), code...))
		cut := testEntry + 3
		c, err := proveTransition(t, im, cut, transitionFace())
		if err != nil {
			t.Fatalf("cut=%s: %v", tc.code, err)
		}
		b, ok := c.Bound()
		if !ok || b.Boundary.Instruction.Op != tc.op || b.Boundary.Instruction.Len != len(code) || !bytes.Equal(b.Boundary.Bytes, code) || !reflect.DeepEqual(straightFetches(t, b), []Span{{testEntry, cut}}) || len(b.Accesses) != 0 {
			t.Fatalf("cut=%s: boundary=%+v instructions=%v accesses=%v", tc.code, b.Boundary, b.Instructions, b.Accesses)
		}
		if tc.op == x86asm.VADDPS && b.Boundary.Instruction.Args[2] != x86asm.X1 {
			t.Fatalf("cut=%s: lost actual ModRM operand: %+v", tc.code, b.Boundary.Instruction)
		}
	}
}

func TestTransitionVectorCutRequiresModRM(t *testing.T) {
	for _, code := range []string{"c5f858", "c4e17858", "62f17c4858", "c5f9d7", "c4e278f2"} {
		t.Run(code, func(t *testing.T) {
			im := image(t, hexBytes(t, "4889e0"+code))
			c, err := proveTransition(t, im, testEntry+3, transitionFace())
			if b, ok := c.Bound(); ok {
				t.Fatalf("missing ModRM published cut: PC=%#x instruction=%#v bytes=%x", b.Boundary.PC, b.Boundary.Instruction, b.Boundary.Bytes)
			}
			transitionRefused(t, c, err)
		})
	}
}

// These cover each trailing-byte reader in avx.go, all three opcode maps,
// both VEX prefix lengths, EVEX, and memory/register/opcode-extension forms.
var vectorCutEncodings = []struct {
	code string
	op   x86asm.Op
}{
	{"c5f858c1", x86asm.VADDPS},
	{"c4e17858c1", x86asm.VADDPS},
	{"62f17c4858c1", x86asm.VADDPS},
	{"c5f9d7c1", x86asm.VPMOVMSKB},    // register-only ModRM form
	{"c4e278f2c1", x86asm.ANDN},       // VEX GPR form, not a vector operand
	{"c4e27900c1", x86asm.VPSHUFB},    // map 0F38
	{"c4e3790fc101", x86asm.VPALIGNR}, // map 0F3A, imm8
	{"62f37d480fc101", x86asm.VPALIGNR},
	{"c5f972f001", x86asm.VPSLLD},      // ModRM opcode extension, imm8
	{"c4e3794ac120", x86asm.VBLENDVPS}, // is4 register selector
	{"c5f85800", x86asm.VADDPS},
	{"c5f8580424", x86asm.VADDPS},         // SIB
	{"c5f858407f", x86asm.VADDPS},         // disp8
	{"c5f8588078563412", x86asm.VADDPS},   // disp32
	{"c5f8580578563412", x86asm.VADDPS},   // RIP-relative disp32
	{"c5f858048578563412", x86asm.VADDPS}, // SIB with no base, disp32
	{"62f17c48580424", x86asm.VADDPS},     // EVEX memory/SIB
}

func TestTransitionVectorCutStructuralBytes(t *testing.T) {
	for _, tc := range vectorCutEncodings {
		t.Run(tc.code, func(t *testing.T) {
			code := hexBytes(t, tc.code)
			cut := testEntry + 3
			for n := 0; n < len(code); n++ {
				// Test both physical EOF and bytes present in the artifact but
				// beyond the executable mapping. Neither supplies missing bytes.
				mapped := elfBytes(append(hexBytes(t, "4889e0"), code[:n]...))
				for _, raw := range [][]byte{mapped, append(append([]byte(nil), mapped...), code[n:]...)} {
					im, err := NewImage(t.Context(), raw)
					if err != nil {
						t.Fatal(err)
					}
					c, err := proveTransition(t, im, cut, transitionFace())
					if err == nil {
						t.Fatalf("truncated cut %x (artifact bytes=%d) accepted", code[:n], len(raw))
					}
					transitionRefused(t, c, err)
				}
			}
			var expected x86asm.Inst
			for following := -1; following < 256; following++ {
				body := append(hexBytes(t, "4889e0"), code...)
				if following >= 0 {
					body = append(body, byte(following))
				}
				im := image(t, body)
				p := TransitionProposal{ImageDigest: im.digest, Entry: testEntry, Cut: cut, Root: 1, Nodes: []TransitionNode{
					{ID: 1, PC: testEntry, Size: 3, Successors: []TransitionOccurrenceID{2}},
					{ID: 2, PC: cut, Size: uint8(len(code))},
				}}
				c, err := CheckTransition(t.Context(), im, transitionFace(), p, TransitionLimits{})
				if err != nil {
					t.Fatalf("following=%d: %v", following, err)
				}
				b, ok := c.Bound()
				if !ok || b.Boundary.PC != cut || b.Boundary.Instruction.Op != tc.op || b.Boundary.Instruction.Len != len(code) || !bytes.Equal(b.Boundary.Bytes, code) {
					t.Fatalf("following=%d: boundary=%+v", following, b.Boundary)
				}
				if following == -1 {
					expected = b.Boundary.Instruction
				} else if !reflect.DeepEqual(b.Boundary.Instruction, expected) {
					t.Fatalf("following=%d changed retained metadata: %#v != %#v", following, b.Boundary.Instruction, expected)
				}
				if !reflect.DeepEqual(straightFetches(t, b), []Span{{testEntry, cut}}) || len(b.Accesses) != 0 || !reflect.DeepEqual(b.Memory, b.InitialMemory) {
					t.Fatalf("following=%d: cut executed: %+v", following, b)
				}
			}
			// A complete boundary still supplies no executed-domain authority.
			im := image(t, append(append(hexBytes(t, "4889e0"), code...), 0xc3))
			c, err := proveTransition(t, im, cut+uint64(len(code)), transitionFace())
			transitionRefused(t, c, err)
			leaf, err := prove(t, im, cut, face(Masks{}, Masks{}))
			requireRefusal(t, leaf, err, "instruction-prefix")
		})
	}
}
