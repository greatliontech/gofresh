package nativeproof

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"math/big"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

func TestDecodedMemoryDisplacements(t *testing.T) {
	for _, shape := range []struct {
		name, prefix string
		base, index  x86asm.Reg
		scale        uint8
	}{
		{"base", "488d80", x86asm.RAX, 0, 0},
		{"base-index", "488d84d8", x86asm.RAX, x86asm.RBX, 8},
		{"index-only", "488d04dd", 0, x86asm.RBX, 8},
		{"absolute-SIB", "488d0425", 0, 0, 1},
		{"RIP", "488d05", x86asm.RIP, 0, 0},
	} {
		for _, disp := range []int32{0, 8, math.MaxInt32, math.MinInt32, -8, -1} {
			code := binary.LittleEndian.AppendUint32(hexBytes(t, shape.prefix), uint32(disp))
			i, _, err := decodeEncoding(image(t, code), testEntry)
			if err != nil {
				t.Fatal(err)
			}
			want := x86asm.Mem{Base: shape.base, Index: shape.index, Scale: shape.scale, Disp: int64(disp)}
			if i.Args[1] != want {
				t.Errorf("%s disp=%d: got %+v want %+v", shape.name, disp, i.Args[1], want)
			}
		}
	}
	for _, tt := range []struct {
		code string
		disp int64
	}{
		{"488d00", 0}, {"488d4000", 0}, {"488d407f", 127}, {"488d4080", -128}, {"488d40f8", -8},
	} {
		i, _, err := decodeEncoding(image(t, hexBytes(t, tt.code)), testEntry)
		if err != nil || i.Args[1] != (x86asm.Mem{Base: x86asm.RAX, Disp: tt.disp}) {
			t.Fatalf("disp8/no-disp %s: %+v, %v", tt.code, i, err)
		}
	}
	// These opcodes carry complete address words, not signed displacements.
	// Exercise both operand directions and data sizes independently of address size.
	for _, prefix := range []string{"a0", "a1", "a2", "a3", "66a1", "66a3", "48a1", "48a3"} {
		for _, address := range []uint64{0x7fffffff, 0x80000000, 0xfffffff8, 0x1234567880000000, math.MaxUint64} {
			code := binary.LittleEndian.AppendUint64(hexBytes(t, prefix), address)
			i, _, err := decodeEncoding(image(t, code), testEntry)
			if err != nil {
				t.Fatalf("moffs %s: %v", prefix, err)
			}
			arg := 1
			if code[len(code)-9]&2 != 0 {
				arg = 0
			}
			if i.Args[arg] != (x86asm.Mem{Disp: int64(address)}) {
				t.Fatalf("moffs %s address=%#x: %+v", prefix, address, i.Args[arg])
			}
		}
	}
}

func TestDisplacementNormalizationPreservesEncodingRefusals(t *testing.T) {
	for _, code := range []string{
		"67488d80f8ffffff", "6748a1f8ffffff", // address-size override is not 64-bit addressing
		"f0488d80f8ffffff", "f3488d80f8ffffff", "64488d80f8ffffff",
		"48488d80f8ffffff", "6666488d80f8ffffff", "488d80f8ffff",
	} {
		im := image(t, hexBytes(t, code))
		if _, _, err := decodeEncoding(im, testEntry); err == nil {
			t.Fatalf("scalar encoding admitted %s", code)
		}
		if _, _, err := decodeValueCall(im, testEntry); err == nil {
			t.Fatalf("value-call encoding admitted %s", code)
		}
	}
	// Structural decoding must not silently reinterpret 32-bit address operands.
	for _, code := range []string{"67488d80f8ffffff", "6748a1f8ffffff"} {
		i, _, err := decodeBytes(image(t, hexBytes(t, code)), testEntry)
		if err != nil || i.AddrSize != 32 || i.Args[1].(x86asm.Mem).Disp != 0xfffffff8 {
			t.Fatalf("32-bit addressing changed: %+v, %v", i, err)
		}
	}
}

func checkLEADisplacement(t testing.TB, x, y uint64, disp int32, indexed bool) {
	t.Helper()
	code := []byte{0x48, 0x8d, 0x80}
	if indexed {
		code = []byte{0x48, 0x8d, 0x84, 0xd8} // RAX + RBX*8 + disp32
	}
	code = append(binary.LittleEndian.AppendUint32(code, uint32(disp)), 0xc3)
	f := face(Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}, Masks{RAX: math.MaxUint64})
	inputs, terms := relationBindings(t, f.Inputs)
	r, err := DeriveRelation(t.Context(), image(t, code), testEntry, f, inputs, RelationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	// Mathematical signed addition modulo 2^64 is independent of the decoder's
	// displacement representation and the native scalar transfer implementation.
	want := new(big.Int).SetUint64(x)
	if indexed {
		want.Add(want, new(big.Int).Mul(new(big.Int).SetUint64(y), big.NewInt(8)))
	}
	want.Add(want, big.NewInt(int64(disp)))
	want.Mod(want, new(big.Int).Lsh(big.NewInt(1), 64))
	got := evalRelationTerm(t, r.Results()[0].Value, map[br.Term]uint64{terms[RAX]: x, terms[RBX]: y}, math.MaxUint64)
	if got != want.Uint64() {
		t.Fatalf("LEA x=%#x y=%#x indexed=%t disp=%d: got=%#x want=%#x", x, y, indexed, disp, got, want.Uint64())
	}
}

func TestRelationDisplacementsAgainstIntegers(t *testing.T) {
	for _, disp := range []int32{math.MinInt32, -8, -1, 0, 8, math.MaxInt32} {
		for _, x := range []uint64{0, 8, 1 << 31, 1 << 63, math.MaxUint64} {
			for _, indexed := range []bool{false, true} {
				checkLEADisplacement(t, x, math.MaxUint64, disp, indexed)
			}
		}
	}
}

func TestTransitionSignedDisplacement(t *testing.T) {
	im, cut := transitionFixture(t, "488d8424f8ffffff") // LEA RAX,[RSP-8]
	c, err := proveTransition(t, im, cut, transitionFace())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if b.Registers[RAX].Pointer != b.Geometry.stackPointer(-8) {
		t.Fatalf("wrong pointer correspondence: %+v", b.Registers[RAX])
	}
	for _, origin := range []uint64{64, 1 << 32, 1<<47 - 16} {
		got := evalRelationTerm(t, b.Registers[RAX].Value, map[br.Term]uint64{b.Origin: origin}, 0)
		if got != origin-8 {
			t.Fatalf("origin=%#x: got=%#x want=%#x", origin, got, origin-8)
		}
	}
}

func FuzzRelationDisplacements(f *testing.F) {
	f.Add(uint64(8), uint64(0), int32(-8), false)
	f.Add(uint64(0), uint64(math.MaxUint64), int32(math.MinInt32), true)
	f.Add(uint64(math.MaxUint64), uint64(1), int32(math.MaxInt32), true)
	f.Fuzz(func(t *testing.T, x, y uint64, disp int32, indexed bool) {
		checkLEADisplacement(t, x, y, disp, indexed)
	})
}

// Both the real negative-displacement destination and its zero-extended decoy
// are mapped. A checker can therefore accept the wrong address, not just refuse
// a valid program. Distinct bytes make the wrong value observable as well.
func displacementImage(t testing.TB, fragment, callee string) *Image {
	t.Helper()
	raw := callbackELF(t, fragment, callee)
	raw = append(raw, make([]byte, 8)...)
	for j, address := range []uint64{testBase, testBase + 1<<32} {
		off := 120 + j*56
		binary.LittleEndian.PutUint32(raw[off+4:], 4)
		binary.LittleEndian.PutUint64(raw[off+16:], address)
		binary.LittleEndian.PutUint64(raw[off+32:], 16)
		binary.LittleEndian.PutUint64(raw[off+40:], 16)
	}
	binary.LittleEndian.PutUint64(raw[0x2000:], 17)
	binary.LittleEndian.PutUint64(raw[0x3000:], 99)
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return im
}

func TestFrameSignedDisplacementFootprints(t *testing.T) {
	for _, tt := range []struct {
		code string
		kind AccessKind
		pc   uint64
	}{
		{"488b88f8ffffffc3", FrameRead, testEntry},
		{"488998f8ffffffc3", FrameWrite, testEntry},
		{"488d88f8ffffff488919c3", FrameWrite, testEntry + 7},
	} {
		f := memoryFace()
		f.Pointers[0].Pointer = RegionPointer{0, 8, 8}
		c, err := proveFrame(t, image(t, hexBytes(t, tt.code)), testEntry, f)
		if err != nil {
			t.Fatalf("%s: %v", tt.code, err)
		}
		b, _ := c.Bound()
		if len(b.Accesses) != 2 || b.Accesses[0] != (FrameAccess{tt.pc, tt.kind, Span{frameData, frameData + 8}, 8}) {
			t.Fatalf("%s: wrong based footprint: %+v", tt.code, b.Accesses)
		}
	}
}

func TestFrameRIPDisplacementDoesNotSelectDecoy(t *testing.T) {
	disp := int64(testBase) - int64(testEntry+7)
	code := append(binary.LittleEndian.AppendUint32([]byte{0x48, 0x8b, 0x0d}, uint32(disp)), 0xc3)
	im := displacementImage(t, hex.EncodeToString(code), "c3")
	f := memoryFace()
	for _, address := range []uint64{testBase, testBase + 1<<32} {
		f.Regions = append(f.Regions, ByteRegion{Span{address, address + 16}, true, false, true})
	}
	c, err := proveFrame(t, im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if b.Accesses[0] != (FrameAccess{testEntry, FrameRead, Span{testBase, testBase + 8}, 8}) {
		t.Fatalf("RIP disp=%d: derived wrong read: %+v", disp, b.Accesses[0])
	}
}

func TestValueCallDisplacementDoesNotSelectDecoy(t *testing.T) {
	for _, shape := range []string{"RIP", "base", "index", "SSE"} {
		t.Run(shape, func(t *testing.T) {
			var code []byte
			want, width := uint64(17), 8
			switch shape {
			case "RIP":
				disp := int64(testBase) - int64(callbackEntry+7)
				code = binary.LittleEndian.AppendUint32([]byte{0x48, 0x8b, 0x05}, uint32(disp))
			case "base", "SSE":
				code = binary.LittleEndian.AppendUint64([]byte{0x48, 0xb8}, testBase+8)
				if shape == "base" {
					code = append(code, hexBytes(t, "488b80f8ffffff")...)
				} else {
					code = append(code, hexBytes(t, "f30f6f80f8ffffff660fd7c0")...)
					want, width = 0, 16 // Every byte of the real 16-byte vector has a clear sign bit.
				}
			case "index":
				code = binary.LittleEndian.AppendUint64([]byte{0x48, 0xb8}, testBase)
				code = append(code, hexBytes(t, "bb02000000488b84d8f0ffffff")...)
			}
			code = append(code, hexBytes(t, "4889442420c3")...)
			im := displacementImage(t, "e87b000000c3", hex.EncodeToString(code))
			r := ValueCallRequest{Entry: testEntry, Target: callbackEntry, Continuation: testEntry + 5,
				Interface: ValueCallInterface{
					Regions: []ByteRegion{{Span{testBase, testBase + 16}, true, false, true}, {Span{testBase + 1<<32, testBase + 1<<32 + 16}, true, false, true}, {Span{valueStack - 16, valueStack + 80}, true, true, false}},
					Stack:   RegionPointer{2, 16, 16}, Readonly: []Span{{testBase, testBase + 16}, {testBase + 1<<32, testBase + 1<<32 + 16}}, Results: []Span{{valueStack + 24, valueStack + 32}},
					Conditions: ValueCallConditions{Machine: ValueCallMachine, InstructionMapping: true, MemoryMapping: true, ImageBytesMapped: true, NoHiddenAliases: true, UnalignedAccess: true, IsolatedInvocation: true, EntryState: true},
				}}
			c, err := CheckValueCall(t.Context(), im, r, FrameLimits{})
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c.Bound()
			if len(b.Results) != 1 || b.Results[0].Value != want {
				t.Fatalf("wrong loaded result: %+v want=%d", b.Results, want)
			}
			reads := 0
			for _, a := range b.Accesses {
				if a.Kind == FrameRead {
					reads++
					if a.Bytes != (Span{testBase, testBase + uint64(width)}) || a.Width != width {
						t.Fatalf("wrong load footprint: %+v", a)
					}
				}
			}
			if reads != 1 {
				t.Fatalf("missing exact load footprint: %+v", b.Accesses)
			}
		})
	}
}
