package nativeproof

import (
	"encoding/binary"
	"reflect"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// vectorCutIntent chooses operation, width, operands and address intent before
// emitting bytes. It is a small ISA-form generator, not copied decoder tables.
// Its population is unmasked VADDPS/VPALIGNR, VBLENDVPS and ANDN, plus the
// separately generated operand-free forms. Other ISA interpretations remain
// outside this independent semantic oracle.
func vectorCutIntent(kind, address, entropy byte, displacement int32, immediate byte) ([]byte, x86asm.Inst) {
	kind %= 7
	evex := kind == 2 || kind == 4
	short := kind == 0
	l := entropy & 1
	if evex {
		l = entropy % 3
	}
	regBase := []x86asm.Reg{x86asm.X0, x86asm.Y0, x86asm.Z0}[l]
	width := 16 << l
	w := byte(0)
	op, opcode, opmap, pp := x86asm.VADDPS, byte(0x58), byte(1), byte(0)
	switch kind {
	case 3, 4:
		op, opcode, opmap, pp = x86asm.VPALIGNR, 0x0f, 3, 1
	case 5:
		op, opcode, opmap, pp = x86asm.VBLENDVPS, 0x4a, 3, 1
	case 6:
		op, opcode, opmap = x86asm.ANDN, 0xf2, 2
		l = 0
		w = (entropy >> 7) & 1
		width = 4 << w
		regBase = x86asm.EAX
		if w != 0 {
			regBase = x86asm.RAX
		}
	}
	dst, src, rm := (entropy>>1)&15, (entropy>>3)&15, entropy&7
	bext, xext := (entropy>>5)&1, (entropy>>6)&1
	if short {
		bext, xext = 0, 0
	}
	if evex {
		dst |= (entropy & 1) << 4
		src |= ((entropy >> 1) & 1) << 4
	}
	want := x86asm.Inst{Op: op, Mode: 64, AddrSize: 64, DataSize: 32}
	if w != 0 {
		want.DataSize = 64
	}
	want.Args[0], want.Args[1] = regBase+x86asm.Reg(dst), regBase+x86asm.Reg(src)
	address %= 7
	mod, encodedRM := byte(0), byte(0)
	var sib, disp []byte
	base := []byte{0, 1, 2, 3, 6, 7}[int(entropy)%6]
	mem := x86asm.Mem{Base: x86asm.RAX + x86asm.Reg(base+8*bext)}
	encodedRM = base
	switch address {
	case 0:
		mod, encodedRM = 3, rm
		idx := rm + 8*bext
		if evex {
			idx += 16 * xext
		}
		want.Args[2] = regBase + x86asm.Reg(idx)
	case 1: // register base, no displacement
	case 2, 6: // SIB with base or explicitly no base
		encodedRM = 4
		base = 3
		mem.Base = x86asm.RBX + x86asm.Reg(8*bext)
		mem.Index = x86asm.RDX + x86asm.Reg(8*xext)
		mem.Scale = 1 << (entropy & 3)
		if address == 6 {
			base = 5
			mem.Base = 0
			mem.Disp = int64(displacement)
			disp = binary.LittleEndian.AppendUint32(nil, uint32(displacement))
		}
		sib = []byte{(entropy&3)<<6 | 2<<3 | base}
	case 3:
		mod = 1
		disp = []byte{byte(displacement)}
		mem.Disp = int64(int8(displacement))
		if evex {
			mem.Disp *= int64(width)
		}
	case 4:
		mod = 2
		mem.Disp = int64(displacement)
		disp = binary.LittleEndian.AppendUint32(nil, uint32(displacement))
	case 5:
		encodedRM = 5
		mem.Base = x86asm.RIP
		mem.Disp = int64(displacement)
		disp = binary.LittleEndian.AppendUint32(nil, uint32(displacement))
	}
	if address != 0 {
		want.Args[2] = mem
		want.MemBytes = width
	}
	var trailing []byte
	if op == x86asm.VPALIGNR {
		want.Args[3] = x86asm.Imm(immediate)
		trailing = []byte{immediate}
	}
	if op == x86asm.VBLENDVPS {
		want.Args[3] = regBase + x86asm.Reg(immediate>>4)
		trailing = []byte{immediate}
	}
	// Emit the selected intent. Prefix extension bits are complemented.
	r := byte(1) - (dst>>3)&1
	var code []byte
	switch {
	case short:
		code = []byte{0xc5, r<<7 | (^src&15)<<3 | l<<2 | pp}
	case evex:
		code = []byte{0x62, r<<7 | (1-xext)<<6 | (1-bext)<<5 | (1-(dst>>4))<<4 | opmap, w<<7 | (^src&15)<<3 | 4 | pp, l<<5 | (1-(src>>4))<<3}
	default:
		code = []byte{0xc4, r<<7 | (1-xext)<<6 | (1-bext)<<5 | opmap, w<<7 | (^src&15)<<3 | l<<2 | pp}
	}
	for n, b := range code {
		want.Prefix[n] = x86asm.Prefix(b)
	}
	if address == 5 {
		want.PCRel = 4
		want.PCRelOff = len(code) + 2
	}
	modrm := mod<<6 | (dst&7)<<3 | encodedRM
	want.Opcode = uint32(opcode)<<24 | uint32(modrm)<<16
	if len(sib) > 0 {
		want.Opcode |= uint32(sib[0]) << 8
	}
	code = append(code, opcode, modrm)
	code = append(code, sib...)
	code = append(code, disp...)
	code = append(code, trailing...)
	want.Len = len(code)
	return code, want
}

func assertGeneratedCut(t testing.TB, code []byte, want x86asm.Inst, tail []byte) {
	t.Helper()
	for _, suffix := range [][]byte{nil, tail} {
		window := append(append([]byte(nil), code...), suffix...)
		b, err := checkCutProperty(t, cutPropertyImage(t, window, nil, true), len(code), true)
		if err != nil {
			t.Fatalf("generated valid form %x: %v", code, err)
		}
		if !reflect.DeepEqual(b.Boundary.Instruction, want) {
			t.Fatalf("form %x: got %#v, want %#v", code, b.Boundary.Instruction, want)
		}
		assertCutOnly(t, b, code, true)
	}
	for n := 0; n < len(code); n++ {
		assertCutEncodingRefused(t, code[:n], code[n:], len(code), true)
	}
	// These forbidden preceding legacy/REX prefixes cannot make the bare
	// vector encoding valid. They grant neither a structural nor execution proof.
	for _, prefix := range []byte{0xf0, 0x66, 0xf2, 0xf3, 0x48} {
		bad := append([]byte{prefix}, code...)
		assertCutEncodingRefused(t, bad, nil, len(bad), true)
	}
}

func FuzzTransitionCutKnownForms(f *testing.F) {
	for kind := byte(0); kind < 7; kind++ {
		for addr := byte(0); addr < 7; addr++ {
			for _, entropy := range []byte{0, 0xff, 0x65} {
				f.Add(kind, addr, entropy, int32(-2147483648), byte(0xa5), []byte{0x04, 0x85, 0xff, 0xff, 0xff, 0xff})
			}
		}
	}
	f.Fuzz(func(t *testing.T, kind, address, entropy uint8, disp int32, imm uint8, tail []byte) {
		tail = tail[:min(len(tail), 15)]
		code, want := vectorCutIntent(kind, address, entropy, disp, imm)
		assertGeneratedCut(t, code, want, tail)
		// Both ZO prefix lengths, both L operations, every extension/W choice
		// and reserved controls are generated in the property body itself.
		for _, long := range []bool{false, true} {
			op := x86asm.VZEROUPPER
			l := (entropy & 1) << 2
			if l != 0 {
				op = x86asm.VZEROALL
			}
			zero := []byte{0xc5, entropy&0x80 | 0x78 | l, 0x77}
			if long {
				zero = []byte{0xc4, entropy&0xe0 | 1, imm&0x80 | 0x78 | l, 0x77}
			}
			w := x86asm.Inst{Op: op, Opcode: 0x77000000, Mode: 64, AddrSize: 64, DataSize: 32, Len: len(zero)}
			for n, b := range zero[:len(zero)-1] {
				w.Prefix[n] = x86asm.Prefix(b)
			}
			assertGeneratedCut(t, zero, w, tail)
			for _, control := range []byte{(entropy%15)<<3 | l, 0x78 | l | (imm%3 + 1)} {
				bad := append([]byte(nil), zero...)
				bad[len(bad)-2] = bad[len(bad)-2]&0x80 | control
				assertCutEncodingRefused(t, bad, nil, len(bad), true)
			}
		}
	})
}
