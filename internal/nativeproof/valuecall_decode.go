package nativeproof

import "golang.org/x/arch/x86/x86asm"

// The SSE inventory is exact encoding/form validation, not a mnemonic approval.
// Scalar/control forms still use the original prefix and transfer validators.
func decodeValueCall(im *Image, pc uint64) (x86asm.Inst, []byte, error) {
	i, b, err := decodeBytes(im, pc)
	if err != nil {
		return i, nil, err
	}
	prefix, opcode := sseEncoding(i.Op)
	if prefix == 0 {
		allow16 := i.Op == x86asm.TEST && i.DataSize == 16 || i.Op == x86asm.MOV && i.DataSize == 16 || len(b) == 2 && b[0] == 0x66 && b[1] == 0x90
		if err := legalScalarPrefixes(pc, b, i, allow16); err != nil {
			return i, nil, err
		}
		for _, arg := range i.Args[2:] {
			if arg != nil {
				return i, nil, refuse(pc, "instruction-shape", "extra scalar operands")
			}
		}
		return i, b, nil
	}
	return validateSSE(pc, i, b, prefix, opcode)
}

func sseEncoding(op x86asm.Op) (byte, byte) {
	switch op {
	case x86asm.MOVQ:
		return 0x66, 0x6e
	case x86asm.PUNPCKLBW:
		return 0x66, 0x60
	case x86asm.PSHUFD:
		return 0x66, 0x70
	case x86asm.MOVDQU:
		return 0xf3, 0x6f
	case x86asm.PCMPEQB:
		return 0x66, 0x74
	case x86asm.PMOVMSKB:
		return 0x66, 0xd7
	}
	return 0, 0
}

func validateSSE(pc uint64, i x86asm.Inst, b []byte, prefix, opcode byte) (x86asm.Inst, []byte, error) {
	bad := func() (x86asm.Inst, []byte, error) {
		return i, nil, refuse(pc, "value-encoding", "unsupported SSE2 encoding/form")
	}
	if i.Mode != 64 || i.AddrSize != 64 || len(b) < 4 || b[0] != prefix {
		return bad()
	}
	for j, p := range i.Prefix {
		// x86asm marks the mandatory 66 of 66 REX.W 0F 6E as ignored
		// alongside REX.W. The exact GP64-to-XMM encoding below, including
		// its mandatory 66 and register ModRM, establishes this form's legality.
		mandatoryMOVQ := i.Op == x86asm.MOVQ && j == 0 && byte(p) == 0x66
		if p&x86asm.PrefixInvalid != 0 || p&x86asm.PrefixIgnored != 0 && !mandatoryMOVQ {
			return bad()
		}
	}
	at := 1
	rex := byte(0)
	if b[at] >= 0x40 && b[at] <= 0x4f {
		rex = b[at]
		at++
	}
	if at+2 >= len(b) || b[at] != 0x0f || b[at+1] != opcode {
		return bad()
	}
	if i.Op == x86asm.MOVQ {
		if rex&8 == 0 || rex&2 != 0 {
			return bad()
		}
	} else if rex&10 != 0 {
		return bad()
	}
	modrm := b[at+2]
	if i.Args[3] != nil {
		return bad()
	}
	if i.Op == x86asm.MOVDQU {
		if _, ok := i.Args[1].(x86asm.Mem); !ok || modrm&0xc0 == 0xc0 || i.MemBytes != 16 {
			return bad()
		}
	} else {
		expected := at + 3
		if i.Op == x86asm.PSHUFD {
			expected++
		}
		if len(b) != expected || modrm&0xc0 != 0xc0 {
			return bad()
		}
	}
	if i.Op == x86asm.PSHUFD {
		if imm, ok := i.Args[2].(x86asm.Imm); !ok || imm < 0 || imm > 255 {
			return bad()
		}
	} else if i.Args[2] != nil {
		return bad()
	}
	return i, b, nil
}

func xmm(arg x86asm.Arg) (int, bool) {
	r, ok := arg.(x86asm.Reg)
	return int(r - x86asm.X0), ok && r >= x86asm.X0 && r <= x86asm.X15
}
