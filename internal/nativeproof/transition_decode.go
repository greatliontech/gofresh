package nativeproof

import (
	"encoding/binary"

	"golang.org/x/arch/x86/x86asm"
)

func fullRegister(arg x86asm.Arg) (alias, bool) {
	r, ok := arg.(x86asm.Reg)
	a, valid := register(r)
	return a, ok && valid && a.width == 64
}

func simpleBase(arg x86asm.Arg) bool {
	m, ok := arg.(x86asm.Mem)
	_, base := fullRegister(m.Base)
	return ok && base && m.Segment == 0 && m.Index == 0
}

// validateTransitionForm admits exact full-width forms before the scalar builder
// sees them. Immediate extension is checked against encoding bytes, not inferred
// from a mnemonic. All memory forms have one full register base and displacement.
func validateTransitionForm(pc uint64, i x86asm.Inst, b []byte) error {
	bad := func() error { return refuse(pc, "transition-form", "unsupported full-width encoding or operand form") }
	if i.Op == x86asm.JMP {
		if _, ok := i.Args[0].(x86asm.Rel); !ok || i.Args[1] != nil || !(len(b) == 2 && b[0] == 0xeb || len(b) == 5 && b[0] == 0xe9) {
			return bad()
		}
		return nil
	}
	if len(b) < 3 || b[0]&0xf8 != 0x48 || i.DataSize != 64 {
		return bad()
	}
	_, dst := fullRegister(i.Args[0])
	_, src := fullRegister(i.Args[1])
	op := b[1]
	switch i.Op {
	case x86asm.MOV:
		switch {
		case op == 0x89 || op == 0x8b:
			if !(dst && src || dst && simpleBase(i.Args[1]) && i.MemBytes == 8 || simpleBase(i.Args[0]) && src && i.MemBytes == 8) {
				return bad()
			}
		case op >= 0xb8 && op <= 0xbf:
			imm, ok := i.Args[1].(x86asm.Imm)
			if !dst || !ok || len(b) != 10 || uint64(imm) != binary.LittleEndian.Uint64(b[2:]) {
				return bad()
			}
		case op == 0xc7:
			imm, ok := i.Args[1].(x86asm.Imm)
			if !ok || b[2]&0x38 != 0 || len(b) < 7 || int64(imm) != int64(int32(binary.LittleEndian.Uint32(b[len(b)-4:]))) || !(dst || simpleBase(i.Args[0]) && i.MemBytes == 8) {
				return bad()
			}
		default:
			return bad()
		}
	case x86asm.LEA:
		if op != 0x8d || !dst || !simpleBase(i.Args[1]) {
			return bad()
		}
	case x86asm.SUB, x86asm.AND:
		imm, ok := i.Args[1].(x86asm.Imm)
		if !dst || !ok {
			return bad()
		}
		group, accumulator := byte(5), byte(0x2d)
		if i.Op == x86asm.AND {
			group, accumulator = 4, 0x25
		}
		switch op {
		case 0x83:
			if len(b) != 4 || b[2]&0xc0 != 0xc0 || (b[2]>>3)&7 != group || int64(imm) != int64(int8(b[3])) {
				return bad()
			}
		case 0x81:
			if len(b) != 7 || b[2]&0xc0 != 0xc0 || (b[2]>>3)&7 != group || int64(imm) != int64(int32(binary.LittleEndian.Uint32(b[3:]))) {
				return bad()
			}
		default:
			if op != accumulator || len(b) != 6 || i.Args[0] != x86asm.RAX || int64(imm) != int64(int32(binary.LittleEndian.Uint32(b[2:]))) {
				return bad()
			}
		}
	default:
		return bad()
	}
	return nil
}

func decodeTransition(im *Image, pc, cut uint64) (decodedInstruction, error) {
	if pc == cut {
		i, _, err := decodeBytes(im, pc)
		if err != nil {
			return decodedInstruction{}, err
		}
		return decodedInstruction{boundary: boundaryCut, size: uint8(i.Len)}, nil
	}
	i, b, err := decodeEncoding(im, pc)
	if err != nil {
		return decodedInstruction{}, err
	}
	if err := validateTransitionForm(pc, i, b); err != nil {
		return decodedInstruction{}, err
	}
	if i.Op == x86asm.JMP {
		return decodeControl(pc, i, b)
	}
	next, ok := plus(pc, uint64(i.Len))
	if !ok {
		return decodedInstruction{}, refuse(pc, "control-target", "instruction end overflow")
	}
	return decodedInstruction{inst: operation{Op: i.Op, Args: [2]x86asm.Arg{i.Args[0], i.Args[1]}}, size: uint8(i.Len), count: 1, targets: [2]uint64{next}}, nil
}
