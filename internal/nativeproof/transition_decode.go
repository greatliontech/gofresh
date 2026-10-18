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

func transitionMemory(arg x86asm.Arg) bool {
	m, ok := arg.(x86asm.Mem)
	return ok && m.Segment == 0 && m.Index == 0 && (m.Base == x86asm.RIP || simpleBase(arg))
}

// Only checked scalar widths reach the shared value interpreter. Prefix and
// structural decoding have already ruled out address overrides and extra operands.
// Immediate sign extension is checked against bytes, including imm8 and imm32
// arithmetic; operand widths are the actual register aliases, never a mnemonic.
func validateTransitionForm(pc uint64, i x86asm.Inst, b []byte) error {
	bad := func() error { return refuse(pc, "transition-form", "unsupported transition encoding or operand form") }
	if i.Op == x86asm.CPUID {
		if len(b) != 2 || b[0] != 0x0f || b[1] != 0xa2 || i.Args != (x86asm.Args{}) {
			return bad()
		}
		return nil
	}
	if i.Op == x86asm.JMP || condition(i.Op) != 0 {
		if _, ok := i.Args[0].(x86asm.Rel); !ok || i.Args[1] != nil {
			return bad()
		}
		if i.Op == x86asm.JMP {
			if !(len(b) == 2 && b[0] == 0xeb || len(b) == 5 && b[0] == 0xe9) {
				return bad()
			}
		} else if !(len(b) == 2 && b[0]&0xf0 == 0x70 || len(b) == 6 && b[0] == 0x0f && b[1]&0xf0 == 0x80) {
			return bad()
		}
		return nil
	}
	at := 0
	if len(b) > 0 && b[0] >= 0x40 && b[0] <= 0x4f {
		at++
	}
	if at >= len(b) {
		return bad()
	}
	op := b[at]
	reg := func(arg x86asm.Arg, width int) bool {
		r, ok := arg.(x86asm.Reg)
		a, valid := register(r)
		return ok && valid && a.width == width
	}
	w := i.DataSize
	if i.Op == x86asm.MOV {
		if op == 0x88 || op == 0x8a || op == 0xc6 || op >= 0xb0 && op <= 0xb7 {
			w = 8
		}
		if w != 8 && w != 32 && w != 64 {
			return bad()
		}
		dst, src := reg(i.Args[0], w), reg(i.Args[1], w)
		mem := func(arg x86asm.Arg) bool { return transitionMemory(arg) && i.MemBytes == w/8 }
		switch {
		case op == 0x88 || op == 0x89 || op == 0x8a || op == 0x8b:
			if !(dst && src || dst && mem(i.Args[1]) || mem(i.Args[0]) && src) {
				return bad()
			}
		case op >= 0xb0 && op <= 0xbf:
			imm, ok := i.Args[1].(x86asm.Imm)
			if !dst || !ok {
				return bad()
			}
			if w == 32 {
				// Preserve the canonical immediate-register form's prefix contract.
				if at != 0 && b[0] != 0x41 {
					return bad()
				}
			}
			if len(b) != at+1+w/8 {
				return bad()
			}
			if w == 64 && uint64(imm) != binary.LittleEndian.Uint64(b[at+1:]) || w == 32 && int64(imm) != int64(int32(binary.LittleEndian.Uint32(b[at+1:]))) || w == 8 && uint8(imm) != b[at+1] {
				return bad()
			}
		case op == 0xc6 || op == 0xc7:
			imm, ok := i.Args[1].(x86asm.Imm)
			if !ok || len(b) < at+3 || b[at+1]&0x38 != 0 || !(dst || mem(i.Args[0])) {
				return bad()
			}
			if w == 8 {
				if uint8(imm) != b[len(b)-1] {
					return bad()
				}
			} else if len(b) < at+6 || int64(imm) != int64(int32(binary.LittleEndian.Uint32(b[len(b)-4:]))) {
				return bad()
			}
		default:
			return bad()
		}
		return nil
	}
	if w != 32 && w != 64 || !reg(i.Args[0], w) {
		return bad()
	}
	if i.Op == x86asm.LEA {
		if w != 64 || op != 0x8d || !transitionMemory(i.Args[1]) {
			return bad()
		}
		return nil
	}
	if i.Op != x86asm.CMP && i.Op != x86asm.TEST && i.Op != x86asm.SUB && i.Op != x86asm.AND {
		return bad()
	}
	if (i.Op == x86asm.SUB || i.Op == x86asm.AND) && w != 64 {
		return bad()
	}
	if reg(i.Args[1], w) {
		if !(i.Op == x86asm.CMP && (op == 0x39 || op == 0x3b) || i.Op == x86asm.TEST && op == 0x85) {
			return bad()
		}
		return nil
	}
	imm, ok := i.Args[1].(x86asm.Imm)
	if !ok {
		return bad()
	}
	group, accumulator := byte(7), byte(0x3d)
	switch i.Op {
	case x86asm.TEST:
		group, accumulator = 0, 0xa9
	case x86asm.SUB:
		group, accumulator = 5, 0x2d
	case x86asm.AND:
		group, accumulator = 4, 0x25
	}
	switch {
	case op == 0x83 && i.Op != x86asm.TEST:
		if len(b) != at+3 || b[at+1]&0xc0 != 0xc0 || (b[at+1]>>3)&7 != group || int64(imm) != int64(int8(b[at+2])) {
			return bad()
		}
	case op == 0x81 && i.Op != x86asm.TEST || op == 0xf7 && i.Op == x86asm.TEST:
		if len(b) != at+6 || b[at+1]&0xc0 != 0xc0 || (b[at+1]>>3)&7 != group || int64(imm) != int64(int32(binary.LittleEndian.Uint32(b[at+2:]))) {
			return bad()
		}
	case op == accumulator:
		a, _ := register(i.Args[0].(x86asm.Reg))
		if a.reg != 0 || len(b) != at+5 || int64(imm) != int64(int32(binary.LittleEndian.Uint32(b[at+1:]))) {
			return bad()
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
	if i.Op == x86asm.JMP || condition(i.Op) != 0 {
		return decodeControl(pc, i, b)
	}
	next, ok := plus(pc, uint64(i.Len))
	if !ok {
		return decodedInstruction{}, refuse(pc, "control-target", "instruction end overflow")
	}
	return decodedInstruction{inst: operation{Op: i.Op, Args: [2]x86asm.Arg{i.Args[0], i.Args[1]}, MemBytes: i.MemBytes}, size: uint8(i.Len), count: 1, targets: [2]uint64{next}}, nil
}

// Structural failure is always fatal, even on an impossible path. Only after
// exact decoding may a missing transfer rule become a candidate false boundary.
// Neither candidate discovery nor a caller's node inventory proves it unreachable.
func decodeTransitionBoundary(im *Image, pc, cut uint64) (decodedInstruction, error) {
	i, _, err := decodeBytes(im, pc)
	if err != nil {
		return decodedInstruction{}, err
	}
	n, err := decodeTransition(im, pc, cut)
	if err == nil {
		return n, nil
	}
	return decodedInstruction{boundary: boundaryUnsupported, size: uint8(i.Len)}, nil
}
