package nativeproof

import (
	"encoding/binary"
	"golang.org/x/arch/x86/x86asm"
)

// TransitionExpansionRequired reports whether discovery requires an explicit
// occurrence-qualified search choice before following this decoded instruction.
// It grants no execution semantics: the selected encoding and operand form must
// still pass validation. Without expansion, the complete incoming guard must be
// independently proved false. Register CMP and nonbyte TEST retain their ordinary
// discovery behavior; memory CMP and byte TEST are distinct operand families.
func TransitionExpansionRequired(i x86asm.Inst) bool {
	if i.Op == x86asm.CALL || i.Op == x86asm.SYSCALL || i.Op == x86asm.XOR || i.Op == x86asm.CMPXCHG || isTransitionSet(i.Op) || i.Op == x86asm.NOP {
		return true
	}
	if i.Op == x86asm.CMP {
		for _, arg := range i.Args {
			if _, memory := arg.(x86asm.Mem); memory {
				return true
			}
		}
	}
	if i.Op == x86asm.TEST {
		if reg, ok := i.Args[0].(x86asm.Reg); ok {
			a, valid := register(reg)
			return valid && a.width == 8
		}
	}
	return false
}

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
	return ok && m.Index == 0 && (m.Segment == 0 && (m.Base == x86asm.RIP || simpleBase(arg)) || m.Segment == x86asm.FS && m.Base == 0)
}

func transitionEncoding(im *Image, pc uint64) (x86asm.Inst, []byte, error) {
	i, b, err := decodeBytes(im, pc)
	if err != nil {
		return i, nil, err
	}
	if len(b) >= 5 && b[0] == 0xf0 {
		// LOCK belongs to this exact REX.W memory CMPXCHG, not a separate step.
		if i.Op != x86asm.CMPXCHG || b[1] < 0x48 || b[1] > 0x4f || b[2] != 0x0f || b[3] != 0xb1 {
			return i, nil, refuse(pc, "transition-form", "unsupported locked instruction")
		}
		copy := i
		copy.Prefix = x86asm.Prefixes{x86asm.Prefix(b[1])}
		if err := legalScalarPrefixes(pc, b[1:], copy, false); err != nil {
			return i, nil, err
		}
	} else if len(b) > 0 && b[0] == 0x64 {
		if i.Op != x86asm.MOV || i.Mode != 64 || i.AddrSize != 64 {
			return i, nil, refuse(pc, "transition-form", "FS prefix requires an admitted long-mode MOV")
		}
		// One FS before at most one REX; no other prefix order or override.
		copy := i
		copy.Prefix = x86asm.Prefixes{}
		if len(b) > 1 && b[1] >= 0x40 && b[1] <= 0x4f {
			copy.Prefix[0] = x86asm.Prefix(b[1])
		}
		if err := legalScalarPrefixes(pc, b[1:], copy, false); err != nil {
			return i, nil, err
		}
		at := 1
		if b[at] >= 0x40 && b[at] <= 0x4f {
			at++
		}
		if at >= len(b) || b[at] != 0x89 && b[at] != 0x8b && b[at] != 0x88 && b[at] != 0x8a && b[at] != 0xc7 && b[at] != 0xc6 {
			return i, nil, refuse(pc, "transition-form", "unsupported FS opcode")
		}
		memory := false
		for _, arg := range i.Args {
			if mem, ok := arg.(x86asm.Mem); ok {
				memory = mem.Segment == x86asm.FS && mem.Base == 0 && mem.Index == 0
			}
		}
		if !memory {
			return i, nil, refuse(pc, "transition-form", "FS requires displacement-only memory")
		}
	} else if err := legalPrefixes(pc, b, i); err != nil {
		return i, nil, err
	}
	for _, arg := range i.Args[2:] {
		if arg != nil {
			return i, nil, refuse(pc, "instruction-shape", "extra operands")
		}
	}
	return i, b, nil
}

// Only checked scalar widths reach the shared value interpreter. Prefix and
// structural decoding have already ruled out address overrides and extra operands.
// Immediate sign extension is checked against bytes, including imm8 and imm32
// arithmetic; operand widths are the actual register aliases, never a mnemonic.
func validateTransitionForm(pc uint64, i x86asm.Inst, b []byte) error {
	bad := func() error { return refuse(pc, "transition-form", "unsupported transition encoding or operand form") }
	if i.Op == x86asm.NOP {
		if len(b) == 1 && b[0] == 0x90 || len(b) == 2 && b[0] == 0x66 && b[1] == 0x90 {
			return nil
		}
		return bad()
	}
	if i.Op == x86asm.CMPXCHG {
		mem, ok := i.Args[0].(x86asm.Mem)
		_, source := fullRegister(i.Args[1])
		if len(b) < 5 || b[0] != 0xf0 || b[1] < 0x48 || b[1] > 0x4f || b[2] != 0x0f || b[3] != 0xb1 || b[4]&0xc0 == 0xc0 || !ok || !source || mem.Segment != 0 || !transitionMemory(mem) || i.MemBytes != 8 || i.DataSize != 64 {
			return bad()
		}
		return nil
	}
	if isTransitionSet(i.Op) {
		at := 0
		if len(b) != 0 && b[0] >= 0x40 && b[0] <= 0x4f {
			at++
		}
		if len(b) < at+3 || b[at] != 0x0f || b[at+1]&0xf0 != 0x90 || b[at+2]&0x38 != 0 || i.Args[1] != nil {
			return bad()
		}
		if r, ok := i.Args[0].(x86asm.Reg); ok {
			a, valid := register(r)
			if !valid || a.width != 8 {
				return bad()
			}
		} else if mem, ok := i.Args[0].(x86asm.Mem); !ok || mem.Segment != 0 || !transitionMemory(mem) || i.MemBytes != 1 {
			return bad()
		}
		return nil
	}
	if i.Op == x86asm.SYSCALL {
		if len(b) != 2 || b[0] != 0x0f || b[1] != 0x05 || i.Args != (x86asm.Args{}) {
			return bad()
		}
		return nil
	}
	if i.Op == x86asm.CALL {
		if len(b) != 5 || b[0] != 0xe8 || i.Args[1] != nil {
			return bad()
		}
		r, ok := i.Args[0].(x86asm.Rel)
		if !ok || int64(r) != int64(int32(binary.LittleEndian.Uint32(b[1:]))) {
			return bad()
		}
		return nil
	}
	if i.Op == x86asm.RET {
		if len(b) != 1 || b[0] != 0xc3 || i.Args != (x86asm.Args{}) {
			return bad()
		}
		return nil
	}
	if i.Op == x86asm.PUSH || i.Op == x86asm.POP {
		a, ok := fullRegister(i.Args[0])
		if !ok || i.Args[1] != nil {
			return bad()
		}
		at, high := 0, 0
		if len(b) == 2 && b[0] == 0x41 {
			at, high = 1, 8
		}
		op := byte(0x50)
		if i.Op == x86asm.POP {
			op = 0x58
		}
		if len(b) != at+1 || b[at] < op || b[at] > op+7 || a.reg != int(b[at]-op)+high {
			return bad()
		}
		return nil
	}
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
	if len(b) > 0 && b[0] == 0x64 {
		at++
	}
	if at < len(b) && b[at] >= 0x40 && b[at] <= 0x4f {
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
	if i.Op == x86asm.TEST && (op == 0x84 || op == 0xf6 || op == 0xa8) {
		w = 8
	}
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
	memory := func(arg x86asm.Arg) bool {
		mem, ok := arg.(x86asm.Mem)
		return ok && mem.Segment == 0 && transitionMemory(mem) && i.MemBytes == w/8
	}
	if w != 32 && w != 64 && !(w == 8 && i.Op == x86asm.TEST) || !(reg(i.Args[0], w) || i.Op == x86asm.CMP && memory(i.Args[0])) {
		return bad()
	}
	if i.Op == x86asm.LEA {
		if w != 64 || op != 0x8d || !transitionMemory(i.Args[1]) {
			return bad()
		}
		return nil
	}
	// A 32-bit self-XOR clears the complete register and its pointer provenance.
	// Only register forms with identical actual operands are admitted here; other
	// XOR shapes retain their own unsupported-transfer boundary.
	if i.Op == x86asm.XOR {
		if w != 32 || !reg(i.Args[1], 32) || i.Args[0] != i.Args[1] || op != 0x31 && op != 0x33 || len(b) != at+2 || b[at+1]&0xc0 != 0xc0 {
			return bad()
		}
		return nil
	}
	if i.Op != x86asm.CMP && i.Op != x86asm.TEST && i.Op != x86asm.SUB && i.Op != x86asm.ADD && i.Op != x86asm.AND {
		return bad()
	}
	if (i.Op == x86asm.SUB || i.Op == x86asm.ADD || i.Op == x86asm.AND) && w != 64 {
		return bad()
	}
	if reg(i.Args[1], w) || i.Op == x86asm.CMP && memory(i.Args[1]) {
		if !(i.Op == x86asm.CMP && (op == 0x39 || op == 0x3b) || i.Op == x86asm.TEST && (op == 0x85 || op == 0x84)) {
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
		if w == 8 {
			accumulator = 0xa8
		}
	case x86asm.SUB:
		group, accumulator = 5, 0x2d
	case x86asm.ADD:
		group, accumulator = 0, 0x05
	case x86asm.AND:
		group, accumulator = 4, 0x25
	}
	switch {
	case op == 0xf6 && i.Op == x86asm.TEST:
		if len(b) != at+3 || b[at+1]&0xc0 != 0xc0 || b[at+1]&0x38 != 0 || uint8(imm) != b[at+2] {
			return bad()
		}
	case op == 0xa8 && i.Op == x86asm.TEST:
		if i.Args[0] != x86asm.AL || len(b) != at+2 || uint8(imm) != b[at+1] {
			return bad()
		}
	case op == 0x83 && i.Op != x86asm.TEST:
		if len(b) < at+3 || !memory(i.Args[0]) && len(b) != at+3 || (b[at+1]>>3)&7 != group || int64(imm) != int64(int8(b[len(b)-1])) {
			return bad()
		}
	case op == 0x81 && i.Op != x86asm.TEST || op == 0xf7 && i.Op == x86asm.TEST:
		if len(b) < at+6 || !memory(i.Args[0]) && len(b) != at+6 || (b[at+1]>>3)&7 != group || int64(imm) != int64(int32(binary.LittleEndian.Uint32(b[len(b)-4:]))) {
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
	i, b, err := transitionEncoding(im, pc)
	if err != nil {
		return decodedInstruction{}, err
	}
	if err := validateTransitionForm(pc, i, b); err != nil {
		return decodedInstruction{}, err
	}
	if i.Op == x86asm.JMP || condition(i.Op) != 0 && !isTransitionSet(i.Op) {
		return decodeControl(pc, i, b)
	}
	if i.Op == x86asm.RET {
		return decodedInstruction{inst: operation{Op: i.Op}, size: uint8(i.Len)}, nil
	}
	next, ok := plus(pc, uint64(i.Len))
	if !ok {
		return decodedInstruction{}, refuse(pc, "control-target", "instruction end overflow")
	}
	if i.Op == x86asm.CALL {
		target, ok := relative(next, int64(i.Args[0].(x86asm.Rel)))
		if !ok {
			return decodedInstruction{}, refuse(pc, "control-target", "CALL target overflow")
		}
		return decodedInstruction{inst: operation{Op: i.Op, Args: [2]x86asm.Arg{i.Args[0]}}, size: uint8(i.Len), count: 1, targets: [2]uint64{target}}, nil
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
