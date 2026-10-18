package transitionoracle

import (
	"encoding/binary"
	"fmt"
)

// Encode emits exactly the requested spelling or an error. It never chooses a
// shorter immediate/displacement, drops ignored bits or truncates an intent.
// Branch displacements are already relative to the eventual instruction end;
// address applicability is checked by Parse when the caller supplies a PC.
func Encode(i Intent, e Encoding) ([]byte, error) {
	bad := func() ([]byte, error) { return nil, fmt.Errorf("invalid intent/encoding: %+v / %+v", i, e) }
	if i.Dst > 15 || i.Src > 15 || i.Base > 15 || e.Scale > 3 || (!e.SIB && e.Scale != 0) {
		return bad()
	}
	mem := i.Operation == Load || i.Operation == Store || i.Operation == StoreImmediate || i.Operation == LEA
	if !mem && (i.Base != 0 || e.DispBytes != 0 || e.SIB || e.Scale != 0) {
		return bad()
	}
	if !mem && i.Operation != Jump && i.SignedDisp != 0 {
		return bad()
	}
	switch i.Operation {
	case MoveRegister:
		if i.Immediate != 0 {
			return bad()
		}
	case Load, LEA:
		if i.Src != 0 || i.Immediate != 0 {
			return bad()
		}
	case Store:
		if i.Dst != 0 || i.Immediate != 0 {
			return bad()
		}
	case MoveImmediate, MoveImmediate32, Subtract, And:
		if i.Src != 0 {
			return bad()
		}
	case StoreImmediate:
		if i.Dst != 0 || i.Src != 0 {
			return bad()
		}
	case Jump:
		if i.Dst != 0 || i.Src != 0 || i.Immediate != 0 {
			return bad()
		}
	default:
		return bad()
	}
	if e.Form == JMPEB || e.Form == JMPE9 {
		if i.Operation != Jump || e.REX != 0 {
			return bad()
		}
		if e.Form == JMPEB {
			if int64(int8(i.SignedDisp)) != i.SignedDisp {
				return bad()
			}
			return []byte{0xeb, byte(i.SignedDisp)}, nil
		}
		if int64(int32(i.SignedDisp)) != i.SignedDisp {
			return bad()
		}
		return binary.LittleEndian.AppendUint32([]byte{0xe9}, uint32(i.SignedDisp)), nil
	}
	if e.Form == MOVB8Imm32 {
		prefix := byte(0)
		if i.Dst >= 8 {
			prefix = 0x41
		}
		if i.Operation != MoveImmediate32 || e.REX != prefix || i.Immediate > 0xffffffff {
			return bad()
		}
		b := []byte{}
		if prefix != 0 {
			b = append(b, prefix)
		}
		b = append(b, 0xb8+i.Dst%8)
		return binary.LittleEndian.AppendUint32(b, uint32(i.Immediate)), nil
	}
	if e.REX < 0x48 || e.REX > 0x4f {
		return bad()
	}
	b := []byte{e.REX}
	if e.Form == MOVB8Imm64 {
		if i.Operation != MoveImmediate || e.REX&1 != i.Dst/8 {
			return bad()
		}
		b = append(b, 0xb8+i.Dst%8)
		return binary.LittleEndian.AppendUint64(b, i.Immediate), nil
	}
	// The effective signed immediate is checked before its low bits are written.
	immBytes := 0
	opcode, reg, rm := byte(0), uint8(0), i.Dst
	regIsOperand := false
	switch e.Form {
	case MOV89:
		if i.Operation != MoveRegister && i.Operation != Store {
			return bad()
		}
		opcode, reg, regIsOperand = 0x89, i.Src, true
	case MOV8B:
		if i.Operation != MoveRegister && i.Operation != Load {
			return bad()
		}
		opcode, reg, rm, regIsOperand = 0x8b, i.Dst, i.Src, true
	case LEA8D:
		if i.Operation != LEA {
			return bad()
		}
		opcode, reg, regIsOperand = 0x8d, i.Dst, true
	case MOVC7:
		if i.Operation != MoveImmediate && i.Operation != StoreImmediate {
			return bad()
		}
		opcode, immBytes = 0xc7, 4
	case SUB83, SUB81, SUB2D, AND83, AND81, AND25:
		if (e.Form == SUB83 || e.Form == SUB81 || e.Form == SUB2D) && i.Operation != Subtract {
			return bad()
		}
		if (e.Form == AND83 || e.Form == AND81 || e.Form == AND25) && i.Operation != And {
			return bad()
		}
		reg, immBytes = 5, 4
		if i.Operation == And {
			reg = 4
		}
		opcode = 0x81
		if e.Form == SUB83 || e.Form == AND83 {
			opcode, immBytes = 0x83, 1
		}
		if e.Form == SUB2D {
			opcode = 0x2d
		}
		if e.Form == AND25 {
			opcode = 0x25
		}
	default:
		return bad()
	}
	if immBytes == 1 && uint64(int64(int8(i.Immediate))) != i.Immediate {
		return bad()
	}
	if immBytes == 4 && uint64(int64(int32(i.Immediate))) != i.Immediate {
		return bad()
	}
	b = append(b, opcode)
	if e.Form == SUB2D || e.Form == AND25 {
		if i.Dst != 0 {
			return bad()
		}
		// REX.R/X/B do not change the accumulator operand.
		return binary.LittleEndian.AppendUint32(b, uint32(i.Immediate)), nil
	}
	if mem {
		rm = i.Base
	}
	if e.REX&1 != rm/8 {
		return bad()
	}
	if regIsOperand && (e.REX>>2)&1 != reg/8 {
		return bad()
	}
	// For groups /0, /4 and /5, REX.R is ignored, not an extension of
	// the opcode selector. REX.X is ignored except in SIB addressing.
	mod := byte(3)
	if mem {
		switch e.DispBytes {
		case 0:
			if i.SignedDisp != 0 || rm%8 == 5 {
				return bad()
			}
			mod = 0
		case 1:
			if int64(int8(i.SignedDisp)) != i.SignedDisp {
				return bad()
			}
			mod = 1
		case 4:
			if int64(int32(i.SignedDisp)) != i.SignedDisp {
				return bad()
			}
			mod = 2
		default:
			return bad()
		}
		if (!e.SIB && rm%8 == 4) || (e.SIB && e.REX&2 != 0) {
			return bad()
		}
	}
	lowRM := rm % 8
	if e.SIB {
		lowRM = 4
	}
	b = append(b, mod*64+(reg%8)*8+lowRM)
	if e.SIB {
		b = append(b, e.Scale*64+4*8+rm%8)
	}
	if mem && e.DispBytes == 1 {
		b = append(b, byte(i.SignedDisp))
	}
	if mem && e.DispBytes == 4 {
		b = binary.LittleEndian.AppendUint32(b, uint32(i.SignedDisp))
	}
	if immBytes == 1 {
		b = append(b, byte(i.Immediate))
	}
	if immBytes == 4 {
		b = binary.LittleEndian.AppendUint32(b, uint32(i.Immediate))
	}
	return b, nil
}
