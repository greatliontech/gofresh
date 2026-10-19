package transitionoracle

import (
	"encoding/binary"
	"fmt"
)

// Extended intent is still chosen before bytes. This encoder uses field assembly;
// Parse independently consumes bytes and uses mathematical signed place values.
func encodeExtended(i Intent, e Encoding) ([]byte, error) {
	bad := func() ([]byte, error) { return nil, fmt.Errorf("invalid extended intent/encoding: %+v / %+v", i, e) }
	if i.Operation == Branch {
		if i.Condition < 2 || i.Condition > 15 || i.Condition == 8 || i.Condition == 9 || i.Width != 0 || i.Dst != 0 || i.Src != 0 || i.Base != 0 || i.Immediate != 0 || i.RIP || i.HighDst || i.HighSrc || e.REX != 0 || e.SIB || e.Scale != 0 || e.DispBytes != 0 {
			return bad()
		}
		if e.Form == JccShort && int64(int8(i.SignedDisp)) == i.SignedDisp {
			return []byte{0x70 + i.Condition, byte(i.SignedDisp)}, nil
		}
		if e.Form == JccNear && int64(int32(i.SignedDisp)) == i.SignedDisp {
			return binary.LittleEndian.AppendUint32([]byte{0x0f, 0x80 + i.Condition}, uint32(i.SignedDisp)), nil
		}
		return bad()
	}
	w := i.Width
	if w == 0 {
		w = 64
	}
	if w != 8 && w != 32 && w != 64 || i.Condition != 0 || i.Dst > 15 || i.Src > 15 || i.Base > 15 || e.Scale > 3 || !e.SIB && e.Scale != 0 {
		return bad()
	}
	if w == 64 && (e.REX < 0x48 || e.REX > 0x4f) || w == 32 && e.REX != 0 && (e.REX < 0x40 || e.REX > 0x47) || w == 8 && e.REX != 0 && (e.REX < 0x40 || e.REX > 0x4f) {
		return bad()
	}
	if (i.HighDst || i.HighSrc) && (w != 8 || e.REX != 0) {
		return bad()
	}
	dst, src := i.Dst, i.Src
	if i.HighDst {
		if dst > 3 {
			return bad()
		}
		dst += 4
	}
	if i.HighSrc {
		if src > 3 {
			return bad()
		}
		src += 4
	}
	if w == 8 && e.REX == 0 && (!i.HighDst && dst >= 4 || !i.HighSrc && src >= 4) {
		return bad()
	}
	mem := i.Operation == Load || i.Operation == Store || i.Operation == StoreImmediate
	if !mem && (i.RIP || i.Base != 0 || i.SignedDisp != 0 || e.DispBytes != 0 || e.SIB || e.Scale != 0) {
		return bad()
	}
	if i.RIP && (i.Base != 0 || e.SIB || e.DispBytes != 4) {
		return bad()
	}
	var opcode, group byte
	reg, rm := src, dst
	operandReg, immediate, accumulator := true, 0, false
	switch e.Form {
	case MOV89, MOV88:
		if i.Operation != MoveRegister && i.Operation != Store || (e.Form == MOV88) != (w == 8) {
			return bad()
		}
		opcode = 0x89
		if w == 8 {
			opcode--
		}
	case MOV8B, MOV8A:
		if i.Operation != MoveRegister && i.Operation != Load || (e.Form == MOV8A) != (w == 8) {
			return bad()
		}
		opcode, reg, rm = 0x8b, dst, src
		if w == 8 {
			opcode--
		}
	case MOVC7, MOVC6:
		if i.Operation != MoveImmediate && i.Operation != StoreImmediate || (e.Form == MOVC6) != (w == 8) {
			return bad()
		}
		opcode, operandReg, immediate = 0xc7, false, 4
		if w == 8 {
			opcode, immediate = 0xc6, 1
		}
	case MOVB0:
		if i.Operation != MoveImmediate || w != 8 || i.Src != 0 || i.Immediate > 255 || e.REX&1 != dst/8 {
			return bad()
		}
		b := []byte{}
		if e.REX != 0 {
			b = append(b, e.REX)
		}
		return append(b, 0xb0+dst%8, byte(i.Immediate)), nil
	case CMP39, CMP3B:
		if i.Operation != Compare || w == 8 {
			return bad()
		}
		opcode = 0x39
		if e.Form == CMP3B {
			opcode, reg, rm = 0x3b, dst, src
		}
	case TEST85:
		if i.Operation != Test || w == 8 {
			return bad()
		}
		opcode = 0x85
	case CMP83, CMP81, CMP3D, TESTF7, TESTA9:
		if w == 8 {
			return bad()
		}
		opcode, group, immediate, operandReg = 0x81, 7, 4, false
		if e.Form == CMP83 {
			opcode, immediate = 0x83, 1
		}
		if e.Form == CMP3D {
			opcode, accumulator = 0x3d, true
		}
		if e.Form == TESTF7 || e.Form == TESTA9 {
			if i.Operation != TestImmediate {
				return bad()
			}
			opcode, group = 0xf7, 0
			if e.Form == TESTA9 {
				opcode, accumulator = 0xa9, true
			}
		} else if i.Operation != CompareImmediate {
			return bad()
		}
	default:
		return bad()
	}
	if !operandReg && i.Src != 0 || operandReg && i.Immediate != 0 || (i.Operation == Store || i.Operation == StoreImmediate) && i.Dst != 0 || i.Operation == Load && i.Src != 0 {
		return bad()
	}
	if immediate > 0 {
		expected := uint64(int64(int32(i.Immediate)))
		if immediate == 1 {
			expected = uint64(int64(int8(i.Immediate)))
		}
		if w == 8 {
			expected = uint64(uint8(i.Immediate))
		} else if w == 32 {
			expected &= 0xffffffff
		}
		if expected != i.Immediate {
			return bad()
		}
	}
	b := []byte{}
	if e.REX != 0 {
		b = append(b, e.REX)
	}
	b = append(b, opcode)
	if accumulator {
		if dst != 0 {
			return bad()
		}
		return binary.LittleEndian.AppendUint32(b, uint32(i.Immediate)), nil
	}
	if mem {
		rm = i.Base
	}
	if !i.RIP && e.REX&1 != rm/8 || operandReg && (e.REX>>2)&1 != reg/8 {
		return bad()
	}
	if !operandReg {
		reg = group
	}
	mod, low := byte(3), rm%8
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
		if i.RIP {
			mod, low = 0, 5
		} else if (!e.SIB && low == 4) || e.SIB && e.REX&2 != 0 {
			return bad()
		}
	}
	if e.SIB {
		low = 4
	}
	b = append(b, mod*64+(reg%8)*8+low)
	if e.SIB {
		b = append(b, e.Scale*64+32+rm%8)
	}
	if mem && e.DispBytes == 1 {
		b = append(b, byte(i.SignedDisp))
	}
	if mem && e.DispBytes == 4 {
		b = binary.LittleEndian.AppendUint32(b, uint32(i.SignedDisp))
	}
	if immediate == 1 {
		b = append(b, byte(i.Immediate))
	}
	if immediate == 4 {
		b = binary.LittleEndian.AppendUint32(b, uint32(i.Immediate))
	}
	return b, nil
}
