package transitionoracle

import "fmt"

// New forms reuse only the encoder's addressing spelling, not the independent
// parser or any native decoder. The original intent is checked before conversion.
func encodeAtomic(i Intent, e Encoding) ([]byte, error) {
	bad := func() ([]byte, error) { return nil, fmt.Errorf("invalid atomic/predicate intent: %+v / %+v", i, e) }
	if i.Operation == NoOp {
		if e.Form == NOP0F1F || e.Form == NOP660F1F {
			if i != (Intent{Operation: NoOp}) || e.DispBytes != 0 || e.SIB || e.Scale != 0 || e.NOPModRM&0x38 != 0 || e.REX != 0 {
				return bad()
			}
			b := []byte{}
			if e.Form == NOP660F1F {
				b = append(b, 0x66)
			}
			b = append(b, 0x0f, 0x1f, e.NOPModRM)
			mode, rm := e.NOPModRM>>6, e.NOPModRM&7
			if mode != 3 && rm == 4 {
				b = append(b, e.NOPSIB)
			} else if e.NOPSIB != 0 {
				return bad()
			}
			n := 0
			if mode == 1 {
				n = 1
			}
			if mode == 2 || mode == 0 && (rm == 5 || rm == 4 && e.NOPSIB&7 == 5) {
				n = 4
			}
			if n == 0 && e.NOPDisp != 0 || n == 1 && int32(int8(e.NOPDisp)) != e.NOPDisp {
				return bad()
			}
			for j := 0; j < n; j++ {
				b = append(b, byte(uint32(e.NOPDisp)>>(8*j)))
			}
			return b, nil
		}
		if i != (Intent{Operation: NoOp}) || e != (Encoding{Form: e.Form}) {
			return bad()
		}
		if e.Form == NOP90 {
			return []byte{0x90}, nil
		}
		if e.Form == NOP6690 {
			return []byte{0x66, 0x90}, nil
		}
		return bad()
	}
	if i.FS {
		return bad()
	}
	original := i
	form := e.Form
	opcode, group, twoByte, locked, dropImmediate := byte(0), byte(0), false, false, false
	switch i.Operation {
	case LockedCompareExchange:
		if i.Width != 0 && i.Width != 32 || i.Dst != 0 || i.HighDst || i.HighSrc || i.Condition != 0 || i.Immediate != 0 || form != LOCKCMPXCHG0FB1 {
			return bad()
		}
		i.Operation, e.Form, opcode, twoByte, locked = Store, MOV89, 0xb1, true, true
	case LockedAnd, LockedOr:
		if i.Width != 8 || i.Condition != 0 || i.Operation == LockedAnd && form != LOCKAND20 || i.Operation == LockedOr && form != LOCKOR08 {
			return bad()
		}
		opcode = 0x20
		if i.Operation == LockedOr {
			opcode = 0x08
		}
		i.Operation, e.Form, locked = Store, MOV88, true
	case LockedAndImmediate, LockedOrImmediate:
		if i.Width != 8 || i.Condition != 0 || i.Operation == LockedAndImmediate && form != LOCKAND80 || i.Operation == LockedOrImmediate && form != LOCKOR80 {
			return bad()
		}
		group = 4
		if i.Operation == LockedOrImmediate {
			group = 1
		}
		i.Operation, e.Form, opcode, locked = StoreImmediate, MOVC6, 0x80, true
	case LockedExchange, LockedExchangeAdd:
		if i.Width != 0 || i.Dst != 0 || i.HighDst || i.HighSrc || i.Condition != 0 || i.Immediate != 0 {
			return bad()
		}
		if i.Operation == LockedExchange && (form == XCHG87 || form == LOCKXCHG87) {
			i.Operation, e.Form, opcode, locked = Store, MOV89, 0x87, form == LOCKXCHG87
		} else if i.Operation == LockedExchangeAdd && form == LOCKXADD0FC1 {
			i.Operation, e.Form, opcode, twoByte, locked = Store, MOV89, 0xc1, true, true
		} else {
			return bad()
		}
	case AddRegister:
		if i.Width != 0 || i.Condition != 0 || i.HighDst || i.HighSrc {
			return bad()
		}
		if form == ADD01 {
			i.Operation, e.Form, opcode = MoveRegister, MOV89, 0x01
		} else if form == ADD03 {
			i.Operation, e.Form, opcode = MoveRegister, MOV8B, 0x03
		} else {
			return bad()
		}
	case SetRegister, SetMemory:
		if i.Width != 8 || i.Src != 0 || i.HighSrc || i.Immediate != 0 || form != SETcc0F90 || !(i.Condition >= 2 && i.Condition <= 7 || i.Condition >= 12 && i.Condition <= 15) {
			return bad()
		}
		i.Operation = MoveImmediate
		if original.Operation == SetMemory {
			i.Operation = StoreImmediate
		}
		i.Condition, e.Form, opcode, twoByte, dropImmediate = 0, MOVC6, 0x90+i.Condition, true, true
	case CompareMemory, CompareFromMemory:
		if i.Width != 0 && i.Width != 32 && i.Width != 8 || i.Condition != 0 {
			return bad()
		}
		if i.Width == 8 && i.Operation == CompareMemory && form == CMP38 {
			i.Operation, e.Form, opcode = Store, MOV88, 0x38
		} else if i.Width == 8 && i.Operation == CompareFromMemory && form == CMP3A {
			i.Operation, e.Form, opcode = Load, MOV8A, 0x3a
		} else if i.Width != 8 && i.Operation == CompareMemory && form == CMP39 {
			i.Operation, e.Form, opcode = Store, MOV89, 0x39
		} else if i.Width != 8 && i.Operation == CompareFromMemory && form == CMP3B {
			i.Operation, e.Form, opcode = Load, MOV8B, 0x3b
		} else {
			return bad()
		}
	case CompareMemoryImmediate:
		if i.Width == 8 && i.Condition == 0 && form == CMP80 {
			i.Operation, e.Form, opcode, group = StoreImmediate, MOVC6, 0x80, 7
			break
		}
		if i.Width != 0 && i.Width != 32 || i.Condition != 0 || form != CMP81 && form != CMP83 {
			return bad()
		}
		if form == CMP83 {
			v := uint64(int64(int8(i.Immediate)))
			if i.Width == 32 {
				v &= 0xffffffff
			}
			if v != i.Immediate {
				return bad()
			}
		}
		i.Operation, e.Form, opcode, group = StoreImmediate, MOVC7, 0x81, 7
	case Test, TestImmediate:
		if i.Width != 8 || i.Condition != 0 {
			return bad()
		}
		if i.Operation == Test && form == TEST84 {
			i.Operation, e.Form, opcode = MoveRegister, MOV88, 0x84
		} else if i.Operation == TestImmediate && form == TESTF6 {
			i.Operation, e.Form, opcode = MoveImmediate, MOVC6, 0xf6
		} else if i.Operation == TestImmediate && form == TESTA8 {
			if i.Dst != 0 || i.Src != 0 || i.Base != 0 || i.HighDst || i.HighSrc || i.RIP || i.SignedDisp != 0 || i.Immediate > 255 || e.DispBytes != 0 || e.SIB || e.Scale != 0 || e.REX != 0 && (e.REX < 0x40 || e.REX > 0x4f) {
				return bad()
			}
			b := []byte{}
			if e.REX != 0 {
				b = append(b, e.REX)
			}
			return append(b, 0xa8, byte(i.Immediate)), nil
		} else {
			return bad()
		}
	default:
		return bad()
	}
	b, err := encodeExtended(i, e)
	if err != nil {
		return nil, err
	}
	at := 0
	if e.REX != 0 {
		at = 1
	}
	b[at] = opcode
	b[at+1] |= group << 3
	if original.Operation == CompareMemoryImmediate && form == CMP83 {
		b[at] = 0x83
		b = append(b[:len(b)-4], byte(original.Immediate))
	}
	if dropImmediate {
		b = b[:len(b)-1]
	}
	if twoByte {
		b = append(b[:at], append([]byte{0x0f}, b[at:]...)...)
	}
	if locked {
		b = append([]byte{0xf0}, b...)
	}
	return b, nil
}
