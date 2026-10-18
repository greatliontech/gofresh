package transitionoracle

import (
	"encoding/binary"
	"fmt"
)

func encodeCallTLS(i Intent, e Encoding) ([]byte, error) {
	bad := func() ([]byte, error) { return nil, fmt.Errorf("invalid call/TLS intent: %+v / %+v", i, e) }
	if i.Operation == Return || i.Operation == Syscall {
		if i != (Intent{Operation: i.Operation}) || e != (Encoding{Form: e.Form}) {
			return bad()
		}
		if i.Operation == Return && e.Form == RETC3 {
			return []byte{0xc3}, nil
		}
		if i.Operation == Syscall && e.Form == SYSCALL0F05 {
			return []byte{0x0f, 0x05}, nil
		}
		return bad()
	}
	if i.Operation == Call {
		if i != (Intent{Operation: Call, SignedDisp: i.SignedDisp}) || e != (Encoding{Form: CALLE8}) || int64(int32(i.SignedDisp)) != i.SignedDisp {
			return bad()
		}
		return binary.LittleEndian.AppendUint32([]byte{0xe8}, uint32(i.SignedDisp)), nil
	}
	if i.Operation == Push || i.Operation == Pop {
		if i != (Intent{Operation: i.Operation, Dst: i.Dst}) || i.Dst > 15 {
			return bad()
		}
		rex := byte(0)
		if i.Dst >= 8 {
			rex = 0x41
		}
		op, form := byte(0x50), PUSH50
		if i.Operation == Pop {
			op, form = 0x58, POP58
		}
		if e != (Encoding{Form: form, REX: rex}) {
			return bad()
		}
		b := []byte{}
		if rex != 0 {
			b = append(b, rex)
		}
		return append(b, op+i.Dst%8), nil
	}
	if i.Operation == Add {
		if i != (Intent{Operation: Add, Dst: i.Dst, Immediate: i.Immediate}) || i.Dst > 15 || e.REX < 0x48 || e.REX > 0x4f || e.DispBytes != 0 || e.SIB || e.Scale != 0 {
			return bad()
		}
		b := []byte{e.REX}
		switch e.Form {
		case ADD83:
			if e.REX&1 != i.Dst/8 || uint64(int64(int8(i.Immediate))) != i.Immediate {
				return bad()
			}
			return append(b, 0x83, 0xc0+i.Dst%8, byte(i.Immediate)), nil
		case ADD81:
			if e.REX&1 != i.Dst/8 || uint64(int64(int32(i.Immediate))) != i.Immediate {
				return bad()
			}
			return binary.LittleEndian.AppendUint32(append(b, 0x81, 0xc0+i.Dst%8), uint32(i.Immediate)), nil
		case ADD05:
			if i.Dst != 0 || uint64(int64(int32(i.Immediate))) != i.Immediate {
				return bad()
			}
			return binary.LittleEndian.AppendUint32(append(b, 5), uint32(i.Immediate)), nil
		}
		return bad()
	}
	if !i.FS || i.Base != 0 || i.RIP || i.Condition != 0 || e.DispBytes != 4 || !e.SIB || e.Scale > 3 || e.REX&2 != 0 || int64(int32(i.SignedDisp)) != i.SignedDisp {
		return bad()
	}
	w := i.Width
	if w == 0 {
		w = 64
	}
	if w != 8 && w != 32 && w != 64 || e.REX != 0 && (e.REX < 0x40 || e.REX > 0x4f) || w == 64 && e.REX&8 == 0 || w == 32 && e.REX&8 != 0 {
		return bad()
	}
	var op, reg byte
	imm := 0
	switch i.Operation {
	case Load:
		if i.Src != 0 || i.Immediate != 0 || i.HighSrc {
			return bad()
		}
		op, reg = 0x8b, i.Dst
		if w == 8 {
			op = 0x8a
		}
		if e.Form != MOV8B && w != 8 || w == 8 && e.Form != MOV8A {
			return bad()
		}
	case Store:
		if i.Dst != 0 || i.Immediate != 0 || i.HighDst {
			return bad()
		}
		op, reg = 0x89, i.Src
		if w == 8 {
			op = 0x88
		}
		if e.Form != MOV89 && w != 8 || w == 8 && e.Form != MOV88 {
			return bad()
		}
	case StoreImmediate:
		if i.Dst != 0 || i.Src != 0 || i.HighDst || i.HighSrc {
			return bad()
		}
		op, imm = 0xc7, 4
		if w == 8 {
			op, imm = 0xc6, 1
		}
		if e.Form != MOVC7 && w != 8 || w == 8 && e.Form != MOVC6 {
			return bad()
		}
	default:
		return bad()
	}
	if i.HighDst || i.HighSrc {
		if w != 8 || e.REX != 0 || reg > 3 {
			return bad()
		}
		reg += 4
	} else if w == 8 && e.REX == 0 && reg >= 4 {
		return bad()
	}
	if reg > 15 || imm == 0 && (e.REX>>2)&1 != reg/8 {
		return bad()
	}
	if imm != 0 {
		want := uint64(int64(int32(i.Immediate)))
		if w == 32 {
			want = uint64(uint32(i.Immediate))
		}
		if w == 8 {
			want = uint64(byte(i.Immediate))
		}
		if want != i.Immediate {
			return bad()
		}
	}
	b := []byte{0x64}
	if e.REX != 0 {
		b = append(b, e.REX)
	}
	b = append(b, op, (reg%8)*8+4, e.Scale*64+37)
	b = binary.LittleEndian.AppendUint32(b, uint32(i.SignedDisp))
	if imm == 1 {
		b = append(b, byte(i.Immediate))
	}
	if imm == 4 {
		b = binary.LittleEndian.AppendUint32(b, uint32(i.Immediate))
	}
	return b, nil
}
