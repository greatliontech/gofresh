package transitionoracle

import "fmt"

func encodeScalar(i Intent, e Encoding) ([]byte, error) {
	bad := func() ([]byte, error) { return nil, fmt.Errorf("invalid scalar intent/encoding: %+v / %+v", i, e) }
	if i.Dst > 15 || i.Src > 15 || e != (Encoding{Form: e.Form, REX: e.REX}) || e.REX != 0 && (e.REX < 0x40 || e.REX > 0x4f) {
		return bad()
	}
	rm, reg, opcode := i.Dst, i.Src, byte(0)
	want := Intent{Operation: i.Operation, Dst: i.Dst, Width: 32}
	switch i.Operation {
	case Increment64:
		want.Width, reg, opcode = 0, 0, 0xff
		if e.Form != INCFF || e.REX&8 == 0 {
			return bad()
		}
	case ShiftLeft32CL:
		reg, opcode = 4, 0xd3
		if e.Form != SHLD3 || e.REX&8 != 0 {
			return bad()
		}
	case SubtractBorrow32, AndRegister32:
		want.Src = i.Src
		if e.REX&8 != 0 {
			return bad()
		}
		if i.Operation == SubtractBorrow32 {
			switch e.Form {
			case SBB19:
				opcode = 0x19
			case SBB1B:
				opcode, rm, reg = 0x1b, i.Src, i.Dst
			default:
				return bad()
			}
		} else {
			switch e.Form {
			case AND21:
				opcode = 0x21
			case AND23:
				opcode, rm, reg = 0x23, i.Src, i.Dst
			default:
				return bad()
			}
		}
		if (e.REX>>2)&1 != reg/8 {
			return bad()
		}
	default:
		return bad()
	}
	if i != want || e.REX&1 != rm/8 {
		return bad()
	}
	var b []byte
	if e.REX != 0 {
		b = append(b, e.REX)
	}
	return append(b, opcode, 0xc0+8*(reg%8)+rm%8), nil
}
