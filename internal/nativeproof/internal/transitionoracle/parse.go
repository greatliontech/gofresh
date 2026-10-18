package transitionoracle

import "fmt"

// Parse reads one executed instruction at pc. A successful parse consumes only
// that instruction, independently of following bytes. Unknown, truncated or
// out-of-scope forms and wrapping end/branch addresses return a zero Decoded and
// an error. There is no canonical-address or image-boundary policy here; those
// are consumer premises. The byte cursor and integer rules below are independent
// of Encode: no encoder validation, truncating signed casts or binary helpers.
func Parse(code []byte, pc uint64) (Decoded, error) {
	r := byteReader{code: code}
	d := Decoded{}
	fail := func(why string) (Decoded, error) { return Decoded{}, fmt.Errorf("executed instruction: %s", why) }
	first := r.unsigned(1)
	op := first
	if first == 0x41 || first >= 0x48 && first <= 0x4f {
		d.Encoding.REX = byte(first)
		op = r.unsigned(1)
	}
	rex := d.Encoding.REX
	if rex == 0 && op == 0x0f {
		if r.unsigned(1) != 0xa2 {
			return fail("unsupported two-byte opcode")
		}
		d.Intent.Operation, d.Encoding.Form = CPUID, CPUID0FA2
	} else if rex == 0 && (op == 0xeb || op == 0xe9) {
		d.Intent.Operation = Jump
		d.Encoding.Form = JMPEB
		width := 1
		if op == 0xe9 {
			d.Encoding.Form, width = JMPE9, 4
		}
		d.Intent.SignedDisp = r.signed(width)
	} else if op >= 0xb8 && op <= 0xbf {
		d.Intent.Dst = uint8(op - 0xb8)
		if rex&1 != 0 {
			d.Intent.Dst += 8
		}
		switch {
		case rex == 0 || rex == 0x41:
			d.Intent.Operation, d.Encoding.Form = MoveImmediate32, MOVB8Imm32
			d.Intent.Immediate = r.unsigned(4)
		case rex >= 0x48 && rex <= 0x4f:
			d.Intent.Operation, d.Encoding.Form = MoveImmediate, MOVB8Imm64
			d.Intent.Immediate = r.unsigned(8)
		default:
			return fail("immediate MOV prefix")
		}
	} else {
		if rex < 0x48 || rex > 0x4f {
			return fail("missing single REX.W")
		}
		if op == 0x2d || op == 0x25 {
			d.Intent.Operation, d.Encoding.Form = Subtract, SUB2D
			if op == 0x25 {
				d.Intent.Operation, d.Encoding.Form = And, AND25
			}
			d.Intent.Immediate = uint64(r.signed(4))
		} else {
			switch op {
			case 0x89, 0x8b, 0x8d, 0xc7, 0x83, 0x81:
			default:
				return fail("opcode outside executed grammar")
			}
			m := r.unsigned(1)
			mode, selector, low := m>>6, (m>>3)&7, m&7
			operandReg, operandRM := uint8(selector), uint8(low)
			if rex&4 != 0 {
				operandReg += 8
			}
			if rex&1 != 0 {
				operandRM += 8
			}
			memory := mode != 3
			rip := memory && mode == 0 && low == 5 && op == 0x8d
			if memory {
				base := low
				if low == 4 {
					s := r.unsigned(1)
					if rex&2 != 0 || (s>>3)&7 != 4 {
						return fail("indexed address")
					}
					d.Encoding.SIB, d.Encoding.Scale = true, uint8(s>>6)
					base = s & 7
				}
				// mod=00 base=101 is absent/RIP-relative regardless of REX.B.
				if mode == 0 && base == 5 && !rip {
					return fail("address without GPR base")
				}
				if rip {
					d.Encoding.DispBytes, d.Intent.SignedDisp = 4, r.signed(4)
				} else {
					d.Intent.Base = uint8(base)
					if rex&1 != 0 {
						d.Intent.Base += 8
					}
				}
				if mode == 1 {
					d.Encoding.DispBytes, d.Intent.SignedDisp = 1, r.signed(1)
				}
				if mode == 2 {
					d.Encoding.DispBytes, d.Intent.SignedDisp = 4, r.signed(4)
				}
			}
			switch op {
			case 0x89:
				d.Encoding.Form, d.Intent.Src = MOV89, operandReg
				d.Intent.Operation, d.Intent.Dst = MoveRegister, operandRM
				if memory {
					d.Intent.Operation, d.Intent.Dst = Store, 0
				}
			case 0x8b:
				d.Encoding.Form, d.Intent.Dst = MOV8B, operandReg
				d.Intent.Operation, d.Intent.Src = MoveRegister, operandRM
				if memory {
					d.Intent.Operation, d.Intent.Src = Load, 0
				}
			case 0x8d:
				if !memory {
					return fail("register LEA")
				}
				d.Encoding.Form, d.Intent.Operation, d.Intent.Dst = LEA8D, LEA, operandReg
				if rip {
					d.Intent.Operation = LEARIP
				}
			case 0xc7:
				if selector != 0 {
					return fail("C7 opcode extension")
				}
				d.Encoding.Form, d.Intent.Operation, d.Intent.Dst = MOVC7, MoveImmediate, operandRM
				if memory {
					d.Intent.Operation, d.Intent.Dst = StoreImmediate, 0
				}
				d.Intent.Immediate = uint64(r.signed(4))
			case 0x83, 0x81:
				if memory || (selector != 4 && selector != 5) {
					return fail("arithmetic operand or opcode extension")
				}
				d.Intent.Dst = operandRM
				width := 4
				d.Intent.Operation, d.Encoding.Form = Subtract, SUB81
				if selector == 4 {
					d.Intent.Operation, d.Encoding.Form = And, AND81
				}
				if op == 0x83 {
					width = 1
					d.Encoding.Form = SUB83
					if selector == 4 {
						d.Encoding.Form = AND83
					}
				}
				d.Intent.Immediate = uint64(r.signed(width))
			}
		}
	}
	if r.err {
		return fail("truncated bytes")
	}
	d.Length = r.pos
	if pc > ^uint64(0)-uint64(d.Length) {
		return fail("instruction end wraps")
	}
	d.Next = pc + uint64(d.Length)
	if d.Intent.Operation == Jump {
		delta := d.Intent.SignedDisp
		if delta < 0 {
			magnitude := uint64(-delta) // only signed 8/32-bit offsets occur here.
			if magnitude > d.Next {
				return fail("branch target underflows")
			}
			d.Target = d.Next - magnitude
		} else {
			if uint64(delta) > ^uint64(0)-d.Next {
				return fail("branch target overflows")
			}
			d.Target = d.Next + uint64(delta)
		}
	}
	return d, nil
}

// Reading accumulates bytes from most significant to least significant using
// integer place values. Signed fields subtract their modulus when the top bit is
// set, rather than sharing the encoder's narrowing/extension casts.
type byteReader struct {
	code []byte
	pos  int
	err  bool
}

func (r *byteReader) unsigned(width int) uint64 {
	if r.err || width > len(r.code)-r.pos {
		r.err = true
		return 0
	}
	var v uint64
	for n := width - 1; n >= 0; n-- {
		v = v*256 + uint64(r.code[r.pos+n])
	}
	r.pos += width
	return v
}

func (r *byteReader) signed(width int) int64 {
	u := r.unsigned(width)
	modulus := int64(1) << (8 * width)
	if u >= uint64(modulus/2) {
		return int64(u) - modulus
	}
	return int64(u)
}
