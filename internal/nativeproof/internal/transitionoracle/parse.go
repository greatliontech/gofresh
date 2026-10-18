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
	fs := first == 0x64
	if fs {
		first = r.unsigned(1)
	}
	op := first
	if first >= 0x40 && first <= 0x4f {
		d.Encoding.REX = byte(first)
		op = r.unsigned(1)
	}
	rex := d.Encoding.REX
	width := uint8(32)
	if rex&8 != 0 {
		width = 64
	}
	cc := func(n uint64) bool { return n >= 2 && n <= 7 || n >= 12 && n <= 15 }
	if !fs && (op == 0x31 || op == 0x33) {
		m := r.unsigned(1)
		reg, rm := uint8((m/8)%8)+8*((rex/4)%2), uint8(m%8)+8*(rex%2)
		if width != 32 || m/64 != 3 || reg != rm {
			return fail("not a 32-bit self-XOR")
		}
		d.Intent = Intent{Operation: Clear32, Dst: reg}
		d.Encoding.Form = XOR31
		if op == 0x33 {
			d.Encoding.Form = XOR33
		}
	} else if !fs && rex == 0 && (op == 0xe8 || op == 0xc3) {
		if op == 0xe8 {
			d.Intent.Operation, d.Encoding.Form, d.Intent.SignedDisp = Call, CALLE8, r.signed(4)
		} else {
			d.Intent.Operation, d.Encoding.Form = Return, RETC3
		}
	} else if !fs && (rex == 0 || rex == 0x41) && op >= 0x50 && op <= 0x5f {
		d.Intent.Operation, d.Encoding.Form = Push, PUSH50
		if op >= 0x58 {
			d.Intent.Operation, d.Encoding.Form = Pop, POP58
		}
		d.Intent.Dst = uint8(op%8) + 8*(rex&1)
	} else if rex == 0 && op == 0x0f && !fs {
		second := r.unsigned(1)
		if second >= 0x80 && second <= 0x8f && cc(second-0x80) {
			d.Intent.Operation, d.Intent.Condition, d.Encoding.Form = Branch, uint8(second-0x80), JccNear
			d.Intent.SignedDisp = r.signed(4)
		} else if second == 0x05 {
			d.Intent.Operation, d.Encoding.Form = Syscall, SYSCALL0F05
		} else if second != 0xa2 {
			return fail("unsupported two-byte opcode")
		} else {
			d.Intent.Operation, d.Encoding.Form = CPUID, CPUID0FA2
		}
	} else if rex == 0 && op >= 0x70 && op <= 0x7f && cc(op-0x70) {
		d.Intent.Operation, d.Intent.Condition, d.Encoding.Form = Branch, uint8(op-0x70), JccShort
		d.Intent.SignedDisp = r.signed(1)
	} else if rex == 0 && (op == 0xeb || op == 0xe9) {
		d.Intent.Operation = Jump
		d.Encoding.Form = JMPEB
		width := 1
		if op == 0xe9 {
			d.Encoding.Form, width = JMPE9, 4
		}
		d.Intent.SignedDisp = r.signed(width)
	} else if op >= 0xb0 && op <= 0xb7 {
		d.Intent.Operation, d.Intent.Width, d.Encoding.Form = MoveImmediate, 8, MOVB0
		d.Intent.Dst, d.Intent.Immediate = uint8(op-0xb0)+8*(rex&1), r.unsigned(1)
		if rex == 0 && d.Intent.Dst >= 4 {
			d.Intent.Dst -= 4
			d.Intent.HighDst = true
		}
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
		if op == 0x05 || op == 0x2d || op == 0x25 || op == 0x3d || op == 0xa9 {
			d.Intent.Operation, d.Encoding.Form = Subtract, SUB2D
			if op == 0x05 {
				d.Intent.Operation, d.Encoding.Form = Add, ADD05
			}
			if op == 0x25 {
				d.Intent.Operation, d.Encoding.Form = And, AND25
			}
			if op == 0x3d {
				d.Intent.Operation, d.Encoding.Form = CompareImmediate, CMP3D
			}
			if op == 0xa9 {
				d.Intent.Operation, d.Encoding.Form = TestImmediate, TESTA9
			}
			if width != 64 {
				if op == 0x05 || op == 0x2d || op == 0x25 {
					return fail("narrow arithmetic outside grammar")
				}
				d.Intent.Width = width
			}
			d.Intent.Immediate = uint64(r.signed(4))
			if width == 32 {
				d.Intent.Immediate &= 0xffffffff
			}
		} else {
			switch op {
			case 0x88, 0x8a, 0xc6, 0x89, 0x8b, 0x8d, 0xc7, 0x83, 0x81, 0x39, 0x3b, 0x85, 0xf7:
			default:
				return fail("opcode outside executed grammar")
			}
			if op == 0x88 || op == 0x8a || op == 0xc6 {
				width = 8
			}
			if width != 64 {
				d.Intent.Width = width
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
			rip := memory && mode == 0 && low == 5
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
					if !fs {
						return fail("address without GPR base")
					}
					d.Intent.FS, d.Encoding.DispBytes, d.Intent.SignedDisp = true, 4, r.signed(4)
				}
				if rip {
					d.Encoding.DispBytes, d.Intent.SignedDisp = 4, r.signed(4)
					if op != 0x8d {
						d.Intent.RIP = true
					}
				} else if !d.Intent.FS {
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
			case 0x89, 0x88:
				d.Encoding.Form, d.Intent.Src = MOV89, operandReg
				if op == 0x88 {
					d.Encoding.Form = MOV88
				}
				d.Intent.Operation, d.Intent.Dst = MoveRegister, operandRM
				if memory {
					d.Intent.Operation, d.Intent.Dst = Store, 0
				}
			case 0x8b, 0x8a:
				d.Encoding.Form, d.Intent.Dst = MOV8B, operandReg
				if op == 0x8a {
					d.Encoding.Form = MOV8A
				}
				d.Intent.Operation, d.Intent.Src = MoveRegister, operandRM
				if memory {
					d.Intent.Operation, d.Intent.Src = Load, 0
				}
			case 0x8d:
				if !memory || width != 64 {
					return fail("register LEA")
				}
				d.Encoding.Form, d.Intent.Operation, d.Intent.Dst = LEA8D, LEA, operandReg
				if rip {
					d.Intent.Operation = LEARIP
				}
			case 0xc7, 0xc6:
				if selector != 0 {
					return fail("C7 opcode extension")
				}
				d.Encoding.Form, d.Intent.Operation, d.Intent.Dst = MOVC7, MoveImmediate, operandRM
				if op == 0xc6 {
					d.Encoding.Form = MOVC6
				}
				if memory {
					d.Intent.Operation, d.Intent.Dst = StoreImmediate, 0
				}
				if width == 8 {
					d.Intent.Immediate = r.unsigned(1)
				} else {
					d.Intent.Immediate = uint64(r.signed(4))
					if width == 32 {
						d.Intent.Immediate &= 0xffffffff
					}
				}
			case 0x39, 0x3b, 0x85:
				if memory {
					return fail("memory predicate operand")
				}
				d.Intent.Operation, d.Encoding.Form, d.Intent.Dst, d.Intent.Src = Compare, CMP39, operandRM, operandReg
				if op == 0x3b {
					d.Encoding.Form, d.Intent.Dst, d.Intent.Src = CMP3B, operandReg, operandRM
				}
				if op == 0x85 {
					d.Intent.Operation, d.Encoding.Form = Test, TEST85
				}
			case 0xf7:
				if memory || selector != 0 {
					return fail("TEST operand or extension")
				}
				d.Intent.Operation, d.Encoding.Form, d.Intent.Dst = TestImmediate, TESTF7, operandRM
				d.Intent.Immediate = uint64(r.signed(4))
				if width == 32 {
					d.Intent.Immediate &= 0xffffffff
				}
			case 0x83, 0x81:
				if memory || (selector != 0 && selector != 4 && selector != 5 && selector != 7) || selector != 7 && width != 64 {
					return fail("arithmetic operand or opcode extension")
				}
				d.Intent.Dst = operandRM
				immWidth := 4
				d.Intent.Operation, d.Encoding.Form = Subtract, SUB81
				if selector == 0 {
					d.Intent.Operation, d.Encoding.Form = Add, ADD81
				}
				if selector == 4 {
					d.Intent.Operation, d.Encoding.Form = And, AND81
				}
				if selector == 7 {
					d.Intent.Operation, d.Encoding.Form = CompareImmediate, CMP81
				}
				if op == 0x83 {
					immWidth = 1
					d.Encoding.Form = SUB83
					if selector == 0 {
						d.Encoding.Form = ADD83
					}
					if selector == 4 {
						d.Encoding.Form = AND83
					}
					if selector == 7 {
						d.Encoding.Form = CMP83
					}
				}
				d.Intent.Immediate = uint64(r.signed(immWidth))
				if width == 32 {
					d.Intent.Immediate &= 0xffffffff
				}
			}
			if width == 8 && rex == 0 {
				if (d.Intent.Operation == MoveRegister || d.Intent.Operation == Load || d.Intent.Operation == MoveImmediate) && d.Intent.Dst >= 4 {
					d.Intent.Dst -= 4
					d.Intent.HighDst = true
				}
				if (d.Intent.Operation == MoveRegister || d.Intent.Operation == Store) && d.Intent.Src >= 4 {
					d.Intent.Src -= 4
					d.Intent.HighSrc = true
				}
			}
		}
	}
	if r.err {
		return fail("truncated bytes")
	}
	if fs && (!d.Intent.FS || d.Intent.Operation != Load && d.Intent.Operation != Store && d.Intent.Operation != StoreImmediate) {
		return fail("unsupported FS form")
	}
	d.Length = r.pos
	if pc > ^uint64(0)-uint64(d.Length) {
		return fail("instruction end wraps")
	}
	d.Next = pc + uint64(d.Length)
	if d.Intent.Operation == Jump || d.Intent.Operation == Branch || d.Intent.Operation == Call {
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
