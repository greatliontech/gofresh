package transitionoracle

import "fmt"

func parseAtomic(code []byte, pc uint64) (Decoded, bool, error) {
	fail := func() (Decoded, bool, error) {
		return Decoded{}, true, fmt.Errorf("unsupported or truncated locked/SETcc/NOP form")
	}
	if len(code) == 0 {
		return Decoded{}, false, nil
	}
	r := byteReader{code: code}
	first := r.unsigned(1)
	locked := first == 0xf0
	if locked {
		first = r.unsigned(1)
	}
	d := Decoded{}
	if first == 0x90 || first == 0x66 && len(code) > 1 && code[1] == 0x90 {
		if locked {
			return fail()
		}
		d.Intent.Operation, d.Encoding.Form = NoOp, NOP90
		if first == 0x66 {
			r.unsigned(1)
			d.Encoding.Form = NOP6690
		}
	} else {
		operand16 := first == 0x66
		if operand16 {
			first = r.unsigned(1)
			if locked || first != 0x0f {
				return fail()
			}
		}
		if first >= 0x40 && first <= 0x4f {
			d.Encoding.REX = byte(first)
			first = r.unsigned(1)
		}
		xchg := first == 0x87
		logical := locked && (first == 0x20 || first == 0x08 || first == 0x80)
		if first != 0x0f && !xchg && !logical {
			if locked {
				return fail()
			}
			return Decoded{}, false, nil
		}
		second := uint64(0)
		if !xchg && !logical {
			second = r.unsigned(1)
		}
		if !locked && second == 0x1f {
			if d.Encoding.REX != 0 {
				return fail()
			}
			m := r.unsigned(1)
			if (m/8)%8 != 0 {
				return fail()
			}
			d.Intent.Operation, d.Encoding.Form, d.Encoding.NOPModRM = NoOp, NOP0F1F, uint8(m)
			if operand16 {
				d.Encoding.Form = NOP660F1F
			}
			mode, low, base := m/64, m%8, m%8
			if mode != 3 && low == 4 {
				s := r.unsigned(1)
				d.Encoding.NOPSIB, base = uint8(s), s%8
			}
			if mode == 1 {
				d.Encoding.NOPDisp = int32(r.signed(1))
			}
			if mode == 2 || mode == 0 && base == 5 {
				d.Encoding.NOPDisp = int32(r.signed(4))
			}
			if r.err || pc > ^uint64(0)-uint64(r.pos) {
				return fail()
			}
			d.Length, d.Next = r.pos, pc+uint64(r.pos)
			return d, true, nil
		}
		set := second >= 0x92 && second <= 0x97 || second >= 0x9c && second <= 0x9f
		if !locked && !set && !xchg {
			return Decoded{}, false, nil
		}
		if operand16 || (xchg || second == 0xc1) && d.Encoding.REX < 0x48 || locked && !xchg && !logical && second != 0xb1 && second != 0xc1 || set && locked {
			return fail()
		}
		m := r.unsigned(1)
		mode, selector, low := m/64, (m/8)%8, m%8
		rex := d.Encoding.REX
		if set {
			if selector != 0 {
				return fail()
			}
			d.Intent = Intent{Operation: SetRegister, Width: 8, Condition: uint8(second - 0x90), Dst: uint8(low) + 8*(rex%2)}
			d.Encoding.Form = SETcc0F90
			if mode == 3 && rex == 0 && low >= 4 {
				d.Intent.Dst, d.Intent.HighDst = uint8(low-4), true
			}
		} else {
			if mode == 3 {
				return fail()
			}
			d.Intent = Intent{Operation: LockedCompareExchange, Src: uint8(selector) + 8*((rex/4)%2)}
			d.Encoding.Form = LOCKCMPXCHG0FB1
			if logical {
				d.Intent.Operation, d.Intent.Width, d.Encoding.Form = LockedAnd, 8, LOCKAND20
				if first == 0x08 {
					d.Intent.Operation, d.Encoding.Form = LockedOr, LOCKOR08
				}
				if first == 0x80 {
					if selector != 1 && selector != 4 {
						return fail()
					}
					d.Intent.Operation, d.Encoding.Form, d.Intent.Src = LockedAndImmediate, LOCKAND80, 0
					if selector == 1 {
						d.Intent.Operation, d.Encoding.Form = LockedOrImmediate, LOCKOR80
					}
				} else if rex == 0 && selector >= 4 {
					d.Intent.Src, d.Intent.HighSrc = uint8(selector-4), true
				}
			} else if xchg {
				d.Intent.Operation, d.Encoding.Form = LockedExchange, XCHG87
				if locked {
					d.Encoding.Form = LOCKXCHG87
				}
			} else if second == 0xc1 {
				d.Intent.Operation, d.Encoding.Form = LockedExchangeAdd, LOCKXADD0FC1
			} else if rex&8 == 0 {
				d.Intent.Width = 32
			}
		}
		if mode != 3 {
			if set {
				d.Intent.Operation, d.Intent.Dst = SetMemory, 0
			}
			base := low
			if low == 4 {
				s := r.unsigned(1)
				if rex&2 != 0 || (s/8)%8 != 4 {
					return fail()
				}
				d.Encoding.SIB, d.Encoding.Scale, base = true, uint8(s/64), s%8
			}
			if mode == 0 && base == 5 {
				if low == 4 {
					return fail()
				}
				d.Intent.RIP, d.Encoding.DispBytes = true, 4
				d.Intent.SignedDisp = r.signed(4)
			} else {
				d.Intent.Base = uint8(base) + 8*(rex%2)
				if mode == 1 {
					d.Encoding.DispBytes, d.Intent.SignedDisp = 1, r.signed(1)
				}
				if mode == 2 {
					d.Encoding.DispBytes, d.Intent.SignedDisp = 4, r.signed(4)
				}
			}
		}
		if logical && first == 0x80 {
			d.Intent.Immediate = r.unsigned(1)
		}
	}
	if r.err || pc > ^uint64(0)-uint64(r.pos) {
		return fail()
	}
	d.Length, d.Next = r.pos, pc+uint64(r.pos)
	return d, true, nil
}
