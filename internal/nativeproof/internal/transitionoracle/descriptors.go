package transitionoracle

// Descriptor factors a structural spelling from independent immediate and
// displacement payloads. Zero payloads here confer no machine-state premise.
type Descriptor struct {
	Intent   Intent
	Encoding Encoding
}

// Descriptors enumerates the complete admitted structural grammar: all supported
// widths/opcodes, allowed prefix bytes (including ignored REX bits), register
// selectors, address modes, RIP, and all no-index SIB scales. Payloads are factored
// out. This semantic enumerator calls neither the encoder nor the byte parser.
func Descriptors(yield func(Descriptor) bool) {
	emit := func(i Intent, e Encoding) bool { return yield(Descriptor{i, e}) }
	for _, d := range []Descriptor{{Intent{Operation: Call}, Encoding{Form: CALLE8}}, {Intent{Operation: Return}, Encoding{Form: RETC3}}, {Intent{Operation: Syscall}, Encoding{Form: SYSCALL0F05}}} {
		if !yield(d) {
			return
		}
	}
	for reg := uint8(0); reg < 16; reg++ {
		rex := byte(0)
		if reg >= 8 {
			rex = 0x41
		}
		if !emit(Intent{Operation: Push, Dst: reg}, Encoding{Form: PUSH50, REX: rex}) || !emit(Intent{Operation: Pop, Dst: reg}, Encoding{Form: POP58, REX: rex}) {
			return
		}
	}
	for rex := byte(0x48); rex <= 0x4f; rex++ {
		if !emit(Intent{Operation: Add}, Encoding{Form: ADD05, REX: rex}) {
			return
		}
		for low := uint8(0); low < 8; low++ {
			for _, form := range []Form{ADD83, ADD81} {
				if !emit(Intent{Operation: Add, Dst: low + 8*(rex&1)}, Encoding{Form: form, REX: rex}) {
					return
				}
			}
		}
	}
	for _, rex := range []byte{0, 0x40, 0x41, 0x44, 0x45, 0x48, 0x49, 0x4c, 0x4d} {
		for _, form := range []Form{MOV89, MOV8B, MOV88, MOV8A, MOVC7, MOVC6} {
			width := uint8(32)
			if rex&8 != 0 {
				width = 0
			}
			if form == MOV88 || form == MOV8A || form == MOVC6 {
				width = 8
			}
			regs := uint8(8)
			if form == MOVC7 || form == MOVC6 {
				regs = 1
			}
			for low := uint8(0); low < regs; low++ {
				for scale := uint8(0); scale < 4; scale++ {
					i := Intent{Operation: StoreImmediate, FS: true, Width: width}
					reg := low + 8*((rex>>2)&1)
					if form == MOV89 || form == MOV88 {
						i.Operation, i.Src = Store, reg
					}
					if form == MOV8B || form == MOV8A {
						i.Operation, i.Dst = Load, reg
					}
					if width == 8 && rex == 0 && low >= 4 {
						if i.Operation == Load {
							i.Dst, i.HighDst = low-4, true
						} else {
							i.Src, i.HighSrc = low-4, true
						}
					}
					if !emit(i, Encoding{Form: form, REX: rex, DispBytes: 4, SIB: true, Scale: scale}) {
						return
					}
				}
			}
		}
	}
	if !emit(Intent{Operation: CPUID}, Encoding{Form: CPUID0FA2}) {
		return
	}
	for _, f := range []Form{JMPEB, JMPE9} {
		if !emit(Intent{Operation: Jump}, Encoding{Form: f}) {
			return
		}
	}
	for _, cc := range []uint8{2, 3, 4, 5, 6, 7, 12, 13, 14, 15} {
		for _, f := range []Form{JccShort, JccNear} {
			if !emit(Intent{Operation: Branch, Condition: cc}, Encoding{Form: f}) {
				return
			}
		}
	}
	for reg := uint8(0); reg < 16; reg++ {
		rex := byte(0)
		if reg >= 8 {
			rex = 0x41
		}
		if !emit(Intent{Operation: MoveImmediate32, Dst: reg}, Encoding{Form: MOVB8Imm32, REX: rex}) {
			return
		}
	}
	prefixes := []byte{0}
	for rex := byte(0x40); rex <= 0x4f; rex++ {
		prefixes = append(prefixes, rex)
	}
	for _, rex := range prefixes {
		width := uint8(32)
		if rex&8 != 0 {
			width = 0
		}
		bh, rh := uint8(rex&1)*8, uint8(rex>>2&1)*8
		// Physical byte selectors 4..7 without REX designate the high byte of
		// the first four GPRs. Base registers never use that byte alias rule.
		byteAliases := func(i Intent) Intent {
			if i.Width == 8 && rex == 0 {
				if (i.Operation == MoveRegister || i.Operation == MoveImmediate || i.Operation == Load) && i.Dst >= 4 {
					i.Dst -= 4
					i.HighDst = true
				}
				if (i.Operation == MoveRegister || i.Operation == Store) && i.Src >= 4 {
					i.Src -= 4
					i.HighSrc = true
				}
			}
			return i
		}
		for _, f := range []Form{CMP3D, TESTA9, SUB2D, AND25} {
			op := CompareImmediate
			if f == TESTA9 {
				op = TestImmediate
			}
			if f == SUB2D || f == AND25 {
				if width != 0 {
					continue
				}
				op = Subtract
				if f == AND25 {
					op = And
				}
			}
			if !emit(Intent{Operation: op, Width: width}, Encoding{Form: f, REX: rex}) {
				return
			}
		}
		for low := uint8(0); low < 8; low++ {
			for _, f := range []Form{MOVB0, MOVB8Imm64, MOVC6, MOVC7, CMP83, CMP81, TESTF7, SUB83, SUB81, AND83, AND81} {
				i := Intent{Operation: MoveImmediate, Dst: low + bh, Width: width}
				switch f {
				case MOVB0, MOVC6:
					i.Width = 8
				case MOVB8Imm64:
					if width != 0 {
						continue
					}
				case CMP83, CMP81:
					i.Operation = CompareImmediate
				case TESTF7:
					i.Operation = TestImmediate
				case SUB83, SUB81:
					if width != 0 {
						continue
					}
					i.Operation = Subtract
				case AND83, AND81:
					if width != 0 {
						continue
					}
					i.Operation = And
				}
				if !emit(byteAliases(i), Encoding{Form: f, REX: rex}) {
					return
				}
			}
			for reg := uint8(0); reg < 8; reg++ {
				for _, f := range []Form{MOV89, MOV8B, MOV88, MOV8A, CMP39, CMP3B, TEST85} {
					i := Intent{Operation: MoveRegister, Dst: low + bh, Src: reg + rh, Width: width}
					if f == MOV88 || f == MOV8A {
						i.Width = 8
					}
					if f == CMP39 || f == CMP3B {
						i.Operation = Compare
					}
					if f == TEST85 {
						i.Operation = Test
					}
					if f == MOV8B || f == MOV8A || f == CMP3B {
						i.Dst, i.Src = i.Src, i.Dst
					}
					if !emit(byteAliases(i), Encoding{Form: f, REX: rex}) {
						return
					}
				}
			}
		}
		for _, f := range []Form{MOV89, MOV8B, MOV88, MOV8A, MOVC7, MOVC6, LEA8D} {
			if f == LEA8D && width != 0 {
				continue
			}
			regs := uint8(8)
			if f == MOVC7 || f == MOVC6 {
				regs = 1
			}
			for reg := uint8(0); reg < regs; reg++ {
				i := Intent{Width: width}
				switch f {
				case MOV89, MOV88:
					i.Operation, i.Src = Store, reg+rh
				case MOV8B, MOV8A:
					i.Operation, i.Dst = Load, reg+rh
				case MOVC7, MOVC6:
					i.Operation = StoreImmediate
				case LEA8D:
					i.Operation, i.Dst = LEA, reg+rh
				}
				if f == MOV88 || f == MOV8A || f == MOVC6 {
					i.Width = 8
				}
				i = byteAliases(i)
				rip := i
				rip.RIP = true
				if f == LEA8D {
					rip.Operation, rip.RIP = LEARIP, false
				}
				if !emit(rip, Encoding{Form: f, REX: rex, DispBytes: 4}) {
					return
				}
				for base := uint8(0); base < 8; base++ {
					for _, disp := range []uint8{0, 1, 4} {
						if disp == 0 && base == 5 {
							continue
						}
						for variant := 0; variant < 5; variant++ {
							if variant == 0 && base == 4 || variant != 0 && rex&2 != 0 {
								continue
							}
							m := i
							m.Base = base + bh
							e := Encoding{Form: f, REX: rex, DispBytes: disp, SIB: variant != 0}
							if variant != 0 {
								e.Scale = uint8(variant - 1)
							}
							if !emit(m, e) {
								return
							}
						}
					}
				}
			}
		}
	}
}
