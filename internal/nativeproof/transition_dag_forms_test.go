package nativeproof

import (
	"testing"
	"testing/quick"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

func dagEncoding(i to.Intent, choice uint8) to.Encoding {
	if i.Operation == to.Branch {
		f := to.JccNear
		if choice&1 == 0 {
			f = to.JccShort
		}
		return to.Encoding{Form: f}
	}
	e := to.Encoding{}
	width := i.Width
	if width == 0 {
		width = 64
	}
	if width == 64 {
		e.REX = 0x48
	}
	reg, rm, operand := i.Src, i.Dst, true
	mem := i.Operation == to.Load || i.Operation == to.Store || i.Operation == to.StoreImmediate
	switch i.Operation {
	case to.MoveRegister, to.Store:
		e.Form = to.MOV89
		if width == 8 {
			e.Form = to.MOV88
		}
		if i.Operation == to.MoveRegister && choice&1 != 0 {
			e.Form = to.MOV8B
			if width == 8 {
				e.Form = to.MOV8A
			}
			reg, rm = i.Dst, i.Src
		}
	case to.Load:
		e.Form, reg = to.MOV8B, i.Dst
		if width == 8 {
			e.Form = to.MOV8A
		}
	case to.MoveImmediate, to.StoreImmediate:
		e.Form, operand = to.MOVC7, false
		if width == 8 {
			e.Form = to.MOVC6
		}
		if i.Operation == to.MoveImmediate && width == 8 && choice&1 != 0 {
			e.Form = to.MOVB0
		}
	case to.Compare:
		e.Form = to.CMP39
		if choice&1 != 0 {
			e.Form, reg, rm = to.CMP3B, i.Dst, i.Src
		}
	case to.Test:
		e.Form = to.TEST85
	case to.CompareImmediate:
		e.Form, operand = to.CMP81, false
		v := uint64(int64(int8(i.Immediate)))
		if width == 32 {
			v &= 0xffffffff
		}
		if choice%3 == 0 && v == i.Immediate {
			e.Form = to.CMP83
		} else if choice%3 == 2 && i.Dst == 0 {
			e.Form = to.CMP3D
		}
	case to.TestImmediate:
		e.Form, operand = to.TESTF7, false
		if choice&1 != 0 && i.Dst == 0 {
			e.Form = to.TESTA9
		}
	}
	if mem {
		rm = i.Base
	}
	if !i.RIP {
		e.REX |= rm / 8
	}
	if operand {
		e.REX |= reg / 8 << 2
	}
	if e.REX != 0 && e.REX < 0x40 {
		e.REX |= 0x40
	}
	if width == 8 && !i.HighDst && !i.HighSrc {
		e.REX |= 0x40
	}
	if mem {
		e.DispBytes = 4
		if i.RIP {
			return e
		}
		e.SIB = i.Base%8 == 4 || choice&4 != 0
		if e.SIB {
			e.Scale = choice >> 3 & 3
		}
		if i.SignedDisp == 0 && i.Base%8 != 5 && choice%3 == 0 {
			e.DispBytes = 0
		} else if int64(int8(i.SignedDisp)) == i.SignedDisp && choice%3 == 1 {
			e.DispBytes = 1
		}
	}
	return e
}

func TestTransitionGuardedScalarForms(t *testing.T) {
	face := cpuidFace()
	for _, width := range []uint8{32, 0} {
		for _, operation := range []to.Operation{to.Compare, to.CompareImmediate, to.Test, to.TestImmediate} {
			for dst := uint8(0); dst < 16; dst++ {
				for choice := uint8(0); choice < 3; choice++ {
					i := to.Intent{Operation: operation, Dst: dst, Width: width}
					if operation == to.Compare || operation == to.Test {
						i.Src = (dst + choice + 1) % 16
					} else {
						i.Immediate = ^uint64(127)
						if width == 32 {
							i.Immediate = 0xffffff80
						}
					}
					op := dagScalar(i, dagEncoding(i, choice), 1)
					for _, cc := range []uint8{2, 3, 4, 5, 6, 7, 12, 13, 14, 15} {
						ops := []dagOp{op, dagBranch(cc, 2, 3), dagScalar(to.Intent{Operation: to.StoreImmediate, Width: 8, Base: 4, Immediate: 1}, to.Encoding{Form: to.MOVC6, SIB: true}, 4), dagScalar(to.Intent{Operation: to.Store, Width: 32, Base: 4, Src: 0}, to.Encoding{Form: to.MOV89, SIB: true}, 4)}
						initial := stateInitial(face, uint64(dst)*31+uint64(choice))
						if dst != 4 {
							if choice == 0 {
								initial.regs[dst] = i.Immediate
							} else if choice == 1 {
								initial.regs[dst] = 0x8000000000000000
							}
						}
						dagCheck(t, ops, face, initial, uint64(dst+choice), 1)
					}
				}
			}
		}
	}
}

func TestTransitionGuardedMemoryForms(t *testing.T) {
	face := imageStateFace()
	face.Conditions.CPUID = CPUIDModel
	for _, width := range []uint8{8, 32, 0} {
		for choice := uint8(0); choice < 3; choice++ {
			for _, rip := range []bool{false, true} {
				store := to.Intent{Operation: to.Store, Width: width, Base: 4, Src: 3, SignedDisp: 1, RIP: rip}
				if rip {
					store.Base, store.SignedDisp = 0, 0
				}
				load := to.Intent{Operation: to.Load, Width: width, Base: store.Base, Dst: 9, SignedDisp: store.SignedDisp, RIP: rip}
				imm := store
				imm.Operation, imm.Src, imm.Immediate = to.StoreImmediate, 0, 127
				ops := []dagOp{
					dagScalar(to.Intent{Operation: to.MoveRegister, Dst: 3, Src: 4}, to.Encoding{Form: to.MOV89, REX: 0x48}, 1),
					dagScalar(to.Intent{Operation: to.Store, Base: 4, Src: 3}, to.Encoding{Form: to.MOV89, REX: 0x48, SIB: true}, 2),
					dagBranch(4, 3, 4), dagScalar(store, dagEncoding(store, choice), 5), dagScalar(imm, dagEncoding(imm, choice), 5),
					dagScalar(load, dagEncoding(load, choice), 6),
				}
				if rip {
					for _, j := range []int{3, 4, 5} {
						ops[j].address = imageStateAddress + 17
					}
				}
				for flag := 0; flag < 2; flag++ {
					initial := stateInitial(face, uint64(choice))
					initial.flags[1] = flag == 1
					dagCheck(t, ops, face, initial, uint64(choice+3), 2, 5)
				}
			}
		}
	}
	// Register byte aliases include the high four bytes and REX low-byte forms.
	for dst := uint8(0); dst < 16; dst++ {
		for src := uint8(0); src < 16; src++ {
			for _, width := range []uint8{8, 32} {
				i := to.Intent{Operation: to.MoveRegister, Dst: dst, Src: src, Width: width}
				e := dagEncoding(i, dst+src)
				code, err := to.Encode(i, e)
				if err != nil {
					t.Fatal(err)
				}
				compareExecutedEncoding(t, code)
				initial := stateInitial(face, uint64(dst)*16+uint64(src))
				dagCheck(t, []dagOp{dagScalar(i, e, 1)}, face, initial, 0)
			}
		}
	}
	for _, op := range []to.Operation{to.MoveRegister, to.MoveImmediate} {
		for dst := uint8(0); dst < 4; dst++ {
			i := to.Intent{Operation: op, Dst: dst, Width: 8, HighDst: true, Src: 1, HighSrc: true}
			if op == to.MoveImmediate {
				i.Src, i.HighSrc, i.Immediate = 0, false, 255
			}
			for choice := uint8(0); choice < 2; choice++ {
				dagCheck(t, []dagOp{dagScalar(i, dagEncoding(i, choice), 1)}, face, stateInitial(face, 31), 0)
			}
		}
	}
}

func TestTransitionGuardedProduct(t *testing.T) {
	if err := quick.Check(func(a, b uint64, cc uint8, layout uint64, raw [256]byte) bool {
		conditions := []uint8{2, 3, 4, 5, 6, 7, 12, 13, 14, 15}
		cc = conditions[int(cc)%len(conditions)]
		face := cpuidFace()
		initial := stateRawInitial(face, raw[:])
		initial.regs[0], initial.regs[3] = a, b
		initial.outcomes = [][4]uint32{{uint32(a), uint32(a >> 32), uint32(b), uint32(b >> 32)}, {uint32(b), uint32(b >> 32), uint32(a), uint32(a >> 32)}}
		i := to.Intent{Operation: to.Compare, Dst: 0, Src: 3}
		ops := []dagOp{dagScalar(i, dagEncoding(i, 0), 1), dagBranch(cc, 2, 3), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 4), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 4), dagScalar(to.Intent{Operation: to.Test, Width: 32, Dst: 0, Src: 3}, to.Encoding{Form: to.TEST85}, 5), dagBranch(4, 6, 7), dagScalar(to.Intent{Operation: to.Store, Width: 32, Base: 4, Src: 0}, to.Encoding{Form: to.MOV89, SIB: true}, 8), dagScalar(to.Intent{Operation: to.StoreImmediate, Width: 8, Base: 4, Immediate: 1}, to.Encoding{Form: to.MOVC6, SIB: true}, 8)}
		dagCheck(t, ops, face, initial, layout, 1, 4, 5)
		return true
	}, &quick.Config{MaxCount: 64}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionGuardedNarrowImmediateForms(t *testing.T) {
	face := cpuidFace()
	for _, width := range []uint8{8, 32} {
		for dst := uint8(0); dst < 16; dst++ {
			for _, value := range []uint64{0, 1, 127, 128, 255, 0x80000000, 0xffffffff} {
				if width == 8 && value > 255 {
					continue
				}
				for choice := uint8(0); choice < 2; choice++ {
					i := to.Intent{Operation: to.MoveImmediate, Dst: dst, Width: width, Immediate: value}
					x := dagArrange(t, []dagOp{dagScalar(i, dagEncoding(i, choice), 1)}, 0)
					compareExecutedEncoding(t, x.encoded[0])
					c, err := CheckTransition(t.Context(), x.im, face, x.proposal(2), TransitionLimits{})
					if err != nil {
						t.Fatal(err)
					}
					dagAssert(t, c, x, 2, face, stateInitial(face, value), nil)
					want := uint64(0)
					if width == 8 {
						want = ^uint64(255)
					}
					if c.checked.bound.Preserved[dst] != want {
						t.Fatal("wrong partial-write preservation mask")
					}
				}
			}
		}
	}
}

func TestTransitionGuardedPredicatesDoNotWrite(t *testing.T) {
	face := cpuidFace()
	for _, width := range []uint8{0, 32} {
		for _, operation := range []to.Operation{to.Compare, to.CompareImmediate, to.Test, to.TestImmediate} {
			i := to.Intent{Operation: operation, Dst: 4, Width: width}
			if operation == to.Compare || operation == to.Test {
				i.Src = 3
			}
			x := dagArrange(t, []dagOp{dagScalar(i, dagEncoding(i, 0), 1)}, 0)
			c, err := CheckTransition(t.Context(), x.im, face, x.proposal(2), TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			b := c.checked.bound
			for reg, v := range b.Registers {
				if v.Value != b.InitialRegisters[reg] || b.Preserved[reg] != ^uint64(0) {
					t.Fatal("predicate wrote register or preservation", reg)
				}
			}
			if b.Registers[RSP].Pointer != (OriginPointer{Origin: b.Origin}) {
				t.Fatal("predicate destroyed pointer provenance")
			}
			dagAssert(t, c, x, 2, face, stateInitial(face, 37), nil)
		}
	}
}

func FuzzTransitionGuardedProduct(f *testing.F) {
	f.Add(uint64(0), uint64(1), uint8(4), uint64(0), []byte{1, 2, 3, 4})
	f.Add(uint64(0x8000000000000000), ^uint64(0), uint8(12), uint64(31), []byte{255, 128})
	f.Fuzz(func(t *testing.T, a, b uint64, cc uint8, layout uint64, raw []byte) {
		face := cpuidFace()
		initial := stateRawInitial(face, raw)
		initial.regs[0], initial.regs[3] = a, b
		conditions := []uint8{2, 3, 4, 5, 6, 7, 12, 13, 14, 15}
		cc = conditions[int(cc)%len(conditions)]
		i := to.Intent{Operation: to.Compare, Dst: 0, Src: 3}
		if layout&1 != 0 {
			i.Width = 32
		}
		if layout&2 != 0 {
			i.Operation = to.Test
		}
		ops := []dagOp{dagScalar(i, dagEncoding(i, uint8(layout)), 1), dagBranch(cc, 2, 3), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 4), dagScalar(to.Intent{Operation: to.Store, Width: 32, Base: 4, Src: 3}, to.Encoding{Form: to.MOV89, SIB: true}, 4)}
		dagCheck(t, ops, face, initial, layout, 1)
	})
}
