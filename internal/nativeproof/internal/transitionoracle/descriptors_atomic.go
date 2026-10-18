package transitionoracle

// Descriptor transformations preserve independent symbolic address dimensions;
// neither bytes nor decoder answers select this grammar.
func atomicDescriptors(yield func(Descriptor) bool) {
	originalYield, more := yield, true
	yield = func(d Descriptor) bool { more = originalYield(d); return more }
	if !yield(Descriptor{Intent: Intent{Operation: NoOp}, Encoding: Encoding{Form: NOP90}}) || !yield(Descriptor{Intent: Intent{Operation: NoOp}, Encoding: Encoding{Form: NOP6690}}) {
		return
	}
	baseDescriptors(func(d Descriptor) bool {
		i, e := d.Intent, d.Encoding
		if i.FS {
			return true
		}
		if (i.Operation == Store || i.Operation == Load) && i.Width != 8 {
			if i.Operation == Store {
				i.Operation, e.Form = CompareMemory, CMP39
				if !yield(Descriptor{i, e}) {
					return false
				}
				if i.Width == 0 {
					i.Operation, e.Form = LockedCompareExchange, LOCKCMPXCHG0FB1
					if !yield(Descriptor{i, e}) {
						return false
					}
				}
			} else {
				i.Operation, e.Form = CompareFromMemory, CMP3B
				if !yield(Descriptor{i, e}) {
					return false
				}
			}
		}
		if i.Operation == StoreImmediate && i.Width != 8 {
			i.Operation = CompareMemoryImmediate
			for _, f := range []Form{CMP81, CMP83} {
				e.Form = f
				if !yield(Descriptor{i, e}) {
					return false
				}
			}
		}
		i, e = d.Intent, d.Encoding
		if i.Width == 8 && (i.Operation == MoveImmediate || i.Operation == StoreImmediate) && e.Form == MOVC6 {
			i.Operation = SetRegister
			if d.Intent.Operation == StoreImmediate {
				i.Operation = SetMemory
			}
			e.Form = SETcc0F90
			for _, cc := range []uint8{2, 3, 4, 5, 6, 7, 12, 13, 14, 15} {
				i.Condition = cc
				if !yield(Descriptor{i, e}) {
					return false
				}
			}
		}
		i, e = d.Intent, d.Encoding
		if i.Width == 8 && i.Operation == MoveRegister && e.Form == MOV88 {
			i.Operation, e.Form = Test, TEST84
			if !yield(Descriptor{i, e}) {
				return false
			}
		}
		if i.Width == 8 && i.Operation == MoveImmediate && e.Form == MOVC6 {
			i.Operation, e.Form = TestImmediate, TESTF6
			if !yield(Descriptor{i, e}) {
				return false
			}
		}
		return true
	})
	if !more {
		return
	}
	for _, rex := range []byte{0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f} {
		if !yield(Descriptor{Intent: Intent{Operation: TestImmediate, Width: 8}, Encoding: Encoding{Form: TESTA8, REX: rex}}) {
			return
		}
	}
}
