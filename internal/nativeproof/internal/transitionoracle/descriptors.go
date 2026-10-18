package transitionoracle

// Descriptor is one member of the finite executed-encoding population, before
// choosing payloads. Intent has zero immediate/displacement; callers replace
// those independently with values representable by Encoding. No payload is
// derived from an opcode, register, descriptor index or another payload byte.
type Descriptor struct {
	Intent   Intent
	Encoding Encoding
}

// Descriptors visits each structural spelling once (14,707 descriptors). It can
// be used directly as a range-over-function iterator; false stops iteration.
// The finite dimensions are all opcode forms, allowed REX bytes, ModRM register
// selectors and modes, optional/required SIB bases and all four no-index scales.
// Default 64-bit addressing is the only admitted address size; address/operand
// override prefixes belong to the refusal population, not this iterator.
//
// Payload dimensions are intentionally factored OUT: exhaustive descriptor
// enumeration does not exhaust imm64, imm32, imm8 or displacement values. Tests
// and consumers must exercise independent full-word payloads as well. Group
// selectors have no semantic REX.R extension; their ignored bit still produces
// distinct descriptors. The iterator calls neither Encode nor Parse.
func Descriptors(yield func(Descriptor) bool) {
	if !yield(Descriptor{Intent: Intent{Operation: CPUID}, Encoding: Encoding{Form: CPUID0FA2}}) {
		return
	}
	for _, f := range []Form{JMPEB, JMPE9} {
		if !yield(Descriptor{Intent: Intent{Operation: Jump}, Encoding: Encoding{Form: f}}) {
			return
		}
	}
	for reg := uint8(0); reg < 16; reg++ {
		rex := byte(0)
		if reg >= 8 {
			rex = 0x41
		}
		if !yield(Descriptor{Intent: Intent{Operation: MoveImmediate32, Dst: reg}, Encoding: Encoding{Form: MOVB8Imm32, REX: rex}}) {
			return
		}
	}
	for rex := byte(0x48); rex <= 0x4f; rex++ {
		bHigh, rHigh := uint8(0), uint8(0)
		if rex&1 != 0 {
			bHigh = 8
		}
		if rex&4 != 0 {
			rHigh = 8
		}
		for reg := uint8(0); reg < 8; reg++ {
			if !yield(Descriptor{Intent: Intent{Operation: LEARIP, Dst: reg + rHigh}, Encoding: Encoding{Form: LEA8D, REX: rex, DispBytes: 4}}) {
				return
			}
		}
		for _, f := range []Form{SUB2D, AND25} {
			op := Subtract
			if f == AND25 {
				op = And
			}
			if !yield(Descriptor{Intent: Intent{Operation: op}, Encoding: Encoding{Form: f, REX: rex}}) {
				return
			}
		}
		for low := uint8(0); low < 8; low++ {
			for _, f := range []Form{MOVB8Imm64, MOVC7, SUB83, SUB81, AND83, AND81} {
				op := MoveImmediate
				if f == SUB83 || f == SUB81 {
					op = Subtract
				}
				if f == AND83 || f == AND81 {
					op = And
				}
				if !yield(Descriptor{Intent: Intent{Operation: op, Dst: low + bHigh}, Encoding: Encoding{Form: f, REX: rex}}) {
					return
				}
			}
			for reg := uint8(0); reg < 8; reg++ {
				for _, f := range []Form{MOV89, MOV8B} {
					dst, src := low+bHigh, reg+rHigh
					if f == MOV8B {
						dst, src = src, dst
					}
					if !yield(Descriptor{Intent: Intent{Operation: MoveRegister, Dst: dst, Src: src}, Encoding: Encoding{Form: f, REX: rex}}) {
						return
					}
				}
			}
		}
		for _, f := range []Form{MOV89, MOV8B, MOVC7, LEA8D} {
			registers := uint8(8)
			if f == MOVC7 {
				registers = 1
			}
			for reg := uint8(0); reg < registers; reg++ {
				for base := uint8(0); base < 8; base++ {
					for _, width := range []uint8{0, 1, 4} {
						if width == 0 && base == 5 {
							continue
						}
						// variant 0 is non-SIB; 1..4 carry scale bits 0..3.
						for variant := 0; variant < 5; variant++ {
							if variant == 0 && base == 4 || variant != 0 && rex&2 != 0 {
								continue
							}
							i := Intent{Base: base + bHigh}
							switch f {
							case MOV89:
								i.Operation, i.Src = Store, reg+rHigh
							case MOV8B:
								i.Operation, i.Dst = Load, reg+rHigh
							case MOVC7:
								i.Operation = StoreImmediate
							case LEA8D:
								i.Operation, i.Dst = LEA, reg+rHigh
							}
							e := Encoding{Form: f, REX: rex, DispBytes: width, SIB: variant != 0}
							if variant != 0 {
								e.Scale = uint8(variant - 1)
							}
							if !yield(Descriptor{Intent: i, Encoding: e}) {
								return
							}
						}
					}
				}
			}
		}
	}
}
