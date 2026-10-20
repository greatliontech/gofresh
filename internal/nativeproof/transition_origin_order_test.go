package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
	"golang.org/x/arch/x86/x86asm"
)

func originOrderChecker(t testing.TB, domain OriginDomain, envelope RelativeSpan) *transitionChecker {
	t.Helper()
	m := scalarTailChecker(t)
	m.face.Origin, m.face.Envelope = domain, envelope
	var ok bool
	m.lo, m.hi, ok = originRange(domain)
	if !ok {
		t.Fatal("invalid test domain")
	}
	m.bound.Origin = m.scratch(br.Bits(64))
	m.bound.EntryPredicate = m.truth
	return m
}

func originOrderValue(m *transitionChecker, offset int64) TransitionValue {
	return TransitionValue{Value: m.binary(br.Add, m.bound.Origin, m.con(br.Bits(64), uint64(offset))), Pointer: OriginPointer{Origin: m.bound.Origin, Offset: offset}}
}

// The concrete oracle uses unbounded integer subtraction for every flag. Small
// domains are enumerated completely; wide domains exercise both rounded ends.
func TestTransitionOriginOrderConcreteFlags(t *testing.T) {
	domains := []OriginDomain{
		{Min: 31, Max: 31, Modulus: 1},
		{Min: 1<<47 - 32, Max: 1<<47 - 32, Modulus: 1},
		{Min: 1 << 46, Max: 1 << 46, Modulus: 1},
		{Min: 1 << 24, Max: 1<<24 + 31, Modulus: 1},
		{Min: 1 << 24, Max: 1<<24 + 31, Modulus: 2, Residue: 1},
		{Min: 1 << 24, Max: 1<<24 + 31, Modulus: 8, Residue: 3},
		{Min: 32, Max: 1<<47 - 33, Modulus: 16, Residue: 7},
	}
	for _, d := range domains {
		offsets, envelope := []int64{-31, -17, -1, 0, 1, 17, 31}, RelativeSpan{-31, 31}
		if d.Min == 1<<46 {
			offsets = append(offsets, -1<<46, 1<<46-1)
			envelope = RelativeSpan{-1 << 46, 1<<46 - 1}
		}
		for _, a := range offsets {
			for _, b := range offsets {
				m := originOrderChecker(t, d, envelope)
				left, right := originOrderValue(m, a), originOrderValue(m, b)
				var predicates TransitionPredicates
				m.bound.Flags, predicates = m.compareFlags(left.Value, right.Value)
				m.setPredicates(predicates)
				before, inputs, path := m.bound.Flags, m.state.regs, m.state.path
				known, err := m.refineOriginCompare(left, right)
				if err != nil || !known {
					t.Fatal("applicable comparison", a, b, err)
				}
				if m.bound.Flags.OF != before.OF || m.bound.Flags.SF != before.SF || m.bound.Flags.AF != before.AF || m.bound.Flags.PF != before.PF || m.state.regs != inputs || m.state.path != path || m.bound.EntryPredicate != m.truth || len(m.justifications) != 0 {
					t.Fatal("domain inference changed exact flags, inputs or premises")
				}
				origins := []uint64{m.lo, m.hi}
				if m.hi-m.lo < 64 {
					origins = nil
					for s := m.lo; s <= m.hi; s += d.Modulus {
						origins = append(origins, s)
					}
				}
				for _, s := range origins {
					values := map[br.Term]uint64{m.bound.Origin: s}
					_, want := scalarBorrowReference(s+uint64(a), s+uint64(b), 0, 64)
					flags := m.bound.Flags
					for j, f := range []TransitionFlag{flags.CF, flags.ZF, flags.OF, flags.SF, flags.AF, flags.PF} {
						if !f.Defined || f.Preserved || (stateEval(t, f.Value, values) != 0) != want[j] {
							t.Fatalf("domain %+v origin %x offsets %d/%d flag %d", d, s, a, b, j)
						}
					}
					for j, expected := range []bool{want[0], want[1], want[3] != want[2]} {
						if (stateEval(t, m.state.flags[j], values) != 0) != expected || m.state.flags[j].View().Op != br.Constant {
							t.Fatal("private predicate disagrees with concrete CMP", j)
						}
					}
				}
			}
		}
	}
}

func TestTransitionOriginOrderApplicability(t *testing.T) {
	for _, mode := range []string{"pointerless", "foreign", "foreign-pair", "entry-lineage", "narrow32", "byte", "envelope", "wrap-low", "noncanonical-high", "min-offset", "max-offset"} {
		t.Run(mode, func(t *testing.T) {
			m := originOrderChecker(t, OriginDomain{Min: 32, Max: 1<<47 - 33, Modulus: 1}, RelativeSpan{-32, 32})
			left, right := originOrderValue(m, -8), originOrderValue(m, 8)
			failure := false
			switch mode {
			case "pointerless":
				left.Pointer = nil
			case "foreign", "foreign-pair":
				foreign := m.scratch(br.Bits(64))
				left.Pointer = OriginPointer{Origin: foreign, Offset: -8}
				if mode == "foreign-pair" {
					right.Pointer = OriginPointer{Origin: foreign, Offset: 8}
				}
			case "entry-lineage":
				left.Pointer = entryValueLineage{value: left.Value}
			case "narrow32":
				left.Value = m.extract(left.Value, 0, 32)
			case "byte":
				left.Value = m.extract(left.Value, 0, 8)
			case "envelope":
				left = originOrderValue(m, -33)
				failure = true
			default:
				m.face.Envelope = RelativeSpan{math.MinInt64, math.MaxInt64}
				offset := int64(-33)
				if mode == "noncanonical-high" {
					offset = 33
				} else if mode == "min-offset" {
					offset = math.MinInt64
				} else if mode == "max-offset" {
					offset = math.MaxInt64
				}
				left = originOrderValue(m, offset)
				failure = true
			}
			before, predicates := m.bound.Flags, m.state.flags
			known, err := m.refineOriginCompare(left, right)
			if known || (err != nil) != failure || m.bound.Flags != before || m.state.flags != predicates {
				t.Fatal("inapplicable or invalid operand borrowed rule", known, err)
			}
		})
	}
}

func TestTransitionOriginOrderNumericUpperBound(t *testing.T) {
	m := originOrderChecker(t, OriginDomain{Min: 1 << 32, Max: 1 << 44, Modulus: 16, Residue: 8}, RelativeSpan{-70000, 0})
	guard := originOrderValue(m, -65584)
	for _, tc := range []struct {
		offset int64
		want   bool
	}{{-120, true}, {64, true}, {-65584, false}, {-65585, false}} {
		holds, known, err := m.originWordUpperBound(guard, tc.offset)
		if err != nil || !known || holds != tc.want {
			t.Fatal("numeric bound", tc, holds, known, err)
		}
	}
	// Numeric S+64 is outside the pointer envelope. It implies the upper-bound
	// premise, but must still be refused if requested as an address capability.
	if err := m.offset(64); err == nil {
		t.Fatal("numeric upper bound granted an address")
	}
	for _, offset := range []int64{math.MinInt64, math.MaxInt64, -1<<32 - 9, 1<<47 - 1<<44 + 8} {
		if _, known, err := m.originWordUpperBound(guard, offset); err == nil || known {
			t.Fatal("invalid numeric domain accepted", offset)
		}
	}
	guard.Pointer = nil
	if _, known, err := m.originWordUpperBound(guard, -120); known || err != nil {
		t.Fatal("pointerless bound did not leave scalar fallback", known, err)
	}
	if m.bound.EntryPredicate != m.truth || len(m.justifications) != 0 || len(m.bound.Accesses) != 0 {
		t.Fatal("numeric bound fabricated a premise, proof or read")
	}
}

func TestTransitionOriginOrderCancellationAndBudget(t *testing.T) {
	for _, numeric := range []bool{false, true} {
		for _, cancel := range []bool{false, true} {
			m := originOrderChecker(t, OriginDomain{Min: 1024, Max: 2048, Modulus: 1}, RelativeSpan{-8, 8})
			left, right := originOrderValue(m, -8), originOrderValue(m, 8)
			before, predicates := m.bound.Flags, m.state.flags
			if cancel {
				ctx, stop := context.WithCancel(t.Context())
				stop()
				m.ctx = ctx
			} else {
				m.work = m.valueBuilder.limits.Work
			}
			var known bool
			var err error
			if numeric {
				_, known, err = m.originWordUpperBound(left, 8)
			} else {
				known, err = m.refineOriginCompare(left, right)
			}
			if known || err == nil || cancel && !errors.Is(err, context.Canceled) || m.bound.Flags != before || m.state.flags != predicates {
				t.Fatal("cancelled/exhausted inference", known, err)
			}
		}
	}
}

// Reuse the independent descriptor encoder and concrete evolving-state oracle.
// The new surface is affine operand history, not another instruction encoding.
func originOrderSequence(t testing.TB, a, b int64, choice, mode uint8, seed uint64) {
	t.Helper()
	intents := []to.Intent{
		{Operation: to.LEA, Dst: 0, Base: 4, SignedDisp: a},
		{Operation: to.LEA, Dst: 2, Base: 4, SignedDisp: b},
		{Operation: to.Store, Base: 4, Src: 0, SignedDisp: -16},
		{Operation: to.Load, Base: 4, Dst: 1, SignedDisp: -16},
		{Operation: to.Compare, Dst: 1, Src: 2},
		{Operation: to.CompareMemory, Base: 4, SignedDisp: -16, Src: 2},
		{Operation: to.CompareFromMemory, Base: 4, SignedDisp: -16, Dst: 2},
	}
	switch mode % 7 {
	case 1: // A changed lane must invalidate the full pointer word.
		intents = append(intents[:4], append([]to.Intent{{Operation: to.StoreImmediate, Base: 4, SignedDisp: -15, Width: 8, Immediate: 0}}, intents[4:]...)...)
	case 2: // Correct bytes at the wrong lane positions are not a pointer word.
		intents[3].SignedDisp = -15
		intents[5].SignedDisp, intents[6].SignedDisp = -15, -15
	case 3:
		intents[4].Width, intents[5].Width, intents[6].Width = 32, 32, 32
	case 4:
		intents[4] = to.Intent{Operation: to.Test, Dst: 1, Src: 2, Width: 8}
	case 5:
		intents[4].Width, intents[5].Width, intents[6].Width = 32, 8, 8
	case 6:
		intents[4] = to.Intent{Operation: to.Test, Dst: 1, Src: 2}
	}
	ds := make([]to.Descriptor, len(intents))
	for j, i := range intents {
		e := stateEncoding(i, choice+uint8(j))
		if i.Operation == to.CompareMemory || i.Operation == to.CompareFromMemory {
			e = to.Encoding{Form: to.CMP39, REX: 0x48, SIB: true, DispBytes: 1}
			if i.Operation == to.CompareFromMemory {
				e.Form = to.CMP3B
			}
			if i.Width == 32 {
				e.REX = 0
			} else if i.Width == 8 {
				e.REX = 0
				if i.Operation == to.CompareMemory {
					e.Form = to.CMP38
				} else {
					e.Form = to.CMP3A
				}
			}
		} else if i.Operation == to.Test && i.Width == 8 {
			e.Form = to.TEST84
		}
		ds[j] = to.Descriptor{Intent: i, Encoding: e}
	}
	x, face := atomicLayout(t, ds)
	face.Origin.Modulus, face.Origin.Residue = 8, seed%8
	atomicStateCuts(t, x, face, stateInitial(face, seed))
}

func TestTransitionOriginOrderMemoryRoundTrip(t *testing.T) {
	for _, pair := range [][2]int64{{-65584, -120}, {-8, 8}, {8, -8}, {0, 0}} {
		for mode := uint8(0); mode < 7; mode++ {
			originOrderSequence(t, pair[0], pair[1], mode, mode, uint64(mode)*39)
		}
	}
}

func TestTransitionOriginOrderActualCompareBranch(t *testing.T) {
	for _, memory := range []bool{false, true} {
		for _, guard := range []int32{-65584, -120, 8} {
			// LEA -120(SP),AX; LEA guard(SP),CX; optional full-word store;
			// CMP AX,CX/(SP); JBE bad; cut:NOP; bad:UD2.
			code := hexBytes(t, "488d442488488d8c2400000000")
			binary.LittleEndian.PutUint32(code[9:], uint32(guard))
			if memory {
				code = append(code, hexBytes(t, "48890c24")...)
			}
			cmpPC := testEntry + uint64(len(code))
			if memory {
				code = append(code, hexBytes(t, "483b0424")...)
			} else {
				code = append(code, hexBytes(t, "4839c8")...)
			}
			code = append(code, 0x76, 1, 0x90, 0x0f, 0x0b)
			cut := testEntry + uint64(len(code)-3)
			im, face := image(t, code), stateFace(16, 8)
			options := TransitionOptions{}
			if memory {
				options.Expansions = []TransitionExpansion{{PC: cmpPC}}
			}
			proposal, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{}, options)
			if err != nil {
				t.Fatal(err)
			}
			c, err := CheckTransition(t.Context(), im, face, proposal, TransitionLimits{})
			if guard >= -120 {
				transitionRefused(t, c, err)
				continue
			}
			if err != nil {
				t.Fatal("same-origin CMP/JBE failed to exclude slow arm", memory, err)
			}
			b := c.checked.bound
			if len(b.ExcludedBoundaries) != 1 || b.ExcludedBoundaries[0].PC != cut+1 || !literalBool(b.EntryPredicate, 1) || !literalBool(b.Flags.CF.Value, 0) || !literalBool(b.Flags.ZF.Value, 0) {
				t.Fatal("missing domain-derived branch exclusion or fabricated entry premise")
			}
			for _, p := range c.checked.flags {
				if !literalBool(p, 0) {
					t.Fatal("private predicate did not receive origin refinement")
				}
			}
			if memory && (len(b.Accesses) != 2 || b.Accesses[0].Kind != FrameWrite || b.Accesses[1].Kind != FrameRead || b.Accesses[1].PC != cmpPC) || !memory && len(b.Accesses) != 0 {
				t.Fatal("actual memory history differs", b.Accesses)
			}
			prefix, err := ProposeTransition(t.Context(), im, cmpPC, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			root, err := CheckTransition(t.Context(), im, face, prefix, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			continued, err := CheckTransitionContinuation(t.Context(), root, proposal)
			if err != nil {
				t.Fatal(err)
			}
			stateInheritedInputs(t, root.checked.bound, continued.checked.bound)
			assertTransitionAlpha(t, c, continued)
		}
	}
}

func FuzzTransitionOriginOrderSequence(f *testing.F) {
	f.Add(int32(-65584), int32(-120), uint8(0), uint8(0), uint64(8))
	f.Add(int32(0), int32(0), uint8(1), uint8(2), uint64(7))
	f.Add(int32(-1), int32(1), uint8(3), uint8(1), uint64(17))
	f.Fuzz(func(t *testing.T, a, b int32, choice, mode uint8, seed uint64) {
		originOrderSequence(t, int64(a), int64(b), choice, mode, seed)
	})
}

func TestTransitionOriginOrderMemoryReadAndFlags(t *testing.T) {
	// Exercise the memory path directly with a checked current pointer word;
	// the comparison must preserve memory while adding exactly its actual read.
	m := originOrderChecker(t, OriginDomain{Min: 1 << 32, Max: 1 << 44, Modulus: 16}, RelativeSpan{-70000, 64})
	m.memory = make(map[TransitionLocation]TransitionByte)
	m.face.Regions = []RelativeRegion{{Bytes: RelativeSpan{0, 8}, Readable: true, Writable: true}}
	m.state.regs[RSP], m.pointers[RSP] = m.bound.Origin, OriginPointer{Origin: m.bound.Origin}
	guard := originOrderValue(m, -65584)
	m.store(TransitionLocation{}, guard, 8)
	m.state.regs[RAX], m.pointers[RAX] = m.bound.Origin, OriginPointer{Origin: m.bound.Origin}
	before := make(map[TransitionLocation]TransitionByte)
	for key, value := range m.memory {
		before[key] = value
	}
	accesses := len(m.bound.Accesses)
	if err := m.compareOrTest(operation{Op: x86asm.CMP, Args: [2]x86asm.Arg{x86asm.RAX, x86asm.Mem{Base: x86asm.RSP}}, MemBytes: 8}, 4); err != nil {
		t.Fatal(err)
	}
	if len(m.bound.Accesses) != accesses+1 || m.bound.Accesses[accesses].Kind != FrameRead || !reflect.DeepEqual(before, m.memory) || m.state.flags != ([flagCount]br.Term{m.falsity, m.falsity, m.falsity}) || m.bound.EntryPredicate != m.truth {
		t.Fatal("memory CMP erased read, changed memory or lost domain order")
	}
	word := m.memoryValue(TransitionLocation{}, 8)
	if holds, known, err := m.originWordUpperBound(word, -120); err != nil || !known || !holds {
		t.Fatal("actual stored guard lost applicability", holds, known, err)
	}
}
