package closure

import (
	"fmt"
	"go/constant"
	"go/types"
	"slices"
	"strings"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

func assemblyNarrowFrame(t testing.TB, target types.Type, scalars []types.Type, result types.Type) assemblyReferenceFrame {
	t.Helper()
	params := []*types.Var{types.NewVar(0, nil, "ptr", types.NewPointer(target))}
	for i, scalar := range scalars {
		params = append(params, types.NewVar(0, nil, fmt.Sprintf("arg%d", i), scalar))
	}
	results := types.NewTuple()
	if result != nil {
		results = types.NewTuple(types.NewVar(0, nil, "", result))
	}
	frame, err := assemblyReferenceABI(types.NewSignatureType(nil, nil, nil, types.NewTuple(params...), results, false), types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

const assemblyNarrowCASBody = `TEXT ·RenamedCompare(SB),4,$0-17
MOVQ ptr+0(FP), BX
MOVL old+8(FP), AX
MOVL replacement+12(FP), CX
LOCK
CMPXCHGL CX, (BX)
SETEQ ret+16(FP)
RET
`

func TestAssemblyNarrowReferenceTypedCAS(t *testing.T) {
	frame := assemblyNarrowFrame(t, types.Typ[types.Uint32], []types.Type{types.Typ[types.Uint32], types.Typ[types.Uint32]}, types.Typ[types.Bool])
	if frame.targetWidth != 4 || frame.targetAlignment != 4 || frame.size != 25 || frame.result != (assemblyReferenceSlot{24, 1}) || !slices.Equal(frame.arguments, []assemblyReferenceSlot{{8, 8}, {16, 4}, {20, 4}}) {
		t.Fatalf("wrong selected layout: %+v", frame)
	}
	relation := assemblyWordRelation(t, assemblyNarrowCASBody, frame)
	for _, input := range relation.inputs {
		if input.Sort() != br.Bits(32) {
			t.Fatal("narrow formal widened")
		}
	}
	for _, values := range [][3]uint64{{0, 0, 0}, {0, 1, 9}, {0xffffffff, 0xffffffff, 0x80000000}, {0x80000000, 0, 0xffffffff}, {7, 7, 0xffffffff}} {
		current, compare, replacement := values[0], values[1], values[2]
		want := current
		if current == compare {
			want = replacement
		}
		got := assemblyReferenceUnitApply(t, relation, current, compare, replacement)
		if got.Value != want || assemblyReferenceBool(t, got.Result) != (current == compare) || !slices.Equal(got.Accesses, []assemblyReferenceAccess{{false, true, current, 4}, {true, true, want, 4}}) || !slices.Equal(got.Atomics, []assemblyReferenceAtomic{{Statement: 4, Kind: x86asm.CMPXCHG, ReadAccess: 0, WriteAccess: 1, Width: 4}}) {
			t.Fatalf("%x: wrong CAS projection %+v", values, got)
		}
	}
	for i := range 3 {
		values := []uint64{0, 0, 0}
		values[i] = 1 << 32
		if _, err := assemblyReferenceApply(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, relation, values); err == nil {
			t.Fatalf("out-of-width formal %d admitted", i)
		}
	}
}

func TestAssemblyNarrowReferenceFullCASAccumulator(t *testing.T) {
	frame := assemblyNarrowFrame(t, types.Typ[types.Uint32], []types.Type{types.Typ[types.Uint64], types.Typ[types.Uint32]}, types.Typ[types.Uint64])
	body := `TEXT ·Accumulator(SB),4,$0-32
MOVQ ptr+0(FP), BX
MOVQ old+8(FP), AX
MOVL replacement+16(FP), CX
LOCK
CMPXCHGL CX, (BX)
MOVQ AX, ret+24(FP)
RET
`
	relation := assemblyWordRelation(t, body, frame)
	for _, current := range []uint64{0x80000001, 0x80000002} {
		accumulator := uint64(0xdeadbeef80000001)
		got := assemblyReferenceUnitApply(t, relation, current, accumulator, 7)
		want := accumulator
		wantMemory := uint64(7)
		if uint32(accumulator) != uint32(current) {
			want, wantMemory = current, current
		}
		bits, ok := constant.Uint64Val(got.Result.scalar)
		if !ok || bits != want || got.Value != wantMemory {
			t.Fatalf("current %#x: accumulator/result %+v, want %#x/%#x", current, got, want, wantMemory)
		}
	}
}

func TestAssemblyNarrowReferenceByteLogical(t *testing.T) {
	frame := assemblyNarrowFrame(t, types.Typ[types.Uint8], []types.Type{types.Typ[types.Uint8]}, nil)
	if frame.targetWidth != 1 || frame.targetAlignment != 1 || frame.size != 17 || frame.result != (assemblyReferenceSlot{17, 0}) || !slices.Equal(frame.arguments, []assemblyReferenceSlot{{8, 8}, {16, 1}}) {
		t.Fatalf("void argument extent rounded: %+v", frame)
	}
	// Every current byte, with independent masks exercising every bit, sign bit,
	// unchanged result and zero result. This bounded table is not an exhaustive
	// claim over the 65,536 input pairs; the independent grammar also varies bodies.
	for _, op := range []string{"ORB", "ANDB"} {
		for _, locked := range []bool{false, true} {
			prefix := ""
			if locked {
				prefix = "LOCK\n"
			}
			body := "TEXT ·RenamedByte(SB),4,$0-9\nMOVQ ptr+0(FP), AX\nMOVB mask+8(FP), BX\n" + prefix + op + " BX, (AX)\nRET\n"
			relation := assemblyWordRelation(t, body, frame)
			for current := uint64(0); current < 256; current++ {
				for _, mask := range []uint64{0, 1, 2, 4, 8, 16, 32, 64, 128, 0x55, 0xaa, 0xff} {
					want, kind := current|mask, x86asm.OR
					if op == "ANDB" {
						want, kind = current&mask, x86asm.AND
					}
					got := assemblyReferenceUnitApply(t, relation, current, mask)
					if got.Value != want || !slices.Equal(got.Accesses, []assemblyReferenceAccess{{false, locked, current, 1}, {true, locked, want, 1}}) || got.Result.kind != regionAggregate || got.Result.scalar != nil {
						t.Fatalf("%s lock=%v (%x,%x): %+v", op, locked, current, mask, got)
					}
					var atomics []assemblyReferenceAtomic
					if locked {
						atomics = []assemblyReferenceAtomic{{Statement: 3, Kind: kind, ReadAccess: 0, WriteAccess: 1, Width: 1}}
					}
					if !slices.Equal(got.Atomics, atomics) {
						t.Fatalf("wrong lock/group: %+v", got.Atomics)
					}
				}
			}
		}
	}
}

func TestAssemblyNarrowReferenceScalarResultViews(t *testing.T) {
	for _, kind := range []types.BasicKind{types.Int8, types.Uint8, types.Int32, types.Uint32, types.Int64, types.Uint64} {
		named := types.NewNamed(types.NewTypeName(0, nil, "Selected", nil), types.Typ[kind], nil)
		alias := types.NewAlias(types.NewTypeName(0, nil, "View", nil), named)
		frame := assemblyNarrowFrame(t, alias, nil, alias)
		opcode := map[int]string{1: "MOVB", 4: "MOVL", 8: "MOVQ"}[frame.targetWidth]
		body := fmt.Sprintf("TEXT ·ReadView(SB),4,$0-%d\nMOVQ ptr+0(FP), BX\n%s (BX), AX\n%s AX, ret+8(FP)\nRET\n", frame.size-8, opcode, opcode)
		relation := assemblyWordRelation(t, body, frame)
		bits := ^uint64(0) >> (64 - frame.targetWidth*8)
		got := assemblyReferenceUnitApply(t, relation, bits)
		if !types.Identical(frame.targetType, alias) || !types.Identical(got.Result.typ, alias) || got.Result.scalar.Kind() != constant.Int || relation.booleanProof.Valid() {
			t.Fatalf("lost scalar view or interpreted integer as bool: %+v", got)
		}
		if types.Typ[kind].Info()&types.IsUnsigned == 0 {
			value, ok := constant.Int64Val(got.Result.scalar)
			if !ok || value != -1 {
				t.Fatalf("signed width %d decoded as %v", frame.targetWidth, got.Result.scalar)
			}
		} else if value, ok := constant.Uint64Val(got.Result.scalar); !ok || value != bits {
			t.Fatalf("unsigned width %d decoded as %v", frame.targetWidth, got.Result.scalar)
		}
	}
}

func TestAssemblyNarrowReferenceExactExtentAndScratchRefusals(t *testing.T) {
	byteFrame := assemblyNarrowFrame(t, types.Typ[types.Uint8], []types.Type{types.Typ[types.Uint8]}, nil)
	byteBody := "TEXT ·Byte(SB),4,$0-9\nMOVQ ptr+0(FP), AX\nMOVB mask+8(FP), BX\nLOCK\nORB BX, (AX)\nRET\n"
	casFrame := assemblyNarrowFrame(t, types.Typ[types.Uint32], []types.Type{types.Typ[types.Uint32], types.Typ[types.Uint32]}, types.Typ[types.Bool])
	for _, tc := range []struct {
		name, body string
		frame      assemblyReferenceFrame
	}{
		{"rounded-void-TEXT", strings.Replace(byteBody, "$0-9", "$0-16", 1), byteFrame},
		{"void-padding-read", strings.Replace(byteBody, "RET", "MOVB padding+9(FP), CX\nRET", 1), byteFrame},
		{"void-result-write", strings.Replace(byteBody, "RET", "MOVB BX, ret+9(FP)\nRET", 1), byteFrame},
		{"wide-target", strings.Replace(byteBody, "ORB", "CMPXCHGL", 1), byteFrame},
		{"high-alias-scratch", strings.Replace(byteBody, "ORB BX", "ORB BH", 1), byteFrame},
		{"return-escape", strings.Replace(byteBody, "MOVB mask+8(FP), BX", "MOVB 0(SP), BX", 1), byteFrame},
		{"frame-register-write", strings.Replace(byteBody, "MOVB mask+8(FP), BX", "MOVB mask+8(FP), BP", 1), byteFrame},
		{"cas-result-missing", strings.Replace(assemblyNarrowCASBody, "SETEQ ret+16(FP)\n", "", 1), casFrame},
		{"cas-result-argument-slot", strings.Replace(assemblyNarrowCASBody, "ret+16(FP)", "ret+12(FP)", 1), casFrame},
		{"cas-overwide-access", strings.Replace(assemblyNarrowCASBody, "CMPXCHGL", "CMPXCHGQ", 1), casFrame},
		{"cas-unlocked", strings.Replace(assemblyNarrowCASBody, "LOCK\n", "", 1), casFrame},
	} {
		t.Run(tc.name, func(t *testing.T) {
			definitions, err := assemblyReferenceUnitParse(t, tc.body)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], tc.frame); err == nil {
				t.Fatal("invalid body admitted")
			}
		})
	}
}

func TestAssemblyNarrowReferencePaddingAndResultInterpretation(t *testing.T) {
	frame := assemblyNarrowFrame(t, types.Typ[types.Uint8], []types.Type{types.Typ[types.Uint8]}, types.Typ[types.Uint8])
	// The seven bytes preceding the result are owned but arbitrary. A discarded
	// read is permitted; using any of those bits as the result is not justified.
	body := "TEXT ·Padding(SB),4,$0-17\nMOVB padding+9(FP), CX\nMOVB mask+8(FP), AX\nMOVB AX, ret+16(FP)\nRET\n"
	relation := assemblyWordRelation(t, body, frame)
	got := assemblyReferenceUnitApply(t, relation, 0x81, 0xfe)
	value, ok := constant.Uint64Val(got.Result.scalar)
	if !ok || value != 0xfe || got.Value != 0x81 || len(got.Accesses) != 0 || len(relation.accesses) != 4 {
		t.Fatalf("private padding changed scalar meaning or disappeared from the full trace: %+v", got)
	}
	for _, body := range []string{
		strings.Replace(body, "MOVB AX, ret", "MOVB CX, ret", 1),
		strings.Replace(body, "padding+9(FP)", "padding+17(FP)", 1),
		strings.Replace(body, "MOVB mask+8(FP), AX", "MOVB 0(SP), AX", 1),
	} {
		definitions, err := assemblyReferenceUnitParse(t, body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], frame); err == nil {
			t.Fatal("arbitrary or out-of-frame byte acquired scalar meaning")
		}
	}
	// The identical stored representation is an integer two, but cannot be a
	// canonical Boolean. Width alone cannot choose the result interpretation.
	constantBody := "TEXT ·Result(SB),4,$0-9\nMOVB $2, ret+8(FP)\nRET\n"
	for _, kind := range []types.BasicKind{types.Uint8, types.Int8, types.Bool} {
		selected := types.NewNamed(types.NewTypeName(0, nil, "ResultView", nil), types.Typ[kind], nil)
		frame := assemblyNarrowFrame(t, types.Typ[types.Uint8], nil, selected)
		definitions, err := assemblyReferenceUnitParse(t, constantBody)
		if err != nil {
			t.Fatal(err)
		}
		relation, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], frame)
		if kind == types.Bool {
			if err == nil || relation != nil {
				t.Fatal("noncanonical named Boolean admitted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		got := assemblyReferenceUnitApply(t, relation, 7)
		value, ok := constant.Int64Val(got.Result.scalar)
		if !ok || value != 2 || !types.Identical(got.Result.typ, selected) {
			t.Fatalf("one-byte integer acquired Boolean semantics: %+v", got)
		}
	}
}

func TestAssemblyNarrowReferenceReadableWrongSlotsAndByteLanes(t *testing.T) {
	frame := assemblyNarrowFrame(t, types.Typ[types.Uint32], []types.Type{types.Typ[types.Uint32], types.Typ[types.Uint32]}, types.Typ[types.Bool])
	for _, tc := range []struct {
		old, replacement string
		memory           uint64
		success          bool
	}{
		{"old+8(FP)", "old+12(FP)", 5, false},
		{"replacement+12(FP)", "replacement+8(FP)", 5, true},
	} {
		relation := assemblyWordRelation(t, strings.Replace(assemblyNarrowCASBody, tc.old, tc.replacement, 1), frame)
		got := assemblyReferenceUnitApply(t, relation, 5, 5, 9)
		if got.Value != tc.memory || assemblyReferenceBool(t, got.Result) != tc.success || len(got.Accesses) != 2 || got.Accesses[1].Value != tc.memory {
			t.Fatalf("readable wrong slot did not derive its changed meaning: %+v", got)
		}
	}
	byteFrame := assemblyNarrowFrame(t, types.Typ[types.Uint8], []types.Type{types.Typ[types.Uint8]}, nil)
	for _, lane := range []string{"AL", "AH"} {
		body := "TEXT ·Lanes(SB),4,$0-9\nMOVQ ptr+0(FP), SI\nMOVQ $0x112233445566aa55, AX\nMOVB mask+8(FP), AH\nLOCK\nORB " + lane + ", (SI)\nRET\n"
		relation := assemblyWordRelation(t, body, byteFrame)
		for _, mask := range []uint64{0, 0x80, 0xff} {
			got := assemblyReferenceUnitApply(t, relation, 2, mask)
			want := uint64(0x57)
			if lane == "AH" {
				want = 2 | mask
			}
			if got.Value != want || len(got.Accesses) != 2 || got.Accesses[1].Value != want {
				t.Fatalf("%s mask %#x: wrong byte lane %+v", lane, mask, got)
			}
		}
	}
}

func TestAssemblyNarrowReferenceLogicalFlagsAndOccurrenceOrder(t *testing.T) {
	frame := assemblyNarrowFrame(t, types.Typ[types.Uint8], []types.Type{types.Typ[types.Uint8]}, types.Typ[types.Bool])
	for _, op := range []string{"ORB", "ANDB"} {
		for _, condition := range []string{"SETEQ", "SETNE", "SETCS", "SETCC", "SETLT", "SETGE", "SETLE", "SETGT"} {
			body := "TEXT ·Flags(SB),4,$0-17\nMOVQ ptr+0(FP), SI\nMOVB mask+8(FP), AX\nLOCK\n" + op + " AX, (SI)\n" + condition + " ret+16(FP)\nRET\n"
			relation := assemblyWordRelation(t, body, frame)
			if relation.flags.AF.Defined || relation.flags.AF.Preserved {
				t.Fatal("logical operation invented AF authority")
			}
			for _, pair := range [][2]uint64{{0, 0}, {0xff, 0}, {0x80, 0x80}, {0x7f, 1}, {0xff, 0x80}} {
				value := pair[0] | pair[1]
				if op == "ANDB" {
					value = pair[0] & pair[1]
				}
				want := map[string]bool{"SETEQ": value == 0, "SETNE": value != 0, "SETCS": false, "SETCC": true, "SETLT": value&0x80 != 0, "SETGE": value&0x80 == 0, "SETLE": value&0x80 != 0 || value == 0, "SETGT": value&0x80 == 0 && value != 0}[condition]
				got := assemblyReferenceUnitApply(t, relation, pair[0], pair[1])
				if got.Value != value || assemblyReferenceBool(t, got.Result) != want {
					t.Fatalf("%s %s %x: wrong consumed flags %+v", op, condition, pair, got)
				}
			}
		}
	}
	frame = assemblyNarrowFrame(t, types.Typ[types.Uint8], []types.Type{types.Typ[types.Uint8]}, nil)
	body := "TEXT ·Ordered(SB),4,$0-9\nMOVQ ptr+0(FP), SI\nMOVB mask+8(FP), AX\nLOCK\nORB AX, (SI)\nLOCK\nANDB AX, (SI)\nRET\n"
	relation := assemblyWordRelation(t, body, frame)
	got := assemblyReferenceUnitApply(t, relation, 0x80, 0x81)
	if got.Value != 0x81 || !slices.Equal(got.Accesses, []assemblyReferenceAccess{{false, true, 0x80, 1}, {true, true, 0x81, 1}, {false, true, 0x81, 1}, {true, true, 0x81, 1}}) || !slices.Equal(got.Atomics, []assemblyReferenceAtomic{{Statement: 3, Kind: x86asm.OR, ReadAccess: 0, WriteAccess: 1, Width: 1}, {Statement: 5, Kind: x86asm.AND, ReadAccess: 2, WriteAccess: 3, Width: 1}}) {
		t.Fatalf("ordered groups collapsed or lost unchanged write: %+v", got)
	}
	for _, body := range []string{
		strings.Replace(body, "LOCK\nORB", "LOCK\nMOVB AX, CX\nORB", 1),
		strings.Replace(body, "LOCK\nORB", "LOCK\nLOCK\nORB", 1),
		strings.Replace(body, "RET", "LOCK\nRET", 1),
	} {
		definitions, err := assemblyReferenceUnitParse(t, body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], frame); err == nil {
			t.Fatal("split, repeated or unmatched lock prefix admitted")
		}
	}
}

func TestAssemblyNarrowReferenceUnsupportedTypedInterfaces(t *testing.T) {
	for _, unsupported := range []types.Type{types.Typ[types.Int16], types.Typ[types.Uint16], types.Typ[types.Int], types.Typ[types.Uintptr], types.Typ[types.Float32], types.Typ[types.Bool], types.NewArray(types.Typ[types.Uint8], 1)} {
		for _, position := range []string{"target", "parameter", "result"} {
			if position == "result" && types.Identical(unsupported, types.Typ[types.Bool]) {
				continue
			}
			target, parameter, result := types.Type(types.Typ[types.Uint8]), types.Type(types.Typ[types.Uint8]), types.Type(types.Typ[types.Uint8])
			switch position {
			case "target":
				target = unsupported
			case "parameter":
				parameter = unsupported
			case "result":
				result = unsupported
			}
			sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(0, nil, "ptr", types.NewPointer(target)), types.NewVar(0, nil, "arg", parameter)), types.NewTuple(types.NewVar(0, nil, "", result)), false)
			if _, err := assemblyReferenceABI(sig, types.SizesFor("gc", "amd64")); err == nil {
				t.Fatalf("unsupported %s type %s admitted", position, unsupported)
			}
		}
	}
}
