package closure

import (
	"fmt"
	"go/constant"
	"go/types"
	"slices"
	"strings"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

// This fixture proves a conditional source-instruction/frame relation. It does
// not manufacture selected-action authority: the joint fixture separately uses
// assemblyReferenceSelectedSource and assemblyReferenceSelectedPacket.
func assemblyPropertyTypedRelation(t testing.TB, p assemblyReferencePropertyProgram) *assemblyReferenceRelation {
	t.Helper()
	frame, err := assemblyReferenceABI(p.signature(), types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := assemblyReferenceUnitParse(t, p.body)
	if err != nil || len(definitions) != 1 {
		t.Fatalf("parse generated body: %v", err)
	}
	r, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], frame)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func assemblyNarrowPropertyResult(t testing.TB, p assemblyReferencePropertyProgram, r *assemblyReferenceRelation, current, comparison, replacement uint64) {
	t.Helper()
	args := []uint64{comparison}
	if p.op == x86asm.CMPXCHG {
		args = append(args, replacement)
	}
	got := assemblyReferenceUnitApply(t, r, current, args...)
	want := p.oracle(current, comparison, replacement)
	if got.Value != want.Value || !slices.Equal(got.Accesses, want.Accesses) {
		t.Fatalf("width %d %s (%x,%x,%x): relation %+v; independent oracle %+v", p.width, p.op, current, comparison, replacement, got, want)
	}
	if p.op != x86asm.CMPXCHG {
		if got.Result.kind != regionAggregate || len(got.Result.elements) != 0 || got.Result.scalar != nil {
			t.Fatal("void result acquired a scalar")
		}
	} else if p.integerResult {
		value, ok := constant.Uint64Val(got.Result.scalar)
		bit := uint64(0)
		if want.Result {
			bit = 1
		}
		if !types.Identical(got.Result.typ, types.Typ[types.Uint8]) || !ok || value != bit {
			t.Fatalf("integer result decoded as bool or wrong bit: %+v", got.Result)
		}
	} else if assemblyReferenceBool(t, got.Result) != want.Result {
		t.Fatal("predicate disagrees")
	}
	statement := 3
	if p.op == x86asm.CMPXCHG {
		statement = 4
	}
	wantAtomic := []assemblyReferenceAtomic{{Statement: statement, Kind: p.op, ReadAccess: 0, WriteAccess: 1, Width: p.width}}
	if !slices.Equal(got.Atomics, wantAtomic) {
		t.Fatalf("indivisible occurrence = %+v, want %+v", got.Atomics, wantAtomic)
	}
}

func assemblyNarrowPropertyFrame(t testing.TB, p assemblyReferencePropertyProgram, r *assemblyReferenceRelation, scratch uint64) {
	t.Helper()
	// These ABI coordinates are independent of the production descriptor:
	// pointer occupies bytes 8..15; CAS32 arguments 16..19 and 20..23, result
	// byte 24; byte mask occupies byte16 and void ends immediately at17.
	arguments, result, size := []assemblyReferenceSlot{{8, 8}, {16, 1}}, assemblyReferenceSlot{17, 0}, 17
	if p.width == 4 {
		arguments, result, size = []assemblyReferenceSlot{{8, 8}, {16, 4}, {20, 4}}, assemblyReferenceSlot{24, 1}, 25
	}
	if !slices.Equal(r.frame.arguments, arguments) || r.frame.result != result || r.frame.size != size || r.frame.targetWidth != p.width || r.frame.targetAlignment != p.width {
		t.Fatalf("selected ABI: %+v", r.frame)
	}
	for _, input := range r.inputs {
		if input.Sort() != br.Bits(p.width*8) {
			t.Fatal("formal width changed")
		}
	}
	want := []assemblyReferenceSymbolicAccess{{space: r.frame.frameSpace, offset: 8, width: 8}, {space: r.frame.frameSpace, offset: 16, width: p.width}}
	if p.width == 4 {
		want = append(want, assemblyReferenceSymbolicAccess{space: r.frame.frameSpace, offset: 20, width: 4})
		if p.swapped {
			want[1].offset, want[2].offset = 20, 16
		}
	}
	readIndex := len(want)
	want = append(want, assemblyReferenceSymbolicAccess{space: r.frame.targetSpace, width: p.width, locked: true}, assemblyReferenceSymbolicAccess{space: r.frame.targetSpace, width: p.width, write: true, locked: true})
	if p.width == 4 {
		want = append(want, assemblyReferenceSymbolicAccess{space: r.frame.frameSpace, offset: 24, width: 1, write: true})
	}
	if p.extra {
		want = append(want, assemblyReferenceSymbolicAccess{space: r.frame.targetSpace, width: p.width, write: true})
	}
	want = append(want, assemblyReferenceSymbolicAccess{space: r.frame.frameSpace, width: 8, returning: true})
	if len(r.accesses) != len(want) {
		t.Fatalf("private/external access count %d, want %d", len(r.accesses), len(want))
	}
	for i, w := range want {
		g := r.accesses[i]
		if g.space != w.space || g.offset != w.offset || g.width != w.width || g.write != w.write || g.locked != w.locked || g.returning != w.returning || !g.value.Valid() || i > 0 && g.statement < r.accesses[i-1].statement {
			t.Fatalf("access %d: %+v, want %+v", i, g, w)
		}
	}
	if r.accesses[readIndex].statement != r.accesses[readIndex+1].statement {
		t.Fatal("split source atomic group")
	}
	if r.booleanProof.Valid() != (p.width == 4 && !p.integerResult) {
		t.Fatal("Boolean proof does not match typed result")
	}
	if r.booleanProof.Valid() {
		b, _ := r.booleanProof.Roots()
		if b != r.private[24].value {
			t.Fatal("Boolean proof misses complete result byte")
		}
	}
	if !r.returnProof.Valid() {
		t.Fatal("missing return derivation")
	}
	returned, original := r.returnProof.Roots()
	if returned != r.returnWord || original.View().Op != br.Variable || !original.View().Scratch {
		t.Fatal("lost arbitrary protected continuation")
	}
	for i := range 8 {
		v := r.private[i].value.View()
		if v.Op != br.Extract || v.Immediate != uint64(i*8) || len(v.Args) != 1 || v.Args[0] != original {
			t.Fatal("return word changed")
		}
	}
	sp := scratch & ((1 << 46) - 8)
	resumed, err := br.Eval(t.Context(), r.returnedSP, []br.Assignment{{Variable: r.registers[nativeproof.RSP].value, Value: sp}}, br.Limits{})
	if err != nil || resumed != sp+8 {
		t.Fatalf("return increment: %x %v", resumed, err)
	}
}

func assemblyNarrowPropertyCase(t testing.TB, p assemblyReferencePropertyProgram, current, old, replacement uint64, fault uint8) {
	t.Helper()
	mask := uint64(1)<<(p.width*8) - 1
	current, old, replacement = current&mask, old&mask, replacement&mask
	r := assemblyPropertyTypedRelation(t, p)
	comparison := old
	if p.swapped && p.width == 4 {
		comparison = replacement
	}
	for _, value := range []uint64{current, comparison, comparison ^ 1, mask, 1 << (p.width*8 - 1)} {
		assemblyNarrowPropertyResult(t, p, r, value, old, replacement)
	}
	assemblyNarrowPropertyFrame(t, p, r, current)
	bad := p.body
	// Faults reaching interpretation must fail at the relevant body/frame rule,
	// not an unrelated parse or selected-provider failure.
	wantError := ""
	switch fault % 6 {
	case 0:
		bad = strings.Replace(bad, "RET\n", "MOVQ $0, 0(SP)\nRET\n", 1)
		wantError = "permission"
	case 1:
		bad = strings.Replace(bad, "RET\n", fmt.Sprintf("MOVB %d(SP), CX\nRET\n", r.frame.size), 1)
		wantError = "owned extent"
	case 2:
		bad = strings.Replace(bad, "RET\n", "", 1)
		wantError = "return"
	case 3:
		if p.width == 4 {
			bad = strings.Replace(bad, "CMPXCHGL", "CMPXCHGQ", 1)
		} else {
			bad = strings.Replace(bad, "MOVB mask+8(FP)", "MOVL mask+8(FP)", 1)
		}
		wantError = "owned extent"
	case 4:
		if p.width == 4 {
			bad = strings.ReplaceAll(bad, "result+16(FP)", "result+17(FP)")
		} else {
			bad = strings.Replace(bad, "RET\n", "MOVB $0, padding+9(FP)\nRET\n", 1)
		}
		wantError = "owned extent"
	case 5:
		if p.width == 4 {
			bad = strings.Replace(bad, "LOCK\n", "", 1)
			wantError = "LOCK"
		} else {
			// Removing LOCK from byte logical code is a valid ordinary relation,
			// not an invalid source body. Check the semantic discrepancy directly.
			bad = strings.Replace(bad, "LOCK\n", "", 1)
			q := p
			q.body = bad
			ordinary := assemblyPropertyTypedRelation(t, q)
			got := assemblyReferenceUnitApply(t, ordinary, current, old)
			if len(got.Atomics) != 0 || len(got.Accesses) < 2 || got.Accesses[0].Locked || got.Accesses[1].Locked {
				t.Fatal("missing LOCK retained atomic authority")
			}
			return
		}
	}
	definitions, err := assemblyReferenceUnitParse(t, bad)
	if err != nil || len(definitions) != 1 {
		t.Fatalf("fault must reach interpreter: %v", err)
	}
	invalid, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], r.frame)
	if err == nil || invalid != nil || wantError != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(wantError)) {
		t.Fatalf("fault %d wanted %q at body/frame, got %v", fault%6, wantError, err)
	}
}

// Exhaustive pairs are supplied by TestTransferKernelLogicalValuesAndFlags in
// nativeproof. This reference-layer complement checks every byte current against
// 16 independent masks on 64 register shapes (56 distinct encodable pairs: high
// aliases avoid REX), for each logical operation: 524,288 concrete evaluations,
// plus generated signed/extra-write
// variants in the fuzzer. The shared kernel is not used by this integer oracle.
func TestAssemblyReferenceNarrowGeneratedBodies(t *testing.T) {
	for op := uint16(1); op < 4; op++ {
		for shape := uint16(0); shape < 64; shape++ {
			p := assemblyReferencePropertyBody(op<<9|shape, 0x80)
			r := assemblyPropertyTypedRelation(t, p)
			assemblyNarrowPropertyFrame(t, p, r, uint64(shape)<<12)
			if p.width == 1 {
				for current := uint64(0); current < 256; current++ {
					for _, mask := range []uint64{0, 1, 2, 4, 8, 16, 32, 64, 128, 255, 0x55, 0xaa, 0x7f, 0xfe, 0xf0, 0x0f} {
						assemblyNarrowPropertyResult(t, p, r, current, mask, 0)
					}
				}
			} else {
				for _, old := range []uint64{0, 1, 0x7fffffff, 0x80000000, 0xffffffff} {
					for _, replacement := range []uint64{0, 0x80000001, 0xffffffff} {
						for _, current := range []uint64{old, old ^ 1, 0x80000000} {
							assemblyNarrowPropertyResult(t, p, r, current, old, replacement)
						}
					}
				}
			}
		}
	}
}

// The full-accumulator interface is generated from the existing CAS32 body,
// changing only its selected old/result declarations and their exact ABI slots.
// High RAX survives success but failure writes EAX and clears its upper half.
func FuzzAssemblyReferenceNarrowAccumulator(f *testing.F) {
	for _, incoming := range []uint64{0, 0xdeadbeef80000001, 0xffffffff00000000, 0xffffffffffffffff} {
		f.Add(incoming, uint32(0x80000000), uint32(0xffffffff), uint8(incoming))
	}
	f.Fuzz(func(t *testing.T, incoming uint64, current, replacement uint32, shape uint8) {
		p := assemblyReferencePropertyBody(512|uint16(shape&31), uint64(replacement))
		body := strings.NewReplacer("$0-17", "$0-32", "MOVL comparison+8(FP)", "MOVQ comparison+8(FP)", "replacement+12(FP)", "replacement+16(FP)", "SETEQ result+16(FP)", "MOVQ AX, result+24(FP)").Replace(p.body)
		sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(0, nil, "p", types.NewPointer(types.Typ[types.Uint32])), types.NewVar(0, nil, "a", types.Typ[types.Uint64]), types.NewVar(0, nil, "b", types.Typ[types.Uint32])), types.NewTuple(types.NewVar(0, nil, "", types.Typ[types.Uint64])), false)
		frame, err := assemblyReferenceABI(sig, types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		if frame.size != 40 || frame.result != (assemblyReferenceSlot{32, 8}) || !slices.Equal(frame.arguments, []assemblyReferenceSlot{{8, 8}, {16, 8}, {24, 4}}) {
			t.Fatal("full accumulator typed layout drift")
		}
		definitions, err := assemblyReferenceUnitParse(t, body)
		if err != nil || len(definitions) != 1 {
			t.Fatalf("generated accumulator syntax: %v", err)
		}
		r, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], frame)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []uint32{current, uint32(incoming), uint32(incoming) ^ 1} {
			got := assemblyReferenceUnitApply(t, r, uint64(value), incoming, uint64(replacement))
			wantAccumulator, wantMemory := incoming, uint64(replacement)
			if value != uint32(incoming) {
				wantAccumulator, wantMemory = uint64(value), uint64(value)
			}
			bits, ok := constant.Uint64Val(got.Result.scalar)
			if !ok || bits != wantAccumulator || got.Value != wantMemory || !slices.Equal(got.Accesses, []assemblyReferenceAccess{{false, true, uint64(value), 4}, {true, true, wantMemory, 4}}) {
				t.Fatalf("incoming=%x,current=%x: full accumulator/memory %x/%x, want %x/%x", incoming, value, bits, got.Value, wantAccumulator, wantMemory)
			}
		}
	})
}

func TestAssemblyReferenceNarrowSemanticAlternatives(t *testing.T) {
	for _, shape := range []uint16{512, 512 | 128, 512 | 2048, 512 | 4096, 1024, 1024 | 8, 1536 | 24, 1536 | 256} {
		p := assemblyReferencePropertyBody(shape, 0x80)
		for fault := uint8(0); fault < 6; fault++ {
			assemblyNarrowPropertyCase(t, p, 0x80, 0x80, 0xffffffff, fault)
		}
	}
	// Both layouts are permitted reads. A wrong scalar slot is a different
	// meaning, not an invalid frame: compare every chosen value to its own oracle.
	for _, shape := range []uint16{512, 512 | 64} {
		p := assemblyReferencePropertyBody(shape, 0)
		r := assemblyPropertyTypedRelation(t, p)
		assemblyNarrowPropertyResult(t, p, r, 0x80000000, 0x80000000, 0xffffffff)
		got := assemblyReferenceUnitApply(t, r, 0x80000000, 0x80000000, 0xffffffff)
		if assemblyReferenceBool(t, got.Result) == p.swapped {
			t.Fatal("wrong-but-readable slot did not change CAS result")
		}
	}
}
