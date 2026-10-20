package closure

import (
	"fmt"
	"go/constant"
	"go/types"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"golang.org/x/arch/x86/x86asm"
)

func assemblyWordFrame(t testing.TB, scalarTypes []types.Type, result types.Type) assemblyReferenceFrame {
	t.Helper()
	params := []*types.Var{types.NewVar(0, nil, "ptr", types.NewPointer(types.Typ[types.Uint64]))}
	for i, typ := range scalarTypes {
		params = append(params, types.NewVar(0, nil, fmt.Sprintf("value%d", i), typ))
	}
	results := types.NewTuple()
	if result != nil {
		results = types.NewTuple(types.NewVar(0, nil, "", result))
	}
	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(params...), results, false)
	frame, err := assemblyReferenceABI(sig, types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func assemblyWordRelation(t testing.TB, body string, frame assemblyReferenceFrame) *assemblyReferenceRelation {
	t.Helper()
	definitions, err := assemblyReferenceUnitParse(t, body)
	if err != nil || len(definitions) != 1 {
		t.Fatalf("definition: %v %v", definitions, err)
	}
	relation, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], frame)
	if err != nil {
		t.Fatal(err)
	}
	return relation
}

// Kinds select fixture syntax, not implementation summaries: every generated
// body is parsed and interpreted before its result is compared with integer code.
func assemblyWordBody(t testing.TB, kind, register uint8) (string, assemblyReferenceFrame) {
	t.Helper()
	ptr := []string{"BX", "DX", "SI", "DI", "R8", "R10", "R12", "R14"}[register%8]
	result := types.Type(types.Typ[types.Uint64])
	args := []types.Type{types.Typ[types.Uint64]}
	var body string
	switch kind {
	case 0:
		args = nil
		body = fmt.Sprintf("MOVQ ptr+0(FP), %s\nMOVQ 0(%s), AX\nMOVQ AX, ret+8(FP)\nRET\n", ptr, ptr)
	case 1:
		result = nil
		body = fmt.Sprintf("MOVQ ptr+0(FP), %s\nMOVQ value+8(FP), AX\nXCHGQ AX, 0(%s)\nRET\n", ptr, ptr)
	case 2:
		args[0] = types.Typ[types.Int64]
		body = fmt.Sprintf("MOVQ ptr+0(FP), %s\nMOVQ delta+8(FP), AX\nMOVQ AX, CX\nLOCK\nXADDQ AX, 0(%s)\nADDQ CX, AX\nMOVQ AX, ret+16(FP)\nRET\n", ptr, ptr)
	case 3, 4:
		if kind == 4 {
			result = types.Typ[types.Int64]
		}
		body = fmt.Sprintf("MOVQ ptr+0(FP), %s\nMOVQ value+8(FP), AX\nXCHGQ AX, 0(%s)\nMOVQ AX, ret+16(FP)\nRET\n", ptr, ptr)
	default:
		t.Fatal("unknown fixture kind")
	}
	frame := assemblyWordFrame(t, args, result)
	return fmt.Sprintf("TEXT ·Word(SB),4,$0-%d\n%s", frame.size-8, body), frame
}

func assertAssemblyWordResult(t testing.TB, result assemblyReferenceResult, kind uint8, current, argument uint64) {
	t.Helper()
	wantValue, wantResult := current, current
	accesses := []assemblyReferenceAccess{{false, false, current, 8}}
	if kind != 0 {
		wantValue = argument
		if kind == 2 {
			wantValue = current + argument
			wantResult = wantValue
		}
		accesses = []assemblyReferenceAccess{{false, true, current, 8}, {true, true, wantValue, 8}}
	}
	if result.Value != wantValue || !slices.Equal(result.Accesses, accesses) {
		t.Fatalf("kind %d: memory/effects %+v, want value %#x and %v", kind, result, wantValue, accesses)
	}
	if kind == 0 {
		if len(result.Atomics) != 0 {
			t.Fatal("ordinary load invented an atomic occurrence")
		}
	} else {
		want := x86asm.XCHG
		if kind == 2 {
			want = x86asm.XADD
		}
		if len(result.Atomics) != 1 || result.Atomics[0].Kind != want || result.Atomics[0].ReadAccess != 0 || result.Atomics[0].WriteAccess != 1 {
			t.Fatalf("word reference lost its RMW kind/group: %+v", result.Atomics)
		}
	}
	if kind == 1 {
		tuple, ok := result.Result.typ.(*types.Tuple)
		if !ok || tuple.Len() != 0 || result.Result.kind != regionAggregate || len(result.Result.elements) != 0 || result.Result.scalar != nil {
			t.Fatalf("void call invented a scalar result: %+v", result.Result)
		}
		return
	}
	if result.Result.kind != regionConstant || result.Result.scalar == nil || result.Result.scalar.Kind() != constant.Int {
		t.Fatalf("word call lost its typed scalar: %+v", result.Result)
	}
	if kind == 4 {
		value, ok := constant.Int64Val(result.Result.scalar)
		if !types.Identical(result.Result.typ, types.Typ[types.Int64]) || !ok || value != int64(wantResult) {
			t.Fatalf("signed result %+v, want %d", result.Result, int64(wantResult))
		}
	} else {
		value, ok := constant.Uint64Val(result.Result.scalar)
		if !types.Identical(result.Result.typ, types.Typ[types.Uint64]) || !ok || value != wantResult {
			t.Fatalf("unsigned result %+v, want %#x", result.Result, wantResult)
		}
	}
}

func TestAssemblyReferenceWordAndVoidInterfaces(t *testing.T) {
	for kind := uint8(0); kind < 5; kind++ {
		body, frame := assemblyWordBody(t, kind, 0)
		relation := assemblyWordRelation(t, body, frame)
		if !relation.returnProof.Valid() || relation.booleanProof.Valid() || relation.result.Valid() != (kind != 1) {
			t.Fatalf("kind %d: return/result evidence differs from its interface", kind)
		}
		for _, values := range [][2]uint64{{0, 0}, {0, ^uint64(0)}, {^uint64(0), 1}, {1 << 63, 1 << 63}, {(1 << 40) + 1, (1 << 40) + 1}} {
			arguments := []uint64{values[1]}
			if kind == 0 {
				arguments = nil
			}
			got := assemblyReferenceUnitApply(t, relation, values[0], arguments...)
			assertAssemblyWordResult(t, got, kind, values[0], values[1])
		}
	}
}

func TestAssemblyReferenceWordResultAndStorageRefusals(t *testing.T) {
	body, frame := assemblyWordBody(t, 2, 0)
	for _, edited := range []string{
		strings.Replace(body, "LOCK\n", "", 1),
		strings.Replace(body, "MOVQ AX, ret+16(FP)", "MOVL AX, ret+16(FP)", 1),
		strings.Replace(body, "MOVQ AX, ret+16(FP)", "MOVQ AX, ret+8(FP)", 1),
		strings.Replace(body, "XADDQ AX, 0(BX)", "XADDQ AX, 8(BX)", 1),
		strings.Replace(body, "MOVQ AX, ret+16(FP)", "MOVQ BX, ret+16(FP)", 1),
	} {
		definitions, err := assemblyReferenceUnitParse(t, edited)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], frame); err == nil {
			t.Fatalf("invalid word reference admitted:\n%s", edited)
		}
	}
	// Omitting the post-XADD ADD is valid assembly with a different result: it
	// returns the old value, while the memory update remains the modular sum.
	changed := assemblyWordRelation(t, strings.Replace(body, "ADDQ CX, AX\n", "", 1), frame)
	got := assemblyReferenceUnitApply(t, changed, 7, 3)
	value, ok := constant.Uint64Val(got.Result.scalar)
	if !ok || value != 7 || got.Value != 10 {
		t.Fatalf("body edit did not change only the returned value: %+v", got)
	}
}

func TestAssemblyReferenceOwnsExpandedFrameAndInputPopulation(t *testing.T) {
	args := make([]types.Type, assemblyReferenceMaxArguments-1)
	for i := range args {
		args[i] = types.Typ[types.Uint64]
	}
	frame := assemblyWordFrame(t, args, types.Typ[types.Uint64])
	body := fmt.Sprintf("TEXT ·Word(SB),4,$0-%d\nMOVQ last+%d(FP), AX\nMOVQ AX, ret+%d(FP)\nRET\n", frame.size-8, (len(frame.arguments)-1)*8, frame.result.offset-8)
	relation := assemblyWordRelation(t, body, frame)
	frame.arguments[len(frame.arguments)-1].offset = 0
	frame.permissions[0].write = true
	if relation.frame.arguments[len(relation.frame.arguments)-1].offset == 0 || relation.frame.permissions[0].write {
		t.Fatal("checked reference borrows mutable frame containers")
	}
	values := make([]uint64, len(args))
	values[len(values)-1] = 0xfedcba9876543210
	got := assemblyReferenceUnitApply(t, relation, 11, values...)
	result, ok := constant.Uint64Val(got.Result.scalar)
	if !ok || result != values[len(values)-1] || got.Value != 11 || len(got.Accesses) != 0 {
		t.Fatalf("expanded frame mixed formal, pointer or scratch inputs: %+v", got)
	}
	for _, population := range []int{0, len(relation.inputs) - 1, len(relation.inputs) + 1} {
		if _, err := assemblyReferenceApply(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, relation, make([]uint64, population)); err == nil {
			t.Fatalf("accepted %d scalar words for %d inputs", population, len(relation.inputs))
		}
	}
}

// This grammar varies real source instruction bodies, scalar values and target
// registers. Its ordinary-integer oracle covers wrapping and signed delta bits;
// the bounded seeds are not a claim of exhaustive ISA or selected-build coverage.
func FuzzAssemblyWordReferenceRelations(f *testing.F) {
	for kind := uint8(0); kind < 5; kind++ {
		for _, pair := range [][2]uint64{{0, ^uint64(0)}, {^uint64(0), 1}, {1 << 63, 1 << 63}, {(1 << 40) + 1, (1 << 40) + 1}} {
			f.Add(pair[0], int64(pair[1]), kind, kind)
		}
	}
	f.Fuzz(func(t *testing.T, current uint64, argument int64, kind, register uint8) {
		kind %= 5
		body, frame := assemblyWordBody(t, kind, register)
		relation := assemblyWordRelation(t, body, frame)
		arguments := []uint64{uint64(argument)}
		if kind == 0 {
			arguments = nil
		}
		got := assemblyReferenceUnitApply(t, relation, current, arguments...)
		assertAssemblyWordResult(t, got, kind, current, uint64(argument))
	})
}

func TestAssemblyReferenceSelectedWordSubstitution(t *testing.T) {
	if testing.Short() {
		t.Skip("loads selected typed calls and captures their final assembly providers")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected assembly acquisition uses Linux amd64")
	}
	goSource := `package p
//go:noescape
func ReadWord(ptr *uint64) uint64
//go:noescape
func StoreWord(ptr *uint64, value uint64)
//go:noescape
func AddWord(ptr *uint64, delta int64) uint64
//go:noescape
func ExchangeWord(ptr *uint64, value uint64) uint64
//go:noescape
func SignedExchange(ptr *uint64, value uint64) int64
func Stop(ptr *uint64)
func WrappedRead(ptr *uint64) uint64 { return ReadWord(ptr) }
var Cell uint64
func Run() {
	Cell = 7
	StoreWord(&Cell, 9)
	if ReadWord(&Cell) != 9 { panic("store") }
	if AddWord(&Cell, -1) != 8 { panic("add") }
	if ExchangeWord(&Cell, 4) != 8 { panic("exchange") }
	if Cell != 4 { panic("memory") }
	Cell = ^uint64(0)
	if SignedExchange(&Cell, 3) != -1 { panic("signed result") }
	if Cell != 3 { panic("signed memory") }
	if WrappedRead(&Cell) != 3 { panic("wrapped read") }
	Stop(&Cell)
}
`
	names := []string{"ReadWord", "StoreWord", "AddWord", "ExchangeWord", "SignedExchange"}
	assembly := "#include \"textflag.h\"\n"
	for kind, name := range names {
		body, _ := assemblyWordBody(t, uint8(kind), uint8(kind))
		body = strings.Replace(body, "·Word(SB)", "·"+name+"(SB)", 1)
		assembly += strings.Replace(body, ",4,", ",NOSPLIT,", 1)
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/asmword\n\ngo 1.27\n", "word.go": goSource, "word_amd64.s": assembly})
	source := assemblyReferenceSelectedSource(t, dir)
	packet := assemblyReferenceSelectedPacket(t, source, source.prog.Roots[names[0]])
	references := map[*ssa.Function]*assemblyReference{}
	for kind, name := range names {
		target := source.prog.Roots[name]
		reference, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		references[target] = reference
		arguments := []uint64{^uint64(0)}
		if kind == 0 {
			arguments = nil
		}
		result, err := reference.evaluate(t.Context(), 1<<63, arguments...)
		if err != nil {
			t.Fatal(err)
		}
		assertAssemblyWordResult(t, result, uint8(kind), 1<<63, ^uint64(0))
	}
	root := source.prog.Roots["Run"]
	find := func(name string) *ssa.Call {
		t.Helper()
		var found *ssa.Call
		for _, block := range root.Blocks {
			for _, instruction := range block.Instrs {
				call, ok := instruction.(*ssa.Call)
				if ok && call.Call.StaticCallee() == source.prog.Roots[name] {
					if found != nil {
						t.Fatal("fixture needs one exact call occurrence per target")
					}
					found = call
				}
			}
		}
		if found == nil {
			t.Fatalf("missing fixture call %s", name)
		}
		return found
	}
	prefix, err := checkSourceOperandPrefix(t.Context(), source, root, find("StoreWord"), defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ReadWord", "AddWord", "ExchangeWord", "SignedExchange", "WrappedRead", "Stop"} {
		previousCall := prefix.call
		prefix, err = checkSourceOperandContinuation(t.Context(), prefix, find(name), references)
		if err != nil {
			t.Fatalf("continuing to %s: %v", name, err)
		}
		want, atomic := map[string]x86asm.Op{"ReadWord": x86asm.XCHG, "ExchangeWord": x86asm.XADD, "SignedExchange": x86asm.XCHG, "WrappedRead": x86asm.XCHG}[name]
		groups := prefix.region.packet.trace.atomics
		if !atomic {
			if len(groups) != 0 {
				t.Fatalf("ordinary call at %s invented an RMW", name)
			}
		} else if len(groups) != 1 || groups[0].application.at != previousCall || groups[0].atomic.Kind != want || groups[0].atomic.ReadAccess != 0 || groups[0].atomic.WriteAccess != 1 {
			t.Fatalf("call preceding %s lost exact RMW provenance: %+v", name, groups)
		}
	}
	global := prefix.operands[0].location.object.site.(*ssa.Global)
	value := readRegionLocation(prefix.region.packet.observations[0].state, regionLocation{object: regionObject{kind: regionGlobal, site: global}}, types.Typ[types.Uint64])
	if bits, ok := regionUint64(value); !ok || bits != 3 {
		t.Fatalf("typed signed/void substitutions lost the final current heap: %+v", value)
	}
	trace := prefix.region.packet.trace
	if len(trace.calls) != 2 || len(trace.accesses) != 1 {
		t.Fatalf("wrapped reference lost or duplicated its actual calls/access: %+v", trace)
	}
	access := trace.accesses[0]
	nested, ok := access.instruction.(*ssa.Call)
	bits, known := regionUint64(access.value)
	if !ok || nested.Parent() != source.prog.Roots["WrappedRead"] || nested.Call.StaticCallee() != source.prog.Roots["ReadWord"] || access.invocation == (regionInvocation{}) || access.write || access.locked || !known || bits != 3 {
		t.Fatalf("wrapped reference access lost actual invocation provenance: %+v", access)
	}
}

func TestAssemblyReferenceWordFlagConsumers(t *testing.T) {
	frame := assemblyWordFrame(t, []types.Type{types.Typ[types.Uint64]}, types.Typ[types.Bool])
	for _, tc := range []struct {
		name, operations  string
		current, argument uint64
		want              bool
	}{
		{"xadd-carry", "CMPQ AX, AX\nLOCK\nXADDQ AX, (BX)\nSETCS ret+16(FP)", ^uint64(0), 1, true},
		{"xadd-no-carry", "CMPQ AX, AX\nLOCK\nXADDQ AX, (BX)\nSETCS ret+16(FP)", 0, 1, false},
		{"xadd-overflow", "CMPQ AX, AX\nLOCK\nXADDQ AX, (BX)\nSETLT ret+16(FP)", (1 << 63) - 1, 1, false},
		{"xadd-negative-no-overflow", "CMPQ AX, AX\nLOCK\nXADDQ AX, (BX)\nSETLT ret+16(FP)", 1 << 63, 1, true},
		{"add-register-zero", "CMPQ AX, AX\nMOVQ (BX), CX\nADDQ CX, AX\nSETEQ ret+16(FP)", ^uint64(0), 1, true},
		{"add-register-nonzero", "CMPQ AX, AX\nMOVQ (BX), CX\nADDQ CX, AX\nSETEQ ret+16(FP)", 1, 1, false},
		{"add-immediate-carry", "CMPQ AX, AX\nADDQ $1, AX\nSETCS ret+16(FP)", 7, ^uint64(0), true},
		{"add-immediate-no-carry", "CMPQ AX, AX\nADDQ $-1, AX\nSETCS ret+16(FP)", 7, 0, false},
		{"add-negative-immediate-carry", "CMPQ AX, AX\nADDQ $-1, AX\nSETCS ret+16(FP)", 7, (1 << 32) + 1, true},
		{"exchange-preserves-zero", "CMPQ AX, $0\nXCHGQ AX, (BX)\nSETEQ ret+16(FP)", 7, 0, true},
		{"exchange-preserves-nonzero", "CMPQ AX, $0\nXCHGQ AX, (BX)\nSETEQ ret+16(FP)", 0, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "TEXT ·Flags(SB),4,$0-17\nMOVQ ptr+0(FP), BX\nMOVQ value+8(FP), AX\n" + tc.operations + "\nRET\n"
			relation := assemblyWordRelation(t, body, frame)
			got := assemblyReferenceUnitApply(t, relation, tc.current, tc.argument)
			if assemblyReferenceBool(t, got.Result) != tc.want {
				t.Fatalf("derived flag consumer returned %+v, want %v", got, tc.want)
			}
		})
	}
}

func TestAssemblyReferenceMixedAtomicOccurrenceOrder(t *testing.T) {
	frame := assemblyWordFrame(t, []types.Type{types.Typ[types.Uint64]}, types.Typ[types.Uint64])
	body := `TEXT ·Mixed(SB),4,$0-24
MOVQ ptr+0(FP), BX
MOVQ value+8(FP), AX
LOCK
XADDQ AX, (BX)
MOVQ value+8(FP), CX
XCHGQ CX, (BX)
MOVQ AX, ret+16(FP)
RET
`
	relation := assemblyWordRelation(t, body, frame)
	got := assemblyReferenceUnitApply(t, relation, 7, 3)
	want := []assemblyReferenceAtomic{{Statement: 3, Kind: x86asm.XADD, ReadAccess: 0, WriteAccess: 1, Width: 8}, {Statement: 5, Kind: x86asm.XCHG, ReadAccess: 2, WriteAccess: 3, Width: 8}}
	if !slices.Equal(got.Atomics, want) || !slices.Equal(got.Accesses, []assemblyReferenceAccess{{false, true, 7, 8}, {true, true, 10, 8}, {false, true, 10, 8}, {true, true, 3, 8}}) {
		t.Fatalf("mixed reference lost occurrence order or indivisible pairs: %+v", got)
	}
	got.Atomics[0].Kind = x86asm.NOP
	if again := assemblyReferenceUnitApply(t, relation, 7, 3); !slices.Equal(again.Atomics, want) {
		t.Fatal("result projection mutated retained atomic evidence")
	}
}
