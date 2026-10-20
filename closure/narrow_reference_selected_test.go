package closure

import (
	"go/constant"
	"go/types"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

func TestNarrowReferenceSelectedRuntime(t *testing.T) {
	if testing.Short() {
		t.Skip("loads selected compiler source and captures final assembler inputs")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected assembly acquisition uses Linux amd64")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/narrowreference\n\ngo 1.27\n"})
	source, _, _ := loadSourceCommandFixture(t, dir, "cmd/compile")
	var provider *ssa.Package
	for _, pkg := range source.prog.Pkgs {
		if pkg.PkgPath == "internal/runtime/atomic" {
			provider = source.prog.Prog.Package(pkg.Types)
		}
	}
	if provider == nil || provider.Func("Cas") == nil {
		t.Fatal("selected candidate declarations are absent")
	}
	selected, err := source.owner.packageFor(provider.Func("Cas"))
	if err != nil {
		t.Fatal(err)
	}
	// Compiler acquisition includes its selected profile inputs. Use the same
	// bounded acquisition allowance as the complete runtime correspondence fixture.
	packet, err := acquireSelectedAssembly(t.Context(), source.owner, selected, assemblyCaptureLimits{Bytes: 2 << 30})
	if err != nil {
		t.Fatal(err)
	}
	references := map[*ssa.Function]*assemblyReference{}
	for _, tc := range []struct {
		name        string
		kind        x86asm.Op
		width, size int
		arguments   []assemblyReferenceSlot
	}{
		{"Cas", x86asm.CMPXCHG, 4, 25, []assemblyReferenceSlot{{8, 8}, {16, 4}, {20, 4}}},
		{"Or8", x86asm.OR, 1, 17, []assemblyReferenceSlot{{8, 8}, {16, 1}}},
		{"And8", x86asm.AND, 1, 17, []assemblyReferenceSlot{{8, 8}, {16, 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := provider.Func(tc.name)
			if target == nil {
				t.Fatal("selected candidate is absent")
			}
			reference, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
			if err != nil {
				t.Fatal(err)
			}
			references[target] = reference
			relation := reference.checked.relation
			frame := relation.frame
			if frame.size != tc.size || len(frame.arguments) != len(tc.arguments) {
				t.Fatal("reference does not retain its exact declared frame extent")
			}
			for i, want := range tc.arguments {
				if frame.arguments[i] != want {
					t.Fatalf("argument %d has another selected offset or width", i)
				}
			}
			for _, input := range relation.inputs {
				if input.Sort() != br.Bits(tc.width*8) {
					t.Fatal("reference input was widened beyond its selected type")
				}
			}
			for _, permission := range frame.permissions {
				if permission.space == frame.targetSpace && (permission.start != 0 || permission.end != tc.width || !permission.read || !permission.write) {
					t.Fatal("external access permissions exceed the typed scalar extent")
				}
			}
			if tc.kind == x86asm.CMPXCHG {
				if frame.result != (assemblyReferenceSlot{24, 1}) {
					t.Fatal("Boolean result has another ABI location")
				}
				for _, values := range [][3]uint64{{1, 1, 2}, {4, 5, 6}, {0xffffffff, 0xffffffff, 0xfffffffe}} {
					got, err := reference.evaluate(t.Context(), values[0], values[1:]...)
					if err != nil {
						t.Fatal(err)
					}
					success, want := values[0] == values[1], values[0]
					if success {
						want = values[2]
					}
					if got.Value != want || assemblyReferenceBool(t, got.Result) != success {
						t.Fatal("actual selected CAS32 value or Boolean result differs")
					}
					assertNarrowSelectedReferenceGroup(t, got, tc.kind, values[0], want)
				}
			} else {
				if frame.result.width != 0 || relation.result.Valid() {
					t.Fatal("void reference acquired a result slot or scalar result")
				}
				for _, values := range [][2]uint64{{1, 0xf0}, {0xff, 1}, {0, 0}, {0xff, 0xff}} {
					got, err := reference.evaluate(t.Context(), values[0], values[1])
					if err != nil {
						t.Fatal(err)
					}
					want := values[0] & values[1]
					if tc.kind == x86asm.OR {
						want = values[0] | values[1]
					}
					if got.Value != want || got.Result.kind != regionAggregate || len(got.Result.elements) != 0 || got.Result.scalar != nil {
						t.Fatal("actual selected byte operation changed value or invented a result")
					}
					assertNarrowSelectedReferenceGroup(t, got, tc.kind, values[0], want)
				}
			}
		})
	}
	if len(references) != 3 {
		t.Fatal("selected narrow references are incomplete")
	}
	for _, name := range []string{"Cas64", "Store64", "Xadd64", "Xchg64"} {
		target := provider.Func(name)
		if target == nil {
			t.Fatal("selected wide reference declaration is absent", name)
		}
		reference, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
		if err != nil {
			t.Fatal(err)
		}
		references[target] = reference
	}
	assertNarrowSelectedSourcePrefix(t, source, references)
}

func assertNarrowSelectedSourcePrefix(t *testing.T, source computationSource, references map[*ssa.Function]*assemblyReference) {
	t.Helper()
	var root *ssa.Function
	for _, pkg := range source.prog.Pkgs {
		if pkg.PkgPath == "runtime" {
			root = source.prog.Prog.Package(pkg.Types).Func("check")
		}
	}
	if root == nil {
		t.Fatal("selected source root is absent")
	}
	var calls []*ssa.Call
	var boundary *ssa.Convert
	var use regionUse
	for _, block := range root.Blocks {
		for index, instruction := range block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok && references[call.Call.StaticCallee()] != nil {
				calls = append(calls, call)
			}
			convert, ok := instruction.(*ssa.Convert)
			if !ok {
				continue
			}
			pointer, ok := convert.X.Type().Underlying().(*types.Pointer)
			if !ok || !types.Identical(pointer.Elem(), types.Typ[types.Float64]) {
				continue
			}
			if boundary == nil || convert.Pos() < boundary.Pos() {
				boundary, use = convert, regionUse{regionPoint{block, index}, convert.X}
			}
		}
	}
	sort.Slice(calls, func(i, j int) bool { return calls[i].Pos() < calls[j].Pos() })
	if len(calls) != 5 || boundary == nil || boundary.Pos() <= calls[4].Pos() {
		t.Fatal("selected atomic sequence or following unsafe boundary changed")
	}
	limits := defaultRegistrationLimits()
	limits.source.work, limits.source.bytes = 16<<20, 512<<20
	// The complete caller relation retains its earlier states and every finite
	// child occurrence under one cumulative value-copy allowance.
	limits.region.locations = 16 << 10
	limits.region.nodes = 16 << 10
	first, err := checkSourceOperandPrefix(t.Context(), source, root, calls[0], limits)
	if err != nil {
		t.Fatal(err)
	}
	z := first.operands[0].location
	prefix := first
	var beforeOr, beforeAnd *sourceOperandPrefix
	for index, call := range calls[1:] {
		prefix, err = checkSourceOperandContinuation(t.Context(), prefix, call, references)
		if err != nil {
			t.Fatal(err)
		}
		switch index + 1 {
		case 3:
			beforeOr = prefix
		case 4:
			beforeAnd = prefix
		}
	}
	completed, err := checkSourceInstructionContinuation(t.Context(), prefix, use, references)
	if err != nil {
		t.Fatal(err)
	}
	if completed.boundary != boundary || completed.prior != prefix.sourceEffectPrefix || beforeOr == nil || beforeAnd == nil {
		t.Fatal("source continuation lost its actual instruction or predecessor")
	}
	var chain []*sourceEffectPrefix
	for at := completed; at != nil; at = at.prior {
		chain = append(chain, at)
	}
	slices.Reverse(chain)
	if len(chain) != 6 || chain[0] != first.sourceEffectPrefix || chain[0].region.packet.input.entry != (regionPoint{block: root.Blocks[0]}) {
		t.Fatal("selected source relation omitted its complete entry prefix")
	}
	wantKinds := []x86asm.Op{x86asm.CMPXCHG, x86asm.CMPXCHG, x86asm.CMPXCHG, x86asm.OR, x86asm.AND}
	wantBefore := []uint64{1, 4, 0xffffffff, 1, 0xff}
	wantAfter := []uint64{2, 4, 0xfffffffe, 0xf1, 1}
	count := 0
	for _, phase := range chain {
		packet := phase.checkedPacket()
		if packet == nil {
			t.Fatal("selected source phase lacks checked ownership")
		}
		for _, occurrence := range packet.trace.instructions {
			if occurrence.instruction == boundary {
				t.Fatal("unsafe conversion was executed")
			}
		}
		for _, occurrence := range packet.trace.atomics {
			if count >= len(calls) {
				t.Fatal("unexpected selected source atomic occurrence")
			}
			atomic := occurrence.atomic
			width := 4
			if count >= 3 {
				width = 1
			}
			if occurrence.application.at != calls[count] || atomic.Kind != wantKinds[count] || atomic.Width != width || atomic.ReadAccess < 0 || atomic.WriteAccess != atomic.ReadAccess+1 || atomic.WriteAccess >= len(packet.trace.accesses) {
				t.Fatal("selected source atomic lost its statement, width or ordered group")
			}
			read, write := packet.trace.accesses[atomic.ReadAccess], packet.trace.accesses[atomic.WriteAccess]
			if read.write || !write.write || !read.locked || !write.locked || read.instruction != calls[count] || write.instruction != calls[count] || read.location.object != write.location.object || !slices.Equal(read.location.path, write.location.path) {
				t.Fatal("selected source atomic lost a read/write or its storage identity")
			}
			var application *regionCallApplication
			for index := range packet.trace.calls {
				if packet.trace.calls[index].proof == occurrence.application {
					if application != nil {
						t.Fatal("selected call outcome was recorded more than once")
					}
					application = &packet.trace.calls[index]
				}
			}
			if application == nil {
				t.Fatal("selected source atomic lacks its complete call outcome")
			}
			beforeState, afterState := application.proof.initial, application.outcome.state
			if len(beforeState.memory) != len(afterState.memory) {
				t.Fatal("reference-private storage leaked into the source heap")
			}
			for object, value := range beforeState.memory {
				if object != read.location.object && !reflect.DeepEqual(value, afterState.memory[object]) {
					t.Fatal("call-time outcome absorbed a later unrelated heap change")
				}
			}
			for value, prior := range beforeState.values {
				if !reflect.DeepEqual(prior, afterState.values[value]) {
					t.Fatal("reference call changed an already evaluated source value")
				}
			}
			for value := range afterState.values {
				if _, present := beforeState.values[value]; !present && value != calls[count] {
					t.Fatal("call-time outcome acquired a value from a later instruction")
				}
			}
			if count < 3 {
				value, known := regionBool(application.outcome.value)
				if !known || value != (count != 1) {
					t.Fatal("source call lost its actual CAS Boolean outcome")
				}
			} else if application.outcome.value.kind != regionAggregate || len(application.outcome.value.elements) != 0 || application.outcome.value.scalar != nil {
				t.Fatal("void byte call invented a scalar outcome")
			}
			returnedValue := readRegionLocation(afterState, read.location, read.value.typ)
			returnedBits, returnedWidth, exact := storageScalarBits(returnedValue, completed.region.root.pkg.TypesSizes)
			if !exact || returnedWidth != width || returnedBits != wantAfter[count] {
				t.Fatal("call-time heap differs from the actual selected return")
			}
			for index, value := range []regionValue{read.value, write.value} {
				want := wantBefore[count]
				if index == 1 {
					want = wantAfter[count]
				}
				bits, size, exact := storageScalarBits(value, completed.region.root.pkg.TypesSizes)
				if !exact || size != width || bits != want {
					t.Fatal("actual source atomic values differ from selected source intent")
				}
			}
			count++
		}
	}
	if count != 5 {
		t.Fatal("selected source prefix omitted a required atomic")
	}
	assertInteger := func(value regionValue, want uint64) {
		t.Helper()
		got, exact := uint64(0), false
		if value.kind == regionConstant && value.scalar != nil {
			got, exact = constant.Uint64Val(value.scalar)
		}
		if !exact || got != want {
			t.Fatalf("checked source integer=%d exact=%t; want %d", got, exact, want)
		}
	}
	state := completed.region.packet.observations[0].state
	assertInteger(readRegionLocation(state, z, types.Typ[types.Uint32]), 0xfffffffe)
	assertInteger(readRegionLocation(first.region.packet.observations[0].state, z, types.Typ[types.Uint32]), 1)
	m := beforeOr.operands[0].location
	if m.object != beforeAnd.operands[0].location.object || len(m.path) != 1 || m.path[0] != (regionStep{index: 1}) {
		t.Fatal("byte calls lost their common array element")
	}
	for index, want := range []uint64{0xff, 1, 0xff, 0xff} {
		location := regionLocation{object: m.object, path: []regionStep{{index: int64(index)}}}
		assertInteger(readRegionLocation(state, location, types.Typ[types.Uint8]), want)
		assertInteger(readRegionLocation(beforeOr.region.packet.observations[0].state, location, types.Typ[types.Uint8]), 1)
		assertInteger(readRegionLocation(beforeAnd.region.packet.observations[0].state, location, types.Typ[types.Uint8]), 0xff)
	}
	t.Log("complete selected source entry through CAS32 success/failure/high-bit and byte OR/AND; sibling guards checked, unsafe conversion unexecuted")
	assertFloatSelectedSourceContinuation(t, completed, references)
}

func assertNarrowSelectedReferenceGroup(t *testing.T, got assemblyReferenceResult, kind x86asm.Op, before, after uint64) {
	t.Helper()
	if len(got.Accesses) != 2 || len(got.Atomics) != 1 || got.Accesses[0].Write || !got.Accesses[1].Write || !got.Accesses[0].Locked || !got.Accesses[1].Locked || got.Accesses[0].Value != before || got.Accesses[1].Value != after {
		t.Fatal("actual reference lost its indivisible read/write, including unchanged writeback")
	}
	group := got.Atomics[0]
	if group.Kind != kind || group.Statement < 0 || group.ReadAccess != 0 || group.WriteAccess != 1 {
		t.Fatal("atomic group lost its actual selected statement or access ownership")
	}
}
