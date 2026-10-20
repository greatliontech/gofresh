package closure

import (
	"context"
	"errors"
	"go/constant"
	"go/types"
	"maps"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func narrowInstructionUse(t testing.TB, instruction ssa.Instruction, operand ssa.Value) regionUse {
	t.Helper()
	if instruction == nil || instruction.Block() == nil {
		t.Fatal("missing actual instruction")
	}
	return regionUse{at: regionPoint{instruction.Block(), slices.Index(instruction.Block().Instrs, instruction)}, operand: operand}
}

func TestRegionNarrowInstructionContinuations(t *testing.T) {
	source, first := localEffectPrefix(t, `func Stop(*uint32,uint32){};func F(){var a [2]uint32;a[0]=3;a[1]=7;Stop(&a[1],a[1]);a[1]=9;Stop(&a[1],a[1]);a[1]=11;Stop(&a[1],a[1])}`)
	calls := localEffectCalls(t, source.prog.Roots["F"], "Stop")
	var stores []*ssa.Store
	for _, instruction := range calls[0].Block().Instrs {
		if store, ok := instruction.(*ssa.Store); ok && store.Pos() > calls[0].Pos() {
			stores = append(stores, store)
		}
	}
	if len(stores) != 2 {
		t.Fatalf("expected two suffix stores, got %d", len(stores))
	}
	use := narrowInstructionUse(t, stores[0], stores[0].Addr)
	middle, err := checkSourceInstructionContinuation(t.Context(), first, use, nil)
	if err != nil {
		t.Fatal(err)
	}
	if middle.boundary != stores[0] || middle.prior != first.sourceEffectPrefix || middle.region.packet.trace.seen[regionEffectOccurrence{instruction: stores[0]}] {
		t.Fatal("generic prefix consumed its boundary or lost its actual predecessor")
	}
	location := first.operands[0].location
	localEffectInteger(t, readRegionLocation(middle.region.packet.observations[0].state, location, types.Typ[types.Uint32]), 7)
	next, err := checkSourceOperandContinuation(t.Context(), middle, calls[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	localEffectInteger(t, next.operands[1], 9)
	last, err := checkSourceInstructionContinuation(t.Context(), next, narrowInstructionUse(t, stores[1], stores[1].Val), nil)
	if err != nil {
		t.Fatal(err)
	}
	returned := calls[2].Block().Instrs[len(calls[2].Block().Instrs)-1].(*ssa.Return)
	complete, err := checkSourceReturnContinuation(t.Context(), last, returned, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, resumable := any(complete).(sourceResumablePrefix); resumable || complete.checkedPacket() == nil {
		t.Fatal("consumed return became a resumable boundary")
	}
	copyReturn := *complete
	if copyReturn.checkedPacket() != nil {
		t.Fatal("copied consumed-return receipt retained authority")
	}
	localEffectInteger(t, readRegionLocation(complete.region.packet.observations[0].state, location, types.Typ[types.Uint32]), 11)
	for _, endpoint := range []storageSourceEndpoint{middle, next, last, complete} {
		allocation, live, err := endpoint.liveAllocation(location.object, t.Context().Err)
		if err != nil || !live || allocation.location.object != location.object {
			t.Fatalf("mixed chain lost live allocation: %v", err)
		}
	}
	// Both predecessor heap and nested aggregate elements remain branch-owned.
	again, err := checkSourceOperandContinuation(t.Context(), middle, calls[2], nil)
	if err != nil {
		t.Fatal(err)
	}
	localEffectInteger(t, again.operands[1], 11)
	localEffectInteger(t, readRegionLocation(middle.region.packet.observations[0].state, location, types.Typ[types.Uint32]), 7)
	localEffectInteger(t, next.operands[1], 9)
	if middle.region.packet.usage.work <= first.region.packet.usage.work || next.region.packet.usage.work <= middle.region.packet.usage.work || last.binder.work <= next.binder.work {
		t.Fatal("mixed continuation restarted cumulative work")
	}
	copyCore, copyCall := *middle, *next
	for _, receipt := range []sourceResumablePrefix{&copyCore, &copyCall, (*sourceEffectPrefix)(nil), (*sourceOperandPrefix)(nil)} {
		if _, err := checkSourceOperandContinuation(t.Context(), receipt, calls[2], nil); err == nil {
			t.Fatal("copied or absent receipt acquired continuation authority")
		}
	}
	for _, invalid := range []regionUse{
		{at: use.at},
		{at: use.at, operand: calls[0]},
		narrowInstructionUse(t, calls[1], calls[1].Call.Args[0]),
		narrowInstructionUse(t, returned, nil),
	} {
		if _, err := checkSourceInstructionContinuation(t.Context(), first, invalid, nil); err == nil {
			t.Fatal("non-operand or dedicated endpoint admitted as generic instruction")
		}
	}
	_, other := localEffectPrefix(t, `func Stop(*uint32,uint32){};func F(){var x uint32;Stop(&x,x);x=9;Stop(&x,x)}`)
	var foreign *ssa.Store
	for _, instruction := range other.call.Block().Instrs {
		if store, ok := instruction.(*ssa.Store); ok {
			foreign = store
		}
	}
	if foreign == nil {
		t.Fatal("foreign fixture lacks actual store")
	}
	if _, err := checkSourceInstructionContinuation(t.Context(), first, narrowInstructionUse(t, foreign, foreign.Val), nil); err == nil {
		t.Fatal("foreign instruction borrowed predecessor authority")
	}
	if _, err := checkSourceInstructionContinuation(t.Context(), last, use, nil); err == nil {
		t.Fatal("mixed chain reexecuted a retained occurrence")
	}
	measured := &cancelAfterContext{Context: t.Context(), remaining: 1_000_000}
	if _, err := checkSourceInstructionContinuation(measured, first, use, nil); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterContext{Context: t.Context(), remaining: 1_000_000 - measured.remaining - 1}
	if _, err := checkSourceInstructionContinuation(ctx, first, use, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("late cancellation escaped: %v", err)
	}
	limits := defaultRegistrationLimits()
	limits.region.work = first.region.packet.usage.work + 1
	bounded, err := checkSourceOperandPrefix(t.Context(), source, source.prog.Roots["F"], calls[0], limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkSourceInstructionContinuation(t.Context(), bounded, use, nil); err == nil || !strings.Contains(err.Error(), "work budget") {
		t.Fatalf("generic prefix reset region allowance: %v", err)
	}
	limits = defaultRegistrationLimits()
	limits.source.work = first.binder.work + 1
	bounded, err = checkSourceOperandPrefix(t.Context(), source, source.prog.Roots["F"], calls[0], limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkSourceInstructionContinuation(t.Context(), bounded, use, nil); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("generic prefix reset selected-source allowance: %v", err)
	}
}

func TestRegionNarrowSelectedReferenceApplications(t *testing.T) {
	if testing.Short() {
		t.Skip("loads typed source and acquires selected assembler actions")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected assembly acquisition uses Linux amd64")
	}
	dir := t.TempDir()
	const text = `package p
import "unsafe"
type Byte byte
func Cas(p *uint32, old, replacement uint32) bool
func SignedCas(p *int32, old, replacement int32) bool
func Or(p *byte, mask byte)
func And(p *byte, mask byte)
func SignedAnd(p *int8, mask int8)
func Stop() {}
func Scalar(){x:=uint32(0xffffffff);if !Cas(&x,0xffffffff,0x80000000){panic(nil)};if Cas(&x,0,1){panic(nil)};if x!=0x80000000{panic(nil)};Stop()}
func Array(){a:=[3]uint32{3,0x80000000,5};if !Cas(&a[1],0x80000000,0xffffffff){panic(nil)};if a[0]!=3||a[1]!=0xffffffff||a[2]!=5{panic(nil)};Stop()}
func Bytes(){a:=[3]Byte{3,0x80,5};p:=(*byte)(&a[1]);Or(p,0);And(p,0xff);Or(p,1);And(p,0x80);if a[0]!=3||a[1]!=0x80||a[2]!=5{panic(nil)};Stop()}
func Signed(){x:=int32(-2147483648);if !SignedCas(&x,-2147483648,-1){panic(nil)};if SignedCas(&x,0,1){panic(nil)};if x!=-1{panic(nil)};Stop()}
func SignedByte(){x:=int8(-128);SignedAnd(&x,-1);if x!=-128{panic(nil)};Stop()}
func FloatView(){var x float32;p:=(*uint32)(unsafe.Pointer(&x));if !Cas(p,0,0xffffffff){panic(nil)};if x==x{panic(nil)};if Cas(p,0,1){panic(nil)};if x==x{panic(nil)};Stop()}
func SnapshotStop(*byte,*byte) {}
func SnapshotStop32(*uint32,*uint32) {}
func ByteSnapshot(){var a [3]byte;a[0]=2;a[2]=4;other:=byte(6);Or(&a[1],1);a[1]=7;a[0]=8;other=9;SnapshotStop(&a[1],&other)}
func CASSnapshot(){var a [3]uint32;a[0]=2;a[2]=4;other:=uint32(6);Cas(&a[1],0,1);a[1]=7;a[0]=8;other=9;SnapshotStop32(&a[1],&other)}
`
	var assembly strings.Builder
	for _, name := range []string{"Cas", "SignedCas"} {
		assembly.WriteString("TEXT ·" + name + "(SB),4,$0-17\nMOVQ p+0(FP), BX\nMOVL old+8(FP), AX\nMOVL replacement+12(FP), CX\nLOCK\nCMPXCHGL CX, (BX)\nSETEQ ret+16(FP)\nRET\n")
	}
	for _, operation := range []struct{ name, op string }{{"Or", "OR"}, {"And", "AND"}, {"SignedAnd", "AND"}} {
		assembly.WriteString("TEXT ·" + operation.name + "(SB),4,$0-9\nMOVQ p+0(FP), BX\nMOVB mask+8(FP), AX\nLOCK\n" + operation.op + "B AX, (BX)\nRET\n")
	}
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/narrowsource\n\ngo 1.27\n", "p.go": text, "p_amd64.s": assembly.String()})
	source := assemblyReferenceSelectedSource(t, dir)
	packet := assemblyReferenceSelectedPacket(t, source, source.prog.Roots["Cas"])
	references := map[*ssa.Function]*assemblyReference{}
	for _, name := range []string{"Cas", "SignedCas", "Or", "And", "SignedAnd"} {
		target := source.prog.Roots[name]
		reference, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
		if err != nil {
			t.Fatal(err)
		}
		references[target] = reference
	}
	for _, tc := range []struct {
		root, first  string
		width, calls int
		want         uint64
	}{{"Scalar", "Cas", 4, 2, 0x80000000}, {"Array", "Cas", 4, 1, 0xffffffff}, {"Bytes", "Or", 1, 4, 0x80}, {"Signed", "SignedCas", 4, 2, 0xffffffff}, {"SignedByte", "SignedAnd", 1, 1, 0x80}, {"FloatView", "Cas", 4, 2, 0xffffffff}} {
		t.Run(tc.root, func(t *testing.T) {
			root := source.prog.Roots[tc.root]
			firstCall := localEffectCalls(t, root, tc.first)[0]
			first, err := checkSourceOperandPrefix(t.Context(), source, root, firstCall, defaultRegistrationLimits())
			if err != nil {
				t.Fatal(err)
			}
			location := first.operands[0].location
			targetType := firstCall.Call.StaticCallee().Signature.Params().At(0).Type().Underlying().(*types.Pointer).Elem()
			original := first.checker.readLocation(first.region.packet.observations[0].state, location, targetType)
			stop := localEffectCalls(t, root, "Stop")[0]
			ownedReferences := maps.Clone(references)
			end, err := checkSourceOperandContinuation(t.Context(), first, stop, ownedReferences)
			if err != nil {
				t.Fatal(err)
			}
			clear(ownedReferences)
			if len(end.checker.session.references) != len(references) {
				t.Fatal("caller reference-map mutation changed the checked continuation")
			}
			trace := end.region.packet.trace
			if len(trace.atomics) != tc.calls || len(trace.calls) != tc.calls || len(trace.excluded) == 0 {
				t.Fatal("selected application lost atomic occurrences, calls or checked guards")
			}
			current := end.checker.readLocation(end.region.packet.observations[0].state, location, targetType)
			bits, ok := regionReferenceWord(current, tc.width)
			if !ok || bits != tc.want {
				t.Fatalf("wrong selected-width current value: %v", current.scalar)
			}
			wantPairs := map[string][][2]uint64{
				"Scalar":     {{0xffffffff, 0x80000000}, {0x80000000, 0x80000000}},
				"Array":      {{0x80000000, 0xffffffff}},
				"Bytes":      {{0x80, 0x80}, {0x80, 0x80}, {0x80, 0x81}, {0x81, 0x80}},
				"Signed":     {{0x80000000, 0xffffffff}, {0xffffffff, 0xffffffff}},
				"SignedByte": {{0x80, 0x80}},
				"FloatView":  {{0, 0xffffffff}, {0xffffffff, 0xffffffff}},
			}[tc.root]
			for i, group := range trace.atomics {
				if group.atomic.Width != tc.width || group.atomic.WriteAccess != group.atomic.ReadAccess+1 || group.application == nil || group.application.at == nil || group.atomic.Statement < 0 {
					t.Fatal("atomic lost selected width, actual statement or invocation")
				}
				read, write := trace.accesses[group.atomic.ReadAccess], trace.accesses[group.atomic.WriteAccess]
				if read.write || !write.write || !read.locked || !write.locked || read.instruction != group.application.at || write.instruction != read.instruction || read.invocation != write.invocation || read.location.object != location.object || !slices.Equal(read.location.path, location.path) || !slices.Equal(write.location.path, location.path) || !types.Identical(read.value.typ, targetType) || !types.Identical(write.value.typ, targetType) {
					t.Fatal("atomic access lost exact typed subobject ownership")
				}
				before, readOK := regionReferenceWord(read.value, tc.width)
				after, writeOK := regionReferenceWord(write.value, tc.width)
				if !readOK || !writeOK || [2]uint64{before, after} != wantPairs[i] {
					t.Fatalf("atomic %d lost actual access values: %#x -> %#x", i, before, after)
				}
			}
			if tc.root == "Bytes" || tc.root == "Array" {
				stored := end.region.packet.observations[0].state.memory[location.object]
				before := first.region.packet.observations[0].state.memory[location.object]
				if stored.kind != regionAggregate || !types.Identical(stored.typ, before.typ) || len(stored.elements) != 3 {
					t.Fatal("reference replaced the aggregate root or its canonical type")
				}
				localEffectInteger(t, stored.elements[0], 3)
				localEffectInteger(t, stored.elements[2], 5)
				if tc.root == "Bytes" {
					if types.Identical(stored.elements[1].typ, targetType) || !regionScalarView(stored.elements[1].typ, targetType) {
						t.Fatal("named-byte access erased canonical stored type")
					}
					for _, group := range trace.atomics[:2] {
						if !regionSameValue(trace.accesses[group.atomic.ReadAccess].value, trace.accesses[group.atomic.WriteAccess].value) {
							t.Fatal("unchanged byte operation lost its unchanged write")
						}
					}
				}
			}
			if strings.HasPrefix(tc.root, "Signed") {
				value, ok := constant.Int64Val(current.scalar)
				if !ok || value >= 0 {
					t.Fatal("signed raw bits were reconstructed as an unsigned constant")
				}
			}
			if tc.root == "FloatView" {
				value := end.region.packet.observations[0].state.memory[location.object]
				if value.kind != regionFloat || !types.Identical(value.typ, types.Typ[types.Float32]) || value.floatBits != tc.want || end.region.packet.input.storageModel != first.region.packet.input.storageModel {
					t.Fatal("integer reference lost canonical float storage or its model condition")
				}
				t.Run("cancellation-checkpoints", func(t *testing.T) {
					baseline := &relationCallbackContext{Context: t.Context()}
					if _, err := checkSourceOperandContinuation(baseline, first, stop, references); err != nil {
						t.Fatal(err)
					}
					for checkpoint := 1; checkpoint <= baseline.checks; checkpoint++ {
						ctx, cancel := context.WithCancel(t.Context())
						interrupted := &relationCallbackContext{Context: ctx, at: checkpoint, callback: cancel}
						proof, err := checkSourceOperandContinuation(interrupted, first, stop, references)
						cancel()
						if proof != nil || !errors.Is(err, context.Canceled) {
							t.Fatalf("reference float-view checkpoint %d/%d erased cancellation: %v", checkpoint, baseline.checks, err)
						}
					}
				})
			}
			// Re-evaluating an independent branch must not mutate the first receipt.
			again, err := checkSourceOperandContinuation(t.Context(), first, stop, references)
			if err != nil || !regionSameValue(again.region.packet.observations[0].state.memory[location.object], end.region.packet.observations[0].state.memory[location.object]) {
				t.Fatalf("reference continuation branches disagree: %v", err)
			}
			if !regionSameValue(original, first.checker.readLocation(first.region.packet.observations[0].state, location, targetType)) {
				t.Fatal("reference application mutated the predecessor snapshot")
			}
		})
	}
	for _, tc := range []struct{ root, reference, stop string }{
		{"ByteSnapshot", "Or", "SnapshotStop"},
		{"CASSnapshot", "Cas", "SnapshotStop32"},
	} {
		t.Run(tc.root, func(t *testing.T) {
			root := source.prog.Roots[tc.root]
			call := localEffectCalls(t, root, tc.reference)[0]
			stop := localEffectCalls(t, root, tc.stop)[0]
			if call.Block() != stop.Block() {
				t.Fatal("snapshot regression requires same-block caller writes")
			}
			first, err := checkSourceOperandPrefix(t.Context(), source, root, call, defaultRegistrationLimits())
			if err != nil {
				t.Fatal(err)
			}
			end, err := checkSourceOperandContinuation(t.Context(), first, stop, references)
			if err != nil {
				t.Fatal(err)
			}
			trace := end.region.packet.trace
			if len(trace.calls) != 1 || len(trace.atomics) != 1 {
				t.Fatal("snapshot regression lost its actual selected call")
			}
			application := trace.calls[0]
			group := trace.atomics[0]
			location, other := end.operands[0].location, end.operands[1].location
			if application.proof.at != call || application.proof.invocation.root != root || application.proof.invocation.path == "" || end.region.packet.contexts[application.proof.invocation].function != call.Call.StaticCallee() || group.application != application.proof || group.atomic.ReadAccess != 0 || group.atomic.WriteAccess != 1 {
				t.Fatal("snapshot separation changed call or atomic occurrence identity")
			}
			for index, access := range trace.accesses[:2] {
				if access.instruction != call || access.invocation != first.checker.invocation || access.write != (index == 1) || !access.locked || access.location.object != location.object || !slices.Equal(access.location.path, location.path) {
					t.Fatal("snapshot separation changed actual reference accesses")
				}
				localEffectInteger(t, access.value, uint64(index))
			}
			for _, phase := range []struct {
				name  string
				state regionState
				array [3]uint64
				other uint64
			}{
				{"incoming proof", application.proof.initial, [3]uint64{2, 0, 4}, 6},
				{"call-time outcome", application.outcome.state, [3]uint64{2, 1, 4}, 6},
				{"later endpoint", end.region.packet.observations[0].state, [3]uint64{8, 7, 4}, 9},
			} {
				t.Run(phase.name, func(t *testing.T) {
					array := phase.state.memory[location.object]
					if len(phase.state.memory) != 2 || array.kind != regionAggregate || len(array.elements) != 3 || location.object == other.object {
						t.Fatalf("snapshot does not retain both complete independent objects: cells=%d, array kind=%d, elements=%d", len(phase.state.memory), array.kind, len(array.elements))
					}
					for i, want := range phase.array {
						localEffectInteger(t, array.elements[i], want)
					}
					localEffectInteger(t, phase.state.memory[other.object], phase.other)
				})
			}
		})
	}
}
