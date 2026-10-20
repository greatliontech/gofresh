package closure

import (
	"go/token"
	"go/types"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func assertRoundSelectedSourceCompletion(t *testing.T, prior *sourceOperandPrefix, references map[*ssa.Function]*assemblyReference) {
	t.Helper()
	root := prior.region.packet.input.root
	var round *ssa.Call
	var returned *ssa.Return
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			switch instruction := instruction.(type) {
			case *ssa.Call:
				if callee := instruction.Call.StaticCallee(); callee != nil && callee.Name() == "round2" {
					if round != nil {
						t.Fatal("selected root has ambiguous rounding calls")
					}
					round = instruction
				}
			case *ssa.Return:
				if returned != nil {
					t.Fatal("selected root has ambiguous returns")
				}
				returned = instruction
			}
		}
	}
	if round == nil || returned == nil || prior.call.Call.StaticCallee() == nil || prior.call.Call.StaticCallee().Name() != "testAtomic64" {
		t.Fatal("selected source sequence lost its actual call/return boundaries")
	}
	operand, err := checkSourceOperandContinuation(t.Context(), prior, round, references)
	if err != nil {
		t.Fatalf("actual atomic continuation: %v", err)
	}
	if operand.prior != prior.sourceEffectPrefix || len(operand.operands) != 1 || !types.Identical(operand.operands[0].typ, types.Typ[types.Int32]) {
		t.Fatal("selected rounding call lost its actual predecessor or typed argument")
	}
	argument, exact := regionInt(operand.operands[0])
	if !exact || argument != 2048 {
		t.Fatalf("selected actual rounding argument=%d exact=%v; expected linux/amd64 fixture argument 2048", argument, exact)
	}
	before := operand.region.packet.observations[0].state
	for _, tc := range []struct {
		name string
		want uint64
	}{{"test_z64", (3 << 40) + 3}, {"test_x64", 42}} {
		global, ok := root.Pkg.Members[tc.name].(*ssa.Global)
		if !ok {
			t.Fatal("selected atomic test global is absent", tc.name)
		}
		value := readRegionLocation(before, regionLocation{object: regionObject{kind: regionGlobal, site: global}}, types.Typ[types.Uint64])
		bits, width, exact := storageScalarBits(value, operand.region.root.pkg.TypesSizes)
		if !exact || width != 8 || bits != tc.want {
			t.Fatal("actual atomic child did not establish its final global state", tc.name)
		}
	}
	childCalls, loads := 0, 0
	for _, application := range operand.region.packet.trace.calls {
		if application.proof.at == prior.call {
			childCalls++
		}
		if application.proof.target.Name() == "Load64" {
			if application.proof.reference != nil || len(application.proof.target.Blocks) == 0 {
				t.Fatal("actual Go load body was replaced by an opaque reference")
			}
			loads++
		}
	}
	if childCalls != 1 || loads != 4 {
		t.Fatalf("actual atomic child/application inventory differs: child=%d loads=%d", childCalls, loads)
	}
	for object, value := range prior.region.packet.observations[0].state.memory {
		if !regionSameValue(value, before.memory[object]) {
			t.Fatal("atomic child changed the caller's prior local/float heap")
		}
	}
	complete, err := checkSourceReturnContinuation(t.Context(), operand, returned, references)
	if err != nil {
		t.Fatalf("actual rounding completion: %v", err)
	}
	packet := complete.region.packet
	if complete.prior != operand.sourceEffectPrefix || complete.returned != returned || complete.checkedPacket() == nil || len(packet.observations) != 1 || packet.usage.work <= operand.region.packet.usage.work {
		t.Fatal("selected complete return lost its anchored scope or cumulative work")
	}
	if packet.input.selection != prior.region.packet.input.selection || packet.input.storageModel != prior.region.packet.input.storageModel {
		t.Fatal("loop completion changed the source layout or storage-model premise")
	}
	after := packet.observations[0].state
	result, exact := regionInt(after.values[round])
	if !exact || result != argument || !types.Identical(after.values[round].typ, types.Typ[types.Int32]) {
		t.Fatal("actual rounding child did not return the expected typed value")
	}
	if len(before.memory) != len(after.memory) || len(packet.trace.accesses) != 0 || len(packet.trace.atomics) != 0 || len(packet.trace.calls) != 1 {
		t.Fatal("pure finite rounding changed memory or omitted/added a call")
	}
	for object, value := range before.memory {
		if !regionSameValue(value, after.memory[object]) {
			t.Fatal("finite loop changed the preserved current heap")
		}
	}
	callee := round.Call.StaticCallee()
	conditions, increments, shifts, rootReturns := 0, 0, 0, 0
	seen := map[regionEffectOccurrence]bool{}
	for _, occurrence := range packet.trace.instructions {
		if seen[occurrence] {
			t.Fatal("repeated static instruction collapsed distinct execution occurrences")
		}
		seen[occurrence] = true
		if occurrence.instruction == returned {
			rootReturns++
		}
		if occurrence.instruction.Parent() != callee {
			continue
		}
		switch instruction := occurrence.instruction.(type) {
		case *ssa.If:
			conditions++
		case *ssa.BinOp:
			if instruction.Op == token.ADD {
				increments++
			}
			if instruction.Op == token.SHL {
				shifts++
			}
		}
	}
	if conditions != 12 || increments != 11 || shifts != 13 || rootReturns != 1 || len(packet.trace.excluded) != 13 {
		t.Fatalf("selected finite execution differs: conditions=%d increments=%d shifts=%d returns=%d exclusions=%d", conditions, increments, shifts, rootReturns, len(packet.trace.excluded))
	}
	t.Log("complete selected runtime.check source: actual testAtomic64 application, derived round2 argument, eleven backedges and checked caller return; native/root applicability remains open")
	t.Logf("cumulative source account: nodes=%d states=%d locations=%d work=%d", packet.usage.nodes, packet.usage.states, packet.usage.locations, packet.usage.work)
}
