package closure

import (
	"go/token"
	"go/types"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func TestFloatSourceModelSelectedOwner(t *testing.T) {
	source := relationFixture(t, `func F()bool{var x float64;return x==x}`, 64)
	in := sourceRegionInput(t, source)
	other := source
	owner := *source.prog
	other.prog = &owner // Same SSA program, a different selected-layout owner.
	for _, selected := range []computationSource{source, other} {
		in.storageModel = conditionalRegionStorageModel(selected)
		proposal, err := proposeRegion(t.Context(), in, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		packet, err := checkSourceRegion(t.Context(), source, in, proposal, defaultRegistrationLimits().source, defaultRegionLimits())
		if selected.prog != source.prog {
			if packet != nil || err == nil {
				t.Fatal("selected binding borrowed another layout owner's conditional model")
			}
			continue
		}
		if err != nil || packet == nil || packet.packet.input.storageModel != in.storageModel {
			t.Fatalf("selected binding lost its explicit conditional model: %v", err)
		}
	}
}

func assertFloatSelectedSourceContinuation(t *testing.T, prior *sourceEffectPrefix, references map[*ssa.Function]*assemblyReference) {
	t.Helper()
	root := prior.region.packet.input.root
	var boundary *ssa.Call
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok && call.Call.StaticCallee() != nil && call.Call.StaticCallee().Name() == "testAtomic64" {
				if boundary != nil {
					t.Fatal("ambiguous selected following call")
				}
				boundary = call
			}
		}
	}
	if boundary == nil {
		t.Fatal("selected source has no following call boundary")
	}
	completed, err := checkSourceOperandContinuation(t.Context(), prior, boundary, references)
	if err != nil {
		t.Fatal(err)
	}
	packet := completed.region.packet
	if completed.prior != prior || completed.call != boundary || completed.boundary != boundary || packet.input.entry != prior.region.packet.input.use.at || len(packet.observations) != 1 {
		t.Fatal("float continuation lost its actual predecessor, entry or call boundary")
	}
	if packet.usage.work <= prior.region.packet.usage.work {
		t.Fatal("float continuation restarted its work account")
	}
	if packet.input.storageModel == (regionStorageModel{}) || packet.input.storageModel != prior.region.packet.input.storageModel || packet.input.storageModel != conditionalRegionStorageModel(completed.binder.source) {
		t.Fatal("float continuation dropped or moved its conditional storage model")
	}
	state := packet.observations[0].state
	comparisons, conversions := 0, 0
	for _, occurrence := range packet.trace.instructions {
		if occurrence.instruction == boundary {
			t.Fatal("following atomic helper was executed by the float prefix")
		}
		switch instruction := occurrence.instruction.(type) {
		case *ssa.Convert:
			conversions++
		case *ssa.BinOp:
			basic, ok := instruction.X.Type().Underlying().(*types.Basic)
			if !ok || basic.Info()&types.IsFloat == 0 {
				continue
			}
			if instruction.Op != token.EQL && instruction.Op != token.NEQ {
				t.Fatal("selected float prefix acquired another operation")
			}
			value, exact := regionBool(state.values[instruction])
			if !exact || value != (instruction.Op == token.NEQ) {
				t.Fatal("selected NaN comparison has no exact IEEE result")
			}
			comparisons++
		}
	}
	if comparisons != 8 || conversions != 8 || len(packet.trace.excluded) != 8 || len(packet.trace.calls) != 0 || len(packet.trace.atomics) != 0 {
		t.Fatalf("incomplete selected float interval: comparisons=%d conversions=%d exclusions=%d calls=%d atomics=%d", comparisons, conversions, len(packet.trace.excluded), len(packet.trace.calls), len(packet.trace.atomics))
	}
	stores := 0
	for _, access := range packet.trace.accesses {
		if !access.write {
			continue
		}
		if stores >= 4 || access.locked {
			t.Fatal("unexpected float interval write")
		}
		width, want := 8, ^uint64(stores%2)
		if stores >= 2 {
			width, want = 4, uint64(^uint32(stores%2))
		}
		bits, size, exact := storageScalarBits(access.value, completed.region.root.pkg.TypesSizes)
		if !exact || size != width || bits != want {
			t.Fatal("selected integer bit store changed width or payload")
		}
		storageType := completed.checker.locationType(access.location)
		basic, ok := storageType.Underlying().(*types.Basic)
		if !ok || basic.Info()&types.IsFloat == 0 {
			t.Fatal("integer bit store lost its canonical float object")
		}
		current := readRegionLocation(state, access.location, storageType)
		bits, size, exact = storageScalarBits(current, completed.region.root.pkg.TypesSizes)
		if !exact || size != width || bits != want {
			t.Fatal("canonical float heap lost the stored payload")
		}
		before := readRegionLocation(prior.region.packet.observations[0].state, access.location, storageType)
		bits, size, exact = storageScalarBits(before, completed.region.root.pkg.TypesSizes)
		if !exact || size != width || bits != 0 {
			t.Fatal("float continuation changed its retained pre-store snapshot")
		}
		stores++
	}
	if stores != 4 {
		t.Fatal("selected float interval omitted a bit store")
	}
	t.Log("complete selected source entry through four bit stores and eight IEEE comparisons; testAtomic64 remains unexecuted; native applicability remains conditional")
}
