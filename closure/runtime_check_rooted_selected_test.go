package closure

import (
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

func assertSelectedRuntimeRootedApplication(t *testing.T, raw []byte, image *nativeproof.Image, locations map[string]uint64, proof *globalFunctionCorrespondence) {
	t.Helper()
	body, ok := proof.native.BoundFor(image)
	if !ok {
		t.Fatal("complete correspondence has another native owner")
	}
	x, until := selectedRuntimeRootCandidate(t, raw, locations, selectedStartupLayout(t, raw, image, locations))
	// Later spill reloads require readable original slots, and the outgoing
	// argument slots need their own grants before this fresh root is checked.
	x.face.Regions[1].Readable = true
	x.face.Regions = append(x.face.Regions,
		nativeproof.RelativeRegion{Bytes: nativeproof.RelativeSpan{Start: -48, End: -44}, Writable: true},
		nativeproof.RelativeRegion{Bytes: nativeproof.RelativeSpan{Start: -40, End: -32}, Writable: true})
	limits := nativeproof.TransitionLimits{RelationLimits: nativeproof.RelationLimits{Work: 8_000_000, Nodes: 131072}}
	proposal, err := nativeproof.ProposeTransition(t.Context(), image, body.Prefix.Entry, limits, nativeproof.TransitionOptions{Expansions: x.expansions})
	if err != nil {
		t.Fatal(err)
	}
	entered, err := nativeproof.CheckTransition(t.Context(), image, x.face, proposal, limits)
	if err != nil {
		t.Fatal("root-to-body entry", err)
	}
	before, _ := entered.BoundFor(image)
	if before.ConditionalRegion || before.Boundary.PC != body.Prefix.Entry || len(before.Frames) != 1 || before.Frames[0].Return != until || before.Registers[nativeproof.RSP].Pointer != (nativeproof.OriginPointer{Origin: before.Origin, Offset: -56}) || !before.Thread.ContextChanged {
		t.Fatal("selected body entry lacks its actual wrapper activation or root history")
	}
	oldSource, oldNative, oldLayout, oldPairing := proof.source, proof.native, proof.layout, proof.paired
	application, err := nativeproof.CheckTransitionActiveReturn(t.Context(), entered, proof.native)
	if err != nil {
		t.Fatal("rooted complete body return", err)
	}
	rooted, err := checkRootedGlobalApplication(t.Context(), proof, application)
	if err != nil || rooted == nil {
		t.Fatal("rooted source/native specialization", err)
	}
	if rooted.correspondence != proof || rooted.application != application || len(rooted.inputs) != len(proof.inputs) {
		t.Fatal("rooted specialization lost its exact owners or input population")
	}
	if proof.source != oldSource || proof.native != oldNative || proof.layout != oldLayout || proof.paired != oldPairing {
		t.Fatal("rooted application replaced the original correspondence scope")
	}
	requireScopedStorageModel(t, proof)
	a, ok := application.BoundFor(image)
	if !ok || !application.AppliesTo(proof.native) || a.StackShift != -56 || a.ChildEntry.Boundary.ID != before.Boundary.ID || a.Successor.ConditionalRegion || a.Successor.Entry != before.Entry || a.Successor.Origin != before.Origin || a.Successor.EntryPredicate != before.EntryPredicate || a.Successor.InitialRegisters != before.InitialRegisters || a.Successor.InitialVectors != before.InitialVectors || a.Successor.InitialDirection != before.InitialDirection || a.Successor.InitialFS != before.InitialFS || !reflect.DeepEqual(a.Successor.Interface, before.Interface) {
		t.Fatal("rooted application lost exact body or original entry dependencies")
	}
	inputBuilder := br.NewBuilder(65536)
	for i, input := range rooted.inputs {
		original := proof.inputs[i]
		footprint, found := proof.layout.locationFootprint(original.location)
		if !found || !footprint.Image || input.index != i || input.native.Sort() != original.native.Sort() || input.source.Sort() != original.source.Sort() {
			t.Fatal("rooted input changed its original identity, selected width or storage")
		}
		current, err := storageNativeWord(t.Context(), inputBuilder, a.ChildEntry.Memory, nativeproof.TransitionLocation{Image: true, Offset: footprint.Bytes.Start}, int(footprint.Bytes.End-footprint.Bytes.Start))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := br.Prove(t.Context(), input.native, current, br.Limits{}); err != nil {
			t.Fatal("rooted input substituted initial source values for actual current native bytes", err)
		}
	}
	end := a.Successor
	if end.Boundary.PC != until || end.Boundary.Context != 0 || len(end.Frames) != 0 || end.Registers[nativeproof.RSP].Pointer != (nativeproof.OriginPointer{Origin: before.Origin, Offset: -48}) || end.Thread != before.Thread || end.Direction != before.Direction || !end.SSE.MXCSRPreserved || !end.SSE.UpperVectorsPreserved {
		t.Fatal("complete body failed to discharge the wrapper activation with preserved current context")
	}
	if len(end.PrimitiveEffects) != len(before.PrimitiveEffects)+10 || !reflect.DeepEqual(end.PrimitiveEffects[:len(before.PrimitiveEffects)], before.PrimitiveEffects) || !reflect.DeepEqual(end.Abstractions, before.Abstractions) || len(end.Accesses) <= len(before.Accesses) || !reflect.DeepEqual(end.Accesses[:len(before.Accesses)], before.Accesses) {
		t.Fatal("rooted specialization erased preceding CPU/TLS/wrapper effects")
	}
	// The completed body releases its private locals. Only its retained write
	// footprint may differ; startup spills, context words and the outer control
	// word remain concrete and unchanged, not reconstructed from source zeros.
	writes := []storageFootprint{{Bytes: nativeproof.RelativeSpan{Start: -144, End: -56}}}
	for _, binding := range proof.representation.bindings {
		if binding.object.kind == regionGlobal {
			footprint, _ := proof.layout.objectFootprint(binding.object)
			writes = append(writes, footprint)
		}
	}
	if err := selectedStartupMemoryFrame(before.Memory, end.Memory, writes); err != nil {
		t.Fatal(err)
	}
	mapping := map[nativeproof.TransitionOccurrenceID]nativeproof.TransitionOccurrenceID{}
	actual := map[nativeproof.TransitionOccurrenceID]bool{}
	for _, association := range a.Occurrences {
		if association.Input == 0 || association.Current == 0 || mapping[association.Input] != 0 || actual[association.Current] {
			t.Fatal("rooted occurrence embedding is not injective")
		}
		mapping[association.Input], actual[association.Current] = association.Current, true
	}
	if len(mapping) != len(body.Instructions)+len(body.Prefix.ExcludedBoundaries) || mapping[body.Instructions[0].ID] != before.Boundary.ID || actual[end.Boundary.ID] {
		t.Fatal("rooted occurrence account omits body coverage or borrows the parent continuation")
	}
	last := body.Instructions[len(body.Instructions)-1]
	successor, _ := application.Successor()
	ret, err := successor.InstructionAt(t.Context(), mapping[last.ID])
	if err != nil || ret.Op != x86asm.RET {
		t.Fatal("body return occurrence did not map to the actual returned invocation", err)
	}
	groups := map[nativeproof.TransitionOccurrenceID]globalFunctionNativeAtomic{}
	for _, effect := range end.PrimitiveEffects {
		if group, ok := globalFunctionNativeGroup(effect); ok {
			groups[group.id] = group
		}
	}
	for _, pair := range proof.atomics {
		input, ok := globalFunctionNativeGroup(pair.native)
		current, found := groups[mapping[input.id]]
		if !ok || !found || current.kind != input.kind || current.width != input.width || current.write != current.read+1 {
			t.Fatal("source atomic occurrence lost its rooted native kind, width or indivisible group")
		}
	}
	if len(groups) != 10 {
		t.Fatal("rooted body has an unaccounted atomic occurrence")
	}
	t.Logf("complete selected source/native body applies from ELF root %#x through actual wrapper return %#x; exact source/model scope, ten atomic groups, startup effects and residual state retained; process/compiler/use/harness obligations remain", before.Entry, until)
	assertSelectedStartupWordTransfer(t, raw, image, successor, locations)
	assertSelectedStartupWordPermissions(t, raw, image, x.face, proposal, limits, proof.native)
}
