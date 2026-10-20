package closure

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

func assertSelectedStartupWordTransfer(t testing.TB, raw []byte, image *nativeproof.Image, prior nativeproof.TransitionCertificate, locations map[string]uint64) {
	t.Helper()
	before, ok := prior.BoundFor(image)
	if !ok || before.ConditionalRegion {
		t.Fatal("startup word transfer lacks its owned ELF-root predecessor")
	}
	decode := globalCandidateDecoder(t, raw)
	cut := before.Boundary.PC
	for range 4 {
		instruction := decode(cut)
		if instruction.Op != x86asm.MOV {
			t.Fatal("selected outgoing-word candidate is not four ordinary moves")
		}
		cut += uint64(instruction.Len)
	}
	call := decode(cut)
	rel, direct := call.Args[0].(x86asm.Rel)
	if !direct || call.Op != x86asm.CALL || uint64(int64(cut)+int64(call.Len)+int64(rel)) != locations["runtime.args.abi0"] {
		t.Fatal("candidate does not end before the selected argument-preparation call")
	}
	proposal, err := nativeproof.ProposeTransitionContinuation(t.Context(), prior, cut)
	if err != nil {
		t.Fatal(err)
	}
	continued, err := nativeproof.CheckTransitionContinuation(t.Context(), prior, proposal)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := continued.BoundFor(image)
	if after.ConditionalRegion || after.Entry != before.Entry || after.Origin != before.Origin || after.EntryPredicate != before.EntryPredicate || after.InitialRegisters != before.InitialRegisters || after.InitialVectors != before.InitialVectors || after.InitialDirection != before.InitialDirection || after.InitialFS != before.InitialFS || !reflect.DeepEqual(after.InitialMemory, before.InitialMemory) || !reflect.DeepEqual(after.Interface, before.Interface) {
		t.Fatal("outgoing-word transfer replaced original entry inputs or permissions")
	}
	if after.Boundary.PC != cut || after.Boundary.Instruction.Op != x86asm.CALL || after.CutGuard != before.CutGuard || after.Flags != before.Flags || after.Direction != before.Direction || after.Thread != before.Thread || after.SSE != before.SSE || after.Vectors != before.Vectors || !reflect.DeepEqual(after.Frames, before.Frames) || !reflect.DeepEqual(after.PrimitiveEffects, before.PrimitiveEffects) || !reflect.DeepEqual(after.Abstractions, before.Abstractions) || !reflect.DeepEqual(after.ExcludedBoundaries, before.ExcludedBoundaries) {
		t.Fatal("outgoing-word moves changed implicit context or executed the following call")
	}
	for register, value := range after.Registers {
		if nativeproof.Register(register) != nativeproof.RAX && (value != before.Registers[register] || after.Preserved[register] != before.Preserved[register]) {
			t.Fatal("outgoing-word moves changed another register")
		}
	}
	if len(after.Instructions) != len(before.Instructions)+4 || !reflect.DeepEqual(after.Instructions[:len(before.Instructions)], before.Instructions) || len(after.Accesses) != len(before.Accesses)+4 || !reflect.DeepEqual(after.Accesses[:len(before.Accesses)], before.Accesses) {
		t.Fatal("outgoing-word transfer lost ordered coverage or access history")
	}
	b := br.NewBuilder(256)
	initial, err := storageNativeWord(t.Context(), b, before.InitialMemory, nativeproof.TransitionLocation{Offset: 0}, 8)
	if err != nil {
		t.Fatal(err)
	}
	count, _ := b.Make(br.Trunc, br.Bits(32), 0, initial)
	eight, _ := b.Const(br.Bits(64), 8)
	vector, _ := b.Make(br.Add, br.Bits(64), 0, before.Origin, eight)
	// The opaque predecessor already proves arrival at its cut under its
	// original machine/domain premises. Each new move must retain that exact
	// reach condition; scalar normalization alone does not encode those premises.
	account := globalFunctionCorrespondence{antecedent: before.CutGuard}
	for i, expected := range []struct {
		kind  nativeproof.AccessKind
		span  nativeproof.RelativeSpan
		value br.Term
	}{
		{nativeproof.FrameRead, nativeproof.RelativeSpan{Start: -24, End: -20}, count},
		{nativeproof.FrameWrite, nativeproof.RelativeSpan{Start: -48, End: -44}, count},
		{nativeproof.FrameRead, nativeproof.RelativeSpan{Start: -16, End: -8}, vector},
		{nativeproof.FrameWrite, nativeproof.RelativeSpan{Start: -40, End: -32}, vector},
	} {
		access := after.Accesses[len(before.Accesses)+i]
		instruction := after.Instructions[len(before.Instructions)+i]
		if access.Image || access.Kind != expected.kind || access.Bytes != expected.span || access.ID != instruction.ID || access.Context != 0 {
			t.Fatal("outgoing-word access lost exact width, order or occurrence")
		}
		if instruction.Guard != before.CutGuard {
			t.Fatal("outgoing-word occurrence changed the proven incoming reach condition")
		}
		if err := account.equal(t.Context(), access.Value, expected.value); err != nil {
			t.Fatalf("outgoing word %d differs from the original entry relation: %v", i, err)
		}
		if expected.kind == nativeproof.FrameWrite {
			value, err := storageNativeWord(t.Context(), b, after.Memory, nativeproof.TransitionLocation{Offset: expected.span.Start}, int(expected.span.End-expected.span.Start))
			if err != nil {
				t.Fatal(err)
			}
			if err := account.equal(t.Context(), value, expected.value); err != nil {
				t.Fatal("outgoing slot did not retain the actual write", err)
			}
		}
	}
	if err := account.equal(t.Context(), after.Registers[nativeproof.RAX].Value, vector); err != nil || after.Registers[nativeproof.RAX].Pointer != (nativeproof.OriginPointer{Origin: before.Origin, Offset: 8}) {
		t.Fatal("reloaded full word lost original-root address provenance", err)
	}
	for _, cell := range after.Memory {
		if !cell.Image && cell.Offset >= -40 && cell.Offset < -32 && (cell.Pointer != after.Registers[nativeproof.RAX].Pointer || cell.PointerLane != uint8(cell.Offset+40)) {
			t.Fatal("outgoing full-word store lost ordered provenance lanes")
		}
	}
	if err := selectedStartupMemoryFrame(before.Memory, after.Memory, []storageFootprint{
		{Bytes: nativeproof.RelativeSpan{Start: -48, End: -44}},
		{Bytes: nativeproof.RelativeSpan{Start: -40, End: -32}},
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("rooted startup reloads original low32 entry word and origin+8 through outgoing slots to unexecuted CALL %#x; process argument/vector interpretation remains open", cut)
}

func assertSelectedStartupWordPermissions(t testing.TB, raw []byte, image *nativeproof.Image, face nativeproof.TransitionInterface, proposal nativeproof.TransitionProposal, limits nativeproof.TransitionLimits, body nativeproof.TransitionReturnCertificate) {
	t.Helper()
	for _, missing := range []string{"spill-read", "outgoing-write"} {
		unavailable := face
		unavailable.Regions = slices.Clone(face.Regions)
		if missing == "spill-read" {
			unavailable.Regions[1].Readable = false
		} else {
			unavailable.Regions = unavailable.Regions[:3]
		}
		entered, err := nativeproof.CheckTransition(t.Context(), image, unavailable, proposal, limits)
		if err != nil {
			t.Fatal("missing-permission control lacks the original rooted body entry", err)
		}
		applied, err := nativeproof.CheckTransitionActiveReturn(t.Context(), entered, body)
		if err != nil {
			t.Fatal("missing-permission control lacks a completed body", err)
		}
		prior, _ := applied.Successor()
		bound, _ := prior.BoundFor(image)
		decode := globalCandidateDecoder(t, raw)
		cut := bound.Boundary.PC
		for range 4 {
			cut += uint64(decode(cut).Len)
		}
		next, err := nativeproof.ProposeTransitionContinuation(t.Context(), prior, cut)
		if err != nil {
			t.Fatal(err)
		}
		result, err := nativeproof.CheckTransitionContinuation(t.Context(), prior, next)
		var refusal *nativeproof.Refusal
		if _, accepted := result.Bound(); accepted || !errors.As(err, &refusal) || refusal.Premise != "transition-permission" {
			t.Fatalf("%s control acquired undeclared permission: %v", missing, err)
		}
	}
}
