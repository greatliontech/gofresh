package closure

import (
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

// This cut covers the first actual loop header, not a completed loop. Discovery
// selects the first backward signed branch; the checked continuation reconstructs
// the prefix from its original caller root and keeps that branch unexecuted.
func selectedCheckFirstLoopCut(t testing.TB, raw []byte, image *nativeproof.Image, application nativeproof.TransitionCallCertificate) nativeproof.TransitionCertificate {
	t.Helper()
	prior, ok := application.Successor()
	if !ok {
		t.Fatal("missing actual-call successor")
	}
	b, ok := prior.BoundFor(image)
	if !ok {
		t.Fatal("caller successor belongs to another image")
	}
	decode := globalCandidateDecoder(t, raw)
	var expansions []nativeproof.TransitionExpansion
	pc := b.Boundary.PC
	var cut uint64
	for count := 0; count < 32; count++ {
		i := decode(pc)
		if rel, direct := i.Args[0].(x86asm.Rel); direct && i.Op == x86asm.JL && rel < 0 {
			cut = pc
			break
		}
		if nativeproof.TransitionExpansionRequired(i) {
			expansions = append(expansions, nativeproof.TransitionExpansion{PC: pc})
		}
		pc += uint64(i.Len)
		if rel, direct := i.Args[0].(x86asm.Rel); direct && i.Op == x86asm.JMP {
			pc = uint64(int64(pc) + int64(rel))
		}
	}
	if cut == 0 {
		t.Fatal("selected artifact lacks the candidate first loop branch")
	}
	proposal, err := nativeproof.ProposeTransitionContinuation(t.Context(), prior, cut, nativeproof.TransitionOptions{Expansions: expansions})
	if err != nil {
		t.Fatal(err)
	}
	checked, err := nativeproof.CheckTransitionContinuation(t.Context(), prior, proposal)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := checked.Bound()
	constants := br.NewBuilder(16)
	for register, want := range map[nativeproof.Register]uint64{nativeproof.RAX: 0, nativeproof.RCX: 0, nativeproof.RDX: 1, nativeproof.RSI: 0xffffffff} {
		value := after.Registers[register].Value
		expected, err := constants.Make(br.Constant, br.Bits(64), want)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := br.Prove(t.Context(), value, expected, br.Limits{}); err != nil {
			t.Fatalf("first header register %d differs from %#x: %v", register, want, err)
		}
	}
	if after.Entry != b.Entry || after.Origin != b.Origin || after.EntryPredicate != b.EntryPredicate || after.InitialRegisters != b.InitialRegisters || after.InitialVectors != b.InitialVectors || after.Registers[nativeproof.RSP].Pointer != b.Registers[nativeproof.RSP].Pointer || after.Vectors != b.Vectors || after.SSE != b.SSE || !reflect.DeepEqual(after.Memory, b.Memory) || !reflect.DeepEqual(after.Frames, b.Frames) || len(after.Accesses) != len(b.Accesses) || len(after.PrimitiveEffects) != len(b.PrimitiveEffects) {
		t.Fatal("scalar header changed original scope, frame, memory effects or vector context")
	}
	t.Logf("actual first loop branch=%#x instructions=%d accesses=%d primitives=%d; backedge remains unexecuted", cut, len(after.Instructions), len(after.Accesses), len(after.PrimitiveEffects))
	return checked
}
