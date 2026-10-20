package closure

import (
	"errors"
	"reflect"
	"runtime"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

func TestRuntimeStartupSelectedClear(t *testing.T) {
	if testing.Short() {
		t.Skip("checks the selected compiler's rooted direction and vector initialization")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected startup model is Linux amd64")
	}
	raw, image, x := selectedStartupFixture(t)
	// A new original root declares SSE applicability before any continuation.
	// The narrower startup certificate cannot acquire that premise afterward.
	x.face.Conditions.SSE = nativeproof.SSEModel
	root, err := checkSelectedStartupRoot(t.Context(), image, x, x.cut)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := root.BoundFor(image)
	decode := globalCandidateDecoder(t, raw)
	cld := decode(x.cut)
	callPC := x.cut + uint64(cld.Len)
	call := decode(callPC)
	rel, direct := call.Args[0].(x86asm.Rel)
	if cld.Op != x86asm.CLD || call.Op != x86asm.CALL || !direct {
		t.Fatal("selected direction clear is not followed by a direct wrapper call")
	}
	wrapperPC := uint64(int64(callPC) + int64(call.Len) + int64(rel))
	xor := decode(wrapperPC)
	if xor.Op != x86asm.XORPS || xor.Args[0] != x86asm.X15 || xor.Args[1] != x86asm.X15 {
		t.Fatal("selected wrapper does not start with its actual legacy vector clear")
	}
	nextPC := wrapperPC + uint64(xor.Len)
	continueAt := func(prior nativeproof.TransitionCertificate, cut, expansion uint64) nativeproof.TransitionCertificate {
		t.Helper()
		proposal, err := nativeproof.ProposeTransitionContinuation(t.Context(), prior, cut, nativeproof.TransitionOptions{Expansions: []nativeproof.TransitionExpansion{{PC: expansion, AllActivations: true}}})
		if err != nil {
			t.Fatal(err)
		}
		result, err := nativeproof.CheckTransitionContinuation(t.Context(), prior, proposal)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	cleared := continueAt(root, callPC, x.cut)
	c, _ := cleared.BoundFor(image)
	if c.ConditionalRegion || c.Entry != before.Entry || c.Origin != before.Origin || c.InitialDirection != before.InitialDirection || c.InitialDirection.Sort() != br.Bool() || c.InitialDirection.View().Op != br.Variable || c.InitialRegisters != before.InitialRegisters || c.InitialVectors != before.InitialVectors || !reflect.DeepEqual(c.Interface, before.Interface) {
		t.Fatal("CLD continuation changed original rooted inputs or assumed clear entry")
	}
	b := br.NewBuilder(8)
	zero, _ := b.Const(br.Bool(), 0)
	if _, err := br.Prove(t.Context(), c.Direction, zero, br.Limits{}); err != nil {
		t.Fatal("rooted CLD did not establish clear direction", err)
	}
	if c.Flags != before.Flags || c.Registers != before.Registers || c.Vectors != before.Vectors || c.SSE != before.SSE || c.Thread != before.Thread || !reflect.DeepEqual(c.PrimitiveEffects, before.PrimitiveEffects) || !reflect.DeepEqual(c.Accesses, before.Accesses) || !reflect.DeepEqual(c.Frames, before.Frames) {
		t.Fatal("CLD changed another architectural component or erased earlier effects")
	}
	if err := selectedStartupMemoryFrame(before.Memory, c.Memory, nil); err != nil {
		t.Fatal(err)
	}
	entered := continueAt(cleared, wrapperPC, callPC)
	w, _ := entered.BoundFor(image)
	if len(w.Frames) != 1 || w.Frames[0].Call != callPC || w.Frames[0].Return != callPC+uint64(call.Len) || w.Frames[0].Slot != (nativeproof.OriginPointer{Origin: w.Origin, Offset: -56}) || w.Boundary.Context != w.Frames[0].Context || w.Registers[nativeproof.RSP].Pointer != w.Frames[0].Slot || w.Direction != c.Direction || w.InitialDirection != c.InitialDirection {
		t.Fatal("actual wrapper call lost its continuation, shifted origin or current direction")
	}
	if len(w.Instructions) != len(c.Instructions)+1 || !reflect.DeepEqual(w.Instructions[:len(c.Instructions)], c.Instructions) || len(w.Accesses) != len(c.Accesses)+1 || !reflect.DeepEqual(w.Accesses[:len(c.Accesses)], c.Accesses) || w.Flags != c.Flags || w.Vectors != c.Vectors || w.SSE != c.SSE || w.Thread != c.Thread || !reflect.DeepEqual(w.PrimitiveEffects, c.PrimitiveEffects) || !reflect.DeepEqual(w.Abstractions, c.Abstractions) || !reflect.DeepEqual(w.ExcludedBoundaries, c.ExcludedBoundaries) {
		t.Fatal("actual wrapper call changed unrelated context or prior effect history")
	}
	for register, value := range w.Registers {
		if nativeproof.Register(register) != nativeproof.RSP && (value != c.Registers[register] || w.Preserved[register] != c.Preserved[register]) {
			t.Fatal("actual wrapper call changed a non-stack register")
		}
	}
	control := w.Accesses[len(c.Accesses)]
	if control.ID != w.Frames[0].ID || control.Context != c.Boundary.Context || control.PC != callPC || control.Image || control.Kind != nativeproof.FrameWrite || control.Bytes != (nativeproof.RelativeSpan{Start: -56, End: -48}) {
		t.Fatal("actual wrapper CALL lacks its exact control-word write")
	}
	if err := selectedStartupMemoryFrame(c.Memory, w.Memory, []storageFootprint{{Bytes: control.Bytes}}); err != nil {
		t.Fatal(err)
	}
	controlBuilder := br.NewBuilder(32)
	continuation, _ := controlBuilder.Const(br.Bits(64), callPC+uint64(call.Len))
	word, err := storageNativeWord(t.Context(), controlBuilder, w.Memory, nativeproof.TransitionLocation{Offset: -56}, 8)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []br.Term{control.Value, word} {
		if _, err := br.Prove(t.Context(), value, continuation, br.Limits{}); err != nil {
			t.Fatal("actual wrapper control bytes differ from the decoded continuation", err)
		}
	}
	eight, _ := controlBuilder.Const(br.Bits(64), 8)
	stack, _ := controlBuilder.Make(br.Sub, br.Bits(64), 0, c.Registers[nativeproof.RSP].Value, eight)
	if _, err := br.Prove(t.Context(), w.Registers[nativeproof.RSP].Value, stack, br.Limits{}); err != nil {
		t.Fatal("actual wrapper CALL has another stack-value transfer", err)
	}
	complete := continueAt(entered, nextPC, wrapperPC)
	after, _ := complete.BoundFor(image)
	if after.ConditionalRegion || after.Entry != before.Entry || after.Origin != before.Origin || after.InitialDirection != before.InitialDirection || after.Direction != w.Direction || after.InitialRegisters != before.InitialRegisters || after.InitialVectors != before.InitialVectors || !reflect.DeepEqual(after.Interface, before.Interface) {
		t.Fatal("wrapper vector clear substituted a new entry or context")
	}
	if after.Boundary.PC != nextPC || after.Boundary.Instruction.Op != x86asm.MOV || after.Registers != w.Registers || after.Flags != w.Flags || after.Thread != w.Thread || after.SSE != w.SSE || !after.SSE.MXCSRPreserved || !after.SSE.UpperVectorsPreserved || !reflect.DeepEqual(after.PrimitiveEffects, w.PrimitiveEffects) || !reflect.DeepEqual(after.Accesses, w.Accesses) || !reflect.DeepEqual(after.Frames, w.Frames) {
		t.Fatal("XORPS changed flags, ordinary memory, active continuation or implicit context")
	}
	reload := after.Boundary.Instruction
	if memory, ok := reload.Args[1].(x86asm.Mem); !ok || reload.Args[0] != x86asm.R14 || reload.MemBytes != 8 || reload.AddrSize != 64 || memory.Segment != x86asm.FS || memory.Base != 0 || memory.Index != 0 || memory.Disp != -8 {
		t.Fatal("following unexecuted boundary is not the actual FS-relative TLS reload")
	}
	if err := selectedStartupMemoryFrame(w.Memory, after.Memory, nil); err != nil {
		t.Fatal(err)
	}
	wordZero, _ := b.Const(br.Bits(64), 0)
	for register, vector := range after.Vectors {
		if register != 15 {
			if vector != w.Vectors[register] {
				t.Fatal("XORPS changed another vector register")
			}
			continue
		}
		for _, lane := range []br.Term{vector.Lo, vector.Hi} {
			if _, err := br.Prove(t.Context(), lane, wordZero, br.Limits{}); err != nil {
				t.Fatal("selected vector clear left nonzero low-128 bits", err)
			}
		}
	}
	missing := x
	missing.face.Conditions.SSE = ""
	missing.expansions = append(append([]nativeproof.TransitionExpansion(nil), x.expansions...), nativeproof.TransitionExpansion{PC: x.cut, AllActivations: true}, nativeproof.TransitionExpansion{PC: callPC, AllActivations: true}, nativeproof.TransitionExpansion{PC: wrapperPC, AllActivations: true})
	bad, err := checkSelectedStartupRoot(t.Context(), image, missing, nextPC)
	var refusal *nativeproof.Refusal
	if _, accepted := bad.Bound(); accepted || !errors.As(err, &refusal) || refusal.Premise != "transition-sse-premise" {
		t.Fatalf("wrapper acquired missing original SSE applicability: %v", err)
	}
	t.Logf("rooted CLD %#x and actual CALL %#x establish DF=0 and XMM15=0 through legacy XORPS %#x; wrapper continuation, prior FS history and root inputs retained; following TLS reload and callee association remain open", x.cut, callPC, wrapperPC)
}
