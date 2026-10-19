package closure

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

// The source deliberately has two distinct calls, not a source loop. This tests
// the complete-function consumer of native occurrence evidence independently of
// source-loop transport and of actual-runtime caller integration.
func globalOccurrenceSource(t *testing.T) (computationSource, *sourceReturnCompletion, [2]*ssa.Global) {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod": "module example.com/occurrenceeffects\n\ngo 1.27\n",
		"word.go": `package p
var Cell, Other uint64
//go:noescape
func Store(p *uint64, value uint64)
func F() {
 Cell=7; Other=9
 Store(&Cell,9)
 Store(&Cell,9)
}
`,
		"word_amd64.s": `#include "textflag.h"
TEXT ·Store(SB),NOSPLIT,$0-16
 MOVQ p+0(FP),BX
 MOVQ value+8(FP),AX
 XCHGQ AX,0(BX)
 RET
`,
	})
	source := assemblyReferenceSelectedSource(t, dir)
	target := source.prog.Roots["Store"]
	packet := assemblyReferenceSelectedPacket(t, source, target)
	reference, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
	if err != nil {
		t.Fatal(err)
	}
	root := source.prog.Roots["F"]
	var calls []*ssa.Call
	var returned *ssa.Return
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok && call.Call.StaticCallee() == target {
				calls = append(calls, call)
			}
			if ret, ok := instruction.(*ssa.Return); ok {
				returned = ret
			}
		}
	}
	if len(calls) != 2 || returned == nil {
		t.Fatal("fixture lost its two unrolled selected calls and return")
	}
	prefix, err := checkSourceOperandPrefix(t.Context(), source, root, calls[0], defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	references := map[*ssa.Function]*assemblyReference{target: reference}
	next, err := checkSourceOperandContinuation(t.Context(), prefix, calls[1], references)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := checkSourceReturnContinuation(t.Context(), next, returned, references)
	if err != nil {
		t.Fatal(err)
	}
	return source, complete, [2]*ssa.Global{root.Pkg.Members["Cell"].(*ssa.Global), root.Pkg.Members["Other"].(*ssa.Global)}
}

func globalOccurrenceNative(t *testing.T, iterations int) (globalNativeFixture, nativeproof.TransitionOptions, uint64) {
	t.Helper()
	const base, data = uint64(0x401000), uint64(0x700000)
	addresses := [2]uint64{data + 8, data + 80}
	f := globalNativeImage(t, addresses, [3]uint64{7, 9, 9}, addresses[0], data, nil, "")
	code := []byte{0xc3, 0x55, 0x48, 0x89, 0xe5} // separate image entry; PUSH RBP; MOV RBP,RSP
	pc := func() uint64 { return base + uint64(len(code)) }
	mov := func(register byte, value uint64) {
		code = append(code, 0x48, 0xb8+register)
		code = binary.LittleEndian.AppendUint64(code, value)
	}
	store := func(address uint64) {
		at := pc()
		code = append(code, 0x48, 0x89, 0x05)
		code = binary.LittleEndian.AppendUint32(code, uint32(int64(address)-int64(at+7)))
	}
	mov(0, 7)
	store(addresses[0])
	mov(0, 9)
	store(addresses[1])
	at := pc()
	code = append(code, 0x48, 0x8d, 0x0d) // LEA RCX,[Cell]
	code = binary.LittleEndian.AppendUint32(code, uint32(int64(addresses[0])-int64(at+7)))
	mov(2, 0) // RDX is a constant-derived loop counter, not an entry assumption.
	loop := pc()
	mov(0, 9) // Discard the previous exchange's scalar result, retaining its RMW.
	atomicPC := pc()
	code = append(code, 0x48, 0x87, 0x01)                   // XCHG [RCX],RAX
	code = append(code, 0x48, 0xff, 0xc2)                   // INC RDX
	code = append(code, 0x48, 0x83, 0xfa, byte(iterations)) // CMP RDX,iterations
	at = pc()
	code = append(code, 0x72, byte(int64(loop)-int64(at+2))) // JB loop
	code = append(code, 0x5d)                                // POP RBP
	f.cut = pc()
	code = append(code, 0xc3)
	copy(f.raw[4096:], code)
	binary.LittleEndian.PutUint64(f.raw[64+32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(f.raw[64+40:], uint64(len(code)))
	var err error
	f.image, err = nativeproof.NewImage(t.Context(), f.raw)
	if err != nil {
		t.Fatal(err)
	}
	f.face.Regions = []nativeproof.RelativeRegion{{Bytes: nativeproof.RelativeSpan{Start: -8, End: 0}, Readable: true, Writable: true}, {Bytes: nativeproof.RelativeSpan{Start: 0, End: 8}, Readable: true}}
	f.face.ReturnContext = &nativeproof.TransitionReturnContext{Target: base, Preserved: []nativeproof.Register{nativeproof.RBP}}
	f.face.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: nativeproof.RelativeSpan{Start: -8, End: 0}}
	f.face.Conditions.LockedMemory = nativeproof.LockedMemoryModel
	// Eight setup instructions, five per iteration and one epilogue instruction.
	// Discovery's bound is not an asserted execution count: the checker must prove
	// every remaining supported frontier unreachable from the actual entry state.
	options := nativeproof.TransitionOptions{MaxOccurrences: 8 + 5*iterations + 1}
	decode := globalCandidateDecoder(t, f.raw)
	for at := f.entry; at < f.cut; {
		i := decode(at)
		if nativeproof.TransitionExpansionRequired(i) {
			options.Expansions = append(options.Expansions, nativeproof.TransitionExpansion{PC: at})
		}
		at += uint64(i.Len)
	}
	return f, options, atomicPC
}

func TestGlobalFunctionOccurrenceCorrespondence(t *testing.T) {
	if testing.Short() {
		t.Skip("captures selected assembly reference actions")
	}
	source, complete, globals := globalOccurrenceSource(t)
	for _, iterations := range []int{2, 1, 3} {
		t.Run(fmt.Sprintf("native-iterations-%d", iterations), func(t *testing.T) {
			fixture, options, atomicPC := globalOccurrenceNative(t, iterations)
			proposal, err := nativeproof.ProposeRegionTransition(t.Context(), fixture.image, fixture.entry, fixture.cut, nativeproof.TransitionLimits{}, options)
			if err != nil {
				t.Fatal(err)
			}
			prefix, err := nativeproof.CheckRegionTransition(t.Context(), fixture.image, fixture.entry, fixture.face, proposal, nativeproof.TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			returned, err := nativeproof.CheckTransitionReturn(t.Context(), prefix)
			if err != nil {
				t.Fatal(err)
			}
			bound, ok := returned.BoundFor(fixture.image)
			if !ok || len(bound.Prefix.PrimitiveEffects) != iterations {
				t.Fatalf("lost repeated primitive effects: bound=%v effects=%d", ok, len(bound.Prefix.PrimitiveEffects))
			}
			assertConstant := func(term br.Term, value uint64) {
				t.Helper()
				want, err := br.NewBuilder(1).Const(term.Sort(), value)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := br.Prove(t.Context(), term, want, br.Limits{}); err != nil {
					t.Fatalf("expected %d: %v", value, err)
				}
			}
			ids := map[nativeproof.TransitionOccurrenceID]bool{}
			lastWrite := -1
			for index, primitive := range bound.Prefix.PrimitiveEffects {
				effect, ok := primitive.(nativeproof.LockedExchange64Effect)
				if !ok || effect.PC != atomicPC || effect.Context != 0 || effect.ID == 0 || ids[effect.ID] {
					t.Fatal("same-PC, same-activation exchanges lost distinct owned identities")
				}
				ids[effect.ID] = true
				if _, err := returned.InstructionAt(t.Context(), effect.ID); err != nil {
					t.Fatal(err)
				}
				found := false
				for _, instruction := range bound.Instructions {
					if instruction.ID == effect.ID {
						found = instruction.Start == atomicPC && instruction.Context == 0
						assertConstant(instruction.Guard, 1)
					}
				}
				if !found || effect.ReadAccess <= lastWrite || effect.WriteAccess != effect.ReadAccess+1 || effect.WriteAccess >= len(bound.Accesses) {
					t.Fatal("exchange is not a coexecuted ordered indivisible occurrence")
				}
				read, write := bound.Accesses[effect.ReadAccess], bound.Accesses[effect.WriteAccess]
				if read.ID != effect.ID || write.ID != effect.ID || read.Kind != nativeproof.FrameRead || write.Kind != nativeproof.FrameWrite {
					t.Fatal("accesses lost exact atomic owner or read/write order")
				}
				old := uint64(9)
				if index == 0 {
					old = 7
				}
				assertConstant(read.Value, old)
				assertConstant(write.Value, 9)
				lastWrite = effect.WriteAccess
			}
			// All variants return the same represented bytes. Only the number of
			// locked events differs: an unchanged write is still an observable RMW.
			for _, address := range []uint64{0x700008, 0x700050} {
				word, err := globalNativeWord(t.Context(), br.NewBuilder(128), bound.State.Memory, address)
				if err != nil {
					t.Fatal(err)
				}
				assertConstant(word, 9)
			}
			rho := globalRho(source, fixture, globals, [2]uint64{0x700008, 0x700050})
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, complete, returned, rho, nil)
			if iterations != 2 {
				want := "ordered source/native effects differ"
				if iterations == 3 {
					want = "native computation has an unmatched effect"
				}
				if err == nil || proof != nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("missing/extra RMW must refuse at effect correspondence despite equal final bytes: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(proof.atomics) != 2 || len(proof.traces) != 2 || len(proof.matched) != 6 || len(proof.eliminated) != 0 {
				t.Fatal("complete source phases or repeated native effects were collapsed")
			}
			for index, atomic := range proof.atomics {
				if atomic.source.atomic.Kind != x86asm.XCHG || atomic.source.application == nil || atomic.source.atomic.Statement < 0 {
					t.Fatal("selected assembly call/statement provenance was lost")
				}
				if atomic.native.(nativeproof.LockedExchange64Effect).ID != bound.Prefix.PrimitiveEffects[index].(nativeproof.LockedExchange64Effect).ID {
					t.Fatal("source call matched a different native iteration")
				}
			}
			if proof.atomics[0].source.application.at == proof.atomics[1].source.application.at {
				t.Fatal("distinct unrolled source calls were collapsed")
			}
			// This is a detached projection probe, never an authorizing certificate.
			// Borrowing the other iteration's ID leaves PC and activation unchanged.
			first := bound.Prefix.PrimitiveEffects[0].(nativeproof.LockedExchange64Effect)
			second := bound.Prefix.PrimitiveEffects[1].(nativeproof.LockedExchange64Effect)
			second.ID = first.ID
			bound.Prefix.PrimitiveEffects[1] = second
			probe := *proof
			if err := probe.checkEffects(t.Context(), bound); err == nil || !strings.Contains(err.Error(), "atomic accesses have another") {
				t.Fatalf("atomic accepted another same-PC iteration's identity: %v", err)
			}
			// A discovery cutoff before the second RMW is not termination.
			options.MaxOccurrences = 8 + 5 + 1
			short, err := nativeproof.ProposeRegionTransition(t.Context(), fixture.image, fixture.entry, fixture.cut, nativeproof.TransitionLimits{}, options)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := nativeproof.CheckRegionTransition(t.Context(), fixture.image, fixture.entry, fixture.face, short, nativeproof.TransitionLimits{}); err == nil || !strings.Contains(err.Error(), "transition-frontier") {
				t.Fatalf("feasible bounded frontier accepted as a completed loop: %v", err)
			}
		})
	}
}
