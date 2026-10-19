package closure

import (
	"encoding/binary"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

func TestGlobalFunctionAtomicRejectsNarrowNativeCAS(t *testing.T) {
	// Source correspondence still consumes the uint64 assembly relation. A
	// native four-byte CAS has different memory and accumulator semantics even
	// when all currently known scalar values fit in uint32.
	for _, width := range []int{0, 1, 4, 8, 16} {
		e := nativeproof.LockedCompareExchangeEffect{Width: width}
		_, accepted := globalFunctionNativeGroup(e)
		if accepted != (width == 8) {
			t.Fatalf("source64 correspondence admitted native width %d: %v", width, accepted)
		}
	}
	if _, accepted := globalFunctionNativeGroup(nativeproof.LockedLogicalEffect{Width: 1, Kind: x86asm.OR}); accepted {
		t.Fatal("source64 correspondence admitted byte logical effect")
	}
}

func globalFunctionAtomicSource(t *testing.T) (computationSource, *sourceReturnCompletion, [2]*ssa.Global) {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod": "module example.com/completeeffects\n\ngo 1.27\n",
		"word.go": `package p
var Cell, Other uint64
//go:noescape
func Store(p *uint64, value uint64)
//go:noescape
func Add(p *uint64, delta int64) uint64
//go:noescape
func Exchange(p *uint64, value uint64) uint64
func Load(p *uint64) uint64 { return *p }
func F() {
 Cell=7; Other=9
 Store(&Cell,9)
 if Load(&Cell)!=9 { panic("store") }
 if Add(&Cell,-1)!=8 { panic("add") }
 _ = Exchange(&Cell,4)
 if Cell!=4 { panic("exchange") }
}
`,
		"word_amd64.s": `#include "textflag.h"
TEXT ·Store(SB),NOSPLIT,$0-16
 MOVQ p+0(FP),BX
 MOVQ value+8(FP),AX
 XCHGQ AX,0(BX)
 RET
TEXT ·Add(SB),NOSPLIT,$0-24
 MOVQ p+0(FP),BX
 MOVQ delta+8(FP),AX
 MOVQ AX,CX
 LOCK
 XADDQ AX,0(BX)
 ADDQ CX,AX
 MOVQ AX,ret+16(FP)
 RET
TEXT ·Exchange(SB),NOSPLIT,$0-24
 MOVQ p+0(FP),BX
 MOVQ value+8(FP),AX
 XCHGQ AX,0(BX)
 MOVQ AX,ret+16(FP)
 RET
`,
	})
	source := assemblyReferenceSelectedSource(t, dir)
	packet := assemblyReferenceSelectedPacket(t, source, source.prog.Roots["Store"])
	references := map[*ssa.Function]*assemblyReference{}
	for _, name := range []string{"Store", "Add", "Exchange"} {
		target := source.prog.Roots[name]
		ref, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
		if err != nil {
			t.Fatal(err)
		}
		references[target] = ref
	}
	root := source.prog.Roots["F"]
	var first, middle *ssa.Call
	var returned *ssa.Return
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok {
				switch call.Call.StaticCallee() {
				case source.prog.Roots["Store"]:
					first = call
				case source.prog.Roots["Add"]:
					middle = call
				}
			}
			if ret, ok := instruction.(*ssa.Return); ok {
				returned = ret
			}
		}
	}
	prefix, err := checkSourceOperandPrefix(t.Context(), source, root, first, defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	next, err := checkSourceOperandContinuation(t.Context(), prefix, middle, references)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := checkSourceReturnContinuation(t.Context(), next, returned, references)
	if err != nil {
		t.Fatal(err)
	}
	return source, complete, [2]*ssa.Global{root.Pkg.Members["Cell"].(*ssa.Global), root.Pkg.Members["Other"].(*ssa.Global)}
}

func globalFunctionAtomicNative(t testing.TB, variant string) (globalNativeFixture, nativeproof.TransitionReturnCertificate) {
	t.Helper()
	const base, data = uint64(0x401000), uint64(0x700000)
	addresses := [2]uint64{data + 8, data + 80}
	f := globalNativeImage(t, addresses, [3]uint64{7, 9, 4}, addresses[0], data, nil, "")
	code := []byte{0xc3, 0x55, 0x48, 0x89, 0xe5}
	pc := func() uint64 { return base + uint64(len(code)) }
	mov := func(value uint64) {
		code = append(code, 0x48, 0xb8)
		code = binary.LittleEndian.AppendUint64(code, value)
	}
	store := func(address uint64) {
		at := pc()
		code = append(code, 0x48, 0x89, 0x05)
		code = binary.LittleEndian.AppendUint32(code, uint32(int64(address)-int64(at+7)))
	}
	mov(7)
	store(addresses[0])
	mov(9)
	store(addresses[1])
	at := pc()
	code = append(code, 0x48, 0x8d, 0x0d)
	code = binary.LittleEndian.AppendUint32(code, uint32(int64(addresses[0])-int64(at+7)))
	code = append(code, 0x48, 0x87, 0x01) // XCHG [RCX],RAX: Store's indivisible effect
	mov(^uint64(0))
	switch variant {
	case "wrong-kind":
		mov(8)
		code = append(code, 0x48, 0x87, 0x01) // same values, wrong primitive
	case "split-group":
		code = append(code, 0x48, 0x8b, 0x11) // read same old value without indivisibility
		mov(8)
		code = append(code, 0x48, 0x89, 0x01)
	default:
		code = append(code, 0xf0, 0x48, 0x0f, 0xc1, 0x01) // LOCK XADD [RCX],RAX
	}
	// Deliberately omit Add's returned-value ADD. This root is void; its complete
	// source checks resolve under the established heap, and native has no live
	// exceptional branch. The effect-only correspondence contract does not require
	// this dead scalar result to survive optimization.
	mov(4)
	code = append(code, 0x48, 0x87, 0x01, 0x5d)
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
	decode := globalCandidateDecoder(t, f.raw)
	var expansions []nativeproof.TransitionExpansion
	for at := f.entry; at < f.cut; {
		i := decode(at)
		if nativeproof.TransitionExpansionRequired(i) {
			expansions = append(expansions, nativeproof.TransitionExpansion{PC: at})
		}
		at += uint64(i.Len)
	}
	proposal, err := nativeproof.ProposeRegionTransition(t.Context(), f.image, f.entry, f.cut, nativeproof.TransitionLimits{}, nativeproof.TransitionOptions{Expansions: expansions})
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := nativeproof.CheckRegionTransition(t.Context(), f.image, f.entry, f.face, proposal, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	returned, err := nativeproof.CheckTransitionReturn(t.Context(), prefix)
	if err != nil {
		t.Fatal(err)
	}
	return f, returned
}

func TestGlobalFunctionAtomicGroupingAndDeadResults(t *testing.T) {
	if testing.Short() {
		t.Skip("captures selected assembly reference actions")
	}
	source, complete, globals := globalFunctionAtomicSource(t)
	for _, variant := range []string{"complete", "wrong-kind", "split-group"} {
		t.Run(variant, func(t *testing.T) {
			fixture, returned := globalFunctionAtomicNative(t, variant)
			rho := globalRho(source, fixture, globals, [2]uint64{0x700008, 0x700050})
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, complete, returned, rho, nil)
			if variant != "complete" {
				if err == nil || proof != nil {
					t.Fatal("changed indivisibility/kind admitted despite identical final globals")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(proof.atomics) != 3 || len(proof.traces) != 2 || len(proof.eliminated) != 2 {
				t.Fatal("complete ordered source phases/effects were lost")
			}
			for i, want := range []x86asm.Op{x86asm.XCHG, x86asm.XADD, x86asm.XCHG} {
				if proof.atomics[i].source.atomic.Kind != want || proof.atomics[i].source.application == nil || proof.atomics[i].source.atomic.Statement < 0 {
					t.Fatal("atomic statement/call origin was lost")
				}
			}
		})
	}
}
