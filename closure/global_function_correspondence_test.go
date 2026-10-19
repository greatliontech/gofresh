package closure

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

func globalFunctionSource(t testing.TB) (computationSource, *sourceReturnCompletion, [2]*ssa.Global) {
	t.Helper()
	source := relationFixture(t, `var A,B uint64
func Read(p *uint64) uint64 { return *p }
func F() { A=7; B=9; if Read(&A)!=7 { panic("read") }; A=11 }
`, 64)
	root := source.prog.Roots["F"]
	var call *ssa.Call
	var returned *ssa.Return
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			if c, ok := instruction.(*ssa.Call); ok && c.Call.StaticCallee() != nil {
				call = c
			}
			if r, ok := instruction.(*ssa.Return); ok {
				returned = r
			}
		}
	}
	prefix, err := checkSourceOperandPrefix(t.Context(), source, root, call, defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := checkSourceReturnContinuation(t.Context(), prefix, returned, nil)
	if err != nil {
		t.Fatal(err)
	}
	return source, completed, [2]*ssa.Global{root.Pkg.Members["A"].(*ssa.Global), root.Pkg.Members["B"].(*ssa.Global)}
}

// This fixture is generated from effects, not copied compiler bytes. The native
// result registers intentionally have no relation to the selected Read's return.
// All actual memory accesses and the guarded root RET are nevertheless checked.
func globalFunctionNative(t testing.TB, variant string) (globalNativeFixture, nativeproof.TransitionReturnCertificate) {
	t.Helper()
	const base, data = uint64(0x401000), uint64(0x700000)
	addresses := [2]uint64{data + 8, data + 80}
	f := globalNativeImage(t, addresses, [3]uint64{7, 9, 11}, addresses[0], data, nil, "")
	code := []byte{0xc3}
	pc := func() uint64 { return base + uint64(len(code)) }
	guarded := variant != "unguarded" && variant != "entry-pointer-global"
	var slow int
	if guarded {
		code = append(code, 0x49, 0x3b, 0x66, 0x10) // CMP RSP,[R14+16]
		code = append(code, 0x0f, 0x86)             // JBE slow
		slow = len(code)
		code = append(code, 0, 0, 0, 0)
	}
	code = append(code, 0x55, 0x48, 0x89, 0xe5) // PUSH RBP; MOV RBP,RSP
	mov := func(value uint64) {
		code = append(code, 0x48, 0xb8)
		code = binary.LittleEndian.AppendUint64(code, value)
	}
	store := func(address uint64) {
		at := pc()
		code = append(code, 0x48, 0x89, 0x05)
		code = binary.LittleEndian.AppendUint32(code, uint32(int64(address)-int64(at+7)))
	}
	load := func(address uint64) {
		at := pc()
		code = append(code, 0x48, 0x8b, 0x05)
		code = binary.LittleEndian.AppendUint32(code, uint32(int64(address)-int64(at+7)))
	}
	if variant == "early-read" {
		load(addresses[0])
	}
	mov(7)
	if variant == "matched-conditional-write" {
		code = append(code, 0x48, 0x85, 0xdb, 0x74, 0x07) // TEST RBX,RBX; JE over first matched write
	}
	store(addresses[0])
	mov(9)
	store(addresses[1])
	if variant == "retained-read" {
		load(addresses[0])
	}
	if variant == "extra-write" {
		store(addresses[1])
	}
	if variant == "unrelated-read" {
		load(data + 48)
	}
	if variant == "unrelated-write" {
		store(data + 48)
	}
	if variant == "conditional-write" {
		code = append(code, 0x48, 0x85, 0xdb, 0x74, 0x07) // TEST RBX,RBX; JE over store
		store(addresses[1])
	}
	if variant == "inactive-write" {
		code = append(code, 0x48, 0x85, 0xc0, 0x75, 0x07) // known nonzero; JNE over store
		store(addresses[1])
	}
	if variant == "private-atomic" {
		// A disjoint private slot still carries a real indivisible zero-add
		// ordering effect; restoring context does not erase that primitive.
		mov(0)
		code = append(code, 0xf0, 0x48, 0x0f, 0xc1, 0x44, 0x24, 0xf8)
	}
	if variant == "primitive" {
		code = append(code, 0x0f, 0xa2)
	}
	mov(11)
	if variant == "wrong-value" {
		mov(12)
	}
	store(addresses[0])
	if variant == "escape" {
		code = append(code, 0x48, 0x89, 0xe1)
	} // MOV RCX,RSP
	if variant == "vector-escape" || variant == "vector-private-value" {
		if variant == "vector-escape" {
			code = append(code, 0x48, 0x89, 0x64, 0x24, 0xf8) // MOV [RSP-8],RSP
		} else {
			code = append(code, 0x48, 0x89, 0x44, 0x24, 0xf8) // MOV [RSP-8],RAX (11)
		}
		code = append(code, 0xf2, 0x0f, 0x10, 0x44, 0x24, 0xf8) // MOVSD X0,[RSP-8]
	}
	code = append(code, 0x5d) // POP RBP
	f.cut = pc()
	code = append(code, 0xc3)
	if guarded {
		binary.LittleEndian.PutUint32(code[slow:], uint32(int64(pc())-int64(base+uint64(slow)+4)))
		code = append(code, 0xe8, 0, 0, 0, 0, 0xc3)
	}
	copy(f.raw[4096:], code)
	binary.LittleEndian.PutUint64(f.raw[64+32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(f.raw[64+40:], uint64(len(code)))
	var err error
	f.image, err = nativeproof.NewImage(t.Context(), f.raw)
	if err != nil {
		t.Fatal(err)
	}
	f.face.Regions = []nativeproof.RelativeRegion{{Bytes: nativeproof.RelativeSpan{Start: -8, End: 0}, Readable: true, Writable: true}, {Bytes: nativeproof.RelativeSpan{Start: 0, End: 8}, Readable: true}}
	f.face.ReturnContext = &nativeproof.TransitionReturnContext{Target: base, Preserved: []nativeproof.Register{nativeproof.RBP, nativeproof.R14}}
	f.face.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: nativeproof.RelativeSpan{Start: -8, End: 0}}
	if variant == "private-atomic" || variant == "vector-escape" || variant == "vector-private-value" {
		f.face.Regions[0].Bytes.Start = -16
		f.face.PrivateFrame.Bytes.Start = -16
	}
	if variant == "vector-escape" || variant == "vector-private-value" {
		f.face.Conditions.SSE = nativeproof.SSEModel
	}
	if variant == "missing-private" {
		f.face.PrivateFrame = nil
	}
	if guarded {
		f.face.EntryImagePointers = []nativeproof.TransitionEntryImagePointer{{Register: nativeproof.R14, Address: data + 96}}
		f.face.EntryWordUpperBounds = []nativeproof.TransitionEntryWordUpperBound{{Address: data + 112}}
	}
	if variant == "entry-pointer-global" {
		// A preserved pointer into A restricts register bits only. A's original
		// bytes remain arbitrary and independent of the entry predicate.
		f.face.EntryImagePointers = []nativeproof.TransitionEntryImagePointer{{Register: nativeproof.R14, Address: addresses[0]}}
	}
	if variant == "constrained-global" {
		f.face.EntryWordUpperBounds = append(f.face.EntryWordUpperBounds, nativeproof.TransitionEntryWordUpperBound{Address: addresses[0]})
	}
	f.face.Conditions.LockedMemory = nativeproof.LockedMemoryModel
	if variant == "primitive" {
		f.face.Conditions.CPUID = nativeproof.CPUIDModel
	}
	decode := globalCandidateDecoder(t, f.raw)
	var expansions []nativeproof.TransitionExpansion
	for at := f.entry; at < f.cut; {
		instruction := decode(at)
		if nativeproof.TransitionExpansionRequired(instruction) {
			expansions = append(expansions, nativeproof.TransitionExpansion{PC: at})
		}
		at += uint64(instruction.Len)
	}
	proposal, err := nativeproof.ProposeRegionTransition(t.Context(), f.image, f.entry, f.cut, nativeproof.TransitionLimits{}, expansions...)
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

func TestGlobalFunctionCompleteEffectsAndReturn(t *testing.T) {
	source, completed, globals := globalFunctionSource(t)
	for _, variant := range []string{"guarded", "unguarded", "entry-pointer-global", "retained-read", "inactive-write", "early-read", "extra-write", "unrelated-read", "unrelated-write", "conditional-write", "matched-conditional-write", "primitive", "private-atomic", "wrong-value", "escape", "vector-escape", "vector-private-value", "missing-private", "constrained-global"} {
		t.Run(variant, func(t *testing.T) {
			fixture, returned := globalFunctionNative(t, variant)
			rho := globalRho(source, fixture, globals, [2]uint64{0x700008, 0x700050})
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, returned, rho, nil)
			positive := variant == "guarded" || variant == "unguarded" || variant == "entry-pointer-global" || variant == "retained-read" || variant == "inactive-write" || variant == "vector-private-value"
			if !positive {
				if err == nil || proof != nil {
					t.Fatalf("unaccounted effect/premise admitted: %+v", proof)
				}
				if variant == "matched-conditional-write" && !strings.Contains(err.Error(), "not proved to execute") {
					t.Fatalf("conditional matched write failed for another reason: %v", err)
				}
				if variant == "vector-escape" && !strings.Contains(err.Error(), "private frame address escapes in returned vector") {
					t.Fatalf("vector escape failed for another reason: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			bound, _ := proof.native.BoundFor(fixture.image)
			if len(proof.inputs) != 2 || len(proof.accesses) != 4 || len(proof.traces) != 1 || len(proof.traces[0].calls) != 1 || len(proof.administrative) < 3 || !bound.State.CalleeTerminated || proof.rules != globalFunctionRules {
				t.Fatal("complete evidence or administrative account was lost")
			}
			if variant == "guarded" && proof.antecedent.View().Op == br.Constant {
				t.Fatal("guarded antecedent was reset")
			}
			if variant == "inactive-write" && len(proof.inactive) == 0 {
				t.Fatal("inactive access lacks checked exclusion account")
			}
			if variant == "retained-read" && len(proof.eliminated) != 0 {
				t.Fatal("matched read was eliminated")
			}
			if variant != "retained-read" && len(proof.eliminated) != 1 {
				t.Fatal("established ordinary read has no elimination account")
			}
			if len(proof.equalities) == 0 || !proof.paired.Valid() {
				t.Fatal("paired initial relation/equalities missing")
			}
		})
	}
	fixture, returned := globalFunctionNative(t, "guarded")
	rho := globalRho(source, fixture, globals, [2]uint64{0x700008, 0x700050})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if p, err := checkGlobalFunctionCorrespondence(ctx, source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, returned, rho, nil); p != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	for _, budget := range []int{0, 1, 20} {
		if p, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, returned, rho, nil, globalCorrespondenceLimits{work: budget}); p != nil || err == nil {
			t.Fatalf("budget %d admitted", budget)
		}
	}
	for _, entry := range []uint64{fixture.entry + 1, fixture.cut} {
		if p, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, entry, completed, returned, rho, nil); p != nil || err == nil {
			t.Fatalf("wrong actual entry %#x admitted", entry)
		}
	}
	if p, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, nativeproof.TransitionReturnCertificate{}, rho, nil); p != nil || err == nil {
		t.Fatal("operand/prefix evidence substituted for a completed native return")
	}
	foreign, err := nativeproof.NewImage(t.Context(), fixture.raw)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], foreign, fixture.entry, completed, returned, rho, nil); p != nil || err == nil {
		t.Fatal("equal image bytes substituted for the owned image")
	}
	aliased := rho
	aliased.globals[1].address = aliased.globals[0].address + 1
	if p, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, returned, aliased, nil); p != nil || err == nil {
		t.Fatal("overlapping representation admitted")
	}
}

func TestGlobalFunctionGuardImplication(t *testing.T) {
	b := br.NewBuilder(64)
	scope := br.NewScope()
	a, _ := b.Input(br.Bool(), scope, 0)
	c, _ := b.Input(br.Bool(), scope, 1)
	antecedent, _ := b.Make(br.And, br.Bool(), 0, a, c)
	p := &globalFunctionCorrespondence{antecedent: antecedent}
	for _, guard := range []br.Term{a, c, antecedent} {
		if err := p.constant(t.Context(), guard, 1); err != nil {
			t.Fatal(err)
		}
	}
	unknown, _ := b.Input(br.Bool(), scope, 2)
	if err := p.constant(t.Context(), unknown, 1); err == nil {
		t.Fatal("unknown conditional occurrence assumed executed")
	}
	neg, _ := b.Make(br.Not, br.Bool(), 0, a)
	if err := p.constant(t.Context(), neg, 0); err != nil {
		t.Fatal(err)
	}
	if err := p.constant(t.Context(), a, 0); err == nil {
		t.Fatal("active occurrence erased")
	}
}
