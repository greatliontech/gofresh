package closure

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

type storageFunctionOperation struct {
	location nativeproof.TransitionLocation
	width    int
	write    bool
	value    uint64
}

// Inspect actual arguments in an authenticated boundary's checked state. This
// returns test data, not a call receipt or a new continuation capability.
func storageBoundaryOperands(t testing.TB, prefix *sourceEffectPrefix) []regionValue {
	t.Helper()
	packet := prefix.checkedPacket()
	if packet == nil || len(packet.observations) != 1 {
		t.Fatal("missing authenticated source boundary state")
	}
	call, ok := prefix.boundary.(*ssa.Call)
	if !ok {
		t.Fatal("fixture boundary is not an actual call")
	}
	var values []regionValue
	for _, operand := range call.Call.Args {
		values = append(values, prefix.checker.value(packet.observations[0].state, operand))
	}
	return values
}

func storageFunctionNative(t testing.TB, operations []storageFunctionOperation, domain nativeproof.OriginDomain, configure ...func(*nativeproof.TransitionInterface)) (globalNativeFixture, nativeproof.TransitionReturnCertificate) {
	t.Helper()
	const base = uint64(0x401000)
	code := []byte{0xc3, 0x48, 0x83, 0xec, 0x40} // SUB RSP,64
	for _, operation := range operations {
		if operation.write {
			code = append(code, 0x48, 0xb8)
			code = binary.LittleEndian.AppendUint64(code, operation.value)
		}
		pc := base + uint64(len(code))
		if operation.width == 8 {
			code = append(code, 0x48)
		}
		opcode := byte(0x8b)
		if operation.write {
			opcode = 0x89
		}
		if operation.width == 1 {
			opcode = 0x8a
			if operation.write {
				opcode = 0x88
			}
		}
		code = append(code, opcode)
		if operation.location.Image {
			code = append(code, 0x05)
			length := uint64(6)
			if operation.width == 8 {
				length++
			}
			code = binary.LittleEndian.AppendUint32(code, uint32(operation.location.Offset-int64(pc+length)))
		} else {
			code = append(code, 0x44, 0x24, byte(operation.location.Offset+64))
		}
	}
	code = append(code, 0x48, 0x83, 0xc4, 0x40) // ADD RSP,64
	cut := base + uint64(len(code))
	code = append(code, 0xc3)
	return storageFunctionNativeProgram(t, code, cut, domain, configure...)
}

func storageFunctionNativeProgram(t testing.TB, code []byte, cut uint64, domain nativeproof.OriginDomain, configure ...func(*nativeproof.TransitionInterface)) (globalNativeFixture, nativeproof.TransitionReturnCertificate) {
	t.Helper()
	const base, data = uint64(0x401000), uint64(0x700000)
	f := globalNativeImage(t, [2]uint64{data + 8, data + 80}, [3]uint64{}, data+8, data, nil, "")
	f.cut = cut
	copy(f.raw[4096:], code)
	binary.LittleEndian.PutUint64(f.raw[64+32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(f.raw[64+40:], uint64(len(code)))
	var err error
	f.image, err = nativeproof.NewImage(t.Context(), f.raw)
	if err != nil {
		t.Fatal(err)
	}
	f.face.Envelope = nativeproof.RelativeSpan{Start: -64, End: 16}
	f.face.Regions = []nativeproof.RelativeRegion{{Bytes: nativeproof.RelativeSpan{Start: -64, End: 0}, Readable: true, Writable: true}, {Bytes: nativeproof.RelativeSpan{Start: 0, End: 8}, Readable: true}}
	f.face.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: nativeproof.RelativeSpan{Start: -64, End: 0}}
	f.face.ReturnContext = &nativeproof.TransitionReturnContext{Target: base}
	if domain.Modulus != 0 {
		f.face.Origin = domain
	}
	for _, configuration := range configure {
		configuration(&f.face)
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

func storageFunctionSource(t testing.TB, text string) (computationSource, *sourceReturnCompletion) {
	t.Helper()
	source := relationFixture(t, text, 64)
	root := source.prog.Roots["F"]
	var call *ssa.Call
	var returned *ssa.Return
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			if candidate, ok := instruction.(*ssa.Call); ok && candidate.Call.StaticCallee() != nil && call == nil {
				call = candidate
			}
			if candidate, ok := instruction.(*ssa.Return); ok {
				returned = candidate
			}
		}
	}
	prefix, err := checkSourceOperandPrefix(t.Context(), source, root, call, defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	complete, err := checkSourceReturnContinuation(t.Context(), prefix, returned, nil)
	if err != nil {
		t.Fatal(err)
	}
	return source, complete
}

func storageFunctionLocal(t testing.TB, completed *sourceReturnCompletion) regionObject {
	t.Helper()
	for p := completed.prior; p != nil; p = p.prior {
		if allocations := p.region.packet.trace.allocations; len(allocations) > 0 {
			return allocations[0].location.object
		}
	}
	if allocations := completed.region.packet.trace.allocations; len(allocations) > 0 {
		return allocations[0].location.object
	}
	t.Fatal("missing actual local allocation")
	return regionObject{}
}

func TestStorageFunctionScalarLocalWidths(t *testing.T) {
	for _, width := range []int{1, 4, 8} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			source, completed := storageFunctionSource(t, fmt.Sprintf(`func Stop(p *uint%d){if *p!=7 {panic(1)}};func F(){var x uint%d;x=7;Stop(&x)}`, width*8, width*8))
			location := nativeproof.TransitionLocation{Offset: -16}
			for _, variant := range []string{"stored", "retained-read", "initialized-then-overwritten", "missing-write", "early-read", "extra-read", "wrong-value"} {
				t.Run(variant, func(t *testing.T) {
					ops := []storageFunctionOperation{{location, width, true, 7}}
					switch variant {
					case "initialized-then-overwritten":
						ops = append([]storageFunctionOperation{{location, width, true, 0}}, ops...)
					case "retained-read":
						ops = append(ops, storageFunctionOperation{location, width, false, 0})
					case "missing-write":
						ops = nil
					case "early-read":
						ops = append([]storageFunctionOperation{{location, width, false, 0}}, ops...)
					case "extra-read":
						ops = append(ops, storageFunctionOperation{location, width, false, 0}, storageFunctionOperation{location, width, false, 0})
					case "wrong-value":
						ops[0].value = 8
					}
					fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
					rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: storageFunctionLocal(t, completed), base: location}}}
					proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
					positive := variant == "stored" || variant == "retained-read" || variant == "initialized-then-overwritten"
					if (err == nil) != positive {
						t.Fatalf("positive=%v: %v", positive, err)
					}
					if positive {
						bound, ok := proof.native.BoundFor(fixture.image)
						if !ok || !bound.State.CalleeTerminated || len(proof.inputs) != 0 {
							t.Fatal("lost owned return or invented local initial native input")
						}
					}
				})
			}
		})
	}
}

func TestStorageFunctionGlobalPopulation(t *testing.T) {
	for _, count := range []int{0, 1, 3} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			declarations, body := "", ""
			var ops []storageFunctionOperation
			for i := range count {
				declarations += fmt.Sprintf("var G%d uint32;", i)
				body += fmt.Sprintf("G%d=%d;", i, i+7)
				ops = append(ops, storageFunctionOperation{nativeproof.TransitionLocation{Image: true, Offset: int64(0x700008 + 8*i)}, 4, true, uint64(i + 7)})
			}
			source, completed := storageFunctionSource(t, declarations+"func Stop(){};func F(){"+body+"Stop()}")
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image}
			for i := range count {
				rho.bindings = append(rho.bindings, storageBinding{object: regionObject{kind: regionGlobal, site: source.prog.Roots["F"].Pkg.Members[fmt.Sprintf("G%d", i)].(*ssa.Global)}, base: ops[i].location})
			}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(proof.inputs) != count {
				t.Fatal("typed leaf initial population changed")
			}
			seen := map[any]bool{}
			for _, input := range proof.inputs {
				if input.source.Sort().Width() != 32 || seen[input.native] {
					t.Fatal("global initial words alias or lost width")
				}
				seen[input.native] = true
			}
		})
	}
}

func TestStorageFunctionArrayWriteCoverage(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Stop(p *[2]uint32){if p[0]!=7||p[1]!=9 {panic(1)}};func F(){var a [2]uint32;a[0]=7;a[1]=9;Stop(&a)}`)
	base := nativeproof.TransitionLocation{Offset: -16}
	for _, variant := range []string{"separate", "combined", "reversed", "partial", "wrong-lane", "surplus"} {
		t.Run(variant, func(t *testing.T) {
			ops := []storageFunctionOperation{{base, 4, true, 7}, {nativeproof.TransitionLocation{Offset: -12}, 4, true, 9}}
			switch variant {
			case "combined":
				ops = []storageFunctionOperation{{base, 8, true, 7 | uint64(9)<<32}}
			case "reversed":
				ops[0], ops[1] = ops[1], ops[0]
			case "partial":
				ops = ops[:1]
			case "wrong-lane":
				ops = []storageFunctionOperation{{base, 8, true, 9 | uint64(7)<<32}}
			case "surplus":
				ops = append(ops, ops[0])
			}
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: storageFunctionLocal(t, completed), base: base}}}
			_, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			positive := variant == "separate" || variant == "combined" || variant == "reversed"
			if (err == nil) != positive {
				t.Fatalf("positive=%v: %v", positive, err)
			}
		})
	}
}

func TestStorageFunctionLocalInitialization(t *testing.T) {
	for _, writeOnly := range []bool{false, true} {
		t.Run(fmt.Sprint(writeOnly), func(t *testing.T) {
			helper := "if *p!=0 {panic(1)}"
			value := uint64(0)
			if writeOnly {
				helper = "*p=9"
				value = 9
			}
			source, completed := storageFunctionSource(t, `func Stop(p *uint32){`+helper+`};func F(){var x uint32;Stop(&x)}`)
			base := nativeproof.TransitionLocation{Offset: -16}
			ops := []storageFunctionOperation{{base, 4, true, value}}
			if !writeOnly {
				ops = append(ops, storageFunctionOperation{base, 4, false, 0})
			}
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: storageFunctionLocal(t, completed), base: base}}}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !writeOnly && len(proof.materialized) != 1 {
				t.Fatal("zero bytes were not justified by the actual native write")
			}
		})
	}
}

func TestStorageFunctionAuthorityOriginAndControl(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Stop(p *uint64){if *p!=7 {panic(1)}};func F(){var x uint64;x=7;Stop(&x)}`)
	object := storageFunctionLocal(t, completed)
	for _, test := range []struct {
		name             string
		offset           int64
		modulus, residue uint64
		positive         bool
	}{
		{"nonzero-residue", -12, 8, 4, true},
		{"wrong-residue", -16, 8, 4, false},
		{"insufficient-modulus", -12, 4, 0, false},
		{"root-control-slot", 0, 8, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := nativeproof.TransitionLocation{Offset: test.offset}
			ops := []storageFunctionOperation{{base, 8, true, 7}}
			if test.offset == 0 {
				ops = nil
			} // Native root control bytes remain protected.
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{Min: 1 << 40, Max: 1 << 44, Modulus: test.modulus, Residue: test.residue})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: object, base: base}}}
			_, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if (err == nil) != test.positive {
				t.Fatalf("positive=%v: %v", test.positive, err)
			}
			if test.name == "root-control-slot" && !strings.Contains(err.Error(), "represented object overlaps protected control storage") {
				t.Fatalf("control overlap refused for another reason: %v", err)
			}
		})
	}
}

func TestStorageFunctionTerminalAllocationAndIsolation(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Start(){};func Stop(p *uint32){if *p!=7 {panic(1)}};func F(){Start();var x uint32;x=7;Stop(&x)}`)
	object := storageFunctionLocal(t, completed)
	if _, live, err := completed.prior.liveAllocation(object, func() error { return nil }); err != nil || live {
		t.Fatal("fixture local already exists before terminal source segment")
	}
	for _, represented := range []bool{false, true} {
		t.Run(fmt.Sprint(represented), func(t *testing.T) {
			var ops []storageFunctionOperation
			base := nativeproof.TransitionLocation{Offset: -16}
			if represented {
				ops = []storageFunctionOperation{{base, 4, true, 7}}
			}
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image}
			if represented {
				rho.bindings = []storageBinding{{object: object, base: base}}
			}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !represented && len(proof.eliminated) != 2 {
				t.Fatal("isolated source storage has no elimination account")
			}
		})
	}
}

func TestStorageFunctionPaddingCannotHideAccess(t *testing.T) {
	source, completed := storageFunctionSource(t, `type S struct{A uint8;B uint32};func Stop(p *S){if p.A!=7||p.B!=9 {panic(1)}};func F(){var x S;x.A=7;x.B=9;Stop(&x)}`)
	base := nativeproof.TransitionLocation{Offset: -16}
	for _, extra := range []bool{false, true} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			ops := []storageFunctionOperation{{base, 1, true, 7}, {nativeproof.TransitionLocation{Offset: -12}, 4, true, 9}}
			if extra {
				ops = append(ops, storageFunctionOperation{nativeproof.TransitionLocation{Offset: -15}, 1, false, 0})
			}
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: storageFunctionLocal(t, completed), base: base}}}
			_, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if (err == nil) == extra {
				t.Fatalf("extra=%v: %v", extra, err)
			}
		})
	}
}

func TestStorageFunctionCombinedPaddingRetainsActualBytes(t *testing.T) {
	source, completed := storageFunctionSource(t, `type S struct{A uint8;B uint32};func Stop(p *S){if p.A!=7||p.B!=9 {panic(1)}};func F(){var x S;x.A=7;x.B=9;Stop(&x)}`)
	base := nativeproof.TransitionLocation{Offset: -16}
	// The native padding is deliberately nonzero. Source allocation cannot justify
	// any value for it; only this actual write establishes its residual bytes.
	fixture, native := storageFunctionNative(t, []storageFunctionOperation{{base, 8, true, uint64(9)<<32 | 0xa1b2c307}}, nativeproof.OriginDomain{})
	rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: storageFunctionLocal(t, completed), base: base}}}
	proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.padding) != 3 {
		t.Fatal("accessed padding lacks actual native byte account")
	}
	bound, _ := proof.native.BoundFor(fixture.image)
	for i, want := range []uint64{0xc3, 0xb2, 0xa1} {
		found := false
		for _, cell := range bound.State.Memory {
			if cell.TransitionLocation == (nativeproof.TransitionLocation{Offset: -15 + int64(i)}) {
				if err := proof.constant(t.Context(), cell.Value, want); err != nil {
					t.Fatal(err)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("residual native padding disappeared")
		}
	}
}

func TestStorageFunctionCurrentObjectAcrossCuts(t *testing.T) {
	source, first := storageFunctionSource(t, `func Stop(p *uint32,v uint32){if *p!=v {panic(1)}};func F(){var x uint32;x=7;Stop(&x,7);x=9;Stop(&x,9)}`)
	root := source.prog.Roots["F"]
	var second *ssa.Call
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok && call.Call.StaticCallee() != nil && call != first.prior.boundary {
				second = call
			}
		}
	}
	middle, err := checkSourceOperandContinuation(t.Context(), first.prior, second, nil)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := checkSourceReturnContinuation(t.Context(), middle, first.returned, nil)
	if err != nil {
		t.Fatal(err)
	}
	object := storageFunctionLocal(t, completed)
	if middle.operands[0].location.object != object || storageBoundaryOperands(t, first.prior)[0].location.object != object {
		t.Fatal("source allocation was reset at a cut")
	}
	base := nativeproof.TransitionLocation{Offset: -16}
	fixture, native := storageFunctionNative(t, []storageFunctionOperation{{base, 4, true, 7}, {base, 4, true, 9}}, nativeproof.OriginDomain{})
	rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: object, base: base}}}
	proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, fixture.image, fixture.entry, completed, native, rho, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.traces) != 3 || len(proof.eliminated) != 2 {
		t.Fatal("ordered current-state cuts disappeared")
	}
	rho.bindings[0].object.invocation = regionInvocation{root: root, path: "unexecuted"}
	if p, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, fixture.image, fixture.entry, completed, native, rho, nil); err == nil || p != nil {
		t.Fatal("proposed allocation instance supplied its own lifetime evidence")
	}
}

func TestStorageFunctionDistinctInvocationLocals(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Read(p *uint32){if *p!=7 {panic(1)}};func Work(){var x uint32;x=7;Read(&x)};func F(){Work();Work()}`)
	allocations := completed.region.packet.trace.allocations
	if len(allocations) != 2 || allocations[0].instruction != allocations[1].instruction || allocations[0].location.object == allocations[1].location.object {
		t.Fatal("fixture lacks distinct dynamic instances of the same allocation")
	}
	var ops []storageFunctionOperation
	for i := range allocations {
		ops = append(ops, storageFunctionOperation{nativeproof.TransitionLocation{Offset: -16 + int64(8*i)}, 4, true, 7})
	}
	fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
	rho := storageRepresentation{source: source.prog, image: fixture.image}
	for i, allocation := range allocations {
		rho.bindings = append(rho.bindings, storageBinding{object: allocation.location.object, base: ops[i].location})
	}
	proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.eliminated) != 2 || len(proof.matched) != 2 {
		t.Fatal("distinct invocation effects were collapsed")
	}
}

func TestStorageFunctionLocalRequiresNativeLifetimeOwnership(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Stop(p *uint32){if *p!=7 {panic(1)}};func F(){var x uint32;x=7;Stop(&x)}`)
	base := nativeproof.TransitionLocation{Offset: -16}
	for _, absent := range []bool{true, false} {
		t.Run(fmt.Sprint(absent), func(t *testing.T) {
			fixture, native := storageFunctionNative(t, []storageFunctionOperation{{base, 4, true, 7}}, nativeproof.OriginDomain{}, func(face *nativeproof.TransitionInterface) {
				if absent {
					face.PrivateFrame = nil
				} else {
					face.PrivateFrame.Bytes.Start = -8
				}
			})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: storageFunctionLocal(t, completed), base: base}}}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if err == nil || proof != nil || !strings.Contains(err.Error(), "allocation lacks native private lifetime ownership") {
				t.Fatalf("mapped native bytes supplied missing allocation ownership or wrong refusal: %v", err)
			}
		})
	}
}

func TestStorageFunctionCombinedWritesRespectNativeCallContext(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Stop(p *[2]uint32){if p[0]!=7||p[1]!=9 {panic(1)}};func F(){var a [2]uint32;a[0]=7;a[1]=9;Stop(&a)}`)
	const pc = uint64(0x401000)
	for _, child := range []bool{false, true} {
		t.Run(fmt.Sprint(child), func(t *testing.T) {
			var fixture globalNativeFixture
			var native nativeproof.TransitionReturnCertificate
			base := nativeproof.TransitionLocation{Offset: -16}
			if !child {
				fixture, native = storageFunctionNative(t, []storageFunctionOperation{{base, 4, true, 7}, {nativeproof.TransitionLocation{Offset: -12}, 4, true, 9}}, nativeproof.OriginDomain{})
			} else {
				code := []byte{0xc3, 0x48, 0x83, 0xec, 0x40, 0xb8, 7, 0, 0, 0, 0x89, 0x44, 0x24, 48}
				call := len(code)
				code = append(code, 0xe8, 0, 0, 0, 0, 0x48, 0x83, 0xc4, 0x40)
				cut := pc + uint64(len(code))
				code = append(code, 0xc3)
				binary.LittleEndian.PutUint32(code[call+1:], uint32(len(code)-call-5))
				code = append(code, 0xb8, 9, 0, 0, 0, 0x89, 0x44, 0x24, 60, 0xc3)
				fixture, native = storageFunctionNativeProgram(t, code, cut, nativeproof.OriginDomain{}, func(face *nativeproof.TransitionInterface) {
					face.Envelope.Start = -80
					face.Regions[0].Bytes.Start = -80
					face.PrivateFrame.Bytes.Start = -80
				})
				bound, _ := native.BoundFor(fixture.image)
				var contexts []nativeproof.TransitionActivationID
				for _, access := range bound.Accesses {
					if access.Kind == nativeproof.FrameWrite && access.Bytes.Start >= -16 && access.Bytes.End <= -8 {
						contexts = append(contexts, access.Context)
					}
				}
				if len(contexts) != 2 || contexts[0] == contexts[1] {
					t.Fatal("fixture did not cross the actual child activation")
				}
			}
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: storageFunctionLocal(t, completed), base: base}}}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if !child {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || proof != nil || !strings.Contains(err.Error(), "combined native writes cross a call boundary") {
				t.Fatalf("cross-context combining accepted or refused for another cause: %v", err)
			}
		})
	}
}

func TestStorageFunctionBindingBudgetPrecedesCallbacks(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Stop(p *uint32){if *p!=7 {panic(1)}};func F(){var x uint32;x=7;Stop(&x)}`)
	base := nativeproof.TransitionLocation{Offset: -16}
	fixture, native := storageFunctionNative(t, []storageFunctionOperation{{base, 4, true, 7}}, nativeproof.OriginDomain{})
	rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: make([]storageBinding, storageMaxBindings+1)}
	for i := range rho.bindings {
		rho.bindings[i] = storageBinding{object: storageFunctionLocal(t, completed), base: base}
	}
	called := false
	ctx := &storageCallbackContext{Context: t.Context(), callback: func() { called = true }}
	proof, err := checkGlobalFunctionCorrespondence(ctx, source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
	if proof != nil || err == nil || !strings.Contains(err.Error(), "storage binding budget exceeded") || called {
		t.Fatalf("oversized representation reached clone/layout callbacks: called=%v err=%v", called, err)
	}
}

func TestStorageFunctionSourcePointerEscapeRefused(t *testing.T) {
	for _, copied := range []bool{false, true} {
		t.Run(fmt.Sprint(copied), func(t *testing.T) {
			store := "Escaped=p"
			copy := ""
			if copied {
				copy = "func Copy(p *uint32)*uint32{return p};"
				store = "Escaped=Copy(p)"
			}
			source, completed := storageFunctionSource(t, `var Escaped *uint32;`+copy+`func Stop(p *uint32){`+store+`};func F(){var x uint32;x=7;Stop(&x)}`)
			for _, represented := range []bool{false, true} {
				t.Run(fmt.Sprint(represented), func(t *testing.T) {
					base := nativeproof.TransitionLocation{Offset: -16}
					var ops []storageFunctionOperation
					if represented {
						ops = []storageFunctionOperation{{base, 4, true, 7}}
					}
					fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
					rho := storageRepresentation{source: source.prog, image: fixture.image}
					if represented {
						rho.bindings = []storageBinding{{object: storageFunctionLocal(t, completed), base: base}}
					}
					proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
					if proof != nil || err == nil || !strings.Contains(err.Error(), "unrepresented source storage is not isolated") {
						t.Fatalf("source pointer escape erased or refused for wrong cause: %v", err)
					}
				})
			}
		})
	}
}

func TestStorageFunctionDiscardedInternalPointerReturn(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Copy(p *uint32)*uint32{return p};func F(){var x uint32;x=7;_ = Copy(&x)}`)
	fixture, native := storageFunctionNative(t, nil, nativeproof.OriginDomain{})
	rho := storageRepresentation{source: source.prog, image: fixture.image}
	proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.eliminated) != 1 {
		t.Fatal("discarded internal pointer return lost local effect account")
	}
}

func TestStorageFunctionInternalPointerReturnRetainsDependentEffect(t *testing.T) {
	source, completed := storageFunctionSource(t, `var G uint32;func Copy(p *uint32)*uint32{return p};func Read(p *uint32)uint32{return *p};func F(){var x uint32;x=7;G=Read(Copy(&x))}`)
	for _, value := range []uint64{7, 8} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			base := nativeproof.TransitionLocation{Image: true, Offset: 0x700008}
			fixture, native := storageFunctionNative(t, []storageFunctionOperation{{base, 4, true, value}}, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: regionObject{kind: regionGlobal, site: source.prog.Roots["F"].Pkg.Members["G"].(*ssa.Global)}, base: base}}}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if value == 8 {
				if err == nil || proof != nil {
					t.Fatal("eliminated local lost its dependent global effect")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(proof.eliminated) != 2 || len(proof.matched) != 1 {
				t.Fatal("internal pointer return lost actual source effects")
			}
		})
	}
}

func TestStorageFunctionKnownInitializerFieldBesideOpaqueLeaf(t *testing.T) {
	source, completed := storageFunctionSource(t, `type S struct{X uint32;Y float64};func Stop(p *S){if p.X!=0 {panic(1)}};func F(){var x S;Stop(&x)}`)
	base := nativeproof.TransitionLocation{Offset: -32}
	fixture, native := storageFunctionNative(t, []storageFunctionOperation{{base, 4, true, 0}, {base, 4, false, 0}}, nativeproof.OriginDomain{})
	rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: storageFunctionLocal(t, completed), base: base}}}
	proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.materialized) != 1 {
		t.Fatal("supported initializer field lost actual materialization")
	}
}

func TestStorageFunctionAggregateReadByteCoverage(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Stop(p *[2]uint64){v:=*p;if v[0]!=7||v[1]!=9 {panic(1)}};func F(){var a [2]uint64;a[0]=7;a[1]=9;Stop(&a)}`)
	base := nativeproof.TransitionLocation{Offset: -32}
	second := nativeproof.TransitionLocation{Offset: -24}
	for _, extra := range []bool{false, true} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			ops := []storageFunctionOperation{{base, 8, true, 7}, {second, 8, true, 9}, {base, 8, false, 0}, {second, 8, false, 0}}
			if extra {
				ops = append(ops, storageFunctionOperation{base, 8, false, 0})
			}
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: storageFunctionLocal(t, completed), base: base}}}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if extra {
				if err == nil || proof != nil {
					t.Fatal("surplus native aggregate read erased")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStorageFunctionInitializerAtFinalFrontier(t *testing.T) {
	source, completed := storageFunctionSource(t, `var G uint32;func Start(){};func Keep(*uint32){};func F(){G=7;Start();var x uint32;Keep(&x)}`)
	local := nativeproof.TransitionLocation{Offset: -16}
	global := nativeproof.TransitionLocation{Image: true, Offset: 0x700008}
	for _, variant := range []string{"materialized", "omitted", "reinitialized", "wrong-value", "early-read", "before-allocation-frontier"} {
		t.Run(variant, func(t *testing.T) {
			storeGlobal := storageFunctionOperation{global, 4, true, 7}
			initialize := storageFunctionOperation{local, 4, true, 0}
			ops := []storageFunctionOperation{storeGlobal, initialize}
			switch variant {
			case "omitted":
				ops = ops[:1]
			case "reinitialized":
				ops = append(ops, initialize)
			case "wrong-value":
				ops[1].value = 1
			case "early-read":
				ops = []storageFunctionOperation{storeGlobal, {local, 4, false, 0}, initialize}
			case "before-allocation-frontier":
				ops = []storageFunctionOperation{initialize, storeGlobal}
			}
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{
				{object: regionObject{kind: regionGlobal, site: source.prog.Roots["F"].Pkg.Members["G"].(*ssa.Global)}, base: global},
				{object: storageFunctionLocal(t, completed), base: local},
			}}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			positive := variant == "materialized" || variant == "omitted"
			if (err == nil) != positive {
				t.Fatalf("positive=%v: %v", positive, err)
			}
			if variant == "materialized" && len(proof.materialized) != 1 {
				t.Fatal("final checked allocation has no actual native initialization account")
			}
			if variant == "omitted" && len(proof.materialized) != 0 {
				t.Fatal("source allocation invented native initialization")
			}
		})
	}
}

func TestStorageFunctionEliminatedAccessPreservesWritePreference(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Keep(*uint32){};func F(){var x,y uint32;y=7;x=0;Keep(&y);Keep(&x)}`)
	calls := completed.region.packet.trace.calls
	if len(calls) != 2 || len(calls[1].proof.arguments) != 1 {
		t.Fatal("fixture lost its actual source calls")
	}
	object := calls[1].proof.arguments[0].location.object
	if object == storageBoundaryOperands(t, completed.prior)[0].location.object {
		t.Fatal("fixture does not have distinct represented and eliminated locals")
	}
	base := nativeproof.TransitionLocation{Offset: -16}
	for _, variant := range []string{"matched-write", "missing-write", "surplus-write"} {
		t.Run(variant, func(t *testing.T) {
			ops := []storageFunctionOperation{{base, 4, true, 0}}
			switch variant {
			case "missing-write":
				ops = nil
			case "surplus-write":
				ops = append(ops, ops[0])
			}
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: object, base: base}}}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if variant == "matched-write" {
				if err != nil {
					t.Fatal(err)
				}
				if len(proof.materialized) != 0 || len(proof.matched) != 1 || proof.matched[0].source != 1 || len(proof.eliminated) != 1 || proof.eliminated[0] != 0 {
					t.Fatal("eliminated local consumed the represented explicit write")
				}
				return
			}
			want := "missing native effect bytes"
			if variant == "surplus-write" {
				want = "native computation has an unmatched effect"
			}
			if proof != nil || err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("%s accepted or refused at another stage: %v", variant, err)
			}
		})
	}
}

func TestStorageFunctionWriteRunPrecedesInitialization(t *testing.T) {
	base := nativeproof.TransitionLocation{Offset: -16}
	second := nativeproof.TransitionLocation{Offset: -12}
	for _, test := range []struct {
		name, source string
		operations   []storageFunctionOperation
		padding      int
	}{
		{"combined-zero", `func Keep(*[2]uint32){};func F(){var a [2]uint32;a[0]=0;a[1]=0;Keep(&a)}`, []storageFunctionOperation{{base, 8, true, 0}}, 0},
		{"reversed-zero-lane", `func Keep(*[2]uint32){};func F(){var a [2]uint32;a[0]=7;a[1]=0;Keep(&a)}`, []storageFunctionOperation{{second, 4, true, 0}, {base, 4, true, 7}}, 0},
		{"padded-zero", `type S struct{A uint8;B uint32};func Keep(*S){};func F(){var a S;a.A=0;a.B=0;Keep(&a)}`, []storageFunctionOperation{{base, 8, true, 0xa1b2c300}}, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, completed := storageFunctionSource(t, test.source)
			for _, variant := range []string{"matched-writes", "missing-write", "surplus-write"} {
				t.Run(variant, func(t *testing.T) {
					ops := append([]storageFunctionOperation(nil), test.operations...)
					switch variant {
					case "missing-write":
						ops = ops[:len(ops)-1]
					case "surplus-write":
						ops = append(ops, ops[0])
					}
					fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
					rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: storageFunctionLocal(t, completed), base: base}}}
					proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
					if variant == "matched-writes" {
						if err != nil {
							t.Fatal(err)
						}
						if len(proof.materialized) != 0 || len(proof.matched) != 2 || len(proof.eliminated) != 0 || len(proof.padding) != test.padding {
							t.Fatal("initializer preference stole an ordinary run or duplicated padding accounting")
						}
						return
					}
					want := "missing native effect bytes"
					if variant == "surplus-write" {
						want = "native computation has an unmatched effect"
					}
					if proof != nil || err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("%s accepted or refused at another stage: %v", variant, err)
					}
				})
			}
		})
	}
}

func TestStorageFunctionWriteRunAllocationFrontier(t *testing.T) {
	source, completed := storageFunctionSource(t, `var G uint32;func Keep(*uint32){};func F(){G=7;var x uint32;x=0;Keep(&x)}`)
	trace := completed.prior.region.packet.trace
	object := storageFunctionLocal(t, completed)
	allocation := object.site.(*ssa.Alloc)
	passedGlobal := false
	for _, occurrence := range trace.instructions {
		if occurrence == trace.accesses[0].regionEffectOccurrence {
			passedGlobal = true
		}
		if occurrence.instruction == allocation && !passedGlobal {
			t.Fatal("fixture allocation does not follow the global write")
		}
	}
	global := nativeproof.TransitionLocation{Image: true, Offset: 0x700008}
	local := nativeproof.TransitionLocation{Offset: -16}
	for _, reversed := range []bool{false, true} {
		t.Run(fmt.Sprint(reversed), func(t *testing.T) {
			ops := []storageFunctionOperation{{global, 4, true, 7}, {local, 4, true, 0}}
			if reversed {
				ops[0], ops[1] = ops[1], ops[0]
			}
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{
				{object: regionObject{kind: regionGlobal, site: source.prog.Roots["F"].Pkg.Members["G"].(*ssa.Global)}, base: global},
				{object: object, base: local},
			}}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if !reversed {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if proof != nil || err == nil || !strings.Contains(err.Error(), "native effect has missing or surplus byte coverage") {
				t.Fatalf("write run crossed the actual allocation frontier or refused elsewhere: %v", err)
			}
		})
	}
}

func TestStorageFunctionReferenceWriteCallEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("captures selected assembly reference and checks complete ordinary-call effects")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected assembly acquisition requires Linux amd64")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod": "module example.com/storagecallbarrier\n\ngo 1.27\n",
		"word.go": `package p
var G,H uint64
//go:noescape
func Put(ptr *uint64)
func Start(){G=3;Put(&G);H=7}
func End(){G=3;if G!=3 {panic(1)};H=7;Put(&G)}
`,
		"word_amd64.s": `#include "textflag.h"
TEXT ·Put(SB),NOSPLIT,$0-8
 MOVQ ptr+0(FP),BX
 MOVQ $0,AX
 MOVQ AX,0(BX)
 RET
`,
	})
	source := assemblyReferenceSelectedSource(t, dir)
	target := source.prog.Roots["Put"]
	packet := assemblyReferenceSelectedPacket(t, source, target)
	reference, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := reference.evaluate(t.Context(), 3)
	if err != nil || len(outcome.Accesses) != 1 || outcome.Accesses[0] != (assemblyReferenceAccess{Write: true, Value: 0, Width: 8}) || len(outcome.Atomics) != 0 {
		t.Fatalf("selected ordinary write reference was not established: %+v %v", outcome, err)
	}
	g := nativeproof.TransitionLocation{Image: true, Offset: 0x700008}
	h := nativeproof.TransitionLocation{Image: true, Offset: 0x700050}
	for _, endpoint := range []string{"start", "end"} {
		t.Run(endpoint, func(t *testing.T) {
			name := "Start"
			if endpoint == "end" {
				name = "End"
			}
			root := source.prog.Roots[name]
			var call *ssa.Call
			var returned *ssa.Return
			for _, block := range root.Blocks {
				for _, instruction := range block.Instrs {
					if c, ok := instruction.(*ssa.Call); ok && c.Call.StaticCallee() == target {
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
			completed, err := checkSourceReturnContinuation(t.Context(), prefix, returned, map[*ssa.Function]*assemblyReference{target: reference})
			if err != nil {
				t.Fatal(err)
			}
			trace := completed.region.packet.trace
			if len(trace.calls) != 1 || trace.calls[0].proof.reference != reference || len(trace.atomics) != 0 || len(trace.accesses) == 0 || trace.accesses[0].instruction != call || trace.accesses[0].invocation != (regionInvocation{}) || trace.accesses[0].locked || !trace.accesses[0].write {
				t.Fatal("ordinary reference write lost its actual call/caller provenance")
			}
			for _, reordered := range []bool{false, true} {
				t.Run(fmt.Sprint(reordered), func(t *testing.T) {
					ops := []storageFunctionOperation{{g, 8, true, 3}, {g, 8, true, 0}, {h, 8, true, 7}}
					if (endpoint == "end") != reordered {
						ops[1], ops[2] = ops[2], ops[1]
					}
					fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
					rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{
						{object: regionObject{kind: regionGlobal, site: root.Pkg.Members["G"].(*ssa.Global)}, base: g},
						{object: regionObject{kind: regionGlobal, site: root.Pkg.Members["H"].(*ssa.Global)}, base: h},
					}}
					proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, fixture.image, fixture.entry, completed, native, rho, nil)
					if reordered {
						if proof != nil || err == nil || !strings.Contains(err.Error(), "complete effects:") || !strings.Contains(err.Error(), "native effect has missing or surplus byte coverage") {
							t.Fatalf("reordered reference write accepted or refused outside ordered effect matching: %v", err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					callIndex := 1
					wantAccesses := 3
					wantEliminated := 0
					if endpoint == "end" {
						callIndex = 3
						wantAccesses = 4
						wantEliminated = 1
					}
					if len(proof.accesses) != wantAccesses || proof.accesses[callIndex].instruction != call || len(proof.atomics) != 0 || len(proof.matched) != 3 || len(proof.eliminated) != wantEliminated {
						t.Fatal("fixture did not isolate the intended call endpoint")
					}
				})
			}
		})
	}
}

func TestStorageFunctionKnownReadDefersAmbiguousInitialization(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Keep(*uint32){};func F(){var x,y uint32;y=7;if y!=7{panic(1)};x=0;Keep(&x);Keep(&y)}`)
	calls := completed.region.packet.trace.calls
	if len(calls) != 2 || len(storageBoundaryOperands(t, completed.prior)) != 1 || len(calls[1].proof.arguments) != 1 {
		t.Fatal("fixture lost its actual local arguments")
	}
	xObject := storageBoundaryOperands(t, completed.prior)[0].location.object
	yObject := calls[1].proof.arguments[0].location.object
	if xObject == yObject {
		t.Fatal("fixture locals alias")
	}
	x := nativeproof.TransitionLocation{Offset: -16}
	y := nativeproof.TransitionLocation{Offset: -24}
	for _, variant := range []string{"eliminated-read", "retained-read", "initializer-retained-read", "missing-write", "surplus-write"} {
		t.Run(variant, func(t *testing.T) {
			writeY := storageFunctionOperation{y, 4, true, 7}
			writeX := storageFunctionOperation{x, 4, true, 0}
			readY := storageFunctionOperation{y, 4, false, 0}
			ops := []storageFunctionOperation{writeY, writeX}
			switch variant {
			case "retained-read":
				ops = []storageFunctionOperation{writeY, readY, writeX}
			case "initializer-retained-read":
				ops = []storageFunctionOperation{writeY, writeX, readY, writeX}
			case "missing-write":
				ops = []storageFunctionOperation{writeY}
			case "surplus-write":
				ops = []storageFunctionOperation{writeY, writeX, writeX}
			}
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: xObject, base: x}, {object: yObject, base: y}}}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if variant == "missing-write" || variant == "surplus-write" {
				want := "missing native effect bytes"
				if variant == "surplus-write" {
					want = "native computation has an unmatched effect"
				}
				if proof != nil || err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("%s accepted or refused elsewhere: %v", variant, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantMatched, wantEliminated, wantMaterialized := 2, 1, 0
			if variant != "eliminated-read" {
				wantMatched, wantEliminated = 3, 0
			}
			if variant == "initializer-retained-read" {
				wantMaterialized = 1
			}
			if len(proof.matched) != wantMatched || len(proof.eliminated) != wantEliminated || len(proof.materialized) != wantMaterialized {
				t.Fatal("read/initializer choice lost its exact effect account")
			}
			if variant == "eliminated-read" && (proof.matched[0].source != 0 || proof.matched[1].source != 2 || proof.eliminated[0] != 1) {
				t.Fatal("known read stole the later explicit zero write")
			}
		})
	}
}

type storageFunctionReadChoiceFixture struct {
	source    computationSource
	completed *sourceReturnCompletion
	fixture   globalNativeFixture
	native    nativeproof.TransitionReturnCertificate
	rho       storageRepresentation
}

func storageFunctionReadChoices(t testing.TB, variant string) storageFunctionReadChoiceFixture {
	t.Helper()
	source, completed := storageFunctionSource(t, `func Keep(*uint32){};func F(){var x,y uint32;y=7;if y!=7{panic(1)};x=0;if y!=7{panic(1)};Keep(&x);Keep(&y)}`)
	calls := completed.region.packet.trace.calls
	if len(calls) != 2 {
		t.Fatal("fixture lost its checked local calls")
	}
	xObject := storageBoundaryOperands(t, completed.prior)[0].location.object
	yObject := calls[1].proof.arguments[0].location.object
	x := nativeproof.TransitionLocation{Offset: -16}
	y := nativeproof.TransitionLocation{Offset: -24}
	writeY := storageFunctionOperation{y, 4, true, 7}
	writeX := storageFunctionOperation{x, 4, true, 0}
	readY := storageFunctionOperation{y, 4, false, 0}
	ops := []storageFunctionOperation{writeY, writeX, readY}
	switch variant {
	case "retain-both":
		ops = []storageFunctionOperation{writeY, writeX, readY, writeX, readY}
	case "retain-first":
		ops = []storageFunctionOperation{writeY, writeX, readY, writeX}
	case "surplus":
		ops = append(ops, storageFunctionOperation{x, 4, false, 0})
	case "defer-first":
	default:
		t.Fatal("unknown read-choice fixture")
	}
	fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
	rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: xObject, base: x}, {object: yObject, base: y}}}
	return storageFunctionReadChoiceFixture{source, completed, fixture, native, rho}
}

func TestStorageFunctionReadChoiceContinuation(t *testing.T) {
	for _, variant := range []string{"defer-first", "retain-both", "retain-first"} {
		t.Run(variant, func(t *testing.T) {
			f := storageFunctionReadChoices(t, variant)
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), f.source, f.source.prog.Roots["F"], f.fixture.image, f.fixture.entry, f.completed, f.native, f.rho, nil)
			if err != nil {
				t.Fatal(err)
			}
			if variant == "defer-first" {
				if len(proof.matched) != 3 || proof.matched[0].source != 0 || proof.matched[1].source != 2 || proof.matched[2].source != 3 || len(proof.eliminated) != 1 || proof.eliminated[0] != 1 || len(proof.materialized) != 0 {
					t.Fatal("read choice was committed before its continuation matched")
				}
			} else if variant == "retain-first" {
				if len(proof.matched) != 3 || len(proof.materialized) != 1 || len(proof.eliminated) != 1 || proof.eliminated[0] != 3 {
					t.Fatal("valid alternate initializer/read mapping was lost")
				}
			} else if len(proof.matched) != 4 || len(proof.eliminated) != 0 || len(proof.materialized) != 1 {
				t.Fatal("required initializer and retained reads were discarded")
			}
		})
	}
}

// Prepare the search's already-checked ordinary input view from real owned
// source/native computations. These fixtures have no primitive/abstraction arm;
// every instruction guard is proved and administrative bytes use the same checked
// representation. The tests below vary search order, never source effects.
func storageFunctionSearchAccount(t testing.TB, f storageFunctionReadChoiceFixture) (*globalFunctionCorrespondence, nativeproof.TransitionBound, []int) {
	t.Helper()
	bound, ok := f.native.BoundFor(f.fixture.image)
	if !ok {
		t.Fatal("native fixture lost image ownership")
	}
	view := bound.Prefix
	view.Accesses, view.Instructions, view.Memory = bound.Accesses, bound.Instructions, bound.State.Memory
	layout, err := checkStorageAuthority(t.Context(), f.completed, view, f.rho, storageProtectedFootprints(view))
	if err != nil {
		t.Fatal(err)
	}
	p := &globalFunctionCorrespondence{source: f.completed, native: f.native, representation: layout.representation, layout: layout, antecedent: view.EntryPredicate}
	if err := p.collectSource(t.Context(), f.source, f.source.prog.Roots["F"]); err != nil {
		t.Fatal(err)
	}
	if len(view.PrimitiveEffects) != 0 || len(view.Abstractions) != 0 {
		t.Fatal("search fixture has an extraordinary effect")
	}
	for _, trace := range p.traces {
		if len(trace.atomics) != 0 {
			t.Fatal("search fixture has a source atomic group")
		}
	}
	for _, instruction := range view.Instructions {
		if err := p.constant(t.Context(), instruction.Guard, 1); err != nil {
			t.Fatal(err)
		}
	}
	var observable []int
	for index, access := range view.Accesses {
		if p.administrativeAccess(view, access) {
			p.administrative = append(p.administrative, index)
		} else {
			observable = append(observable, index)
		}
	}
	return p, view, observable
}

func TestStorageFunctionReadChoiceCandidateOrder(t *testing.T) {
	for _, variant := range []string{"defer-first", "retain-both", "retain-first"} {
		t.Run(variant, func(t *testing.T) {
			f := storageFunctionReadChoices(t, variant)
			for _, preferRetain := range []bool{true, false} {
				t.Run(fmt.Sprint(preferRetain), func(t *testing.T) {
					p, view, observable := storageFunctionSearchAccount(t, f)
					before := slices.Clone(p.equalities)
					admin := slices.Clone(p.administrative)
					meter := &correspondenceContext{Context: t.Context(), limit: 2_000_000}
					if err := p.searchStorageEffects(meter, view.Accesses, view.InitialMemory, observable, nil, nil, preferRetain); err != nil {
						t.Fatal(err)
					}
					if !slices.Equal(p.equalities[:len(before)], before) || !slices.Equal(p.administrative, admin) {
						t.Fatal("search changed pre-established evidence")
					}
					covered := map[int]int{}
					for _, match := range p.matched {
						covered[match.native]++
					}
					for _, index := range p.materialized {
						covered[index]++
					}
					for _, index := range observable {
						if covered[index] != 1 {
							t.Fatalf("native effect %d lacks one final account: %v", index, covered)
						}
					}
					if variant == "defer-first" && (len(p.materialized) != 0 || len(p.eliminated) != 1 || p.eliminated[0] != 1) {
						t.Fatal("failed retained-read branch escaped into the final account")
					}
				})
			}
		})
	}
}

func TestStorageFunctionReadChoiceRefusalRollsBack(t *testing.T) {
	f := storageFunctionReadChoices(t, "surplus")
	for _, preferRetain := range []bool{true, false} {
		t.Run(fmt.Sprint(preferRetain), func(t *testing.T) {
			p, view, observable := storageFunctionSearchAccount(t, f)
			before := *p
			before.equalities = slices.Clone(p.equalities)
			before.administrative = slices.Clone(p.administrative)
			meter := &correspondenceContext{Context: t.Context(), limit: 2_000_000}
			err := p.searchStorageEffects(meter, view.Accesses, view.InitialMemory, observable, nil, nil, preferRetain)
			var mismatch *storageEffectMismatch
			if !errors.As(err, &mismatch) {
				t.Fatalf("surplus read was accepted or refused operationally: %v", err)
			}
			if !reflect.DeepEqual(p, &before) {
				t.Fatal("failed alternatives leaked proof accounts or changed owned computations")
			}
		})
	}
}

func TestStorageFunctionReadChoiceCumulativeBudget(t *testing.T) {
	f := storageFunctionReadChoices(t, "defer-first")
	p, view, observable := storageFunctionSearchAccount(t, f)
	first := globalFunctionCorrespondence{representation: p.representation, layout: p.layout, antecedent: p.antecedent, accesses: p.accesses, traces: p.traces}
	firstMeter := &correspondenceContext{Context: t.Context(), limit: 2_000_000}
	plan := storageReadPlan{preferRetain: true, bound: len(p.accesses)}
	if err := first.matchStorageEffectAttempt(firstMeter, view.Accesses, view.InitialMemory, observable, nil, nil, &plan); !storageEffectRetryable(err) || len(plan.path) == 0 {
		t.Fatalf("fixture did not need a failed retained-read alternative: %v", err)
	}
	selected := globalFunctionCorrespondence{representation: p.representation, layout: p.layout, antecedent: p.antecedent, accesses: p.accesses, traces: p.traces}
	selectedMeter := &correspondenceContext{Context: t.Context(), limit: 2_000_000}
	selectedPlan := storageReadPlan{prefix: []storageEffectReadChoice{{1, false}, {3, true}}, preferRetain: true, bound: len(p.accesses)}
	if err := selected.matchStorageEffectAttempt(selectedMeter, view.Accesses, view.InitialMemory, observable, nil, nil, &selectedPlan); err != nil || len(selectedPlan.path) != 2 {
		t.Fatalf("independently checked alternative did not complete: %v", err)
	}
	observer := &storageSearchWorkContext{Context: t.Context()}
	full := &correspondenceContext{Context: observer, limit: 2_000_000}
	observer.account = full
	if err := p.searchStorageEffects(full, view.Accesses, view.InitialMemory, observable, nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if observer.decreased || full.work < firstMeter.work+selectedMeter.work {
		t.Fatal("successful search did not retain cumulative failed-attempt work")
	}
	p, view, observable = storageFunctionSearchAccount(t, f)
	before := *p
	before.equalities = slices.Clone(p.equalities)
	before.administrative = slices.Clone(p.administrative)
	limited := &correspondenceContext{Context: t.Context(), limit: full.work - 1}
	err := p.searchStorageEffects(limited, view.Accesses, view.InitialMemory, observable, nil, nil, true)
	if err == nil || storageEffectRetryable(err) || limited.work != limited.limit {
		t.Fatalf("search reset or hid its cumulative budget: work=%d limit=%d err=%v", limited.work, limited.limit, err)
	}
	if !reflect.DeepEqual(p, &before) {
		t.Fatal("budget exhaustion committed a tentative proof")
	}
	cancelAt := &storageSearchWorkContext{Context: t.Context(), cancelAt: full.work - 1}
	cancelled := &correspondenceContext{Context: cancelAt, limit: 2_000_000}
	cancelAt.account = cancelled
	if err := p.searchStorageEffects(cancelled, view.Accesses, view.InitialMemory, observable, nil, nil, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("search hid cancellation: %v", err)
	}
	if !reflect.DeepEqual(p, &before) {
		t.Fatal("cancelled search changed the caller proof")
	}
}

type storageSearchWorkContext struct {
	context.Context
	account        *correspondenceContext
	last, cancelAt int
	decreased      bool
}

func (c *storageSearchWorkContext) Err() error {
	if c.account != nil {
		if c.account.work < c.last {
			c.decreased = true
		}
		c.last = c.account.work
		if c.cancelAt > 0 && c.account.work >= c.cancelAt {
			return context.Canceled
		}
	}
	return c.Context.Err()
}

func TestStorageFunctionReadChoiceFailureClasses(t *testing.T) {
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, errors.New("operational failure"), &br.Refusal{Code: br.Budget}, &br.Refusal{Code: br.Cancelled}, &br.Refusal{Code: br.Malformed}, &br.Refusal{Code: br.Endpoint}, &br.Refusal{Code: br.InvalidRule}} {
		if storageEffectRetryable(err) {
			t.Fatalf("operational failure became an alignment alternative: %v", err)
		}
	}
	for _, err := range []error{storageMismatch("unmatched effect"), &br.Refusal{Code: br.Unsupported}} {
		if !storageEffectRetryable(fmt.Errorf("obligation: %w", err)) {
			t.Fatalf("branch refusal lost its structured classification: %v", err)
		}
	}
}

func TestStorageFunctionEliminatesUnmaterializedSourceRead(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Read(p *uint32)uint32{return *p};func Keep(*uint32){};func F(){var x uint32;if Read(&x)!=0 {panic(1)};x=7;Keep(&x)}`)
	base := nativeproof.TransitionLocation{Offset: -16}
	object := storageBoundaryOperands(t, completed.prior)[0].location.object
	for _, variant := range []string{"eliminated", "materialized", "early-read", "missing-write", "wrong-write"} {
		t.Run(variant, func(t *testing.T) {
			write := storageFunctionOperation{base, 4, true, 7}
			read := storageFunctionOperation{base, 4, false, 0}
			ops := []storageFunctionOperation{write}
			switch variant {
			case "materialized":
				ops = []storageFunctionOperation{{base, 4, true, 0}, read, write}
			case "early-read":
				ops = []storageFunctionOperation{read, write}
			case "missing-write":
				ops = nil
			case "wrong-write":
				ops[0].value = 8
			}
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: object, base: base}}}
			bound, _ := native.BoundFor(fixture.image)
			if variant == "early-read" || variant == "materialized" {
				var actual nativeproof.TransitionAccess
				for _, access := range bound.Accesses {
					if access.Kind == nativeproof.FrameRead && access.Image == base.Image && access.Bytes.Start == base.Offset {
						actual = access
						break
					}
				}
				if actual.ID == 0 {
					t.Fatal("fixture lacks its actual native read")
				}
				if variant == "early-read" {
					var assignments []br.Assignment
					for _, cell := range bound.Prefix.InitialMemory {
						if !cell.Image && cell.Offset >= base.Offset && cell.Offset < base.Offset+4 {
							if cell.Value.View().Op != br.Variable || cell.Value.Sort() != br.Bits(8) || cell.Pointer != nil {
								t.Fatal("native initial local bytes were specialized")
							}
							assignments = append(assignments, br.Assignment{Variable: cell.Value, Value: 0xa5})
						}
					}
					value, err := br.Eval(t.Context(), actual.Value, assignments, br.Limits{})
					if err != nil || value != 0xa5a5a5a5 {
						t.Fatalf("independently valid native read lost arbitrary nonzero initial bytes: value=%x err=%v", value, err)
					}
				}
				proposal, err := nativeproof.ProposeRegionTransition(t.Context(), fixture.image, fixture.entry, actual.PC, nativeproof.TransitionLimits{})
				if err != nil {
					t.Fatal(err)
				}
				prefix, err := nativeproof.CheckRegionTransition(t.Context(), fixture.image, fixture.entry, fixture.face, proposal, nativeproof.TransitionLimits{})
				if err != nil {
					t.Fatal(err)
				}
				call := completed.prior.boundary.(*ssa.Call)
				// Obtain a real call-operand receipt for this separate operand
				// judgment; the completed return retains only its common prefix.
				callPrefix := globalPrefix(t, source, call)
				operand, err := checkGlobalOperandCorrespondence(t.Context(), source, source.prog.Roots["F"], call, fixture.image, fixture.entry, actual.PC, callPrefix, prefix, rho)
				if variant == "materialized" {
					if err != nil || operand == nil {
						t.Fatalf("actual initialized read boundary refused: %v", err)
					}
				} else {
					var refusal *br.Refusal
					if operand != nil || !errors.As(err, &refusal) || refusal.Code != br.Unsupported {
						t.Fatalf("actual read boundary invented native zero bytes or refused elsewhere: %v", err)
					}
				}
			}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			positive := variant == "eliminated" || variant == "materialized"
			if !positive {
				if proof != nil || err == nil || !strings.Contains(err.Error(), "complete effects:") {
					t.Fatalf("invalid native effects accepted or refused outside correspondence: %v", err)
				}
				if variant == "missing-write" && !strings.Contains(err.Error(), "missing native effect bytes") {
					t.Fatalf("missing ordinary write refused elsewhere: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if proof.accesses[0].instruction.Parent() != completed.prior.boundary.(*ssa.Call).Call.StaticCallee() || proof.accesses[0].invocation == (regionInvocation{}) {
				t.Fatal("source read lacks actual checked child invocation")
			}
			if variant == "eliminated" {
				if len(proof.eliminated) != 1 || proof.eliminated[0] != 0 || len(proof.matched) != 1 || proof.matched[0].source != 1 || len(proof.materialized) != 0 {
					t.Fatal("source-only read supplied native initialization or erased the explicit write")
				}
			} else if len(proof.eliminated) != 0 || len(proof.matched) != 2 || len(proof.materialized) != 1 {
				t.Fatal("actual initialized read lost its native effects")
			}
		})
	}
}

func TestStorageFunctionEliminatedReadDoesNotMaterialize(t *testing.T) {
	source, completed := storageFunctionSource(t, `var G uint32;func Read(p *uint32)uint32{return *p};func Keep(*uint32){};func F(){var x uint32;if Read(&x)!=0 {panic(1)};G=7;if Read(&x)!=0 {panic(1)};x=7;Keep(&x)}`)
	x := nativeproof.TransitionLocation{Offset: -16}
	g := nativeproof.TransitionLocation{Image: true, Offset: 0x700008}
	ops := []storageFunctionOperation{{g, 4, true, 7}, {x, 4, true, 0}, {x, 4, false, 0}, {x, 4, true, 7}}
	fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
	rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{
		{object: storageBoundaryOperands(t, completed.prior)[0].location.object, base: x},
		{object: regionObject{kind: regionGlobal, site: source.prog.Roots["F"].Pkg.Members["G"].(*ssa.Global)}, base: g},
	}}
	proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.eliminated) != 1 || proof.eliminated[0] != 0 || len(proof.materialized) != 1 || proof.materialized[0] != 1 || len(proof.matched) != 3 {
		t.Fatal("source-only elimination supplied or displaced actual later materialization")
	}
}

func TestStorageFunctionLocalReadDoesNotEraseAtomic(t *testing.T) {
	source, completed := storageFunctionSource(t, `func Read(p *uint32)uint32{return *p};func Keep(*uint32){};func F(){var x uint32;if Read(&x)!=0 {panic(1)};x=7;Keep(&x)}`)
	const pc = uint64(0x401000)
	for _, atomic := range []bool{false, true} {
		t.Run(fmt.Sprint(atomic), func(t *testing.T) {
			// Both variants materialize zero, then read zero and write seven.
			// Only the indivisible nature of those last two accesses differs.
			code := []byte{0xc3, 0x48, 0x83, 0xec, 0x40,
				0xb8, 0, 0, 0, 0, 0x89, 0x44, 0x24, 48,
				0xba, 7, 0, 0, 0}
			if atomic {
				code = append(code, 0xf0, 0x0f, 0xb1, 0x54, 0x24, 48)
			} else {
				code = append(code, 0x8b, 0x44, 0x24, 48, 0x89, 0x54, 0x24, 48)
			}
			code = append(code, 0x48, 0x83, 0xc4, 0x40)
			cut := pc + uint64(len(code))
			code = append(code, 0xc3)
			fixture, native := storageFunctionNativeProgram(t, code, cut, nativeproof.OriginDomain{}, func(face *nativeproof.TransitionInterface) {
				face.Conditions.LockedMemory = nativeproof.LockedMemoryModel
			})
			bound, _ := native.BoundFor(fixture.image)
			if len(bound.Accesses) != 4 {
				t.Fatal("fixture lost materialization, read/write or actual return")
			}
			if atomic {
				if len(bound.Prefix.PrimitiveEffects) != 1 {
					t.Fatal("fixture lost its actual atomic primitive")
				}
				effect, ok := bound.Prefix.PrimitiveEffects[0].(nativeproof.LockedCompareExchangeEffect)
				if !ok || effect.Width != 4 || effect.ReadAccess != 1 || effect.WriteAccess != 2 {
					t.Fatal("fixture did not execute the intended narrow atomic group")
				}
			} else if len(bound.Prefix.PrimitiveEffects) != 0 {
				t.Fatal("ordinary control acquired an atomic")
			}
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: storageBoundaryOperands(t, completed.prior)[0].location.object, base: nativeproof.TransitionLocation{Offset: -16}}}}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if !atomic {
				if err != nil || proof == nil || len(proof.materialized) != 1 || len(proof.matched) != 2 || len(proof.eliminated) != 0 {
					t.Fatalf("ordinary read/write control refused: %v", err)
				}
			} else if proof != nil || err == nil || !strings.Contains(err.Error(), "ordered source/native effects differ") {
				t.Fatalf("ordinary source accesses erased an actual atomic group: %v", err)
			}
		})
	}
}

func TestStorageFunctionLocalReadIsolation(t *testing.T) {
	for _, escaped := range []bool{false, true} {
		t.Run(fmt.Sprint(escaped), func(t *testing.T) {
			keep := `func Keep(*uint32){}`
			if escaped {
				keep = `var Escaped *uint32;func Keep(p *uint32){Escaped=p}`
			}
			source, completed := storageFunctionSource(t, `func Read(p *uint32)uint32{return *p};`+keep+`;func F(){var x uint32;if Read(&x)!=0 {panic(1)};x=7;Keep(&x)}`)
			base := nativeproof.TransitionLocation{Offset: -16}
			fixture, native := storageFunctionNative(t, []storageFunctionOperation{{base, 4, true, 7}}, nativeproof.OriginDomain{})
			object := storageBoundaryOperands(t, completed.prior)[0].location.object
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: object, base: base}}}
			f := storageFunctionReadChoiceFixture{source, completed, fixture, native, rho}
			account, _, _ := storageFunctionSearchAccount(t, f)
			read := -1
			for i, access := range account.accesses {
				if !access.write && access.location.object == object {
					read = i
					break
				}
			}
			if read < 0 {
				t.Fatal("fixture lacks its checked local read")
			}
			isolated, err := account.isolatedAllocatedRead(t.Context(), read)
			if err != nil || isolated == escaped {
				t.Fatalf("actual allocation/read isolation: escaped=%v isolated=%v err=%v", escaped, isolated, err)
			}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
			if escaped {
				if proof != nil || err == nil {
					t.Fatal("escaped local read gained source-only elimination")
				}
				return
			}
			if err != nil || proof == nil {
				t.Fatalf("isolated source read could not be eliminated: %v", err)
			}
		})
	}
}
