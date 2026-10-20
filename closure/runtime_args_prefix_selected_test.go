package closure

import (
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

type selectedArgsLayout struct {
	call, wrapper, nested, body, cut uint64
	argc, argv, barrier, guard       uint64
	excluded                         []uint64
	regions                          []nativeproof.Span
	expansions                       []nativeproof.TransitionExpansion
}

// Small fresh ELF models isolate the two exclusion premises without rebuilding
// the selected source/body proof for each counterexample. No projected
// certificate state is ever edited. The actual selected consumers above retain
// independent full-root permission and coverage controls.
func TestNarrowReferenceSelectedRuntimeArgsControls(t *testing.T) {
	for _, mode := range []string{"zero-fill", "padding-nonzero", "intervening-write", "one-byte-zero", "guard-value", "guard-provenance"} {
		t.Run(mode, func(t *testing.T) {
			const base, data = uint64(0x401000), uint64(0x600000)
			f := globalNativeImage(t, [2]uint64{data, data + 8}, [3]uint64{}, data, data, nil, "")
			var code []byte
			pc := func() uint64 { return base + uint64(len(code)) }
			rip := func(prefix []byte, address uint64, tail ...byte) {
				next := pc() + uint64(len(prefix)+4+len(tail))
				code = append(code, prefix...)
				code = binary.LittleEndian.AppendUint32(code, uint32(int64(address)-int64(next)))
				code = append(code, tail...)
			}
			// Derive and materialize the current origin-relative guard, then
			// enter with the same SP displacement as the selected nested call.
			code = append(code, 0x48, 0x8d, 0x84, 0x24)
			distance := int32(-65584)
			if mode == "guard-value" {
				distance = 8
			}
			code = binary.LittleEndian.AppendUint32(code, uint32(distance))
			rip([]byte{0x48, 0x89, 0x05}, data+16)
			rip([]byte{0x4c, 0x8d, 0x35}, data)
			if mode == "guard-provenance" {
				rip([]byte{0xc6, 0x05}, data+23, 0xff)
			}
			if mode == "intervening-write" {
				rip([]byte{0xc6, 0x05}, data+33, 1)
			}
			if mode == "one-byte-zero" {
				rip([]byte{0xc6, 0x05}, data+32, 0)
			}
			code = append(code, 0x48, 0x83, 0xec, 88)
			guard := pc()
			code = append(code, 0x49, 0x3b, 0x66, 0x10, 0x76, 0)
			guardBranch := len(code) - 1
			barrier := pc()
			rip([]byte{0x83, 0x3d}, data+32, 0)
			code = append(code, 0x74, 5)
			// Both unexpanded slow CALLs are structurally valid, but may end
			// coverage only under an independently proved false guard.
			code = append(code, 0xe8, 0, 0, 0, 0)
			cut := pc()
			code = append(code, 0x90)
			code[guardBranch] = byte(len(code) - guardBranch - 1)
			code = append(code, 0xe8, 0, 0, 0, 0)
			copy(f.raw[4096:], code)
			binary.LittleEndian.PutUint64(f.raw[64+32:], uint64(len(code)))
			binary.LittleEndian.PutUint64(f.raw[64+40:], uint64(len(code)))
			// A genuine PT_LOAD zero tail supplies all four bytes, including
			// padding. The nonzero case instead owns file-backed padding.
			binary.LittleEndian.PutUint64(f.raw[64+56+32:], 0)
			if mode == "padding-nonzero" {
				binary.LittleEndian.PutUint64(f.raw[64+56+32:], 128)
				f.raw[8192+33] = 1
			}
			image, err := nativeproof.NewImage(t.Context(), f.raw)
			if err != nil {
				t.Fatal(err)
			}
			face := globalNativeFace([]nativeproof.Span{{Start: data, End: data + 24}, {Start: data + 32, End: data + 36}})
			face.Envelope = nativeproof.RelativeSpan{Start: -65584, End: 8}
			if mode != "one-byte-zero" {
				face.Initialization, err = nativeproof.CheckImageInitialization(t.Context(), image, nativeproof.StaticELFInitialization)
				if err != nil {
					t.Fatal(err)
				}
			}
			options := nativeproof.TransitionOptions{Expansions: []nativeproof.TransitionExpansion{{PC: guard}, {PC: barrier}}}
			prefix, err := nativeproof.ProposeTransition(t.Context(), image, guard, nativeproof.TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			prior, err := nativeproof.CheckTransition(t.Context(), image, face, prefix, nativeproof.TransitionLimits{})
			if err != nil {
				t.Fatal("fresh exclusion control lacks valid current-state prefix", err)
			}
			proposal, err := nativeproof.ProposeTransitionContinuation(t.Context(), prior, cut, options)
			if err != nil {
				t.Fatal(err)
			}
			result, err := nativeproof.CheckTransitionContinuation(t.Context(), prior, proposal)
			if mode == "zero-fill" {
				bound, ok := result.BoundFor(image)
				if err != nil || !ok || len(bound.ExcludedBoundaries) != 2 {
					t.Fatal("full current premises did not exclude both slow calls", err)
				}
			} else {
				var refusal *nativeproof.Refusal
				wantPC := cut - 5
				if mode == "guard-value" || mode == "guard-provenance" {
					wantPC = cut + 1
				}
				if _, ok := result.Bound(); ok || !errors.As(err, &refusal) || refusal.Premise != "transition-guard" || refusal.PC != wantPC {
					t.Fatal("invalid current premise acquired a complete cut", mode, err)
				}
				t.Logf("%s refused at %s: %v", mode, refusal.Premise, err)
			}
		})
	}
}

// Names locate candidates. Actual CALL operands, memory widths and native
// membership are checked again by the production transition checker.
func selectedArgsCandidate(t testing.TB, raw []byte, locations map[string]uint64, start uint64) selectedArgsLayout {
	t.Helper()
	decode := globalCandidateDecoder(t, raw)
	x := selectedArgsLayout{}
	for range 4 {
		start += uint64(decode(start).Len)
	}
	x.call = start
	target := func(pc uint64) uint64 {
		i := decode(pc)
		r, ok := i.Args[0].(x86asm.Rel)
		if i.Op != x86asm.CALL || !ok {
			t.Fatal("argument candidate lacks a direct CALL")
		}
		return uint64(int64(pc) + int64(i.Len) + int64(r))
	}
	x.wrapper = target(x.call)
	if x.wrapper != locations["runtime.args.abi0"] {
		t.Fatal("startup CALL does not target candidate wrapper")
	}
	expand := func(pc uint64) {
		x.expansions = append(x.expansions, nativeproof.TransitionExpansion{PC: pc, AllActivations: true})
	}
	expand(x.call)
	for pc, n := x.wrapper, 0; n < 64; n++ {
		i := decode(pc)
		if i.Op == x86asm.CALL {
			x.nested, x.body = pc, target(pc)
			expand(pc)
			break
		}
		if i.Op == x86asm.XORPS || i.Op == x86asm.NOP {
			expand(pc)
		}
		pc += uint64(i.Len)
	}
	if x.body == 0 || x.body != locations["runtime.args"] {
		t.Fatal("wrapper CALL does not target candidate body")
	}
	// Scan through the restart JMP solely to locate proposals for both excluded
	// calls. The checked graph, not this linear search bound, establishes coverage.
	for pc, n := x.body, 0; n < 128; n++ {
		i := decode(pc)
		if i.Op == x86asm.CMP {
			expand(pc)
			if mem, ok := i.Args[1].(x86asm.Mem); ok && mem.Base == x86asm.R14 && mem.Disp == 16 && i.MemBytes == 8 {
				x.guard = pc
			}
		}
		for _, arg := range i.Args {
			mem, ok := arg.(x86asm.Mem)
			if !ok || mem.Base != x86asm.RIP {
				continue
			}
			address := uint64(int64(pc) + int64(i.Len) + mem.Disp)
			switch {
			case i.Op == x86asm.MOV && i.Args[0] == arg && i.MemBytes == 4 && address == locations["runtime.argc"]:
				x.argc = address
			case i.Op == x86asm.MOV && i.Args[0] == arg && i.MemBytes == 8 && address == locations["runtime.argv"]:
				x.argv = address
			case i.Op == x86asm.CMP && i.MemBytes == 4 && address == locations["runtime.writeBarrier"]:
				x.barrier = address
			}
		}
		if i.Op == x86asm.CALL {
			if target(pc) == locations["runtime.sysargs"] {
				x.cut = pc
			} else {
				x.excluded = append(x.excluded, pc)
			}
		}
		if i.Op == x86asm.JMP {
			break
		}
		pc += uint64(i.Len)
	}
	if x.argc == 0 || x.argv == 0 || x.barrier == 0 || x.guard == 0 || x.cut == 0 || len(x.excluded) != 2 {
		t.Fatal("argument candidate lacks exact stores, comparisons, cut or slow calls")
	}
	x.regions = []nativeproof.Span{{Start: x.argc, End: x.argc + 4}, {Start: x.argv, End: x.argv + 8}, {Start: x.barrier, End: x.barrier + 4}}
	return x
}

func selectedArgsProposal(t testing.TB, prior nativeproof.TransitionCertificate, x selectedArgsLayout) nativeproof.TransitionProposal {
	t.Helper()
	p, err := nativeproof.ProposeTransitionContinuation(t.Context(), prior, x.cut, nativeproof.TransitionOptions{Expansions: x.expansions})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func assertSelectedArgsPrefix(t testing.TB, raw []byte, image *nativeproof.Image, prior nativeproof.TransitionCertificate, x selectedArgsLayout) {
	t.Helper()
	before, _ := prior.BoundFor(image)
	p := selectedArgsProposal(t, prior, x)
	continued, err := nativeproof.CheckTransitionContinuation(t.Context(), prior, p)
	if err != nil {
		t.Fatal("selected argument prefix", err)
	}
	after, _ := continued.BoundFor(image)
	if before.Boundary.PC != x.call || after.ConditionalRegion || after.Entry != before.Entry || after.Origin != before.Origin || after.EntryPredicate != before.EntryPredicate || after.InitialRegisters != before.InitialRegisters || after.InitialVectors != before.InitialVectors || after.InitialPredicates != before.InitialPredicates || after.InitialDirection != before.InitialDirection || after.InitialFS != before.InitialFS || !reflect.DeepEqual(after.InitialMemory, before.InitialMemory) || !reflect.DeepEqual(after.Words, before.Words) || !reflect.DeepEqual(after.Interface, before.Interface) || !reflect.DeepEqual(after.ExcludedOrigins, before.ExcludedOrigins) {
		t.Fatal("argument prefix replaced original authority, inputs or premises")
	}
	if after.Boundary.PC != x.cut || after.Boundary.Instruction.Op != x86asm.CALL || after.Thread != before.Thread || after.Direction != before.Direction || after.SSE != before.SSE || !reflect.DeepEqual(after.PrimitiveEffects, before.PrimitiveEffects) || !reflect.DeepEqual(after.Abstractions, before.Abstractions) || !reflect.DeepEqual(after.Instructions[:len(before.Instructions)], before.Instructions) || !reflect.DeepEqual(after.Accesses[:len(before.Accesses)], before.Accesses) || !reflect.DeepEqual(after.ExcludedBoundaries[:len(before.ExcludedBoundaries)], before.ExcludedBoundaries) {
		t.Fatal("argument prefix lost prior effects or executed beyond the cut")
	}
	decode := globalCandidateDecoder(t, raw)
	if len(after.Frames) != 2 || after.Frames[0].Call != x.call || after.Frames[0].Return != x.call+uint64(decode(x.call).Len) || !storageTestStack(after.Geometry, after.Frames[0].Slot, -56) || after.Frames[1].Call != x.nested || after.Frames[1].Return != x.nested+uint64(decode(x.nested).Len) || !storageTestStack(after.Geometry, after.Frames[1].Slot, -88) || after.Boundary.Context != nativeproof.TransitionActivationID(after.Frames[1].ID) {
		t.Fatal("argument prefix lost actual nested control words or active contexts")
	}
	b := br.NewBuilder(4096)
	account := globalFunctionCorrespondence{antecedent: before.CutGuard}
	claim := 0
	equal := func(got, want br.Term) {
		t.Helper()
		claim++
		if err := account.equal(t.Context(), got, want); err != nil {
			t.Fatalf("argument prefix universal value relation %d: %v\n%s", claim, err, correspondenceExpressionPair(got, want))
		}
	}
	word := func(memory []nativeproof.TransitionByte, image bool, offset int64, width int) br.Term {
		t.Helper()
		v, err := storageNativeWord(t.Context(), b, memory, storageTestExtent(t, before.Geometry, storageTestSelector(image, offset), int64(width)), width)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	initial := word(before.InitialMemory, false, 0, 8)
	count, _ := b.Make(br.Trunc, br.Bits(32), 0, initial)
	count64, _ := b.Make(br.ZExt, br.Bits(64), 0, count)
	eight, _ := b.Const(br.Bits(64), 8)
	vector, _ := b.Make(br.Add, br.Bits(64), 0, before.Origin, eight)
	zero32, _ := b.Const(br.Bits(32), 0)
	zero64, _ := b.Const(br.Bits(64), 0)
	equal(word(after.Memory, true, int64(x.argc), 4), count)
	equal(word(after.Memory, true, int64(x.argv), 8), vector)
	equal(word(before.InitialMemory, true, int64(x.barrier), 4), zero32)
	equal(word(before.Memory, true, int64(x.barrier), 4), zero32)
	equal(after.Registers[nativeproof.RAX].Value, count64)
	equal(after.Registers[nativeproof.RBX].Value, vector)
	equal(after.CutGuard, before.CutGuard)
	for _, flag := range []struct {
		actual nativeproof.TransitionFlag
		value  uint64
	}{{after.Flags.CF, 0}, {after.Flags.OF, 0}, {after.Flags.SF, 0}, {after.Flags.ZF, 1}, {after.Flags.AF, 0}, {after.Flags.PF, 1}} {
		if !flag.actual.Defined || flag.actual.Preserved {
			t.Fatal("final four-byte comparison lost its defined arithmetic flags")
		}
		want, _ := b.Const(br.Bool(), flag.value)
		equal(flag.actual.Value, want)
	}
	for reg, offset := range map[nativeproof.Register]int64{nativeproof.RSP: -112, nativeproof.RBP: -96, nativeproof.RBX: 8} {
		if !storageTestStack(before.Geometry, after.Registers[reg].Pointer, offset) {
			t.Fatal("argument register lost origin provenance", reg)
		}
	}
	for reg, value := range after.Registers {
		switch nativeproof.Register(reg) {
		case nativeproof.RAX, nativeproof.RBX, nativeproof.RSP, nativeproof.RBP, nativeproof.R14:
		default:
			if value != before.Registers[reg] || after.Preserved[reg] != before.Preserved[reg] {
				t.Fatal("argument prefix changed another register", reg)
			}
		}
	}
	for reg, value := range after.Vectors {
		if reg == 15 {
			equal(value.Lo, zero64)
			equal(value.Hi, zero64)
		} else if value != before.Vectors[reg] {
			t.Fatal("argument prefix changed another vector")
		}
	}
	for _, cell := range after.Memory {
		cell := storageTestByte(t, after.Geometry, cell)
		if cell.Image && cell.Offset >= int64(x.argv) && cell.Offset < int64(x.argv+8) && (cell.Pointer != after.Registers[nativeproof.RBX].Pointer || cell.PointerLane != uint8(cell.Offset-int64(x.argv))) {
			t.Fatal("stored full pointer lost its ordered origin lanes")
		}
		if !cell.Image && cell.Offset >= -96 && cell.Offset < -88 && (!storageTestStack(before.Geometry, cell.Pointer, -64) || cell.PointerLane != uint8(cell.Offset+96)) {
			t.Fatal("saved wrapper BP lost its full original-origin relation")
		}
	}
	writes := []storageFootprint{{Bytes: storageTestExtent(t, after.Geometry, nativeproof.StackOffset(-56), 8)}, {Bytes: storageTestExtent(t, after.Geometry, nativeproof.StackOffset(-64), 8)}, {Bytes: storageTestExtent(t, after.Geometry, nativeproof.StackOffset(-88), 8)}, {Bytes: storageTestExtent(t, after.Geometry, nativeproof.StackOffset(-96), 8)}, {Bytes: storageTestExtent(t, after.Geometry, nativeproof.ImageAddress(x.argc), 4)}, {Bytes: storageTestExtent(t, after.Geometry, nativeproof.ImageAddress(x.argv), 8)}}
	if err := selectedStartupMemoryFrame(after.Geometry, before.Memory, after.Memory, writes); err != nil {
		t.Fatal(err)
	}
	fsDescription, fsErr := before.Geometry.DescribePointer(before.Thread.FS.Pointer)
	contextDescription, contextErr := after.Geometry.DescribePointer(after.Registers[nativeproof.R14].Pointer)
	fs, fsOK := fsDescription.Coordinate.(nativeproof.ImageAddress)
	context, contextOK := contextDescription.Coordinate.(nativeproof.ImageAddress)
	if fsErr != nil || contextErr != nil || !fsOK || !contextOK {
		t.Fatal("wrapper lost current FS/image provenance")
	}
	equal(after.Registers[nativeproof.R14].Value, word(before.Memory, true, int64(fs)-8, 8))
	// Origin alignment is part of the opaque native theorem, not an
	// unconditional scalar rewrite of the startup AND. Check its exact origin
	// lanes and unchanged current bytes; do not invent an extra scalar premise.
	guardValue := word(before.Memory, true, int64(context+16), 8)
	for _, cell := range before.Memory {
		cell := storageTestByte(t, before.Geometry, cell)
		if cell.Image && cell.Offset >= int64(context+16) && cell.Offset < int64(context+24) && (!storageTestStack(before.Geometry, cell.Pointer, -65584) || cell.PointerLane != uint8(cell.Offset-int64(context+16))) {
			t.Fatal("current guard lacks full original-origin provenance")
		}
	}
	outerReturn, _ := b.Const(br.Bits(64), after.Frames[0].Return)
	innerReturn, _ := b.Const(br.Bits(64), after.Frames[1].Return)
	// Complete ordered pointer lanes establish S-64 under the native
	// scalar/provenance invariant. The scalar account below also checks that
	// the saved word is exactly this PUSH's actual value, with no restored bytes.
	wrapperBP := word(after.Memory, false, -96, 8)
	expected := []struct {
		image bool
		kind  nativeproof.AccessKind
		start int64
		width int
		value br.Term
	}{
		{false, nativeproof.FrameWrite, -56, 8, outerReturn},
		{false, nativeproof.FrameWrite, -64, 8, before.Registers[nativeproof.RBP].Value},
		{false, nativeproof.FrameRead, -48, 4, count},
		{false, nativeproof.FrameRead, -40, 8, vector},
		{true, nativeproof.FrameRead, int64(fs) - 8, 8, after.Registers[nativeproof.R14].Value},
		{false, nativeproof.FrameWrite, -88, 8, innerReturn},
		{true, nativeproof.FrameRead, int64(context + 16), 8, guardValue},
		{false, nativeproof.FrameWrite, -96, 8, wrapperBP},
		{true, nativeproof.FrameWrite, int64(x.argc), 4, count},
		{true, nativeproof.FrameRead, int64(x.barrier), 4, zero32},
		{true, nativeproof.FrameRead, int64(x.argv), 8, word(before.Memory, true, int64(x.argv), 8)},
		{true, nativeproof.FrameWrite, int64(x.argv), 8, vector},
	}
	accesses := after.Accesses[len(before.Accesses):]
	if len(accesses) != len(expected) {
		t.Fatalf("argument prefix has %d accesses, want %d", len(accesses), len(expected))
	}
	for i, want := range expected {
		got := storageTestAccess(t, after.Geometry, accesses[i])
		if got.Image != want.image || got.Kind != want.kind || got.Bytes != (nativeproof.RelativeSpan{Start: want.start, End: want.start + int64(want.width)}) {
			t.Fatal("argument access lost exact width or order", i, got)
		}
		equal(got.Value, want.value)
		if got.Kind == nativeproof.FrameWrite {
			equal(word(after.Memory, want.image, want.start, want.width), want.value)
		}
		instruction := slices.IndexFunc(after.Instructions[len(before.Instructions):], func(g nativeproof.GuardedInstruction) bool {
			return g.ID == got.ID && g.Start == got.PC && g.Context == got.Context
		})
		if instruction < 0 {
			t.Fatal("argument access lost its executed occurrence")
		}
		guard := before.CutGuard
		if want.image && want.kind == nativeproof.FrameRead && want.start == int64(x.argv) {
			// The scalar condition is provably false but need not normalize to
			// a literal before transfer. Its retained read is conditional, not
			// an executed barrier arm or an erased dependency.
			guard, _ = b.Const(br.Bool(), 0)
		}
		equal(after.Instructions[len(before.Instructions)+instruction].Guard, guard)
	}
	if len(after.ExcludedBoundaries) != len(before.ExcludedBoundaries)+2 {
		t.Fatal("missing slow-call exclusion")
	}
	for _, pc := range x.excluded {
		if !slices.ContainsFunc(after.ExcludedBoundaries[len(before.ExcludedBoundaries):], func(e nativeproof.ExcludedBoundary) bool {
			return e.PC == pc && e.Instruction.Op == x86asm.CALL && !e.Frontier
		}) {
			t.Fatal("slow CALL has no independent exclusion")
		}
	}
	// A proposal cannot omit a call target or replace it with its continuation.
	for _, mode := range []string{"missing-node", "wrong-call-target"} {
		bad := selectedArgsProposal(t, prior, x)
		for i, node := range bad.Nodes {
			if node.PC != x.nested {
				continue
			}
			if mode == "missing-node" {
				bad.Nodes = slices.Delete(bad.Nodes, i, i+1)
			} else {
				for _, other := range bad.Nodes {
					if other.PC == x.cut {
						bad.Nodes[i].Successors = []nativeproof.TransitionOccurrenceID{other.ID}
						break
					}
				}
			}
			break
		}
		result, err := nativeproof.CheckTransitionContinuation(t.Context(), prior, bad)
		if _, ok := result.Bound(); ok || err == nil {
			t.Fatal("invalid argument coverage acquired authority", mode)
		}
	}
	t.Logf("conditional ELF-root argument prefix through wrapper %#x/body %#x stops before CALL %#x: low32(W), S+8; active returns %#x/%#x, SP=S-112, BP=S-96, current guard and four-byte barrier exclusions; count/vector interpretation remains open", x.wrapper, x.body, x.cut, after.Frames[0].Return, after.Frames[1].Return)
}

func assertSelectedArgsPermissions(t testing.TB, raw []byte, image *nativeproof.Image, locations map[string]uint64, face nativeproof.TransitionInterface, root nativeproof.TransitionProposal, limits nativeproof.TransitionLimits, body nativeproof.TransitionReturnCertificate, x selectedArgsLayout) {
	t.Helper()
	for _, missing := range []string{"count-read", "pointer-read", "count-write", "pointer-write", "barrier-read", "barrier-padding"} {
		bad := face
		bad.Regions, bad.ImageRegions = slices.Clone(face.Regions), slices.Clone(face.ImageRegions)
		switch missing {
		case "count-read":
			bad.Regions[3].Readable = false
		case "pointer-read":
			bad.Regions[4].Readable = false
		default:
			address := x.barrier
			if missing == "count-write" {
				address = x.argc
			}
			if missing == "pointer-write" {
				address = x.argv
			}
			bad.ImageRegions = slices.DeleteFunc(bad.ImageRegions, func(s nativeproof.Span) bool { return s.Start == address })
			if missing == "barrier-padding" {
				bad.ImageRegions = append(bad.ImageRegions, nativeproof.Span{Start: address, End: address + 1})
			}
		}
		entered, err := nativeproof.CheckTransition(t.Context(), image, bad, root, limits)
		if err != nil {
			t.Fatal("permission control lacks rooted body entry", missing, err)
		}
		applied, err := nativeproof.CheckTransitionActiveReturn(t.Context(), entered, body)
		if err != nil {
			t.Fatal("permission control lacks completed body", missing, err)
		}
		returned, _ := applied.Successor()
		prior := assertSelectedStartupWordTransfer(t, raw, image, returned, locations)
		result, err := nativeproof.CheckTransitionContinuation(t.Context(), prior, selectedArgsProposal(t, prior, x))
		var refusal *nativeproof.Refusal
		if _, ok := result.Bound(); ok || !errors.As(err, &refusal) || refusal.Premise != "transition-permission" {
			t.Fatal("missing argument permission was not independently refused", missing, err)
		}
	}
}
