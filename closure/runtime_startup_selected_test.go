package closure

import (
	"context"
	"encoding/binary"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

type selectedStartupCandidate struct {
	face                     nativeproof.TransitionInterface
	call, syscall, join, cut uint64
	context, machine, tls    uint64
	expansions               []nativeproof.TransitionExpansion
}

// Symbols and decoded operands locate a bounded proposal only. The native
// checker obtains the entry from the ELF and independently checks every path,
// byte, pointer, permission and loading premise through the proposed boundary.
func selectedStartupLayout(t testing.TB, raw []byte, image *nativeproof.Image, locations map[string]uint64) selectedStartupCandidate {
	t.Helper()
	x := selectedStartupCandidate{context: locations["runtime.g0"], machine: locations["runtime.m0"]}
	decode := globalCandidateDecoder(t, raw)
	for pc, count := locations["runtime.rt0_go.abi0"], 0; count < 512; count++ {
		i := decode(pc)
		if i.Op == x86asm.CLD {
			x.cut = pc
			break
		}
		if i.Op == x86asm.LEA {
			if mem, ok := i.Args[1].(x86asm.Mem); ok && mem.Base == x86asm.RIP {
				address := uint64(int64(pc) + int64(i.Len) + mem.Disp)
				if i.Args[0] == x86asm.RDI {
					x.tls = address
				}
				if x.call != 0 && i.Args[0] == x86asm.RCX && address == x.context {
					x.join = pc
				}
			}
		}
		if rel, ok := i.Args[0].(x86asm.Rel); ok && i.Op == x86asm.CALL && uint64(int64(pc)+int64(i.Len)+int64(rel)) == locations["runtime.settls.abi0"] {
			x.call = pc
		}
		pc += uint64(i.Len)
	}
	for pc, count := locations["runtime.settls.abi0"], 0; count < 64; count++ {
		i := decode(pc)
		if i.Op == x86asm.SYSCALL {
			x.syscall = pc
		}
		if i.Op == x86asm.RET {
			break
		}
		pc += uint64(i.Len)
	}
	for _, address := range []uint64{x.context, x.machine, x.tls, x.call, x.syscall, x.join, x.cut, locations["runtime.isIntel"], locations["runtime.processorVersionInfo"], locations["_cgo_init"]} {
		if address == 0 {
			t.Fatal("selected startup candidate is incomplete")
		}
	}
	x.expansions = []nativeproof.TransitionExpansion{{PC: x.call, AllActivations: true}, {PC: x.syscall, AllActivations: true}}
	x.face = globalNativeFace([]nativeproof.Span{
		{Start: x.context, End: x.context + 32},
		{Start: x.context + 48, End: x.context + 56},
		{Start: x.machine, End: x.machine + 8},
		{Start: x.tls, End: x.tls + 8},
		{Start: locations["runtime.isIntel"], End: locations["runtime.isIntel"] + 1},
		{Start: locations["runtime.processorVersionInfo"], End: locations["runtime.processorVersionInfo"] + 4},
		{Start: locations["_cgo_init"], End: locations["_cgo_init"] + 8},
	})
	// The distant LEA needs addressability, not backing for the unused gap.
	// Grants cover the actual entry read, spills, control word and saved BP only.
	x.face.Envelope = nativeproof.RelativeSpan{Start: -65584, End: 8}
	x.face.Regions = []nativeproof.RelativeRegion{
		{Bytes: nativeproof.RelativeSpan{Start: 0, End: 8}, Readable: true},
		{Bytes: nativeproof.RelativeSpan{Start: -24, End: -8}, Writable: true},
		{Bytes: nativeproof.RelativeSpan{Start: -64, End: -48}, Readable: true, Writable: true},
	}
	x.face.Words = []int64{0}
	x.face.Conditions.CPUID = nativeproof.CPUIDModel
	x.face.Conditions.Syscall = nativeproof.LinuxAMD64SyscallModel
	x.face.Conditions.UserAddressBits = 48
	var err error
	x.face.Initialization, err = nativeproof.CheckImageInitialization(t.Context(), image, nativeproof.StaticELFInitialization)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func checkSelectedStartupRoot(ctx context.Context, image *nativeproof.Image, candidate selectedStartupCandidate, cut uint64) (nativeproof.TransitionCertificate, error) {
	proposal, err := nativeproof.ProposeTransition(ctx, image, cut, nativeproof.TransitionLimits{}, nativeproof.TransitionOptions{Expansions: candidate.expansions})
	if err != nil {
		return nativeproof.TransitionCertificate{}, err
	}
	return nativeproof.CheckTransition(ctx, image, candidate.face, proposal, nativeproof.TransitionLimits{})
}

// The suffix writes only these footprints. Other current bytes, including
// startup spills and returned call-frame scratch, keep their exact value and
// provenance; retaining initial memory or access history alone cannot show that.
func selectedStartupMemoryFrame(before, after []nativeproof.TransitionByte, writes []storageFootprint) error {
	if len(before) != len(after) {
		return fmt.Errorf("startup memory membership changed")
	}
	current := make(map[nativeproof.TransitionLocation]nativeproof.TransitionByte, len(after))
	for _, cell := range after {
		if _, exists := current[cell.TransitionLocation]; exists {
			return fmt.Errorf("startup memory location repeated")
		}
		current[cell.TransitionLocation] = cell
	}
	for _, old := range before {
		now, found := current[old.TransitionLocation]
		if !found {
			return fmt.Errorf("startup memory location disappeared")
		}
		written := false
		for _, span := range writes {
			written = written || old.Image == span.Image && old.Offset >= span.Bytes.Start && old.Offset < span.Bytes.End
		}
		if !written && old != now {
			return fmt.Errorf("untouched startup byte or provenance changed at %+v", old.TransitionLocation)
		}
	}
	return nil
}

func selectedStartupFixture(t *testing.T) ([]byte, *nativeproof.Image, selectedStartupCandidate) {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/startupprefix\n\ngo 1.27\n"})
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, image, locations := selectedRuntimeCheckArtifact(t, h)
	return raw, image, selectedStartupLayout(t, raw, image, locations)
}

func TestRuntimeStartupSelectedWrites(t *testing.T) {
	if testing.Short() {
		t.Skip("checks the selected compiler's initialized ELF startup and TLS effects")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected startup model is Linux amd64")
	}
	raw, image, x := selectedStartupFixture(t)
	prior, err := checkSelectedStartupRoot(t.Context(), image, x, x.join)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := prior.BoundFor(image)
	proposal, err := nativeproof.ProposeTransitionContinuation(t.Context(), prior, x.cut)
	if err != nil {
		t.Fatal(err)
	}
	continued, err := nativeproof.CheckTransitionContinuation(t.Context(), prior, proposal)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := continued.BoundFor(image)
	if !ok || b.ConditionalRegion || b.Entry != binary.LittleEndian.Uint64(raw[24:32]) || b.Entry != before.Entry || b.Origin != before.Origin || b.EntryPredicate != before.EntryPredicate || b.InitialRegisters != before.InitialRegisters || !reflect.DeepEqual(b.InitialMemory, before.InitialMemory) || !reflect.DeepEqual(b.Interface, before.Interface) {
		t.Fatal("startup continuation lost its actual ELF root or original inputs")
	}
	if b.Boundary.PC != x.cut || b.Boundary.Instruction.Op != x86asm.CLD || len(b.Frames) != 0 || b.Interface.PrivateFrame != nil || b.Interface.ReturnContext != nil {
		t.Fatal("startup prefix invented a completed call, private lifetime or CLD transfer")
	}
	if len(b.Instructions) != len(before.Instructions)+5 || !reflect.DeepEqual(b.Instructions[:len(before.Instructions)], before.Instructions) || len(b.Accesses) != len(before.Accesses)+3 || !reflect.DeepEqual(b.Accesses[:len(before.Accesses)], before.Accesses) || !reflect.DeepEqual(b.PrimitiveEffects, before.PrimitiveEffects) || !reflect.DeepEqual(b.ExcludedBoundaries, before.ExcludedBoundaries) || b.Flags != before.Flags || b.Thread != before.Thread {
		t.Fatal("numeric context writes lost prefix effects, exclusions or machine state")
	}
	if !b.Thread.ContextChanged || b.Thread.SelectorPreserved || b.Registers[nativeproof.RSP].Pointer != (nativeproof.OriginPointer{Origin: b.Origin, Offset: -48}) {
		t.Fatal("prior FS replacement or current stack relation was erased")
	}
	queries, replacements := 0, 0
	for _, effect := range b.PrimitiveEffects {
		switch effect.(type) {
		case nativeproof.CPUIDEffect:
			queries++
		case nativeproof.ArchSetFSEffect:
			replacements++
		default:
			t.Fatal("unexpected startup primitive")
		}
	}
	if queries != 2 || replacements != 1 || len(b.ExcludedBoundaries) != 3 {
		t.Fatal("lost conditional CPU queries, actual FS replacement or excluded error arms")
	}
	if err := selectedStartupMemoryFrame(before.Memory, b.Memory, []storageFootprint{{Image: true, Bytes: nativeproof.RelativeSpan{Start: int64(x.tls), End: int64(x.tls + 8)}}, {Image: true, Bytes: nativeproof.RelativeSpan{Start: int64(x.machine), End: int64(x.machine + 8)}}, {Image: true, Bytes: nativeproof.RelativeSpan{Start: int64(x.context + 48), End: int64(x.context + 56)}}}); err != nil {
		t.Fatal(err)
	}
	builder := br.NewBuilder(32)
	for i, tc := range []struct{ address, value uint64 }{{x.tls, x.context}, {x.machine, x.context}, {x.context + 48, x.machine}} {
		access := b.Accesses[len(before.Accesses)+i]
		if !access.Image || access.Kind != nativeproof.FrameWrite || access.Bytes != (nativeproof.RelativeSpan{Start: int64(tc.address), End: int64(tc.address + 8)}) {
			t.Fatal("numeric startup write footprint/order differs")
		}
		value, err := storageNativeWord(t.Context(), builder, b.Memory, nativeproof.TransitionLocation{Image: true, Offset: int64(tc.address)}, 8)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := builder.Const(br.Bits(64), tc.value)
		if _, err := br.Prove(t.Context(), value, want, br.Limits{}); err != nil {
			t.Fatal("numeric startup pointer value differs", err)
		}
		for _, cell := range b.Memory {
			if !cell.Image || cell.Offset < int64(tc.address) || cell.Offset >= int64(tc.address+8) {
				continue
			}
			pointer, ok := cell.Pointer.(nativeproof.ImagePointer)
			if !ok || pointer.Address != tc.value || cell.PointerLane != uint8(cell.Offset-int64(tc.address)) {
				t.Fatal("numeric startup pointer store lost owned image provenance")
			}
		}
	}
	for _, variant := range []string{"initialization", "machine-word", "context-word", "foreign-initialization", "syscall-model"} {
		t.Run(variant, func(t *testing.T) {
			bad := x
			bad.face.ImageRegions = slices.Clone(x.face.ImageRegions)
			switch variant {
			case "initialization":
				bad.face.Initialization = nativeproof.ImageInitialization{}
			case "machine-word":
				bad.face.ImageRegions = slices.DeleteFunc(bad.face.ImageRegions, func(span nativeproof.Span) bool { return span.Start == x.machine })
			case "context-word":
				bad.face.ImageRegions = slices.DeleteFunc(bad.face.ImageRegions, func(span nativeproof.Span) bool { return span.Start == x.context+48 })
			case "foreign-initialization":
				foreign, err := nativeproof.NewImage(t.Context(), raw)
				if err != nil {
					t.Fatal(err)
				}
				bad.face.Initialization, err = nativeproof.CheckImageInitialization(t.Context(), foreign, nativeproof.StaticELFInitialization)
				if err != nil {
					t.Fatal(err)
				}
			case "syscall-model":
				bad.face.Conditions.Syscall = ""
			}
			proof, err := checkSelectedStartupRoot(t.Context(), image, bad, x.cut)
			if _, accepted := proof.Bound(); accepted || err == nil {
				t.Fatal("startup accepted unavailable original premise", variant)
			}
		})
	}
	t.Logf("checked ELF entry %#x through TLS and three numeric context writes to unexecuted CLD %#x; process/loader applicability, typed storage and private lifetime remain open", b.Entry, b.Boundary.PC)
}

func TestSelectedStartupMemoryFrame(t *testing.T) {
	b := br.NewBuilder(8)
	value, _ := b.Const(br.Bits(8), 7)
	other, _ := b.Const(br.Bits(8), 9)
	origin, _ := b.Input(br.Bits(64), br.NewScope(), 0)
	_, owned := globalFunctionNative(t, "entry-pointer-global")
	_, foreign := globalFunctionNative(t, "entry-pointer-global")
	ownedBound, _ := owned.Bound()
	foreignBound, _ := foreign.Bound()
	pointer := ownedBound.State.Registers[nativeproof.R14].Pointer
	foreignPointer := foreignBound.State.Registers[nativeproof.R14].Pointer
	if pointer == nil || pointer == foreignPointer || !reflect.DeepEqual(pointer, foreignPointer) {
		t.Fatal("foreign-owner control must share bytes/address but not pointer identity")
	}
	before := []nativeproof.TransitionByte{
		{TransitionLocation: nativeproof.TransitionLocation{Offset: -24}, Value: value},
		{TransitionLocation: nativeproof.TransitionLocation{Offset: -56}, Value: value, Pointer: nativeproof.OriginPointer{Origin: origin, Offset: -48}, PointerLane: 1},
		{TransitionLocation: nativeproof.TransitionLocation{Image: true, Offset: 0x700000}, Value: value, Pointer: pointer},
		{TransitionLocation: nativeproof.TransitionLocation{Image: true, Offset: 0x700030}, Value: value},
	}
	writes := []storageFootprint{{Image: true, Bytes: nativeproof.RelativeSpan{Start: 0x700030, End: 0x700038}}}
	for _, variant := range []string{"unchanged", "allowed-write", "allowed-stack", "wrong-space", "spill-value", "scratch-pointer", "scratch-lane", "prior-image", "foreign-image", "missing", "duplicate", "moved"} {
		t.Run(variant, func(t *testing.T) {
			after := slices.Clone(before)
			admitted := slices.Clone(writes)
			switch variant {
			case "allowed-write":
				after[3].Value = other
			case "allowed-stack", "wrong-space":
				after[0].Value = other
				admitted = append(admitted, storageFootprint{Image: variant == "wrong-space", Bytes: nativeproof.RelativeSpan{Start: -24, End: -23}})
			case "spill-value":
				after[0].Value = other
			case "scratch-pointer":
				after[1].Pointer = nil
			case "scratch-lane":
				after[1].PointerLane = 0
			case "prior-image":
				after[2].Value = other
			case "foreign-image":
				after[2].Pointer = foreignPointer
			case "missing":
				after = after[1:]
			case "duplicate":
				after[0] = after[1]
			case "moved":
				after[0].Offset--
			}
			err := selectedStartupMemoryFrame(before, after, admitted)
			if (err == nil) != (variant == "unchanged" || variant == "allowed-write" || variant == "allowed-stack") {
				t.Fatalf("startup frame %s: %v", variant, err)
			}
		})
	}
}
