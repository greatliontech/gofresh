package closure

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

// Discovery supplies only candidate addresses and coverage choices. A fresh
// native root checks the actual prologue through executed RET; the previous
// post-prologue operand theorem supplies none of its entry premises.
func selectedAtomicReturn(t testing.TB, raw []byte, image *nativeproof.Image, locations map[string]uint64) nativeproof.TransitionReturnCertificate {
	t.Helper()
	entry, caller, context := locations["runtime.testAtomic64"], locations["runtime.check"], locations["runtime.g0"]
	if entry == 0 || caller == 0 || context == 0 {
		t.Fatal("selected artifact lacks candidate entry, caller or context storage")
	}
	decode := globalCandidateDecoder(t, raw)
	var ret, continuation uint64
	var expansions []nativeproof.TransitionExpansion
	for pc, count := entry, 0; count < 256; count++ {
		i := decode(pc)
		if i.Op == x86asm.RET {
			ret = pc
			break
		}
		if nativeproof.TransitionExpansionRequired(i) {
			expansions = append(expansions, nativeproof.TransitionExpansion{PC: pc})
		}
		pc += uint64(i.Len)
	}
	for pc, count := caller, 0; count < 512; count++ {
		i := decode(pc)
		if rel, ok := i.Args[0].(x86asm.Rel); ok && i.Op == x86asm.CALL && uint64(int64(pc)+int64(i.Len)+int64(rel)) == entry {
			continuation = pc + uint64(i.Len)
			break
		}
		if i.Op == x86asm.RET {
			break
		}
		pc += uint64(i.Len)
	}
	if ret == 0 || continuation == 0 {
		t.Fatal("candidate discovery did not find actual RET and caller continuation")
	}
	face := globalNativeFace([]nativeproof.Span{
		{Start: locations["runtime.test_z64"], End: locations["runtime.test_z64"] + 8},
		{Start: locations["runtime.test_x64"], End: locations["runtime.test_x64"] + 8},
		{Start: context, End: context + 24},
	})
	// Admit the actual translated startup entries (S-120) as well as a broad
	// surrounding domain. This is a newly checked interface, not a modified
	// theorem projection or an assertion that startup reaches this callee.
	face.Origin.Min -= 256
	face.Origin.Residue = 8
	face.Envelope = nativeproof.RelativeSpan{Start: -24, End: 8}
	face.Regions = []nativeproof.RelativeRegion{
		{Bytes: nativeproof.RelativeSpan{Start: -24, End: 0}, Readable: true, Writable: true},
		{Bytes: nativeproof.RelativeSpan{Start: 0, End: 8}, Readable: true},
	}
	face.EntryImagePointers = []nativeproof.TransitionEntryImagePointer{{Register: nativeproof.R14, Address: context}}
	face.EntryWordUpperBounds = []nativeproof.TransitionEntryWordUpperBound{{Address: context + 16}}
	face.ReturnContext = &nativeproof.TransitionReturnContext{Target: continuation, Preserved: []nativeproof.Register{nativeproof.RBP, nativeproof.R14}}
	face.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: nativeproof.RelativeSpan{Start: -24, End: 0}}
	setPairedAtomicModel(&face)
	p, err := nativeproof.ProposeRegionTransition(t.Context(), image, entry, ret, nativeproof.TransitionLimits{}, nativeproof.TransitionOptions{Expansions: expansions})
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := nativeproof.CheckRegionTransition(t.Context(), image, entry, face, p, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	returned, err := nativeproof.CheckTransitionReturn(t.Context(), prefix)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := returned.BoundFor(image)
	if !ok || b.Prefix.Entry != entry || !b.State.CalleeTerminated || b.State.PC != continuation || len(b.Prefix.PrimitiveEffects) != 5 || len(b.Instructions) != len(b.Prefix.Instructions)+1 || b.Instructions[len(b.Instructions)-1].Start != ret || b.Accesses[len(b.Accesses)-1].Kind != nativeproof.FrameReturnRead {
		t.Fatal("fresh theorem lost complete entry, atomic effects or executed RET")
	}
	t.Logf("actual entry=%#x RET=%#x continuation=%#x origin=%+v instructions=%d accesses=%d primitives=%d excluded=%d", entry, ret, continuation, b.Prefix.Interface.Origin, len(b.Instructions), len(b.Accesses), len(b.Prefix.PrimitiveEffects), len(b.Prefix.ExcludedBoundaries))
	return returned
}

func TestGlobalReturnSelectedRuntimeArtifact(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("native model is Linux amd64")
	}
	path := filepath.Join(runtime.GOROOT(), "pkg", "tool", "linux_amd64", "compile")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("selected compiler=%s SHA256=%x", path, sha256.Sum256(raw))
	image, err := nativeproof.NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Close()
	symbols, err := parsed.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	locations := make(map[string]uint64)
	for _, symbol := range symbols {
		locations[symbol.Name] = symbol.Value
	}
	selectedAtomicReturn(t, raw, image, locations)
}
