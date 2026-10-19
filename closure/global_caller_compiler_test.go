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

// Candidate discovery never supplies entry applicability or semantics. The fresh
// caller theorem starts before its guard and executes all prefix operations.
func selectedCheckPrefix(t testing.TB, raw []byte, image *nativeproof.Image, locations map[string]uint64, callee nativeproof.TransitionReturnCertificate) nativeproof.TransitionCertificate {
	t.Helper()
	child, ok := callee.BoundFor(image)
	if !ok {
		t.Fatal("callee does not belong to this owned image")
	}
	entry, context := locations["runtime.check"], locations["runtime.g0"]
	decode := globalCandidateDecoder(t, raw)
	var call, incomingContinuation uint64
	var expansions []nativeproof.TransitionExpansion
	for pc, count := entry, 0; count < 512; count++ {
		i := decode(pc)
		if rel, direct := i.Args[0].(x86asm.Rel); direct && i.Op == x86asm.CALL && uint64(int64(pc)+int64(i.Len)+int64(rel)) == child.Prefix.Entry {
			call = pc
			break
		}
		if i.Op == x86asm.RET {
			break
		}
		if nativeproof.TransitionExpansionRequired(i) {
			expansions = append(expansions, nativeproof.TransitionExpansion{PC: pc})
		}
		pc += uint64(i.Len)
	}
	// The ABI wrapper tail-jumps into check. Its outer CALL locates an incoming
	// continuation only; this test does not establish the omitted root prefix.
	for pc, count := locations["runtime.rt0_go.abi0"], 0; count < 512; count++ {
		i := decode(pc)
		if rel, direct := i.Args[0].(x86asm.Rel); direct && i.Op == x86asm.CALL && uint64(int64(pc)+int64(i.Len)+int64(rel)) == locations["runtime.check.abi0"] {
			incomingContinuation = pc + uint64(i.Len)
			break
		}
		if i.Op == x86asm.RET {
			break
		}
		pc += uint64(i.Len)
	}
	if entry == 0 || context == 0 || call == 0 || incomingContinuation == 0 {
		t.Fatal("candidate caller, call or incoming continuation missing")
	}
	face := globalNativeFace(child.Prefix.Interface.ImageRegions)
	// The child's origin is S-64, so all translated origins stay in its declared
	// domain. These are conditional bounds, not observed stack coordinates.
	face.Origin.Min += 64
	face.Envelope = nativeproof.RelativeSpan{Start: -88, End: 8}
	face.Regions = []nativeproof.RelativeRegion{
		{Bytes: nativeproof.RelativeSpan{Start: -88, End: 0}, Readable: true, Writable: true},
		{Bytes: nativeproof.RelativeSpan{Start: 0, End: 8}, Readable: true},
	}
	face.EntryImagePointers = []nativeproof.TransitionEntryImagePointer{{Register: nativeproof.R14, Address: context}}
	face.EntryWordUpperBounds = []nativeproof.TransitionEntryWordUpperBound{{Address: context + 16, OriginOffset: -64}}
	face.ReturnContext = &nativeproof.TransitionReturnContext{Target: incomingContinuation, Preserved: []nativeproof.Register{nativeproof.RBP, nativeproof.R14}}
	face.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: nativeproof.RelativeSpan{Start: -88, End: 0}}
	setPairedAtomicModel(&face)
	face.Conditions.SSE = nativeproof.SSEModel
	limits := nativeproof.TransitionLimits{RelationLimits: nativeproof.RelationLimits{Work: 8_000_000, Nodes: 131072}}
	proposal, err := nativeproof.ProposeRegionTransition(t.Context(), image, entry, call, limits, expansions...)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := nativeproof.CheckRegionTransition(t.Context(), image, entry, face, proposal, limits)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := checked.Bound()
	if b.Entry != entry || b.Boundary.PC != call || len(b.PrimitiveEffects) != 5 || len(b.Frames) != 0 || b.Registers[nativeproof.RSP].Pointer != (nativeproof.OriginPointer{Origin: b.Origin, Offset: -56}) || b.Registers[nativeproof.RBP].Pointer != (nativeproof.OriginPointer{Origin: b.Origin, Offset: -8}) {
		t.Fatal("caller prefix lost actual stack, context or atomic effects")
	}
	t.Logf("actual caller entry=%#x CALL=%#x instructions=%d accesses=%d primitives=%d exclusions=%d", entry, call, len(b.Instructions), len(b.Accesses), len(b.PrimitiveEffects), len(b.ExcludedBoundaries))
	return checked
}

func TestGlobalCallerSelectedRuntimeArtifact(t *testing.T) {
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
	callee := selectedAtomicReturn(t, raw, image, locations)
	caller := selectedCheckPrefix(t, raw, image, locations, callee)
	application, err := nativeproof.CheckTransitionCallReturn(t.Context(), caller, callee)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := application.BoundFor(image)
	child, _ := callee.Bound()
	if !ok || !application.AppliesTo(callee) || b.StackShift != -64 || b.Continuation != child.State.PC || len(b.Successor.PrimitiveEffects) != 10 || len(b.Successor.Frames) != 0 || b.Successor.Boundary.Context != "" || b.Successor.Registers[nativeproof.RSP].Pointer != (nativeproof.OriginPointer{Origin: b.Successor.Origin, Offset: -56}) || b.Successor.Registers[nativeproof.RBP].Pointer != (nativeproof.OriginPointer{Origin: b.Successor.Origin, Offset: -8}) {
		t.Fatal("actual application lost callee identity, effects or caller frame")
	}
	if !b.Successor.SSE.MXCSRPreserved || !b.Successor.SSE.UpperVectorsPreserved || b.Successor.Vectors != b.ChildEntry.Vectors {
		t.Fatal("integer callee application lost caller's floating/vector context")
	}
	t.Logf("actual composed return=%#x instructions=%d accesses=%d primitives=%d exclusions=%d", b.Continuation, len(b.Successor.Instructions), len(b.Successor.Accesses), len(b.Successor.PrimitiveEffects), len(b.Successor.ExcludedBoundaries))
	selectedCheckFirstLoopCut(t, raw, image, application)
}
