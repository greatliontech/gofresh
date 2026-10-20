package closure

import (
	"errors"
	"reflect"
	"runtime"
	"testing"

	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

func TestRuntimeStartupSelectedAtomicApplication(t *testing.T) {
	if testing.Short() {
		t.Skip("composes the selected atomic callee from the actual initialized ELF root")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected startup model is Linux amd64")
	}
	raw, image, locations, x := selectedStartupFixture(t)
	callee := selectedAtomicReturn(t, raw, image, locations)
	conditional := selectedCheckPrefix(t, raw, image, locations, callee)
	child, _ := callee.BoundFor(image)
	candidate, _ := conditional.BoundFor(image)
	if child.Prefix.Interface.Origin.Residue != 8 || candidate.Interface.Origin.Residue != 8 {
		t.Fatal("selected conditional theorems were not rederived for actual entry congruence")
	}
	decode := globalCandidateDecoder(t, raw)
	x, until := selectedRuntimeRootCandidate(t, raw, locations, x)
	outerCall := x.cut + uint64(decode(x.cut).Len)
	for _, expansion := range candidate.Expansions {
		x.expansions = append(x.expansions, nativeproof.TransitionExpansion{PC: expansion.PC, AllActivations: true})
	}
	// These are original-root premises and discovery proposals, never copied
	// conditional callee outputs. Loading, TLS, wrapper and the caller body are
	// all rechecked from the ELF before applying the exact completed callee.
	limits := nativeproof.TransitionLimits{RelationLimits: nativeproof.RelationLimits{Work: 8_000_000, Nodes: 131072}}
	proposal, err := nativeproof.ProposeTransition(t.Context(), image, candidate.Boundary.PC, limits, nativeproof.TransitionOptions{Expansions: x.expansions})
	if err != nil {
		t.Fatal(err)
	}
	caller, err := nativeproof.CheckTransition(t.Context(), image, x.face, proposal, limits)
	if err != nil {
		t.Fatal("root-to-actual-call prefix", err)
	}
	before, ok := caller.BoundFor(image)
	if !ok || before.ConditionalRegion || len(before.Frames) != 1 || before.Frames[0].Call != outerCall || before.Frames[0].Return != until || before.Registers[nativeproof.RSP].Pointer != (nativeproof.OriginPointer{Origin: before.Origin, Offset: -112}) || !before.Thread.ContextChanged {
		t.Fatal("rooted caller lost the actual wrapper frame, stack relation or FS history")
	}
	application, err := nativeproof.CheckTransitionCallReturn(t.Context(), caller, callee)
	if err != nil {
		t.Fatal("rooted actual child application", err)
	}
	a, ok := application.BoundFor(image)
	if !ok || !application.AppliesTo(callee) || a.StackShift != -120 || a.ChildEntry.ConditionalRegion || a.Successor.ConditionalRegion || a.Successor.Entry != before.Entry || a.Successor.Origin != before.Origin || a.Successor.InitialDirection != before.InitialDirection || a.Successor.InitialFS != before.InitialFS || a.Successor.InitialRegisters != before.InitialRegisters || !reflect.DeepEqual(a.Successor.Interface, before.Interface) || !reflect.DeepEqual(a.Successor.Frames, before.Frames) {
		t.Fatal("rooted application substituted a conditional root or lost original premises")
	}
	if a.Thread != before.Thread || a.Successor.Thread != before.Thread || a.Successor.Direction != before.Direction || a.Successor.Registers[nativeproof.RSP].Pointer != before.Registers[nativeproof.RSP].Pointer || a.Successor.Boundary.PC != child.State.PC {
		t.Fatal("rooted return did not preserve current caller context and original FS history")
	}
	queries, syscalls, atomics := 0, 0, 0
	for _, effect := range a.Successor.PrimitiveEffects {
		switch effect.(type) {
		case nativeproof.CPUIDEffect:
			queries++
		case nativeproof.ArchSetFSEffect:
			syscalls++
		default:
			if _, ok := globalFunctionNativeGroup(effect); !ok {
				t.Fatal("rooted application acquired an unexpected primitive")
			}
			atomics++
		}
	}
	if queries != 2 || syscalls != 1 || atomics != 10 || len(a.Successor.Abstractions) != 1 {
		t.Fatal("rooted application lost startup effects, saved-flags abstraction or atomic groups")
	}
	// Permission alone cannot replace the original finite lifetime premise.
	without := x.face
	without.PrivateFrame = nil
	unowned, err := nativeproof.CheckTransition(t.Context(), image, without, proposal, limits)
	if err != nil {
		t.Fatal("negative ownership control lacks its valid native prefix", err)
	}
	bad, err := nativeproof.CheckTransitionCallReturn(t.Context(), unowned, callee)
	var refusal *nativeproof.Refusal
	if _, accepted := bad.Bound(); accepted || !errors.As(err, &refusal) || refusal.Premise != "transition-application-private" {
		t.Fatalf("root permissions were promoted to private lifetime: %v", err)
	}
	t.Logf("ELF root %#x establishes child entry shift -120 and current guard under declared root ownership through %#x; returned child retains outer wrapper activation and FS history; process ownership and complete source/native wrapper composition remain open", before.Entry, until)
}

func selectedRuntimeRootCandidate(t testing.TB, raw []byte, locations map[string]uint64, x selectedStartupCandidate) (selectedStartupCandidate, uint64) {
	t.Helper()
	decode := globalCandidateDecoder(t, raw)
	outerCall := x.cut + uint64(decode(x.cut).Len)
	call := decode(outerCall)
	rel, direct := call.Args[0].(x86asm.Rel)
	if call.Op != x86asm.CALL || !direct {
		t.Fatal("startup candidate has no actual wrapper CALL")
	}
	wrapper := uint64(int64(outerCall) + int64(call.Len) + int64(rel))
	if decode(wrapper).Op != x86asm.XORPS {
		t.Fatal("selected wrapper candidate no longer starts with its vector clear")
	}
	until := outerCall + uint64(call.Len)
	x.face.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: nativeproof.RelativeSpan{Start: -144, End: -48}, Until: &until}
	x.face.Regions[2].Bytes = x.face.PrivateFrame.Bytes
	x.face.Conditions.SSE = nativeproof.SSEModel
	setPairedAtomicModel(&x.face)
	for _, name := range []string{"runtime.test_x64", "runtime.test_z64"} {
		x.face.ImageRegions = append(x.face.ImageRegions, nativeproof.Span{Start: locations[name], End: locations[name] + 8})
	}
	x.expansions = append(x.expansions,
		nativeproof.TransitionExpansion{PC: x.cut, AllActivations: true},
		nativeproof.TransitionExpansion{PC: outerCall, AllActivations: true},
		nativeproof.TransitionExpansion{PC: wrapper, AllActivations: true})
	return x, until
}
