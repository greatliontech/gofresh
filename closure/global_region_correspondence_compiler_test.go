package closure

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

// The installed executable remains the native input throughout fresh acquisition
// of the current package's assembly reference. Build output never replaces it.
func TestGlobalRegionCorrespondenceSelectedRuntimeArtifact(t *testing.T) {
	if testing.Short() {
		t.Skip("loads selected compiler source and captures its current final assembly inputs")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/pairedcompiler\n\ngo 1.27\n"})
	source, _, h := loadSourceCommandFixture(t, dir, "cmd/compile")
	identity, err := h.runner.Run(t.Context(), h.dir, h.env, "env", "GOVERSION", "GOROOT", "GOTOOLDIR", "GOFLAGS", "GOEXPERIMENT", "GOAMD64", "GOOS", "GOARCH")
	if err != nil {
		t.Fatal(err)
	}
	selection := strings.Split(strings.TrimSpace(string(identity)), "\n")
	if len(selection) != 8 || selection[6] != "linux" || selection[7] != "amd64" {
		t.Fatalf("selected native model requires linux/amd64: %q", identity)
	}
	path := filepath.Join(selection[2], "compile")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	t.Logf("selected identity=%q installed compiler=%s SHA256 before=%x", identity, path, digest)
	t.Cleanup(func() {
		after, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
			return
		}
		t.Logf("installed compiler SHA256 after=%x", sha256.Sum256(after))
		if !bytes.Equal(raw, after) {
			t.Error("installed native artifact changed during current reference acquisition/proof")
		}
	})
	var root, target *ssa.Function
	var globals [2]*ssa.Global
	for _, pkg := range source.prog.Pkgs {
		switch pkg.PkgPath {
		case "runtime":
			selected := source.prog.Prog.Package(pkg.Types)
			root = selected.Func("testAtomic64")
			globals = [2]*ssa.Global{selected.Members["test_z64"].(*ssa.Global), selected.Members["test_x64"].(*ssa.Global)}
		case "internal/runtime/atomic":
			target = source.prog.Prog.Package(pkg.Types).Func("Cas64")
		}
	}
	if root == nil || target == nil {
		t.Fatal("selected runtime source candidates are absent")
	}
	calls := pairedCalls(t, root, target)
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
	locations := map[string]uint64{}
	for _, symbol := range symbols {
		locations[symbol.Name] = symbol.Value
	}
	addresses := [2]uint64{locations["runtime.test_z64"], locations["runtime.test_x64"]}
	function := locations["runtime.testAtomic64"]
	decode := globalCandidateDecoder(t, raw)
	fixture := pairedNativeFixture{globalNativeFixture: globalNativeFixture{image: image, raw: raw, face: globalNativeFace([]nativeproof.Span{{Start: addresses[0], End: addresses[0] + 8}, {Start: addresses[1], End: addresses[1] + 8}})}}
	atomics := 0
	for pc, count := function, 0; count < 80; count++ {
		i := decode(pc)
		if fixture.entry == 0 && i.Op == x86asm.MOV && i.MemBytes == 8 {
			if memory, ok := i.Args[0].(x86asm.Mem); ok && memory.Base == x86asm.RIP {
				fixture.entry = pc
			}
		}
		if fixture.entry != 0 {
			if nativeproof.TransitionExpansionRequired(i) {
				fixture.expansions = append(fixture.expansions, nativeproof.TransitionExpansion{PC: pc})
			}
			switch i.Op {
			case x86asm.CMPXCHG:
				atomics++
				if atomics == 1 {
					fixture.cut = pc
				} else if atomics == 2 {
					fixture.next[0] = pc
				}
			case x86asm.TEST:
				if atomics > 0 && atomics <= 2 {
					fixture.use[atomics-1] = pc
				}
			case x86asm.MOV:
				if _, memory := i.Args[1].(x86asm.Mem); atomics == 2 && memory && i.MemBytes == 8 {
					fixture.next[1] = pc
				}
			}
		}
		if fixture.next[1] != 0 {
			break
		}
		pc += uint64(i.Len)
	}
	if fixture.entry == 0 || fixture.cut == 0 || fixture.next[0] == 0 || fixture.next[1] == 0 || fixture.use[0] == 0 || fixture.use[1] == 0 {
		t.Fatal("candidate discovery did not locate both complete result uses and the following load")
	}
	limits := defaultRegistrationLimits()
	limits.source = selectedSourceLimits{work: 20_000_000, depth: 256, bytes: 256 << 20}
	prefix, err := checkSourceOperandPrefix(t.Context(), source, root, calls[0], limits)
	if err != nil {
		t.Fatal(err)
	}
	setPairedAtomicModel(&fixture.face)
	var prefixExpansions []nativeproof.TransitionExpansion
	for _, e := range fixture.expansions {
		if e.PC < fixture.cut {
			prefixExpansions = append(prefixExpansions, e)
		}
	}
	proposal, err := nativeproof.ProposeRegionTransition(t.Context(), image, fixture.entry, fixture.cut, nativeproof.TransitionLimits{}, nativeproof.TransitionOptions{Expansions: prefixExpansions})
	if err != nil {
		t.Fatal(err)
	}
	native, err := nativeproof.CheckRegionTransition(t.Context(), image, fixture.entry, fixture.face, pairedProposalIDs(t, proposal), nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	rho := globalRho(source, fixture.globalNativeFixture, globals, addresses)
	prior, err := checkGlobalOperandCorrespondence(t.Context(), source, root, calls[0], image, fixture.entry, fixture.cut, prefix, native, rho)
	if err != nil {
		t.Fatal(err)
	}
	// The complete compiler build graph exceeds the small-selection acquisition
	// default in cumulative protected reads. Retain every observation under an
	// explicit finite allowance, just as the full-source binder above does.
	reference := globalRegionReference(t, source, target, assemblyCaptureLimits{Bytes: 2 << 30})
	proof, err := continueGlobalOperandCorrespondence(t.Context(), prior, pairedSteps(t, fixture, calls), map[*ssa.Function]*assemblyReference{target: reference})
	if err != nil {
		t.Fatal(err)
	}
	assertPairedSource(t, proof, pairedIntent{current: 42, old: 0, replacement: 1, secondOld: 42, secondReplacement: 1}, globals)
	final, ok := proof.phases[1].native.BoundFor(image)
	if !ok || len(final.PrimitiveEffects) != 2 {
		t.Fatal("paired native evidence lost atomic occurrences")
	}
	t.Logf("source %s -> unexecuted %s; native entry=%#x atomic=%#x/%#x TEST=%#x/%#x load=%#x; globals=%#x/%#x; instructions=%d accesses=%d primitives=%d universal equalities=%d cumulative work=%d", source.prog.Prog.Fset.Position(calls[0].Pos()), source.prog.Prog.Fset.Position(calls[2].Pos()), fixture.entry, fixture.cut, fixture.next[0], fixture.use[0], fixture.use[1], fixture.next[1], addresses[0], addresses[1], len(final.Instructions), len(final.Accesses), len(final.PrimitiveEffects), len(proof.equalities), proof.work)
	t.Logf("scope remains conditional; open obligations=%+v", prior.open)
	// Complete the source leg independently, retaining the actual Go load body
	// and selected assembly bodies. This does not extend the native prefix above
	// or establish its omitted prologue and return.
	references := map[*ssa.Function]*assemblyReference{target: reference}
	var returned *ssa.Return
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			if ret, ok := instruction.(*ssa.Return); ok {
				if returned != nil {
					t.Fatal("selected fixture has multiple proposed return endpoints")
				}
				returned = ret
			}
			call, ok := instruction.(*ssa.Call)
			if !ok {
				continue
			}
			callee := call.Call.StaticCallee()
			if callee == nil || len(callee.Blocks) != 0 || references[callee] != nil {
				continue
			}
			checked, err := checkAssemblyReference(t.Context(), source, callee, reference.checked.acquisition, assemblyReferenceLimits{})
			if err != nil {
				t.Fatal(err)
			}
			references[callee] = checked
		}
	}
	completed, err := checkSourceReturnContinuation(t.Context(), proof.phases[len(proof.phases)-1].source, returned, references)
	if err != nil {
		t.Fatal(err)
	}
	trace := completed.region.packet.trace
	if len(trace.calls) != 7 || len(trace.accesses) != 10 || len(trace.atomics) != 3 || completed.returned != returned {
		t.Fatalf("selected source suffix lost calls, effects or its actual return: calls=%d accesses=%d", len(trace.calls), len(trace.accesses))
	}
	for i, want := range []struct {
		kind        x86asm.Op
		read, write int
	}{{x86asm.XCHG, 1, 2}, {x86asm.XADD, 4, 5}, {x86asm.XCHG, 7, 8}} {
		got := trace.atomics[i]
		if got.application == nil || got.application.reference == nil || got.atomic.Kind != want.kind || got.atomic.ReadAccess != want.read || got.atomic.WriteAccess != want.write {
			t.Fatalf("selected source atomic %d lost call provenance or cumulative access indices: %+v", i, got)
		}
	}
	nativeReturn := selectedAtomicReturn(t, raw, image, locations)
	complete, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, image, function, completed, nativeReturn, rho, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(complete.atomics) != 5 || len(complete.inputs) != 2 || len(complete.administrative) != 4 {
		t.Fatal("complete correspondence lost paired inputs, atomic groups or administrative effects")
	}
	t.Logf("complete void correspondence: %d source accesses, %d matched accesses, %d eliminated ordinary reads, %d atomic groups, %d administrative accesses, %d equalities; work=%d", len(complete.accesses), len(complete.matched), len(complete.eliminated), len(complete.atomics), len(complete.administrative), len(complete.equalities), complete.work)
}
