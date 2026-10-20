package closure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

func selectedRuntimeCheckArtifact(t *testing.T, h *Hasher) ([]byte, *nativeproof.Image, map[string]uint64) {
	t.Helper()
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
	t.Logf("selected identity=%q installed compiler=%s SHA256=%x", identity, path, sha256.Sum256(raw))
	t.Cleanup(func() {
		after, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
		} else if !bytes.Equal(raw, after) {
			t.Error("installed compiler changed during reference acquisition and correspondence")
		}
	})
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
	locations := make(map[string]uint64, len(symbols))
	for _, symbol := range symbols {
		locations[symbol.Name] = symbol.Value
	}
	return raw, image, locations
}

// Coordinates are an untrusted placement proposal. Source objects come from
// actual checked accesses, and the complete correspondence must validate every
// byte, lifetime, alias, effect and protected-slot relation at these coordinates.
func selectedRuntimeCheckStorage(t *testing.T, source computationSource, image *nativeproof.Image, locations map[string]uint64, completed *sourceReturnCompletion) storageRepresentation {
	t.Helper()
	root := completed.region.packet.input.root
	var chain []*sourceEffectPrefix
	for at := completed.prior; at != nil; at = at.prior {
		chain = append(chain, at)
	}
	slices.Reverse(chain)
	traces := make([]*regionEffectTrace, 0, len(chain)+1)
	for _, phase := range chain {
		traces = append(traces, phase.region.packet.trace)
	}
	traces = append(traces, completed.region.packet.trace)
	rho := storageRepresentation{source: source.prog, image: image}
	bound := map[regionObject]nativeproof.TransitionLocation{}
	add := func(object regionObject, location nativeproof.TransitionLocation) {
		if prior, exists := bound[object]; exists {
			if prior != location {
				t.Fatal("source object has conflicting candidate placements")
			}
			return
		}
		bound[object] = location
		rho.bindings = append(rho.bindings, storageBinding{object: object, base: location})
	}
	for _, trace := range traces {
		for _, occurrence := range trace.atomics {
			if occurrence.application.caller.invocation != (regionInvocation{}) {
				continue
			}
			access := trace.accesses[occurrence.atomic.ReadAccess]
			switch {
			case occurrence.atomic.Kind == x86asm.CMPXCHG && occurrence.atomic.Width == 4:
				if len(access.location.path) != 0 {
					t.Fatal("selected CAS32 operand is not the scalar allocation")
				}
				add(access.location.object, nativeproof.TransitionLocation{Offset: -36})
			case occurrence.atomic.Width == 1:
				if !slices.Equal(access.location.path, []regionStep{{index: 1}}) {
					t.Fatal("selected byte atomic lost its array subobject")
				}
				add(access.location.object, nativeproof.TransitionLocation{Offset: -40})
			}
		}
		for _, access := range trace.accesses {
			if !access.write || access.location.object.kind != regionAllocation {
				continue
			}
			typ := completed.checker.locationType(access.location)
			basic, scalar := typ.Underlying().(*types.Basic)
			if !scalar || basic.Info()&types.IsFloat == 0 {
				continue
			}
			if len(access.location.path) != 0 {
				t.Fatal("selected float bit store is not a scalar allocation")
			}
			bits, width, exact := storageScalarBits(access.value, completed.region.root.pkg.TypesSizes)
			var offset int64
			switch {
			case exact && width == 8 && bits == ^uint64(0):
				offset = -16
			case exact && width == 8 && bits == ^uint64(1):
				offset = -24
			case exact && width == 4 && bits == uint64(^uint32(0)):
				offset = -28
			case exact && width == 4 && bits == uint64(^uint32(1)):
				offset = -32
			default:
				t.Fatal("selected float bit-store candidate changed")
			}
			add(access.location.object, nativeproof.TransitionLocation{Offset: offset})
		}
	}
	for _, name := range []string{"test_z64", "test_x64"} {
		global, ok := root.Pkg.Members[name].(*ssa.Global)
		address := locations["runtime."+name]
		if !ok || address == 0 {
			t.Fatal("selected global placement candidate is absent", name)
		}
		add(regionObject{kind: regionGlobal, site: global}, nativeproof.TransitionLocation{Image: true, Offset: int64(address)})
	}
	if len(rho.bindings) != 8 {
		t.Fatalf("selected representation has %d objects, expected six locals and two globals", len(rho.bindings))
	}
	return rho
}

func assertSelectedRuntimeCheckCorrespondence(t *testing.T, source computationSource, raw []byte, image *nativeproof.Image, locations map[string]uint64, completed *sourceReturnCompletion, child *sourceOperandPrefix) *globalFunctionCorrespondence {
	t.Helper()
	callee := selectedAtomicReturn(t, raw, image, locations)
	caller := selectedCheckPrefix(t, raw, image, locations, callee)
	application, err := nativeproof.CheckTransitionCallReturn(t.Context(), caller, callee)
	if err != nil {
		t.Fatal(err)
	}
	header := selectedCheckFirstLoopCut(t, raw, image, application)
	_, tail := selectedCheckCompleteReturn(t, raw, image, application, header)
	rho := selectedRuntimeCheckStorage(t, source, image, locations, completed)
	root := completed.region.packet.input.root
	// This account includes both rechecking the finite native tail and the whole
	// source/native relation. Neither phase nor an alignment retry gets a reset.
	proof, err := checkGlobalFunctionCallComposition(t.Context(), source, root, image, completed, child, application, tail, rho, globalCorrespondenceLimits{work: 4_000_000})
	if err != nil {
		t.Fatalf("complete selected actual-call correspondence: %v", err)
	}
	if proof == nil || proof.call == nil || proof.source != completed || proof.call.prefix != child || proof.call.native != application || proof.call.application.proof.caller != child.cursor || proof.call.application.proof.at != child.call {
		t.Fatal("complete selected relation lost its actual source/native application owners")
	}
	requireScopedStorageModel(t, proof)
	assertSelectedCheckReturn(t, image, proof.call.bound.Successor, proof.native)
	if len(proof.layout.objects) != 8 || len(proof.atomics) != 10 || proof.call.sourceUsage.work <= completed.region.packet.usage.work {
		t.Fatal("complete selected relation lost its fixed storage, atomic groups or cumulative current-state checking")
	}
	parentGroups, childGroups := 0, 0
	for _, pair := range proof.atomics {
		group, ok := globalFunctionNativeGroup(pair.native)
		if !ok {
			t.Fatal("matched atomic has no complete native group")
		}
		inside := group.read >= proof.call.nativeFence[0] && group.write < proof.call.nativeFence[1]
		if inside {
			childGroups++
			if group.width != 8 || pair.source.application.caller.invocation == (regionInvocation{}) {
				t.Fatal("child wide atomic lost its actual source invocation")
			}
		} else {
			parentGroups++
			if group.width != 1 && group.width != 4 || pair.source.application.caller.invocation != (regionInvocation{}) {
				t.Fatal("parent narrow atomic borrowed a child occurrence")
			}
		}
	}
	if parentGroups != 5 || childGroups != 5 {
		t.Fatal("actual call did not retain both complete atomic populations")
	}
	sourceComparisons := 0
	for _, occurrence := range proof.storageModel.modelOccurrences {
		if op, ok := occurrence.instruction.(*ssa.BinOp); ok && (op.Op == token.EQL || op.Op == token.NEQ) && regionFloatWidth(op.X.Type()) != 0 {
			sourceComparisons++
		}
	}
	bound, _ := proof.native.BoundFor(image)
	nativeComparisons, nativeLoads, err := selectedRuntimeFloatingActivity(t.Context(), proof.native)
	if err != nil {
		t.Fatal(err)
	}
	if sourceComparisons != 8 || nativeComparisons != 4 || nativeLoads != 4 || len(proof.eliminated) == 0 || !bound.State.SSE.MXCSRPreserved || !bound.State.SSE.UpperVectorsPreserved {
		t.Fatal("selected optimized float comparison reuse/elimination or preserved context was lost")
	}
	t.Logf("complete selected actual-call correspondence: eight objects, ten atomic groups, %d source/%d native float comparisons, scoped model consequences; root/use/harness/producing obligations retained", sourceComparisons, nativeComparisons)
	t.Logf("complete actual-call correspondence work=%d", proof.work)
	return proof
}

// Qualification counts actual operations, not merely retained instructions on
// excluded branches. This separate account never modifies the completed proof.
func selectedRuntimeFloatingActivity(ctx context.Context, native nativeproof.TransitionReturnCertificate) (comparisons, loads int, err error) {
	bound, ok := native.Bound()
	if !ok {
		return 0, 0, fmt.Errorf("missing native completion")
	}
	meter := &correspondenceContext{Context: ctx, limit: 2_000_000}
	guards := globalFunctionCorrespondence{antecedent: bound.Prefix.EntryPredicate}
	for _, occurrence := range bound.Instructions {
		instruction, err := native.InstructionAt(meter, occurrence.ID)
		if err != nil {
			return 0, 0, err
		}
		switch instruction.Op {
		case x86asm.UCOMISS, x86asm.UCOMISD:
			comparisons++
		case x86asm.MOVSS, x86asm.MOVSD_XMM:
			if _, memory := instruction.Args[1].(x86asm.Mem); !memory {
				return 0, 0, fmt.Errorf("selected scalar move is not a memory load")
			}
			loads++
		default:
			continue
		}
		if err := guards.constant(meter, occurrence.Guard, 1); err != nil {
			return 0, 0, fmt.Errorf("retained floating occurrence is not proved active: %w", err)
		}
	}
	return comparisons, loads, meter.Err()
}

func TestSelectedRuntimeFloatingActivity(t *testing.T) {
	code, cut := storageModelSSECode(8, 0, "correct")
	_, native, err := storageModelCheckSSE(t, code, cut, nativeproof.SSEModel)
	if err != nil {
		t.Fatal(err)
	}
	if comparisons, loads, err := selectedRuntimeFloatingActivity(t.Context(), native); err != nil || comparisons != 1 || loads != 2 {
		t.Fatalf("actual floating population: comparisons=%d loads=%d: %v", comparisons, loads, err)
	}
	// XOR EAX,EAX; JE over UCOMISS X0,X0; RET. The excluded fallthrough is
	// retained in native evidence, but its compare must not count as executed.
	code = []byte{0xc3, 0x31, 0xc0, 0x74, 3, 0x0f, 0x2e, 0xc0, 0xc3}
	_, native, err = storageModelCheckSSE(t, code, 0x401008, nativeproof.SSEModel)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := selectedRuntimeFloatingActivity(t.Context(), native); err == nil || !strings.Contains(err.Error(), "not proved active") {
		t.Fatalf("excluded comparison counted as executed: %v", err)
	}
}
