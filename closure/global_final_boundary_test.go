package closure

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

// Every negative changes only the unexecuted endpoint. Both source calls and
// their native implementations still have independently accepted continuations;
// the rejection must therefore come from the final source/native use binding.
func TestGlobalRegionFinalLoadBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("acquires a selected source assembly reference for endpoint binding")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod": "module example.com/loadboundary\n\ngo 1.27\n",
		"main.go": `package main
import "example.com/loadboundary/ops"
var z, x uint64
func load(p *uint64) uint64 { return *p }
func Fz() {
 z=42; x=0
 if ops.Swap(&z,x,1) { panic(1) }
 if x!=0 { panic(2) }
 x=42
 if !ops.Swap(&z,x,1) { panic(3) }
 if x!=42 || z!=1 { panic(4) }
 _=load(&z)
}
func Fx() {
 z=42; x=0
 if ops.Swap(&z,x,1) { panic(1) }
 if x!=0 { panic(2) }
 x=42
 if !ops.Swap(&z,x,1) { panic(3) }
 if x!=42 || z!=1 { panic(4) }
 _=load(&x)
}
func main() { Fz(); Fx() }
`,
		"ops/ops.go":      "package ops\n//go:noescape\nfunc Swap(p *uint64, old, new uint64) bool\n",
		"ops/ops_amd64.s": "#include \"textflag.h\"\nTEXT ·Swap(SB),NOSPLIT,$0-25\nMOVQ p+0(FP),BX\nMOVQ old+8(FP),AX\nMOVQ new+16(FP),CX\nLOCK\nCMPXCHGQ CX,0(BX)\nSETEQ ret+24(FP)\nRET\n",
	})
	source, main, _ := loadSourceCommandFixture(t, dir, "example.com/loadboundary")
	var target *ssa.Function
	for _, pkg := range source.prog.Pkgs {
		if pkg.PkgPath == "example.com/loadboundary/ops" {
			target = source.prog.Prog.Package(pkg.Types).Func("Swap")
		}
	}
	if target == nil {
		t.Fatal("selected reference declaration absent")
	}
	reference := globalRegionReference(t, source, target)
	references := map[*ssa.Function]*assemblyReference{target: reference}
	globals := [2]*ssa.Global{main.Pkg.Members["z"].(*ssa.Global), main.Pkg.Members["x"].(*ssa.Global)}
	addresses := [2]uint64{0x800008, 0x800050}
	intent := pairedIntent{42, 0, 1, 42, 1}
	baseline := pairedNativeImage(t, addresses, intent, 0x800000, nil)
	const codeBase = uint64(0x401000)
	endpoint := 4096 + int(baseline.next[1]-codeBase)
	cases := []struct {
		name, root, refusal string
		change              func([]byte)
	}{
		{name: "unchanged", root: "Fz"},
		{name: "native-address", root: "Fz", refusal: "global correspondence: final load uses another represented address", change: func(raw []byte) {
			binary.LittleEndian.PutUint32(raw[endpoint+3:], uint32(int64(addresses[1])-int64(baseline.next[1]+7)))
		}},
		{name: "native-width", root: "Fz", refusal: "global correspondence: final native boundary is not the represented unexecuted load", change: func(raw []byte) {
			raw[endpoint] = 0x40 // same-length MOV EDX,[RIP+disp], rather than MOV RDX
		}},
		{name: "source-pointer", root: "Fx", refusal: "global correspondence: final load uses another represented address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := baseline
			if tc.change != nil {
				fixture.raw = slices.Clone(baseline.raw)
				tc.change(fixture.raw)
				if !bytes.Equal(fixture.raw[:endpoint], baseline.raw[:endpoint]) || !bytes.Equal(fixture.raw[endpoint+7:], baseline.raw[endpoint+7:]) {
					t.Fatal("negative changed bytes outside the final unexecuted load")
				}
				var err error
				fixture.image, err = nativeproof.NewImage(t.Context(), fixture.raw)
				if err != nil {
					t.Fatal(err)
				}
			}
			root := main.Pkg.Func(tc.root)
			calls := pairedCalls(t, root, target)
			prior := pairedOperandProof(t, source, root, calls, globals, addresses, fixture)
			steps := pairedSteps(t, fixture, calls)
			// Establish the two source/native subderivations independently before
			// asking the consumer to associate the final pointer and operand.
			src, machine := prior.source, prior.native
			for _, step := range steps {
				var err error
				src, err = checkSourceOperandContinuation(t.Context(), src, step.call, references)
				if err != nil {
					t.Fatalf("source subordinate unexpectedly refused: %v", err)
				}
				machine, err = nativeproof.CheckTransitionContinuation(t.Context(), machine, step.use)
				if err == nil {
					machine, err = nativeproof.CheckTransitionContinuation(t.Context(), machine, step.next)
				}
				if err != nil {
					t.Fatalf("native subordinate unexpectedly refused: %v", err)
				}
			}
			bound, ok := machine.BoundFor(fixture.image)
			if !ok || bound.Boundary.PC != fixture.next[1] || len(bound.PrimitiveEffects) != 2 || src.call != calls[2] {
				t.Fatal("subderivations did not establish the intended final scope")
			}
			for _, occurrence := range bound.Instructions {
				if occurrence.Start == bound.Boundary.PC {
					t.Fatal("native final load was executed")
				}
			}
			proof, err := continueGlobalOperandCorrespondence(t.Context(), prior, steps, references)
			if tc.refusal == "" {
				if err != nil {
					t.Fatal(err)
				}
				assertPairedSource(t, proof, intent, globals)
			} else if proof != nil || err == nil || !strings.HasPrefix(err.Error(), tc.refusal) {
				t.Fatalf("expected final-use obligation, got proof=%t error=%v", proof != nil, err)
			}
		})
	}
}
