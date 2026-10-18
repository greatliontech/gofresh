package closure

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

// Each input constructs its own selected source and actual assembly acquisition.
// The grammar varies five uint64 operands, both outcome guards, layout and image
// payload bytes; it covers two calls, not arbitrary functions or concurrency.
func FuzzGlobalRegionReferenceSubstitution(f *testing.F) {
	if testing.Short() {
		f.Skip("generated selected source and actual assembly acquisition")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		f.Skip("selected assembly acquisition uses Linux amd64")
	}
	for mode := byte(0); mode < 8; mode++ {
		f.Add(uint64(0x8000000000000000), uint64(7), ^uint64(0), uint64(11), uint64(0), mode, []byte{0xa5, 0x5a})
	}
	f.Fuzz(func(t *testing.T, current, old, replacement, secondOld, secondReplacement uint64, mode byte, payload []byte) {
		if len(payload) > 128 {
			t.Skip("bounded 128-byte image payload")
		}
		intent := pairedIntent{current, old, replacement, secondOld, secondReplacement}
		if mode&1 != 0 {
			intent.old = intent.current
		}
		_, middle, _, _ := intent.outcomes()
		if mode&2 != 0 {
			intent.secondOld = middle
		}
		first, _, second, final := intent.outcomes()
		text := fmt.Sprintf(`package main
import "example.com/paired/ops"
var z,x uint64
func load(p *uint64)uint64{return *p}
func F(){z=%d;x=%d;if ops.Swap(&z,x,%d)!=%t{panic(nil)};if x!=%d{panic(nil)};x=%d;if ops.Swap(&z,x,%d)!=%t{panic(nil)};if x!=%d||z!=%d{panic(nil)};_ = load(&z)}
func main(){F()}
`, intent.current, intent.old, intent.replacement, first, intent.old, intent.secondOld, intent.secondReplacement, second, intent.secondOld, final)
		dir := t.TempDir()
		writeTree(t, dir, map[string]string{
			"go.mod":          "module example.com/paired\n\ngo 1.27\n",
			"main.go":         text,
			"ops/ops.go":      "package ops\n//go:noescape\nfunc Swap(p *uint64, old, new uint64) bool\n",
			"ops/ops_amd64.s": assemblyReferenceUnitBody,
		})
		source, main, _ := loadSourceCommandFixture(t, dir, "example.com/paired")
		var target *ssa.Function
		for _, pkg := range source.prog.Pkgs {
			if pkg.PkgPath == "example.com/paired/ops" {
				target = source.prog.Prog.Package(pkg.Types).Func("Swap")
			}
		}
		if target == nil {
			t.Fatal("generated selected declaration absent")
		}
		packet := assemblyReferenceSelectedPacket(t, source, target)
		reference, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
		if err != nil {
			t.Fatal(err)
		}
		root := main.Pkg.Func("F")
		calls := pairedCalls(t, root, target)
		globals := [2]*ssa.Global{main.Pkg.Members["z"].(*ssa.Global), main.Pkg.Members["x"].(*ssa.Global)}
		base := uint64(0x700000) + uint64(mode>>4)*4096
		addresses := [2]uint64{base + 8, base + 80}
		if mode&4 != 0 {
			addresses[0], addresses[1] = addresses[1], addresses[0]
		}
		fixture := pairedNativeImage(t, addresses, intent, base, payload)
		prior := pairedOperandProof(t, source, root, calls, globals, addresses, fixture)
		steps := pairedSteps(t, fixture, calls)
		refs := map[*ssa.Function]*assemblyReference{target: reference}
		proof, err := continueGlobalOperandCorrespondence(t.Context(), prior, steps, refs)
		if err != nil {
			t.Fatal(err)
		}
		assertPairedSource(t, proof, intent, globals)
		absent, missingErr := continueGlobalOperandCorrespondence(t.Context(), prior, steps, nil)
		var missing *regionOperationFailure
		if absent != nil || !errors.As(missingErr, &missing) || missing.instruction != calls[0] {
			t.Fatalf("missing reference did not refuse at the actual first call: %v", missingErr)
		}
		if second {
			// Only the second replacement immediate changes. This arm executes
			// that write, so the independent source outcome necessarily differs.
			bad := fixture
			bad.raw = slices.Clone(fixture.raw)
			binary.LittleEndian.PutUint64(bad.raw[bad.replacementOperand:], intent.secondReplacement^1)
			bad.image, err = nativeproof.NewImage(t.Context(), bad.raw)
			if err != nil {
				t.Fatal(err)
			}
			badPrior := pairedOperandProof(t, source, root, calls, globals, addresses, bad)
			if accepted, err := continueGlobalOperandCorrespondence(t.Context(), badPrior, pairedSteps(t, bad, calls), refs); err == nil || accepted != nil || !strings.Contains(err.Error(), "bitrelation") {
				t.Fatalf("different executed replacement did not fail checked equality: %v", err)
			}
		}
	})
}
