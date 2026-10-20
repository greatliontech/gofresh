package closure

import (
	"fmt"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

// These relations compare independently checked native effects to source-derived
// outcomes. The native body deliberately contains no floating instruction: its
// constant effect must agree with every checked source comparison it replaces.
func TestFloatStorageEliminatedComparisonEffects(t *testing.T) {
	for _, width := range []int{4, 8} {
		quiet := uint64(1) << 22
		if width == 8 {
			quiet = uint64(1) << 51
		}
		for _, tc := range []struct {
			name string
			bits uint64
			want uint64
		}{
			{"zero", 0, 1},
			{"negative-zero", uint64(1) << (width*8 - 1), 1},
			{"nan", ^uint64(0) >> (64 - width*8), 2},
			// These source encodings are valid even though actually executing
			// UCOMIS on them would fail its independent no-exception proof.
			{"signaling-nan", (^uint64(0) >> (64 - width*8)) &^ quiet, 2},
			{"subnormal", 1, 1},
		} {
			t.Run(fmt.Sprintf("%d/%s", width, tc.name), func(t *testing.T) {
				text := fmt.Sprintf(`import "unsafe";var G uint32;func Check(p *float%d){if *p==*p {G=1}else{G=2}};func F(){var x float%d;*(*uint%d)(unsafe.Pointer(&x))=%d;Check(&x)}`, width*8, width*8, width*8, tc.bits)
				source, completed := storageFunctionSource(t, text)
				global := source.prog.Roots["F"].Pkg.Members["G"].(*ssa.Global)
				base := nativeproof.ImageAddress(0x700008)
				for _, value := range []uint64{tc.want, 3 - tc.want} {
					fixture, native := storageFunctionNative(t, []storageFunctionOperation{{base, 4, true, value}}, nativeproof.OriginDomain{})
					rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: regionObject{kind: regionGlobal, site: global}, base: base}}}
					proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
					if value != tc.want {
						if err == nil || proof != nil {
							t.Fatal("wrong native effect borrowed an eliminated float comparison")
						}
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					if len(proof.eliminated) != 3 || len(proof.matched) != 1 || !proof.open.applicability || !proof.open.initialization || !proof.open.actualUse {
						t.Fatal("float elimination lost its source effects or open composition conditions")
					}
					requireScopedStorageModel(t, proof)
					bound, _ := native.Bound()
					if bound.Prefix.Interface.Conditions.SSE != "" || len(proof.representation.bindings) != 1 {
						t.Fatal("eliminated float acquired an invented machine premise or physical object")
					}
				}
			})
		}
	}
}

func TestFloatStorageMaterializationAndReadOrder(t *testing.T) {
	for _, width := range []int{4, 8} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			bits := ^uint64(0) >> (64 - width*8)
			source, completed := storageFunctionSource(t, fmt.Sprintf(`import "unsafe";func Check(p *float%d){if *p==*p {panic(1)}};func F(){var x float%d;*(*uint%d)(unsafe.Pointer(&x))=%d;Check(&x)}`, width*8, width*8, width*8, bits))
			base := nativeproof.StackOffset(-16)
			for _, variant := range []string{"stored", "initialized", "read", "wrong", "early-read", "extra-read"} {
				t.Run(variant, func(t *testing.T) {
					ops := []storageFunctionOperation{{base, width, true, bits}}
					switch variant {
					case "initialized":
						ops = append([]storageFunctionOperation{{base, width, true, 0}}, ops...)
					case "read":
						ops = append(ops, storageFunctionOperation{base, width, false, 0})
					case "wrong":
						ops[0].value ^= 1
					case "early-read":
						ops = append([]storageFunctionOperation{{base, width, false, 0}}, ops...)
					case "extra-read":
						for range 3 {
							ops = append(ops, storageFunctionOperation{base, width, false, 0})
						}
					}
					fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
					rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: storageFunctionLocal(t, completed), base: base}}}
					proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], fixture.image, fixture.entry, completed, native, rho, nil)
					if variant == "wrong" || variant == "early-read" || variant == "extra-read" {
						if err == nil || proof != nil {
							t.Fatal("invalid native float-storage access acquired correspondence")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if variant == "initialized" && len(proof.materialized) != 1 {
						t.Fatal("actual float-zero materialization was not justified")
					}
					requireScopedStorageModel(t, proof)
				})
			}
		})
	}
}
