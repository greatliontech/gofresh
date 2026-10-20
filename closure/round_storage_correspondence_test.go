package closure

import (
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

func TestStorageFunctionRepeatedSourceOccurrences(t *testing.T) {
	source, completed := storageFunctionSource(t, `var G uint32;func Start(*uint32){};func F(){var x uint32;Start(&x);for i:=uint32(1);i<3;i++ {x=i;G=x}}`)
	root := source.prog.Roots["F"]
	local := nativeproof.StackOffset(-16)
	global := nativeproof.ImageAddress(0x700008)
	accesses := completed.region.packet.trace.accesses
	if len(accesses) != 6 || accesses[0].instruction != accesses[3].instruction || accesses[0].regionEffectOccurrence == accesses[3].regionEffectOccurrence || accesses[1].instruction != accesses[4].instruction || accesses[1].regionEffectOccurrence == accesses[4].regionEffectOccurrence {
		t.Fatal("finite loop collapsed distinct visits of its actual store/load")
	}
	for _, variant := range []string{"matched", "wrong-second-value", "early-read", "reversed", "extra-read"} {
		t.Run(variant, func(t *testing.T) {
			ops := []storageFunctionOperation{{local, 4, true, 1}, {local, 4, false, 0}, {global, 4, true, 1}, {local, 4, true, 2}, {local, 4, false, 0}, {global, 4, true, 2}}
			switch variant {
			case "wrong-second-value":
				ops[3].value = 1
			case "early-read":
				ops = append([]storageFunctionOperation{{local, 4, false, 0}}, ops...)
			case "reversed":
				ops = append(ops[3:6:6], ops[:3]...)
			case "extra-read":
				ops = append(ops, storageFunctionOperation{local, 4, false, 0})
			}
			fixture, native := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{
				{object: storageFunctionLocal(t, completed), base: local},
				{object: regionObject{kind: regionGlobal, site: root.Pkg.Members["G"].(*ssa.Global)}, base: global},
			}}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, fixture.image, fixture.entry, completed, native, rho, nil)
			if variant != "matched" {
				if proof != nil || err == nil {
					t.Fatal("incorrect native effects borrowed another source visit")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(proof.matched) != 6 || len(proof.eliminated) != 0 || !proof.open.applicability || !proof.open.actualUse {
				t.Fatal("loop correspondence lost exact effects or open applicability")
			}
			matched := map[regionEffectOccurrence]bool{}
			for _, pair := range proof.matched {
				occurrence := proof.accesses[pair.source].regionEffectOccurrence
				if matched[occurrence] {
					t.Fatal("distinct ordinary accesses reused one source occurrence")
				}
				matched[occurrence] = true
			}
		})
	}
}
