package closure

import (
	"math"
	"testing"
	"unicode/utf16"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/bitrelation"
)

func TestComputationRelationSelectedUTF16(t *testing.T) {
	if testing.Short() {
		t.Skip("loads actual selected package-test source and standard library")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":    "module example.com/relation\n\ngo 1.27\n",
		"p.go":      "package p\nimport (\"unicode/utf16\";\"os\")\nfunc F(r rune)bool{return utf16.IsSurrogate(r)}\nfunc Constant()bool{return utf16.IsSurrogate(0xd800)}\nfunc Discarded()bool{os.Getenv(\"RELATION_TEST\");return true}\n",
		"p_test.go": "package p\nimport \"testing\"\nfunc TestScalar(t *testing.T){if !F(0xd800){t.Fail()}}\n",
	})
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	loader := newFixturePrograms(t, h)
	loader.supply(t, "example.com/relation")
	metas, err := h.list("example.com/relation")
	if err != nil {
		t.Fatal(err)
	}
	s := computationSource{prog: loader.loaded, metas: metas}
	// This includes the generated test main, testing state and native runtime.
	// The local theorem must not require or pretend those are all pure.
	if _, _, err := s.declarations(t.Context()); err == nil {
		t.Fatal("whole-startup control unexpectedly accepted")
	}
	if relation, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["Discarded"], bitrelation.NewScope(), nil, computationRelationLimits{}); relation != nil || err == nil {
		t.Fatal("discarded selected environment read acquired a pure relation")
	}
	var roots []*ssa.Function
	roots = append(roots, s.prog.Roots["F"], s.prog.Roots["Constant"])
	for _, p := range s.prog.Pkgs {
		if p.PkgPath == "unicode/utf16" {
			roots = append(roots, s.prog.Prog.Package(p.Types).Func("IsSurrogate"))
		}
	}
	if len(roots) != 3 {
		t.Fatalf("selected roots: %v", roots)
	}
	for _, root := range roots {
		scope := bitrelation.NewScope()
		builder := bitrelation.NewBuilder(0)
		var inputs []bitrelation.Term
		if len(root.Params) != 0 {
			input, err := builder.Input(bitrelation.Bits(32), scope, 0)
			if err != nil {
				t.Fatal(err)
			}
			inputs = append(inputs, input)
		}
		r, err := deriveComputationRelation(t.Context(), s, root, scope, inputs, computationRelationLimits{})
		if err != nil {
			t.Fatalf("%s: %v", root, err)
		}
		if len(inputs) == 0 {
			if relationEvaluate(t, r)[0] != 1 {
				t.Fatal("raw source constant call")
			}
			continue
		}
		for _, runeValue := range []rune{math.MinInt32, -1, 0, 0xd7ff, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xe000, math.MaxInt32} {
			want := uint64(0)
			if utf16.IsSurrogate(runeValue) {
				want = 1
			}
			if got := relationEvaluate(t, r, uint64(uint32(runeValue)))[0]; got != want {
				t.Fatalf("%s(%d)=%d want %d", root, runeValue, got, want)
			}
		}
	}
}
