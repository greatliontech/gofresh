package closure

import (
	"fmt"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

func unusedPointerSource(t testing.TB, parameter, before, after string) (computationSource, *ssa.Call, *ssa.Return, [2]*ssa.Global) {
	t.Helper()
	source := relationFixture(t, fmt.Sprintf(`var A,B uint64
func Read(p *uint64) uint64 { return *p }
func F(%s) { %s; A=7; B=9; if Read(&A)!=7 { panic("read") }; A=11; %s }
`, parameter, before, after), 64)
	root := source.prog.Roots["F"]
	var call *ssa.Call
	var returned *ssa.Return
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			if c, ok := instruction.(*ssa.Call); ok && c.Call.StaticCallee() != nil && c.Call.StaticCallee().Name() == "Read" {
				call = c
			}
			if r, ok := instruction.(*ssa.Return); ok {
				returned = r
			}
		}
	}
	return source, call, returned, [2]*ssa.Global{root.Pkg.Members["A"].(*ssa.Global), root.Pkg.Members["B"].(*ssa.Global)}
}

func TestSourceUnusedPointerWholeRoot(t *testing.T) {
	for _, tc := range []struct {
		name, parameter, before, after string
		positive                       bool
	}{
		{"unused", "p *uint64", "", "", true},
		{"aliased-unused", "p,q *uint64", "", "", true},
		{"scalar", "p uint64", "", "", false},
		{"read-before", "p *uint64", "_ = *p", "", false},
		{"read-after", "p *uint64", "", "_ = *p", false},
		{"write-after", "p *uint64", "", "*p = 11", false},
		{"dead-arm-use", "p *uint64", "", "if A != 11 { *p = 2 }", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, call, returned, globals := unusedPointerSource(t, tc.parameter, tc.before, tc.after)
			root := source.prog.Roots["F"]
			prefix, err := checkSourceOperandPrefix(t.Context(), source, root, call, defaultRegistrationLimits())
			if !tc.positive {
				if err == nil || prefix != nil {
					t.Fatal("used or non-pointer argument acquired unused-argument proof")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			completed, err := checkSourceReturnContinuation(t.Context(), prefix, returned, nil)
			if err != nil {
				t.Fatal(err)
			}
			fixture, native := globalFunctionNative(t, "guarded")
			rho := globalRho(source, fixture, globals, [2]uint64{0x700008, 0x700050})
			arguments := []globalFunctionArgument{}
			for i, parameter := range root.Params {
				arguments = append(arguments, globalFunctionArgument{parameter: parameter, register: nativeproof.Register(i)})
			}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, fixture.image, fixture.entry, completed, native, rho, arguments)
			if err != nil || len(proof.argumentInputs) != len(root.Params) {
				t.Fatal("unused argument relation missing", err)
			}
			for _, bad := range [][]globalFunctionArgument{nil, {{parameter: root.Params[0], register: nativeproof.R14}}, {{parameter: root.Params[0], register: nativeproof.RSP}}} {
				if proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, fixture.image, fixture.entry, completed, native, rho, bad); err == nil || proof != nil {
					t.Fatal("missing, constrained or stack argument acquired independent input relation")
				}
			}
		})
	}
}
