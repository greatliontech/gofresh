package closure

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

func TestComputationCallbackVoidAndOpaqueInput(t *testing.T) {
	for _, word := range []int{32, 64} {
		for _, text := range []string{"func F(){}", "func F(p *int){}", "func F(p *int,x int32)int32{return x+1}"} {
			t.Run(fmt.Sprintf("%d/%s", word, text), func(t *testing.T) {
				s := relationFixture(t, text, word)
				r := relationProve(t, s)
				if r.open != (computationRelationObligations{true, true, true, true, true}) {
					t.Fatal("local body closed surrounding obligations")
				}
				if len(r.outputs) != s.prog.Roots["F"].Signature.Results().Len() {
					t.Fatal("void body invented result bits")
				}
				if len(r.inputs) != 0 {
					p := r.root.parameters[0]
					if p.pointerBits != word || p.sort != (bitrelation.Sort{}) || p.name != "*int" || r.inputs[0].Sort() != bitrelation.Bits(word) {
						t.Fatalf("lost opaque pointer interpretation: %+v", p)
					}
				}
			})
		}
	}
	args := []computationScalarLocation{{nativeproof.RAX, 0, 64}}
	s := relationFixture(t, "func F(p *int){}", 64)
	c, err := deriveComputationCorrespondence(t.Context(), s, s.prog.Roots["F"], correspondenceImage(t, "c3"), 0x401000, correspondenceFace(args, nil), args, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireCorrespondenceWitnesses(t, c, 0)
	if bound, ok := c.native.Bound(); !ok || len(bound.Instructions) == 0 || bound.Interface.Results != (nativeproof.Masks{}) {
		t.Fatal("void correspondence lacks native effect/return certificate")
	}
	if c.open != (computationCorrespondenceObligations{true, true, true, true, true}) {
		t.Fatal("void correspondence granted runtime authority")
	}
}

func TestComputationCallbackReachablePointerUseRefuses(t *testing.T) {
	for _, text := range []string{
		"func F(p *int){println(*p)}",
		"func F(p *int){*p=7}",
		"var saved *int;func F(p *int){saved=p}",
		"func take(p *int){};func F(p *int){take(p)}",
		"func F(p *int)bool{return p==nil}",
		"func F(p,q *int)bool{return p==q}",
		"func F(p *int)*int{return p}",
		"func F(p *int){for {}}",
		"func F(p *int,b bool){if b{*p=7}}",
	} {
		t.Run(text, func(t *testing.T) {
			s := relationFixture(t, text, 64)
			root := s.prog.Roots["F"]
			// The actual instruction operands remain intact while the optional
			// referrer inventory is deliberately made to claim no uses.
			if refs := root.Params[0].Referrers(); refs != nil {
				*refs = nil
			}
			scope, inputs := relationInputs(t, s)
			if r, err := deriveComputationRelation(t.Context(), s, root, scope, inputs, computationRelationLimits{}); r != nil || err == nil {
				t.Fatal("reachable pointer use admitted from missing referrers")
			}
		})
	}
}

func TestComputationCallbackVoidCorrespondenceRefusals(t *testing.T) {
	args := []computationScalarLocation{{nativeproof.RAX, 0, 64}}
	for _, tc := range []struct {
		name, text, code string
		args, results    []computationScalarLocation
		face             nativeproof.Interface
	}{
		{"native-load", "func F(p *int){}", "488b08c3", args, nil, correspondenceFace(args, nil)},
		{"native-store", "func F(p *int){}", "488908c3", args, nil, correspondenceFace(args, nil)},
		{"native-cycle", "func F(p *int){}", "ebfe", args, nil, correspondenceFace(args, nil)},
		{"source-effect", "func F(p *int){println(7)}", "c3", args, nil, correspondenceFace(args, nil)},
		{"source-result-omitted", "func F(p *int)int{return 1}", "c3", args, nil, correspondenceFace(args, nil)},
		{"invented-result", "func F(p *int){}", "c3", args, args, correspondenceFace(args, args)},
		{"native-result-mask", "func F(p *int){}", "c3", args, nil, correspondenceFace(args, args)},
		{"pointer-width", "func F(p *int){}", "c3", []computationScalarLocation{{nativeproof.RAX, 0, 32}}, nil, correspondenceFace([]computationScalarLocation{{nativeproof.RAX, 0, 32}}, nil)},
		{"pointer-missing", "func F(p *int){}", "c3", nil, nil, correspondenceFace(nil, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := relationFixture(t, tc.text, 64)
			if c, err := deriveComputationCorrespondence(t.Context(), s, s.prog.Roots["F"], correspondenceImage(t, tc.code), 0x401000, tc.face, tc.args, tc.results); c != nil || err == nil {
				t.Fatal("invalid void interface/effect acquired correspondence")
			}
		})
	}
	s := relationFixture(t, "func F(p *int){}", 64)
	scope := bitrelation.NewScope()
	b := bitrelation.NewBuilder(0)
	wrong, _ := b.Input(bitrelation.Bool(), scope, 0)
	if r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, []bitrelation.Term{wrong}, computationRelationLimits{}); r != nil || err == nil {
		t.Fatal("Boolean caller input reinterpreted as pointer")
	}
}

func requireSourceExclusions(t *testing.T, r *computationRelation) {
	t.Helper()
	if len(r.exclusions) == 0 {
		t.Fatal("missing checked path exclusions")
	}
	for _, x := range r.exclusions {
		left, right := x.witness.Roots()
		if !x.witness.Valid() || left != x.path || right.Sort() != bitrelation.Bool() || right.View().Op != bitrelation.Constant || right.View().Immediate != 0 || x.dependency < 0 || x.dependency >= len(r.dependencies) || x.block < 0 {
			t.Fatal("unbound path exclusion")
		}
	}
}

func TestComputationCallbackCheckedDeadPaths(t *testing.T) {
	for _, text := range []string{
		"func no()bool{return false};func native();func F(){if no(){native()}}",
		"func no()bool{return false};func F(p *int){if no(){*p=7}}",
		"func no()bool{return false};func F(){if no(){panic(7)}}",
	} {
		t.Run(text, func(t *testing.T) {
			r := relationProve(t, relationFixture(t, text, 64))
			requireSourceExclusions(t, r)
			if len(r.outputs) != 0 {
				t.Fatal("void exclusion invented result")
			}
		})
	}
	for _, text := range []string{
		"func yes()bool{return true};func native();func F(){if yes(){native()}}",
		"func native();func F(b bool){if b{native()}}",
		"func F(p *int,b bool){if b{*p=7}}",
		"func F(b bool){if b{panic(7)}}",
		// This contradiction currently exceeds the rewrite proposer's rules.
		// Unknown proof is still a refusal, never permission to omit the call.
		"func native();func F(b bool){if b{if !b{native()}}}",
	} {
		t.Run(text, func(t *testing.T) {
			s := relationFixture(t, text, 64)
			scope, inputs := relationInputs(t, s)
			if r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{}); r != nil || err == nil {
				t.Fatal("satisfiable or unproven effect path excluded")
			}
		})
	}
}

func TestComputationCallbackPhiRequiresDeadEdgeWitness(t *testing.T) {
	const text = "func no()bool{return false};func native()int32;func F(x int32)int32{var y int32;if no(){y=native()}else{y=x+1};return y}"
	s := relationFixture(t, text, 64)
	r := relationProve(t, s)
	requireSourceExclusions(t, r)
	phiWitness := false
	for _, x := range r.exclusions {
		phiWitness = phiWitness || x.predecessor >= 0
	}
	if !phiWitness {
		t.Fatal("phi dropped an unavailable operand without an edge witness")
	}
	if got := relationEvaluate(t, r, 17)[0]; got != 18 {
		t.Fatal("phi lost its live predecessor", got)
	}
	for _, dep := range r.dependencies {
		if strings.HasSuffix(dep.function, ".native") {
			t.Fatal("excluded native call received semantic dependency")
		}
	}
	for _, block := range s.prog.Roots["F"].Blocks {
		for _, ins := range block.Instrs {
			if phi, ok := ins.(*ssa.Phi); ok {
				for i, operand := range phi.Edges {
					if _, call := operand.(*ssa.Call); !call {
						phi.Edges[i] = nil
					}
				}
			}
		}
	}
	scope, inputs := relationInputs(t, s)
	if r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{}); r != nil || err == nil {
		t.Fatal("missing live phi value hidden by another edge's exclusion")
	}
}

func TestComputationCallbackDeadBlocksKeepGraphObligations(t *testing.T) {
	for _, mode := range []string{"instruction-owner", "block-index", "return-arity", "cycle"} {
		t.Run(mode, func(t *testing.T) {
			text := "func no()bool{return false};func F(p *int){if no(){*p=7;return};return}"
			if mode == "cycle" {
				text = "func no()bool{return false};func F(p *int){if no(){for{}}}"
			}
			s := relationFixture(t, text, 64)
			root := s.prog.Roots["F"]
			mutated := mode == "cycle"
			for _, block := range root.Blocks {
				for index, instruction := range block.Instrs {
					if _, ok := instruction.(*ssa.Store); ok {
						switch mode {
						case "instruction-owner":
							block.Instrs[index] = root.Blocks[0].Instrs[0]
						case "block-index":
							block.Index = root.Blocks[0].Index
						case "return-arity":
							terminal, ok := block.Instrs[len(block.Instrs)-1].(*ssa.Return)
							if !ok {
								t.Fatal("fixture has no dead return")
							}
							terminal.Results = []ssa.Value{root.Params[0]}
						}
						mutated = true
					}
				}
			}
			if !mutated {
				t.Fatal("fixture has no dead store")
			}
			scope, inputs := relationInputs(t, s)
			if r, err := deriveComputationRelation(t.Context(), s, root, scope, inputs, computationRelationLimits{}); r != nil || err == nil {
				t.Fatal("dead path hid an invalid or cyclic original graph")
			}
		})
	}
}

func TestComputationCallbackExclusionWitnessAndBudget(t *testing.T) {
	s := relationFixture(t, "func F(){}", 64)
	root := s.prog.Roots["F"]
	builder := bitrelation.NewBuilder(0)
	truth, _ := builder.Const(bitrelation.Bool(), 1)
	falsity, _ := builder.Const(bitrelation.Bool(), 0)
	w, err := bitrelation.Prove(t.Context(), truth, truth, bitrelation.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	falseWitness, err := bitrelation.Prove(t.Context(), falsity, falsity, bitrelation.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path   bitrelation.Term
		forged bitrelation.Witness
	}{
		{falsity, bitrelation.Witness{}}, {falsity, w}, {truth, w}, {truth, falseWitness},
	} {
		c := &computationRelationChecker{selectedSourceBinder: selectedSourceFixtureBinder(t, s), provePaths: true, pathProofs: map[bitrelation.Term]bitrelation.Witness{tc.path: tc.forged}}
		if yes, _ := c.exclude(root, root.Pos(), 0, 1, -1, tc.path, falsity); yes || len(c.exclusions) != 0 {
			t.Fatal("forged/unrelated witness excluded a path")
		}
	}
	c := &computationRelationChecker{selectedSourceBinder: selectedSourceFixtureBinder(t, s), provePaths: true, pathProofs: map[bitrelation.Term]bitrelation.Witness{}}
	c.limits.work = c.work + 1
	if yes, err := c.exclude(root, root.Pos(), 0, 1, -1, falsity, falsity); yes || err == nil || !strings.Contains(err.Error(), "budget") || len(c.exclusions) != 0 {
		t.Fatal("proof budget became absence of a live path", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c.ctx = ctx
	if yes, err := c.exclude(root, root.Pos(), 0, 1, -1, falsity, falsity); yes || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled path proof", err)
	}
}

func TestComputationCallbackRetryKeepsContextBudget(t *testing.T) {
	s := relationFixture(t, "func no()bool{return false};func native();func F(){if no(){native()}}", 64)
	scope, inputs := relationInputs(t, s)
	for _, contexts := range []int{3, 4} {
		limits := defaultComputationRelationLimits()
		limits.contexts = contexts
		r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, limits)
		if contexts == 3 {
			if r != nil || err == nil || !strings.Contains(err.Error(), "context/depth budget") {
				t.Fatal("retry reset the spent context budget", err)
			}
		} else if err != nil {
			t.Fatal("adequate shared context budget", err)
		}
	}
}

func FuzzComputationCallbackBranchExclusions(f *testing.F) {
	f.Add(int32(0), int32(17), false)
	f.Add(int32(-1), int32(-2147483648), true)
	f.Fuzz(func(t *testing.T, threshold, x int32, invert bool) {
		condition := fmt.Sprintf("equal(%d,%d)", threshold, threshold)
		if !invert {
			condition = "!" + condition
		}
		text := fmt.Sprintf("func equal(a,b int32)bool{return a==b};func native();func F(x int32)int32{if %s{native()};return x+1}", condition)
		s := relationFixture(t, text, 64)
		scope, inputs := relationInputs(t, s)
		r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{})
		if invert {
			if r != nil || err == nil {
				t.Fatal("satisfiable generated branch excluded")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		requireSourceExclusions(t, r)
		if got := relationEvaluate(t, r, uint64(uint32(x)))[0]; got != uint64(uint32(x+1)) {
			t.Fatal("excluded a satisfiable branch or lost modular result")
		}
	})
}
