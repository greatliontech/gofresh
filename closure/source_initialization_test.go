package closure

import (
	"context"
	"errors"
	"go/constant"
	"go/types"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
)

// Rewire selected synthetic blocks into a diamond with alternative stores to
// the same globals. This tests the binder's structural obligation alone, not
// source/expression correspondence or an interpreted value claim. Instructions
// retain their actual owners; the source inventory and InitOrder stay intact.
func initializationDiamond(t *testing.T) (sourceStartupInput, *ssa.Function, *packages.Package, *ssa.BasicBlock, *ssa.BasicBlock, *ssa.BasicBlock, *ssa.BasicBlock) {
	t.Helper()
	in, main, _ := startupFixture(t, map[string][]string{"main": {`package main
var Gate bool
var A=Gate||Gate
var B=Gate||Gate
var C=Gate||Gate
func init(){}
func consume(bool){}
func main(){consume(C)}`}})
	fn := main.Pkg.Func("init")
	start, body, done := fn.Blocks[0], fn.Blocks[1], fn.Blocks[0].Succs[0]
	stores := map[string]*ssa.Store{}
	var arms []*ssa.BasicBlock
	for _, block := range fn.Blocks {
		for _, ins := range block.Instrs {
			if store, ok := ins.(*ssa.Store); ok {
				if global, ok := store.Addr.(*ssa.Global); ok {
					stores[global.Name()] = store
				}
			}
		}
		if block != body && len(block.Instrs) == 2 {
			if _, ok := block.Instrs[1].(*ssa.Jump); ok {
				arms = append(arms, block)
			}
		}
	}
	if len(arms) != 3 || stores["A"] == nil || stores["B"] == nil || stores["C"] == nil {
		t.Fatal("fixture lacks the required actual branch/store blocks")
	}
	left, right, tail := stores["A"].Block(), stores["B"].Block(), stores["C"].Block()
	for _, block := range []*ssa.BasicBlock{left, right} {
		original := stores["A"]
		if block == right {
			original = stores["B"]
		}
		first, second := *original, *original
		first.Addr, second.Addr = stores["A"].Addr, stores["B"].Addr
		first.Val = ssa.NewConst(constant.MakeBool(false), types.Typ[types.Bool])
		second.Val = ssa.NewConst(constant.MakeBool(true), types.Typ[types.Bool])
		branch := block.Instrs[len(block.Instrs)-1].(*ssa.If)
		branch.Cond = ssa.NewConst(constant.MakeBool(true), types.Typ[types.Bool])
		block.Instrs = []ssa.Instruction{&first, &second, branch}
		block.Succs = arms[:2:2]
	}
	for _, block := range arms[:2] {
		block.Instrs = block.Instrs[len(block.Instrs)-1:]
		block.Succs = []*ssa.BasicBlock{tail}
	}
	tail.Instrs = tail.Instrs[len(tail.Instrs)-3:]
	body.Succs = []*ssa.BasicBlock{left, right}
	fn.Blocks = []*ssa.BasicBlock{start, body, done, left, right, arms[0], arms[1], tail}
	initializationPreds(fn)
	return in, main, in.source.prog.Pkgs[0], left, right, tail, arms[2]
}

func initializationPreds(fn *ssa.Function) {
	for i, block := range fn.Blocks {
		block.Index, block.Preds = i, nil
	}
	for _, block := range fn.Blocks {
		for _, succ := range block.Succs {
			succ.Preds = append(succ.Preds, block)
		}
	}
}

func TestSourceInitializationPathProgress(t *testing.T) {
	for _, mode := range []string{"complete", "missing-left", "missing-right", "reordered", "doubled", "extra-global", "join-progress", "join-progress-left", "drop-branch", "drop-edge", "duplicate-edge", "drop-suffix", "bypass-suffix", "complete-bypass-suffix", "incomplete-tail", "extra-init", "cycle", "index", "terminal", "detached"} {
		t.Run(mode, func(t *testing.T) {
			in, main, selected, left, right, tail, spare := initializationDiamond(t)
			fn := main.Pkg.Func("init")
			switch mode {
			case "missing-left":
				left.Instrs = left.Instrs[1:]
			case "missing-right":
				right.Instrs = right.Instrs[1:]
			case "reordered":
				left.Instrs[0], left.Instrs[1] = left.Instrs[1], left.Instrs[0]
			case "doubled":
				copy := *left.Instrs[0].(*ssa.Store)
				left.Instrs = append([]ssa.Instruction{&copy}, left.Instrs...)
			case "extra-global":
				left.Instrs[1].(*ssa.Store).Addr = main.Pkg.Members["Gate"].(*ssa.Global)
			case "join-progress":
				// Both arms have ordered prefixes, but one has not yet done B.
				right.Instrs = append(right.Instrs[:1], right.Instrs[2:]...)
			case "join-progress-left":
				// The complete predecessor is visited last. Merely overwriting
				// the join's progress would conceal the earlier incomplete path.
				left.Instrs = append(left.Instrs[:1], left.Instrs[2:]...)
			case "drop-branch":
				fn.Blocks = slices.Delete(fn.Blocks, right.Index, right.Index+1)
				for i, block := range fn.Blocks {
					block.Index = i
				}
			case "drop-edge":
				left.Preds = nil
			case "duplicate-edge":
				left.Succs = []*ssa.BasicBlock{left.Succs[0], left.Succs[0]}
				initializationPreds(fn)
			case "drop-suffix":
				tail.Instrs = append(tail.Instrs[:1], tail.Instrs[2:]...)
			case "bypass-suffix":
				left.Succs[0].Succs[0] = fn.Blocks[0].Succs[0]
				initializationPreds(fn)
			case "complete-bypass-suffix":
				// Both routes finish every variable initializer, but only the
				// right route executes the explicit init. Store counts and join
				// compatibility alone cannot establish suffix coverage.
				done := fn.Blocks[0].Succs[0]
				copy := *left.Instrs[1].(*ssa.Store)
				copy.Addr = main.Pkg.Members["C"].(*ssa.Global)
				left.Instrs = []ssa.Instruction{left.Instrs[0], left.Instrs[1], &copy, left.Instrs[2]}
				right.Succs = []*ssa.BasicBlock{right.Succs[1], tail}
				left.Succs = []*ssa.BasicBlock{left.Succs[0], spare}
				left.Succs[0].Succs = []*ssa.BasicBlock{done}
				spare.Instrs = spare.Instrs[len(spare.Instrs)-1:]
				spare.Succs = []*ssa.BasicBlock{done}
				fn.Blocks = append(fn.Blocks[:len(fn.Blocks)-1], spare, tail)
				initializationPreds(fn)
			case "incomplete-tail":
				tail.Instrs = tail.Instrs[1:]
			case "extra-init":
				copy := *tail.Instrs[1].(*ssa.Call)
				tail.Instrs = append([]ssa.Instruction{&copy}, tail.Instrs...)
			case "cycle":
				left.Succs[0].Succs[0] = left
				initializationPreds(fn)
			case "index":
				right.Index = left.Index
			case "terminal":
				left.Instrs = left.Instrs[:len(left.Instrs)-1]
			case "detached":
				fn.Blocks[1].Succs[1] = tail
				initializationPreds(fn)
			}
			binder, err := newSelectedSourceBinder(t.Context(), in.source, main, defaultRegistrationLimits().source)
			if err != nil {
				t.Fatal(err)
			}
			got, err := binder.bindInitialization(selected)
			if mode == "complete" {
				if err != nil {
					t.Fatal("compatible alternative store paths refused", err)
				}
				if got.suffix != (regionPoint{tail, 1}) || got.entry != (regionPoint{fn.Blocks[1], 1}) || got.end.at.block != fn.Blocks[0].Succs[0] {
					t.Fatal("lost exact entry/common suffix/return")
				}
			} else if got != nil || err == nil {
				t.Fatalf("incomplete or malformed path accepted: %v, %v", got, err)
			}
		})
	}
}

func TestSourceInitializationGraphBudgetAndCancellation(t *testing.T) {
	in, main, selected, _, _, _, _ := initializationDiamond(t)
	ctx := &regionCallCountingContext{Context: t.Context()}
	binder, err := newSelectedSourceBinder(ctx, in.source, main, defaultRegistrationLimits().source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binder.bindInitialization(selected); err != nil {
		t.Fatal(err)
	}
	limits := defaultRegistrationLimits().source
	limits.work = binder.work - 1
	limited, err := newSelectedSourceBinder(t.Context(), in.source, main, limits)
	if err != nil {
		t.Fatal("budget should reach initialization traversal", err)
	}
	if got, err := limited.bindInitialization(selected); got != nil || err == nil || !strings.Contains(err.Error(), "work budget") {
		t.Fatal("late graph work escaped the shared source meter", got, err)
	}
	for _, stop := range []int{ctx.checks / 2, ctx.checks - 1} {
		cancelled, err := newSelectedSourceBinder(&regionCallCountingContext{Context: t.Context(), stop: stop}, in.source, main, defaultRegistrationLimits().source)
		if err != nil {
			t.Fatal("cancellation should reach initialization traversal", err)
		}
		if got, err := cancelled.bindInitialization(selected); got != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled graph traversal returned a binding", got, err)
		}
	}
}
