package closure

import (
	"context"
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func regionOperandPopulation(t *testing.T, local bool) regionInput {
	t.Helper()
	typ, arg, head := "int", "x", "func F(x int){"
	if local {
		typ, arg, head = "*int", "v", "func F(){v:=new(int);"
	}
	var params, args []string
	for i := range 64 {
		params = append(params, fmt.Sprintf("p%d %s", i, typ))
		args = append(args, arg)
	}
	text := "func target(" + strings.Join(params, ",") + "){};" + head
	for range 16 {
		text += "target(" + strings.Join(args, ",") + ");"
	}
	return regionFixture(t, text+"}")
}

func TestRegionOperandIndexAccountsForRepeatedUses(t *testing.T) {
	in := regionOperandPopulation(t, false)
	limits := defaultRegionLimits()
	limits.work = 512
	if _, err := newRegionKernel(t.Context(), in, limits); err == nil || !strings.Contains(err.Error(), "work budget") {
		t.Fatal("many occurrences of one parameter bypassed work bound", err)
	}
	counted := &regionCallCountingContext{Context: t.Context(), stop: 512}
	if _, err := newRegionKernel(counted, in, defaultRegionLimits()); !errors.Is(err, context.Canceled) {
		t.Fatal("parameter use traversal bypassed cancellation", err)
	}
	in = regionOperandPopulation(t, true)
	limits = defaultRegionLimits()
	limits.locations = 128
	if _, err := newRegionKernel(t.Context(), in, limits); err == nil || !strings.Contains(err.Error(), "index storage budget") {
		t.Fatal("retained local use index bypassed storage bound", err)
	}
}

func regionFramePopulation(t *testing.T) (*regionKernel, regionObject, []types.Type) {
	t.Helper()
	var text strings.Builder
	for i := range 64 {
		fmt.Fprintf(&text, "type T%d int;", i)
	}
	text.WriteString("func F()map[string]int{return make(map[string]int)}")
	in := regionFixture(t, text.String())
	in.normalReturns = true
	k, err := newRegionKernel(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	var object regionObject
	for _, block := range in.root.Blocks {
		for _, ins := range block.Instrs {
			if m, ok := ins.(*ssa.MakeMap); ok {
				object = regionObject{kind: regionMapAllocation, site: m, context: in.root}
			}
		}
	}
	var names []types.Type
	for i := range 64 {
		names = append(names, in.root.Pkg.Pkg.Scope().Lookup(fmt.Sprintf("T%d", i)).Type())
	}
	return k, object, names
}

func TestRegionWriteFrameTraversalBudgets(t *testing.T) {
	t.Run("merge-work", func(t *testing.T) {
		k, _, names := regionFramePopulation(t)
		k.meter.limits.work = k.meter.work + 512
		if err := k.mergeFrame(regionWriteFrame{typed: names}); err == nil || !strings.Contains(err.Error(), "work budget") {
			t.Fatal("pairwise type comparisons bypassed work bound", err)
		}
	})
	t.Run("merge-storage", func(t *testing.T) {
		k, _, names := regionFramePopulation(t)
		k.meter.limits.locations = 8
		if err := k.mergeFrame(regionWriteFrame{typed: names}); err == nil || !strings.Contains(err.Error(), "type budget") {
			t.Fatal("write types bypassed storage bound", err)
		}
	})
	t.Run("merge-cancellation", func(t *testing.T) {
		k, _, names := regionFramePopulation(t)
		k.meter.ctx = &regionCallCountingContext{Context: t.Context(), stop: 128}
		if err := k.mergeFrame(regionWriteFrame{typed: names}); !errors.Is(err, context.Canceled) {
			t.Fatal("pairwise type comparisons bypassed cancellation", err)
		}
	})
	for _, cancel := range []bool{false, true} {
		t.Run(fmt.Sprintf("map-frame-cancel-%v", cancel), func(t *testing.T) {
			k, object, names := regionFramePopulation(t)
			var maps []types.Type
			for _, name := range names {
				maps = append(maps, types.NewMap(name, types.Typ[types.Int]))
			}
			if cancel {
				k.meter.ctx = &regionCallCountingContext{Context: t.Context(), stop: 8}
			} else {
				k.meter.limits.work = k.meter.work + 8
			}
			_, err := k.framePreserves(regionWriteFrame{maps: maps}, object)
			if cancel {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("map frame comparisons bypassed cancellation", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "work budget") {
				t.Fatal("map frame comparisons bypassed work bound", err)
			}
		})
	}
}

func TestRegionMapProjectionValidationCountsIgnoredFields(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprintf("nested-%v", nested), func(t *testing.T) {
			// No lookup or update is executed, so equalityTotal cannot accidentally
			// supply the work/cancellation checks owed by invariant validation itself.
			text := "type Inner struct{" + strings.Repeat("_ int;", 2048) + "_ string};type K=Inner;"
			if nested {
				text = "type Inner struct{" + strings.Repeat("_ int;", 2048) + "_ string};type K struct{Nested Inner};"
			}
			in := regionFixture(t, text+`func seed()map[K]int{return make(map[K]int)};func F(){}`)
			in.normalReturns = true
			seed := in.root.Pkg.Func("seed")
			var allocation *ssa.MakeMap
			for _, block := range seed.Blocks {
				for _, ins := range block.Instrs {
					if m, ok := ins.(*ssa.MakeMap); ok {
						allocation = m
					}
				}
			}
			if allocation == nil {
				t.Fatal("missing actual incoming map allocation")
			}
			object := regionObject{kind: regionMapAllocation, site: allocation, context: seed}
			incoming := regionValue{typ: allocation.Type(), kind: regionMapContents, keys: &regionMapKeys{}}
			in.initial.memory = map[regionObject]regionValue{object: incoming}
			limits := defaultRegionLimits()
			small := limits
			small.work = 128
			if _, err := proposeRegion(t.Context(), in, small); err == nil || !strings.Contains(err.Error(), "work budget") {
				t.Fatal("initial blank-field scan bypassed work bound", err)
			}
			cancelled := &regionCallCountingContext{Context: t.Context(), stop: 128}
			if _, err := proposeRegion(cancelled, in, limits); !errors.Is(err, context.Canceled) {
				t.Fatal("initial blank-field scan bypassed cancellation", err)
			}
			proposal, err := proposeRegion(t.Context(), in, limits)
			if err != nil {
				t.Fatal("sufficient initial-validation budget refused", err)
			}
			checked, err := checkRegion(t.Context(), in, proposal, limits)
			if err != nil {
				t.Fatal(err)
			}
			for _, out := range normalMapObservations(t, checked) {
				if keys := out.state.memory[object].keys; keys == nil || keys.empty || len(keys.projections) != 0 {
					t.Fatal("blank fields supplied distinguishing or empty-map evidence")
				}
			}

			// An empty entry premise needs no key traversal. Widen only the proposed
			// block invariant to unconstrained contents; this is sound, but validating
			// its projection schema still has to account for all the ignored fields.
			empty := incoming
			empty.keys = &regionMapKeys{empty: true}
			in.initial.memory = map[regionObject]regionValue{object: empty}
			proposal, err = proposeRegion(t.Context(), in, limits)
			if err != nil {
				t.Fatal(err)
			}
			state := proposal.entries[in.entry.block][0]
			state.memory = map[regionObject]regionValue{object: incoming}
			proposal.entries[in.entry.block] = []regionState{state}
			if _, err := checkRegion(t.Context(), in, proposal, small); err == nil || !strings.Contains(err.Error(), "work budget") {
				t.Fatal("proposed blank-field scan bypassed work bound", err)
			}
			cancelled = &regionCallCountingContext{Context: t.Context(), stop: 128}
			if _, err := checkRegion(cancelled, in, proposal, limits); !errors.Is(err, context.Canceled) {
				t.Fatal("proposed blank-field scan bypassed cancellation", err)
			}
			checked, err = checkRegion(t.Context(), in, proposal, limits)
			if err != nil {
				t.Fatal("sufficient proposal-validation budget refused", err)
			}
			for _, out := range normalMapObservations(t, checked) {
				if keys := out.state.memory[object].keys; keys == nil || keys.empty || len(keys.projections) != 0 {
					t.Fatal("blank fields acquired projected equality evidence")
				}
			}
		})
	}
}
