package bitrelation_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func sliceFields(f factory, base br.Term, offset, lowWidth, highWidth int, trunc bool) (br.Term, br.Term) {
	low := f.make(br.Extract, br.Bits(lowWidth), uint64(offset), base)
	if trunc && offset == 0 {
		low = f.make(br.Trunc, low.Sort(), 0, base)
	}
	high := f.make(br.Extract, br.Bits(highWidth), uint64(offset+lowWidth), base)
	joined := f.make(br.Concat, br.Bits(lowWidth+highWidth), 0, low, high)
	want := base
	if offset != 0 {
		want = f.make(br.Extract, joined.Sort(), uint64(offset), base)
	} else if joined.Sort() != base.Sort() {
		want = f.make(br.Trunc, joined.Sort(), 0, base)
	}
	return joined, want
}

// byteReload models a little-endian spill and reload without assigning any
// value to its input. Each byte is extracted from the same immutable word.
func byteReload(f factory, word br.Term, width int) br.Term {
	var joined br.Term
	for offset := 0; offset < width; offset += 8 {
		part := f.make(br.Extract, br.Bits(8), uint64(offset), word)
		if offset == 0 {
			joined = part
		} else {
			joined = f.make(br.Concat, br.Bits(offset+8), 0, joined, part)
		}
	}
	return joined
}

func TestSliceReassemblyTwoLevelByteReload(t *testing.T) {
	for _, width := range []int{32, 64} {
		for _, add := range []bool{false, true} {
			t.Run(fmt.Sprintf("width%d/add%t", width, add), func(t *testing.T) {
				f := newFactory(t)
				x := f.variable(br.Bits(64), br.NewScope(), 0, false)
				base := x
				if add {
					base = f.make(br.Add, br.Bits(64), 0, x, f.con(br.Bits(64), 8))
				}
				initial := byteReload(f, base, 64)
				left, right := byteReload(f, initial, width), initial
				if width == 32 {
					right = f.make(br.Trunc, br.Bits(32), 0, initial)
				}
				prove(t, left, right)
				want := base
				if width == 32 {
					want = f.make(br.Trunc, br.Bits(32), 0, base)
				}
				proof := prove(t, left, want)
				used := false
				for _, step := range proof.Steps {
					used = used || step.Rule == br.Conversion && step.Left.View().Op == br.Concat
				}
				if !used {
					t.Fatal("byte reload did not exercise checked slice reassembly")
				}
				// Finite edge checks supplement the symbolic all-input proof.
				for _, value := range []uint64{0, 1, 7, 8, 255, 256, 1<<31 - 1, 1 << 31, 1<<32 - 1, 1 << 32, 1<<63 - 1, 1 << 63, ^uint64(0) - 8, ^uint64(0) - 7, ^uint64(0), 0x0123456789abcdef} {
					assertValues(t, left, want, map[br.Term]uint64{x: value})
				}
			})
		}
	}
}

func TestSliceReassemblyEverySmallRangeAndValuation(t *testing.T) {
	// Every nonempty adjacent pair, including unequal fields and proper ranges,
	// and every base valuation at widths 2..7. No valuations enter the proof.
	for width := 2; width <= 7; width++ {
		f := newFactory(t)
		x := f.variable(br.Bits(width), br.NewScope(), 0, false)
		for offset := 0; offset < width-1; offset++ {
			for low := 1; low < width-offset; low++ {
				for high := 1; high <= width-offset-low; high++ {
					for _, trunc := range []bool{false, true} {
						left, right := sliceFields(f, x, offset, low, high, trunc)
						direct(t, br.Conversion, left, right)
						prove(t, left, right)
						for value := uint64(0); value <= widthMask(width); value++ {
							assertValues(t, left, right, map[br.Term]uint64{x: value})
						}
					}
				}
			}
		}
	}
}

func TestSliceReassemblyWideBoundaries(t *testing.T) {
	f := newFactory(t)
	x := f.variable(br.Bits(64), br.NewScope(), 0, true)
	for _, shape := range [][3]int{{0, 1, 63}, {0, 63, 1}, {0, 8, 24}, {1, 31, 32}, {7, 1, 55}, {62, 1, 1}, {8, 8, 8}, {0, 1, 1}} {
		for _, trunc := range []bool{false, true} {
			left, right := sliceFields(f, x, shape[0], shape[1], shape[2], trunc)
			direct(t, br.Conversion, left, right)
			prove(t, left, right)
			for _, value := range []uint64{0, 1, 1 << 63, 1<<63 - 1, ^uint64(0), 0x0123456789abcdef, 0xfedcba9876543210} {
				assertValues(t, left, right, map[br.Term]uint64{x: value})
			}
		}
	}
}

func TestSliceReassemblyExactScopedBaseAcrossBuilders(t *testing.T) {
	f, other := newFactory(t), newFactory(t)
	scope := br.NewScope()
	x := f.variable(br.Bits(64), scope, 0, true)
	y := other.variable(br.Bits(64), scope, 0, true)
	a := f.make(br.Add, br.Bits(64), 0, x, f.con(br.Bits(64), 8))
	b := other.make(br.Add, br.Bits(64), 0, y, other.con(br.Bits(64), 8))
	left := f.make(br.Concat, br.Bits(64), 0, f.make(br.Trunc, br.Bits(17), 0, a), other.make(br.Extract, br.Bits(47), 17, b))
	direct(t, br.Conversion, left, a)
	prove(t, left, b)
}

func TestSliceReassemblyRetainsOriginalCommonBase(t *testing.T) {
	f := newFactory(t)
	x := f.variable(br.Bits(64), br.NewScope(), 0, false)
	base := f.make(br.Trunc, br.Bits(48), 0, x)
	// Normalizing the low field collapses Trunc(Trunc(x)), while the high
	// field still names Trunc(x). The original shared-base identity remains a
	// checked candidate independently of those different normalized shapes.
	left, right := sliceFields(f, base, 0, 8, 8, true)
	direct(t, br.Conversion, left, right)
	prove(t, left, right)
	prove(t, left, f.make(br.Trunc, br.Bits(16), 0, x))
	// Retain the fuzz-discovered three-field case: joining just the first
	// pair and immediately normalizing it would again lose the shared base.
	y := f.variable(br.Bits(51), br.NewScope(), 0, false)
	loaded := byteReload(f, byteReload(f, y, 48), 24)
	prove(t, loaded, f.make(br.Trunc, br.Bits(24), 0, y))
}

func TestSliceReassemblyAfterCheckedChildNormalization(t *testing.T) {
	f := newFactory(t)
	x := f.variable(br.Bits(32), br.NewScope(), 0, false)
	computed := f.make(br.Add, x.Sort(), 0, x, f.con(x.Sort(), 0))
	left := f.make(br.Concat, br.Bits(16), 0, f.make(br.Trunc, br.Bits(8), 0, computed), f.make(br.Extract, br.Bits(8), 8, x))
	right := f.make(br.Trunc, br.Bits(16), 0, x)
	// Semantic equality of different bases is not a local slice side condition.
	// The full proof must first establish it with its own checked inferences.
	refusal(t, left, right, br.Proof{Steps: []br.Step{{Rule: br.Conversion, Left: left, Right: right}}}, br.InvalidRule)
	prove(t, left, right)
}

func TestSliceReassemblyRejectsWrongRangesAndScopes(t *testing.T) {
	f := newFactory(t)
	scope := br.NewScope()
	x := f.variable(br.Bits(8), scope, 0, false)
	foreign := f.variable(br.Bits(8), br.NewScope(), 0, false)
	scratch := f.variable(br.Bits(8), scope, 0, true)
	slot := f.variable(br.Bits(8), scope, 1, false)
	left, right := sliceFields(f, x, 1, 2, 3, false)
	low, high := left.View().Args[0], left.View().Args[1]
	part := func(base br.Term, width, offset int) br.Term {
		return f.make(br.Extract, br.Bits(width), uint64(offset), base)
	}
	cat := func(lo, hi br.Term) br.Term { return f.make(br.Concat, br.Bits(5), 0, lo, hi) }
	cases := map[string][2]br.Term{
		"foreign-high":            {cat(low, part(foreign, 3, 3)), right},
		"foreign-low":             {cat(part(foreign, 2, 1), high), right},
		"scratch":                 {cat(low, part(scratch, 3, 3)), right},
		"slot":                    {cat(low, part(slot, 3, 3)), right},
		"gap":                     {cat(low, part(x, 3, 4)), right},
		"overlap":                 {cat(low, part(x, 3, 2)), right},
		"swap":                    {cat(high, low), right},
		"changed-low-offset":      {cat(part(x, 2, 0), high), right},
		"changed-result-offset":   {left, part(x, 5, 2)},
		"result-scope":            {left, part(foreign, 5, 1)},
		"wrong-result-conversion": {left, f.make(br.Trunc, br.Bits(5), 0, x)},
		"changed-field-widths":    {cat(part(x, 3, 1), part(x, 2, 3)), right},
		"high-trunc":              {cat(low, f.make(br.Trunc, br.Bits(3), 0, x)), right},
		"wrong-result-sort":       {left, part(x, 4, 1)},
	}
	a := f.make(br.Add, br.Bits(8), 0, x, f.con(br.Bits(8), 8))
	b := f.make(br.Add, br.Bits(8), 0, x, f.con(br.Bits(8), 9))
	cases["changed-base-immediate"] = [2]br.Term{cat(part(a, 2, 1), part(b, 3, 3)), part(a, 5, 1)}
	whole, _ := sliceFields(f, x, 0, 3, 5, true)
	cases["full-result-scope"] = [2]br.Term{whole, foreign}
	partial, _ := sliceFields(f, x, 0, 2, 3, true)
	cases["trunc-result-scope"] = [2]br.Term{partial, f.make(br.Trunc, br.Bits(5), 0, foreign)}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			refusal(t, pair[0], pair[1], br.Proof{Steps: []br.Step{{Rule: br.Conversion, Left: pair[0], Right: pair[1]}}}, br.InvalidRule)
			if witness, err := br.Prove(t.Context(), pair[0], pair[1], br.Limits{}); err == nil || witness.Valid() {
				t.Fatalf("false slice identity proved: %v", err)
			}
		})
	}
	// Construction owns field/result typing and the base's bounds, before any
	// checker can see these malformed ranges. Identity fields cannot be adjacent
	// within the same base; their nonempty neighbor necessarily exceeds it.
	for _, shape := range [][2]int{{8, 1}, {5, 4}, {1, 8}} {
		if _, err := f.b.Make(br.Extract, br.Bits(shape[0]), uint64(shape[1]), x); err == nil {
			t.Fatalf("out-of-base range constructed: %v", shape)
		}
	}
	identity := f.make(br.Concat, br.Bits(9), 0, x, part(x, 1, 0))
	refusal(t, identity, f.make(br.ZExt, br.Bits(9), 0, x), br.Proof{Steps: []br.Step{{Rule: br.Conversion, Left: identity, Right: f.make(br.ZExt, br.Bits(9), 0, x)}}}, br.InvalidRule)
}

func TestSliceReassemblyPreservesEstablishedNormalForms(t *testing.T) {
	f := newFactory(t)
	x := f.variable(br.Bits(8), br.NewScope(), 0, false)
	joined, _ := sliceFields(f, x, 0, 3, 5, true)
	low, high := joined.View().Args[0], joined.View().Args[1]
	masked, fields := concatMaskTerms(f, low, high, 0x55)
	pairs := [][2]br.Term{
		{masked, fields},
		{f.make(br.Trunc, br.Bits(2), 0, joined), f.make(br.Trunc, br.Bits(2), 0, x)},
		{f.make(br.Trunc, br.Bits(5), 0, joined), f.make(br.Concat, br.Bits(5), 0, low, f.make(br.Trunc, br.Bits(2), 0, high))},
		{f.make(br.Extract, br.Bits(5), 3, joined), high},
	}
	for _, pair := range pairs {
		proof := prove(t, pair[0], pair[1])
		for _, step := range proof.Steps {
			if step.Rule == br.Conversion && step.Left.View().Op == br.Concat {
				t.Fatal("previously joining normal form needlessly reassembled its fields")
			}
		}
	}
}

func TestSliceReassemblyCompleteProofCorruption(t *testing.T) {
	f := newFactory(t)
	x := f.variable(br.Bits(64), br.NewScope(), 0, false)
	left := byteReload(f, byteReload(f, x, 64), 32)
	right := f.make(br.Trunc, br.Bits(32), 0, x)
	proof := prove(t, left, right)
	corrupted := 0
	for i, step := range proof.Steps {
		if step.Rule != br.Conversion || step.Left.View().Op != br.Concat {
			continue
		}
		for _, mode := range []string{"result", "rule", "premise"} {
			bad := br.Proof{Steps: append([]br.Step(nil), proof.Steps...)}
			switch mode {
			case "result":
				bad.Steps[i].Right = f.variable(step.Right.Sort(), br.NewScope(), 0, false)
			case "rule":
				bad.Steps[i].Rule = br.Reflexivity
			case "premise":
				bad.Steps[i].Premises = []int{0}
			}
			witness, err := br.Check(t.Context(), left, right, bad, br.Limits{})
			var re *br.Refusal
			if witness.Valid() || !errors.As(err, &re) || re.Code != br.InvalidRule || re.Step != i {
				t.Fatalf("%s corruption did not fail at reassembly step %d: %v", mode, i, err)
			}
			corrupted++
		}
	}
	if corrupted == 0 {
		t.Fatal("no reassembly inference was corrupted")
	}
	foreign := f.variable(br.Bits(64), br.NewScope(), 0, false)
	refusal(t, left, f.make(br.Trunc, br.Bits(32), 0, foreign), proof, br.Endpoint)
}

func TestSliceReassemblyCancellationBudgetsAndOwnership(t *testing.T) {
	f := newFactory(t)
	x := f.variable(br.Bits(8), br.NewScope(), 0, false)
	left, right := sliceFields(f, x, 1, 2, 3, true)
	count := &conditionalCheckpoint{Context: t.Context()}
	proof, err := br.Propose(count, left, right, br.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	proposalCalls := count.calls
	count = &conditionalCheckpoint{Context: t.Context()}
	if w, err := br.Check(count, left, right, proof, br.Limits{}); err != nil || !w.Valid() {
		t.Fatal(err)
	}
	checkerCalls := count.calls
	for _, checking := range []bool{false, true} {
		calls := proposalCalls
		if checking {
			calls = checkerCalls
		}
		for at := 1; at <= calls; at++ {
			ctx, cancel := context.WithCancel(t.Context())
			callback := &conditionalCheckpoint{Context: ctx, action: func(n int) {
				if n == at {
					cancel()
				}
			}}
			if checking {
				var witness br.Witness
				witness, err = br.Check(callback, left, right, proof, br.Limits{})
				if witness.Valid() {
					t.Fatal("cancelled checking returned a witness")
				}
			} else {
				_, err = br.Propose(callback, left, right, br.Limits{})
			}
			cancel()
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("checking=%t cancellation at %d/%d: %v", checking, at, calls, err)
			}
		}
		for _, limits := range []br.Limits{{Nodes: 1}, {Work: calls - 1}, {Steps: len(proof.Steps) - 1}} {
			if checking {
				var witness br.Witness
				witness, err = br.Check(t.Context(), left, right, proof, limits)
				if witness.Valid() {
					t.Fatal("exhausted checking returned a witness")
				}
			} else {
				_, err = br.Propose(t.Context(), left, right, limits)
			}
			var re *br.Refusal
			if !errors.As(err, &re) || re.Code != br.Budget {
				t.Fatalf("checking=%t limits=%+v did not refuse cumulatively: %v", checking, limits, err)
			}
		}
	}
	owned := br.Proof{Steps: append([]br.Step(nil), proof.Steps...)}
	callback := &conditionalCheckpoint{Context: t.Context(), action: func(n int) {
		if n == 1 {
			for i := range owned.Steps {
				owned.Steps[i].Rule = br.Reflexivity
				owned.Steps[i].Right = left
				owned.Steps[i].Premises = []int{i}
			}
		}
	}}
	if w, err := br.Check(callback, left, right, owned, br.Limits{}); err != nil || !w.Valid() {
		t.Fatalf("callback changed the owned certificate: %v", err)
	}
}

func TestSliceReassemblyGeneratedNodesStayCumulative(t *testing.T) {
	f := newFactory(t)
	x := f.variable(br.Bits(64), br.NewScope(), 0, false)
	left := byteReload(f, byteReload(f, x, 64), 32)
	right := f.make(br.Trunc, br.Bits(32), 0, x)
	proof := prove(t, left, right)
	walk := func(roots ...br.Term) map[br.Term]bool {
		seen := make(map[br.Term]bool)
		for len(roots) > 0 {
			n := roots[len(roots)-1]
			roots = roots[:len(roots)-1]
			if seen[n] {
				continue
			}
			seen[n] = true
			roots = append(roots, n.View().Args...)
		}
		return seen
	}
	inputs := walk(left, right)
	before, after, all := make(map[br.Term]bool), make(map[br.Term]bool), make(map[br.Term]bool)
	reassembling := false
	for _, step := range proof.Steps {
		reassembling = reassembling || step.Rule == br.Conversion && step.Left.View().Op == br.Concat
		phase := before
		if reassembling {
			phase = after
		}
		for term := range walk(step.Left, step.Right) {
			if !inputs[term] {
				phase[term], all[term] = true, true
			}
		}
	}
	// The allowance fits the input graph and each observed group of generated
	// nodes alone, but not their union. A phase-local fresh arena would evade it.
	limit := max(len(inputs), len(before), len(after))
	if limit >= len(all) {
		t.Fatalf("fixture does not separate cumulative generated nodes: input=%d before=%d after=%d union=%d", len(inputs), len(before), len(after), len(all))
	}
	_, err := br.Propose(t.Context(), left, right, br.Limits{Nodes: limit})
	var re *br.Refusal
	if !errors.As(err, &re) || re.Code != br.Budget || re.Detail != "builder node budget" {
		t.Fatalf("reassembly restarted its generated-node allowance: %v", err)
	}
}
