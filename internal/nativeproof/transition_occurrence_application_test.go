package nativeproof

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestTransitionOccurrenceApplicationExcludedRootReturn(t *testing.T) {
	im := occurrenceImage(t, "e80b00000090"+strings.Repeat("90", 10)+"b80000000085c07501c3c3")
	childFace := occurrenceFace()
	childFace.Origin = OriginDomain{Min: 1 << 39, Max: 1 << 45, Modulus: 8}
	childFace.Envelope = RelativeSpan{-32, 32}
	childFace.Regions = []RelativeRegion{{Bytes: RelativeSpan{-32, 32}, Readable: true, Writable: true}}
	childFace.ReturnContext = &TransitionReturnContext{Target: occurrenceEntry + 5}
	p, err := ProposeRegionTransition(t.Context(), im, occurrenceEntry+16, occurrenceEntry+25, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	child, err := CheckRegionTransition(t.Context(), im, occurrenceEntry+16, childFace, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	before := child.checked.bound
	if len(before.ExcludedBoundaries) != 1 || before.ExcludedBoundaries[0].PC != occurrenceEntry+26 || before.ExcludedBoundaries[0].Frontier {
		t.Fatal("fixture lacks unsupported false root RET")
	}
	theorem, err := CheckTransitionReturn(t.Context(), child)
	if err != nil {
		t.Fatal(err)
	}
	caller, _ := occurrenceProof(t, im, occurrenceEntry, TransitionOptions{})
	applied, err := CheckTransitionCallReturn(t.Context(), caller, theorem)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := applied.Bound()
	assertApplicationOccurrences(t, applied, theorem)
	if !applied.AppliesTo(theorem) || len(b.Successor.ExcludedBoundaries) != 1 || !b.Successor.ExcludedBoundaries[0].Frontier || b.Successor.ExcludedBoundaries[0].PC != occurrenceEntry+26 || b.Successor.ExcludedBoundaries[0].Context != b.Activation {
		t.Fatal("mapped return exclusion lost bytes/context or frontier obligation")
	}
	for _, ins := range b.Successor.Instructions {
		if ins.Start == occurrenceEntry+26 {
			t.Fatal("excluded return acquired execution")
		}
	}
	if len(b.Successor.Accesses) != 2 || b.Successor.Boundary.PC != occurrenceEntry+5 || len(b.Successor.Frames) != 0 {
		t.Fatal("callee application did not complete its actual return")
	}
}

func TestTransitionOccurrenceActivationConflictPath(t *testing.T) {
	im := occurrenceImage(t, "85c07407e808000000eb05e80100000090c3")
	p, err := ProposeTransition(t.Context(), im, occurrenceEntry+16, TransitionLimits{}, TransitionOptions{Expansions: []TransitionExpansion{{PC: occurrenceEntry + 4}, {PC: occurrenceEntry + 11}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckTransition(t.Context(), im, occurrenceFace(), p, TransitionLimits{}); err != nil {
		t.Fatal("distinct-activation baseline", err)
	}
	var first, second TransitionOccurrenceID
	for _, n := range p.Nodes {
		if n.PC == occurrenceEntry+4 {
			first = n.Successors[0]
		}
		if n.PC == occurrenceEntry+11 {
			second = n.Successors[0]
		}
	}
	for j := range p.Nodes {
		if p.Nodes[j].PC == occurrenceEntry+11 {
			p.Nodes[j].Successors[0] = first
		}
	}
	p.Nodes = slices.DeleteFunc(p.Nodes, func(n TransitionNode) bool { return n.ID == second })
	c, err := CheckTransition(t.Context(), im, occurrenceFace(), p, TransitionLimits{})
	var r *Refusal
	if c.checked != nil || !errors.As(err, &r) || r.Premise != "transition-context" || r.PC != occurrenceEntry+17 || !slices.Equal(r.Path, []uint64{occurrenceEntry, occurrenceEntry + 2, occurrenceEntry + 4, occurrenceEntry + 17}) {
		t.Fatal("conflicting activation lost actual entry path", err)
	}
}

func TestTransitionOccurrenceApplicationReturnFrontierMustBeFalse(t *testing.T) {
	im := occurrenceImage(t, "e8010000009085c07501c3c3")
	p, err := ProposeTransition(t.Context(), im, occurrenceEntry+5, TransitionLimits{}, TransitionOptions{Expansions: []TransitionExpansion{{PC: occurrenceEntry}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckTransition(t.Context(), im, occurrenceFace(), p, TransitionLimits{}); err != nil {
		t.Fatal("both-return baseline", err)
	}
	for j := range p.Nodes {
		if p.Nodes[j].PC == occurrenceEntry+11 {
			p.Nodes[j].Frontier = true
			p.Nodes[j].Successors = nil
		}
	}
	c, err := CheckTransition(t.Context(), im, occurrenceFace(), p, TransitionLimits{})
	var r *Refusal
	if c.checked != nil || !errors.As(err, &r) || r.Premise != "transition-frontier" || r.PC != occurrenceEntry+11 {
		t.Fatal("feasible actual return was hidden", err)
	}
}
