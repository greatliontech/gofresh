package closure

import (
	"go/constant"
	"go/types"
	"testing"
)

func TestRegionActivationProjectionOwnership(t *testing.T) {
	packet, _ := proveActivation(t, `func F()(int,int){return 1,2}`)
	want := packet.outcomes[0].value
	want.elements[0].scalar = constant.MakeInt64(99)
	if got, err := packet.projectNormal(t.Context(), want); got != nil || err == nil {
		t.Fatal("changing a copied aggregate rewrote authenticated evidence")
	}
	want.elements[0].scalar = constant.MakeInt64(1)
	if _, err := packet.projectNormal(t.Context(), want); err != nil {
		t.Fatal(err)
	}

	panicking, _ := proveActivation(t, `func F(){panic([2]int{1,2})}`)
	payload := panicking.outcomes[0].panic.payload
	payload.elements[0].elements[0].scalar = constant.MakeInt64(99)
	localEffectInteger(t, panicking.snapshot.outcomes[0].panic.payload.elements[0].elements[0], 1)
}

func TestRegionActivationProjectedPredecessorIsolation(t *testing.T) {
	source := relationFixture(t, `var B bool;func F()(int,int){if B{return 1,2};return 3,4}`, 64)
	in := activationInput(source, "F")
	whole := activationWhole(t, in)
	var prior *checkedRegionActivation
	for cut := uint64(1); cut < whole.snapshot.transitions; cut++ {
		candidate, _ := activationPartition(t, in, cut)
		if len(candidate.outcomes) != 0 && len(candidate.snapshot.work) != 0 {
			prior = candidate
			break
		}
	}
	if prior == nil {
		t.Fatal("missing completed outcome beside pending sibling work")
	}
	proposal, err := proposeRegionActivationContinuation(t.Context(), prior, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() {
		prior.outcomes[0].value.elements[0].scalar = constant.MakeInt64(99)
		prior.events[0].rule = activationReturn
		prior.input.premises[0] = "changed projection"
	}}
	after, err := checkRegionActivationContinuation(ctx, prior, 0, proposal)
	if err != nil {
		t.Fatal(err)
	}
	equalActivations(t, whole, after)
	proposal, err = proposeRegionActivationContinuation(t.Context(), prior, 0)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := checkRegionActivationContinuation(t.Context(), prior, 0, proposal)
	if err != nil {
		t.Fatal(err)
	}
	after.outcomes[0].value.elements[0].scalar = constant.MakeInt64(88)
	equalActivations(t, whole, sibling)
}

func TestSourceActivationProjectedCallsAreNotAuthority(t *testing.T) {
	source := relationFixture(t, `func child()int{return 7};func F()int{return child()}`, 64)
	in := activationInput(source, "F")
	packet := activationWhole(t, in)
	packet.calls = nil
	packet.input.root = in.root.Pkg.Func("child")
	binder, err := newSelectedSourceBinder(t.Context(), source, in.root, defaultRegistrationLimits().source)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := binder.checkSourceActivation(packet)
	if err != nil {
		t.Fatal(err)
	}
	if bound.root.function != in.root || len(bound.calls) != 1 || bound.calls[0].call.target != in.root.Pkg.Func("child") {
		t.Fatal("inspection projections replaced authenticated selected dependencies")
	}
}

func TestSourceActivationSpecializationProjectionOwnership(t *testing.T) {
	if testing.Short() {
		t.Skip("actual selected generic package load")
	}
	const pkg = "example.com/activationprojection"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod": "module " + pkg + "\n\ngo 1.27\n",
		"p.go":   `package p;func child[T any](x T)T{return x};func F()int{return child[int](7)}`,
	})
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	loader := newFixturePrograms(t, h)
	loader.supply(t, pkg)
	metas, err := h.list(pkg)
	if err != nil {
		t.Fatal(err)
	}
	source := computationSource{prog: loader.loaded, metas: metas}
	in := activationInput(source, "F")
	// These small integers need only the common language range. Instantiated
	// functions have no direct SSA package for the optional numeric-layout arm;
	// selected callable ownership is checked separately by the source binder.
	in.selection = nil
	whole := activationWhole(t, in)
	var prior *sourceActivation
	for cut := uint64(1); cut < whole.snapshot.transitions; cut++ {
		proposal, err := proposeRegionActivationSegment(t.Context(), in, cut, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := checkSourceActivationSegment(t.Context(), source, in, cut, proposal, defaultRegistrationLimits().source, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		if len(candidate.calls) != 0 {
			prior = candidate
			break
		}
	}
	if prior == nil || len(prior.calls[0].bound.typeArguments) != 1 {
		t.Fatal("missing selected generic call before continuation")
	}
	target := prior.calls[0].call.target
	prior.calls[0].bound.typeArguments[0] = types.Typ[types.String]
	for range 2 {
		proposal, err := proposeRegionActivationContinuation(t.Context(), prior.packet, 0)
		if err != nil {
			t.Fatal(err)
		}
		after, err := checkSourceActivationContinuation(t.Context(), prior, 0, proposal)
		if err != nil {
			t.Fatal(err)
		}
		if len(after.calls) != 1 || !types.Identical(after.calls[0].bound.typeArguments[0], types.Typ[types.Int]) {
			t.Fatal("inspection changed a sibling's selected specialization")
		}
		after.calls[0].bound.typeArguments[0] = types.Typ[types.String]
	}
	// A generic root exposes the same kind of descriptor as a called body.
	in.root = target
	proposal, err := proposeRegionActivation(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	root, err := checkSourceActivation(t.Context(), source, in, proposal, defaultRegistrationLimits().source, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	root.root.typeArguments[0] = types.Typ[types.String]
	again, err := root.binder.bindCallable(target)
	if err != nil {
		t.Fatal(err)
	}
	if !types.Identical(again.typeArguments[0], types.Typ[types.Int]) {
		t.Fatal("root inspection changed the cached selected specialization")
	}
}
