package closure

import (
	"context"
	"fmt"
	"slices"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

// rootedGlobalInput specializes the exact input at index in correspondence.inputs.
// source is a total typed valuation of that input, not a new arbitrary variable.
type rootedGlobalInput struct {
	index          int
	native, source br.Term
}

// rootedGlobalApplication retains the original complete relation and its exact
// checked native application. The latter owns the rooted successor, geometry,
// occurrence associations and current context beside the original root history.
// Its checked geometry association maps the retained materialized storage; it
// grants no address to eliminated objects. Occurrence associations identify
// witnesses, not execution: their native guards and exclusions remain required.
// Neither owner is replaced, and the original input relation, source-model
// antecedent, scoped model discharge and open obligations all remain in force.
type rootedGlobalApplication struct {
	correspondence *globalFunctionCorrespondence
	application    nativeproof.TransitionCallCertificate
	inputs         []rootedGlobalInput
	equalities     []br.Witness
	work, limit    int
}

// checkRootedGlobalApplication establishes a total source input valuation at the
// actual ELF-rooted body entry of a completed zero-argument, void relation. Native
// applicability already owns machine, memory, lifetime, active-return and replay
// proofs; this adapter checks only the additional typed input obligation.
func checkRootedGlobalApplication(ctx context.Context, p *globalFunctionCorrespondence, application nativeproof.TransitionCallCertificate, options ...globalCorrespondenceLimits) (*rootedGlobalApplication, error) {
	fail := func(s string) (*rootedGlobalApplication, error) {
		return nil, globalFunctionError("rooted application: " + s)
	}
	if ctx == nil || p == nil || p.rules != globalFunctionRules || p.completion == nil || p.completion.owner != p || p.layout == nil || p.representation.image == nil {
		return fail("missing complete owned correspondence")
	}
	packet := p.source.checkedPacket()
	if packet == nil || packet.input.selection != p.representation.source || packet.input.root.Signature.Results().Len() != 0 || len(packet.input.root.Params) != 0 || len(p.arguments) != 0 || len(p.argumentInputs) != 0 {
		return fail("missing authenticated zero-argument void completion")
	}
	if !application.AppliesTo(p.native) {
		return fail("application does not own the exact native theorem")
	}
	if p.storageModel != nil && !p.storageModel.boundFor(p, p.source, p.native, p.layout) {
		return fail("foreign scoped storage model discharge")
	}
	limit := 2_000_000
	if len(options) > 1 {
		return fail("more than one proof budget")
	}
	if len(options) == 1 {
		limit = options[0].work
	}
	if limit < 1 || limit > 20_000_000 || len(p.inputs) > 65536 {
		return fail("invalid proof budget or input population")
	}
	// Freeze projections before context callbacks. The checked owners themselves
	// are immutable; no copy acquires their completion or applicability authority.
	inputs := slices.Clone(p.inputs)
	a, ok := application.BoundFor(p.representation.image)
	prefix, _ := p.native.Prefix()
	n, nativeOK := prefix.BoundFor(p.representation.image)
	if !ok || !nativeOK || a.ChildEntry.ConditionalRegion || a.ChildEntry.Rules != nativeproof.TransitionRules || a.ChildEntry.Boundary.PC != n.Entry {
		return fail("missing same-image rooted application at the exact body entry")
	}
	if len(a.Memory) > 65536 || len(a.Occurrences) > 65536 || len(a.Words) > 65536 {
		return fail("application projection exceeds finite bounds")
	}
	meter := &correspondenceContext{Context: ctx, limit: limit}
	ctx = meter
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for range len(inputs) + len(a.Words) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	// BoundFor captures owned projections, including the retained endpoints. Pay
	// for those new containers without importing either owner's prior proof work.
	for _, bound := range []nativeproof.TransitionBound{a.ChildEntry, a.Successor, n} {
		if err := chargeStorageGeometry(ctx, bound.Geometry); err != nil {
			return nil, err
		}
		for _, count := range []int{len(bound.InitialMemory), len(bound.Memory), len(bound.Words), len(bound.Instructions), len(bound.Accesses), len(bound.PrimitiveEffects), len(bound.Abstractions), len(bound.Frames), len(bound.Expansions), len(bound.ExcludedBoundaries), len(bound.ExcludedOrigins), len(bound.Interface.Regions), len(bound.Interface.ImageRegions), len(bound.Interface.Words), len(bound.Interface.EntryImagePointers), len(bound.Interface.EntryWordUpperBounds)} {
			if count > 65536 {
				return fail("endpoint projection exceeds finite bounds")
			}
			for range count {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
		}
	}
	r := &rootedGlobalApplication{correspondence: p, application: application, limit: limit}
	// This is only an independent equality account, with no completion token or
	// copied correspondence. Never add the desired Boolean encoding to its domain.
	proof := globalFunctionCorrespondence{antecedent: a.ChildEntry.EntryPredicate}
	bytes := make(map[br.Term]br.Term, len(a.Memory))
	for _, association := range a.Memory {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		input := association.Input.Value
		if input.View().Op != br.Variable {
			continue
		}
		if previous, exists := bytes[input]; exists && previous != association.Current.Value {
			return fail("ambiguous checked input-byte association")
		}
		bytes[input] = association.Current.Value
	}
	// Charge the captured association population, not the native work already
	// retained and charged by the application. There is no second effect matcher.
	for range a.Occurrences {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	builder := br.NewBuilder(65536)
	for index, input := range inputs {
		word, err := rootedGlobalWord(ctx, builder, input.native, bytes)
		if err != nil {
			return nil, fmt.Errorf("rooted global input %d: %w", index, err)
		}
		value := word
		if input.source.Sort() == br.Bool() {
			value, err = builder.Make(br.Nonzero, br.Bool(), 0, word)
			if err != nil {
				return nil, err
			}
			encoded, err := builder.Make(br.BoolToBits, input.native.Sort(), 0, value)
			if err != nil {
				return nil, err
			}
			if err := proof.equal(ctx, encoded, word); err != nil {
				return nil, fmt.Errorf("rooted global input %d Boolean encoding: %w", index, err)
			}
		} else if input.source.Sort() != word.Sort() {
			return fail("original typed input width differs from actual word")
		}
		r.inputs = append(r.inputs, rootedGlobalInput{index: index, native: word, source: value})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.equalities, r.work = proof.equalities, meter.work
	return r, nil
}

// rootedGlobalWord accepts only storageNativeWord's original byte-variable and
// little-endian concatenation grammar. Current bytes stay opaque expressions:
// this is input substitution, never an evaluator for the native computation.
func rootedGlobalWord(ctx context.Context, builder *br.Builder, original br.Term, bytes map[br.Term]br.Term) (br.Term, error) {
	if err := ctx.Err(); err != nil {
		return br.Term{}, err
	}
	width := original.Sort().Width()
	view := original.View()
	if width == 8 && view.Op == br.Variable {
		current, ok := bytes[original]
		if !ok || current.Sort() != br.Bits(8) {
			return br.Term{}, globalFunctionError("missing checked original byte association")
		}
		return current, nil
	}
	if width < 16 || width > 64 || width%8 != 0 || view.Op != br.Concat || len(view.Args) != 2 || view.Args[0].Sort() != br.Bits(width-8) || view.Args[1].Sort() != br.Bits(8) {
		return br.Term{}, globalFunctionError("unsupported original native input-word grammar")
	}
	low, err := rootedGlobalWord(ctx, builder, view.Args[0], bytes)
	if err != nil {
		return br.Term{}, err
	}
	high, err := rootedGlobalWord(ctx, builder, view.Args[1], bytes)
	if err != nil {
		return br.Term{}, err
	}
	return builder.Make(br.Concat, original.Sort(), 0, low, high)
}
