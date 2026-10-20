package closure

import (
	"context"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

const scopedStorageModelRules = "gofresh/scoped-storage-model@1;" + globalFunctionRules

// globalFunctionCompletion is issued only at the complete account's successful
// effects/final-state exit, after any supplied actual-call constraints. The owner
// is essential: a copied account, a phase projection or a search attempt cannot
// inherit completion by copying its fields.
type globalFunctionCompletion struct{ owner *globalFunctionCorrespondence }

// scopedStorageModelDischarge establishes the model-dependent consequences of
// this complete void computation under its original input relation and native
// entry conditions. It is neither a physical encoding theorem nor applicability
// of the source model outside this scope. The source antecedent remains intact.
//
// scope retains the whole checked effect account, layout, actual-call association
// and opaque native return theorem. The latter owns all actual instruction operand
// and status proofs; source occurrence counts are not native-operation obligations.
// dependent conservatively retains the entire executed computation, including
// dependent control, calls and effects, rather than granting a source-only value
// claim for the smaller modelOccurrences inventory.
type scopedStorageModelDischarge struct {
	self             *scopedStorageModelDischarge
	completion       *globalFunctionCompletion
	scope            globalFunctionCorrespondence
	rules            string
	model            regionStorageModel
	modelOccurrences []regionEffectOccurrence
	dependent        []regionEffectOccurrence
}

// boundFor requires the exact completed correspondence and all of its endpoint
// owners. In particular equal bytes, the same static function in another call,
// and an equal-coordinate replacement layout confer no borrowing authority.
func (d *scopedStorageModelDischarge) boundFor(p *globalFunctionCorrespondence, source *sourceReturnCompletion, native nativeproof.TransitionReturnCertificate, layout *storageLayout) bool {
	if d == nil || d.self != d || p == nil || d.completion == nil || d.completion.owner != p || p.completion != d.completion || d.rules != scopedStorageModelRules {
		return false
	}
	s := &d.scope
	return source == s.source && source == p.source && source.checkedPacket() != nil &&
		native == s.native && native == p.native && layout == s.layout && layout == p.layout &&
		p.rules == s.rules && p.call == s.call && p.antecedent == s.antecedent && p.paired == s.paired &&
		p.representation.source == s.representation.source && p.representation.image == s.representation.image &&
		slices.Equal(p.representation.bindings, s.representation.bindings) &&
		source.region.packet.input.storageModel == d.model
}

// checkScopedStorageModel consumes complete correspondence, not proposed byte
// matches. The completion capability must be installed by the complete checker
// only after its final checks succeed. No prefix or retry installs that capability.
// A supported model marker with no executed model use yields no discharge.
func checkScopedStorageModel(ctx context.Context, p *globalFunctionCorrespondence) (*scopedStorageModelDischarge, error) {
	fail := func(s string) (*scopedStorageModelDischarge, error) {
		return nil, globalFunctionError("scoped storage model: " + s)
	}
	if ctx == nil || p == nil || p.completion == nil || p.completion.owner != p || p.rules != globalFunctionRules || p.layout == nil {
		return fail("missing complete owned correspondence")
	}
	// A direct internal re-derivation inherits the already consumed allowance;
	// the normal construction hook receives the complete checker's running meter.
	if meter, ok := ctx.(*correspondenceContext); ok {
		if meter == nil || meter.Context == nil || meter.limit < 1 || meter.limit > 20_000_000 || meter.limit > p.limit || meter.work < p.work || meter.work < 0 || meter.work > meter.limit {
			return fail("invalid cumulative proof account")
		}
	} else {
		if p.limit < 1 || p.limit > 20_000_000 || p.work < 0 || p.work > p.limit {
			return fail("invalid cumulative proof account")
		}
		meter := &correspondenceContext{Context: ctx, work: p.work, limit: p.limit}
		ctx = meter
		defer func() { p.work = meter.work }()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	packet := p.source.checkedPacket()
	if packet == nil || packet.input.selection != p.representation.source || packet.input.root.Signature.Results().Len() != 0 || len(p.source.returned.Results) != 0 {
		return fail("missing authenticated selected void completion")
	}
	if packet.input.storageModel != conditionalRegionStorageModel() || !packet.input.storageModel.valid(packet.input) {
		return fail("unsupported or missing source storage model")
	}
	bound, ok := p.native.BoundFor(p.representation.image)
	if !ok || !bound.State.CalleeTerminated || bound.Prefix.Rules != nativeproof.TransitionRules || bound.Prefix.Interface.ReturnContext == nil || bound.State.PC != bound.Prefix.Interface.ReturnContext.Target || bound.State.Thread.ContextChanged {
		return fail("missing owned complete native return")
	}
	// The sealed native theorem has checked actual scalar loads, UCOMIS operand
	// exclusions and current flags under their actual reach guards. Its SSE model
	// requires neither default MXCSR nor chosen exception masks. A computation
	// without actual SSE needs no invented SSE premise or physical float object.
	if bound.Prefix.Interface.Conditions.SSE != "" && (bound.Prefix.Interface.Conditions.SSE != nativeproof.SSEModel || !bound.State.SSE.MXCSRPreserved || !bound.State.SSE.UpperVectorsPreserved) {
		return fail("missing preserved floating context")
	}
	d := &scopedStorageModelDischarge{completion: p.completion, scope: *p, rules: scopedStorageModelRules, model: packet.input.storageModel}
	seen := map[regionEffectOccurrence]bool{}
	for _, trace := range p.traces {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if trace == nil || trace.owner == nil || len(trace.instructions) > 65536-len(d.dependent) {
			return fail("missing or oversized executed source scope")
		}
		for _, occurrence := range trace.instructions {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if occurrence.owner != trace.owner || occurrence.instruction == nil || !trace.seen[occurrence] || seen[occurrence] {
				return fail("unestablished or repeated source occurrence")
			}
			seen[occurrence] = true
			d.dependent = append(d.dependent, occurrence)
			uses, err := storageModelInstruction(ctx, occurrence.instruction)
			if err != nil {
				return nil, err
			}
			if uses {
				d.modelOccurrences = append(d.modelOccurrences, occurrence)
			}
		}
		for _, call := range trace.calls {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if call.proof == nil || call.proof.selection != packet.input.selection || call.proof.storageModel != d.model {
				return fail("call lost selected model antecedent")
			}
		}
	}
	if !seen[p.source.occurrence] {
		return fail("dependent scope omits the executed source return")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(d.modelOccurrences) == 0 {
		return nil, nil
	}
	// Freeze the candidate binding inventory; object and layout authority still
	// comes only from the complete matcher's retained fixed layout and effects.
	d.scope.representation.bindings = slices.Clone(p.representation.bindings)
	d.self = d
	return d, nil
}

// storageModelInstruction identifies executed typed uses, including constants,
// initialized float-containing objects and live pointer views. This inventory is
// descriptive: the proof of every consequence is the complete correspondence,
// not recognition of an opcode or equality of source/native event counts.
func storageModelInstruction(ctx context.Context, instruction ssa.Instruction) (bool, error) {
	seen := map[types.Type]bool{}
	var contains func(types.Type) (bool, error)
	contains = func(typ types.Type) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if typ == nil || seen[typ] {
			return false, nil
		}
		seen[typ] = true
		if regionFloatWidth(typ) != 0 {
			return true, nil
		}
		switch typ := typ.Underlying().(type) {
		case *types.Array:
			return contains(typ.Elem())
		case *types.Struct:
			for i := range typ.NumFields() {
				if yes, err := contains(typ.Field(i).Type()); yes || err != nil {
					return yes, err
				}
			}
		case *types.Tuple:
			for i := range typ.Len() {
				if yes, err := contains(typ.At(i).Type()); yes || err != nil {
					return yes, err
				}
			}
		}
		return false, nil
	}
	// Merely passing an unused float pointer interprets no floating bits. Only
	// allocation initialization and executed live views inspect a pointed-to
	// type here; ordinary loads/stores expose their actual scalar value types.
	inspect := func(typ types.Type) (bool, error) {
		switch instruction.(type) {
		case *ssa.Alloc, *ssa.Convert, *ssa.ChangeType:
			if pointer, ok := typ.Underlying().(*types.Pointer); ok {
				typ = pointer.Elem()
			}
		}
		return contains(typ)
	}
	if value, ok := instruction.(ssa.Value); ok {
		if yes, err := inspect(value.Type()); yes || err != nil {
			return yes, err
		}
	}
	for _, operand := range instruction.Operands(nil) {
		if operand != nil && *operand != nil {
			if yes, err := inspect((*operand).Type()); yes || err != nil {
				return yes, err
			}
		}
	}
	return false, nil
}
