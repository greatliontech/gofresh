package closure

import (
	"context"
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"maps"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

const globalFunctionRules = "gofresh/global-function-correspondence@7;" + regionRules + ";" + nativeproof.TransitionRules + ";" + br.RuleModel

// A mapping names the actual typed parameter and its incoming full native word.
// The present effect-only grammar admits only unused pointer parameters. A word
// mapping gives neither dereference permission nor an alias exclusion.
type globalFunctionArgument struct {
	parameter *ssa.Parameter
	register  nativeproof.Register
}

type globalFunctionInput struct {
	location       regionLocation
	source, native br.Term
}

type globalFunctionAtomic struct {
	source regionAtomicOccurrence
	native nativeproof.PrimitiveEffect
}

type globalFunctionAccess struct{ source, native int }

type storagePaddingAccess struct {
	native   int
	location nativeproof.TransitionLocation
	value    br.Term
}

// globalFunctionCorrespondence retains BOTH complete computations. In particular
// its native theorem starts at the supplied callee entry, never at the operand
// prefix's post-prologue cut. Initial pairs describe arbitrary prior typed words;
// the administrative antecedent is checked independent of all those words.
// Source phases retain exact call, invocation and assembly-statement origins.
// Administrative access indices are a projection account, not erased state.
// The returned native theorem keeps concrete residual scratch bytes for later use.
type globalFunctionCorrespondence struct {
	rules                string
	source               *sourceReturnCompletion
	native               nativeproof.TransitionReturnCertificate
	call                 *globalCallComposition
	completion           *globalFunctionCompletion
	storageModel         *scopedStorageModelDischarge
	representation       storageRepresentation
	layout               *storageLayout
	arguments            []globalFunctionArgument
	inputs               []globalFunctionInput
	argumentInputs       []br.Term
	antecedent           br.Term
	paired               br.Term
	accesses             []regionEffectAccess
	traces               []*regionEffectTrace
	atomics              []globalFunctionAtomic
	matched              []globalFunctionAccess
	administrative       []int
	inactive             []int
	inactivePrimitives   []int
	inactiveAbstractions []int
	eliminated           []int
	materialized         []int
	padding              []storagePaddingAccess
	equalities           []br.Witness
	constants            map[globalFunctionConstant]error
	open                 computationCorrespondenceObligations
	work, limit          int
}

// checkGlobalFunctionCorrespondence checks a void, effect-and-return relation.
// Scalar results of internal calls need not match register-by-register: their
// actual source/native uses are included in the complete checked effects and
// exceptional paths. No expected output or expected atomic inventory is input.
func checkGlobalFunctionCorrespondence(ctx context.Context, source computationSource, root *ssa.Function, image *nativeproof.Image, entry uint64, completed *sourceReturnCompletion, native nativeproof.TransitionReturnCertificate, rho storageRepresentation, arguments []globalFunctionArgument, options ...globalCorrespondenceLimits) (*globalFunctionCorrespondence, error) {
	fail := func(s string) (*globalFunctionCorrespondence, error) { return nil, globalFunctionError(s) }
	if ctx == nil || source.prog == nil || root == nil || image == nil || rho.image == nil || rho.source != source.prog || completed == nil || completed.region == nil || completed.region.packet == nil || completed.prior == nil || completed.returned == nil {
		return fail("missing owned source completion, image or representation")
	}
	if len(rho.bindings) > storageMaxBindings {
		return fail("storage binding budget exceeded")
	}
	limit := 2_000_000
	if len(options) > 1 {
		return fail("more than one proof budget")
	}
	if len(options) == 1 {
		limit = options[0].work
	}
	if limit < 1 || limit > 20_000_000 || len(arguments) > 15 {
		return fail("invalid cumulative proof budget or argument inventory")
	}
	ownedImage, representedImage := *image, *rho.image
	rho.image = &representedImage
	rho.bindings = slices.Clone(rho.bindings)
	arguments = slices.Clone(arguments)
	meter := &correspondenceContext{Context: ctx, limit: limit}
	return checkGlobalFunctionAccount(meter, source, root, &ownedImage, entry, completed, native, rho, arguments, nil)
}

// The complete-return consumers share one account. Actual-call construction passes
// its already-running meter and owned association, so continuation and alignment
// retries cannot each acquire a fresh allowance.
func checkGlobalFunctionAccount(meter *correspondenceContext, source computationSource, root *ssa.Function, image *nativeproof.Image, entry uint64, completed *sourceReturnCompletion, native nativeproof.TransitionReturnCertificate, rho storageRepresentation, arguments []globalFunctionArgument, call *globalCallComposition) (*globalFunctionCorrespondence, error) {
	ctx := context.Context(meter)
	fail := func(s string) (*globalFunctionCorrespondence, error) { return nil, globalFunctionError(s) }
	b, ok := native.BoundFor(image)
	if _, represented := native.BoundFor(rho.image); !ok || !represented || !b.Prefix.ConditionalRegion || b.Prefix.Rules != nativeproof.TransitionRules || b.Prefix.Entry != entry || b.Prefix.Interface.ReturnContext == nil || !b.State.CalleeTerminated || b.State.PC != b.Prefix.Interface.ReturnContext.Target || b.Continuation.PC != b.State.PC || len(b.Prefix.Frames) != 0 || b.State.Thread.ContextChanged {
		return fail("missing actual-entry complete native return under the same image")
	}
	if len(b.Accesses) > 65536 || len(b.Instructions) > 65536 || len(b.State.Memory) > 65536 || len(b.Prefix.InitialMemory) > 65536 {
		return fail("complete projection exceeds finite correspondence bounds")
	}
	p := &globalFunctionCorrespondence{rules: globalFunctionRules, source: completed, native: native, call: call, representation: rho, arguments: arguments, antecedent: b.Prefix.EntryPredicate,
		open: computationCorrespondenceObligations{true, true, true, true, true}, limit: meter.limit}
	view := b.Prefix
	view.Instructions, view.Accesses, view.Memory = b.Instructions, b.Accesses, b.State.Memory
	var err error
	p.layout, err = checkStorageAuthority(ctx, completed, view, rho, storageProtectedFootprints(view))
	if err != nil {
		return nil, err
	}
	p.representation = p.layout.representation
	if err := p.collectSource(ctx, source, root); err != nil {
		return nil, err
	}
	if call != nil {
		if err := p.bindActualCall(ctx, source, root, view); err != nil {
			return nil, err
		}
	}
	builder := br.NewBuilder(65536)
	if err := p.checkInputs(ctx, builder, source, root, b.Prefix); err != nil {
		return nil, err
	}
	if err := p.checkEffects(ctx, view); err != nil {
		return nil, fmt.Errorf("complete effects: %w", err)
	}
	if err := p.checkFinal(ctx, builder, b); err != nil {
		return nil, fmt.Errorf("returned state: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Only this full-return exit issues completion authority. Prefix accounts and
	// failed alignment candidates cannot acquire it by copying projections.
	p.completion = &globalFunctionCompletion{owner: p}
	p.storageModel, err = checkScopedStorageModel(ctx, p)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.work = meter.work
	return p, nil
}

func globalFunctionError(s string) error { return fmt.Errorf("global function correspondence: %s", s) }

// Each opaque continuation was checked from precisely its prior current state.
// Collecting oldest first preserves phase order without borrowing native premises
// from any older region correspondence that may have supplied these source phases.
func (p *globalFunctionCorrespondence) collectSource(ctx context.Context, source computationSource, root *ssa.Function) error {
	packet := p.source.region.packet
	if root.Signature.Results().Len() != 0 || len(root.FreeVars) != 0 || packet.rules != regionRules || packet.input.owner != source.prog.Prog || packet.input.root != root || p.source.region.root.function != root || p.source.returned.Parent() != root || len(p.source.returned.Results) != 0 || packet.trace == nil || len(packet.observations) != 1 {
		return globalFunctionError("source is not the selected void root's checked return")
	}
	var chain []*sourceEffectPrefix
	seen := map[*sourceEffectPrefix]bool{}
	for at := p.source.prior; at != nil; at = at.prior {
		if err := ctx.Err(); err != nil {
			return err
		}
		if seen[at] || len(chain) >= 256 || at.checkedPacket() == nil || at.region.packet.input.root != root || at.region.packet.input.owner != source.prog.Prog {
			return globalFunctionError("source continuation chain has a foreign owner or repeated phase")
		}
		seen[at] = true
		chain = append(chain, at)
	}
	slices.Reverse(chain)
	first := chain[0].region.packet
	if first.trace == nil || first.input.entry != (regionPoint{root.Blocks[0], 0}) || len(first.input.initial.memory) != 0 || len(first.input.initial.values) != 0 {
		return globalFunctionError("source does not start at the arbitrary-state root prefix")
	}
	p.traces = append(p.traces, first.trace)
	for _, phase := range chain[1:] {
		if phase.region.packet.trace == nil {
			return globalFunctionError("missing source continuation trace")
		}
		p.traces = append(p.traces, phase.region.packet.trace)
	}
	p.traces = append(p.traces, packet.trace)
	for _, trace := range p.traces {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(trace.accesses) > 65536-len(p.accesses) {
			return globalFunctionError("source effect population exceeds bound")
		}
		p.accesses = append(p.accesses, trace.accesses...)
	}
	return nil
}

// Check the actual closed entry vocabulary, plus syntactic variable separation.
// Every represented byte is a distinct arbitrary input, and no administrative
// predicate mentions it. Consequently each arbitrary source valuation has the
// same nonempty native administrative domain established by the native checker.
func (p *globalFunctionCorrespondence) checkInputs(ctx context.Context, builder *br.Builder, source computationSource, root *ssa.Function, b nativeproof.TransitionBound) error {
	if err := p.checkStorageInputs(ctx, builder, b); err != nil {
		return err
	}
	scope := br.NewScope()
	variables := map[br.Term]bool{}
	if len(p.arguments) != len(root.Params) {
		return globalFunctionError("typed argument mapping is incomplete")
	}
	registers := map[nativeproof.Register]bool{}
	for i, argument := range p.arguments {
		if err := ctx.Err(); err != nil {
			return err
		}
		if argument.parameter != root.Params[i] || argument.register > nativeproof.R15 || argument.register == nativeproof.RSP || registers[argument.register] {
			return globalFunctionError("argument mapping is foreign, aliased or not a full incoming word")
		}
		if p.source.region.root.pkg.TypesSizes.Sizeof(argument.parameter.Type()) != 8 {
			return globalFunctionError("effect-only argument is not a selected pointer word")
		}
		if err := checkUnusedSourcePointer(root, argument.parameter, ctx.Err); err != nil {
			return err
		}
		registers[argument.register] = true
		variables[b.InitialRegisters[argument.register]] = true
		input, err := builder.Input(br.Bits(64), scope, uint64(i))
		if err != nil {
			return err
		}
		p.argumentInputs = append(p.argumentInputs, input)
		if err := p.pair(builder, input, b.InitialRegisters[argument.register]); err != nil {
			return err
		}
	}
	return globalFunctionIndependent(ctx, p.antecedent, variables)
}

func (p *globalFunctionCorrespondence) checkStorageInputs(ctx context.Context, builder *br.Builder, b nativeproof.TransitionBound) error {
	p.paired = p.antecedent
	scope := br.NewScope()
	variables := map[br.Term]bool{}
	for _, binding := range p.representation.bindings {
		if err := ctx.Err(); err != nil {
			return err
		}
		if binding.object.kind != regionGlobal {
			continue
		}
		footprint, _ := p.layout.objectFootprint(binding.object)
		for _, bound := range b.Interface.EntryWordUpperBounds {
			if footprint.overlaps(storageFootprint{Image: true, Bytes: nativeproof.RelativeSpan{Start: int64(bound.Address), End: int64(bound.Address + 8)}}) {
				return globalFunctionError("administrative entry predicate constrains represented source storage")
			}
		}
		for offset := footprint.Bytes.Start; offset < footprint.Bytes.End; offset++ {
			var found bool
			for _, cell := range b.InitialMemory {
				if err := ctx.Err(); err != nil {
					return err
				}
				if !cell.Image || cell.Offset != offset {
					continue
				}
				if found || cell.Pointer != nil || cell.Value.Sort() != br.Bits(8) || cell.Value.View().Op != br.Variable || variables[cell.Value] {
					return globalFunctionError("represented initial bytes are not independent arbitrary inputs")
				}
				found, variables[cell.Value] = true, true
			}
			if !found {
				return globalFunctionError("missing represented initial byte")
			}
		}
		leaves, err := p.layout.typedLeaves(ctx, binding.object)
		if err != nil {
			return err
		}
		for _, leaf := range leaves {
			basic, ok := leaf.typ.Underlying().(*types.Basic)
			if !ok || basic.Info()&(types.IsBoolean|types.IsInteger) == 0 {
				return globalFunctionError("unsupported typed global input")
			}
			width := int(leaf.footprint.Bytes.End - leaf.footprint.Bytes.Start)
			initial, err := storageNativeWord(ctx, builder, b.InitialMemory, nativeproof.TransitionLocation{Image: true, Offset: leaf.footprint.Bytes.Start}, width)
			if err != nil {
				return err
			}
			sort := br.Bits(width * 8)
			if basic.Info()&types.IsBoolean != 0 {
				sort = br.Bool()
			}
			input, err := builder.Input(sort, scope, uint64(len(p.inputs)))
			if err != nil {
				return err
			}
			p.inputs = append(p.inputs, globalFunctionInput{leaf.location, input, initial})
			storage := input
			if sort == br.Bool() {
				storage, err = builder.Make(br.BoolToBits, br.Bits(width*8), 0, input)
				if err != nil {
					return err
				}
			}
			if err := p.pair(builder, storage, initial); err != nil {
				return err
			}
		}
	}
	return globalFunctionIndependent(ctx, p.antecedent, variables)
}

func (p *globalFunctionCorrespondence) pair(b *br.Builder, source, native br.Term) error {
	equality, err := b.Make(br.Equal, br.Bool(), 0, source, native)
	if err != nil {
		return err
	}
	p.paired, err = b.Make(br.And, br.Bool(), 0, p.paired, equality)
	return err
}

func globalFunctionIndependent(ctx context.Context, term br.Term, forbidden map[br.Term]bool) error {
	return globalFunctionIndependentWhen(ctx, term, forbidden, nil)
}

// A returned scalar may retain a joined expression whose untaken branch or
// selector mentions the stack origin. A checked guard implication permits
// inspecting just its selected arm; absent that proof, every operand remains
// required. Entry-domain separation calls this with no conditional discharge,
// since using the entry predicate to justify its own independence is circular.
func globalFunctionIndependentWhen(ctx context.Context, term br.Term, forbidden map[br.Term]bool, prove func(br.Term, uint64) error) error {
	seen := map[br.Term]bool{}
	var visit func(br.Term) error
	visit = func(t br.Term) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if forbidden[t] {
			return globalFunctionError("administrative or escaping value depends on a protected input")
		}
		if seen[t] {
			return nil
		}
		seen[t] = true
		view := t.View()
		if prove != nil && view.Op == br.ITE {
			for _, value := range []uint64{1, 0} {
				if err := prove(view.Args[0], value); err == nil {
					return visit(view.Args[2-int(value)])
				} else if !globalFunctionUnproved(err) {
					return err
				}
			}
		}
		for _, arg := range view.Args {
			if err := visit(arg); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(term)
}

// Implication is itself checked by bitrelation. In particular an instruction's
// guard is never reset to true merely because it occurs in a native inventory.
func (p *globalFunctionCorrespondence) equal(ctx context.Context, a, b br.Term) error {
	builder := br.NewBuilder(8)
	equal, err := builder.Make(br.Equal, br.Bool(), 0, a, b)
	if err != nil {
		return err
	}
	unequal, err := builder.Make(br.Not, br.Bool(), 0, equal)
	if err != nil {
		return err
	}
	violation, err := builder.Make(br.And, br.Bool(), 0, p.antecedent, unequal)
	if err != nil {
		return err
	}
	falsity, err := builder.Const(br.Bool(), 0)
	if err != nil {
		return err
	}
	witness, err := br.Prove(ctx, violation, falsity, br.Limits{})
	if err == nil {
		p.equalities = append(p.equalities, witness)
	}
	return err
}

// Exact immutable term handles retain variable scopes as well as expression
// identity. The antecedent is part of the query: a proof under one entry domain
// cannot authorize the same expression under a different domain.
type globalFunctionConstant struct {
	antecedent, actual br.Term
	value              uint64
}

func (p *globalFunctionCorrespondence) constant(ctx context.Context, actual br.Term, value uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := globalFunctionConstant{p.antecedent, actual, value}
	if result, found := p.constants[key]; found {
		return result
	}
	err := p.constantUncached(ctx, actual, value)
	if stopped := ctx.Err(); stopped != nil {
		return stopped
	}
	if err == nil || globalFunctionUnproved(err) {
		// Success retains its checked witnesses in this account. Unsupported is
		// only a remembered search refusal, never a proof of the opposite value.
		// Failed, cancelled and budget-exhausted work cannot become authority.
		if p.constants == nil {
			p.constants = make(map[globalFunctionConstant]error)
		}
		p.constants[key] = err
	}
	return err
}

func (p *globalFunctionCorrespondence) constantUncached(ctx context.Context, actual br.Term, value uint64) error {
	direct := p.constantDirect(ctx, actual, value)
	if direct == nil || !globalFunctionUnproved(direct) {
		return direct
	}
	view := actual.View()
	if actual.Sort() == br.Bool() && value <= 1 && view.Op == br.Not {
		return p.constant(ctx, view.Args[0], 1-value)
	}
	if actual.Sort() == br.Bool() && (value == 1 && view.Op == br.And || value == 0 && view.Op == br.Or) {
		// A => (B && C) precisely when both implications hold. This checked
		// structural decomposition exposes conjunction leaves to bitrelation's
		// independently checked contradiction rule without assuming any leaf.
		for _, conjunct := range view.Args {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := p.constant(ctx, conjunct, value); err != nil {
				return err
			}
		}
		return nil
	}
	if actual.Sort() == br.Bool() && (value == 1 && view.Op == br.Or || value == 0 && view.Op == br.And) {
		// One independently proved sufficient arm is enough; failed search is
		// never an assumption and resource/cancellation failures remain fatal.
		for _, arm := range view.Args {
			if err := p.constant(ctx, arm, value); err == nil {
				return nil
			} else if !globalFunctionUnproved(err) {
				return err
			}
		}
	}
	return direct
}

func (p *globalFunctionCorrespondence) constantDirect(ctx context.Context, actual br.Term, value uint64) error {
	b := br.NewBuilder(8)
	if actual.Sort() == br.Bool() && value <= 1 {
		bad := actual
		var err error
		if value == 1 {
			bad, err = b.Make(br.Not, br.Bool(), 0, bad)
		}
		if err != nil {
			return err
		}
		violation, err := b.Make(br.And, br.Bool(), 0, p.antecedent, bad)
		if err != nil {
			return err
		}
		zero, err := b.Const(br.Bool(), 0)
		if err != nil {
			return err
		}
		w, err := br.Prove(ctx, violation, zero, br.Limits{})
		if err == nil {
			p.equalities = append(p.equalities, w)
		}
		return err
	}
	want, err := b.Const(actual.Sort(), value)
	if err != nil {
		return err
	}
	return p.equal(ctx, actual, want)
}

func globalFunctionUnproved(err error) bool {
	var refusal *br.Refusal
	return errors.As(err, &refusal) && refusal.Code == br.Unsupported
}

type globalFunctionNativeAtomic struct {
	kind        x86asm.Op
	width       int
	id          nativeproof.TransitionOccurrenceID
	read, write int
	effect      nativeproof.PrimitiveEffect
}

func globalFunctionNativeGroup(effect nativeproof.PrimitiveEffect) (globalFunctionNativeAtomic, bool) {
	switch e := effect.(type) {
	case nativeproof.LockedCompareExchangeEffect:
		return globalFunctionNativeAtomic{x86asm.CMPXCHG, e.Width, e.ID, e.ReadAccess, e.WriteAccess, effect}, e.Width == 4 || e.Width == 8
	case nativeproof.LockedExchange64Effect:
		return globalFunctionNativeAtomic{x86asm.XCHG, 8, e.ID, e.ReadAccess, e.WriteAccess, effect}, true
	case nativeproof.LockedExchangeAdd64Effect:
		return globalFunctionNativeAtomic{x86asm.XADD, 8, e.ID, e.ReadAccess, e.WriteAccess, effect}, true
	case nativeproof.LockedLogicalEffect:
		return globalFunctionNativeAtomic{e.Kind, e.Width, e.ID, e.ReadAccess, e.WriteAccess, effect}, e.Width == 1 && (e.Kind == x86asm.AND || e.Kind == x86asm.OR)
	}
	return globalFunctionNativeAtomic{}, false
}

func (p *globalFunctionCorrespondence) checkEffects(ctx context.Context, b nativeproof.TransitionBound) error {
	guards := map[nativeproof.TransitionOccurrenceID]br.Term{}
	for _, ins := range b.Instructions {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, found := guards[ins.ID]; found || ins.ID == 0 {
			return globalFunctionError("ambiguous native dynamic occurrence")
		}
		guards[ins.ID] = ins.Guard
	}
	nativeGroups := map[int]globalFunctionNativeAtomic{}
	for primitiveIndex, effect := range b.PrimitiveEffects {
		if err := ctx.Err(); err != nil {
			return err
		}
		group, ok := globalFunctionNativeGroup(effect)
		if !ok {
			var at nativeproof.TransitionOccurrenceID
			switch e := effect.(type) {
			case nativeproof.CPUIDEffect:
				at = e.ID
			case nativeproof.ArchSetFSEffect:
				at = e.ID
			default:
				return globalFunctionError("unknown primitive cannot be projected away")
			}
			guard, found := guards[at]
			if !found {
				return globalFunctionError("primitive has no actual instruction guard")
			}
			if err := p.constant(ctx, guard, 0); err != nil {
				return fmt.Errorf("unmatched primitive is not proved inactive: %w", err)
			}
			p.inactivePrimitives = append(p.inactivePrimitives, primitiveIndex)
			continue
		}
		if group.read < 0 || group.write != group.read+1 || group.write >= len(b.Accesses) {
			return globalFunctionError("atomic has incomplete access grouping")
		}
		for _, index := range []int{group.read, group.write} {
			access := b.Accesses[index]
			if _, found := nativeGroups[index]; found || access.ID != group.id {
				return globalFunctionError("atomic accesses have another statement or activation")
			}
			if access.Bytes.End-access.Bytes.Start != int64(group.width) {
				return globalFunctionError("atomic access width differs from its primitive")
			}
			nativeGroups[index] = group
		}
		guard, found := guards[group.id]
		if !found {
			return globalFunctionError("atomic has no actual instruction guard")
		}
		if err := p.constant(ctx, guard, 0); err == nil {
			p.inactivePrimitives = append(p.inactivePrimitives, primitiveIndex)
		} else if !globalFunctionUnproved(err) {
			return err
		}
	}
	for index, abstraction := range b.Abstractions {
		guard, found := guards[abstraction.ID]
		if !found {
			return globalFunctionError("abstraction has no actual instruction guard")
		}
		if err := p.constant(ctx, guard, 0); err != nil {
			return fmt.Errorf("active native abstraction has no source relation: %w", err)
		}
		p.inactiveAbstractions = append(p.inactiveAbstractions, index)
	}
	// Record exact source assembly grouping before any ordinary read elimination.
	sourceGroups := map[int]regionAtomicOccurrence{}
	base := len(p.accesses)
	for _, trace := range p.traces {
		base -= len(trace.accesses)
	}
	for _, trace := range p.traces {
		for _, group := range trace.atomics {
			if err := ctx.Err(); err != nil {
				return err
			}
			a := group.atomic
			if group.application == nil || group.application.reference == nil || a.Statement < 0 || a.ReadAccess < 0 || a.WriteAccess != a.ReadAccess+1 || a.WriteAccess >= len(trace.accesses) {
				return globalFunctionError("source atomic lacks complete statement provenance")
			}
			found := false
			for _, call := range trace.calls {
				found = found || call.proof == group.application
			}
			read, write := trace.accesses[a.ReadAccess], trace.accesses[a.WriteAccess]
			if !found || read.regionEffectOccurrence != group.application.caller || write.regionEffectOccurrence != read.regionEffectOccurrence || read.instruction != group.application.at || read.location.object != write.location.object || !slices.Equal(read.location.path, write.location.path) || read.write || !write.write || !read.locked || !write.locked {
				return globalFunctionError("source atomic grouping lost actual call/context/read-write provenance")
			}
			footprint, represented := p.layout.locationFootprint(read.location)
			if !represented || a.Width <= 0 || footprint.Bytes.End-footprint.Bytes.Start != int64(a.Width) {
				return globalFunctionError("source atomic width differs from its represented typed location")
			}
			for _, index := range []int{base + a.ReadAccess, base + a.WriteAccess} {
				if _, found := sourceGroups[index]; found {
					return globalFunctionError("source atomic groups overlap")
				}
				sourceGroups[index] = group
			}
		}
		base += len(trace.accesses)
	}
	// Filter only proved-inactive effects and independently justified administrative
	// memory. Even a private locked RMW is not an administrative ordinary access.
	var observable []int
	for index, access := range b.Accesses {
		if err := ctx.Err(); err != nil {
			return err
		}
		guard, found := guards[access.ID]
		if !found {
			return globalFunctionError("access has no instruction occurrence")
		}
		if err := p.constant(ctx, guard, 0); err == nil {
			p.inactive = append(p.inactive, index)
			continue
		} else if !globalFunctionUnproved(err) {
			return err
		}
		_, atomic := nativeGroups[index]
		if !atomic && p.administrativeAccess(b, access) {
			p.administrative = append(p.administrative, index)
			continue
		}
		// Every source effect in this finite trace actually executes. Matching an
		// unknown conditional native effect would invent a missing source path.
		if err := p.constant(ctx, guard, 1); err != nil {
			return fmt.Errorf("native access %d at %#x is not proved to execute: %w", index, access.PC, err)
		}
		observable = append(observable, index)
	}
	return p.matchStorageEffects(ctx, b.Accesses, b.InitialMemory, observable, sourceGroups, nativeGroups)
}

func (p *globalFunctionCorrespondence) administrativeAccess(b nativeproof.TransitionBound, access nativeproof.TransitionAccess) bool {
	if p.layout.classifyAccess(storageFootprint{Image: access.Image, Bytes: access.Bytes}) != storageDisjoint {
		return false
	}
	if !access.Image {
		if access.Kind == nativeproof.FrameReturnRead && access.Bytes == (nativeproof.RelativeSpan{Start: 0, End: 8}) && access.ID == b.Boundary.ID && access.Context == 0 {
			return true
		}
		frame := b.Interface.PrivateFrame
		return frame != nil && frame.Bytes.Start < frame.Bytes.End && frame.Bytes.End <= 0 && access.Bytes.Start >= frame.Bytes.Start && access.Bytes.End <= frame.Bytes.End && access.Bytes.Start < access.Bytes.End
	}
	if access.Kind != nativeproof.FrameRead {
		return false
	}
	for _, bound := range b.Interface.EntryWordUpperBounds {
		if access.Bytes.Start >= int64(bound.Address) && access.Bytes.End <= int64(bound.Address+8) && access.Bytes.Start < access.Bytes.End {
			return true
		}
	}
	return false
}

// storageEffectBytes uses the canonical typed leaves, never the aggregate's
// padding. The event's value is the value at this occurrence, not its endpoint.
func (p *globalFunctionCorrespondence) storageEffectBytes(ctx context.Context, access regionEffectAccess) (storageFootprint, map[nativeproof.TransitionLocation]byte, error) {
	return p.storageValueBytes(ctx, access, false)
}

// A language initializer may retain known leaves beside opaque scalar leaves.
// partial preserves only those known bytes; actual effect projection always
// requires every leaf and never uses this weaker initialization-only view.
func (p *globalFunctionCorrespondence) storageValueBytes(ctx context.Context, access regionEffectAccess, partial bool) (storageFootprint, map[nativeproof.TransitionLocation]byte, error) {
	footprint, ok := p.layout.locationFootprint(access.location)
	if !ok {
		return storageFootprint{}, nil, globalFunctionError("source access leaves fixed storage")
	}
	meter := storageLayoutMeter{ctx: ctx}
	_, sizes, err := meter.objectType(p.representation.source, access.location.object)
	if err != nil {
		return storageFootprint{}, nil, err
	}
	leaves, err := p.layout.typedLeaves(ctx, access.location.object)
	if err != nil {
		return storageFootprint{}, nil, err
	}
	lanes := map[nativeproof.TransitionLocation]byte{}
leavesLoop:
	for _, leaf := range leaves {
		if err := ctx.Err(); err != nil {
			return storageFootprint{}, nil, err
		}
		if len(leaf.location.path) < len(access.location.path) || !slices.Equal(leaf.location.path[:len(access.location.path)], access.location.path) {
			continue
		}
		value := access.value
		for _, step := range leaf.location.path[len(access.location.path):] {
			if value.kind != regionAggregate || step.index < 0 || step.index >= int64(len(value.elements)) {
				if partial {
					continue leavesLoop
				}
				return storageFootprint{}, nil, globalFunctionError("unknown aggregate effect")
			}
			value = value.elements[step.index]
		}
		if viewed, sameDomain := regionViewValue(value, leaf.typ); sameDomain {
			value = viewed
		} else if !regionBitViewTypes(value.typ, leaf.typ) {
			return storageFootprint{}, nil, globalFunctionError("effect type differs from canonical storage")
		}
		// A checked source bit-view event retains its access interpretation while
		// the leaf retains canonical ownership. Their common exact-width word is
		// compared as bytes; no numeric conversion or new alias is inferred here.
		// The owning source proof still carries the storage-model antecedent.
		bits, width, ok := storageScalarBits(value, sizes)
		if !ok && partial {
			continue
		}
		if !ok || int64(width) != leaf.footprint.Bytes.End-leaf.footprint.Bytes.Start {
			return storageFootprint{}, nil, globalFunctionError("effect lacks selected typed bits")
		}
		for lane := range width {
			lanes[nativeproof.TransitionLocation{Image: footprint.Image, Offset: leaf.footprint.Bytes.Start + int64(lane)}] = byte(bits >> (8 * lane))
		}
	}
	if len(lanes) == 0 && !partial {
		return storageFootprint{}, nil, globalFunctionError("effect has no typed leaves")
	}
	return footprint, lanes, nil
}

// storageWriteRunAdjacent preserves checked call and allocation frontiers between
// writes. Complete occurrence identity, rather than source position or declaration
// name, selects the actual interval; an effect-free call still ends a write run.
// Reference effects attached to a call retain that barrier at either endpoint.
func (p *globalFunctionCorrespondence) storageWriteRunAdjacent(ctx context.Context, a, b regionEffectAccess) bool {
	if _, call := a.instruction.(*ssa.Call); call {
		return false
	}
	if _, call := b.instruction.(*ssa.Call); call {
		return false
	}
	if a.owner != b.owner || a.invocation != b.invocation {
		return false
	}
	active := false
	for _, trace := range p.traces {
		for _, occurrence := range trace.instructions {
			if ctx.Err() != nil {
				return false
			}
			if occurrence == a.regionEffectOccurrence {
				if occurrence == b.regionEffectOccurrence {
					return trace.seen[occurrence]
				}
				active = true
				continue
			}
			if !active {
				continue
			}
			if occurrence == b.regionEffectOccurrence {
				return true
			}
			switch occurrence.instruction.(type) {
			case *ssa.Call, *ssa.Alloc:
				return false
			}
		}
	}
	return false
}

// isolatedStorage checks actual SSA pointer uses all the way through substituted
// ordinary calls and their actual pointer results. A typed address cannot
// disappear through a store, opaque call, escaping return, address-observing
// conversion or interface construction. An actually checked provenance-preserving
// view remains traversable; every use of that view is checked in turn.
// Values read through it still have
// their checked source uses, outcomes and any resulting represented effects.
func (p *globalFunctionCorrespondence) isolatedStorage(ctx context.Context, object regionObject) (bool, error) {
	allocation, ok := object.site.(*ssa.Alloc)
	if object.kind != regionAllocation || !ok {
		return false, nil
	}
	seen := map[ssa.Value]bool{}
	var visit func(ssa.Value) (bool, error)
	visit = func(pointer ssa.Value) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if seen[pointer] {
			return true, nil
		}
		seen[pointer] = true
		refs := pointer.Referrers()
		if refs == nil {
			return false, nil
		}
		for _, use := range *refs {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			switch x := use.(type) {
			case *ssa.DebugRef:
			case *ssa.Convert:
				if x.X != pointer {
					return false, nil
				}
				if admitted, err := p.checkedStorageView(ctx, x); !admitted || err != nil {
					return admitted, err
				}
				if safe, err := visit(x); !safe || err != nil {
					return safe, err
				}
			case *ssa.ChangeType:
				if x.X != pointer {
					return false, nil
				}
				if admitted, err := p.checkedStorageView(ctx, x); !admitted || err != nil {
					return admitted, err
				}
				if safe, err := visit(x); !safe || err != nil {
					return safe, err
				}
			case *ssa.FieldAddr:
				if safe, err := visit(x); !safe || err != nil {
					return safe, err
				}
			case *ssa.IndexAddr:
				if safe, err := visit(x); !safe || err != nil {
					return safe, err
				}
			case *ssa.UnOp:
				if x.Op != token.MUL || x.X != pointer {
					return false, nil
				}
			case *ssa.Store:
				if x.Addr != pointer || x.Val == pointer {
					return false, nil
				}
			case *ssa.Call:
				found := false
				for _, trace := range p.traces {
					for _, application := range trace.calls {
						if err := ctx.Err(); err != nil {
							return false, err
						}
						proof := application.proof
						if proof.at != x || proof.reference != nil {
							continue
						}
						for i, arg := range x.Call.Args {
							if arg == pointer {
								if i >= len(proof.target.Params) {
									return false, nil
								}
								if safe, err := visit(proof.target.Params[i]); !safe || err != nil {
									return safe, err
								}
								found = true
							}
						}
					}
				}
				if !found {
					return false, nil
				}
			case *ssa.Return:
				// A source helper's pointer result stays internal only when its
				// checked actual outcome identifies this object and every use of
				// the caller's returned SSA value is nonescaping in turn.
				found := false
				for _, trace := range p.traces {
					for _, application := range trace.calls {
						if err := ctx.Err(); err != nil {
							return false, err
						}
						proof := application.proof
						if proof.reference != nil || proof.target != x.Parent() || len(x.Results) != 1 || x.Results[0] != pointer || application.outcome.value.kind != regionPointer || application.outcome.value.location.object != object {
							continue
						}
						if safe, err := visit(proof.at); !safe || err != nil {
							return safe, err
						}
						found = true
					}
				}
				if !found {
					return false, nil
				}
			default:
				return false, nil
			}
		}
		return true, nil
	}
	return visit(allocation)
}

// The finite source checker admits pointer conversions only as checked live-object
// views. A syntactically plausible conversion in an unexecuted arm supplies no
// such evidence. Consuming its actual checked occurrence avoids a second layout
// or unsafe-conversion rule in the native effect matcher. The enclosing source
// certificate continues to own the conditional storage-model antecedent.
func (p *globalFunctionCorrespondence) checkedStorageView(ctx context.Context, instruction ssa.Instruction) (bool, error) {
	for _, trace := range p.traces {
		for _, occurrence := range trace.instructions {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if occurrence.instruction == instruction && trace.seen[occurrence] {
				return true, nil
			}
		}
	}
	return false, nil
}

// isolatedAllocatedRead derives a source-only elimination premise from the
// checked access and its actual preceding allocation occurrence. The caller
// separately projects the read's known typed value and retains all checked
// dependent uses and call outcomes. Native placement/lifetime authority is a
// prerequisite, not inferred here. This premise supplies no native byte values.
func (p *globalFunctionCorrespondence) isolatedAllocatedRead(ctx context.Context, index int) (bool, error) {
	if index < 0 || index >= len(p.accesses) {
		return false, globalFunctionError("invalid source read index")
	}
	access := p.accesses[index]
	object := access.location.object
	if access.write || access.locked || object.kind != regionAllocation || p.layout == nil {
		return false, nil
	}
	if _, represented := p.layout.objects[object]; !represented {
		return false, nil
	}
	site, ok := object.site.(*ssa.Alloc)
	if !ok {
		return false, nil
	}
	allocated := false
	for _, trace := range p.traces {
		for _, occurrence := range trace.instructions {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if occurrence.instruction == site && occurrence.invocation == object.invocation {
				for _, allocation := range trace.allocations {
					if err := ctx.Err(); err != nil {
						return false, err
					}
					if allocation.regionEffectOccurrence == occurrence && allocation.location.object == object && len(allocation.location.path) == 0 && trace.seen[occurrence] {
						allocated = true
						break
					}
				}
			}
			if occurrence == access.regionEffectOccurrence {
				if !allocated || !trace.seen[occurrence] {
					return false, nil
				}
				return p.isolatedStorage(ctx, object)
			}
		}
	}
	return false, nil
}

// storageEffectMismatch is a failed candidate alignment, not an operational or
// authority failure. Only this class and an unsupported bit equality permit
// trying another independently checked alignment.
type storageEffectMismatch struct{ detail string }

func (e *storageEffectMismatch) Error() string { return "global function correspondence: " + e.detail }
func storageMismatch(detail string) error      { return &storageEffectMismatch{detail} }

func storageEffectRetryable(err error) bool {
	var mismatch *storageEffectMismatch
	return errors.As(err, &mismatch) || globalFunctionUnproved(err)
}

type storageEffectReadChoice struct {
	source int
	retain bool
}

// A choice prefix proposes alignments only. Every use rechecks its source site
// and read eligibility, and success still requires the entire effect relation.
type storageReadPlan struct {
	prefix, path []storageEffectReadChoice
	preferRetain bool
	bound        int
}

func (p *storageReadPlan) choose(ctx context.Context, source int) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	depth := len(p.path)
	if depth >= p.bound || source < 0 || source >= p.bound || depth > 0 && p.path[depth-1].source >= source {
		return false, globalFunctionError("invalid or exhausted source read-choice population")
	}
	retain := p.preferRetain
	if depth < len(p.prefix) {
		if p.prefix[depth].source != source {
			return false, globalFunctionError("read-choice prefix has a different source occurrence")
		}
		retain = p.prefix[depth].retain
	}
	p.path = append(p.path, storageEffectReadChoice{source, retain})
	return retain, nil
}

// matchStorageEffects is the single bytewise ordinary/indivisible relation used
// by prefix, phase and complete-function consumers. Native indices are never
// renumbered, and source atomic groups retain their actual reference occurrence.
func (p *globalFunctionCorrespondence) matchStorageEffects(ctx context.Context, native []nativeproof.TransitionAccess, initialMemory []nativeproof.TransitionByte, observable []int, sourceGroups map[int]regionAtomicOccurrence, nativeGroups map[int]globalFunctionNativeAtomic) error {
	return p.searchStorageEffects(ctx, native, initialMemory, observable, sourceGroups, nativeGroups, true)
}

// A known read may either retain an available native read (and its initializer
// prefix) or disappear before a later ordinary write/read. Local footprint
// agreement cannot select between those alignments: their complete continuations
// must be checked. Depth-first replay proposes finite source-indexed choices to
// the same checker, retaining only one path and one pending prefix. Depth is at
// most the bounded source-access population; all attempts and replay work share
// the caller's cumulative account. Operational failures never trigger replay.
//
// Each attempt owns a fresh proof delta and fresh byte/cursor/allocation state.
// Guard, administrative and inactive accounts were checked before this search and
// are never modified by an attempt. Only a complete successful continuation can
// append its witnesses and effect accounts to the caller. Neither a failed choice
// nor a successful search changes the owned source or native computations.
func (p *globalFunctionCorrespondence) searchStorageEffects(ctx context.Context, native []nativeproof.TransitionAccess, initialMemory []nativeproof.TransitionByte, observable []int, sourceGroups map[int]regionAtomicOccurrence, nativeGroups map[int]globalFunctionNativeAtomic, preferRetain bool) error {
	if ctx == nil || p.layout == nil || len(p.accesses) > 65536 || len(p.traces) > 65536 || len(native) > 65536 || len(observable) > len(native) || len(initialMemory) > storageMaxBytes || len(sourceGroups) > 65536 || len(nativeGroups) > 65536 {
		return globalFunctionError("invalid or oversized effect search inputs")
	}
	// Public consumers already supply this account. Direct internal consumers
	// receive the existing default once for the whole search, never per attempt.
	if meter, ok := ctx.(*correspondenceContext); ok {
		if meter == nil || meter.limit < 1 || meter.limit > 20_000_000 || meter.work < 0 || meter.work > meter.limit {
			return globalFunctionError("invalid effect search work account")
		}
	} else {
		limit := p.limit
		if limit == 0 {
			limit = 2_000_000
		}
		if limit < 1 || limit > 20_000_000 || p.work < 0 || p.work > limit {
			return globalFunctionError("invalid effect search work account")
		}
		ctx = &correspondenceContext{Context: ctx, work: p.work, limit: limit}
	}
	// These are the already-owned, guarded projections. Freeze their containers
	// once before callbacks; every replay observes exactly these same inputs.
	native = slices.Clone(native)
	initialMemory = slices.Clone(initialMemory)
	observable = slices.Clone(observable)
	sourceGroups = maps.Clone(sourceGroups)
	nativeGroups = maps.Clone(nativeGroups)
	accesses, traces := slices.Clone(p.accesses), slices.Clone(p.traces)
	for range len(native) + len(initialMemory) + len(observable) + len(sourceGroups) + len(nativeGroups) + len(accesses) + len(traces) {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	last := -1
	for _, index := range observable {
		if err := ctx.Err(); err != nil {
			return err
		}
		if index <= last || index < 0 || index >= len(native) {
			return globalFunctionError("invalid ordered native effect projection")
		}
		last = index
	}
	var prefix []storageEffectReadChoice
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		plan := storageReadPlan{prefix: prefix, preferRetain: preferRetain, bound: len(accesses)}
		// Only immutable checker inputs are shared. Every mutable proof account
		// starts empty, so abandoning an attempt cannot leak tentative evidence.
		candidate := globalFunctionCorrespondence{representation: p.representation, layout: p.layout, antecedent: p.antecedent, inputs: p.inputs, accesses: accesses, traces: traces, call: p.call}
		err := candidate.matchStorageEffectAttempt(ctx, native, initialMemory, observable, sourceGroups, nativeGroups, &plan)
		if stopped := ctx.Err(); stopped != nil {
			return stopped
		}
		if err == nil {
			if len(plan.path) < len(prefix) {
				return globalFunctionError("effect search left an unchecked choice prefix")
			}
			// Charge copying before any caller account is changed. The checker
			// above is the sole writer of these six attempt-local output accounts.
			for range len(p.equalities) + len(candidate.equalities) + len(p.matched) + len(candidate.matched) + len(p.eliminated) + len(candidate.eliminated) + len(p.materialized) + len(candidate.materialized) + len(p.padding) + len(candidate.padding) + len(p.atomics) + len(candidate.atomics) {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			p.equalities = append(p.equalities, candidate.equalities...)
			p.matched = append(p.matched, candidate.matched...)
			p.eliminated = append(p.eliminated, candidate.eliminated...)
			p.materialized = append(p.materialized, candidate.materialized...)
			p.padding = append(p.padding, candidate.padding...)
			p.atomics = append(p.atomics, candidate.atomics...)
			return nil
		}
		if !storageEffectRetryable(err) {
			return err
		}
		alternate := -1
		for i := len(plan.path) - 1; i >= 0; i-- {
			if stopped := ctx.Err(); stopped != nil {
				return stopped
			}
			if plan.path[i].retain == preferRetain {
				alternate = i
				break
			}
		}
		if alternate < 0 {
			return err
		}
		for range alternate + 1 {
			if stopped := ctx.Err(); stopped != nil {
				return stopped
			}
		}
		prefix = slices.Clone(plan.path[:alternate+1])
		prefix[alternate].retain = !preferRetain
	}
}

// One attempt checks a candidate alignment from the original initial memory.
// Its local state and all appended proof accounts are private to the search.
func (p *globalFunctionCorrespondence) matchStorageEffectAttempt(ctx context.Context, native []nativeproof.TransitionAccess, initialMemory []nativeproof.TransitionByte, observable []int, sourceGroups map[int]regionAtomicOccurrence, nativeGroups map[int]globalFunctionNativeAtomic, plan *storageReadPlan) error {
	known := map[nativeproof.TransitionLocation]byte{}
	padding := map[nativeproof.TransitionLocation]br.Term{}
	typed := map[nativeproof.TransitionLocation]bool{}
	for object := range p.layout.objects {
		leaves, err := p.layout.typedLeaves(ctx, object)
		if err != nil {
			return err
		}
		for _, leaf := range leaves {
			for offset := leaf.footprint.Bytes.Start; offset < leaf.footprint.Bytes.End; offset++ {
				if err := ctx.Err(); err != nil {
					return err
				}
				typed[nativeproof.TransitionLocation{Image: leaf.footprint.Image, Offset: offset}] = true
			}
		}
	}
	for _, cell := range initialMemory {
		if p.layout.representedByte(cell.TransitionLocation) && !typed[cell.TransitionLocation] {
			padding[cell.TransitionLocation] = cell.Value
		}
	}
	initializers := map[nativeproof.TransitionLocation]byte{}
	initializerChild := map[nativeproof.TransitionLocation]bool{}
	positions := map[regionEffectOccurrence]int{}
	var allocations []regionEffectAllocation
	position := 0
	for _, trace := range p.traces {
		allocations = append(allocations, trace.allocations...)
		for _, occurrence := range trace.instructions {
			if _, duplicate := positions[occurrence]; duplicate || !trace.seen[occurrence] {
				return globalFunctionError("source instruction occurrence is repeated or unestablished")
			}
			positions[occurrence] = position
			position++
		}
	}
	activated := map[regionObject]bool{}
	matched := map[int]int{}
	next := 0
	// The cursor ceiling is an actual application-owned cumulative index, not a
	// child slice. It changes only after checking the corresponding source frontier.
	fence := 0
	ceiling := func() int {
		if p.call != nil && fence < 2 {
			return p.call.nativeFence[fence]
		}
		return len(native)
	}
	available := func(cursor int) bool {
		return cursor < len(observable) && observable[cursor] < ceiling()
	}
	proveBytes := func(index int, access nativeproof.TransitionAccess, want map[nativeproof.TransitionLocation]byte) ([]storagePaddingAccess, error) {
		width := access.Bytes.End - access.Bytes.Start
		if width <= 0 || width > 8 || access.Value.Sort() != br.Bits(int(width*8)) {
			return nil, globalFunctionError("unsupported native effect width")
		}
		var bits uint64
		var gaps []nativeproof.TransitionLocation
		for lane := int64(0); lane < width; lane++ {
			location := nativeproof.TransitionLocation{Image: access.Image, Offset: access.Bytes.Start + lane}
			v, ok := want[location]
			if !ok {
				if _, pad := padding[location]; !pad {
					return nil, storageMismatch("native effect has missing or surplus byte coverage")
				}
				gaps = append(gaps, location)
			}
			bits |= uint64(v) << (8 * lane)
		}
		if len(gaps) == 0 {
			return nil, p.constant(ctx, access.Value, bits)
		}
		if len(gaps) == int(width) {
			return nil, storageMismatch("padding-only effect has no source operation")
		}
		builder := br.NewBuilder(128)
		var paddingAccesses []storagePaddingAccess
		for lane := int64(0); lane < width; lane++ {
			value, err := storageNativeLane(builder, access.Value, int(lane))
			if err != nil {
				return nil, err
			}
			location := nativeproof.TransitionLocation{Image: access.Image, Offset: access.Bytes.Start + lane}
			if v, ok := want[location]; ok {
				if err := p.constant(ctx, value, uint64(v)); err != nil {
					return nil, err
				}
				continue
			}
			if access.Kind == nativeproof.FrameRead {
				if err := p.equal(ctx, value, padding[location]); err != nil {
					return nil, err
				}
			}
			paddingAccesses = append(paddingAccesses, storagePaddingAccess{index, location, value})
		}
		return paddingAccesses, nil
	}
	recordPadding := func(accesses []storagePaddingAccess) {
		for _, access := range accesses {
			if native[access.native].Kind == nativeproof.FrameWrite {
				padding[access.location] = access.value
			}
		}
		p.padding = append(p.padding, accesses...)
	}
	matchBytes := func(index int, access nativeproof.TransitionAccess, want map[nativeproof.TransitionLocation]byte) error {
		accesses, err := proveBytes(index, access, want)
		if err != nil {
			return err
		}
		recordPadding(accesses)
		return nil
	}
	knownValue := func(lanes map[nativeproof.TransitionLocation]byte) (bool, error) {
		for location, value := range lanes {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if old, ok := known[location]; !ok || old != value {
				return false, nil
			}
		}
		return true, nil
	}
	readEliminable := func(index int, lanes map[nativeproof.TransitionLocation]byte) (bool, error) {
		known, err := knownValue(lanes)
		if err != nil || known {
			return known, err
		}
		return p.isolatedAllocatedRead(ctx, index)
	}
	ordinaryReadAt := func(cursor int, footprint storageFootprint) bool {
		if !available(cursor) {
			return false
		}
		index := observable[cursor]
		access := native[index]
		_, atomic := nativeGroups[index]
		return !atomic && access.Kind == nativeproof.FrameRead && access.Image == footprint.Image && access.Bytes.Start >= footprint.Bytes.Start && access.Bytes.End <= footprint.Bytes.End
	}
	// A frontier is a position in the actual checked source instruction trace.
	// Allocation evidence becomes available there even when no ordinary access
	// follows it. Activation contributes only language bits; the ordered native
	// cursor and proved writes alone establish physical materialization.
	consumeInitializers := func(frontier int, ordinaryWrite map[nativeproof.TransitionLocation]byte, retain func(int) bool) error {
		for _, allocation := range allocations {
			if err := ctx.Err(); err != nil {
				return err
			}
			object := allocation.location.object
			if activated[object] {
				continue
			}
			allocatedAt, found := positions[allocation.regionEffectOccurrence]
			if !found || allocatedAt >= frontier {
				continue
			}
			activated[object] = true
			if _, represented := p.layout.objects[object]; !represented {
				continue
			}
			_, lanes, err := p.storageValueBytes(ctx, regionEffectAccess{location: allocation.location, value: allocation.initializer}, true)
			if err != nil {
				return err
			}
			for location, value := range lanes {
				initializers[location] = value
				initializerChild[location] = p.call != nil && allocatedAt > p.call.sourceFence[0] && allocatedAt < p.call.sourceFence[1]
			}
		}
		// Initialization is optional native work, justified by the actual source
		// allocation. It never seeds known bytes: only an executed native write
		// whose entire value agrees may materialize an as-yet unknown footprint.
		// A known read may need to defer these writes to later ordinary effects.
		// Plan them without changing the native cursor, byte knowledge or padding;
		// retain decides whether the resulting cursor justifies that choice.
		checkpoint := len(p.equalities)
		cursor := next
		pending := map[nativeproof.TransitionLocation]bool{}
		var planned []struct {
			index   int
			padding []storagePaddingAccess
		}
		for available(cursor) {
			if err := ctx.Err(); err != nil {
				return err
			}
			index := observable[cursor]
			access := native[index]
			_, nativeAtomic := nativeGroups[index]
			if nativeAtomic || access.Kind != nativeproof.FrameWrite || access.Image || access.Bytes.End-access.Bytes.Start > 8 || access.Bytes.Start >= access.Bytes.End {
				break
			}
			// Prefer the already planned ordinary run, including its narrow
			// pieces and actual padding. A preference proof does not consume or
			// update padding; the selected match records those bytes exactly once.
			ordinary := ordinaryWrite != nil && p.layout.classifyAccess(storageFootprint{Bytes: access.Bytes}) == storageInside
			covered := 0
			for offset := access.Bytes.Start; offset < access.Bytes.End; offset++ {
				location := nativeproof.TransitionLocation{Offset: offset}
				_, found := ordinaryWrite[location]
				_, pad := padding[location]
				ordinary = ordinary && (found || pad)
				if found {
					covered++
				}
			}
			ordinary = ordinary && covered != 0
			if ordinary {
				if _, err := proveBytes(index, access, ordinaryWrite); err != nil {
					if !globalFunctionUnproved(err) {
						return err
					}
					ordinary = false
				}
			}
			if ordinary {
				break
			}
			eligible := p.layout.classifyAccess(storageFootprint{Bytes: access.Bytes}) == storageInside
			for offset := access.Bytes.Start; offset < access.Bytes.End; offset++ {
				location := nativeproof.TransitionLocation{Offset: offset}
				_, initial := initializers[location]
				_, pad := padding[location]
				_, materialized := known[location]
				eligible = eligible && (initial || pad) && !materialized && !pending[location]
				if p.call != nil && initial && initializerChild[location] != (fence == 1) {
					eligible = false
				}
			}
			if !eligible {
				break
			}
			paddingAccesses, err := proveBytes(index, access, initializers)
			if err != nil {
				if !globalFunctionUnproved(err) {
					return err
				}
				break
			}
			for offset := access.Bytes.Start; offset < access.Bytes.End; offset++ {
				location := nativeproof.TransitionLocation{Offset: offset}
				if _, initial := initializers[location]; initial {
					pending[location] = true
				}
			}
			planned = append(planned, struct {
				index   int
				padding []storagePaddingAccess
			}{index, paddingAccesses})
			cursor++
		}
		if retain != nil && !retain(cursor) {
			p.equalities = p.equalities[:checkpoint]
			// Successful memo entries refer to witnesses in this account. The
			// abandoned lookahead cannot leave a success whose witness was cut.
			p.constants = nil
			return nil
		}
		for _, plan := range planned {
			if err := ctx.Err(); err != nil {
				return err
			}
			recordPadding(plan.padding)
			access := native[plan.index]
			for offset := access.Bytes.Start; offset < access.Bytes.End; offset++ {
				location := nativeproof.TransitionLocation{Offset: offset}
				if value, initial := initializers[location]; initial {
					known[location] = value
				}
			}
			p.materialized = append(p.materialized, plan.index)
		}
		next = cursor
		return nil
	}
	advanceCallFences := func(frontier int) error {
		for p.call != nil && fence < 2 && p.call.sourceFence[fence] <= frontier {
			if err := ctx.Err(); err != nil {
				return err
			}
			// Even a child without accesses has checked instruction entry/return
			// frontiers. Complete the preceding initialization work under its own
			// native ceiling, then check the actual current state before crossing.
			if err := consumeInitializers(p.call.sourceFence[fence], nil, nil); err != nil {
				return err
			}
			if available(next) {
				return storageMismatch("unmatched native effect before actual-call fence")
			}
			if err := p.checkCallCheckpoint(ctx, fence == 1, known); err != nil {
				return err
			}
			fence++
		}
		return nil
	}
	for i := 0; i < len(p.accesses); {
		if err := ctx.Err(); err != nil {
			return err
		}
		source := p.accesses[i]
		at, atOK := positions[source.regionEffectOccurrence]
		if !atOK {
			return globalFunctionError("effect has no checked source occurrence")
		}
		if err := advanceCallFences(at); err != nil {
			return err
		}
		group, atomic := sourceGroups[i]
		if source.locked != atomic {
			return globalFunctionError("source locked access lacks its atomic group")
		}
		_, represented := p.layout.objects[source.location.object]
		var footprint storageFootprint
		var lanes, ordinaryWrite map[nativeproof.TransitionLocation]byte
		if represented {
			var err error
			footprint, lanes, err = p.storageEffectBytes(ctx, source)
			if err != nil {
				return err
			}
		}
		if !represented {
			safe, err := p.isolatedStorage(ctx, source.location.object)
			if err != nil {
				return err
			}
			if !safe || atomic {
				return globalFunctionError("unrepresented source storage is not isolated")
			}
			p.eliminated = append(p.eliminated, i)
			i++
			continue
		}
		// Plan one byte account before initialization can consume a competing
		// write. Only disjoint adjacent ordinary writes join this plan; reads,
		// calls, atomics and allocation frontiers cannot be crossed.
		end := i + 1
		owners := map[nativeproof.TransitionLocation]int{}
		for location := range lanes {
			owners[location] = i
		}
		for source.write && !atomic && end < len(p.accesses) && p.accesses[end].write && !p.accesses[end].locked && p.storageWriteRunAdjacent(ctx, p.accesses[end-1], p.accesses[end]) {
			_, more, err := p.storageEffectBytes(ctx, p.accesses[end])
			if err != nil {
				break
			}
			overlap := false
			for location := range more {
				_, exists := lanes[location]
				overlap = overlap || exists
			}
			if overlap {
				break
			}
			for location, value := range more {
				lanes[location], owners[location] = value, end
			}
			end++
		}
		if source.write {
			ordinaryWrite = lanes
		}
		// An eliminated source-only access cannot consume the native write that
		// a later represented access needs. Keep the native cursor in place until
		// that access can exercise ordinary-write preference, or the final cut.
		var retainRead func(int) bool
		deferRead := false
		var choiceErr error
		if !source.write && !atomic {
			eliminable, err := readEliminable(i, lanes)
			if err != nil {
				return err
			}
			if eliminable {
				retainRead = func(cursor int) bool {
					if !ordinaryReadAt(cursor, footprint) {
						return false
					}
					var retain bool
					retain, choiceErr = plan.choose(ctx, i)
					deferRead = choiceErr == nil && !retain
					return choiceErr == nil && retain
				}
			}
		}
		if err := consumeInitializers(at, ordinaryWrite, retainRead); err != nil {
			return err
		}
		if choiceErr != nil {
			return choiceErr
		}
		if deferRead {
			p.eliminated = append(p.eliminated, i)
			i++
			continue
		}
		splitRead := false
		if !source.write && !atomic && ordinaryReadAt(next, footprint) {
			access := native[observable[next]]
			splitRead = access.Bytes != footprint.Bytes
		}
		if !atomic && (source.write || splitRead) {
			// A split ordinary read uses the same coverage plan for one source
			// operation; only the ordinary-write planner above may extend it.
			remaining := len(lanes)
			seen := map[nativeproof.TransitionLocation]bool{}
			previous := -1
			kind := nativeproof.FrameWrite
			if splitRead {
				kind = nativeproof.FrameRead
			}
			for remaining != 0 {
				if !available(next) {
					return storageMismatch("missing native effect bytes")
				}
				index := observable[next]
				access := native[index]
				if splitRead && (access.Image != footprint.Image || access.Bytes.Start < footprint.Bytes.Start || access.Bytes.End > footprint.Bytes.End || previous >= 0 && access.Bytes.Start < native[previous].Bytes.End) {
					return storageMismatch("split native read leaves ordered source footprint")
				}
				if previous >= 0 && access.Context != native[previous].Context {
					return storageMismatch("combined native writes cross a call boundary")
				}
				for between := previous + 1; previous >= 0 && between < index; between++ {
					if native[between].Kind == nativeproof.FrameReturnRead || native[between].Context != native[previous].Context {
						return storageMismatch("combined native writes cross a call boundary")
					}
				}
				if _, atomic := nativeGroups[index]; atomic || access.Kind != kind || p.layout.classifyAccess(storageFootprint{Image: access.Image, Bytes: access.Bytes}) != storageInside {
					return storageMismatch("ordered source/native effects differ")
				}
				if err := matchBytes(index, access, lanes); err != nil {
					return err
				}
				accounts := map[int]bool{}
				for offset := access.Bytes.Start; offset < access.Bytes.End; offset++ {
					location := nativeproof.TransitionLocation{Image: access.Image, Offset: offset}
					if seen[location] {
						return storageMismatch("native effect repeats an already matched byte")
					}
					seen[location] = true
					if _, pad := padding[location]; pad {
						continue
					}
					seen[location], known[location], accounts[owners[location]] = true, lanes[location], true
					remaining--
				}
				for owner := i; owner < end; owner++ {
					if accounts[owner] {
						p.matched = append(p.matched, globalFunctionAccess{owner, index})
					}
				}
				next++
				previous = index
			}
			i = end
			continue
		}
		kind := nativeproof.FrameRead
		if source.write {
			kind = nativeproof.FrameWrite
		}
		match := false
		if available(next) {
			index := observable[next]
			access := native[index]
			nativeGroup, nativeAtomic := nativeGroups[index]
			match = access.Image == footprint.Image && access.Bytes == footprint.Bytes && access.Kind == kind && atomic == nativeAtomic
			if atomic {
				match = match && nativeGroup.kind == group.atomic.Kind && nativeGroup.width == group.atomic.Width && footprint.Bytes.End-footprint.Bytes.Start == int64(group.atomic.Width)
			}
			if match {
				if err := matchBytes(index, access, lanes); err != nil {
					return err
				}
				matched[i] = index
				p.matched = append(p.matched, globalFunctionAccess{i, index})
				next++
			}
		}
		if !match {
			if source.write || atomic {
				return storageMismatch("ordered source/native effects differ")
			}
			eliminable, err := readEliminable(i, lanes)
			if err != nil {
				return err
			}
			if !eliminable {
				return storageMismatch("source read lacks materialized native bytes")
			}
			p.eliminated = append(p.eliminated, i)
		} else {
			// Only an actual matched native access establishes native bytes. A
			// source-only local read may have a known language value while those
			// physical bytes remain arbitrary until a later real write.
			for location, value := range lanes {
				known[location] = value
			}
		}
		i++
	}
	if err := advanceCallFences(position); err != nil {
		return err
	}
	if err := consumeInitializers(position, nil, nil); err != nil {
		return err
	}
	if next != len(observable) {
		return storageMismatch("native computation has an unmatched effect")
	}
	for i, access := range p.accesses {
		source, atomic := sourceGroups[i]
		if !atomic || !access.write {
			continue
		}
		read, readOK := matched[i-1]
		write, writeOK := matched[i]
		group := nativeGroups[write]
		if !readOK || !writeOK || group.read != read || group.write != write || read+1 != write {
			return storageMismatch("source indivisible group was split across native occurrences")
		}
		p.atomics = append(p.atomics, globalFunctionAtomic{source, group.effect})
	}
	return nil
}

func storageNativeLane(builder *br.Builder, value br.Term, lane int) (br.Term, error) {
	if lane < 0 || lane >= value.Sort().Width()/8 {
		return br.Term{}, globalFunctionError("invalid native byte lane")
	}
	if value.Sort() == br.Bits(8) {
		return value, nil
	}
	return builder.Make(br.Extract, br.Bits(8), uint64(8*lane), value)
}

func (p *globalFunctionCorrespondence) checkStorageValues(ctx context.Context, builder *br.Builder, state regionState, memory []nativeproof.TransitionByte, globalsOnly bool) error {
	for _, binding := range p.representation.bindings {
		if globalsOnly && binding.object.kind != regionGlobal {
			continue
		}
		if err := p.checkStorageLocationValues(ctx, builder, state, memory, regionLocation{object: binding.object}); err != nil {
			return err
		}
	}
	return nil
}

// checkStorageLocationValues checks precisely the selected subobject. A pending
// field read cannot demand initialization of unrelated fields or padding.
func (p *globalFunctionCorrespondence) checkStorageLocationValues(ctx context.Context, builder *br.Builder, state regionState, memory []nativeproof.TransitionByte, location regionLocation) error {
	if _, ok := p.layout.locationFootprint(location); !ok {
		return globalFunctionError("current location leaves fixed storage")
	}
	leaves, err := p.layout.typedLeaves(ctx, location.object)
	if err != nil {
		return err
	}
	meter := storageLayoutMeter{ctx: ctx}
	_, sizes, err := meter.objectType(p.representation.source, location.object)
	if err != nil {
		return err
	}
	for _, leaf := range leaves {
		if len(leaf.location.path) < len(location.path) || !slices.Equal(leaf.location.path[:len(location.path)], location.path) {
			continue
		}
		value := readRegionLocation(state, leaf.location, leaf.typ)
		bits, width, ok := storageScalarBits(value, sizes)
		if !ok {
			width = int(leaf.footprint.Bytes.End - leaf.footprint.Bytes.Start)
		}
		actual, err := storageNativeWord(ctx, builder, memory, nativeproof.TransitionLocation{Image: leaf.footprint.Image, Offset: leaf.footprint.Bytes.Start}, width)
		if err != nil {
			return err
		}
		if !ok {
			preserved := false
			for _, input := range p.inputs {
				if input.location.object == leaf.location.object && slices.Equal(input.location.path, leaf.location.path) {
					if err := p.equal(ctx, actual, input.native); err != nil {
						return err
					}
					preserved = true
					break
				}
			}
			if !preserved {
				return globalFunctionError("current source leaf has no established typed value")
			}
			continue
		}
		if err := p.constant(ctx, actual, bits); err != nil {
			return err
		}
	}
	return nil
}

func (p *globalFunctionCorrespondence) checkFinal(ctx context.Context, builder *br.Builder, b nativeproof.TransitionReturnBound) error {
	if b.Prefix.Interface.Conditions.SSE != "" && (!b.State.SSE.MXCSRPreserved || !b.State.SSE.UpperVectorsPreserved) {
		return globalFunctionError("floating control or higher vector context was not preserved")
	}
	// The checked root is void, and the effect relation admits neither a pointer
	// store to externally observable storage nor an opaque pointer-consuming call.
	// Together with private native lifetime ownership and the escape checks below,
	// these facts permit releasing local storage. A return alone is not nonescape
	// evidence, and release neither resets nor discards residual native bytes.
	if err := p.checkStorageValues(ctx, builder, p.source.region.packet.observations[0].state, b.State.Memory, true); err != nil {
		return err
	}
	view := b.Prefix
	view.Memory = b.State.Memory
	if err := p.checkStorageFrame(ctx, view); err != nil {
		return err
	}
	prefix, _ := p.native.Prefix()
	for _, register := range b.Prefix.Interface.ReturnContext.Preserved {
		if !slices.Contains(b.State.Restored, register) {
			return globalFunctionError("required caller register lacks derived restoration")
		}
		if _, image := b.State.Registers[register].Pointer.(nativeproof.ImagePointer); !image {
			original, ok := prefix.EntryValueRegister(b.State.Registers[register].Pointer)
			if !ok || original != register {
				return globalFunctionError("restored register lost incoming value lineage")
			}
		}
	}
	// Private storage is disjoint from image storage by the native root's mapping
	// relation and from the incoming control word by its negative relative extent.
	// At the void return no private address may escape via another register. The
	// fresh-root ownership premise separately excludes preexisting aliases.
	if b.Prefix.Interface.PrivateFrame != nil {
		independent := func(term br.Term) error {
			return globalFunctionIndependentWhen(ctx, term, map[br.Term]bool{b.Prefix.Origin: true}, func(guard br.Term, value uint64) error {
				return p.constant(ctx, guard, value)
			})
		}
		for register, value := range b.State.Registers {
			if nativeproof.Register(register) == nativeproof.RSP || slices.Contains(b.State.Restored, nativeproof.Register(register)) {
				continue
			}
			if pointer, ok := value.Pointer.(nativeproof.OriginPointer); ok && pointer.Offset < 0 {
				return globalFunctionError("private frame pointer escapes in returned context")
			}
			if err := independent(value.Value); err != nil {
				return fmt.Errorf("private frame address escapes in returned register %d: %w", register, err)
			}
		}
		if b.Prefix.Interface.Conditions.SSE != "" {
			for _, vector := range b.State.Vectors {
				for _, lane := range []br.Term{vector.Lo, vector.Hi} {
					if err := independent(lane); err != nil {
						return fmt.Errorf("private frame address escapes in returned vector: %w", err)
					}
				}
			}
		}
	}
	return nil
}

// checkStorageFrame preserves the original caller bytes outside represented
// objects and the separately owned private lifetime. It never discards residual
// private bytes from the native theorem.
func (p *globalFunctionCorrespondence) checkStorageFrame(ctx context.Context, b nativeproof.TransitionBound) error {
	current := map[nativeproof.TransitionLocation]nativeproof.TransitionByte{}
	for _, cell := range b.Memory {
		current[cell.TransitionLocation] = cell
	}
	for _, old := range b.InitialMemory {
		if err := ctx.Err(); err != nil {
			return err
		}
		private := b.Interface.PrivateFrame
		if !old.Image && private != nil && old.Offset >= private.Bytes.Start && old.Offset < private.Bytes.End {
			continue
		}
		if p.layout.representedByte(old.TransitionLocation) {
			continue
		}
		now, found := current[old.TransitionLocation]
		if !found || now.Pointer != old.Pointer || now.PointerLane != old.PointerLane {
			return globalFunctionError("unrelated caller memory/provenance was not preserved")
		}
		if err := p.equal(ctx, old.Value, now.Value); err != nil {
			return err
		}
	}
	return nil
}
