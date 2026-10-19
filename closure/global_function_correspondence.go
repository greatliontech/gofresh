package closure

import (
	"context"
	"errors"
	"fmt"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

const globalFunctionRules = "gofresh/global-function-correspondence@2;" + regionRules + ";" + nativeproof.TransitionRules + ";" + br.RuleModel

// A mapping names the actual typed parameter and its incoming full native word.
// The present effect-only grammar admits only unused pointer parameters. A word
// mapping gives neither dereference permission nor an alias exclusion.
type globalFunctionArgument struct {
	parameter *ssa.Parameter
	register  nativeproof.Register
}

type globalFunctionInput struct {
	global         *ssa.Global
	source, native br.Term
}

type globalFunctionAtomic struct {
	source regionAtomicOccurrence
	native nativeproof.PrimitiveEffect
}

type globalFunctionAccess struct{ source, native int }

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
	representation       globalRepresentation
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
	equalities           []br.Witness
	open                 computationCorrespondenceObligations
	work, limit          int
}

// checkGlobalFunctionCorrespondence checks a void, effect-and-return relation.
// Scalar results of internal calls need not match register-by-register: their
// actual source/native uses are included in the complete checked effects and
// exceptional paths. No expected output or expected atomic inventory is input.
func checkGlobalFunctionCorrespondence(ctx context.Context, source computationSource, root *ssa.Function, image *nativeproof.Image, entry uint64, completed *sourceReturnCompletion, native nativeproof.TransitionReturnCertificate, rho globalRepresentation, arguments []globalFunctionArgument, options ...globalCorrespondenceLimits) (*globalFunctionCorrespondence, error) {
	fail := func(s string) (*globalFunctionCorrespondence, error) { return nil, globalFunctionError(s) }
	if ctx == nil || source.prog == nil || root == nil || image == nil || rho.image == nil || rho.source != source.prog || completed == nil || completed.region == nil || completed.region.packet == nil || completed.prior == nil || completed.returned == nil {
		return fail("missing owned source completion, image or representation")
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
	arguments = slices.Clone(arguments)
	meter := &correspondenceContext{Context: ctx, limit: limit}
	ctx = meter
	b, ok := native.BoundFor(&ownedImage)
	if _, represented := native.BoundFor(rho.image); !ok || !represented || !b.Prefix.ConditionalRegion || b.Prefix.Rules != nativeproof.TransitionRules || b.Prefix.Entry != entry || b.Prefix.Interface.ReturnContext == nil || !b.State.CalleeTerminated || b.State.PC != b.Prefix.Interface.ReturnContext.Target || b.Continuation.PC != b.State.PC || len(b.Prefix.Frames) != 0 || b.State.Thread.ContextChanged {
		return fail("missing actual-entry complete native return under the same image")
	}
	if len(b.Accesses) > 65536 || len(b.Instructions) > 65536 || len(b.State.Memory) > 65536 || len(b.Prefix.InitialMemory) > 65536 {
		return fail("complete projection exceeds finite correspondence bounds")
	}
	p := &globalFunctionCorrespondence{rules: globalFunctionRules, source: completed, native: native, representation: rho, arguments: arguments, antecedent: b.Prefix.EntryPredicate,
		open: computationCorrespondenceObligations{true, true, true, true, true}, limit: limit}
	if err := p.collectSource(ctx, source, root); err != nil {
		return nil, err
	}
	builder := br.NewBuilder(65536)
	if err := p.checkInputs(ctx, builder, source, root, b.Prefix); err != nil {
		return nil, err
	}
	if err := p.checkEffects(ctx, b); err != nil {
		return nil, fmt.Errorf("complete effects: %w", err)
	}
	if err := p.checkFinal(ctx, builder, b); err != nil {
		return nil, fmt.Errorf("returned state: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.work = meter.work
	return p, nil
}

func globalFunctionError(s string) error { return fmt.Errorf("global function correspondence: %s", s) }

func (p *globalFunctionCorrespondence) address(g *ssa.Global) (uint64, bool) {
	for _, binding := range p.representation.globals {
		if binding.global == g {
			return binding.address, true
		}
	}
	return 0, false
}

// Each opaque continuation was checked from precisely its prior current state.
// Collecting oldest first preserves phase order without borrowing native premises
// from any older region correspondence that may have supplied these source phases.
func (p *globalFunctionCorrespondence) collectSource(ctx context.Context, source computationSource, root *ssa.Function) error {
	packet := p.source.region.packet
	if root.Signature.Results().Len() != 0 || len(root.FreeVars) != 0 || packet.rules != regionRules || packet.input.owner != source.prog.Prog || packet.input.root != root || p.source.region.root.function != root || p.source.returned.Parent() != root || len(p.source.returned.Results) != 0 || packet.trace == nil || len(packet.observations) != 1 {
		return globalFunctionError("source is not the selected void root's checked return")
	}
	var chain []*sourceOperandPrefix
	seen := map[*sourceOperandPrefix]bool{}
	for at := p.source.prior; at != nil; at = at.prior {
		if err := ctx.Err(); err != nil {
			return err
		}
		if seen[at] || len(chain) >= 256 || at.region == nil || at.region.packet == nil || at.binder == nil || at.region.packet.rules != regionRules || at.region.packet.input.root != root || at.region.packet.input.owner != source.prog.Prog {
			return globalFunctionError("source continuation chain has a foreign owner or repeated phase")
		}
		seen[at] = true
		chain = append(chain, at)
	}
	slices.Reverse(chain)
	first := chain[0].region.packet
	if first.prefix == nil || first.trace != nil || first.input.entry != (regionPoint{root.Blocks[0], 0}) || len(first.input.initial.memory) != 0 || len(first.input.initial.values) != 0 {
		return globalFunctionError("source does not start at the arbitrary-state root prefix")
	}
	for _, event := range first.prefix.events {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, ok := regionUint64(event.value)
		if !ok {
			return globalFunctionError("prefix effect has no established word")
		}
		p.accesses = append(p.accesses, regionEffectAccess{instruction: event.instruction, global: event.global, write: event.write, value: value})
	}
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
	p.paired = p.antecedent
	scope := br.NewScope()
	variables := map[br.Term]bool{}
	for i, binding := range p.representation.globals {
		if err := ctx.Err(); err != nil {
			return err
		}
		g := binding.global
		if g == nil || g.Pkg == nil || g.Pkg.Prog != source.prog.Prog || source.prog.Prog.Package(g.Pkg.Pkg) != g.Pkg || g.Pkg.Members[g.Name()] != g || binding.address > (1<<47)-8 {
			return globalFunctionError("foreign global or invalid represented extent")
		}
		typ, ok := g.Type().Underlying().(*types.Pointer)
		if !ok || !types.Identical(typ.Elem(), types.Typ[types.Uint64]) || p.source.region.root.pkg.TypesSizes.Sizeof(g.Type()) != 8 || p.source.region.root.pkg.TypesSizes.Sizeof(typ.Elem()) != 8 {
			return globalFunctionError("representation is not selected 64-bit uint64 storage")
		}
		for _, old := range p.representation.globals[:i] {
			if old.global == g || binding.address < old.address+8 && old.address < binding.address+8 {
				return globalFunctionError("represented source objects or native extents alias")
			}
		}
		for _, bound := range b.Interface.EntryWordUpperBounds {
			if binding.address < bound.Address+8 && bound.Address < binding.address+8 {
				return globalFunctionError("administrative entry predicate constrains represented source storage")
			}
		}
		for lane := range 8 {
			var found bool
			for _, cell := range b.InitialMemory {
				if err := ctx.Err(); err != nil {
					return err
				}
				if !cell.Image || cell.Offset != int64(binding.address)+int64(lane) {
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
		initial, err := globalNativeWord(ctx, builder, b.InitialMemory, binding.address)
		if err != nil {
			return err
		}
		input, err := builder.Input(br.Bits(64), scope, uint64(i))
		if err != nil {
			return err
		}
		p.inputs = append(p.inputs, globalFunctionInput{g, input, initial})
		if err := p.pair(builder, input, initial); err != nil {
			return err
		}
	}
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
		input, err := builder.Input(br.Bits(64), scope, uint64(len(p.inputs)+i))
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

func (p *globalFunctionCorrespondence) pair(b *br.Builder, source, native br.Term) error {
	equality, err := b.Make(br.Equal, br.Bool(), 0, source, native)
	if err != nil {
		return err
	}
	p.paired, err = b.Make(br.And, br.Bool(), 0, p.paired, equality)
	return err
}

func globalFunctionIndependent(ctx context.Context, term br.Term, forbidden map[br.Term]bool) error {
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
		for _, arg := range t.View().Args {
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

func (p *globalFunctionCorrespondence) constant(ctx context.Context, actual br.Term, value uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	id          nativeproof.TransitionOccurrenceID
	read, write int
	effect      nativeproof.PrimitiveEffect
}

func globalFunctionNativeGroup(effect nativeproof.PrimitiveEffect) (globalFunctionNativeAtomic, bool) {
	switch e := effect.(type) {
	case nativeproof.LockedCompareExchangeEffect:
		return globalFunctionNativeAtomic{x86asm.CMPXCHG, e.ID, e.ReadAccess, e.WriteAccess, effect}, e.Width == 8
	case nativeproof.LockedExchange64Effect:
		return globalFunctionNativeAtomic{x86asm.XCHG, e.ID, e.ReadAccess, e.WriteAccess, effect}, true
	case nativeproof.LockedExchangeAdd64Effect:
		return globalFunctionNativeAtomic{x86asm.XADD, e.ID, e.ReadAccess, e.WriteAccess, effect}, true
	}
	return globalFunctionNativeAtomic{}, false
}

func (p *globalFunctionCorrespondence) checkEffects(ctx context.Context, b nativeproof.TransitionReturnBound) error {
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
	for primitiveIndex, effect := range b.Prefix.PrimitiveEffects {
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
	for index, abstraction := range b.Prefix.Abstractions {
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
			if !found || read.instruction != group.application.at || write.instruction != read.instruction || read.invocation != write.invocation || read.global != write.global || read.write || !write.write || !read.locked || !write.locked {
				return globalFunctionError("source atomic grouping lost actual call/context/read-write provenance")
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
	known := map[*ssa.Global]uint64{}
	matched := map[int]int{}
	next := 0
	for i, source := range p.accesses {
		if err := ctx.Err(); err != nil {
			return err
		}
		address, represented := p.address(source.global)
		if !represented {
			return globalFunctionError("source access leaves the fixed representation")
		}
		group, atomic := sourceGroups[i]
		if source.locked != atomic {
			return globalFunctionError("source locked access lacks its atomic group")
		}
		kind := nativeproof.FrameRead
		if source.write {
			kind = nativeproof.FrameWrite
		}
		match := false
		if next < len(observable) {
			index := observable[next]
			access := b.Accesses[index]
			nativeGroup, nativeAtomic := nativeGroups[index]
			match = access.Image && access.Bytes == (nativeproof.RelativeSpan{Start: int64(address), End: int64(address + 8)}) && access.Kind == kind && atomic == nativeAtomic
			if atomic {
				match = match && nativeGroup.kind == group.atomic.Kind
			}
			if match {
				if err := p.constant(ctx, access.Value, source.value); err != nil {
					return err
				}
				matched[i] = index
				p.matched = append(p.matched, globalFunctionAccess{i, index})
				next++
			}
		}
		if !match {
			old, established := known[source.global]
			if source.write || source.locked || !established || old != source.value {
				return globalFunctionError("ordered source/native effects differ")
			}
			p.eliminated = append(p.eliminated, i)
		}
		known[source.global] = source.value
	}
	if next != len(observable) {
		return globalFunctionError("native computation has an unmatched effect")
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
			return globalFunctionError("source indivisible group was split across native occurrences")
		}
		p.atomics = append(p.atomics, globalFunctionAtomic{source, group.effect})
	}
	return nil
}

func (p *globalFunctionCorrespondence) administrativeAccess(b nativeproof.TransitionReturnBound, access nativeproof.TransitionAccess) bool {
	if !access.Image {
		if access.Kind == nativeproof.FrameReturnRead && access.Bytes == (nativeproof.RelativeSpan{Start: 0, End: 8}) && access.ID == b.Prefix.Boundary.ID && access.Context == 0 {
			return true
		}
		frame := b.Prefix.Interface.PrivateFrame
		return frame != nil && frame.Bytes.Start < frame.Bytes.End && frame.Bytes.End <= 0 && access.Bytes.Start >= frame.Bytes.Start && access.Bytes.End <= frame.Bytes.End && access.Bytes.Start < access.Bytes.End
	}
	if access.Kind != nativeproof.FrameRead {
		return false
	}
	for _, binding := range p.representation.globals {
		if access.Bytes.Start < int64(binding.address+8) && int64(binding.address) < access.Bytes.End {
			return false
		}
	}
	for _, bound := range b.Prefix.Interface.EntryWordUpperBounds {
		if access.Bytes.Start >= int64(bound.Address) && access.Bytes.End <= int64(bound.Address+8) && access.Bytes.Start < access.Bytes.End {
			return true
		}
	}
	return false
}

func (p *globalFunctionCorrespondence) checkFinal(ctx context.Context, builder *br.Builder, b nativeproof.TransitionReturnBound) error {
	if b.Prefix.Interface.Conditions.SSE != "" && (!b.State.SSE.MXCSRPreserved || !b.State.SSE.UpperVectorsPreserved) {
		return globalFunctionError("floating control or higher vector context was not preserved")
	}
	for _, binding := range p.representation.globals {
		value := readRegionLocation(p.source.region.packet.observations[0].state, regionLocation{object: regionObject{kind: regionGlobal, site: binding.global}}, types.Typ[types.Uint64])
		word, ok := regionUint64(value)
		if !ok {
			return globalFunctionError("final source global has no established value")
		}
		actual, err := globalNativeWord(ctx, builder, b.State.Memory, binding.address)
		if err != nil {
			return err
		}
		if err := p.constant(ctx, actual, word); err != nil {
			return err
		}
	}
	current := map[nativeproof.TransitionLocation]nativeproof.TransitionByte{}
	for _, cell := range b.State.Memory {
		current[cell.TransitionLocation] = cell
	}
	for _, old := range b.Prefix.InitialMemory {
		if err := ctx.Err(); err != nil {
			return err
		}
		private := b.Prefix.Interface.PrivateFrame
		if !old.Image && private != nil && old.Offset >= private.Bytes.Start && old.Offset < private.Bytes.End {
			continue
		}
		represented := false
		for _, binding := range p.representation.globals {
			represented = represented || old.Image && old.Offset >= int64(binding.address) && old.Offset < int64(binding.address+8)
		}
		if represented {
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
		for register, value := range b.State.Registers {
			if nativeproof.Register(register) == nativeproof.RSP || slices.Contains(b.State.Restored, nativeproof.Register(register)) {
				continue
			}
			if pointer, ok := value.Pointer.(nativeproof.OriginPointer); ok && pointer.Offset < 0 {
				return globalFunctionError("private frame pointer escapes in returned context")
			}
			if err := globalFunctionIndependent(ctx, value.Value, map[br.Term]bool{b.Prefix.Origin: true}); err != nil {
				return err
			}
		}
		if b.Prefix.Interface.Conditions.SSE != "" {
			for _, vector := range b.State.Vectors {
				for _, lane := range []br.Term{vector.Lo, vector.Hi} {
					if err := globalFunctionIndependent(ctx, lane, map[br.Term]bool{b.Prefix.Origin: true}); err != nil {
						return fmt.Errorf("private frame address escapes in returned vector: %w", err)
					}
				}
			}
		}
	}
	return nil
}
