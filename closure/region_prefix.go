package closure

import (
	"context"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// sourceEffectPrefix owns an actual unexecuted instruction boundary and its
// checked current state. It is independent of call-specific operand evidence.
type sourceEffectPrefix struct {
	cursor   regionEffectOccurrence
	region   *sourceRegion
	prior    *sourceEffectPrefix
	binder   *selectedSourceBinder
	checker  *regionKernel
	boundary ssa.Instruction
	self     *sourceEffectPrefix
}

type sourceOperandPrefix struct {
	*sourceEffectPrefix
	callee   selectedSourceDeclaration
	call     *ssa.Call
	operands []regionValue
	self     *sourceOperandPrefix
}

// Completed returns deliberately do not implement this interface. Authenticate
// the dynamic receipt before extracting its common continuation state.
type sourceResumablePrefix interface {
	resumableSourcePrefix()
}

func (*sourceEffectPrefix) resumableSourcePrefix()  {}
func (*sourceOperandPrefix) resumableSourcePrefix() {}

func checkedSourcePrefix(prefix sourceResumablePrefix) *sourceEffectPrefix {
	switch p := prefix.(type) {
	case *sourceOperandPrefix:
		if p.checkedPacket() != nil {
			return p.sourceEffectPrefix
		}
	case *sourceEffectPrefix:
		if p.checkedPacket() != nil {
			return p
		}
	}
	return nil
}

func regionCallBoundaryOperand(call *ssa.Call) ssa.Value {
	if len(call.Call.Args) != 0 {
		return call.Call.Args[0]
	}
	return call.Call.Value
}

// The retained interpreter belongs to this exact checked source cut. A heap
// projection or a checker for another cut is not a continuation capability.
func (p *sourceOperandPrefix) checkedPacket() *checkedRegion {
	if p == nil || p.self != p || p.call == nil || p.sourceEffectPrefix.checkedPacket() == nil || p.boundary != p.call {
		return nil
	}
	return p.region.packet
}

func (p *sourceEffectPrefix) checkedPacket() *checkedRegion {
	if p == nil || p.self != p || p.checker == nil || p.region == nil || p.region.packet == nil || p.binder == nil || p.binder.source.prog == nil {
		return nil
	}
	packet := checkedSourceEffectPacket(p.region, p.checker)
	if packet == nil || p.checker.fullReturns || p.prior != p.checker.session.predecessor || p.boundary == nil || len(packet.observations) != 1 || p.cursor != packet.observations[0].occurrence || p.cursor != p.checker.boundaryOccurrence(p.boundary) || p.cursor.owner == nil || packet.trace.seen[p.cursor] || regionInstruction(packet.input.use.at) != p.boundary || p.binder.source.prog.Prog != packet.input.owner || packet.input.selection != p.binder.source.prog || packet.input.storageModel != conditionalRegionStorageModel() ||
		p.prior != nil && (p.prior.checkedPacket() == nil || p.prior.region.packet.input.unwind != packet.input.unwind || p.prior.region.packet.input.pendingAntecedent != packet.input.pendingAntecedent || !slices.Equal(p.prior.region.packet.input.premises, packet.input.premises) || p.prior.region.packet.input.storageModel != packet.input.storageModel || p.prior.region.packet.input.selection != packet.input.selection || p.prior.cursor.owner != p.cursor.owner) {
		return nil
	}
	return packet
}

func checkedSourceEffectPacket(region *sourceRegion, checker *regionKernel) *checkedRegion {
	if region == nil || region.packet == nil || checker == nil || checker.session == nil {
		return nil
	}
	packet, input := region.packet, checker.input
	if packet.input.normalReturns || input.normalReturns {
		return nil
	}
	if packet.rules != regionRules || packet.trace == nil || packet.trace.owner == nil || checker.trace != packet.trace || input.unwind != packet.input.unwind || input.pendingAntecedent != packet.input.pendingAntecedent || !slices.Equal(input.premises, packet.input.premises) || input.owner != packet.input.owner || input.selection != packet.input.selection || input.root != packet.input.root || input.entry != packet.input.entry || input.use != packet.input.use || input.storageModel != packet.input.storageModel || region.root.function != input.root {
		return nil
	}
	return packet
}

// liveAllocation derives a retained singleton from the checked allocation event,
// context and current heap. A copied heap or allocation-shaped identity supplies
// none of this evidence. tick charges the consuming operation's work account.
// Continuations also seed their occurrence guard from this same predecessor chain.
func (p *sourceOperandPrefix) liveAllocation(object regionObject, tick func() error) (regionEffectAllocation, bool, error) {
	packet := p.checkedPacket()
	if packet == nil {
		return regionEffectAllocation{}, false, nil
	}
	return liveRegionAllocation(packet, p.checker, p.prior, object, tick)
}

func (p *sourceEffectPrefix) liveAllocation(object regionObject, tick func() error) (regionEffectAllocation, bool, error) {
	packet := p.checkedPacket()
	if packet == nil {
		return regionEffectAllocation{}, false, nil
	}
	return liveRegionAllocation(packet, p.checker, p.prior, object, tick)
}

// Both operand cuts and completed returns use the same checked current heap and
// occurrence chain. A completed return retains resident contents; this lookup
// neither ends a lifetime nor supplies an escape or native-byte relation.
func liveRegionAllocation(packet *checkedRegion, checker *regionKernel, prior *sourceEffectPrefix, object regionObject, tick func() error) (regionEffectAllocation, bool, error) {
	if object.kind != regionAllocation || !checker.singleton(object) {
		return regionEffectAllocation{}, false, nil
	}
	if len(packet.observations) != 1 {
		return regionEffectAllocation{}, false, nil
	}
	if _, present := packet.observations[0].state.memory[object]; !present {
		return regionEffectAllocation{}, false, nil
	}
	for {
		if err := tick(); err != nil {
			return regionEffectAllocation{}, false, err
		}
		trace := packet.trace
		for _, allocation := range trace.allocations {
			if err := tick(); err != nil {
				return regionEffectAllocation{}, false, err
			}
			if allocation.location.object == object && trace.seen[allocation.regionEffectOccurrence] {
				return allocation, true, nil
			}
		}
		if prior == nil {
			break
		}
		packet = prior.checkedPacket()
		if packet == nil {
			return regionEffectAllocation{}, false, nil
		}
		prior = prior.prior
	}
	return regionEffectAllocation{}, false, nil
}

// checkSourceOperandPrefix owns the complete selected root but checks execution
// only up to the actual call's operand boundary. The empty initial heap denotes
// arbitrary prior global values; local initialization comes from actual checked
// allocations, never a caller's proposed heap or expected output.
// Unused pointer parameters remain arbitrary and supply no storage or effects.
// An optional unwind scope is an explicit conditional entry antecedent, not
// evidence that the omitted caller or startup established ordinary invocation.
func checkSourceOperandPrefix(ctx context.Context, source computationSource, root *ssa.Function, call *ssa.Call, limits registrationLimits, scope ...regionUnwindScope) (*sourceOperandPrefix, error) {
	if ctx == nil || !limits.region.valid() || root == nil || call == nil || len(root.Blocks) == 0 || root.Blocks[0] == nil || len(root.Blocks[0].Instrs) > limits.region.nodes || len(root.Params) > limits.region.nodes || len(root.FreeVars) != 0 || call.Parent() != root || call.Block() == nil || call.Call.IsInvoke() || call.Call.StaticCallee() == nil || len(call.Call.Args) > limits.region.nodes {
		return nil, regionError("operand prefix requires a concrete root and actual direct call boundary")
	}
	at := slices.Index(call.Block().Instrs, ssa.Instruction(call))
	if at < 0 {
		return nil, regionError("operand call is not in the actual root")
	}
	in := regionInput{owner: root.Prog, selection: source.prog, root: root, entry: regionPoint{root.Blocks[0], 0},
		storageModel: conditionalRegionStorageModel(),
		use:          regionUse{at: regionPoint{call.Block(), at}, operand: regionCallBoundaryOperand(call)},
		premises:     []string{"immutable selected typed owner; isolated prefix; ordinary live typed storage; omitted native prefix and actual use remain open"}}
	if len(scope) > 1 {
		return nil, regionError("multiple unwind scopes")
	}
	if len(scope) == 1 {
		in.unwind = scope[0]
	}
	meter := &regionMeter{ctx: ctx, limits: limits.region}
	for _, parameter := range root.Params {
		if err := checkUnusedSourcePointer(root, parameter, meter.tick); err != nil {
			return nil, err
		}
	}
	in, _, err := regionCaptureMeter(in, nil, meter)
	if err != nil {
		return nil, err
	}
	owner := &regionOccurrenceOwner{}
	newKernel := func(input regionInput) (*regionKernel, error) {
		session := newRegionCallSession(ctx, input, limits.region)
		session.meter = meter
		session.source = source
		k, err := newRegionContextKernel(input, session, regionInvocation{}, false)
		if err == nil {
			k.trace = &regionEffectTrace{owner: owner, seen: map[regionEffectOccurrence]bool{}}
		}
		return k, err
	}
	proposer, err := newKernel(in)
	if err != nil {
		return nil, err
	}
	p, err := proposeRegionKernel(proposer)
	if err != nil {
		return nil, err
	}
	in, p, err = regionCaptureMeter(in, p, meter)
	if err != nil {
		return nil, err
	}
	k, err := newKernel(in)
	if err != nil {
		return nil, err
	}
	packet, err := checkRegionKernel(k, p)
	if err != nil {
		return nil, err
	}
	if len(packet.observations) != 1 {
		return nil, regionError("operand prefix has unaccounted paths or calls")
	}
	b, err := newSelectedSourceBinder(ctx, source, root, limits.source)
	if err != nil {
		return nil, err
	}
	selected, err := b.checkSourceRegion(packet)
	if err != nil {
		return nil, err
	}
	callee, err := b.bindDeclaration(call.Call.StaticCallee())
	if err != nil {
		return nil, err
	}
	var operands []regionValue
	for _, arg := range call.Call.Args {
		v := k.value(packet.observations[0].state, arg)
		if err := k.validateValue(v, 0); err != nil {
			return nil, err
		}
		operands = append(operands, v)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	packet.usage = *meter
	packet.usage.ctx = nil
	core := &sourceEffectPrefix{region: selected, binder: b, checker: k, boundary: call, cursor: packet.observations[0].occurrence}
	core.self = core
	prefix := &sourceOperandPrefix{sourceEffectPrefix: core, callee: callee, call: call, operands: operands}
	prefix.self = prefix
	return prefix, nil
}

// checkUnusedSourcePointer checks the actual whole-root operand inventory, not
// referrer metadata or only the prefix. Even a use in an excluded arm is outside
// this deliberately bounded unused-argument grammar. Debug markers are inert.
func checkUnusedSourcePointer(root *ssa.Function, parameter *ssa.Parameter, tick func() error) error {
	if _, ok := parameter.Type().Underlying().(*types.Pointer); !ok {
		return regionError("unused root argument is not a typed pointer")
	}
	for _, block := range root.Blocks {
		for _, ins := range block.Instrs {
			if err := tick(); err != nil {
				return err
			}
			if _, debug := ins.(*ssa.DebugRef); debug {
				continue
			}
			for _, operand := range ins.Operands(nil) {
				if operand != nil && *operand == parameter {
					return regionError("pointer parameter is used by source computation")
				}
			}
		}
	}
	return nil
}
