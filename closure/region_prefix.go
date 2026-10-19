package closure

import (
	"context"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// regionPrefixEffects is a finite, ordered effect relation produced alongside
// the existing transfers. Its grammar is deliberately restricted to straight-line
// uint64 global loads/stores and debug markers. Calls (even empty ones), implicit
// allocations, branches and unknown effects cannot disappear into endpoint values.
type regionPrefixEffects struct {
	events []regionPrefixAccess
}

type regionPrefixAccess struct {
	instruction ssa.Instruction
	global      *ssa.Global
	write       bool
	value       regionValue
}

type sourceOperandPrefix struct {
	region   *sourceRegion
	callee   selectedSourceDeclaration
	call     *ssa.Call
	operands []regionValue
	prior    *sourceOperandPrefix
	binder   *selectedSourceBinder
}

// checkSourceOperandPrefix owns the complete selected root but checks execution
// only up to the actual call's operand boundary. The empty initial heap denotes
// arbitrary prior values; no initialization or expected output enters the proof.
// Unused pointer parameters remain arbitrary and supply no storage or effects.
func checkSourceOperandPrefix(ctx context.Context, source computationSource, root *ssa.Function, call *ssa.Call, limits registrationLimits) (*sourceOperandPrefix, error) {
	if ctx == nil || !limits.region.valid() || root == nil || call == nil || len(root.Blocks) == 0 || root.Blocks[0] == nil || len(root.Blocks[0].Instrs) > limits.region.nodes || len(root.Params) > limits.region.nodes || len(root.FreeVars) != 0 || call.Parent() != root || call.Block() != root.Blocks[0] || call.Call.IsInvoke() || call.Call.StaticCallee() == nil || len(call.Call.Args) == 0 || len(call.Call.Args) > limits.region.nodes {
		return nil, regionError("operand prefix requires a concrete root and actual direct call boundary")
	}
	at := -1
	for i, ins := range root.Blocks[0].Instrs {
		if ins == call {
			at = i
			break
		}
	}
	if at < 0 {
		return nil, regionError("operand call is not in the actual root")
	}
	in := regionInput{owner: root.Prog, root: root, entry: regionPoint{root.Blocks[0], 0},
		use:      regionUse{at: regionPoint{root.Blocks[0], at}, operand: call.Call.Args[0]},
		premises: []string{"immutable selected typed owner; isolated prefix; ordinary live typed global storage; omitted native prefix and actual use remain open"}}
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
	newKernel := func(input regionInput) (*regionKernel, error) {
		session := newRegionCallSession(ctx, input, limits.region)
		session.meter = meter
		return newRegionContextKernel(input, session, regionInvocation{}, false)
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
	if k.cycle[in.entry.block] || len(p.entries) != 1 || len(p.entries[in.entry.block]) != 1 {
		return nil, regionError("operand prefix requires one straight-line entry state")
	}
	k.prefix = &regionPrefixEffects{}
	packet, err := checkRegionKernel(k, p)
	if err != nil {
		return nil, err
	}
	if len(packet.observations) != 1 || len(packet.calls) != 0 {
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
	return &sourceOperandPrefix{region: selected, callee: callee, call: call, operands: operands, binder: b}, nil
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

// prefixTransfer records operands from the same pre-state that transfer consumes.
// No event is evidence unless that transfer and the complete region check succeed.
func (k *regionKernel) prefixTransfer(s regionState, ins ssa.Instruction) error {
	if err := k.meter.tick(); err != nil {
		return err
	}
	var address ssa.Value
	e := regionPrefixAccess{instruction: ins}
	switch x := ins.(type) {
	case *ssa.DebugRef:
		return nil
	case *ssa.Store:
		address, e.write, e.value = x.Addr, true, k.value(s, x.Val)
	case *ssa.UnOp:
		if x.Op != token.MUL {
			return regionError("operand prefix supports only typed loads and stores")
		}
		address = x.X
	default:
		return regionError("operand prefix has an intervening operation or call")
	}
	p := k.value(s, address)
	g, err := k.effectGlobal(p)
	if err != nil {
		return err
	}
	if g.Pkg != k.input.root.Pkg {
		return regionError("operand prefix access is not exact uint64 global storage")
	}
	e.global = g
	if !e.write {
		e.value = readRegionLocation(s, p.location, types.Typ[types.Uint64])
	}
	if len(k.prefix.events) >= k.meter.limits.nodes {
		return regionError("operand prefix effect budget exhausted")
	}
	k.prefix.events = append(k.prefix.events, e)
	return nil
}
