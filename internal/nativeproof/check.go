package nativeproof

import (
	"context"
	"fmt"
)

// Check validates a proposal against freshly decoded image bytes and a separately
// selected entry/interface. Changing a proposal cannot enlarge those conditions.
// The caller must keep its proposal stable for this call; the certificate retains
// none of its mutable slices. The image container is captured before any context
// callback; subsequent replacement of that container cannot alter the check or
// certificate. Cancellation returns no certificate.
func Check(ctx context.Context, im *Image, entry uint64, face Interface, p Proposal) (Certificate, error) {
	im = im.snapshot()
	if err := ctx.Err(); err != nil {
		return Certificate{}, err
	}
	if err := validInterface(entry, face); err != nil {
		return Certificate{}, err
	}
	if im == nil || len(im.data) == 0 {
		return Certificate{}, refuse(entry, "image-binding", "missing constructed image")
	}
	if p.Entry != entry || p.Interface != face {
		return Certificate{}, refuse(entry, "proposal-binding", "entry or interface differs")
	}
	g, err := decodeGraph(ctx, im, entry)
	if err != nil {
		return Certificate{}, err
	}
	if err := checkInventory(ctx, g, p.Nodes, "proposal-inventory"); err != nil {
		return Certificate{}, err
	}
	return checkGraph(ctx, im, entry, face, g)
}

// checkInventory validates complete proposed instruction/edge inventories for
// every graph domain. Semantic transfer never consumes proposed successors.
func checkInventory(ctx context.Context, g *graph, nodes []Node, premise string) error {
	return checkContextInventory(ctx, g, nodes, premise, false)
}

func checkContextInventory(ctx context.Context, g *graph, nodes []Node, premise string, transitions bool) error {
	// Zero means missing; otherwise the slot identifies the caller's node plus
	// one. Proposal order is independent of discovery and topological order.
	proposed := make([]int, len(g.nodes))
	var extra map[programPoint]struct{}
	for j, n := range nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !transitions && n.Context != "" {
			return refuse(n.PC, premise, "call-free inventory carries an activation context")
		}
		key := programPoint{n.PC, n.Context}
		index, exists := g.byPoint[key]
		if !exists {
			if _, duplicate := extra[key]; duplicate {
				return g.failureAt(key, refuse(n.PC, premise, "duplicate instruction start"))
			}
			if extra == nil {
				extra = make(map[programPoint]struct{})
			}
			extra[key] = struct{}{}
			continue
		}
		if proposed[index] != 0 {
			return g.failureAt(key, refuse(n.PC, premise, "duplicate instruction start"))
		}
		proposed[index] = j + 1
	}
	for _, index := range g.order {
		if err := ctx.Err(); err != nil {
			return err
		}
		ins := &g.nodes[index]
		pc := ins.pc
		if proposed[index] == 0 {
			return g.failureAt(ins.point(), refuse(pc, premise, "omitted or inconsistent instruction/edge"))
		}
		n := nodes[proposed[index]-1]
		if n.Size != ins.size || len(n.Successors) != int(ins.count) {
			return g.failureAt(ins.point(), refuse(pc, premise, "omitted or inconsistent instruction/edge"))
		}
		for edge, next := range ins.next[:ins.count] {
			if n.Successors[edge] != g.nodes[next].pc {
				return g.failureAt(ins.point(), refuse(pc, premise, "omitted or inconsistent instruction/edge"))
			}
		}
	}
	if len(extra) != 0 {
		entry := g.nodes[0].pc
		return refuse(entry, premise, "unreachable or invented instruction")
	}
	return nil
}

// checkGraph consumes only a graph independently decoded from the privately
// captured image, never a caller-owned inventory. Both conditional frontends use
// this same operand, effect, flag-definedness and preserved-context judgment.
func checkGraph(ctx context.Context, im *Image, entry uint64, face Interface, g *graph) (Certificate, error) {
	// An all-unknown incoming state is legitimate; the initialized bit separates
	// it from a node whose first predecessor has not yet propagated its state.
	type incoming struct {
		value       state
		initialized bool
	}
	states := make([]incoming, len(g.nodes))
	for reg, mask := range face.Inputs {
		states[0].value.regs[reg].defined = mask
	}
	states[0].initialized = true
	b := Bound{ImageDigest: im.digest, Rules: RuleModel, Entry: entry, Interface: face, Instructions: make([]Span, 0, len(g.nodes))}
	for _, index := range g.order {
		if err := ctx.Err(); err != nil {
			return Certificate{}, err
		}
		ins := &g.nodes[index]
		pc := ins.pc
		s := states[index].value
		if err := transfer(pc, ins.inst, &s, face); err != nil {
			return Certificate{}, g.failure(pc, err)
		}
		b.Instructions = append(b.Instructions, Span{pc, pc + uint64(ins.size)})
		for _, next := range ins.next[:ins.count] {
			if states[next].initialized {
				states[next].value = join(states[next].value, s)
			} else {
				states[next] = incoming{value: s, initialized: true}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Certificate{}, err
	}
	return Certificate{&checked{image: im, bound: b}}, nil
}

func validInterface(pc uint64, face Interface) error {
	return validInterfaceAt(pc, face, true)
}

func validInterfaceAt(pc uint64, face Interface, requireReturn bool) error {
	c := face.Conditions
	if c.Machine != MachineModel || !c.InstructionMapping || requireReturn && !c.ReturnSlot || !c.EntryInputs || !c.IsolatedInvocation {
		return refuse(pc, "machine-premises", "all explicit machine, mapping, input, return and isolation conditions are required")
	}
	if face.Inputs[RSP]|face.Results[RSP]|face.Preserved[RSP] != 0 {
		return refuse(pc, "return-interface", "RSP belongs to the return interface")
	}
	return nil
}

func missingBits(pc uint64, reg int, want, have uint64) error {
	return refuse(pc, "result-input-bound", fmt.Sprintf("register %d result bits %#x depend on undeclared entry state", reg, want&^have))
}
