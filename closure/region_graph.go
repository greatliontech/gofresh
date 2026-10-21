package closure

import (
	"go/token"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// Facts belong to the immutable, independently validated typed owner. Sharing
// them does not share invocation cardinality, entry premises or checked results.
type regionFunctionFacts struct {
	owned     map[ssa.Value]bool
	cycle     map[*ssa.BasicBlock]bool
	constants map[*ssa.Const]regionValue
	last      map[ssa.Value]ssa.Instruction
	uses      map[ssa.Value][]ssa.Instruction
}

// A stack-shaped allocation is activation-local only when every actual use
// stays in its address/load/store tree. Heap flags do not supply this proof.
func (k *regionKernel) privateAllocation(a *ssa.Alloc) bool {
	seen := map[ssa.Value]bool{}
	var visit func(ssa.Value) bool
	visit = func(v ssa.Value) bool {
		if seen[v] {
			return true
		}
		seen[v] = true
		if k.meter.tick() != nil {
			return false
		}
		for _, use := range k.session.functions[a.Parent()].uses[v] {
			if k.meter.tick() != nil {
				return false
			}
			switch x := use.(type) {
			case *ssa.FieldAddr:
				if x.X != v || !visit(x) {
					return false
				}
			case *ssa.IndexAddr:
				if x.X != v || !visit(x) {
					return false
				}
			case *ssa.UnOp:
				if x.Op != token.MUL || x.X != v {
					return false
				}
			case *ssa.Store:
				if x.Addr != v || x.Val == v {
					return false
				}
			case *ssa.DebugRef:
			default:
				return false
			}
		}
		return true
	}
	return visit(a)
}

func (k *regionKernel) regionLocalLast(fn *ssa.Function) (map[ssa.Value]ssa.Instruction, map[ssa.Value][]ssa.Instruction, error) {
	last := map[ssa.Value]ssa.Instruction{}
	uses := map[ssa.Value][]ssa.Instruction{}
	positions := map[ssa.Instruction]int{}
	for _, block := range fn.Blocks {
		for i, ins := range block.Instrs {
			if err := k.meter.tick(); err != nil {
				return nil, nil, err
			}
			positions[ins] = i
			for _, op := range ins.Operands(nil) {
				if err := k.meter.tick(); err != nil {
					return nil, nil, err
				}
				if op != nil && *op != nil {
					// Parameters, constants, globals and function values are never
					// candidates for instruction liveness or local allocation escape.
					if value, local := (*op).(ssa.Instruction); local && value.Parent() == fn {
						if k.meter.locations >= k.meter.limits.locations {
							return nil, nil, regionError("operand use index storage budget exhausted")
						}
						k.meter.locations++
						uses[*op] = append(uses[*op], ins)
					}
				}
			}
		}
	}
	for _, block := range fn.Blocks {
		for _, ins := range block.Instrs {
			if err := k.meter.tick(); err != nil {
				return nil, nil, err
			}
			v, ok := ins.(ssa.Value)
			if !ok {
				continue
			}
			{
				end := ins
				index := positions[ins]
				local := true
				for _, ref := range uses[v] {
					if err := k.meter.tick(); err != nil {
						return nil, nil, err
					}
					if ref.Block() != block {
						local = false
						break
					}
					i := positions[ref]
					if i > index {
						index = i
						end = ref
					}
				}
				if local {
					last[v] = end
				}
			}
		}
	}
	return last, uses, nil
}

func (k *regionKernel) dropLocalValues(s *regionState, ins ssa.Instruction) error {
	if !k.input.normalReturns {
		return nil
	}
	last := k.session.functions[k.input.root].last
	for _, operand := range ins.Operands(nil) {
		if err := k.meter.tick(); err != nil {
			return err
		}
		if operand != nil && last[*operand] == ins {
			delete(s.values, *operand)
		}
	}
	if v, ok := ins.(ssa.Value); ok && last[v] == ins {
		delete(s.values, v)
	}
	return nil
}

// Forget unreachable facts, never infer deallocation or freshness. Values hidden
// in abstract map payloads can only be recovered as unknown by this domain.
func (k *regionKernel) trimHeap(s *regionState) error {
	if !k.input.normalReturns {
		return nil
	}
	seen := map[regionObject]bool{}
	var visit func(regionValue) error
	visit = func(v regionValue) error {
		if err := k.meter.tick(); err != nil {
			return err
		}
		if regionObjectReference(v) {
			o := v.location.object
			if !seen[o] {
				seen[o] = true
				if value, ok := s.memory[o]; ok {
					if err := visit(value); err != nil {
						return err
					}
				}
			}
		}
		for _, list := range [][]regionValue{v.elements, v.environment} {
			for _, child := range list {
				if err := visit(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, v := range s.values {
		if err := visit(v); err != nil {
			return err
		}
	}
	for _, roots := range k.session.suspended {
		for _, v := range roots {
			if err := visit(v); err != nil {
				return err
			}
		}
	}
	for object, v := range s.memory {
		if object.kind == regionGlobal {
			seen[object] = true
			if err := visit(v); err != nil {
				return err
			}
		}
	}
	for object := range s.memory {
		if !seen[object] {
			delete(s.memory, object)
		}
	}
	return nil
}

func (k *regionKernel) findCycles() error {
	indices, low := map[*ssa.BasicBlock]int{}, map[*ssa.BasicBlock]int{}
	on := map[*ssa.BasicBlock]bool{}
	var stack []*ssa.BasicBlock
	next := 0
	var visit func(*ssa.BasicBlock) error
	visit = func(b *ssa.BasicBlock) error {
		if err := k.meter.tick(); err != nil {
			return err
		}
		next++
		indices[b], low[b] = next, next
		stack = append(stack, b)
		on[b] = true
		for _, succ := range b.Succs {
			if err := k.meter.tick(); err != nil {
				return err
			}
			if indices[succ] == 0 {
				if err := visit(succ); err != nil {
					return err
				}
				low[b] = min(low[b], low[succ])
			} else if on[succ] {
				low[b] = min(low[b], indices[succ])
			}
		}
		if low[b] == indices[b] {
			var component []*ssa.BasicBlock
			for {
				v := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				on[v] = false
				component = append(component, v)
				if v == b {
					break
				}
			}
			cyclic := len(component) > 1
			for _, succ := range b.Succs {
				cyclic = cyclic || succ == b
			}
			if cyclic {
				for _, v := range component {
					k.cycle[v] = true
				}
			}
		}
		return nil
	}
	for _, block := range k.input.root.Blocks {
		if indices[block] == 0 {
			if err := visit(block); err != nil {
				return err
			}
		}
	}
	return nil
}
