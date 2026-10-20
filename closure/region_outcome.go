package closure

import "github.com/greatliontech/go-x-tools/go/ssa"

// The excluded continuation is retained as normal-return-only evidence. It
// grants no effect bound for the instructions or callbacks on that outcome.
type regionExcludedContinuation struct {
	invocation   regionInvocation
	at           regionPoint
	nilMapUpdate bool
}

func (k *regionKernel) excludeContinuation(at regionPoint, nilMapUpdate bool) error {
	if err := k.meter.tick(); err != nil {
		return err
	}
	if k.session.exceptional == nil {
		k.session.exceptional = map[regionExcludedContinuation]bool{}
	}
	point := regionExcludedContinuation{k.invocation, at, nilMapUpdate}
	if !k.session.exceptional[point] && len(k.session.exceptional) >= k.meter.limits.nodes {
		return regionError("exceptional continuation budget exhausted")
	}
	k.session.exceptional[point] = true
	return nil
}

// noNormalExit checks a finite, acyclic ordinary continuation ending only in
// language panic. A call supplies no frame: its effects, callbacks, divergence
// and exceptional outcomes are arbitrary. If it returns, its actual successor
// still cannot return from this invocation. Context validation separately refuses
// deferred recovery and concurrency. A cycle is not evidence of nonreturn.
func (k *regionKernel) noNormalExit(at regionPoint) (bool, error) {
	if k.terminal == nil {
		k.terminal = map[*ssa.BasicBlock]bool{}
	}
	active := map[*ssa.BasicBlock]bool{}
	var visit func(regionPoint) (bool, error)
	visit = func(p regionPoint) (bool, error) {
		if err := k.meter.tick(); err != nil {
			return false, err
		}
		if active[p.block] {
			return false, nil
		}
		if result, known := k.terminal[p.block]; known {
			return result, nil
		}
		active[p.block] = true
		defer delete(active, p.block)
		// Validated SSA has no intra-block control transfer. Context validation
		// has already refused deferred and concurrent control throughout the body.
		switch p.block.Instrs[len(p.block.Instrs)-1].(type) {
		case *ssa.Panic:
			k.terminal[p.block] = true
			return true, nil
		case *ssa.Return, *ssa.Defer, *ssa.RunDefers, *ssa.Go:
			k.terminal[p.block] = false
			return false, nil
		}
		if len(p.block.Succs) == 0 {
			return false, nil
		}
		for _, next := range p.block.Succs {
			yes, err := visit(regionPoint{next, 0})
			if err != nil || !yes {
				k.terminal[p.block] = false
				return false, err
			}
		}
		k.terminal[p.block] = true
		return true, nil
	}
	return visit(at)
}
