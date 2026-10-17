package closure

import (
	"context"
	"go/constant"
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

type regionKernel struct {
	input       regionInput
	meter       *regionMeter
	session     *regionCallSession
	invocation  regionInvocation
	fullReturns bool
	owned       map[ssa.Value]bool
	cycle       map[*ssa.BasicBlock]bool
	// A site already represented at entry may include an earlier invocation's
	// object. Executing it now must not reset that object's surviving aliases.
	preexisting map[regionObject]bool
	constants   map[*ssa.Const]regionValue
}

// newRegionKernel checks typed ownership and the actual graph, not proposal
// labels. The source loader's SSA/type objects must remain immutable throughout.
func newRegionKernel(ctx context.Context, in regionInput, limits regionLimits) (*regionKernel, error) {
	session := newRegionCallSession(ctx, in, limits)
	return newRegionContextKernel(in, session, regionInvocation{}, false)
}

func newRegionContextKernel(in regionInput, session *regionCallSession, invocation regionInvocation, fullReturns bool) (*regionKernel, error) {
	limits := session.meter.limits
	k := &regionKernel{input: in, meter: session.meter, session: session, invocation: invocation, fullReturns: fullReturns, owned: map[ssa.Value]bool{}, cycle: map[*ssa.BasicBlock]bool{}, preexisting: session.preexisting, constants: map[*ssa.Const]regionValue{}}
	if err := k.meter.tick(); err != nil {
		return nil, err
	}
	fn := in.root
	if in.owner == nil || fn == nil || fn.Prog != in.owner || len(fn.Blocks) == 0 || len(fn.Blocks) > limits.nodes ||
		len(fn.Params) > limits.nodes || len(fn.FreeVars) > limits.nodes || fn.Signature == nil || fn.Signature.TypeParams().Len() != 0 && fn.Origin() == nil || len(in.premises) == 0 {
		return nil, regionError("missing typed owner, concrete root, or explicit entry/frame premises")
	}
	if regionInstruction(in.entry) == nil || in.entry.block.Parent() != fn || !fullReturns && (regionInstruction(in.use.at) == nil || in.use.at.block.Parent() != fn) {
		return nil, regionError("invalid scope instruction boundary")
	}
	if !fullReturns && in.use.operand == nil {
		ret, ok := regionInstruction(in.use.at).(*ssa.Return)
		if !ok || len(ret.Results) != 0 {
			return nil, regionError("missing actual consuming operand")
		}
	}
	for _, parameter := range fn.Params {
		k.owned[parameter] = true
	}
	for _, free := range fn.FreeVars {
		k.owned[free] = true
	}
	blocks := map[*ssa.BasicBlock]bool{}
	for i, block := range fn.Blocks {
		if err := k.meter.tick(); err != nil {
			return nil, err
		}
		if block == nil || block.Parent() != fn || block.Index != i || blocks[block] || len(block.Instrs) == 0 || len(block.Preds) > len(fn.Blocks) || len(block.Succs) > 2 {
			return nil, regionError("invalid block ownership")
		}
		blocks[block] = true
		k.meter.nodes += len(block.Instrs)
		if k.meter.nodes > limits.nodes {
			return nil, regionError("node budget exhausted")
		}
		seenNonPhi := false
		for _, instruction := range block.Instrs {
			if err := k.meter.tick(); err != nil {
				return nil, err
			}
			if instruction == nil || instruction.Block() != block || instruction.Parent() != fn {
				return nil, regionError("invalid instruction ownership")
			}
			if !regionBoundedOperands(instruction, limits.nodes) {
				return nil, regionError("instruction operand budget exhausted")
			}
			if value, ok := instruction.(ssa.Value); ok {
				k.owned[value] = true
			}
			if phi, ok := instruction.(*ssa.Phi); ok {
				if seenNonPhi || len(phi.Edges) != len(block.Preds) {
					return nil, regionError("phi does not cover actual predecessors")
				}
			} else {
				seenNonPhi = true
			}
		}
	}
	if !blocks[in.entry.block] || !fullReturns && !blocks[in.use.at.block] {
		return nil, regionError("scope outside root")
	}
	if !fullReturns && in.use.operand != nil {
		found := false
		for _, operand := range regionInstruction(in.use.at).Operands(nil) {
			found = found || operand != nil && *operand == in.use.operand
		}
		if !found {
			return nil, regionError("claimed value is not the actual consuming operand")
		}
	}
	for _, block := range fn.Blocks {
		for _, pair := range []struct {
			edges   []*ssa.BasicBlock
			forward bool
		}{{block.Succs, true}, {block.Preds, false}} {
			seen := map[*ssa.BasicBlock]bool{}
			for _, edge := range pair.edges {
				if !blocks[edge] || seen[edge] {
					return nil, regionError("invalid or duplicate CFG edge")
				}
				seen[edge] = true
				back := edge.Succs
				if pair.forward {
					back = edge.Preds
				}
				if !slices.Contains(back, block) {
					return nil, regionError("CFG edge lacks reverse predecessor")
				}
			}
		}
		for i, instruction := range block.Instrs {
			for _, operand := range instruction.Operands(nil) {
				if operand != nil {
					if c, ok := (*operand).(*ssa.Const); ok && c.Value == nil && !c.IsNil() {
						if _, exists := k.constants[c]; !exists {
							zero, err := k.zero(c.Type(), 0)
							if err != nil {
								return nil, err
							}
							k.constants[c] = zero
						}
					}
				}
				if operand != nil && *operand != nil && !k.owns(*operand) {
					return nil, regionError("operand is outside typed owner")
				}
			}
			last := i == len(block.Instrs)-1
			switch instruction.(type) {
			case *ssa.If:
				if !last || len(block.Succs) != 2 {
					return nil, regionError("invalid branch successors")
				}
			case *ssa.Jump:
				if !last || len(block.Succs) != 1 {
					return nil, regionError("invalid jump successor")
				}
			case *ssa.Return, *ssa.Panic:
				if !last || len(block.Succs) != 0 {
					return nil, regionError("invalid terminal successors")
				}
			default:
				if last {
					return nil, regionError("missing terminal instruction")
				}
			}
		}
		// A bounded graph search proves whether this site's allocation can recur.
		// This is a cost-bounded structural check, not execution unrolling.
		seen := map[*ssa.BasicBlock]bool{}
		queue := slices.Clone(block.Succs)
		for len(queue) != 0 {
			if err := k.meter.tick(); err != nil {
				return nil, err
			}
			next := queue[0]
			queue = queue[1:]
			if next == block {
				k.cycle[block] = true
				break
			}
			if seen[next] {
				continue
			}
			seen[next] = true
			queue = append(queue, next.Succs...)
		}
	}
	// A mid-block entry is a genuine scope cut, not permission to skip that
	// prefix again when a backedge returns to the block.
	if in.entry.index != 0 && k.cycle[in.entry.block] {
		return nil, regionError("mid-block entry has a backedge")
	}
	info := session.contexts[invocation]
	info.function = fn
	info.cycle = k.cycle
	session.contexts[invocation] = info
	if err := k.validateState(in.initial); err != nil {
		return nil, err
	}
	var remember func(regionValue)
	remember = func(v regionValue) {
		if v.kind == regionPointer || v.kind == regionSlice {
			if !session.completed[v.location.object.invocation.root] {
				k.preexisting[v.location.object] = true
			}
		}
		for _, list := range [][]regionValue{v.elements, v.environment} {
			for _, item := range list {
				remember(item)
			}
		}
	}
	if !fullReturns {
		for object, value := range in.initial.memory {
			if !session.completed[object.invocation.root] {
				k.preexisting[object] = true
			}
			remember(value)
		}
		for _, value := range in.initial.values {
			remember(value)
		}
	}
	return k, nil
}

// Bound variadic operand containers before SSA's Operands method allocates its
// projection. The remaining SSA instructions have fixed, small operand counts.
func regionBoundedOperands(instruction ssa.Instruction, limit int) bool {
	switch x := instruction.(type) {
	case *ssa.Phi:
		return len(x.Edges) <= limit
	case *ssa.MakeClosure:
		return len(x.Bindings) < limit
	case *ssa.Call:
		return len(x.Call.Args) < limit
	case *ssa.Go:
		return len(x.Call.Args) < limit
	case *ssa.Defer:
		return len(x.Call.Args) < limit
	case *ssa.Return:
		return len(x.Results) <= limit
	case *ssa.Select:
		return len(x.States) <= limit/2
	}
	return true
}

func (k *regionKernel) owns(v ssa.Value) bool {
	if v == nil {
		return false
	}
	if k.owned[v] {
		return true
	}
	switch x := v.(type) {
	case *ssa.Const:
		if x == nil || x.Type() == nil {
			return false
		}
		_, zero := k.constants[x]
		if x.Value != nil && x.Value.Kind() == constant.String && len(constant.StringVal(x.Value)) > k.meter.limits.locations {
			return false
		}
		return zero || x.IsNil() || regionScalarConstant(x.Type(), x.Value)
	case *ssa.Builtin:
		return x != nil && x.Type() != nil
	case *ssa.Global:
		return x != nil && x.Type() != nil && x.Pkg != nil && x.Pkg.Prog == k.input.owner && k.input.owner.Package(x.Pkg.Pkg) == x.Pkg && x.Pkg.Members[x.Name()] == x
	case *ssa.Function:
		return x != nil && x.Prog == k.input.owner && x.Signature != nil
	}
	return false
}

func (k *regionKernel) objectType(o regionObject) types.Type {
	switch o.kind {
	case regionGlobal:
		g, ok := o.site.(*ssa.Global)
		if !ok || g == nil || !k.owns(g) || o.context != nil || o.invocation != (regionInvocation{}) {
			return nil
		}
	case regionAllocation:
		a, ok := o.site.(*ssa.Alloc)
		if !ok || a == nil || a.Parent() != o.context || o.context == nil || o.context.Prog != k.input.owner || a.Block() == nil || !slices.Contains(a.Block().Instrs, ssa.Instruction(a)) {
			return nil
		}
	case regionFormal:
		switch site := o.site.(type) {
		case *ssa.Parameter:
			if site == nil {
				return nil
			}
		case *ssa.FreeVar:
			if site == nil {
				return nil
			}
		default:
			return nil
		}
		if o.context == nil || o.context.Prog != k.input.owner || o.site.Parent() != o.context {
			return nil
		}
		switch site := o.site.(type) {
		case *ssa.Parameter:
			if !slices.Contains(o.context.Params, site) {
				return nil
			}
		case *ssa.FreeVar:
			if !slices.Contains(o.context.FreeVars, site) {
				return nil
			}
		}
	default:
		return nil
	}
	p, ok := o.site.Type().Underlying().(*types.Pointer)
	if !ok {
		return nil
	}
	return p.Elem()
}

func (k *regionKernel) locationType(loc regionLocation) types.Type {
	t := k.objectType(loc.object)
	for _, step := range loc.path {
		if t == nil {
			return nil
		}
		if step.field {
			s, ok := t.Underlying().(*types.Struct)
			if !ok || step.summary || step.index < 0 || step.index >= int64(s.NumFields()) {
				return nil
			}
			t = s.Field(int(step.index)).Type()
		} else {
			a, ok := t.Underlying().(*types.Array)
			if !ok || !step.summary && (step.index < 0 || step.index >= a.Len()) {
				return nil
			}
			t = a.Elem()
		}
	}
	return t
}

func (k *regionKernel) validateState(s regionState) error {
	for key, value := range s.values {
		if !k.owned[key] || !types.Identical(key.Type(), value.typ) {
			return regionError("invalid typed register invariant")
		}
		if err := k.validateValue(value, 0); err != nil {
			return err
		}
	}
	for object, value := range s.memory {
		if !types.Identical(k.objectType(object), value.typ) {
			return regionError("invalid typed memory invariant")
		}
		if err := k.validateValue(value, 0); err != nil {
			return err
		}
	}
	return nil
}

func (k *regionKernel) validateValue(v regionValue, depth int) error {
	if err := k.meter.tick(); err != nil {
		return err
	}
	if depth > k.meter.limits.depth || v.typ == nil {
		return regionError("invalid value type/depth")
	}
	hasLocation := v.location.object != (regionObject{}) || len(v.location.path) != 0
	if v.scalar != nil && v.kind != regionConstant || hasLocation && v.kind != regionPointer && v.kind != regionSlice && v.kind != regionCallable ||
		(v.start != 0 || v.length != 0 || v.capacity != 0) && v.kind != regionSlice || v.target != nil && v.kind != regionCallable ||
		len(v.environment) != 0 && v.kind != regionCallable || len(v.elements) != 0 && v.kind != regionAggregate && v.kind != regionInterface {
		return regionError("noncanonical value payload")
	}
	// Child types are proposer input too. Validate them before invoking type
	// predicates on them; notably AssignableTo requires a nonnil source type.
	for _, list := range [][]regionValue{v.elements, v.environment} {
		for _, item := range list {
			if err := k.validateValue(item, depth+1); err != nil {
				return err
			}
		}
	}
	valid := false
	switch v.kind {
	case regionUnknown:
		valid = true
	case regionConstant:
		valid = regionScalarConstant(v.typ, v.scalar)
		if valid && v.scalar.Kind() == constant.String && len(constant.StringVal(v.scalar)) > k.meter.limits.locations {
			return regionError("constant storage budget exhausted")
		}
	case regionNil:
		switch v.typ.Underlying().(type) {
		case *types.Pointer, *types.Slice, *types.Signature, *types.Interface, *types.Map, *types.Chan:
			valid = true
		}
	case regionPointer:
		p, ok := v.typ.Underlying().(*types.Pointer)
		valid = ok && regionAccessType(k.locationType(v.location), p.Elem())
	case regionSlice:
		s, ok := v.typ.Underlying().(*types.Slice)
		t := k.locationType(v.location)
		if ok && t != nil {
			a, ok := t.Underlying().(*types.Array)
			valid = ok && types.Identical(s.Elem(), a.Elem()) && v.start >= 0 && v.length >= 0 && v.capacity >= v.length && v.start <= a.Len() && v.capacity <= a.Len()-v.start
		}
	case regionCallable:
		valid = v.target != nil && k.owns(v.target) && types.Identical(v.typ.Underlying(), v.target.Type().Underlying()) && len(v.environment) == len(v.target.FreeVars)
		if hasLocation {
			site, ok := v.location.object.site.(*ssa.MakeClosure)
			valid = valid && ok && site != nil && v.location.object.kind == regionClosureEnvironment && len(v.location.path) == 0 && site.Parent() == v.location.object.context && site.Parent() != nil && site.Parent().Prog == k.input.owner && site.Fn == v.target && slices.Contains(site.Block().Instrs, ssa.Instruction(site))
		} else if len(v.environment) != 0 {
			valid = false
		}
		if valid {
			for i, item := range v.environment {
				if !types.Identical(item.typ, v.target.FreeVars[i].Type()) {
					valid = false
				}
			}
		}
	case regionInterface:
		_, ok := v.typ.Underlying().(*types.Interface)
		valid = ok && len(v.elements) == 1 && types.AssignableTo(v.elements[0].typ, v.typ)
	case regionAggregate:
		switch t := v.typ.Underlying().(type) {
		case *types.Struct:
			valid = len(v.elements) == t.NumFields()
			if valid {
				for i, item := range v.elements {
					if !types.Identical(item.typ, t.Field(i).Type()) {
						valid = false
					}
				}
			}
		case *types.Array:
			valid = int64(len(v.elements)) == t.Len()
			if valid {
				for _, item := range v.elements {
					if !types.Identical(item.typ, t.Elem()) {
						valid = false
					}
				}
			}
		case *types.Tuple:
			valid = len(v.elements) == t.Len()
			if valid {
				for i, item := range v.elements {
					if !types.Identical(item.typ, t.At(i).Type()) {
						valid = false
					}
				}
			}
		}
	}
	if !valid {
		return regionError("invalid typed region value")
	}
	return nil
}

// checkRegion snapshots the complete independent input and proposal before any
// callback. It checks edge inclusion, not equality with a proposer execution.
func checkRegion(ctx context.Context, input regionInput, proposal *regionProposal, limits regionLimits) (*checkedRegion, error) {
	in, p, err := regionCapture(input, proposal, limits)
	if err != nil {
		return nil, err
	}
	k, err := newRegionKernel(ctx, in, limits)
	if err != nil {
		return nil, err
	}
	return checkRegionKernel(k, p)
}

func checkRegionKernel(k *regionKernel, p *regionProposal) (*checkedRegion, error) {
	in := k.input
	if p == nil || p.input.owner != in.owner || p.input.root != in.root || p.input.entry != in.entry || p.input.use != in.use || !slices.Equal(p.input.premises, in.premises) {
		return nil, regionError("proposal is not bound to the complete input")
	}
	k.session.proofs = p.calls
	if err := k.validateState(p.input.initial); err != nil {
		return nil, err
	}
	for _, pair := range [][2]regionState{{in.initial, p.input.initial}, {p.input.initial, in.initial}} {
		same, err := k.included(pair[0], pair[1])
		if err != nil {
			return nil, err
		}
		if !same {
			return nil, regionError("proposal initial premise differs from input")
		}
	}
	observations, err := k.checkEntries(p.entries)
	if err != nil {
		return nil, err
	}
	if err := k.meter.ctx.Err(); err != nil {
		return nil, err
	}
	return &checkedRegion{rules: regionRules, input: in, observations: observations, calls: k.session.used}, nil
}

func (k *regionKernel) checkEntries(entries map[*ssa.BasicBlock][]regionState) ([]regionObservation, error) {
	in := k.input
	for block, states := range entries {
		if block == nil || block.Parent() != in.root || !slices.Contains(in.root.Blocks, block) || len(states) == 0 {
			return nil, regionError("invalid invariant block")
		}
		for _, state := range states {
			if err := k.validateState(state); err != nil {
				return nil, err
			}
		}
	}
	covered, err := k.covered(in.initial, entries[in.entry.block])
	if err != nil {
		return nil, err
	}
	if !covered {
		return nil, regionError("entry invariant omits initial states")
	}
	var observations []regionObservation
	seen := map[*ssa.BasicBlock]bool{}
	queue := []*ssa.BasicBlock{in.entry.block}
	for len(queue) != 0 {
		block := queue[0]
		queue = queue[1:]
		if seen[block] {
			continue
		}
		seen[block] = true
		states := entries[block]
		if len(states) == 0 {
			return nil, regionError("reachable block invariant omitted")
		}
		for _, state := range states {
			edges, outcomes, err := k.block(block, state)
			if err != nil {
				return nil, err
			}
			observations = append(observations, outcomes...)
			for _, edge := range edges {
				covered, err := k.covered(edge.state, entries[edge.block])
				if err != nil {
					return nil, err
				}
				if !covered {
					return nil, regionError("actual edge/backedge or phi transfer not included")
				}
				queue = append(queue, edge.block)
			}
		}
	}
	if len(seen) != len(entries) || len(observations) == 0 {
		return nil, regionError("unused invariant or consuming use is unreachable")
	}
	if err := k.meter.ctx.Err(); err != nil {
		return nil, err
	}
	return observations, nil
}

type regionEdge struct {
	block *ssa.BasicBlock
	state regionState
}

// Lattice comparisons are part of the work budget too. Charge every recursive
// term visited before the bounded structural equality test; an adversarial
// invariant cannot hide work inside a join or an inclusion check.
func (k *regionKernel) chargeValue(v regionValue) error {
	if err := k.meter.tick(); err != nil {
		return err
	}
	for _, list := range [][]regionValue{v.elements, v.environment} {
		for _, item := range list {
			if err := k.chargeValue(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func (k *regionKernel) included(a, b regionState) (bool, error) {
	for key, value := range b.values {
		if err := k.chargeValue(value); err != nil {
			return false, err
		}
		actual, ok := a.values[key]
		if !ok {
			actual = regionUnknownValue(key.Type())
		}
		if !regionValueIncluded(actual, value) {
			return false, nil
		}
	}
	for object, value := range b.memory {
		if err := k.chargeValue(value); err != nil {
			return false, err
		}
		actual, ok := a.memory[object]
		if !ok {
			actual = regionUnknownValue(value.typ)
		}
		if !regionValueIncluded(actual, value) {
			return false, nil
		}
	}
	return true, k.meter.tick()
}

func (k *regionKernel) covered(state regionState, invariant []regionState) (bool, error) {
	for _, candidate := range invariant {
		included, err := k.included(state, candidate)
		if err != nil || included {
			return included, err
		}
	}
	return false, nil
}

func (k *regionKernel) join(states []regionState, state regionState) ([]regionState, bool, error) {
	covered, err := k.covered(state, states)
	if err != nil || covered {
		return states, false, err
	}
	joined := make([]regionState, 0, len(states)+1)
	for _, old := range states {
		included, err := k.included(old, state)
		if err != nil {
			return nil, false, err
		}
		if !included {
			joined = append(joined, old)
		}
	}
	if len(joined) >= k.meter.limits.alternatives {
		return []regionState{{}}, true, nil
	}
	return append(joined, state), true, nil
}

func (k *regionKernel) value(s regionState, value ssa.Value) regionValue {
	switch v := value.(type) {
	case *ssa.Const:
		if zero, ok := k.constants[v]; ok {
			return zero
		}
		return regionConst(v)
	case *ssa.Global:
		return regionValue{typ: v.Type(), kind: regionPointer, location: regionLocation{object: regionObject{kind: regionGlobal, site: v}}}
	case *ssa.Function:
		if len(v.FreeVars) == 0 {
			return regionValue{typ: v.Type(), kind: regionCallable, target: v}
		}
	}
	if v, ok := s.values[value]; ok {
		return v
	}
	return regionUnknownValue(value.Type())
}

func (k *regionKernel) clone(s regionState) (regionState, error) {
	// State terms are immutable after capture; transfers copy only maps and the
	// changed aggregate spine. Charge their full size before allocating the maps.
	if err := k.meter.tick(); err != nil {
		return regionState{}, err
	}
	k.meter.states++
	if k.meter.states > k.meter.limits.states || len(s.values)+len(s.memory) > k.meter.limits.locations {
		return regionState{}, regionError("state/location budget exhausted")
	}
	r := regionState{values: make(map[ssa.Value]regionValue, len(s.values)), memory: make(map[regionObject]regionValue, len(s.memory))}
	for key, v := range s.values {
		if err := k.meter.tick(); err != nil {
			return regionState{}, err
		}
		r.values[key] = v
	}
	for key, v := range s.memory {
		if err := k.meter.tick(); err != nil {
			return regionState{}, err
		}
		r.memory[key] = v
	}
	return r, nil
}

func (k *regionKernel) block(block *ssa.BasicBlock, initial regionState) ([]regionEdge, []regionObservation, error) {
	s, err := k.clone(initial)
	if err != nil {
		return nil, nil, err
	}
	start := 0
	if block == k.input.entry.block {
		start = k.input.entry.index
	}
	states := []regionState{s}
	for index := start; index < len(block.Instrs); index++ {
		if err := k.meter.tick(); err != nil {
			return nil, nil, err
		}
		var edges []regionEdge
		var observations []regionObservation
		var continuing []regionState
		for _, s := range states {
			if !k.fullReturns && block == k.input.use.at.block && index == k.input.use.at.index {
				var value regionValue
				if k.input.use.operand != nil {
					value = k.value(s, k.input.use.operand)
				}
				observations = append(observations, regionObservation{value: value, state: s})
				continue
			}
			instruction := block.Instrs[index]
			switch x := instruction.(type) {
			case *ssa.Phi:
				// Assigned simultaneously on the actual predecessor edge below.
				continuing = append(continuing, s)
			case *ssa.Jump, *ssa.If:
				for i, successor := range block.Succs {
					if branch, ok := instruction.(*ssa.If); ok {
						if b, known := regionBool(k.value(s, branch.Cond)); known && b != (i == 0) {
							continue
						}
					}
					next, err := k.clone(s)
					if err != nil {
						return nil, nil, err
					}
					if branch, ok := instruction.(*ssa.If); ok {
						if _, known := regionBool(k.value(s, branch.Cond)); !known {
							// The condition itself is an immutable SSA value. Retain the
							// selected edge's Boolean fact, without inventing relations
							// between an unmodeled comparison's operands.
							next.values[branch.Cond] = regionValue{typ: branch.Cond.Type(), kind: regionConstant, scalar: constant.MakeBool(i == 0)}
						}
					}
					pred := slices.Index(successor.Preds, block)
					if pred < 0 {
						return nil, nil, regionError("missing actual phi predecessor")
					}
					for _, ins := range successor.Instrs {
						phi, ok := ins.(*ssa.Phi)
						if !ok {
							break
						}
						if pred >= len(phi.Edges) {
							return nil, nil, regionError("missing actual phi edge")
						}
						next.values[phi] = k.value(s, phi.Edges[pred])
					}
					edges = append(edges, regionEdge{block: successor, state: next})
				}
			case *ssa.Return:
				if !k.fullReturns {
					return nil, nil, &regionOperationFailure{instruction, regionError("terminal path is outside the named use boundary")}
				}
				value, err := k.returnValue(x, s)
				if err != nil {
					return nil, nil, &regionOperationFailure{instruction, err}
				}
				observations = append(observations, regionObservation{value: value, state: s})
			case *ssa.Call:
				if _, builtin := x.Call.Value.(*ssa.Builtin); builtin {
					if err := k.transfer(&s, x); err != nil {
						return nil, nil, &regionOperationFailure{instruction, err}
					}
					continuing = append(continuing, s)
				} else {
					returned, err := k.call(x, s)
					if err != nil {
						return nil, nil, &regionOperationFailure{instruction, err}
					}
					for _, after := range returned {
						var err error
						continuing, _, err = k.join(continuing, after)
						if err != nil {
							return nil, nil, err
						}
					}
				}
			default:
				if err := k.transfer(&s, x); err != nil {
					return nil, nil, &regionOperationFailure{instruction, err}
				}
				continuing = append(continuing, s)
			}
		}
		if len(edges) != 0 || len(observations) != 0 {
			return edges, observations, nil
		}
		states = continuing
	}
	return nil, nil, regionError("scope has no terminal transfer")
}

func (k *regionKernel) zero(t types.Type, depth int) (regionValue, error) {
	if err := k.meter.tick(); err != nil {
		return regionValue{}, err
	}
	k.meter.locations++
	if depth > k.meter.limits.depth || k.meter.locations > k.meter.limits.locations {
		return regionValue{}, regionError("zero-value budget exhausted")
	}
	v := regionValue{typ: t}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		v.kind = regionConstant
		switch {
		case u.Info()&types.IsBoolean != 0:
			v.scalar = constant.MakeBool(false)
		case u.Info()&types.IsString != 0:
			v.scalar = constant.MakeString("")
		case u.Info()&types.IsInteger != 0:
			v.scalar = constant.MakeInt64(0)
		default:
			return regionValue{}, regionError("unsupported zero scalar")
		}
	case *types.Pointer, *types.Slice, *types.Signature, *types.Interface, *types.Map, *types.Chan:
		v.kind = regionNil
	case *types.Struct:
		if u.NumFields() > k.meter.limits.locations-k.meter.locations {
			return regionValue{}, regionError("aggregate budget exhausted")
		}
		v.kind = regionAggregate
		v.elements = make([]regionValue, u.NumFields())
		for i := range v.elements {
			z, err := k.zero(u.Field(i).Type(), depth+1)
			if err != nil {
				return regionValue{}, err
			}
			v.elements[i] = z
		}
	case *types.Array:
		if u.Len() > int64(k.meter.limits.locations-k.meter.locations) {
			return regionValue{}, regionError("array budget exhausted")
		}
		v.kind = regionAggregate
		v.elements = make([]regionValue, int(u.Len()))
		for i := range v.elements {
			z, err := k.zero(u.Elem(), depth+1)
			if err != nil {
				return regionValue{}, err
			}
			v.elements[i] = z
		}
	default:
		return regionValue{}, regionError("unsupported zero type")
	}
	return v, nil
}

func (k *regionKernel) singleton(object regionObject) bool {
	if object.kind == regionGlobal {
		return true
	}
	a, ok := object.site.(*ssa.Alloc)
	info, derived := k.session.contexts[object.invocation]
	return object.kind == regionAllocation && ok && derived && object.context == info.function && !info.repeated && !info.cycle[a.Block()] && !k.preexisting[object]
}

func regionReplace(v regionValue, path []regionStep, value regionValue) regionValue {
	if len(path) == 0 {
		return value
	}
	step := path[0]
	if step.summary || v.kind != regionAggregate || step.index < 0 || step.index >= int64(len(v.elements)) {
		return regionUnknownValue(v.typ)
	}
	v.elements = slices.Clone(v.elements)
	v.elements[step.index] = regionReplace(v.elements[step.index], path[1:], value)
	return v
}

func (k *regionKernel) transfer(s *regionState, instruction ssa.Instruction) error {
	set := func(value ssa.Value, result regionValue) error {
		if !types.Identical(value.Type(), result.typ) {
			return regionError("instruction result type mismatch")
		}
		if len(s.values)+len(s.memory) >= k.meter.limits.locations {
			return regionError("location budget exhausted")
		}
		if err := k.validateValue(result, 0); err != nil {
			return err
		}
		s.values[value] = result
		return nil
	}
	get := func(value ssa.Value) regionValue { return k.value(*s, value) }
	switch x := instruction.(type) {
	case *ssa.DebugRef:
		return nil
	case *ssa.Alloc:
		p, ok := x.Type().Underlying().(*types.Pointer)
		if !ok {
			return regionError("allocation is not typed storage")
		}
		object := regionObject{kind: regionAllocation, site: x, context: k.input.root, invocation: k.invocation}
		v := regionUnknownValue(p.Elem())
		if k.singleton(object) {
			var err error
			v, err = k.zero(p.Elem(), 0)
			if err != nil {
				return err
			}
		}
		// A summary site's fresh object must not reset its earlier instances.
		// Top includes both their contents and the new zero object.
		s.memory[object] = v
		return set(x, regionValue{typ: x.Type(), kind: regionPointer, location: regionLocation{object: object}})
	case *ssa.FieldAddr:
		v := get(x.X)
		if v.kind != regionPointer {
			return regionError("field address has unknown/nil base")
		}
		v.typ = x.Type()
		v.location.path = append(slices.Clone(v.location.path), regionStep{field: true, index: int64(x.Field)})
		if len(v.location.path) > k.meter.limits.depth || k.locationType(v.location) == nil {
			return regionError("invalid field address")
		}
		return set(x, v)
	case *ssa.IndexAddr:
		v := get(x.X)
		index, known := regionInt(get(x.Index))
		if !known || index < 0 {
			return regionError("unknown/negative array index")
		}
		var bound int64
		if v.kind == regionSlice {
			bound = v.length
			index += v.start
		} else if v.kind == regionPointer {
			t := k.locationType(v.location)
			if t == nil {
				return regionError("unknown indexed object")
			}
			a, ok := t.Underlying().(*types.Array)
			if !ok {
				return regionError("indexed pointer is not an array")
			}
			bound = a.Len()
		} else {
			return regionError("index address has unknown/nil base")
		}
		if v.kind == regionSlice {
			if index-v.start >= bound {
				return regionError("slice index may panic")
			}
		} else if index >= bound {
			return regionError("array index may panic")
		}
		loc := v.location
		loc.path = append(slices.Clone(loc.path), regionStep{index: index})
		if len(loc.path) > k.meter.limits.depth {
			return regionError("location depth exhausted")
		}
		return set(x, regionValue{typ: x.Type(), kind: regionPointer, location: loc})
	case *ssa.Store:
		addr := get(x.Addr)
		if addr.kind != regionPointer {
			return regionError("unknown/nil write has no checked frame")
		}
		t := k.locationType(addr.location)
		v := get(x.Val)
		pointer, ok := addr.typ.Underlying().(*types.Pointer)
		if !ok || !types.Identical(pointer.Elem(), v.typ) || !regionAccessType(t, pointer.Elem()) {
			return regionError("store type mismatch")
		}
		v, ok = regionViewValue(v, t)
		if !ok {
			return regionError("store has no supported storage view")
		}
		// Formal regions may alias any selected object. A write through one
		// invalidates the whole heap; a concrete write invalidates every formal
		// view of it. No implicit disjointness premise is inferred from names.
		if addr.location.object.kind == regionFormal {
			clear(s.memory)
			return nil
		}
		for object := range s.memory {
			if object.kind == regionFormal || object.kind == regionUnknownObject {
				delete(s.memory, object)
			}
		}
		old, ok := s.memory[addr.location.object]
		if !ok {
			old = regionUnknownValue(k.objectType(addr.location.object))
		}
		if k.singleton(addr.location.object) {
			s.memory[addr.location.object] = regionReplace(old, addr.location.path, v)
		} else {
			// A weak store joins the old and updated whole object. The exact
			// equal-term case retains all old/new possibilities without granting
			// singleton ownership. Other joins still widen to top.
			if err := k.chargeValue(old); err != nil {
				return err
			}
			updated := regionReplace(old, addr.location.path, v)
			if regionSameValue(old, updated) {
				s.memory[addr.location.object] = old
			} else {
				s.memory[addr.location.object] = regionUnknownValue(old.typ)
			}
		}
		return nil
	case *ssa.UnOp:
		v := get(x.X)
		if x.Op == token.MUL {
			if v.kind != regionPointer {
				return regionError("unknown/nil load may panic")
			}
			return set(x, readRegionLocation(*s, v.location, x.Type()))
		}
		if x.Op == token.NOT {
			if b, known := regionBool(v); known {
				return set(x, regionValue{typ: x.Type(), kind: regionConstant, scalar: constant.MakeBool(!b)})
			}
			return set(x, regionUnknownValue(x.Type()))
		}
		return regionError("unsupported unary transfer")
	case *ssa.Slice:
		v := get(x.X)
		text, stringBase := regionString(v)
		var length, capacity, start int64
		if stringBase {
			if x.Max != nil {
				return regionError("three-index string slice is not a Go operation")
			}
			length, capacity = int64(len(text)), int64(len(text))
		} else if v.kind == regionPointer {
			t := k.locationType(v.location)
			if t == nil {
				return regionError("unknown slice backing")
			}
			a, ok := t.Underlying().(*types.Array)
			if !ok {
				return regionError("slice backing is not array")
			}
			length, capacity = a.Len(), a.Len()
		} else if v.kind == regionSlice {
			length, capacity = v.length, v.capacity
			start = v.start
		} else {
			return regionError("unsupported slice base")
		}
		bound := func(value ssa.Value, fallback int64) (int64, bool) {
			if value == nil {
				return fallback, true
			}
			return regionInt(get(value))
		}
		low, a := bound(x.Low, 0)
		high, b := bound(x.High, length)
		max, c := bound(x.Max, capacity)
		if !a || !b || !c || low < 0 || low > high || high > max || max > capacity {
			return regionError("slice bounds may panic")
		}
		if stringBase {
			return set(x, regionValue{typ: x.Type(), kind: regionConstant, scalar: constant.MakeString(text[low:high])})
		}
		return set(x, regionValue{typ: x.Type(), kind: regionSlice, location: v.location, start: start + low, length: high - low, capacity: max - low})
	case *ssa.Field:
		v := get(x.X)
		if v.kind == regionAggregate && x.Field >= 0 && x.Field < len(v.elements) {
			return set(x, v.elements[x.Field])
		}
		return set(x, regionUnknownValue(x.Type()))
	case *ssa.Index:
		v := get(x.X)
		index, known := regionInt(get(x.Index))
		if !known || index < 0 {
			return regionError("unknown value index")
		}
		if text, ok := regionString(v); ok {
			if index >= int64(len(text)) {
				return regionError("string index may panic")
			}
			return set(x, regionValue{typ: x.Type(), kind: regionConstant, scalar: constant.MakeInt64(int64(text[index]))})
		}
		if v.kind != regionAggregate || index >= int64(len(v.elements)) {
			return regionError("value index may panic")
		}
		return set(x, v.elements[index])
	case *ssa.MakeClosure:
		target, ok := x.Fn.(*ssa.Function)
		if !ok || !k.owns(target) || len(x.Bindings) != len(target.FreeVars) {
			return regionError("unbound closure context")
		}
		v := regionValue{typ: x.Type(), kind: regionCallable, target: target, location: regionLocation{object: regionObject{kind: regionClosureEnvironment, site: x, context: k.input.root, invocation: k.invocation}}}
		for _, binding := range x.Bindings {
			v.environment = append(v.environment, get(binding))
		}
		return set(x, v)
	case *ssa.MakeInterface:
		return set(x, regionValue{typ: x.Type(), kind: regionInterface, elements: []regionValue{get(x.X)}})
	case *ssa.ChangeInterface:
		v := get(x.X)
		if v.kind != regionInterface && v.kind != regionNil {
			return set(x, regionUnknownValue(x.Type()))
		}
		v.typ = x.Type()
		return set(x, v)
	case *ssa.Extract:
		v := get(x.Tuple)
		if v.kind == regionAggregate && x.Index >= 0 && x.Index < len(v.elements) {
			return set(x, v.elements[x.Index])
		}
		return set(x, regionUnknownValue(x.Type()))
	case *ssa.ChangeType:
		if !types.Identical(x.Type().Underlying(), x.X.Type().Underlying()) && !regionPointerChange(x.X.Type(), x.Type()) {
			return regionError("unsupported representation change")
		}
		v := get(x.X)
		v.typ = x.Type()
		return set(x, v)
	case *ssa.BinOp:
		if !regionIsComparison(x.Op) {
			return regionError("unsupported numeric transfer")
		}
		a, b := get(x.X), get(x.Y)
		if x.Op == token.EQL || x.Op == token.NEQ {
			if equal, known := regionNilEquality(a, b); known {
				return set(x, regionValue{typ: x.Type(), kind: regionConstant, scalar: constant.MakeBool(equal == (x.Op == token.EQL))})
			}
			if equal, known := k.pointerEquality(a, b); known {
				return set(x, regionValue{typ: x.Type(), kind: regionConstant, scalar: constant.MakeBool(equal == (x.Op == token.EQL))})
			}
			if a.kind != regionNil && b.kind != regionNil {
				total, err := k.equalityTotal(x.X.Type(), true, 0, map[types.Type]bool{})
				if err != nil {
					return err
				}
				if !total {
					return regionError("equality has no proof against dynamic-comparison panic")
				}
			}
		}
		if a.kind == regionConstant && b.kind == regionConstant {
			return set(x, regionValue{typ: x.Type(), kind: regionConstant, scalar: constant.MakeBool(constant.Compare(a.scalar, x.Op, b.scalar))})
		}
		return set(x, regionUnknownValue(x.Type()))
	case *ssa.Call:
		builtin, ok := x.Call.Value.(*ssa.Builtin)
		if !ok || x.Call.IsInvoke() || len(x.Call.Args) != 1 || builtin.Name() != "len" && builtin.Name() != "cap" {
			return regionError("call effects, callbacks and continuation are unproved")
		}
		v := get(x.Call.Args[0])
		var n int64
		if basic, ok := v.typ.Underlying().(*types.Basic); ok && basic.Info()&types.IsString != 0 && builtin.Name() == "len" {
			text, known := regionString(v)
			if !known {
				// len is total even when the string is unknown. No bound on
				// that unknown value is inferred for a later slice or index.
				return set(x, regionUnknownValue(x.Type()))
			}
			n = int64(len(text))
		} else if v.kind == regionSlice {
			n = v.length
			if builtin.Name() == "cap" {
				n = v.capacity
			}
		} else if v.kind == regionNil {
			switch v.typ.Underlying().(type) {
			case *types.Slice:
			default:
				return regionError("unsupported nil builtin operand")
			}
		} else {
			return regionError("unknown builtin operand")
		}
		return set(x, regionValue{typ: x.Type(), kind: regionConstant, scalar: constant.MakeInt64(n)})
	case *ssa.Go:
		return regionError("goroutine capture has open invocation, concurrency and continuation effects")
	case *ssa.Defer, *ssa.RunDefers:
		return regionError("deferred capture has open invocation and continuation effects")
	default:
		return regionError("unsupported instruction transfer")
	}
}

// equalityTotal establishes that equality cannot panic before its result is
// widened to an unknown Boolean. Static Go comparability is not enough: an
// interface anywhere in a compared aggregate can hold an incomparable value.
// Zero-length arrays and blank fields perform no dynamic comparisons, but their
// types must still be statically comparable. Pointers/channels compare identity,
// never their referents. The active set and shared limits bound by-value walks.
func (k *regionKernel) equalityTotal(t types.Type, compared bool, depth int, active map[types.Type]bool) (bool, error) {
	if err := k.meter.tick(); err != nil {
		return false, err
	}
	if t == nil || depth > k.meter.limits.depth {
		return false, regionError("equality type/depth budget exhausted")
	}
	if active[t] {
		return false, regionError("recursive by-value equality type is unproved")
	}
	active[t] = true
	defer delete(active, t)
	if _, parameter := t.(*types.TypeParam); parameter {
		return false, nil
	}
	switch typ := t.Underlying().(type) {
	case *types.Basic:
		return typ.Kind() != types.Invalid && typ.Kind() != types.UntypedNil, nil
	case *types.Pointer, *types.Chan:
		return true, nil
	case *types.Interface:
		return !compared, nil
	case *types.Array:
		return k.equalityTotal(typ.Elem(), compared && typ.Len() != 0, depth+1, active)
	case *types.Struct:
		if typ.NumFields() > k.meter.limits.nodes {
			return false, regionError("equality field budget exhausted")
		}
		for i := 0; i < typ.NumFields(); i++ {
			field := typ.Field(i)
			total, err := k.equalityTotal(field.Type(), compared && field.Name() != "_", depth+1, active)
			if err != nil || !total {
				return total, err
			}
		}
		return true, nil
	default:
		return false, nil
	}
}
