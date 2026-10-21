package closure

import (
	"context"
	"go/token"
	"go/types"
	"maps"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// Contexts contain only checked immutable entry/scope facts. A resumed frame
// borrows these facts without re-running activation initialization or treating
// its current allocations as incoming, possibly earlier instances.
type activationContext struct {
	input       regionInput
	invocation  regionInvocation
	fullReturns bool
	owned       map[ssa.Value]bool
	cycle       map[*ssa.BasicBlock]bool
	constants   map[*ssa.Const]regionValue
	sizes       types.Sizes
}

func activationContextOf(k *regionKernel) *activationContext {
	in := k.input
	in.initial = regionState{}
	return &activationContext{in, k.invocation, k.fullReturns, k.owned, k.cycle, k.constants, k.sizes}
}
func (c *activationContext) kernel(s *regionCallSession) *regionKernel {
	return &regionKernel{input: c.input, invocation: c.invocation, fullReturns: c.fullReturns, owned: c.owned, cycle: c.cycle, constants: c.constants, sizes: c.sizes, session: s, meter: s.meter, preexisting: s.preexisting}
}

type activationPhase uint8

const (
	activationExecute activationPhase = iota
	activationUnwind
	activationAwaitCall
	activationAwaitDefer
	activationDeliver
	activationPanicAlternative
	activationStopAlternative
)

// Control is checker-created. next is an ordinary successor only in Execute or
// AwaitCall, or the post-RunDefers successor of an ordinary Unwind. A recovered
// unwind instead enters the actual SSA Recover block.
type activationControl struct {
	phase     activationPhase
	at        regionPoint
	next      regionPoint
	call      *ssa.Call
	reason    *regionActivationPanic
	recovered bool
	result    regionActivationOutcome
}
type activationFrame struct {
	context  *activationContext
	values   map[ssa.Value]regionValue
	pending  regionDeferStack
	eligible *regionActivationPanic
	consumed bool
	depth    int
	control  activationControl
}
type activationJob struct {
	heap   map[regionObject]regionValue
	frames []activationFrame
}

func (j *activationJob) top() *activationFrame { return &j.frames[len(j.frames)-1] }
func (j *activationJob) state() regionState {
	f := j.top()
	return regionState{values: f.values, memory: j.heap, pending: f.pending}
}
func (j *activationJob) install(s regionState) {
	f := j.top()
	f.values, f.pending, j.heap = s.values, s.pending, s.memory
}

type activationSnapshot struct {
	input       regionActivationInput
	root        *activationContext
	work        []activationJob
	frontiers   []activationJob
	outcomes    []regionActivationOutcome
	events      []regionActivationEvent
	calls       []regionActivationCall
	contexts    map[regionInvocation]regionContextFacts
	functions   map[*ssa.Function]regionFunctionFacts
	preexisting map[regionObject]bool
	transitions uint64
	usage       regionMeter
}
type activationMachine struct {
	activationSnapshot
	session  *regionCallSession
	checking bool
	proposed []regionActivationEvent
	cursor   int
}

func newActivationMachine(in regionActivationInput, k *regionKernel) (*activationMachine, error) {
	c := activationContextOf(k)
	s, err := k.clone(k.input.initial)
	if err != nil {
		return nil, err
	}
	j := activationJob{heap: s.memory, frames: []activationFrame{{context: c, values: s.values, pending: s.pending, control: activationControl{phase: activationExecute, at: k.input.entry}}}}
	return &activationMachine{activationSnapshot: activationSnapshot{input: in, root: c, work: []activationJob{j}}, session: k.session}, nil
}

// State terms and completed captures are immutable. Copy the mutable maps and
// frame spine, charging the existing shared clone operation for each frame and
// the one current heap. No saved frame owns a stale second heap.
func cloneActivationJob(j activationJob, meter *regionMeter) (activationJob, error) {
	if len(j.frames) == 0 || len(j.frames) > meter.limits.depth {
		return activationJob{}, regionError("activation frame budget exhausted")
	}
	k := &regionKernel{meter: meter}
	s, err := k.clone(regionState{memory: j.heap})
	if err != nil {
		return activationJob{}, err
	}
	result := activationJob{heap: s.memory, frames: slices.Clone(j.frames)}
	for i := range result.frames {
		f := &result.frames[i]
		s, err := k.clone(regionState{values: f.values, pending: f.pending})
		if err != nil {
			return activationJob{}, err
		}
		f.values, f.pending = s.values, s.pending
	}
	return result, nil
}

func continueActivation(ctx context.Context, prior *checkedRegionActivation, stop uint64, proposal *regionActivationProposal) (*activationMachine, *regionActivationProposal, error) {
	if !prior.authenticated() {
		return nil, nil, regionError("missing authenticated activation predecessor")
	}
	s := *prior.snapshot
	if len(s.work) == 0 || stop != 0 && stop <= s.transitions {
		return nil, nil, regionError("activation continuation cannot advance this frontier")
	}
	meter := s.usage
	meter.ctx = nil
	in, p, err := captureActivationMeter(s.input, proposal, &meter)
	if err != nil {
		return nil, nil, err
	}
	if p != nil && (p.predecessor != prior || p.offset != len(s.events) || p.stop != stop) {
		return nil, nil, regionError("activation continuation predecessor or offset differs")
	}
	s.input = in
	s.work = slices.Clone(s.work)
	s.frontiers = slices.Clone(s.frontiers)
	for _, jobs := range [][]activationJob{s.work, s.frontiers} {
		for i := range jobs {
			jobs[i], err = cloneActivationJob(jobs[i], &meter)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	s.events = slices.Clone(s.events)
	s.calls = slices.Clone(s.calls)
	s.outcomes = slices.Clone(s.outcomes)
	for i := range s.outcomes {
		if s.outcomes[i].kind != activationStopped {
			s.outcomes[i].state.store, err = (&regionKernel{meter: &meter}).clone(s.outcomes[i].state.store)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	s.contexts = maps.Clone(s.contexts)
	s.functions = maps.Clone(s.functions)
	s.preexisting = maps.Clone(s.preexisting)
	for range len(s.events) + len(s.calls) + len(s.outcomes) + len(s.contexts) + len(s.functions) + len(s.preexisting) {
		if err := meter.tick(); err != nil {
			return nil, nil, err
		}
	}
	if ctx == nil {
		return nil, nil, regionError("missing activation continuation context")
	}
	meter.ctx = ctx
	session := newRegionCallSession(ctx, in.regionInput(), meter.limits)
	session.meter, session.contexts, session.functions, session.preexisting = &meter, s.contexts, s.functions, s.preexisting
	m := &activationMachine{activationSnapshot: s, session: session}
	if p != nil {
		if err := sameActivationInput(s.root.kernel(session), in, p.input); err != nil {
			return nil, nil, err
		}
	}
	return m, p, nil
}

func (m *activationMachine) publish() (*checkedRegionActivation, error) {
	s := m.activationSnapshot
	s.contexts, s.functions, s.preexisting = m.session.contexts, m.session.functions, m.session.preexisting
	// Inspection fields are owned projections, never aliases of the authenticated
	// payload. In particular, copying an aggregate value must not let a consumer
	// rewrite the checked outcome by modifying its elements or a recovered payload.
	meter := *m.session.meter
	meter.keyCopies, meter.stringCopies, meter.stringAtoms = nil, nil, nil
	input, _, err := captureActivationMeter(s.input, nil, &meter)
	if err != nil {
		return nil, err
	}
	outcomes := slices.Clone(s.outcomes)
	for i := range outcomes {
		out := &outcomes[i]
		if out.kind != activationStopped {
			out.state.store, err = meter.copyState(out.state.store)
			if err != nil {
				return nil, err
			}
		}
		if out.value.typ != nil {
			out.value, err = meter.copyValue(out.value, 0)
			if err != nil {
				return nil, err
			}
		}
		if out.panic != nil {
			p := *out.panic
			p.payload, err = meter.copyValue(p.payload, 0)
			if err != nil {
				return nil, err
			}
			out.panic = &p
		}
	}
	for range len(s.events) + len(s.calls) + len(s.outcomes) {
		if err := meter.tick(); err != nil {
			return nil, err
		}
	}
	s.usage = meter
	s.usage.ctx, s.usage.keyCopies, s.usage.stringCopies, s.usage.stringAtoms = nil, nil, nil, nil
	p := &checkedRegionActivation{rules: regionActivationRules, input: input, events: slices.Clone(s.events), outcomes: outcomes, calls: slices.Clone(s.calls), usage: s.usage, snapshot: &s}
	p.self = p
	return p, nil
}

func (m *activationMachine) run(stop uint64) error {
	if stop > uint64(m.session.meter.limits.nodes) {
		return regionError("activation stop exceeds bounded transition inventory")
	}
	for len(m.work) != 0 && (stop == 0 || m.transitions < stop) {
		if err := m.session.meter.tick(); err != nil {
			return err
		}
		if m.transitions >= uint64(m.session.meter.limits.nodes) {
			return regionError("activation transition budget exhausted")
		}
		if err := m.step(); err != nil {
			return err
		}
		m.transitions++
	}
	if stop != 0 && m.transitions != stop {
		return regionError("activation stop is beyond the checked execution")
	}
	if m.checking && m.cursor != len(m.proposed) {
		return regionError("activation has unused inferences")
	}
	return m.session.meter.tick()
}

func (m *activationMachine) event(k *regionKernel, ins ssa.Instruction, rule regionActivationRule, choice int, target *ssa.Function) (regionEffectOccurrence, error) {
	if err := k.meter.tick(); err != nil {
		return regionEffectOccurrence{}, err
	}
	if ins == nil || ins.Parent() != k.input.root || ins.Block() == nil {
		return regionEffectOccurrence{}, regionError("activation inference lacks actual instruction")
	}
	index := slices.Index(ins.Block().Instrs, ins)
	k.meter.nodes++
	if index < 0 || len(m.events) >= k.meter.limits.nodes || k.meter.nodes > k.meter.limits.nodes {
		return regionEffectOccurrence{}, regionError("activation inference position or node budget invalid")
	}
	e := regionActivationEvent{regionPoint{ins.Block(), index}, k.invocation, rule, choice, target}
	if m.checking {
		if m.cursor >= len(m.proposed) || m.proposed[m.cursor] != e {
			return regionEffectOccurrence{}, regionError("activation inference omits or changes an actual alternative")
		}
		m.cursor++
	}
	o := regionEffectOccurrence{instruction: ins, invocation: k.invocation, ordinal: uint64(len(m.events))}
	m.events = append(m.events, e)
	return o, nil
}

func (m *activationMachine) push(j activationJob) error {
	n := len(m.work) + len(m.frontiers) + len(m.outcomes)
	if n >= m.session.meter.limits.states {
		return regionError("activation alternative storage budget exhausted")
	}
	m.work = append(m.work, j)
	return nil
}
func (m *activationMachine) terminal(out regionActivationOutcome) error {
	m.session.meter.locations++
	if len(m.work)+len(m.frontiers)+len(m.outcomes) >= m.session.meter.limits.states || m.session.meter.locations > m.session.meter.limits.locations {
		return regionError("activation outcome storage budget exhausted")
	}
	m.outcomes = append(m.outcomes, out)
	return nil
}

func (m *activationMachine) step() error {
	n := len(m.work) - 1
	j := m.work[n]
	m.work = m.work[:n]
	f := j.top()
	if f.depth > m.session.meter.limits.depth {
		return regionError("activation path depth exhausted")
	}
	// Active calls are ancestry of this alternative, not the union of queued
	// siblings. A shared mutable kernel would silently retain the wrong ancestry.
	m.session.active = make(map[*ssa.Function]bool, len(j.frames))
	for _, frame := range j.frames {
		m.session.active[frame.context.input.root] = true
	}
	k := f.context.kernel(m.session)
	switch f.control.phase {
	case activationExecute:
		return m.execute(k, j)
	case activationUnwind:
		return m.unwind(k, j)
	case activationDeliver:
		return m.deliver(k, j)
	case activationPanicAlternative:
		return m.beginPanic(k, j, regionUnknownValue(types.Universe.Lookup("any").Type()))
	case activationStopAlternative:
		o, err := m.event(k, regionInstruction(f.control.at), activationNoncompletion, 0, nil)
		if err != nil {
			return err
		}
		return m.terminal(regionActivationOutcome{kind: activationStopped, origin: o})
	default:
		return regionError("activation exposed a suspended caller without its child")
	}
}

func (m *activationMachine) execute(k *regionKernel, j activationJob) error {
	f := j.top()
	at := f.control.at
	ins := regionInstruction(at)
	if ins == nil || k.cycle[at.block] {
		return regionError("activation has an invalid boundary or reachable cycle")
	}
	if len(j.frames) == 1 && m.input.limit != nil && at == m.input.limit.at {
		if _, err := m.event(k, ins, activationFrontier, 0, nil); err != nil {
			return err
		}
		m.frontiers = append(m.frontiers, j)
		return nil
	}
	// The narrow cardinality proof covers only this forward block segment.
	if len(j.frames) == 1 && m.input.limit != nil && k.input.entry.block == m.input.limit.at.block && at.block != k.input.root.Recover && (at.block != k.input.entry.block || at.index < k.input.entry.index || at.index > m.input.limit.at.index) {
		return regionError("activation crossed its scoped non-reexecution boundary")
	}
	occ, err := m.event(k, ins, activationStep, 0, nil)
	if err != nil {
		return err
	}
	next := regionPoint{at.block, at.index + 1}
	s := j.state()
	switch x := ins.(type) {
	case *ssa.Phi:
	case *ssa.Jump, *ssa.If:
		edges, err := k.branchEdges(ins, s)
		if err != nil {
			return err
		}
		jobs := make([]activationJob, 0, len(edges))
		for _, edge := range edges {
			if _, err := m.event(k, ins, activationBranch, edge.slot, nil); err != nil {
				return err
			}
			child, err := cloneActivationJob(j, k.meter)
			if err != nil {
				return err
			}
			child.install(edge.state)
			child.top().depth++
			child.top().control = activationControl{phase: activationExecute, at: regionPoint{edge.block, 0}}
			jobs = append(jobs, child)
		}
		for i := len(jobs) - 1; i >= 0; i-- {
			if err := m.push(jobs[i]); err != nil {
				return err
			}
		}
		return nil
	case *ssa.Return:
		value, err := k.returnValue(x, s)
		if err != nil {
			return err
		}
		o, err := m.event(k, ins, activationReturn, 0, nil)
		if err != nil {
			return err
		}
		f.control = activationControl{phase: activationDeliver, result: regionActivationOutcome{kind: activationNormal, value: value, origin: o}}
		return m.push(j)
	case *ssa.Panic:
		payload := k.value(s, x.X)
		if payload.kind == regionNil {
			return regionError("explicit nil panic has no selected panic-nil semantics")
		}
		return m.beginPanic(k, j, payload)
	case *ssa.MakeChan:
		value, err := k.channelConstruction(s, x)
		if err != nil {
			return err
		}
		stopped, err := cloneActivationJob(j, k.meter)
		if err != nil {
			return err
		}
		panicking, err := cloneActivationJob(j, k.meter)
		if err != nil {
			return err
		}
		stopped.top().control.phase = activationStopAlternative
		panicking.top().control.phase = activationPanicAlternative
		if err := m.push(stopped); err != nil {
			return err
		}
		if err := m.push(panicking); err != nil {
			return err
		}
		if err := k.setValue(&s, x, value); err != nil {
			return err
		}
		if _, err := m.event(k, ins, activationChannelSuccess, 0, nil); err != nil {
			return err
		}
		f.depth++
	case *ssa.RunDefers:
		f.control = activationControl{phase: activationUnwind, at: at, next: next}
		return m.push(j)
	case *ssa.Call:
		if builtin, ok := x.Call.Value.(*ssa.Builtin); ok {
			if builtin.Name() == "recover" {
				if x.Call.IsInvoke() || len(x.Call.Args) != 0 {
					return regionError("invalid builtin recovery")
				}
				value := regionValue{typ: x.Type(), kind: regionNil}
				choice := 0
				if f.eligible != nil && !f.consumed {
					value = f.eligible.payload
					value.typ = x.Type()
					f.consumed = true
					choice = 1
				}
				if _, err := m.event(k, ins, activationRecover, choice, nil); err != nil {
					return err
				}
				if err := k.setValue(&s, x, value); err != nil {
					return err
				}
			} else if err := k.transfer(&s, ins); err != nil {
				return &regionOperationFailure{ins, err}
			}
		} else {
			callable, args, err := k.callOperands(x, s)
			if err != nil {
				return err
			}
			f.control = activationControl{phase: activationAwaitCall, at: at, next: next, call: x}
			return m.invoke(k, j, x, ins, callable, args, nil, nil)
		}
	case *ssa.Defer:
		if _, builtin := x.Call.Value.(*ssa.Builtin); builtin {
			return regionError("deferred builtin panic/recover is outside activation grammar")
		}
		if err := k.registerDeferOccurrence(&s, x, occ); err != nil {
			return err
		}
	default:
		if err := k.transfer(&s, ins); err != nil {
			return &regionOperationFailure{ins, err}
		}
	}
	j.install(s)
	f.control = activationControl{phase: activationExecute, at: next}
	return m.push(j)
}

func (m *activationMachine) beginPanic(k *regionKernel, j activationJob, payload regionValue) error {
	if payload.typ == nil {
		return regionError("panic payload lacks a type")
	}
	if _, ok := payload.typ.Underlying().(*types.Interface); !ok {
		return regionError("panic payload is not an interface")
	}
	f := j.top()
	o, err := m.event(k, regionInstruction(f.control.at), activationBeginPanic, 0, nil)
	if err != nil {
		return err
	}
	f.control = activationControl{phase: activationUnwind, at: f.control.at, reason: &regionActivationPanic{origin: o, payload: payload}}
	return m.push(j)
}

func (m *activationMachine) invoke(k *regionKernel, j activationJob, call ssa.CallInstruction, dispatch ssa.Instruction, callable regionValue, args []regionValue, capture *regionDeferredCall, eligible *regionActivationPanic) error {
	k.meter.applications++
	initial, err := k.callEntry(j.state(), callable, args)
	if err != nil {
		return &regionOperationFailure{call, err}
	}
	id, err := k.invocationDispatch(call, callable.target, capture, dispatch)
	if err != nil {
		return err
	}
	if _, err := m.event(k, dispatch, activationCall, 0, callable.target); err != nil {
		return err
	}
	if len(m.calls) >= k.meter.limits.nodes {
		return regionError("activation call count exhausted")
	}
	application := regionActivationCall{site: call, dispatch: dispatch, invocation: id, target: callable.target}
	if capture != nil {
		application.registration = capture.registration
	}
	m.calls = append(m.calls, application)
	in := k.input
	in.root, in.entry, in.initial = callable.target, regionPoint{callable.target.Blocks[0], 0}, initial
	in.unwind = regionUnknownUnwind
	child, err := newRegionContextKernel(in, k.session, id, true)
	if err != nil {
		return err
	}
	depth := j.top().depth + 1
	j.heap = child.input.initial.memory
	j.frames = append(j.frames, activationFrame{context: activationContextOf(child), values: child.input.initial.values, pending: child.input.initial.pending, eligible: eligible, depth: depth, control: activationControl{phase: activationExecute, at: child.input.entry}})
	return m.push(j)
}

func (m *activationMachine) unwind(k *regionKernel, j activationJob) error {
	f := j.top()
	c := f.control
	trigger := regionInstruction(c.at)
	if !f.pending.known {
		return regionError("activation drain has unknown stack")
	}
	if _, err := m.event(k, trigger, activationDrain, len(f.pending.captures), nil); err != nil {
		return err
	}
	if n := len(f.pending.captures); n != 0 {
		capture := f.pending.captures[n-1]
		f.pending.captures = f.pending.captures[:n-1]
		f.control.phase = activationAwaitDefer
		return m.invoke(k, j, capture.site, trigger, capture.callable, capture.arguments, &capture, c.reason)
	}
	if c.reason != nil {
		o, err := m.event(k, trigger, activationEscape, 0, nil)
		if err != nil {
			return err
		}
		f.control = activationControl{phase: activationDeliver, result: regionActivationOutcome{kind: activationPanicking, panic: c.reason, origin: o}}
	} else if c.recovered {
		block := k.input.root.Recover
		if block == nil || block.Parent() != k.input.root || !slices.Contains(k.input.root.Blocks, block) || len(block.Preds) != 0 || len(block.Succs) != 0 || len(block.Instrs) == 0 {
			return regionError("recovered activation lacks its actual recovery entry")
		}
		for i, ins := range block.Instrs {
			if err := k.meter.tick(); err != nil {
				return err
			}
			if i == len(block.Instrs)-1 {
				if _, ok := ins.(*ssa.Return); !ok {
					return regionError("recovery entry lacks terminal return")
				}
			} else if load, ok := ins.(*ssa.UnOp); !ok || load.Op != token.MUL {
				return regionError("unsupported recovery result continuation")
			}
		}
		if _, err := m.event(k, block.Instrs[0], activationRecoveryEntry, 0, nil); err != nil {
			return err
		}
		f.control = activationControl{phase: activationExecute, at: regionPoint{block, 0}}
		f.depth++
	} else {
		f.control = activationControl{phase: activationExecute, at: c.next}
		f.depth++
	}
	return m.push(j)
}

func (m *activationMachine) deliver(k *regionKernel, j activationJob) error {
	f := j.top()
	out := f.control.result
	if len(j.frames) == 1 {
		out.state = regionActivationState{store: j.state(), recovered: f.consumed}
		return m.terminal(out)
	}
	consumed := f.consumed
	j.frames = j.frames[:len(j.frames)-1]
	parent := j.top()
	c := parent.control
	parent.depth++
	switch c.phase {
	case activationAwaitCall:
		if out.kind == activationPanicking {
			parent.control = activationControl{phase: activationUnwind, at: c.at, reason: out.panic}
		} else {
			pk := parent.context.kernel(m.session)
			s := j.state()
			if err := pk.setValue(&s, c.call, out.value); err != nil {
				return err
			}
			j.install(s)
			parent.control = activationControl{phase: activationExecute, at: c.next}
		}
	case activationAwaitDefer:
		c.phase = activationUnwind
		if out.kind == activationPanicking {
			c.reason, c.recovered = out.panic, false
		} else if consumed {
			if c.reason == nil {
				return regionError("recovery consumed no incoming panic")
			}
			c.reason, c.recovered = nil, true
		}
		parent.control = c
	default:
		return regionError("activation delivery lacks its actual suspended caller")
	}
	return m.push(j)
}
