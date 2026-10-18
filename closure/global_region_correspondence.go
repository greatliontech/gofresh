package closure

import (
	"context"
	"fmt"
	"go/types"
	"maps"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

// Each step proposes the next actual source operand boundary and two native
// boundaries: the byte TEST consuming the current call's result, then the next
// operation. Neither inventory supplies register inputs, source state or a new
// representation. Every native inventory covers the complete original prefix.
type globalCorrespondenceStep struct {
	call      *ssa.Call
	use, next nativeproof.TransitionProposal
}

type globalCorrespondencePhase struct {
	source *sourceOperandPrefix
	use    nativeproof.TransitionCertificate
	native nativeproof.TransitionCertificate
}

// globalRegionCorrespondence owns a composition of the operand lemma with
// checked source references and actual inline transitions. The original local
// entry authority and open whole-operation obligations are retained verbatim.
type globalRegionCorrespondence struct {
	root       *globalOperandCorrespondence
	phases     []globalCorrespondencePhase
	equalities []br.Witness
	work       int
}

func captureGlobalSteps(steps []globalCorrespondenceStep) ([]globalCorrespondenceStep, error) {
	if len(steps) == 0 || len(steps) > 16 {
		return nil, fmt.Errorf("global correspondence: invalid continuation step count")
	}
	owned := slices.Clone(steps)
	nodes := 0
	for i := range owned {
		for _, p := range []*nativeproof.TransitionProposal{&owned[i].use, &owned[i].next} {
			if len(p.Nodes) > 65536-nodes || len(p.Expansions) > 65536-nodes {
				return nil, fmt.Errorf("global correspondence: proposal capture bound exceeded")
			}
			nodes += len(p.Nodes) + len(p.Expansions)
			if nodes > 65536 {
				return nil, fmt.Errorf("global correspondence: cumulative proposal capture bound exceeded")
			}
			p.Nodes = slices.Clone(p.Nodes)
			for j := range p.Nodes {
				if len(p.Nodes[j].Successors) > 2 || len(p.Nodes[j].Context) > 4096 {
					return nil, fmt.Errorf("global correspondence: invalid node capture extent")
				}
				p.Nodes[j].Successors = slices.Clone(p.Nodes[j].Successors)
			}
			p.Expansions = slices.Clone(p.Expansions)
			for _, expansion := range p.Expansions {
				if len(expansion.Context) > 4096 {
					return nil, fmt.Errorf("global correspondence: expansion context bound exceeded")
				}
			}
		}
	}
	return owned, nil
}

func continueGlobalOperandCorrespondence(ctx context.Context, predecessor *globalOperandCorrespondence, steps []globalCorrespondenceStep, references map[*ssa.Function]*assemblyReference) (*globalRegionCorrespondence, error) {
	fail := func(message string) (*globalRegionCorrespondence, error) {
		return nil, fmt.Errorf("global correspondence: %s", message)
	}
	if ctx == nil || predecessor == nil || predecessor.rules != globalOperandRules || predecessor.source == nil || predecessor.source.binder == nil || predecessor.limit < 1 || predecessor.work < 0 || predecessor.work >= predecessor.limit || len(references) > 256 {
		return fail("missing current opaque operand predecessor or resource account")
	}
	owned, err := captureGlobalSteps(steps)
	if err != nil {
		return nil, err
	}
	refs := maps.Clone(references)
	meter := &correspondenceContext{Context: ctx, work: predecessor.work, limit: predecessor.limit}
	ctx = meter
	proof := &globalRegionCorrespondence{root: predecessor}
	currentSource, currentNative := predecessor.source, predecessor.native
	for _, step := range owned {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		before, ok := currentNative.BoundFor(predecessor.representation.image)
		if !ok || !before.ConditionalRegion || before.Rules != nativeproof.TransitionRules {
			return fail("native predecessor has another image, root kind or rules")
		}
		source, err := checkSourceOperandContinuation(ctx, currentSource, step.call, refs)
		if err != nil {
			return nil, err
		}
		trace := source.region.packet.trace
		if trace == nil || len(trace.calls) != 1 || trace.calls[0].proof.at != currentSource.call {
			return fail("phase does not consume precisely its retained source call")
		}
		use, err := nativeproof.CheckTransitionContinuation(ctx, currentNative, step.use)
		if err != nil {
			return nil, err
		}
		consuming, ok := use.BoundFor(predecessor.representation.image)
		if !ok {
			return fail("Boolean use has a foreign image")
		}
		if err := proof.checkBooleanUse(ctx, currentSource, currentNative, before, use, consuming, trace.calls[0]); err != nil {
			return nil, err
		}
		native, err := nativeproof.CheckTransitionContinuation(ctx, use, step.next)
		if err != nil {
			return nil, err
		}
		after, ok := native.BoundFor(predecessor.representation.image)
		if !ok || after.Entry != before.Entry || !after.ConditionalRegion || len(after.Frames) != 0 || after.Thread.ContextChanged || len(after.Abstractions) != len(before.Abstractions) || len(after.PrimitiveEffects) != len(before.PrimitiveEffects)+1 {
			return fail("phase has an unaccounted primitive, frame or context effect")
		}
		if err := proof.checkPhaseEffects(ctx, before, native, after, trace); err != nil {
			return nil, err
		}
		if err := proof.checkCurrentRepresentation(ctx, source, before, after); err != nil {
			return nil, err
		}
		proof.phases = append(proof.phases, globalCorrespondencePhase{source, use, native})
		currentSource, currentNative = source, native
	}
	// The final boundary is an actual unexecuted eight-byte load using the
	// represented source pointer, not a caller-supplied endpoint value.
	last, _ := currentNative.BoundFor(predecessor.representation.image)
	if err := proof.checkLoadBoundary(currentSource, last); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proof.work = meter.work
	return proof, nil
}

func (p *globalRegionCorrespondence) equal(ctx context.Context, a, b br.Term) error {
	witness, err := br.Prove(ctx, a, b, br.Limits{})
	if err != nil {
		return err
	}
	p.equalities = append(p.equalities, witness)
	return nil
}

func (p *globalRegionCorrespondence) constant(ctx context.Context, actual br.Term, value uint64) error {
	b := br.NewBuilder(8)
	want, err := b.Const(actual.Sort(), value)
	if err != nil {
		return err
	}
	return p.equal(ctx, actual, want)
}

func (p *globalRegionCorrespondence) address(global *ssa.Global) (uint64, bool) {
	for _, binding := range p.root.representation.globals {
		if binding.global == global {
			return binding.address, true
		}
	}
	return 0, false
}

func (p *globalRegionCorrespondence) checkBooleanUse(ctx context.Context, source *sourceOperandPrefix, predecessor nativeproof.TransitionCertificate, before nativeproof.TransitionBound, use nativeproof.TransitionCertificate, after nativeproof.TransitionBound, application regionReferenceApplication) error {
	fail := func(s string) error { return fmt.Errorf("global correspondence Boolean use: %s", s) }
	boundary := before.Boundary.Instruction
	if boundary.Op != x86asm.CMPXCHG || boundary.MemBytes != 8 || len(source.operands) != 3 || after.Boundary.Instruction.Op != x86asm.TEST || after.Boundary.Instruction.MemBytes != 0 || after.Boundary.Context != before.Boundary.Context {
		return fail("actual atomic/result-consuming boundaries differ")
	}
	old, oldOK := regionUint64(source.operands[1])
	replacement, newOK := regionUint64(source.operands[2])
	register, registerOK := boundary.Args[1].(x86asm.Reg)
	if !oldOK || !newOK || !registerOK {
		return fail("source scalars or replacement-register binding is absent")
	}
	value, err := predecessor.RegisterValue(ctx, register)
	if err != nil || value.Sort() != br.Bits(64) {
		return fail("actual replacement operand is not a full register")
	}
	if err := p.constant(ctx, value, replacement); err != nil {
		return err
	}
	if err := p.constant(ctx, before.Registers[nativeproof.RAX].Value, old); err != nil {
		return err
	}
	test := after.Boundary.Instruction
	resultRegister, ok := test.Args[0].(x86asm.Reg)
	if !ok || test.Args[1] != resultRegister || test.Args[2] != nil || test.Args[3] != nil {
		return fail("Boolean consumer is not the actual same-byte test")
	}
	result, err := use.RegisterValue(ctx, resultRegister)
	if err != nil || result.Sort() != br.Bits(8) {
		return fail("Boolean consumer does not read exactly one byte")
	}
	if len(after.Instructions) < len(before.Instructions)+2 {
		return fail("atomic/condition-code producer coverage is incomplete")
	}
	pc := before.Boundary.PC
	for index, occurrence := range after.Instructions[len(before.Instructions):] {
		if occurrence.Start != pc || occurrence.Context != before.Boundary.Context {
			return fail("result producer is not the actual uninterrupted occurrence")
		}
		if err := p.constant(ctx, occurrence.Guard, 1); err != nil {
			return err
		}
		instruction, err := use.InstructionAt(ctx, occurrence.Start, occurrence.Context)
		if err != nil {
			return err
		}
		switch index {
		case 0:
			if instruction.Op != x86asm.CMPXCHG {
				return fail("first occurrence is not the retained atomic operation")
			}
		case 1:
			if instruction.Op != x86asm.SETE && instruction.Op != x86asm.SETNE || instruction.Args[0] != resultRegister {
				return fail("result is not produced in the consumed byte")
			}
		default:
			if instruction.Op != x86asm.NOP {
				return fail("unaccounted operation between result production and use")
			}
		}
		pc = occurrence.End
	}
	if pc != after.Boundary.PC || len(after.PrimitiveEffects) != len(before.PrimitiveEffects)+1 || len(after.Accesses) != len(before.Accesses)+2 {
		return fail("atomic result prefix has extra effects or a different endpoint")
	}
	first, second := after.Accesses[len(before.Accesses)], after.Accesses[len(before.Accesses)+1]
	atomic, atomicOK := after.PrimitiveEffects[len(before.PrimitiveEffects)].(nativeproof.LockedCompareExchange64Effect)
	if !atomicOK || atomic.PC != before.Boundary.PC || atomic.Context != before.Boundary.Context || atomic.ReadAccess != len(before.Accesses) || atomic.WriteAccess != len(before.Accesses)+1 {
		return fail("read/write cycle lacks its retained indivisible ordering occurrence")
	}
	for _, equality := range []struct {
		actual br.Term
		value  uint64
	}{{atomic.Before, application.current}, {atomic.Compare, old}, {atomic.Replacement, replacement}, {atomic.After, application.value}} {
		if err := p.constant(ctx, equality.actual, equality.value); err != nil {
			return err
		}
	}
	g, ok := source.operands[0].location.object.site.(*ssa.Global)
	address, represented := p.address(g)
	if source.operands[0].kind != regionPointer || source.operands[0].location.object.kind != regionGlobal || len(source.operands[0].location.path) != 0 || !ok || !represented || !first.Image || !second.Image || first.PC != before.Boundary.PC || second.PC != first.PC || first.Context != before.Boundary.Context || second.Context != first.Context || first.Kind != nativeproof.FrameRead || second.Kind != nativeproof.FrameWrite || first.Bytes != (nativeproof.RelativeSpan{Start: int64(address), End: int64(address + 8)}) || second.Bytes != first.Bytes {
		return fail("atomic read/write occurrence differs from source pointer provenance")
	}
	boolean := uint64(0)
	if application.result {
		boolean = 1
	}
	return p.constant(ctx, result, boolean)
}

func (p *globalRegionCorrespondence) checkPhaseEffects(ctx context.Context, before nativeproof.TransitionBound, native nativeproof.TransitionCertificate, after nativeproof.TransitionBound, source *regionEffectTrace) error {
	if len(after.Accesses) < len(before.Accesses) {
		return fmt.Errorf("global correspondence: predecessor accesses disappeared")
	}
	accesses := after.Accesses[len(before.Accesses):]
	for _, access := range accesses {
		found := false
		for _, occurrence := range after.Instructions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if occurrence.Start != access.PC || occurrence.Context != access.Context {
				continue
			}
			if found {
				return fmt.Errorf("global correspondence: ambiguous access occurrence")
			}
			found = true
			if err := p.constant(ctx, occurrence.Guard, 1); err != nil {
				return err
			}
		}
		if !found {
			return fmt.Errorf("global correspondence: access lacks its executed instruction")
		}
	}
	i := 0
	for _, effect := range source.accesses {
		if err := ctx.Err(); err != nil {
			return err
		}
		address, represented := p.address(effect.global)
		if !represented {
			return fmt.Errorf("global correspondence: source effect is outside the fixed representation")
		}
		kind := nativeproof.FrameRead
		if effect.write {
			kind = nativeproof.FrameWrite
		}
		matched := i < len(accesses) && accesses[i].Image && accesses[i].Kind == kind && accesses[i].Bytes == (nativeproof.RelativeSpan{Start: int64(address), End: int64(address + 8)})
		if matched {
			instruction, err := native.InstructionAt(ctx, accesses[i].PC, accesses[i].Context)
			if err != nil {
				return err
			}
			matched = effect.locked == (instruction.Op == x86asm.CMPXCHG)
		}
		if !matched {
			// A source ordinary read of already established live singleton storage
			// is removable in this isolated grammar. No native access, write,
			// locked occurrence or unknown source value is removed by this rule.
			if !effect.write && !effect.locked {
				continue
			}
			return fmt.Errorf("global correspondence: ordered read/write population differs")
		}
		if err := p.constant(ctx, accesses[i].Value, effect.value); err != nil {
			return err
		}
		i++
	}
	if i != len(accesses) {
		return fmt.Errorf("global correspondence: native phase has extra accesses")
	}
	return nil
}

func (p *globalRegionCorrespondence) checkCurrentRepresentation(ctx context.Context, source *sourceOperandPrefix, before, after nativeproof.TransitionBound) error {
	b := br.NewBuilder(4096)
	for _, binding := range p.root.representation.globals {
		value := readRegionLocation(source.region.packet.observations[0].state, regionLocation{object: regionObject{kind: regionGlobal, site: binding.global}}, types.Typ[types.Uint64])
		n, ok := regionUint64(value)
		if !ok {
			return fmt.Errorf("global correspondence: current source storage is unestablished")
		}
		word, err := globalNativeWord(ctx, b, after.Memory, binding.address)
		if err != nil {
			return err
		}
		if err := p.constant(ctx, word, n); err != nil {
			return err
		}
	}
	current := make(map[nativeproof.TransitionLocation]nativeproof.TransitionByte, len(after.Memory))
	for _, cell := range after.Memory {
		current[cell.TransitionLocation] = cell
	}
	for _, old := range before.Memory {
		if err := ctx.Err(); err != nil {
			return err
		}
		represented := false
		for _, binding := range p.root.representation.globals {
			represented = represented || old.Image && old.Offset >= int64(binding.address) && old.Offset < int64(binding.address+8)
		}
		if represented {
			continue
		}
		now, found := current[old.TransitionLocation]
		if !found || old.Pointer != now.Pointer || old.PointerLane != now.PointerLane {
			return fmt.Errorf("global correspondence: unrelated current memory/provenance differs")
		}
		if err := p.equal(ctx, old.Value, now.Value); err != nil {
			return err
		}
	}
	return nil
}

func (p *globalRegionCorrespondence) checkLoadBoundary(source *sourceOperandPrefix, native nativeproof.TransitionBound) error {
	if len(source.operands) != 1 || source.operands[0].kind != regionPointer || source.operands[0].location.object.kind != regionGlobal || len(source.operands[0].location.path) != 0 {
		return fmt.Errorf("global correspondence: final source operand has no exact global provenance")
	}
	g, ok := source.operands[0].location.object.site.(*ssa.Global)
	address, represented := p.address(g)
	i := native.Boundary.Instruction
	memory, memoryOK := i.Args[1].(x86asm.Mem)
	_, registerOK := i.Args[0].(x86asm.Reg)
	if !ok || !represented || i.Op != x86asm.MOV || i.MemBytes != 8 || i.Mode != 64 || i.AddrSize != 64 || !memoryOK || !registerOK || memory.Base != x86asm.RIP || memory.Index != 0 || memory.Segment != 0 || i.Args[2] != nil || i.Args[3] != nil {
		return fmt.Errorf("global correspondence: final native boundary is not the represented unexecuted load")
	}
	if native.Boundary.PC >= 1<<47 || uint64(i.Len) > (1<<47)-native.Boundary.PC {
		return fmt.Errorf("global correspondence: final load instruction extent wraps")
	}
	next := int64(native.Boundary.PC + uint64(i.Len))
	// The next PC is low canonical and displacement is a sign-extended int32.
	// Their signed sum fits int64; range checking precedes conversion to uint64.
	if memory.Disp < -(1<<31) || memory.Disp >= 1<<31 || next+memory.Disp < 0 || uint64(next+memory.Disp) != address {
		return fmt.Errorf("global correspondence: final load uses another represented address")
	}
	return nil
}
