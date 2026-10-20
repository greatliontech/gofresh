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
	source  *sourceOperandPrefix
	use     nativeproof.TransitionCertificate
	native  nativeproof.TransitionCertificate
	account *globalFunctionCorrespondence
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
			if len(p.Nodes) > 65536-nodes {
				return nil, fmt.Errorf("global correspondence: proposal capture bound exceeded")
			}
			nodes += len(p.Nodes)
			p.Nodes = slices.Clone(p.Nodes)
			for j := range p.Nodes {
				if len(p.Nodes[j].Successors) > 2 {
					return nil, fmt.Errorf("global correspondence: invalid node capture extent")
				}
				p.Nodes[j].Successors = slices.Clone(p.Nodes[j].Successors)
			}
		}
	}
	return owned, nil
}

func continueGlobalOperandCorrespondence(ctx context.Context, predecessor *globalOperandCorrespondence, steps []globalCorrespondenceStep, references map[*ssa.Function]*assemblyReference) (*globalRegionCorrespondence, error) {
	fail := func(message string) (*globalRegionCorrespondence, error) {
		return nil, fmt.Errorf("global correspondence: %s", message)
	}
	if ctx == nil || predecessor == nil || predecessor.rules != globalOperandRules || predecessor.source == nil || predecessor.source.binder == nil || predecessor.account == nil || predecessor.account.layout == nil || predecessor.limit < 1 || predecessor.work < 0 || predecessor.work >= predecessor.limit || len(references) > 256 {
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
		packet := source.checkedPacket()
		if packet == nil || source.prior != currentSource.sourceEffectPrefix {
			return fail("phase lacks its exact opaque source predecessor")
		}
		trace := packet.trace
		if len(trace.calls) == 0 || trace.calls[0].proof == nil || trace.calls[0].proof.at != currentSource.call {
			return fail("phase does not first consume its retained source call")
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
		if !ok || after.Entry != before.Entry || !after.ConditionalRegion || after.Thread.ContextChanged || len(after.Abstractions) != len(before.Abstractions) || len(after.PrimitiveEffects) != len(before.PrimitiveEffects)+1 {
			return fail("phase has an unaccounted primitive, frame or context effect")
		}
		account, err := proof.checkPhaseEffects(ctx, source, native, after)
		if err != nil {
			return nil, err
		}
		account.work = meter.work
		proof.phases = append(proof.phases, globalCorrespondencePhase{source: source, use: use, native: native, account: account})
		currentSource, currentNative = source, native
	}
	// The final boundary is an actual unexecuted eight-byte load using the
	// represented source pointer, not a caller-supplied endpoint value.
	if err := proof.checkLoadBoundary(ctx, currentSource, currentNative); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proof.work = meter.work
	return proof, nil
}

func (p *globalRegionCorrespondence) equal(ctx context.Context, a, b br.Term) error {
	account := globalFunctionCorrespondence{antecedent: p.root.account.antecedent}
	if err := account.equal(ctx, a, b); err != nil {
		return err
	}
	p.equalities = append(p.equalities, account.equalities...)
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

func (p *globalRegionCorrespondence) checkBooleanUse(ctx context.Context, source *sourceOperandPrefix, predecessor nativeproof.TransitionCertificate, before nativeproof.TransitionBound, use nativeproof.TransitionCertificate, after nativeproof.TransitionBound, application regionCallApplication) error {
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
		instruction, err := use.InstructionAt(ctx, occurrence.ID)
		if err != nil {
			return err
		}
		switch index {
		case 0:
			if instruction.Op != x86asm.CMPXCHG || occurrence.ID != before.Boundary.ID {
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
	atomic, atomicOK := after.PrimitiveEffects[len(before.PrimitiveEffects)].(nativeproof.LockedCompareExchangeEffect)
	if !atomicOK || atomic.Width != 8 || atomic.ID != before.Boundary.ID || atomic.ReadAccess != len(before.Accesses) || atomic.WriteAccess != len(before.Accesses)+1 {
		return fail("read/write cycle lacks its retained indivisible ordering occurrence")
	}
	if application.proof == nil || len(application.proof.arguments) != 3 || application.proof.arguments[0].kind != regionPointer {
		return fail("source atomic application lacks its actual pointer argument")
	}
	location := application.proof.arguments[0].location
	current, currentOK := regionUint64(readRegionLocation(application.proof.initial, location, types.Typ[types.Uint64]))
	updated, updatedOK := regionUint64(readRegionLocation(application.outcome.state, location, types.Typ[types.Uint64]))
	if !currentOK || !updatedOK {
		return fail("source atomic application has no exact before/after word")
	}
	for _, equality := range []struct {
		actual br.Term
		value  uint64
	}{{atomic.Before, current}, {atomic.Compare, old}, {atomic.Replacement, replacement}, {atomic.After, updated}} {
		if err := p.constant(ctx, equality.actual, equality.value); err != nil {
			return err
		}
	}
	footprint, represented := p.root.account.layout.locationFootprint(source.operands[0].location)
	if source.operands[0].kind != regionPointer || !regionSameValue(source.operands[0], application.proof.arguments[0]) || !represented || footprint.Bytes.Width() != 8 || first.ID != before.Boundary.ID || second.ID != first.ID || first.Kind != nativeproof.FrameRead || second.Kind != nativeproof.FrameWrite || first.Bytes != footprint.Bytes || second.Bytes != first.Bytes {
		return fail("atomic read/write occurrence differs from source pointer provenance")
	}
	boolean := uint64(0)
	resultValue, known := regionBool(application.outcome.value)
	if !known {
		return fail("source call has no established Boolean result")
	}
	if resultValue {
		boolean = 1
	}
	return p.constant(ctx, result, boolean)
}

// Recheck the whole cumulative effect inventory from the original arbitrary
// native inputs. Inherited occurrences retain their identities and primitive
// indices; no suffix projection can accidentally remap an indivisible group.
func (p *globalRegionCorrespondence) checkPhaseEffects(ctx context.Context, source *sourceOperandPrefix, native nativeproof.TransitionCertificate, bound nativeproof.TransitionBound) (*globalFunctionCorrespondence, error) {
	packet := source.checkedPacket()
	if packet == nil {
		return nil, fmt.Errorf("global correspondence: unchecked source phase")
	}
	if err := checkStoragePrefixBounds(bound, packet.trace); err != nil {
		return nil, err
	}
	previous := p.root.account
	if len(p.phases) != 0 {
		previous = p.phases[len(p.phases)-1].account
	}
	if len(packet.trace.accesses) > 65536-len(previous.accesses) || len(previous.traces) >= 256 {
		return nil, fmt.Errorf("global correspondence: cumulative source effect bound exceeded")
	}
	occurrences := len(packet.trace.instructions)
	for _, trace := range previous.traces {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(trace.instructions) > 65536-occurrences {
			return nil, fmt.Errorf("global correspondence: cumulative source occurrence bound exceeded")
		}
		occurrences += len(trace.instructions)
	}
	layout, err := checkStorageAuthority(ctx, source, bound, p.root.representation, storageProtectedFootprints(ctx, bound))
	if err != nil {
		return nil, err
	}
	account := &globalFunctionCorrespondence{representation: layout.representation, layout: layout, antecedent: p.root.account.antecedent,
		traces: append(slices.Clone(previous.traces), packet.trace), accesses: append(slices.Clone(previous.accesses), packet.trace.accesses...), limit: p.root.limit}
	if err := checkStoragePrefixAccount(ctx, account, source, native, bound); err != nil {
		return nil, err
	}
	return account, nil
}

func (p *globalRegionCorrespondence) checkLoadBoundary(ctx context.Context, source *sourceOperandPrefix, native nativeproof.TransitionCertificate) error {
	bound, ok := native.BoundFor(p.root.representation.image)
	if !ok || len(source.operands) != 1 || bound.Boundary.Instruction.Op != x86asm.MOV || bound.Boundary.Instruction.MemBytes != 8 {
		return fmt.Errorf("global correspondence: final boundary is not an unexecuted word load")
	}
	witnesses, err := checkStorageOperandBoundary(ctx, source, native, p.root.account.layout)
	if err != nil {
		return err
	}
	p.equalities = append(p.equalities, witnesses...)
	return nil
}
