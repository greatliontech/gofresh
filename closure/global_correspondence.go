package closure

import (
	"context"
	"fmt"
	"go/constant"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

const globalOperandRules = "gofresh/global-operand-correspondence@4;" + regionRules + ";" + nativeproof.TransitionRules

// globalOperandCorrespondence relates a checked source prefix to a conditional
// native prefix at their actual unexecuted operand boundaries. The common account
// retains arbitrary global input pairs, typed effects and materialization proofs.
// Local allocation supplies no native initialization. The fixed representation
// grants neither the unexecuted operation's semantics nor whole-function coverage.
type globalOperandCorrespondence struct {
	rules          string
	source         *sourceOperandPrefix
	native         nativeproof.TransitionCertificate
	representation storageRepresentation
	account        *globalFunctionCorrespondence
	open           computationCorrespondenceObligations
	work, limit    int
}

type globalCorrespondenceLimits struct{ work int }

// This account spans equality construction and all later source/native
// continuations. Subordinate engines retain their own structural limits too.
type correspondenceContext struct {
	context.Context
	work, limit int
}

func (c *correspondenceContext) Err() error {
	if err := c.Context.Err(); err != nil {
		return err
	}
	if c.work >= c.limit {
		return fmt.Errorf("global correspondence: cumulative proof work exhausted")
	}
	c.work++
	return nil
}

// checkGlobalOperandCorrespondence consumes opaque independently derived endpoints
// and checks their effect/frame and actual operand relation. There is deliberately
// no expected-value input. Source objects remain under their immutable owner.
func checkGlobalOperandCorrespondence(ctx context.Context, source computationSource, root *ssa.Function, call *ssa.Call, image *nativeproof.Image, entry, cut uint64, prefix *sourceOperandPrefix, native nativeproof.TransitionCertificate, rho storageRepresentation, options ...globalCorrespondenceLimits) (*globalOperandCorrespondence, error) {
	fail := func(s string) (*globalOperandCorrespondence, error) {
		return nil, fmt.Errorf("global operand correspondence: %s", s)
	}
	if ctx == nil || image == nil || rho.image == nil || source.prog == nil || rho.source != source.prog || root == nil || prefix == nil {
		return fail("missing or foreign source/image owner")
	}
	limit := 2_000_000
	if len(options) > 1 {
		return fail("more than one proof budget")
	}
	if len(options) == 1 {
		limit = options[0].work
	}
	if limit < 1 || limit > 20_000_000 || len(rho.bindings) > storageMaxBindings {
		return fail("invalid proof work budget")
	}
	// Freeze candidate-owned containers before any context callback.
	ownedImage, representationImage := *image, *rho.image
	rho.image = &representationImage
	rho.bindings = slices.Clone(rho.bindings)
	meter := &correspondenceContext{Context: ctx, limit: limit}
	ctx = meter
	packet := prefix.checkedPacket()
	if packet == nil || packet.input.owner != source.prog.Prog || packet.input.root != root || prefix.region.root.function != root || prefix.binder.source.prog != source.prog || prefix.call != call || call == nil || call.Parent() != root || prefix.prior != nil || len(root.Blocks) == 0 || packet.input.entry != (regionPoint{root.Blocks[0], 0}) || len(packet.input.initial.memory) != 0 || len(packet.input.initial.values) != 0 || len(packet.observations) != 1 || len(prefix.operands) != len(call.Call.Args) {
		return fail("source does not start at the owned arbitrary-state root prefix")
	}
	b, ok := native.BoundFor(&ownedImage)
	if _, represented := native.BoundFor(rho.image); !ok || !represented || b.Rules != nativeproof.TransitionRules || !b.ConditionalRegion || b.Entry != entry || b.Boundary.PC != cut || b.Thread.ContextChanged {
		return fail("native prefix scope/owner differs")
	}
	if err := checkStoragePrefixBounds(b, packet.trace); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	layout, err := checkStorageAuthority(ctx, prefix, b, rho, storageProtectedFootprints(ctx, b))
	if err != nil {
		return nil, err
	}
	// A declared return interface retains the prologue's actual administrative
	// effects. Without that interface, retain the operand lemma's preserved
	// register context rather than silently broadening its caller contract.
	if b.Interface.ReturnContext == nil {
		for reg := nativeproof.RAX; reg <= nativeproof.R15; reg++ {
			if reg != nativeproof.RAX && reg != nativeproof.RCX && reg != nativeproof.RDX && b.Preserved[reg] != ^uint64(0) {
				return fail("native administrative context is not preserved")
			}
		}
	}
	account := &globalFunctionCorrespondence{representation: layout.representation, layout: layout, antecedent: b.EntryPredicate,
		traces: []*regionEffectTrace{packet.trace}, accesses: slices.Clone(packet.trace.accesses), limit: limit}
	if err := checkStoragePrefixAccount(ctx, account, prefix, native, b); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	account.work = meter.work
	return &globalOperandCorrespondence{rules: globalOperandRules, source: prefix, native: native, representation: layout.representation, account: account,
		open: computationCorrespondenceObligations{true, true, true, true, true}, work: meter.work, limit: meter.limit}, nil
}

// Bounds precede projection-sized allocations in authority and effect checking.
func checkStoragePrefixBounds(native nativeproof.TransitionBound, trace *regionEffectTrace) error {
	if trace == nil || len(trace.accesses) > 65536 || len(trace.instructions) > 65536 || len(trace.allocations) > 65536 || len(trace.calls) > 65536 || len(trace.atomics) > 65536 || len(native.Instructions) > 65536 || len(native.Accesses) > 65536 || len(native.InitialMemory) > 65536 || len(native.Memory) > 65536 || len(native.PrimitiveEffects) > 65536 || len(native.Abstractions) > 65536 || len(native.Frames) > 65536 {
		return fmt.Errorf("global correspondence: finite prefix projection bound exceeded")
	}
	if err := regionNativeTraceControl(trace); err != nil {
		return err
	}
	return nil
}

// The same cumulative account serves the initial cut and every later phase.
// Native access indices and source atomic indices remain in their original
// inventories; slicing away the inherited accesses would corrupt their pairing.
func checkStoragePrefixAccount(ctx context.Context, account *globalFunctionCorrespondence, source *sourceOperandPrefix, native nativeproof.TransitionCertificate, bound nativeproof.TransitionBound) error {
	if err := account.checkDirection(ctx, bound.InitialDirection, bound.Direction); err != nil {
		return err
	}
	builder := br.NewBuilder(65536)
	if err := account.checkStorageInputs(ctx, builder, bound); err != nil {
		return err
	}
	if err := account.constant(ctx, bound.CutGuard, 1); err != nil {
		return err
	}
	if err := account.checkEffects(ctx, bound); err != nil {
		return err
	}
	packet := source.checkedPacket()
	if packet == nil || len(packet.observations) != 1 {
		return fmt.Errorf("global correspondence: missing owned current source state")
	}
	state := packet.observations[0].state
	if err := account.checkStorageValues(ctx, builder, state, bound.Memory, true); err != nil {
		return err
	}
	witnesses, err := checkStorageOperandBoundary(ctx, source, native, account.layout)
	if err != nil {
		return err
	}
	account.equalities = append(account.equalities, witnesses...)
	// Both admitted pointer boundaries read their operand storage. Unrelated
	// allocated locals need no physical zero bytes at a zero-argument cut.
	// A plain store consumes its pointer and new value, not the destination's
	// old contents. Operand matching separately checks that actual store shape.
	_, destination := bound.Boundary.Instruction.Args[0].(x86asm.Mem)
	writeOnly := bound.Boundary.Instruction.Op == x86asm.MOV && destination
	if !writeOnly && len(source.operands) != 0 && source.operands[0].location.object.kind == regionAllocation {
		if err := account.checkStorageLocationValues(ctx, builder, state, bound.Memory, source.operands[0].location); err != nil {
			return err
		}
	}
	return account.checkStorageFrame(ctx, bound)
}

func regionUint64(v regionValue) (uint64, bool) {
	if v.kind != regionConstant || v.scalar == nil || !types.Identical(v.typ, types.Typ[types.Uint64]) || v.scalar.Kind() != constant.Int {
		return 0, false
	}
	return constant.Uint64Val(v.scalar)
}
