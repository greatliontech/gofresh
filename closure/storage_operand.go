package closure

import (
	"context"
	"fmt"
	"math"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

// storageBoundaryLocation resolves only the simple address vocabulary retained
// by the operand relation. The cut is unexecuted: this resolution grants neither
// access permission nor instruction semantics. Register provenance comes from
// the checked current state, not from numerically address-shaped scalar bits.
func storageBoundaryLocation(bound nativeproof.TransitionBound, memory x86asm.Mem) (nativeproof.TransitionLocation, bool) {
	if memory.Index != 0 || memory.Segment != 0 {
		return nativeproof.TransitionLocation{}, false
	}
	if memory.Base == x86asm.RIP {
		pc := bound.Boundary.PC
		size := uint64(len(bound.Boundary.Bytes))
		if pc >= 1<<47 || size > (1<<47)-pc {
			return nativeproof.TransitionLocation{}, false
		}
		return storageOffset(nativeproof.TransitionLocation{Image: true, Offset: int64(pc + size)}, memory.Disp)
	}
	register, offset, width, ok := nativeproof.RegisterAlias(memory.Base)
	if !ok || offset != 0 || width != 64 {
		return nativeproof.TransitionLocation{}, false
	}
	switch pointer := bound.Registers[register].Pointer.(type) {
	case nativeproof.ImagePointer:
		if pointer.Address >= 1<<47 {
			return nativeproof.TransitionLocation{}, false
		}
		return storageOffset(nativeproof.TransitionLocation{Image: true, Offset: int64(pointer.Address)}, memory.Disp)
	case nativeproof.OriginPointer:
		if pointer.Origin != bound.Origin {
			return nativeproof.TransitionLocation{}, false
		}
		return storageOffset(nativeproof.TransitionLocation{Offset: pointer.Offset}, memory.Disp)
	default:
		return nativeproof.TransitionLocation{}, false
	}
}

func storageOffset(base nativeproof.TransitionLocation, delta int64) (nativeproof.TransitionLocation, bool) {
	if delta > 0 && base.Offset > math.MaxInt64-delta || delta < 0 && base.Offset < math.MinInt64-delta {
		return nativeproof.TransitionLocation{}, false
	}
	base.Offset += delta
	if base.Image && (base.Offset < 0 || base.Offset >= 1<<47) {
		return nativeproof.TransitionLocation{}, false
	}
	return base, true
}

// checkStorageOperandBoundary checks actual operands at two owned, unexecuted
// boundaries. It does not substitute a bodyless source call or execute a native
// atomic. Only the represented pointer and exact typed scalar operands are
// related here; complete effects and storage authority are checked by the caller.
func checkStorageOperandBoundary(ctx context.Context, source *sourceOperandPrefix, native nativeproof.TransitionCertificate, layout *storageLayout) ([]br.Witness, error) {
	fail := func(reason string) ([]br.Witness, error) {
		return nil, fmt.Errorf("storage operand correspondence: %s", reason)
	}
	if source == nil || source.region == nil || source.region.packet == nil || layout == nil || source.region.packet.input.owner != layout.representation.source.Prog {
		return fail("missing or foreign source endpoint")
	}
	bound, ok := native.BoundFor(layout.representation.image)
	if !ok || ctx == nil {
		return fail("missing context or foreign native endpoint")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(source.operands) == 0 {
		// There is no scalar or pointer operand to map. This says nothing about
		// the unexecuted callee's behavior or its implementation selection.
		return nil, nil
	}
	pointer := source.operands[0]
	if pointer.kind != regionPointer {
		return fail("first source operand lacks exact storage provenance")
	}
	footprint, represented := layout.locationFootprint(pointer.location)
	if !represented {
		return fail("source pointer has no represented native storage")
	}
	instruction := bound.Boundary.Instruction
	var memory x86asm.Mem
	var scalarRegisters []x86asm.Reg
	switch instruction.Op {
	case x86asm.CMPXCHG:
		var valid bool
		memory, valid = instruction.Args[0].(x86asm.Mem)
		if !valid || len(source.operands) != 3 || instruction.MemBytes != 4 && instruction.MemBytes != 8 {
			return fail("compare-exchange operand shape differs")
		}
	case x86asm.MOV:
		if destination, store := instruction.Args[0].(x86asm.Mem); store {
			value, register := instruction.Args[1].(x86asm.Reg)
			if !register || len(source.operands) != 2 {
				return fail("store operand shape differs")
			}
			memory, scalarRegisters = destination, []x86asm.Reg{value}
		} else {
			var valid bool
			memory, valid = instruction.Args[1].(x86asm.Mem)
			if !valid || len(source.operands) != 1 {
				return fail("load operand shape differs")
			}
		}
	default:
		return fail("unsupported actual operand boundary")
	}
	if instruction.Mode != 64 || instruction.AddrSize != 64 || instruction.Args[2] != nil || instruction.Args[3] != nil || int64(instruction.MemBytes) != footprint.Bytes.End-footprint.Bytes.Start {
		return fail("native operand width or address mode differs")
	}
	location, resolved := storageBoundaryLocation(bound, memory)
	if !resolved || location.Image != footprint.Image || location.Offset != footprint.Bytes.Start {
		return fail("native operand has another storage origin or subobject")
	}
	if instruction.Op == x86asm.CMPXCHG {
		replacement, valid := instruction.Args[1].(x86asm.Reg)
		if !valid {
			return fail("replacement is not an actual register operand")
		}
		accumulator := x86asm.RAX
		if instruction.MemBytes == 4 {
			accumulator = x86asm.EAX
		}
		scalarRegisters = []x86asm.Reg{accumulator, replacement}
	}
	relation := globalFunctionCorrespondence{antecedent: bound.CutGuard}
	for index, register := range scalarRegisters {
		value, width, exact := storageScalarBits(source.operands[index+1], source.region.root.pkg.TypesSizes)
		if !exact || width != instruction.MemBytes {
			return fail("typed scalar width differs from actual native operand")
		}
		actual, err := native.RegisterValue(ctx, register)
		if err != nil {
			return nil, err
		}
		if actual.Sort() != br.Bits(width*8) {
			return fail("actual register operand has another width")
		}
		if err := relation.constant(ctx, actual, value); err != nil {
			return nil, err
		}
	}
	return relation.equalities, nil
}
