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
func storageBoundaryLocation(ctx context.Context, bound nativeproof.TransitionBound, memory x86asm.Mem, width int64) (nativeproof.TransitionExtent, bool) {
	if memory.Index != 0 || memory.Segment != 0 && memory.Segment != x86asm.FS {
		return nativeproof.TransitionExtent{}, false
	}
	if memory.Segment == x86asm.FS {
		if memory.Base != 0 {
			return nativeproof.TransitionExtent{}, false
		}
		extent, err := bound.Geometry.ResolvePointer(ctx, bound.Thread.FS.Pointer, memory.Disp, width)
		return extent, err == nil
	}
	if memory.Base == x86asm.RIP {
		pc := bound.Boundary.PC
		size := uint64(len(bound.Boundary.Bytes))
		if pc >= 1<<47 || size > (1<<47)-pc {
			return nativeproof.TransitionExtent{}, false
		}
		address := int64(pc + size)
		if memory.Disp > 0 && address > math.MaxInt64-memory.Disp || memory.Disp < 0 && address < math.MinInt64-memory.Disp {
			return nativeproof.TransitionExtent{}, false
		}
		extent, err := bound.Geometry.ResolveStorage(ctx, nativeproof.ImageAddress(address+memory.Disp), width)
		return extent, err == nil
	}
	register, offset, registerWidth, ok := nativeproof.RegisterAlias(memory.Base)
	if !ok || offset != 0 || registerWidth != 64 {
		return nativeproof.TransitionExtent{}, false
	}
	extent, err := bound.Geometry.ResolvePointer(ctx, bound.Registers[register].Pointer, memory.Disp, width)
	return extent, err == nil
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
	var scalarOperands []x86asm.Arg
	switch instruction.Op {
	case x86asm.CMPXCHG:
		var valid bool
		memory, valid = instruction.Args[0].(x86asm.Mem)
		if !valid || len(source.operands) != 3 || instruction.MemBytes != 4 && instruction.MemBytes != 8 {
			return fail("compare-exchange operand shape differs")
		}
	case x86asm.MOV:
		if destination, store := instruction.Args[0].(x86asm.Mem); store {
			if len(source.operands) != 2 {
				return fail("store operand shape differs")
			}
			memory, scalarOperands = destination, []x86asm.Arg{instruction.Args[1]}
		} else {
			var valid bool
			memory, valid = instruction.Args[1].(x86asm.Mem)
			if !valid || len(source.operands) != 1 {
				return fail("load operand shape differs")
			}
		}
	case x86asm.AND, x86asm.OR:
		var valid bool
		memory, valid = instruction.Args[0].(x86asm.Mem)
		if !valid || len(source.operands) != 2 || instruction.MemBytes != 1 {
			return fail("byte logical operand shape differs")
		}
		scalarOperands = []x86asm.Arg{instruction.Args[1]}
	default:
		return fail("unsupported actual operand boundary")
	}
	if instruction.Mode != 64 || instruction.AddrSize != 64 || instruction.Args[2] != nil || instruction.Args[3] != nil || int64(instruction.MemBytes) != footprint.Bytes.Width() {
		return fail("native operand width or address mode differs")
	}
	location, resolved := storageBoundaryLocation(ctx, bound, memory, int64(instruction.MemBytes))
	if !resolved || location != footprint.Bytes {
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
		scalarOperands = []x86asm.Arg{accumulator, replacement}
	}
	relation := globalFunctionCorrespondence{antecedent: bound.CutGuard}
	for index, operand := range scalarOperands {
		value, width, exact := storageScalarBits(source.operands[index+1], source.region.root.pkg.TypesSizes)
		if !exact || width != instruction.MemBytes {
			return fail("typed scalar width differs from actual native operand")
		}
		var actual br.Term
		var err error
		switch argument := operand.(type) {
		case x86asm.Reg:
			actual, err = native.RegisterValue(ctx, argument)
		case x86asm.Imm:
			// Decoded signed immediates denote their operand-width bit pattern.
			// This does not execute the boundary or supply a memory value.
			bits := uint64(argument)
			if width < 8 {
				bits &= uint64(1)<<(width*8) - 1
			}
			actual, err = br.NewBuilder(1).Const(br.Bits(width*8), bits)
		default:
			return fail("scalar operand is not an actual register or immediate")
		}
		if err != nil {
			return nil, err
		}
		if actual.Sort() != br.Bits(width*8) {
			return fail("actual scalar operand has another width")
		}
		if err := relation.constant(ctx, actual, value); err != nil {
			return nil, err
		}
	}
	return relation.equalities, nil
}
