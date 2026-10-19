package nativeproof

import (
	"context"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// InstructionAt decodes the certificate's own immutable bytes for one retained
// executed occurrence. Its guard still determines whether that occurrence runs;
// excluded boundaries and the unexecuted cut are not executed instructions.
func (c TransitionCertificate) InstructionAt(ctx context.Context, pc uint64, activation string) (x86asm.Inst, error) {
	if ctx == nil || c.checked == nil {
		return x86asm.Inst{}, refuse(pc, "transition-inspection", "missing context or checked transition")
	}
	if err := ctx.Err(); err != nil {
		return x86asm.Inst{}, err
	}
	if len(activation) > c.checked.limits.Work {
		return x86asm.Inst{}, refuse(pc, "transition-inspection", "activation exceeds retained bound")
	}
	for _, occurrence := range c.checked.bound.Instructions {
		if err := ctx.Err(); err != nil {
			return x86asm.Inst{}, err
		}
		if occurrence.Start != pc || occurrence.Context != activation {
			continue
		}
		i, _, err := decodeBytes(c.checked.image, pc)
		if err != nil {
			return x86asm.Inst{}, err
		}
		if occurrence.End-pc != uint64(i.Len) {
			return x86asm.Inst{}, refuse(pc, "transition-inspection", "retained instruction extent differs")
		}
		if err := ctx.Err(); err != nil {
			return x86asm.Inst{}, err
		}
		return i, nil
	}
	return x86asm.Inst{}, refuse(pc, "transition-inspection", "no retained executed occurrence")
}

// RegisterValue projects exactly an integer alias at the current unexecuted cut.
// It does not assert canonical high bits for a narrow alias or an earlier value.
func (c TransitionCertificate) RegisterValue(ctx context.Context, reg x86asm.Reg) (br.Term, error) {
	if ctx == nil || c.checked == nil {
		return br.Term{}, refuse(0, "transition-inspection", "missing context or checked transition")
	}
	if err := ctx.Err(); err != nil {
		return br.Term{}, err
	}
	return projectTransitionRegister(ctx, c.checked.bound.Registers, reg)
}

func projectTransitionRegister(ctx context.Context, registers [16]TransitionValue, reg x86asm.Reg) (br.Term, error) {
	a, ok := register(reg)
	if !ok {
		return br.Term{}, refuse(0, "transition-inspection", "unsupported register alias")
	}
	v := registers[a.reg].Value
	if a.width == 64 {
		return v, nil
	}
	// Projection introduces one bounded Extract, with no reconstruction of the
	// predecessor, new input variables or semantic proof resource allowance.
	b := br.NewBuilder(1)
	t, err := b.Make(br.Extract, br.Bits(a.width), uint64(a.shift), v)
	if err != nil {
		return br.Term{}, err
	}
	if err := ctx.Err(); err != nil {
		return br.Term{}, err
	}
	return t, nil
}
