package nativeproof

import (
	"context"
	"errors"
	"math/bits"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

func TestTransferKernelLogicalValuesAndFlags(t *testing.T) {
	for _, width := range []int{8, 32, 64} {
		for _, op := range []x86asm.Op{x86asm.AND, x86asm.OR} {
			b, scope := br.NewBuilder(2), br.NewScope()
			left, right := inputTerm(t, b, scope, 0, width), inputTerm(t, b, scope, 1, width)
			k, err := NewTransferKernel(t.Context(), RelationLimits{})
			if err != nil {
				t.Fatal(err)
			}
			r, err := k.Logical(op, left, right)
			if err != nil {
				t.Fatal(err)
			}
			if r.Value.Sort() != br.Bits(width) || r.Flags.AF != (TransitionFlag{}) {
				t.Fatal("logical width or undefined AF differs")
			}
			check := func(a, b uint64) bool {
				a, b = a&mask(width), b&mask(width)
				want := a & b
				if op == x86asm.OR {
					want = a | b
				}
				values := map[br.Term]uint64{left: a, right: b}
				if stateEval(t, r.Value, values) != want {
					t.Fatal("logical value differs", op, width, a, b)
				}
				flags := [5]bool{false, false, want>>(width-1) != 0, want == 0, bits.OnesCount8(byte(want))%2 == 0}
				for j, f := range []TransitionFlag{r.Flags.CF, r.Flags.OF, r.Flags.SF, r.Flags.ZF, r.Flags.PF} {
					if !f.Defined || f.Preserved || (stateEval(t, f.Value, values) != 0) != flags[j] {
						t.Fatal("logical flag differs", op, width, a, b, j)
					}
				}
				for j, p := range []br.Term{r.Predicates.CF, r.Predicates.ZF, r.Predicates.SFXorOF} {
					if p.Sort() != br.Bool() || (stateEval(t, p, values) != 0) != [3]bool{false, flags[3], flags[2]}[j] {
						t.Fatal("logical predicate differs", op, width, a, b, j)
					}
				}
				return true
			}
			if width == 8 {
				for a := uint64(0); a < 256; a++ {
					for b := uint64(0); b < 256; b++ {
						check(a, b)
					}
				}
			}
			for _, a := range []uint64{0, 1, 127, 128, 255, 256, 1<<31 - 1, 1 << 31, 1<<63 - 1, 1 << 63, ^uint64(0)} {
				for _, b := range []uint64{0, a, ^a, a + 1} {
					check(a, b)
				}
			}
			if err := quick.Check(check, &quick.Config{MaxCount: 128}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestTransferKernelNarrowCumulativeImportsAndCancellation(t *testing.T) {
	for _, name := range []string{"cas32", "cas64", "and8", "or8"} {
		t.Run(name, func(t *testing.T) {
			width := 8
			if name == "cas32" {
				width = 32
			} else if name == "cas64" {
				width = 64
			}
			operands := func(depth int) [3]br.Term {
				b, scope := br.NewBuilder(512), br.NewScope()
				a, x, y := inputTerm(t, b, scope, 0, 64), inputTerm(t, b, scope, 1, width), inputTerm(t, b, scope, 2, width)
				// A foreign DAG, not just isolated scalar leaves, must be imported
				// under the shared depth/node/work allowance before transfer.
				for j := 3; j < 3+depth; j++ {
					v := inputTerm(t, b, scope, uint64(j), width)
					var err error
					x, err = b.Make(br.Add, br.Bits(width), 0, x, v)
					if err != nil {
						t.Fatal(err)
					}
				}
				return [3]br.Term{a, x, y}
			}
			first, second, hostile := operands(16), operands(16), operands(160)
			invoke := func(k *TransferKernel, a [3]br.Term) error {
				if name == "cas32" || name == "cas64" {
					r, err := k.CompareExchange(a[0], a[1], a[2])
					if err != nil && r != (CompareExchangeResult{}) {
						t.Fatal("partial compare/exchange escaped")
					}
					return err
				}
				op := x86asm.AND
				if name == "or8" {
					op = x86asm.OR
				}
				r, err := k.Logical(op, a[1], a[2])
				if err != nil && r != (ArithmeticResult{}) {
					t.Fatal("partial logical result escaped")
				}
				return err
			}
			counter := &imageCallbackContext{Context: t.Context()}
			baseline, err := NewTransferKernel(counter, RelationLimits{})
			if err != nil {
				t.Fatal(err)
			}
			if err := invoke(baseline, first); err != nil {
				t.Fatal(err)
			}
			for _, limits := range []RelationLimits{{Work: baseline.meter.work}, {Nodes: len(baseline.meter.depth)}} {
				k, err := NewTransferKernel(t.Context(), limits)
				if err != nil {
					t.Fatal(err)
				}
				if err := invoke(k, first); err != nil {
					t.Fatal("first operation must fit exact allowance", limits, err)
				}
				var refusal *Refusal
				if err := invoke(k, second); !errors.As(err, &refusal) || refusal.Premise != "relation-budget" {
					t.Fatal("second imported DAG reset cumulative allowance", limits, err)
				}
				if err := invoke(k, first); err == nil {
					t.Fatal("exhausted kernel recovered")
				}
			}
			// Each allowance fits scalar construction and the smaller input DAG.
			// The larger foreign DAG alone must exhaust it; a failure caused only
			// by flag construction would not test the import obligation.
			for _, limits := range []RelationLimits{{Work: 256}, {Nodes: 256}, {Depth: 64}} {
				k, err := NewTransferKernel(t.Context(), limits)
				if err != nil {
					t.Fatal(err)
				}
				if err := invoke(k, first); err != nil {
					t.Fatal("small imported DAG must fit", limits, err)
				}
				k, err = NewTransferKernel(t.Context(), limits)
				if err != nil {
					t.Fatal(err)
				}
				var refusal *Refusal
				if err := invoke(k, hostile); !errors.As(err, &refusal) || refusal.Premise != "relation-budget" {
					t.Fatal("foreign DAG escaped import limits", limits, err)
				}
			}
			for at := 1; at <= counter.calls; at++ {
				ctx, cancel := context.WithCancel(t.Context())
				callback := &imageCallbackContext{Context: ctx, onErr: func(n int) {
					if n == at {
						cancel()
					}
				}}
				k, err := NewTransferKernel(callback, RelationLimits{})
				if err == nil {
					err = invoke(k, first)
				}
				cancel()
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation escaped at construction/import/transfer tick", at, err)
				}
			}
		})
	}
}

func TestTransferKernelLogicalRefusals(t *testing.T) {
	b, scope := br.NewBuilder(8), br.NewScope()
	x, y := inputTerm(t, b, scope, 0, 8), inputTerm(t, b, scope, 1, 8)
	word, half := inputTerm(t, b, scope, 2, 64), inputTerm(t, b, scope, 3, 16)
	truth, _ := b.Const(br.Bool(), 1)
	invoke := func(k *TransferKernel, op x86asm.Op, a, b br.Term) error {
		r, err := k.Logical(op, a, b)
		if err != nil && r != (ArithmeticResult{}) {
			t.Fatal("logical refusal leaked partial result")
		}
		return err
	}
	for _, op := range []x86asm.Op{x86asm.AND, x86asm.OR} {
		for _, pair := range [][2]br.Term{{x, word}, {word, x}, {half, half}, {truth, truth}, {x, {}}, {{}, y}} {
			k, _ := NewTransferKernel(t.Context(), RelationLimits{})
			if invoke(k, op, pair[0], pair[1]) == nil {
				t.Fatal("invalid logical operands")
			}
		}
		if invoke(nil, op, x, y) == nil || invoke(&TransferKernel{}, op, x, y) == nil {
			t.Fatal("missing kernel")
		}
		ctx, cancel := context.WithCancel(t.Context())
		k, _ := NewTransferKernel(ctx, RelationLimits{})
		cancel()
		if err := invoke(k, op, x, y); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled logical operation", err)
		}
		for _, limits := range []RelationLimits{{Work: 3}, {Nodes: 4}, {Depth: 1}} {
			k, _ := NewTransferKernel(t.Context(), limits)
			if invoke(k, op, x, y) == nil {
				t.Fatal("unbounded logical operation", limits)
			}
		}
	}
	for _, op := range []x86asm.Op{x86asm.XOR, x86asm.TEST, x86asm.ADD} {
		k, _ := NewTransferKernel(t.Context(), RelationLimits{})
		if invoke(k, op, x, y) == nil {
			t.Fatal("unsupported logical operation", op)
		}
	}
}
