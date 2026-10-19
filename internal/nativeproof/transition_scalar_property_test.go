package nativeproof

import (
	"math/rand/v2"
	"testing"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

func TestTransitionScalarDescriptorPopulation(t *testing.T) {
	raw := make([]byte, 137)
	for j := range raw {
		raw[j] = byte(j*31 + 17)
	}
	count := 0
	for d := range to.Descriptors {
		if d.Intent.Operation < to.Increment64 {
			continue
		}
		code, err := to.Encode(d.Intent, d.Encoding)
		if err != nil {
			t.Fatal(err)
		}
		compareExecutedEncoding(t, code)
		descriptorState(t, d, 0, 0, raw)
		count++
	}
	if count != 2440 {
		t.Fatal("incomplete scalar descriptor population", count)
	}
	t.Logf("%d scalar descriptors: every admitted prefix, GPR, direction and alias", count)
}

func TestTransitionScalarEncodingControls(t *testing.T) {
	fixtures := []struct {
		i     to.Intent
		e     to.Encoding
		bytes string
	}{
		{to.Intent{Operation: to.Increment64, Dst: 15}, to.Encoding{Form: to.INCFF, REX: 0x49}, "\x49\xff\xc7"},
		{to.Intent{Operation: to.ShiftLeft32CL, Dst: 1, Width: 32}, to.Encoding{Form: to.SHLD3}, "\xd3\xe1"},
		{to.Intent{Operation: to.SubtractBorrow32, Dst: 15, Src: 8, Width: 32}, to.Encoding{Form: to.SBB19, REX: 0x45}, "\x45\x19\xc7"},
		{to.Intent{Operation: to.SubtractBorrow32, Dst: 15, Src: 8, Width: 32}, to.Encoding{Form: to.SBB1B, REX: 0x45}, "\x45\x1b\xf8"},
		{to.Intent{Operation: to.AndRegister32, Dst: 9, Src: 2, Width: 32}, to.Encoding{Form: to.AND21, REX: 0x41}, "\x41\x21\xd1"},
		{to.Intent{Operation: to.AndRegister32, Dst: 9, Src: 2, Width: 32}, to.Encoding{Form: to.AND23, REX: 0x44}, "\x44\x23\xca"},
	}
	refuse := func(code []byte) {
		t.Helper()
		if d, err := to.Parse(code, testEntry); err == nil || d != (to.Decoded{}) {
			t.Fatalf("negative accepted: %x %+v %v", code, d, err)
		}
		compareExecutedEncoding(t, code)
	}
	for _, f := range fixtures {
		code, err := to.Encode(f.i, f.e)
		if err != nil || string(code) != f.bytes {
			t.Fatalf("literal encoder: %x %v", code, err)
		}
		d, err := to.Parse([]byte(f.bytes), testEntry)
		if err != nil || d.Intent != f.i || d.Encoding != f.e {
			t.Fatalf("literal parser: %+v %v", d, err)
		}
		compareExecutedEncoding(t, code)
		for n := 0; n < len(code); n++ {
			refuse(code[:n])
		}
		for _, prefix := range []byte{0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x64, 0x65, 0x2e} {
			refuse(append([]byte{prefix}, code...))
		}
		if code[0] >= 0x40 && code[0] <= 0x4f {
			refuse(append([]byte{0x40}, code...))
		}
		memory := append([]byte(nil), code...)
		memory[len(memory)-1] &= 0x3f
		// Append enough address bytes to distinguish unsupported memory from truncation.
		refuse(append(memory, make([]byte, 8)...))
	}
	for _, code := range [][]byte{{0xff, 0xc0}, {0x48, 0xd3, 0xe0}, {0x48, 0x19, 0xc0}, {0x48, 0x1b, 0xc0}, {0x48, 0x21, 0xc0}, {0x48, 0x23, 0xc0}, {0xd3, 0xe8}, {0xd1, 0xe0}, {0xc1, 0xe0, 1}, {0x48, 0xff, 0xc8}, {0x18, 0xc0}, {0x20, 0xc0}} {
		refuse(code)
	}
}

func scalarDescriptorsFor(intents ...to.Intent) []to.Descriptor {
	ds := make([]to.Descriptor, len(intents))
	for j, i := range intents {
		ds[j] = to.Descriptor{Intent: i, Encoding: stateEncoding(i, uint8(j))}
	}
	return ds
}

func TestTransitionScalarEvolvingState(t *testing.T) {
	counts := []uint64{0, 1, 2, 31, 32, 33, 63, 64, 255}
	edges := []uint64{0, 1, 15, 16, 0x7fffffff, 0x80000000, 0xffffffff, 0x7fffffffffffffff, ^uint64(0), 0xdeadbeef80000001}
	cases := 0
	for dst := uint8(0); dst < 16; dst++ {
		for _, count := range counts {
			for carry := uint64(0); carry < 2; carry++ {
				// Both initial CF values cross INC before SBB. The second SBB
				// consumes the shift's current carry, not the root predicate.
				intents := []to.Intent{
					{Operation: to.Increment64, Dst: dst},
					{Operation: to.SubtractBorrow32, Dst: dst, Src: (dst + 7) % 16, Width: 32},
					{Operation: to.MoveImmediate, Dst: 1, Immediate: 0xabcdef0000000000 | count},
					{Operation: to.ShiftLeft32CL, Dst: dst, Width: 32},
					{Operation: to.SubtractBorrow32, Dst: (dst + 3) % 16, Src: dst, Width: 32},
					{Operation: to.AndRegister32, Dst: dst, Src: (dst + 3) % 16, Width: 32},
					{Operation: to.Increment64, Dst: dst},
				}
				x, f := atomicLayout(t, scalarDescriptorsFor(intents...))
				r := stateInitial(f, count+uint64(dst)*37)
				for reg := range r.regs {
					if reg != 4 {
						r.regs[reg] = edges[(reg+int(dst)+int(count))%len(edges)]
					}
				}
				r.flags[0] = carry != 0
				atomicStateCuts(t, x, f, r)
				cases++
			}
		}
	}
	t.Logf("%d evolving sequences, every instruction boundary checked by continuation; final state also checked directly", cases)
}

// The input records select semantic descriptors and valuations independently.
// The existing descriptor/state grammar supplies every new spelling; this
// bounded sequence factor keeps evolving operands rather than resetting a case
// before each operation. A separate seed exercises overwrite-sensitive CF.
func FuzzTransitionScalarSequence(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0, 0}, []byte{0}, uint64(0)) // symbolic zero-count valuation then INC
	f.Add([]byte{1, 1, 0, 2, 0, 1, 0, 1, 0}, []byte{33, 255}, uint64(731))
	f.Add([]byte{4, 0, 15, 1, 1, 0, 2, 0, 1, 5, 0, 15, 0, 15, 0, 6, 15, 0, 7, 0, 4}, []byte{0, 255}, uint64(119))
	for _, count := range []byte{0, 1, 2, 31, 32, 33, 63, 64, 255} {
		f.Add([]byte{0, 0, 0, 1, 1, 0, 2, 1, 1, 3, 2, 1, 0, 2, 0}, []byte{count, 255, 128, 1}, uint64(count))
	}
	f.Fuzz(func(t *testing.T, records, raw []byte, seed uint64) {
		var ds []to.Descriptor
		// Sixteen operations bound this scalar factor's expression/SAT work;
		// larger dependency-depth campaigns belong to the existing depth oracle.
		for len(records) > 0 && len(ds) < 16 {
			var record [3]byte
			n := copy(record[:], records)
			records = records[n:]
			op := []to.Operation{to.Increment64, to.ShiftLeft32CL, to.SubtractBorrow32, to.AndRegister32, to.Compare, to.Test, to.Clear32, to.MoveRegister}[record[0]%8]
			i := to.Intent{Operation: op, Dst: record[1] % 16}
			if op != to.Increment64 && op != to.Clear32 && op != to.MoveRegister {
				i.Width = 32
			}
			if op == to.SubtractBorrow32 || op == to.AndRegister32 || op == to.Compare || op == to.Test || op == to.MoveRegister {
				i.Src = record[2] % 16
			}
			ds = append(ds, to.Descriptor{Intent: i, Encoding: stateEncoding(i, record[0]>>3)})
		}
		x, face := atomicLayout(t, ds)
		r := stateRawInitial(face, raw)
		if len(raw) > 0 {
			r.regs[1] = uint64(raw[0]) | seed<<8
		}
		atomicStateCuts(t, x, face, r)
	})
}

func TestTransitionScalarShiftGuarantees(t *testing.T) {
	for _, domain := range []struct {
		name    string
		mask    uint64
		literal bool
		defined [6]bool
	}{
		{"zero", 0, true, [6]bool{true, true, true, true, true, true}},
		{"one", 1, true, [6]bool{true, true, true, true, false, true}},
		{"two", 2, true, [6]bool{true, true, false, true, false, true}},
		{"zero-or-one", 1, false, [6]bool{true, true, true, true, false, true}},
		{"zero-or-two", 2, false, [6]bool{true, true, false, true, false, true}},
		{"zero-or-31", 31, false, [6]bool{true, true, false, true, false, true}},
	} {
		t.Run(domain.name, func(t *testing.T) {
			for _, oldWriter := range []bool{false, true} {
				var ops []dagOp
				add := func(i to.Intent, next int) { ops = append(ops, dagScalar(i, stateEncoding(i, 0), next)) }
				if domain.literal {
					add(to.Intent{Operation: to.MoveImmediate, Dst: 1, Immediate: domain.mask}, 1)
				} else {
					// The existing joined-value domain represents both possible
					// counts exactly, selected by the original entry carry.
					branch := dagScalar(to.Intent{Operation: to.Branch, Condition: 2}, to.Encoding{Form: to.JccNear}, 1)
					branch.taken = 2
					ops = append(ops, branch)
					add(to.Intent{Operation: to.MoveImmediate, Dst: 1, Immediate: 0}, 3)
					add(to.Intent{Operation: to.MoveImmediate, Dst: 1, Immediate: domain.mask}, 3)
				}
				// SBB supplies every individual flag. CMP deliberately exposes
				// only CF/ZF and its combined signed predicate, never old OF/PF.
				writer := to.Compare
				if oldWriter {
					writer = to.SubtractBorrow32
				}
				add(to.Intent{Operation: writer, Dst: 9, Src: 10, Width: 32}, len(ops)+1)
				add(to.Intent{Operation: to.ShiftLeft32CL, Dst: 2, Width: 32}, len(ops)+1)
				x := dagArrange(t, ops, 0)
				face := stateFace(16, 0)
				c, err := CheckTransition(t.Context(), x.im, face, x.proposal(len(x.intents)), TransitionLimits{})
				if err != nil {
					t.Fatal(err)
				}
				for j, predicate := range c.checked.flags {
					available := j != 2 || domain.defined[2] && domain.defined[3]
					if predicate.Valid() != available {
						t.Fatalf("writer=%v predicate%d availability=%v want=%v", oldWriter, j, predicate.Valid(), available)
					}
				}
				for j, flag := range []TransitionFlag{c.checked.bound.Flags.CF, c.checked.bound.Flags.ZF, c.checked.bound.Flags.OF, c.checked.bound.Flags.SF, c.checked.bound.Flags.AF, c.checked.bound.Flags.PF} {
					if flag.Defined != domain.defined[j] {
						t.Fatalf("writer=%v flag%d guarantee=%v want=%v", oldWriter, j, flag.Defined, domain.defined[j])
					}
					if domain.defined[j] && (oldWriter || domain.literal && domain.mask != 0 || j < 2) && !flag.Value.Valid() {
						t.Fatalf("missing guaranteed flag value %d", j)
					}
					if !oldWriter && (!domain.literal || domain.mask == 0) && j >= 2 && flag.Value.Valid() {
						t.Fatalf("invented unavailable incoming flag %d", j)
					}
				}
				for seed := uint64(0); seed < 4; seed++ {
					r := stateInitial(face, seed)
					dagCheck(t, ops, face, r, seed, len(ops)-1)
				}
			}
		})
	}
}

func TestTransitionScalarBorrowBoundaryPopulation(t *testing.T) {
	values := []uint64{0, 1, 15, 16, 0x7fffffff, 0x80000000, 0xffffffff, 0xffffffff80000000}
	rng := rand.New(rand.NewPCG(0x534242, 0x494e43))
	for range 8 {
		values = append(values, rng.Uint64())
	}
	for _, a := range values {
		for _, b := range values {
			for carry := 0; carry < 2; carry++ {
				ds := scalarDescriptorsFor(to.Intent{Operation: to.SubtractBorrow32, Dst: 0, Src: 15, Width: 32})
				x, f := atomicLayout(t, ds)
				r := stateInitial(f, a^b)
				r.regs[0], r.regs[15], r.flags[0] = a, b, carry != 0
				atomicStateCuts(t, x, f, r)
			}
		}
	}
}

func TestTransitionScalarZeroCountPreservesEntryFlags(t *testing.T) {
	for dst := uint8(0); dst < 16; dst++ {
		for _, count := range []uint64{0, 32, 64} {
			x, face := atomicLayout(t, scalarDescriptorsFor(
				to.Intent{Operation: to.MoveImmediate, Dst: 1, Immediate: 0xdeadbeef00000000 | count},
				to.Intent{Operation: to.ShiftLeft32CL, Dst: dst, Width: 32},
			))
			c, err := CheckTransition(t.Context(), x.im, face, x.proposal(len(x.intents)), TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			b := c.checked.bound
			for _, flag := range []TransitionFlag{b.Flags.CF, b.Flags.ZF, b.Flags.OF, b.Flags.SF, b.Flags.AF, b.Flags.PF} {
				if flag != (TransitionFlag{Defined: true, Preserved: true}) {
					t.Fatal("zero count changed entry flag metadata", flag)
				}
			}
			if b.InitialPredicates != (TransitionPredicates{c.checked.flags[0], c.checked.flags[1], c.checked.flags[2]}) {
				t.Fatal("zero count replaced original entry predicates")
			}
			atomicStateCuts(t, x, face, stateInitial(face, count+uint64(dst)))
		}
	}
}

func TestTransitionScalarShiftConsumers(t *testing.T) {
	for _, count := range []uint64{0, 1, 2, 31, 32, 33, 63, 64, 255} {
		for _, consumer := range []to.Operation{to.Compare, to.Test, to.Branch} {
			for _, cc := range []uint8{2, 4, 10, 12} {
				if consumer == to.Branch && cc == 12 && count&31 > 1 {
					continue
				}
				var ops []dagOp
				add := func(i to.Intent) { ops = append(ops, dagScalar(i, stateEncoding(i, 0), len(ops)+1)) }
				add(to.Intent{Operation: to.SubtractBorrow32, Dst: 9, Src: 10, Width: 32})
				add(to.Intent{Operation: to.MoveImmediate, Dst: 1, Immediate: count})
				add(to.Intent{Operation: to.ShiftLeft32CL, Dst: 0, Width: 32})
				if consumer != to.Branch {
					add(to.Intent{Operation: consumer, Dst: 0, Src: 15, Width: 32})
				}
				if consumer != to.Branch && cc == 10 {
					// The established wide CMP/TEST metadata has no public PF;
					// the direct shift branch above exercises its actual parity.
					continue
				}
				branch := len(ops)
				ops = append(ops, dagBranch(cc, branch+1, branch+2))
				add(to.Intent{Operation: to.MoveImmediate, Dst: 8, Immediate: 0x1111111180000000})
				ops[len(ops)-1].next = branch + 3
				add(to.Intent{Operation: to.MoveImmediate, Dst: 8, Immediate: 0x222222227fffffff})
				add(to.Intent{Operation: to.SubtractBorrow32, Dst: 8, Src: 0, Width: 32})
				face := stateFace(16, 0)
				for seed := uint64(0); seed < 2; seed++ {
					r := stateInitial(face, seed)
					r.flags[0] = seed != 0
					dagCheck(t, ops, face, r, seed, 3, branch+3)
				}
			}
		}
	}

}

func TestTransitionScalarPartialPointerLanes(t *testing.T) {
	for _, op := range []to.Operation{to.Increment64, to.ShiftLeft32CL, to.SubtractBorrow32, to.AndRegister32} {
		for _, high := range []bool{false, true} {
			i := to.Intent{Operation: op, Dst: 0}
			if op != to.Increment64 {
				i.Width = 32
			}
			if op == to.SubtractBorrow32 || op == to.AndRegister32 {
				i.Src = 15
			}
			ops := []to.Intent{
				{Operation: to.MoveRegister, Dst: 0, Src: 4},
				{Operation: to.MoveImmediate, Dst: 0, HighDst: high, Width: 8, Immediate: 0x37},
				i,
				{Operation: to.Store, Base: 4, Src: 0},
				{Operation: to.Load, Base: 4, Dst: 2},
			}
			x, face := atomicLayout(t, scalarDescriptorsFor(ops...))
			atomicStateCuts(t, x, face, stateInitial(face, 731))
		}
	}
}
