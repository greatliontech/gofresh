package nativeproof

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

func FuzzTransitionInitializedDecision(f *testing.F) {
	for _, word := range []uint64{0, 1, 1 << 32, 1 << 63, ^uint64(0)} {
		for mode := uint8(0); mode < 16; mode++ {
			f.Add(word, mode)
		}
	}
	f.Fuzz(func(t *testing.T, word uint64, mode uint8) {
		file, inverted, unknown, readonly := mode&1 != 0, mode&2 != 0, mode&4 != 0, mode&8 != 0
		im, face, cut, call := initializedDecision(t, word, file, inverted, nil)
		if readonly {
			raw := append([]byte(nil), im.data...)
			binary.LittleEndian.PutUint32(raw[124:], 4)
			im, face = initializedImage(t, raw, face)
		}
		if unknown {
			face.Initialization = ImageInitialization{}
		}
		known := !unknown && (file || !readonly)
		value := word
		if !file {
			value = 0
		}
		c, err := proveTransition(t, im, cut, face)
		dead := known && ((value == 0) != inverted)
		if !dead {
			transitionRefused(t, c, err)
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if len(c.checked.bound.ExcludedBoundaries) != 1 || c.checked.bound.ExcludedBoundaries[0].PC != call {
				t.Fatal("wrong excluded transfer")
			}
		}
		// Independently observe the admitted TEST64 transfer before either edge:
		// high bits participate, operands do not change, CF/OF=0, AF undefined.
		before, err := proveTransition(t, im, testEntry+7, face)
		if err != nil {
			t.Fatal(err)
		}
		after, err := CheckTransitionContinuation(t.Context(), before, continuationProposal(t, before, testEntry+10))
		if err != nil {
			t.Fatal(err)
		}
		a, b := before.checked.bound, after.checked.bound
		for r := range a.Registers {
			if a.Registers[r] != b.Registers[r] {
				t.Fatal("TEST wrote operand")
			}
		}
		if !literalBool(b.Flags.CF.Value, 0) || !literalBool(b.Flags.OF.Value, 0) || b.Flags.AF.Defined {
			t.Fatal("TEST flags differ")
		}
		if known {
			if stateEval(t, b.Registers[RAX].Value, nil) != value || (stateEval(t, b.Flags.ZF.Value, nil) != 0) != (value == 0) || (stateEval(t, b.Flags.SF.Value, nil) != 0) != (value>>63 != 0) {
				t.Fatal("TEST64 value/high-bit relation differs")
			}
		} else {
			for _, cell := range b.InitialMemory {
				if cell.Image && uint64(cell.Offset) >= imageStateAddress+64 && uint64(cell.Offset) < imageStateAddress+72 && cell.Value.View().Op != br.Variable {
					t.Fatal("unknown BSS gained a constant")
				}
			}
		}
	})
}

func FuzzTransitionInitializedImageSequence(f *testing.F) {
	for _, distance := range []int32{-8, -7, -1, 0, 1, 7, 8, 112} {
		f.Add(imageSequenceRecords(distance, 0, imageStateAddress), []byte{}, []byte{255, 255, 255}, make([]byte, 512), uint64(4096), uint64(781))
	}
	f.Fuzz(func(t *testing.T, records, blocks, cuts, raw []byte, requested, layout uint64) {
		limit := sequencePositiveLimit(requested)
		program := sequenceRecords(records, blocks, limit)
		checkStateSequenceProfileAt(t, imageStateFace(), program, raw, cuts, layout, testEntry, limit, true, imageSequenceLoads(len(program))...)
	})
}

func FuzzTransitionInitializedBranches(f *testing.F) {
	for _, width := range []uint8{0, 1, 2} {
		f.Add(width, uint64(7), make([]byte, 32), make([]byte, 512), make([]byte, 16))
	}
	f.Fuzz(func(t *testing.T, width uint8, layout uint64, file, raw, inactive []byte) {
		w := []uint8{8, 32, 64}[width%3]
		store := to.Intent{Operation: to.Store, RIP: true, Width: w, Src: 3}
		enc := to.Encoding{Form: to.MOV89, DispBytes: 4}
		if w == 8 {
			enc.Form = to.MOV88
		}
		if w == 64 {
			enc.REX = 0x48
		}
		ops := []dagOp{
			{i: to.Intent{Operation: to.Load, RIP: true, Dst: 0}, e: to.Encoding{Form: to.MOV8B, REX: 0x48, DispBytes: 4}, next: 1, address: imageStateAddress + 28},
			dagScalar(to.Intent{Operation: to.Store, Base: 4, Src: 0}, to.Encoding{Form: to.MOV89, REX: 0x48, SIB: true}, 2),
			{i: to.Intent{Operation: to.Load, RIP: true, Dst: 3}, e: to.Encoding{Form: to.MOV8B, REX: 0x48, DispBytes: 4}, next: 3, address: imageStateAddress + 0x200c},
			dagBranch(4, 4, 5),
			{i: store, e: enc, next: 6, address: imageStateAddress + 31},
			dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 6),
			{i: to.Intent{Operation: to.Load, RIP: true, Dst: 1}, e: to.Encoding{Form: to.MOV8B, REX: 0x48, DispBytes: 4}, next: 7, address: imageStateAddress + 31},
			dagScalar(to.Intent{Operation: to.Load, Base: 4, Dst: 2}, to.Encoding{Form: to.MOV8B, REX: 0x48, SIB: true}, 8),
		}
		x := dagArrange(t, ops, layout)
		input := append([]byte(nil), x.im.data...)
		var bytes [32]byte
		copy(bytes[:], file)
		copy(input[x.mappings[1].file:], bytes[:])
		var err error
		x.im, err = NewImage(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		x.digest = sha256.Sum256(input)
		face := imageStateFace()
		face.Conditions.CPUID = CPUIDModel
		face.Initialization, err = CheckImageInitialization(t.Context(), x.im, StaticELFInitialization)
		if err != nil {
			t.Fatal(err)
		}
		initial := initializedReference(face, input, x.mappings, raw)
		direct, err := CheckTransition(t.Context(), x.im, face, x.proposal(16), TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		dagAssert(t, direct, x, 16, face, initial, inactive)
		root, err := CheckTransition(t.Context(), x.im, face, x.proposal(0), TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		for _, cut := range []int{6, 12, 16} {
			before := root.checked.bound
			root, err = CheckTransitionContinuation(t.Context(), root, x.proposal(cut))
			if err != nil {
				t.Fatal(err)
			}
			stateInheritedInputs(t, before, root.checked.bound)
			dagAssert(t, root, x, cut, face, initial, inactive)
		}
		assertTransitionAlpha(t, direct, root)
	})
}
