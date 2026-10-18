package nativeproof

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// Expectations come from fixture file bytes and mapping intent, independently
// of initializer coverage or the transition's initial-memory projection.
func initializedReference(face TransitionInterface, raw []byte, loads []interfaceMapping, values []byte) stateReference {
	r := stateRawInitial(face, values)
	r.initialized = map[stateLocation]bool{}
	for key := range r.memory {
		if !key.image {
			continue
		}
		addr := uint64(key.off)
		for _, load := range loads {
			if addr < load.start || addr >= load.end {
				continue
			}
			var value byte
			if addr-load.start < load.filesz {
				value = raw[load.file+addr-load.start]
			} else if !load.write || load.execute {
				continue
			}
			r.initialized[key] = true
			r.memory[key] = stateByte{value: value}
		}
	}
	return r
}

func initializedImage(t testing.TB, raw []byte, face TransitionInterface) (*Image, TransitionInterface) {
	t.Helper()
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	face.Initialization, err = CheckImageInitialization(t.Context(), im, StaticELFInitialization)
	if err != nil {
		t.Fatal(err)
	}
	return im, face
}

func TestTransitionInitializationMixedCoverage(t *testing.T) {
	if err := quick.Check(func(file [32]byte, arbitrary [512]byte, split uint8) bool {
		loads := imageStateLoads()
		loads[0].filesz = uint64(split%32 + 1)
		raw := transitionImageELF(t, []byte{0xc3}, loads)
		copy(raw[loads[0].file:loads[0].file+loads[0].filesz], file[:])
		im, face := initializedImage(t, raw, imageStateFace())
		c, err := proveTransition(t, im, im.entry, face)
		if err != nil {
			t.Fatal(err)
		}
		initial := initializedReference(face, raw, loads, arbitrary[:])
		stateBindings(t, c, face, initial)
		if !reflect.DeepEqual(c.checked.bound.InitialMemory, c.checked.bound.Memory) {
			t.Fatal("root-only memory differs")
		}
		// Zero-valued file bytes remain file-derived, not BSS-derived.
		for _, r := range face.Initialization.checked.ranges {
			if r.Start == loads[0].start && (!r.file || r.offset != loads[0].file) {
				t.Fatal("file provenance lost")
			}
		}
		return true
	}, &quick.Config{MaxCount: 64}); err != nil {
		t.Fatal(err)
	}
}

func initializedDecision(t testing.TB, value uint64, file bool, inverted bool, prefix []byte) (*Image, TransitionInterface, uint64, uint64) {
	t.Helper()
	loads := imageStateLoads()
	address := imageStateAddress + 64
	if file {
		address = imageStateAddress + 8
	}
	code := append([]byte(nil), prefix...)
	loadPC := testEntry + uint64(len(code))
	code = append(code, 0x48, 0x8b, 0x05, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(code[len(code)-4:], uint32(int64(address)-int64(loadPC+7)))
	code = append(code, 0x48, 0x85, 0xc0, 0x74, 0x02, 0xff, 0xd0, 0x48, 0x89, 0xc3, 0x0f, 0x0b)
	if inverted {
		code[len(prefix)+10] = 0x75
	}
	raw := transitionImageELF(t, code, loads)
	if file {
		binary.LittleEndian.PutUint64(raw[loads[0].file+8:], value)
	}
	im, face := initializedImage(t, raw, imageStateFace())
	return im, face, loadPC + 17, loadPC + 12
}

func TestTransitionInitializedDeadCall(t *testing.T) {
	for _, file := range []bool{false, true} {
		im, face, cut, call := initializedDecision(t, 0, file, false, nil)
		c, err := proveTransition(t, im, cut, face)
		if err != nil {
			t.Fatal(err)
		}
		b := c.checked.bound
		if len(b.ExcludedBoundaries) != 1 || b.ExcludedBoundaries[0].PC != call || !bytes.Equal(b.ExcludedBoundaries[0].Bytes, []byte{0xff, 0xd0}) {
			t.Fatal("missing actual CALL boundary")
		}
		for _, i := range b.Instructions {
			if i.Start == call {
				t.Fatal("excluded CALL executed a fetch")
			}
		}
		if len(b.Accesses) != 1 || len(b.PrimitiveEffects) != 0 || b.Registers[RSP].Value != b.InitialRegisters[RSP] || b.Registers[RAX].Pointer != nil || stateEval(t, b.Registers[RAX].Value, nil) != 0 {
			t.Fatal("excluded call performed effects or invented pointer")
		}
		left, right := c.checked.exclusions[0].Roots()
		if left != b.ExcludedBoundaries[0].Guard || right.Sort() != br.Bool() || !literalBool(right, 0) {
			t.Fatal("wrong false proof")
		}
		for _, oldCut := range []uint64{im.entry, im.entry + 7, im.entry + 10, cut - 3} {
			root, err := proveTransition(t, im, oldCut, face)
			if err != nil {
				t.Fatal(err)
			}
			continued, err := CheckTransitionContinuation(t.Context(), root, continuationProposal(t, im, cut))
			if err != nil {
				t.Fatal(err)
			}
			assertTransitionAlpha(t, c, continued)
			if len(continued.checked.exclusions) != 1 {
				t.Fatal("continuation lost dead terminal")
			}
		}
		face.Initialization = ImageInitialization{}
		unknown, err := proveTransition(t, im, cut, face)
		transitionRefused(t, unknown, err)
	}
	for _, value := range []uint64{1, 1 << 32, 1 << 63, ^uint64(0)} {
		im, face, cut, _ := initializedDecision(t, value, true, false, nil)
		c, err := proveTransition(t, im, cut, face)
		transitionRefused(t, c, err)
	}
	im, face, cut, _ := initializedDecision(t, 0, false, true, nil)
	c, err := proveTransition(t, im, cut, face)
	transitionRefused(t, c, err)
}

func TestTransitionInitializationOwnership(t *testing.T) {
	im, face, cut, _ := initializedDecision(t, 0, false, false, nil)
	other, err := NewImage(t.Context(), im.data)
	if err != nil {
		t.Fatal(err)
	}
	c, err := proveTransition(t, other, cut, face)
	transitionRefused(t, c, err)
	copyImage := *im
	c, err = proveTransition(t, &copyImage, cut, face)
	if err != nil {
		t.Fatal("same backing refused", err)
	}
	before := lifecycleSnapshot(c.checked.bound)
	projection, _ := c.Bound()
	projection.ExcludedBoundaries[0].Guard = projection.CutGuard
	projection.ExcludedBoundaries[0].Bytes[0] = 0xc3
	projection.Interface.Initialization = ImageInitialization{}
	after, _ := c.Bound()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("projection mutated evidence")
	}
	for _, model := range []string{"", "linux", "unknown", StaticELFInitialization + "unknown"} {
		k, err := CheckImageInitialization(t.Context(), im, model)
		if err == nil || k.checked != nil {
			t.Fatal("unknown model accepted")
		}
	}
	k := *face.Initialization.checked
	k.rules += "unknown"
	bad := face
	bad.Initialization = ImageInitialization{&k}
	c, err = proveTransition(t, im, cut, bad)
	transitionRefused(t, c, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	init, err := CheckImageInitialization(ctx, im, StaticELFInitialization)
	if !errors.Is(err, context.Canceled) || init.checked != nil {
		t.Fatal("cancelled initializer succeeded", err)
	}
	// Snapshot the image container before even the first context callback.
	owned := *im
	callback := &imageCallbackContext{Context: t.Context(), onErr: func(int) { *im = *other }}
	init, err = CheckImageInitialization(callback, im, StaticELFInitialization)
	if err != nil || !sameImage(init.checked.image, &owned) {
		t.Fatal("initializer borrowed mutable container", err)
	}
}

func TestTransitionInitializationCurrentWrites(t *testing.T) {
	for _, width := range []int{8, 32, 64} {
		for _, value := range []uint64{1, 0x80, 0x80000000, 1 << 63, ^uint64(0)} {
			i := to.Intent{Operation: to.StoreImmediate, Width: uint8(width), Base: 0, RIP: true, SignedDisp: int64(imageStateAddress+64) - int64(testEntry+7), Immediate: value}
			// Use a register store so all BV64 values, including bit63 alone, are represented.
			move, _ := to.Encode(to.Intent{Operation: to.MoveImmediate, Dst: 3, Immediate: value}, to.Encoding{Form: to.MOVB8Imm64, REX: 0x48})
			i.Operation, i.Src, i.Immediate = to.Store, 3, 0
			i.SignedDisp = int64(imageStateAddress+64) - int64(testEntry+uint64(len(move))+7)
			enc := to.Encoding{Form: to.MOV89, REX: 0x48, DispBytes: 4}
			if width == 32 {
				enc.REX = 0
			}
			if width == 8 {
				enc.Form = to.MOV88
				enc.REX = 0
			}
			store, err := to.Encode(i, enc)
			if err != nil {
				t.Fatal(err)
			}
			// RIP displacement depends on actual encoding length.
			i.SignedDisp = int64(imageStateAddress+64) - int64(testEntry+uint64(len(move)+len(store)))
			store, err = to.Encode(i, enc)
			if err != nil {
				t.Fatal(err)
			}
			prefix := append(move, store...)
			im, face, cut, _ := initializedDecision(t, 0, false, false, prefix)
			root, err := proveTransition(t, im, testEntry+uint64(len(prefix)), face)
			if err != nil {
				t.Fatal(err)
			}
			before := root.checked.bound
			want := value
			if width < 64 {
				want &= (uint64(1) << width) - 1
			}
			if want != 0 {
				c, err := CheckTransitionContinuation(t.Context(), root, continuationProposal(t, im, cut))
				transitionRefused(t, c, err)
			} else {
				c, err := CheckTransitionContinuation(t.Context(), root, continuationProposal(t, im, cut))
				if err != nil {
					t.Fatal(err)
				}
				if stateEval(t, c.checked.bound.Registers[RAX].Value, nil) != 0 {
					t.Fatal("partial store read differs")
				}
			}
			for _, cell := range before.Memory {
				if cell.Image && uint64(cell.Offset) >= imageStateAddress+64 && uint64(cell.Offset) < imageStateAddress+72 {
					if stateEval(t, cell.Value, nil) != uint64(byte(want>>(8*(uint64(cell.Offset)-imageStateAddress-64)))) {
						t.Fatal("current overwritten lane differs")
					}
				}
			}
		}
	}
}
