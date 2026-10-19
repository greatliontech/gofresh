package nativeproof

import (
	"context"
	"errors"
	"testing"
	"testing/quick"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

func TestTransitionLocked32AccumulatorAndLanes(t *testing.T) {
	for _, source := range []uint8{0, 2, 9} {
		e := to.Encoding{Form: to.LOCKCMPXCHG0FB1, SIB: true, DispBytes: 1}
		if source >= 8 {
			e.REX = 0x44
		}
		d := to.Descriptor{Intent: to.Intent{Operation: to.LockedCompareExchange, Width: 32, Base: 4, Src: source, SignedDisp: 4}, Encoding: e}
		x, f := atomicLayout(t, []to.Descriptor{d})
		check := func(current, replacement uint32, high uint64) bool {
			for _, success := range []bool{false, true} {
				r := stateInitial(f, high)
				old := current
				if !success {
					old ^= 1
				}
				r.regs[source] = uint64(replacement) | 0xabcddcba00000000
				r.regs[0] = uint64(old) | (high|0x80000000)<<32
				for lane := 0; lane < 4; lane++ {
					r.memory[stateLocation{off: int64(4 + lane)}] = stateByte{value: byte(current >> (8 * lane))}
				}
				r.words[0] = 0
				for lane := 0; lane < 8; lane++ {
					r.words[0] |= uint64(r.memory[stateLocation{off: int64(lane)}].value) << (8 * lane)
				}
				atomicStateCuts(t, x, f, r)
				c, err := CheckTransition(t.Context(), x.im, f, x.proposal(1), TransitionLimits{})
				if err != nil {
					t.Fatal(err)
				}
				b, _ := c.Bound()
				want := uint64(current)
				if success {
					want = r.regs[0]
				}
				if got := stateEval(t, b.Registers[RAX].Value, stateBindings(t, c, f, r)); got != want {
					t.Fatalf("success=%v RAX=%x want=%x", success, got, want)
				}
			}
			return true
		}
		for _, v := range []uint32{0, 1, 0x7fffffff, 0x80000000, 0xffffffff} {
			check(v, ^v, 0xdeadbeef)
		}
		if err := quick.Check(check, &quick.Config{MaxCount: 24}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTransitionLockedByteEffectsAndOrder(t *testing.T) {
	ds := []to.Descriptor{
		{Intent: to.Intent{Operation: to.LockedOr, Width: 8, Base: 4, Src: 0, HighSrc: true, SignedDisp: 1}, Encoding: to.Encoding{Form: to.LOCKOR08, SIB: true, DispBytes: 1}},
		{Intent: to.Intent{Operation: to.SetRegister, Width: 8, Dst: 1, Condition: 4}, Encoding: to.Encoding{Form: to.SETcc0F90}},
		{Intent: to.Intent{Operation: to.LockedAndImmediate, Width: 8, Base: 4, Immediate: 0x80, SignedDisp: 1}, Encoding: to.Encoding{Form: to.LOCKAND80, SIB: true, DispBytes: 1}},
		{Intent: to.Intent{Operation: to.LockedOrImmediate, Width: 8, Base: 4, SignedDisp: 1}, Encoding: to.Encoding{Form: to.LOCKOR80, SIB: true, DispBytes: 1}},
		{Intent: to.Intent{Operation: to.LockedAndImmediate, Width: 8, Base: 4, Immediate: 255, SignedDisp: 1}, Encoding: to.Encoding{Form: to.LOCKAND80, SIB: true, DispBytes: 1}},
		{Intent: to.Intent{Operation: to.SetMemory, Width: 8, Base: 4, SignedDisp: 3, Condition: 12}, Encoding: to.Encoding{Form: to.SETcc0F90, SIB: true, DispBytes: 1}},
		{Intent: to.Intent{Operation: to.CompareMemoryImmediate, Width: 8, Base: 4, Immediate: 0x80, SignedDisp: 1}, Encoding: to.Encoding{Form: to.CMP80, SIB: true, DispBytes: 1}},
		{Intent: to.Intent{Operation: to.NoOp}, Encoding: to.Encoding{Form: to.NOP660F1F, NOPModRM: 0x44}},
		{Intent: to.Intent{Operation: to.StoreImmediate, Width: 8, Base: 4, SignedDisp: 1}, Encoding: to.Encoding{Form: to.MOVC6, SIB: true, DispBytes: 1}},
	}
	x, f := atomicLayout(t, ds)
	check := func(seed uint64) bool { atomicStateCuts(t, x, f, stateInitial(f, seed)); return true }
	for _, seed := range []uint64{0, 1, 0x80, ^uint64(0), 0x0123456789abcdef} {
		check(seed)
	}
	if err := quick.Check(check, &quick.Config{MaxCount: 32}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionNarrowLockedPremisesAndLimits(t *testing.T) {
	for _, code := range []string{"f00fb11424", "f0800c2480", "f08024247f", "f0800c2400", "f0802424ff"} {
		raw := hexBytes(t, code)
		im := image(t, append(raw, 0xc3))
		p, err := ProposeTransition(t.Context(), im, testEntry+uint64(len(raw)), TransitionLimits{}, TransitionOptions{Expansions: []TransitionExpansion{{PC: testEntry}}})
		if err != nil {
			t.Fatal(err)
		}
		width := int64(1)
		if code == "f00fb11424" {
			width = 4
		}
		f := stateFace(16, 0)
		f.Words = nil
		f.Regions = []RelativeRegion{{RelativeSpan{0, width}, true, true}}
		f.Conditions.LockedMemory = LockedMemoryModel
		f.Origin.Modulus, f.Origin.Residue = uint64(width), 0
		for _, mode := range []string{"good", "readonly", "writeonly", "missing", "unknown", "unaligned", "varying", "short"} {
			face := cloneTransitionInterface(f)
			switch mode {
			case "readonly":
				face.Regions[0].Writable = false
			case "writeonly":
				face.Regions[0].Readable = false
			case "missing":
				face.Conditions.LockedMemory = ""
			case "unknown":
				face.Conditions.LockedMemory = "unknown"
			case "unaligned":
				if width == 1 {
					continue
				}
				face.Origin.Residue = 1
			case "varying":
				if width == 1 {
					continue
				}
				face.Origin.Modulus = 2
			case "short":
				face.Regions[0].Bytes.End--
			}
			c, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
			if mode == "good" {
				if err != nil {
					t.Fatal(code, err)
				}
			} else {
				transitionRefused(t, c, err)
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		c, err := CheckTransition(ctx, im, f, p, TransitionLimits{})
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		transitionRefused(t, c, err)
		for _, limits := range []TransitionLimits{{RelationLimits: RelationLimits{Nodes: 20}}, {RelationLimits: RelationLimits{Work: 10}}, {RelationLimits: RelationLimits{Depth: 2}}, {LiveStateBytes: 100}} {
			c, err := CheckTransition(t.Context(), im, f, p, limits)
			transitionRefused(t, c, err)
		}
		counter := &imageCallbackContext{Context: t.Context()}
		if _, err := CheckTransition(counter, im, f, p, TransitionLimits{}); err != nil {
			t.Fatal(err)
		}
		for at := 1; at <= counter.calls; at++ {
			ctx, cancel := context.WithCancel(t.Context())
			callback := &imageCallbackContext{Context: ctx, onErr: func(n int) {
				if n == at {
					cancel()
				}
			}}
			c, err := CheckTransition(callback, im, f, p, TransitionLimits{})
			cancel()
			if !errors.Is(err, context.Canceled) || c.checked != nil {
				t.Fatal("narrow cancellation leaked evidence", code, at, err)
			}
		}
	}
}

func TestTransitionNarrowFailedWritebackAndPointerLanes(t *testing.T) {
	// Loading EAX then incrementing RAX forces unequal low 32 bits even at wrap.
	im := image(t, hexBytes(t, "8b04244883c001f00fb11424c3"))
	p, err := ProposeTransition(t.Context(), im, testEntry+12, TransitionLimits{}, TransitionOptions{Expansions: []TransitionExpansion{{PC: testEntry + 7}}})
	if err != nil {
		t.Fatal(err)
	}
	f := stateFace(16, 0)
	f.Words = nil
	f.Conditions.LockedMemory = LockedMemoryModel
	f.Regions = []RelativeRegion{{RelativeSpan{0, 4}, true, false}}
	c, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
	transitionRefused(t, c, err)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.PC != testEntry+7 || refusal.Premise != "transition-permission" {
		t.Fatal("failed CAS32 write cycle not checked", err)
	}
	for _, partial := range []bool{false, true} {
		raw := hexBytes(t, "48892424") // Preserve a complete pointer word.
		var expansions []TransitionExpansion
		if partial {
			expansions = append(expansions, TransitionExpansion{PC: testEntry + 4})
			raw = append(raw, hexBytes(t, "f0800c2400")...) // Equal bytes still lose that lane's provenance.
		}
		raw = append(raw, hexBytes(t, "488b0424488b08c3")...)
		im := image(t, raw)
		p, err := ProposeTransition(t.Context(), im, testEntry+uint64(len(raw)-1), TransitionLimits{}, TransitionOptions{Expansions: expansions})
		if err != nil {
			t.Fatal(err)
		}
		f.Regions = []RelativeRegion{{RelativeSpan{0, 8}, true, true}}
		c, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
		if partial {
			transitionRefused(t, c, err)
		} else if err != nil {
			t.Fatal("complete pointer roundtrip", err)
		}
	}
}

func TestTransitionNarrowEncodingForms(t *testing.T) {
	for _, code := range []string{"f00fb111", "f0450fb14d04", "f00811", "f02021", "f08049ff80", "f0418065017f", "3831", "3a31", "807901ff", "660f1f440000", "f080c801", "f02111", "f0662011", "f080710101", "f00fc111", "f0660f1f440000", "f0f00811", "f2670801", "66f00fb111", "f0670801"} {
		compareExecutedEncoding(t, hexBytes(t, code))
	}
}
