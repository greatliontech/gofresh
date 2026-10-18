package nativeproof

import (
	"context"
	"encoding/binary"
	"math/rand"
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

func TestTransitionConditionalRegionBinding(t *testing.T) {
	im, cut := transitionFixture(t, "c3b82a00000031c9")
	entry := testEntry + 1
	face := transitionFace()
	p, err := ProposeRegionTransition(t.Context(), im, entry, cut, TransitionLimits{}, TransitionExpansion{PC: entry + 5})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckRegionTransition(t.Context(), im, entry, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b, ok := c.BoundFor(im)
	if !ok || !b.ConditionalRegion || b.Entry != entry || b.Boundary.PC != cut || b.InitialRegisters[RAX] == b.Registers[RAX].Value {
		t.Fatal("missing conditional root/derived state")
	}
	foreign, err := NewImage(t.Context(), im.data)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.BoundFor(foreign); ok {
		t.Fatal("equal-byte owner borrowed theorem")
	}
	init, err := CheckImageInitialization(t.Context(), im, StaticELFInitialization)
	if err != nil {
		t.Fatal(err)
	}
	// Equal numeric entries do not collapse the two entry authorities. A region
	// at the header's PC still cannot import loading facts through this API.
	samePC, err := ProposeRegionTransition(t.Context(), im, testEntry, testEntry, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	local, err := CheckRegionTransition(t.Context(), im, testEntry, face, samePC, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	localBound, _ := local.Bound()
	loadedFace := face
	loadedFace.Initialization = init
	if got, err := CheckRegionTransition(t.Context(), im, testEntry, loadedFace, samePC, TransitionLimits{}); got.checked != nil || err == nil {
		t.Fatal("same-PC region acquired loader authority")
	}
	elfRoot, err := CheckTransition(t.Context(), im, loadedFace, samePC, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	elfBound, _ := elfRoot.Bound()
	if !localBound.ConditionalRegion || elfBound.ConditionalRegion {
		t.Fatal("numeric entry collapsed root authority")
	}
	for _, mode := range []string{"ELF-upgrade", "entry-substitution", "unmapped-entry", "initialization", "cancel", "budget", "middle-cut"} {
		t.Run(mode, func(t *testing.T) {
			f, q, start, image := face, p, entry, im
			ctx := t.Context()
			limits := TransitionLimits{}
			switch mode {
			case "entry-substitution":
				q.Entry++
			case "unmapped-entry":
				start, q.Entry = 1, 1
			case "initialization":
				f.Initialization = init
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "budget":
				limits.RelationLimits.Instructions = 1
			case "middle-cut":
				q.Cut = entry + 2
			}
			var got TransitionCertificate
			var err error
			if mode == "ELF-upgrade" {
				got, err = CheckTransition(ctx, image, f, q, limits)
			} else {
				got, err = CheckRegionTransition(ctx, image, start, f, q, limits)
			}
			if _, ok := got.Bound(); ok || err == nil {
				t.Fatal("invalid conditional scope accepted", mode)
			}
		})
	}
	first, err := ProposeRegionTransition(t.Context(), im, entry, entry+5, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	prior, err := CheckRegionTransition(t.Context(), im, entry, face, first, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := prior.Bound()
	// Determine a finite allowance that admits this exact root, then require the
	// longer suffix to share it rather than receiving a fresh work budget.
	limited, err := CheckRegionTransition(t.Context(), im, entry, face, first, TransitionLimits{RelationLimits: RelationLimits{Work: prior.checked.work + 1}})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := CheckTransitionContinuation(t.Context(), limited, p); got.checked != nil || err == nil {
		t.Fatal("continuation reset cumulative budget")
	}
	continued, err := CheckTransitionContinuation(t.Context(), prior, p)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := continued.Bound()
	if !after.ConditionalRegion || after.Entry != entry || after.Origin != before.Origin || after.InitialRegisters != before.InitialRegisters || !reflect.DeepEqual(before.InitialMemory, after.InitialMemory) {
		t.Fatal("continuation reset entry authority/state")
	}
	assertTransitionAlpha(t, c, continued)
	// Mutating projections and replacing the original Image container cannot
	// mutate the certificate's retained root or privately owned image.
	after.ConditionalRegion, after.Entry = false, testEntry
	*im = *foreign
	retained, _ := continued.Bound()
	if !retained.ConditionalRegion || retained.Entry != entry {
		t.Fatal("projection upgraded root")
	}
	if _, ok := continued.BoundFor(im); ok {
		t.Fatal("replaced container borrowed old image")
	}
}

func TestTransitionConditionalRegionStateProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(0x524547494f4e))
	for sample := 0; sample < 12; sample++ {
		raw := make([]byte, 512)
		for i := 0; i < len(raw); i += 8 {
			binary.LittleEndian.PutUint64(raw[i:], rng.Uint64())
		}
		for distance := int32(-8); distance <= 8; distance++ {
			records := imageSequenceRecords(distance, byte(sample), rng.Uint64())
			records = append(records, sequenceRecord(to.Intent{Operation: to.Clear32, Dst: uint8(sample)}, byte(sample))...)
			records = append(records, sequenceRecord(to.Intent{Operation: to.Load, Dst: 15, Base: uint8(sample)}, 0)...)
			program := sequenceRecords(records, []byte{byte(sample)}, 4096)
			checkStateSequenceRootAt(t, imageStateFace(), program, raw, []byte{255, 255, 255}, rng.Uint64(), testEntry, 4096, false, true, imageSequenceLoads(len(program))...)
		}
	}
}

func TestTransitionConditionalRegionCallTLS(t *testing.T) {
	for _, seed := range []uint64{0, 17, 43} {
		raw := make([]byte, 512)
		for i := range raw {
			raw[i] = byte(uint64(i)*37 + seed)
		}
		checkCallTLSRootPopulation(t, seed, raw, true)
	}
}

func FuzzTransitionConditionalRegionSequence(f *testing.F) {
	f.Add(imageSequenceRecords(8, 0, imageStateAddress), []byte{}, []byte{255, 255}, make([]byte, 512), uint64(17))
	f.Add(imageSequenceRecords(-1, 3, ^uint64(0)), []byte{0x24}, []byte{0x55}, []byte{1, 2, 3}, uint64(91))
	f.Add(append(sequenceRecord(to.Intent{Operation: to.Clear32, Dst: 4}, 7), sequenceRecord(to.Intent{Operation: to.Load, Dst: 0, Base: 4}, 0)...), []byte{}, []byte{255}, []byte{255}, uint64(33))
	f.Fuzz(func(t *testing.T, records, blocks, cuts, values []byte, layout uint64) {
		program := sequenceRecords(records, blocks, 256)
		checkStateSequenceRootAt(t, imageStateFace(), program, values, cuts, layout, testEntry, 256, false, true, imageSequenceLoads(len(program))...)
	})
}

func TestTransitionConditionalRegionClear32Population(t *testing.T) {
	for _, rex := range []byte{0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47} {
		for _, op := range []byte{0x31, 0x33} {
			for modrm := 0; modrm < 256; modrm++ {
				var raw []byte
				if rex != 0 {
					raw = append(raw, rex)
				}
				compareExecutedEncoding(t, append(raw, op, byte(modrm)))
			}
		}
	}
	for d := range to.Descriptors {
		if d.Intent.Operation != to.Clear32 {
			continue
		}
		reg := int(d.Intent.Dst)
		encoded, err := to.Encode(d.Intent, d.Encoding)
		if err != nil {
			t.Fatal(err)
		}
		code := append([]byte{0xc3}, encoded...)
		cut := testEntry + uint64(len(code))
		im := image(t, append(code, 0xc3))
		p, err := ProposeRegionTransition(t.Context(), im, testEntry+1, cut, TransitionLimits{}, TransitionExpansion{PC: testEntry + 1})
		if err != nil {
			t.Fatal(err)
		}
		c, err := CheckRegionTransition(t.Context(), im, testEntry+1, transitionFace(), p, TransitionLimits{})
		if err != nil {
			t.Fatal(reg, d.Encoding, err)
		}
		b, _ := c.Bound()
		builder := br.NewBuilder(0)
		zero, _ := builder.Const(br.Bits(64), 0)
		if _, err := br.Prove(t.Context(), b.Registers[reg].Value, zero, br.Limits{}); err != nil {
			t.Fatal("self-XOR did not universally clear high bits", err)
		}
		if b.Registers[reg].Pointer != nil || b.Preserved[reg] != 0 || b.Flags.AF != (TransitionFlag{}) {
			t.Fatal("self-XOR retained provenance/preservation/AF")
		}
		for r := range b.Registers {
			if r != reg && (b.Registers[r].Value != b.InitialRegisters[r] || b.Preserved[r] != ^uint64(0)) {
				t.Fatal("self-XOR modified another register")
			}
		}
		for i, f := range []TransitionFlag{b.Flags.CF, b.Flags.OF, b.Flags.SF, b.Flags.ZF, b.Flags.PF} {
			value := uint64(0)
			if i >= 3 {
				value = 1
			}
			want, _ := builder.Const(br.Bool(), value)
			if !f.Defined || f.Preserved {
				t.Fatal("bad self-XOR flag definedness")
			}
			if _, err := br.Prove(t.Context(), f.Value, want, br.Limits{}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, bad := range [][]byte{{0x31, 0xc1}, {0x48, 0x31, 0xc0}, {0x66, 0x31, 0xc0}, {0x31, 0x00}, {0xf0, 0x31, 0xc0}} {
		im := image(t, append(append([]byte{}, bad...), 0xc3))
		p, err := ProposeRegionTransition(t.Context(), im, testEntry, testEntry+uint64(len(bad)), TransitionLimits{}, TransitionExpansion{PC: testEntry})
		if err == nil {
			_, err = CheckRegionTransition(t.Context(), im, testEntry, transitionFace(), p, TransitionLimits{})
		}
		if err == nil {
			t.Fatalf("unsupported XOR form accepted: %x", bad)
		}
	}
}
