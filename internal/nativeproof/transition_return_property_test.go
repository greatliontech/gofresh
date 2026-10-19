package nativeproof

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"math/rand"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

// This interface/stack population varies all non-RSP saved registers, their
// push order, independent caller bit patterns (including numerical aliases),
// and frame sizes 0..256. Intent fixes the stack slots and original values before
// native bytes or proof projections exist. No normal-return assumption is input.
func returnFrameRegisters(registers []byte) []Register {
	var saved []Register
	var seen [16]bool
	for _, selector := range registers {
		r := Register(selector % 16)
		if r != RSP && !seen[r] {
			seen[r] = true
			saved = append(saved, r)
		}
	}
	if len(saved) == 0 {
		saved = []Register{RBP}
	}
	return saved
}

func checkReturnFramePopulation(t testing.TB, registers []byte, frame uint16, seed uint64, wrongPop bool) {
	t.Helper()
	saved := returnFrameRegisters(registers)
	depth := int64(frame % 257)
	var code []byte
	stackRegister := func(pop bool, reg Register) {
		if reg >= 8 {
			code = append(code, 0x41)
		}
		op := byte(0x50)
		if pop {
			op = 0x58
		}
		code = append(code, op+byte(reg)%8)
	}
	for _, r := range saved {
		stackRegister(false, r)
	}
	firstCut := testEntry + uint64(len(code))
	code = binary.LittleEndian.AppendUint32(append(code, 0x48, 0x81, 0xec), uint32(depth))
	for _, r := range saved {
		if r >= 8 {
			code = append(code, 0x41)
		}
		code = binary.LittleEndian.AppendUint32(append(code, 0xb8+byte(r)%8), uint32(seed)^uint32(r))
	}
	code = binary.LittleEndian.AppendUint32(append(code, 0x48, 0x81, 0xc4), uint32(depth))
	for j := len(saved) - 1; j >= 0; j-- {
		r := saved[j]
		if wrongPop && j == 0 {
			r = (r + 1) % 16
			if r == RSP {
				r++
			}
		}
		stackRegister(true, r)
	}
	ret := testEntry + uint64(len(code))
	code = append(code, 0xc3)
	for j := 0; j < 16; j++ {
		code = append(code, 0x90)
	}
	target := testEntry + uint64(len(code))
	code = append(code, 0xc3)
	im, err := NewImage(t.Context(), elfBytes(code))
	if err != nil {
		t.Fatal(err)
	}
	bottom := -8*int64(len(saved)) - depth
	face := TransitionInterface{
		Origin: OriginDomain{Min: 1 << 40, Max: 1 << 41, Modulus: 1}, Envelope: RelativeSpan{bottom, 8}, Conditions: interfaceConditions(),
		Regions:       []RelativeRegion{{Bytes: RelativeSpan{bottom, 0}, Readable: true, Writable: true}, {Bytes: RelativeSpan{0, 8}, Readable: true}},
		ReturnContext: &TransitionReturnContext{Target: target, Preserved: saved},
		PrivateFrame:  &TransitionPrivateFrame{Bytes: RelativeSpan{bottom, 0}},
	}
	prefix := returnPrefix(t, im, face, ret)
	complete, err := CheckTransitionReturn(t.Context(), prefix)
	if wrongPop {
		returnRefused(t, complete, err)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	b, _ := complete.Bound()
	if b.Prefix.Interface.PrivateFrame == nil || *b.Prefix.Interface.PrivateFrame != *face.PrivateFrame {
		t.Fatal("frame population lost its explicit private lifetime premise")
	}
	if len(b.Accesses) != 2*len(saved)+1 || b.Accesses[len(b.Accesses)-1].Kind != FrameReturnRead || b.State.PC != target {
		t.Fatal("frame population lost ordered stack effects or continuation")
	}
	rng := rand.New(rand.NewSource(int64(seed)))
	values := map[br.Term]uint64{}
	var original [16]uint64
	for r, term := range b.Prefix.InitialRegisters {
		original[r] = rng.Uint64()
		if seed&1 != 0 {
			original[r] = seed // all caller words may alias numerically
		}
		values[term] = original[r]
	}
	base := uint64(1<<40) + seed%(1<<40)
	values[b.Prefix.Origin] = base
	for _, v := range b.Prefix.InitialMemory {
		values[v.Value] = uint64(byte(rng.Uint64()))
	}
	for j, r := range saved {
		if stateEval(t, b.State.Registers[r].Value, values) != original[r] || b.State.Preserved[r] != 0 {
			t.Fatal("saved register bits were not restored", r)
		}
		reg, ok := prefix.EntryValueRegister(b.State.Registers[r].Pointer)
		if !ok || reg != r {
			t.Fatal("caller provenance lineage was not restored", r)
		}
		slot := int64(-8 * (j + 1))
		if b.Accesses[j].Bytes != (RelativeSpan{slot, slot + 8}) || b.Accesses[j].Kind != FrameWrite || b.Accesses[len(saved)+j].Kind != FrameRead {
			t.Fatal("push/pop stack slot or order differs")
		}
		for _, v := range b.State.Memory {
			if !v.Image && v.Offset >= slot && v.Offset < slot+8 {
				if stateEval(t, v.Value, values) != original[r]>>(8*uint(v.Offset-slot))&255 {
					t.Fatal("return erased or changed residual saved bytes")
				}
			}
		}
	}
	if stateEval(t, b.State.Registers[RSP].Value, values) != base+8 {
		t.Fatal("RET failed to advance the restored stack")
	}
	prior := returnPrefix(t, im, face, firstCut)
	segmented, err := CheckTransitionContinuation(t.Context(), prior, entryRelationProposal(t, im, ret))
	if err != nil {
		t.Fatal(err)
	}
	assertTransitionAlpha(t, prefix, segmented)
	checkedReturn(t, segmented)
}

func FuzzTransitionReturnFrames(f *testing.F) {
	for _, regs := range [][]byte{{5}, {14, 5, 3}, {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 3, 2, 1, 0}, {0, 1, 2, 3}, {4, 4, 4}} {
		for _, size := range []uint16{0, 1, 16, 127, 128, 255, 256} {
			f.Add(regs, size, uint64(size)*0x123456789abcdef, false)
			f.Add(regs, size, uint64(size)|1, true)
		}
	}
	f.Fuzz(func(t *testing.T, regs []byte, size uint16, seed uint64, wrong bool) {
		checkReturnFramePopulation(t, regs, size, seed, wrong)
	})
}

func TestTransitionReturnValueLineageLanes(t *testing.T) {
	// A full copy restores lineage. Rewriting one byte from the SAME original
	// low byte preserves scalar bits but destroys the complete-word lane proof;
	// numerical equality must not recreate caller provenance.
	for lane := byte(0); lane < 8; lane++ {
		code := []byte{0x48, 0x89, 0x6c, 0x24, 0xf8, // MOV [RSP-8],RBP
			0x48, 0x8b, 0x44, 0x24, 0xf8 + lane} // MOV RAX,[RSP-8+lane]
		// A single RW region permits the unaligned read across the protected
		// word. It does not permit writing the control word itself.
		im, face := returnFixture(t, hex.EncodeToString(append(append([]byte{}, code...), 0xc3)))
		face.Regions = []RelativeRegion{{Bytes: RelativeSpan{-24, 8}, Readable: true, Writable: true}}
		face.ReturnContext.Preserved = []Register{RBP}
		good := returnPrefix(t, im, face, testEntry+uint64(len(code)))
		checkedReturn(t, good) // original RBP remains intact
		// AL is the actual byte just read at this lane, not a sampled constant.
		code = append(code, 0x88, 0x44, 0x24, 0xf8+lane)
		code = append(code, 0x48, 0x8b, 0x6c, 0x24, 0xf8)
		ret := testEntry + uint64(len(code))
		im, _ = returnFixture(t, hex.EncodeToString(append(code, 0xc3)))
		prefix := returnPrefix(t, im, face, ret)
		b, _ := prefix.Bound()
		for _, original := range []uint64{0, 0x123456789abcdef, math.MaxUint64} {
			values := entryRelationValues(b, 4096, 0)
			values[b.InitialRegisters[RBP]] = original
			if stateEval(t, b.Registers[RBP].Value, values) != original {
				t.Fatal("partial-copy control changed scalar bits, masking lineage loss")
			}
		}
		c, err := CheckTransitionReturn(t.Context(), prefix)
		returnRefused(t, c, err)
	}
	// Concrete pointer provenance and caller lineage share the same whole-word
	// lane transport, but restoring the concrete bound register retains its arm.
	im, face := returnFixture(t, "415641be00000000415ec3")
	face.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 8}}
	face.EntryImagePointers = []TransitionEntryImagePointer{{Register: R14, Address: imageStateAddress}}
	face.ReturnContext.Preserved = []Register{R14}
	prefix := returnPrefix(t, im, face, testEntry+10)
	b, _ := checkedReturn(t, prefix).Bound()
	if _, ok := b.State.Registers[R14].Pointer.(ImagePointer); !ok {
		t.Fatal("concrete entry pointer became unconstrained lineage")
	}
	values := entryRelationValues(b.Prefix, 4096, 0)
	if stateEval(t, b.State.Registers[R14].Value, values) != imageStateAddress || b.State.Preserved[R14] != 0 {
		t.Fatal("concrete pointer bits were not actually restored")
	}
}

func TestTransitionReturnRegisterAliasLineage(t *testing.T) {
	for r := Register(0); r <= R15; r++ {
		if r == RSP {
			continue
		}
		for _, width := range []int{8, 32, 64} {
			var code []byte
			rex := byte(0x40)
			if r >= 8 {
				rex |= 5
			}
			if width == 64 {
				rex |= 8
			}
			if rex != 0x40 || width == 8 && r >= 4 {
				code = append(code, rex)
			}
			op := byte(0x89)
			if width == 8 {
				op = 0x88
			}
			code = append(code, op, 0xc0+byte(r%8)*9)
			ret := testEntry + uint64(len(code))
			im, face := returnFixture(t, hex.EncodeToString(append(code, 0xc3)))
			face.ReturnContext.Preserved = []Register{r}
			prefix := returnPrefix(t, im, face, ret)
			c, err := CheckTransitionReturn(t.Context(), prefix)
			if width == 64 {
				if err != nil || c.checked == nil {
					t.Fatal("full-register copy lost caller lineage", r, err)
				}
			} else {
				returnRefused(t, c, err)
			}
		}
	}
	for r := Register(0); r <= RBX; r++ {
		code := []byte{0x88, 0xc0 + (4+byte(r))*9, 0xc3} // AH/CH/DH/BH self-copy
		im, face := returnFixture(t, hex.EncodeToString(code))
		face.ReturnContext.Preserved = []Register{r}
		prefix := returnPrefix(t, im, face, testEntry+2)
		c, err := CheckTransitionReturn(t.Context(), prefix)
		returnRefused(t, c, err)
	}
	// Distinct entry tokens cannot exclude equality of their arbitrary bits.
	im, face := returnFixture(t, "4839e875020f0bc3")
	face.ReturnContext.Preserved = []Register{RAX, RBP}
	p := entryRelationProposal(t, im, testEntry+7)
	c, err := CheckRegionTransition(t.Context(), im, testEntry, face, p, TransitionLimits{})
	transitionRefused(t, c, err)
}

func TestTransitionReturnRetainedResourceLimits(t *testing.T) {
	im, face := returnFixture(t, "c3")
	face.Regions = []RelativeRegion{{Bytes: RelativeSpan{0, 8}, Readable: true}}
	face.Envelope = RelativeSpan{0, 8}
	p := entryRelationProposal(t, im, testEntry)
	for _, limits := range []TransitionLimits{
		{RelationLimits: RelationLimits{Depth: 1}},
		{LiveStateBytes: 16 << 10},
	} {
		prefix, err := CheckRegionTransition(t.Context(), im, testEntry, face, p, limits)
		if err != nil {
			t.Fatal("resource control did not admit the original prefix", limits, err)
		}
		c, err := CheckTransitionReturn(t.Context(), prefix)
		returnRefused(t, c, err)
	}
}

func TestTransitionReturnLineageCannotBecomeFSAddress(t *testing.T) {
	// The arbitrary incoming RSI word may contain any caller-side pointer, but
	// its private lineage does not establish a user-address range or TLS heap.
	im, face := returnFixture(t, "b89e000000bf021000000f0564488b042500000000c3")
	face.Conditions.Syscall, face.Conditions.UserAddressBits = LinuxAMD64SyscallModel, 48
	face.ReturnContext.Preserved = []Register{RSI}
	cut := testEntry + 12
	prefix := returnPrefix(t, im, face, cut, TransitionExpansion{PC: testEntry + 10})
	b, _ := prefix.Bound()
	if b.Thread.FS.Pointer != nil {
		t.Fatal("syscall converted caller value lineage into an address capability")
	}
	for _, base := range []uint64{0, imageStateAddress, 1 << 47, math.MaxUint64} {
		values := entryRelationValues(b, 4096, 0)
		values[b.InitialRegisters[RSI]], values[b.InitialFS] = base, 17
		want := uint64(17)
		if base < 1<<47-4096 {
			want = base
		}
		if stateEval(t, b.Thread.FS.Value, values) != want {
			t.Fatal("lineage incorrectly restricted raw syscall base bits")
		}
	}
	p := entryRelationProposal(t, im, testEntry+21, TransitionExpansion{PC: testEntry + 10})
	c, err := CheckTransitionContinuation(t.Context(), prefix, p)
	transitionRefused(t, c, err)
}
