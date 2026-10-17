package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"math/rand/v2"
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

const entryPrefix = "eb020f0b488b3c24488d742408eb020f0b4889f84889f34883ec284883e4f0488944241848895c2420"

func transitionFace() TransitionInterface {
	return TransitionInterface{
		Origin: OriginDomain{Min: 64, Max: 1<<47 - 8, Modulus: 16}, Envelope: RelativeSpan{-48, 8},
		Regions: []RelativeRegion{{RelativeSpan{0, 8}, true, false}, {RelativeSpan{-24, -8}, false, true}}, Words: []int64{0},
		Conditions: TransitionConditions{Machine: MachineModel, InstructionMapping: true, EntryState: true, IsolatedExecution: true, MemoryMapping: true, NoHiddenAliases: true, UnalignedAccess: true},
	}
}

func transitionFixture(t testing.TB, prefix string) (*Image, uint64) {
	t.Helper()
	code := hexBytes(t, prefix)
	cut := testEntry + uint64(len(code))
	return image(t, append(code, hexBytes(t, "bd00000000")...)), cut
}

func proveTransition(t testing.TB, im *Image, cut uint64, f TransitionInterface) (TransitionCertificate, error) {
	t.Helper()
	p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{})
	if err != nil {
		return TransitionCertificate{}, err
	}
	return CheckTransition(t.Context(), im, f, p, TransitionLimits{})
}

func transitionRefused(t testing.TB, c TransitionCertificate, err error) {
	t.Helper()
	if err == nil || c.checked != nil {
		t.Fatalf("wanted no proof, got %v / %v", c, err)
	}
	var r *Refusal
	if !errors.As(err, &r) && !errors.Is(err, context.Canceled) {
		t.Fatalf("unstructured refusal: %v", err)
	}
}

func TestTransitionEntryPrefix(t *testing.T) {
	im, cut := transitionFixture(t, entryPrefix)
	c, err := proveTransition(t, im, cut, transitionFace())
	if err != nil {
		t.Fatal(err)
	}
	b, ok := c.Bound()
	if !ok || b.Entry != im.entry || b.Rules != TransitionRules || b.ImageDigest != im.digest || b.Origin != b.InitialRegisters[RSP] {
		t.Fatal("missing dependencies/origin")
	}
	if b.Boundary.PC != cut || b.Boundary.Instruction.Op != x86asm.MOV || b.Boundary.Instruction.Args[0] != x86asm.EBP || len(b.Boundary.Bytes) != 5 {
		t.Fatal("cut boundary", b.Boundary)
	}
	if len(b.Instructions) != 10 || len(b.Accesses) != 3 {
		t.Fatalf("incomplete executed coverage: %v %v", b.Instructions, b.Accesses)
	}
	for j, want := range []RelativeSpan{{0, 8}, {-24, -16}, {-16, -8}} {
		if b.Accesses[j].Bytes != want || (b.Accesses[j].Kind == FrameRead) != (j == 0) {
			t.Fatal("access inventory", b.Accesses)
		}
	}
	for _, r := range []Register{RSP, RBX, RSI} {
		want := int64(8)
		if r == RSP {
			want = -48
		}
		if b.Registers[r].Pointer != (OriginPointer{b.Origin, want}) {
			t.Fatal("wrong origin relation", r, b.Registers[r])
		}
	}
	for _, r := range []Register{RAX, RDI} {
		if b.Registers[r].Pointer != (OriginPointer{}) {
			t.Fatal("raw input word gained provenance")
		}
	}
	if b.Flags.AF.Defined || b.Flags.AF.Preserved || !b.Flags.PF.Defined || b.Flags.PF.Preserved || b.Flags.PF.Value != (br.Term{}) {
		t.Fatal("undefined/unprojected flags invented or preserved", b.Flags)
	}
	for _, f := range []TransitionFlag{b.Flags.CF, b.Flags.OF, b.Flags.SF, b.Flags.ZF} {
		if f.Preserved || !f.Defined || f.Value == (br.Term{}) || evalRelationTerm(t, f.Value, nil, 0) != 0 {
			t.Fatal("wrong derived flag", f)
		}
	}
	assertTransitionOracle(t, im, b, 160)
	// A later bound has a new quantified origin even for identical image bytes.
	d, err := proveTransition(t, im, cut, transitionFace())
	if err != nil {
		t.Fatal(err)
	}
	x, _ := d.Bound()
	if x.Origin == b.Origin {
		t.Fatal("fresh origin namespace reused")
	}
}

// The reference machine uses ordinary ISA uint64 arithmetic and actual bytes,
// without symbolic offsets, permission helpers, scalar transfer or provenance
// rules. Sampled S values exercise this oracle only; the proof quantifies S.
func assertTransitionOracle(t testing.TB, im *Image, b TransitionBound, samples int) {
	t.Helper()
	rng := rand.New(rand.NewPCG(0x91ac, 0x73bd))
	var previousPointer [8]byte
	for sample := 0; sample < samples; sample++ {
		domain := b.Interface.Origin
		s := uint64(0x100000000) + (rng.Uint64() & 0xfffffff0)
		s = (s &^ (domain.Modulus - 1)) + domain.Residue
		lo, hi, _ := originRange(domain)
		if sample == 0 {
			s = lo
		}
		if sample == 1 {
			s = hi
		}
		a := rng.Uint64()
		switch sample {
		case 0:
			a = 0
		case 1:
			a = math.MaxUint64
		case 2:
			a = s + 8 // numerical coincidence still supplies no pointer provenance
		case 3:
			a = 1 << 63
		}
		values := map[br.Term]uint64{b.Origin: s}
		var regs [16]uint64
		for r, v := range b.InitialRegisters {
			regs[r] = rng.Uint64()
			values[v] = regs[r]
		}
		regs[RSP], values[b.Origin] = s, s
		for _, w := range b.Words {
			values[w.Value] = a
		}
		memory := map[uint64]byte{}
		for _, v := range b.InitialMemory {
			if v.Value.View().Op == br.Variable {
				values[v.Value] = uint64(rng.Uint32() & 255)
			}
			memory[s+uint64(v.Offset)] = byte(evalRelationTerm(t, v.Value, values, 0))
		}
		initialRegs := regs
		initialMemory := map[uint64]byte{}
		for p, v := range memory {
			initialMemory[p] = v
		}
		var accesses []TransitionAccess
		pc := b.Entry
		for steps := 0; pc != b.Boundary.PC; steps++ {
			if steps > len(b.Instructions) {
				t.Fatal("oracle missed cut")
			}
			bytes, err := im.instructionBytes(pc)
			if err != nil {
				t.Fatal(err)
			}
			i, err := x86asm.Decode(bytes, 64)
			if err != nil {
				t.Fatal(err)
			}
			next := pc + uint64(i.Len)
			address := func(m x86asm.Mem) uint64 { return regs[int(m.Base-x86asm.RAX)] + uint64(m.Disp) }
			read := func(arg x86asm.Arg) uint64 {
				switch x := arg.(type) {
				case x86asm.Reg:
					return regs[int(x-x86asm.RAX)]
				case x86asm.Imm:
					return uint64(x)
				case x86asm.Mem:
					p := address(x)
					var bytes [8]byte
					for j := range bytes {
						bytes[j] = memory[p+uint64(j)]
					}
					accesses = append(accesses, TransitionAccess{pc, FrameRead, RelativeSpan{int64(p - s), int64(p-s) + 8}})
					return binary.LittleEndian.Uint64(bytes[:])
				default:
					t.Fatalf("oracle operand %v", arg)
					return 0
				}
			}
			switch i.Op {
			case x86asm.JMP:
				next += uint64(i.Args[0].(x86asm.Rel))
			case x86asm.MOV:
				v := read(i.Args[1])
				if mem, ok := i.Args[0].(x86asm.Mem); ok {
					p := address(mem)
					var bytes [8]byte
					binary.LittleEndian.PutUint64(bytes[:], v)
					for j, x := range bytes {
						memory[p+uint64(j)] = x
					}
					accesses = append(accesses, TransitionAccess{pc, FrameWrite, RelativeSpan{int64(p - s), int64(p-s) + 8}})
				} else {
					regs[int(i.Args[0].(x86asm.Reg)-x86asm.RAX)] = v
				}
			case x86asm.LEA:
				regs[int(i.Args[0].(x86asm.Reg)-x86asm.RAX)] = address(i.Args[1].(x86asm.Mem))
			case x86asm.SUB:
				regs[int(i.Args[0].(x86asm.Reg)-x86asm.RAX)] -= uint64(i.Args[1].(x86asm.Imm))
			case x86asm.AND:
				regs[int(i.Args[0].(x86asm.Reg)-x86asm.RAX)] &= uint64(i.Args[1].(x86asm.Imm))
			default:
				t.Fatalf("oracle instruction %v", i)
			}
			pc = next
		}
		if !reflect.DeepEqual(accesses, b.Accesses) {
			t.Fatalf("access sequence differs: %v != %v", accesses, b.Accesses)
		}
		for r, v := range b.Registers {
			if got := evalRelationTerm(t, v.Value, values, rng.Uint64()); got != regs[r] {
				t.Fatalf("register %d S=%#x: got %#x want %#x", r, s, got, regs[r])
			}
			if b.Preserved[r] != 0 && regs[r] != initialRegs[r] {
				t.Fatal("preserved GPR changed", r)
			}
			if v.Pointer.Origin != (br.Term{}) && (v.Pointer.Origin != b.Origin || regs[r] != s+uint64(v.Pointer.Offset)) {
				t.Fatal("pointer/scalar disagreement", r)
			}
		}
		for _, v := range b.Memory {
			p := s + uint64(v.Offset)
			if got := byte(evalRelationTerm(t, v.Value, values, rng.Uint64())); got != memory[p] {
				t.Fatalf("memory offset %d: %#x != %#x", v.Offset, got, memory[p])
			}
			written := false
			for _, access := range accesses {
				written = written || access.Kind == FrameWrite && v.Offset >= access.Bytes.Start && v.Offset < access.Bytes.End
			}
			if !written && memory[p] != initialMemory[p] {
				t.Fatal("memory outside write footprint changed")
			}
			if v.Pointer.Origin != (br.Term{}) && memory[p] != byte((s+uint64(v.Pointer.Offset))>>(8*v.PointerLane)) {
				t.Fatal("pointer byte relation differs")
			}
		}
		var pointer [8]byte
		spill := b.Accesses[2].Bytes.Start
		for j := range pointer {
			pointer[j] = memory[s+uint64(spill)+uint64(j)]
		}
		if sample > 0 && pointer == previousPointer {
			t.Fatal("rebasing retained identical pointer spill bytes")
		}
		previousPointer = pointer
	}
}

func TestTransitionOriginsAndPermissions(t *testing.T) {
	im, cut := transitionFixture(t, entryPrefix)
	for _, tt := range []struct {
		name   string
		change func(*TransitionInterface)
	}{
		{"empty", func(f *TransitionInterface) { f.Origin.Min = 100; f.Origin.Max = 90 }},
		{"no-residue", func(f *TransitionInterface) { f.Origin.Min = 65; f.Origin.Max = 79 }},
		{"bad-modulus", func(f *TransitionInterface) { f.Origin.Modulus = 3 }},
		{"bad-residue", func(f *TransitionInterface) { f.Origin.Residue = 16 }},
		{"weak-congruence", func(f *TransitionInterface) { f.Origin.Modulus = 8; f.Origin.Max = 1<<47 - 16 }},
		{"underflow", func(f *TransitionInterface) { f.Origin.Min = 0 }},
		{"noncanonical", func(f *TransitionInterface) { f.Origin.Max = 1 << 47 }},
		{"noncanonical-endpoint", func(f *TransitionInterface) { f.Origin.Modulus = 8 }},
		{"envelope-overflow", func(f *TransitionInterface) { f.Envelope.Start = math.MinInt64 }},
		{"envelope-is-not-permission", func(f *TransitionInterface) { f.Regions = f.Regions[:1] }},
		{"short-read", func(f *TransitionInterface) { f.Regions[0].Bytes.End = 7 }},
		{"short-write", func(f *TransitionInterface) { f.Regions[1].Bytes.End = -9 }},
		{"permissions", func(f *TransitionInterface) { f.Regions[1].Writable = false }},
		{"permission-conflict", func(f *TransitionInterface) {
			f.Regions = append(f.Regions, RelativeRegion{RelativeSpan{0, 8}, true, true})
		}},
		{"overlap-words", func(f *TransitionInterface) { f.Words = append(f.Words, 0) }},
		{"image-excludes-all", func(f *TransitionInterface) { f.Origin.Min = testEntry + 64; f.Origin.Max = testEntry + 4096 - 16 }},
		{"joint-image-exclusions", func(f *TransitionInterface) { f.Origin.Min = testEntry; f.Origin.Max = testEntry + 4096 + 16 }},
		{"missing-premise", func(f *TransitionInterface) { f.Conditions.NoHiddenAliases = false }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := transitionFace()
			tt.change(&f)
			c, err := proveTransition(t, im, cut, f)
			transitionRefused(t, c, err)
			if tt.name == "weak-congruence" {
				var r *Refusal
				if !errors.As(err, &r) || r.Premise != "transition-alignment" {
					t.Fatalf("congruence refusal was masked by another failure: %v", err)
				}
			}
		})
	}
	// A real subset of origins may collide; they remain excluded predicates. A
	// witness outside those pages proves joint nonemptiness, not a fixed base.
	f := transitionFace()
	f.Origin.Min = testEntry - 32
	f.Origin.Max = testEntry + 4096 + 64
	c, err := proveTransition(t, im, cut, f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if len(b.ExcludedOrigins) == 0 || b.Interface.Origin != f.Origin {
		t.Fatal("image exclusions or universal domain lost")
	}
}

func TestTransitionControlAndEncodingRefusals(t *testing.T) {
	for _, code := range []string{
		"4889e04883ec284883e4f0", // no A or spills is a valid theorem, tested separately below
	} {
		im, cut := transitionFixture(t, code)
		if _, err := proveTransition(t, im, cut, transitionFace()); err != nil {
			t.Fatal(err)
		}
	}
	for _, code := range []string{"89e4", "4883ec284883e4e0", "64488b0424", "67488b0424", "f048892424", "664889e4", "484889e4", "488d044c", "488b0500000000", "488b04c4", "7400", "e800000000", "c3", "0f05", "0fa2", "ffe0", "ebfe", "48c7c001000000488b00"} {
		t.Run(code, func(t *testing.T) {
			im, cut := transitionFixture(t, code)
			c, err := proveTransition(t, im, cut, transitionFace())
			transitionRefused(t, c, err)
		})
	}
	im, cut := transitionFixture(t, entryPrefix)
	for _, bad := range []uint64{cut + 1, cut + 5, testEntry + 1, testEntry + 2, testEntry - 1} {
		c, err := proveTransition(t, im, bad, transitionFace())
		transitionRefused(t, c, err)
	}
	p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*TransitionProposal){
		func(p *TransitionProposal) { p.Nodes = p.Nodes[1:] },
		func(p *TransitionProposal) { p.Nodes[0].Successors = nil },
		func(p *TransitionProposal) { p.Nodes[0].Successors = []uint64{cut} },
		func(p *TransitionProposal) { p.Entry += 4 },
		func(p *TransitionProposal) { p.Nodes[len(p.Nodes)-1].Successors = []uint64{cut + 5} },
	} {
		q := p
		q.Nodes = append([]Node(nil), p.Nodes...)
		change(&q)
		c, err := CheckTransition(t.Context(), im, transitionFace(), q, TransitionLimits{})
		transitionRefused(t, c, err)
	}
	// No usable ELF entry is required by existing leaf clients, only this checker.
	raw := elfBytes(hexBytes(t, "c3"))
	binary.LittleEndian.PutUint64(raw[24:], 0)
	noEntry, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prove(t, noEntry, testEntry, face(Masks{}, Masks{})); err != nil {
		t.Fatal(err)
	}
	if _, err := ProposeTransition(t.Context(), noEntry, testEntry, TransitionLimits{}); err == nil {
		t.Fatal("substituted caller entry")
	}
}

func TestTransitionPointerRoundTrips(t *testing.T) {
	f := transitionFace()
	f.Regions[1] = RelativeRegion{RelativeSpan{-24, 0}, true, true}
	for _, tt := range []struct {
		tail    string
		pointer bool
	}{
		{"488b4c2420", true},
		{"4889442421488b4c2420", false}, // eight-byte store partially overlaps the pointer
		{"48895c2421488b4c2420", false}, // same pointer, but shifted lanes do not reconstruct a word
		{"4889442420488b4c2420", false}, // raw A, even if numerically equal to S+8
	} {
		im, cut := transitionFixture(t, entryPrefix+tt.tail)
		c, err := proveTransition(t, im, cut, f)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := c.Bound()
		if got := b.Registers[RCX].Pointer.Origin != (br.Term{}); got != tt.pointer {
			t.Fatal("incorrect pointer reconstruction", tt)
		}
		assertTransitionOracle(t, im, b, 20)
	}
	// A raw scalar with the same numerical value as an address cannot address RAM.
	im, cut := transitionFixture(t, entryPrefix+"488b0f")
	c, err := proveTransition(t, im, cut, f)
	transitionRefused(t, c, err)
	// One-past is representable but does not gain readable bytes.
	im, cut = transitionFixture(t, entryPrefix+"488b0e")
	c, err = proveTransition(t, im, cut, f)
	transitionRefused(t, c, err)
}

func TestTransitionAlignmentRule(t *testing.T) {
	for _, d := range []int64{math.MinInt64, math.MinInt64 + 1, -65, -48, -40, -1, 0, 1, 40, math.MaxInt64} {
		for k := uint64(1); k <= 1024; k *= 2 {
			for r := uint64(0); r < k; r++ {
				checkAlignmentOracle(t, d, k, r, k)
			}
		}
	}
	for _, p := range [][4]uint64{{0, 0, 0, 1}, {0, 16, 16, 16}, {0, 16, 0, 32}, {0, 16, 0, 3}, {0, 16, 0, 0}} {
		if _, ok := alignmentOffset(int64(p[0]), p[1], p[2], p[3]); ok {
			t.Fatal("invalid alignment premise accepted", p)
		}
	}
}

func TestTransitionAlignmentZeroFlags(t *testing.T) {
	// No data is accessed: these are admissible ISA states for the conditional
	// theorem, not assertions about a Linux loader's actual initial stack.
	for _, maximum := range []uint64{0, 32} {
		face := transitionFace()
		face.Origin = OriginDomain{Min: 0, Max: maximum, Modulus: 16}
		face.Envelope = RelativeSpan{0, 8}
		face.Regions, face.Words = nil, nil
		im, cut := transitionFixture(t, "4883e4f0")
		certificate, err := proveTransition(t, im, cut, face)
		if err != nil {
			t.Fatal(err)
		}
		bound, _ := certificate.Bound()
		zf := bound.Flags.ZF
		if !zf.Defined || zf.Preserved {
			t.Fatal("AND omitted its zero-flag write")
		}
		if maximum == 0 {
			if zf.Value == (br.Term{}) || evalRelationTerm(t, zf.Value, nil, 0) != 1 {
				t.Fatal("zero result lost its derived ZF")
			}
		} else if zf.Value != (br.Term{}) {
			t.Fatal("mixed zero/nonzero origins acquired one constant ZF")
		}
	}
}

func TestTransitionAlignmentResiduesAndImmediateExtensions(t *testing.T) {
	// The resulting pointer offset changes with the origin's residue. The same
	// machine arithmetic and scalar expression are checked for every residue.
	for residue := uint64(0); residue < 16; residue++ {
		f := transitionFace()
		f.Origin.Residue = residue
		f.Origin.Max = 1<<47 - 17
		f.Envelope.Start = -64
		f.Regions[1] = RelativeRegion{RelativeSpan{-48, 0}, false, true}
		im, cut := transitionFixture(t, entryPrefix)
		c, err := proveTransition(t, im, cut, f)
		if err != nil {
			t.Fatal(residue, err)
		}
		b, _ := c.Bound()
		want := -int64(40 + (residue+8)%16)
		if b.Registers[RSP].Pointer.Offset != want {
			t.Fatal("alignment assumed zero residue", residue, b.Registers[RSP])
		}
		// The independent reference machine covers the complete register/byte
		// relation, with S chosen in this residue rather than a fixed aligned base.
		assertTransitionOracle(t, im, b, 8)
	}
	for _, code := range []string{
		"4889e0482d280000004825f0ffffff",     // accumulator imm32 forms
		"4881ec280000004881e4f0ffffff",       // group imm32 forms
		"48c7c0ffffffff48bb8877665544332211", // sign-extended imm32 and exact imm64
		"4883ecf84883ec08",                   // subtracting a negative immediate advances the pointer
	} {
		im, cut := transitionFixture(t, code)
		c, err := proveTransition(t, im, cut, transitionFace())
		if err != nil {
			t.Fatal(code, err)
		}
		b, _ := c.Bound()
		vals := map[br.Term]uint64{b.Origin: 0x100000000}
		switch code {
		case "4889e0482d280000004825f0ffffff":
			if b.Registers[RAX].Pointer.Offset != -48 || evalRelationTerm(t, b.Registers[RAX].Value, vals, 7) != 0x100000000-48 {
				t.Fatal("accumulator imm32 extension")
			}
		case "4881ec280000004881e4f0ffffff":
			if b.Registers[RSP].Pointer.Offset != -48 || evalRelationTerm(t, b.Registers[RSP].Value, vals, 7) != 0x100000000-48 {
				t.Fatal("group imm32 extension")
			}
		case "48c7c0ffffffff48bb8877665544332211":
			if evalRelationTerm(t, b.Registers[RAX].Value, vals, 7) != math.MaxUint64 || evalRelationTerm(t, b.Registers[RBX].Value, vals, 7) != 0x1122334455667788 {
				t.Fatal("MOV immediate extension")
			}
		default:
			if b.Registers[RSP].Pointer.Offset != 0 || evalRelationTerm(t, b.Registers[RSP].Value, vals, 7) != 0x100000000 {
				t.Fatal("negative SUB immediate extension")
			}
		}
	}
}

func TestTransitionJointOriginDomainAgainstEnumeration(t *testing.T) {
	im, _ := transitionFixture(t, entryPrefix)
	rng := rand.New(rand.NewPCG(7, 91))
	for trial := 0; trial < 200; trial++ {
		f := transitionFace()
		f.Origin.Min = testEntry - 64 + uint64(rng.IntN(4200))
		f.Origin.Max = f.Origin.Min + uint64(rng.IntN(80))
		f.Origin.Modulus = 1 << uint(rng.IntN(7))
		f.Origin.Residue = rng.Uint64() % f.Origin.Modulus
		inhabited := false
		for s := f.Origin.Min; s <= f.Origin.Max; s++ {
			if s%f.Origin.Modulus != f.Origin.Residue {
				continue
			}
			good := true
			for _, r := range f.Regions {
				start, end := s+uint64(r.Bytes.Start), s+uint64(r.Bytes.End)
				// The fixture has one image page; byte intersection with that
				// full page is equivalent to the required page disjointness.
				if start < testEntry+4096 && testEntry < end {
					good = false
				}
			}
			inhabited = inhabited || good
		}
		// A zero-length executed prefix isolates admissibility from alignment
		// transfer. The entry instruction is still decoded as the unexecuted cut.
		c, err := proveTransition(t, im, im.entry, f)
		if (err == nil) != inhabited || (c.checked != nil) != inhabited {
			t.Fatalf("trial %d domain %+v: inhabited=%v, err=%v", trial, f.Origin, inhabited, err)
		}
	}
}

func FuzzTransitionOriginBounds(f *testing.F) {
	f.Add(uint64(64), uint64(1<<47-8), uint8(4), uint64(0), int64(-48))
	f.Add(uint64(0), uint64(63), uint8(3), uint64(0), int64(-8))
	f.Add(uint64(1<<47-16), uint64(1<<47-1), uint8(0), uint64(0), int64(8))
	f.Fuzz(func(t *testing.T, low, high uint64, power uint8, residue uint64, offset int64) {
		low %= 1 << 47
		high %= 1 << 47
		if low > high {
			low, high = high, low
		}
		modulus := uint64(1) << (power % 47)
		residue %= modulus
		lo, hi, ok := originRange(OriginDomain{low, high, modulus, residue})
		// Independent big-integer division finds the first and last members.
		k := new(big.Int).SetUint64(modulus)
		first := new(big.Int).SetUint64(low)
		rem := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).SetUint64(residue), first), k)
		first.Add(first, rem)
		last := new(big.Int).SetUint64(high)
		rem.Mod(new(big.Int).Sub(last, new(big.Int).SetUint64(residue)), k)
		last.Sub(last, rem)
		wantOK := first.Cmp(last) <= 0
		if ok != wantOK || ok && (lo != first.Uint64() || hi != last.Uint64()) {
			t.Fatal("origin interval differs from integer congruence")
		}
		if !ok {
			return
		}
		m := &transitionChecker{valueBuilder: &valueBuilder{}, lo: lo, hi: hi, face: TransitionInterface{Envelope: RelativeSpan{math.MinInt64, math.MaxInt64}}}
		err := m.offset(offset)
		first.Add(first, big.NewInt(offset))
		last.Add(last, big.NewInt(offset))
		canonical := first.Sign() >= 0 && last.Cmp(new(big.Int).Lsh(big.NewInt(1), 47)) < 0
		if (err == nil) != canonical {
			t.Fatal("universal canonical/nonwrap check differs from integer oracle")
		}
	})
}

func checkAlignmentOracle(t testing.TB, d int64, modulus, residue, k uint64) {
	t.Helper()
	got, ok := alignmentOffset(d, modulus, residue, k)
	x := new(big.Int).Add(big.NewInt(d), new(big.Int).SetUint64(residue))
	rem := new(big.Int).Mod(x, new(big.Int).SetUint64(k))
	want := new(big.Int).Sub(big.NewInt(d), rem)
	if ok != want.IsInt64() || ok && got != want.Int64() {
		t.Fatalf("d=%d mod=%d r=%d k=%d: %d/%v != %s", d, modulus, residue, k, got, ok, want)
	}
}

func FuzzTransitionAlignment(f *testing.F) {
	f.Add(int64(-40), uint8(4), uint64(0), uint8(0))
	f.Add(int64(math.MinInt64+7), uint8(6), uint64(63), uint8(2))
	f.Add(int64(math.MaxInt64), uint8(20), uint64(177), uint8(5))
	f.Fuzz(func(t *testing.T, d int64, power uint8, residue uint64, weaker uint8) {
		power %= 47
		modulus := uint64(1) << power
		residue %= modulus
		k := modulus >> uint(weaker%(power+1))
		checkAlignmentOracle(t, d, modulus, residue, k)
	})
}
