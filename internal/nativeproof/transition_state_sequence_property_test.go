package nativeproof

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	quickrand "math/rand"
	"math/rand/v2"
	"slices"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// Sequence records are literal operations on the evolving state. No register
// is reserved, and no MOV/LEA is injected to repair an operand or mint pointer
// provenance. In particular, an anchor is available only after an actual input
// MOV record copies RSP. The state invariant at each boundary consists of all
// register values/tags, byte values/ordered lanes, flags and the ordered frame.
// The next operation's independently checked preconditions refer to that very
// state. This is the induction needed to compose arithmetic and heap effects;
// agreement of separately reset local cases would not establish it.
//
// A record has 32 bytes: operation, destination, source, base, encoding choice,
// reserved padding, uint64 immediate at 8, and int32 displacement at 24. Each
// field is independent. Missing final bytes are zero padded. Blocks are selected
// by a separate bit stream; no set bits means entirely contiguous execution.
func sequenceRecords(data, blocks []byte, instructionLimit int) []stateInstruction {
	var program []stateInstruction
	for recordIndex := 0; len(data) != 0; recordIndex++ {
		var record [32]byte
		n := copy(record[:], data)
		data = data[n:]
		dst, src, base := record[1]%16, record[2]%16, record[3]%16
		imm := binary.LittleEndian.Uint64(record[8:16])
		disp := int64(int32(binary.LittleEndian.Uint32(record[24:28])))
		var i to.Intent
		switch record[0] % 12 {
		case 0:
			i = to.Intent{Operation: to.MoveRegister, Dst: dst, Src: src}
		case 1:
			i = to.Intent{Operation: to.MoveImmediate, Dst: dst, Immediate: imm}
		case 2:
			i = to.Intent{Operation: to.MoveImmediate32, Dst: dst, Immediate: uint64(uint32(imm))}
		case 3:
			i = to.Intent{Operation: to.Load, Dst: dst, Base: base, SignedDisp: disp}
		case 4:
			i = to.Intent{Operation: to.Store, Src: src, Base: base, SignedDisp: disp}
		case 5:
			i = to.Intent{Operation: to.StoreImmediate, Base: base, SignedDisp: disp, Immediate: uint64(int64(int32(imm)))}
		case 6:
			i = to.Intent{Operation: to.LEA, Dst: dst, Base: base, SignedDisp: disp}
		case 7:
			i = to.Intent{Operation: to.Subtract, Dst: dst, Immediate: uint64(int64(int32(imm)))}
		case 8:
			i = to.Intent{Operation: to.And, Dst: dst, Immediate: uint64(int64(int32(imm)))}
		case 9:
			i = to.Intent{Operation: to.LEARIP, Dst: dst, SignedDisp: disp}
		case 10:
			i = to.Intent{Operation: to.CPUID}
		case 11:
			i = to.Intent{Operation: to.Clear32, Dst: dst}
		}
		program = append(program, stateOp(i, record[4]))
		if len(program) >= instructionLimit {
			break // the cut adds the first node beyond the actual supplied limit
		}
		if len(data) != 0 && recordIndex/8 < len(blocks) && blocks[recordIndex/8]&(1<<(recordIndex%8)) != 0 {
			program = append(program, stateOp(to.Intent{Operation: to.Jump}, record[4]))
			if len(program) >= instructionLimit {
				break
			}
		}
	}
	return program
}

// Every positive representable int is retained verbatim. Only zero and fuzz
// values outside the host-int domain select another positive configuration.
func sequencePositiveLimit(raw uint64) int {
	maximum := uint64(^uint(0) >> 1)
	if raw == 0 || raw > maximum {
		raw = 1 + raw%maximum
	}
	return int(raw)
}

// Work and nodes depend on the materialized image/state, never the numerical
// instruction allowance. MaxInt instructions with a three-instruction image
// therefore remains cheap. Big integers prevent host-int overflow, including on
// 386. Initial validation includes declared-byte sorting and word/region pairs;
// each continuation includes graph reconstruction and live-term imports.
// Unrepresentable allowances deliberately produce an invalid configuration,
// following the existing interface-state controls. That result is explicitly a
// configuration refusal, not an execution theorem or a tolerated work failure.
func sequenceLimits(face TransitionInterface, native, cardinality, continuations, instructionLimit int) (TransitionLimits, bool) {
	l := TransitionLimits{RelationLimits: RelationLimits{Instructions: instructionLimit, Nodes: -1, Work: -1, Depth: 512}, Regions: 256, Bytes: 1 << 20}
	product := func(values ...int) *big.Int {
		v := big.NewInt(1)
		for _, value := range values {
			v.Mul(v, big.NewInt(int64(value)))
		}
		return v
	}
	declared := new(big.Int)
	for _, region := range face.Regions {
		n := new(big.Int).Sub(big.NewInt(region.Bytes.End), big.NewInt(region.Bytes.Start))
		if n.Sign() > 0 {
			declared.Add(declared, n)
		}
	}
	for _, region := range face.ImageRegions {
		n := new(big.Int).Sub(interfaceU(region.End), interfaceU(region.Start))
		if n.Sign() > 0 {
			declared.Add(declared, n)
		}
	}
	if declared.Cmp(big.NewInt(1<<20+1)) > 0 {
		declared.SetInt64(1<<20 + 1) // larger declarations refuse before initialization
	}
	r, w := len(face.Regions)+len(face.ImageRegions), len(face.Words)
	levels := 1
	for remaining := cardinality; remaining > 0; remaining /= 2 {
		levels++
	}
	nodes := big.NewInt(256)
	for _, term := range []*big.Int{product(16, native), product(1, cardinality), product(9, w)} {
		nodes.Add(nodes, term)
	}
	work := big.NewInt(4096)
	work.Add(work, new(big.Int).Mul(declared, big.NewInt(32)))
	for _, term := range []*big.Int{product(32, cardinality), product(16, cardinality, levels), product(64, native), product(64, w), product(32, r), product(w, r)} {
		work.Add(work, term)
	}
	for _, count := range []int{r, w} {
		if count > 1 {
			work.Add(work, new(big.Int).Div(product(count, count-1), big.NewInt(2)))
		}
	}
	perSegment := product(64, native)
	perSegment.Add(perSegment, new(big.Int).Mul(big.NewInt(16), nodes))
	perSegment.Add(perSegment, product(64, cardinality))
	perSegment.Add(perSegment, product(8, cardinality, levels))
	perSegment.Add(perSegment, product(32, w))
	perSegment.Add(perSegment, big.NewInt(4096))
	work.Add(work, new(big.Int).Mul(perSegment, big.NewInt(int64(continuations))))
	maximum := new(big.Int).SetUint64(uint64(^uint(0) >> 1))
	if nodes.Sign() <= 0 || work.Sign() <= 0 || nodes.Cmp(maximum) > 0 || work.Cmp(maximum) > 0 {
		return l, false
	}
	l.Nodes, l.Work = int(nodes.Int64()), int(work.Int64())
	return l, true
}

// No production address, alignment, permission or transfer helper participates.
// Integer offset arithmetic is unbounded until its representability is proved.
// The rounded domain endpoints are the pre-exclusion endpoints: removing image
// collisions cannot repair an invalid envelope or pointer arithmetic premise.
func sequenceOperationFault(face TransitionInterface, domain interfaceInterval, r stateReference, i to.Intent, nextPC ...uint64) string {
	offset := func(v *big.Int) string {
		if !v.IsInt64() {
			return "transition-origin"
		}
		if v.Cmp(big.NewInt(face.Envelope.Start)) < 0 || v.Cmp(big.NewInt(face.Envelope.End)) > 0 {
			return "transition-envelope"
		}
		ceiling := new(big.Int).Lsh(big.NewInt(1), 47)
		for _, s := range []*big.Int{domain.lo, domain.hi} {
			x := new(big.Int).Add(s, v)
			if x.Sign() < 0 || x.Cmp(ceiling) >= 0 {
				return "transition-origin"
			}
		}
		return ""
	}
	advance := func(p statePointer, delta int64) (*big.Int, string) {
		v := new(big.Int).Add(big.NewInt(p.off), big.NewInt(delta))
		if p.image {
			load := r.loads[p.load]
			if v.Cmp(interfaceU(load.start)) < 0 || v.Cmp(interfaceU(load.end)) > 0 || v.Cmp(new(big.Int).Lsh(big.NewInt(1), 47)) >= 0 {
				return v, "transition-image"
			}
			return v, ""
		}
		return v, offset(v)
	}
	switch i.Operation {
	case to.CPUID:
		if face.Conditions.CPUID == "" {
			return "transition-primitive-premise"
		}
	case to.LEARIP:
		if len(nextPC) != 1 {
			panic("RIP reference needs located next PC")
		}
		v := new(big.Int).Add(interfaceU(nextPC[0]), big.NewInt(i.SignedDisp))
		if v.Sign() < 0 || v.Cmp(new(big.Int).Lsh(big.NewInt(1), 47)) >= 0 {
			return "transition-image"
		}
		for _, load := range r.loads {
			if v.Cmp(interfaceU(load.start)) >= 0 && v.Cmp(interfaceU(load.end)) < 0 {
				return ""
			}
		}
		return "transition-image"
	case to.Load, to.Store, to.StoreImmediate:
		p := r.ptrs[i.Base]
		if !p.valid {
			return "transition-provenance"
		}
		lo, fault := advance(p, i.SignedDisp)
		if fault != "" {
			return fault
		}
		hi := new(big.Int).Add(lo, big.NewInt(8))
		if p.image {
			load := r.loads[p.load]
			if hi.Cmp(interfaceU(load.end)) > 0 {
				return "transition-image"
			}
			granted := load.write && !load.execute
			if i.Operation == to.Load {
				granted = load.read
			}
			for _, region := range face.ImageRegions {
				if granted && lo.Cmp(interfaceU(region.Start)) >= 0 && hi.Cmp(interfaceU(region.End)) <= 0 {
					return ""
				}
			}
			return "transition-permission"
		}
		if fault = offset(hi); fault != "" {
			return fault
		}
		for _, region := range face.Regions {
			granted := region.Writable
			if i.Operation == to.Load {
				granted = region.Readable
			}
			if granted && lo.Cmp(big.NewInt(region.Bytes.Start)) >= 0 && hi.Cmp(big.NewInt(region.Bytes.End)) <= 0 {
				return ""
			}
		}
		return "transition-permission"
	case to.LEA:
		if p := r.ptrs[i.Base]; p.valid {
			_, fault := advance(p, i.SignedDisp)
			return fault
		}
	case to.Subtract:
		if p := r.ptrs[i.Dst]; p.valid {
			_, fault := advance(p, -int64(i.Immediate))
			return fault
		}
	case to.And:
		p := r.ptrs[i.Dst]
		k := new(big.Int).Neg(big.NewInt(int64(i.Immediate)))
		if !p.valid || p.image || k.Sign() <= 0 || !k.IsInt64() {
			return "transition-alignment"
		}
		odd := new(big.Int).Set(k)
		for odd.Bit(0) == 0 {
			odd.Div(odd, big.NewInt(2))
		}
		if odd.Cmp(big.NewInt(1)) != 0 || new(big.Int).Mod(interfaceU(face.Origin.Modulus), k).Sign() != 0 {
			return "transition-alignment"
		}
		if fault := offset(big.NewInt(p.off)); fault != "" {
			return fault
		}
		rem := new(big.Int).Mod(new(big.Int).Add(interfaceU(face.Origin.Residue), big.NewInt(p.off)), k)
		return offset(new(big.Int).Sub(big.NewInt(p.off), rem))
	}
	return ""
}

// Every block may contain any number of semantic instructions. Only explicitly
// selected block boundaries acquire a JMP; an empty partition stream gives a
// completely contiguous program. Logical order, physical permutation and gap
// bytes are independent. A fixed, page-rounded LOAD extent is chosen from the
// instruction count before encoding, so interface admission can precede the ISA
// reference execution and encoding without borrowing Image's mapping inventory.
func sequenceMappingSize(count int) int {
	return ((count+1)*64 + 4095) / 4096 * 4096
}

func sequenceLayout(t testing.TB, program []stateInstruction, seed uint64, dataLoads ...interfaceMapping) stateLayout {
	t.Helper()
	return sequenceLayoutAt(t, program, seed, testEntry, dataLoads...)
}

func sequenceLayoutAt(t testing.TB, program []stateInstruction, seed, entry uint64, dataLoads ...interfaceMapping) stateLayout {
	t.Helper()
	type block struct {
		start, end, capacity int
	}
	x := stateLayout{pcs: make([]uint64, len(program)+1), encoded: make([][]byte, len(program)+1)}
	blocks := []block{{}}
	for j, op := range program {
		x.intents = append(x.intents, op.intent)
		b := &blocks[len(blocks)-1]
		b.end = j + 1
		if op.intent.Operation == to.Jump {
			b.capacity += 5
			blocks = append(blocks, block{start: j + 1, end: j + 1})
			continue
		}
		encoded, err := to.Encode(op.intent, stateEncoding(op.intent, op.choice))
		if err != nil {
			t.Fatal(err)
		}
		x.encoded[j] = encoded
		b.capacity += len(encoded)
	}
	blocks[len(blocks)-1].capacity += 2
	rng := rand.New(rand.NewPCG(seed, 0x53455155454e4345))
	permutation := rng.Perm(len(blocks))
	for j, b := range permutation {
		if b == 0 {
			permutation[0], permutation[j] = 0, permutation[0]
			break
		}
	}
	positions := make([]int, len(blocks))
	end := 0
	for _, b := range permutation {
		positions[b] = end
		end += blocks[b].capacity + int(rng.Uint64()%17)
	}
	code := make([]byte, sequenceMappingSize(len(program)))
	if end > len(code) {
		t.Fatal("independent LOAD extent underestimated layout")
	}
	for j := range code {
		code[j] = byte(rng.Uint64())
	}
	for b, block := range blocks {
		off := positions[b]
		for j := block.start; j < block.end; j++ {
			x.pcs[j] = entry + uint64(off)
			if program[j].intent.Operation == to.Jump {
				target := entry + uint64(positions[b+1])
				disp := int64(target) - int64(x.pcs[j]+5)
				choice := uint8(1)
				short := int64(target) - int64(x.pcs[j]+2)
				if program[j].choice&1 == 0 && short >= -128 && short <= 127 {
					disp, choice = short, 0
				}
				jump := to.Intent{Operation: to.Jump, SignedDisp: disp}
				var err error
				x.encoded[j], err = to.Encode(jump, stateEncoding(jump, choice))
				if err != nil {
					t.Fatal(err)
				}
			}
			copy(code[off:], x.encoded[j])
			off += len(x.encoded[j])
		}
		if b == len(blocks)-1 {
			x.pcs[len(program)] = entry + uint64(off)
			x.encoded[len(program)] = []byte{0x0f, 0x0b}
			copy(code[off:], x.encoded[len(program)])
		}
	}
	x.mappings = append([]interfaceMapping{{start: entry, end: entry + uint64(len(code)), file: 0x1000, filesz: uint64(len(code)), read: true, execute: true}}, dataLoads...)
	raw := transitionImageELF(t, code, dataLoads)
	binary.LittleEndian.PutUint64(raw[24:], entry)
	binary.LittleEndian.PutUint64(raw[80:], entry)
	x.digest = sha256.Sum256(raw)
	var err error
	x.im, err = NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func sequenceOrigin(face TransitionInterface, verdict interfaceVerdict, data []byte) uint64 {
	var field [8]byte
	copy(field[:], data)
	index := binary.LittleEndian.Uint64(field[:])
	total := uint64(0)
	for _, component := range verdict.allowed {
		first, last, ok := interfaceCongruent(component, face.Origin)
		if ok {
			total += (last.Uint64()-first.Uint64())/face.Origin.Modulus + 1
		}
	}
	index %= total
	for _, component := range verdict.allowed {
		first, last, ok := interfaceCongruent(component, face.Origin)
		if !ok {
			continue
		}
		n := (last.Uint64()-first.Uint64())/face.Origin.Modulus + 1
		if index < n {
			return first.Uint64() + index*face.Origin.Modulus
		}
		index -= n
	}
	panic("nonempty independent origin set lost its selected member")
}

func sequenceRefused(t testing.TB, c TransitionCertificate, err error, premise string, pc uint64) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) || c.checked != nil || r.Premise != premise || r.PC != pc {
		t.Fatalf("expected %s at %#x, got %v", premise, pc, err)
	}
}

func sequenceCardinality(face TransitionInterface) int {
	image := TransitionInterface{}
	for _, span := range face.ImageRegions {
		image.Regions = append(image.Regions, RelativeRegion{Bytes: RelativeSpan{int64(span.Start), int64(span.End)}})
	}
	imageCount := 0
	if len(image.Regions) != 0 {
		imageCount = sequenceCardinality(image)
	}
	var spans []RelativeSpan
	for _, region := range face.Regions {
		spans = append(spans, region.Bytes)
	}
	slices.SortFunc(spans, func(a, b RelativeSpan) int { return cmp.Compare(a.Start, b.Start) })
	count := int64(0)
	var end int64
	for j, span := range spans {
		lo := span.Start
		if j > 0 {
			lo = max(lo, end)
		}
		if span.End > lo {
			count += span.End - lo
		}
		end = max(end, span.End)
		if j == 0 {
			end = span.End
		}
	}
	// The independent admission oracle already bounded the declared sum by 1MiB.
	return int(count) + imageCount
}

func sequenceExclusions(t testing.TB, b TransitionBound, verdict interfaceVerdict) {
	t.Helper()
	actual := []interfaceInterval{verdict.base}
	for _, span := range b.ExcludedOrigins {
		if span.Start >= span.End || interfaceU(span.Start).Cmp(verdict.base.lo) < 0 || interfaceU(span.End-1).Cmp(verdict.base.hi) > 0 {
			t.Fatal("invalid projected origin exclusion")
		}
		actual = interfaceSubtract(actual, interfaceInterval{interfaceU(span.Start), interfaceU(span.End - 1)})
	}
	if len(actual) != len(verdict.allowed) {
		t.Fatal("origin exclusion component count differs")
	}
	for j, component := range actual {
		if component.lo.Cmp(verdict.allowed[j].lo) != 0 || component.hi.Cmp(verdict.allowed[j].hi) != 0 {
			t.Fatal("origin exclusions differ from the independent interface oracle")
		}
	}
}

// The same whole-certificate oracle serves arbitrary interleavings and arbitrary
// admitted geometry. Initial values and semantic operands are independently
// supplied; layout fixes RIP's next PC without borrowing decoded operands or
// checker state. A semantic or depth failure stops the reference before the
// unsupported operation, whose exact PC is checked against that layout.
// Every accepted root and continuation is checked in full. Re-running the small
// reference to selected cuts avoids retaining a byte-map clone per instruction
// for the large-geometry domain. Uninstantiated input tails carry no theorem.
func checkStateSequence(t testing.TB, face TransitionInterface, program []stateInstruction, raw, cutBits []byte, layout uint64, instructionLimit int, dataLoads ...interfaceMapping) {
	t.Helper()
	checkStateSequenceAt(t, face, program, raw, cutBits, layout, testEntry, instructionLimit, dataLoads...)
}

type sequenceOutcome struct {
	cut           int
	premise       string
	configuration bool
}

// Returning the independently predicted frontier lets geometry families require
// successful complete controls beside each negative, rather than passing a
// population consisting solely of correctly refused constructions.
func checkStateSequenceAt(t testing.TB, face TransitionInterface, program []stateInstruction, raw, cutBits []byte, layout, entry uint64, instructionLimit int, dataLoads ...interfaceMapping) sequenceOutcome {
	return checkStateSequenceProfileAt(t, face, program, raw, cutBits, layout, entry, instructionLimit, false, dataLoads...)
}

func checkStateSequenceProfileAt(t testing.TB, face TransitionInterface, program []stateInstruction, raw, cutBits []byte, layout, entry uint64, instructionLimit int, initialized bool, dataLoads ...interfaceMapping) sequenceOutcome {
	return checkStateSequenceRootAt(t, face, program, raw, cutBits, layout, entry, instructionLimit, initialized, false, dataLoads...)
}

// The same independently generated transfers, oracle and continuation comparisons
// exercise conditional roots too. Only this synthetic fixture's ELF header is
// generated differently; actual artifact positives never rewrite their image.
func checkStateSequenceRootAt(t testing.TB, face TransitionInterface, program []stateInstruction, raw, cutBits []byte, layout, entry uint64, instructionLimit int, initialized, region bool, dataLoads ...interfaceMapping) sequenceOutcome {
	t.Helper()
	loads := [][2]uint64{{entry, entry + uint64(sequenceMappingSize(len(program)))}}
	mappings := append([]interfaceMapping{{start: loads[0][0], end: loads[0][1], file: 0x1000, filesz: loads[0][1] - loads[0][0], read: true, execute: true}}, dataLoads...)
	for _, m := range dataLoads {
		loads = append(loads, [2]uint64{m.start, m.end})
	}
	// Layout supplies PCs, never reconstructed semantic operands. RIP uses the
	// independently encoded instruction's full length and its original intent.
	x := sequenceLayoutAt(t, program, layout, entry, dataLoads...)
	if region {
		data := append([]byte(nil), x.im.data...)
		binary.LittleEndian.PutUint64(data[24:], x.pcs[len(program)])
		var err error
		x.im, err = NewImage(t.Context(), data)
		if err != nil {
			t.Fatal(err)
		}
		x.digest = sha256.Sum256(data)
	}
	checkRoot := func(p TransitionProposal, limits TransitionLimits) (TransitionCertificate, error) {
		if region {
			return CheckRegionTransition(t.Context(), x.im, entry, face, p, limits)
		}
		return CheckTransition(t.Context(), x.im, face, p, limits)
	}
	if initialized {
		var err error
		face.Initialization, err = CheckImageInitialization(t.Context(), x.im, StaticELFInitialization)
		if err != nil {
			t.Fatal(err)
		}
	}
	preflight := TransitionLimits{RelationLimits: RelationLimits{Instructions: instructionLimit}, Regions: 256, Bytes: 1 << 20}
	verdict := interfaceOracleLimits(t, face, loads, preflight, mappings...)
	// Invalid inventories are never materialized into reference byte maps.
	if verdict.premise != "" {
		limits, representable := sequenceLimits(face, len(program), 0, 0, instructionLimit)
		c, err := checkRoot(x.proposal(0), limits)
		if !representable {
			sequenceRefused(t, c, err, "transition-budget", 0)
			return sequenceOutcome{premise: "transition-budget", configuration: true}
		} else {
			pc := x.pcs[0]
			if len(face.Regions)+len(face.ImageRegions) > limits.Regions || len(face.Words) > limits.Bytes/8 {
				pc = 0
			}
			sequenceRefused(t, c, err, verdict.premise, pc)
		}
		return sequenceOutcome{premise: verdict.premise}
	}
	cardinality := sequenceCardinality(face)
	if limits, ok := sequenceLimits(face, len(program), cardinality, 0, instructionLimit); !ok {
		c, err := checkRoot(x.proposal(0), limits)
		sequenceRefused(t, c, err, "transition-budget", 0)
		return sequenceOutcome{premise: "transition-budget", configuration: true}
	}
	initial := stateRawInitial(face, raw)
	if initialized {
		initial = initializedReference(face, x.im.data, mappings, raw)
	}
	initial.loads = mappings
	initial.origin = sequenceOrigin(face, verdict, raw)
	initial.regs[4] = initial.origin
	r := initial.clone()
	depth := stateInitialDepth(face)
	cut := min(len(program), instructionLimit-1)
	fault, depthFault := "", false
	for j := 0; j < cut; j++ {
		i := program[j].intent
		if fault = sequenceOperationFault(face, verdict.base, r, i, x.pcs[j]+uint64(len(x.encoded[j]))); fault != "" {
			cut = j
			break
		}
		if depth.step(i, r) > 512 {
			cut, depthFault = j, true
			break
		}
		r.referenceExec(t, i, j, x.pcs[j]+uint64(len(x.encoded[j])))
	}
	var cuts []int
	for j := 1; j < cut; j++ {
		if (j-1)/8 < len(cutBits) && cutBits[(j-1)/8]&(1<<((j-1)%8)) != 0 {
			cuts = append(cuts, j)
		}
	}
	if cut > 0 {
		cuts = append(cuts, cut)
	}
	limits, representable := sequenceLimits(face, len(program), len(initial.memory), len(cuts), instructionLimit)
	if !representable {
		c, err := checkRoot(x.proposal(0), limits)
		sequenceRefused(t, c, err, "transition-budget", 0)
		return sequenceOutcome{premise: "transition-budget", configuration: true}
	}
	check := func(c TransitionCertificate, at int, values map[br.Term]uint64) {
		t.Helper()
		sequenceExclusions(t, c.checked.bound, verdict)
		want := initial.clone()
		profile := stateInitialDepth(face)
		for j := 0; j < at; j++ {
			profile.step(program[j].intent, want)
			want.referenceExec(t, program[j].intent, j, x.pcs[j]+uint64(len(x.encoded[j])))
		}
		stateAssert(t, c, x, at, initial, want, values)
		profile.assertProjection(t, c)
	}
	direct, err := checkRoot(x.proposal(cut), limits)
	if err != nil {
		t.Fatalf("independently admitted evolving prefix refused: %v", err)
	}
	check(direct, cut, stateBindings(t, direct, face, initial))
	root, err := checkRoot(x.proposal(0), limits)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := root.Bound()
	if original.ConditionalRegion != region {
		t.Fatal("root authority changed")
	}
	if original.Origin.View().Scope == direct.checked.bound.Origin.View().Scope {
		t.Fatal("independent sequence roots reused a variable namespace")
	}
	values := stateBindings(t, root, face, initial)
	check(root, 0, values)
	for _, next := range cuts {
		prior := root.checked.bound
		root, err = CheckTransitionContinuation(t.Context(), root, x.proposal(next))
		if err != nil {
			t.Fatal("admitted evolving continuation refused", err)
		}
		stateInheritedInputs(t, original, root.checked.bound)
		if root.checked.bound.ConditionalRegion != region || root.checked.bound.Entry != entry {
			t.Fatal("continuation changed root authority")
		}
		stateInheritedInputs(t, prior, root.checked.bound)
		check(root, next, values)
	}
	assertTransitionAlpha(t, direct, root)
	if fault != "" || depthFault {
		// Executing just the first unsupported instruction avoids confusing a
		// later inventory overflow with its independently established cause.
		proposal := x.proposal(cut + 1)
		c, err := checkRoot(proposal, limits)
		if depthFault {
			stateExpressionDepthRefused(t, c, err, x.pcs[cut])
		} else {
			sequenceRefused(t, c, err, fault, x.pcs[cut])
		}
		c, err = CheckTransitionContinuation(t.Context(), root, proposal)
		if depthFault {
			stateExpressionDepthRefused(t, c, err, x.pcs[cut])
		} else {
			sequenceRefused(t, c, err, fault, x.pcs[cut])
		}
		stateInheritedInputs(t, original, root.checked.bound)
		check(root, cut, values)
	}
	if len(program) >= instructionLimit {
		p := x.proposal(len(program))
		c, err := checkRoot(p, limits)
		stateInventoryOverflow(t, c, err, len(p.Nodes), instructionLimit)
		c, err = CheckTransitionContinuation(t.Context(), root, p)
		stateInventoryOverflow(t, c, err, len(p.Nodes), instructionLimit)
	}
	if depthFault {
		fault = "relation-budget"
	}
	return sequenceOutcome{cut: cut, premise: fault}
}

func sequenceRecord(i to.Intent, form byte) []byte {
	r := make([]byte, 32)
	operations := []to.Operation{to.MoveRegister, to.MoveImmediate, to.MoveImmediate32, to.Load, to.Store, to.StoreImmediate, to.LEA, to.Subtract, to.And, to.LEARIP, to.CPUID, to.Clear32}
	for j, operation := range operations {
		if i.Operation == operation {
			r[0] = byte(j)
		}
	}
	r[1], r[2], r[3], r[4] = i.Dst, i.Src, i.Base, form
	binary.LittleEndian.PutUint64(r[8:], i.Immediate)
	binary.LittleEndian.PutUint32(r[24:], uint32(i.SignedDisp))
	return r
}

func sequenceInterleaving(a, b, displacement int32, rotation uint8) []byte {
	reg := func(r uint8) uint8 { return (r + rotation) % 16 }
	// The first operation is an actual record, not seeded pointer metadata.
	ops := []to.Intent{
		{Operation: to.MoveRegister, Dst: reg(12), Src: 4},
		{Operation: to.Subtract, Dst: reg(0), Immediate: uint64(int64(a))},
		{Operation: to.Store, Base: reg(12), Src: reg(0)},
		{Operation: to.Load, Base: reg(12), Dst: reg(1)},
		{Operation: to.Subtract, Dst: reg(1), Immediate: uint64(int64(b))},
		{Operation: to.Store, Base: reg(12), Src: reg(1), SignedDisp: 8},
		{Operation: to.Load, Base: reg(12), Dst: reg(2), SignedDisp: 8},
		{Operation: to.LEA, Dst: reg(3), Base: reg(2), SignedDisp: int64(displacement)},
		{Operation: to.Store, Base: reg(12), Src: reg(3), SignedDisp: 16},
		{Operation: to.MoveRegister, Dst: reg(5), Src: reg(12)},
		{Operation: to.Subtract, Dst: reg(5), Immediate: 1},
		{Operation: to.And, Dst: reg(5), Immediate: ^uint64(15)},
		{Operation: to.Store, Base: reg(12), Src: reg(5), SignedDisp: 24},
		{Operation: to.Load, Base: reg(12), Dst: reg(6), SignedDisp: 24},
		{Operation: to.Load, Base: reg(6), Dst: reg(7), SignedDisp: 16},
	}
	var records []byte
	for j, i := range ops {
		records = append(records, sequenceRecord(i, byte(j))...)
	}
	return records
}

func sequenceFace(residue uint32) TransitionInterface {
	face := stateFace(1<<31, uint64(residue)%(1<<31))
	face.Envelope = RelativeSpan{-1 << 34, 1 << 34}
	return face
}

func FuzzTransitionStateEvolvingSequence(f *testing.F) {
	values := make([]byte, 224)
	for j := range values {
		values[j] = byte(j*37 + 17)
	}
	for _, limit := range []uint64{1, 4, 64, 4096, 65536, uint64(^uint(0) >> 1)} {
		for _, blocks := range [][]byte{nil, {0x24, 0x18}, {0xff, 0xff}} {
			f.Add(sequenceInterleaving(-2147483648, 2147483647, -7919, 0), blocks, []byte{0xff, 0xff, 0xff, 0xff}, values, limit, uint64(731), uint32(7))
		}
	}
	// A small contiguous image that actually exceeds the old 4096-node
	// configuration: accepting only small images below that limit is insufficient
	// to show that a larger supplied instruction allowance is honored.
	for _, limit := range []uint64{65536, uint64(^uint(0) >> 1)} {
		f.Add(make([]byte, 32*4097), []byte{}, []byte{0x55}, values, limit, uint64(917), uint32(7))
	}
	for _, i := range []to.Intent{
		{Operation: to.Load, Dst: 1, Base: 0},
		{Operation: to.Load, Dst: 1, Base: 4, SignedDisp: 56},
		{Operation: to.And, Dst: 0, Immediate: ^uint64(15)},
		{Operation: to.And, Dst: 4, Immediate: 7},
	} {
		f.Add(sequenceRecord(i, 0), []byte{}, []byte{0xff}, values, uint64(65536), uint64(971), uint32(3))
	}
	f.Fuzz(func(t *testing.T, records, blocks, cuts, valuation []byte, requestedLimit, layout uint64, residue uint32) {
		limit := sequencePositiveLimit(requestedLimit)
		checkStateSequence(t, sequenceFace(residue), sequenceRecords(records, blocks, limit), valuation, cuts, layout, limit)
	})
}

func TestTransitionStateEvolvingSequenceProperty(t *testing.T) {
	t.Parallel()
	if err := quick.Check(func(a, b, displacement int32, rotation uint8, values [28]uint64, partition, layout, requestedLimit uint64, residue uint32) bool {
		var raw []byte
		for _, value := range values {
			raw = binary.LittleEndian.AppendUint64(raw, value)
		}
		blocks := binary.LittleEndian.AppendUint64(nil, partition)
		limit := sequencePositiveLimit(requestedLimit)
		program := sequenceRecords(sequenceInterleaving(a, b, displacement, rotation), blocks, limit)
		// Cuts immediately before and after every arithmetic and heap operation
		// make a dropped load or a reset operand observable at its first use.
		cuts := make([]byte, (len(program)+7)/8)
		for j := range cuts {
			cuts[j] = 0xff
		}
		checkStateSequence(t, sequenceFace(residue), program, raw, cuts, layout, limit)
		return true
	}, &quick.Config{MaxCount: 32, Rand: quickrand.New(quickrand.NewSource(0x53455155454e4345))}); err != nil {
		t.Fatal(err)
	}
}

// Raw geometry retains full signed offsets, permissions, ordering, overlap and
// word selection. Only the first independently counted over-limit list is
// retained. Unlike the earlier small-interface decoder, the word inventory is
// permitted through the actual 1 MiB / 8 maximum, not capped at 64 words.
func sequenceGeometry(regions, words []byte) ([]RelativeRegion, []int64) {
	return interfaceRecords(regions, words, 256, interfaceMaxBytes/8)
}

// The stateful geometry factor is a whole certificate, not a union of separately
// initialized and transferred facts. Each accepted arbitrary interface is
// instantiated with independent raw values, then the selected address is reached
// by actual LEAs. A load, dependent SUB and overwrite cross continuation cuts.
// All bytes, including every untouched region, are checked on every accepted
// certificate. The invariant is that transfer can affect only its independently
// derived eight-byte footprint; inherited state supplies its exact operands and
// lane metadata. No restriction to a fixed-size byte union is used.
func FuzzTransitionStatefulGeometry(f *testing.F) {
	seed := func(face TransitionInterface, address int64, operation uint8, limit uint64) {
		r, w := interfaceEncode(face)
		values := make([]byte, 264)
		for j := range values {
			values[j] = byte(j*37 + 17)
		}
		f.Add(r, w, values, face.Origin.Min, face.Origin.Max, face.Origin.Modulus, face.Origin.Residue, face.Envelope.Start, face.Envelope.End, address, operation, limit, uint64(731))
	}
	for _, size := range []int64{8, 17, 513, 4097} {
		face := TransitionInterface{Origin: OriginDomain{1 << 41, 1 << 46, 16, 7}, Envelope: RelativeSpan{-1 << 40, 1 << 40}, Regions: []RelativeRegion{{RelativeSpan{-9, size - 9}, true, true}}, Words: []int64{-9}, Conditions: interfaceConditions()}
		seed(face, -9, 0, 65536)
		seed(face, -9, 1, uint64(^uint(0)>>1))
	}
	face := sequenceFace(0)
	seed(face, 56, 0, 4096) // writable-only bytes: load must refuse
	seed(face, 56, 1, 4096) // the store is independently admitted
	seed(face, 40, 0, 4096) // one-past pointer grants no read
	face.Regions = []RelativeRegion{{RelativeSpan{0, 8}, true, true}, {RelativeSpan{0, 8}, true, false}}
	seed(face, 0, 0, 4096)
	f.Fuzz(func(t *testing.T, regions, words, valuation []byte, low, high, modulus, residue uint64, start, end, address int64, operation uint8, requestedLimit, layout uint64) {
		rs, ws := sequenceGeometry(regions, words)
		face := TransitionInterface{Origin: OriginDomain{low, high, modulus, residue}, Envelope: RelativeSpan{start, end}, Regions: rs, Words: ws, Conditions: interfaceConditions()}
		limit := sequencePositiveLimit(requestedLimit)
		// First use a conservative one-page, empty-scope admission check. An
		// inadmissible interface is checked without constructing a huge address
		// walk; an admissible one is rejudged against its actual final mapping.
		admission := interfaceOracleLimits(t, face, [][2]uint64{{testEntry, testEntry + 4096}}, TransitionLimits{Regions: 256, Bytes: 1 << 20})
		var program []stateInstruction
		if admission.premise == "" {
			program = append(program, stateOp(to.Intent{Operation: to.MoveRegister, Dst: 12, Src: 4}, 0))
			remaining := new(big.Int).SetInt64(address)
			for remaining.Sign() != 0 && len(program) < limit {
				step := new(big.Int).Set(remaining)
				if step.Cmp(big.NewInt(2147483647)) > 0 {
					step.SetInt64(2147483647)
				}
				if step.Cmp(big.NewInt(-2147483648)) < 0 {
					step.SetInt64(-2147483648)
				}
				program = append(program, stateOp(to.Intent{Operation: to.LEA, Dst: 12, Base: 12, SignedDisp: step.Int64()}, operation))
				remaining.Sub(remaining, step)
				// Stop at the first independently established semantic/depth
				// frontier, rather than allocating a walk toward an int64 extreme.
				progress := new(big.Int).Sub(big.NewInt(address), remaining)
				if progress.Cmp(big.NewInt(face.Envelope.Start)) < 0 || progress.Cmp(big.NewInt(face.Envelope.End)) > 0 || len(program) > 512 {
					break
				}
			}
			if remaining.Sign() == 0 && len(program) < limit {
				if operation&1 == 0 {
					program = append(program, stateOp(to.Intent{Operation: to.Load, Dst: 0, Base: 12}, operation))
					if len(program) < limit {
						program = append(program, stateOp(to.Intent{Operation: to.Subtract, Dst: 0, Immediate: uint64(int64(int8(operation)))}, operation))
					}
				}
				if len(program) < limit {
					program = append(program, stateOp(to.Intent{Operation: to.Store, Src: 0, Base: 12}, operation))
				}
			}
		}
		// Three segment boundaries suffice to carry the address, loaded value
		// and overwritten heap across this factor; no per-byte/step cut matrix.
		cuts := make([]byte, (len(program)+7)/8)
		for _, cut := range []int{1, len(program) - 1, len(program) - 2} {
			if cut > 0 && cut < len(program) {
				cuts[(cut-1)/8] |= 1 << ((cut - 1) % 8)
			}
		}
		checkStateSequence(t, face, program, valuation, cuts, layout, limit)
		// Even an invalid geometry case contains a nonempty expected-accept
		// control, so an implementation that always refuses cannot pass.
		good := []stateInstruction{stateOp(to.Intent{Operation: to.MoveRegister, Dst: 0, Src: 4}, 0)}
		checkStateSequence(t, sequenceFace(0), good, valuation, nil, layout, 16)
	})
}

func TestTransitionStateSequenceLimitArithmetic(t *testing.T) {
	face := sequenceFace(0)
	for _, instructions := range []int{1, 4096, 65536, int(^uint(0) >> 1)} {
		l, ok := sequenceLimits(face, 3, 80, 3, instructions)
		if !ok || l.Instructions != instructions || l.Nodes <= 0 || l.Work <= 0 {
			t.Fatal("small image failed checked budget derivation", instructions, l)
		}
	}
	maximum := int(^uint(0) >> 1)
	l, ok := sequenceLimits(face, maximum, maximum, maximum, maximum)
	if ok || l.Nodes != -1 || l.Work != -1 {
		t.Fatal("unrepresentable arithmetic wrapped or silently requested defaults", l)
	}
}
