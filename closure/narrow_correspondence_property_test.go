package closure

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"go/token"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

// This finite instruction-intent grammar drives three independent products:
// selected source ASM + Go SSA, synthetic native bytes, and concrete integer
// effects. The oracle never reads a reference evaluation, source trace, or native
// proof to obtain expected values. Its roots are conditional synthetic entries,
// not actual runtime implementation-use claims.
type narrowJointAtomic struct {
	op               x86asm.Op
	compare, operand uint32
}

type narrowJointIntent struct {
	initial uint32
	bytes   [3]byte
	atomics []narrowJointAtomic
	shape   uint16
}

// The actual native MOV seeds full RAX before CAS32. The selected source
// comparison still has only 32 bits; the high half is independent native intent.
func (p narrowJointIntent) accumulator(compare uint32) uint64 {
	return uint64(0xa5960000|uint32(p.shape))<<32 | uint64(compare)
}

func narrowJointProgram(current, compare, replacement uint32, bytes uint32, shape uint16) narrowJointIntent {
	// The independent first triple is followed by forced success and failure,
	// each comparing the current heap rather than the allocation's first value.
	after := current
	if current == compare {
		after = replacement
	}
	p := narrowJointIntent{initial: current, bytes: [3]byte{byte(bytes >> 16), byte(bytes), byte(bytes >> 24)}, shape: shape}
	p.atomics = []narrowJointAtomic{{x86asm.CMPXCHG, compare, replacement}, {x86asm.CMPXCHG, after, replacement ^ 0x80000000}, {x86asm.CMPXCHG, (replacement ^ 0x80000000) ^ 1, current},
		{x86asm.OR, 0, 0}, {x86asm.AND, 0, 255}, {x86asm.OR, 0, uint32(byte(bytes >> 8))}, {x86asm.AND, 0, uint32(byte(shape))}}
	return p
}

type narrowJointEvent struct {
	at     storageByteLocation
	width  int
	write  bool
	value  uint64
	atomic int // -1 for ordinary traffic
}

type narrowJointOracle struct {
	events []narrowJointEvent
	final  map[storageByteLocation]byte
}

var narrowJointGlobals = []string{"C0", "C1", "C2", "G", "H"}

func narrowJointGlobal(i int) storageByteLocation {
	return storageByteLocation{Image: true, Offset: 0x700008 + int64(i*8)}
}

func (p narrowJointIntent) oracle(initial map[storageByteLocation]byte) narrowJointOracle {
	o := narrowJointOracle{final: map[storageByteLocation]byte{}}
	for at, v := range initial {
		o.final[at] = v
	}
	emit := func(at storageByteLocation, width int, write bool, value uint64, atomic int) {
		o.events = append(o.events, narrowJointEvent{at, width, write, value, atomic})
		if write {
			for lane := range width {
				o.final[storageAt(at, int64(lane))] = byte(value >> (8 * lane))
			}
		}
	}
	x := p.initial
	m := p.bytes
	emit(storageByteLocation{Offset: -16}, 4, true, uint64(x), -1)
	for i, v := range m {
		emit(storageByteLocation{Offset: -24 + int64(i)}, 1, true, uint64(v), -1)
	}
	cas := 0
	for i, a := range p.atomics {
		if a.op == x86asm.CMPXCHG {
			old := x
			success := x == a.compare
			if success {
				x = a.operand
			}
			emit(storageByteLocation{Offset: -16}, 4, false, uint64(old), i)
			emit(storageByteLocation{Offset: -16}, 4, true, uint64(x), i)
			result := uint64(2)
			if success {
				result = 1
			}
			emit(narrowJointGlobal(cas), 4, true, result, -1)
			cas++
		} else {
			old := m[1]
			if a.op == x86asm.OR {
				m[1] |= byte(a.operand)
			} else {
				m[1] &= byte(a.operand)
			}
			emit(storageByteLocation{Offset: -23}, 1, false, uint64(old), i)
			emit(storageByteLocation{Offset: -23}, 1, true, uint64(m[1]), i)
		}
	}
	// Sibling checks are actual source reads; their native loads are retained.
	emit(storageByteLocation{Offset: -24}, 1, false, uint64(m[0]), -1)
	emit(storageByteLocation{Offset: -22}, 1, false, uint64(m[2]), -1)
	emit(storageByteLocation{Offset: -16}, 4, false, uint64(x), -1)
	emit(narrowJointGlobal(3), 4, true, uint64(x), -1)
	emit(storageByteLocation{Offset: -23}, 1, false, uint64(m[1]), -1)
	emit(narrowJointGlobal(4), 1, true, uint64(m[1]), -1)
	return o
}

func (p narrowJointIntent) source(name string) string {
	typ, ptr := "byte", "&m[1]"
	if p.shape&128 != 0 {
		typ, ptr = "Byte", "(*byte)(&m[1])"
	}
	text := fmt.Sprintf("func %s(){x:=uint32(%d);var m [3]%s;m[0]=%d;m[1]=%d;m[2]=%d;", name, p.initial, typ, p.bytes[0], p.bytes[1], p.bytes[2])
	cas := 0
	for _, a := range p.atomics {
		if a.op == x86asm.CMPXCHG {
			text += fmt.Sprintf("if OpC(&x,%d,%d){C%d=1}else{C%d=2};", a.compare, a.operand, cas, cas)
			cas++
		} else {
			name := "OpO"
			if a.op == x86asm.AND {
				name = "OpA"
			}
			text += fmt.Sprintf("%s(%s,%d);", name, ptr, a.operand)
		}
	}
	return text + fmt.Sprintf("if m[0]!=%d||m[2]!=%d{panic(nil)};G=x;H=byte(m[1])}\n", p.bytes[0], p.bytes[2])
}

func narrowJointSelected(t *testing.T, programs []narrowJointIntent, fault string) (computationSource, map[*ssa.Function]*assemblyReference) {
	t.Helper()
	goSource := "package p\ntype Byte byte\nvar C0,C1,C2,G uint32\nvar H byte\nfunc OpC(*uint32,uint32,uint32)bool\nfunc OpO(*byte,byte)\nfunc OpA(*byte,byte)\n"
	for i, p := range programs {
		goSource += p.source(fmt.Sprintf("F%d", i))
	}
	var asm strings.Builder
	for i, name := range []string{"OpC", "OpO", "OpA"} {
		p := assemblyReferencePropertyBody(uint16(i+1)<<9|(programs[0].shape&31), 0)
		body := strings.Replace(p.body, "·Swap", "·"+name, 1)
		switch fault {
		case "predicate":
			if i == 0 {
				body = strings.Replace(body, "SETEQ", "SETNE", 1)
			}
		case "logical":
			if i == 1 {
				body = strings.Replace(body, "ORB", "ANDB", 1)
			}
		case "missing-lock":
			if i == 1 {
				body = strings.Replace(body, "LOCK\n", "", 1)
			}
		case "extra-write":
			if i == 1 {
				body = strings.Replace(body, "RET\n", fmt.Sprintf("MOVB $0, 0(%s)\nRET\n", p.pointer), 1)
			}
		case "split-groups":
			if i == 1 {
				for _, line := range strings.Split(body, "\n") {
					if strings.HasPrefix(line, "ORB ") {
						body = strings.Replace(body, "RET\n", "LOCK\n"+line+"\nRET\n", 1)
						break
					}
				}
			}
		}
		asm.WriteString(body)
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/narrowjoint\n\ngo 1.27\n", "p.go": goSource, "p_amd64.s": asm.String()})
	source := assemblyReferenceSelectedSource(t, dir)
	packet := assemblyReferenceSelectedPacket(t, source, source.prog.Roots["OpC"])
	refs := map[*ssa.Function]*assemblyReference{}
	for _, name := range []string{"OpC", "OpO", "OpA"} {
		fn := source.prog.Roots[name]
		r, err := checkAssemblyReference(t.Context(), source, fn, packet, assemblyReferenceLimits{})
		if err != nil {
			t.Fatalf("selected reference %s: %v", name, err)
		}
		refs[fn] = r
	}
	return source, refs
}

type narrowJointSourceProof struct {
	first        *sourceOperandPrefix
	last         *sourceEffectPrefix
	complete     *sourceReturnCompletion
	local, array regionObject
}

func narrowJointComplete(t testing.TB, source computationSource, root *ssa.Function, refs map[*ssa.Function]*assemblyReference) narrowJointSourceProof {
	t.Helper()
	calls := localEffectCalls(t, root, "OpC")
	first, err := checkSourceOperandPrefix(t.Context(), source, root, calls[0], defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	var load *ssa.UnOp
	var returned *ssa.Return
	for _, block := range root.Blocks {
		for _, ins := range block.Instrs {
			if s, ok := ins.(*ssa.Store); ok && s.Addr == root.Pkg.Members["G"].(*ssa.Global) {
				load, _ = s.Val.(*ssa.UnOp)
			}
			if r, ok := ins.(*ssa.Return); ok {
				returned = r
			}
		}
	}
	if load == nil || load.Op != token.MUL || returned == nil {
		t.Fatal("missing real post-byte load/return boundary")
	}
	last, err := checkSourceInstructionContinuation(t.Context(), first, narrowInstructionUse(t, load, load.X), refs)
	if err != nil {
		t.Fatalf("actual source prefix: %v", err)
	}
	complete, err := checkSourceReturnContinuation(t.Context(), last, returned, refs)
	if err != nil {
		t.Fatalf("actual source return: %v", err)
	}
	local := first.operands[0].location.object
	var array regionObject
	if len(first.region.packet.trace.allocations) != 2 {
		t.Fatal("intent requires exactly the scalar and array allocations")
	}
	for _, allocation := range first.region.packet.trace.allocations {
		if allocation.location.object != local {
			array = allocation.location.object
		}
	}
	if array.site == nil {
		t.Fatal("missing independent array allocation")
	}
	return narrowJointSourceProof{first, last, complete, local, array}
}

// Encoding is intentionally separate from concrete execution. RAX/RCX/RDX are
// scratch; byte forms select DL or DH, independently of source register names.
func narrowJointCode(p narrowJointIntent, fault string) ([]byte, uint64) {
	const base = uint64(0x401000)
	code := []byte{0xc3, 0x48, 0x83, 0xec, 0x40}
	pc := func() uint64 { return base + uint64(len(code)) }
	imm := func(reg byte, value uint32) {
		code = append(code, 0xb8+reg)
		code = binary.LittleEndian.AppendUint32(code, value)
	}
	mem := func(at storageByteLocation, width int, write bool) {
		op := byte(0x8b)
		if write {
			op = 0x89
		}
		if width == 1 {
			op--
		}
		start := pc()
		code = append(code, op)
		if at.Image {
			code = append(code, 0x05)
			code = binary.LittleEndian.AppendUint32(code, uint32(at.Offset-int64(start+6)))
		} else {
			code = append(code, 0x44, 0x24, byte(at.Offset+64))
		}
	}
	store := func(at storageByteLocation, width int, value uint32) { imm(0, value); mem(at, width, true) }
	store(storageByteLocation{Offset: -16}, 4, p.initial)
	for i, v := range p.bytes {
		store(storageByteLocation{Offset: -24 + int64(i)}, 1, uint32(v))
	}
	cas := 0
	for i, a := range p.atomics {
		offset := byte(48)
		if a.op != x86asm.CMPXCHG {
			offset = 41
		}
		if fault == "wrong-element" && a.op != x86asm.CMPXCHG {
			offset = 40
		}
		code = append(code, 0x48, 0x8d, 0x4c, 0x24, offset) // LEA RCX,[RSP+offset].
		if a.op == x86asm.CMPXCHG {
			code = append(code, 0x48, 0xb8) // MOV RAX,imm64; high bits survive successful CAS32.
			code = binary.LittleEndian.AppendUint64(code, p.accumulator(a.compare))
			imm(2, a.operand)
			code = append(code, 0xf0, 0x0f, 0xb1, 0x11) // LOCK CMPXCHG [RCX],EDX.
			// Actual result-dependent branches choose the observable global store.
			code = append(code, 0x0f, 0x85)
			branch := len(code)
			code = append(code, 0, 0, 0, 0)
			store(narrowJointGlobal(cas), 4, 1)
			code = append(code, 0xe9)
			join := len(code)
			code = append(code, 0, 0, 0, 0)
			binary.LittleEndian.PutUint32(code[branch:], uint32(int64(pc())-int64(base+uint64(branch)+4)))
			store(narrowJointGlobal(cas), 4, 2)
			binary.LittleEndian.PutUint32(code[join:], uint32(int64(pc())-int64(base+uint64(join)+4)))
			cas++
		} else {
			mask := a.operand
			reg := byte(2)
			if p.shape&64 != 0 {
				mask <<= 8
				reg = 6
			}
			imm(2, mask)
			op := byte(0x08)
			if a.op == x86asm.AND {
				op = 0x20
			}
			if fault != "missing-lock" || i != 3 {
				code = append(code, 0xf0)
			}
			code = append(code, op, reg<<3|1)
		}
	}
	// Actual ordinary sibling loads. Their values are independently checked in
	// the source; no native effect or byte is hidden in an invented private frame.
	for _, offset := range []int64{-24, -22} {
		imm(0, 0)
		mem(storageByteLocation{Offset: offset}, 1, false)
	}
	mem(storageByteLocation{Offset: -16}, 4, false)
	mem(narrowJointGlobal(3), 4, true)
	imm(0, 0)
	mem(storageByteLocation{Offset: -23}, 1, false)
	mem(narrowJointGlobal(4), 1, true)
	if fault == "extra-write" {
		store(storageByteLocation{Offset: -23}, 1, 0)
	}
	imm(1, 0) // Erase private pointer provenance before return.
	code = append(code, 0x48, 0x83, 0xc4, 0x40)
	cut := pc()
	code = append(code, 0xc3)
	return code, cut
}

func narrowJointNative(t testing.TB, p narrowJointIntent, fault string) (globalNativeFixture, nativeproof.TransitionReturnCertificate) {
	t.Helper()
	code, cut := narrowJointCode(p, fault)
	return storageFunctionNativeProgram(t, code, cut, nativeproof.OriginDomain{Min: 1 << 40, Max: (1 << 40) + 0x10000, Modulus: 16}, func(face *nativeproof.TransitionInterface) {
		face.Conditions.LockedMemory = nativeproof.LockedMemoryModel
		face.ReturnContext.Preserved = []nativeproof.Register{nativeproof.RBX, nativeproof.RBP, nativeproof.RSI, nativeproof.RDI, nativeproof.R8, nativeproof.R9, nativeproof.R10, nativeproof.R11, nativeproof.R12, nativeproof.R13, nativeproof.R14, nativeproof.R15}
	})
}

func narrowJointRepresentation(source computationSource, root *ssa.Function, s narrowJointSourceProof, image *nativeproof.Image) storageRepresentation {
	rho := storageRepresentation{source: source.prog, image: image, bindings: []storageBinding{{object: s.local, base: nativeproof.StackOffset(-16)}, {object: s.array, base: nativeproof.StackOffset(-24)}}}
	for i, name := range narrowJointGlobals {
		rho.bindings = append(rho.bindings, storageBinding{object: regionObject{kind: regionGlobal, site: root.Pkg.Members[name].(*ssa.Global)}, base: nativeproof.ImageAddress(narrowJointGlobal(i).Offset)})
	}
	return rho
}

// Metadata is checked independently of accesses and final registers: later MOVs
// overwrite the CAS accumulator, so a correct returned state cannot certify an
// earlier retained primitive result. Returning errors also lets detached test
// projections exercise this exact assertion without forging a certificate.
func narrowJointPrimitiveMetadata(ctx context.Context, a narrowJointAtomic, incoming, before, after uint64, effect nativeproof.PrimitiveEffect, assignments []br.Assignment) error {
	check := func(name string, term br.Term, sort br.Sort, want uint64) error {
		if term.Sort() != sort {
			return fmt.Errorf("%s metadata sort differs", name)
		}
		got, err := br.Eval(ctx, term, assignments, br.Limits{})
		if err != nil {
			return fmt.Errorf("%s metadata evaluation: %w", name, err)
		}
		if got != want {
			return fmt.Errorf("%s metadata = %#x, want %#x", name, got, want)
		}
		return nil
	}
	var values []struct {
		name string
		term br.Term
		sort br.Sort
		want uint64
	}
	switch n := effect.(type) {
	case nativeproof.LockedCompareExchangeEffect:
		if a.op != x86asm.CMPXCHG || n.Width != 4 {
			return fmt.Errorf("CAS metadata kind/width differs")
		}
		success := before == uint64(a.compare)
		accumulator := incoming
		if !success {
			accumulator = uint64(uint32(before))
		}
		values = []struct {
			name string
			term br.Term
			sort br.Sort
			want uint64
		}{
			{"Before", n.Before, br.Bits(32), before}, {"After", n.After, br.Bits(32), after},
			{"Compare", n.Compare, br.Bits(32), uint64(a.compare)}, {"Replacement", n.Replacement, br.Bits(32), uint64(a.operand)},
			{"Success", n.Success, br.Bool(), narrowJointBit(success)}, {"Accumulator", n.Accumulator, br.Bits(64), accumulator},
		}
	case nativeproof.LockedLogicalEffect:
		if (a.op != x86asm.AND && a.op != x86asm.OR) || n.Kind != a.op || n.Width != 1 {
			return fmt.Errorf("logical metadata kind/width differs")
		}
		values = []struct {
			name string
			term br.Term
			sort br.Sort
			want uint64
		}{
			{"Before", n.Before, br.Bits(8), before}, {"After", n.After, br.Bits(8), after}, {"Operand", n.Operand, br.Bits(8), uint64(a.operand)},
		}
	default:
		return fmt.Errorf("unexpected native atomic metadata kind")
	}
	for _, v := range values {
		if err := check(v.name, v.term, v.sort, v.want); err != nil {
			return err
		}
	}
	return nil
}

// Exact retained values and occurrence coordinates must come from this return
// bound's own primitive inventory, then from exactly one instruction occurrence.
func narrowJointOwnedPrimitive(effect nativeproof.PrimitiveEffect, bound nativeproof.TransitionReturnBound) error {
	var id nativeproof.TransitionOccurrenceID
	var pc uint64
	var activation nativeproof.TransitionActivationID
	found := 0
	switch n := effect.(type) {
	case nativeproof.LockedCompareExchangeEffect:
		id, pc, activation = n.ID, n.PC, n.Context
		for _, candidate := range bound.Prefix.PrimitiveEffects {
			if owned, ok := candidate.(nativeproof.LockedCompareExchangeEffect); ok && owned == n {
				found++
			}
		}
	case nativeproof.LockedLogicalEffect:
		id, pc, activation = n.ID, n.PC, n.Context
		for _, candidate := range bound.Prefix.PrimitiveEffects {
			if owned, ok := candidate.(nativeproof.LockedLogicalEffect); ok && owned == n {
				found++
			}
		}
	default:
		return fmt.Errorf("unexpected native atomic ownership kind")
	}
	if found != 1 {
		return fmt.Errorf("primitive is not an exact unique member of its owning return bound")
	}
	found = 0
	for _, instruction := range bound.Instructions {
		if instruction.ID == id {
			if instruction.Start != pc || instruction.Context != activation {
				return fmt.Errorf("primitive instruction PC/context differs")
			}
			found++
		}
	}
	if found != 1 {
		return fmt.Errorf("primitive lacks its unique owning instruction ID")
	}
	return nil
}

func narrowJointInitialBytes(seed uint64) map[storageByteLocation]byte {
	initial := map[storageByteLocation]byte{}
	for offset := int64(-64); offset < 8; offset++ {
		initial[storageByteLocation{Offset: offset}] = byte(seed ^ uint64(offset)*0x9d)
	}
	for offset := int64(0x700000); offset < 0x700080; offset++ {
		initial[storageByteLocation{Image: true, Offset: offset}] = byte(seed ^ uint64(offset)*0x63)
	}
	for lane := range 8 {
		initial[storageByteLocation{Offset: int64(lane)}] = byte(uint64(0x401000) >> (8 * lane))
	}
	return initial
}

func narrowJointCheck(t testing.TB, p narrowJointIntent, source computationSource, root *ssa.Function, s narrowJointSourceProof, f globalNativeFixture, proof *globalFunctionCorrespondence, seed uint64) {
	t.Helper()
	b, ok := proof.native.BoundFor(f.image)
	if !ok || !b.State.CalleeTerminated || b.State.PC != 0x401000 || !b.Prefix.ConditionalRegion || b.Prefix.Entry != f.entry || b.Continuation.PC != 0x401000 {
		t.Fatal("lost conditional full return")
	}
	initial := narrowJointInitialBytes(seed)
	want := p.oracle(initial)
	origin := uint64(1<<40) + 0x100
	assignments, registers := storageJointAssignments(t, b.Prefix, initial, origin, seed)
	if len(proof.inputs) != len(narrowJointGlobals) {
		t.Fatal("arbitrary initial global population changed")
	}
	antecedentVariables := storageJointVariables(proof.antecedent)
	initialTerms := map[storageByteLocation]br.Term{}
	for _, cell := range b.Prefix.InitialMemory {
		initialTerms[storageTestCoordinate(t, b.Prefix.Geometry, cell.TransitionLocation)] = cell.Value
	}
	inputVariables := map[storageJointVariable]bool{}
	for _, input := range proof.inputs {
		global, ok := input.location.object.site.(*ssa.Global)
		if !ok {
			t.Fatal("non-global initial typed input")
		}
		i := slices.Index(narrowJointGlobals, global.Name())
		if i < 0 {
			t.Fatal("foreign global input")
		}
		if global != root.Pkg.Members[narrowJointGlobals[i]] || input.location.object.kind != regionGlobal || len(input.location.path) != 0 {
			t.Fatal("initial input lost actual selected global")
		}
		sourceID, variable := storageJointVariableOf(input.source)
		if !variable || inputVariables[sourceID] || antecedentVariables[sourceID] {
			t.Fatal("source initial input is fixed, correlated or constrained")
		}
		inputVariables[sourceID] = true
		width := 4
		if i == 4 {
			width = 1
		}
		var value uint64
		wantVariables := map[storageJointVariable]bool{}
		for lane := range width {
			at := storageAt(narrowJointGlobal(i), int64(lane))
			value |= uint64(initial[at]) << (8 * lane)
			term := initialTerms[at]
			id, variable := storageJointVariableOf(term)
			if !variable || term.Sort() != br.Bits(8) || inputVariables[id] || antecedentVariables[id] {
				t.Fatal("native initial global bytes lost unconstrained independent inputs")
			}
			inputVariables[id], wantVariables[id] = true, true
		}
		actualVariables := storageJointVariables(input.native)
		if len(actualVariables) != len(wantVariables) {
			t.Fatal("native initial pair borrows wrong byte population")
		}
		for id := range wantVariables {
			if !actualVariables[id] {
				t.Fatal("native initial pair borrows another global's byte")
			}
		}
		if input.source.Sort() != br.Bits(width*8) || input.native.Sort() != br.Bits(width*8) || storageJointEval(t, input.native, assignments) != value {
			t.Fatal("initial pair has wrong extent/value")
		}
		assignments = append(assignments, br.Assignment{Variable: input.source, Value: value})
	}
	if storageJointEval(t, proof.antecedent, assignments) != 1 || storageJointEval(t, proof.paired, assignments) != 1 {
		t.Fatal("arbitrary globals/scratch excluded")
	}
	if len(b.State.Memory) != len(want.final) {
		t.Fatal("residual byte population changed")
	}
	seen := map[storageByteLocation]bool{}
	for _, cell := range b.State.Memory {
		at := storageTestCoordinate(t, b.Prefix.Geometry, cell.TransitionLocation)
		v, present := want.final[at]
		if !present || seen[at] || storageJointEval(t, cell.Value, assignments) != uint64(v) {
			t.Fatalf("residual native byte %+v differs from integer intent", at)
		}
		seen[at] = true
	}
	// Every occurrence ID refers to one actual instruction and activation. Keep
	// inactive branch accesses in the certificate, but compare only the executed
	// event stream against the concrete branch oracle.
	guards := map[nativeproof.TransitionOccurrenceID]uint64{}
	for _, ins := range b.Instructions {
		if _, exists := guards[ins.ID]; exists {
			t.Fatal("reused native occurrence ID")
		}
		guards[ins.ID] = storageJointEval(t, ins.Guard, assignments)
	}
	event := 0
	for _, access := range b.Accesses {
		access := storageTestAccess(t, b.Prefix.Geometry, access)
		guard, present := guards[access.ID]
		if !present || access.Context != 0 {
			t.Fatal("access lost actual instruction activation")
		}
		if guard == 0 {
			continue
		}
		if access.Kind == nativeproof.FrameReturnRead {
			if event != len(want.events) || access.PC != f.cut || access.Image || access.Bytes.Start != 0 || access.Bytes.End != 8 || storageJointEval(t, access.Value, assignments) != 0x401000 {
				t.Fatal("return read/order mismatch")
			}
			continue
		}
		if event >= len(want.events) {
			t.Fatal("extra executed native effect")
		}
		w := want.events[event]
		kind := nativeproof.FrameRead
		if w.write {
			kind = nativeproof.FrameWrite
		}
		if access.Kind != kind || access.Image != w.at.Image || access.Bytes.Start != w.at.Offset || access.Bytes.End-access.Bytes.Start != int64(w.width) || storageJointEval(t, access.Value, assignments) != w.value {
			t.Fatalf("native event %d %+v != intent %+v", event, access, w)
		}
		event++
	}
	if event != len(want.events) || len(proof.atomics) != len(p.atomics) || len(b.Prefix.PrimitiveEffects) != len(p.atomics) {
		t.Fatal("lost complete ordinary/atomic effects")
	}
	var calls []*ssa.Call
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok && call.Call.StaticCallee() != nil {
				calls = append(calls, call)
			}
		}
	}
	slices.SortFunc(calls, func(a, b *ssa.Call) int { return int(a.Pos() - b.Pos()) })
	if len(calls) != len(p.atomics) {
		t.Fatal("intent lost actual source call inventory")
	}
	invocations := map[regionInvocation]bool{}
	primitiveIDs := map[nativeproof.TransitionOccurrenceID]bool{}
	for i, group := range proof.atomics {
		a := p.atomics[i]
		width := 1
		if a.op == x86asm.CMPXCHG {
			width = 4
		}
		sg := group.source
		statement := 3
		if width == 4 {
			statement = 4
		}
		if sg.atomic.Kind != a.op || sg.atomic.Width != width || sg.atomic.Statement != statement || sg.atomic.WriteAccess != sg.atomic.ReadAccess+1 || sg.application == nil || sg.application.at != calls[i] || sg.application.at.Parent() != root || sg.application.invocation.root != root || sg.application.invocation.path == "" || invocations[sg.application.invocation] {
			t.Fatal("source atomic lost exact statement/call/pair")
		}
		invocations[sg.application.invocation] = true
		var expected []narrowJointEvent
		for _, event := range want.events {
			if event.atomic == i {
				expected = append(expected, event)
			}
		}
		if len(expected) != 2 {
			t.Fatal("intent lacks atomic pair")
		}
		if err := narrowJointPrimitiveMetadata(t.Context(), a, p.accumulator(a.compare), expected[0].value, expected[1].value, group.native, assignments); err != nil {
			t.Fatal(err)
		}
		if err := narrowJointOwnedPrimitive(group.native, b); err != nil {
			t.Fatal(err)
		}
		var readIndex, writeIndex, nativeWidth int
		var id nativeproof.TransitionOccurrenceID
		var pc uint64
		switch n := group.native.(type) {
		case nativeproof.LockedCompareExchangeEffect:
			readIndex, writeIndex, nativeWidth, id, pc = n.ReadAccess, n.WriteAccess, n.Width, n.ID, n.PC
			if n.Context != 0 {
				t.Fatal("native CAS activation differs")
			}
		case nativeproof.LockedLogicalEffect:
			readIndex, writeIndex, nativeWidth, id, pc = n.ReadAccess, n.WriteAccess, n.Width, n.ID, n.PC
			if n.Context != 0 {
				t.Fatal("native logical activation differs")
			}
		default:
			t.Fatal("unexpected native atomic kind")
		}
		if nativeWidth != width || writeIndex != readIndex+1 || readIndex < 0 || writeIndex >= len(b.Accesses) || guards[id] != 1 || primitiveIDs[id] {
			t.Fatal("native atomic group split or inactive")
		}
		primitiveIDs[id] = true
		for lane, index := range []int{readIndex, writeIndex} {
			access := storageTestAccess(t, b.Prefix.Geometry, b.Accesses[index])
			w := expected[lane]
			if access.ID != id || access.PC != pc || access.Context != 0 || access.Image != w.at.Image || access.Bytes.Start != w.at.Offset || access.Bytes.End-access.Bytes.Start != int64(width) || storageJointEval(t, access.Value, assignments) != w.value {
				t.Fatal("native atomic index lost actual full-width occurrence")
			}
		}
		// Group coordinates belong to its actual phase trace, never a concatenated
		// list with silently shifted indices.
		found := false
		for _, trace := range proof.traces {
			for _, candidate := range trace.atomics {
				if candidate.application == sg.application && candidate.atomic == sg.atomic {
					read, write := trace.accesses[sg.atomic.ReadAccess], trace.accesses[sg.atomic.WriteAccess]
					if read.instruction != sg.application.at || write.instruction != read.instruction || read.invocation != write.invocation || read.write || !write.write || !read.locked || !write.locked {
						t.Fatal("split source occurrence")
					}
					before, ok1 := regionReferenceWord(read.value, width)
					after, ok2 := regionReferenceWord(write.value, width)
					if !ok1 || !ok2 || before != expected[0].value || after != expected[1].value || read.invocation != (regionInvocation{}) || read.location.object != write.location.object || !slices.Equal(read.location.path, write.location.path) {
						t.Fatal("source atomic value/location/invocation differs from intent")
					}
					if width == 4 && (read.location.object != s.local || read.location.path != nil || write.location.path != nil) || width == 1 && (read.location.object != s.array || !slices.Equal(read.location.path, []regionStep{{index: 1}})) {
						t.Fatal("source atomic used wrong owning allocation/path")
					}
					found = true
				}
			}
		}
		if !found {
			t.Fatal("atomic detached from owning phase")
		}
	}
	registers[nativeproof.RAX] = uint64(want.final[storageByteLocation{Offset: -23}])
	registers[nativeproof.RCX] = 0
	registers[nativeproof.RDX] = uint64(p.atomics[len(p.atomics)-1].operand)
	if p.shape&64 != 0 {
		registers[nativeproof.RDX] <<= 8
	}
	registers[nativeproof.RSP] = origin + 8
	for i, value := range registers {
		if storageJointEval(t, b.State.Registers[i].Value, assignments) != value {
			t.Fatalf("returned GPR %d lost scratch/explicit transfer", i)
		}
	}
	if len(b.State.Restored) != len(f.face.ReturnContext.Preserved) || b.State.Vectors != b.Prefix.InitialVectors || b.State.Thread.ContextChanged {
		t.Fatal("lost preserved return context")
	}
	// This integer-only interface does not enable syscall/TLS state. Absence is
	// retained as absence, rather than inventing an initial FS value or selector
	// preservation projection that the interface never selected.
	if b.Prefix.InitialFS.Valid() || b.State.Thread != (nativeproof.TransitionThread{}) {
		t.Fatal("integer-only return introduced a thread-context projection")
	}
	for i, flag := range []nativeproof.TransitionFlag{b.State.Flags.CF, b.State.Flags.OF, b.State.Flags.SF, b.State.Flags.ZF, b.State.Flags.AF, b.State.Flags.PF} {
		value := uint64(0)
		if i == 5 {
			value = 1
		}
		// ADD RSP,64 restores a positive, nonzero, low-byte-zero origin.
		if !flag.Defined || storageJointEval(t, flag.Value, assignments) != value {
			t.Fatal("returned flags differ from explicit stack restoration")
		}
	}
	// The source prefix stops before the real load; the consumed return retains
	// that exact predecessor and the already allocated scalar/array objects.
	if s.complete.prior != s.last || s.last.prior != s.first.sourceEffectPrefix || len(s.last.region.packet.trace.allocations) != 0 {
		t.Fatal("continuation reset or reallocated source heap")
	}
	if proof.representation.source != source.prog {
		t.Fatal("lost selected source owner")
	}
}

func narrowJointBit(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func TestNarrowJointPrimitiveMetadataProbes(t *testing.T) {
	p := narrowJointProgram(0x80000000, 0x80000000, 0xffffffff, 0x35aa8057, 0xdf)
	fixture, native := narrowJointNative(t, p, "")
	bound, ok := native.BoundFor(fixture.image)
	if !ok || len(bound.Prefix.PrimitiveEffects) != len(p.atomics) {
		t.Fatal("missing actual native return primitive inventory")
	}
	initial := narrowJointInitialBytes(0xdeadbeef)
	want := p.oracle(initial)
	assignments, _ := storageJointAssignments(t, bound.Prefix, initial, (1<<40)+0x100, 0xdeadbeef)
	constant := func(width int, value uint64) br.Term {
		term, err := br.NewBuilder(1).Make(br.Constant, br.Bits(width), value)
		if err != nil {
			t.Fatal(err)
		}
		return term
	}
	// These are read-only certificate projections. Mutations below affect only
	// copied metadata handed to the assertion helpers, never an authorizing
	// certificate, actual accesses, or the completed native state.
	for i, original := range bound.Prefix.PrimitiveEffects {
		a := p.atomics[i]
		var pair []narrowJointEvent
		for _, event := range want.events {
			if event.atomic == i {
				pair = append(pair, event)
			}
		}
		if len(pair) != 2 {
			t.Fatal("independent intent lacks atomic pair")
		}
		metadata := func(effect nativeproof.PrimitiveEffect) error {
			return narrowJointPrimitiveMetadata(t.Context(), a, p.accumulator(a.compare), pair[0].value, pair[1].value, effect, assignments)
		}
		if err := metadata(original); err != nil {
			t.Fatalf("positive primitive %d: %v", i, err)
		}
		if err := narrowJointOwnedPrimitive(original, bound); err != nil {
			t.Fatal(err)
		}
		fields := []string{"Before", "After"}
		if a.op == x86asm.CMPXCHG {
			fields = append(fields, "Accumulator")
		}
		for _, field := range fields {
			t.Run(fmt.Sprintf("%d/%s", i, field), func(t *testing.T) {
				var detached nativeproof.PrimitiveEffect
				switch n := original.(type) {
				case nativeproof.LockedCompareExchangeEffect:
					switch field {
					case "Before":
						n.Before = constant(32, pair[0].value^1)
					case "After":
						n.After = constant(32, pair[1].value^1)
					case "Accumulator":
						// Deliberately exchange the two upper-RAX rules: zero the
						// high half on success, retain it on failure. Later MOV EAX
						// instructions overwrite RAX, so final-GPR tests cannot see it.
						wrong := uint64(a.compare)
						if pair[0].value != uint64(a.compare) {
							wrong = p.accumulator(uint32(pair[0].value))
						}
						n.Accumulator = constant(64, wrong)
					}
					detached = n
				case nativeproof.LockedLogicalEffect:
					if field == "Before" {
						n.Before = constant(8, pair[0].value^1)
					} else {
						n.After = constant(8, pair[1].value^1)
					}
					detached = n
				default:
					t.Fatal("unexpected primitive kind")
				}
				if err := metadata(detached); err == nil || !strings.HasPrefix(err.Error(), field+" metadata = ") {
					t.Fatalf("corruption escaped its exact metadata assertion: %v", err)
				}
				if err := narrowJointOwnedPrimitive(detached, bound); err == nil || !strings.Contains(err.Error(), "exact unique member") {
					t.Fatalf("same-kind/width detached effect borrowed ownership: %v", err)
				}
				again, ok := native.BoundFor(fixture.image)
				if !ok || !reflect.DeepEqual(again.Prefix.PrimitiveEffects, bound.Prefix.PrimitiveEffects) || !reflect.DeepEqual(again.Accesses, bound.Accesses) || !reflect.DeepEqual(again.State, bound.State) {
					t.Fatal("detached metadata probe changed owning evidence/accesses/final state")
				}
			})
		}
	}
	first := bound.Prefix.PrimitiveEffects[0].(nativeproof.LockedCompareExchangeEffect)
	for _, fault := range []string{"missing-member", "duplicate-member", "instruction-id", "instruction-pc", "instruction-context"} {
		t.Run(fault, func(t *testing.T) {
			detached := bound
			detached.Prefix.PrimitiveEffects = slices.Clone(bound.Prefix.PrimitiveEffects)
			detached.Instructions = slices.Clone(bound.Instructions)
			want := "exact unique member"
			switch fault {
			case "missing-member":
				detached.Prefix.PrimitiveEffects = detached.Prefix.PrimitiveEffects[1:]
			case "duplicate-member":
				detached.Prefix.PrimitiveEffects = append(detached.Prefix.PrimitiveEffects, first)
			default:
				for i := range detached.Instructions {
					if detached.Instructions[i].ID == first.ID {
						switch fault {
						case "instruction-id":
							detached.Instructions[i].ID = 0
							want = "unique owning instruction ID"
						case "instruction-pc":
							detached.Instructions[i].Start++
							want = "instruction PC/context differs"
						case "instruction-context":
							detached.Instructions[i].Context++
							want = "instruction PC/context differs"
						}
						break
					}
				}
			}
			if err := narrowJointOwnedPrimitive(first, detached); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("detached ownership projection escaped its exact assertion: %v", err)
			}
		})
	}
}

// Both encodings initialize the same eight-byte extent and replace 7 with 1.
// The sole semantic difference is the indivisible CAS access width. RAX has no
// high-half junk, and no result-dependent branch can mask that distinction.
func narrowWidthNative(t testing.TB, width int) (globalNativeFixture, nativeproof.TransitionReturnCertificate) {
	t.Helper()
	if width != 4 && width != 8 {
		t.Fatal("width adversary requires CAS32 or CAS64")
	}
	const base = uint64(0x401000)
	code := []byte{0xc3, 0x48, 0x83, 0xec, 0x40, 0x48, 0xb8} // SUB RSP,64; MOV RAX,7.
	code = binary.LittleEndian.AppendUint64(code, 7)
	code = append(code, 0x48, 0x89, 0x44, 0x24, 48, 0x48, 0xba) // MOV [RSP+48],RAX; MOV RDX,1.
	code = binary.LittleEndian.AppendUint64(code, 1)
	code = append(code, 0xf0)
	if width == 8 {
		code = append(code, 0x48)
	}
	code = append(code, 0x0f, 0xb1, 0x54, 0x24, 48) // LOCK CMPXCHG [RSP+48],EDX/RDX.
	code = append(code, 0x48, 0x83, 0xc4, 0x40)
	cut := base + uint64(len(code))
	code = append(code, 0xc3)
	return storageFunctionNativeProgram(t, code, cut, nativeproof.OriginDomain{Min: 1 << 40, Max: (1 << 40) + 0x10000, Modulus: 16}, func(face *nativeproof.TransitionInterface) {
		face.Conditions.LockedMemory = nativeproof.LockedMemoryModel
		face.ReturnContext.Preserved = []nativeproof.Register{nativeproof.RCX, nativeproof.RBX, nativeproof.RBP, nativeproof.RSI, nativeproof.RDI, nativeproof.R8, nativeproof.R9, nativeproof.R10, nativeproof.R11, nativeproof.R12, nativeproof.R13, nativeproof.R14, nativeproof.R15}
	})
}

func TestNarrowJointCompleteAtomicWidthBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("acquires selected CAS32/CAS64 assembly and checks complete typed-width correspondence")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected amd64 interface")
	}
	dir := t.TempDir()
	const text = `package p
func Narrow(*uint32,uint32,uint32)bool
func Wide(*uint64,uint64,uint64)bool
func NarrowRoot(){var x [2]uint32;x[0]=7;x[1]=0;Narrow(&x[0],7,1)}
func WideRoot(){var x uint64;x=7;Wide(&x,7,1)}
`
	narrow := assemblyReferencePropertyBody(512, 0)
	wide := assemblyReferencePropertyBody(0, 0)
	assembly := strings.Replace(narrow.body, "·Swap", "·Narrow", 1) + strings.Replace(wide.body, "·Swap", "·Wide", 1)
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/atomicwidth\n\ngo 1.27\n", "p.go": text, "p_amd64.s": assembly})
	source := assemblyReferenceSelectedSource(t, dir)
	packet := assemblyReferenceSelectedPacket(t, source, source.prog.Roots["Narrow"])
	refs := map[*ssa.Function]*assemblyReference{}
	for _, tc := range []struct {
		name  string
		width int
	}{{"Narrow", 4}, {"Wide", 8}} {
		fn := source.prog.Roots[tc.name]
		r, err := checkAssemblyReference(t.Context(), source, fn, packet, assemblyReferenceLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.boundTo(source, fn); err != nil {
			t.Fatal(err)
		}
		frame := r.checked.relation.frame
		if frame.size != 17+2*tc.width || frame.targetWidth != tc.width || frame.result != (assemblyReferenceSlot{16 + 2*tc.width, 1}) || !slices.Equal(frame.arguments, []assemblyReferenceSlot{{8, 8}, {16, tc.width}, {16 + tc.width, tc.width}}) {
			t.Fatal("selected reference lost exact CAS ABI0 extent")
		}
		refs[fn] = r
	}
	type nativeCase struct {
		fixture  globalNativeFixture
		returned nativeproof.TransitionReturnCertificate
	}
	natives := map[int]nativeCase{}
	// Establish native producer success and identical complete final bytes before
	// any negative correspondence judgment. This oracle starts from independent
	// sentinel bytes, not the source trace or native endpoint's proposed values.
	finals := map[uint64]map[storageByteLocation]byte{}
	for _, width := range []int{4, 8} {
		fixture, returned := narrowWidthNative(t, width)
		natives[width] = nativeCase{fixture, returned}
		bound, ok := returned.BoundFor(fixture.image)
		if !ok || !bound.State.CalleeTerminated || bound.State.PC != 0x401000 || len(bound.Prefix.PrimitiveEffects) != 1 || len(bound.Accesses) != 4 {
			t.Fatal("width baseline lacks its actual complete native producer")
		}
		group, ok := bound.Prefix.PrimitiveEffects[0].(nativeproof.LockedCompareExchangeEffect)
		if !ok || group.Width != width || group.Context != 0 || group.ReadAccess != 1 || group.WriteAccess != 2 {
			t.Fatal("actual CAS metadata lost selected width/adjacent access indices")
		}
		if err := narrowJointOwnedPrimitive(group, bound); err != nil {
			t.Fatal(err)
		}
		for _, seed := range []uint64{0, 0xffffffffffffffff} {
			initial := narrowJointInitialBytes(seed)
			assignments, registers := storageJointAssignments(t, bound.Prefix, initial, (1<<40)+0x100, seed)
			for _, scalar := range []struct {
				term  br.Term
				bits  int
				value uint64
			}{{group.Before, width * 8, 7}, {group.After, width * 8, 1}, {group.Compare, width * 8, 7}, {group.Replacement, width * 8, 1}, {group.Accumulator, 64, 7}} {
				if scalar.term.Sort() != br.Bits(scalar.bits) || storageJointEval(t, scalar.term, assignments) != scalar.value {
					t.Fatal("width baselines differ in primitive scalar value")
				}
			}
			if storageJointEval(t, group.Success, assignments) != 1 {
				t.Fatal("width baseline must actually succeed")
			}
			for i, access := range bound.Accesses {
				access := storageTestAccess(t, bound.Prefix.Geometry, access)
				start, extent, value, kind := int64(-16), int64(width), uint64(7), nativeproof.FrameRead
				switch i {
				case 0:
					extent, kind = 8, nativeproof.FrameWrite
				case 2:
					value, kind = 1, nativeproof.FrameWrite
				case 3:
					start, extent, value, kind = 0, 8, 0x401000, nativeproof.FrameReturnRead
				}
				if access.Image || access.Bytes != (nativeproof.RelativeSpan{Start: start, End: start + extent}) || access.Kind != kind || storageJointEval(t, access.Value, assignments) != value {
					t.Fatalf("width %d native access %d differs from independent intent", width, i)
				}
				if (i == 1 || i == 2) && (access.ID != group.ID || access.PC != group.PC || access.Context != group.Context) {
					t.Fatal("CAS extent is detached from its actual occurrence")
				}
			}
			want := map[storageByteLocation]byte{}
			for at, value := range initial {
				want[at] = value
			}
			for lane := range 8 {
				want[storageByteLocation{Offset: -16 + int64(lane)}] = byte(uint64(1) >> (8 * lane))
			}
			got := map[storageByteLocation]byte{}
			for _, cell := range bound.State.Memory {
				at := storageTestCoordinate(t, bound.Prefix.Geometry, cell.TransitionLocation)
				value := storageJointEval(t, cell.Value, assignments)
				if _, duplicate := got[at]; duplicate || value > 255 {
					t.Fatal("returned native byte population is invalid")
				}
				got[at] = byte(value)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("native endpoint differs from independent full-byte result")
			}
			if width == 4 {
				finals[seed] = got
			} else if !reflect.DeepEqual(got, finals[seed]) {
				t.Fatal("width baselines do not have identical complete final bytes")
			}
			registers[nativeproof.RAX], registers[nativeproof.RDX], registers[nativeproof.RSP] = 7, 1, (1<<40)+0x108
			for i, value := range registers {
				if storageJointEval(t, bound.State.Registers[i].Value, assignments) != value {
					t.Fatal("width baseline changes final register values")
				}
			}
		}
	}
	for _, tc := range []struct {
		root, callee string
		width        int
	}{{"NarrowRoot", "Narrow", 4}, {"WideRoot", "Wide", 8}} {
		root := source.prog.Roots[tc.root]
		call := localEffectCalls(t, root, tc.callee)[0]
		prefix, err := checkSourceOperandPrefix(t.Context(), source, root, call, defaultRegistrationLimits())
		if err != nil {
			t.Fatal(err)
		}
		returns := storageOracleInstructions[*ssa.Return](root)
		if len(returns) != 1 || len(prefix.region.packet.trace.allocations) != 1 {
			t.Fatal("width baseline needs one actual local allocation and return")
		}
		complete, err := checkSourceReturnContinuation(t.Context(), prefix, returns[0], refs)
		if err != nil {
			t.Fatal(err)
		}
		object := prefix.operands[0].location.object
		current := complete.region.packet.observations[0].state.memory[object]
		if tc.width == 4 {
			if current.kind != regionAggregate || len(current.elements) != 2 || !slices.Equal(prefix.operands[0].location.path, []regionStep{{index: 0}}) {
				t.Fatal("narrow source lost whole array and actual first-element pointer")
			}
			first, ok1 := regionReferenceWord(current.elements[0], 4)
			second, ok2 := regionReferenceWord(current.elements[1], 4)
			if !ok1 || !ok2 || first != 1 || second != 0 {
				t.Fatal("narrow source final eight bytes differ from independent intent")
			}
		} else if value, ok := regionReferenceWord(current, 8); !ok || value != 1 || prefix.operands[0].location.path != nil {
			t.Fatal("wide source final eight bytes differ from independent intent")
		}
		for _, nativeWidth := range []int{4, 8} {
			t.Run(fmt.Sprintf("source%d/native%d", tc.width*8, nativeWidth*8), func(t *testing.T) {
				n := natives[nativeWidth]
				rho := storageRepresentation{source: source.prog, image: n.fixture.image, bindings: []storageBinding{{object: object, base: nativeproof.StackOffset(-16)}}}
				proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, n.fixture.image, n.fixture.entry, complete, n.returned, rho, nil)
				if tc.width == nativeWidth {
					if err != nil || proof == nil {
						t.Fatalf("matching-width complete positive: %v", err)
					}
					whole, owned := proof.layout.objectFootprint(object)
					actual, represented := proof.layout.locationFootprint(prefix.operands[0].location)
					if !owned || !represented || whole.Bytes != storageTestExtent(t, proof.layout.geometry, nativeproof.StackOffset(-16), 8) || actual.Bytes != storageTestExtent(t, proof.layout.geometry, nativeproof.StackOffset(-16), int64(tc.width)) || len(proof.atomics) != 1 {
						t.Fatal("matching-width proof lost whole-object versus atomic-subobject extents")
					}
					return
				}
				var mismatch *storageEffectMismatch
				if proof != nil || !errors.As(err, &mismatch) || mismatch.detail != "ordered source/native effects differ" || !strings.HasPrefix(err.Error(), "complete effects:") {
					t.Fatalf("same-values/final-bytes width mismatch must refuse at ordered typed atomic effects: %v", err)
				}
			})
		}
	}
}

func TestNarrowJointCorrespondenceGenerated(t *testing.T) {
	if testing.Short() {
		t.Skip("acquires selected ASM and checks conditional full source/native returns")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected amd64 interface")
	}
	programs := []narrowJointIntent{
		narrowJointProgram(0x80000000, 0x80000000, 0xffffffff, 0x35aa8057, 0),
		narrowJointProgram(0xffffffff, 0, 0x80000000, 0x7f55f081, 0xc1),
		narrowJointProgram(0, 1, 0xffffffff, 0x198001fe, 0xff),
		narrowJointProgram(7, 7, 7, 0x5533ffff, 0x80),
	}
	source, refs := narrowJointSelected(t, programs, "")
	for i, p := range programs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			root := source.prog.Roots[fmt.Sprintf("F%d", i)]
			s := narrowJointComplete(t, source, root, refs)
			f, native := narrowJointNative(t, p, "")
			rho := narrowJointRepresentation(source, root, s, f.image)
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, f.image, f.entry, s.complete, native, rho, nil)
			if err != nil {
				t.Fatalf("production joint positive: %v", err)
			}
			for _, seed := range []uint64{0, 0xffffffffffffffff, 0xdeadbeef80000001} {
				narrowJointCheck(t, p, source, root, s, f, proof, seed)
			}
		})
	}
}

func FuzzNarrowJointCorrespondence(f *testing.F) {
	if testing.Short() {
		f.Skip("acquires selected ASM and checks conditional full source/native returns")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		f.Skip("selected amd64 interface")
	}
	f.Add(uint32(0x80000001), uint32(0x80000001), uint32(0xffffffff), uint32(0x80ff80aa), uint16(0xc1), uint64(0xdeadbeef))
	f.Add(uint32(7), uint32(9), uint32(0x80000000), uint32(0xff0f0fff), uint16(0x80), uint64(0))
	f.Add(uint32(0xffffffff), uint32(0xffffffff), uint32(0x80000001), uint32(0x01aa8055), uint16(0xdf), uint64(0xffffffffffffffff))
	f.Fuzz(func(t *testing.T, current, compare, replacement, bytes uint32, shape uint16, seed uint64) {
		p := narrowJointProgram(current, compare, replacement, bytes, shape)
		source, refs := narrowJointSelected(t, []narrowJointIntent{p}, "")
		root := source.prog.Roots["F0"]
		s := narrowJointComplete(t, source, root, refs)
		native, returned := narrowJointNative(t, p, "")
		proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, native.image, native.entry, s.complete, returned, narrowJointRepresentation(source, root, s, native.image), nil)
		if err != nil {
			t.Fatal(err)
		}
		narrowJointCheck(t, p, source, root, s, native, proof, seed)
	})
}

func TestNarrowJointSemanticDisagreements(t *testing.T) {
	if testing.Short() {
		t.Skip("acquires semantically different selected ASM under fixed native code")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected amd64 interface")
	}
	p := narrowJointProgram(0x80000000, 0x80000000, 0xffffffff, 0x35aa8057, 0xff)
	// OR0 preserves 0x57 whereas AND0 clears it; the initial CAS succeeds, so
	// SETNE selects C0=2 instead of C0=1. Additional ordinary writes and repeated
	// locked OR0 groups change effects even when later byte endpoints coincide.
	for _, fault := range []string{"predicate", "logical", "missing-lock", "extra-write", "split-groups"} {
		t.Run("source-"+fault, func(t *testing.T) {
			source, refs := narrowJointSelected(t, []narrowJointIntent{p}, fault)
			root := source.prog.Roots["F0"]
			s := narrowJointComplete(t, source, root, refs)
			f, native := narrowJointNative(t, p, "")
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, f.image, f.entry, s.complete, native, narrowJointRepresentation(source, root, s, f.image), nil)
			if err == nil || proof != nil || !strings.Contains(err.Error(), "complete effects:") {
				t.Fatalf("selected semantic edit must fail actual effect correspondence, not acquisition/return: %v", err)
			}
		})
	}
	source, refs := narrowJointSelected(t, []narrowJointIntent{p}, "")
	root := source.prog.Roots["F0"]
	s := narrowJointComplete(t, source, root, refs)
	for _, fault := range []string{"wrong-element", "extra-write"} {
		t.Run("native-"+fault, func(t *testing.T) {
			f, native := narrowJointNative(t, p, fault)
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, f.image, f.entry, s.complete, native, narrowJointRepresentation(source, root, s, f.image), nil)
			if err == nil || proof != nil || !strings.Contains(err.Error(), "complete effects:") {
				t.Fatalf("native edit must fail actual effect correspondence after native return proof: %v", err)
			}
		})
	}
	t.Run("native-missing-lock", func(t *testing.T) {
		// Unlocked byte OR is outside the admitted native transfer grammar. It
		// must fail at that actual instruction, before a return theorem exists;
		// the source-side missing-LOCK case above separately reaches matching.
		fixture, _ := narrowJointNative(t, p, "")
		code, cut := narrowJointCode(p, "missing-lock")
		raw := slices.Clone(fixture.raw)
		copy(raw[4096:], code)
		binary.LittleEndian.PutUint64(raw[64+32:], uint64(len(code)))
		binary.LittleEndian.PutUint64(raw[64+40:], uint64(len(code)))
		image, err := nativeproof.NewImage(t.Context(), raw)
		if err != nil {
			t.Fatal(err)
		}
		decode := globalCandidateDecoder(t, raw)
		var expansions []nativeproof.TransitionExpansion
		var ordinaryPC uint64
		for pc := fixture.entry; pc < cut; {
			instruction := decode(pc)
			if instruction.Op == x86asm.OR && ordinaryPC == 0 {
				ordinaryPC = pc
			}
			if nativeproof.TransitionExpansionRequired(instruction) {
				expansions = append(expansions, nativeproof.TransitionExpansion{PC: pc})
			}
			pc += uint64(instruction.Len)
		}
		if ordinaryPC == 0 {
			t.Fatal("missing actual unlocked OR instruction")
		}
		_, err = nativeproof.ProposeRegionTransition(t.Context(), image, fixture.entry, cut, nativeproof.TransitionLimits{}, nativeproof.TransitionOptions{Expansions: expansions})
		var refusal *nativeproof.Refusal
		if !errors.As(err, &refusal) || refusal.PC != ordinaryPC || refusal.Premise != "transition-expansion" || refusal.Detail != "selected encoding has no admitted transfer" {
			t.Fatalf("missing LOCK refused at wrong producer stage: %v", err)
		}
	})
}
