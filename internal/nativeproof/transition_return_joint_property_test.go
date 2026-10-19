package nativeproof

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// This is a branching effect grammar, rather than a second stack interpreter.
// It reuses the saved-register grammar, DAG assembler, concrete transfer oracle
// (including RET), and primitive-order oracle. All intent and concrete inputs
// precede checking. Sample evaluation supplements the checker's universal
// conditional theorem; it is not exhaustive machine or interface verification.
type jointReturnProgram struct {
	x                           dagLayout
	face                        TransitionInterface
	saved                       []Register
	source                      uint8
	ret, slow, error, body, end int
	fixedAddress, fixedWord     uint64
	geometry, fault             uint8
}

func jointReturnProgramFor(t testing.TB, registers []byte, frame uint16, order, source, geometry, fault uint8, placement uint64) jointReturnProgram {
	t.Helper()
	p := jointReturnProgram{saved: returnFrameRegisters(registers), source: source % 16, geometry: geometry % 5, fault: fault % 11}
	if p.source == uint8(RSP) || p.source == uint8(R14) {
		p.source = uint8(RDX)
	}
	var ops []dagOp
	emit := func(i to.Intent, e to.Encoding) int {
		j := len(ops)
		ops = append(ops, dagOp{i: i, e: e, next: j + 1})
		return j
	}
	stack := func(r Register, pop bool) {
		i, e := to.Intent{Operation: to.Push, Dst: uint8(r)}, to.Encoding{Form: to.PUSH50}
		if pop {
			i.Operation, e.Form = to.Pop, to.POP58
		}
		if r >= 8 {
			e.REX = 0x41
		}
		emit(i, e)
	}
	emit(to.Intent{Operation: to.CompareFromMemory, Dst: 4, Base: 14, SignedDisp: 16}, to.Encoding{Form: to.CMP3B, REX: 0x49, DispBytes: 1})
	guard := emit(to.Intent{Operation: to.Branch, Condition: 6}, to.Encoding{Form: to.JccNear})
	for _, r := range p.saved {
		stack(r, false)
	}
	depth := int64(frame % 257)
	emit(to.Intent{Operation: to.Subtract, Dst: 4, Immediate: uint64(depth)}, to.Encoding{Form: to.SUB81, REX: 0x48})
	p.body = 2 * len(ops)
	emit(to.Intent{Operation: to.CompareMemoryImmediate, Base: 14, SignedDisp: 16, Immediate: 1}, to.Encoding{Form: to.CMP83, REX: 0x49, DispBytes: 1})
	fork := emit(to.Intent{Operation: to.Branch, Condition: 6}, to.Encoding{Form: to.JccNear})
	permutations := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	atomic := func(kind int) {
		i := to.Intent{Operation: []to.Operation{to.LockedCompareExchange, to.LockedExchange, to.LockedExchangeAdd}[kind], Base: 14, Src: p.source}
		e := to.Encoding{Form: []to.Form{to.LOCKCMPXCHG0FB1, to.XCHG87, to.LOCKXADD0FC1}[kind], REX: 0x49 | (p.source/8)<<2, DispBytes: 1}
		if kind == 1 && order&8 != 0 {
			e.Form = to.LOCKXCHG87
		}
		emit(i, e)
	}
	var skips, tails []int
	for arm := 0; arm < 2; arm++ {
		if arm == 1 {
			ops[fork].taken = len(ops)
			p.error = 2 * len(ops)
		}
		for _, kind := range permutations[(int(order)+arm)%len(permutations)] {
			atomic(kind)
		}
		// The last arithmetic primitive's actual ZF chooses whether an extra
		// RMW executes; an image-word branch alone would not test this dependency.
		skips = append(skips, emit(to.Intent{Operation: to.Branch, Condition: 5}, to.Encoding{Form: to.JccNear}))
		atomic(1 + arm)
		tails = append(tails, len(ops)-1)
	}
	join := len(ops)
	for _, j := range skips {
		ops[j].taken = join
	}
	for _, j := range tails {
		ops[j].next = join
	}
	p.end = 2 * join
	// Erase scalar results deliberately. Primitive occurrences and residual
	// image bytes must still be checked, not inferred from final registers.
	erase := []uint8{0, p.source}
	for _, r := range p.saved {
		erase = append(erase, uint8(r))
	}
	for _, r := range erase {
		rex := byte(0)
		if r >= 8 {
			rex = 0x41
		}
		emit(to.Intent{Operation: to.MoveImmediate32, Dst: r}, to.Encoding{Form: to.MOVB8Imm32, REX: rex})
	}
	emit(to.Intent{Operation: to.Add, Dst: 4, Immediate: uint64(depth)}, to.Encoding{Form: to.ADD81, REX: 0x48})
	for j := len(p.saved) - 1; j >= 0; j-- {
		r := p.saved[j]
		if p.fault == 8 && j == 0 {
			r = (r + 1) % 16
			if r == RSP {
				r++
			}
		}
		stack(r, true)
	}
	p.ret = 2 * emit(to.Intent{Operation: to.Return}, to.Encoding{Form: to.RETC3})
	caller := emit(to.Intent{Operation: to.MoveImmediate32, Dst: 3, Immediate: 1}, to.Encoding{Form: to.MOVB8Imm32})
	p.slow = 2 * len(ops)
	ops[guard].taken = len(ops)
	ops = append(ops, dagOp{boundary: []byte{0x0f, 0x0b}})
	if p.fault == 2 {
		ops[p.error/2].boundary = []byte{0x0f, 0x0b}
	}
	// This independent immutable code word participates in joint nonvacuity.
	// It is not used to initialize the mutable guard or atomic destination.
	last := imageStateAddress - 16 // highest 16-congruent origin below its page
	switch p.geometry {
	case 1:
		p.fixedWord = last - 1
	case 2:
		p.fixedWord = last
	case 3:
		p.fixedWord = imageStateAddress + 511 // raw upper endpoint is excluded
	case 4:
		p.fixedWord = 0x9090909090909090
	}
	fixed := len(ops)
	word := binary.LittleEndian.AppendUint64(nil, p.fixedWord)
	ops = append(ops, dagOp{boundary: word})
	p.x = dagArrange(t, ops, placement)
	p.fixedAddress = p.x.pcs[2*fixed]
	target := p.x.pcs[2*caller]
	// Vary a continuation within the code load versus a distinct owned RX load.
	// The bytes and mapping are fixture inputs, not recovered from a theorem.
	loads := slices.Clone(p.x.mappings[1:])
	if p.fault == 4 {
		loads[0].write = false
	}
	code := slices.Clone(p.x.im.data[0x1000 : 0x1000+32*(len(ops)+1)])
	if placement&1 != 0 {
		target = 0x900000
		loads = append(loads, interfaceMapping{start: target, end: target + 1, file: loads[len(loads)-1].file + 4096, filesz: 1, read: true, execute: true})
	}
	raw := transitionImageELF(t, code, loads)
	if placement&1 != 0 {
		raw[loads[len(loads)-1].file] = 0xc3
	}
	binary.LittleEndian.PutUint64(raw[24:], p.x.pcs[0])
	var err error
	p.x.im, err = NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	p.x.digest = sha256.Sum256(raw)
	p.x.mappings = append(p.x.mappings[:1:1], loads...)
	bottom := -8*int64(len(p.saved)) - depth
	p.face = TransitionInterface{
		Origin: OriginDomain{Min: 1 << 40, Max: 1 << 41, Modulus: 16}, Envelope: RelativeSpan{bottom, 8}, Conditions: interfaceConditions(),
		Regions:              []RelativeRegion{{Bytes: RelativeSpan{bottom, 0}, Readable: true, Writable: true}, {Bytes: RelativeSpan{0, 8}, Readable: true}},
		ImageRegions:         []Span{{imageStateAddress, imageStateAddress + 24}, {p.fixedAddress, p.fixedAddress + 8}},
		EntryImagePointers:   []TransitionEntryImagePointer{{Register: R14, Address: imageStateAddress}},
		EntryWordUpperBounds: []TransitionEntryWordUpperBound{{Address: imageStateAddress + 16}, {Address: p.fixedAddress}},
		ReturnContext:        &TransitionReturnContext{Target: target, Preserved: p.saved}, PrivateFrame: &TransitionPrivateFrame{Bytes: RelativeSpan{bottom, 0}},
	}
	p.face.Conditions.LockedMemory = LockedMemoryModel
	if p.geometry >= 1 && p.geometry <= 3 {
		p.face.Origin = OriginDomain{Min: imageStateAddress - 512, Max: imageStateAddress + 512, Modulus: 16}
	}
	switch p.fault {
	case 1:
		p.face.EntryWordUpperBounds[0].OriginOffset = 1
	case 3:
		p.face.Conditions.LockedMemory = ""
	case 5:
		p.face.Regions[1].Readable = false
	case 6:
		p.face.PrivateFrame.Bytes.End = 1
	case 7:
		p.face.ReturnContext.Target = imageStateAddress + 0x2000 // mapped data, not executable
	case 9:
		p.face.PrivateFrame = nil // allowed: concrete writes do not disappear
	case 10:
		p.face.Conditions.NoHiddenAliases = false
	}
	return p
}

func jointReturnInitial(p jointReturnProgram, raw []byte, old, compare, delta, guard uint64, aliases uint8) stateReference {
	r := stateRawInitial(p.face, raw)
	if p.geometry >= 1 && p.geometry <= 3 {
		r.origin = imageStateAddress - 16
	}
	if aliases%3 != 0 {
		for j := range r.regs {
			r.regs[j] = r.origin - 8 // a preexisting numeric alias of private scratch is allowed
			if aliases%3 == 2 {
				r.regs[j] = imageStateAddress
			}
		}
	}
	r.regs[RSP], r.regs[RAX], r.regs[p.source] = r.origin, compare, delta
	r.regs[R14] = imageStateAddress
	r.ptrs[R14] = statePointer{valid: true, image: true, off: int64(imageStateAddress), load: 1}
	r.loads = p.x.mappings
	g := guard % r.origin
	if p.fault == 1 {
		g = r.origin // satisfies weakened G<S+1, reaches the exceptional arm
	}
	if p.fault == 2 {
		g = 0 // satisfies G<S, reaches the feasible inner exceptional arm
	}
	for key, value := range map[stateLocation]uint64{
		{off: 0}: p.face.ReturnContext.Target,
		{image: true, off: int64(imageStateAddress)}:      old,
		{image: true, off: int64(imageStateAddress + 16)}: g,
		{image: true, off: int64(p.fixedAddress)}:         p.fixedWord,
	} {
		for lane := int64(0); lane < 8; lane++ {
			r.memory[key.add(lane)] = stateByte{value: byte(value >> (8 * uint(lane)))}
		}
	}
	return r
}

func jointReturnReference(t testing.TB, p jointReturnProgram, initial stateReference) (stateReference, []uint64, bool) {
	t.Helper()
	r := initial.clone()
	var fetches []uint64
	for index, steps := 0, 0; ; steps++ {
		if steps > len(p.x.intents) {
			t.Fatal("joint generator is not acyclic")
		}
		if index == p.slow || p.fault == 2 && index == p.error {
			return r, fetches, true
		}
		i := p.x.intents[index]
		fetches = append(fetches, p.x.pcs[index])
		r.referenceExec(t, i, index, p.x.pcs[index]+uint64(len(p.x.encoded[index])))
		if i.Operation == to.Return {
			return r, fetches, false
		}
		edge := 0
		if i.Operation == to.Branch && dagCondition(t, i.Condition, r.flags) {
			edge = 1
		}
		index = p.x.edges[index][edge]
	}
}

// Normalize only indices into the active trace so the existing scalar/group
// oracle can check it. The original indices and adjacent read/write pairing are
// checked first, preventing normalization from repairing malformed evidence.
func jointReturnActive(t testing.TB, b TransitionReturnBound, values map[br.Term]uint64) (TransitionBound, []uint64) {
	t.Helper()
	active := b.Prefix
	active.Accesses, active.PrimitiveEffects = nil, nil
	guards := map[uint64]bool{}
	var fetches []uint64
	for _, i := range b.Instructions {
		if i.Context != "" {
			t.Fatal("joint call-free grammar acquired an activation")
		}
		guards[i.Start] = stateEval(t, i.Guard, values) != 0
		if guards[i.Start] {
			fetches = append(fetches, i.Start)
		}
	}
	indices := map[int]int{}
	for j, a := range b.Accesses {
		if _, exists := guards[a.PC]; !exists {
			t.Fatal("access lacks its instruction guard")
		}
		if guards[a.PC] {
			indices[j] = len(active.Accesses)
			active.Accesses = append(active.Accesses, a)
		}
	}
	remap := func(pc uint64, read, write int) (int, int, bool) {
		if _, exists := guards[pc]; !exists || read < 0 || write != read+1 || write >= len(b.Accesses) || b.Accesses[read].PC != pc || b.Accesses[write].PC != pc {
			t.Fatal("primitive lost its original occurrence/access group")
		}
		return indices[read], indices[write], guards[pc]
	}
	for _, effect := range b.Prefix.PrimitiveEffects {
		switch e := effect.(type) {
		case LockedCompareExchangeEffect:
			r, w, yes := remap(e.PC, e.ReadAccess, e.WriteAccess)
			if yes {
				e.ReadAccess, e.WriteAccess = r, w
				active.PrimitiveEffects = append(active.PrimitiveEffects, e)
			}
		case LockedExchange64Effect:
			r, w, yes := remap(e.PC, e.ReadAccess, e.WriteAccess)
			if yes {
				e.ReadAccess, e.WriteAccess = r, w
				active.PrimitiveEffects = append(active.PrimitiveEffects, e)
			}
		case LockedExchangeAdd64Effect:
			r, w, yes := remap(e.PC, e.ReadAccess, e.WriteAccess)
			if yes {
				e.ReadAccess, e.WriteAccess = r, w
				active.PrimitiveEffects = append(active.PrimitiveEffects, e)
			}
		default:
			t.Fatalf("unexpected primitive %T", effect)
		}
	}
	return active, fetches
}

func assertJointReturn(t testing.TB, p jointReturnProgram, c TransitionReturnCertificate, initial, want stateReference, fetches []uint64) {
	t.Helper()
	b, ok := c.BoundFor(p.x.im)
	if !ok || !b.Prefix.ConditionalRegion || b.Prefix.Entry != p.x.pcs[0] || b.Prefix.ImageDigest != p.x.digest || b.Prefix.Rules != TransitionRules || !b.State.CalleeTerminated || b.State.PC != p.face.ReturnContext.Target || b.State.PC != want.returnTarget || !reflect.DeepEqual(b.Prefix.Interface, p.face) {
		t.Fatal("joint returned scope/context differs")
	}
	values := map[br.Term]uint64{}
	for r, v := range b.Prefix.InitialRegisters {
		values[v] = initial.regs[r]
	}
	for _, v := range b.Prefix.InitialMemory {
		original, exists := initial.memory[stateByteLocation(v)]
		if !exists {
			t.Fatal("invented initial byte")
		}
		if v.Value.View().Op == br.Variable {
			values[v.Value] = uint64(original.value)
		} else if stateEval(t, v.Value, nil) != uint64(original.value) {
			t.Fatal("entry fixed byte differs from independent control context")
		}
	}
	for j, term := range []br.Term{b.Prefix.InitialPredicates.CF, b.Prefix.InitialPredicates.ZF, b.Prefix.InitialPredicates.SFXorOF} {
		if []bool{initial.flags[0], initial.flags[1], initial.flags[3] != initial.flags[2]}[j] {
			values[term] = 1
		} else {
			values[term] = 0
		}
	}
	if stateEval(t, b.Prefix.EntryPredicate, values) != 1 || stateEval(t, b.Prefix.CutGuard, values) != 1 {
		t.Fatal("independent admitted state lost entry/complete-return reach")
	}
	active, gotFetches := jointReturnActive(t, b, values)
	if !slices.Equal(gotFetches, fetches) || len(active.Accesses) != len(want.accesses) {
		t.Fatal("filtered full execution or access order differs", gotFetches, fetches)
	}
	for j, expected := range want.accesses {
		a := active.Accesses[j]
		kind := FrameRead
		if expected.write {
			kind = FrameWrite
		} else if expected.returnRead {
			kind = FrameReturnRead
		}
		if a.PC != p.x.pcs[expected.instruction] || a.Context != expected.context || a.Image != expected.off.image || a.Kind != kind || a.Bytes != (RelativeSpan{expected.off.off, expected.off.off + int64(expected.width)}) || stateEval(t, a.Value, values) != expected.value {
			t.Fatalf("ordered access %d differs: %+v versus %+v", j, a, expected)
		}
	}
	if err := statePrimitiveBindings(t, active, p.x.stateLayout, want, values); err != nil {
		t.Fatal(err)
	}
	for r, v := range b.State.Registers {
		if stateEval(t, v.Value, values) != want.regs[r] {
			t.Fatal("joint final register differs", r)
		}
	}
	if b.State.Registers[RSP].Pointer != (OriginPointer{Origin: b.Prefix.Origin, Offset: 8}) || want.regs[RSP] != initial.origin+8 {
		t.Fatal("return did not consume the original control slot")
	}
	prefix, _ := c.Prefix()
	for _, r := range p.saved {
		if r == R14 {
			ptr, valid := b.State.Registers[r].Pointer.(ImagePointer)
			if !valid || ptr.Address != imageStateAddress || ptr.owner != &p.x.im.data[0] {
				t.Fatal("restored concrete image pointer differs")
			}
		} else if reg, valid := prefix.EntryValueRegister(b.State.Registers[r].Pointer); !valid || reg != r {
			t.Fatal("caller lineage lost across branching primitives and return", r)
		}
	}
	if len(b.State.Memory) != len(want.memory) {
		t.Fatal("residual memory extent differs")
	}
	seen := map[stateLocation]bool{}
	for _, v := range b.State.Memory {
		key := stateByteLocation(v)
		expected, exists := want.memory[key]
		if !exists || seen[key] || stateEval(t, v.Value, values) != uint64(expected.value) {
			t.Fatal("residual private/image/control byte differs", key)
		}
		seen[key] = true
		for j, r := range p.saved {
			slot := -8 * int64(j+1)
			if v.Image || v.Offset < slot || v.Offset >= slot+8 {
				continue
			}
			if v.PointerLane != uint8(v.Offset-slot) {
				t.Fatal("residual saved word lost ordered lanes")
			}
			if r == R14 {
				ptr, valid := v.Pointer.(ImagePointer)
				if !valid || ptr.Address != imageStateAddress || ptr.owner != &p.x.im.data[0] {
					t.Fatal("residual concrete saved pointer differs")
				}
			} else if reg, valid := prefix.EntryValueRegister(v.Pointer); !valid || reg != r {
				t.Fatal("released scratch lost its actual caller-word lineage")
			}
		}
	}
	for j, flag := range []TransitionFlag{b.State.Flags.CF, b.State.Flags.ZF, b.State.Flags.OF, b.State.Flags.SF, b.State.Flags.AF, b.State.Flags.PF} {
		if !flag.Defined || !flag.Value.Valid() || (stateEval(t, flag.Value, values) != 0) != want.flags[j] {
			t.Fatal("returned arithmetic flag differs", j)
		}
	}
	// The same oracle must notice reordered primitives even though every final
	// byte/register in this non-authorizing projection remains untouched.
	active.PrimitiveEffects[0], active.PrimitiveEffects[1] = active.PrimitiveEffects[1], active.PrimitiveEffects[0]
	if err := statePrimitiveBindings(t, active, p.x.stateLayout, want, values); err == nil {
		t.Fatal("primitive order oracle accepted a permuted complete-return trace")
	}
}

type jointReturnCoverage struct{ arms, counts, comparisons, kinds, mappings uint8 }

func checkJointReturn(t testing.TB, registers, raw []byte, frame uint16, order, source, geometry, fault, aliases uint8, placement, old, compare, delta, guard uint64) jointReturnCoverage {
	t.Helper()
	p := jointReturnProgramFor(t, registers, frame, order, source, geometry, fault, placement)
	initial := jointReturnInitial(p, raw, old, compare, delta, guard, aliases)
	var want stateReference
	var fetches []uint64
	if p.geometry < 2 && (p.fault == 0 || p.fault == 1 || p.fault == 2 || p.fault == 8 || p.fault == 9) {
		var trapped bool
		want, fetches, trapped = jointReturnReference(t, p, initial)
		if trapped != (p.fault == 1 || p.fault == 2) {
			t.Fatal("feasible exceptional-path control lacks its intended concrete witness")
		}
	}
	positive := p.geometry < 2 && (p.fault == 0 || p.fault == 9)
	proposal := p.x.proposal(p.ret)
	prefix, err := CheckRegionTransition(t.Context(), p.x.im, p.x.pcs[0], p.face, proposal, TransitionLimits{})
	var complete TransitionReturnCertificate
	if err == nil {
		complete, err = CheckTransitionReturn(t.Context(), prefix)
	}
	if !positive {
		returnRefused(t, complete, err)
		// Single-premise controls must fail for that premise, not a coincident
		// resource limit or unrelated unsupported transfer. Multi-fault fuzz
		// products require refusal without prescribing validation precedence.
		premise := ""
		if p.fault == 0 && p.geometry >= 2 {
			premise = "transition-entry"
		} else if p.geometry == 0 {
			premise = map[uint8]string{1: "transition-guard", 2: "transition-guard", 3: "transition-primitive-premise", 4: "transition-permission", 5: "transition-return", 6: "transition-private-frame", 7: "instruction-mapping", 8: "transition-return-preserved", 10: "transition-premises"}[p.fault]
		}
		if premise != "" {
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Premise != premise {
				t.Fatalf("single-premise control wanted %s, got %v", premise, err)
			}
		}
		return jointReturnCoverage{}
	}
	if err != nil {
		t.Fatal(err)
	}
	assertJointReturn(t, p, complete, initial, want, fetches)
	// Split before branching/primitive execution and after its common join.
	// Neither segment can replace the root private/control/entry premises.
	prior, err := CheckRegionTransition(t.Context(), p.x.im, p.x.pcs[0], p.face, p.x.proposal(p.body), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	root, _ := prior.Bound()
	projection, _ := prior.Bound()
	if projection.Interface.PrivateFrame != nil {
		projection.Interface.PrivateFrame.Bytes = RelativeSpan{-1, 0}
	} else {
		projection.Interface.PrivateFrame = &TransitionPrivateFrame{Bytes: RelativeSpan{-1, 0}}
	}
	projection.Interface.ReturnContext.Target = 1
	for _, cut := range []int{p.end, p.ret} {
		prior, err = CheckTransitionContinuation(t.Context(), prior, p.x.proposal(cut))
		if err != nil {
			t.Fatal(err)
		}
		stateInheritedInputs(t, root, prior.checked.bound)
	}
	segmented := checkedReturn(t, prior)
	assertJointReturn(t, p, segmented, initial, want, fetches)
	assertTransitionAlpha(t, prefix, prior)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	stopped, err := CheckTransitionReturn(ctx, prior)
	returnRefused(t, stopped, err)
	foreign, err := NewImage(t.Context(), p.x.im.data)
	if err != nil {
		t.Fatal(err)
	}
	if _, borrowed := complete.BoundFor(foreign); borrowed {
		t.Fatal("joint return evidence borrowed an equal-byte image owner")
	}
	if p.geometry == 0 && p.fault == 0 && order == 0 && guard == 0 && old == 0 && compare == 0 && delta == 0 {
		limits := TransitionLimits{RelationLimits: RelationLimits{Work: prefix.checked.work + 1}}
		limited, err := CheckRegionTransition(t.Context(), p.x.im, p.x.pcs[0], p.face, proposal, limits)
		if err != nil {
			t.Fatal("joint cumulative-work control did not admit its prefix", err)
		}
		result, err := CheckTransitionReturn(t.Context(), limited)
		returnRefused(t, result, err)
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.Premise != "relation-budget" {
			t.Fatal("joint return exhaustion was not the cumulative work boundary", err)
		}
	}
	if len(want.primitives) < 3 || len(want.primitives) > 4 {
		t.Fatal("joint reference escaped its primitive-count grammar")
	}
	coverage := jointReturnCoverage{arms: 1, counts: 1 << (len(want.primitives) - 3), mappings: 1 << (placement & 1)}
	if slices.Contains(fetches, p.x.pcs[p.error]) {
		coverage.arms = 2
	}
	for _, primitive := range want.primitives {
		e := primitive.(stateRMW)
		switch e.kind {
		case to.LockedExchange:
			coverage.kinds |= 2
		case to.LockedExchangeAdd:
			coverage.kinds |= 4
		default:
			coverage.kinds |= 1
			if e.success {
				coverage.comparisons |= 1
			} else {
				coverage.comparisons |= 2
			}
		}
	}
	return coverage
}

func TestTransitionReturnJointPopulation(t *testing.T) {
	var coverage jointReturnCoverage
	for order := uint8(0); order < 6; order++ {
		for _, guard := range []uint64{0, 1, 2, ^uint64(0)} {
			for _, operands := range [][3]uint64{{0, 0, 0}, {7, 7, 11}, {7, 9, ^uint64(0)}} {
				name := fmt.Sprintf("order%d/guard%d/operands%x", order, guard, operands)
				t.Run(name, func(t *testing.T) {
					got := checkJointReturn(t, []byte{5, 14, 0, 2}, []byte{17, 31, 63, 127, 255}, uint16(order)*17, order, 2, order%2, 0, order%3, uint64(order), operands[0], operands[1], operands[2], guard)
					coverage.arms |= got.arms
					coverage.counts |= got.counts
					coverage.comparisons |= got.comparisons
					coverage.kinds |= got.kinds
					coverage.mappings |= got.mappings
				})
			}
		}
	}
	if coverage != (jointReturnCoverage{arms: 3, counts: 3, comparisons: 3, kinds: 7, mappings: 3}) {
		t.Fatal("independent reference population missed a promised interaction", coverage)
	}
	for fault := uint8(1); fault <= 10; fault++ {
		t.Run(fmt.Sprintf("premise%d", fault), func(t *testing.T) {
			checkJointReturn(t, []byte{5, 14, 2}, nil, 16, 0, 2, 0, fault, 1, 1, 7, 7, 11, 0)
		})
	}
	for geometry := uint8(1); geometry <= 4; geometry++ {
		t.Run(fmt.Sprintf("nonvacuity%d", geometry), func(t *testing.T) {
			checkJointReturn(t, []byte{5, 14}, nil, 16, 0, 2, geometry, 0, 2, 0, 0, 0, 0, 2)
		})
	}
}

func FuzzTransitionReturnJointEffects(f *testing.F) {
	for _, sample := range []struct{ order, source, geometry, fault, aliases uint8 }{
		{8, 2, 0, 0, 0}, {1, 0, 1, 0, 1}, {10, 5, 0, 0, 2}, {3, 8, 0, 0, 0}, {12, 15, 1, 0, 1}, {5, 3, 0, 9, 2},
		{0, 2, 0, 1, 1}, {0, 2, 0, 2, 1}, {0, 2, 0, 4, 1}, {0, 2, 2, 0, 1}, {0, 2, 3, 0, 1}, {0, 2, 4, 0, 1},
	} {
		for _, guard := range []uint64{0, 2} {
			f.Add([]byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 3, 2, 1, 0}, []byte{17, 31, 63, 127, 255}, uint16(256), sample.order, sample.source, sample.geometry, sample.fault, sample.aliases, uint64(sample.order), uint64(7), uint64(7), uint64(11), guard)
		}
	}
	f.Fuzz(func(t *testing.T, registers, raw []byte, frame uint16, order, source, geometry, fault, aliases uint8, placement, old, compare, delta, guard uint64) {
		checkJointReturn(t, registers, raw, frame, order, source, geometry, fault, aliases, placement, old, compare, delta, guard)
	})
}
