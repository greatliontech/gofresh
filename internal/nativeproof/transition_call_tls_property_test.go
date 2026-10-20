package nativeproof

import (
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"slices"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// The reference writes/reads bytes using concrete arithmetic, without invoking
// the production address, lane, frame or transfer helpers.
func (r *stateReference) referenceStack(t testing.TB, i to.Intent, index int, next ...uint64) {
	t.Helper()
	sp := r.regs[4]
	if !r.ptrs[4].valid || r.ptrs[4].image {
		t.Fatal("reference stack has no origin")
	}
	if i.Operation == to.Push || i.Operation == to.Call {
		value, p := r.regs[i.Dst], r.ptrs[i.Dst]
		if i.Operation == to.Call {
			if len(next) != 1 {
				t.Fatal("CALL next")
			}
			value, p = next[0], statePointer{}
		}
		sp -= 8
		off := stateLocation{off: int64(sp - r.origin)}
		for lane := 0; lane < 8; lane++ {
			k := off.add(int64(lane))
			if _, ok := r.memory[k]; !ok {
				t.Fatal("reference stack store outside declared bytes")
			}
			b := stateByte{value: byte(value >> uint(lane*8)), ptr: p}
			if p.valid {
				b.lane = uint8(lane)
			}
			r.memory[k] = b
			r.frame[k] = true
		}
		r.accesses = append(r.accesses, stateAccess{instruction: index, write: true, off: off, width: 8, context: r.context, value: value})
		r.regs[4] = sp
		r.ptrs[4].off -= 8
		r.written[4] = true
		return
	}
	off := stateLocation{off: int64(sp - r.origin)}
	var value uint64
	p := r.memory[off].ptr
	for lane := 0; lane < 8; lane++ {
		b, ok := r.memory[off.add(int64(lane))]
		if !ok {
			t.Fatal("reference stack read outside declared bytes")
		}
		value |= uint64(b.value) << uint(lane*8)
		if b.ptr != r.memory[off].ptr || b.lane != uint8(lane) {
			p = statePointer{}
		}
	}
	r.accesses = append(r.accesses, stateAccess{instruction: index, off: off, width: 8, context: r.context, returnRead: i.Operation == to.Return, value: value})
	r.regs[4] += 8
	r.ptrs[4].off += 8
	r.written[4] = true
	if i.Operation == to.Return {
		r.returnTarget = value
	} else {
		r.regs[i.Dst], r.ptrs[i.Dst], r.written[i.Dst] = value, p, true
	}
}

type referenceOccurrence struct {
	context TransitionActivationID
	index   int
}
type referenceActivation struct {
	parent      TransitionActivationID
	after, call int
	slot        uint64
}

// Fixture IDs are independent of discovery order, bounded by the generated
// population's depth and 4096-operation limit. Activation is the actual CALL ID.
func referenceID(parent TransitionActivationID, index int) TransitionOccurrenceID {
	return TransitionOccurrenceID(parent)*4096 + TransitionOccurrenceID(index+1)
}
func referenceContext(parent TransitionActivationID, index int) TransitionActivationID {
	return TransitionActivationID(referenceID(parent, index))
}

func referenceCallAfter(x dagLayout, j int) int {
	if x.callReturns != nil {
		return x.callReturns[j]
	}
	return j + 1
}

func callInventory(t testing.TB, x dagLayout, cut int) TransitionProposal {
	t.Helper()
	p := TransitionProposal{ImageDigest: x.digest, Entry: x.pcs[0], Cut: x.pcs[cut], Root: referenceID(0, 0)}
	queue := []referenceOccurrence{{}}
	seen := map[referenceOccurrence]bool{}
	contexts := map[TransitionActivationID]referenceActivation{}
	for at := 0; at < len(queue); at++ {
		o := queue[at]
		if seen[o] {
			continue
		}
		seen[o] = true
		if len(seen) > 4096 {
			t.Fatal("independent occurrence inventory bound")
		}
		j := o.index
		n := TransitionNode{ID: referenceID(o.context, j), PC: x.pcs[j], Size: uint8(len(x.encoded[j]))}
		var next []referenceOccurrence
		if j != cut {
			i := x.intents[j]
			switch i.Operation {
			case to.Call:
				child := referenceContext(o.context, j)
				contexts[child] = referenceActivation{parent: o.context, after: referenceCallAfter(x, j), call: j}
				next = []referenceOccurrence{{child, x.edges[j][0]}}
				n.Expanded = true
			case to.Return:
				a, ok := contexts[o.context]
				if !ok {
					t.Fatal("reference root return")
				}
				next = []referenceOccurrence{{a.parent, a.after}}
			default:
				for _, k := range x.edges[j] {
					next = append(next, referenceOccurrence{o.context, k})
				}
				if to.RequiresExpansion(i) {
					n.Expanded = true
				}
			}
		}
		for _, k := range next {
			n.Successors = append(n.Successors, referenceID(k.context, k.index))
			queue = append(queue, k)
		}
		p.Nodes = append(p.Nodes, n)
	}
	return p
}

type callEvent struct {
	pc      uint64
	context TransitionActivationID
	kind    string
	off     stateLocation
	width   int
}

func callTLSAssert(t testing.TB, c TransitionCertificate, x dagLayout, cut int, face TransitionInterface, initial stateReference) {
	t.Helper()
	r := initial.clone()
	r.loads = x.mappings
	var want []callEvent
	var active []referenceActivation
	context := TransitionActivationID(0)
	for j, steps := 0, 0; j != cut; steps++ {
		if steps >= 4096 {
			t.Fatal("reference execution did not reach cut")
		}
		i := x.intents[j]
		if i.Operation == 0 {
			t.Fatal("reference reached structural-only boundary")
		}
		r.context = context
		want = append(want, callEvent{pc: x.pcs[j], context: context, kind: "fetch", width: len(x.encoded[j])})
		a, firstPrimitive := len(r.accesses), len(r.primitives)
		r.referenceExec(t, i, j, x.pcs[j]+uint64(len(x.encoded[j])))
		for _, v := range r.accesses[a:] {
			kind := "read"
			if v.write {
				kind = "write"
			}
			if v.returnRead {
				kind = "return-read"
			}
			want = append(want, callEvent{x.pcs[j], context, kind, v.off, v.width})
		}
		for _, event := range r.primitives[firstPrimitive:] {
			switch event.(type) {
			case stateQuery:
				want = append(want, callEvent{pc: x.pcs[j], context: context, kind: "query"})
			case stateSyscall:
				want = append(want, callEvent{pc: x.pcs[j], context: context, kind: "syscall"}, callEvent{pc: x.pcs[j], context: context, kind: "abstraction"})
			default:
				t.Fatal("unsupported call/TLS reference primitive")
			}
		}
		switch i.Operation {
		case to.Call:
			active = append(active, referenceActivation{parent: context, after: referenceCallAfter(x, j), call: j, slot: r.regs[4]})
			context = referenceContext(context, j)
			j = x.edges[j][0]
		case to.Return:
			if len(active) == 0 {
				t.Fatal("reference unpaired RET")
			}
			a := active[len(active)-1]
			active = active[:len(active)-1]
			if r.returnTarget != x.pcs[a.after] {
				t.Fatal("reference return word changed")
			}
			context, j = a.parent, a.after
		default:
			edge := 0
			if i.Operation == to.Branch && dagCondition(t, i.Condition, r.flags) {
				edge = 1
			}
			j = x.edges[j][edge]
		}
	}
	b := c.checked.bound
	if b.ImageDigest != x.digest || b.Entry != x.pcs[0] || b.Rules != TransitionRules {
		t.Fatal("call/TLS scope binding differs")
	}
	inventory := callInventory(t, x, cut)
	if len(inventory.Nodes) != len(b.Instructions)+len(b.ExcludedBoundaries)+1 {
		t.Fatal("call/TLS structural population differs")
	}
	if b.Boundary.ID != referenceID(context, cut) || b.Boundary.PC != x.pcs[cut] || b.Boundary.Context != context || !slices.Equal(b.Boundary.Bytes, x.encoded[cut]) {
		t.Fatal("wrong cut occurrence")
	}
	values := stateBindings(t, c, face, initial)
	type key struct {
		pc      uint64
		context TransitionActivationID
	}
	guards := map[key]br.Term{}
	structural := map[key]TransitionNode{}
	for _, n := range inventory.Nodes {
		structural[key{n.PC, TransitionActivationID((n.ID - 1) / 4096)}] = n
	}
	for _, i := range b.Instructions {
		k := key{i.Start, i.Context}
		if guards[k].Valid() || structural[k].ID != i.ID || structural[k].Size != uint8(i.End-i.Start) {
			t.Fatal("collapsed occurrence")
		}
		guards[k] = i.Guard
	}
	queries := map[key]stateQuery{}
	for q := range statePrimitivesOf[stateQuery](r) {
		queries[key{x.pcs[q.instruction], q.context}] = q
	}
	syscalls := map[key]stateSyscall{}
	for q := range statePrimitivesOf[stateSyscall](r) {
		syscalls[key{x.pcs[q.instruction], q.context}] = q
	}
	abstractions := map[key]TransitionAbstraction{}
	for _, a := range b.Abstractions {
		k := key{a.PC, a.Context}
		if structural[k].ID != a.ID {
			t.Fatal("abstraction lost exact occurrence")
		}
		if _, ok := abstractions[k]; ok {
			t.Fatal("duplicate abstraction")
		}
		abstractions[k] = a
	}
	primitiveKinds := map[key]string{}
	scopes := map[br.Scope]bool{b.Origin.View().Scope: true}
	var orderedPrimitives []callEvent
	for _, effect := range b.PrimitiveEffects {
		switch e := effect.(type) {
		case CPUIDEffect:
			k := key{e.PC, e.Context}
			g, exists := guards[k]
			if !exists || structural[k].ID != e.ID || primitiveKinds[k] != "" {
				t.Fatal("unbound primitive occurrence")
			}
			active := stateEval(t, g, values) != 0
			q, present := queries[k]
			if active != present {
				t.Fatal("query reach differs")
			}
			leaf, sub := stateEval(t, e.Leaf, values), stateEval(t, e.Subleaf, values)
			if active && (leaf != uint64(q.leaf) || sub != uint64(q.subleaf)) {
				t.Fatal("query selectors differ")
			}
			scope := e.ResultsEAX.View().Scope
			if scopes[scope] {
				t.Fatal("query occurrence scope reused")
			}
			scopes[scope] = true
			for j, v := range []br.Term{e.ResultsEAX, e.ResultsEBX, e.ResultsECX, e.ResultsEDX} {
				view := v.View()
				if view.Op != br.Variable || view.Scratch || view.Scope != scope || view.Immediate != uint64(j) || view.Sort != br.Bits(32) {
					t.Fatal("query outcome origin")
				}
				values[v] = uint64(q.results[j])
				if !active {
					values[v] = uint64(0x12345678 + uint32(j)*17)
				}
			}
			primitiveKinds[k] = "query"
			if active {
				orderedPrimitives = append(orderedPrimitives, callEvent{pc: e.PC, context: e.Context, kind: "query"})
			}
		case ArchSetFSEffect:
			k := key{e.PC, e.Context}
			g, exists := guards[k]
			if !exists || structural[k].ID != e.ID || primitiveKinds[k] != "" {
				t.Fatal("unbound syscall occurrence")
			}
			active := stateEval(t, g, values) != 0
			q, present := syscalls[k]
			if active != present {
				t.Fatal("syscall reach differs")
			}
			got := []uint64{stateEval(t, e.Number, values), stateEval(t, e.Operation, values), stateEval(t, e.Base, values), stateEval(t, e.BeforeFS, values), stateEval(t, e.AfterFS, values), stateEval(t, e.Result, values)}
			if active && !slices.Equal(got, []uint64{q.number, q.option, q.base, q.before, q.after, q.result}) {
				t.Fatal("syscall exact relation differs", got, q)
			}
			if active && (stateEval(t, e.Valid, values) != 0) != q.valid {
				t.Fatal("syscall validity differs")
			}
			a, ok := abstractions[k]
			if !ok {
				t.Fatal("missing R11 analysis abstraction")
			}
			for j, p := range []br.Term{a.Predicates.CF, a.Predicates.ZF, a.Predicates.SFXorOF} {
				v := stateEval(t, p, values) != 0
				if active && v != q.predicates[j] {
					t.Fatal("abstraction lost incoming flag dependency")
				}
			}
			v := a.Value.View()
			if v.Op != br.Variable || v.Scratch || v.Sort != br.Bits(64) || v.Immediate != 0 || scopes[v.Scope] {
				t.Fatal("unbound abstraction origin")
			}
			scopes[v.Scope] = true
			values[a.Value] = q.r11
			if !active {
				values[a.Value] = 0x202
			}
			primitiveKinds[k] = "syscall"
			if active {
				orderedPrimitives = append(orderedPrimitives, callEvent{pc: e.PC, context: e.Context, kind: "syscall"}, callEvent{pc: e.PC, context: e.Context, kind: "abstraction"})
			}
		default:
			t.Fatal("unknown primitive")
		}
	}
	accesses := map[key][]TransitionAccess{}
	var orderedAccess []callEvent
	for _, a := range b.Accesses {
		k := key{a.PC, a.Context}
		if !guards[k].Valid() || structural[k].ID != a.ID {
			t.Fatal("access without occurrence")
		}
		accesses[k] = append(accesses[k], a)
		kind := "read"
		if a.Kind == FrameWrite {
			kind = "write"
		} else if a.Kind == FrameReturnRead {
			kind = "return-read"
		} else if a.Kind != FrameRead {
			t.Fatal("unknown access")
		}
		if stateEval(t, guards[k], values) != 0 {
			orderedAccess = append(orderedAccess, callEvent{a.PC, a.Context, kind, stateLocation{a.Image, a.Bytes.Start}, int(a.Bytes.End - a.Bytes.Start)})
		}
	}
	var got []callEvent
	for _, i := range b.Instructions {
		if stateEval(t, i.Guard, values) == 0 {
			continue
		}
		k := key{i.Start, i.Context}
		got = append(got, callEvent{pc: i.Start, context: i.Context, kind: "fetch", width: int(i.End - i.Start)})
		for _, a := range accesses[k] {
			kind := "read"
			if a.Kind == FrameWrite {
				kind = "write"
			}
			if a.Kind == FrameReturnRead {
				kind = "return-read"
			}
			got = append(got, callEvent{a.PC, a.Context, kind, stateLocation{a.Image, a.Bytes.Start}, int(a.Bytes.End - a.Bytes.Start)})
		}
		if kind := primitiveKinds[k]; kind != "" {
			got = append(got, callEvent{pc: i.Start, context: i.Context, kind: kind})
			if kind == "syscall" {
				got = append(got, callEvent{pc: i.Start, context: i.Context, kind: "abstraction"})
			}
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ordered occurrence trace differs\ngot %v\nwant %v", got, want)
	}
	var wantAccess, wantPrimitive []callEvent
	for _, v := range want {
		switch v.kind {
		case "read", "write", "return-read":
			wantAccess = append(wantAccess, v)
		case "query", "syscall", "abstraction":
			wantPrimitive = append(wantPrimitive, v)
		}
	}
	if !slices.Equal(orderedAccess, wantAccess) || !slices.Equal(orderedPrimitives, wantPrimitive) {
		t.Fatal("retained slice order differs")
	}
	assertCallTLSState(t, c, r, initial, values, active)
	for j, frame := range b.Frames {
		a := active[j]
		if frame.ID != referenceID(a.parent, a.call) || frame.Context != referenceContext(a.parent, a.call) || frame.Call != x.pcs[a.call] || frame.Return != x.pcs[a.after] || frame.Slot.Origin != b.Origin || frame.Slot.Offset != int64(a.slot-initial.origin) {
			t.Fatal("active frame relation differs")
		}
	}
	if stateEval(t, b.CutGuard, values) != 1 {
		t.Fatal("cut not total")
	}
}

func assertCallTLSState(t testing.TB, c TransitionCertificate, r, initial stateReference, values map[br.Term]uint64, frames []referenceActivation) {
	t.Helper()
	b := c.checked.bound
	if b.Direction.Sort() != br.Bool() || (stateEval(t, b.Direction, values) != 0) != r.direction {
		t.Fatal("call/syscall current direction differs")
	}
	pointer := func(p TransitionPointer, w statePointer) {
		t.Helper()
		if p == nil {
			return
		}
		if !w.valid {
			t.Fatal("invented pointer")
		}
		switch p := p.(type) {
		case OriginPointer:
			if w.image || p.Origin != b.Origin || p.Offset != w.off {
				t.Fatal("wrong origin pointer")
			}
		case ImagePointer:
			if !w.image || p.Address != uint64(w.off) || p.owner != &c.checked.image.data[0] || p.load != w.load {
				t.Fatal("wrong image pointer")
			}
		default:
			t.Fatal("unknown pointer")
		}
	}
	for j, v := range b.Registers {
		if stateEval(t, v.Value, values) != r.regs[j] {
			t.Fatalf("GPR %d differs", j)
		}
		pointer(v.Pointer, r.ptrs[j])
		if (initial.regs[j]^r.regs[j])&b.Preserved[j] != 0 {
			t.Fatal("false GPR preservation")
		}
	}
	if len(b.Memory) != len(r.memory) {
		t.Fatal("memory domain differs")
	}
	seen := map[stateLocation]bool{}
	for _, v := range b.Memory {
		k := stateByteLocation(v)
		w, ok := r.memory[k]
		if !ok || seen[k] || stateEval(t, v.Value, values) != uint64(w.value) {
			t.Fatal("current byte differs", k)
		}
		seen[k] = true
		pointer(v.Pointer, w.ptr)
		if v.Pointer != nil && v.PointerLane != w.lane {
			t.Fatal("pointer lane differs")
		}
	}
	for j, p := range c.checked.flags {
		want := []bool{r.flags[0], r.flags[1], r.flags[3] != r.flags[2]}[j]
		if (stateEval(t, p, values) != 0) != want {
			t.Fatal("private predicate differs")
		}
	}
	for j, f := range []TransitionFlag{b.Flags.CF, b.Flags.ZF, b.Flags.OF, b.Flags.SF, b.Flags.AF, b.Flags.PF} {
		if f.Preserved && r.writer != 0 {
			t.Fatal("false flag preservation")
		}
		if f.Value.Valid() && (stateEval(t, f.Value, values) != 0) != r.flags[j] {
			t.Fatal("flag projection differs")
		}
	}
	if b.InitialFS.Valid() {
		if stateEval(t, b.Thread.FS.Value, values) != r.fs {
			t.Fatal("FS state differs")
		}
		pointer(b.Thread.FS.Pointer, r.fsp)
		for q := range statePrimitivesOf[stateSyscall](r) {
			if !b.Thread.ContextChanged {
				t.Fatal("syscall context falsely preserved")
			}
			if q.valid && b.Thread.SelectorPreserved {
				t.Fatal("FS selector falsely preserved")
			}
		}
	}
	if len(b.Frames) != len(frames) {
		t.Fatal("active frame count differs")
	}
	for j, e := range b.ExcludedBoundaries {
		if stateEval(t, e.Guard, values) != 0 {
			t.Fatal("live excluded occurrence")
		}
		left, right := c.checked.exclusions[j].Roots()
		if left != e.Guard || !literalBool(right, 0) {
			t.Fatal("unbound exclusion proof")
		}
	}
}

func callTLSFace() TransitionInterface {
	f := imageStateFace()
	f.Regions = []RelativeRegion{{RelativeSpan{-256, 64}, true, true}}
	f.Words = []int64{0}
	f.Conditions.CPUID = CPUIDModel
	f.Conditions.Syscall = LinuxAMD64SyscallModel
	f.Conditions.UserAddressBits = 48
	return f
}

// Each CALL's child and following continuation are distinct logical nodes before
// physical permutation. Two outer activations execute the same nested callee.
func callTLSOps() []dagOp {
	imm := func(reg uint8, v uint64, next int) dagOp {
		return dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: reg, Immediate: v}, to.Encoding{Form: to.MOVB8Imm32}, next)
	}
	return []dagOp{
		{i: to.Intent{Operation: to.LEARIP, Dst: 6}, e: to.Encoding{Form: to.LEA8D, REX: 0x48, DispBytes: 4}, address: imageStateAddress + 72, next: 1},
		{i: to.Intent{Operation: to.Call}, e: to.Encoding{Form: to.CALLE8}, taken: 5, next: 2},
		{i: to.Intent{Operation: to.Call}, e: to.Encoding{Form: to.CALLE8}, taken: 5, next: 3},
		{i: to.Intent{Operation: to.StoreImmediate, FS: true, SignedDisp: -8, Immediate: 0x123}, e: to.Encoding{Form: to.MOVC7, REX: 0x48, SIB: true, DispBytes: 4}, next: 4},
		{i: to.Intent{Operation: to.Load, RIP: true, Dst: 0}, e: to.Encoding{Form: to.MOV8B, REX: 0x48, DispBytes: 4}, address: imageStateAddress + 64, next: 12},
		dagScalar(to.Intent{Operation: to.Push, Dst: 5}, to.Encoding{Form: to.PUSH50}, 6),
		{i: to.Intent{Operation: to.Call}, e: to.Encoding{Form: to.CALLE8}, taken: 9, next: 7},
		dagScalar(to.Intent{Operation: to.Pop, Dst: 5}, to.Encoding{Form: to.POP58}, 8),
		dagScalar(to.Intent{Operation: to.Return}, to.Encoding{Form: to.RETC3}, 12),
		imm(7, 0x1002, 10), imm(0, 158, 11),
		dagScalar(to.Intent{Operation: to.Syscall}, to.Encoding{Form: to.SYSCALL0F05}, 13),
		// Root's exit jumps over both physical callee bodies to the cut.
		dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 11}, to.Encoding{Form: to.MOVB8Imm32, REX: 0x41}, 15),
		dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 14),
		dagScalar(to.Intent{Operation: to.Return}, to.Encoding{Form: to.RETC3}, 15),
	}
}

func checkCallTLSPopulation(t testing.TB, seed uint64, raw []byte) {
	checkCallTLSRootPopulation(t, seed, raw, false)
}

func checkCallTLSRootPopulation(t testing.TB, seed uint64, raw []byte, region bool) {
	t.Helper()
	ops := callTLSOps()
	x := dagArrange(t, ops, seed)
	face := callTLSFace()
	initial := stateRawInitial(face, raw)
	initial.outcomes = [][4]uint32{{1, 2, 3, 4}, {5, 6, 7, 8}}
	end := len(ops) * 2
	if region {
		// Generate a distinct synthetic ELF entry, retaining the same independent
		// intent/oracle and the conditional region's actual selected start.
		data := append([]byte(nil), x.im.data...)
		binary.LittleEndian.PutUint64(data[24:], x.pcs[end])
		var err error
		x.im, err = NewImage(t.Context(), data)
		if err != nil {
			t.Fatal(err)
		}
		x.digest = sha256.Sum256(data)
	}
	checkRoot := func(q TransitionProposal) (TransitionCertificate, error) {
		if region {
			return CheckRegionTransition(t.Context(), x.im, x.pcs[0], face, q, TransitionLimits{})
		}
		return CheckTransition(t.Context(), x.im, face, q, TransitionLimits{})
	}
	p := callInventory(t, x, end)
	var proposed TransitionProposal
	var err error
	if region {
		proposed, err = ProposeRegionTransition(t.Context(), x.im, x.pcs[0], p.Cut, TransitionLimits{}, transitionTestOptions(p))
	} else {
		proposed, err = ProposeTransition(t.Context(), x.im, p.Cut, TransitionLimits{}, transitionTestOptions(p))
	}
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(proposed, p) { // Ordering is discovery-defined on both independently built inventories.
		stateSameContextInventory(t, proposed, p)
	}
	flat, err := checkRoot(p)
	if err != nil {
		t.Fatal(err)
	}
	callTLSAssert(t, flat, x, end, face, initial)
	// Split inside the first nested activation, then after both actual returns.
	var c TransitionCertificate
	for n, cut := range []int{0, 2, 18, 22, 4, 6, end} {
		q := callInventory(t, x, cut)
		var before TransitionBound
		if n != 0 {
			before = c.checked.bound
		}
		if n == 0 {
			c, err = checkRoot(q)
		} else {
			c, err = CheckTransitionContinuation(t.Context(), c, q)
		}
		if err != nil {
			t.Fatalf("split %d: %v", cut, err)
		}
		if n != 0 {
			stateInheritedInputs(t, before, c.checked.bound)
		}
		if c.checked.bound.ConditionalRegion != region || c.checked.bound.Entry != x.pcs[0] {
			t.Fatal("call/thread continuation changed root authority")
		}
		callTLSAssert(t, c, x, cut, face, initial)
	}
	assertCallTLSAlpha(t, flat, c)
}

// Splitting at a complete cut may reorder always-inactive occurrences in the
// topological inventory. Compare their relations by occurrence identity; each
// certificate separately passes the independent guard-filtered trace oracle.
func assertCallTLSAlpha(t testing.TB, a, b TransitionCertificate) {
	t.Helper()
	normalize := func(c TransitionCertificate) TransitionBound {
		x := lifecycleSnapshot(c.checked.bound)
		less := func(ac TransitionActivationID, ap uint64, bc TransitionActivationID, bp uint64) int {
			if ac < bc {
				return -1
			}
			if ac > bc {
				return 1
			}
			if ap < bp {
				return -1
			}
			if ap > bp {
				return 1
			}
			return 0
		}
		slices.SortFunc(x.Instructions, func(a, b GuardedInstruction) int { return less(a.Context, a.Start, b.Context, b.Start) })
		slices.SortFunc(x.ExcludedBoundaries, func(a, b ExcludedBoundary) int { return less(a.Context, a.PC, b.Context, b.PC) })
		return x
	}
	assertCutStateAlpha(t, normalize(a), normalize(b))
}

func stateSameContextInventory(t testing.TB, a, b TransitionProposal) {
	t.Helper()
	transitionInventoryMap(t, a, b)
}

func TestTransitionCallTLSCompositions(t *testing.T) {
	if err := quick.Check(func(seed uint64, raw [768]byte) bool { checkCallTLSPopulation(t, seed, raw[:]); return true }, &quick.Config{MaxCount: 24}); err != nil {
		t.Fatal(err)
	}
}

func FuzzTransitionCallTLSCompositions(f *testing.F) {
	for _, seed := range []uint64{0, 1, 7, 255, ^uint64(0)} {
		f.Add(seed, []byte{0, 255, 128, 1})
	}
	f.Fuzz(func(t *testing.T, seed uint64, raw []byte) { checkCallTLSPopulation(t, seed, raw) })
}

// Generate a bounded acyclic call tree before placement. Depth, repeated call
// sites, frame allocations and CPUID payloads vary independently; no checker
// graph or state supplies the generator's successors or reference answers.
func callTLSTree(depth, repeats int, selector uint64) []dagOp {
	var ops []dagOp
	add := func(i to.Intent, e to.Encoding) int {
		at := len(ops)
		ops = append(ops, dagScalar(i, e, at+1))
		return at
	}
	lea := add(to.Intent{Operation: to.LEARIP, Dst: 6}, to.Encoding{Form: to.LEA8D, REX: 0x48, DispBytes: 4})
	ops[lea].address = imageStateAddress + 72
	var calls []int
	for n := 0; n < repeats; n++ {
		calls = append(calls, add(to.Intent{Operation: to.Call}, to.Encoding{Form: to.CALLE8}))
	}
	add(to.Intent{Operation: to.StoreImmediate, FS: true, SignedDisp: -8, Immediate: 0x123}, to.Encoding{Form: to.MOVC7, REX: 0x48, SIB: true, DispBytes: 4})
	last := add(to.Intent{Operation: to.MoveImmediate32, Dst: 11}, to.Encoding{Form: to.MOVB8Imm32, REX: 0x41})
	for level := 0; level < depth; level++ {
		entry := len(ops)
		for _, at := range calls {
			ops[at].taken = entry
		}
		calls = nil
		add(to.Intent{Operation: to.Push, Dst: 5}, to.Encoding{Form: to.PUSH50})
		allocation := uint64(8 * ((selector >> uint(level*2)) % 4))
		add(to.Intent{Operation: to.Subtract, Dst: 4, Immediate: allocation}, to.Encoding{Form: to.SUB83, REX: 0x48})
		if level+1 < depth {
			for n := 0; n < 1+int((selector>>uint(level+8))&1); n++ {
				calls = append(calls, add(to.Intent{Operation: to.Call}, to.Encoding{Form: to.CALLE8}))
			}
		} else {
			add(to.Intent{Operation: to.MoveImmediate32, Dst: 0, Immediate: 158}, to.Encoding{Form: to.MOVB8Imm32})
			add(to.Intent{Operation: to.MoveImmediate32, Dst: 7, Immediate: 0x1002}, to.Encoding{Form: to.MOVB8Imm32})
			add(to.Intent{Operation: to.Syscall}, to.Encoding{Form: to.SYSCALL0F05})
			add(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2})
		}
		add(to.Intent{Operation: to.Add, Dst: 4, Immediate: allocation}, to.Encoding{Form: to.ADD83, REX: 0x48})
		add(to.Intent{Operation: to.Pop, Dst: 5}, to.Encoding{Form: to.POP58})
		add(to.Intent{Operation: to.Return}, to.Encoding{Form: to.RETC3})
	}
	ops[last].next = len(ops)
	return ops
}

func checkCallTLSTree(t testing.TB, shape, placement uint64, raw []byte) {
	t.Helper()
	ops := callTLSTree(1+int(shape%3), 1+int(shape/3%3), shape)
	x := dagArrange(t, ops, placement)
	f := callTLSFace()
	r := stateRawInitial(f, raw)
	end := 2 * len(ops)
	p := callInventory(t, x, end)
	c, err := CheckTransition(t.Context(), x.im, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	callTLSAssert(t, c, x, end, f, r)
	// The root's final store follows every return, so this cut is common even
	// when the same callee PC has many separately originated occurrences.
	cut := 2 * (2 + int(shape/3%3))
	q := callInventory(t, x, cut)
	root, err := CheckTransition(t.Context(), x.im, f, q, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	continued, err := CheckTransitionContinuation(t.Context(), root, p)
	if err != nil {
		t.Fatal(err)
	}
	stateInheritedInputs(t, root.checked.bound, continued.checked.bound)
	callTLSAssert(t, continued, x, end, f, r)
	assertCallTLSAlpha(t, c, continued)
}

func TestTransitionGeneratedCallTrees(t *testing.T) {
	if err := quick.Check(func(shape, placement uint64, raw [2048]byte) bool {
		checkCallTLSTree(t, shape, placement, raw[:])
		return true
	}, &quick.Config{MaxCount: 32}); err != nil {
		t.Fatal(err)
	}
}

func FuzzTransitionGeneratedCallTrees(f *testing.F) {
	for _, shape := range []uint64{0, 1, 2, 8, 0x300, 0xffff} {
		f.Add(shape, shape*17, []byte{0, 255, 128, 1})
	}
	f.Fuzz(func(t *testing.T, shape, placement uint64, raw []byte) { checkCallTLSTree(t, shape, placement, raw) })
}

func TestTransitionCallTLSAllCuts(t *testing.T) {
	ops := callTLSOps()
	x := dagArrange(t, ops, 37)
	f := callTLSFace()
	r := stateInitial(f, 31)
	end := 2 * len(ops)
	p := callInventory(t, x, end)
	flat, err := CheckTransition(t.Context(), x.im, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	var returns []int
	for j := 0; j != end; {
		if !seen[j] {
			seen[j] = true
			q := callInventory(t, x, j)
			root, err := CheckTransition(t.Context(), x.im, f, q, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			callTLSAssert(t, root, x, j, f, r)
			c, err := CheckTransitionContinuation(t.Context(), root, p)
			if err != nil {
				t.Fatal(err)
			}
			stateInheritedInputs(t, root.checked.bound, c.checked.bound)
			callTLSAssert(t, c, x, end, f, r)
			assertCallTLSAlpha(t, flat, c)
		}
		switch x.intents[j].Operation {
		case to.Call:
			returns = append(returns, j+1)
			j = x.edges[j][0]
		case to.Return:
			j = returns[len(returns)-1]
			returns = returns[:len(returns)-1]
		default:
			j = x.edges[j][0]
		}
	}
}

func callTLSDescriptorState(t testing.TB, d to.Descriptor, i to.Intent, raw []byte) {
	t.Helper()
	face := callTLSFace()
	face.Words = nil
	face.Regions = []RelativeRegion{{RelativeSpan{-16, 16}, true, true}}
	var ops []dagOp
	add := func(i to.Intent, e to.Encoding) { ops = append(ops, dagScalar(i, e, len(ops)+1)) }
	setupSyscall := func() {
		add(to.Intent{Operation: to.MoveImmediate32, Dst: 7, Immediate: 0x1002}, to.Encoding{Form: to.MOVB8Imm32})
		add(to.Intent{Operation: to.MoveImmediate32, Dst: 0, Immediate: 158}, to.Encoding{Form: to.MOVB8Imm32})
	}
	cut := -1
	switch {
	case i.FS:
		add(to.Intent{Operation: to.MoveRegister, Dst: 6, Src: 4}, to.Encoding{Form: to.MOV89, REX: 0x48})
		add(to.Intent{Operation: to.Subtract, Dst: 6, Immediate: uint64(i.SignedDisp)}, to.Encoding{Form: to.SUB81, REX: 0x48})
		setupSyscall()
		add(to.Intent{Operation: to.Syscall}, to.Encoding{Form: to.SYSCALL0F05})
		add(i, d.Encoding)
	case i.Operation == to.Syscall:
		setupSyscall()
		add(i, d.Encoding)
	case i.Operation == to.Push:
		add(i, d.Encoding)
	case i.Operation == to.Pop:
		add(to.Intent{Operation: to.Push, Dst: 4}, to.Encoding{Form: to.PUSH50})
		add(i, d.Encoding)
	default:
		call, ret := to.Intent{Operation: to.Call}, to.Intent{Operation: to.Return}
		ce, re := to.Encoding{Form: to.CALLE8}, to.Encoding{Form: to.RETC3}
		if i.Operation == to.Call {
			call, ce = i, d.Encoding
		} else {
			ret, re = i, d.Encoding
		}
		ops = []dagOp{{i: call, e: ce, taken: 2, next: 1}, dagScalar(to.Intent{Operation: to.MoveRegister, Dst: 0, Src: 0}, to.Encoding{Form: to.MOV89, REX: 0x48}, 3), dagScalar(ret, re, 3)}
		cut = 2
	}
	x := dagArrange(t, ops, 0)
	if cut < 0 {
		cut = 2 * len(ops)
	}
	p := callInventory(t, x, cut)
	initial := stateRawInitial(face, raw)
	c, err := CheckTransition(t.Context(), x.im, face, p, TransitionLimits{})
	if err != nil {
		t.Fatalf("call/TLS descriptor %+v / %+v: %v", i, d.Encoding, err)
	}
	callTLSAssert(t, c, x, cut, face, initial)
}
