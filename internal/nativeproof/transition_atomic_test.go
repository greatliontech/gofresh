package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"math/bits"
	"reflect"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
	"golang.org/x/arch/x86/x86asm"
)

func atomicDescriptorState(t testing.TB, d to.Descriptor, i to.Intent, raw []byte) {
	t.Helper()
	f := stateFace(16, 0)
	f.Regions, f.Words = nil, nil
	f.Conditions.Locked64 = Locked64Model
	var ops []dagOp
	rmw := i.Operation == to.LockedCompareExchange || i.Operation == to.LockedExchange || i.Operation == to.LockedExchangeAdd
	mem := rmw || i.Operation == to.SetMemory || i.Operation == to.CompareMemory || i.Operation == to.CompareFromMemory || i.Operation == to.CompareMemoryImmediate
	w := 8
	if i.Width != 0 {
		w = int(i.Width) / 8
	}
	if rmw {
		i.SignedDisp &= ^int64(7)
	}
	if mem && !i.RIP {
		if i.Base != 4 {
			p := to.Intent{Operation: to.MoveRegister, Dst: i.Base, Src: 4}
			ops = append(ops, dagScalar(p, stateEncoding(p, 0), 1))
		}
		f.Regions = []RelativeRegion{{Bytes: RelativeSpan{i.SignedDisp, i.SignedDisp + int64(w)}, Readable: true, Writable: true}}
	}
	op := dagScalar(i, d.Encoding, len(ops)+1)
	if i.RIP {
		op.address = imageStateAddress + 32
		f.ImageRegions = []Span{{imageStateAddress + 32, imageStateAddress + 40}}
	}
	ops = append(ops, op)
	x := dagArrange(t, ops, 0).stateLayout
	r := stateRawInitial(f, raw)
	r.loads = x.mappings
	c, err := CheckTransition(t.Context(), x.im, f, x.proposal(len(x.intents)), TransitionLimits{})
	if err != nil {
		t.Fatalf("atomic descriptor %+v: %v", d, err)
	}
	want := r.clone()
	for j, i := range x.intents {
		want.referenceExec(t, i, j, x.pcs[j]+uint64(len(x.encoded[j])))
	}
	stateAssert(t, c, x, len(x.intents), r, want, stateBindings(t, c, f, r))
}

func atomicLayout(t testing.TB, descriptors []to.Descriptor) (stateLayout, TransitionInterface) {
	t.Helper()
	ops := make([]dagOp, 0, len(descriptors))
	for j, d := range descriptors {
		ops = append(ops, dagScalar(d.Intent, d.Encoding, j+1))
	}
	x := dagArrange(t, ops, 0).stateLayout
	f := stateFace(16, 0)
	f.Conditions.Locked64 = Locked64Model
	return x, f
}

func atomicStateCuts(t testing.TB, x stateLayout, f TransitionInterface, initial stateReference) {
	t.Helper()
	initial.loads = x.mappings
	root, err := CheckTransition(t.Context(), x.im, f, x.proposal(0), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	values := stateBindings(t, root, f, initial)
	want := initial.clone()
	for j, i := range x.intents {
		want.referenceExec(t, i, j, x.pcs[j]+uint64(len(x.encoded[j])))
		before := root.checked.bound
		root, err = CheckTransitionContinuation(t.Context(), root, x.proposal(j+1))
		if err != nil {
			t.Fatal("atomic continuation", j, err)
		}
		stateInheritedInputs(t, before, root.checked.bound)
		stateAssert(t, root, x, j+1, initial, want, values)
	}
	direct, err := CheckTransition(t.Context(), x.im, f, x.proposal(len(x.intents)), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	stateAssert(t, direct, x, len(x.intents), initial, want, stateBindings(t, direct, f, initial))
	assertTransitionAlpha(t, direct, root)
}

func TestTransitionLocked64BothOutcomesAndBytes(t *testing.T) {
	ds := []to.Descriptor{
		{Intent: to.Intent{Operation: to.LockedCompareExchange, Base: 4, Src: 2}, Encoding: to.Encoding{Form: to.LOCKCMPXCHG0FB1, REX: 0x48, SIB: true}},
		{Intent: to.Intent{Operation: to.SetRegister, Width: 8, Dst: 1, Condition: 4}, Encoding: to.Encoding{Form: to.SETcc0F90}},
		{Intent: to.Intent{Operation: to.Test, Width: 8, Dst: 1, Src: 1}, Encoding: to.Encoding{Form: to.TEST84}},
		{Intent: to.Intent{Operation: to.CompareMemoryImmediate, Base: 4, Immediate: 42}, Encoding: to.Encoding{Form: to.CMP83, REX: 0x48, SIB: true}},
		{Intent: to.Intent{Operation: to.SetMemory, Width: 8, Base: 4, SignedDisp: 9, Condition: 5}, Encoding: to.Encoding{Form: to.SETcc0F90, SIB: true, DispBytes: 1}},
	}
	x, f := atomicLayout(t, ds)
	check := func(current, old, new, high uint64) bool {
		for _, equal := range []bool{false, true} {
			r := stateInitial(f, high)
			r.regs[0], r.regs[2], r.regs[1] = old, new, high
			if equal {
				r.regs[0] = current
			}
			r.words[0] = current
			for lane := 0; lane < 8; lane++ {
				r.memory[stateLocation{off: int64(lane)}] = stateByte{value: byte(current >> (8 * lane))}
			}
			atomicStateCuts(t, x, f, r)
		}
		return true
	}
	for _, v := range []uint64{0, 1, 15, 16, 127, 128, 255, 1<<63 - 1, 1 << 63, ^uint64(0)} {
		check(v, ^v, 42, ^uint64(0))
	}
	if err := quick.Check(check, &quick.Config{MaxCount: 32}); err != nil {
		t.Fatal(err)
	}
}

func TestTransferKernelIndependentArithmetic(t *testing.T) {
	b := br.NewBuilder(3)
	scope := br.NewScope()
	a, _ := b.Input(br.Bits(64), scope, 0)
	current, _ := b.Input(br.Bits(64), scope, 1)
	replacement, _ := b.Input(br.Bits(64), scope, 2)
	k, err := NewTransferKernel(t.Context(), RelationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := k.CompareExchange64(a, current, replacement)
	if err != nil {
		t.Fatal(err)
	}
	var conditions []br.Term
	ccs := []uint8{2, 3, 4, 5, 6, 7, 12, 13, 14, 15}
	ops := []x86asm.Op{x86asm.SETB, x86asm.SETAE, x86asm.SETE, x86asm.SETNE, x86asm.SETBE, x86asm.SETA, x86asm.SETL, x86asm.SETGE, x86asm.SETLE, x86asm.SETG}
	for _, op := range ops {
		v, err := k.SetCondition(op, r.Predicates)
		if err != nil {
			t.Fatal(err)
		}
		conditions = append(conditions, v)
	}
	check := func(old, now, new uint64) bool {
		values := map[br.Term]uint64{a: old, current: now, replacement: new}
		z := old - now
		flags := [6]bool{old < now, z == 0, (old^now)&(old^z)&(1<<63) != 0, z>>63 != 0, (old^now^z)&16 != 0, bits.OnesCount8(byte(z))%2 == 0}
		for j, f := range []TransitionFlag{r.Flags.CF, r.Flags.ZF, r.Flags.OF, r.Flags.SF, r.Flags.AF, r.Flags.PF} {
			if !f.Defined || f.Preserved || (stateEval(t, f.Value, values) != 0) != flags[j] {
				t.Fatal("CMPXCHG flag differs", j, old, now)
			}
		}
		wantMemory, wantAccumulator := now, now
		if old == now {
			wantMemory, wantAccumulator = new, old
		}
		if stateEval(t, r.Memory, values) != wantMemory || stateEval(t, r.Accumulator, values) != wantAccumulator {
			t.Fatal("CMPXCHG arm differs")
		}
		for j, v := range conditions {
			if (stateEval(t, v, values) != 0) != dagCondition(t, ccs[j], flags) || stateEval(t, v, values) > 1 {
				t.Fatal("SET predicate differs")
			}
		}
		return true
	}
	for _, old := range []uint64{0, 1, 15, 16, 127, 128, 1<<63 - 1, 1 << 63, ^uint64(0)} {
		for _, now := range []uint64{0, old, ^old, old + 1} {
			check(old, now, 17)
		}
	}
	if err := quick.Check(check, &quick.Config{MaxCount: 128}); err != nil {
		t.Fatal(err)
	}
}

func TestTransferKernelRefusesMissingAndExhaustedInputs(t *testing.T) {
	b := br.NewBuilder(8)
	word, _ := b.Const(br.Bits(64), 1)
	narrow, _ := b.Const(br.Bits(8), 1)
	truth, _ := b.Const(br.Bool(), 1)
	newKernel := func() *TransferKernel {
		k, err := NewTransferKernel(t.Context(), RelationLimits{})
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	for _, inputs := range [][3]br.Term{{word, word, narrow}, {word, narrow, word}, {narrow, word, word}, {word, br.Term{}, word}, {truth, word, word}} {
		r, err := newKernel().CompareExchange64(inputs[0], inputs[1], inputs[2])
		if err == nil || r != (CompareExchangeResult{}) {
			t.Fatal("invalid typed RMW acquired result")
		}
	}
	if _, err := newKernel().SetCondition(x86asm.SETE, TransitionPredicates{}); err == nil {
		t.Fatal("unbound flag")
	}
	if _, err := newKernel().SetCondition(x86asm.JE, TransitionPredicates{ZF: truth}); err == nil {
		t.Fatal("branch accepted as SET")
	}
	if _, err := newKernel().Compare(word, narrow); err == nil {
		t.Fatal("mixed compare widths")
	}
	ctx, cancel := context.WithCancel(t.Context())
	k, err := NewTransferKernel(ctx, RelationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if r, err := k.CompareExchange64(word, word, word); !errors.Is(err, context.Canceled) || r != (CompareExchangeResult{}) {
		t.Fatal("cancelled kernel result", r, err)
	}
	limited, err := NewTransferKernel(t.Context(), RelationLimits{Work: 10})
	if err != nil {
		t.Fatal(err)
	}
	if r, err := limited.CompareExchange64(word, word, word); err == nil || r != (CompareExchangeResult{}) {
		t.Fatal("exhausted kernel result")
	}
	if _, err := NewTransferKernel(nil, RelationLimits{}); err == nil {
		t.Fatal("missing context")
	}
}

func TestTransitionLocked64PermissionsModelAndAlignment(t *testing.T) {
	im := image(t, hexBytes(t, "f0480fb114240f94c184c9c3"))
	choices := []TransitionExpansion{{PC: testEntry}, {PC: testEntry + 6}, {PC: testEntry + 9}}
	p, err := ProposeTransition(t.Context(), im, testEntry+11, TransitionLimits{}, choices...)
	if err != nil {
		t.Fatal(err)
	}
	f := stateFace(16, 0)
	f.Conditions.Locked64 = Locked64Model
	for _, mode := range []string{"good", "missing", "unknown", "readonly", "writeonly", "unaligned", "varying-alignment", "short", "expansion", "wrong-context"} {
		t.Run(mode, func(t *testing.T) {
			face := cloneTransitionInterface(f)
			q := p
			q.Expansions = append([]TransitionExpansion(nil), p.Expansions...)
			face.Words = nil
			face.Regions = []RelativeRegion{{RelativeSpan{0, 8}, true, true}}
			switch mode {
			case "missing":
				face.Conditions.Locked64 = ""
			case "unknown":
				face.Conditions.Locked64 = "unknown"
			case "readonly":
				face.Regions[0].Writable = false
			case "writeonly":
				face.Regions[0].Readable = false
			case "unaligned":
				face.Origin.Residue = 1
			case "varying-alignment":
				face.Origin.Modulus = 4
			case "short":
				face.Regions[0].Bytes.End = 7
			case "expansion":
				q.Expansions = q.Expansions[1:]
			case "wrong-context":
				q.Expansions[0].Context = "/foreign"
			}
			c, err := CheckTransition(t.Context(), im, face, q, TransitionLimits{})
			if mode == "good" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			transitionRefused(t, c, err)
		})
	}
	// A predecessor without the optional premise cannot acquire it by continuing.
	rootP, err := ProposeTransition(t.Context(), im, testEntry, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	absent := f
	absent.Conditions.Locked64 = ""
	root, err := CheckTransition(t.Context(), im, absent, rootP, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransitionContinuation(t.Context(), root, p)
	transitionRefused(t, c, err)
	// Loading current then incrementing RAX forces inequality even at modular
	// wrap. Failure still needs write permission, despite leaving bytes equal.
	failedImage := image(t, hexBytes(t, "488b04244883c001f0480fb11424c3"))
	failedProposal, err := ProposeTransition(t.Context(), failedImage, testEntry+14, TransitionLimits{}, TransitionExpansion{PC: testEntry + 8})
	if err != nil {
		t.Fatal(err)
	}
	readonly := f
	readonly.Words = nil
	readonly.Regions = []RelativeRegion{{Bytes: RelativeSpan{0, 8}, Readable: true}}
	c, err = CheckTransition(t.Context(), failedImage, readonly, failedProposal, TransitionLimits{})
	transitionRefused(t, c, err)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.PC != testEntry+8 || refusal.Premise != "transition-permission" {
		t.Fatal("failed writeback refused at wrong premise", err)
	}
}

func TestTransitionAtomicInspectionOwnershipAndCancellation(t *testing.T) {
	im := image(t, hexBytes(t, "f0480fb114240f94c184c9c3"))
	f := stateFace(16, 0)
	f.Conditions.Locked64 = Locked64Model
	p, err := ProposeTransition(t.Context(), im, testEntry+9, TransitionLimits{}, TransitionExpansion{PC: testEntry}, TransitionExpansion{PC: testEntry + 6})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := c.Bound()
	i, err := c.InstructionAt(t.Context(), testEntry+6, "")
	if err != nil || i.Op != x86asm.SETE || i.Args[0] != x86asm.CL {
		t.Fatal(i, err)
	}
	if _, err := c.InstructionAt(t.Context(), testEntry+9, ""); err == nil {
		t.Fatal("cut relabeled executed")
	}
	if _, err := c.InstructionAt(t.Context(), testEntry, "/foreign"); err == nil {
		t.Fatal("foreign occurrence")
	}
	if _, err := c.RegisterValue(t.Context(), x86asm.X0); err == nil {
		t.Fatal("vector alias accepted")
	}
	v, err := c.RegisterValue(t.Context(), x86asm.CL)
	if err != nil || v.Sort() != br.Bits(8) {
		t.Fatal(err)
	}
	foreign := image(t, hexBytes(t, "f0480fb114240f94c184c9c3"))
	if _, ok := c.BoundFor(foreign); ok {
		t.Fatal("foreign equal-byte owner")
	}
	count := &imageCallbackContext{Context: t.Context()}
	if _, err := CheckTransition(count, im, f, p, TransitionLimits{}); err != nil {
		t.Fatal(err)
	}
	for at := 1; at <= count.calls; at++ {
		ctx, cancel := context.WithCancel(t.Context())
		callback := &imageCallbackContext{Context: ctx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		failed, err := CheckTransition(callback, im, f, p, TransitionLimits{})
		cancel()
		if !errors.Is(err, context.Canceled) || failed.checked != nil {
			t.Fatal("cancellation leaked result", at, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.InstructionAt(ctx, testEntry, ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := c.RegisterValue(ctx, x86asm.CL); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, limits := range []TransitionLimits{{RelationLimits: RelationLimits{Work: 10}}, {RelationLimits: RelationLimits{Nodes: 20}}, {RelationLimits: RelationLimits{Depth: 2}}, {LiveStateBytes: 100}} {
		failed, err := CheckTransition(t.Context(), im, f, p, limits)
		transitionRefused(t, failed, err)
	}
	projection, _ := c.Bound()
	projection.Accesses[0].Value = br.Term{}
	projection.PrimitiveEffects[0] = LockedCompareExchange64Effect{}
	after, _ := c.Bound()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("projection/sibling changed checked state")
	}
}

func TestTransitionDeferredAtomicBoundaries(t *testing.T) {
	for _, code := range []string{"f0480fb11424", "0f94c1", "0f940424"} {
		boundary := hexBytes(t, code)
		// Zero EAX then TEST makes the opaque arm impossible. Its undiscovered
		// successor loops forever, so optional expansion cannot be error fallback.
		raw := append(hexBytes(t, "b80000000085c074"), byte(len(boundary)+2))
		raw = append(raw, boundary...)
		raw = append(raw, 0xeb, 0xfe, 0xc3)
		im := image(t, raw)
		cut := testEntry + uint64(len(raw)-1)
		p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		c, err := CheckTransition(t.Context(), im, stateFace(16, 0), p, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if len(c.checked.bound.ExcludedBoundaries) != 1 || len(c.checked.bound.PrimitiveEffects) != 0 {
			t.Fatal("dead boundary executed")
		}
		if _, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{}, TransitionExpansion{PC: testEntry + 9}); err == nil {
			t.Fatal("expanded cycle accepted")
		}
	}
}

func TestTransitionAtomicRawEncodingControls(t *testing.T) {
	forms := []string{"f0480fb111", "f04d0fb14df8", "0f94c4", "400f94c4", "0f95442409", "84e1", "f6c180", "a8ff", "48833df8ffffff2a", "48391424", "483b1424"}
	prefixes := []byte{0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67}
	for p := byte(0x40); p <= 0x4f; p++ {
		prefixes = append(prefixes, p)
	}
	for _, form := range forms {
		code := hexBytes(t, form)
		compareExecutedEncoding(t, code)
		for _, prefix := range prefixes {
			compareExecutedEncoding(t, append([]byte{prefix}, code...))
		}
		for j := 1; j < len(code); j++ {
			compareExecutedEncoding(t, code[:j])
		}
	}
	for _, form := range []string{"480fb111", "f00fb111", "f066480fb111", "f0f0480fb111", "f0480fb1d1", "f0480fb1042500000000", "f04b0fb11424", "f2480fb111", "f0480fb011", "0f94c8", "0f90c0", "0f98c0", "660f94c1", "f00f94c1", "6684c1", "f6c9ff", "0f94042500000000"} {
		compareExecutedEncoding(t, hexBytes(t, form))
	}
}

func TestTransitionReadOnlyComparisonValues(t *testing.T) {
	x, f := atomicLayout(t, []to.Descriptor{
		{Intent: to.Intent{Operation: to.CompareMemoryImmediate, Base: 4, Immediate: 42}, Encoding: to.Encoding{Form: to.CMP83, REX: 0x48, SIB: true}},
		{Intent: to.Intent{Operation: to.CompareFromMemory, Base: 4, Dst: 2}, Encoding: to.Encoding{Form: to.CMP3B, REX: 0x48, SIB: true}},
	})
	f.Words = nil
	f.Regions = []RelativeRegion{{RelativeSpan{0, 8}, true, false}}
	atomicStateCuts(t, x, f, stateInitial(f, 721))
}

func TestTransitionAtomicEffectsSurviveOverwrites(t *testing.T) {
	ds := []to.Descriptor{
		{Intent: to.Intent{Operation: to.Add, Dst: 2, Immediate: 7}, Encoding: to.Encoding{Form: to.ADD83, REX: 0x48}},
		{Intent: to.Intent{Operation: to.LockedCompareExchange, Base: 4, Src: 2}, Encoding: to.Encoding{Form: to.LOCKCMPXCHG0FB1, REX: 0x48, SIB: true}},
		{Intent: to.Intent{Operation: to.StoreImmediate, Base: 4, Immediate: 0}, Encoding: to.Encoding{Form: to.MOVC7, REX: 0x48, SIB: true}},
		{Intent: to.Intent{Operation: to.MoveImmediate32, Dst: 0}, Encoding: to.Encoding{Form: to.MOVB8Imm32}},
		{Intent: to.Intent{Operation: to.MoveImmediate32, Dst: 2}, Encoding: to.Encoding{Form: to.MOVB8Imm32}},
		{Intent: to.Intent{Operation: to.Test, Width: 32, Dst: 0, Src: 0}, Encoding: to.Encoding{Form: to.TEST85}},
		{Intent: to.Intent{Operation: to.NoOp}, Encoding: to.Encoding{Form: to.NOP90}},
	}
	x, f := atomicLayout(t, ds)
	for _, seed := range []uint64{0, 17, ^uint64(0)} {
		atomicStateCuts(t, x, f, stateInitial(f, seed))
	}
}

func TestTransitionAtomicActivationAndCumulativeResources(t *testing.T) {
	for _, tc := range []struct {
		name, rmw string
		op        x86asm.Op
	}{
		{"cmpxchg", "f0480fb1542408", x86asm.CMPXCHG},
		{"xchg", "4887542408", x86asm.XCHG},
		{"xadd", "f0480fc1542408", x86asm.XADD},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Two calls enter the same body; its data lies above the actual CALL word.
			code := hexBytes(t, "e806000000e801000000c3"+tc.rmw+"0f94442410c3")
			im := image(t, code)
			end := testEntry + 10
			setPC := testEntry + 11 + uint64(len(hexBytes(t, tc.rmw)))
			ctx1, ctx2 := callContext("", testEntry), callContext("", testEntry+5)
			if ctx1 == "" || ctx2 == "" || ctx1 == ctx2 {
				t.Fatal("fixture lacks distinct callee activations")
			}
			choices := []TransitionExpansion{{PC: testEntry}, {PC: testEntry + 5}, {PC: testEntry + 11, Context: ctx1}, {PC: setPC, Context: ctx1}, {PC: testEntry + 11, Context: ctx2}, {PC: setPC, Context: ctx2}}
			f := stateFace(16, 0)
			f.Conditions.Locked64 = Locked64Model
			p, err := ProposeTransition(t.Context(), im, end, TransitionLimits{}, choices...)
			if err != nil {
				t.Fatal(err)
			}
			first, err := ProposeTransition(t.Context(), im, testEntry+5, TransitionLimits{}, choices[0], choices[2], choices[3])
			if err != nil {
				t.Fatal(err)
			}
			prior, err := CheckTransition(t.Context(), im, f, first, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			c, err := CheckTransitionContinuation(t.Context(), prior, p)
			if err != nil {
				t.Fatal(err)
			}
			direct, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			assertTransitionAlpha(t, direct, c)
			b := c.checked.bound
			if len(b.PrimitiveEffects) != 2 || len(b.Frames) != 0 || len(b.Accesses) != 10 {
				t.Fatal("incomplete repeated activation effects", len(b.Accesses))
			}
			for j, context := range []string{ctx1, ctx2} {
				var pc uint64
				var activation string
				var read, write int
				switch tc.op {
				case x86asm.CMPXCHG:
					e, ok := b.PrimitiveEffects[j].(LockedCompareExchange64Effect)
					if !ok {
						t.Fatal("wrong CMPXCHG primitive type")
					}
					pc, activation, read, write = e.PC, e.Context, e.ReadAccess, e.WriteAccess
				case x86asm.XCHG:
					e, ok := b.PrimitiveEffects[j].(LockedExchange64Effect)
					if !ok {
						t.Fatal("wrong XCHG primitive type")
					}
					pc, activation, read, write = e.PC, e.Context, e.ReadAccess, e.WriteAccess
				case x86asm.XADD:
					e, ok := b.PrimitiveEffects[j].(LockedExchangeAdd64Effect)
					if !ok {
						t.Fatal("wrong XADD primitive type")
					}
					pc, activation, read, write = e.PC, e.Context, e.ReadAccess, e.WriteAccess
				}
				if activation != context || pc != testEntry+11 || read != j*5+1 || write != j*5+2 {
					t.Fatal("collapsed dynamic RMW", b.PrimitiveEffects[j])
				}
				for _, index := range []int{read, write} {
					if b.Accesses[index].PC != pc || b.Accesses[index].Context != context {
						t.Fatal("RMW access borrowed another activation", index)
					}
				}
				i, err := c.InstructionAt(t.Context(), pc, context)
				if err != nil || i.Op != tc.op {
					t.Fatal(i, err)
				}
				for _, wrong := range []string{"", "/foreign"} {
					_, err := c.InstructionAt(t.Context(), pc, wrong)
					var refusal *Refusal
					if !errors.As(err, &refusal) || refusal.PC != pc || refusal.Premise != "transition-inspection" {
						t.Fatal("RMW context was not the deciding refusal", wrong, err)
					}
				}
			}
			stateInheritedInputs(t, prior.checked.bound, b)
			prefix := prior.checked.bound
			if !reflect.DeepEqual(prefix.Accesses, b.Accesses[:len(prefix.Accesses)]) || !reflect.DeepEqual(prefix.Instructions, b.Instructions[:len(prefix.Instructions)]) {
				t.Fatal("continuation changed the first activation's access/instruction prefix")
			}
			// The exact prefix fits an allowance smaller than the whole derivation. A
			// continuation must inherit it rather than resetting it at the second CALL.
			limited, err := CheckTransition(t.Context(), im, f, first, TransitionLimits{RelationLimits: RelationLimits{Work: prior.checked.work + 10}})
			if err != nil {
				t.Fatal(err)
			}
			failed, err := CheckTransitionContinuation(t.Context(), limited, p)
			transitionRefused(t, failed, err)
			for _, choice := range []TransitionExpansion{{PC: testEntry + 11}, {PC: testEntry + 11, Context: "/foreign"}, {PC: setPC, Context: "/foreign"}, {PC: testEntry + 5, Context: ctx1}} {
				q := p
				q.Expansions = append(append([]TransitionExpansion(nil), p.Expansions...), choice)
				failed, err := CheckTransitionContinuation(t.Context(), prior, q)
				transitionRefused(t, failed, err)
				var refusal *Refusal
				if !errors.As(err, &refusal) || refusal.PC != choice.PC || refusal.Premise != "transition-expansion" {
					t.Fatal("wrong-context choice was not the deciding refusal", choice, err)
				}
			}
		})
	}
}

func TestTransitionExchangePreservesUndefinedFlags(t *testing.T) {
	for _, producer := range []struct {
		name, code string
		clear      bool
	}{
		{"byte-test", "84c0", false},
		{"self-xor", "31c0", true},
	} {
		for _, exchange := range []string{"48871424", "f048871424"} {
			t.Run(producer.name+"/"+exchange, func(t *testing.T) {
				prefix := hexBytes(t, producer.code)
				rmw := hexBytes(t, exchange)
				code := append(append(prefix, rmw...), 0xc3)
				im := image(t, code)
				at := testEntry + uint64(len(prefix))
				cut := at + uint64(len(rmw))
				f := stateFace(16, 0)
				f.Conditions.Locked64 = Locked64Model
				first, err := ProposeTransition(t.Context(), im, at, TransitionLimits{}, TransitionExpansion{PC: testEntry})
				if err != nil {
					t.Fatal(err)
				}
				prior, err := CheckTransition(t.Context(), im, f, first, TransitionLimits{})
				if err != nil {
					t.Fatal(err)
				}
				before := prior.checked.bound.Flags
				if before.AF != (TransitionFlag{}) {
					t.Fatal("producer did not establish undefined AF", before.AF)
				}
				p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{}, TransitionExpansion{PC: testEntry}, TransitionExpansion{PC: at})
				if err != nil {
					t.Fatal(err)
				}
				next, err := CheckTransitionContinuation(t.Context(), prior, p)
				if err != nil {
					t.Fatal(err)
				}
				if next.checked.bound.Flags != before || next.checked.flags != prior.checked.flags {
					t.Fatal("XCHG changed flag definedness, preservation, value identity or private predicates")
				}
				stateInheritedInputs(t, prior.checked.bound, next.checked.bound)
				direct, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
				if err != nil {
					t.Fatal(err)
				}
				assertTransitionAlpha(t, direct, next)
				flags := func(f TransitionFlags) []TransitionFlag { return []TransitionFlag{f.CF, f.ZF, f.OF, f.SF, f.AF, f.PF} }
				for _, c := range []TransitionCertificate{prior, next, direct} {
					for j, flag := range flags(c.checked.bound.Flags) {
						original := flags(before)[j]
						if flag.Defined != original.Defined || flag.Preserved != original.Preserved || flag.Value.Valid() != original.Value.Valid() {
							t.Fatal("XCHG changed public flag status", j)
						}
						if j != 4 && (!flag.Defined || flag.Preserved || !flag.Value.Valid()) {
							t.Fatal("missing producer flag relation", j)
						}
					}
					for _, input := range []uint64{0, 1, 127, 128, 255, 256, ^uint64(0)} {
						result := byte(input)
						if producer.clear {
							result = 0
						}
						want := [6]bool{false, result == 0, false, result&128 != 0, false, bits.OnesCount8(result)%2 == 0}
						values := map[br.Term]uint64{c.checked.bound.InitialRegisters[RAX]: input}
						for j, flag := range flags(c.checked.bound.Flags) {
							if j != 4 && (stateEval(t, flag.Value, values) != 0) != want[j] {
								t.Fatal("XCHG changed a defined flag value", j, input)
							}
						}
						for j, predicate := range c.checked.flags {
							if !predicate.Valid() || predicate.Sort() != br.Bool() || (stateEval(t, predicate, values) != 0) != [3]bool{want[0], want[1], want[3] != want[2]}[j] {
								t.Fatal("XCHG changed private predicate", j, input)
							}
						}
					}
				}
			})
		}
	}
}

func FuzzTransitionAtomicValues(f *testing.F) {
	for _, v := range []uint64{0, 1, 15, 16, 127, 128, 255, 1<<63 - 1, 1 << 63, ^uint64(0)} {
		f.Add(v, v, ^v, uint8(0), uint8(4), []byte{})
		f.Add(v, ^v, v, uint8(1), uint8(15), []byte{255, 128, 17, 0})
	}
	for phase := uint8(0); phase < 16; phase++ {
		f.Add(uint64(42), uint64(42), uint64(99), phase<<4|1, uint8(4), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	}
	for kind := uint8(1); kind <= 2; kind++ {
		for _, v := range []uint64{0, 15, 1<<63 - 1, 1 << 63, ^uint64(0)} {
			f.Add(v, v, ^v, uint8(0), kind<<6|4, []byte{255, 128, 17, 0})
		}
	}
	for _, v := range []uint64{15, 1<<63 - 1, ^uint64(0)} {
		f.Add(v, uint64(0), uint64(1), uint8(0), uint8(2<<6|4), []byte{})
	}
	f.Fuzz(func(t *testing.T, current, old, replacement uint64, alias, condition uint8, responses []byte) {
		atomicPermissionProperty(t, condition>>6, alias, condition, byte(current), byte(old), int8(replacement))
		ccs := []uint8{2, 3, 4, 5, 6, 7, 12, 13, 14, 15}
		cc := ccs[int(condition)%len(ccs)]
		dst := alias % 16
		rex := byte(0x40)
		if dst >= 8 {
			rex |= 1
		}
		// High selector bits choose independent query positions and complete result
		// overwrites. The separate response bytes cover the full outcome product,
		// not values obtained from the native checker. All cuts are exercised.
		phase := alias >> 4
		query := to.Descriptor{Intent: to.Intent{Operation: to.CPUID}, Encoding: to.Encoding{Form: to.CPUID0FA2}}
		var program []to.Descriptor
		if phase&1 != 0 {
			program = append(program, query)
		}
		rmwKind := int(condition>>6) % 3
		program = append(program, to.Descriptor{Intent: to.Intent{Operation: []to.Operation{to.LockedCompareExchange, to.LockedExchange, to.LockedExchangeAdd}[rmwKind], Base: 4, Src: 2}, Encoding: to.Encoding{Form: []to.Form{to.LOCKCMPXCHG0FB1, to.XCHG87, to.LOCKXADD0FC1}[rmwKind], REX: 0x48, SIB: true}})
		if phase&2 != 0 {
			program = append(program, query)
		}
		if phase&8 != 0 {
			for _, reg := range []uint8{0, 1, 2, 3} {
				program = append(program, to.Descriptor{Intent: to.Intent{Operation: to.MoveImmediate32, Dst: reg}, Encoding: to.Encoding{Form: to.MOVB8Imm32}})
			}
			program = append(program, to.Descriptor{Intent: to.Intent{Operation: to.StoreImmediate, Base: 4}, Encoding: to.Encoding{Form: to.MOVC7, REX: 0x48, SIB: true}})
		}
		program = append(program, []to.Descriptor{
			{Intent: to.Intent{Operation: to.SetRegister, Width: 8, Dst: dst, Condition: cc}, Encoding: to.Encoding{Form: to.SETcc0F90, REX: rex}},
			{Intent: to.Intent{Operation: to.TestImmediate, Width: 8, Dst: dst, Immediate: 255}, Encoding: to.Encoding{Form: to.TESTF6, REX: rex}},
		}...)
		if phase&4 != 0 {
			program = append(program, query)
		}
		x, face := atomicLayout(t, program)
		face.Conditions.CPUID = CPUIDModel
		r := stateInitial(face, old)
		for len(responses) > 0 {
			var raw [16]byte
			n := copy(raw[:], responses)
			responses = responses[n:]
			var outcome [4]uint32
			for j := range outcome {
				outcome[j] = binary.LittleEndian.Uint32(raw[j*4:])
			}
			r.outcomes = append(r.outcomes, outcome)
		}
		r.regs[0], r.regs[2] = old, replacement
		r.words[0] = current
		for lane := 0; lane < 8; lane++ {
			r.memory[stateLocation{off: int64(lane)}] = stateByte{value: byte(current >> (8 * lane))}
		}
		atomicStateCuts(t, x, face, r)
	})
}
