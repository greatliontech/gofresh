package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

func deadDirectCall(t testing.TB, selector uint8, delta int32, live bool) (*Image, TransitionInterface, TransitionProposal) {
	t.Helper()
	code := make([]byte, 64)
	for j := range code {
		code[j] = 0xcc
	}
	// Load independently initialized zero-fill, compare, and bypass the CALL.
	copy(code, []byte{0x48, 0x8b, 0x05, 0, 0, 0, 0, 0x48, 0x83, 0xf8, 0, 0x74, 5, 0xe8, 0, 0, 0, 0, 0x0f, 0x0b})
	if live {
		code[11] = 0x75
	}
	binary.LittleEndian.PutUint32(code[3:], uint32(imageStateAddress+64-testEntry-7))
	target := int64(testEntry) + 32
	switch selector % 4 {
	case 0:
		target = int64(testEntry) + 0x100000 + int64(delta&0xffff)
	case 1:
		copy(code[32:], []byte{0xeb, 0xfe})
	case 2:
		copy(code[32:], []byte{0x0f, 0x0b})
	case 3:
		for j := 32; j < 48; j++ {
			code[j] = 0x66
		}
	}
	binary.LittleEndian.PutUint32(code[14:], uint32(target-int64(testEntry+18)))
	im, err := NewImage(t.Context(), transitionImageELF(t, code, imageStateLoads()))
	if err != nil {
		t.Fatal(err)
	}
	f := callTLSFace()
	f.Conditions.Syscall = ""
	f.Conditions.UserAddressBits = 0
	f.Initialization, err = CheckImageInitialization(t.Context(), im, StaticELFInitialization)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ProposeTransition(t.Context(), im, testEntry+18, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return im, f, p
}

func TestTransitionDeadDirectCallPopulation(t *testing.T) {
	if err := quick.Check(func(selector uint8, delta int32) bool {
		im, f, p := deadDirectCall(t, selector, delta, false)
		c, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		b := c.checked.bound
		if len(b.ExcludedBoundaries) != 1 || b.ExcludedBoundaries[0].PC != testEntry+13 || len(b.Accesses) != 1 || b.Accesses[0].Kind != FrameRead || len(b.Frames) != 0 {
			t.Fatal("excluded CALL fabricated an effect")
		}
		live, lf, lp := deadDirectCall(t, selector, delta, true)
		bad, err := CheckTransition(t.Context(), live, lf, lp, TransitionLimits{})
		transitionRefused(t, bad, err)
		// Explicit expansion never turns a bad target into a normal-return premise.
		expanded, err := ProposeTransition(t.Context(), live, lp.Cut, TransitionLimits{}, TransitionOptions{Expansions: []TransitionExpansion{{PC: testEntry + 13}}})
		if err == nil {
			bad, err = CheckTransition(t.Context(), live, lf, expanded, TransitionLimits{})
			transitionRefused(t, bad, err)
		}
		return true
	}, &quick.Config{MaxCount: 64}); err != nil {
		t.Fatal(err)
	}
}

func syscallLayout(t testing.TB, base uint64, unknown bool) (dagLayout, TransitionInterface, int) {
	t.Helper()
	f := callTLSFace()
	ops := []dagOp{
		dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 0, Immediate: 158}, to.Encoding{Form: to.MOVB8Imm32}, 1),
		dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 7, Immediate: 0x1002}, to.Encoding{Form: to.MOVB8Imm32}, 2),
		dagScalar(to.Intent{Operation: to.MoveImmediate, Dst: 6, Immediate: base}, to.Encoding{Form: to.MOVB8Imm64, REX: 0x48}, 3),
		dagScalar(to.Intent{Operation: to.Syscall}, to.Encoding{Form: to.SYSCALL0F05}, 4),
	}
	if unknown {
		ops[2] = dagScalar(to.Intent{Operation: to.MoveRegister, Dst: 6, Src: 3}, to.Encoding{Form: to.MOV89, REX: 0x48}, 3)
	}
	return dagArrange(t, ops, base), f, 8
}

func TestTransitionSyscallOutcomePopulation(t *testing.T) {
	for _, bits := range []int{48, 57} {
		ceiling := uint64(1)<<(bits-1) - 4096
		for _, base := range []uint64{0, 1, 0x1d09c88, ceiling - 1, ceiling, ceiling + 1, ^uint64(0)} {
			for _, unknown := range []bool{false, true} {
				x, f, end := syscallLayout(t, base, unknown)
				f.Conditions.UserAddressBits = bits
				p := callInventory(t, x, end)
				c, err := CheckTransition(t.Context(), x.im, f, p, TransitionLimits{})
				if err != nil {
					t.Fatal(err)
				}
				for flags := 0; flags < 8; flags++ {
					r := stateInitial(f, base+uint64(flags))
					r.regs[3] = base
					r.flags = [6]bool{flags&1 != 0, flags&2 != 0, false, flags&4 != 0, true, false}
					callTLSAssert(t, c, x, end, f, r)
				}
			}
		}
	}
	// A broad scalar argument really retains both outcomes, rather than a
	// success-only range inferred from the selected artifact's convenient base.
	x, f, end := syscallLayout(t, 0, true)
	p := callInventory(t, x, end)
	for _, change := range []func(*TransitionInterface){func(f *TransitionInterface) { f.Conditions.Syscall = ""; f.Conditions.UserAddressBits = 0 }, func(f *TransitionInterface) { f.Conditions.Syscall = "x32" }, func(f *TransitionInterface) { f.Conditions.UserAddressBits = 32 }, func(f *TransitionInterface) { f.Conditions.IsolatedExecution = false }} {
		g := f
		change(&g)
		c, err := CheckTransition(t.Context(), x.im, g, p, TransitionLimits{})
		transitionRefused(t, c, err)
	}
}

func TestTransitionCallReturnControls(t *testing.T) {
	for _, overwrite := range []uint64{0, 1, 0x401000, ^uint64(0)} {
		ops := []dagOp{
			{i: to.Intent{Operation: to.Call}, e: to.Encoding{Form: to.CALLE8}, taken: 2, next: 1},
			dagScalar(to.Intent{Operation: to.MoveRegister, Dst: 0, Src: 0}, to.Encoding{Form: to.MOV89, REX: 0x48}, 4),
			dagScalar(to.Intent{Operation: to.StoreImmediate, Base: 4, Immediate: overwrite, Width: 8}, to.Encoding{Form: to.MOVC6, SIB: true}, 3),
			dagScalar(to.Intent{Operation: to.Return}, to.Encoding{Form: to.RETC3}, 4),
		}
		ops[2].i.Immediate &= 255
		x := dagArrange(t, ops, overwrite)
		f := callTLSFace()
		p := callInventory(t, x, 2)
		// Set a byte different from the actual return word, independent of the
		// checker, while preserving every other byte and the stack relation.
		ops[2].i.Immediate = uint64(byte(x.pcs[1]) ^ 255)
		x = dagArrange(t, ops, overwrite)
		p = callInventory(t, x, 2)
		c, err := CheckTransition(t.Context(), x.im, f, p, TransitionLimits{})
		transitionRefused(t, c, err)
		var failure *Refusal
		if !errors.As(err, &failure) || failure.Premise != "transition-return" || len(failure.Path) < 2 || failure.Path[0] != x.pcs[0] || failure.PC != x.pcs[6] {
			t.Fatal("return refusal lost its actual activation path", err)
		}
	}
	x := dagArrange(t, callTLSOps(), 17)
	f := callTLSFace()
	p := callInventory(t, x, 30)
	for _, regions := range [][]RelativeRegion{nil, {{RelativeSpan{-256, 64}, true, false}}, {{RelativeSpan{-256, 64}, false, true}}, {{RelativeSpan{-7, 64}, true, true}}} {
		g := f
		g.Regions = regions
		g.Words = nil
		c, err := CheckTransition(t.Context(), x.im, g, p, TransitionLimits{})
		transitionRefused(t, c, err)
	}
	for _, change := range []func(*TransitionProposal){
		func(p *TransitionProposal) { p.Nodes = append(p.Nodes, p.Nodes[0]) },
		func(p *TransitionProposal) { p.Nodes[0].Successors[0] = p.Root },
		func(p *TransitionProposal) { p.Nodes[0].PC++ },
		func(p *TransitionProposal) { p.Nodes[0].ID = 0 },
		func(p *TransitionProposal) {
			for j := range p.Nodes {
				if p.Nodes[j].Expanded {
					p.Nodes[j].Expanded = false
					return
				}
			}
		},
	} {
		q := lifecycleProposal(p)
		change(&q)
		c, err := CheckTransition(t.Context(), x.im, f, q, TransitionLimits{})
		transitionRefused(t, c, err)
	}
}

func TestTransitionCallTLSOwnershipAndBudgets(t *testing.T) {
	x := dagArrange(t, callTLSOps(), 31)
	f := callTLSFace()
	p := callInventory(t, x, 30)
	root, err := CheckTransition(t.Context(), x.im, f, callInventory(t, x, 22), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	before := lifecycleSnapshot(root.checked.bound)
	count := &imageCallbackContext{Context: t.Context()}
	c, err := CheckTransitionContinuation(count, root, p)
	if err != nil {
		t.Fatal(err)
	}
	full := lifecycleSnapshot(c.checked.bound)
	// Checkpoints cover the complete operation, including graph reconstruction,
	// expression import, side-condition proofs and final ownership capture.
	for _, at := range []int{1, count.calls / 4, count.calls / 2, 3 * count.calls / 4, count.calls} {
		ctx, cancel := context.WithCancel(t.Context())
		callback := &imageCallbackContext{Context: ctx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		bad, err := CheckTransitionContinuation(callback, root, p)
		cancel()
		if bad.checked != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled call/TLS continuation accepted", at, err)
		}
	}
	projection, _ := c.Bound()
	projection.Frames = append(projection.Frames, TransitionFrame{})
	projection.Expansions[0].PC++
	projection.Abstractions[0].Value = br.Term{}
	projection.Thread = TransitionThread{}
	rootProjection, _ := root.Bound()
	if len(rootProjection.Frames) == 0 {
		t.Fatal("ownership fixture lacks an active frame")
	}
	rootProjection.Frames[0].Slot.offset++
	rootProjection.Expansions[0].Context = 999
	rootProjection.Thread.FS.Value = br.Term{}
	sibling, err := CheckTransitionContinuation(t.Context(), root, p)
	if err != nil {
		t.Fatal(err)
	}
	stateInheritedInputs(t, before, sibling.checked.bound)
	if !reflect.DeepEqual(before, root.checked.bound) || !reflect.DeepEqual(full, c.checked.bound) {
		t.Fatal("projection/sibling changed retained evidence")
	}
	for _, at := range []int{1, count.calls / 2, count.calls} {
		owned := lifecycleProposal(p)
		callback := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n == at {
				for j := range owned.Nodes {
					owned.Nodes[j].ID++
					owned.Nodes[j].Expanded = !owned.Nodes[j].Expanded
				}
			}
		}}
		checked, err := CheckTransitionContinuation(callback, root, owned)
		if err != nil {
			t.Fatal("capture did not own expansion/context containers", err)
		}
		assertCutStateAlpha(t, c.checked.bound, checked.checked.bound)
	}
	for _, limits := range []TransitionLimits{{RelationLimits: RelationLimits{Instructions: len(p.Nodes) - 1}}, {RelationLimits: RelationLimits{Work: 100}}, {RelationLimits: RelationLimits{Nodes: 64}}, {RelationLimits: RelationLimits{Depth: 4}}, {LiveStateBytes: 4096}} {
		bad, err := CheckTransition(t.Context(), x.im, f, p, limits)
		transitionRefused(t, bad, err)
	}
	// The old root's remaining meter, not a suffix-local allowance, governs work.
	limited := *root.checked
	limited.limits.Work = limited.work + 1
	bad, err := CheckTransitionContinuation(t.Context(), TransitionCertificate{&limited}, p)
	transitionRefused(t, bad, err)
}

func TestTransitionCallTLSBranches(t *testing.T) {
	for _, cc := range []uint8{2, 3, 4, 5, 6, 7, 12, 13, 14, 15} {
		for flags := 0; flags < 8; flags++ {
			ops := []dagOp{
				dagBranch(cc, 1, 2),
				{i: to.Intent{Operation: to.Call}, e: to.Encoding{Form: to.CALLE8}, taken: 4, next: 3},
				{i: to.Intent{Operation: to.Call}, e: to.Encoding{Form: to.CALLE8}, taken: 4, next: 3},
				dagScalar(to.Intent{Operation: to.MoveRegister, Dst: 15, Src: 0}, to.Encoding{Form: to.MOV89, REX: 0x49}, 8),
				dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 0, Immediate: 158}, to.Encoding{Form: to.MOVB8Imm32}, 5),
				dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 7, Immediate: 0x1002}, to.Encoding{Form: to.MOVB8Imm32}, 6),
				dagScalar(to.Intent{Operation: to.Syscall}, to.Encoding{Form: to.SYSCALL0F05}, 7),
				dagScalar(to.Intent{Operation: to.Return}, to.Encoding{Form: to.RETC3}, 8),
			}
			x := dagArrange(t, ops, uint64(cc)*17+uint64(flags))
			f := callTLSFace()
			r := stateInitial(f, uint64(flags))
			r.flags = [6]bool{flags&1 != 0, flags&2 != 0, false, flags&4 != 0, true, false}
			r.regs[6] = []uint64{0, 1 << 47, ^uint64(0)}[flags%3]
			p := callInventory(t, x, 16)
			flat, err := CheckTransition(t.Context(), x.im, f, p, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			callTLSAssert(t, flat, x, 16, f, r)
			root, err := CheckTransition(t.Context(), x.im, f, callInventory(t, x, 6), TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			c, err := CheckTransitionContinuation(t.Context(), root, p)
			if err != nil {
				t.Fatal(err)
			}
			callTLSAssert(t, c, x, 16, f, r)
			assertCallTLSAlpha(t, flat, c)
			// Both possible activations first encounter this numeric callee PC.
			ambiguous := callInventory(t, x, 8)
			bad, err := CheckTransition(t.Context(), x.im, f, ambiguous, TransitionLimits{})
			transitionRefused(t, bad, err)
		}
	}
	t.Run("asymmetric-fs", checkTransitionAsymmetricFSJoins)
}

// Each arm calls the same body with a separately constructed argument. The
// complete independent state/trace oracle must see the selected effective base
// at the join; checking just the per-syscall records cannot establish that join.
func checkTransitionAsymmetricFSJoins(t *testing.T) {
	imageBase := func(address uint64) dagOp {
		return dagOp{i: to.Intent{Operation: to.LEARIP, Dst: 6}, e: to.Encoding{Form: to.LEA8D, REX: 0x48, DispBytes: 4}, address: address}
	}
	scalarBase := func(value uint64) dagOp {
		return dagOp{i: to.Intent{Operation: to.MoveImmediate, Dst: 6, Immediate: value}, e: to.Encoding{Form: to.MOVB8Imm64, REX: 0x48}}
	}
	stackBase := func() dagOp {
		return dagOp{i: to.Intent{Operation: to.MoveRegister, Dst: 6, Src: 4}, e: to.Encoding{Form: to.MOV89, REX: 0x48}}
	}
	for _, bits := range []int{48, 57} {
		ceiling := uint64(1)<<(bits-1) - 4096
		cases := []struct {
			name        string
			left, right dagOp
			readable    bool
		}{
			{"scalar-low", scalarBase(0), scalarBase(1), false},
			{"scalar-valid-ceiling", scalarBase(ceiling - 2), scalarBase(ceiling - 1), false},
			{"different-image-pointers", imageBase(imageStateAddress + 72), imageBase(imageStateAddress + 80), false},
			{"image-and-stack-pointers", imageBase(imageStateAddress + 80), stackBase(), false},
			{"equal-number-without-provenance", imageBase(imageStateAddress + 72), scalarBase(imageStateAddress + 72), false},
			{"valid-versus-invalid-ceiling", imageBase(imageStateAddress + 80), scalarBase(ceiling), false},
			{"valid-versus-invalid-above", imageBase(imageStateAddress + 80), scalarBase(ceiling + 1), false},
			{"valid-versus-invalid-max", imageBase(imageStateAddress + 80), scalarBase(^uint64(0)), false},
			{"equal-image-provenance", imageBase(imageStateAddress + 72), imageBase(imageStateAddress + 72), true},
			{"equal-provenance-after-failure", stackBase(), scalarBase(ceiling), true},
		}
		for caseIndex, tc := range cases {
			for _, cc := range []uint8{2, 4, 12} {
				left, right := tc.left, tc.right
				left.next, right.next = 6, 8
				ops := []dagOp{
					stackBase(),
					dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 0, Immediate: 158}, to.Encoding{Form: to.MOVB8Imm32}, 2),
					dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 7, Immediate: 0x1002}, to.Encoding{Form: to.MOVB8Imm32}, 3),
					dagScalar(to.Intent{Operation: to.Syscall}, to.Encoding{Form: to.SYSCALL0F05}, 4),
					dagBranch(cc, 5, 7), left,
					{i: to.Intent{Operation: to.Call}, e: to.Encoding{Form: to.CALLE8}, taken: 10, next: 9}, right,
					{i: to.Intent{Operation: to.Call}, e: to.Encoding{Form: to.CALLE8}, taken: 10, next: 9},
					dagScalar(to.Intent{Operation: to.Load, FS: true, Dst: 0, SignedDisp: -8}, to.Encoding{Form: to.MOV8B, REX: 0x48, SIB: true, DispBytes: 4}, 14),
					dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 0, Immediate: 158}, to.Encoding{Form: to.MOVB8Imm32}, 11),
					dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 7, Immediate: 0x1002}, to.Encoding{Form: to.MOVB8Imm32}, 12),
					dagScalar(to.Intent{Operation: to.Syscall}, to.Encoding{Form: to.SYSCALL0F05}, 13),
					dagScalar(to.Intent{Operation: to.Return}, to.Encoding{Form: to.RETC3}, 14),
				}
				ops[0].next = 1
				seed := uint64(bits*1000 + caseIndex*17 + int(cc))
				x := dagArrange(t, ops, seed)
				f := callTLSFace()
				f.Conditions.UserAddressBits = bits
				join, end := 18, 28
				p := callInventory(t, x, join)
				flat, err := CheckTransition(t.Context(), x.im, f, p, TransitionLimits{})
				if err != nil {
					t.Fatalf("%s/%d: %v", tc.name, bits, err)
				}
				root, err := CheckTransition(t.Context(), x.im, f, callInventory(t, x, 8), TransitionLimits{})
				if err != nil {
					t.Fatal(err)
				}
				split, err := CheckTransitionContinuation(t.Context(), root, p)
				if err != nil {
					t.Fatal(err)
				}
				stateInheritedInputs(t, root.checked.bound, split.checked.bound)
				assertCallTLSAlpha(t, flat, split)
				fullProposal := callInventory(t, x, end)
				full, fullErr := CheckTransition(t.Context(), x.im, f, fullProposal, TransitionLimits{})
				continued, continuedErr := CheckTransitionContinuation(t.Context(), split, fullProposal)
				for _, c := range []TransitionCertificate{flat, split} {
					if (c.checked.bound.Thread.FS.Pointer != nil) != tc.readable {
						t.Fatalf("%s: joined FS provenance differs", tc.name)
					}
				}
				if tc.readable {
					if fullErr != nil || continuedErr != nil {
						t.Fatalf("%s: equal provenance failed to authorize FS read: %v / %v", tc.name, fullErr, continuedErr)
					}
					stateInheritedInputs(t, split.checked.bound, continued.checked.bound)
					assertCallTLSAlpha(t, full, continued)
				} else {
					for _, attempt := range []struct {
						c   TransitionCertificate
						err error
					}{{full, fullErr}, {continued, continuedErr}} {
						transitionRefused(t, attempt.c, attempt.err)
						var r *Refusal
						if !errors.As(attempt.err, &r) || r.PC != x.pcs[join] || r.Premise != "transition-provenance" {
							t.Fatalf("%s: lost-provenance access refused for wrong reason: %v", tc.name, attempt.err)
						}
					}
				}
				for flags := 0; flags < 8; flags++ {
					r := stateInitial(f, seed+uint64(flags))
					r.flags = [6]bool{flags&1 != 0, flags&2 != 0, false, flags&4 != 0, flags&1 == 0, flags&2 == 0}
					for _, c := range []TransitionCertificate{flat, split} {
						callTLSAssert(t, c, x, join, f, r)
					}
					if tc.readable {
						for _, c := range []TransitionCertificate{full, continued} {
							callTLSAssert(t, c, x, end, f, r)
						}
					}
				}
			}
		}
	}
}

func TestTransitionDeadDirectCallMergedGuards(t *testing.T) {
	for seed := uint64(0); seed < 24; seed++ {
		ops := multiExclusionOps(uint8(seed), false)
		ops[8].boundary = []byte{0xe8, 0xff, 0xff, 0xff, 0x7f}
		x := dagArrange(t, ops, seed)
		f := imageStateFace()
		f.Conditions.CPUID = CPUIDModel
		p := callInventory(t, x, 24)
		c, err := CheckTransition(t.Context(), x.im, f, p, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		for _, zero := range []bool{false, true} {
			r := stateInitial(f, seed)
			if zero {
				r.regs[0] = 0
			} else {
				r.regs[0] |= 1
			}
			callTLSAssert(t, c, x, 24, f, r)
		}
		ops[2] = dagBranch(5, 3, 8)
		y := dagArrange(t, ops, seed)
		bad, err := CheckTransition(t.Context(), y.im, f, callInventory(t, y, 24), TransitionLimits{})
		transitionRefused(t, bad, err)
	}
}

func TestCallFreeInventoryRejectsActivation(t *testing.T) {
	im := image(t, []byte{0xc3})
	f := face(Masks{}, Masks{})
	p, err := Propose(t.Context(), im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	p.Nodes[0].Context = "/0000000000401000"
	c, err := Check(t.Context(), im, testEntry, f, p)
	if err == nil || c.checked != nil {
		t.Fatal("leaf accepted forged activation")
	}
}

// REQ-impl-claim-refusal and REQ-impl-native-transition require the failed
// occurrence's actual dependency path, not ancestry borrowed by numeric PC.
func TestTransitionInventoryActivationPaths(t *testing.T) {
	code := make([]byte, 20)
	copy(code, []byte{0xe8, 11, 0, 0, 0, 0xe8, 6, 0, 0, 0, 0x0f, 0x0b})
	copy(code[16:], []byte{0x48, 0x89, 0xd8, 0xc3})
	im := image(t, code)
	f := stateFace(16, 0)
	f.Regions = []RelativeRegion{{RelativeSpan{-16, 16}, true, true}}
	f.Words = nil
	p, err := ProposeTransition(t.Context(), im, testEntry+10, TransitionLimits{}, TransitionOptions{Expansions: []TransitionExpansion{{PC: testEntry}, {PC: testEntry + 5}}})
	if err != nil {
		t.Fatal(err)
	}
	if c, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{}); err != nil || c.checked == nil {
		t.Fatal("valid repeated-call inventory refused", err)
	}
	for ordinal, call := range []uint64{testEntry, testEntry + 5} {
		id := transitionTestID(t, p, testEntry+16, ordinal)
		want := []uint64{testEntry, testEntry + 16}
		if call != testEntry {
			want = []uint64{testEntry, testEntry + 16, testEntry + 19, testEntry + 5, testEntry + 16}
		}
		for _, fault := range []string{"size", "omit", "duplicate", "successor-count", "successor-target"} {
			q := lifecycleProposal(p)
			at := -1
			for j, n := range q.Nodes {
				if n.ID == id {
					at = j
					break
				}
			}
			if at < 0 {
				t.Fatal("missing independently selected occurrence")
			}
			switch fault {
			case "size":
				q.Nodes[at].Size++
			case "omit":
				q.Nodes = append(q.Nodes[:at], q.Nodes[at+1:]...)
			case "duplicate":
				q.Nodes = append(q.Nodes, q.Nodes[at])
			case "successor-count":
				q.Nodes[at].Successors = nil
			case "successor-target":
				q.Nodes[at].Successors[0] = transitionTestID(t, p, testEntry+10, 0)
			}
			c, err := CheckTransition(t.Context(), im, f, q, TransitionLimits{})
			transitionRefused(t, c, err)
			var r *Refusal
			if !errors.As(err, &r) || r.Premise != "transition-proposal" || r.PC != testEntry+16 || !slices.Equal(r.Path, want) {
				t.Fatalf("%s in occurrence %d lost its activation ancestry: %+v", fault, id, r)
			}
		}
	}
	// This PC is reachable at the root, but not in the invented child context.
	// Duplicating that undiscovered point must not borrow the root's ancestry.
	q := lifecycleProposal(p)
	extra := TransitionNode{ID: 999, PC: testEntry + 5, Size: 5}
	q.Nodes = append(q.Nodes, extra, extra)
	c, err := CheckTransition(t.Context(), im, f, q, TransitionLimits{})
	transitionRefused(t, c, err)
	var r *Refusal
	if !errors.As(err, &r) || !slices.Equal(r.Path, []uint64{testEntry + 5}) {
		t.Fatal("invented occurrence borrowed reachable root ancestry", err)
	}
	leaf := image(t, []byte{0x48, 0x89, 0xd8, 0xc3})
	lf := face(Masks{RBX: ^uint64(0)}, Masks{RAX: ^uint64(0)})
	lp, err := Propose(t.Context(), leaf, testEntry, lf)
	if err != nil {
		t.Fatal(err)
	}
	for j := range lp.Nodes {
		if lp.Nodes[j].PC == testEntry+3 {
			lp.Nodes[j].Size++
		}
	}
	lc, err := Check(t.Context(), leaf, testEntry, lf, lp)
	if err == nil || lc.checked != nil || !errors.As(err, &r) || !slices.Equal(r.Path, []uint64{testEntry, testEntry + 3}) {
		t.Fatal("call-free root ancestry changed", err)
	}
}

func TestTransitionFSProvenanceAndPermissions(t *testing.T) {
	for variant := 0; variant < 8; variant++ {
		ops := []dagOp{
			{i: to.Intent{Operation: to.LEARIP, Dst: 6}, e: to.Encoding{Form: to.LEA8D, REX: 0x48, DispBytes: 4}, address: imageStateAddress + 72, next: 1},
			dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 0, Immediate: 158}, to.Encoding{Form: to.MOVB8Imm32}, 2),
			dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 7, Immediate: 0x1002}, to.Encoding{Form: to.MOVB8Imm32}, 3),
			dagScalar(to.Intent{Operation: to.Syscall}, to.Encoding{Form: to.SYSCALL0F05}, 4),
			dagScalar(to.Intent{Operation: to.StoreImmediate, FS: true, SignedDisp: -8, Immediate: 0x123}, to.Encoding{Form: to.MOVC7, REX: 0x48, SIB: true, DispBytes: 4}, 5),
		}
		f := callTLSFace()
		switch variant {
		case 1:
			ops[0] = dagScalar(to.Intent{Operation: to.MoveImmediate, Dst: 6, Immediate: imageStateAddress + 72}, to.Encoding{Form: to.MOVB8Imm64, REX: 0x48}, 1)
		case 2:
			f.ImageRegions = []Span{{imageStateAddress + 64, imageStateAddress + 71}}
		case 3:
			f.ImageRegions = nil
		case 4:
			ops[1].i.Immediate = 0x4000009e
		case 5:
			ops[2].i.Immediate = 0x1001
		case 6:
			ops[1] = dagScalar(to.Intent{Operation: to.MoveImmediate, Dst: 0, Immediate: 1<<32 | 158}, to.Encoding{Form: to.MOVB8Imm64, REX: 0x48}, 2)
		case 7:
			ops[2] = dagScalar(to.Intent{Operation: to.MoveImmediate, Dst: 7, Immediate: 0xabcdef1200001002}, to.Encoding{Form: to.MOVB8Imm64, REX: 0x48}, 3)
		}
		x := dagArrange(t, ops, uint64(variant))
		p := callInventory(t, x, 10)
		c, err := CheckTransition(t.Context(), x.im, f, p, TransitionLimits{})
		if variant >= 1 && variant <= 5 {
			transitionRefused(t, c, err)
		} else {
			if err != nil {
				t.Fatal(err)
			}
			callTLSAssert(t, c, x, 10, f, stateInitial(f, uint64(variant)))
		}
	}
}

func TestTransitionUnknownBaseKeepsLiveError(t *testing.T) {
	for mode := 0; mode < 3; mode++ {
		base := dagScalar(to.Intent{Operation: to.MoveRegister, Dst: 6, Src: 3}, to.Encoding{Form: to.MOV89, REX: 0x48}, 1)
		if mode != 0 {
			value := uint64(0)
			if mode == 2 {
				value = ^uint64(0)
			}
			base = dagScalar(to.Intent{Operation: to.MoveImmediate, Dst: 6, Immediate: value}, to.Encoding{Form: to.MOVB8Imm64, REX: 0x48}, 1)
		}
		ops := []dagOp{base,
			dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 0, Immediate: 158}, to.Encoding{Form: to.MOVB8Imm32}, 2),
			dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 7, Immediate: 0x1002}, to.Encoding{Form: to.MOVB8Imm32}, 3),
			dagScalar(to.Intent{Operation: to.Syscall}, to.Encoding{Form: to.SYSCALL0F05}, 4),
			dagScalar(to.Intent{Operation: to.CompareImmediate, Dst: 0, Width: 64}, to.Encoding{Form: to.CMP83, REX: 0x48}, 5),
			dagBranch(4, 6, 7), {boundary: []byte{0xe8, 0xff, 0xff, 0xff, 0x7f}},
		}
		x := dagArrange(t, ops, uint64(mode))
		f := callTLSFace()
		p := callInventory(t, x, 14)
		c, err := CheckTransition(t.Context(), x.im, f, p, TransitionLimits{})
		if mode != 1 {
			transitionRefused(t, c, err)
		} else {
			if err != nil {
				t.Fatal(err)
			}
			callTLSAssert(t, c, x, 14, f, stateInitial(f, 19))
		}
	}
}

func TestTransitionSymbolicFSAddressCeiling(t *testing.T) {
	for _, bits := range []int{48, 57} {
		ops := []dagOp{
			dagScalar(to.Intent{Operation: to.MoveRegister, Dst: 6, Src: 4}, to.Encoding{Form: to.MOV89, REX: 0x48}, 1),
			dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 0, Immediate: 158}, to.Encoding{Form: to.MOVB8Imm32}, 2),
			dagScalar(to.Intent{Operation: to.MoveImmediate32, Dst: 7, Immediate: 0x1002}, to.Encoding{Form: to.MOVB8Imm32}, 3),
			dagScalar(to.Intent{Operation: to.Syscall}, to.Encoding{Form: to.SYSCALL0F05}, 4),
		}
		x := dagArrange(t, ops, uint64(bits))
		f := callTLSFace()
		f.Conditions.UserAddressBits = bits
		ceiling := uint64(1)<<47 - 4096
		f.Origin = OriginDomain{Min: ceiling - 16, Max: ceiling + 16, Modulus: 16}
		f.Envelope = RelativeSpan{-16, 16}
		f.Regions = nil
		f.Words = nil
		p := callInventory(t, x, 8)
		c, err := CheckTransition(t.Context(), x.im, f, p, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		for _, origin := range []uint64{ceiling - 16, ceiling, ceiling + 16} {
			r := stateInitial(f, origin)
			r.origin = origin
			r.regs[4] = origin
			callTLSAssert(t, c, x, 8, f, r)
		}
	}
}

func TestTransitionScalarAddPopulation(t *testing.T) {
	check := func(raw [8 + 16*8]byte, immediate int32) {
		for reg := uint8(0); reg < 16; reg++ {
			for _, form := range []to.Form{to.ADD83, to.ADD81} {
				value := uint64(int64(immediate))
				if form == to.ADD83 {
					value = uint64(int64(int8(immediate)))
				}
				rex := byte(0x48)
				if reg >= 8 {
					rex = 0x49
				}
				ops := []dagOp{dagScalar(to.Intent{Operation: to.MoveRegister, Dst: 4, Src: 0}, to.Encoding{Form: to.MOV89, REX: 0x48}, 1), dagScalar(to.Intent{Operation: to.Add, Dst: reg, Immediate: value}, to.Encoding{Form: form, REX: rex}, 2)}
				x := dagArrange(t, ops, uint64(reg))
				f := stateFace(16, 0)
				r := stateRawInitial(f, raw[:])
				p := callInventory(t, x, 4)
				c, err := CheckTransition(t.Context(), x.im, f, p, TransitionLimits{})
				if err != nil {
					t.Fatal(err)
				}
				callTLSAssert(t, c, x, 4, f, r)
			}
		}
	}
	if err := quick.Check(func(raw [8 + 16*8]byte, imm int32) bool { check(raw, imm); return true }, &quick.Config{MaxCount: 24}); err != nil {
		t.Fatal(err)
	}
	for _, word := range []uint64{0, 1, 1<<63 - 1, 1 << 63, ^uint64(0)} {
		var raw [8 + 16*8]byte
		for j := 8; j+8 <= len(raw); j += 8 {
			binary.LittleEndian.PutUint64(raw[j:], word)
		}
		if got := stateRawInitial(stateFace(16, 0), raw[:]).regs[15]; got != word {
			t.Fatalf("R15 boundary input was truncated or zero-padded: got %#x want %#x", got, word)
		}
		for _, imm := range []int32{0, 1, -1, -2147483648, 2147483647} {
			check(raw, imm)
		}
	}
}
