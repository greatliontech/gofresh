package nativeproof

import (
	"encoding/binary"
	"math/rand/v2"
	"reflect"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// The first terminal has two incoming edges: Z&!Z and !Z&Z. Only the Z
// arm queries CPUID. Both arms write current image bytes before the common cut.
// After that cut, CMP RDX,RDX excludes a second terminal. Changing only the
// suffix branch to JE gives that second terminal a live incoming twin.
func multiExclusionOps(width uint8, live bool) []dagOp {
	w := []uint8{8, 32, 64}[width%3]
	store := func(src uint8, next int) dagOp {
		e := to.Encoding{Form: to.MOV89, DispBytes: 4}
		if w == 8 {
			e.Form = to.MOV88
		}
		if w == 64 {
			e.REX = 0x48
		}
		return dagOp{i: to.Intent{Operation: to.Store, RIP: true, Width: w, Src: src}, e: e, next: next, address: imageStateAddress + 64}
	}
	cc := uint8(5)
	if live {
		cc = 4
	}
	return []dagOp{
		dagScalar(to.Intent{Operation: to.Test, Dst: 0, Src: 0, Width: 64}, to.Encoding{Form: to.TEST85, REX: 0x48}, 1),
		dagBranch(4, 2, 4), dagBranch(4, 3, 8), store(3, 7),
		dagBranch(5, 5, 8), dagScalar(to.Intent{Operation: to.CPUID}, to.Encoding{Form: to.CPUID0FA2}, 6), store(0, 7),
		dagScalar(to.Intent{Operation: to.Compare, Dst: 2, Src: 2, Width: 64}, to.Encoding{Form: to.CMP39, REX: 0x48}, 9),
		{boundary: []byte{0xff, 0xd0}}, dagBranch(cc, 10, 11),
		{i: to.Intent{Operation: to.Load, Dst: 7, RIP: true}, e: to.Encoding{Form: to.MOV8B, REX: 0x48, DispBytes: 4}, next: 12, address: imageStateAddress + 64},
		{boundary: []byte{0x0f, 0x05}},
	}
}

func checkMultiExclusion(t testing.TB, width uint8, layout uint64, raw, inactive []byte, tuple [4]uint32) {
	t.Helper()
	arrange := func(ops []dagOp) dagLayout {
		return dagArrangePermutation(t, ops, rand.New(rand.NewPCG(layout, 0x6578636c756465)).Perm(len(ops)+1))
	}
	x := arrange(multiExclusionOps(width, false))
	face := imageStateFace()
	face.Conditions.CPUID = CPUIDModel
	var err error
	face.Initialization, err = CheckImageInitialization(t.Context(), x.im, StaticELFInitialization)
	if err != nil {
		t.Fatal(err)
	}
	root, err := CheckTransition(t.Context(), x.im, face, x.proposal(14), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	before := lifecycleSnapshot(root.checked.bound)
	if len(before.ExcludedBoundaries) != 1 || before.ExcludedBoundaries[0].PC != x.pcs[16] || len(root.checked.exclusions) != 1 {
		t.Fatal("first merged exclusion absent")
	}
	// The guard must actually be a union of both independently impossible edges,
	// not a single dead edge accidentally used as the terminal's condition.
	v := before.ExcludedBoundaries[0].Guard.View()
	if v.Op != br.Or || len(v.Args) != 2 {
		t.Fatal("multi-incoming guard is not a complete union", v)
	}
	builder := br.NewBuilder(16)
	zero, err := builder.Const(br.Bool(), 0)
	if err != nil {
		t.Fatal(err)
	}
	// Build the two source-bound edge expressions from TEST64's fixture intent,
	// not by accepting whatever false expressions the terminal reports.
	makeTerm := func(op br.Op, sort br.Sort, args ...br.Term) br.Term {
		r, err := builder.Make(op, sort, 0, args...)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	wordZero, err := builder.Const(br.Bits(64), 0)
	if err != nil {
		t.Fatal(err)
	}
	rax := before.InitialRegisters[RAX]
	predicate := makeTerm(br.Equal, br.Bool(), makeTerm(br.BitAnd, br.Bits(64), rax, rax), wordZero)
	negated := makeTerm(br.Not, br.Bool(), predicate)
	a, b := makeTerm(br.And, br.Bool(), predicate, negated), makeTerm(br.And, br.Bool(), negated, predicate)
	if !(sameExclusionSourceShape(v.Args[0], a) && sameExclusionSourceShape(v.Args[1], b) || sameExclusionSourceShape(v.Args[0], b) && sameExclusionSourceShape(v.Args[1], a)) {
		t.Fatal("terminal lost an exact incoming source guard")
	}
	for _, edge := range v.Args {
		p, err := br.Propose(t.Context(), edge, zero, br.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := br.Check(t.Context(), edge, zero, p, br.Limits{}); err != nil {
			t.Fatal(err)
		}
	}
	continued, err := CheckTransitionContinuation(t.Context(), root, x.proposal(24))
	if err != nil {
		t.Fatal(err)
	}
	direct, err := CheckTransition(t.Context(), x.im, face, x.proposal(24), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	assertTransitionAlpha(t, direct, continued)
	stateInheritedInputs(t, before, continued.checked.bound)
	if len(continued.checked.exclusions) != 2 || continued.checked.exclusions[0] != root.checked.exclusions[0] || continued.checked.bound.ExcludedBoundaries[0].Guard != before.ExcludedBoundaries[0].Guard || root.checked.coverageGuard != before.CutGuard {
		t.Fatal("old exact proof/guard roots were replaced")
	}
	for _, zeroInput := range []bool{false, true} {
		initial := initializedReference(face, x.im.data, x.mappings, raw)
		// Each map is onto its class; in particular even nonzero values and
		// bit63-only values are preserved, rather than forcing an odd operand.
		if zeroInput {
			initial.regs[0] = 0
		} else if initial.regs[0] == 0 {
			initial.regs[0] = 1
		}
		initial.outcomes = [][4]uint32{tuple}
		dagAssert(t, root, x, 14, face, initial, inactive)
		for _, c := range []TransitionCertificate{continued, direct} {
			dagAssert(t, c, x, 24, face, initial, inactive)
		}
	}
	// Expected state is independently cloned before mutating the RAW production
	// projection. This catches either shallow outer slices or shallow Bytes.
	projection, _ := root.Bound()
	for j := range projection.ExcludedBoundaries {
		projection.ExcludedBoundaries[j].Bytes[0] ^= 255
		projection.ExcludedBoundaries[j].Guard = projection.CutGuard
	}
	for j := range projection.Instructions {
		projection.Instructions[j] = GuardedInstruction{}
	}
	for j := range projection.Memory {
		projection.Memory[j] = TransitionByte{}
	}
	for j := range projection.InitialMemory {
		projection.InitialMemory[j] = TransitionByte{}
	}
	for j := range projection.Accesses {
		projection.Accesses[j] = TransitionAccess{}
	}
	for j := range projection.PrimitiveEffects {
		projection.PrimitiveEffects[j] = CPUIDEffect{}
	}
	for j := range projection.Interface.Regions {
		projection.Interface.Regions[j] = RelativeRegion{}
	}
	for j := range projection.Interface.ImageRegions {
		projection.Interface.ImageRegions[j] = Span{}
	}
	for j := range projection.Interface.Words {
		projection.Interface.Words[j] = 99
	}
	for j := range projection.Words {
		projection.Words[j] = TransitionWord{}
	}
	for j := range projection.ExcludedOrigins {
		projection.ExcludedOrigins[j] = Span{}
	}
	for j := range projection.Boundary.Bytes {
		projection.Boundary.Bytes[j] ^= 255
	}
	if !reflect.DeepEqual(before, root.checked.bound) {
		t.Fatal("mutable projection changed retained prefix")
	}
	// Identical layout and all other node intents, changing only the last JNE.
	y := arrange(multiExclusionOps(width, true))
	liveFace := face
	liveFace.Initialization, err = CheckImageInitialization(t.Context(), y.im, StaticELFInitialization)
	if err != nil {
		t.Fatal(err)
	}
	liveRoot, err := CheckTransition(t.Context(), y.im, liveFace, y.proposal(14), TransitionLimits{})
	if err != nil {
		t.Fatal("same live-twin prefix refused", err)
	}
	c, err := CheckTransitionContinuation(t.Context(), liveRoot, y.proposal(24))
	exclusionRefusal(t, c, err, y.pcs[22], "transition-guard", "bitrelation unsupported: bounded rewrites did not join")
	c, err = CheckTransition(t.Context(), y.im, liveFace, y.proposal(24), TransitionLimits{})
	exclusionRefusal(t, c, err, y.pcs[22], "transition-guard", "bitrelation unsupported: bounded rewrites did not join")
	// A second twin changes only ONE of the shared terminal's two incoming
	// edges. The other remains independently dead; using just that edge's proof
	// would falsely accept this now-live merged guard.
	liveIncoming := multiExclusionOps(width, false)
	liveIncoming[2] = dagBranch(5, 3, 8)
	y = arrange(liveIncoming)
	liveFace.Initialization, err = CheckImageInitialization(t.Context(), y.im, StaticELFInitialization)
	if err != nil {
		t.Fatal(err)
	}
	liveRoot, err = CheckTransition(t.Context(), y.im, liveFace, y.proposal(2), TransitionLimits{})
	if err != nil {
		t.Fatal("shared-edge twin prefix refused", err)
	}
	c, err = CheckTransitionContinuation(t.Context(), liveRoot, y.proposal(24))
	exclusionRefusal(t, c, err, y.pcs[16], "transition-guard", "bitrelation unsupported: bounded rewrites did not join")
	c, err = CheckTransition(t.Context(), y.im, liveFace, y.proposal(24), TransitionLimits{})
	exclusionRefusal(t, c, err, y.pcs[16], "transition-guard", "bitrelation unsupported: bounded rewrites did not join")
}

func sameExclusionSourceShape(a, b br.Term) bool {
	x, y := a.View(), b.View()
	if x.Op != y.Op || x.Sort != y.Sort || x.Immediate != y.Immediate || x.Scope != y.Scope || x.Scratch != y.Scratch || len(x.Args) != len(y.Args) {
		return false
	}
	if x.Op == br.Variable {
		return a == b
	}
	for j := range x.Args {
		if !sameExclusionSourceShape(x.Args[j], y.Args[j]) {
			return false
		}
	}
	return true
}

func TestTransitionMultipleExclusions(t *testing.T) {
	if err := quick.Check(func(width uint8, layout uint64, raw [512]byte, inactive [32]byte, tuple [4]uint32) bool {
		checkMultiExclusion(t, width, layout, raw[:], inactive[:], tuple)
		return true
	}, &quick.Config{MaxCount: 32}); err != nil {
		t.Fatal(err)
	}
}

func FuzzTransitionMultipleExclusions(f *testing.F) {
	for width := uint8(0); width < 3; width++ {
		raw := make([]byte, 512)
		binary.LittleEndian.PutUint64(raw[8:], uint64(1)<<[]uint{1, 32, 63}[width])
		f.Add(width, uint64(width), raw, make([]byte, 32), uint32(17), uint32(23), uint32(31), uint32(47))
	}
	f.Fuzz(func(t *testing.T, width uint8, layout uint64, raw, inactive []byte, a, b, c, d uint32) {
		checkMultiExclusion(t, width, layout, raw, inactive, [4]uint32{a, b, c, d})
	})
}
