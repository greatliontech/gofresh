package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func TestTransitionExclusionExactProofBindings(t *testing.T) {
	im, face, cut, _ := initializedDecision(t, 0, false, false, nil)
	root, err := proveTransition(t, im, cut-3, face)
	if err != nil {
		t.Fatal(err)
	}
	p := continuationProposal(t, root, cut)
	assertTransitionRetainedExpressionUnion(t, root, p)
	builder := br.NewBuilder(30)
	zero, _ := builder.Make(br.Constant, br.Bool(), 0)
	one, _ := builder.Make(br.Constant, br.Bool(), 1)
	bvzero, _ := builder.Make(br.Constant, br.Bits(1), 0)
	foreign, _ := builder.Input(br.Bool(), br.NewScope(), 9)
	neg, _ := builder.Make(br.Not, br.Bool(), 0, foreign)
	falseGuard, _ := builder.Make(br.And, br.Bool(), 0, foreign, neg)
	witness := func(left, right br.Term) br.Witness {
		p, err := br.Propose(t.Context(), left, right, br.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		w, err := br.Check(t.Context(), left, right, p, br.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	wrong := []br.Witness{{}, witness(zero, zero), witness(falseGuard, zero), witness(bvzero, bvzero), witness(one, one)}
	for _, w := range wrong {
		fake := *root.checked
		fake.exclusions = append([]br.Witness(nil), fake.exclusions...)
		fake.exclusions[0] = w
		c, err := CheckTransitionContinuation(t.Context(), TransitionCertificate{&fake}, p)
		transitionRefused(t, c, err)
	}
	// Isolate the RIGHT endpoint: the authentic, nonliteral derived false guard
	// remains the exact left handle, and a valid reflexive proof changes only the
	// claimed right endpoint. A truth/sort/wrong-left control cannot test this.
	guard := root.checked.bound.ExcludedBoundaries[0].Guard
	if guard.View().Op == br.Constant {
		t.Fatal("right-endpoint control needs a nonliteral guard")
	}
	fake := *root.checked
	fake.exclusions = append([]br.Witness(nil), fake.exclusions...)
	fake.exclusions[0] = witness(guard, guard)
	c, err := CheckTransitionContinuation(t.Context(), TransitionCertificate{&fake}, p)
	exclusionRefusal(t, c, err, root.checked.bound.ExcludedBoundaries[0].PC, "transition-continuation", "invalid retained exclusion")
	if c, err := CheckTransitionContinuation(t.Context(), root, p); err != nil || c.checked == nil {
		t.Fatal("authentic exclusion continuation refused", err)
	}
	for _, mutate := range []func(*checkedTransition){
		func(c *checkedTransition) { c.bound.ExcludedBoundaries[0].Guard = zero },
		func(c *checkedTransition) { c.bound.ExcludedBoundaries[0].PC++ },
		func(c *checkedTransition) { c.bound.ExcludedBoundaries[0].Bytes[0] ^= 1 },
		func(c *checkedTransition) { c.bound.ExcludedBoundaries = nil },
		func(c *checkedTransition) { c.bound.CutGuard = one },
		func(c *checkedTransition) { c.bound.Instructions = c.bound.Instructions[1:] },
		func(c *checkedTransition) {
			c.bound.Rules = "gofresh/native-transition@5;" + ValueRules + ";" + FrameRules + ";" + cpuidRules
		},
	} {
		fake := *root.checked
		fake.bound = cloneTransitionBound(fake.bound)
		mutate(&fake)
		c, err := CheckTransitionContinuation(t.Context(), TransitionCertificate{&fake}, p)
		transitionRefused(t, c, err)
	}
	// Every original terminal is in the full proposal, despite not being fetched.
	for j := range p.Nodes {
		bad := lifecycleProposal(p)
		bad.Nodes = append(bad.Nodes[:j], bad.Nodes[j+1:]...)
		c, err := CheckTransitionContinuation(t.Context(), root, bad)
		transitionRefused(t, c, err)
	}
}

func TestTransitionExclusionStructuralFailures(t *testing.T) {
	for _, tail := range [][]byte{{0xff}, {0xf0, 0xff, 0xd0}, {0xc5, 0xf8}, {0xeb, 0xfe}, {0x48, 0x8b, 0x05, 0, 0, 0}} {
		// MOV EAX,0; TEST EAX,EAX; JE cut; JMP dead; cut UD2; dead tail.
		code := append([]byte{0xb8, 0, 0, 0, 0, 0x85, 0xc0, 0x74, 2, 0xeb, 2, 0x0f, 0x0b}, tail...)
		im, err := NewImage(t.Context(), elfBytes(code))
		if err != nil {
			t.Fatal(err)
		}
		p, err := ProposeTransition(t.Context(), im, testEntry+11, TransitionLimits{})
		if err == nil {
			t.Fatalf("invalid/truncated/cyclic dead arm proposed: %x %+v", tail, p)
		}
	}
	// A separate entry edge directly into the CALL makes its merged incoming
	// guard live for some original flags, defeating the initialized-zero proof.
	im, face, cut, call := initializedDecision(t, 0, false, false, []byte{0x74, 0})
	raw := append([]byte(nil), im.data...)
	raw[0x1001] = byte(call - testEntry - 2)
	im, face = initializedImage(t, raw, face)
	c, err := proveTransition(t, im, cut, face)
	transitionRefused(t, c, err)
	// Entering after the CALL through a separate edge still discovers those bytes.
	raw[0x1001] = byte(call + 2 - testEntry - 2)
	raw[0x1000+call+2-testEntry] = 0x0f
	raw[0x1000+call+3-testEntry] = 0x05
	im, face = initializedImage(t, raw, face)
	c, err = proveTransition(t, im, cut, face)
	transitionRefused(t, c, err)
}

func TestTransitionExclusionCumulativeResources(t *testing.T) {
	im, face, cut, _ := initializedDecision(t, 0, false, false, nil)
	p := rootTransitionProposal(t, im, cut)
	count := &imageCallbackContext{Context: t.Context()}
	c, err := CheckTransition(count, im, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	// Independently count the proof kernel's own checkpoints. The root work meter
	// must include BOTH complete invocations, besides importing candidate terms;
	// deriving a limit from the transition's own work alone would miss a reset.
	left, right := c.checked.exclusions[0].Roots()
	kernelCount := &imageCallbackContext{Context: t.Context()}
	limits := br.Limits{Nodes: 32768, Steps: 32768, Work: 1_000_000}
	proof, err := br.Propose(kernelCount, left, right, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := br.Check(kernelCount, left, right, proof, limits); err != nil {
		t.Fatal(err)
	}
	lm, err := transitionLimits(TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := newTransitionChecker(t.Context(), im, transitionRoot{entry: im.entry}, lm, 0)
	if err != nil {
		t.Fatal(err)
	}
	m.builder, m.falsity = br.NewBuilder(lm.Nodes), right
	if err := m.importTerm(left); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		before := m.work
		if _, err := m.proveFalseGuard(left); err != nil {
			t.Fatal(err)
		}
		if m.work-before < kernelCount.calls {
			t.Fatalf("root charged %d checkpoints for %d kernel checkpoints", m.work-before, kernelCount.calls)
		}
	}
	for _, at := range []int{1, count.calls / 2, count.calls - 1, count.calls} {
		ctx, cancel := context.WithCancel(t.Context())
		callback := &imageCallbackContext{Context: ctx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		bad, err := CheckTransition(callback, im, face, p, TransitionLimits{})
		cancel()
		if !errors.Is(err, context.Canceled) || bad.checked != nil {
			t.Fatal("cancelled exclusion escaped", err)
		}
	}
	// General construction-budget examples. The proof-specific node/import/depth
	// and live-storage frontiers have separate same-allowance prefix controls.
	for _, l := range []TransitionLimits{{RelationLimits: RelationLimits{Work: c.checked.work - 1}}, {RelationLimits: RelationLimits{Instructions: len(p.Nodes) - 1}}, {RelationLimits: RelationLimits{Nodes: 20}}, {RelationLimits: RelationLimits{Depth: 2}}, {LiveStateBytes: 1}} {
		bad, err := CheckTransition(t.Context(), im, face, p, l)
		transitionRefused(t, bad, err)
	}
	// A predecessor retains its spent proof work, not just transfer work.
	l := TransitionLimits{RelationLimits: RelationLimits{Work: c.checked.work}}
	root, err := CheckTransition(t.Context(), im, face, rootTransitionProposal(t, im, cut-3), l)
	if err != nil {
		t.Fatal(err)
	}
	before := lifecycleSnapshot(root.checked.bound)
	bad, err := CheckTransitionContinuation(t.Context(), root, p)
	transitionRefused(t, bad, err)
	after, _ := root.Bound()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed proof mutated predecessor")
	}
}

func exclusionRefusal(t testing.TB, c TransitionCertificate, err error, pc uint64, premise, detail string) {
	t.Helper()
	var r *Refusal
	if c.checked != nil || !errors.As(err, &r) || r.PC != pc || r.Premise != premise || r.Detail != detail {
		t.Fatalf("wanted %x %s %q, got %v", pc, premise, detail, err)
	}
}

func TestImageInitializationOperationGeometry(t *testing.T) {
	for _, unknownFirst := range []bool{false, true} {
		loads := imageStateLoads()
		if unknownFirst {
			loads[0], loads[1] = loads[1], loads[0]
		}
		raw := transitionImageELF(t, []byte{0xc3}, loads)
		assertInitializationGeometry(t, raw, loads, 128)
		im, face := initializedImage(t, raw, imageStateFace())
		c, err := proveTransition(t, im, im.entry, face)
		if err != nil {
			t.Fatal(err)
		}
		stateBindings(t, c, face, initializedReference(face, raw, loads, []byte{1, 2, 3}))
	}
	for _, zeroPrefix := range []bool{false, true} {
		loads := imageStateLoads()
		loads[1].file = loads[0].file
		if zeroPrefix {
			loads[1].file++
			loads[1].start++
			loads[1].filesz = 0
		}
		raw := transitionImageELF(t, []byte{0xc3}, loads)
		im, face := initializedImage(t, raw, imageStateFace())
		for _, r := range face.Initialization.checked.ranges {
			if r.Start >= imageStateAddress {
				t.Fatal("aliased backing supplied initialization")
			}
		}
		c, err := proveTransition(t, im, im.entry, face)
		transitionRefused(t, c, err)
	}
	// Nonmonotonic header order does not itself justify dropping independent
	// facts; aggregate operation footprints, rather than header ordering, decide.
	loads := []interfaceMapping{{start: 0x900000, end: 0x900010, file: 0x20000, filesz: 16, read: true}, {start: 0x700000, end: 0x800000, file: 0x10000, filesz: 0, read: true, write: true}}
	raw := transitionImageELF(t, []byte{0xc3}, loads)
	assertInitializationGeometry(t, raw, loads, 8192)
	// Format admission, including relocations/interpreter/dynamic headers, is
	// inherited from NewImage rather than silently reparsed under a weaker policy.
	for _, kind := range []uint32{2, 3} {
		bad := append([]byte(nil), raw...)
		binary.LittleEndian.PutUint32(bad[120:], kind)
		if _, err := NewImage(t.Context(), bad); err == nil {
			t.Fatal("unsupported loading header accepted")
		}
	}
}
