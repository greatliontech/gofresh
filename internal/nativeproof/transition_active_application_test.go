package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

const activeApplicationBody = applicationChild + 32

// Use the ordinary application fixture's CALL, memory grants and return oracle.
// The CALL targets a wrapper whose actual tail JMP reaches the selected body.
func newActiveApplicationFixture(t testing.TB, wrapper, body string) applicationFixture {
	t.Helper()
	code := hexBytes(t, wrapper)
	if len(code)+5 > 32 {
		t.Fatal("wrapper exceeds fixture's body offset")
	}
	distance := 32 - len(code) - 5
	code = append(code, 0xe9)
	code = binary.LittleEndian.AppendUint32(code, uint32(distance))
	for len(code) < 32 {
		code = append(code, 0x90)
	}
	code = append(code, hexBytes(t, body)...)
	f := newApplicationFixture(t, "", fmt.Sprintf("%x", code))
	f.parentExp = []TransitionExpansion{{PC: f.call}}
	return f
}

func activeApplicationCertificates(t testing.TB, f applicationFixture) (TransitionCertificate, TransitionReturnCertificate) {
	t.Helper()
	entered := applicationRoot(t, f.im, testEntry, activeApplicationBody, f.parent, f.parentExp)
	child := checkedReturn(t, applicationRoot(t, f.im, activeApplicationBody, f.ret, f.child, f.childExp))
	return entered, child
}

func TestTransitionActiveApplicationWrapperTailAndBodyPreservation(t *testing.T) {
	f := newActiveApplicationFixture(t, "0fa2488d6c241848896c24e8", "554889e5b82a0000005dc3")
	f.parent.Conditions.CPUID = CPUIDModel
	f.child.Words = []int64{-24}
	entered, child := activeApplicationCertificates(t, f)
	before, _ := entered.Bound()
	childBefore, _ := child.Bound()
	c, err := CheckTransitionActiveReturn(t.Context(), entered, child)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := c.BoundFor(f.im)
	if !ok || !c.AppliesTo(child) || c.AppliesTo(checkedReturn(t, child.checked.prefix)) {
		t.Fatal("lost exact owned callee")
	}
	if b.ID != before.Frames[0].ID || b.Call != f.call || b.Continuation != f.call+5 || b.Activation != before.Boundary.Context || b.StackShift != -8 || len(b.Successor.Frames) != 0 || b.Successor.Boundary.Context != 0 || b.Successor.Boundary.PC != f.call+5 {
		t.Fatal("active wrapper/tail invocation did not return to its parent")
	}
	if !reflect.DeepEqual(b.ChildEntry, before) || b.Registers[RBP] != before.Registers[RBP] || b.Registers[RBP].Value == before.InitialRegisters[RBP] || b.Successor.Registers[RBP].Pointer != before.Registers[RBP].Pointer {
		t.Fatal("preserved RBP was related to pre-wrapper state")
	}
	if len(b.Words) != 1 || b.Words[0].Current.Pointer != before.Registers[RBP].Pointer {
		t.Fatal("body input word lost the wrapper's stored pointer")
	}
	lanes := 0
	for _, association := range b.Memory {
		if !association.Input.Image && association.Input.Offset >= -24 && association.Input.Offset < -16 {
			if association.Current.Offset != association.Input.Offset+b.StackShift || association.Current.Pointer != before.Registers[RBP].Pointer || association.Current.PointerLane != uint8(association.Input.Offset+24) {
				t.Fatal("body byte association lost actual wrapper memory or pointer lane")
			}
			lanes++
		}
	}
	if lanes != 8 {
		t.Fatal("body entry word lacks its eight actual byte associations")
	}
	stateInheritedInputs(t, before, b.Successor)
	if len(b.Successor.PrimitiveEffects) != 1 || !reflect.DeepEqual(before.PrimitiveEffects, b.Successor.PrimitiveEffects) || !reflect.DeepEqual(b.Successor.Accesses[:len(before.Accesses)], before.Accesses) {
		t.Fatal("wrapper history disappeared")
	}
	for _, base := range []uint64{65536, 100000, 131072} {
		values := map[br.Term]uint64{before.Origin: base}
		if stateEval(t, b.Successor.Registers[RBP].Value, values) != base+16 || stateEval(t, b.Successor.Registers[RSP].Value, values) != base || stateEval(t, b.Successor.Registers[RAX].Value, values) != 42 {
			t.Fatal("active successor lost actual body-entry values")
		}
	}
	successor, _ := c.Successor()
	p, err := ProposeTransitionContinuation(t.Context(), successor, f.call+10)
	if err != nil {
		t.Fatal(err)
	}
	later, err := CheckTransitionContinuation(t.Context(), successor, p)
	if err != nil || later.checked.bound.Registers[RAX].Pointer != before.Registers[RBP].Pointer {
		t.Fatal("body scratch lost its residual saved pointer", err)
	}
	if successor.checked.work <= entered.checked.work+child.checked.work || successor.checked.limits.LiveStateBytes >= entered.checked.limits.LiveStateBytes || successor.checked.limits.Nodes >= entered.checked.limits.Nodes {
		t.Fatal("active application reset work or retained dependency allowances")
	}
	if c.checked.entry.checked.limits.LiveStateBytes >= entered.checked.limits.LiveStateBytes || c.checked.entry.checked.limits.Nodes >= entered.checked.limits.Nodes || successor.checked.limits.LiveStateBytes >= c.checked.entry.checked.limits.LiveStateBytes || successor.checked.limits.Nodes >= c.checked.entry.checked.limits.Nodes {
		t.Fatal("hydration discarded the already imported child dependency account")
	}
	if after, _ := entered.Bound(); !reflect.DeepEqual(before, after) {
		t.Fatal("active input mutated")
	}
	if after, _ := child.Bound(); !reflect.DeepEqual(childBefore, after) {
		t.Fatal("callee input mutated")
	}
	// Direct application must still bind the encoded target, not a later body.
	caller := applicationRoot(t, f.im, testEntry, f.call, f.parent, nil)
	bad, err := CheckTransitionCallReturn(t.Context(), caller, child)
	applicationRefused(t, bad, err)
}

func TestTransitionActiveApplicationControlHistory(t *testing.T) {
	for _, tc := range []struct{ name, wrapper string }{
		{"same-value-wrapper", "488b042448890424"},
		{"overwritten-and-restored", "488b042448c704240000000048890424"},
		// CALL nested; JMP past its body. The nested activation stores its
		// caller's saved control word unchanged at [RSP+8], then really returns.
		{"same-value-descendant", "e802000000eb0b488b4424084889442408c3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newActiveApplicationFixture(t, tc.wrapper, "c3")
			if tc.name == "same-value-descendant" {
				// CALL reaches +7; its continuation jumps to the tail at +18.
				f.parentExp = append(f.parentExp, TransitionExpansion{PC: applicationChild, AllActivations: true})
			}
			entered, child := activeApplicationCertificates(t, f)
			c, err := CheckTransitionActiveReturn(t.Context(), entered, child)
			applicationRefused(t, c, err)
			var cause *Refusal
			if !errors.As(err, &cause) || cause.Premise != "transition-application-protected" {
				t.Fatal("control protection did not audit wrapper/descendant writes", err)
			}
		})
	}
}

func TestTransitionActiveApplicationNestedParent(t *testing.T) {
	code := hexBytes(t, "e81b000000c3")
	for len(code) < 32 {
		code = append(code, 0x90)
	}
	code = append(code, hexBytes(t, "55b82a0000005dc3")...)
	f := newApplicationFixture(t, "", fmt.Sprintf("%x", code))
	f.parentExp = []TransitionExpansion{{PC: f.call}, {PC: applicationChild, AllActivations: true}}
	f.child.Origin.Min -= 8
	f.child.Origin.Max -= 8
	f.child.Origin.Residue = 0
	f.child.ReturnContext.Target = applicationChild + 5
	entered, child := activeApplicationCertificates(t, f)
	before := entered.checked.bound
	c, err := CheckTransitionActiveReturn(t.Context(), entered, child)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if len(before.Frames) != 2 || b.StackShift != -16 || b.Call != applicationChild || b.Continuation != applicationChild+5 || !slices.Equal(b.Successor.Frames, before.Frames[:1]) || b.Successor.Boundary.Context != before.Frames[0].Context || b.Successor.Registers[RSP].Pointer != (OriginPointer{Origin: before.Origin, Offset: -8}) {
		t.Fatal("active return lost its still-active parent frame")
	}
	assertApplicationOccurrences(t, c, child)
}

func TestTransitionActiveApplicationAffineStackGuard(t *testing.T) {
	// The wrapper allocates and releases scratch before its tail JMP. RSP's
	// actual scalar spelling is ((S-8)-56)+56, with the same checked slot.
	f := newActiveApplicationFixture(t, "4883ec384883c438", returnFrameCode)
	f.ret = activeApplicationBody + 24
	f.childExp = []TransitionExpansion{{PC: activeApplicationBody}}
	for _, face := range []*TransitionInterface{&f.parent, &f.child} {
		face.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 24}}
		face.EntryImagePointers = []TransitionEntryImagePointer{{Register: R14, Address: imageStateAddress}}
		face.EntryWordUpperBounds = []TransitionEntryWordUpperBound{{Address: imageStateAddress + 16}}
	}
	f.parent.EntryWordUpperBounds[0].OriginOffset = -8
	entered, child := activeApplicationCertificates(t, f)
	c, err := CheckTransitionActiveReturn(t.Context(), entered, child)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	if b.StackShift != -8 || len(b.Successor.ExcludedBoundaries) != 1 || b.Successor.ExcludedBoundaries[0].Context != b.Activation || b.Registers[RSP] != entered.checked.bound.Registers[RSP] {
		t.Fatal("affine normalization changed body-entry associations or guard")
	}
	assertApplicationOccurrences(t, c, child)
}

func TestTransitionActiveApplicationEntryControls(t *testing.T) {
	f := newActiveApplicationFixture(t, "488d6c2418", "b82a000000c3")
	entered, child := activeApplicationCertificates(t, f)
	for _, tc := range []struct {
		name string
		edit func(*checkedTransition)
	}{
		{"wrong-entry", func(c *checkedTransition) { c.bound.Boundary.PC++ }},
		{"no-frame", func(c *checkedTransition) { c.bound.Frames = nil }},
		{"boundary-context", func(c *checkedTransition) { c.bound.Boundary.Context++ }},
		{"frame-context", func(c *checkedTransition) { c.bound.Frames[0].Context++ }},
		{"frame-id", func(c *checkedTransition) { c.bound.Frames[0].ID++ }},
		{"frame-call", func(c *checkedTransition) { c.bound.Frames[0].Call++ }},
		{"frame-slot", func(c *checkedTransition) { c.bound.Frames[0].Slot.Offset++ }},
		{"frame-return", func(c *checkedTransition) { c.bound.Frames[0].Return++ }},
		{"missing-call-store", func(c *checkedTransition) { c.bound.Accesses = nil }},
		{"call-store-context", func(c *checkedTransition) { c.bound.Accesses[0].Context = c.bound.Frames[0].Context }},
		{"call-store-extent", func(c *checkedTransition) { c.bound.Accesses[0].Bytes.End++ }},
		{"missing-call-instruction", func(c *checkedTransition) { c.bound.Instructions = c.bound.Instructions[1:] }},
		{"missing-call-witness", func(c *checkedTransition) { c.witness.Nodes = c.witness.Nodes[1:] }},
		{"old-rules", func(c *checkedTransition) { c.bound.Rules = "gofresh/native-transition@19" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := *entered.checked
			copy.bound = cloneTransitionBound(copy.bound)
			tc.edit(&copy)
			c, err := CheckTransitionActiveReturn(t.Context(), TransitionCertificate{&copy}, child)
			applicationRefused(t, c, err)
		})
	}
	other := newActiveApplicationFixture(t, "488d6c2418", "b82a000000c3")
	_, otherChild := activeApplicationCertificates(t, other)
	c, err := CheckTransitionActiveReturn(t.Context(), entered, otherChild)
	applicationRefused(t, c, err)
	if accepted, err := CheckTransitionActiveReturn(t.Context(), entered, child); err != nil {
		t.Fatal(err)
	} else if _, ok := accepted.BoundFor(other.im); ok {
		t.Fatal("equal-byte image borrowed owner")
	}
	wrong := f
	wrong.child.ReturnContext = &TransitionReturnContext{Target: testEntry + 128, Preserved: []Register{RBP}}
	_, wrongChild := activeApplicationCertificates(t, wrong)
	c, err = CheckTransitionActiveReturn(t.Context(), entered, wrongChild)
	applicationRefused(t, c, err)
	// Reachable body entry with an active frame but RSP below its saved slot.
	f = newActiveApplicationFixture(t, "488d6424f8", "c3")
	entered, child = activeApplicationCertificates(t, f)
	c, err = CheckTransitionActiveReturn(t.Context(), entered, child)
	applicationRefused(t, c, err)
	// An independently checked body region supplies no executed CALL authority.
	root := applicationRoot(t, f.im, activeApplicationBody, activeApplicationBody, f.child, nil)
	c, err = CheckTransitionActiveReturn(t.Context(), root, child)
	applicationRefused(t, c, err)
	for _, inputs := range []struct {
		ctx     context.Context
		entered TransitionCertificate
		child   TransitionReturnCertificate
	}{{nil, entered, child}, {t.Context(), TransitionCertificate{}, child}, {t.Context(), entered, TransitionReturnCertificate{}}} {
		c, err := CheckTransitionActiveReturn(inputs.ctx, inputs.entered, inputs.child)
		applicationRefused(t, c, err)
	}
}

func TestTransitionActiveApplicationFiniteLifetime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		until  uint64
		accept bool
	}{
		{"unexpired", testEntry + 128, true},
		{"return-at-deadline", testEntry + 5, true},
		{"expired-at-call", testEntry, false},
		{"expired-in-wrapper", applicationChild, false},
		{"current-deadline", activeApplicationBody, false},
		{"body-deadline", activeApplicationBody + 1, false},
		{"return-deadline", activeApplicationBody + 7, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newActiveApplicationFixture(t, "488d6c2418", "55b82a0000005dc3")
			f.parent.ReturnContext = nil
			f.parent.PrivateFrame.Until = &tc.until
			p, err := ProposeTransition(t.Context(), f.im, activeApplicationBody, TransitionLimits{}, TransitionOptions{Expansions: f.parentExp})
			if err != nil {
				t.Fatal(err)
			}
			entered, err := CheckTransition(t.Context(), f.im, f.parent, p, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			child := checkedReturn(t, applicationRoot(t, f.im, activeApplicationBody, f.ret, f.child, nil))
			c, err := CheckTransitionActiveReturn(t.Context(), entered, child)
			if !tc.accept {
				privateLifetimeRefused(t, c, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c.Bound()
			if b.Successor.ConditionalRegion || !reflect.DeepEqual(b.Successor.Interface, entered.checked.bound.Interface) {
				t.Fatal("active application replaced executable root or lifetime")
			}
			stateInheritedInputs(t, entered.checked.bound, b.Successor)
		})
	}
}

func TestTransitionActiveApplicationCumulativeLimitsAndCancellation(t *testing.T) {
	f := newActiveApplicationFixture(t, "488d6c2418", "554889e5b82a0000005dc3")
	entered, child := activeApplicationCertificates(t, f)
	before, _ := entered.Bound()
	const generous = 10000000
	count := &checkpointContext{Context: t.Context(), remaining: generous}
	c, err := CheckTransitionActiveReturn(count, entered, child)
	if err != nil {
		t.Fatal(err)
	}
	calls := generous - count.remaining
	for _, at := range []int{1, 100, calls / 2, calls - 1, calls} {
		ctx := &checkpointContext{Context: t.Context(), remaining: at}
		bad, err := CheckTransitionActiveReturn(ctx, entered, child)
		applicationRefused(t, bad, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation hidden", at, err)
		}
	}
	work := c.checked.successor.checked.work
	for _, limit := range []int{entered.checked.work, entered.checked.work + child.checked.work, work - 1, work} {
		copy := *entered.checked
		copy.limits.Work = limit
		got, err := CheckTransitionActiveReturn(t.Context(), TransitionCertificate{&copy}, child)
		if limit == work {
			if err != nil {
				t.Fatal("exact work refused", err)
			}
		} else {
			applicationRefused(t, got, err)
		}
	}
	copy := *entered.checked
	copy.limits.LiveStateBytes = 8192
	bad, err := CheckTransitionActiveReturn(t.Context(), TransitionCertificate{&copy}, child)
	applicationRefused(t, bad, err)
	if after, _ := entered.Bound(); !reflect.DeepEqual(before, after) {
		t.Fatal("failed application changed input")
	}
	if _, err := CheckTransitionActiveReturn(t.Context(), entered, child); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionActiveApplicationCurrentMachineAssociations(t *testing.T) {
	for _, tc := range []struct {
		name, wrapper string
		configure     func(*applicationFixture)
	}{
		{"FS", fmt.Sprintf("%x", applicationFSCode(0x12340)), func(f *applicationFixture) {
			f.parent.Conditions.Syscall, f.child.Conditions.Syscall = LinuxAMD64SyscallModel, LinuxAMD64SyscallModel
			f.parent.Conditions.UserAddressBits, f.child.Conditions.UserAddressBits = 48, 48
			f.parentExp = append(f.parentExp, TransitionExpansion{PC: applicationChild + uint64(len(applicationFSCode(0))-2), AllActivations: true})
		}},
		{"DF", "fc", func(f *applicationFixture) {
			f.parentExp = append(f.parentExp, TransitionExpansion{PC: applicationChild, AllActivations: true})
		}},
		{"vector", "f30f10442418", func(f *applicationFixture) {
			f.parent.Conditions.SSE, f.child.Conditions.SSE = SSEModel, SSEModel
			f.parentExp = append(f.parentExp, TransitionExpansion{PC: applicationChild, AllActivations: true})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newActiveApplicationFixture(t, tc.wrapper, "c3")
			tc.configure(&f)
			entered, child := activeApplicationCertificates(t, f)
			before, _ := entered.Bound()
			c, err := CheckTransitionActiveReturn(t.Context(), entered, child)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c.Bound()
			if b.Thread != before.Thread || b.Direction != before.Direction || b.Vectors != before.Vectors || b.Registers != before.Registers || b.Successor.Thread != before.Thread || b.Successor.Direction != before.Direction || b.Successor.Vectors != before.Vectors {
				t.Fatal("active associations replaced actual machine state")
			}
			if b.InputFS != child.checked.prefix.checked.bound.InitialFS || b.InputDirection != child.checked.prefix.checked.bound.InitialDirection || b.InputVectors != child.checked.prefix.checked.bound.InitialVectors {
				t.Fatal("lost child input identities")
			}
		})
	}
}

func assertApplicationOccurrences(t testing.TB, c TransitionCallCertificate, child TransitionReturnCertificate) {
	t.Helper()
	b, _ := c.Bound()
	nodes := child.checked.prefix.checked.witness.Nodes
	if len(b.Occurrences) != len(nodes) {
		t.Fatal("incomplete child occurrence map")
	}
	seen := make(map[TransitionOccurrenceID]bool)
	for j, association := range b.Occurrences {
		if association.Input != nodes[j].ID || association.Current == 0 || seen[association.Current] || association.Current == b.Successor.Boundary.ID {
			t.Fatal("invalid or noninjective occurrence association")
		}
		seen[association.Current] = true
		found := false
		for _, node := range c.checked.successor.checked.witness.Nodes {
			if node.ID == association.Current {
				found = node.PC == nodes[j].PC
			}
		}
		if !found {
			t.Fatal("association is not the actual embedded occurrence")
		}
		if association.Input == child.checked.prefix.checked.witness.Root && association.Current != b.ChildEntry.Boundary.ID {
			t.Fatal("child root not mapped to actual body entry")
		}
		if association.Input == child.checked.prefix.checked.bound.Boundary.ID {
			if !slices.ContainsFunc(b.Successor.Accesses, func(a TransitionAccess) bool {
				return a.ID == association.Current && a.Kind == FrameReturnRead && a.Context == b.Activation
			}) {
				t.Fatal("terminal RET not mapped to actual return read")
			}
		}
	}
	b.Occurrences[0].Current = 0
	fresh, _ := c.Bound()
	if fresh.Occurrences[0].Current == 0 {
		t.Fatal("mutable occurrence association aliases authority")
	}
}

func TestTransitionActiveApplicationOccurrenceAssociations(t *testing.T) {
	// The independent theorem conditionally reads scratch. At actual entry the
	// wrapper makes the branch literal false, so replay drops that read while
	// retaining the occurrence embedding and terminal RET.
	// XOR makes CF literally false; INC preserves CF while defining the other
	// arithmetic flags required at body entry. The child tests incoming CF.
	f := newActiveApplicationFixture(t, "31c048ffc0", "7305488b4424e8c3")
	f.parentExp = append(f.parentExp, TransitionExpansion{PC: applicationChild, AllActivations: true}, TransitionExpansion{PC: applicationChild + 2, AllActivations: true})
	p, err := ProposeRegionTransition(t.Context(), f.im, activeApplicationBody, f.ret, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	// Use nontrivial IDs to prevent an accidental numeric-offset mapping.
	ids := make(map[TransitionOccurrenceID]TransitionOccurrenceID)
	for j, node := range p.Nodes {
		ids[node.ID] = TransitionOccurrenceID(1000 + j*17)
	}
	p.Root = ids[p.Root]
	for j := range p.Nodes {
		p.Nodes[j].ID = ids[p.Nodes[j].ID]
		for k, id := range p.Nodes[j].Successors {
			p.Nodes[j].Successors[k] = ids[id]
		}
	}
	prefix, err := CheckRegionTransition(t.Context(), f.im, activeApplicationBody, f.child, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	child := checkedReturn(t, prefix)
	entered := applicationRoot(t, f.im, testEntry, activeApplicationBody, f.parent, f.parentExp)
	c, err := CheckTransitionActiveReturn(t.Context(), entered, child)
	if err != nil {
		t.Fatal(err)
	}
	assertApplicationOccurrences(t, c, child)
	b, _ := c.Bound()
	if len(prefix.checked.bound.Accesses) != 1 || len(b.Successor.Accesses)-len(b.ChildEntry.Accesses) != 1 {
		t.Fatal("fixture did not drop the specialized scratch read")
	}
}

// Reuse the existing 48-program application grammar and independent concrete
// oracle at the already-entered boundary: 384 joint valuations across origin,
// branch, stack displacement, frame size, memory history and BP provenance.
func TestTransitionActiveApplicationJointPopulation(t *testing.T) {
	for _, delta := range []int{0, 16, 32, 48} {
		for _, frame := range []int{16, 32} {
			for _, seeded := range []bool{false, true} {
				for bp := 0; bp < 3; bp++ {
					p := applicationPopulation{delta, frame, seeded, bp}
					t.Run(fmt.Sprintf("delta%d/frame%d/seeded%t/bp%d", delta, frame, seeded, bp), func(t *testing.T) {
						code := applicationPopulationBuild(t, p)
						entered := applicationRoot(t, code.im, testEntry, testEntry+128, code.parent, []TransitionExpansion{{PC: code.call}})
						child := checkedReturn(t, applicationRoot(t, code.im, testEntry+128, code.childRet, code.child, nil))
						c, err := CheckTransitionActiveReturn(t.Context(), entered, child)
						if err != nil {
							t.Fatal(err)
						}
						assertApplicationOccurrences(t, c, child)
						b, _ := c.Bound()
						successor, _ := c.Successor()
						proposal, err := ProposeTransitionContinuation(t.Context(), successor, code.rootRet)
						if err != nil {
							t.Fatal(err)
						}
						beforeRET, err := CheckTransitionContinuation(t.Context(), successor, proposal)
						if err != nil {
							t.Fatal(err)
						}
						completed, _ := checkedReturn(t, beforeRET).Bound()
						for origin := 0; origin < 4; origin++ {
							for arm := 0; arm < 2; arm++ {
								values, initial := applicationPopulationInputs(t, b.Successor, p, origin, arm)
								entry, returned, complete := applicationConcreteRun(p, code, initial, b.Activation)
								applicationPopulationAssert(t, b.ChildEntry.Registers, b.ChildEntry.Memory, b.ChildEntry.Instructions, b.ChildEntry.Accesses, values, entry)
								applicationPopulationAssert(t, b.Successor.Registers, b.Successor.Memory, b.Successor.Instructions, b.Successor.Accesses, values, returned)
								applicationPopulationAssert(t, completed.State.Registers, completed.State.Memory, completed.Instructions, completed.Accesses, values, complete)
							}
						}
					})
				}
			}
		}
	}
}
