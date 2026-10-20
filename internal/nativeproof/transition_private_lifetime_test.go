package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func privateLifetimeFixture(t testing.TB, prefix, body string, until uint64) applicationFixture {
	t.Helper()
	f := newApplicationFixture(t, prefix, body)
	f.parent.ReturnContext = nil
	f.parent.PrivateFrame.Until = &until
	return f
}

func privateLifetimeRoot(t testing.TB, f applicationFixture, options TransitionOptions) TransitionCertificate {
	t.Helper()
	p, err := ProposeTransition(t.Context(), f.im, f.call, TransitionLimits{}, options)
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransition(t.Context(), f.im, f.parent, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func privateLifetimeChild(t testing.TB, f applicationFixture) TransitionReturnCertificate {
	t.Helper()
	return checkedReturn(t, applicationRoot(t, f.im, applicationChild, f.ret, f.child, f.childExp))
}

func privateLifetimeRefused(t testing.TB, c TransitionCallCertificate, err error) {
	t.Helper()
	applicationRefused(t, c, err)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Premise != "transition-application-private" {
		t.Fatal("expected ownership/lifetime refusal", err)
	}
}

func TestTransitionPrivateLifetimeRootKindsAndPermissions(t *testing.T) {
	f := privateLifetimeFixture(t, "", "c3", testEntry+128)
	p, err := ProposeTransition(t.Context(), f.im, f.call, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	root := privateLifetimeRoot(t, f, TransitionOptions{})
	if root.checked.bound.ConditionalRegion || root.checked.bound.Interface.ReturnContext != nil {
		t.Fatal("finite premise invented conditional callee authority")
	}
	for _, tc := range []struct {
		name string
		edit func(*TransitionInterface)
	}{
		{"nil-deadline", func(f *TransitionInterface) { f.PrivateFrame.Until = nil }},
		{"empty", func(f *TransitionInterface) { f.PrivateFrame.Bytes.Start = 0 }},
		{"positive", func(f *TransitionInterface) { f.PrivateFrame.Bytes.End = 1 }},
		{"outside-envelope", func(f *TransitionInterface) { f.PrivateFrame.Bytes.Start = -65 }},
		{"no-memory", func(f *TransitionInterface) { f.Regions = f.Regions[1:] }},
		{"no-read", func(f *TransitionInterface) { f.Regions[0].Readable = false }},
		{"no-write", func(f *TransitionInterface) { f.Regions[0].Writable = false }},
		{"unmapped-deadline", func(f *TransitionInterface) { *f.PrivateFrame.Until = 1 << 45 }},
		{"data-deadline", func(f *TransitionInterface) { *f.PrivateFrame.Until = imageStateAddress }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			face := cloneTransitionInterface(f.parent)
			tc.edit(&face)
			c, err := CheckTransition(t.Context(), f.im, face, p, TransitionLimits{})
			transitionRefused(t, c, err)
		})
	}
	plain := cloneTransitionInterface(f.parent)
	plain.PrivateFrame = nil
	parent, err := CheckTransition(t.Context(), f.im, plain, p, TransitionLimits{})
	if err != nil || parent.checked.bound.Interface.PrivateFrame != nil {
		t.Fatal("plain ELF root changed", err)
	}
	child := privateLifetimeChild(t, f)
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	privateLifetimeRefused(t, c, err) // permissions and CALL alone grant no ownership

	// A finite deadline is not another way to end a conditional callee lifetime.
	conditional := cloneTransitionInterface(f.parent)
	conditional.ReturnContext = &TransitionReturnContext{Target: testEntry + 128}
	bad, err := CheckRegionTransition(t.Context(), f.im, testEntry, conditional, p, TransitionLimits{})
	transitionRefused(t, bad, err)
	conditional.PrivateFrame.Until = nil
	// Even a target already encountered in this callee remains an actual-return
	// lifetime. It must not be converted into a first-PC-arrival deadline.
	conditional.ReturnContext.Target = testEntry
	parent = applicationRoot(t, f.im, testEntry, f.call, conditional, nil)
	if _, err := CheckTransitionCallReturn(t.Context(), parent, child); err != nil {
		t.Fatal("conditional return lifetime was reinterpreted as a PC deadline", err)
	}
}

func TestTransitionPrivateLifetimeDeadlineOccupancy(t *testing.T) {
	// MOV EAX,0x90909090: its immediate also decodes as NOPs, but a deadline
	// inside those bytes must not become an independent instruction boundary.
	f := privateLifetimeFixture(t, "b890909090", "c3", testEntry+1)
	p, err := ProposeTransition(t.Context(), f.im, f.call, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransition(t.Context(), f.im, f.parent, p, TransitionLimits{})
	transitionRefused(t, c, err)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Premise != "transition-private-frame" {
		t.Fatal("deadline overlap was not checked against reconstructed occupancy", err)
	}
	// The future overlap can be absent from the first graph, then appear only
	// when continuation establishes the instruction containing the deadline.
	p, err = ProposeTransition(t.Context(), f.im, testEntry, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	// The original cut itself also owns its complete decoded extent.
	c, err = CheckTransition(t.Context(), f.im, f.parent, p, TransitionLimits{})
	transitionRefused(t, c, err)

	f = privateLifetimeFixture(t, "bb01000000b890909090", "c3", testEntry+6)
	p, err = ProposeTransition(t.Context(), f.im, testEntry, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err = CheckTransition(t.Context(), f.im, f.parent, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	q, err := ProposeTransitionContinuation(t.Context(), c, f.call)
	if err != nil {
		t.Fatal(err)
	}
	next, err := CheckTransitionContinuation(t.Context(), c, q)
	transitionRefused(t, next, err)

	// The borrowed child's graph establishes new occupancy too. Its own
	// conditional return theorem has no finite deadline, so only replay under
	// the unchanged ELF root can discover this conflict.
	f = privateLifetimeFixture(t, "", "b890909090c3", applicationChild+1)
	parent, child := privateLifetimeRoot(t, f, TransitionOptions{}), privateLifetimeChild(t, f)
	call, err := CheckTransitionCallReturn(t.Context(), parent, child)
	applicationRefused(t, call, err)
	if !errors.As(err, &refusal) || refusal.Premise != "transition-private-frame" {
		t.Fatal("application did not check new child occupancy", err)
	}
}

func TestTransitionPrivateLifetimeOwnsZeroDeadline(t *testing.T) {
	code := hexBytes(t, "b801000000b902000000e81100000090")
	for len(code) < 32 {
		code = append(code, 0x90)
	}
	code = append(code, hexBytes(t, "b82a000000c3")...)
	raw := elfBytes(code)
	binary.LittleEndian.PutUint64(raw[24:], 0)
	binary.LittleEndian.PutUint64(raw[80:], 0)
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	until := uint64(0)
	face := occurrenceFace()
	face.PrivateFrame = &TransitionPrivateFrame{Bytes: RelativeSpan{-64, 0}, Until: &until}
	p, err := ProposeTransition(t.Context(), im, 5, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	count := &imageCallbackContext{Context: t.Context()}
	c, err := CheckTransition(count, im, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{1, count.calls / 2, count.calls} {
		f := cloneTransitionInterface(face)
		ctx := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n == at {
				*f.PrivateFrame.Until = 999
			}
		}}
		got, err := CheckTransition(ctx, im, f, p, TransitionLimits{})
		if err != nil || got.checked.bound.Interface.PrivateFrame.Until == nil || *got.checked.bound.Interface.PrivateFrame.Until != 0 {
			t.Fatal("callback changed the captured optional zero deadline", at, err)
		}
	}
	until = 999
	b, _ := c.Bound()
	*b.Interface.PrivateFrame.Until = 777
	q, err := ProposeTransitionContinuation(t.Context(), c, 10)
	if err != nil {
		t.Fatal(err)
	}
	next, err := CheckTransitionContinuation(t.Context(), c, q)
	if err != nil {
		t.Fatal("generic continuation beyond an expired grant refused", err)
	}
	after, _ := next.BoundFor(im)
	if after.Interface.PrivateFrame.Until == nil || *after.Interface.PrivateFrame.Until != 0 || len(after.Instructions) != 2 {
		t.Fatal("projection/continuation renewed or lost zero deadline/history")
	}
	*after.Interface.PrivateFrame.Until = 333
	fresh, _ := c.Bound()
	if *fresh.Interface.PrivateFrame.Until != 0 {
		t.Fatal("successor projection changed predecessor")
	}
	childFace := cloneTransitionInterface(fresh.Interface)
	childFace.Origin.Min -= 8
	childFace.Origin.Max -= 8
	childFace.Origin.Residue = 8
	childFace.Envelope = RelativeSpan{-8, 8}
	childFace.Regions = []RelativeRegion{{Bytes: RelativeSpan{-8, 0}, Readable: true, Writable: true}, {Bytes: RelativeSpan{0, 8}, Readable: true}}
	childFace.PrivateFrame = &TransitionPrivateFrame{Bytes: RelativeSpan{-8, 0}}
	childFace.ReturnContext = &TransitionReturnContext{Target: 15}
	child := checkedReturn(t, applicationRoot(t, im, 32, 37, childFace, nil))
	borrowed, err := CheckTransitionCallReturn(t.Context(), next, child)
	privateLifetimeRefused(t, borrowed, err)
	// The same code and child are usable under a genuinely unexpired root grant.
	lateFace := cloneTransitionInterface(fresh.Interface)
	late := uint64(15)
	lateFace.PrivateFrame.Until = &late
	parent := continuationRoot(t, im, 10, lateFace, TransitionLimits{})
	if _, err := CheckTransitionCallReturn(t.Context(), parent, child); err != nil {
		t.Fatal("zero-deadline refusal lacks an otherwise applicable child", err)
	}
}

func TestTransitionPrivateLifetimeApplicationArrivals(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, body string
		until              uint64
		options            TransitionOptions
		accept             bool
	}{
		{"not-yet-arrived", "", "55b82a0000005dc3", testEntry + 128, TransitionOptions{}, true},
		{"return-arrives-at-deadline", "", "55b82a0000005dc3", testEntry + 5, TransitionOptions{}, true},
		{"deadline-at-call", "", "c3", testEntry, TransitionOptions{}, false},
		{"deadline-at-child-entry", "", "c3", applicationChild, TransitionOptions{}, false},
		{"deadline-inside-child", "", "55b82a0000005dc3", applicationChild + 1, TransitionOptions{}, false},
		{"deadline-at-child-ret", "", "55b82a0000005dc3", applicationChild + 7, TransitionOptions{}, false},
		{"past-deadline", "b801000000", "c3", testEntry, TransitionOptions{}, false},
		{"reentered-deadline", "b8000000004883c0014883f80275f6", "c3", testEntry + 5, TransitionOptions{MaxOccurrences: 10}, false},
		{"unknown-expired-join", "7405b801000000", "c3", testEntry + 2, TransitionOptions{}, false},
		{"false-guard-deadline", "39c07405b801000000", "c3", testEntry + 4, TransitionOptions{}, true},
		{"excluded-deadline", "39c074020f0b", "c3", testEntry + 4, TransitionOptions{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := privateLifetimeFixture(t, tc.prefix, tc.body, tc.until)
			parent, child := privateLifetimeRoot(t, f, tc.options), privateLifetimeChild(t, f)
			before, _ := parent.Bound()
			c, err := CheckTransitionCallReturn(t.Context(), parent, child)
			if !tc.accept {
				privateLifetimeRefused(t, c, err)
			} else {
				if err != nil {
					t.Fatal(err)
				}
				b, _ := c.Bound()
				if b.Successor.ConditionalRegion || !reflect.DeepEqual(before.Interface, b.Successor.Interface) || b.Successor.Boundary.PC != f.call+5 || len(b.Successor.Frames) != 0 {
					t.Fatal("application replaced root premises or failed actual return")
				}
				stateInheritedInputs(t, before, b.Successor)
				if tc.name == "false-guard-deadline" {
					found := false
					for _, ins := range before.Instructions {
						found = found || ins.Start == tc.until
					}
					if !found || len(c.checked.proofs) == 0 || len(c.checked.successor.checked.justifications) <= len(parent.checked.justifications) {
						t.Fatal("false-guard history lacked retained checked justification")
					}
				}
				if tc.name == "excluded-deadline" && len(b.Successor.ExcludedBoundaries) != 1 {
					t.Fatal("excluded deadline acquired execution or lost exclusion")
				}
			}
			after, _ := parent.Bound()
			if !reflect.DeepEqual(before, after) {
				t.Fatal("application changed immutable caller")
			}
		})
	}
}

func TestTransitionPrivateLifetimeNestedChildDeadline(t *testing.T) {
	// The borrowed child calls another activation at +80. That descendant is
	// part of the whole borrowed lifetime even though its RET is not the child's
	// final return and has a different occurrence/activation context.
	for _, until := range []uint64{testEntry + 5, applicationChild + 16} {
		f := privateLifetimeFixture(t, "", "e80b000000c3"+strings.Repeat("90", 10)+"b82a000000c3", until)
		f.ret = applicationChild + 5
		f.childExp = []TransitionExpansion{{PC: applicationChild}}
		parent, child := privateLifetimeRoot(t, f, TransitionOptions{}), privateLifetimeChild(t, f)
		c, err := CheckTransitionCallReturn(t.Context(), parent, child)
		if until == testEntry+5 {
			if err != nil || !c.AppliesTo(child) {
				t.Fatal("nested lifetime control has no accepted baseline", err)
			}
		} else {
			privateLifetimeRefused(t, c, err)
		}
	}
}

func TestTransitionPrivateLifetimeReturnReleaseAndLaterBorrow(t *testing.T) {
	f := privateLifetimeFixture(t, "488d6c2418", "554889e5b82a0000005dc3", testEntry+10)
	// Replace the original root RET after its residual saved-BP load with a
	// second CALL to the same body. Its own return theorem has a new continuation.
	raw := append([]byte(nil), f.im.data...)
	copy(raw[4096+15:], []byte{0xe8, 0, 0, 0, 0, 0x90})
	binary.LittleEndian.PutUint32(raw[4096+16:], uint32(applicationChild-(testEntry+20)))
	var err error
	f.im, err = NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := privateLifetimeRoot(t, f, TransitionOptions{}), privateLifetimeChild(t, f)
	c, err := CheckTransitionCallReturn(t.Context(), parent, child)
	if err != nil {
		t.Fatal(err)
	}
	successor, _ := c.Successor()
	b, _ := c.Bound()
	if b.Successor.Boundary.PC != *f.parent.PrivateFrame.Until || len(b.Successor.Accesses) != 4 {
		t.Fatal("return to unexecuted deadline lost residual write/control trace")
	}
	// Mutating both projections cannot renew the successor's original deadline.
	*b.ChildEntry.Interface.PrivateFrame.Until = testEntry + 128
	*b.Successor.Interface.PrivateFrame.Until = testEntry + 128
	p, err := ProposeTransitionContinuation(t.Context(), successor, testEntry+15)
	if err != nil {
		t.Fatal(err)
	}
	later, err := CheckTransitionContinuation(t.Context(), successor, p)
	if err != nil {
		t.Fatal(err)
	}
	stateInheritedInputs(t, parent.checked.bound, later.checked.bound)
	if got := stateEval(t, later.checked.bound.Registers[RAX].Value, map[br.Term]uint64{parent.checked.bound.Origin: 65536}); got != 65560 {
		t.Fatal("release reset residual saved pointer", got)
	}
	if *later.checked.bound.Interface.PrivateFrame.Until != testEntry+10 || len(later.checked.bound.Accesses) != 5 {
		t.Fatal("generic continuation renewed lifetime or erased history")
	}
	f.child.ReturnContext.Target = testEntry + 20
	secondChild := privateLifetimeChild(t, f)
	again, err := CheckTransitionCallReturn(t.Context(), later, secondChild)
	privateLifetimeRefused(t, again, err)
	if _, err := CheckTransitionCallReturn(t.Context(), parent, child); err != nil {
		t.Fatal("later refusal damaged reusable original input", err)
	}
}

func TestTransitionPrivateLifetimeCumulativeWorkAndCancellation(t *testing.T) {
	f := privateLifetimeFixture(t, "39c07405b801000000", "c3", testEntry+4)
	parent, child := privateLifetimeRoot(t, f, TransitionOptions{}), privateLifetimeChild(t, f)
	before, _ := parent.Bound()
	const generous = 10000000
	count := &checkpointContext{Context: t.Context(), remaining: generous}
	c, err := CheckTransitionCallReturn(count, parent, child)
	if err != nil {
		t.Fatal(err)
	}
	calls, work := generous-count.remaining, c.checked.successor.checked.work
	for _, at := range []int{1, calls / 2, calls - 1, calls} {
		ctx := &checkpointContext{Context: t.Context(), remaining: at}
		got, err := CheckTransitionCallReturn(ctx, parent, child)
		applicationRefused(t, got, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled lifetime proof published", at, err)
		}
	}
	for _, limit := range []int{parent.checked.work + child.checked.work, work - 1, work} {
		copy := *parent.checked
		copy.limits.Work = limit
		got, err := CheckTransitionCallReturn(t.Context(), TransitionCertificate{&copy}, child)
		if limit == work {
			if err != nil {
				t.Fatal("exact cumulative account refused", err)
			}
		} else {
			applicationRefused(t, got, err)
		}
	}
	after, _ := parent.Bound()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("cancelled/bounded sibling changed original caller")
	}
	if _, err := CheckTransitionCallReturn(t.Context(), parent, child); err != nil {
		t.Fatal("original input unusable after refusal", err)
	}
}
