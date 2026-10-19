package nativeproof

import (
	"errors"
	"testing"
	"unsafe"
)

func TestTransitionReturnTerminalStorage(t *testing.T) {
	im, face := returnFixture(t, "c3")
	face.Conditions.SSE = SSEModel
	prefix := returnPrefix(t, im, face, testEntry)
	returned := checkedReturn(t, prefix)
	b, _ := returned.Bound()
	if b.State.Vectors != b.Prefix.InitialVectors || !b.State.SSE.MXCSRPreserved || !b.State.SSE.UpperVectorsPreserved {
		t.Fatal("terminal projection lost original vector or floating context")
	}
	// Isolate the terminal allocation from graph and inherited-state budgets.
	// The predecessor is valid; the narrowed allowance leaves room to import it
	// and preserve all context, but cannot retain the complete terminal object.
	prior := *prefix.checked
	m, err := newTransitionChecker(t.Context(), im, transitionRoot{entry: prior.bound.Entry, region: true}, prior.limits, prior.work)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.inherit(prior); err != nil {
		t.Fatal(err)
	}
	prior.limits.LiveStateBytes = m.liveStateBytes + 1024 + int(unsafe.Sizeof(NativeReturnedState{})) - 1
	got, err := CheckTransitionReturn(t.Context(), TransitionCertificate{checked: &prior})
	returnRefused(t, got, err)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Premise != "transition-budget" || err.Error() == "" {
		t.Fatal("terminal allocation refused for another reason", err)
	}
	if refusal.Detail != "terminal return state" {
		t.Fatal("earlier or later work hid missing terminal storage", err)
	}
}
