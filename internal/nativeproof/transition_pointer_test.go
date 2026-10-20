package nativeproof

import "testing"

// A stack-only expectation must fail on both None and Image, rather than
// projecting either to a zero origin/offset and accidentally accepting it.
func requireStackPointer(t testing.TB, p TransitionPointer) AddressPointer {
	t.Helper()
	s, ok := p.(AddressPointer)
	if !ok || s.view == nil || s.view.backing.role != stackBacking || !s.view.backing.geometry.origin.Valid() || s.view != &s.view.backing.geometry.stackView {
		t.Fatalf("want Stack provenance, got %T %+v", p, p)
	}
	return s
}

// Direct transfer fixtures own their geometry just as a root constructor does.
// They deliberately bypass interface validation when probing refusal branches.
func fixtureGeometry(t testing.TB, m *transitionChecker) {
	t.Helper()
	if m.im == nil {
		m.im = image(t, []byte{0xc3})
	}
	m.bound.Geometry = newTransitionGeometry(m.im, cloneTransitionInterface(m.face), m.bound.Origin)
}

// Independent expected coordinates retain ownership while comparing their
// observable spelling; they do not ask the resolver to decide the expectation.
func extentCoordinates(e TransitionExtent) RelativeSpan {
	return RelativeSpan{e.start.offset, e.start.offset + e.width}
}
