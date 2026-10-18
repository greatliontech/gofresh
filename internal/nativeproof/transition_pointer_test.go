package nativeproof

import "testing"

// A stack-only expectation must fail on both None and Image, rather than
// projecting either to a zero origin/offset and accidentally accepting it.
func requireStackPointer(t testing.TB, p TransitionPointer) OriginPointer {
	t.Helper()
	s, ok := p.(OriginPointer)
	if !ok || !s.Origin.Valid() {
		t.Fatalf("want Stack provenance, got %T %+v", p, p)
	}
	return s
}
