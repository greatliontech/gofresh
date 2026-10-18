package nativeproof

import "testing"

// Straight-line controls additionally require every occurrence to be unconditional.
func straightFetches(t testing.TB, b TransitionBound) []Span {
	t.Helper()
	var spans []Span
	for _, i := range b.Instructions {
		if stateEval(t, i.Guard, nil) != 1 {
			t.Fatal("straight-line occurrence became conditional")
		}
		spans = append(spans, i.Span)
	}
	if stateEval(t, b.CutGuard, nil) != 1 {
		t.Fatal("straight-line cut not reached")
	}
	return spans
}
