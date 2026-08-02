package harnesswrap

import (
	"os"
	"testing"
)

// quietT satisfies testing.TB through the embedded core while
// overriding Fatal with an effect-free body: the dispatch target set is
// no longer harness-only, and the admission must keep the widen even
// though the override does nothing — classifiability is a property of
// the dispatch shape, never of what the extra target happens to do.
type quietT struct{ *testing.T }

func (quietT) Fatal(...any) {}

func helper(tb testing.TB) []byte {
	data, err := os.ReadFile("baseline.txt")
	if err != nil {
		tb.Fatal(err)
	}
	return data
}

func TestQuietWrappedFatal(t *testing.T) {
	if len(helper(quietT{t})) == 0 {
		t.Fatalf("empty baseline")
	}
}
