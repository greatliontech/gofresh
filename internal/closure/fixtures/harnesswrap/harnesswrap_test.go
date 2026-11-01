package harnesswrap

import (
	"os"
	"testing"
)

// quietT satisfies testing.TB through the embedded core while
// overriding Fatal with an effect-free body: the dispatch target set is
// no longer harness-only, so the subject-determined dispatch admission
// classifies the enumerated targets instead of widening - the admission
// keys on operand provenance and target analyzability, never on what
// the override's body happens to do. The wrapper type's promoted
// method set drains testing's bodies into the walk, and the subject
// then refuses causally on the file I/O reached there.
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
