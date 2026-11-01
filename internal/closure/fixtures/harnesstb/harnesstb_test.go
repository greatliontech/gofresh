package harnesstb

import (
	"os"
	"testing"
)

// mustBaseline routes the harness failure channel through testing.TB, so
// the subject reaches Fatal as an RTA-resolved interface dispatch rather
// than a static call.
func mustBaseline(tb testing.TB) []byte {
	data, err := os.ReadFile("baseline.txt")
	if err != nil {
		tb.Fatal(err)
	}
	return data
}

func TestHelperTBFatal(t *testing.T) {
	if len(mustBaseline(t)) == 0 {
		t.Fatalf("empty baseline")
	}
}

// TestHelperTBTwice feeds one interface value to two call sites of the
// same helper: a completed provenance evaluation of the shared value
// must not poison the second site's check.
func TestHelperTBTwice(t *testing.T) {
	var tb testing.TB = t
	if len(mustBaseline(tb)) == 0 {
		t.Fatalf("empty baseline")
	}
	if len(mustBaseline(tb)) == 0 {
		t.Fatalf("still empty")
	}
}

// mustBaselineDeep threads the interface value through its own
// recursion: the provenance walk's cycle guard must refuse fail-closed
// (and terminate) rather than admit or diverge.
func mustBaselineDeep(tb testing.TB, n int) []byte {
	if n > 0 {
		return mustBaselineDeep(tb, n-1)
	}
	data, err := os.ReadFile("baseline.txt")
	if err != nil {
		tb.Fatal(err)
	}
	return data
}

func TestHelperTBRecursive(t *testing.T) {
	if len(mustBaselineDeep(t, 2)) == 0 {
		t.Fatalf("empty baseline")
	}
}
