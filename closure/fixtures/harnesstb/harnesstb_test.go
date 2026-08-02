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
