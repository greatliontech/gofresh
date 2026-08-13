package harnesstbenv

import (
	"os"
	"testing"
)

// mustEnv routes a non-audited harness method through the interface
// dispatch shape: the subject-determined dispatch admission classifies
// the enumerated targets instead of widening, and testing.Setenv's own
// process-mutation classification refuses the subject causally.
func mustEnv(tb testing.TB) {
	tb.Setenv("HARNESSTBENV_FIXTURE", "1")
}

func TestHelperTBSetenv(t *testing.T) {
	mustEnv(t)
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
}
