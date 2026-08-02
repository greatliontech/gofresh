package harnesstbenv

import (
	"os"
	"testing"
)

// mustEnv routes a non-audited harness method through the interface
// dispatch shape: the target set is not harness-only, so the invoke
// keeps the widen no matter what the target does.
func mustEnv(tb testing.TB) {
	tb.Setenv("HARNESSTBENV_FIXTURE", "1")
}

func TestHelperTBSetenv(t *testing.T) {
	mustEnv(t)
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
}
