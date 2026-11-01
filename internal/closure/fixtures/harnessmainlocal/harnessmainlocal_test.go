package harnessmainlocal

import (
	"os"
	"testing"
)

type quiet interface{ Quiet() }

type quietDoer struct{}

func (quietDoer) Quiet() {}

// TestMain dispatches only its own locally-constructed value through a
// package-local interface: the startup widen must not fire — the
// planted channel is shared mutable state, never a test-main's own
// constructions.
func TestMain(m *testing.M) {
	var q quiet = quietDoer{}
	_ = m.Run()
	q.Quiet()
}

func TestRead(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
}
