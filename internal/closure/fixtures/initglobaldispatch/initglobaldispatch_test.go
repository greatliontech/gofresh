package initglobaldispatch

import (
	"os"
	"testing"
)

type noter interface{ note() }

type quietNote struct{}

func (quietNote) note() {}

// handler is shared mutable state an initializer dispatches through:
// initializer flow stays unwidened — nothing is plantable before tests
// run — so this package's subjects keep their proofs.
var handler noter = quietNote{}

func init() {
	handler.note()
}

func TestRead(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
}
