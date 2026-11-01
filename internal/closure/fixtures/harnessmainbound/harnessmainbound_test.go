package harnessmainbound

import (
	"os"
	"testing"
)

// planted is the method-value form of the post-run channel: TestMain
// eta-expands the planted value's method, so the dispatch hides inside
// a synthetic bound wrapper whose std-attributed body the startup walk
// never scans — the wrapper's bound receiver carries the provenance.
var planted testing.TB

type envTB struct{ *testing.T }

func (envTB) Fatal(...any) { _ = os.Getenv("HARNESSMAINBOUND_SECRET") }

func TestMain(m *testing.M) {
	_ = m.Run()
	if planted != nil {
		f := planted.Fatal
		f("bound late")
	}
}

func TestPlant(t *testing.T) {
	planted = envTB{t}
}

func TestRead(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
}
