package harnessmainlaunder

import (
	"os"
	"testing"
)

// planted reaches TestMain's call laundered through the empty
// interface: the interface hop must not wash the wrapper obligation
// off the closed-value walk.
var planted testing.TB

type envTB struct{ *testing.T }

func (envTB) Fatal(...any) { _ = os.Getenv("HARNESSMAINLAUNDER_SECRET") }

func TestMain(m *testing.M) {
	_ = m.Run()
	if planted != nil {
		var x any = planted.Fatal
		f := x.(func(...any))
		f("laundered late")
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
