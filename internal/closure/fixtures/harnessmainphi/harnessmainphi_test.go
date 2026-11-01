package harnessmainphi

import (
	"os"
	"testing"
)

// planted reaches TestMain's call through a phi of bound-method values:
// the closed-value walk's binding obligation, not the call site's
// syntax, must carry the refusal.
var planted testing.TB

type envTB struct{ *testing.T }

func (envTB) Fatal(...any) { _ = os.Getenv("HARNESSMAINPHI_SECRET") }

func TestMain(m *testing.M) {
	_ = m.Run()
	if planted != nil {
		f := planted.Fatal
		if len("x") == 1 {
			f = planted.Fatal
		}
		f("phi late")
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
