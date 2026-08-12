package harnessobserved

import (
	"os"
	"testing"
)

// setup runs inside TestMain and reads a fixture file - test-main flow
// runs with the test log installed (the log installs in the
// toolchain-generated test-main package's initializer, after every
// dependency initializer and before the user test main), so the
// admitted read is a bracketed observation input, not a startup
// effect.
func setup() {
	if f, err := os.Open("fixture.dat"); err == nil {
		f.Close()
	}
}

func TestMain(m *testing.M) {
	setup()
	os.Exit(m.Run())
}

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
